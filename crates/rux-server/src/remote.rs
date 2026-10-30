//! A minimal Rex control-protocol client. `rex.server(label)` uses it
//! to forward calls to the server a `rex.host` declaration names,
//! instead of running them locally. Endpoints are tried in order.
//! Supported forms: `unix:///path`, `tcp://host:port`, `ws://`,
//! `http://`, `wss://`, `https://`, and a bare `host:port`. The WebSocket
//! path defaults to `/api/control`. TLS verifies against the system CA
//! bundle.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mlua::{Lua, LuaSerdeExt, Value as LuaValue};
use serde_json::{json, Value};
use tungstenite::client::ClientRequestBuilder;
use tungstenite::Message;

const TIMEOUT: Duration = Duration::from_secs(15);

/// Call `method` on the server at the first endpoint that answers.
/// Errors carry the endpoint that produced them.
pub fn call(endpoints: &[String], method: &str, payload: Value) -> Result<Value, String> {
    if endpoints.is_empty() {
        return Err("the host has no endpoints".into());
    }
    let mut last_error = String::new();
    for endpoint in endpoints {
        match call_one(endpoint, method, &payload) {
            Ok(value) => return Ok(value),
            Err(error) => last_error = format!("{endpoint}: {error}"),
        }
    }
    Err(last_error)
}

/// The `rex.call`-shaped wrapper the Lua proxy closures share: a result
/// value, or nil and a message. Never raises.
pub fn invoke_lua(
    lua: &Lua,
    endpoints: &[String],
    method: &str,
    payload: Value,
) -> mlua::Result<(LuaValue, Option<String>)> {
    match call(endpoints, method, payload) {
        Ok(result) => Ok((lua.to_value(&result)?, None)),
        Err(error) => Ok((LuaValue::Nil, Some(error))),
    }
}

fn call_one(endpoint: &str, method: &str, payload: &Value) -> Result<Value, String> {
    if let Some(path) = endpoint.strip_prefix("unix://") {
        let stream = UnixStream::connect(path)
            .map_err(|error| format!("cannot connect: {error}"))?;
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        return talk(stream, "ws://localhost/api/control", method, payload);
    }
    let (tls, rest) = if let Some(rest) = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("wss://"))
    {
        (true, rest)
    } else if let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("ws://"))
        .or_else(|| endpoint.strip_prefix("tcp://"))
    {
        (false, rest)
    } else {
        (false, endpoint)
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) if !path.is_empty() => (authority, format!("/{path}")),
        _ => (rest, "/api/control".to_string()),
    };
    let address = std::net::ToSocketAddrs::to_socket_addrs(&authority)
        .map_err(|error| format!("cannot resolve: {error}"))?
        .next()
        .ok_or_else(|| "the address did not resolve".to_string())?;
    let tcp = TcpStream::connect_timeout(&address, TIMEOUT)
        .map_err(|error| format!("cannot connect: {error}"))?;
    let _ = tcp.set_read_timeout(Some(TIMEOUT));
    let _ = tcp.set_write_timeout(Some(TIMEOUT));
    let _ = tcp.set_nodelay(true);
    if tls {
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or(authority)
            .split(':')
            .next()
            .unwrap_or(authority);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let connection = rustls::ClientConnection::new(tls_config()?, server_name)
            .map_err(|error| format!("TLS setup failed: {error}"))?;
        let stream = rustls::StreamOwned::new(connection, tcp);
        talk(stream, &format!("wss://{authority}{path}"), method, payload)
    } else {
        talk(tcp, &format!("ws://{authority}{path}"), method, payload)
    }
}

fn talk<S: Read + Write>(
    stream: S,
    uri: &str,
    method: &str,
    payload: &Value,
) -> Result<Value, String> {
    let request = ClientRequestBuilder::new(
        uri.parse()
            .map_err(|_| format!("invalid endpoint URI {uri}"))?,
    )
    .with_sub_protocol(rux_proto::PROTOCOL);
    let (mut socket, _) = tungstenite::client::client(request, stream)
        .map_err(|error| format!("WebSocket handshake failed: {error}"))?;
    let hello = json!({
        "type": "hello",
        "client": { "kind": "cli", "name": "rux", "version": env!("CARGO_PKG_VERSION") },
        "api_revision": 7,
    });
    socket
        .write(Message::Text(hello.to_string().into()))
        .and_then(|_| socket.flush())
        .map_err(|error| format!("sending hello: {error}"))?;
    let request = json!({
        "type": "request",
        "id": "1",
        "method": method,
        "payload": payload,
    });
    let mut welcomed = false;
    loop {
        let message = socket
            .read()
            .map_err(|error| format!("reading from the host: {error}"))?;
        match message {
            Message::Text(text) => {
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                match value.get("type").and_then(Value::as_str) {
                    Some("welcome") if !welcomed => {
                        welcomed = true;
                        socket
                            .write(Message::Text(request.to_string().into()))
                            .and_then(|_| socket.flush())
                            .map_err(|error| format!("sending the request: {error}"))?;
                    }
                    Some("response")
                        if value.get("id").and_then(Value::as_str) == Some("1") =>
                    {
                        if let Some(error) = value.get("error") {
                            let message = error
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("the host returned an error");
                            return Err(message.to_string());
                        }
                        return Ok(value.get("payload").cloned().unwrap_or(Value::Null));
                    }
                    _ => {}
                }
            }
            Message::Ping(data) => {
                let _ = socket.write(Message::Pong(data));
                let _ = socket.flush();
            }
            Message::Close(_) => return Err("the host closed the connection".into()),
            _ => {}
        }
    }
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let bundle = std::env::var_os("SSL_CERT_FILE")
                .map(std::path::PathBuf::from)
                .filter(|path| path.is_file())
                .or_else(|| {
                    [
                        "/etc/ssl/certs/ca-certificates.crt",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                    ]
                    .iter()
                    .map(std::path::PathBuf::from)
                    .find(|path| path.is_file())
                })
                .ok_or_else(|| "no system CA bundle found for TLS endpoints".to_string())?;
            let pem = std::fs::read(&bundle)
                .map_err(|error| format!("reading {}: {error}", bundle.display()))?;
            let mut added = 0;
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert.map_err(|error| format!("parsing the CA bundle: {error}"))?;
                roots
                    .add(cert)
                    .map_err(|error| format!("adding a CA certificate: {error}"))?;
                added += 1;
            }
            if added == 0 {
                return Err("the CA bundle held no certificates".into());
            }
            Ok(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        })
        .clone()
}
