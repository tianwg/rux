//! HTTP + WebSocket transport.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Extension, Request, State as AxumState};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use rux_proto::{
    ClientInfo, DATA_PROTOCOL, PROTOCOL, Response as ApiResponse, ServerMessage, Welcome,
};
use serde_json::{Value, json};

use crate::api;
use crate::state::State;
use crate::tailscale::{ServeHeaders, TailnetGate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    Local,
    Remote,
    Tailnet,
    TailnetServe,
}

#[derive(Clone)]
struct AppState {
    server: Arc<State>,
    ingress: Ingress,
    allow_anonymous: bool,
    remote_token: Option<Arc<str>>,
    tailnet: Option<Arc<TailnetGate>>,
}

#[derive(Clone)]
struct TailnetPrincipal(Value);

pub fn router(
    state: Arc<State>,
    ingress: Ingress,
    allow_anonymous: bool,
    remote_token: Option<Arc<str>>,
    tailnet: Option<Arc<TailnetGate>>,
) -> Router {
    let app = AppState {
        server: state,
        ingress,
        allow_anonymous,
        remote_token,
        tailnet,
    };
    let mut router = Router::new()
        .route("/api/help", get(help))
        .route("/api/control", get(control_upgrade))
        .route("/api/data", get(data_upgrade))
        .route("/llms.txt", get(llms))
        .route("/llms.html", get(llms_html));
    if ingress == Ingress::Tailnet {
        router = router.route_layer(middleware::from_fn_with_state(
            app.clone(),
            require_tailnet_peer,
        ));
    } else if ingress == Ingress::TailnetServe {
        router = router.route_layer(middleware::from_fn_with_state(
            app.clone(),
            require_serve_peer,
        ));
    }
    router.with_state(app)
}

async fn help(AxumState(app): AxumState<AppState>) -> Json<Value> {
    Json(app.server.help.clone())
}

async fn llms_html(AxumState(app): AxumState<AppState>) -> axum::response::Html<String> {
    axum::response::Html(render_llms_html(&app.server.help))
}

fn render_llms_html(help: &Value) -> String {
    let mut body = String::from(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>rux server</title></head><body><h1>rux server</h1><ul>",
    );
    if let Some(methods) = help.get("methods").and_then(|value| value.as_array()) {
        for method in methods {
            let name = method
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let desc = method
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            body.push_str(&format!(
                "<li><code>{}</code>: {}</li>",
                html_escape(name),
                html_escape(desc)
            ));
        }
    }
    body.push_str("</ul></body></html>");
    body
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn llms(AxumState(app): AxumState<AppState>) -> String {
    let mut out = String::from("# rux server\n\n");
    if let Some(methods) = app.server.help.get("methods").and_then(|x| x.as_array()) {
        for m in methods {
            let name = m.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let desc = m.get("description").and_then(|x| x.as_str()).unwrap_or("");
            out.push_str(&format!("- `{name}`: {desc}\n"));
        }
    }
    out
}

async fn control_upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    peer: Option<Extension<TailnetPrincipal>>,
    AxumState(app): AxumState<AppState>,
) -> AxumResponse {
    let (local, principal) = match admission(&app, &headers, peer.as_ref().map(|ext| &ext.0)) {
        Ok(admission) => admission,
        Err((status, message)) => return (status, message).into_response(),
    };
    let state = app.server;
    ws.protocols([PROTOCOL])
        .on_upgrade(move |socket| control_loop(socket, state, local, principal))
}

async fn data_upgrade(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    peer: Option<Extension<TailnetPrincipal>>,
    AxumState(app): AxumState<AppState>,
) -> AxumResponse {
    if let Err((status, message)) = admission(&app, &headers, peer.as_ref().map(|ext| &ext.0)) {
        return (status, message).into_response();
    }
    let state = app.server;
    ws.protocols([DATA_PROTOCOL])
        .on_upgrade(move |socket| data_loop(socket, state))
}

async fn require_tailnet_peer(
    AxumState(app): AxumState<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> AxumResponse {
    let Some(gate) = app.tailnet.as_ref() else {
        return (StatusCode::FORBIDDEN, "tailnet listener is not configured").into_response();
    };
    match gate.authorize_tcp(addr).await {
        Ok(principal) => {
            request.extensions_mut().insert(TailnetPrincipal(principal));
            next.run(request).await
        }
        Err(err) => {
            tracing::warn!(%addr, %err, "rejected tailnet connection");
            (StatusCode::FORBIDDEN, err).into_response()
        }
    }
}

async fn require_serve_peer(
    AxumState(app): AxumState<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> AxumResponse {
    let Some(gate) = app.tailnet.as_ref() else {
        return (StatusCode::FORBIDDEN, "tailnet listener is not configured").into_response();
    };
    let identity = ServeHeaders {
        login: header_str(&headers, "tailscale-user-login"),
        display_name: header_str(&headers, "tailscale-user-name"),
        forwarded_for: header_str(&headers, "x-forwarded-for"),
        funnel: headers.get("tailscale-funnel-request").is_some(),
    };
    match gate.authorize_serve(&identity).await {
        Ok(principal) => {
            request.extensions_mut().insert(TailnetPrincipal(principal));
            next.run(request).await
        }
        Err(err) => {
            tracing::warn!(%err, "rejected tailnet-serve connection");
            (StatusCode::FORBIDDEN, err).into_response()
        }
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn admission(
    app: &AppState,
    headers: &HeaderMap,
    peer: Option<&TailnetPrincipal>,
) -> Result<(bool, Value), (StatusCode, String)> {
    if let Some(principal) = tsnet_principal(app, headers) {
        return Ok((false, principal));
    }
    match app.ingress {
        Ingress::Local => Ok((true, app.server.principal())),
        Ingress::Remote => {
            if remote_authorized(app, headers) {
                Ok((
                    false,
                    json!({
                        "kind": "anonymous",
                        "transport": "tcp",
                        "display": "anonymous",
                    }),
                ))
            } else if app.remote_token.is_some() {
                Err((
                    StatusCode::UNAUTHORIZED,
                    "remote control access is not authorized".to_string(),
                ))
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    "remote control access is not authorized".to_string(),
                ))
            }
        }
        Ingress::Tailnet | Ingress::TailnetServe => match peer {
            Some(peer) => Ok((false, peer.0.clone())),
            None => Err((
                StatusCode::FORBIDDEN,
                "tailnet peer is not authorized".to_string(),
            )),
        },
    }
}

fn tsnet_principal(app: &AppState, headers: &HeaderMap) -> Option<Value> {
    let token = app.server.tsnet_token.lock().unwrap().clone()?;
    crate::tsnet::principal_from_headers(
        &token,
        header_str(headers, "x-rux-tsnet-token").as_deref(),
        header_str(headers, "x-rux-tsnet-user").as_deref(),
        header_str(headers, "x-rux-tsnet-login").as_deref(),
        header_str(headers, "x-rux-tsnet-node").as_deref(),
        header_str(headers, "x-rux-tsnet-tags").as_deref(),
        header_str(headers, "x-rux-tsnet-remote").as_deref(),
    )
}

fn remote_authorized(app: &AppState, headers: &HeaderMap) -> bool {
    app.allow_anonymous
        || app.remote_token.as_ref().is_some_and(|token| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .is_some_and(|value| constant_time_eq(value.as_bytes(), token.as_bytes()))
        })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn control_loop(socket: WebSocket, state: Arc<State>, local: bool, principal: Value) {
    let (mut sink, mut stream) = socket.split();

    let first = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next()).await;
    let hello = match first {
        Ok(Some(Ok(msg))) => parse_text(&msg),
        _ => {
            let _ = sink.close().await;
            return;
        }
    };
    let hello = match hello {
        Some(v) if v.get("type").and_then(|x| x.as_str()) == Some("hello") => v,
        _ => {
            let _ = sink.close().await;
            return;
        }
    };
    let mut info: ClientInfo =
        serde_json::from_value(hello.get("client").cloned().unwrap_or_else(|| json!({})))
            .unwrap_or_default();
    sanitize_client_info(&mut info);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
    let (client_id, seq, send_lock) = state.register_client(info, tx.clone(), principal);

    // Writer task: serializes every server message.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&msg) else {
                continue;
            };
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let _ = tx.send(ServerMessage::Welcome(Welcome::new(
        client_id.clone(),
        uuid::Uuid::now_v7().to_string(),
    )));

    while let Some(Ok(msg)) = stream.next().await {
        let Some(v) = parse_text(&msg) else {
            continue;
        };
        if v.get("type").and_then(|x| x.as_str()) != Some("request") {
            continue;
        }
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let method = v
            .get("method")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let payload = v.get("payload").cloned().unwrap_or(Value::Null);
        let result = api::dispatch(&state, &client_id, local, &method, payload).await;
        let _send_guard = send_lock.lock().unwrap();
        let current = seq.load(Ordering::SeqCst);
        let response = match result {
            Ok(payload) => ServerMessage::Response(ApiResponse::ok(id, current, payload)),
            Err(err) => ServerMessage::Response(ApiResponse::err(id, current, err)),
        };
        if tx.send(response).is_err() {
            break;
        }
    }

    state.remove_client(&client_id);
}

fn sanitize_client_info(info: &mut ClientInfo) {
    let Some(label) = info.label.take() else {
        return;
    };
    let label = label.trim();
    if label.is_empty() || label.chars().any(char::is_control) {
        return;
    }
    let mut end = label.len().min(64);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    if end > 0 {
        info.label = Some(label[..end].to_string());
    }
}

/// One data-stream frame carries at most this much terminal output.
const OUTPUT_FRAME_CAP: usize = 64 * 1024;

/// Merge a just-received output chunk with whatever else is already
/// queued for this stream, up to OUTPUT_FRAME_CAP. A flood arrives as
/// many small chunks, and one WebSocket frame per chunk spends most of
/// the stream's time on framing and socket writes (the official server
/// ships ~40 KB frames). Only already-queued bytes are merged, so
/// interactive traffic never waits for more. Each take is reported
/// through the subscription's accounting, so the terminal's
/// per-subscriber budgets track what is really still queued; a closed
/// queue simply ends the merge, and the caller handles the closure
/// (and the cut flag) on its next receive.
fn merge_queued_output(
    output: &mut crate::terminal::OutputSubscription,
    first: Vec<u8>,
) -> Vec<u8> {
    if first.len() >= OUTPUT_FRAME_CAP {
        return first;
    }
    let mut merged = first;
    while merged.len() < OUTPUT_FRAME_CAP {
        match output.rx.try_recv() {
            Ok(chunk) => {
                output.drained(chunk.len());
                merged.extend_from_slice(&chunk);
            }
            Err(_) => break,
        }
    }
    merged
}

/// Wake when the terminal's child exits (the reader thread fires
/// exit_notify the moment it records the code) or when the backstop
/// poll ticks, whichever comes first. The poll remains as a backstop
/// because Notify has no memory: an exit that lands between two loop
/// iterations is caught by the tick, never lost.
async fn exit_wake(term: &crate::terminal::Terminal, poll: &mut tokio::time::Interval) {
    tokio::select! {
        _ = poll.tick() => {}
        _ = term.exit_notify.notified() => {}
    }
}

/// How long a dropped data stream is kept for a resume, in
/// milliseconds; advertised in every WELCOME.
const RESUME_GRACE_MS: u32 = 30_000;
/// How much sent output a stream retains for resume replay. A
/// resume that counts fewer bytes than the retained window reaches
/// back to is refused, matching the official close table's "more
/// output piled up while the client was away than the server could
/// keep".
const STREAM_HISTORY_CAP: usize = 8 * 1024 * 1024;

fn stream_key(client_id: &str, block_id: &str, data_ref_id: &str) -> String {
    format!("{client_id}\u{1f}{block_id}\u{1f}{data_ref_id}")
}

/// Note bytes about to go on the wire in the stream's replay
/// history, evicting the oldest frames past the cap.
fn record_frame(
    history: &mut std::collections::VecDeque<Vec<u8>>,
    history_bytes: &mut usize,
    history_start: &mut u64,
    sent_total: &mut u64,
    frame: &[u8],
) {
    *sent_total += frame.len() as u64;
    *history_bytes += frame.len();
    history.push_back(frame.to_vec());
    while *history_bytes > STREAM_HISTORY_CAP && history.len() > 1 {
        let front = history.pop_front().unwrap();
        *history_bytes -= front.len();
        *history_start += front.len() as u64;
    }
}

/// The stream bytes in [count, sent_total) as wire frames: the
/// retained frames with the already-received prefix of the first
/// one cut. Frame boundaries carry no meaning, so replaying the
/// retained frames (minus the prefix) reproduces the byte stream.
fn replay_frames(
    history: &std::collections::VecDeque<Vec<u8>>,
    history_start: u64,
    count: u64,
) -> Vec<Vec<u8>> {
    let mut skip = (count - history_start) as usize;
    let mut out = Vec::new();
    for frame in history {
        if skip >= frame.len() {
            skip -= frame.len();
            continue;
        }
        out.push(frame[skip..].to_vec());
        skip = 0;
    }
    out
}

/// Drop parked streams whose grace has lapsed, unsubscribing them.
fn sweep_parked_streams(state: &Arc<State>) {
    let expired: Vec<crate::state::ParkedStream> = {
        let mut parked = state.parked_streams.lock().unwrap();
        let keys: Vec<String> = parked
            .iter()
            .filter(|(_, stream)| {
                stream.parked_at.elapsed()
                    >= std::time::Duration::from_millis(RESUME_GRACE_MS as u64)
            })
            .map(|(key, _)| key.clone())
            .collect();
        keys.iter()
            .filter_map(|key| parked.remove(key))
            .collect()
    };
    for stream in expired {
        stream.term.unsubscribe_output(stream.subscription.id);
    }
}

/// End any parked stream for a data source (a fresh HELLO starts
/// over, per the protocol document).
fn end_parked_for_key(state: &Arc<State>, key: &str) {
    let streams: Vec<crate::state::ParkedStream> = {
        let mut parked = state.parked_streams.lock().unwrap();
        let keys: Vec<String> = parked
            .iter()
            .filter(|(_, stream)| stream.key == key)
            .map(|(token, _)| token.clone())
            .collect();
        keys.iter()
            .filter_map(|token| parked.remove(token))
            .collect()
    };
    for stream in streams {
        stream.term.unsubscribe_output(stream.subscription.id);
    }
}

/// What one connection's run of a stream carries, and what parking
/// hands back: the output subscription and event receiver (both
/// survive the connection), and the replay accounting.
struct StreamRun {
    output: crate::terminal::OutputSubscription,
    events: tokio::sync::broadcast::Receiver<Value>,
    history: std::collections::VecDeque<Vec<u8>>,
    history_bytes: usize,
    history_start: u64,
    sent_total: u64,
    /// True when the stream should be parked for a resume rather
    /// than ended (a drop, a failure mid-send, a supersede). The
    /// paths that end a stream - a normal client close, the cut for
    /// falling behind, a completed child-exit close - clear it.
    park: bool,
}

/// Run one connection's share of a stream until it ends or parks.
/// `record_frame` is applied to every byte put on the wire, so the
/// replay history always covers what a later RESUME may ask for.
async fn stream_loop(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    term: &Arc<crate::terminal::Terminal>,
    owner: &Option<String>,
    nonce: u64,
    supersede: &Arc<tokio::sync::Notify>,
    mut run: StreamRun,
) -> StreamRun {
    let mut child_exit_poll = tokio::time::interval(std::time::Duration::from_millis(100));
    let mut process_poll = tokio::time::interval(std::time::Duration::from_millis(500));
    let mut park = true;
    'data: loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Close(frame))) => {
                    // A normal close ends the stream; any other
                    // close (or a drop, below) leaves it parked. An
                    // empty close frame carries no code but is a
                    // deliberate close all the same, so it ends the
                    // stream too.
                    park = frame.as_ref().is_some_and(|f| f.code != 1000);
                    break;
                }
                None | Some(Err(_)) => break,
                Some(Ok(Message::Ping(bytes))) => {
                    if sink.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                // The Rex data stream is server-to-client; post-WELCOME
                // client messages are deliberately ignored.
                Some(Ok(_)) => {}
            },
            chunk = run.output.rx.recv() => match chunk {
                Some(chunk) => {
                    run.output.drained(chunk.len());
                    let frame = merge_queued_output(&mut run.output, chunk);
                    record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &frame);
                    if sink.send(Message::Binary(frame.into())).await.is_err() { break; }
                }
                None => {
                    // The queue closed. Either the terminal cut this
                    // stream for falling past its hard budget - close
                    // 1013 so the client resyncs from a snapshot - or
                    // the terminal itself is gone. Either way the
                    // stream is over, not parked.
                    if run.output.cut.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = sink.send(Message::Close(Some(CloseFrame {
                            code: 1013,
                            reason: "data reconnect required".into(),
                        }))).await;
                    }
                    park = false;
                    break;
                }
            },
            event = run.events.recv() => match event {
                Ok(event) => {
                    if event.get("name").and_then(Value::as_str) == Some("resized") {
                        // Answer with the same resize APC the bootstrap
                        // sends: it tells the client the terminal's current
                        // size, and the client re-lays out (and reflows)
                        // its local copy. A raw snapshot frame here would
                        // be fed to the terminal as output bytes - garbage.
                        let message = term.resize_message(nonce, owner.as_deref());
                        record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &message);
                        if sink.send(Message::Binary(message.into())).await.is_err() { break; }
                    } else if let Some(message) = terminal_stream_event(nonce, event) {
                        record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &message);
                        if sink.send(Message::Binary(message.into())).await.is_err() { break; }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    park = false;
                    break;
                }
            },
            _ = supersede.notified() => {
                // A RESUME arrived on a new connection for this
                // stream: park it so the resume can take over.
                break;
            }
            _ = exit_wake(term, &mut child_exit_poll) => {
                let exit_code = { *term.exit_code.lock().unwrap() };
                if let Some(code) = exit_code {
                    // The child is gone, so this terminal stream is finished.
                    // The reader thread published every output chunk before
                    // recording the exit code, so anything still queued here
                    // is final output: flush queued output and events first,
                    // then deliver `child_exited` and close the socket.
                    // Keeping the socket open leaves GUI clients rendering a
                    // dead terminal forever (observed with Rex Beta: it
                    // badges the pane "Exited" but only tears the pane down
                    // when the stream ends). If a send fails the stream
                    // parks instead, so a resume can still deliver the
                    // tail and the exit notice. The block itself stays in
                    // the session, which `rex new --keep-open` and a later
                    // `rex capture` rely on.
                    'drain: loop {
                        let mut drained_any = false;
                        while let Ok(chunk) = run.output.rx.try_recv() {
                            drained_any = true;
                            run.output.drained(chunk.len());
                            // Merge the backlog into full frames too:
                            // what is left at exit is exactly the flood
                            // case.
                            let frame = merge_queued_output(&mut run.output, chunk);
                            record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &frame);
                            if sink.send(Message::Binary(frame.into())).await.is_err() { break 'data; }
                        }
                        while let Ok(event) = run.events.try_recv() {
                            drained_any = true;
                            if let Some(message) = terminal_stream_event(nonce, event) {
                                record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &message);
                                if sink.send(Message::Binary(message.into())).await.is_err() { break 'data; }
                            }
                        }
                        if !drained_any { break 'drain; }
                    }
                    let mut payload = json!({ "type": "child_exited", "exit_code": code });
                    if code != 0 { payload["error"] = json!(format!("exit status {code}")); }
                    let message = terminal_stream_apc(nonce, &payload);
                    record_frame(&mut run.history, &mut run.history_bytes, &mut run.history_start, &mut run.sent_total, &message);
                    if sink.send(Message::Binary(message.into())).await.is_err() { break; }
                    if sink
                        .send(Message::Close(Some(CloseFrame {
                            code: 1000,
                            reason: "child exited".into(),
                        })))
                        .await
                        .is_ok()
                    {
                        park = false;
                    }
                    break;
                }
            }
            _ = process_poll.tick() => {
                let process_term = term.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    process_term.emit_process_changed(false)
                }).await;
            }
        }
    }
    run.park = park;
    run
}

/// The shared tail of a stream run: unregister as live, then either
/// park the stream for a resume or end it for good.
#[allow(clippy::too_many_arguments)]
fn finish_stream(
    state: &Arc<State>,
    key: &str,
    token_key: &str,
    session_id: &str,
    block_id: &str,
    subprotocol: Option<String>,
    term: &Arc<crate::terminal::Terminal>,
    owner: Option<String>,
    nonce: u64,
    run: StreamRun,
) {
    {
        let mut live = state.live_streams.lock().unwrap();
        if live.get(key).map(|entry| &entry.token) == Some(&token_key.to_string()) {
            live.remove(key);
        }
    }
    if run.park {
        let parked = crate::state::ParkedStream {
            key: key.to_string(),
            session_id: session_id.to_string(),
            block_id: block_id.to_string(),
            subprotocol,
            term: term.clone(),
            owner,
            nonce,
            subscription: run.output,
            events: run.events,
            history: run.history,
            history_start: run.history_start,
            sent_total: run.sent_total,
            parked_at: std::time::Instant::now(),
        };
        state
            .parked_streams
            .lock()
            .unwrap()
            .insert(token_key.to_string(), parked);
    } else {
        term.unsubscribe_output(run.output.id);
    }
}

fn build_welcome(token: &[u8; 16], nonce: u64) -> Vec<u8> {
    let mut welcome = Vec::with_capacity(32);
    welcome.push(0x81);
    welcome.extend_from_slice(token);
    welcome.extend_from_slice(&[0; 3]);
    welcome.extend_from_slice(&RESUME_GRACE_MS.to_le_bytes());
    welcome.extend_from_slice(&nonce.to_le_bytes());
    welcome
}

async fn data_loop(socket: WebSocket, state: Arc<State>) {
    let negotiated_protocol = socket
        .protocol()
        .and_then(|protocol| protocol.to_str().ok())
        .map(str::to_string);
    let (mut sink, mut stream) = socket.split();
    sweep_parked_streams(&state);
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next()).await;
    let hello = match first {
        Ok(Some(Ok(Message::Binary(bytes)))) => bytes,
        _ => {
            reject_data_handshake(&mut sink, 0x05).await;
            return;
        }
    };
    match hello.first() {
        Some(0x01) if hello.len() >= 17 => {
            data_hello(&mut sink, &mut stream, &state, negotiated_protocol, &hello).await;
        }
        Some(0x02) if hello.len() >= 25 => {
            data_resume(&mut sink, &mut stream, &state, negotiated_protocol, &hello).await;
        }
        _ => {
            reject_data_handshake(&mut sink, 0x05).await;
        }
    }
}

/// The HELLO handshake: redeem a one-time ticket from data.connect
/// and start a fresh stream. Wire layout and REJECT reasons are in
/// spec/notes/data-resume.md.
async fn data_hello(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &Arc<State>,
    negotiated_protocol: Option<String>,
    hello: &[u8],
) {
    // The wire token is base64url only on the control API.
    let ticket = URL_SAFE_NO_PAD.encode(&hello[1..17]);
    let ticket_opt = {
        let mut tickets = state.tickets.lock().unwrap();
        tickets.remove(&ticket)
    };
    let ticket = match ticket_opt {
        Some(t) if t.expires_at > std::time::Instant::now() => t,
        _ => {
            reject_data_handshake(sink, 0x01).await;
            return;
        }
    };
    if ticket
        .subprotocol
        .as_deref()
        .is_some_and(|required| negotiated_protocol.as_deref() != Some(required))
    {
        reject_data_handshake(sink, 0x07).await;
        return;
    }

    let source = {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|s| s.id == ticket.session_id)
            .and_then(|s| s.blocks.get(&ticket.block_id))
            .and_then(|block| {
                (ticket.data_ref_id == "terminal")
                    .then(|| {
                        block
                            .terminal
                            .clone()
                            .map(|term| (term, block.owner.clone()))
                    })
                    .flatten()
            })
    };
    let Some((term, owner)) = source else {
        reject_data_handshake(sink, 0x03).await;
        return;
    };

    let key = stream_key(&ticket.client_id, &ticket.block_id, &ticket.data_ref_id);
    // A fresh HELLO ends any stream still waiting for a resume on
    // this data source, and one client can hold only one live
    // stream per data source.
    end_parked_for_key(state, &key);
    if state.live_streams.lock().unwrap().contains_key(&key) {
        reject_data_handshake(sink, 0x02).await;
        return;
    }

    let token: [u8; 16] = uuid::Uuid::new_v4().into_bytes();
    let token_key = URL_SAFE_NO_PAD.encode(token);
    let nonce_bytes = uuid::Uuid::new_v4().into_bytes();
    let mut nonce_raw = [0u8; 8];
    nonce_raw.copy_from_slice(&nonce_bytes[..8]);
    let nonce = u64::from_le_bytes(nonce_raw).max(1);
    // Register before the WELCOME goes out, so a concurrent HELLO
    // for the same data source sees the live stream and is refused
    // rather than racing the registration.
    let supersede = Arc::new(tokio::sync::Notify::new());
    state.live_streams.lock().unwrap().insert(
        key.clone(),
        crate::state::LiveStream {
            token: token_key.clone(),
            supersede: supersede.clone(),
        },
    );
    if sink
        .send(Message::Binary(build_welcome(&token, nonce).into()))
        .await
        .is_err()
    {
        let mut live = state.live_streams.lock().unwrap();
        if live.get(&key).map(|entry| &entry.token) == Some(&token_key) {
            live.remove(&key);
        }
        return;
    }

    let (bootstrap, output, events) = term.data_bootstrap(nonce, owner.as_deref());
    let mut run = StreamRun {
        output,
        events,
        history: std::collections::VecDeque::new(),
        history_bytes: 0,
        history_start: 0,
        sent_total: 0,
        park: true,
    };
    let process_term = term.clone();
    let _ = tokio::task::spawn_blocking(move || process_term.emit_process_changed(true)).await;
    for chunk in bootstrap.chunks(64 * 1024) {
        let frame = chunk.to_vec();
        record_frame(
            &mut run.history,
            &mut run.history_bytes,
            &mut run.history_start,
            &mut run.sent_total,
            &frame,
        );
        if sink.send(Message::Binary(frame.into())).await.is_err() {
            {
                let mut live = state.live_streams.lock().unwrap();
                if live.get(&key).map(|entry| &entry.token) == Some(&token_key) {
                    live.remove(&key);
                }
            }
            term.unsubscribe_output(run.output.id);
            return;
        }
    }

    let run = stream_loop(sink, stream, &term, &owner, nonce, &supersede, run).await;
    finish_stream(
        state,
        &key,
        &token_key,
        &ticket.session_id,
        &ticket.block_id,
        ticket.subprotocol.clone(),
        &term,
        owner,
        nonce,
        run,
    );
}

/// The RESUME handshake: redeem the reconnect token from the latest
/// WELCOME plus the exact number of stream bytes the client has
/// used, and continue the parked stream from the first byte it has
/// not received. No ticket and no control connection are involved.
async fn data_resume(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &Arc<State>,
    negotiated_protocol: Option<String>,
    hello: &[u8],
) {
    let token_key = URL_SAFE_NO_PAD.encode(&hello[1..17]);
    let count = u64::from_le_bytes(hello[17..25].try_into().unwrap());

    let mut entry = state.parked_streams.lock().unwrap().remove(&token_key);
    if entry.is_none() {
        // The stream may still be live on a connection the server
        // has not noticed dropping: ask it to park and hand over.
        let live_hit = {
            let live = state.live_streams.lock().unwrap();
            live.values()
                .find(|entry| entry.token == token_key)
                .map(|entry| entry.supersede.clone())
        };
        if let Some(supersede) = live_hit {
            supersede.notify_one();
            for _ in 0..80 {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                entry = state.parked_streams.lock().unwrap().remove(&token_key);
                if entry.is_some() {
                    break;
                }
            }
        }
    }
    let Some(entry) = entry else {
        reject_data_handshake(sink, 0x01).await;
        return;
    };

    if entry
        .subprotocol
        .as_deref()
        .is_some_and(|required| negotiated_protocol.as_deref() != Some(required))
    {
        // Not this stream's protocol; leave it parked.
        state
            .parked_streams
            .lock()
            .unwrap()
            .insert(token_key, entry);
        reject_data_handshake(sink, 0x07).await;
        return;
    }

    // The block the stream belongs to must still be there.
    let block_alive = {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|s| s.id == entry.session_id)
            .and_then(|s| s.blocks.get(&entry.block_id))
            .is_some_and(|block| block.terminal.is_some())
    };
    if !block_alive {
        entry.term.unsubscribe_output(entry.subscription.id);
        reject_data_handshake(sink, 0x03).await;
        return;
    }
    if entry.subscription.cut.load(std::sync::atomic::Ordering::SeqCst) {
        // Output overflowed the hard budget while the client was
        // away; the stream is over.
        entry.term.unsubscribe_output(entry.subscription.id);
        reject_data_handshake(sink, 0x01).await;
        return;
    }
    if count > entry.sent_total {
        // Counted more than the server ever sent: refuse and end
        // the stream, per the protocol document.
        entry.term.unsubscribe_output(entry.subscription.id);
        reject_data_handshake(sink, 0x05).await;
        return;
    }
    if count < entry.history_start {
        // The bytes it missed have already fallen out of the
        // retained window: refuse and end the stream.
        entry.term.unsubscribe_output(entry.subscription.id);
        reject_data_handshake(sink, 0x03).await;
        return;
    }

    let crate::state::ParkedStream {
        key,
        session_id,
        block_id,
        subprotocol,
        term,
        owner,
        nonce,
        subscription,
        events,
        history,
        history_start,
        sent_total,
        parked_at: _,
    } = entry;
    let history_bytes: usize = history.iter().map(Vec::len).sum();
    let mut run = StreamRun {
        output: subscription,
        events,
        history,
        history_bytes,
        history_start,
        sent_total,
        park: true,
    };

    // Rotate the token: the WELCOME carries a fresh one and the old
    // token stops working, with the channel nonce unchanged.
    let new_token: [u8; 16] = uuid::Uuid::new_v4().into_bytes();
    let new_token_key = URL_SAFE_NO_PAD.encode(new_token);
    let supersede = Arc::new(tokio::sync::Notify::new());
    let repark = |state: &Arc<State>, run: StreamRun| {
        finish_stream(
            state,
            &key,
            &new_token_key,
            &session_id,
            &block_id,
            subprotocol.clone(),
            &term,
            owner.clone(),
            nonce,
            run,
        );
    };
    if sink
        .send(Message::Binary(build_welcome(&new_token, nonce).into()))
        .await
        .is_err()
    {
        repark(state, run);
        return;
    }
    for frame in replay_frames(&run.history, run.history_start, count) {
        if sink.send(Message::Binary(frame.into())).await.is_err() {
            repark(state, run);
            return;
        }
    }
    // One resize APC at the current size, in case a resize event
    // fell out of the event ring while the stream was parked.
    let message = term.resize_message(nonce, owner.as_deref());
    record_frame(
        &mut run.history,
        &mut run.history_bytes,
        &mut run.history_start,
        &mut run.sent_total,
        &message,
    );
    if sink.send(Message::Binary(message.into())).await.is_err() {
        repark(state, run);
        return;
    }
    state.live_streams.lock().unwrap().insert(
        key.clone(),
        crate::state::LiveStream {
            token: new_token_key.clone(),
            supersede: supersede.clone(),
        },
    );

    let run = stream_loop(sink, stream, &term, &owner, nonce, &supersede, run).await;
    finish_stream(
        state,
        &key,
        &new_token_key,
        &session_id,
        &block_id,
        subprotocol,
        &term,
        owner,
        nonce,
        run,
    );
}

async fn reject_data_handshake(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    reason: u8,
) {
    let _ = sink.send(Message::Binary(vec![0x82, reason].into())).await;
    let _ = sink
        .send(Message::Close(Some(CloseFrame {
            code: 1002,
            reason: "data handshake rejected".into(),
        })))
        .await;
}

fn terminal_stream_event(nonce: u64, event: Value) -> Option<Vec<u8>> {
    let name = event.get("name").and_then(Value::as_str)?;
    let body = event.get("payload").cloned().unwrap_or(Value::Null);
    let mut payload = json!({ "type": name });
    if let (Some(target), Some(source)) = (payload.as_object_mut(), body.as_object()) {
        target.extend(source.clone());
    } else if !body.is_null() {
        payload["payload"] = body;
    }
    Some(terminal_stream_apc(nonce, &payload))
}

fn terminal_stream_apc(nonce: u64, payload: &Value) -> Vec<u8> {
    let json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
    format!("\x1b_rex1;{nonce};{json}\x1b\\").into_bytes()
}

fn parse_text(msg: &Message) -> Option<Value> {
    match msg {
        Message::Text(t) => serde_json::from_str(t).ok(),
        Message::Binary(b) => serde_json::from_slice(b).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale::{TailnetGate, TailnetPolicy};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn merge_queued_output_concatenates_and_accounts() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let queued = std::sync::Arc::new(AtomicUsize::new(0));
        let mut sub = crate::terminal::OutputSubscription {
            id: 0,
            rx,
            queued_bytes: queued.clone(),
            cut: std::sync::Arc::new(AtomicBool::new(false)),
        };
        // Simulate the terminal publishing three chunks.
        for chunk in [b"one ".as_slice(), b"two ".as_slice(), b"three".as_slice()] {
            queued.fetch_add(chunk.len(), Ordering::SeqCst);
            tx.try_send(chunk.to_vec()).unwrap();
        }
        let first = sub.rx.try_recv().unwrap();
        sub.drained(first.len());
        let frame = merge_queued_output(&mut sub, first);
        assert_eq!(frame, b"one two three");
        // Every queued byte was accounted back out by the merge.
        assert_eq!(queued.load(Ordering::SeqCst), 0);

        // A chunk already at the cap is sent as-is; nothing merges in.
        tx.try_send(b"late".to_vec()).unwrap();
        let big = vec![7u8; OUTPUT_FRAME_CAP];
        let frame = merge_queued_output(&mut sub, big.clone());
        assert_eq!(frame, big);
    }

    #[test]
    fn replay_frames_cuts_the_received_prefix() {
        let history: std::collections::VecDeque<Vec<u8>> = [
            b"hello ".to_vec(),
            b"world".to_vec(),
            b"!".to_vec(),
        ]
        .into_iter()
        .collect();
        // Received everything: nothing to replay.
        assert!(replay_frames(&history, 0, 12).is_empty());
        // Received nothing: the whole history, unaltered.
        assert_eq!(
            replay_frames(&history, 0, 0),
            vec![b"hello ".to_vec(), b"world".to_vec(), b"!".to_vec()]
        );
        // Received a prefix that ends mid-frame: the first replayed
        // frame is the remainder of the frame it cut into.
        assert_eq!(
            replay_frames(&history, 0, 8),
            vec![b"rld".to_vec(), b"!".to_vec()]
        );
        // The window can start mid-history (older frames evicted):
        // with "hello " gone, absolute offset 6 is the window start.
        let window: std::collections::VecDeque<Vec<u8>> =
            [b"world".to_vec(), b"!".to_vec()].into_iter().collect();
        assert_eq!(
            replay_frames(&window, 6, 8),
            vec![b"rld".to_vec(), b"!".to_vec()]
        );
    }

    #[test]
    fn record_frame_evicts_the_oldest_bytes_past_the_cap() {
        let mut history = std::collections::VecDeque::new();
        let mut bytes = 0usize;
        let mut start = 0u64;
        let mut total = 0u64;
        let frame = vec![7u8; 1024];
        // Fill well past the cap with 1 KiB frames.
        for _ in 0..(STREAM_HISTORY_CAP / 1024 + 100) {
            record_frame(&mut history, &mut bytes, &mut start, &mut total, &frame);
        }
        assert_eq!(total, (STREAM_HISTORY_CAP + 100 * 1024) as u64);
        assert!(bytes <= STREAM_HISTORY_CAP);
        // Everything evicted is accounted in history_start, and the
        // retained window is contiguous with the total.
        assert_eq!(start + bytes as u64, total);
        // A single frame larger than the cap is still retained whole
        // (it can never be split); the window then starts at its end.
        let big = vec![9u8; STREAM_HISTORY_CAP + 1];
        record_frame(&mut history, &mut bytes, &mut start, &mut total, &big);
        assert_eq!(history.len(), 1);
        assert_eq!(start + bytes as u64, total);
    }

    #[test]
    fn llms_html_escapes_method_descriptions() {
        let html = render_llms_html(&json!({
            "methods": [{ "name": "server.version", "description": "version <build>" }]
        }));
        assert!(html.contains("<code>server.version</code>"));
        assert!(html.contains("version &lt;build&gt;"));
        assert!(!html.contains("version <build>"));
    }

    #[tokio::test]
    async fn tailnet_listener_rejects_a_non_tailscale_peer() {
        let dir = std::env::temp_dir().join(format!("rux-tailnet-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = Arc::new(State::new(
            json!({}),
            json!({}),
            String::new(),
            Some(dir.join("state")),
            dir.join("init.lua"),
        ));
        let gate = Arc::new(TailnetGate::new(
            PathBuf::from("/no/such/tailscaled.sock"),
            TailnetPolicy {
                allow_identified: true,
                http_port: Some(7297),
                https_serve: false,
            },
        ));
        let app = router(state, Ingress::Tailnet, false, None, Some(gate));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        let body = tokio::time::timeout(Duration::from_secs(3), async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    b"GET /api/help HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut body = Vec::new();
            let _ = stream.read_to_end(&mut body).await;
            String::from_utf8_lossy(&body).into_owned()
        })
        .await
        .expect("timed out waiting for the tailnet rejection");
        assert!(
            body.contains("403") && body.contains("not from a Tailscale"),
            "unexpected response: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
