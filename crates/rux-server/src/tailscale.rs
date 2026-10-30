//! Host Tailscale integration.
//!
//! Rux does not embed a userspace Tailscale stack. It uses the machine's
//! `tailscaled`:
//!
//! * `tailnet://:PORT` binds only addresses in the Tailscale ranges
//!   (100.64.0.0/10 and fd7a:115c:a1e0::/48) and identifies the TCP peer with
//!   the LocalAPI `whois` call.
//! * `tailnet-serve://SOCKET` accepts Tailscale Serve's reverse proxy. Serve
//!   keeps HTTPS on the tailnet and forwards identity in headers plus
//!   `X-Forwarded-For`. Public Funnel requests are refused.
//!
//! This matches the listeners documented for the real `rex` server
//! (`tailnet://` and `tailnet-serve://`). The stock client connects with
//! `-S http://<magicdns>:PORT` or, once Serve is up, `-S https://<magicdns>`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const DEFAULT_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";
const ALT_SOCKET: &str = "/run/tailscale/tailscaled.sock";
const STATUS_TTL: Duration = Duration::from_secs(5);
const WHOIS_OK_TTL: Duration = Duration::from_secs(30);
const WHOIS_ERR_TTL: Duration = Duration::from_secs(2);
const LOCALAPI_LIMIT: usize = 8 * 1024 * 1024;
const LOCALAPI_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct TailnetPolicy {
    pub allow_identified: bool,
    pub http_port: Option<u16>,
    pub https_serve: bool,
}

pub struct TailnetGate {
    socket: PathBuf,
    policy: TailnetPolicy,
    status_cache: Mutex<Option<(Instant, ParsedStatus)>>,
    whois_cache: Mutex<HashMap<IpAddr, (Instant, Result<PeerInfo, String>)>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedStatus {
    pub backend_state: String,
    pub dns_name: Option<String>,
    pub tailnet_name: Option<String>,
    pub login_name: Option<String>,
    pub user_id: Option<String>,
    pub tags: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub auth_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub user_id: Option<String>,
    pub login_name: Option<String>,
    pub display_name: Option<String>,
    pub node: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeHeaders {
    pub login: Option<String>,
    pub display_name: Option<String>,
    pub forwarded_for: Option<String>,
    pub funnel: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenSpec {
    Unix(PathBuf),
    Http(String),
    Https(String),
    Tailnet { host: Option<IpAddr>, port: u16 },
    TailnetServe(PathBuf),
}

impl TailnetGate {
    pub fn new(socket: PathBuf, policy: TailnetPolicy) -> Self {
        Self {
            socket,
            policy,
            status_cache: Mutex::new(None),
            whois_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> &TailnetPolicy {
        &self.policy
    }

    /// Whois only. The login server maps this identity through accounts.jsonc
    /// and does not apply the owner-only tailnet policy.
    pub async fn identify_tcp(&self, addr: SocketAddr) -> Result<PeerInfo, String> {
        let ip = normalize_ip(addr.ip());
        if !is_tailscale_ip(ip) {
            return Err("refusing a connection that is not from a Tailscale address".to_string());
        }
        self.whois(ip, Some(addr.port())).await
    }

    pub async fn authorize_tcp(&self, addr: SocketAddr) -> Result<Value, String> {
        let ip = normalize_ip(addr.ip());
        if !is_tailscale_ip(ip) {
            return Err("refusing a connection that is not from a Tailscale address".to_string());
        }
        let peer = self.whois(ip, Some(addr.port())).await?;
        let local = self.status().await?;
        authorize_peer(
            &self.policy,
            Some(&local),
            &peer,
            Some(&addr.to_string()),
            "tailnet",
        )
    }

    pub async fn authorize_serve(&self, headers: &ServeHeaders) -> Result<Value, String> {
        if headers.funnel {
            return Err("Tailscale Funnel is public; rux refuses Funnel connections".to_string());
        }
        if let Some(forwarded) = headers.forwarded_for.as_deref() {
            let ip = parse_forwarded_ip(forwarded).ok_or_else(|| {
                "Tailscale Serve forwarded an address that is not a Tailscale IP".to_string()
            })?;
            if !is_tailscale_ip(ip) {
                return Err(
                    "Tailscale Serve forwarded an address that is not a Tailscale IP".to_string(),
                );
            }
            let peer = self.whois(ip, None).await?;
            let local = self.status().await.ok();
            return authorize_peer(
                &self.policy,
                local.as_ref(),
                &peer,
                Some(forwarded),
                "tailnet-serve",
            );
        }
        let login = headers
            .login
            .as_deref()
            .map(decode_header_value)
            .transpose()?
            .filter(|value| !value.is_empty());
        let Some(login) = login else {
            return Err(
                "Tailscale Serve did not identify this peer (tagged nodes have no identity headers; use the tailnet port)"
                    .to_string(),
            );
        };
        let display_name = headers
            .display_name
            .as_deref()
            .map(decode_header_value)
            .transpose()?;
        let peer = PeerInfo {
            user_id: None,
            login_name: Some(login),
            display_name,
            node: None,
            tags: Vec::new(),
        };
        let local = self.status().await.ok();
        authorize_peer(&self.policy, local.as_ref(), &peer, None, "tailnet-serve")
    }

    pub async fn status(&self) -> Result<ParsedStatus, String> {
        if let Some(cached) = self.fresh_status() {
            return Ok(cached);
        }
        let socket = self.socket.clone();
        let value =
            tokio::task::spawn_blocking(move || localapi_get_json(&socket, "/localapi/v0/status"))
                .await
                .map_err(|err| format!("tailscaled status task failed: {err}"))??;
        let parsed = parse_status(&value)?;
        *self.status_cache.lock().expect("tailnet status cache") =
            Some((Instant::now(), parsed.clone()));
        Ok(parsed)
    }

    pub async fn discover_ips(&self) -> Result<Vec<IpAddr>, String> {
        let status = self.status().await?;
        if status.ips.is_empty() {
            return Err(
                "tailscaled has no Tailscale addresses yet; wait until `tailscale ip` prints one"
                    .to_string(),
            );
        }
        Ok(status.ips)
    }

    async fn whois(&self, ip: IpAddr, port: Option<u16>) -> Result<PeerInfo, String> {
        if let Some(cached) = self.fresh_whois(ip) {
            return cached;
        }
        let socket = self.socket.clone();
        let query = whois_query(ip, port);
        let fetched = tokio::task::spawn_blocking(move || localapi_get_json(&socket, &query))
            .await
            .map_err(|err| format!("tailscaled whois task failed: {err}"));
        let parsed = match fetched {
            Ok(Ok(value)) => parse_whois(&value).map_err(|err| err.to_string()),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(err),
        };
        if self.whois_cache.lock().expect("whois cache").len() > 256 {
            self.whois_cache.lock().expect("whois cache").clear();
        }
        self.whois_cache
            .lock()
            .expect("whois cache")
            .insert(ip, (Instant::now(), parsed.clone()));
        parsed
    }

    fn fresh_status(&self) -> Option<ParsedStatus> {
        let cache = self.status_cache.lock().expect("tailnet status cache");
        let (at, status) = cache.as_ref()?;
        (at.elapsed() < STATUS_TTL).then(|| status.clone())
    }

    fn fresh_whois(&self, ip: IpAddr) -> Option<Result<PeerInfo, String>> {
        let cache = self.whois_cache.lock().expect("whois cache");
        let (at, result) = cache.get(&ip)?;
        let ttl = if result.is_ok() {
            WHOIS_OK_TTL
        } else {
            WHOIS_ERR_TTL
        };
        (at.elapsed() < ttl).then(|| result.clone())
    }
}

pub fn default_socket_path() -> PathBuf {
    for candidate in socket_candidates() {
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(DEFAULT_SOCKET)
}

/// Host tailscaled LocalAPI sockets. Linux uses `/var/run/tailscale/tailscaled.sock`
/// (and `/run/tailscale/...`). Homebrew `tailscaled` on macOS uses
/// `/var/run/tailscaled.socket`. The Tailscale macOS app uses a socket inside
/// its group container.
pub fn socket_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(DEFAULT_SOCKET),
        PathBuf::from(ALT_SOCKET),
        PathBuf::from("/var/run/tailscaled.socket"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let group = PathBuf::from(home).join("Library/Group Containers");
        if let Ok(entries) = std::fs::read_dir(&group) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains("io.tailscale.ipn.") {
                    candidates.push(entry.path().join("tailscaled.sock"));
                }
            }
        }
    }
    candidates
}

pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 100 && (64..=127).contains(&b)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

pub fn parse_listen(value: &str) -> anyhow::Result<ListenSpec> {
    if let Some(address) = value.strip_prefix("http://") {
        if address.is_empty() {
            anyhow::bail!("HTTP endpoint must include HOST:PORT");
        }
        return Ok(ListenSpec::Http(address.to_string()));
    }
    if let Some(address) = value.strip_prefix("https://") {
        if address.is_empty() {
            anyhow::bail!("HTTPS endpoint must include HOST:PORT");
        }
        return Ok(ListenSpec::Https(address.to_string()));
    }
    if let Some(rest) = value.strip_prefix("tailnet://") {
        let (host, port) = parse_tailnet_host_port(rest)?;
        if let Some(ip) = host {
            if ip.is_unspecified() || ip.is_loopback() || !is_tailscale_ip(ip) {
                anyhow::bail!(
                    "refusing tailnet bind {ip}; rux only binds Tailscale addresses (100.64.0.0/10 and fd7a:115c:a1e0::/48), never 0.0.0.0 or ::"
                );
            }
        }
        return Ok(ListenSpec::Tailnet { host, port });
    }
    if let Some(rest) = value.strip_prefix("tailnet-serve://") {
        if !rest.starts_with('/') || rest.len() < 2 {
            anyhow::bail!("tailnet-serve:// requires an absolute socket path");
        }
        return Ok(ListenSpec::TailnetServe(PathBuf::from(rest)));
    }
    // `--extra-listen :7297` is plain HTTP on every interface, not a socket path.
    if let Some(port) = value.strip_prefix(':') {
        if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow::anyhow!("HTTP port must be between 1 and 65535"))?;
            if port == 0 {
                anyhow::bail!("HTTP port must be between 1 and 65535");
            }
            return Ok(ListenSpec::Http(format!("0.0.0.0:{port}")));
        }
    }
    let path = value.strip_prefix("unix://").unwrap_or(value);
    if path.is_empty() {
        anyhow::bail!("Unix socket path cannot be empty");
    }
    Ok(ListenSpec::Unix(PathBuf::from(path)))
}

pub fn enforce_tailnet_only(spec: &ListenSpec, tailnet_only: bool) -> anyhow::Result<()> {
    if !tailnet_only {
        return Ok(());
    }
    match spec {
        ListenSpec::Http(address) | ListenSpec::Https(address) => {
            anyhow::bail!(
                "--tailnet-only refuses {address}; use tailnet://:PORT or tailnet-serve://SOCKET so the server is not reachable off the tailnet"
            );
        }
        ListenSpec::Tailnet { host: Some(ip), .. }
            if !is_tailscale_ip(*ip) || ip.is_unspecified() =>
        {
            anyhow::bail!("refusing non-tailnet bind {ip}");
        }
        ListenSpec::Unix(_) | ListenSpec::Tailnet { .. } | ListenSpec::TailnetServe(_) => Ok(()),
    }
}

pub fn bind_targets(
    spec_host: Option<IpAddr>,
    discovered: &[IpAddr],
) -> anyhow::Result<Vec<IpAddr>> {
    let discovered: Vec<IpAddr> = discovered
        .iter()
        .copied()
        .map(normalize_ip)
        .filter(|ip| is_tailscale_ip(*ip) && !ip.is_unspecified())
        .collect();
    match spec_host {
        None => {
            if discovered.is_empty() {
                anyhow::bail!(
                    "no Tailscale addresses to bind; refusing 0.0.0.0. Bring tailscaled up and retry"
                );
            }
            Ok(discovered)
        }
        Some(ip) => {
            let ip = normalize_ip(ip);
            if ip.is_unspecified() || !is_tailscale_ip(ip) {
                anyhow::bail!("refusing to bind {ip}; not a Tailscale address");
            }
            if !discovered.is_empty() && !discovered.contains(&ip) {
                anyhow::bail!(
                    "{ip} is not one of this node's Tailscale addresses ({})",
                    discovered
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(vec![ip])
        }
    }
}

pub fn socket_addr_for(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(normalize_ip(ip), port)
}

pub fn authorize_peer(
    policy: &TailnetPolicy,
    local: Option<&ParsedStatus>,
    peer: &PeerInfo,
    remote_addr: Option<&str>,
    path: &str,
) -> Result<Value, String> {
    if !peer_is_identified(peer) {
        return Err("tailscaled did not identify this peer".to_string());
    }
    if !policy.allow_identified && !owner_match(local, peer)? {
        return Err(owner_deny_message(local, peer));
    }
    Ok(principal_json(peer, remote_addr, path))
}

pub fn parse_status(value: &Value) -> Result<ParsedStatus, String> {
    let backend_state = value
        .get("BackendState")
        .and_then(Value::as_str)
        .unwrap_or("NoState")
        .to_string();
    let self_node = value.get("Self").cloned().unwrap_or(Value::Null);
    let user_id = self_node.get("UserID").and_then(json_id);
    let tags = string_list(self_node.get("Tags"));
    let mut ips = ip_list(self_node.get("TailscaleIPs"));
    if ips.is_empty() {
        ips = cidr_list(self_node.get("Addrs"));
    }
    ips.retain(|ip| is_tailscale_ip(*ip));
    let dns_name = self_node
        .get("DNSName")
        .and_then(Value::as_str)
        .map(strip_dot)
        .filter(|name| !name.is_empty());
    let tailnet_name = value
        .pointer("/CurrentTailnet/MagicDNSSuffix")
        .and_then(Value::as_str)
        .or_else(|| value.get("MagicDNSSuffix").and_then(Value::as_str))
        .or_else(|| {
            value
                .pointer("/CurrentTailnet/Name")
                .and_then(Value::as_str)
        })
        .map(strip_dot)
        .filter(|name| !name.is_empty());
    let login_name = user_id.as_deref().and_then(|id| login_for_user(value, id));
    let auth_url = value
        .get("AuthURL")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(str::to_string);
    Ok(ParsedStatus {
        backend_state,
        dns_name,
        tailnet_name,
        login_name,
        user_id,
        tags,
        ips,
        auth_url,
    })
}

pub fn parse_whois(value: &Value) -> Result<PeerInfo, String> {
    let node = value.get("Node").cloned().unwrap_or(Value::Null);
    if node.is_null() {
        return Err("whois response has no node".to_string());
    }
    let profile = value.get("UserProfile").cloned().unwrap_or(Value::Null);
    let user_id = profile
        .get("ID")
        .and_then(json_id)
        .or_else(|| node.get("User").and_then(json_id));
    let login_name = profile
        .get("LoginName")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty());
    let display_name = profile
        .get("DisplayName")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty());
    let node_name = node
        .get("Name")
        .and_then(Value::as_str)
        .or_else(|| node.get("ComputedName").and_then(Value::as_str))
        .map(strip_dot)
        .filter(|value| !value.is_empty());
    Ok(PeerInfo {
        user_id,
        login_name,
        display_name,
        node: node_name,
        tags: string_list(node.get("Tags")),
    })
}

pub fn client_commands(status: &ParsedStatus, policy: &TailnetPolicy) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(dns) = &status.dns_name {
        if policy.https_serve {
            commands.push(format!("rex -S https://{dns}"));
        }
        if let Some(port) = policy.http_port {
            commands.push(format!("rex -S http://{dns}:{port}"));
        }
    }
    if let Some(port) = policy.http_port {
        for ip in &status.ips {
            match ip {
                IpAddr::V4(ip) => commands.push(format!("rex -S http://{ip}:{port}")),
                IpAddr::V6(ip) => commands.push(format!("rex -S http://[{ip}]:{port}")),
            }
        }
    }
    commands
}

pub fn decode_header_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let Some(rest) = value.strip_prefix("=?") else {
        reject_header_chars(value)?;
        return Ok(value.to_string());
    };
    let rest = rest.strip_suffix("?=").ok_or("truncated RFC 2047 header")?;
    let mut parts = rest.splitn(3, '?');
    let charset = parts.next().unwrap_or("");
    let encoding = parts.next().unwrap_or("");
    let text = parts.next().ok_or("truncated RFC 2047 header")?;
    if !charset.eq_ignore_ascii_case("utf-8") || !encoding.eq_ignore_ascii_case("q") {
        return Err("unsupported Tailscale header encoding".to_string());
    }
    let mut bytes = Vec::new();
    let raw = text.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'_' => {
                bytes.push(b' ');
                index += 1;
            }
            b'=' => {
                if index + 2 >= raw.len() {
                    return Err("truncated RFC 2047 hex escape".to_string());
                }
                let hex = std::str::from_utf8(&raw[index + 1..index + 3])
                    .map_err(|_| "invalid RFC 2047 hex escape".to_string())?;
                let byte = u8::from_str_radix(hex, 16)
                    .map_err(|_| "invalid RFC 2047 hex escape".to_string())?;
                bytes.push(byte);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    let decoded = String::from_utf8(bytes).map_err(|_| "header is not UTF-8".to_string())?;
    reject_header_chars(&decoded)?;
    Ok(decoded)
}

fn owner_match(local: Option<&ParsedStatus>, peer: &PeerInfo) -> Result<bool, String> {
    let Some(local) = local else {
        return Err(
            "cannot confirm the tailnet owner because tailscaled status is unavailable".to_string(),
        );
    };
    if !local.tags.is_empty() {
        return Ok(false);
    }
    if !peer.tags.is_empty() {
        return Ok(false);
    }
    if let (Some(local_id), Some(peer_id)) = (&local.user_id, &peer.user_id) {
        return Ok(!local_id.is_empty() && local_id == peer_id);
    }
    if let (Some(local_login), Some(peer_login)) = (&local.login_name, &peer.login_name) {
        return Ok(!local_login.is_empty() && local_login.eq_ignore_ascii_case(peer_login));
    }
    Err("tailscaled did not report a user id for the local node or the peer".to_string())
}

fn owner_deny_message(local: Option<&ParsedStatus>, peer: &PeerInfo) -> String {
    if local.is_some_and(|status| !status.tags.is_empty()) {
        return "this node is tagged and has no owner; restart with --tailnet-allow-identified and restrict access with tailnet ACLs".to_string();
    }
    if !peer.tags.is_empty() {
        return "tagged tailnet devices are not the node owner; pass --tailnet-allow-identified to admit them".to_string();
    }
    "this tailnet user is not the owner of this node".to_string()
}

fn peer_is_identified(peer: &PeerInfo) -> bool {
    peer.login_name
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || peer.user_id.as_ref().is_some_and(|value| !value.is_empty())
        || peer.node.as_ref().is_some_and(|value| !value.is_empty())
        || !peer.tags.is_empty()
}

fn principal_json(peer: &PeerInfo, remote_addr: Option<&str>, path: &str) -> Value {
    let display = peer
        .login_name
        .clone()
        .or_else(|| peer.node.clone())
        .unwrap_or_else(|| "tailscale".to_string());
    let mut principal = json!({
        "kind": "tailscale",
        "transport": "tailscale",
        "display": display,
        "path": [path],
    });
    if let Some(remote_addr) = remote_addr {
        principal["remote_addr"] = json!(remote_addr);
    }
    if let Some(user_id) = &peer.user_id {
        principal["user_id"] = json!(user_id);
    }
    if let Some(login_name) = &peer.login_name {
        principal["login_name"] = json!(login_name);
    }
    if let Some(node) = &peer.node {
        principal["node"] = json!(node);
    }
    if !peer.tags.is_empty() {
        principal["tags"] = json!(peer.tags);
    }
    principal
}

fn parse_tailnet_host_port(rest: &str) -> anyhow::Result<(Option<IpAddr>, u16)> {
    if rest.is_empty() {
        anyhow::bail!("tailnet:// requires a port, for example tailnet://:7297");
    }
    if let Some(port_text) = rest.strip_prefix(':') {
        return Ok((None, parse_port(port_text)?));
    }
    if let Some(rest) = rest.strip_prefix('[') {
        let (host, port_text) = rest.rsplit_once("]:").ok_or_else(|| {
            anyhow::anyhow!(
                "IPv6 tailnet address must look like tailnet://[fd7a:115c:a1e0::1]:7297"
            )
        })?;
        let ip: IpAddr = host
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv6 address in tailnet listener"))?;
        return Ok((Some(ip), parse_port(port_text)?));
    }
    let (host, port_text) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("tailnet:// requires HOST:PORT or :PORT"))?;
    if host.is_empty() {
        return Ok((None, parse_port(port_text)?));
    }
    let ip: IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid address {host} in tailnet listener"))?;
    Ok((Some(ip), parse_port(port_text)?))
}

fn parse_port(text: &str) -> anyhow::Result<u16> {
    let port: u16 = text
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port {text}"))?;
    if port == 0 {
        anyhow::bail!("tailnet port must be non-zero");
    }
    Ok(port)
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    let ip: IpAddr = first.parse().ok()?;
    let ip = normalize_ip(ip);
    is_tailscale_ip(ip).then_some(ip)
}

fn whois_query(ip: IpAddr, port: Option<u16>) -> String {
    let addr = match (normalize_ip(ip), port) {
        (IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        (IpAddr::V6(ip), None) => ip.to_string(),
        (IpAddr::V4(ip), Some(port)) => format!("{ip}:{port}"),
        (IpAddr::V4(ip), None) => ip.to_string(),
    };
    format!(
        "/localapi/v0/whois?addr={}&proto=tcp",
        urlencoding_query(&addr)
    )
}

fn localapi_get_json(socket: &Path, path_and_query: &str) -> Result<Value, String> {
    let bytes = localapi_get(socket, path_and_query)?;
    serde_json::from_slice(&bytes).map_err(|err| format!("tailscaled returned invalid JSON: {err}"))
}

fn localapi_get(socket: &Path, path_and_query: &str) -> Result<Vec<u8>, String> {
    localapi_get_timeout(socket, path_and_query, LOCALAPI_TIMEOUT)
}

fn localapi_get_timeout(
    socket: &Path,
    path_and_query: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket)
        .map_err(|err| format!("connecting to tailscaled at {}: {err}", socket.display()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: local-tailscaled.sock\r\nSec-Tailscale: localapi\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("writing localapi request: {err}"))?;
    read_http_body_deadline(&mut stream, Instant::now() + timeout, timeout)
}

/// Reads one LocalAPI response and stops at the end of the body.
///
/// tailscaled 1.102 answers `status` and `whois` with `Transfer-Encoding:
/// chunked` and does not close the socket. The chunk-size line is often a
/// decimal number, which `serde_json` accepts as a value and then rejects
/// the pretty-printed object on the next line (`trailing characters at line
/// 2 column 1`). Content-Length responses stop at that length so a
/// keep-alive connection cannot append the next message.
#[cfg_attr(not(test), allow(dead_code))]
fn read_http_body<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    read_http_body_deadline(reader, Instant::now() + LOCALAPI_TIMEOUT, LOCALAPI_TIMEOUT)
}

fn read_http_body_deadline<R: Read>(
    reader: R,
    deadline: Instant,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut conn = ByteBuf::new(reader, deadline, timeout);
    let header_pos = conn.read_until(b"\r\n\r\n")?;
    let header_bytes = conn.consume(header_pos + 4);
    let header_text = std::str::from_utf8(&header_bytes[..header_pos])
        .map_err(|_| "tailscaled response headers are not UTF-8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "empty tailscaled response".to_string())?;
    let code = status.split_whitespace().nth(1).unwrap_or("0");
    if code != "200" {
        return Err(format!("tailscaled localapi returned HTTP {code}"));
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .to_ascii_lowercase()
                .split(',')
                .any(|item| item.trim() == "chunked")
        {
            chunked = true;
        }
    }
    if chunked {
        read_chunked(&mut conn)
    } else if let Some(length) = content_length {
        if length > LOCALAPI_LIMIT {
            return Err("tailscaled response exceeded 8 MiB".to_string());
        }
        conn.read_exact(length)
    } else {
        let mut body = std::mem::take(&mut conn.buf);
        loop {
            match conn.fill()? {
                ReadMore::Bytes(chunk) => {
                    if body.len() + chunk.len() > LOCALAPI_LIMIT {
                        return Err("tailscaled response exceeded 8 MiB".to_string());
                    }
                    body.extend(chunk);
                }
                ReadMore::Eof => break,
            }
        }
        Ok(body)
    }
}

enum ReadMore {
    Bytes(Vec<u8>),
    Eof,
}

struct ByteBuf<R> {
    inner: R,
    buf: Vec<u8>,
    deadline: Instant,
    timeout: Duration,
}

impl<R: Read> ByteBuf<R> {
    fn new(inner: R, deadline: Instant, timeout: Duration) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            deadline,
            timeout,
        }
    }

    fn timed_out(&self) -> String {
        format!(
            "timed out waiting for tailscaled after {:.1}s",
            self.timeout.as_secs_f32()
        )
    }

    /// Reads the next socket bytes and appends them. A non-empty buffer is not
    /// a reason to return: chunked responses from tailscaled 1.102 are often
    /// one chunk larger than this 8 KiB buffer, and the terminating `0` chunk
    /// can arrive in a later write. Returning early left `read_exact` spinning
    /// at 100% CPU with the body still sitting in the socket receive queue.
    fn read_some(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut tmp = [0u8; 8192];
        loop {
            if Instant::now() >= self.deadline {
                return Err(self.timed_out());
            }
            match self.inner.read(&mut tmp) {
                Ok(0) => return Ok(None),
                Ok(n) => return Ok(Some(tmp[..n].to_vec())),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(self.timed_out());
                }
                Err(err) => return Err(format!("reading tailscaled response: {err}")),
            }
        }
    }

    fn fill(&mut self) -> Result<ReadMore, String> {
        if !self.buf.is_empty() {
            return Ok(ReadMore::Bytes(std::mem::take(&mut self.buf)));
        }
        match self.read_some()? {
            Some(chunk) => Ok(ReadMore::Bytes(chunk)),
            None => Ok(ReadMore::Eof),
        }
    }

    fn pull(&mut self) -> Result<(), String> {
        let before = self.buf.len();
        match self.read_some()? {
            Some(chunk) => {
                if before.saturating_add(chunk.len()) > LOCALAPI_LIMIT {
                    return Err("tailscaled response exceeded 8 MiB".to_string());
                }
                self.buf.extend(chunk);
                if self.buf.len() == before {
                    return Err("tailscaled read made no progress".to_string());
                }
                Ok(())
            }
            None => Err("tailscaled closed the connection before the response ended".to_string()),
        }
    }

    fn read_until(&mut self, needle: &[u8]) -> Result<usize, String> {
        loop {
            if needle.len() <= self.buf.len()
                && let Some(pos) = self
                    .buf
                    .windows(needle.len())
                    .position(|window| window == needle)
            {
                return Ok(pos);
            }
            if self.buf.len() > LOCALAPI_LIMIT {
                return Err("tailscaled response exceeded 8 MiB".to_string());
            }
            self.pull()?;
        }
    }

    fn consume(&mut self, n: usize) -> Vec<u8> {
        let out = self.buf[..n].to_vec();
        self.buf.drain(..n);
        out
    }

    fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            self.pull()?;
        }
        Ok(self.consume(n))
    }

    fn read_line(&mut self) -> Result<String, String> {
        let pos = self.read_until(b"\n")?;
        let mut line = self.consume(pos + 1);
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| "tailscaled response is not UTF-8".to_string())
    }
}

fn read_chunked<R: Read>(conn: &mut ByteBuf<R>) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = conn.read_line()?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() {
            return Err("tailscaled sent an empty chunk size".to_string());
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("tailscaled sent a bad chunk size: {size_text}"))?;
        if size == 0 {
            loop {
                if conn.read_line()?.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len().saturating_add(size) > LOCALAPI_LIMIT {
            return Err("tailscaled response exceeded 8 MiB".to_string());
        }
        body.extend(conn.read_exact(size)?);
        let crlf = conn.read_exact(2)?;
        if crlf.as_slice() != b"\r\n" {
            return Err("tailscaled chunk is missing its trailing CRLF".to_string());
        }
    }
    Ok(body)
}

fn login_for_user(status: &Value, user_id: &str) -> Option<String> {
    let users = status.get("User")?.as_object()?;
    if let Some(login) = users.get(user_id).and_then(login_name_of) {
        return Some(login);
    }
    users.values().find_map(|user| {
        let id = user.get("ID").and_then(json_id)?;
        (id == user_id).then(|| login_name_of(user)).flatten()
    })
}

fn login_name_of(user: &Value) -> Option<String> {
    user.get("LoginName")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn json_id(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        Value::Number(number) => number
            .as_i64()
            .map(|id| id.to_string())
            .or_else(|| number.as_u64().map(|id| id.to_string())),
        _ => None,
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn ip_list(value: Option<&Value>) -> Vec<IpAddr> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|text| text.parse().ok())
                .map(normalize_ip)
                .collect()
        })
        .unwrap_or_default()
}

fn cidr_list(value: Option<&Value>) -> Vec<IpAddr> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|text| text.split('/').next())
                .filter_map(|text| text.parse().ok())
                .map(normalize_ip)
                .collect()
        })
        .unwrap_or_default()
}

fn strip_dot(value: &str) -> String {
    value.trim_end_matches('.').to_string()
}

fn reject_header_chars(value: &str) -> Result<(), String> {
    if value.chars().any(|ch| ch.is_control() || ch == '\u{007f}') {
        return Err("Tailscale identity header contains control characters".to_string());
    }
    if value.len() > 256 {
        return Err("Tailscale identity header is too long".to_string());
    }
    Ok(())
}

fn urlencoding_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn socket_candidates_include_linux_and_macos_paths() {
        let found = socket_candidates();
        let text: Vec<String> = found
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        assert!(
            text.iter()
                .any(|path| path == "/var/run/tailscale/tailscaled.sock")
        );
        assert!(
            text.iter()
                .any(|path| path == "/run/tailscale/tailscaled.sock")
        );
        assert!(text.iter().any(|path| path == "/var/run/tailscaled.socket"));
    }

    fn chunked_response(body: &[u8]) -> Vec<u8> {
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend(body);
        raw.extend(b"\r\n0\r\n\r\n");
        raw
    }

    struct OneByte<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    /// First read returns only the chunk body. The `0` chunk is a later read.
    struct LateChunk {
        head: Vec<u8>,
        sent: usize,
        term: &'static [u8],
        term_sent: usize,
    }

    impl Read for LateChunk {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.sent < self.head.len() {
                let n = (self.head.len() - self.sent).min(buf.len()).min(8192);
                buf[..n].copy_from_slice(&self.head[self.sent..self.sent + n]);
                self.sent += n;
                return Ok(n);
            }
            if self.term_sent < self.term.len() {
                let n = (self.term.len() - self.term_sent).min(buf.len());
                buf[..n].copy_from_slice(&self.term[self.term_sent..self.term_sent + n]);
                self.term_sent += n;
                return Ok(n);
            }
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "terminator already consumed",
            ))
        }
    }

    struct StallAfter {
        data: Vec<u8>,
        sent: usize,
    }

    impl Read for StallAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.sent < self.data.len() {
                let n = (self.data.len() - self.sent).min(buf.len()).min(8192);
                buf[..n].copy_from_slice(&self.data[self.sent..self.sent + n]);
                self.sent += n;
                return Ok(n);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminating chunk never arrived",
            ))
        }
    }

    fn policy(allow_identified: bool) -> TailnetPolicy {
        TailnetPolicy {
            allow_identified,
            http_port: Some(7297),
            https_serve: true,
        }
    }

    fn owner_status() -> ParsedStatus {
        ParsedStatus {
            backend_state: "Running".into(),
            dns_name: Some("host.example.ts.net".into()),
            tailnet_name: Some("example.ts.net".into()),
            login_name: Some("alice@example.com".into()),
            user_id: Some("42".into()),
            tags: Vec::new(),
            ips: vec![
                "100.64.1.2".parse().unwrap(),
                "fd7a:115c:a1e0::2".parse().unwrap(),
            ],
            auth_url: None,
        }
    }

    fn person(id: &str, login: &str) -> PeerInfo {
        PeerInfo {
            user_id: Some(id.into()),
            login_name: Some(login.into()),
            display_name: Some("Alice".into()),
            node: Some("laptop.example.ts.net".into()),
            tags: Vec::new(),
        }
    }

    #[test]
    fn tailscale_ranges_match_cgnat_and_ula() {
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.255".parse().unwrap()));
        assert!(!is_tailscale_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_tailscale_ip("100.128.0.1".parse().unwrap()));
        assert!(!is_tailscale_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_tailscale_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_tailscale_ip("10.0.0.5".parse().unwrap()));
        assert!(is_tailscale_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(is_tailscale_ip("fd7a:115c:a1e0:ffff::1".parse().unwrap()));
        assert!(!is_tailscale_ip("fd7a:115c:a1e1::1".parse().unwrap()));
        assert!(!is_tailscale_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        let mapped = IpAddr::V6("::ffff:100.64.0.9".parse().unwrap());
        assert!(is_tailscale_ip(mapped));
        assert_eq!(
            normalize_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))
        );
    }

    #[test]
    fn parser_refuses_unspecified_and_public_binds() {
        let all = parse_listen("tailnet://:7297").unwrap();
        assert!(matches!(
            all,
            ListenSpec::Tailnet {
                host: None,
                port: 7297
            }
        ));
        let v4 = parse_listen("tailnet://100.64.1.2:7297").unwrap();
        assert!(matches!(
            v4,
            ListenSpec::Tailnet {
                host: Some(ip),
                port: 7297
            } if ip == "100.64.1.2".parse::<IpAddr>().unwrap()
        ));
        let v6 = parse_listen("tailnet://[fd7a:115c:a1e0::1]:7297").unwrap();
        assert!(matches!(
            v6,
            ListenSpec::Tailnet {
                host: Some(_),
                port: 7297
            }
        ));
        assert!(parse_listen("tailnet://0.0.0.0:7297").is_err());
        assert!(parse_listen("tailnet://[::]:7297").is_err());
        assert!(parse_listen("tailnet://127.0.0.1:7297").is_err());
        assert!(parse_listen("tailnet://10.0.0.8:7297").is_err());
        assert!(parse_listen("tailnet://:0").is_err());
        let serve = parse_listen("tailnet-serve:///run/rux/serve.sock").unwrap();
        assert_eq!(
            serve,
            ListenSpec::TailnetServe(PathBuf::from("/run/rux/serve.sock"))
        );
        assert!(parse_listen("tailnet-serve://relative.sock").is_err());
        let plain = parse_listen(":7297").unwrap();
        assert!(matches!(plain, ListenSpec::Http(ref addr) if addr == "0.0.0.0:7297"));
        assert!(enforce_tailnet_only(&plain, true).is_err());
        assert!(parse_listen(":0").is_err());
        assert!(enforce_tailnet_only(&parse_listen("http://0.0.0.0:7297").unwrap(), true).is_err());
        assert!(enforce_tailnet_only(&parse_listen("https://0.0.0.0:443").unwrap(), true).is_err());
        assert!(enforce_tailnet_only(&parse_listen("tailnet://:7297").unwrap(), true).is_ok());
        assert!(
            enforce_tailnet_only(&parse_listen("unix:///run/rux/server.sock").unwrap(), true)
                .is_ok()
        );
    }

    #[test]
    fn bind_targets_never_include_unspecified_or_foreign_ips() {
        let discovered = vec![
            "100.64.1.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            "fd7a:115c:a1e0::2".parse().unwrap(),
        ];
        let bound = bind_targets(None, &discovered).unwrap();
        assert_eq!(
            bound,
            vec![
                "100.64.1.2".parse::<IpAddr>().unwrap(),
                "fd7a:115c:a1e0::2".parse().unwrap(),
            ]
        );
        assert!(bind_targets(Some("0.0.0.0".parse().unwrap()), &discovered).is_err());
        assert!(bind_targets(Some("100.70.0.1".parse().unwrap()), &discovered).is_err());
        assert!(bind_targets(None, &["1.2.3.4".parse().unwrap()]).is_err());
    }

    #[test]
    fn status_and_whois_parse_localapi_shape() {
        let status = parse_status(&json!({
            "BackendState": "Running",
            "AuthURL": "",
            "MagicDNSSuffix": "example.ts.net",
            "Self": {
                "DNSName": "host.example.ts.net.",
                "UserID": 42,
                "TailscaleIPs": ["100.64.1.2", "fd7a:115c:a1e0::2"],
                "Tags": null
            },
            "User": {
                "42": { "ID": 42, "LoginName": "alice@example.com", "DisplayName": "Alice" }
            },
            "CurrentTailnet": { "Name": "alice@example.com", "MagicDNSSuffix": "example.ts.net." }
        }))
        .unwrap();
        assert_eq!(status.dns_name.as_deref(), Some("host.example.ts.net"));
        assert_eq!(status.user_id.as_deref(), Some("42"));
        assert_eq!(status.login_name.as_deref(), Some("alice@example.com"));
        assert_eq!(status.ips.len(), 2);
        assert!(status.tags.is_empty());

        let tagged = parse_status(&json!({
            "BackendState": "Running",
            "Self": {
                "DNSName": "host.example.ts.net.",
                "UserID": 0,
                "Tags": ["tag:server"],
                "Addrs": ["100.90.0.5/32"]
            }
        }))
        .unwrap();
        assert_eq!(tagged.tags, vec!["tag:server".to_string()]);
        assert_eq!(tagged.ips, vec!["100.90.0.5".parse::<IpAddr>().unwrap()]);

        let peer = parse_whois(&json!({
            "Node": {
                "Name": "laptop.example.ts.net.",
                "User": 42,
                "Tags": ["tag:ci"]
            },
            "UserProfile": { "ID": 42, "LoginName": "alice@example.com", "DisplayName": "Alice" }
        }))
        .unwrap();
        assert_eq!(peer.node.as_deref(), Some("laptop.example.ts.net"));
        assert_eq!(peer.tags, vec!["tag:ci".to_string()]);
        assert_eq!(peer.user_id.as_deref(), Some("42"));
    }

    #[test]
    fn owner_policy_admits_only_the_same_user() {
        let local = owner_status();
        let owner = person("42", "alice@example.com");
        let other = person("7", "bob@example.com");
        let mut tagged_peer = person("42", "alice@example.com");
        tagged_peer.tags = vec!["tag:ci".into()];
        assert!(
            authorize_peer(
                &policy(false),
                Some(&local),
                &owner,
                Some("100.64.1.8:1"),
                "tailnet"
            )
            .is_ok()
        );
        let denied =
            authorize_peer(&policy(false), Some(&local), &other, None, "tailnet").unwrap_err();
        assert!(denied.contains("not the owner"));
        assert!(
            authorize_peer(&policy(false), Some(&local), &tagged_peer, None, "tailnet").is_err()
        );
        assert!(authorize_peer(&policy(true), Some(&local), &other, None, "tailnet").is_ok());

        let mut tagged_local = local.clone();
        tagged_local.tags = vec!["tag:server".into()];
        let message = authorize_peer(&policy(false), Some(&tagged_local), &owner, None, "tailnet")
            .unwrap_err();
        assert!(message.contains("--tailnet-allow-identified"));
        assert!(
            authorize_peer(&policy(true), Some(&tagged_local), &owner, None, "tailnet").is_ok()
        );
    }

    #[test]
    fn serve_login_matches_owner_without_a_user_id() {
        let local = owner_status();
        let peer = PeerInfo {
            user_id: None,
            login_name: Some("Alice@Example.com".into()),
            display_name: Some("Alice".into()),
            node: None,
            tags: Vec::new(),
        };
        let principal =
            authorize_peer(&policy(false), Some(&local), &peer, None, "tailnet-serve").unwrap();
        assert_eq!(principal["kind"], "tailscale");
        assert_eq!(principal["path"][0], "tailnet-serve");
        assert_eq!(principal["login_name"], "Alice@Example.com");
        let stranger = PeerInfo {
            login_name: Some("bob@example.com".into()),
            ..peer
        };
        assert!(
            authorize_peer(
                &policy(false),
                Some(&local),
                &stranger,
                None,
                "tailnet-serve"
            )
            .is_err()
        );
    }

    #[test]
    fn rfc2047_q_encoding_and_funnel_header() {
        assert_eq!(
            decode_header_value("=?utf-8?q?Ferris_B=C3=BCller?=").unwrap(),
            "Ferris Büller"
        );
        assert_eq!(
            decode_header_value("alice@example.com").unwrap(),
            "alice@example.com"
        );
        assert!(decode_header_value("alice\r\n@example.com").is_err());
    }

    #[test]
    fn client_commands_prefer_magicdns() {
        let commands = client_commands(&owner_status(), &policy(false));
        assert_eq!(commands[0], "rex -S https://host.example.ts.net");
        assert_eq!(commands[1], "rex -S http://host.example.ts.net:7297");
        assert!(
            commands
                .iter()
                .any(|line| line == "rex -S http://100.64.1.2:7297")
        );
    }

    #[test]
    fn localapi_http_parser_reads_content_length_and_chunks() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: keep-alive\r\n\r\n{\"ok\":true}TRAIL";
        assert_eq!(read_http_body(&mut &raw[..]).unwrap(), br#"{"ok":true}"#);
        let missing = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(
            read_http_body(&mut &missing[..])
                .unwrap_err()
                .contains("404")
        );
        // A decimal chunk size is itself valid JSON. Leaving it in the body
        // makes serde report trailing characters on the next line.
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\n\t\"Version\":\"1\"\r\n0\r\n\r\n";
        assert_eq!(
            read_http_body(&mut &chunked[..]).unwrap(),
            b"{\n\t\"Version\":\"1\""
        );
        let split = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\na;ext=1\r\n{\"ok\":true\r\n1\r\n}\r\n0\r\nX-Trace: 1\r\n\r\n";
        assert_eq!(read_http_body(&mut &split[..]).unwrap(), br#"{"ok":true}"#);
    }

    #[test]
    fn localapi_reads_a_chunk_larger_than_the_socket_buffer() {
        let mut body = b"{\"Version\":\"1.102.4\",\"pad\":\"".to_vec();
        body.extend(std::iter::repeat(b'a').take(12_000));
        body.extend(br#""}"#);
        assert!(body.len() > 8192);
        let raw = chunked_response(&body);
        let parsed = read_http_body(&mut &raw[..]).unwrap();
        assert_eq!(parsed, body);
        let value: Value = serde_json::from_slice(&parsed).unwrap();
        assert_eq!(value["Version"], "1.102.4");
        assert_eq!(value["pad"].as_str().unwrap().len(), 12_000);
    }

    #[test]
    fn localapi_reads_a_chunk_split_across_one_byte_reads() {
        let body = br#"{"BackendState":"Running","Self":{"DNSName":"vm.example.ts.net.","UserID":9,"TailscaleIPs":["100.64.5.5"]},"User":{"9":{"ID":9,"LoginName":"a@b"}}}"#;
        let raw = chunked_response(body);
        let parsed = read_http_body(&mut OneByte { data: &raw, pos: 0 }).unwrap();
        let value: Value = serde_json::from_slice(&parsed).unwrap();
        assert_eq!(
            parse_status(&value).unwrap().dns_name.as_deref(),
            Some("vm.example.ts.net")
        );
    }

    #[test]
    fn localapi_waits_for_a_late_terminating_chunk_and_does_not_spin() {
        let body = br#"{"ok":true,"n":1}"#;
        let mut head = chunked_response(body);
        assert!(head.ends_with(b"0\r\n\r\n"));
        head.truncate(head.len() - b"0\r\n\r\n".len());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let result = read_http_body(&mut LateChunk {
                head,
                sent: 0,
                term: b"0\r\n\r\n",
                term_sent: 0,
            });
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("chunked reader spun instead of reading the rest of the socket");
        assert_eq!(result.unwrap(), body);
    }

    #[test]
    fn localapi_times_out_when_the_terminating_chunk_never_arrives() {
        let body = vec![b'x'; 9000];
        let mut head = chunked_response(&body);
        head.truncate(head.len() - b"0\r\n\r\n".len());
        let started = Instant::now();
        let err = read_http_body_deadline(
            &mut StallAfter {
                data: head,
                sent: 0,
            },
            Instant::now() + Duration::from_millis(200),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(err.contains("timed out waiting for tailscaled"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn localapi_roundtrip_over_a_unix_socket() {
        let dir = std::env::temp_dir().join(format!("rux-localapi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("tailscaled.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let body = br#"{"BackendState":"Running","Self":{"DNSName":"vm.example.ts.net.","UserID":9,"TailscaleIPs":["100.64.5.5"]},"User":{"9":{"ID":9,"LoginName":"a@b"}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let value = localapi_get_json(&socket, "/localapi/v0/status").unwrap();
        let parsed = parse_status(&value).unwrap();
        assert_eq!(parsed.dns_name.as_deref(), Some("vm.example.ts.net"));
        assert_eq!(parsed.login_name.as_deref(), Some("a@b"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localapi_reads_chunked_pretty_json_without_waiting_for_close() {
        let dir = std::env::temp_dir().join(format!(
            "rux-localapi-chunk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("tailscaled.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let status = "{\n\t\"Version\": \"1.102.4-test\",\n\t\"BackendState\": \"Running\",\n\t\"Self\": {\n\t\t\"DNSName\": \"vm.example.ts.net.\",\n\t\t\"UserID\": 9,\n\t\t\"TailscaleIPs\": [\"100.64.5.5\"]\n\t},\n\t\"User\": {\n\t\t\"9\": {\"ID\": 9, \"LoginName\": \"a@b\"}\n\t}\n}\n";
        let whois = "{\n\t\"Node\": {\n\t\t\"Name\": \"peer.example.ts.net.\",\n\t\t\"User\": 9\n\t},\n\t\"UserProfile\": {\n\t\t\"ID\": 9,\n\t\t\"LoginName\": \"a@b\"\n\t}\n}\n";
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&tmp[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let body = if request.windows(5).any(|window| window == b"whois") {
                    whois.as_bytes()
                } else {
                    status.as_bytes()
                };
                let mut framed = Vec::new();
                for piece in body.chunks(16) {
                    framed.extend(format!("{:x}\r\n", piece.len()).into_bytes());
                    framed.extend(piece);
                    framed.extend(b"\r\n");
                }
                framed.extend(b"0\r\n\r\n");
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&framed).unwrap();
                stream.flush().unwrap();
                let mut sink = [0u8; 8];
                let _ = stream.read(&mut sink);
            }
        });
        let started = Instant::now();
        let value = localapi_get_json(&socket, "/localapi/v0/status").unwrap();
        let parsed = parse_status(&value).unwrap();
        assert_eq!(parsed.backend_state, "Running");
        assert_eq!(parsed.dns_name.as_deref(), Some("vm.example.ts.net"));
        assert_eq!(value["Version"], "1.102.4-test");
        let who =
            localapi_get_json(&socket, "/localapi/v0/whois?addr=100.64.5.5:1&proto=tcp").unwrap();
        let peer = parse_whois(&who).unwrap();
        assert_eq!(peer.login_name.as_deref(), Some("a@b"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "chunked keep-alive read waited for the socket to close"
        );
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localapi_socket_timeout_is_an_error_when_the_chunk_never_ends() {
        let dir = std::env::temp_dir().join(format!(
            "rux-localapi-stall-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("tailscaled.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let body = vec![b'y'; 14_000];
        let mut framed = chunked_response(&body);
        framed.truncate(framed.len() - b"0\r\n\r\n".len());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        request.extend_from_slice(&tmp[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            stream.write_all(&framed).unwrap();
            stream.flush().unwrap();
            let mut sink = [0u8; 8];
            let _ = stream.read(&mut sink);
        });
        let started = Instant::now();
        let err = localapi_get_timeout(&socket, "/localapi/v0/status", Duration::from_millis(400))
            .unwrap_err();
        assert!(err.contains("timed out waiting for tailscaled"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "LocalAPI call hung instead of hitting its timeout"
        );
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tcp_authorization_rejects_loopback_without_calling_tailscaled() {
        let gate = Arc::new(TailnetGate::new(
            PathBuf::from("/no/such/tailscaled.sock"),
            policy(true),
        ));
        let err = gate
            .authorize_tcp("127.0.0.1:40000".parse().unwrap())
            .await
            .unwrap_err();
        assert!(err.contains("not from a Tailscale"));
        let err = gate
            .authorize_serve(&ServeHeaders {
                login: None,
                display_name: None,
                forwarded_for: None,
                funnel: true,
            })
            .await
            .unwrap_err();
        assert!(err.contains("Funnel"));
    }
}
