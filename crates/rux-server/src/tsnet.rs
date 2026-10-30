//! Built-in Tailscale, the `server.tailscale.*` methods.
//!
//! The live device is a `rux-tsnet` process (Go `tsnet`). Tests use an
//! in-memory device that speaks the same status object, so they never join a
//! tailnet or invent a MagicDNS name on `server.status` unless a device is on.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rux_proto::ApiError;
use serde_json::{Value, json};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TsnetNode {
    engine: Mutex<Engine>,
    view: Mutex<View>,
    on_change: Mutex<Option<Arc<dyn Fn(Value) + Send + Sync>>>,
}

struct View {
    up: bool,
    signed_in: bool,
    hostname: String,
    allow_members: bool,
    tags: Vec<String>,
    phase: String,
    auth_url: Option<String>,
    login_started: bool,
    account: Option<String>,
    tailnet_name: Option<String>,
    dns_name: Option<String>,
    https: Option<String>,
    https_url: Option<String>,
    error: Option<String>,
}

enum Engine {
    Memory(MemoryDevice),
    Process(ProcessDevice),
}

struct MemoryDevice {
    signed_in: bool,
    hostname: String,
    account: Option<String>,
    tailnet_name: Option<String>,
    dns_name: Option<String>,
    allow_members: bool,
    tags: Vec<String>,
    auth_url: Option<String>,
    phase: String,
    https: Option<String>,
}

struct ProcessDevice {
    child: Child,
    stdin: ChildStdin,
    pending: Arc<Mutex<HashMap<u64, Sender<Result<Value, String>>>>>,
    next_id: u64,
}

pub struct EnableRequest {
    pub hostname: Option<String>,
    pub allow_members: bool,
    pub auth_key: Option<String>,
    pub advertise_tags: Vec<String>,
}

impl TsnetNode {
    pub fn memory() -> Self {
        Self::from_engine(Engine::Memory(MemoryDevice {
            signed_in: false,
            hostname: "rex".into(),
            account: None,
            tailnet_name: None,
            dns_name: None,
            allow_members: false,
            tags: Vec::new(),
            auth_url: None,
            phase: "disabled".into(),
            https: None,
        }))
    }

    pub fn spawn(
        bin: &Path,
        state_dir: &Path,
        backend: &str,
        token: &str,
    ) -> Result<Arc<Self>, String> {
        let mut child = Command::new(bin)
            .arg("--state-dir")
            .arg(state_dir)
            .arg("--backend")
            .arg(backend)
            .arg("--token")
            .arg(token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("starting {}: {error}", bin.display()))?;
        let stdin = child.stdin.take().ok_or("tsnet sidecar has no stdin")?;
        let stdout = child.stdout.take().ok_or("tsnet sidecar has no stdout")?;
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let slot = Arc::new(Mutex::new(None));
        let reader_slot = slot.clone();
        let reader_pending = pending.clone();
        std::thread::spawn(move || read_sidecar(stdout, reader_pending, reader_slot));
        let node = Arc::new(Self::from_engine(Engine::Process(ProcessDevice {
            child,
            stdin,
            pending,
            next_id: 1,
        })));
        *slot.lock().unwrap() = Some(node.clone());
        Ok(node)
    }

    fn from_engine(engine: Engine) -> Self {
        Self {
            engine: Mutex::new(engine),
            view: Mutex::new(View::disabled()),
            on_change: Mutex::new(None),
        }
    }

    pub fn set_on_change<F>(&self, callback: F)
    where
        F: Fn(Value) + Send + Sync + 'static,
    {
        *self.on_change.lock().unwrap() = Some(Arc::new(callback));
    }

    pub fn snapshot(&self) -> Value {
        self.view.lock().unwrap().to_json()
    }

    pub fn enable(&self, request: EnableRequest) -> Result<Value, ApiError> {
        if let Some(hostname) = &request.hostname {
            validate_hostname(hostname)?;
        }
        let already = self.view.lock().unwrap().up;
        if already {
            self.view.lock().unwrap().allow_members = request.allow_members;
            let _ = self.roundtrip(
                "set_members",
                json!({ "allow_tailnet_members": request.allow_members }),
            );
            return Ok(self.wrap());
        }
        if !request.advertise_tags.is_empty() && !request.allow_members {
            return Err(ApiError::bad_request(
                "advertise_tags requires allow_tailnet_members",
            ));
        }
        for tag in &request.advertise_tags {
            if !valid_tag(tag) {
                return Err(ApiError::bad_request(format!(
                    "invalid Tailscale tag {tag}"
                )));
            }
        }
        let hostname = request
            .hostname
            .clone()
            .unwrap_or_else(|| self.view.lock().unwrap().hostname.clone());
        validate_hostname(&hostname)?;
        {
            let mut view = self.view.lock().unwrap();
            view.up = true;
            view.hostname = hostname.clone();
            view.allow_members = request.allow_members;
            view.tags = request.advertise_tags.clone();
            view.phase = "starting".into();
            view.error = None;
            view.https = Some("pending".into());
            view.login_started = false;
        }
        let body = json!({
            "hostname": hostname,
            "allow_tailnet_members": request.allow_members,
            "auth_key": request.auth_key.unwrap_or_default(),
            "advertise_tags": request.advertise_tags,
        });
        self.apply_backend("enable", body)?;
        Ok(self.wrap())
    }

    pub fn disable(&self) -> Result<Value, ApiError> {
        if !self.view.lock().unwrap().up {
            return Ok(self.wrap());
        }
        self.apply_backend("disable", json!({}))?;
        let mut view = self.view.lock().unwrap();
        view.up = false;
        view.phase = "disabled".into();
        view.https = None;
        view.https_url = None;
        view.auth_url = None;
        view.dns_name = None;
        view.login_started = false;
        drop(view);
        Ok(self.wrap())
    }

    pub fn login(&self) -> Result<Value, ApiError> {
        if !self.view.lock().unwrap().up {
            return Err(ApiError::conflict(
                "built-in Tailscale is off; call server.tailscale.enable first",
            ));
        }
        if self.view.lock().unwrap().login_started {
            return Ok(self.wrap());
        }
        self.view.lock().unwrap().login_started = true;
        self.apply_backend("login", json!({}))?;
        Ok(self.wrap())
    }

    pub fn logout(&self) -> Result<Value, ApiError> {
        if !self.view.lock().unwrap().up {
            return Ok(self.wrap());
        }
        self.apply_backend("logout", json!({}))?;
        let mut view = self.view.lock().unwrap();
        view.up = false;
        view.signed_in = false;
        view.phase = "disabled".into();
        view.account = None;
        view.auth_url = None;
        view.https = None;
        view.https_url = None;
        view.dns_name = None;
        view.tailnet_name = None;
        view.tags.clear();
        view.login_started = false;
        drop(view);
        Ok(self.wrap())
    }

    pub fn rename(&self, hostname: &str) -> Result<Value, ApiError> {
        validate_hostname(hostname)?;
        if !self.view.lock().unwrap().up {
            return Err(ApiError::conflict(
                "built-in Tailscale is off; pass hostname to server.tailscale.enable",
            ));
        }
        let previous_dns = self.view.lock().unwrap().dns_name.clone();
        self.apply_backend("rename", json!({ "hostname": hostname }))?;
        self.view.lock().unwrap().hostname = hostname.to_string();
        let mut returned = self.snapshot();
        if let Some(previous) = previous_dns {
            returned["dns_name"] = json!(previous);
        }
        Ok(json!({ "tailscale": returned }))
    }

    pub fn note_https_failure(&self, message: &str) {
        let mut view = self.view.lock().unwrap();
        view.up = false;
        view.phase = "disabled".into();
        view.https = None;
        view.https_url = None;
        view.error = Some(message.to_string());
        let status = view.to_json();
        drop(view);
        self.publish(status);
    }

    fn apply_backend(&self, op: &str, body: Value) -> Result<(), ApiError> {
        let result = {
            let mut engine = self.engine.lock().unwrap();
            engine.call(op, body)
        };
        match result {
            Ok(status) => {
                self.merge_status(&status);
                Ok(())
            }
            Err(error) => {
                if op == "logout" {
                    return Err(ApiError::new(502, "bad_gateway", error));
                }
                Err(ApiError::bad_request(error))
            }
        }
    }

    fn roundtrip(&self, op: &str, body: Value) -> Result<(), ApiError> {
        let mut engine = self.engine.lock().unwrap();
        match engine.call(op, body) {
            Ok(status) => {
                drop(engine);
                self.merge_status(&status);
                Ok(())
            }
            Err(error) => Err(ApiError::bad_request(error)),
        }
    }

    fn merge_status(&self, status: &Value) {
        let mut view = self.view.lock().unwrap();
        if let Some(phase) = status.get("state").and_then(Value::as_str) {
            view.phase = phase.to_string();
            view.up = phase != "disabled";
        }
        if let Some(value) = status.get("allow_tailnet_members").and_then(Value::as_bool) {
            view.allow_members = value;
        }
        if let Some(name) = status.get("dns_name").and_then(Value::as_str) {
            view.dns_name = Some(name.to_string());
        }
        if let Some(url) = status.get("auth_url").and_then(Value::as_str) {
            view.auth_url = Some(url.to_string());
            view.login_started = true;
        }
        if let Some(login) = status
            .get("account")
            .and_then(|account| account.get("login_name"))
            .and_then(Value::as_str)
        {
            view.account = Some(login.to_string());
            view.signed_in = true;
        }
        if let Some(name) = status.get("tailnet_name").and_then(Value::as_str) {
            view.tailnet_name = Some(name.to_string());
        }
        if let Some(tags) = status.get("tags").and_then(Value::as_array) {
            view.tags = tags
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
        }
        if let Some(https) = status.get("https") {
            view.https = https
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_string);
            view.https_url = https.get("url").and_then(Value::as_str).map(str::to_string);
        }
        if status.get("state").and_then(Value::as_str) == Some("running") {
            view.signed_in = true;
            view.login_started = false;
        }
        let published = view.to_json();
        drop(view);
        self.publish(published);
    }

    fn publish(&self, status: Value) {
        if let Some(callback) = self.on_change.lock().unwrap().clone() {
            callback(status);
        }
    }

    fn wrap(&self) -> Value {
        json!({ "tailscale": self.snapshot() })
    }
}

impl View {
    fn disabled() -> Self {
        Self {
            up: false,
            signed_in: false,
            hostname: "rex".into(),
            allow_members: false,
            tags: Vec::new(),
            phase: "disabled".into(),
            auth_url: None,
            login_started: false,
            account: None,
            tailnet_name: None,
            dns_name: None,
            https: None,
            https_url: None,
            error: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut status = json!({
            "state": self.phase,
            "allow_tailnet_members": self.allow_members,
        });
        if let Some(error) = &self.error {
            status["error"] = json!(error);
        }
        if let Some(name) = &self.dns_name {
            status["dns_name"] = json!(name);
        }
        if self.phase == "needs_login"
            && let Some(url) = &self.auth_url
        {
            status["auth_url"] = json!(url);
        }
        if let Some(login) = &self.account {
            status["account"] = json!({ "login_name": login });
        }
        if let Some(name) = &self.tailnet_name {
            status["tailnet_name"] = json!(name);
        }
        if !self.tags.is_empty() {
            status["tags"] = json!(self.tags);
        }
        if self.up
            && let Some(state) = &self.https
        {
            let mut https = json!({ "state": state });
            if state == "available"
                && let Some(url) = &self.https_url
            {
                https["url"] = json!(url);
            }
            status["https"] = https;
        }
        status
    }
}

impl Engine {
    fn call(&mut self, op: &str, body: Value) -> Result<Value, String> {
        match self {
            Engine::Memory(device) => device.call(op, &body),
            Engine::Process(device) => device.call(op, body),
        }
    }
}

impl MemoryDevice {
    fn call(&mut self, op: &str, body: &Value) -> Result<Value, String> {
        match op {
            "enable" => {
                let hostname = body
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or("rex");
                self.hostname = hostname.to_string();
                self.allow_members = body
                    .get("allow_tailnet_members")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let key = body.get("auth_key").and_then(Value::as_str).unwrap_or("");
                let tags = body
                    .get("advertise_tags")
                    .and_then(Value::as_array)
                    .map(|tags| {
                        tags.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                self.tags = tags;
                if self.signed_in || key == "test-key" {
                    self.signed_in = true;
                    self.account = Some("alice@example.com".into());
                    self.tailnet_name = Some("example.com".into());
                    self.dns_name = Some(format!("{hostname}.example.ts.net"));
                    self.phase = "running".into();
                    self.https = Some("available".into());
                    self.auth_url = None;
                } else if key == "approve" {
                    self.phase = "needs_machine_approval".into();
                    self.https = Some("pending".into());
                } else if key == "slow" {
                    return Err("timed out".into());
                } else {
                    self.phase = "needs_login".into();
                    self.auth_url = Some("https://login.tailscale.com/a/example".into());
                    self.https = Some("pending".into());
                }
            }
            "set_members" => {
                self.allow_members = body
                    .get("allow_tailnet_members")
                    .and_then(Value::as_bool)
                    .unwrap_or(self.allow_members);
            }
            "disable" => {
                self.phase = "disabled".into();
                self.https = None;
                self.auth_url = None;
            }
            "login" => {
                if self.auth_url.is_none() {
                    self.auth_url = Some("https://login.tailscale.com/a/example".into());
                }
                if self.phase != "running" {
                    self.phase = "needs_login".into();
                }
            }
            "logout" => {
                if self.hostname == "stuck" {
                    return Err("Tailscale did not answer within 10 seconds".into());
                }
                self.signed_in = false;
                self.account = None;
                self.phase = "disabled".into();
                self.https = None;
                self.auth_url = None;
                self.dns_name = None;
            }
            "rename" => {
                let hostname = body
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or("rex");
                self.hostname = hostname.to_string();
                if self.dns_name.is_some() {
                    self.dns_name = Some(format!("{hostname}.example.ts.net"));
                }
            }
            _ => return Err(format!("unknown op {op}")),
        }
        let mut status = self.status();
        if op == "disable" || op == "logout" {
            status["state"] = json!("disabled");
            status.as_object_mut().unwrap().remove("https");
            status.as_object_mut().unwrap().remove("auth_url");
        }
        Ok(status)
    }

    fn status(&self) -> Value {
        let mut status = json!({
            "state": self.phase,
            "allow_tailnet_members": self.allow_members,
        });
        if let Some(name) = &self.dns_name {
            status["dns_name"] = json!(name);
        }
        if let Some(url) = &self.auth_url {
            status["auth_url"] = json!(url);
        }
        if let Some(login) = &self.account {
            status["account"] = json!({ "login_name": login });
        }
        if let Some(name) = &self.tailnet_name {
            status["tailnet_name"] = json!(name);
        }
        if !self.tags.is_empty() {
            status["tags"] = json!(self.tags);
        }
        if let Some(state) = &self.https {
            let mut https = json!({ "state": state });
            if state == "available"
                && let Some(name) = &self.dns_name
            {
                https["url"] = json!(format!("https://{name}"));
            }
            status["https"] = https;
        }
        status
    }
}

impl ProcessDevice {
    fn call(&mut self, op: &str, mut body: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(object) = body.as_object_mut() {
            object.insert("id".into(), json!(id));
            object.insert("op".into(), json!(op));
        } else {
            body = json!({ "id": id, "op": op });
        }
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let line = serde_json::to_string(&body).map_err(|error| error.to_string())?;
        writeln!(self.stdin, "{line}").map_err(|error| error.to_string())?;
        let timeout = if op == "login" || op == "logout" {
            LOGIN_TIMEOUT
        } else {
            Duration::from_secs(30)
        };
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err("Tailscale did not answer within 10 seconds".into())
            }
        }
    }
}

impl Drop for ProcessDevice {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_sidecar(
    stdout: impl std::io::Read,
    pending: Arc<Mutex<HashMap<u64, Sender<Result<Value, String>>>>>,
    node: Arc<Mutex<Option<Arc<TsnetNode>>>>,
) {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if value.get("event").and_then(Value::as_str) == Some("status") {
            if let Some(status) = value.get("status").cloned()
                && let Some(node) = node.lock().unwrap().clone()
            {
                node.merge_status(&status);
            }
            continue;
        }
        let Some(id) = value.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let Some(tx) = pending.lock().unwrap().remove(&id) else {
            continue;
        };
        if value.get("ok").and_then(Value::as_bool) == Some(true) {
            let _ = tx.send(Ok(value
                .get("status")
                .cloned()
                .unwrap_or_else(|| json!({}))));
        } else {
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("tailscale sidecar failed")
                .to_string();
            let _ = tx.send(Err(message));
        }
    }
}

pub fn validate_hostname(hostname: &str) -> Result<(), ApiError> {
    let bytes = hostname.as_bytes();
    let ok = (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !hostname.starts_with('-')
        && !hostname.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "hostname must be 1 to 63 ASCII letters, digits, and hyphens, and must not start or end with a hyphen",
        ))
    }
}

fn valid_tag(tag: &str) -> bool {
    let Some(name) = tag.strip_prefix("tag:") else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        && name.len() <= 63
}

pub fn locate_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUX_TSNET_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    for name in ["rux-tsnet", "rux-tsnet.exe"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn read_auth_key(path: &Path) -> Result<String, String> {
    let text = if path == Path::new("-") {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)
            .map_err(|error| error.to_string())?;
        buffer
    } else {
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?
    };
    let key = text.trim().to_string();
    if key.is_empty() {
        return Err("tailscale auth key is empty".into());
    }
    Ok(key)
}

/// Identity the sidecar stamps on a proxied request. The token is a process
/// secret; a header without it is ignored.
pub fn principal_from_headers(
    token: &str,
    presented: Option<&str>,
    user_id: Option<&str>,
    login_name: Option<&str>,
    node: Option<&str>,
    tags: Option<&str>,
    remote: Option<&str>,
) -> Option<Value> {
    let presented = presented?;
    if presented.len() != token.len() {
        return None;
    }
    let mismatch = presented
        .bytes()
        .zip(token.bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right));
    if mismatch != 0 {
        return None;
    }
    let login_name = login_name.filter(|value| !value.is_empty());
    let node = node.filter(|value| !value.is_empty());
    let user_id = user_id.filter(|value| !value.is_empty());
    let tags: Vec<&str> = tags
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .collect();
    if user_id.is_none() && tags.is_empty() {
        return None;
    }
    let display = login_name.or(node).unwrap_or("tailscale").to_string();
    let mut principal = json!({
        "kind": "tailscale",
        "transport": "tailscale",
        "display": display,
    });
    if let Some(user_id) = user_id {
        principal["user_id"] = json!(user_id);
    }
    if let Some(login_name) = login_name {
        principal["login_name"] = json!(login_name);
    }
    if let Some(node) = node {
        principal["node"] = json!(node);
    }
    if !tags.is_empty() {
        principal["tags"] = json!(tags);
    }
    if let Some(remote) = remote.filter(|value| !value.is_empty()) {
        principal["remote_addr"] = json!(remote);
    }
    Some(principal)
}

/// Shared with the sidecar: a tagged device has no owner, so it is admitted
/// only when members are allowed. Otherwise only the device owner's user id.
pub fn admit_peer(
    owner_user: Option<&str>,
    peer_user: Option<&str>,
    peer_tagged: bool,
    allow_members: bool,
) -> bool {
    if peer_tagged {
        return allow_members;
    }
    if allow_members {
        return peer_user.is_some();
    }
    match (owner_user, peer_user) {
        (Some(owner), Some(peer)) => owner == peer && !owner.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> Value {
        let help: Value = serde_json::from_str(include_str!("../assets/api-help.json")).unwrap();
        help["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|method| method["name"] == "server.tailscale.enable")
            .unwrap()["output_schema"]
            .clone()
    }

    #[test]
    fn memory_device_follows_enable_login_logout_and_rename() {
        let node = TsnetNode::memory();
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = events.clone();
        node.set_on_change(move |status| recorded.lock().unwrap().push(status));

        let missing = node
            .enable(EnableRequest {
                hostname: None,
                allow_members: false,
                auth_key: None,
                advertise_tags: vec!["tag:rex".into()],
            })
            .unwrap_err();
        assert_eq!(missing.code, "bad_request");

        let bad_tag = node
            .enable(EnableRequest {
                hostname: Some("rex".into()),
                allow_members: true,
                auth_key: None,
                advertise_tags: vec!["rex".into()],
            })
            .unwrap_err();
        assert!(
            bad_tag.message.contains("invalid Tailscale tag"),
            "{}",
            bad_tag.message
        );

        let started = node
            .enable(EnableRequest {
                hostname: Some("rex".into()),
                allow_members: false,
                auth_key: None,
                advertise_tags: Vec::new(),
            })
            .unwrap();
        crate::schema::validate(&schema(), &started).unwrap();
        assert_eq!(started["tailscale"]["state"], "needs_login");
        assert!(started["tailscale"]["auth_url"].is_string());
        assert_eq!(started["tailscale"]["https"]["state"], "pending");

        let again = node.login().unwrap();
        assert_eq!(
            again["tailscale"]["auth_url"],
            started["tailscale"]["auth_url"]
        );

        node.disable().unwrap();
        assert_eq!(node.snapshot()["state"], "disabled");
        assert!(node.snapshot().get("https").is_none());

        let off = node.login().unwrap_err();
        assert_eq!(off.code, "conflict");

        let running = node
            .enable(EnableRequest {
                hostname: Some("rex".into()),
                allow_members: true,
                auth_key: Some("test-key".into()),
                advertise_tags: vec!["tag:rex".into()],
            })
            .unwrap();
        assert_eq!(running["tailscale"]["state"], "running");
        assert_eq!(running["tailscale"]["dns_name"], "rex.example.ts.net");
        assert_eq!(running["tailscale"]["https"]["state"], "available");
        assert_eq!(
            running["tailscale"]["https"]["url"],
            "https://rex.example.ts.net"
        );
        assert_eq!(
            running["tailscale"]["account"]["login_name"],
            "alice@example.com"
        );
        assert_eq!(running["tailscale"]["tags"][0], "tag:rex");
        assert!(running["tailscale"].get("auth_url").is_none());
        assert!(!running.to_string().contains("test-key"));

        let renamed = node.rename("studio").unwrap();
        assert_eq!(renamed["tailscale"]["dns_name"], "rex.example.ts.net");
        assert_eq!(node.snapshot()["dns_name"], "studio.example.ts.net");
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|status| status["dns_name"] == "studio.example.ts.net")
        );

        let bad_name = node.rename("-no").unwrap_err();
        assert_eq!(bad_name.code, "bad_request");

        node.logout().unwrap();
        assert_eq!(node.snapshot()["state"], "disabled");
        assert!(node.snapshot().get("account").is_none());
        let fresh = node
            .enable(EnableRequest {
                hostname: None,
                allow_members: false,
                auth_key: None,
                advertise_tags: Vec::new(),
            })
            .unwrap();
        assert_eq!(fresh["tailscale"]["state"], "needs_login");

        node.note_https_failure("https listener failed");
        assert_eq!(node.snapshot()["state"], "disabled");
        assert!(
            node.snapshot()["error"]
                .as_str()
                .unwrap()
                .contains("https listener")
        );
        let cleared = node
            .enable(EnableRequest {
                hostname: Some("rex".into()),
                allow_members: false,
                auth_key: Some("test-key".into()),
                advertise_tags: Vec::new(),
            })
            .unwrap();
        assert!(cleared["tailscale"].get("error").is_none(), "{cleared}");
    }

    #[test]
    fn owner_policy_matches_the_built_in_column() {
        assert!(admit_peer(Some("user-1"), Some("user-1"), false, false));
        assert!(!admit_peer(Some("user-1"), Some("user-2"), false, false));
        assert!(admit_peer(Some("user-1"), Some("user-2"), false, true));
        assert!(!admit_peer(None, Some("user-2"), true, false));
        assert!(admit_peer(None, None, true, true));
        assert!(!admit_peer(None, None, false, false));
    }

    #[test]
    fn principal_requires_the_sidecar_token() {
        let principal = principal_from_headers(
            "secret",
            Some("secret"),
            Some("user-1"),
            Some("alice@example.com"),
            Some("laptop"),
            Some("tag:ci"),
            Some("100.1.2.3:1"),
        )
        .unwrap();
        assert_eq!(principal["kind"], "tailscale");
        assert_eq!(principal["transport"], "tailscale");
        assert_eq!(principal["login_name"], "alice@example.com");
        assert_eq!(principal["tags"][0], "tag:ci");
        assert!(
            principal_from_headers(
                "secret",
                Some("nope"),
                Some("user-1"),
                None,
                None,
                None,
                None
            )
            .is_none()
        );
        assert!(
            principal_from_headers("secret", Some("secret"), None, None, None, None, None)
                .is_none()
        );
    }

    #[test]
    fn protocol_client_reads_a_sidecar_status() {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(
                r#"
import json,sys,time
for line in sys.stdin:
    req=json.loads(line)
    status={"state":"needs_login","allow_tailnet_members":False,"auth_url":"https://login.tailscale.com/a/from-sidecar","https":{"state":"pending"}}
    sys.stdout.write(json.dumps({"id":req["id"],"ok":True,"status":status})+"\n")
    sys.stdout.flush()
    time.sleep(0.2)
    sys.stdout.write(json.dumps({"event":"status","status":{"state":"running","allow_tailnet_members":False,"dns_name":"rex.example.ts.net","account":{"login_name":"alice@example.com"},"tailnet_name":"example.com","https":{"state":"available","url":"https://rex.example.ts.net"}}})+"\n")
    sys.stdout.flush()
"#,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let slot = Arc::new(Mutex::new(None));
        let reader_slot = slot.clone();
        let reader_pending = pending.clone();
        std::thread::spawn(move || read_sidecar(stdout, reader_pending, reader_slot));
        let node = Arc::new(TsnetNode::from_engine(Engine::Process(ProcessDevice {
            child,
            stdin,
            pending,
            next_id: 1,
        })));
        *slot.lock().unwrap() = Some(node.clone());
        let started = node
            .enable(EnableRequest {
                hostname: Some("rex".into()),
                allow_members: false,
                auth_key: None,
                advertise_tags: Vec::new(),
            })
            .unwrap();
        assert_eq!(started["tailscale"]["state"], "needs_login");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while node.snapshot()["state"] != "running" && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(node.snapshot()["state"], "running");
        assert_eq!(
            node.snapshot()["https"]["url"],
            "https://rex.example.ts.net"
        );
    }
}
