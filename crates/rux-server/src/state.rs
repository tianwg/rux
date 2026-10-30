//! Server state: sessions, windows, layers, blocks, clients.

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rux_proto::*;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use crate::config::LuaConfig;
use crate::terminal::Terminal;

/// Enough to start `rux-tsnet` on `--tailscale` or the first enable call.
#[derive(Clone)]
pub struct TsnetLaunch {
    pub bin: PathBuf,
    pub state_dir: PathBuf,
    pub backend: String,
}

pub struct State {
    pub instance_id: String,
    pub host_id: String,
    pub started_at: DateTime<Utc>,
    pub uid: u32,
    pub pid: u32,
    /// Primary listen address as a URL ("unix:///…/server.sock"), handed to
    /// terminal children as REX_SERVER so tools inside a terminal can find
    /// their server. Set once by main after startup args are resolved;
    /// stays None for states that do not serve.
    pub server_addr: Mutex<Option<String>>,
    /// From `--log-path`. Kept for the process; `server.status` does not report it.
    #[allow(dead_code)]
    pub log_path: String,
    pub state_dir: Option<PathBuf>,
    pub hosts_path: Option<PathBuf>,
    pub hosts_store_error: Mutex<Option<String>>,
    pub hosts: Mutex<Vec<Value>>,
    pub hidden_host_ids: Mutex<HashSet<String>>,
    pub config: Mutex<LuaConfig>,
    pub sessions: Mutex<Vec<Session>>,
    pub clients: Mutex<HashMap<String, ClientHandle>>,
    pub pending_performs: Mutex<HashMap<String, PendingPerform>>,
    pub perform_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub perform_waiting: Mutex<HashMap<String, usize>>,
    pub perform_sequence: AtomicU64,
    /// session id -> subscribed client ids
    pub subs: Mutex<HashMap<String, Vec<String>>>,
    pub tickets: Mutex<HashMap<String, Ticket>>,
    /// Data streams parked for a resume, by reconnect token.
    pub parked_streams: Mutex<HashMap<String, ParkedStream>>,
    /// Live data streams, by (client, block, data ref) key.
    pub live_streams: Mutex<HashMap<String, LiveStream>>,
    pub help: Value,
    pub creators: Value,
    /// Set by `server.stop` after the reply is ready. Tests observe this
    /// instead of exiting the process.
    pub shutting_down: AtomicBool,
    /// Per-client script inboxes. Events are the same objects sent on the socket.
    pub script_events: Mutex<HashMap<String, std::sync::mpsc::Sender<Value>>>,
    /// Built-in Tailscale, after `--tailscale` or `server.tailscale.enable`.
    /// Host `tailscaled` mode leaves this empty so the sidecar is not a second node.
    pub tsnet: Mutex<Option<Arc<crate::tsnet::TsnetNode>>>,
    /// How to start the sidecar later. Set when `rux-tsnet` is installed, without starting it.
    pub tsnet_launch: Mutex<Option<TsnetLaunch>>,
    /// Shared secret the sidecar must present. Absent until a sidecar starts.
    pub tsnet_token: Mutex<Option<String>>,
    /// `0` means no cap. `session.create` returns `conflict` at the cap.
    pub max_sessions: AtomicU64,
    /// Personal servers stop after the last session and connection close.
    pub exit_empty: AtomicBool,
}

/// True once an `--exit-empty` server has had no sessions and no clients
/// for about ten seconds.
pub fn idle_exit_ready(enabled: bool, busy: bool, idle_for: std::time::Duration) -> bool {
    enabled && !busy && idle_for >= std::time::Duration::from_secs(10)
}

pub struct ClientHandle {
    pub id: String,
    pub info: ClientInfo,
    pub principal: Value,
    pub actions: Option<Vec<Value>>,
    pub all_events: bool,
    pub connection_state: String,
    pub connected_at: DateTime<Utc>,
    pub tx: tokio::sync::mpsc::UnboundedSender<ServerMessage>,
    pub seq: Arc<AtomicU64>,
    pub send_lock: Arc<Mutex<()>>,
}

pub struct PendingPerform {
    pub requester_id: String,
    pub target_client_id: String,
    pub reply: tokio::sync::oneshot::Sender<Result<Value, ApiError>>,
}

/// A data stream parked after its connection dropped, waiting out
/// the resume grace period. The output subscription stays
/// registered, so output keeps queueing (bounded by the usual
/// per-subscriber hard budget); `history` retains the most recent
/// sent bytes for replay, starting at absolute stream offset
/// `history_start`, with `sent_total` the offset just past the last
/// byte ever sent on the stream.
pub struct ParkedStream {
    /// (client, block, data ref) identity, for superseding on a
    /// fresh HELLO and for the one-live-stream rule.
    pub key: String,
    pub session_id: String,
    pub block_id: String,
    pub subprotocol: Option<String>,
    pub term: Arc<crate::terminal::Terminal>,
    pub owner: Option<String>,
    pub nonce: u64,
    pub subscription: crate::terminal::OutputSubscription,
    pub events: tokio::sync::broadcast::Receiver<Value>,
    pub history: std::collections::VecDeque<Vec<u8>>,
    pub history_start: u64,
    pub sent_total: u64,
    pub parked_at: std::time::Instant,
}

/// A live data stream's registry entry: its current reconnect token
/// and a handle the resume path fires to make the owning connection
/// park the stream and hand it over.
pub struct LiveStream {
    pub token: String,
    pub supersede: Arc<tokio::sync::Notify>,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub session_id: String,
    pub block_id: String,
    pub data_ref_id: String,
    pub subprotocol: Option<String>,
    #[allow(dead_code)]
    pub client_id: String,
    pub expires_at: std::time::Instant,
}

pub struct Session {
    pub id: String,
    pub label: String,
    pub revision: u64,
    pub windows: Vec<Window>,
    pub active_window: Option<String>,
    pub blocks: IndexMap<String, Block>,
}

pub struct Window {
    pub id: String,
    pub label: String,
    pub focused_block: Option<String>,
    pub zoomed_block: Option<String>,
    pub layers: Vec<Layer>,
}

pub struct Layer {
    pub id: String,
    pub kind: String,
    pub bounds: Rect,
    pub layout: Option<Layout>,
}

#[derive(Clone)]
pub enum Layout {
    Leaf {
        rect: Rect,
        block_id: String,
    },
    Split {
        rect: Rect,
        split_id: String,
        direction: String,
        ratio: f64,
        before: Box<Layout>,
        after: Box<Layout>,
    },
}

pub struct Block {
    pub id: String,
    pub label: String,
    pub creator_name: String,
    pub flavor: String,
    pub host_id: String,
    pub owner: Option<String>,
    pub terminal: Option<Arc<Terminal>>,
    pub onboarding: Option<Arc<Mutex<OnboardingState>>>,
}

pub struct OnboardingState {
    pub generation: u64,
    pub step: String,
}

fn default_data_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("REX_DATA_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    #[cfg(target_os = "macos")]
    {
        return std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/rex"));
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            if !dir.is_empty() {
                return Some(PathBuf::from(dir).join("rex"));
            }
        }
        return std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/rex"));
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("rex"));
    }
    #[allow(unreachable_code)]
    None
}

/// The host identity is stable across server restarts. The real server keeps
/// it in its data directory, so reuse that file when it exists.
fn load_or_create_host_id(state_dir: Option<&Path>) -> String {
    let Some(dir) = state_dir else {
        return uuid::Uuid::new_v4().to_string();
    };
    let path = dir.join("host-id");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(id) = uuid::Uuid::parse_str(text.trim()) {
            return id.to_string();
        }
        tracing::warn!(path = %path.display(), "ignoring invalid host-id file");
        return uuid::Uuid::new_v4().to_string();
    }

    let id = uuid::Uuid::new_v4();
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        writeln!(file, "{id}")?;
        Ok(())
    };
    if let Err(err) = write() {
        // Another server may have won the race; prefer its id.
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(existing) = uuid::Uuid::parse_str(text.trim()) {
                return existing.to_string();
            }
        }
        tracing::warn!(path = %path.display(), %err, "could not persist host-id");
    }
    id.to_string()
}

fn load_hosts(path: Option<&Path>) -> (Vec<Value>, HashSet<String>, Option<String>) {
    let Some(path) = path else {
        return (Vec::new(), HashSet::new(), None);
    };
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() <= 1024 * 1024 => match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Array(hosts)) => (hosts, HashSet::new(), None),
            Ok(Value::Object(mut store)) => {
                let hosts = store
                    .remove("hosts")
                    .and_then(|value| value.as_array().cloned())
                    .unwrap_or_default();
                let hidden = store
                    .remove("removed")
                    .and_then(|value| value.as_array().cloned())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|value| value.as_str().map(str::to_string))
                    .collect();
                (hosts, hidden, None)
            }
            Ok(_) => (
                Vec::new(),
                HashSet::new(),
                Some(format!(
                    "{}: host store must be an array or object",
                    path.display()
                )),
            ),
            Err(err) => (
                Vec::new(),
                HashSet::new(),
                Some(format!("{}: {err}", path.display())),
            ),
        },
        Ok(_) => (
            Vec::new(),
            HashSet::new(),
            Some(format!("{}: host store exceeds 1 MiB", path.display())),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            (Vec::new(), HashSet::new(), None)
        }
        Err(err) => (
            Vec::new(),
            HashSet::new(),
            Some(format!("{}: {err}", path.display())),
        ),
    }
}

/// The version string reported as `rex_version` by server.version and as
/// TERM_PROGRAM_VERSION to terminal children.
pub fn rex_version() -> String {
    format!("{}-rux", env!("CARGO_PKG_VERSION"))
}

impl State {
    pub fn new(
        help: Value,
        creators: Value,
        log_path: String,
        state_dir: Option<PathBuf>,
        config_path: PathBuf,
    ) -> Self {
        let state_dir = state_dir.or_else(default_data_dir);
        let host_id = load_or_create_host_id(state_dir.as_deref());
        let hosts_path = state_dir.as_ref().map(|dir| dir.join("hosts.json"));
        let (hosts, hidden_host_ids, hosts_store_error) = load_hosts(hosts_path.as_deref());
        let instance_id = uuid::Uuid::now_v7().to_string();
        let config = LuaConfig::load(config_path, 1, &instance_id);
        Self {
            instance_id,
            host_id,
            started_at: Utc::now(),
            uid: unsafe { libc_getuid() },
            pid: std::process::id(),
            server_addr: Mutex::new(None),
            log_path,
            state_dir,
            hosts_path,
            hosts_store_error: Mutex::new(hosts_store_error),
            hosts: Mutex::new(hosts),
            hidden_host_ids: Mutex::new(hidden_host_ids),
            config: Mutex::new(config),
            sessions: Mutex::new(Vec::new()),
            clients: Mutex::new(HashMap::new()),
            pending_performs: Mutex::new(HashMap::new()),
            perform_locks: Mutex::new(HashMap::new()),
            perform_waiting: Mutex::new(HashMap::new()),
            perform_sequence: AtomicU64::new(0),
            subs: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            parked_streams: Mutex::new(HashMap::new()),
            live_streams: Mutex::new(HashMap::new()),
            help,
            creators,
            shutting_down: AtomicBool::new(false),
            script_events: Mutex::new(HashMap::new()),
            tsnet: Mutex::new(None),
            tsnet_launch: Mutex::new(None),
            tsnet_token: Mutex::new(None),
            max_sessions: AtomicU64::new(0),
            exit_empty: AtomicBool::new(false),
        }
    }

    pub fn busy(&self) -> bool {
        !self.sessions.lock().unwrap().is_empty() || !self.clients.lock().unwrap().is_empty()
    }

    /// Starts the sidecar once. Host tailnet mode never calls this at startup.
    pub fn ensure_tsnet(self: &Arc<Self>) -> Result<Arc<crate::tsnet::TsnetNode>, String> {
        let mut slot = self.tsnet.lock().unwrap();
        if let Some(node) = slot.clone() {
            return Ok(node);
        }
        let launch = self
            .tsnet_launch
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "rux-tsnet is not installed".to_string())?;
        std::fs::create_dir_all(&launch.state_dir)
            .map_err(|err| format!("creating {}: {err}", launch.state_dir.display()))?;
        let token = uuid::Uuid::now_v7().simple().to_string();
        let node = crate::tsnet::TsnetNode::spawn(
            &launch.bin,
            &launch.state_dir,
            &launch.backend,
            &token,
        )?;
        let emit = Arc::downgrade(self);
        node.set_on_change(move |status| {
            if let Some(state) = emit.upgrade() {
                state.emit_tailscale_status(status);
            }
        });
        *self.tsnet_token.lock().unwrap() = Some(token);
        *slot = Some(node.clone());
        Ok(node)
    }

    /// Drop clients that came in through built-in Tailscale. Sessions stay.
    pub fn disconnect_tailscale_clients(&self) {
        let ids: Vec<String> = self
            .clients
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, client)| {
                client.principal.get("transport").and_then(Value::as_str) == Some("tailscale")
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.remove_client(&id);
        }
    }

    pub fn host_store_error(&self) -> Option<String> {
        self.hosts_store_error.lock().unwrap().clone()
    }

    pub fn principal(&self) -> Value {
        json!({
            "kind": "peer",
            "transport": "unix",
            "display": format!("uid {}", self.uid),
            "uid": self.uid,
            "gid": unsafe { libc_getgid() },
            "pid": self.pid,
        })
    }

    // -- clients ---------------------------------------------------------

    pub fn register_client(
        &self,
        info: ClientInfo,
        tx: tokio::sync::mpsc::UnboundedSender<ServerMessage>,
        principal: Value,
    ) -> (String, Arc<AtomicU64>, Arc<Mutex<()>>) {
        let id = ids::client();
        let seq = Arc::new(AtomicU64::new(0));
        let send_lock = Arc::new(Mutex::new(()));
        let handle = ClientHandle {
            id: id.clone(),
            info: info.clone(),
            principal,
            actions: None,
            all_events: false,
            connection_state: "connected".into(),
            connected_at: Utc::now(),
            tx,
            seq: seq.clone(),
            send_lock: send_lock.clone(),
        };
        self.clients.lock().unwrap().insert(id.clone(), handle);
        self.emit_server_event_except(
            json!({
                "type": "client_joined",
                "payload": { "client": self.client_json(&id) },
            }),
            Some(&id),
        );
        (id, seq, send_lock)
    }

    pub fn client_principal(&self, id: &str) -> Value {
        self.clients
            .lock()
            .unwrap()
            .get(id)
            .map(|client| client.principal.clone())
            .unwrap_or_else(|| self.principal())
    }

    pub fn client_actions(&self, id: &str) -> Option<Vec<Value>> {
        self.clients
            .lock()
            .unwrap()
            .get(id)
            .and_then(|client| client.actions.clone())
    }

    pub fn send_client_event(&self, id: &str, event: Value) -> bool {
        let clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(id) {
            send_event(client, event);
            true
        } else {
            false
        }
    }

    pub fn set_client_all_events(&self, id: &str, enabled: bool) {
        if let Some(client) = self.clients.lock().unwrap().get_mut(id) {
            client.all_events = enabled;
        }
    }

    pub fn emit_all_clients_event(&self, event: Value) {
        let clients = self.clients.lock().unwrap();
        for client in clients.values().filter(|client| client.all_events) {
            send_event(client, event.clone());
        }
    }

    pub fn perform_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.perform_locks
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub fn enqueue_perform(&self, id: &str) -> bool {
        let mut queues = self.perform_waiting.lock().unwrap();
        let count = queues.entry(id.to_string()).or_default();
        if *count >= 16 {
            return false;
        }
        *count += 1;
        true
    }

    pub fn dequeue_perform(&self, id: &str) {
        let mut queues = self.perform_waiting.lock().unwrap();
        if let Some(count) = queues.get_mut(id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                queues.remove(id);
            }
        }
    }

    pub fn client_json(&self, id: &str) -> Value {
        let clients = self.clients.lock().unwrap();
        match clients.get(id) {
            Some(c) => json!({
                "client_id": c.id,
                "info": c.info,
                "principal": c.principal,
                "connected_at": c.connected_at,
                "connection_state": c.connection_state,
            }),
            None => Value::Null,
        }
    }

    pub fn note_client_connection(&self, client_id: &str, connection_state: &str) {
        let principal = {
            let mut clients = self.clients.lock().unwrap();
            let Some(client) = clients.get_mut(client_id) else {
                return;
            };
            if client.connection_state == connection_state {
                return;
            }
            client.connection_state = connection_state.to_string();
            client.principal.clone()
        };
        let session_ids: Vec<String> = self
            .subs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, clients)| clients.iter().any(|id| id == client_id))
            .map(|(id, _)| id.clone())
            .collect();
        for sid in session_ids {
            self.emit_to_session(
                &sid,
                session_event(
                    &sid,
                    json!({
                        "type": "client_connection_changed",
                        "payload": {
                            "client_id": client_id,
                            "principal": principal,
                            "connection_state": connection_state,
                        },
                    }),
                ),
            );
        }
    }

    pub fn emit_creator_changed(&self) {
        let session_ids: Vec<String> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|session| session.id.clone())
            .collect();
        for sid in session_ids {
            self.emit_to_session(
                &sid,
                session_event(&sid, json!({ "type": "creator_changed", "payload": {} })),
            );
        }
    }

    pub fn emit_tailscale_status(&self, tailscale: Value) {
        self.emit_all_clients_event(json!({
            "type": "tailscale_status_changed",
            "payload": tailscale,
        }));
    }

    pub fn remove_client(&self, client_id: &str) {
        self.note_client_connection(client_id, "lost");
        let removed = self.clients.lock().unwrap().remove(client_id);
        let Some(removed) = removed else { return };
        let cancelled: Vec<_> = {
            let mut pending = self.pending_performs.lock().unwrap();
            let ids: Vec<String> = pending
                .iter()
                .filter(|(_, call)| {
                    call.requester_id == client_id || call.target_client_id == client_id
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| pending.remove(&id))
                .collect()
        };
        for call in cancelled {
            let _ = call.reply.send(Err(ApiError::new(
                503,
                "client_unavailable",
                "client disconnected while an action was pending",
            )));
        }
        let session_ids: Vec<String> = {
            let mut subs = self.subs.lock().unwrap();
            let mut ids = Vec::new();
            for (sid, clients) in subs.iter_mut() {
                if let Some(pos) = clients.iter().position(|c| c == client_id) {
                    clients.remove(pos);
                    ids.push(sid.clone());
                }
            }
            ids
        };
        for sid in session_ids {
            let event = session_event(
                &sid,
                json!({
                    "type": "client_disconnected",
                    "payload": {
                        "client_id": client_id,
                        "principal": removed.principal,
                    },
                }),
            );
            self.emit_to_session(&sid, event);
        }
        self.emit_server_event(json!({
            "type": "client_left",
            "payload": { "client_id": client_id },
        }));
    }

    // -- events ----------------------------------------------------------

    pub fn emit_server_event(&self, payload: Value) {
        self.emit_server_event_except(payload, None);
    }

    pub fn emit_server_event_except(&self, payload: Value, skip: Option<&str>) {
        let clients = self.clients.lock().unwrap();
        let script_ids: Vec<String> = clients
            .values()
            .filter(|client| client.all_events && Some(client.id.as_str()) != skip)
            .map(|client| client.id.clone())
            .collect();
        for c in clients.values() {
            if Some(c.id.as_str()) == skip {
                continue;
            }
            send_event(c, payload.clone());
        }
        drop(clients);
        let scripts = self.script_events.lock().unwrap();
        for id in script_ids {
            if let Some(tx) = scripts.get(&id) {
                let _ = tx.send(payload.clone());
            }
        }
    }

    pub fn emit_to_session(&self, session_id: &str, payload: Value) {
        let subs = self.subscribers(session_id);
        self.fanout(&subs, payload);
    }

    pub fn subscribers(&self, session_id: &str) -> Vec<String> {
        self.subs
            .lock()
            .unwrap()
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn subscribe(&self, session_id: &str, client_id: &str) {
        let mut subs = self.subs.lock().unwrap();
        let list = subs.entry(session_id.to_string()).or_default();
        if !list.iter().any(|c| c == client_id) {
            list.push(client_id.to_string());
        }
    }

    pub fn unsubscribe(&self, session_id: &str, client_id: &str) {
        let mut subs = self.subs.lock().unwrap();
        if let Some(list) = subs.get_mut(session_id) {
            list.retain(|c| c != client_id);
        }
    }

    pub fn fanout(&self, client_ids: &[String], payload: Value) {
        let clients = self.clients.lock().unwrap();
        for id in client_ids {
            if let Some(c) = clients.get(id) {
                send_event(c, payload.clone());
            }
        }
        drop(clients);
        let scripts = self.script_events.lock().unwrap();
        for id in client_ids {
            if let Some(tx) = scripts.get(id) {
                let _ = tx.send(payload.clone());
            }
        }
    }

    // -- sessions --------------------------------------------------------

    pub fn find_session(&self, id: &str) -> Option<usize> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .position(|s| s.id == id)
    }

    pub fn session_exists(&self, id: &str) -> bool {
        self.find_session(id).is_some()
    }
}

fn send_event(client: &ClientHandle, payload: Value) {
    let _guard = client.send_lock.lock().unwrap();
    let seq = client.seq.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = client
        .tx
        .send(ServerMessage::Event(Event::new(seq, payload)));
}

pub fn session_event(session_id: &str, event: Value) -> Value {
    json!({
        "type": "session_event",
        "payload": {
            "session_id": session_id,
            "event": event,
        },
    })
}

pub fn block_event(
    session_id: &str,
    block_id: &str,
    creator_name: &str,
    name: &str,
    payload: Value,
) -> Value {
    session_event(
        session_id,
        json!({
            "type": "block_event",
            "payload": {
                "block_id": block_id,
                "creator_name": creator_name,
                "name": name,
                "payload": payload,
            },
        }),
    )
}

// -- view conversion ------------------------------------------------------

pub fn session_view(s: &Session, _host_id: &str) -> View {
    let windows = s
        .windows
        .iter()
        .map(|w| {
            let layers = w
                .layers
                .iter()
                .map(|l| LayerView {
                    layer_id: l.id.clone(),
                    kind: l.kind.clone(),
                    bounds: l.bounds,
                    layout: l.layout.as_ref().map(|n| layout_view(n, s)),
                    blocks: l
                        .layout
                        .as_ref()
                        .map(|n| {
                            let mut ids = Vec::new();
                            collect_block_ids(n, &mut ids);
                            ids.into_iter()
                                .filter_map(|id| s.blocks.get(&id))
                                .map(|b| BlockSummary {
                                    block_id: b.id.clone(),
                                    label: b.label.clone(),
                                    creator_name: b.creator_name.clone(),
                                    flavor: b.flavor.clone(),
                                    host_id: b.host_id.clone(),
                                    owner: b.owner.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect();
            WindowView {
                window_id: w.id.clone(),
                label: w.label.clone(),
                focused_block_id: w.focused_block.clone(),
                zoomed_block_id: w.zoomed_block.clone(),
                layers,
            }
        })
        .collect();
    View {
        revision: s.revision,
        session_id: s.id.clone(),
        label: s.label.clone(),
        active_window_id: s.active_window.clone(),
        windows,
    }
}

fn layout_view(n: &Layout, s: &Session) -> LayoutNode {
    match n {
        Layout::Leaf { rect, block_id } => LayoutNode {
            rect: *rect,
            block_id: Some(block_id.clone()),
            split: None,
        },
        Layout::Split {
            rect,
            split_id,
            direction,
            ratio,
            before,
            after,
        } => {
            let _ = s;
            LayoutNode {
                rect: *rect,
                block_id: None,
                split: Some(Box::new(Split {
                    split_id: split_id.clone(),
                    direction: direction.clone(),
                    ratio: *ratio,
                    before: layout_view(before, s),
                    after: layout_view(after, s),
                })),
            }
        }
    }
}

pub fn collect_block_ids(n: &Layout, out: &mut Vec<String>) {
    match n {
        Layout::Leaf { block_id, .. } => out.push(block_id.clone()),
        Layout::Split { before, after, .. } => {
            collect_block_ids(before, out);
            collect_block_ids(after, out);
        }
    }
}

// -- layout mutation ------------------------------------------------------

/// Split the node that holds `anchor` (a block id or split id) and return the
/// new split id. `new_layout` is inserted on `side`.
pub fn split_at(
    node: &mut Layout,
    anchor: &str,
    direction: &str,
    side: &str,
    ratio: f64,
    new_layout: Layout,
) -> Option<String> {
    let is_anchor = match node {
        Layout::Split { split_id, .. } => split_id == anchor,
        Layout::Leaf { block_id, .. } => block_id == anchor,
    };

    if is_anchor {
        let old = node.clone();
        let old_rect = match &old {
            Layout::Leaf { rect, .. } => *rect,
            Layout::Split { rect, .. } => *rect,
        };
        let mut fresh = new_layout;
        set_rect(
            &mut fresh,
            split_rect(old_rect, direction, ratio, side == "before"),
        );
        let (b, a) = if side == "before" {
            (fresh, old)
        } else {
            (old, fresh)
        };
        let sid = ids::split();
        *node = Layout::Split {
            rect: old_rect,
            split_id: sid.clone(),
            direction: direction.to_string(),
            ratio,
            before: Box::new(b),
            after: Box::new(a),
        };
        reflow(node);
        return Some(sid);
    }

    if let Layout::Split { before, after, .. } = node {
        if let Some(sid) = split_at(before, anchor, direction, side, ratio, new_layout.clone()) {
            return Some(sid);
        }
        if let Some(sid) = split_at(after, anchor, direction, side, ratio, new_layout) {
            return Some(sid);
        }
    }
    None
}

pub fn set_rect(n: &mut Layout, rect: Rect) {
    match n {
        Layout::Leaf { rect: r, .. } => *r = rect,
        Layout::Split {
            rect: r,
            before,
            after,
            direction,
            ratio,
            ..
        } => {
            *r = rect;
            let br = split_rect(rect, direction, *ratio, true);
            let ar = split_rect(rect, direction, *ratio, false);
            set_rect(before, br);
            set_rect(after, ar);
        }
    }
}

/// Recompute every rect under `node` from its own rect.
pub fn reflow(n: &mut Layout) {
    let rect = match n {
        Layout::Leaf { rect, .. } => *rect,
        Layout::Split { rect, .. } => *rect,
    };
    set_rect(n, rect);
}

/// What happened when a block was removed from a layout tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveResult {
    /// The block was not in this layout.
    NotFound,
    /// The layout was a leaf holding the block; the caller should clear it.
    RootLeaf,
    /// The block was removed from a split, which collapsed. The split's id is
    /// returned so callers can report it.
    Collapsed(String),
}

/// Remove `block_id` from the tree. When a split loses one of its two leaf
/// children, the surviving child takes over the split's full rectangle.
pub fn remove_block_tracked(n: &mut Layout, block_id: &str) -> RemoveResult {
    match n {
        Layout::Leaf { block_id: id, .. } => {
            if id == block_id {
                RemoveResult::RootLeaf
            } else {
                RemoveResult::NotFound
            }
        }
        Layout::Split {
            rect,
            split_id,
            before,
            after,
            ..
        } => {
            let full = *rect;
            let split_id = split_id.clone();
            if let Layout::Leaf { block_id: id, .. } = before.as_ref() {
                if id == block_id {
                    let mut keep = after.as_ref().clone();
                    set_rect(&mut keep, full);
                    *n = keep;
                    return RemoveResult::Collapsed(split_id);
                }
            }
            if let Layout::Leaf { block_id: id, .. } = after.as_ref() {
                if id == block_id {
                    let mut keep = before.as_ref().clone();
                    set_rect(&mut keep, full);
                    *n = keep;
                    return RemoveResult::Collapsed(split_id);
                }
            }
            match remove_block_tracked(before, block_id) {
                RemoveResult::NotFound => {}
                result => {
                    reflow(n);
                    return result;
                }
            }
            match remove_block_tracked(after, block_id) {
                RemoveResult::NotFound => {}
                result => {
                    reflow(n);
                    return result;
                }
            }
            RemoveResult::NotFound
        }
    }
}

pub fn contains_block(n: &Layout, block_id: &str) -> bool {
    match n {
        Layout::Leaf { block_id: id, .. } => id == block_id,
        Layout::Split { before, after, .. } => {
            contains_block(before, block_id) || contains_block(after, block_id)
        }
    }
}

/// Replace one block id in a layout tree. Returns whether anything changed.
pub fn replace_block_id(n: &mut Layout, from: &str, to: &str) -> bool {
    match n {
        Layout::Leaf { block_id, .. } => {
            if block_id == from {
                *block_id = to.to_string();
                true
            } else {
                false
            }
        }
        Layout::Split { before, after, .. } => {
            let a = replace_block_id(before, from, to);
            let b = replace_block_id(after, from, to);
            a || b
        }
    }
}

pub fn collect_split_ids(n: &Layout, out: &mut Vec<String>) {
    if let Layout::Split {
        split_id,
        before,
        after,
        ..
    } = n
    {
        out.push(split_id.clone());
        collect_split_ids(before, out);
        collect_split_ids(after, out);
    }
}

/// Resize the innermost split that has `before_id` on its before side and
/// `after_id` on its after side. Returns `None` when no split matches,
/// `Some(false)` when the split already has the requested ratio, and
/// `Some(true)` when the ratio changed.
pub fn resize_split_between(
    n: &mut Layout,
    direction: &str,
    before_id: &str,
    after_id: &str,
    ratio: f64,
) -> Option<bool> {
    match n {
        Layout::Leaf { .. } => None,
        Layout::Split {
            direction: dir,
            ratio: r,
            before,
            after,
            ..
        } => {
            if let Some(changed) =
                resize_split_between(before, direction, before_id, after_id, ratio)
            {
                if changed {
                    reflow(n);
                }
                return Some(changed);
            }
            if let Some(changed) =
                resize_split_between(after, direction, before_id, after_id, ratio)
            {
                if changed {
                    reflow(n);
                }
                return Some(changed);
            }
            if dir == direction
                && contains_block(before, before_id)
                && contains_block(after, after_id)
            {
                if *r == ratio {
                    return Some(false);
                }
                *r = ratio;
                reflow(n);
                return Some(true);
            }
            None
        }
    }
}

// -- naming ---------------------------------------------------------------

const ADJECTIVES: &[&str] = &[
    "misty", "dusty", "quiet", "brave", "amber", "silver", "cobalt", "ivory", "north", "lunar",
    "rapid", "still", "wild", "soft", "hidden", "golden",
];
const NOUNS: &[&str] = &[
    "mesa", "forest", "river", "harbor", "meadow", "canyon", "summit", "island", "valley", "ridge",
    "delta", "grove", "basin", "shore", "field", "creek",
];

pub fn auto_label() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize)
        .unwrap_or(0);
    format!(
        "{}-{}",
        ADJECTIVES[n % ADJECTIVES.len()],
        NOUNS[(n / 7) % NOUNS.len()]
    )
}

pub(crate) unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

unsafe fn libc_getgid() -> u32 {
    unsafe extern "C" {
        fn getgid() -> u32;
    }
    unsafe { getgid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: &str, rect: Rect) -> Layout {
        Layout::Leaf {
            rect,
            block_id: id.to_string(),
        }
    }

    fn split(
        id: &str,
        direction: &str,
        ratio: f64,
        rect: Rect,
        before: Layout,
        after: Layout,
    ) -> Layout {
        Layout::Split {
            rect,
            split_id: id.to_string(),
            direction: direction.to_string(),
            ratio,
            before: Box::new(before),
            after: Box::new(after),
        }
    }

    #[test]
    fn removing_leaf_collapses_split_and_expands_survivor() {
        let full = [0.0, 0.0, 1.0, 1.0];
        let mut tree = split(
            "split-root",
            "horizontal",
            0.4,
            full,
            leaf("a", [0.0, 0.0, 0.4, 1.0]),
            leaf("b", [0.4, 0.0, 0.6, 1.0]),
        );

        assert_eq!(
            remove_block_tracked(&mut tree, "a"),
            RemoveResult::Collapsed("split-root".into())
        );
        assert!(
            matches!(tree, Layout::Leaf { ref block_id, rect } if block_id == "b" && rect == full)
        );
    }

    #[test]
    fn resizing_uses_innermost_matching_split_and_detects_noop() {
        let full = [0.0, 0.0, 1.0, 1.0];
        let right = [0.5, 0.0, 0.5, 1.0];
        let mut tree = split(
            "root",
            "horizontal",
            0.5,
            full,
            leaf("a", [0.0, 0.0, 0.5, 1.0]),
            split(
                "inner",
                "horizontal",
                0.5,
                right,
                leaf("b", [0.5, 0.0, 0.25, 1.0]),
                leaf("c", [0.75, 0.0, 0.25, 1.0]),
            ),
        );

        assert_eq!(
            resize_split_between(&mut tree, "horizontal", "b", "c", 0.25),
            Some(true)
        );
        assert_eq!(
            resize_split_between(&mut tree, "horizontal", "b", "c", 0.25),
            Some(false)
        );
        assert_eq!(
            resize_split_between(&mut tree, "vertical", "b", "c", 0.25),
            None
        );
        match tree {
            Layout::Split { after, .. } => match *after {
                Layout::Split {
                    ratio,
                    before,
                    after,
                    ..
                } => {
                    assert_eq!(ratio, 0.25);
                    assert!(
                        matches!(*before, Layout::Leaf { rect, .. } if rect == [0.5, 0.0, 0.125, 1.0])
                    );
                    assert!(
                        matches!(*after, Layout::Leaf { rect, .. } if rect == [0.625, 0.0, 0.375, 1.0])
                    );
                }
                _ => panic!("expected inner split"),
            },
            _ => panic!("expected root split"),
        }
    }

    #[test]
    fn splitting_an_existing_split_reflows_both_subtrees() {
        let full = [0.0, 0.0, 1.0, 1.0];
        let mut tree = split(
            "root",
            "horizontal",
            0.5,
            full,
            leaf("a", [0.0, 0.0, 0.5, 1.0]),
            leaf("b", [0.5, 0.0, 0.5, 1.0]),
        );
        let fresh = leaf("c", full);

        assert!(split_at(&mut tree, "root", "vertical", "before", 0.25, fresh).is_some());
        match tree {
            Layout::Split {
                direction,
                ratio,
                before,
                after,
                ..
            } => {
                assert_eq!(direction, "vertical");
                assert_eq!(ratio, 0.25);
                assert!(
                    matches!(*before, Layout::Leaf { block_id, rect } if block_id == "c" && rect == [0.0, 0.0, 1.0, 0.25])
                );
                match *after {
                    Layout::Split {
                        rect,
                        before,
                        after,
                        ..
                    } => {
                        assert_eq!(rect, [0.0, 0.25, 1.0, 0.75]);
                        assert!(
                            matches!(*before, Layout::Leaf { rect, .. } if rect == [0.0, 0.25, 0.5, 0.75])
                        );
                        assert!(
                            matches!(*after, Layout::Leaf { rect, .. } if rect == [0.5, 0.25, 0.5, 0.75])
                        );
                    }
                    _ => panic!("expected original split to survive"),
                }
            }
            _ => panic!("expected new outer split"),
        }
    }

    #[test]
    fn connection_creator_and_tailscale_events_use_the_documented_audience() {
        let dir = std::env::temp_dir().join(format!("rux-event-{}", uuid::Uuid::now_v7()));
        let state = State::new(
            json!({}),
            json!({}),
            String::new(),
            Some(dir.clone()),
            dir.join("init.lua"),
        );
        let sid = "session:11111111-1111-7111-8111-111111111111".to_string();
        state.sessions.lock().unwrap().push(Session {
            id: sid.clone(),
            label: String::new(),
            revision: 0,
            windows: Vec::new(),
            active_window: None,
            blocks: IndexMap::new(),
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (id, _, _) = state.register_client(
            ClientInfo::default(),
            tx,
            json!({ "kind": "peer", "transport": "unix" }),
        );
        state.subscribe(&sid, &id);
        state.note_client_connection(&id, "restored");
        let ServerMessage::Event(restored) = rx.try_recv().unwrap() else {
            panic!("expected an event");
        };
        assert_eq!(
            restored.payload["payload"]["event"]["type"],
            "client_connection_changed"
        );
        assert_eq!(
            restored.payload["payload"]["event"]["payload"]["connection_state"],
            "restored"
        );

        let (other_tx, mut other_rx) = tokio::sync::mpsc::unbounded_channel();
        let (other, _, _) = state.register_client(
            ClientInfo::default(),
            other_tx,
            json!({ "kind": "peer", "transport": "unix" }),
        );
        while rx.try_recv().is_ok() {}
        state.set_client_all_events(&other, true);
        state.emit_tailscale_status(json!({ "state": "needs_login" }));
        assert!(rx.try_recv().is_err());
        let ServerMessage::Event(status) = other_rx.try_recv().unwrap() else {
            panic!("expected an event");
        };
        assert_eq!(status.payload["type"], "tailscale_status_changed");
        assert_eq!(status.payload["payload"]["state"], "needs_login");

        state.emit_creator_changed();
        let ServerMessage::Event(creators) = rx.try_recv().unwrap() else {
            panic!("expected an event");
        };
        assert_eq!(
            creators.payload["payload"]["event"]["type"],
            "creator_changed"
        );
        assert_eq!(creators.payload["payload"]["event"]["payload"], json!({}));

        state.remove_client(&id);
        let ServerMessage::Event(lost) = rx.try_recv().unwrap() else {
            panic!("expected an event");
        };
        assert_eq!(
            lost.payload["payload"]["event"]["payload"]["connection_state"],
            "lost"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
