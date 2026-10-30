//! Control API dispatch.

use indexmap::IndexMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rux_proto::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::state::*;
use crate::terminal::{Terminal, TerminalOptions};

pub async fn dispatch(
    state: &Arc<State>,
    client_id: &str,
    local: bool,
    method: &str,
    payload: Value,
) -> Result<Value, ApiError> {
    let mut payload = payload;
    if payload.is_null() {
        payload = json!({});
    }
    if let Some(schema) = input_schema(&state.help, method) {
        crate::schema::reject(schema, &payload)?;
    }
    match method {
        "help.all" => Ok(state.help.clone()),
        "server.version" => Ok(server_version()),
        "server.status" => Ok(server_status(state, Some(client_id))),
        "server.whoami" => Ok(server_whoami(state, client_id)),
        "server.config_reload" => Ok(server_config_reload(state)),
        "server.stop" => server_stop(state, client_id, local, &payload),
        "server.tailscale.enable"
        | "server.tailscale.disable"
        | "server.tailscale.login"
        | "server.tailscale.logout"
        | "server.tailscale.rename" => tailscale_method(state, local, method, &payload),
        "block_creator.list" => Ok(block_creators(state)),
        "session.list" => Ok(json!({ "sessions": session_list(state) })),
        "session.create" => session_create(state, client_id, &payload),
        "session.attach" => session_attach(state, client_id, &payload),
        "session.attach_all" => session_attach_all(state, client_id, &payload),
        "session.bootstrap" => session_bootstrap(state, client_id, &payload),
        "session.detach" => session_detach(state, client_id, &payload),
        "session.view" => {
            let sid = req_str(&payload, "session_id")?;
            let sessions = state.sessions.lock().unwrap();
            let s = sessions
                .iter()
                .find(|s| s.id == sid)
                .ok_or_else(|| ApiError::session_not_found(&sid))?;
            Ok(serde_json::to_value(session_view(s, &state.host_id)).unwrap())
        }
        "session.destroy" => session_destroy(state, &payload),
        "session.new_window" => session_new_window(state, client_id, &payload),
        "session.new_split" => session_new_split(state, client_id, &payload),
        "session.focus_block" => session_focus_block(state, &payload),
        "session.focus_window" => session_focus_window(state, &payload),
        "session.focus_next_pane" => session_focus_relative(state, &payload, 1),
        "session.focus_previous_pane" => session_focus_relative(state, &payload, -1),
        "session.focus_next_window" => session_focus_window_relative(state, &payload, 1),
        "session.focus_previous_window" => session_focus_window_relative(state, &payload, -1),
        "session.set_label" => session_set_label(state, &payload),
        "session.set_window_label" => session_set_window_label(state, &payload),
        "session.set_block_label" => session_set_block_label(state, &payload),
        "session.close_window" => session_close_window(state, &payload),
        "session.close_layer" => session_close_layer(state, &payload),
        "session.zoom_block" => session_zoom_block(state, &payload),
        "session.focus_direction" => session_focus_direction(state, &payload),
        "session.move" => session_move(state, client_id, &payload),
        "session.move_window" => session_move_window(state, &payload),
        "session.move_block" => session_move_block(state, &payload),
        "session.swap_blocks" => session_swap_blocks(state, &payload),
        "session.resize_pane" => session_resize_pane(state, &payload),
        "session.resize_layer" => session_resize_layer(state, &payload),
        "session.float_block" => session_float_block(state, &payload),
        "session.detach_block" => session_detach_block(state, &payload),
        "session.new_layer" => session_new_layer(state, client_id, &payload),
        "session.new_block" => session_new_block(state, client_id, &payload),
        "session.raise_layer" => session_raise_layer(state, &payload, true),
        "session.lower_layer" => session_raise_layer(state, &payload, false),
        "session.own_block" => session_own_block(state, client_id, &payload),
        "session.disown_block" => session_disown_block(state, client_id, &payload),
        "session.list_blocks" => session_list_blocks(state, &payload),
        "session.describe_block" => session_describe_block(state, &payload),
        "client.key" => client_key(state, &payload),
        "session.list_clients" => {
            let sid = req_str(&payload, "session_id")?;
            Ok(json!({ "clients": client_list(state, Some(sid.as_str())) }))
        }
        "session.help" => session_help(state, &payload),
        "block.close" => block_close(state, &payload),
        "block.method" => block_method(state, Some(client_id), &payload),
        "block.event" => block_event(state, &payload),
        "client.list" => Ok(json!({
            "clients": client_list(
                state,
                opt_id_str(&payload, "session_id", "session")?.as_deref(),
            ),
        })),
        "client.set_label" => client_set_label(state, client_id, &payload),
        "client.inspect" => client_inspect(state, &payload),
        "client.keymap" => client_keymap(state, client_id, &payload),
        "client.action" => client_action(state, client_id, local, &payload).await,
        "client.perform" => client_perform(state, client_id, &payload).await,
        "client.reply" => client_reply(state, client_id, &payload),
        "client.set_script" => client_set_script(state, client_id, &payload).await,
        "hosts.list" => hosts_list(state),
        "hosts.put" => hosts_put(state, client_id, &payload),
        "hosts.remove" => hosts_remove(state, &payload),
        "data.connect" => data_connect(state, client_id, &payload),
        "target.resolve" => Ok(target_resolve(state, &payload)),
        "target.complete" => Ok(target_complete(state, &payload)),
        "server.apple.privacy_status" => {
            if !local {
                Err(ApiError::new(403, "forbidden", "this method is local-only"))
            } else {
                Ok(crate::apple::privacy_status())
            }
        }
        "server.apple.grant_file_access" => {
            if !local {
                Err(ApiError::new(403, "forbidden", "this method is local-only"))
            } else {
                apple_grant_file_access(&payload)
            }
        }
        other => Err(ApiError::method_not_found(other)),
    }
}

// -- helpers --------------------------------------------------------------

fn req_str(v: &Value, key: &str) -> Result<String, ApiError> {
    let value = v
        .get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| ApiError::bad_request(format!("{key} is required")))?;
    match id_kind(key) {
        Some(kind) => decode_id_value(&value, kind),
        None => Ok(value),
    }
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

fn id_kind(key: &str) -> Option<&'static str> {
    match key {
        "session_id" | "before_session_id" | "preferred_session_id" => Some("session"),
        "window_id" | "before_window_id" => Some("window"),
        "layer_id" | "relative_layer_id" => Some("layer"),
        "split_id" => Some("split"),
        "block_id" | "anchor_block_id" | "before_block_id" | "after_block_id"
        | "other_block_id" => Some("block"),
        "client_id" => Some("client"),
        _ => None,
    }
}

fn decode_id_value(value: &str, kind: &str) -> Result<String, ApiError> {
    let prefix = format!("{kind}:");
    let Some(raw_uuid) = value.strip_prefix(&prefix) else {
        return Err(ApiError::bad_request(format!(
            "decoding input: {kind} ID must start with \"{prefix}\": \"{value}\""
        )));
    };
    let uuid = uuid::Uuid::parse_str(raw_uuid).map_err(|_| {
        let reason = if raw_uuid.len() != 36 && raw_uuid.len() != 32 {
            format!("invalid UUID length: {}", raw_uuid.len())
        } else {
            "invalid UUID format".to_string()
        };
        ApiError::bad_request(format!("decoding input: invalid {kind} ID UUID: {reason}"))
    })?;
    Ok(format!("{kind}:{uuid}"))
}

fn opt_id_str(v: &Value, key: &str, kind: &str) -> Result<Option<String>, ApiError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value.as_str().ok_or_else(|| {
                ApiError::bad_request(format!("decoding input: {key} must be a string"))
            })?;
            let decoded = decode_id_value(value, kind)?;
            if decoded.ends_with("00000000-0000-0000-0000-000000000000") {
                Ok(None)
            } else {
                Ok(Some(decoded))
            }
        }
    }
}

fn opt_anchor_id(v: &Value) -> Result<Option<String>, ApiError> {
    match v.get("anchor_id") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value.as_str().ok_or_else(|| {
                ApiError::bad_request("decoding input: anchor_id must be a string")
            })?;
            let kind = if value.starts_with("block:") {
                "block"
            } else if value.starts_with("split:") {
                "split"
            } else {
                return Err(ApiError::bad_request(format!(
                    "decoding input: anchor ID must start with \"block:\" or \"split:\": \"{value}\""
                )));
            };
            let decoded = decode_id_value(value, kind)?;
            if decoded.ends_with("00000000-0000-0000-0000-000000000000") {
                Ok(None)
            } else {
                Ok(Some(decoded))
            }
        }
    }
}

fn opt_bool(v: &Value, key: &str, default: bool) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(default)
}

fn req_ratio(payload: &Value, key: &str, default: Option<f64>) -> Result<f64, ApiError> {
    let ratio = match payload.get(key).and_then(Value::as_f64) {
        Some(r) => r,
        None => default.ok_or_else(|| ApiError::bad_request(format!("{key} is required")))?,
    };
    if !ratio.is_finite() || ratio <= 0.0 || ratio >= 1.0 {
        return Err(ApiError::bad_request(format!(
            "input: validating: {key} must be finite, greater than 0, and less than 1"
        )));
    }
    Ok(ratio)
}

/// A split ratio where zero (and a missing value) means an even split.
fn req_split_ratio(payload: &Value, key: &str, default: f64) -> Result<f64, ApiError> {
    let ratio = payload.get(key).and_then(Value::as_f64).unwrap_or(default);
    if ratio == 0.0 {
        return Ok(0.5);
    }
    if !ratio.is_finite() || ratio < 0.0 || ratio >= 1.0 {
        return Err(ApiError::bad_request(
            "input: validating: split ratio must be greater than 0 and less than 1",
        ));
    }
    Ok(ratio)
}

fn parse_rect(v: Option<&Value>) -> Result<Rect, ApiError> {
    let v = v.ok_or_else(|| ApiError::bad_request("bounds is required"))?;
    let nums: [Option<f64>; 4] = if let Some(a) = v.as_array() {
        if a.len() != 4 {
            return Err(ApiError::bad_request(format!(
                "decoding input: rectangle must be [x, y, w, h], got {} numbers",
                a.len()
            )));
        }
        [a[0].as_f64(), a[1].as_f64(), a[2].as_f64(), a[3].as_f64()]
    } else if v.is_object() {
        [
            v.get("x").and_then(Value::as_f64),
            v.get("y").and_then(Value::as_f64),
            v.get("w").and_then(Value::as_f64),
            v.get("h").and_then(Value::as_f64),
        ]
    } else {
        return Err(ApiError::bad_request(
            "decoding input: rectangle must be [x, y, w, h] or an object with x, y, w, and h",
        ));
    };
    let x = nums[0].ok_or_else(|| {
        ApiError::bad_request("decoding input: rectangle must contain four numbers")
    })?;
    let y = nums[1].ok_or_else(|| {
        ApiError::bad_request("decoding input: rectangle must contain four numbers")
    })?;
    let w = nums[2].ok_or_else(|| {
        ApiError::bad_request("decoding input: rectangle must contain four numbers")
    })?;
    let h = nums[3].ok_or_else(|| {
        ApiError::bad_request("decoding input: rectangle must contain four numbers")
    })?;
    if !(x.is_finite() && y.is_finite() && w.is_finite() && h.is_finite())
        || w <= 0.0
        || h <= 0.0
        || x < 0.0
        || y < 0.0
        || x + w > 1.0 + 1e-9
        || y + h > 1.0 + 1e-9
    {
        return Err(ApiError::bad_request(
            "input: validating: bounds must be a finite normalized rectangle with positive size contained within the unit square",
        ));
    }
    Ok([x, y, w, h])
}

fn active_window_index(s: &Session) -> Option<usize> {
    s.windows
        .iter()
        .position(|w| Some(&w.id) == s.active_window.as_ref())
        .or_else(|| if s.windows.is_empty() { None } else { Some(0) })
}

fn window_contains_block(w: &Window, block_id: &str) -> bool {
    w.layers.iter().any(|l| {
        l.layout
            .as_ref()
            .map(|n| contains_block(n, block_id))
            .unwrap_or(false)
    })
}

fn repair_window_focus(w: &mut Window) {
    let focus_ok = match &w.focused_block {
        Some(id) => window_contains_block(w, id),
        None => false,
    };
    if !focus_ok {
        let mut ids = Vec::new();
        for l in &w.layers {
            if let Some(layout) = &l.layout {
                collect_block_ids(layout, &mut ids);
            }
        }
        w.focused_block = ids.first().cloned();
    }
    let zoom_ok = match &w.zoomed_block {
        Some(id) => window_contains_block(w, id),
        None => false,
    };
    if !zoom_ok {
        w.zoomed_block = None;
    }
}

struct LayoutCleanup {
    removed_windows: Vec<String>,
    active_changed: bool,
    active_window: Option<String>,
}

/// Drop empty floating layers and windows that no longer hold a block, then
/// repair focus and the active window.
fn cleanup_windows(s: &mut Session) -> LayoutCleanup {
    let before: Vec<String> = s.windows.iter().map(|w| w.id.clone()).collect();
    let active_before = s.active_window.clone();
    for w in s.windows.iter_mut() {
        w.layers
            .retain(|l| l.kind != "floating" || l.layout.is_some());
    }
    s.windows
        .retain(|w| w.layers.iter().any(|l| l.layout.is_some()));
    for w in s.windows.iter_mut() {
        repair_window_focus(w);
    }
    if let Some(active) = s.active_window.clone() {
        if !s.windows.iter().any(|w| w.id == active) {
            s.active_window = s.windows.first().map(|w| w.id.clone());
        }
    } else if !s.windows.is_empty() {
        s.active_window = s.windows.first().map(|w| w.id.clone());
    }
    if s.windows.is_empty() {
        s.active_window = None;
    }
    let removed_windows = before
        .into_iter()
        .filter(|id| !s.windows.iter().any(|w| &w.id == id))
        .collect();
    LayoutCleanup {
        removed_windows,
        active_changed: s.active_window != active_before,
        active_window: s.active_window.clone(),
    }
}

/// Remove a block from every layout in the session. Returns whether the block
/// was placed and, when a split collapsed, that split's id.
fn remove_block_from_session(s: &mut Session, block_id: &str) -> (bool, Option<String>) {
    let mut placed = false;
    let mut removed_split = None;
    for w in s.windows.iter_mut() {
        for l in w.layers.iter_mut() {
            let mut clear = false;
            if let Some(layout) = l.layout.as_mut() {
                match remove_block_tracked(layout, block_id) {
                    RemoveResult::NotFound => {}
                    RemoveResult::RootLeaf => {
                        placed = true;
                        clear = true;
                    }
                    RemoveResult::Collapsed(split_id) => {
                        placed = true;
                        if removed_split.is_none() {
                            removed_split = Some(split_id);
                        }
                    }
                }
            }
            if clear {
                l.layout = None;
            }
        }
    }
    (placed, removed_split)
}

/// Convert a layer-relative layout rectangle into window coordinates.
fn layer_rect(layer: &Layer, rect: Rect) -> Rect {
    let [bx, by, bw, bh] = layer.bounds;
    [
        bx + rect[0] * bw,
        by + rect[1] * bh,
        rect[2] * bw,
        rect[3] * bh,
    ]
}

/// Find a layer by id, or the floating layer holding the active window's
/// focused block when no id is given.
fn find_layer(s: &Session, layer_id: Option<&str>) -> Option<(usize, usize)> {
    if let Some(id) = layer_id {
        for (wi, w) in s.windows.iter().enumerate() {
            for (li, l) in w.layers.iter().enumerate() {
                if l.id == id {
                    return Some((wi, li));
                }
            }
        }
        return None;
    }
    let wi = active_window_index(s)?;
    let w = &s.windows[wi];
    let focused = w.focused_block.as_deref()?;
    let li = w.layers.iter().position(|l| {
        l.kind == "floating"
            && l.layout
                .as_ref()
                .map(|n| contains_block(n, focused))
                .unwrap_or(false)
    })?;
    Some((wi, li))
}

fn emit_window_cleanup(state: &State, session_id: &str, cleanup: &LayoutCleanup) {
    for wid in &cleanup.removed_windows {
        state.emit_to_session(
            session_id,
            session_event(
                session_id,
                json!({ "type": "window_closed", "payload": { "window_id": wid } }),
            ),
        );
    }
    if cleanup.active_changed {
        state.emit_to_session(
            session_id,
            session_event(
                session_id,
                json!({
                    "type": "active_window_changed",
                    "payload": active_window_event_payload(cleanup),
                }),
            ),
        );
    }
}

fn active_window_event_payload(cleanup: &LayoutCleanup) -> Value {
    let mut payload = json!({});
    if let Some(window_id) = &cleanup.active_window {
        payload["window_id"] = json!(window_id);
    }
    payload
}

fn block_owner_json(id: &str, owner: Option<&String>) -> Value {
    let mut v = json!({ "block_id": id });
    if let Some(owner) = owner {
        v["owner"] = json!(owner);
    }
    v
}

fn account_name() -> Option<String> {
    ["USER", "LOGNAME"]
        .into_iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|name| !name.is_empty())
}

fn server_whoami(state: &State, client_id: &str) -> Value {
    let mut body = json!({ "principal": state.client_principal(client_id) });
    if let Some(account) = account_name() {
        body["account"] = json!(account);
    }
    body
}

fn server_stop(
    state: &State,
    client_id: &str,
    local: bool,
    payload: &Value,
) -> Result<Value, ApiError> {
    if !local {
        return Err(ApiError::new(
            403,
            "forbidden",
            "server.stop is only accepted on a local socket",
        ));
    }
    let if_idle = payload
        .get("if_idle")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if if_idle {
        let sessions = state.sessions.lock().unwrap();
        let clients = state.clients.lock().unwrap();
        let session_count = sessions.len();
        let other_clients = clients.keys().filter(|id| id.as_str() != client_id).count();
        if session_count > 0 || other_clients > 0 {
            return Err(ApiError::conflict(idle_conflict_message(
                session_count,
                other_clients,
            )));
        }
    }
    state
        .shutting_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    schedule_process_exit();
    Ok(json!({}))
}

fn idle_conflict_message(sessions: usize, clients: usize) -> String {
    let mut parts = Vec::new();
    if sessions > 0 {
        parts.push(format!(
            "{sessions} session{}",
            if sessions == 1 { "" } else { "s" }
        ));
    }
    if clients > 0 {
        parts.push(format!(
            "{clients} other client{}",
            if clients == 1 { "" } else { "s" }
        ));
    }
    format!("server is in use ({})", parts.join(", "))
}

pub(crate) fn schedule_process_exit() {
    #[cfg(not(test))]
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        std::process::exit(0);
    });
}

fn session_help(state: &State, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    if !state.session_exists(&sid) {
        return Err(ApiError::session_not_found(&sid));
    }
    let methods = state
        .help
        .get("methods")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|method| session_answers(method))
        .collect::<Vec<_>>();
    let mut body = json!({
        "methods": methods,
        "block_types": state.help.get("block_types").cloned().unwrap_or_else(|| json!([])),
    });
    if let Some(http) = state.help.get("http") {
        body["http"] = http.clone();
    }
    Ok(body)
}

fn session_answers(method: &Value) -> bool {
    let name = method.get("name").and_then(Value::as_str).unwrap_or("");
    if matches!(name, "block.close" | "block.method" | "block.event") {
        return true;
    }
    name.starts_with("session.") && method_has_session_id(method)
}

fn method_has_session_id(method: &Value) -> bool {
    method
        .get("input_schema")
        .and_then(|schema| schema.get("properties"))
        .and_then(|properties| properties.get("session_id"))
        .is_some()
}

fn input_schema<'a>(help: &'a Value, method: &str) -> Option<&'a Value> {
    help.get("methods")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(method))?
        .get("input_schema")
}

fn block_args_schema<'a>(help: &'a Value, creator: &str, method: &str) -> Option<&'a Value> {
    let schema = help
        .get("block_types")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("creator").and_then(Value::as_str) == Some(creator))?
        .get("methods")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(method))?
        .get("args_schema")?;
    if schema.is_null() { None } else { Some(schema) }
}

fn child_exit_event_payload(code: i32, err: Option<String>) -> Value {
    let mut payload = json!({ "exit_code": code });
    if code != 0 {
        payload["error"] = json!(err.unwrap_or_else(|| format!("exit status {code}")));
    }
    payload
}

fn platform_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}_{arch}")
}

fn server_version() -> Value {
    let mut version = json!({
        "rex_version": crate::state::rex_version(),
        "platform": platform_name(),
        "dirty": false,
        "api_revision": API_REVISION,
        "api_min_revision": API_MIN_REVISION,
    });
    if let Some(commit) = option_env!("RUX_COMMIT").filter(|commit| !commit.is_empty()) {
        version["commit"] = json!(commit);
    }
    if let Some(built_at) = option_env!("RUX_BUILT_AT").filter(|built_at| !built_at.is_empty()) {
        version["built_at"] = json!(built_at);
    }
    version
}

fn server_config_reload(state: &Arc<State>) -> Value {
    let previous_hosts_hash = host_list_hash(&visible_hosts(state));
    let (generation, hash, diagnostics) = {
        let mut config = state.config.lock().unwrap();
        config.reload(&state.instance_id);
        (config.generation, config.hash.clone(), config.diagnostics())
    };
    state.emit_server_event(json!({
        "type": "keymap_changed",
        "payload": { "generation": generation, "hash": hash },
    }));
    let current_hosts_hash = host_list_hash(&visible_hosts(state));
    if current_hosts_hash != previous_hosts_hash {
        state.emit_server_event(json!({
            "type": "hosts_changed",
            "payload": { "hash": current_hosts_hash },
        }));
    }
    json!({ "generation": generation, "diagnostics": diagnostics })
}

fn server_status(state: &State, _client_id: Option<&str>) -> Value {
    let count = state.sessions.lock().unwrap().len();
    let config = state.config.lock().unwrap().status();
    let mut status = json!({
        "pid": state.pid,
        "instance_id": state.instance_id,
        "started_at": state.started_at.to_rfc3339(),
        "exit_empty": state.exit_empty.load(std::sync::atomic::Ordering::SeqCst),
        "session_count": count,
        "api_revision": API_REVISION,
        "api_min_revision": API_MIN_REVISION,
        "config": config,
    });
    if state.state_dir.is_some() {
        status["host_id"] = json!(state.host_id);
    }
    if let Some(node) = state.tsnet.lock().unwrap().clone() {
        status["tailscale"] = node.snapshot();
    } else if state.tsnet_launch.lock().unwrap().is_some() {
        status["tailscale"] = json!({
            "state": "disabled",
            "allow_tailnet_members": false,
        });
    }
    status
}

fn tailscale_method(
    state: &Arc<State>,
    local: bool,
    method: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    if !local {
        return Err(ApiError::new(403, "forbidden", "this method is local-only"));
    }
    if state
        .shutting_down
        .load(std::sync::atomic::Ordering::SeqCst)
        && method == "server.tailscale.enable"
    {
        return Err(ApiError::conflict("server is shutting down"));
    }
    let node = if let Some(node) = state.tsnet.lock().unwrap().clone() {
        node
    } else if state.tsnet_launch.lock().unwrap().is_some() {
        state.ensure_tsnet().map_err(|error| {
            ApiError::new(
                500,
                "internal",
                format!("could not start the rux-tsnet sidecar: {error}"),
            )
        })?
    } else {
        return Err(not_supported(
            "built-in Tailscale is not embedded in this build; use the host tailscaled with a tailnet:// listener",
        ));
    };
    let result = match method {
        "server.tailscale.enable" => {
            let tags = payload
                .get("advertise_tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            node.enable(crate::tsnet::EnableRequest {
                hostname: payload
                    .get("hostname")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                allow_members: payload
                    .get("allow_tailnet_members")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| ApiError::bad_request("allow_tailnet_members is required"))?,
                auth_key: payload
                    .get("auth_key")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                advertise_tags: tags,
            })
        }
        "server.tailscale.disable" => {
            let result = node.disable();
            state.disconnect_tailscale_clients();
            result
        }
        "server.tailscale.login" => node.login(),
        "server.tailscale.logout" => node.logout(),
        "server.tailscale.rename" => {
            let hostname = req_str(payload, "hostname")?;
            node.rename(&hostname)
        }
        _ => Err(ApiError::method_not_found(method)),
    }?;
    Ok(result)
}

fn not_supported(message: impl Into<String>) -> ApiError {
    ApiError::new(501, "not_supported", message)
}

fn apple_grant_file_access(payload: &Value) -> Result<Value, ApiError> {
    let files = payload
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("files is required"))?;
    if files.len() > 256 {
        return Err(ApiError::bad_request(
            "files must contain at most 256 entries",
        ));
    }
    let results: Vec<Value> = files
        .iter()
        .map(|entry| {
            let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
            let file_path = std::path::Path::new(path);
            let token = entry.get("token").and_then(Value::as_str);
            let mut token_failed = false;
            let access = if !file_path.is_absolute() {
                "denied"
            } else if file_is_readable(file_path) {
                "readable"
            } else if let Some(token) = token {
                // The token is used only when the path does not
                // already open, exactly as documented.
                if crate::apple::consume_sandbox_token(path, token)
                    && file_is_readable(file_path)
                {
                    "granted"
                } else {
                    token_failed = true;
                    "denied"
                }
            } else {
                "denied"
            };
            let mut result = json!({ "path": path, "access": access });
            if access == "denied" {
                let message = if !file_path.is_absolute() {
                    "path must be absolute"
                } else if token_failed {
                    if cfg!(target_os = "macos") {
                        "the sandbox token did not make the path readable"
                    } else {
                        "this build cannot consume macOS sandbox extension tokens"
                    }
                } else {
                    "server could not read the path"
                };
                result["message"] = json!(message);
            }
            result
        })
        .collect();
    Ok(json!({ "files": results }))
}

fn file_is_readable(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() && !metadata.is_dir() {
        return false;
    }
    std::fs::File::open(path).is_ok()
}

fn host_list_sorted(hosts: &[Value]) -> Vec<Value> {
    let mut hosts = hosts.to_vec();
    hosts.sort_by(|a, b| {
        let label_a = a.get("label").and_then(Value::as_str).unwrap_or("");
        let label_b = b.get("label").and_then(Value::as_str).unwrap_or("");
        label_a
            .to_lowercase()
            .cmp(&label_b.to_lowercase())
            .then_with(|| {
                a.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("id").and_then(Value::as_str).unwrap_or(""))
            })
    });
    hosts
}

fn host_list_hash(hosts: &[Value]) -> String {
    let bytes = serde_json::to_vec(&host_list_sorted(hosts)).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn persist_hosts(
    state: &State,
    hosts: &[Value],
    hidden_ids: &std::collections::HashSet<String>,
) -> Result<(), ApiError> {
    if let Some(error) = state.host_store_error() {
        return Err(ApiError::conflict(format!(
            "host store is unreadable: {error}"
        )));
    }
    let path = state
        .hosts_path
        .as_ref()
        .ok_or_else(|| not_supported("server has no state directory for hosts"))?;
    let mut hidden: Vec<&String> = hidden_ids.iter().collect();
    hidden.sort();
    let bytes = serde_json::to_vec(&json!({ "hosts": hosts, "removed": hidden }))
        .map_err(|err| ApiError::conflict(format!("encoding host store: {err}")))?;
    if bytes.len() > 1024 * 1024 {
        return Err(ApiError::new(
            413,
            "too_large",
            "host store would exceed 1 MiB",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::conflict("host store has no parent directory"))?;
    std::fs::create_dir_all(parent)
        .map_err(|err| ApiError::conflict(format!("creating host store directory: {err}")))?;
    let temp_path = parent.join(format!(".hosts-{}.tmp", uuid::Uuid::now_v7()));
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(ApiError::conflict(format!("writing host store: {err}")));
    }
    Ok(())
}

fn host_store_ready(state: &State) -> Result<(), ApiError> {
    if let Some(error) = state.host_store_error() {
        return Err(ApiError::conflict(format!(
            "host store is unreadable: {error}"
        )));
    }
    Ok(())
}

fn hosts_list(state: &Arc<State>) -> Result<Value, ApiError> {
    host_store_ready(state)?;
    let hosts = visible_hosts(state);
    let sorted = host_list_sorted(&hosts);
    Ok(json!({ "hosts": sorted, "hash": host_list_hash(&hosts) }))
}

fn visible_hosts(state: &State) -> Vec<Value> {
    let declared = state.config.lock().unwrap().hosts();
    let stored = state.hosts.lock().unwrap().clone();
    let hidden = state.hidden_host_ids.lock().unwrap().clone();
    let mut visible = Vec::new();
    let mut used_stored = std::collections::HashSet::new();
    for host in declared {
        let id = host.get("id").and_then(Value::as_str).unwrap_or("");
        if hidden.contains(id) {
            continue;
        }
        if let Some((index, replacement)) = stored
            .iter()
            .enumerate()
            .find(|(_, record)| record.get("id").and_then(Value::as_str) == Some(id))
        {
            visible.push(replacement.clone());
            used_stored.insert(index);
        } else {
            visible.push(host);
        }
    }
    visible.extend(
        stored
            .into_iter()
            .enumerate()
            .filter_map(|(index, host)| (!used_stored.contains(&index)).then_some(host)),
    );
    visible
}

fn validate_host_id(id: &str) -> Result<String, ApiError> {
    let raw = id.strip_prefix("host:").ok_or_else(|| {
        ApiError::bad_request("decoding input: host ID must start with \"host:\"")
    })?;
    let uuid = uuid::Uuid::parse_str(raw).map_err(|_| {
        let reason = if raw.len() != 36 && raw.len() != 32 {
            format!("invalid UUID length: {}", raw.len())
        } else {
            "invalid UUID format".to_string()
        };
        ApiError::bad_request(format!("decoding input: invalid host ID UUID: {reason}"))
    })?;
    Ok(format!("host:{uuid}"))
}

fn hosts_put(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    host_store_ready(state)?;
    if state.hosts_path.is_none() {
        return Err(not_supported("server has no state directory for hosts"));
    }
    let input = payload
        .get("host")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::bad_request("host is required"))?;
    let label = input
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("host.label is required"))?;
    if label.is_empty()
        || label.trim() != label
        || label.len() > 64
        || label.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "host.label must be non-empty, trimmed, and at most 64 bytes",
        ));
    }
    let endpoints = input
        .get("endpoints")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("host.endpoints is required"))?;
    if endpoints.is_empty()
        || endpoints.iter().any(|endpoint| {
            endpoint.as_str().is_none_or(|value| {
                value.trim().is_empty()
                    || value.starts_with("unix://")
                    || value.starts_with("\\\\.\\pipe\\")
            })
        })
    {
        return Err(ApiError::bad_request(
            "host.endpoints must contain at least one Rex network endpoint",
        ));
    }

    let id = match input.get("id") {
        Some(Value::String(id)) => validate_host_id(id)?,
        Some(Value::Null) | None => format!("host:{}", uuid::Uuid::now_v7()),
        Some(_) => return Err(ApiError::bad_request("host.id must be a string")),
    };
    let mut host = Value::Object(input.clone());
    host["id"] = json!(id);
    host["updated_at"] = json!(Utc::now().to_rfc3339());
    if let Some(object) = host.as_object_mut() {
        object.remove("source");
        if !object.contains_key("added_from") {
            if let Some(client) = state.clients.lock().unwrap().get(client_id) {
                let display = client.info.name.as_str();
                if !display.is_empty() {
                    object.insert("added_from".into(), json!(display));
                }
            }
        }
    }

    let declared = state.config.lock().unwrap().hosts();
    let mut hosts = state.hosts.lock().unwrap();
    let mut hidden = state.hidden_host_ids.lock().unwrap();
    if let Some(duplicate) = hosts.iter().chain(declared.iter()).find(|existing| {
        existing.get("id").and_then(Value::as_str) != Some(id.as_str())
            && existing
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|other| other.eq_ignore_ascii_case(label))
    }) {
        let other = duplicate.get("label").and_then(Value::as_str).unwrap_or("");
        let source = duplicate
            .get("source")
            .and_then(Value::as_str)
            .map(|source| format!(" ({source})"))
            .unwrap_or_default();
        return Err(ApiError::conflict(format!(
            "host label {label:?} is already used by {other:?}{source}"
        )));
    }
    let old_index = hosts
        .iter()
        .position(|existing| existing.get("id").and_then(Value::as_str) == Some(&id));
    let old = old_index.map(|index| hosts[index].clone());
    let same = old.as_ref().is_some_and(|old| {
        let mut old = old.clone();
        let mut new = host.clone();
        if let Some(o) = old.as_object_mut() {
            o.remove("updated_at");
        }
        if let Some(n) = new.as_object_mut() {
            n.remove("updated_at");
        }
        old == new
    });
    if same && !hidden.contains(&id) {
        let stored = old.unwrap();
        drop(hidden);
        drop(hosts);
        let hash = host_list_hash(&visible_hosts(state));
        return Ok(json!({ "host": stored, "hash": hash }));
    }

    let mut next = hosts.clone();
    if let Some(index) = old_index {
        next[index] = host.clone();
    } else {
        next.push(host.clone());
    }
    let mut next_hidden = hidden.clone();
    next_hidden.remove(&id);
    persist_hosts(state, &next, &next_hidden)?;
    *hosts = next;
    *hidden = next_hidden;
    drop(hidden);
    drop(hosts);
    let hash = host_list_hash(&visible_hosts(state));
    state.emit_server_event(json!({
        "type": "hosts_changed",
        "payload": { "hash": hash },
    }));
    Ok(json!({ "host": host, "hash": hash }))
}

fn hosts_remove(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    host_store_ready(state)?;
    if state.hosts_path.is_none() {
        return Err(not_supported("server has no state directory for hosts"));
    }
    let id = match payload.get("id") {
        Some(Value::String(id)) => Some(validate_host_id(id)?),
        Some(Value::Null) | None => None,
        Some(_) => return Err(ApiError::bad_request("id must be a host ID string")),
    };
    let declared = state.config.lock().unwrap().hosts();
    let mut hosts = state.hosts.lock().unwrap();
    let mut hidden = state.hidden_host_ids.lock().unwrap();
    let Some(id) = id else {
        drop(hidden);
        drop(hosts);
        let hash = host_list_hash(&visible_hosts(state));
        return Ok(json!({ "removed": false, "hash": hash }));
    };
    let stored_exists = hosts
        .iter()
        .any(|host| host.get("id").and_then(Value::as_str) == Some(id.as_str()));
    let declared_exists = declared
        .iter()
        .any(|host| host.get("id").and_then(Value::as_str) == Some(id.as_str()));
    let was_hidden = hidden.contains(&id);
    let removed = stored_exists || (declared_exists && !was_hidden);
    if removed {
        let next: Vec<Value> = hosts
            .iter()
            .filter(|host| host.get("id").and_then(Value::as_str) != Some(id.as_str()))
            .cloned()
            .collect();
        let mut next_hidden = hidden.clone();
        if declared_exists {
            next_hidden.insert(id.clone());
        }
        persist_hosts(state, &next, &next_hidden)?;
        *hosts = next;
        *hidden = next_hidden;
        drop(hidden);
        drop(hosts);
        let hash = host_list_hash(&visible_hosts(state));
        state.emit_server_event(json!({
            "type": "hosts_changed",
            "payload": { "hash": hash },
        }));
        Ok(json!({ "removed": true, "hash": hash }))
    } else {
        drop(hidden);
        drop(hosts);
        let hash = host_list_hash(&visible_hosts(state));
        Ok(json!({ "removed": false, "hash": hash }))
    }
}

fn block_creators(state: &State) -> Value {
    let mut v = state.creators.clone();
    if let Some(arr) = v.get_mut("creators").and_then(|x| x.as_array_mut()) {
        for c in arr {
            c["host_id"] = json!(state.host_id);
        }
    }
    v
}

fn session_list(state: &State) -> Vec<Value> {
    state
        .sessions
        .lock()
        .unwrap()
        .iter()
        .map(|s| json!({ "session_id": s.id, "label": s.label }))
        .collect()
}

fn client_list(state: &State, session_id: Option<&str>) -> Vec<Value> {
    let allowed: Option<Vec<String>> = session_id.map(|sid| state.subscribers(sid));
    let clients = state.clients.lock().unwrap();
    clients
        .values()
        .filter(|c| {
            allowed
                .as_ref()
                .map(|a| a.iter().any(|x| x == &c.id))
                .unwrap_or(true)
        })
        .map(|c| {
            json!({
                "client_id": c.id,
                "info": c.info,
                "principal": c.principal,
                "connected_at": c.connected_at,
                "connection_state": c.connection_state,
            })
        })
        .collect()
}

async fn client_set_script(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let scripts = payload
        .get("scripts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let sources = scripts
        .iter()
        .map(|script| {
            let name = script
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("script.lua")
                .to_string();
            let source = script
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (name, source)
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        state.script_events.lock().unwrap().remove(client_id);
        return Ok(json!({ "bindings": [], "diagnostics": [] }));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = tokio::runtime::Handle::current();
    let api_state = state.clone();
    let caller = client_id.to_string();
    let script_client = caller.clone();
    let api: crate::config::ApiCall = std::sync::Arc::new(move |method, payload| {
        if method == "rux.client_queue" {
            // A script's queued action is performed immediately: route it
            // through client.perform so the client is asked with the same
            // request/reply flow as an API caller, and the script hears
            // about a refusal or a timeout.
            let mut perform = json!({
                "client_id": caller,
                "action": payload.get("action").cloned().unwrap_or(Value::Null),
                "origin": "script",
            });
            for key in ["args", "session_id", "block_id"] {
                if let Some(value) = payload.get(key) {
                    perform[key] = value.clone();
                }
            }
            return handle
                .block_on(dispatch(&api_state, &caller, true, "client.perform", perform))
                .map_err(|error| error.message);
        }
        handle
            .block_on(dispatch(&api_state, &caller, true, &method, payload))
            .map_err(|error| error.message)
    });
    let (hosts, host_endpoints) =
        crate::script::host_labels_and_endpoints(&state.config.lock().unwrap().hosts());
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let loaded =
            crate::script::start_client_scripts(
                sources,
                None,
                Some(script_client),
                hosts,
                host_endpoints,
                rx,
                api,
            );
        let _ = done_tx.send(loaded);
    });
    match done_rx.await {
        Ok(Ok((result, _worker))) => {
            state
                .script_events
                .lock()
                .unwrap()
                .insert(client_id.to_string(), tx);
            Ok(json!({
                "bindings": result.bindings,
                "diagnostics": result.diagnostics,
            }))
        }
        Ok(Err(error)) => Err(ApiError::bad_request(error)),
        Err(_) => Err(ApiError::bad_request("script load was dropped")),
    }
}

fn client_inspect(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let client_id = req_str(payload, "client_id")?;
    let client = state.client_json(&client_id);
    if client.is_null() {
        return Err(ApiError::not_found(format!("client {client_id} not found")));
    }
    let mut result = json!({ "client": client });
    if let Some(actions) = state.client_actions(&client_id) {
        result["actions"] = json!(actions);
    }
    Ok(result)
}

fn client_set_label(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let label = req_str(payload, "label")?;
    let label = label.trim();
    if label.len() > 64 {
        return Err(ApiError::bad_request("label must be at most 64 bytes"));
    }
    if label.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "label must not contain control characters",
        ));
    }
    let label = if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    };
    let changed = {
        let mut clients = state.clients.lock().unwrap();
        let client = clients
            .get_mut(client_id)
            .ok_or_else(|| ApiError::not_found(format!("client {client_id} not found")))?;
        if client.info.label == label {
            false
        } else {
            client.info.label = label;
            true
        }
    };
    if changed {
        state.emit_server_event(json!({
            "type": "client_changed",
            "payload": { "client_id": client_id },
        }));
    }
    Ok(json!({}))
}

fn creator_actions(state: &State) -> Vec<Value> {
    let mut actions = Vec::new();
    let Some(creators) = state.creators.get("creators").and_then(Value::as_array) else {
        return actions;
    };
    for creator in creators {
        let Some(name) = creator.get("name").and_then(Value::as_str) else {
            continue;
        };
        if let Some(methods) = creator
            .get("api")
            .and_then(|api| api.get("methods"))
            .and_then(Value::as_object)
        {
            for (method_name, method) in methods {
                if let Some(declared_actions) = method.get("actions").and_then(Value::as_array) {
                    for declared in declared_actions {
                        let mut action = declared.clone();
                        action["name"] = json!(format!("{name}.{method_name}"));
                        action["kind"] = json!("block");
                        actions.push(action);
                    }
                } else {
                    let mut action = json!({
                        "name": format!("{name}.{method_name}"),
                        "kind": "block",
                        "description": method.get("description").and_then(Value::as_str).unwrap_or(""),
                    });
                    if let Some(schema) = method.get("input_schema") {
                        action["args"] = schema.clone();
                    }
                    actions.push(action);
                }
            }
        }
        if let Some(creator_actions) = creator
            .get("api")
            .and_then(|api| api.get("actions"))
            .and_then(Value::as_object)
        {
            for (action_name, definition) in creator_actions {
                let mut action = json!({
                    "name": format!("{name}.{action_name}"),
                    "kind": "block",
                });
                if let Some(title) = definition.get("title") {
                    action["title"] = title.clone();
                }
                if let Some(description) = definition.get("description") {
                    action["description"] = description.clone();
                }
                actions.push(action);
            }
        }
    }
    actions.sort_by(|a, b| {
        a.get("name")
            .and_then(Value::as_str)
            .cmp(&b.get("name").and_then(Value::as_str))
    });
    actions
}

fn client_keymap(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let actions = match payload.get("actions") {
        None => None,
        Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(actions)) => Some(actions.clone()),
        Some(_) => return Err(ApiError::bad_request("actions must be an array")),
    };
    let mut clients = state.clients.lock().unwrap();
    let client = clients
        .get_mut(client_id)
        .ok_or_else(|| ApiError::not_found(format!("client {client_id} not found")))?;
    if let Some(actions) = actions {
        client.actions = Some(actions);
    }
    drop(clients);

    let config = state.config.lock().unwrap();
    let config_actions = config.actions();
    let has_key_functions = config.has_key_functions();
    let mut actions = config_actions.clone();
    let server_actions = payload
        .get("server_actions")
        .and_then(Value::as_str)
        .unwrap_or("all");
    if server_actions != "none" {
        if server_actions != "configured" {
            actions.extend(creator_actions(state));
        }
        if has_key_functions {
            actions.push(json!({
                "name": "client.key.forward",
                "kind": "lua",
            }));
        }
    } else {
        actions.clear();
    }
    let config_bindings = config.bindings();
    let config_removals = config.removals();
    let mut bindings = Vec::new();
    append_keymap_layers(&mut bindings, payload.get("defaults"));
    apply_keymap_removals(&mut bindings, &config_removals);
    bindings.extend(config_bindings);
    append_keymap_layers(&mut bindings, payload.get("overrides"));
    let diagnostics = config.diagnostics();
    let mut modes = config.modes();
    for removal in &config_removals {
        if removal
            .get("keys")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && let Some(mode) = removal.get("mode").and_then(Value::as_str)
        {
            modes.retain(|entry| entry.get("name").and_then(Value::as_str) != Some(mode));
        }
    }
    modes.sort_by(|a, b| {
        a.get("name")
            .and_then(Value::as_str)
            .cmp(&b.get("name").and_then(Value::as_str))
    });
    let config_json = config.keymap_config(&state.instance_id);
    let mut response = json!({
        "bindings": bindings,
        "diagnostics": diagnostics,
        "modes": modes,
        "config": config_json,
    });
    if server_actions != "none" {
        response["actions"] = json!(actions);
    }
    Ok(response)
}

async fn client_action(
    state: &Arc<State>,
    client_id: &str,
    local: bool,
    payload: &Value,
) -> Result<Value, ApiError> {
    let action = req_str(payload, "action")?;
    let args = match payload.get("args") {
        None | Some(Value::Null) => json!({}),
        Some(Value::Object(_)) => payload["args"].clone(),
        Some(_) => return Err(ApiError::bad_request("args must be an object")),
    };
    let session_id = opt_id_str(payload, "session_id", "session")?;
    let block_id = opt_id_str(payload, "block_id", "block")?;
    if block_id.is_some() && session_id.is_none() {
        return Err(ApiError::bad_request("block_id requires session_id"));
    }
    let origin = match opt_str(payload, "origin").as_deref() {
        Some("key" | "palette" | "api") => opt_str(payload, "origin").unwrap(),
        _ => "api".to_string(),
    };

    let focused_block = if let Some(session_id) = &session_id {
        if !state
            .subscribers(session_id)
            .iter()
            .any(|id| id == client_id)
        {
            return Err(ApiError::conflict(format!(
                "stream is not attached to session {session_id}"
            )));
        }
        let sessions = state.sessions.lock().unwrap();
        let session = sessions
            .iter()
            .find(|session| &session.id == session_id)
            .ok_or_else(|| ApiError::session_not_found(session_id))?;
        block_id.clone().or_else(|| {
            active_window_index(session).and_then(|wi| session.windows[wi].focused_block.clone())
        })
    } else {
        None
    };

    if action != "client.key.forward"
        && let Some((creator, method)) = action.rsplit_once('.')
    {
        if !creator.starts_with("com.superlogical.") {
            return Err(ApiError::not_found(format!("action {action} not found")));
        }
        let (session_id, block_id) = match (session_id, focused_block) {
            (Some(session_id), Some(block_id)) => (session_id, block_id),
            (None, _) => return Err(ApiError::bad_request("block actions require session_id")),
            (_, None) => return Err(ApiError::conflict("session has no focused block")),
        };
        let (block_creator, terminal) = {
            let sessions = state.sessions.lock().unwrap();
            let session = sessions
                .iter()
                .find(|session| session.id == session_id)
                .ok_or_else(|| ApiError::session_not_found(&session_id))?;
            let block = session
                .blocks
                .get(&block_id)
                .ok_or_else(|| ApiError::not_found(format!("block {block_id} not found")))?;
            (block.creator_name.clone(), block.terminal.is_some())
        };
        if block_creator != creator {
            return Err(ApiError::conflict(format!(
                "action {action} does not belong to block creator {block_creator}"
            )));
        }
        if !terminal {
            return Err(ApiError::conflict(format!(
                "block {block_id} has no methods"
            )));
        }
        let creator_def = state
            .creators
            .get("creators")
            .and_then(Value::as_array)
            .and_then(|creators| {
                creators
                    .iter()
                    .find(|entry| entry.get("name").and_then(Value::as_str) == Some(creator))
            })
            .ok_or_else(|| ApiError::not_found(format!("block creator {creator} not found")))?;
        let method_def = creator_def
            .get("api")
            .and_then(|api| api.get("methods"))
            .and_then(Value::as_object)
            .and_then(|methods| methods.get(method))
            .ok_or_else(|| ApiError::not_found(format!("action {action} not found")))?;
        if method_def
            .get("actions")
            .and_then(Value::as_array)
            .is_some_and(|actions| !actions.is_empty())
            && payload.get("args").is_some()
        {
            return Err(ApiError::bad_request("block actions do not accept args"));
        }
        let result = block_method(
            state,
            None,
            &json!({
                "session_id": session_id,
                "block_id": block_id,
                "method": method,
                "args": args,
            }),
        )?;
        return Ok(json!({ "result": result, "client_actions": [] }));
    }

    if let Some(session_id) = &session_id
        && state.session_exists(session_id)
        && !state
            .subscribers(session_id)
            .iter()
            .any(|id| id == client_id)
    {
        return Err(ApiError::conflict(format!(
            "stream is not attached to session {session_id}"
        )));
    }
    let mut context = json!({
        "session_id": session_id,
        "block_id": focused_block,
        "client_id": client_id,
        "origin": origin,
    });
    if let Some(servers) = payload.get("servers") {
        context["servers"] = servers.clone();
    }
    if let Some(server) = payload.get("server") {
        context["server"] = server.clone();
    }
    let action_name = action.clone();
    let api_call = lua_api_caller(state, client_id, local, context.clone());
    let config = state.config.lock().unwrap();
    if action_name == "client.key.forward" {
        let binding_id = args
            .get("binding_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad_request("binding_id is required"))?
            .to_string();
        let (result, client_actions) = config
            .invoke_key_function(&binding_id, context, args, api_call)
            .map_err(|error| ApiError::new(500, "internal", error))?;
        let mut response = json!({ "client_actions": client_actions });
        if !result.is_null() && result != json!(true) {
            response["result"] = result;
        }
        return Ok(response);
    }
    if !config.has_action(&action_name) {
        return Err(ApiError::not_found(format!(
            "action {action_name} not found"
        )));
    }
    let (result, client_actions) = config
        .invoke_action(&action_name, context, args, api_call)
        .map_err(|error| ApiError::new(500, "internal", error))?;
    let mut response = json!({ "client_actions": client_actions });
    if !result.is_null() && result != json!(true) {
        response["result"] = result;
    }
    Ok(response)
}

fn lua_api_caller(
    state: &Arc<State>,
    client_id: &str,
    local: bool,
    context: Value,
) -> crate::config::ApiCall {
    let caller_id = client_id.to_string();
    let state = state.clone();
    Arc::new(move |method, mut args| {
        if matches!(
            method.as_str(),
            "client.action" | "client.keymap" | "server.config_reload" | "server.status"
        ) {
            return Err(format!("{method} cannot be called from a Lua action"));
        }
        if let Some(object) = args.as_object_mut() {
            if object.get("session_id").is_none()
                && let Some(session_id) = context.get("session_id").filter(|value| !value.is_null())
            {
                object.insert("session_id".into(), session_id.clone());
            }
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(dispatch(&state, &caller_id, local, &method, args))
        })
        .map_err(|error| error.message)
    })
}

fn append_keymap_layers(out: &mut Vec<Value>, value: Option<&Value>) {
    let Some(layers) = value.and_then(Value::as_array) else {
        return;
    };
    for layer in layers {
        let source = layer.get("name").and_then(Value::as_str).unwrap_or("");
        if let Some(removals) = layer.get("removals").and_then(Value::as_array) {
            apply_keymap_removals(out, removals);
        }
        if let Some(bindings) = layer.get("bindings").and_then(Value::as_array) {
            for binding in bindings {
                let mut binding = binding.clone();
                if !source.is_empty() {
                    binding["source"] = json!(source);
                }
                out.push(binding);
            }
        }
    }
}

fn apply_keymap_removals(bindings: &mut Vec<Value>, removals: &[Value]) {
    for removal in removals {
        let keys = removal.get("keys").and_then(Value::as_array);
        let mode = removal.get("mode").and_then(Value::as_str);
        let action = removal.get("action").and_then(Value::as_str);
        bindings.retain(|binding| {
            if binding.get("mode").and_then(Value::as_str) != mode {
                return true;
            }
            if let Some(keys) = keys
                && binding.get("keys").and_then(Value::as_array) != Some(keys)
            {
                return true;
            }
            if let Some(action) = action
                && binding.get("action").and_then(Value::as_str) != Some(action)
            {
                return true;
            }
            false
        });
    }
}

async fn client_perform(
    state: &Arc<State>,
    requester_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let target_id = req_str(payload, "client_id")?;
    let action = req_str(payload, "action")?;
    let args = match payload.get("args") {
        None | Some(Value::Null) => None,
        Some(Value::Object(_)) => Some(payload["args"].clone()),
        Some(_) => return Err(ApiError::bad_request("args must be an object")),
    };
    let timeout_ms = match payload.get("timeout_ms").and_then(Value::as_i64) {
        Some(value) if value < 0 => {
            return Err(ApiError::bad_request("timeout_ms must not be negative"));
        }
        Some(value) => value.min(30_000) as u64,
        None => 10_000,
    };
    let target = state.client_json(&target_id);
    if target.is_null() {
        return Err(ApiError::not_found(format!("client {target_id} not found")));
    }
    if let Some(actions) = state.client_actions(&target_id)
        && !actions.is_empty()
        && !actions
            .iter()
            .any(|item| item.get("name").and_then(Value::as_str) == Some(&action))
    {
        return Err(not_supported(format!(
            "client {target_id} has not declared action {action}"
        )));
    }

    // One action per target runs at a time, matching the client's reply flow.
    if !state.enqueue_perform(&target_id) {
        return Err(ApiError::new(
            503,
            "client_unavailable",
            "client already has 16 requests waiting",
        ));
    }
    let lock = state.perform_lock(&target_id);
    let _guard = lock.lock().await;
    state.dequeue_perform(&target_id);
    if state.client_json(requester_id).is_null() {
        return Err(ApiError::new(
            503,
            "client_unavailable",
            "requesting client disconnected",
        ));
    }
    if state.client_json(&target_id).is_null() {
        return Err(ApiError::new(
            503,
            "client_unavailable",
            format!("client {target_id} disconnected"),
        ));
    }
    let call_id = state
        .perform_sequence
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;
    let call_id = call_id.to_string();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    state.pending_performs.lock().unwrap().insert(
        call_id.clone(),
        PendingPerform {
            requester_id: requester_id.to_string(),
            target_client_id: target_id.clone(),
            reply: reply_tx,
        },
    );
    let requester = state.client_json(requester_id);
    let mut event_payload = json!({
        "call_id": call_id,
        "action": action,
        "origin": opt_str(payload, "origin").unwrap_or_else(|| "api".into()),
        "requester": {
            "client_id": requester_id,
            "info": requester.get("info").cloned().unwrap_or(Value::Null),
            "principal": requester.get("principal").cloned().unwrap_or(Value::Null),
        }
    });
    if let Some(args) = args {
        event_payload["args"] = args;
    }
    for key in ["session_id", "block_id"] {
        if let Some(value) = payload.get(key).and_then(Value::as_str) {
            event_payload[key] = json!(value);
        }
    }
    let event = json!({
        "type": "client_perform_requested",
        "payload": event_payload,
    });
    if !state.send_client_event(&target_id, event) {
        state.pending_performs.lock().unwrap().remove(&call_id);
        return Err(ApiError::new(
            503,
            "client_unavailable",
            format!("client {target_id} disconnected"),
        ));
    }

    let outcome =
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), reply_rx).await;
    state.pending_performs.lock().unwrap().remove(&call_id);
    let outcome = match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(ApiError::new(
            503,
            "client_unavailable",
            format!("client {target_id} disconnected while action was pending"),
        )),
        Err(_) => Err(ApiError::new(
            504,
            "timeout",
            format!("client {target_id} did not answer in time"),
        )),
    };
    let mut event_payload = json!({
        "call_id": call_id,
        "client_id": target_id,
        "action": action,
    });
    match &outcome {
        Ok(result) => event_payload["result"] = result.clone(),
        Err(error) => {
            event_payload["error"] = json!({ "code": error.code, "message": error.message });
        }
    }
    state.emit_all_clients_event(json!({
        "type": "client_performed",
        "payload": event_payload,
    }));
    let result = outcome?;
    let mut response = json!({ "performed_by": target_id });
    if !result.is_null() {
        response["result"] = result;
    }
    Ok(response)
}

fn client_reply(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let call_id = req_str(payload, "call_id")?;
    let result = payload.get("result");
    let error = payload.get("error").filter(|value| !value.is_null());
    if result.is_some() == error.is_some() {
        return Err(ApiError::bad_request("set exactly one of result or error"));
    }
    let outcome = if let Some(result) = result {
        Ok(result.clone())
    } else {
        let error = error
            .and_then(Value::as_object)
            .ok_or_else(|| ApiError::bad_request("error must contain code and message"))?;
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("internal");
        let code = if code.is_empty() { "internal" } else { code };
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad_request("error.message is required"))?;
        let status = match code {
            "not_supported" => 501,
            "refused" => 403,
            "timeout" => 504,
            "client_unavailable" => 503,
            _ => 400,
        };
        Err(ApiError::new(status, code, message))
    };
    let pending = {
        let mut calls = state.pending_performs.lock().unwrap();
        let Some(pending) = calls.get(&call_id) else {
            return Err(ApiError::not_found(format!("call {call_id} not found")));
        };
        if pending.target_client_id != client_id {
            return Err(ApiError::bad_request(
                "call_id belongs to a different client",
            ));
        }
        calls.remove(&call_id).expect("call checked above")
    };
    let _ = pending.reply.send(outcome);
    Ok(json!({}))
}

// -- blocks ---------------------------------------------------------------

fn flavor_exists(state: &State, flavor: &str) -> bool {
    state
        .creators
        .get("creators")
        .and_then(Value::as_array)
        .map(|creators| {
            creators.iter().any(|creator| {
                creator
                    .get("flavors")
                    .and_then(Value::as_array)
                    .map(|flavors| {
                        flavors
                            .iter()
                            .any(|f| f.get("flavor").and_then(Value::as_str) == Some(flavor))
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn create_block(
    state: &Arc<State>,
    session_id: &str,
    flavor: &str,
    label: Option<String>,
    options: &Value,
    owner: &str,
) -> Result<Block, ApiError> {
    if !flavor_exists(state, flavor) {
        return Err(ApiError::bad_request(format!(
            "input: validating: invalid block flavor: \"{flavor}\""
        )));
    }
    let id = ids::block();
    let creator = flavor.rsplit_once('.').map(|(a, _)| a).unwrap_or(flavor);
    let is_terminal = flavor.starts_with("com.superlogical.terminal");
    let label = label.unwrap_or_else(|| {
        if is_terminal {
            "shell".to_string()
        } else {
            creator.rsplit('.').next().unwrap_or("block").to_string()
        }
    });

    let terminal = if is_terminal {
        let mut opts = TerminalOptions::from_json(options);
        opts.env
            .push(("REX_SESSION".into(), session_id.to_string()));
        opts.env.push(("REX_BLOCK".into(), id.clone()));
        if let Some(addr) = state.server_addr.lock().unwrap().clone() {
            opts.env.push(("REX_SERVER".into(), addr));
        }
        let st = state.clone();
        let sid = session_id.to_string();
        let bid = id.clone();
        // What happens after the child exits depends on who owns the
        // block. A block owned by another client kind stays: `rex new
        // --keep-open` relies on a later `rex capture` still finding it,
        // and `rex ls` still listing the session. A block owned by an
        // `app` client closes, matching the GUI flow (see
        // auto_close_app_block).
        let term = crate::terminal::Terminal::spawn(opts, move |code, err| {
            let payload = child_exit_event_payload(code, err);
            st.emit_to_session(
                &sid,
                crate::state::block_event(
                    &sid,
                    &bid,
                    "com.superlogical.terminal",
                    "child_exited",
                    payload,
                ),
            );
            auto_close_app_block(&st, &sid, &bid);
        })
        .map_err(|e| ApiError::bad_request(format!("starting terminal: {e}")))?;
        let mut events = term.events.subscribe();
        let event_state = state.clone();
        let event_session_id = session_id.to_string();
        let event_block_id = id.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        let Some(name) = event.get("name").and_then(Value::as_str) else {
                            continue;
                        };
                        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
                        event_state.emit_to_session(
                            &event_session_id,
                            crate::state::block_event(
                                &event_session_id,
                                &event_block_id,
                                "com.superlogical.terminal",
                                name,
                                payload,
                            ),
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Some(term)
    } else {
        None
    };
    let onboarding = (flavor == "com.superlogical.onboarding.onboarding").then(|| {
        Arc::new(std::sync::Mutex::new(OnboardingState {
            generation: 0,
            step: options
                .get("step")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }))
    });

    Ok(Block {
        id,
        label,
        creator_name: creator.to_string(),
        flavor: flavor.to_string(),
        host_id: state.host_id.clone(),
        owner: Some(owner.to_string()),
        terminal,
        onboarding,
    })
}

fn build_layout(
    state: &Arc<State>,
    session_id: &str,
    spec: &CreateLayout,
    rect: Rect,
    owner: &str,
    blocks: &mut IndexMap<String, Block>,
    created: &mut Vec<String>,
) -> Result<Layout, ApiError> {
    match spec {
        CreateLayout::Block(b) => {
            let block = create_block(
                state,
                session_id,
                &b.flavor,
                b.label.clone(),
                &b.options,
                owner,
            )?;
            let id = block.id.clone();
            blocks.insert(id.clone(), block);
            created.push(id.clone());
            Ok(Layout::Leaf { rect, block_id: id })
        }
        CreateLayout::Split(s) => {
            let ratio = match s.ratio {
                Some(r) if r != 0.0 => r,
                _ => 0.5,
            };
            let br = split_rect(rect, &s.direction, ratio, true);
            let ar = split_rect(rect, &s.direction, ratio, false);
            let before = build_layout(state, session_id, &s.before, br, owner, blocks, created)?;
            let after = build_layout(state, session_id, &s.after, ar, owner, blocks, created)?;
            Ok(Layout::Split {
                rect,
                split_id: ids::split(),
                direction: s.direction.clone(),
                ratio,
                before: Box::new(before),
                after: Box::new(after),
            })
        }
    }
}

fn parse_layout_required(v: Option<&Value>, missing: &str) -> Result<CreateLayout, ApiError> {
    let v = v
        .filter(|v| !v.is_null())
        .ok_or_else(|| ApiError::bad_request(missing))?;
    serde_json::from_value(v.clone())
        .map_err(|e| ApiError::bad_request(format!("malformed layout: {e}")))
}

fn validate_create_layout(spec: &CreateLayout, ratio_prefix: &str) -> Result<(), ApiError> {
    match spec {
        CreateLayout::Block(_) => Ok(()),
        CreateLayout::Split(s) => {
            if !matches!(s.direction.as_str(), "horizontal" | "vertical") {
                return Err(ApiError::bad_request(format!(
                    "decoding input: unknown split direction \"{}\"",
                    s.direction
                )));
            }
            if let Some(ratio) = s.ratio {
                if !ratio.is_finite() || ratio < 0.0 || ratio >= 1.0 {
                    return Err(ApiError::bad_request(format!(
                        "{ratio_prefix}split ratio must be greater than 0 and less than 1"
                    )));
                }
            }
            validate_create_layout(&s.before, ratio_prefix)?;
            validate_create_layout(&s.after, ratio_prefix)?;
            Ok(())
        }
    }
}

struct NewWindow {
    window: Window,
    blocks: IndexMap<String, Block>,
    created: Vec<String>,
}

fn default_window_label(window_id: &str) -> String {
    let uuid = window_id.strip_prefix("window:").unwrap_or(window_id);
    let short: String = uuid
        .chars()
        .filter(char::is_ascii_hexdigit)
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("Window {short}")
}

fn make_window(
    state: &Arc<State>,
    session_id: &str,
    label: &str,
    spec: &CreateLayout,
    owner: &str,
) -> Result<NewWindow, ApiError> {
    let window_id = ids::window();
    let label = if label.trim().is_empty() {
        default_window_label(&window_id)
    } else {
        label.trim().to_string()
    };
    let layer_id = ids::layer();
    let mut blocks = IndexMap::new();
    let mut created = Vec::new();
    let layout = build_layout(
        state,
        session_id,
        spec,
        [0.0, 0.0, 1.0, 1.0],
        owner,
        &mut blocks,
        &mut created,
    )?;
    let focused = created.first().cloned();
    let window = Window {
        id: window_id,
        label,
        focused_block: focused,
        zoomed_block: None,
        layers: vec![Layer {
            id: layer_id,
            kind: "tiled".into(),
            bounds: [0.0, 0.0, 1.0, 1.0],
            layout: Some(layout),
        }],
    };
    Ok(NewWindow {
        window,
        blocks,
        created,
    })
}

fn emit_created(
    state: &State,
    session_id: &str,
    blocks: &[String],
    window: Option<(&str, &str)>,
    owner: &str,
) {
    for id in blocks {
        state.emit_to_session(
            session_id,
            session_event(
                session_id,
                json!({
                    "type": "block_created",
                    "payload": { "block_id": id },
                }),
            ),
        );
        state.emit_to_session(
            session_id,
            session_event(
                session_id,
                json!({
                    "type": "block_owner_changed",
                    "payload": {
                        "block_id": id,
                        "owner": owner,
                        "reason": "create",
                    },
                }),
            ),
        );
    }
    if let Some((wid, label)) = window {
        state.emit_to_session(
            session_id,
            session_event(
                session_id,
                json!({
                    "type": "window_created",
                    "payload": { "window_id": wid, "label": label },
                }),
            ),
        );
    }
}

fn emit_view_changed(state: &State, session_id: &str, revision: u64) {
    state.emit_to_session(
        session_id,
        session_event(
            session_id,
            json!({
                "type": "session_view_changed",
                "payload": { "revision": revision },
            }),
        ),
    );
}

// -- session methods ------------------------------------------------------

fn session_create(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let cap = state.max_sessions.load(std::sync::atomic::Ordering::SeqCst);
    if cap > 0 && state.sessions.lock().unwrap().len() as u64 >= cap {
        return Err(ApiError::conflict("session limit reached"));
    }
    let label = opt_str(payload, "label")
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty())
        .unwrap_or_else(auto_label);
    let sid = ids::session();
    let initial = payload
        .get("initial_windows")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let mut session = Session {
        id: sid.clone(),
        label: label.clone(),
        revision: 0,
        windows: Vec::new(),
        active_window: None,
        blocks: IndexMap::new(),
    };
    let mut created_windows = Vec::new();

    for (i, w) in initial.into_iter().enumerate() {
        let spec = parse_layout_required(
            w.get("layout"),
            &format!("initial_windows[{i}]: layout is required"),
        )?;
        validate_create_layout(&spec, &format!("initial_windows[{i}]: "))?;
        let wlabel = w
            .get("window_label")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let nw = make_window(state, &sid, &wlabel, &spec, client_id)?;
        session.blocks.extend(nw.blocks);
        if session.active_window.is_none() {
            session.active_window = Some(nw.window.id.clone());
        }
        session.revision += 1;
        created_windows.push(json!({
            "window_id": nw.window.id,
            "block_ids": nw.created,
            "revision": session.revision,
        }));
        session.windows.push(nw.window);
    }

    state.sessions.lock().unwrap().push(session);
    state.emit_server_event(json!({
        "type": "session_created",
        "payload": { "session": { "session_id": sid, "label": label } },
    }));
    let mut out = json!({ "session_id": sid });
    if !created_windows.is_empty() {
        out["initial_windows"] = json!(created_windows);
    }
    Ok(out)
}

fn session_attach(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let view = {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        session_view(s, &state.host_id)
    };
    state.subscribe(&sid, client_id);
    let event = session_event(
        &sid,
        json!({
            "type": "client_connected",
            "payload": {
                "client_id": client_id,
                "principal": state.client_principal(client_id),
                "connected_at": Utc::now().to_rfc3339(),
            },
        }),
    );
    state.emit_to_session(&sid, event);
    Ok(json!({ "client_id": client_id, "view": view }))
}

fn session_attach_all(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let scope = opt_str(payload, "event_scope").unwrap_or_else(|| "session".into());
    state.set_client_all_events(client_id, scope == "all");
    let sessions = session_list(state);
    if scope == "all" {
        for s in &sessions {
            if let Some(sid) = s.get("session_id").and_then(|x| x.as_str()) {
                state.subscribe(sid, client_id);
            }
        }
    }
    Ok(json!({ "sessions": sessions }))
}

fn session_bootstrap(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let attach_all = session_attach_all(state, client_id, payload)?;
    let preferred = opt_id_str(payload, "preferred_session_id", "session")?;
    let selected = preferred.and_then(|sid| {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|s| s.id == sid)
            .map(|s| json!({ "session_id": s.id, "view": session_view(s, &state.host_id) }))
    });
    Ok(json!({
        "client_id": client_id,
        "server_status": server_status(state, Some(client_id)),
        "attach_all": attach_all,
        "selected_session": selected,
    }))
}

fn session_detach(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    state.unsubscribe(&sid, client_id);
    let event = session_event(
        &sid,
        json!({
            "type": "client_disconnected",
            "payload": {
                "client_id": client_id,
                "principal": state.client_principal(client_id),
            },
        }),
    );
    state.emit_to_session(&sid, event);
    Ok(json!({}))
}

fn session_destroy(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let removed = {
        let mut sessions = state.sessions.lock().unwrap();
        match sessions.iter().position(|s| s.id == sid) {
            Some(i) => sessions.remove(i),
            None => return Err(ApiError::session_not_found(&sid)),
        }
    };
    for b in removed.blocks.values() {
        if let Some(t) = &b.terminal {
            t.close();
        }
    }
    state.subs.lock().unwrap().remove(&sid);
    state.emit_server_event(json!({
        "type": "session_destroyed",
        "payload": { "session_id": sid },
    }));
    Ok(json!({}))
}

fn session_new_window(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let spec = parse_layout_required(
        payload.get("layout"),
        "input: validating: layout is required",
    )?;
    validate_create_layout(&spec, "input: validating: ")?;
    let wlabel = opt_str(payload, "window_label").unwrap_or_default();
    let focus = opt_bool(payload, "focus", true);
    if !state.session_exists(&sid) {
        return Err(ApiError::session_not_found(&sid));
    }
    let nw = make_window(state, &sid, &wlabel, &spec, client_id)?;
    let window_id = nw.window.id.clone();
    let window_label = nw.window.label.clone();
    let created = nw.created.clone();
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == sid).unwrap();
        s.blocks.extend(nw.blocks);
        if focus || s.active_window.is_none() {
            s.active_window = Some(window_id.clone());
        }
        s.windows.push(nw.window);
        s.revision += 1;
        s.revision
    };
    emit_created(
        state,
        &sid,
        &created,
        Some((&window_id, &window_label)),
        client_id,
    );
    emit_view_changed(state, &sid, revision);
    Ok(json!({
        "window_id": window_id,
        "block_ids": created,
        "revision": revision,
    }))
}

fn find_node_rect(n: &Layout, id: &str) -> Option<Rect> {
    match n {
        Layout::Leaf { rect, block_id } => {
            if block_id == id {
                Some(*rect)
            } else {
                None
            }
        }
        Layout::Split {
            rect,
            split_id,
            before,
            after,
            ..
        } => {
            if split_id == id {
                return Some(*rect);
            }
            find_node_rect(before, id).or_else(|| find_node_rect(after, id))
        }
    }
}

fn find_in_session(s: &Session, id: &str) -> Option<(usize, usize, Rect)> {
    for (wi, w) in s.windows.iter().enumerate() {
        for (li, l) in w.layers.iter().enumerate() {
            if let Some(layout) = &l.layout {
                if let Some(rect) = find_node_rect(layout, id) {
                    return Some((wi, li, rect));
                }
            }
        }
    }
    None
}

fn session_new_split(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let direction = req_str(payload, "direction")?;
    let side = req_str(payload, "side")?;
    if !matches!(direction.as_str(), "horizontal" | "vertical") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown split direction \"{direction}\""
        )));
    }
    if !matches!(side.as_str(), "before" | "after") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown side \"{side}\""
        )));
    }
    let ratio = req_split_ratio(payload, "ratio", 0.5)?;
    let focus = opt_bool(payload, "focus", false);
    let spec = parse_layout_required(
        payload.get("layout"),
        "input: validating: layout is required",
    )?;
    validate_create_layout(&spec, "input: validating: ")?;
    let anchor_req = opt_anchor_id(payload)?;
    let window_req = opt_id_str(payload, "window_id", "window")?;
    if anchor_req.is_some() && window_req.is_some() {
        return Err(ApiError::bad_request(
            "input: validating: anchor_id and window_id are mutually exclusive",
        ));
    }

    let (anchor, rect, window_idx) = {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let anchor = if let Some(a) = anchor_req.clone() {
            a
        } else if let Some(wid) = window_req.clone() {
            let w = s
                .windows
                .iter()
                .find(|w| w.id == wid)
                .ok_or_else(|| ApiError::not_found(format!("window {wid} not found")))?;
            w.focused_block
                .clone()
                .ok_or_else(|| ApiError::conflict("window has no focused block"))?
        } else {
            let w = s
                .windows
                .iter()
                .find(|w| Some(&w.id) == s.active_window.as_ref())
                .or_else(|| s.windows.first())
                .ok_or_else(|| ApiError::conflict("session has no windows"))?;
            w.focused_block
                .clone()
                .ok_or_else(|| ApiError::conflict("window has no focused block"))?
        };
        let (wi, _li, rect) = find_in_session(s, &anchor).ok_or_else(|| {
            let kind = if anchor.starts_with("split:") {
                "split"
            } else {
                "block"
            };
            ApiError::not_found(format!("{kind} {anchor} not found in any window"))
        })?;
        (anchor, rect, wi)
    };

    let new_rect = split_rect(rect, &direction, ratio, side == "before");
    let mut blocks = IndexMap::new();
    let mut created = Vec::new();
    let new_layout = build_layout(
        state,
        &sid,
        &spec,
        new_rect,
        client_id,
        &mut blocks,
        &mut created,
    )?;
    let mut nested_splits = Vec::new();
    collect_split_ids(&new_layout, &mut nested_splits);

    let (revision, split_id) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == sid).unwrap();
        let layer = &mut s.windows[window_idx].layers[0];
        let layout = layer
            .layout
            .as_mut()
            .ok_or_else(|| ApiError::conflict("layer has no layout"))?;
        let split_id = split_at(layout, &anchor, &direction, &side, ratio, new_layout)
            .ok_or_else(|| ApiError::not_found(format!("anchor {anchor}")))?;
        s.blocks.extend(blocks);
        if focus {
            s.active_window = Some(s.windows[window_idx].id.clone());
            s.windows[window_idx].focused_block = created.first().cloned();
        }
        s.revision += 1;
        (s.revision, split_id)
    };

    emit_created(state, &sid, &created, None, client_id);
    emit_view_changed(state, &sid, revision);
    let mut split_ids = vec![split_id];
    split_ids.extend(nested_splits);
    Ok(json!({
        "anchor_id": anchor,
        "block_ids": created,
        "split_ids": split_ids,
        "revision": revision,
    }))
}

fn session_focus_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let wi = s
            .windows
            .iter()
            .position(|w| {
                w.layers.iter().any(|l| {
                    l.layout
                        .as_ref()
                        .map(|n| find_node_rect(n, &bid).is_some())
                        .unwrap_or(false)
                })
            })
            .ok_or_else(|| ApiError::not_found(format!("block {bid} not found in any window")))?;
        let active = s.active_window.as_deref() == Some(s.windows[wi].id.as_str());
        let focused = s.windows[wi].focused_block.as_deref() == Some(bid.as_str());
        if active && focused {
            (s.revision, false)
        } else {
            if !focused {
                s.windows[wi].zoomed_block = None;
            }
            s.windows[wi].focused_block = Some(bid);
            s.active_window = Some(s.windows[wi].id.clone());
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_focus_window(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let wid = req_str(payload, "window_id")?;
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if !s.windows.iter().any(|w| w.id == wid) {
            return Err(ApiError::not_found(format!("window {wid} not found")));
        }
        if s.active_window.as_deref() == Some(wid.as_str()) {
            (s.revision, false)
        } else {
            s.active_window = Some(wid);
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

/// Pick the nearest eligible block in screen-space. `candidates` must be
/// ordered front-to-back, with blocks in each layer in layout order; that
/// ordering resolves exact ties the same way the server does.
fn choose_directional_focus(
    candidates: &[(String, Rect)],
    focused: &str,
    direction: &str,
    wrap: bool,
) -> Option<String> {
    let cur = candidates
        .iter()
        .find(|(id, _)| id == focused)
        .map(|(_, rect)| *rect)?;
    let cur_cx = cur[0] + cur[2] / 2.0;
    let cur_cy = cur[1] + cur[3] / 2.0;
    let mut best: Option<(f64, f64, usize, String)> = None;
    let mut opposite: Option<(f64, f64, usize, String)> = None;

    for (idx, (id, rect)) in candidates.iter().enumerate() {
        if id == focused {
            continue;
        }
        let cx = rect[0] + rect[2] / 2.0;
        let cy = rect[1] + rect[3] / 2.0;
        // A block lies in a direction only when it is wholly on that side
        // of the focused block; touching edges count. Diagonal candidates
        // are allowed if their near edge clears the focused block's far edge.
        let (in_direction, gap, secondary, opposite_edge) = match direction {
            "left" => (
                rect[0] + rect[2] <= cur[0] + 1e-9,
                (cur[0] - (rect[0] + rect[2])).max(0.0),
                (cy - cur_cy).abs(),
                -cx,
            ),
            "right" => (
                rect[0] >= cur[0] + cur[2] - 1e-9,
                (rect[0] - (cur[0] + cur[2])).max(0.0),
                (cy - cur_cy).abs(),
                cx,
            ),
            "up" => (
                rect[1] + rect[3] <= cur[1] + 1e-9,
                (cur[1] - (rect[1] + rect[3])).max(0.0),
                (cx - cur_cx).abs(),
                -cy,
            ),
            "down" => (
                rect[1] >= cur[1] + cur[3] - 1e-9,
                (rect[1] - (cur[1] + cur[3])).max(0.0),
                (cx - cur_cx).abs(),
                cy,
            ),
            _ => return None,
        };
        let score = (gap + secondary * 0.5, secondary, idx, id.clone());
        if in_direction
            && best
                .as_ref()
                .map(|b| (score.0, score.1, score.2) < (b.0, b.1, b.2))
                .unwrap_or(true)
        {
            best = Some(score);
        }
        let opposite_score = (opposite_edge, secondary, idx, id.clone());
        if opposite
            .as_ref()
            .map(|b| (opposite_score.0, opposite_score.1, opposite_score.2) < (b.0, b.1, b.2))
            .unwrap_or(true)
        {
            opposite = Some(opposite_score);
        }
    }

    best.or_else(|| if wrap { opposite } else { None })
        .map(|(_, _, _, id)| id)
}

fn session_focus_relative(
    state: &Arc<State>,
    payload: &Value,
    delta: i32,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let wi = s
            .windows
            .iter()
            .position(|w| Some(&w.id) == s.active_window.as_ref())
            .unwrap_or(0);
        let mut ids = Vec::new();
        if let Some(l) = s.windows.get(wi).and_then(|w| w.layers.first()) {
            if let Some(layout) = &l.layout {
                collect_block_ids(layout, &mut ids);
            }
        }
        if ids.is_empty() {
            return Ok(json!({ "revision": s.revision }));
        }
        let cur = s.windows[wi]
            .focused_block
            .as_ref()
            .and_then(|b| ids.iter().position(|x| x == b))
            .unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(ids.len() as i32) as usize;
        s.windows[wi].focused_block = Some(ids[next].clone());
        s.revision += 1;
        s.revision
    };
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_focus_window_relative(
    state: &Arc<State>,
    payload: &Value,
    delta: i32,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if s.windows.is_empty() {
            return Ok(json!({ "revision": s.revision }));
        }
        let cur = s
            .windows
            .iter()
            .position(|w| Some(&w.id) == s.active_window.as_ref())
            .unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(s.windows.len() as i32) as usize;
        s.active_window = Some(s.windows[next].id.clone());
        s.revision += 1;
        s.revision
    };
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_set_label(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let label = req_str(payload, "label")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        s.label = label.clone();
        s.revision += 1;
        s.revision
    };
    state.emit_to_session(
        &sid,
        session_event(
            &sid,
            json!({ "type": "session_label_changed", "payload": { "label": label } }),
        ),
    );
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_set_window_label(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let wid = req_str(payload, "window_id")?;
    let requested_label = req_str(payload, "label")?;
    let label = if requested_label.trim().is_empty() {
        default_window_label(&wid)
    } else {
        requested_label.trim().to_string()
    };
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let w = s
            .windows
            .iter_mut()
            .find(|w| w.id == wid)
            .ok_or_else(|| ApiError::not_found(format!("window {wid}")))?;
        if w.label == label {
            return Ok(json!({ "revision": s.revision }));
        }
        w.label = label.clone();
        s.revision += 1;
        (s.revision, true)
    };
    if changed {
        state.emit_to_session(
            &sid,
            session_event(
                &sid,
                json!({
                    "type": "window_label_changed",
                    "payload": { "window_id": wid, "label": label },
                }),
            ),
        );
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_set_block_label(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let label = req_str(payload, "label")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let b = s
            .blocks
            .get_mut(&bid)
            .ok_or_else(|| ApiError::not_found(format!("block {bid}")))?;
        b.label = label;
        s.revision += 1;
        s.revision
    };
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_close_window(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let wid = req_str(payload, "window_id")?;
    let (revision, closed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let wi = s
            .windows
            .iter()
            .position(|w| w.id == wid)
            .ok_or_else(|| ApiError::not_found(format!("window {wid}")))?;
        let w = s.windows.remove(wi);
        let mut ids = Vec::new();
        for l in &w.layers {
            if let Some(layout) = &l.layout {
                collect_block_ids(layout, &mut ids);
            }
        }
        for id in &ids {
            if let Some(b) = s.blocks.shift_remove(id) {
                if let Some(t) = b.terminal {
                    t.close();
                }
            }
        }
        if s.active_window.as_ref() == Some(&wid) {
            s.active_window = s.windows.first().map(|w| w.id.clone());
        }
        s.revision += 1;
        (s.revision, ids)
    };
    state.emit_to_session(
        &sid,
        session_event(
            &sid,
            json!({ "type": "window_closed", "payload": { "window_id": wid } }),
        ),
    );
    for id in closed {
        state.emit_to_session(
            &sid,
            session_event(
                &sid,
                json!({ "type": "block_closed", "payload": { "block_id": id } }),
            ),
        );
    }
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_close_layer(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let layer_id = req_str(payload, "layer_id")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let mut closed = Vec::new();
        for w in s.windows.iter_mut() {
            if let Some(pos) = w.layers.iter().position(|l| l.id == layer_id) {
                let l = w.layers.remove(pos);
                if let Some(layout) = &l.layout {
                    collect_block_ids(layout, &mut closed);
                }
                for id in &closed {
                    if let Some(b) = s.blocks.shift_remove(id) {
                        if let Some(t) = b.terminal {
                            t.close();
                        }
                    }
                }
                break;
            }
        }
        s.revision += 1;
        s.revision
    };
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_zoom_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = opt_id_str(payload, "block_id", "block")?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        for w in s.windows.iter_mut() {
            if w.zoomed_block == bid {
                w.zoomed_block = None;
            } else if bid.is_some() {
                w.zoomed_block = bid.clone();
            }
        }
        s.revision += 1;
        s.revision
    };
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "revision": revision }))
}

fn session_focus_direction(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let direction = req_str(payload, "direction")?;
    if !matches!(direction.as_str(), "left" | "right" | "up" | "down") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown direction \"{direction}\""
        )));
    }
    let wrap = opt_bool(payload, "wrap", false);
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let wi =
            active_window_index(s).ok_or_else(|| ApiError::conflict("session has no windows"))?;
        let focused = s.windows[wi]
            .focused_block
            .clone()
            .ok_or_else(|| ApiError::conflict("window has no focused block"))?;
        // Front-most layers win ties, so walk floating layers front to back
        // and the tiled layout last.
        let mut candidates: Vec<(String, Rect)> = Vec::new();
        for layer in s.windows[wi].layers.iter().rev() {
            if let Some(layout) = &layer.layout {
                let mut ids = Vec::new();
                collect_block_ids(layout, &mut ids);
                for id in ids {
                    if let Some(rect) = find_node_rect(layout, &id) {
                        candidates.push((id, layer_rect(layer, rect)));
                    }
                }
            }
        }
        let chosen = choose_directional_focus(&candidates, &focused, &direction, wrap);
        match chosen {
            Some(id) => {
                s.windows[wi].focused_block = Some(id);
                s.windows[wi].zoomed_block = None;
                s.revision += 1;
                (s.revision, true)
            }
            None => (s.revision, false),
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_move(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let before = opt_id_str(payload, "before_session_id", "session")?;
    if before.as_deref() == Some(sid.as_str()) {
        return Err(ApiError::bad_request(
            "before_session_id must identify a different session",
        ));
    }
    if !state.subscribers(&sid).iter().any(|c| c == client_id) {
        return Err(ApiError::conflict(format!(
            "stream is not attached to session {sid}"
        )));
    }
    let mut sessions = state.sessions.lock().unwrap();
    let from = sessions
        .iter()
        .position(|s| s.id == sid)
        .ok_or_else(|| ApiError::session_not_found(&sid))?;
    let to = match &before {
        Some(b) => sessions
            .iter()
            .position(|s| &s.id == b)
            .ok_or_else(|| ApiError::not_found(format!("session {b}")))?,
        None => sessions.len(),
    };
    if from == to || from + 1 == to {
        return Ok(json!({}));
    }
    let session = sessions.remove(from);
    let to = if to > from { to - 1 } else { to };
    let to = to.min(sessions.len());
    sessions.insert(to, session);
    Ok(json!({}))
}

fn session_move_window(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let window_id = opt_id_str(payload, "window_id", "window")?;
    let before = opt_id_str(payload, "before_window_id", "window")?;
    if let (Some(w), Some(b)) = (&window_id, &before) {
        if w == b {
            return Err(ApiError::bad_request(
                "before_window_id must identify a different window",
            ));
        }
    }
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let from = match &window_id {
            Some(w) => s
                .windows
                .iter()
                .position(|x| &x.id == w)
                .ok_or_else(|| ApiError::not_found(format!("window {w}")))?,
            None => active_window_index(s)
                .ok_or_else(|| ApiError::conflict("session has no windows"))?,
        };
        let to = match &before {
            Some(b) => s
                .windows
                .iter()
                .position(|x| &x.id == b)
                .ok_or_else(|| ApiError::not_found(format!("window {b}")))?,
            None => s.windows.len(),
        };
        if from == to || from + 1 == to {
            (s.revision, false)
        } else {
            let window = s.windows.remove(from);
            let to = if to > from { to - 1 } else { to };
            s.windows.insert(to.min(s.windows.len()), window);
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_new_block(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let flavor = req_str(payload, "flavor")?;
    let label = opt_str(payload, "label");
    let options = payload.get("options").cloned().unwrap_or(Value::Null);
    if !state.session_exists(&sid) {
        return Err(ApiError::session_not_found(&sid));
    }
    let block = create_block(state, &sid, &flavor, label, &options, client_id)?;
    let block_id = block.id.clone();
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        s.blocks.insert(block_id.clone(), block);
        s.revision
    };
    emit_created(state, &sid, &[block_id.clone()], None, client_id);
    Ok(json!({ "block_id": block_id, "revision": revision }))
}

fn session_new_layer(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bounds = parse_rect(payload.get("bounds"))?;
    let spec = parse_layout_required(
        payload.get("layout"),
        "input: validating: layout is required",
    )?;
    validate_create_layout(&spec, "input: validating: ")?;
    let focus = opt_bool(payload, "focus", false);
    let window_req = opt_id_str(payload, "window_id", "window")?;
    let window_id = {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        match window_req {
            Some(wid) => {
                if !s.windows.iter().any(|w| w.id == wid) {
                    return Err(ApiError::not_found(format!("window {wid}")));
                }
                wid
            }
            None => {
                let wi = active_window_index(s)
                    .ok_or_else(|| ApiError::conflict("session has no windows"))?;
                s.windows[wi].id.clone()
            }
        }
    };

    let layer_id = ids::layer();
    let mut blocks = IndexMap::new();
    let mut created = Vec::new();
    let layout = build_layout(
        state,
        &sid,
        &spec,
        bounds,
        client_id,
        &mut blocks,
        &mut created,
    )?;
    let revision = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let wi = s
            .windows
            .iter()
            .position(|w| w.id == window_id)
            .ok_or_else(|| ApiError::not_found(format!("window {window_id}")))?;
        s.windows[wi].layers.push(Layer {
            id: layer_id.clone(),
            kind: "floating".into(),
            bounds,
            layout: Some(layout),
        });
        s.blocks.extend(blocks);
        if focus {
            s.active_window = Some(window_id);
            s.windows[wi].focused_block = created.first().cloned();
        }
        s.revision += 1;
        s.revision
    };
    emit_created(state, &sid, &created, None, client_id);
    emit_view_changed(state, &sid, revision);
    Ok(json!({
        "layer_id": layer_id,
        "block_ids": created,
        "revision": revision,
    }))
}

fn session_move_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let block_id = req_str(payload, "block_id")?;
    let anchor = req_str(payload, "anchor_block_id")?;
    if block_id == anchor {
        return Err(ApiError::bad_request(
            "input: validating: block_id and anchor_block_id must differ",
        ));
    }
    let direction = opt_str(payload, "direction").unwrap_or_else(|| "horizontal".into());
    let side = opt_str(payload, "side").unwrap_or_else(|| "after".into());
    if !matches!(direction.as_str(), "horizontal" | "vertical") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown direction \"{direction}\""
        )));
    }
    if !matches!(side.as_str(), "before" | "after") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown side \"{side}\""
        )));
    }
    let ratio = req_split_ratio(payload, "ratio", 0.5)?;

    let (revision, created_split_id, removed_split_id, cleanup) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if !s.blocks.contains_key(&block_id) {
            return Err(ApiError::not_found(format!(
                "block {block_id} not found in any window"
            )));
        }
        if !s.blocks.contains_key(&anchor) {
            return Err(ApiError::not_found(format!(
                "block {anchor} not found in any window"
            )));
        }
        let source_window_id =
            find_in_session(s, &block_id).map(|(wi, _, _)| s.windows[wi].id.clone());
        let dest_window_id = find_in_session(s, &anchor).map(|(wi, _, _)| s.windows[wi].id.clone());
        let was_focused = s
            .windows
            .iter()
            .any(|w| w.focused_block.as_deref() == Some(block_id.as_str()));
        let (_, removed_split_id) = remove_block_from_session(s, &block_id);
        let cleanup = cleanup_windows(s);
        let (wi, li, rect) = find_in_session(s, &anchor).ok_or_else(|| {
            ApiError::not_found(format!("block {anchor} not found in any window"))
        })?;
        let new_rect = split_rect(rect, &direction, ratio, side == "before");
        let new_layout = Layout::Leaf {
            rect: new_rect,
            block_id: block_id.clone(),
        };
        let layer = &mut s.windows[wi].layers[li];
        let layout = layer
            .layout
            .as_mut()
            .ok_or_else(|| ApiError::conflict("anchor layer has no layout"))?;
        let created_split_id = split_at(layout, &anchor, &direction, &side, ratio, new_layout)
            .ok_or_else(|| ApiError::not_found(format!("anchor {anchor}")))?;
        if was_focused {
            s.windows[wi].focused_block = Some(block_id.clone());
            s.active_window = Some(s.windows[wi].id.clone());
        }
        // A move changes both windows it touches, so any zoom in them ends.
        for w in s.windows.iter_mut() {
            if Some(&w.id) == source_window_id.as_ref() || Some(&w.id) == dest_window_id.as_ref() {
                w.zoomed_block = None;
            }
        }
        s.revision += 1;
        (s.revision, created_split_id, removed_split_id, cleanup)
    };
    emit_window_cleanup(state, &sid, &cleanup);
    emit_view_changed(state, &sid, revision);
    let mut out = json!({
        "created_split_id": created_split_id,
        "revision": revision,
    });
    if let Some(removed_split_id) = removed_split_id {
        out["removed_split_id"] = json!(removed_split_id);
    }
    Ok(out)
}

fn session_swap_blocks(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let a = req_str(payload, "block_id")?;
    let b = req_str(payload, "other_block_id")?;
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if !s.blocks.contains_key(&a) {
            return Err(ApiError::not_found(format!(
                "block {a} not found in any window"
            )));
        }
        if !s.blocks.contains_key(&b) {
            return Err(ApiError::not_found(format!(
                "block {b} not found in any window"
            )));
        }
        if a == b {
            return Err(ApiError::bad_request(
                "input: validating: block_id and other_block_id must differ",
            ));
        } else {
            if find_in_session(s, &a).is_none() || find_in_session(s, &b).is_none() {
                return Err(ApiError::not_found(format!(
                    "block {} not found in any window",
                    if find_in_session(s, &a).is_none() {
                        &a
                    } else {
                        &b
                    }
                )));
            }
            let focused = active_window_index(s).and_then(|wi| s.windows[wi].focused_block.clone());
            const TMP: &str = "\u{0}rux-swap";
            for w in s.windows.iter_mut() {
                for l in w.layers.iter_mut() {
                    if let Some(layout) = l.layout.as_mut() {
                        replace_block_id(layout, &a, TMP);
                    }
                }
            }
            for w in s.windows.iter_mut() {
                for l in w.layers.iter_mut() {
                    if let Some(layout) = l.layout.as_mut() {
                        replace_block_id(layout, &b, &a);
                    }
                }
            }
            for w in s.windows.iter_mut() {
                for l in w.layers.iter_mut() {
                    if let Some(layout) = l.layout.as_mut() {
                        replace_block_id(layout, TMP, &b);
                    }
                }
            }
            if let Some(focused) = focused {
                if focused == a || focused == b {
                    if let Some((wi, _, _)) = find_in_session(s, &focused) {
                        s.active_window = Some(s.windows[wi].id.clone());
                        s.windows[wi].focused_block = Some(focused);
                    }
                }
            }
            for w in s.windows.iter_mut() {
                repair_window_focus(w);
            }
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_resize_pane(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let direction = req_str(payload, "direction")?;
    if !matches!(direction.as_str(), "horizontal" | "vertical") {
        return Err(ApiError::bad_request(format!(
            "decoding input: unknown direction \"{direction}\""
        )));
    }
    let before = req_str(payload, "before_block_id")?;
    let after = req_str(payload, "after_block_id")?;
    if before == after {
        return Err(ApiError::bad_request(
            "input: validating: before_block_id and after_block_id must differ",
        ));
    }
    let ratio = req_ratio(payload, "ratio", None)?;
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let (before_wi, before_li, _) = find_in_session(s, &before).ok_or_else(|| {
            ApiError::not_found(format!("block {before} not found in any window"))
        })?;
        let (after_wi, after_li, _) = find_in_session(s, &after)
            .ok_or_else(|| ApiError::not_found(format!("block {after} not found in any window")))?;
        if before_wi != after_wi {
            return Err(ApiError::bad_request(format!(
                "blocks {before} and {after} are not in the same window"
            )));
        }
        if before_li != after_li {
            return Err(ApiError::bad_request(format!(
                "blocks {before} and {after} are not in the same layer"
            )));
        }
        let layout = s.windows[before_wi].layers[before_li]
            .layout
            .as_mut()
            .ok_or_else(|| {
                ApiError::not_found(format!("block {before} not found in any window"))
            })?;
        match resize_split_between(layout, &direction, &before, &after, ratio) {
            Some(true) => {
                s.revision += 1;
                (s.revision, true)
            }
            Some(false) => (s.revision, false),
            None => {
                return Err(ApiError::bad_request(format!(
                    "no {direction} split has block {before} before it and block {after} after it"
                )));
            }
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_resize_layer(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let layer_id = opt_id_str(payload, "layer_id", "layer")?;
    let bounds = parse_rect(payload.get("bounds"))?;
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let (wi, li) = find_layer(s, layer_id.as_deref())
            .ok_or_else(|| ApiError::not_found("floating layer"))?;
        let layer = &mut s.windows[wi].layers[li];
        if layer.kind != "floating" {
            return Err(ApiError::bad_request("layer is not floating"));
        }
        if layer.bounds == bounds {
            (s.revision, false)
        } else {
            layer.bounds = bounds;
            if let Some(layout) = layer.layout.as_mut() {
                set_rect(layout, bounds);
            }
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_float_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let block_id = req_str(payload, "block_id")?;
    let bounds = parse_rect(payload.get("bounds"))?;
    let (revision, layer_id, cleanup) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if !s.blocks.contains_key(&block_id) {
            return Err(ApiError::not_found(format!("block {block_id}")));
        }
        let (wi, li, _) = find_in_session(s, &block_id).ok_or_else(|| {
            ApiError::not_found(format!("block {block_id} not found in any window"))
        })?;
        if s.windows[wi].layers[li].kind == "floating" {
            return Err(ApiError::bad_request(format!(
                "block {block_id} is already in floating layer {}",
                s.windows[wi].layers[li].id
            )));
        }
        let layer_id = ids::layer();
        let mut clear = false;
        if let Some(layout) = s.windows[wi].layers[li].layout.as_mut() {
            match remove_block_tracked(layout, &block_id) {
                RemoveResult::NotFound => {
                    return Err(ApiError::bad_request(format!(
                        "block {block_id} is not in a window"
                    )));
                }
                RemoveResult::RootLeaf => clear = true,
                RemoveResult::Collapsed(_) => {}
            }
        }
        if clear {
            s.windows[wi].layers[li].layout = None;
        }
        s.windows[wi].layers.push(Layer {
            id: layer_id.clone(),
            kind: "floating".into(),
            bounds,
            layout: Some(Layout::Leaf {
                rect: bounds,
                block_id: block_id.clone(),
            }),
        });
        s.windows[wi].zoomed_block = None;
        let cleanup = cleanup_windows(s);
        s.revision += 1;
        (s.revision, layer_id, cleanup)
    };
    emit_window_cleanup(state, &sid, &cleanup);
    emit_view_changed(state, &sid, revision);
    Ok(json!({ "layer_id": layer_id, "revision": revision }))
}

fn session_detach_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let block_id = req_str(payload, "block_id")?;
    let (revision, changed, cleanup) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        if !s.blocks.contains_key(&block_id) {
            return Err(ApiError::not_found(format!("block {block_id}")));
        }
        let (placed, _) = remove_block_from_session(s, &block_id);
        if !placed {
            (
                s.revision,
                false,
                LayoutCleanup {
                    removed_windows: Vec::new(),
                    active_changed: false,
                    active_window: s.active_window.clone(),
                },
            )
        } else {
            let cleanup = cleanup_windows(s);
            s.revision += 1;
            (s.revision, true, cleanup)
        }
    };
    emit_window_cleanup(state, &sid, &cleanup);
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn session_raise_layer(
    state: &Arc<State>,
    payload: &Value,
    raise: bool,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let layer_id = opt_id_str(payload, "layer_id", "layer")?;
    let relative_id = opt_id_str(payload, "relative_layer_id", "layer")?;
    if let (Some(a), Some(b)) = (&layer_id, &relative_id) {
        if a == b {
            return Err(ApiError::bad_request(
                "relative_layer_id must identify a different layer",
            ));
        }
    }
    let (revision, changed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let (wi, li) = find_layer(s, layer_id.as_deref())
            .ok_or_else(|| ApiError::not_found("floating layer"))?;
        if s.windows[wi].layers[li].kind != "floating" {
            return Err(ApiError::bad_request("layer is not floating"));
        }
        let w = &mut s.windows[wi];
        if let Some(relative_id) = &relative_id {
            let relative = w
                .layers
                .iter()
                .find(|l| &l.id == relative_id)
                .ok_or_else(|| ApiError::not_found(format!("layer {relative_id}")))?;
            if relative.kind != "floating" {
                return Err(ApiError::bad_request("relative layer is not floating"));
            }
        }
        let old_order: Vec<String> = w.layers.iter().map(|l| l.id.clone()).collect();
        let layer = w.layers.remove(li);
        let insert_at = if raise {
            match &relative_id {
                Some(relative_id) => w
                    .layers
                    .iter()
                    .position(|l| &l.id == relative_id)
                    .map(|i| i + 1)
                    .ok_or_else(|| ApiError::not_found(format!("layer {relative_id}")))?,
                None => w.layers.len(),
            }
        } else {
            match &relative_id {
                Some(relative_id) => w
                    .layers
                    .iter()
                    .position(|l| &l.id == relative_id)
                    .ok_or_else(|| ApiError::not_found(format!("layer {relative_id}")))?,
                None => w
                    .layers
                    .iter()
                    .rposition(|l| l.kind == "tiled")
                    .map(|i| i + 1)
                    .unwrap_or(0),
            }
        };
        w.layers.insert(insert_at.min(w.layers.len()), layer);
        let new_order: Vec<String> = w.layers.iter().map(|l| l.id.clone()).collect();
        if old_order == new_order {
            (s.revision, false)
        } else {
            s.revision += 1;
            (s.revision, true)
        }
    };
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "revision": revision }))
}

fn requested_block_ids(payload: &Value, s: &Session) -> Result<Vec<String>, ApiError> {
    match payload.get("block_ids").and_then(Value::as_array) {
        Some(ids) if !ids.is_empty() => {
            let mut out = Vec::new();
            for value in ids {
                let id = value.as_str().ok_or_else(|| {
                    ApiError::bad_request("decoding input: block_ids entries must be strings")
                })?;
                let id = decode_id_value(id, "block")?;
                if !out.iter().any(|seen| seen == &id) {
                    out.push(id);
                }
            }
            Ok(out)
        }
        _ => Ok(s.blocks.keys().cloned().collect()),
    }
}

fn session_own_block(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let mode = opt_str(payload, "mode").unwrap_or_else(|| "take".into());
    if !matches!(mode.as_str(), "take" | "request") {
        return Err(ApiError::bad_request(format!(
            "unknown mode \"{mode}\": expected \"take\" or \"request\""
        )));
    }
    let (revision, changed, blocks, events, claimed) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let ids = requested_block_ids(payload, s)?;
        for id in &ids {
            if !s.blocks.contains_key(id) {
                return Err(ApiError::bad_request(format!(
                    "block {id} is not in the session"
                )));
            }
        }
        let mut events = Vec::new();
        let mut changed = false;
        let mut claimed = Vec::new();
        for id in &ids {
            let block = s.blocks.get_mut(id).expect("validated above");
            let claim = match mode.as_str() {
                "take" => block.owner.as_deref() != Some(client_id),
                _ => block.owner.is_none(),
            };
            if claim {
                block.owner = Some(client_id.to_string());
                events.push(json!({
                    "block_id": id,
                    "owner": client_id,
                    "reason": mode,
                }));
                claimed.push(id.clone());
                changed = true;
            }
        }
        let blocks: Vec<Value> = ids
            .iter()
            .filter_map(|id| s.blocks.get(id))
            .map(|b| block_owner_json(&b.id, b.owner.as_ref()))
            .collect();
        if changed {
            s.revision += 1;
        }
        (s.revision, changed, blocks, events, claimed)
    };
    for event in events {
        state.emit_to_session(
            &sid,
            session_event(
                &sid,
                json!({ "type": "block_owner_changed", "payload": event }),
            ),
        );
    }
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    // The exit path only auto-closes a pane when its owner at exit time is
    // an app client. A block whose process exited while owned by a non-app
    // client (say a CLI that created it and disconnected) is therefore kept
    // forever, and an app taking ownership of it later would face a dead
    // pane that nothing closes. Sweep those here: an app claiming a block
    // whose process already exited closes it, as the exit path would have.
    let caller_is_app = state
        .clients
        .lock()
        .unwrap()
        .get(client_id)
        .map(|c| c.info.kind == "app")
        .unwrap_or(false);
    if caller_is_app {
        for id in &claimed {
            let exited = {
                let sessions = state.sessions.lock().unwrap();
                sessions
                    .iter()
                    .find(|s| s.id == sid)
                    .and_then(|s| s.blocks.get(id))
                    .and_then(|b| b.terminal.as_ref())
                    .map(|t| t.has_exited())
                    .unwrap_or(false)
            };
            if exited {
                auto_close_app_block(state, &sid, id);
            }
        }
    }
    Ok(json!({ "blocks": blocks }))
}

fn session_disown_block(
    state: &Arc<State>,
    client_id: &str,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let (revision, changed, blocks, events) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let ids = requested_block_ids(payload, s)?;
        for id in &ids {
            if !s.blocks.contains_key(id) {
                return Err(ApiError::bad_request(format!(
                    "block {id} is not in the session"
                )));
            }
        }
        let mut events = Vec::new();
        let mut changed = false;
        for id in &ids {
            let block = s.blocks.get_mut(id).expect("validated above");
            if block.owner.as_deref() == Some(client_id) {
                let previous = block.owner.take();
                events.push(json!({
                    "block_id": id,
                    "previous": previous,
                    "reason": "disown",
                }));
                changed = true;
            }
        }
        let blocks: Vec<Value> = ids
            .iter()
            .filter_map(|id| s.blocks.get(id))
            .map(|b| block_owner_json(&b.id, b.owner.as_ref()))
            .collect();
        if changed {
            s.revision += 1;
        }
        (s.revision, changed, blocks, events)
    };
    for event in events {
        state.emit_to_session(
            &sid,
            session_event(
                &sid,
                json!({ "type": "block_owner_changed", "payload": event }),
            ),
        );
    }
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "blocks": blocks }))
}

fn session_list_blocks(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let sessions = state.sessions.lock().unwrap();
    let s = sessions
        .iter()
        .find(|s| s.id == sid)
        .ok_or_else(|| ApiError::session_not_found(&sid))?;
    let blocks: Vec<Value> = s
        .blocks
        .values()
        .map(|b| {
            let placed = find_in_session(s, &b.id);
            let mut v = json!({
                "block_id": b.id,
                "label": b.label,
                "creator_name": b.creator_name,
                "flavor": b.flavor,
                "host_id": b.host_id,
                "placement": if placed.is_some() { "placed" } else { "detached" },
            });
            if let Some((wi, _, _)) = placed {
                v["window_id"] = json!(s.windows[wi].id);
            }
            if let Some(owner) = &b.owner {
                v["owner"] = json!(owner);
            }
            v
        })
        .collect();
    Ok(json!({ "blocks": blocks }))
}

/// Close a terminal block whose child just exited, when the block's
/// owner is an `app` client. In the GUI flow the pane leaves the session
/// structure as soon as its shell exits: the block goes, an emptied
/// window goes with it, and a session with nothing left in it is
/// destroyed — the app simply mirrors the structure, so all of that has
/// to happen server-side. Blocks owned by any other client kind are not
/// touched; they keep the keep-open behaviour described in create_block.
fn auto_close_app_block(state: &Arc<State>, session_id: &str, block_id: &str) {
    let owner_is_app = {
        let owner = {
            let sessions = state.sessions.lock().unwrap();
            sessions
                .iter()
                .find(|s| s.id == session_id)
                .and_then(|s| s.blocks.get(block_id))
                .and_then(|b| b.owner.clone())
        };
        match owner {
            Some(owner_id) => {
                let clients = state.clients.lock().unwrap();
                clients
                    .get(&owner_id)
                    .map(|c| c.info.kind == "app")
                    .unwrap_or(false)
            }
            None => false,
        }
    };
    if !owner_is_app {
        return;
    }
    let _ = block_close(
        state,
        &json!({ "session_id": session_id, "block_id": block_id }),
    );
    let emptied = {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|s| s.id == session_id)
            .map(|s| s.windows.is_empty() && s.blocks.is_empty())
            .unwrap_or(false)
    };
    if emptied {
        let _ = session_destroy(state, &json!({ "session_id": session_id }));
    }
}

/// The block a window-scoped call acts on: the window's focused block,
/// falling back to its first block when focus is unset or stale.
fn focused_block_of_window(
    state: &Arc<State>,
    session_id: &str,
    window_id: &str,
) -> Result<String, ApiError> {
    let sessions = state.sessions.lock().unwrap();
    let s = sessions
        .iter()
        .find(|s| s.id == session_id)
        .ok_or_else(|| ApiError::session_not_found(session_id))?;
    let w = s
        .windows
        .iter()
        .find(|w| w.id == window_id)
        .ok_or_else(|| ApiError::not_found(format!("window {window_id}")))?;
    if let Some(bid) = &w.focused_block {
        if window_contains_block(w, bid) {
            return Ok(bid.clone());
        }
    }
    let mut ids = Vec::new();
    for l in &w.layers {
        if let Some(layout) = &l.layout {
            collect_block_ids(layout, &mut ids);
        }
    }
    ids.into_iter()
        .next()
        .ok_or_else(|| ApiError::not_found(format!("window {window_id} has no blocks")))
}

/// True when the block sits in a window and is that window's only block,
/// floating layers included. Detached blocks are not in any window and
/// return false.
fn is_last_block_in_window(state: &Arc<State>, session_id: &str, block_id: &str) -> bool {
    let sessions = state.sessions.lock().unwrap();
    let Some(s) = sessions.iter().find(|s| s.id == session_id) else {
        return false;
    };
    for w in &s.windows {
        let mut ids = Vec::new();
        for l in &w.layers {
            if let Some(layout) = &l.layout {
                collect_block_ids(layout, &mut ids);
            }
        }
        if ids.iter().any(|id| id == block_id) {
            return ids.len() <= 1;
        }
    }
    false
}

fn block_close(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let keep_last = opt_bool(payload, "keep_last", false);
    // The caller names the block directly, or names a window and means
    // its focused block — the GUI's Close Pane sends only the window.
    // Both at once is a client error, and so is neither.
    let bid = match (
        opt_id_str(payload, "block_id", "block")?,
        opt_id_str(payload, "window_id", "window")?,
    ) {
        (Some(bid), None) => bid,
        (None, Some(wid)) => focused_block_of_window(state, &sid, &wid)?,
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "send block_id or window_id, not both",
            ));
        }
        (None, None) => return Err(ApiError::bad_request("block_id is required")),
    };
    if keep_last && is_last_block_in_window(state, &sid, &bid) {
        return Err(ApiError::bad_request(
            "cannot close the last block in the window",
        ));
    }
    let (revision, changed, cleanup) = {
        let mut sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter_mut()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let block = s
            .blocks
            .shift_remove(&bid)
            .ok_or_else(|| ApiError::not_found(format!("block {bid}")))?;
        if let Some(t) = block.terminal {
            t.close();
        }
        let mut placed = false;
        for w in s.windows.iter_mut() {
            for l in w.layers.iter_mut() {
                let mut clear = false;
                if let Some(layout) = l.layout.as_mut() {
                    match remove_block_tracked(layout, &bid) {
                        RemoveResult::NotFound => {}
                        RemoveResult::RootLeaf => {
                            placed = true;
                            clear = true;
                        }
                        RemoveResult::Collapsed(_) => placed = true,
                    }
                }
                if clear {
                    l.layout = None;
                }
            }
        }
        let cleanup = cleanup_windows(s);
        if placed {
            s.revision += 1;
        }
        (s.revision, placed, cleanup)
    };
    state.emit_to_session(
        &sid,
        session_event(
            &sid,
            json!({ "type": "block_closed", "payload": { "block_id": bid } }),
        ),
    );
    emit_window_cleanup(state, &sid, &cleanup);
    if changed {
        emit_view_changed(state, &sid, revision);
    }
    Ok(json!({ "block_id": bid, "revision": revision }))
}

const MAX_REPLY_BYTES: usize = 983_040;

fn json_string_prefix(text: &str, max_encoded_bytes: usize) -> &str {
    if max_encoded_bytes < 2 {
        return "";
    }
    let mut encoded = 2usize; // surrounding JSON quotes
    let mut end = 0usize;
    for (index, ch) in text.char_indices() {
        let bytes = serde_json::to_vec(&ch.to_string()).unwrap_or_default();
        let char_bytes = bytes.len().saturating_sub(2);
        if encoded + char_bytes > max_encoded_bytes {
            break;
        }
        encoded += char_bytes;
        end = index + ch.len_utf8();
    }
    &text[..end]
}

fn block_format(term: &Arc<Terminal>, args: &Value) -> Result<Value, ApiError> {
    let format = args.get("format").and_then(Value::as_str).unwrap_or("text");
    if !matches!(format, "text" | "html" | "vt") {
        return Err(ApiError::bad_request(format!(
            "unknown terminal format {format:?}"
        )));
    }
    let trim = opt_bool(args, "trim", false);
    let unwrap = opt_bool(args, "unwrap", false);
    let content = {
        let screen = term.screen.lock().unwrap();
        match format {
            "vt" => screen.format_vt(),
            "html" => screen.format_html(trim, unwrap),
            _ => screen.format_text(trim, unwrap),
        }
    };
    let Some(requested) = args.get("max_bytes") else {
        if serde_json::to_vec(&Value::String(content.clone()))
            .unwrap_or_default()
            .len()
            > MAX_REPLY_BYTES
        {
            return Err(ApiError::new(
                413,
                "too_large",
                "terminal output exceeds one reply",
            ));
        }
        return Ok(json!({ "content": content }));
    };
    let requested = requested
        .as_i64()
        .ok_or_else(|| ApiError::bad_request("max_bytes must be an integer"))?;
    if requested < 0 {
        return Err(ApiError::bad_request("max_bytes must not be negative"));
    }
    let budget = if requested == 0 {
        MAX_REPLY_BYTES
    } else {
        (requested as usize).min(MAX_REPLY_BYTES)
    }
    .saturating_sub(256);
    let prefix = json_string_prefix(&content, budget);
    let mut response = json!({
        "content": prefix,
        "total": content.len(),
        "eof": prefix.len() == content.len(),
    });
    if prefix.len() < content.len() {
        response["id"] = json!(term.store_blob(content));
    }
    Ok(response)
}

fn block_blob_read(term: &Arc<Terminal>, args: &Value) -> Result<Value, ApiError> {
    let id = match args.get("id") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("id must be a non-negative integer"))?,
    };
    let offset = match args.get("offset") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("offset must be a non-negative integer"))?,
    };
    let requested = match args.get("max_bytes") {
        None | Some(Value::Null) => 49_152,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("max_bytes must be a non-negative integer"))?,
    };
    let max_bytes = if requested == 0 {
        49_152
    } else {
        requested.min(MAX_REPLY_BYTES as u64) as usize
    }
    .saturating_sub(128);
    let (id, text) = term
        .blob(id)
        .ok_or_else(|| ApiError::not_found("blob result not found"))?;
    let offset =
        usize::try_from(offset).map_err(|_| ApiError::bad_request("offset is too large"))?;
    if offset > text.len() {
        return Err(ApiError::bad_request(
            "offset is past the end of the result",
        ));
    }
    let mut start = offset;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let chunk = json_string_prefix(&text[start..], max_bytes);
    let end = start + chunk.len();
    Ok(json!({
        "id": id,
        "data": chunk,
        "total": text.len(),
        "eof": end == text.len(),
    }))
}

fn block_clipboard_read(term: &Arc<Terminal>, args: &Value) -> Result<Value, ApiError> {
    let id = match args.get("id") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("id must be a non-negative integer"))?,
    };
    let offset = match args.get("offset") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("offset must be a non-negative integer"))?,
    };
    let requested = match args.get("max_bytes") {
        None | Some(Value::Null) => 49_152,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::bad_request("max_bytes must be a non-negative integer"))?,
    };
    let budget = if requested == 0 {
        49_152
    } else {
        requested.min(MAX_REPLY_BYTES as u64) as usize
    }
    .saturating_sub(128);
    let (id, text) = term
        .clipboard_copy(id)
        .ok_or_else(|| ApiError::not_found("clipboard copy not found"))?;
    let offset =
        usize::try_from(offset).map_err(|_| ApiError::bad_request("offset is too large"))?;
    if offset > text.len() {
        return Err(ApiError::bad_request("offset is past the end of the copy"));
    }
    let mut start = offset;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let data = json_string_prefix(&text[start..], budget);
    let end = start + data.len();
    Ok(json!({
        "id": id,
        "data": data,
        "total": text.len(),
        "eof": end == text.len(),
    }))
}

fn block_list_dir(term: &Arc<Terminal>, args: &Value) -> Value {
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = terminal_cwd(&term.cwd(), &home);
    let requested = args.get("path").and_then(Value::as_str).unwrap_or("");
    let resolved = resolve_terminal_path(requested, cwd.as_deref(), &home);
    let display_path = resolved.to_string_lossy().into_owned();
    let files = opt_bool(args, "files", false);
    let prefix = args
        .get("prefix")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .filter(|limit| *limit > 0)
        .unwrap_or(2000)
        .min(2000) as usize;
    let mut entries = Vec::new();
    let read_dir = match std::fs::read_dir(&resolved) {
        Ok(entries) => entries,
        Err(err) => {
            let status = match err.kind() {
                std::io::ErrorKind::NotFound => "missing",
                std::io::ErrorKind::PermissionDenied => "denied",
                _ if resolved.exists() => "not_dir",
                _ => "missing",
            };
            return json!({
                "path": display_path,
                "home": home,
                "status": status,
                "entries": [],
                "truncated": false,
            });
        }
    };
    let mut truncated = false;
    for entry in read_dir {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.to_lowercase().starts_with(&prefix) {
            continue;
        }
        let Ok(link_metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let symlink = link_metadata.file_type().is_symlink();
        let Ok(metadata) = std::fs::metadata(entry.path()) else {
            // Rex leaves broken symlinks out of a listing.
            continue;
        };
        let is_file = !metadata.is_dir();
        if is_file && !files {
            continue;
        }
        if entries.len() == limit {
            truncated = true;
            break;
        }
        let mut item = json!({ "name": name, "symlink": symlink });
        if files {
            item["file"] = json!(is_file);
        }
        entries.push(item);
    }
    json!({
        "path": display_path,
        "home": home,
        "status": "ok",
        "entries": entries,
        "truncated": truncated,
    })
}

fn terminal_cwd(value: &str, home: &str) -> Option<std::path::PathBuf> {
    if value.is_empty() {
        return (!home.is_empty()).then(|| std::path::PathBuf::from(home));
    }
    let path = value
        .strip_prefix("file://")
        .map(|uri| uri.find('/').map(|i| &uri[i..]).unwrap_or(uri))
        .unwrap_or(value);
    Some(std::path::PathBuf::from(path))
}

fn resolve_terminal_path(
    path: &str,
    cwd: Option<&std::path::Path>,
    home: &str,
) -> std::path::PathBuf {
    let path = if path.is_empty() {
        cwd.map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from(home))
    } else if path == "~" {
        std::path::PathBuf::from(home)
    } else if let Some(suffix) = path.strip_prefix("~/") {
        std::path::PathBuf::from(home).join(suffix)
    } else {
        std::path::PathBuf::from(path)
    };
    if path.is_absolute() {
        path
    } else {
        cwd.unwrap_or_else(|| std::path::Path::new(home)).join(path)
    }
}

fn block_method(
    state: &Arc<State>,
    client_id: Option<&str>,
    payload: &Value,
) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let method = req_str(payload, "method")?;
    let mut args = payload.get("args").cloned().unwrap_or(Value::Null);
    if args.is_null() {
        args = json!({});
    }

    let (term, onboarding, creator_name) = {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let b = s
            .blocks
            .get(&bid)
            .ok_or_else(|| ApiError::not_found(format!("block {bid}")))?;
        (
            b.terminal.clone(),
            b.onboarding.clone(),
            b.creator_name.clone(),
        )
    };
    if let Some(schema) = block_args_schema(&state.help, &creator_name, &method) {
        crate::schema::reject_as(schema, &args, "args")?;
    }
    if let Some(onboarding) = onboarding {
        if creator_name != "com.superlogical.onboarding" {
            return Err(ApiError::conflict("block creator state is inconsistent"));
        }
        return match method.as_str() {
            "state" => {
                let onboarding = onboarding.lock().unwrap();
                let mut result = json!({ "generation": onboarding.generation });
                if !onboarding.step.is_empty() {
                    result["step"] = json!(onboarding.step);
                }
                Ok(result)
            }
            "set_step" => {
                let step = req_str(&args, "step")?;
                let changed = {
                    let mut onboarding = onboarding.lock().unwrap();
                    if onboarding.step == step {
                        (onboarding.generation, false)
                    } else {
                        onboarding.step = step.clone();
                        onboarding.generation += 1;
                        (onboarding.generation, true)
                    }
                };
                if changed.1 {
                    state.emit_to_session(
                        &sid,
                        crate::state::block_event(
                            &sid,
                            &bid,
                            "com.superlogical.onboarding",
                            "step_changed",
                            json!({ "generation": changed.0, "step": step }),
                        ),
                    );
                }
                let mut result = json!({ "generation": changed.0 });
                if !step.is_empty() {
                    result["step"] = json!(step);
                }
                Ok(result)
            }
            other => Err(ApiError::method_not_found(other)),
        };
    }
    let term = term.ok_or_else(|| ApiError::not_found(format!("block {bid} has no terminal")))?;

    match method.as_str() {
        "write" => {
            let data = req_str(&args, "data")?;
            let n = term.write(data.as_bytes());
            Ok(json!({ "bytes_written": n }))
        }
        "resize" => {
            let cols = args.get("columns").and_then(|x| x.as_u64()).unwrap_or(80) as u16;
            let rows = args.get("rows").and_then(|x| x.as_u64()).unwrap_or(24) as u16;
            // Arbitrated: inside another client's claim window this
            // is a no-op; the caller still gets the true size from
            // the next snapshot or resized event.
            term.resize_from(cols, rows, client_id);
            Ok(json!({}))
        }
        "size" => {
            let (cols, rows) = term.size();
            Ok(json!({
                "columns": cols,
                "rows": rows,
                "cell_width_px": 0,
                "cell_height_px": 0,
                "owner": Value::Null,
                "desired": [],
            }))
        }
        "format" => block_format(&term, &args),
        "title" => {
            let title = term.title();
            let mut body = json!({ "title": title });
            if !title.is_empty()
                && let Some(owner) = term.event_owner()
            {
                body["owner"] = owner;
            }
            Ok(body)
        }
        "pwd" => {
            let pwd = term.pwd();
            if pwd.is_empty() {
                Ok(json!({}))
            } else {
                let mut body = json!({ "pwd": pwd });
                if let Some(owner) = term.event_owner() {
                    body["owner"] = owner;
                }
                Ok(body)
            }
        }
        "modes" => {
            let screen = term.screen.lock().unwrap();
            Ok(json!({
                "screen": if screen.alternate_screen() { "alternate" } else { "primary" },
                "modes": screen.active_modes(),
            }))
        }
        "process" => Ok(term.process_info()),
        "input_mode" => Ok(term.input_mode()),
        "clear" => {
            term.clear_screen();
            Ok(json!({}))
        }
        "reset" => {
            term.reset_screen();
            Ok(json!({}))
        }
        "set_theme" => term
            .set_theme(&args)
            .map(|_| json!({}))
            .map_err(ApiError::bad_request),
        "program_status" => Ok(json!({ "records": term.program_status_records() })),
        "clipboard_read" => block_clipboard_read(&term, &args),
        "blob_read" => block_blob_read(&term, &args),
        "list_dir" => Ok(block_list_dir(&term, &args)),
        other => Err(ApiError::new(
            404,
            "method_not_found",
            format!("block method {other} not found"),
        )),
    }
}

/// First numeric value found under any of `keys`, as a 1-based cell
/// coordinate. Clients may send 0-based or 1-based, integer or float;
/// a 0 is read as the first cell either way.
fn raw_coord(body: &Value, keys: &[&str]) -> Option<u32> {
    for key in keys {
        if let Some(v) = body.get(key) {
            if let Some(n) = v.as_u64() {
                return Some((n.max(1) as u32).min(4096));
            }
            if let Some(f) = v.as_f64() {
                if f.is_finite() {
                    return Some((f.floor().max(1.0) as u32).min(4096));
                }
            }
        }
    }
    None
}

/// A cell coordinate from the app, which reports 0-based cells;
/// terminal mouse reports are 1-based.
fn event_cell(body: &Value, keys: &[&str]) -> u32 {
    fn raw(body: &Value, keys: &[&str]) -> Option<u32> {
        for key in keys {
            if let Some(v) = body.get(key) {
                if let Some(n) = v.as_u64() {
                    return Some(n.min(4095) as u32);
                }
                if let Some(f) = v.as_f64() {
                    if f.is_finite() {
                        return Some(f.floor().clamp(0.0, 4095.0) as u32);
                    }
                }
            }
        }
        None
    }
    let found = raw(body, keys)
        .or_else(|| body.get("position").and_then(|inner| raw(inner, keys)))
        .or_else(|| body.get("cell").and_then(|inner| raw(inner, keys)));
    found.map(|v| v + 1).unwrap_or(1)
}

fn event_coord(body: &Value, keys: &[&str]) -> u32 {
    raw_coord(body, keys)
        .or_else(|| body.get("position").and_then(|inner| raw_coord(inner, keys)))
        .or_else(|| body.get("cell").and_then(|inner| raw_coord(inner, keys)))
        .unwrap_or(1)
}

/// Signed delta under any of `keys` (or a nested `delta` object).
fn event_delta(body: &Value, keys: &[&str]) -> f64 {
    for key in keys {
        if let Some(f) = body.get(key).and_then(Value::as_f64) {
            return f;
        }
    }
    if let Some(inner) = body.get("delta") {
        for key in keys {
            if let Some(f) = inner.get(key).and_then(Value::as_f64) {
                return f;
            }
        }
    }
    0.0
}

/// Modifier bits for a mouse report (+4 shift, +8 alt, +16 ctrl) from
/// an array of names, an object of booleans, or nothing.
fn event_modifiers(body: &Value) -> u8 {
    let mut bits = 0u8;
    let mods = body
        .get("modifiers")
        .or_else(|| body.get("mods"))
        .cloned()
        .unwrap_or(Value::Null);
    let has = |name: &str| -> bool {
        match &mods {
            Value::Array(items) => items
                .iter()
                .any(|i| i.as_str().map(|s| s.eq_ignore_ascii_case(name)) == Some(true)),
            Value::Object(map) => map
                .get(name)
                .and_then(Value::as_bool)
                .unwrap_or(false),
            Value::String(text) => text.to_ascii_lowercase().contains(name),
            _ => false,
        }
    };
    if has("shift") {
        bits += 4;
    }
    if has("alt") || has("option") || has("meta") {
        bits += 8;
    }
    if has("ctrl") || has("control") {
        bits += 16;
    }
    bits
}

/// Handle a `wheel` block event: translate it into mouse reports in
/// the format the program in the terminal negotiated, and write them
/// to the PTY. Does nothing when the program never asked for the mouse.
fn block_event_wheel(term: &Arc<crate::terminal::Terminal>, body: &Value) {
    use crate::vt::MouseTracking;
    let (tracking, format) = {
        let screen = term.screen.lock().unwrap();
        (screen.mouse_tracking(), screen.mouse_format())
    };
    if tracking == MouseTracking::Off {
        return;
    }
    tracing::debug!(payload = %body, "wheel event");
    let x = event_cell(body, &["x", "column", "col"]);
    let y = event_cell(body, &["y", "row"]);
    let mods = event_modifiers(body);
    let direction = body
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut notches: Vec<u8> = Vec::new();
    let mut dy = event_delta(body, &["delta_y", "dy", "deltaY", "scroll_y", "vertical"]);
    let mut dx = event_delta(body, &["delta_x", "dx", "deltaX", "scroll_x", "horizontal"]);
    if body.get("delta_mode").and_then(Value::as_str) == Some("pixel") {
        // Pixel deltas: turn them into lines with the cell size this
        // very event implies (pixel offset / cell index), else ~20px.
        let cell_of = |axis: &str, cell_key: &str| -> f64 {
            let px = body
                .get("pixel")
                .and_then(|px| px.get(axis))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let cell = body.get(cell_key).and_then(Value::as_f64).unwrap_or(0.0);
            if px > 0.0 && cell >= 1.0 {
                px / cell
            } else {
                20.0
            }
        };
        dy /= cell_of("y", "y");
        dx /= cell_of("x", "x");
    }
    let push = |notches: &mut Vec<u8>, button: u8, delta: f64| {
        if delta.abs() >= 0.5 {
            let n = (delta.abs().round() as usize).clamp(1, 20);
            notches.extend(std::iter::repeat(button).take(n));
        }
    };
    if dy != 0.0 || dx != 0.0 {
        push(&mut notches, if dy < 0.0 { 64 } else { 65 }, dy);
        push(&mut notches, if dx < 0.0 { 66 } else { 67 }, dx);
    } else {
        let count = event_delta(body, &["amount", "ticks", "lines", "count"]);
        let n = if count > 0.0 {
            (count.ceil() as usize).clamp(1, 20)
        } else {
            3
        };
        let button = match direction.as_str() {
            "up" => 64,
            "left" => 66,
            "right" => 67,
            _ => 65,
        };
        notches.extend(std::iter::repeat(button).take(n));
    }
    let mut bytes = Vec::new();
    for button in notches {
        bytes.extend(crate::vt::encode_mouse_report(
            format,
            button + mods,
            x,
            y,
            false,
            false,
        ));
    }
    term.write(&bytes);
}

/// Handle a `mouse` block event (press / release / motion) the same
/// way, honouring what the negotiated tracking mode reports.
fn block_event_mouse(term: &Arc<crate::terminal::Terminal>, body: &Value) {
    use crate::vt::MouseTracking;
    let (tracking, format) = {
        let screen = term.screen.lock().unwrap();
        (screen.mouse_tracking(), screen.mouse_format())
    };
    if tracking == MouseTracking::Off {
        return;
    }
    tracing::debug!(payload = %body, "mouse event");
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let (release, motion) = match action.as_str() {
        "release" | "up" => (true, false),
        "move" | "motion" | "drag" | "moved" => (false, true),
        _ => (false, false),
    };
    if release && tracking == MouseTracking::X10 {
        return; // X10 reports presses only.
    }
    // The button the event names, if any ("unknown" = none held).
    let named_button: Option<u8> = match body.get("button") {
        Some(Value::String(name)) => match name.to_ascii_lowercase().as_str() {
            "left" => Some(0),
            "middle" => Some(1),
            "right" => Some(2),
            _ => None,
        },
        Some(Value::Number(n)) => match n.as_u64() {
            Some(v) if v <= 2 => Some(v as u8),
            Some(v) if (1..=3).contains(&v) => Some((v - 1) as u8),
            _ => None,
        },
        _ => None,
    };
    let button: u8 = if motion {
        match (tracking, named_button) {
            // Button-event tracking reports motion only during a drag.
            (MouseTracking::Button, Some(b)) => b,
            // Any-event tracking also reports motion with no button.
            (MouseTracking::Any, b) => b.unwrap_or(3),
            _ => return,
        }
    } else {
        named_button.unwrap_or(0)
    };
    if motion && !term.accept_motion() {
        return; // ~100 Hz raw motion is throttled to one report per 16 ms.
    }
    let x = event_cell(body, &["x", "column", "col"]);
    let y = event_cell(body, &["y", "row"]);
    let mods = event_modifiers(body);
    let bytes = crate::vt::encode_mouse_report(format, button + mods, x, y, release, motion);
    term.write(&bytes);
}

fn block_event(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let event = payload.get("event").cloned().unwrap_or(Value::Null);
    let kind = event
        .get("type")
        .and_then(|x| x.as_str())
        .unwrap_or_default();
    let body = event.get("payload").cloned().unwrap_or(Value::Null);
    let term = {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        s.blocks
            .get(&bid)
            .and_then(|b| b.terminal.clone())
            .ok_or_else(|| ApiError::not_found(format!("block {bid}")))?
    };
    match kind {
        "paste" => {
            let text = body
                .get("text")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            term.write(text.as_bytes());
            Ok(json!({}))
        }
        "key" => {
            let text = body
                .get("text")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            term.write(text.as_bytes());
            Ok(json!({}))
        }
        "wheel" | "mouse" => {
            // Drop the duplicate copy the app sends of every event.
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            kind.hash(&mut hasher);
            body.to_string().hash(&mut hasher);
            if term.accept_input_event(hasher.finish()) {
                if kind == "wheel" {
                    block_event_wheel(&term, &body);
                } else {
                    block_event_mouse(&term, &body);
                }
            }
            Ok(json!({}))
        }
        "focus" => {
            let action = body
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let reporting = {
                let screen = term.screen.lock().unwrap();
                screen.focus_reporting()
            };
            if reporting {
                match action {
                    "in" => term.write(b"\x1b[I"),
                    "out" => term.write(b"\x1b[O"),
                    _ => 0,
                };
            }
            Ok(json!({}))
        }
        "selection_copied" => {
            let text = body.get("text").and_then(Value::as_str).unwrap_or_default();
            let mut copied = json!({});
            if !text.is_empty() {
                copied["bytes"] = json!(text.len());
                if text.len() <= 48 * 1024 {
                    copied["text"] = json!(text);
                } else {
                    copied["id"] = json!(term.store_blob(text.to_string()));
                }
            }
            state.emit_to_session(
                &sid,
                crate::state::block_event(
                    &sid,
                    &bid,
                    "com.superlogical.terminal",
                    "selection_copied",
                    copied,
                ),
            );
            Ok(json!({}))
        }
        _ => Ok(json!({})),
    }
}

fn data_connect(state: &Arc<State>, client_id: &str, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let data_ref_id = req_str(payload, "data_ref_id")?;
    let subprotocol = opt_str(payload, "subprotocol");
    {
        let sessions = state.sessions.lock().unwrap();
        let s = sessions
            .iter()
            .find(|s| s.id == sid)
            .ok_or_else(|| ApiError::session_not_found(&sid))?;
        let block = s
            .blocks
            .get(&bid)
            .ok_or_else(|| ApiError::not_found(format!("block {bid} not found")))?;
        if data_ref_id != "terminal" || block.terminal.is_none() {
            return Err(ApiError::not_found(format!(
                "block {bid} has no data source {data_ref_id:?}"
            )));
        }
        if subprotocol
            .as_deref()
            .is_some_and(|protocol| protocol != DATA_PROTOCOL)
        {
            return Err(ApiError::bad_request(format!(
                "unsupported data subprotocol {:?}",
                subprotocol.as_deref().unwrap_or_default()
            )));
        }
    }
    if !state.subscribers(&sid).iter().any(|c| c == client_id) {
        return Err(ApiError::conflict(format!(
            "stream is not attached to session {sid}"
        )));
    }
    // Rex validates that tickets are URL-safe base64 tokens, not UUID text.
    let ticket_id = uuid::Uuid::new_v4();
    let ticket = URL_SAFE_NO_PAD.encode(ticket_id.as_bytes());
    state.tickets.lock().unwrap().insert(
        ticket.clone(),
        Ticket {
            session_id: sid,
            block_id: bid,
            data_ref_id,
            subprotocol,
            client_id: client_id.to_string(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
        },
    );
    Ok(json!({ "ticket": ticket, "expires_in_ms": 60_000 }))
}

// -- targets --------------------------------------------------------------

/// Last six hexadecimal digits of an ID. Listing commands print this form.
fn short_id(id: &str) -> String {
    let hex = hex_digits(id);
    let start = hex.len().saturating_sub(6);
    hex[start..].to_string()
}

fn id_parts(id: &str) -> (Option<&str>, &str) {
    match id.split_once(':') {
        Some((kind, body)) if !kind.is_empty() && !body.is_empty() => (Some(kind), body),
        _ => (None, id),
    }
}

fn hex_digits(id: &str) -> String {
    let (_, body) = id_parts(id);
    body.chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn is_full_uuid(body: &str) -> bool {
    let hex = hex_digits(body);
    hex.len() == 32
        && hex.chars().all(|c| c.is_ascii_hexdigit())
        && body.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Rex matches a full ID before any other form. The kind prefix is optional
/// when the rest is the whole UUID; a different kind prefix does not match.
fn full_id_eq(id: &str, q: &str) -> bool {
    if id.eq_ignore_ascii_case(q) {
        return true;
    }
    let (id_kind, id_body) = id_parts(id);
    let (q_kind, q_body) = id_parts(q);
    if let (Some(id_kind), Some(q_kind)) = (id_kind, q_kind) {
        if !id_kind.eq_ignore_ascii_case(q_kind) {
            return false;
        }
    }
    if !is_full_uuid(q_body) {
        return false;
    }
    id_body.eq_ignore_ascii_case(q_body) || hex_digits(id_body) == hex_digits(q_body)
}

/// The end of an ID, at least four hexadecimal digits, after hyphens are removed.
fn suffix_eq(id: &str, q: &str) -> bool {
    if q.contains(':') {
        return false;
    }
    let compact: String = q.chars().filter(|c| *c != '-').collect();
    if compact.len() < 4 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let q_hex = compact.to_ascii_lowercase();
    let id_hex = hex_digits(id);
    q_hex.len() < id_hex.len() && id_hex.ends_with(&q_hex)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum QueryRank {
    FullId = 0,
    Label = 1,
    Ordinal = 2,
    Suffix = 3,
}

/// One candidate's best match. Callers keep only the best rank across the set,
/// which is Rex's "stop at the first kind of match" order: full ID, label,
/// window position, then the end of an ID.
fn rank_match(id: &str, label: &str, ordinal: Option<u64>, q: &str) -> Option<QueryRank> {
    if full_id_eq(id, q) {
        return Some(QueryRank::FullId);
    }
    if !label.is_empty() && label.eq_ignore_ascii_case(q) {
        return Some(QueryRank::Label);
    }
    if let (Some(ordinal), Some(n)) = (ordinal, q.parse::<u64>().ok()) {
        if n == ordinal {
            return Some(QueryRank::Ordinal);
        }
    }
    if suffix_eq(id, q) {
        return Some(QueryRank::Suffix);
    }
    None
}

fn unique_ranked(ranked: Vec<(QueryRank, String)>) -> Result<Option<String>, ()> {
    let Some(best) = ranked.iter().map(|(rank, _)| *rank).min() else {
        return Ok(None);
    };
    let mut ids: Vec<String> = ranked
        .into_iter()
        .filter(|(rank, _)| *rank == best)
        .map(|(_, id)| id)
        .collect();
    match ids.len() {
        0 => Ok(None),
        1 => Ok(ids.pop()),
        _ => Err(()),
    }
}

fn resolve_session(state: &State, q: &str) -> Result<Option<String>, ()> {
    let sessions = state.sessions.lock().unwrap();
    let mut ranked = Vec::new();
    for session in sessions.iter() {
        if let Some(rank) = rank_match(&session.id, &session.label, None, q) {
            ranked.push((rank, session.id.clone()));
        }
    }
    unique_ranked(ranked)
}

fn live_session_id(state: &State, id: &str) -> Option<String> {
    let sessions = state.sessions.lock().unwrap();
    sessions
        .iter()
        .find(|session| full_id_eq(&session.id, id))
        .map(|session| session.id.clone())
}

fn resolve_window(state: &State, session_id: Option<&str>, q: &str) -> Result<Option<String>, ()> {
    let sessions = state.sessions.lock().unwrap();
    let mut ranked = Vec::new();
    for session in sessions.iter() {
        if session_id.is_some_and(|id| session.id != id) {
            continue;
        }
        for (index, window) in session.windows.iter().enumerate() {
            if let Some(rank) = rank_match(&window.id, &window.label, Some((index + 1) as u64), q) {
                ranked.push((rank, window.id.clone()));
            }
        }
    }
    unique_ranked(ranked)
}

struct SearchScope {
    /// Limits windows and blocks. A context session that no longer exists is
    /// left unset so the search is not narrowed to nothing.
    session_id: Option<String>,
    window_id: Option<String>,
    /// Set only from `scope.session`. Client search is then limited to clients
    /// attached to that session. A caller's context session does not do this.
    client_session_id: Option<String>,
}

fn search_scope(state: &State, payload: &Value, kinds: &[String]) -> Result<SearchScope, String> {
    let context_session = payload
        .get("context")
        .and_then(|context| context.get("session_id"))
        .and_then(|value| value.as_str())
        .filter(|id| !id.is_empty());
    let scope_session = payload
        .get("scope")
        .and_then(|scope| scope.get("session"))
        .and_then(|value| value.as_str())
        .filter(|id| !id.is_empty());
    let scope_window = payload
        .get("scope")
        .and_then(|scope| scope.get("window"))
        .and_then(|value| value.as_str())
        .filter(|id| !id.is_empty());

    let mut client_session_id = None;
    let session_id = if let Some(query) = scope_session {
        match resolve_session(state, query) {
            Ok(Some(id)) => {
                client_session_id = Some(id.clone());
                Some(id)
            }
            Ok(None) => return Err(format!("no session matches {query}")),
            Err(()) => return Err(format!("session scope {query} is ambiguous")),
        }
    } else if let Some(id) = context_session {
        live_session_id(state, id)
    } else {
        None
    };

    let blocks_only = !kinds.is_empty() && kinds.iter().all(|kind| kind == "block");
    let window_id = if let Some(query) = scope_window {
        if !blocks_only {
            return Err("window scope is only allowed when kinds is just block".into());
        }
        match resolve_window(state, session_id.as_deref(), query) {
            Ok(Some(id)) => Some(id),
            Ok(None) => return Err(format!("no window matches {query}")),
            Err(()) => return Err(format!("window scope {query} is ambiguous")),
        }
    } else {
        None
    };

    Ok(SearchScope {
        session_id,
        window_id,
        client_session_id,
    })
}

fn kind_id<'a>(target: &'a Value) -> &'a str {
    let key = match target.get("kind").and_then(|value| value.as_str()) {
        Some("session") => "session_id",
        Some("window") => "window_id",
        Some("block") => "block_id",
        Some("client") => "client_id",
        _ => return "",
    };
    target
        .get(key)
        .and_then(|value| value.as_str())
        .unwrap_or("")
}

fn target_json(
    kind: &str,
    session_id: Option<&str>,
    window_id: Option<&str>,
    block_id: Option<&str>,
    client_id: Option<&str>,
    label: &str,
    ordinal: Option<usize>,
    where_: &str,
) -> Value {
    let mut v = json!({ "kind": kind, "label": label });
    if let Some(x) = session_id {
        v["session_id"] = json!(x);
    }
    if let Some(x) = window_id {
        v["window_id"] = json!(x);
    }
    if let Some(x) = block_id {
        v["block_id"] = json!(x);
    }
    if let Some(x) = client_id {
        v["client_id"] = json!(x);
    }
    if let Some(n) = ordinal {
        v["ordinal"] = json!(n + 1);
    }
    if !where_.is_empty() {
        v["where"] = json!(where_);
    }
    v
}

fn gather_targets(state: &State, kinds: &[String], scope: &SearchScope) -> Vec<Value> {
    let sessions = state.sessions.lock().unwrap();
    let mut out = Vec::new();
    let in_scope = |session: &Session| {
        scope
            .session_id
            .as_deref()
            .is_none_or(|id| session.id == id)
    };
    if kinds.iter().any(|k| k == "session") {
        for s in sessions.iter() {
            out.push(target_json(
                "session",
                Some(&s.id),
                None,
                None,
                None,
                &s.label,
                None,
                "",
            ));
        }
    }
    if kinds.iter().any(|k| k == "window") {
        for s in sessions.iter().filter(|s| in_scope(s)) {
            for (i, w) in s.windows.iter().enumerate() {
                if scope.window_id.as_deref().is_some_and(|id| id != w.id) {
                    continue;
                }
                out.push(target_json(
                    "window",
                    Some(&s.id),
                    Some(&w.id),
                    None,
                    None,
                    &w.label,
                    Some(i),
                    &format!("window {}", i + 1),
                ));
            }
        }
    }
    if kinds.iter().any(|k| k == "block") {
        for s in sessions.iter().filter(|s| in_scope(s)) {
            for w in &s.windows {
                if scope.window_id.as_deref().is_some_and(|id| id != w.id) {
                    continue;
                }
                let mut ids = Vec::new();
                for l in &w.layers {
                    if let Some(layout) = &l.layout {
                        collect_block_ids(layout, &mut ids);
                    }
                }
                for id in ids {
                    if let Some(b) = s.blocks.get(&id) {
                        out.push(target_json(
                            "block",
                            Some(&s.id),
                            Some(&w.id),
                            Some(&b.id),
                            None,
                            &b.label,
                            None,
                            "",
                        ));
                    }
                }
            }
            if scope.window_id.is_some() {
                continue;
            }
            for b in s.blocks.values() {
                let placed = s.windows.iter().any(|w| {
                    w.layers.iter().any(|l| {
                        l.layout
                            .as_ref()
                            .map(|n| find_node_rect(n, &b.id).is_some())
                            .unwrap_or(false)
                    })
                });
                if !placed {
                    out.push(target_json(
                        "block",
                        Some(&s.id),
                        None,
                        Some(&b.id),
                        None,
                        &b.label,
                        None,
                        "detached",
                    ));
                }
            }
        }
    }
    if kinds.iter().any(|k| k == "client") {
        let attached = scope
            .client_session_id
            .as_deref()
            .map(|sid| state.subscribers(sid));
        let clients = state.clients.lock().unwrap();
        for c in clients.values() {
            if attached
                .as_ref()
                .is_some_and(|ids| !ids.iter().any(|id| id == &c.id))
            {
                continue;
            }
            out.push(target_json(
                "client",
                None,
                None,
                None,
                Some(&c.id),
                &c.info.name,
                None,
                "",
            ));
        }
    }
    out
}

fn target_resolve(state: &State, payload: &Value) -> Value {
    let kinds: Vec<String> = payload
        .get("kinds")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let queries: Vec<String> = payload
        .get("queries")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let context = payload.get("context").cloned().unwrap_or(Value::Null);
    let context_block = context
        .get("block_id")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let context_client = context
        .get("client_id")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let scope = match search_scope(state, payload, &kinds) {
        Ok(scope) => scope,
        Err(reason) => {
            let results: Vec<Value> = queries
                .into_iter()
                .map(|query| {
                    json!({
                        "query": query,
                        "status": "not_found",
                        "reason": reason,
                    })
                })
                .collect();
            return json!({ "results": results });
        }
    };

    let all = gather_targets(state, &kinds, &scope);

    // Snapshot enough of the scoped session to answer empty ("default") queries.
    let default_targets = {
        let sessions = state.sessions.lock().unwrap();
        let scoped = scope
            .session_id
            .as_ref()
            .and_then(|id| sessions.iter().find(|s| &s.id == id))
            .or_else(|| {
                if scope.session_id.is_none() {
                    sessions.first()
                } else {
                    None
                }
            });
        let mut out: Vec<Value> = Vec::new();
        if let Some(s) = scoped {
            let active = s
                .windows
                .iter()
                .find(|w| Some(&w.id) == s.active_window.as_ref())
                .or_else(|| s.windows.first());
            if kinds.iter().any(|k| k == "session") {
                out.push(target_json(
                    "session",
                    Some(&s.id),
                    None,
                    None,
                    None,
                    &s.label,
                    None,
                    "",
                ));
            }
            let active = if let Some(window_id) = &scope.window_id {
                s.windows.iter().find(|w| &w.id == window_id)
            } else {
                active
            };
            if let Some(w) = active {
                if kinds.iter().any(|k| k == "window") {
                    out.push(target_json(
                        "window",
                        Some(&s.id),
                        Some(&w.id),
                        None,
                        None,
                        &w.label,
                        s.windows.iter().position(|x| x.id == w.id),
                        "",
                    ));
                }
            }
            let mut focus: Option<(String, Option<String>)> = None;
            if let Some(b) = context_block.clone() {
                for w in &s.windows {
                    if scope.window_id.as_deref().is_some_and(|id| id != w.id) {
                        continue;
                    }
                    let hit = w.layers.iter().any(|l| {
                        l.layout
                            .as_ref()
                            .map(|n| find_node_rect(n, &b).is_some())
                            .unwrap_or(false)
                    });
                    if hit {
                        focus = Some((b, Some(w.id.clone())));
                        break;
                    }
                }
            }
            if focus.is_none() {
                if let Some(w) = active {
                    if let Some(b) = &w.focused_block {
                        focus = Some((b.clone(), Some(w.id.clone())));
                    }
                }
            }
            if kinds.iter().any(|k| k == "block") {
                if let Some((bid, wid)) = focus {
                    if let Some(b) = s.blocks.get(&bid) {
                        out.push(target_json(
                            "block",
                            Some(&s.id),
                            wid.as_deref(),
                            Some(&b.id),
                            None,
                            &b.label,
                            None,
                            "",
                        ));
                    }
                }
            }
        }
        if kinds.iter().any(|k| k == "client") {
            if let Some(cid) = &context_client {
                if let Some(c) = state.clients.lock().unwrap().get(cid) {
                    out.push(target_json(
                        "client",
                        None,
                        None,
                        None,
                        Some(&c.id),
                        &c.info.name,
                        None,
                        "",
                    ));
                }
            }
        }
        out
    };

    let mut results = Vec::new();
    for q in queries {
        let mut result = json!({ "query": q });
        if q.is_empty() {
            if let Some(t) = default_targets.first() {
                result["status"] = json!("resolved");
                result["target"] = t.clone();
            } else {
                result["status"] = json!("not_found");
                result["reason"] = json!("no default target");
            }
            results.push(result);
            continue;
        }
        let ranked: Vec<(QueryRank, Value)> = all
            .iter()
            .filter_map(|t| {
                let label = t.get("label").and_then(|x| x.as_str()).unwrap_or("");
                let ordinal = t.get("ordinal").and_then(|x| x.as_u64());
                rank_match(kind_id(t), label, ordinal, &q).map(|rank| (rank, t.clone()))
            })
            .collect();
        let best = ranked.iter().map(|(rank, _)| *rank).min();
        let mut matches: Vec<Value> = ranked
            .into_iter()
            .filter(|(rank, _)| Some(*rank) == best)
            .map(|(_, target)| target)
            .collect();
        match matches.len() {
            0 => {
                result["status"] = json!("not_found");
                result["reason"] = json!(format!("no {} matches {}", kinds.join("/"), q));
            }
            1 => {
                result["status"] = json!("resolved");
                result["target"] = matches.remove(0);
            }
            _ => {
                result["status"] = json!("ambiguous");
                result["candidates"] = json!(matches.into_iter().take(8).collect::<Vec<_>>());
            }
        }
        results.push(result);
    }
    json!({ "results": results })
}

fn target_complete(state: &State, payload: &Value) -> Value {
    let kinds: Vec<String> = payload
        .get("kinds")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let prefix = payload
        .get("prefix")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let scope = match search_scope(state, payload, &kinds) {
        Ok(scope) => scope,
        Err(_) => return json!({ "completions": [] }),
    };
    let all = gather_targets(state, &kinds, &scope);
    let mut completions = Vec::new();
    let prefix_folded = prefix.to_lowercase();
    for t in all {
        let label = t.get("label").and_then(|x| x.as_str()).unwrap_or("");
        let short = short_id(kind_id(&t));
        if !label.is_empty() && label.to_lowercase().starts_with(&prefix_folded) {
            completions.push(json!({ "value": label, "form": "label", "target": t }));
        }
        if !short.is_empty() && short.starts_with(&prefix_folded) {
            completions.push(json!({ "value": short, "form": "id", "target": t }));
        }
        if let Some(n) = t.get("ordinal").and_then(|x| x.as_u64()) {
            if n.to_string().starts_with(&prefix) {
                completions.push(json!({ "value": n.to_string(), "form": "ordinal", "target": t }));
            }
        }
    }
    json!({ "completions": completions.into_iter().take(64).collect::<Vec<_>>() })
}

fn session_describe_block(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let sessions = state.sessions.lock().unwrap();
    let s = sessions
        .iter()
        .find(|s| s.id == sid)
        .ok_or_else(|| ApiError::session_not_found(&sid))?;
    let b = s
        .blocks
        .get(&bid)
        .ok_or_else(|| ApiError::not_found(format!("block {bid}")))?;
    let mut window_id: Option<String> = None;
    for w in &s.windows {
        for l in &w.layers {
            if let Some(layout) = &l.layout {
                if find_node_rect(layout, &bid).is_some() {
                    window_id = Some(w.id.clone());
                }
            }
        }
    }
    let api = state
        .creators
        .get("creators")
        .and_then(|x| x.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|c| c.get("name").and_then(|x| x.as_str()) == Some(b.creator_name.as_str()))
        })
        .and_then(|c| c.get("api"))
        .cloned()
        .unwrap_or_else(|| json!({ "methods": {}, "events": {} }));
    let mut block = json!({
        "block_id": b.id,
        "label": b.label,
        "creator_name": b.creator_name,
        "flavor": b.flavor,
        "host_id": b.host_id,
        "placement": if window_id.is_some() { "placed" } else { "detached" },
    });
    if let Some(wid) = &window_id {
        block["window_id"] = json!(wid);
    }
    if let Some(owner) = &b.owner {
        block["owner"] = json!(owner);
    }
    Ok(json!({ "block": block, "api": api }))
}

fn client_key(state: &Arc<State>, payload: &Value) -> Result<Value, ApiError> {
    let sid = req_str(payload, "session_id")?;
    let bid = req_str(payload, "block_id")?;
    let key = payload.get("key").cloned().unwrap_or(Value::Null);
    let action = key
        .get("action")
        .and_then(|x| x.as_str())
        .unwrap_or("press");
    if action != "press" && action != "repeat" {
        return Ok(json!({}));
    }
    let term = {
        let sessions = state.sessions.lock().unwrap();
        let Some(s) = sessions.iter().find(|s| s.id == sid) else {
            return Err(ApiError::session_not_found(&sid));
        };
        let Some(block) = s.blocks.get(&bid) else {
            return Err(ApiError::not_found(format!("block {bid}")));
        };
        block.terminal.clone()
    };
    let Some(term) = term else {
        return Ok(json!({}));
    };
    let app_cursor = term.screen.lock().unwrap().application_cursor();
    let bytes = key_to_bytes(&key, app_cursor);
    if !bytes.is_empty() {
        term.write(&bytes);
    }
    Ok(json!({}))
}

fn key_to_bytes(key: &Value, app_cursor: bool) -> Vec<u8> {
    let name = key.get("key").and_then(|x| x.as_str()).unwrap_or("");
    let mods = key.get("mods").and_then(|x| x.as_str()).unwrap_or("");
    let text = key.get("text").and_then(|x| x.as_str()).unwrap_or("");
    let codepoint = key
        .get("unshifted_codepoint")
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;

    let has = |m: &str| mods.split('+').any(|part| part == m);
    let ctrl = has("ctrl");
    let alt = has("alt");
    let shift = has("shift");
    if has("super") {
        // Command shortcuts belong to the client application, not the shell.
        return Vec::new();
    }
    let modifier = 1 + u8::from(shift) + 2 * u8::from(alt) + 4 * u8::from(ctrl);

    let letter = name
        .strip_prefix("key_")
        .and_then(|rest| rest.chars().next());

    // Control characters for ctrl+<key>.
    let mut base: Option<Vec<u8>> = None;
    if ctrl {
        if let Some(ch) = letter {
            if ch.is_ascii_alphabetic() {
                base = Some(vec![(ch.to_ascii_lowercase() as u8) & 0x1f]);
            }
        }
        if base.is_none() {
            base = match name {
                "space" | "key_2" | "key_@" => Some(vec![0x00]),
                "bracket_left" | "key_[" => Some(vec![0x1b]),
                "backslash" | "key_\\" => Some(vec![0x1c]),
                "bracket_right" | "key_]" => Some(vec![0x1d]),
                "key_6" | "caret" => Some(vec![0x1e]),
                "minus" | "key__" => Some(vec![0x1f]),
                "slash" | "key_?" => Some(vec![0x7f]),
                _ => None,
            };
        }
    }

    let sequence = |final_byte: char, modifier: u8, app: bool| -> Vec<u8> {
        if modifier > 1 {
            format!("\x1b[1;{modifier}{final_byte}").into_bytes()
        } else if app {
            format!("\x1bO{final_byte}").into_bytes()
        } else {
            format!("\x1b{final_byte}").into_bytes()
        }
    };
    let tilde = |number: u8, modifier: u8| -> Vec<u8> {
        if modifier > 1 {
            format!("\x1b[{number};{modifier}~").into_bytes()
        } else {
            format!("\x1b[{number}~").into_bytes()
        }
    };

    let mut bytes = match name {
        "enter" | "return" => Some(vec![b'\r']),
        "tab" => {
            if shift {
                Some(b"\x1b[Z".to_vec())
            } else {
                Some(vec![b'\t'])
            }
        }
        "escape" => Some(vec![0x1b]),
        "backspace" => Some(vec![0x7f]),
        "delete" => Some(tilde(3, modifier)),
        "insert" => Some(tilde(2, modifier)),
        "page_up" | "pageup" => Some(tilde(5, modifier)),
        "page_down" | "pagedown" => Some(tilde(6, modifier)),
        "home" => Some(sequence('H', modifier, app_cursor)),
        "end" => Some(sequence('F', modifier, app_cursor)),
        "arrow_up" | "up" => Some(sequence('A', modifier, app_cursor)),
        "arrow_down" | "down" => Some(sequence('B', modifier, app_cursor)),
        "arrow_right" | "right" => Some(sequence('C', modifier, app_cursor)),
        "arrow_left" | "left" => Some(sequence('D', modifier, app_cursor)),
        "f1" => Some(if modifier > 1 {
            format!("\x1b[1;{modifier}P").into_bytes()
        } else {
            b"\x1bOP".to_vec()
        }),
        "f2" => Some(if modifier > 1 {
            format!("\x1b[1;{modifier}Q").into_bytes()
        } else {
            b"\x1bOQ".to_vec()
        }),
        "f3" => Some(if modifier > 1 {
            format!("\x1b[1;{modifier}R").into_bytes()
        } else {
            b"\x1bOR".to_vec()
        }),
        "f4" => Some(if modifier > 1 {
            format!("\x1b[1;{modifier}S").into_bytes()
        } else {
            b"\x1bOS".to_vec()
        }),
        "f5" => Some(tilde(15, modifier)),
        "f6" => Some(tilde(17, modifier)),
        "f7" => Some(tilde(18, modifier)),
        "f8" => Some(tilde(19, modifier)),
        "f9" => Some(tilde(20, modifier)),
        "f10" => Some(tilde(21, modifier)),
        "f11" => Some(tilde(23, modifier)),
        "f12" => Some(tilde(24, modifier)),
        _ => None,
    };

    if bytes.is_none() && base.is_some() {
        bytes = base;
    }

    if bytes.is_none() {
        if !text.is_empty() {
            bytes = Some(text.as_bytes().to_vec());
        } else if codepoint > 0 {
            if let Some(ch) = char::from_u32(codepoint) {
                bytes = Some(ch.to_string().into_bytes());
            }
        }
    }

    let mut bytes = bytes.unwrap_or_default();
    if alt && !bytes.is_empty() && !ctrl {
        bytes.insert(0, 0x1b);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_uses_go_os_and_arch_names() {
        let name = platform_name();
        assert!(
            name.starts_with("linux_")
                || name.starts_with("darwin_")
                || name.starts_with("windows_")
        );
        assert!(!name.contains("aarch64"));
        assert!(!name.contains("x86_64"));
        assert!(!name.contains("macos"));
    }

    #[test]
    fn empty_window_label_uses_the_go_server_default() {
        assert_eq!(
            default_window_label("window:01a17155-1aea-7013-bcda-7ec4e8757161"),
            "Window e8757161"
        );
    }

    #[test]
    fn directional_focus_accepts_diagonal_blocks_beyond_the_edge() {
        let candidates = vec![
            ("a".into(), [0.0, 0.0, 0.4, 0.4]),
            ("b".into(), [0.6, 0.6, 0.4, 0.4]),
        ];
        assert_eq!(
            choose_directional_focus(&candidates, "a", "down", false),
            Some("b".into())
        );
        assert_eq!(
            choose_directional_focus(&candidates, "a", "right", false),
            Some("b".into())
        );
    }

    #[test]
    fn directional_focus_rejects_candidates_that_overlap_in_primary_axis() {
        let candidates = vec![
            ("d".into(), [0.2, 0.0, 0.3, 1.0]),
            ("c".into(), [0.5, 0.5, 0.5, 0.5]),
        ];
        assert_eq!(
            choose_directional_focus(&candidates, "d", "down", false),
            None
        );
    }

    #[test]
    fn directional_focus_wraps_and_resolves_ties_by_candidate_order() {
        // Front-to-back order puts C before A; equal positions therefore
        // resolve to C when moving left or up from B.
        let candidates = vec![
            ("c".into(), [0.0, 0.0, 0.4, 0.4]),
            ("a".into(), [0.0, 0.0, 0.4, 0.4]),
            ("b".into(), [0.6, 0.6, 0.4, 0.4]),
        ];
        assert_eq!(
            choose_directional_focus(&candidates, "b", "left", false),
            Some("c".into())
        );
        assert_eq!(
            choose_directional_focus(&candidates, "b", "up", false),
            Some("c".into())
        );
        assert_eq!(
            choose_directional_focus(&candidates, "a", "left", true),
            Some("b".into())
        );
        assert_eq!(
            choose_directional_focus(&candidates, "a", "left", false),
            None
        );
    }

    #[test]
    fn id_decoder_checks_kind_and_uuid_and_normalizes_case() {
        let uppercase = "block:550E8400-E29B-41D4-A716-446655440000";
        assert_eq!(
            decode_id_value(uppercase, "block").unwrap(),
            "block:550e8400-e29b-41d4-a716-446655440000"
        );
        let bad_uuid = decode_id_value("block:nope", "block").unwrap_err();
        assert_eq!(
            bad_uuid.message,
            "decoding input: invalid block ID UUID: invalid UUID length: 4"
        );
        let bad_prefix =
            decode_id_value("window:550e8400-e29b-41d4-a716-446655440000", "block").unwrap_err();
        assert_eq!(
            bad_prefix.message,
            "decoding input: block ID must start with \"block:\": \"window:550e8400-e29b-41d4-a716-446655440000\""
        );
    }

    #[test]
    fn empty_host_hash_matches_sha256_of_empty_list() {
        assert_eq!(
            host_list_hash(&[]),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }

    #[test]
    fn hosts_put_remove_and_reload_use_the_configured_state_dir() {
        let dir = std::env::temp_dir().join(format!("rux-host-test-{}", uuid::Uuid::now_v7()));
        let state = Arc::new(State::new(
            json!({}),
            json!({}),
            String::new(),
            Some(dir.clone()),
            dir.join("init.lua"),
        ));
        let payload = json!({
            "host": {
                "label": "studio",
                "endpoints": ["http://studio.example:45231"],
                "icon": "computer"
            }
        });
        let put = hosts_put(&state, "client:test", &payload).unwrap();
        let id = put["host"]["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("host:"));
        assert!(put["host"]["updated_at"].is_string());
        assert_eq!(
            hosts_list(&state).unwrap()["hosts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let reload = Arc::new(State::new(
            json!({}),
            json!({}),
            String::new(),
            Some(dir.clone()),
            dir.join("init.lua"),
        ));
        assert_eq!(hosts_list(&reload).unwrap()["hosts"][0]["id"], id);

        let removed = hosts_remove(&reload, &json!({ "id": id })).unwrap();
        assert_eq!(removed["removed"], true);
        assert_eq!(hosts_remove(&reload, &json!({})).unwrap()["removed"], false);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cleanup_drops_empty_layers_windows_and_repairs_active_focus() {
        let keep = Window {
            id: "window-keep".into(),
            label: "keep".into(),
            focused_block: None,
            zoomed_block: Some("stale-block".into()),
            layers: vec![
                Layer {
                    id: "layer-tiled".into(),
                    kind: "tiled".into(),
                    bounds: [0.0, 0.0, 1.0, 1.0],
                    layout: Some(Layout::Leaf {
                        rect: [0.0, 0.0, 1.0, 1.0],
                        block_id: "block-a".into(),
                    }),
                },
                Layer {
                    id: "layer-empty".into(),
                    kind: "floating".into(),
                    bounds: [0.1, 0.1, 0.4, 0.4],
                    layout: None,
                },
            ],
        };
        let remove = Window {
            id: "window-remove".into(),
            label: "remove".into(),
            focused_block: None,
            zoomed_block: None,
            layers: vec![Layer {
                id: "layer-empty-tiled".into(),
                kind: "tiled".into(),
                bounds: [0.0, 0.0, 1.0, 1.0],
                layout: None,
            }],
        };
        let mut session = Session {
            id: "session-test".into(),
            label: "test".into(),
            revision: 0,
            windows: vec![keep, remove],
            active_window: Some("window-remove".into()),
            blocks: IndexMap::new(),
        };

        let cleanup = cleanup_windows(&mut session);

        assert_eq!(cleanup.removed_windows, vec!["window-remove"]);
        assert!(cleanup.active_changed);
        assert_eq!(cleanup.active_window.as_deref(), Some("window-keep"));
        assert_eq!(
            active_window_event_payload(&cleanup)["window_id"],
            "window-keep"
        );
        assert_eq!(session.active_window.as_deref(), Some("window-keep"));
        assert_eq!(session.windows.len(), 1);
        assert_eq!(session.windows[0].layers.len(), 1);
        assert_eq!(session.windows[0].focused_block.as_deref(), Some("block-a"));
        assert_eq!(session.windows[0].zoomed_block, None);
    }

    fn strip_catalog_prose(value: &mut Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    strip_catalog_prose(item);
                }
            }
            Value::Object(map) => {
                map.retain(|key, child| {
                    if (key == "description" || key == "title") && child.is_string() {
                        false
                    } else {
                        strip_catalog_prose(child);
                        true
                    }
                });
            }
            _ => {}
        }
    }

    #[test]
    fn embedded_catalog_is_generated_from_rux_wording() {
        let wording: Value = serde_json::from_str(include_str!("../catalog/wording.json")).unwrap();
        let mut help: Value =
            serde_json::from_str(include_str!("../assets/api-help.json")).unwrap();
        let help_schema: Value =
            serde_json::from_str(include_str!("../catalog/api-help.schema.json")).unwrap();
        for method in help["methods"].as_array().unwrap() {
            let name = method["name"].as_str().unwrap();
            assert_eq!(
                method["description"].as_str().unwrap(),
                wording["methods"][name].as_str().unwrap(),
                "{name}"
            );
        }
        for block in help["block_types"].as_array().unwrap() {
            let creator = block["creator"].as_str().unwrap();
            for method in block["methods"].as_array().unwrap() {
                let key = format!("{creator}.{}", method["name"].as_str().unwrap());
                assert_eq!(
                    method["description"].as_str().unwrap(),
                    wording["block_methods"][key.as_str()].as_str().unwrap(),
                    "{key}"
                );
            }
        }
        strip_catalog_prose(&mut help);
        assert_eq!(help, help_schema);

        let mut creators: Value =
            serde_json::from_str(include_str!("../assets/block-creators.json")).unwrap();
        let creators_schema: Value =
            serde_json::from_str(include_str!("../catalog/block-creators.schema.json")).unwrap();
        for creator in creators["creators"].as_array().unwrap() {
            let name = creator["name"].as_str().unwrap();
            assert_eq!(
                creator["description"].as_str().unwrap(),
                wording["creators"][name]["description"].as_str().unwrap()
            );
            assert_eq!(
                creator["title"].as_str().unwrap(),
                wording["creators"][name]["title"].as_str().unwrap()
            );
            let methods = creator["api"]["methods"].as_object().unwrap();
            assert!(
                methods.contains_key("title") || name != "com.superlogical.terminal",
                "terminal creator is missing title"
            );
            for (method_name, method) in methods {
                let key = format!("{name}.{method_name}");
                assert_eq!(
                    method["description"].as_str().unwrap(),
                    wording["block_methods"][key.as_str()].as_str().unwrap(),
                    "{key}"
                );
            }
        }
        strip_catalog_prose(&mut creators);
        assert_eq!(creators, creators_schema);
    }

    fn catalog_state() -> (Arc<State>, std::path::PathBuf) {
        let help: Value = serde_json::from_str(include_str!("../assets/api-help.json")).unwrap();
        let dir = std::env::temp_dir().join(format!("rux-api-test-{}", uuid::Uuid::now_v7()));
        let state = Arc::new(State::new(
            help,
            json!({}),
            "/tmp/rux-test.log".into(),
            Some(dir.clone()),
            dir.join("init.lua"),
        ));
        (state, dir)
    }

    fn output_schema(help: &Value, method: &str) -> Value {
        help.get("methods")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(method))
            .unwrap()
            .get("output_schema")
            .cloned()
            .unwrap()
    }

    #[tokio::test]
    async fn documented_shapes_reject_typos_and_match_the_catalog() {
        let (state, dir) = catalog_state();
        let err = dispatch(
            &state,
            "client:test",
            true,
            "session.set_block_label",
            json!({
                "session_id": "session:11111111-1111-7111-8111-111111111111",
                "lable": "x"
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "bad_request");
        assert!(
            err.message
                .contains("input: validating: unexpected property lable"),
            "{}",
            err.message
        );

        let missing = dispatch(
            &state,
            "client:test",
            true,
            "block.method",
            json!({ "session_id": "session:11111111-1111-7111-8111-111111111111" }),
        )
        .await
        .unwrap_err();
        assert!(
            missing.message.contains("block_id is required"),
            "{}",
            missing.message
        );

        let version = dispatch(&state, "client:test", true, "server.version", Value::Null)
            .await
            .unwrap();
        assert!(version.get("commit").is_none(), "{version}");
        assert!(version.get("built_at").is_none(), "{version}");
        assert_eq!(version["api_min_revision"], API_MIN_REVISION);
        assert_eq!(version["dirty"], false);
        crate::schema::validate(&output_schema(&state.help, "server.version"), &version).unwrap();

        let status = dispatch(&state, "client:test", false, "server.status", json!({}))
            .await
            .unwrap();
        assert!(status.get("log_path").is_none(), "{status}");
        assert!(status.get("you").is_none(), "{status}");
        assert!(status.get("tailscale").is_none(), "{status}");
        assert_eq!(status["exit_empty"], false);
        assert_eq!(status["api_min_revision"], API_MIN_REVISION);
        crate::schema::validate(&output_schema(&state.help, "server.status"), &status).unwrap();

        let who = dispatch(&state, "client:test", true, "server.whoami", json!({}))
            .await
            .unwrap();
        assert!(who["account"].is_string(), "{who}");
        crate::schema::validate(&output_schema(&state.help, "server.whoami"), &who).unwrap();

        let remote = dispatch(&state, "client:test", false, "server.stop", json!({}))
            .await
            .unwrap_err();
        assert_eq!(remote.status, 403);
        assert!(
            !state
                .shutting_down
                .load(std::sync::atomic::Ordering::SeqCst)
        );

        state.sessions.lock().unwrap().push(Session {
            id: ids::session(),
            label: "busy".into(),
            revision: 0,
            windows: Vec::new(),
            active_window: None,
            blocks: IndexMap::new(),
        });
        let busy = dispatch(
            &state,
            "client:test",
            true,
            "server.stop",
            json!({ "if_idle": true }),
        )
        .await
        .unwrap_err();
        assert_eq!(busy.status, 409);
        assert!(busy.message.contains("session"), "{}", busy.message);
        assert!(
            !state
                .shutting_down
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        state.sessions.lock().unwrap().clear();

        let sid = ids::session();
        state.sessions.lock().unwrap().push(Session {
            id: sid.clone(),
            label: "help".into(),
            revision: 0,
            windows: Vec::new(),
            active_window: None,
            blocks: IndexMap::new(),
        });
        let help = dispatch(
            &state,
            "client:test",
            true,
            "session.help",
            json!({ "session_id": sid }),
        )
        .await
        .unwrap();
        assert!(help.get("http").is_some(), "{help}");
        assert!(
            help.get("block_types")
                .and_then(Value::as_array)
                .unwrap()
                .len()
                >= 1
        );
        let names = help["methods"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|method| method.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(names.contains(&"session.view"));
        assert!(names.contains(&"session.new_split"));
        assert!(names.contains(&"block.method"));
        assert!(!names.contains(&"session.list"));
        assert!(!names.contains(&"session.create"));
        assert!(!names.contains(&"server.version"));

        let stopped = dispatch(
            &state,
            "client:test",
            true,
            "server.stop",
            json!({ "if_idle": false }),
        )
        .await
        .unwrap();
        assert_eq!(stopped, json!({}));
        assert!(
            state
                .shutting_down
                .load(std::sync::atomic::Ordering::SeqCst)
        );

        let scripted = dispatch(
            &state,
            "client:test",
            true,
            "client.set_script",
            json!({
                "scripts": [{
                    "name": "init.lua",
                    "source": "rex.bind(\"ctrl+g\", function() return true end)\nreturn rex.call(\"server.version\").rex_version"
                }]
            }),
        )
        .await
        .unwrap();
        crate::schema::validate(&output_schema(&state.help, "client.set_script"), &scripted)
            .unwrap();
        assert_eq!(scripted["bindings"], json!(["ctrl+g"]));
        assert!(
            scripted["diagnostics"].as_array().unwrap().is_empty(),
            "{scripted}"
        );
        assert!(scripted["bindings"][0].as_str().unwrap().contains("ctrl+g"));

        assert!(child_exit_event_payload(0, None).get("error").is_none());
        assert_eq!(child_exit_event_payload(1, None)["error"], "exit status 1");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn max_sessions_returns_conflict() {
        let (state, dir) = catalog_state();
        state
            .max_sessions
            .store(1, std::sync::atomic::Ordering::SeqCst);
        dispatch(
            &state,
            "client:test",
            true,
            "session.create",
            json!({ "label": "one" }),
        )
        .await
        .unwrap();
        let err = dispatch(
            &state,
            "client:test",
            true,
            "session.create",
            json!({ "label": "two" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "conflict");
        assert!(err.message.contains("session limit"), "{}", err.message);
        state
            .exit_empty
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(state.busy());
        assert!(!crate::state::idle_exit_ready(
            true,
            state.busy(),
            std::time::Duration::from_secs(10),
        ));
        assert!(
            crate::state::idle_exit_ready(false, false, std::time::Duration::from_secs(10),)
                == false
        );
        assert!(crate::state::idle_exit_ready(
            true,
            false,
            std::time::Duration::from_secs(10),
        ));
        assert!(!crate::state::idle_exit_ready(
            true,
            false,
            std::time::Duration::from_secs(9),
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn every_catalog_method_is_handled() {
        let (state, dir) = catalog_state();
        let names: Vec<String> = state.help["methods"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|method| method["name"].as_str().map(str::to_string))
            .collect();
        assert_eq!(names.len(), 73);
        for name in &names {
            let error = dispatch(&state, "client:test", true, name, json!({}))
                .await
                .err();
            if let Some(error) = error {
                assert_ne!(error.code, "method_not_found", "{name}: {error:?}");
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn built_in_tailscale_matches_the_catalog_and_stays_local() {
        let (state, dir) = catalog_state();
        let missing = dispatch(
            &state,
            "client:test",
            true,
            "server.tailscale.enable",
            json!({ "allow_tailnet_members": false }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code, "not_supported");

        let node = std::sync::Arc::new(crate::tsnet::TsnetNode::memory());
        let emit = std::sync::Arc::downgrade(&state);
        node.set_on_change(move |status| {
            if let Some(state) = emit.upgrade() {
                state.emit_tailscale_status(status);
            }
        });
        *state.tsnet.lock().unwrap() = Some(node);

        let status = dispatch(&state, "client:test", true, "server.status", json!({}))
            .await
            .unwrap();
        assert_eq!(status["tailscale"]["state"], "disabled");
        crate::schema::validate(&output_schema(&state.help, "server.status"), &status).unwrap();

        let remote = dispatch(
            &state,
            "client:test",
            false,
            "server.tailscale.enable",
            json!({ "allow_tailnet_members": true }),
        )
        .await
        .unwrap_err();
        assert_eq!(remote.status, 403);

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (client_id, _, _) = state.register_client(
            rux_proto::ClientInfo {
                kind: "gui".into(),
                name: "rex".into(),
                platform: "darwin".into(),
                version: "0".into(),
                label: None,
            },
            tx,
            json!({
                "kind": "tailscale",
                "transport": "tailscale",
                "display": "alice@example.com",
                "login_name": "alice@example.com",
                "user_id": "user-1",
                "node": "laptop",
            }),
        );
        state.set_client_all_events(&client_id, true);

        let enabled = dispatch(
            &state,
            "client:test",
            true,
            "server.tailscale.enable",
            json!({
                "allow_tailnet_members": true,
                "hostname": "rex",
                "auth_key": "test-key",
                "advertise_tags": ["tag:rex"]
            }),
        )
        .await
        .unwrap();
        crate::schema::validate(
            &output_schema(&state.help, "server.tailscale.enable"),
            &enabled,
        )
        .unwrap();
        assert_eq!(enabled["tailscale"]["state"], "running");
        assert_eq!(
            enabled["tailscale"]["https"]["url"],
            "https://rex.example.ts.net"
        );
        assert!(!enabled.to_string().contains("test-key"));

        let disabled = dispatch(
            &state,
            "client:test",
            true,
            "server.tailscale.disable",
            json!({}),
        )
        .await
        .unwrap();
        assert_eq!(disabled["tailscale"]["state"], "disabled");
        assert!(state.clients.lock().unwrap().get(&client_id).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn leaf_window(window_id: &str, label: &str, block_id: &str) -> Window {
        Window {
            id: window_id.into(),
            label: label.into(),
            focused_block: Some(block_id.into()),
            zoomed_block: None,
            layers: vec![Layer {
                id: format!("layer-{window_id}"),
                kind: "tiled".into(),
                bounds: [0.0, 0.0, 1.0, 1.0],
                layout: Some(Layout::Leaf {
                    rect: [0.0, 0.0, 1.0, 1.0],
                    block_id: block_id.into(),
                }),
            }],
        }
    }

    fn plain_block(id: &str, label: &str) -> Block {
        Block {
            id: id.into(),
            label: label.into(),
            creator_name: "com.superlogical.terminal".into(),
            flavor: "com.superlogical.terminal.shell".into(),
            host_id: "host".into(),
            owner: Some("client:owner".into()),
            terminal: None,
            onboarding: None,
        }
    }

    fn resolved_block(state: &State, payload: Value) -> String {
        let result = target_resolve(state, &payload);
        let row = &result["results"][0];
        assert_eq!(row["status"], "resolved", "{result}");
        row["target"]["block_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn block_targets_use_the_block_id_and_sessions_survive_disconnect() {
        let (state, dir) = catalog_state();
        let created = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(dispatch(
                &state,
                "client:test",
                true,
                "session.create",
                json!({ "label": "kept" }),
            ))
            .unwrap();
        let kept = created["session_id"].as_str().unwrap().to_string();
        state.remove_client("client:test");
        let listed = session_list(&state);
        assert!(
            listed
                .iter()
                .any(|session| session["session_id"] == kept && session["label"] == "kept"),
            "{listed:?}"
        );

        // The short id printed by `rex block list` is the last six hex digits.
        // Comparing a block query to session_id made both this and the full id
        // return `no block matches`.
        let shell = "block:01a17344-b2bc-7368-8941-3b174acd1fa8";
        let logs = "block:01a17344-b2bc-7368-8941-3b174a111111";
        let other = "block:01a17344-b2bc-7368-8941-3b174a222222";
        let session_a = "session:01a17344-b2bc-7368-8941-3b174ac7167b";
        let session_b = "session:01a17344-b2bc-7368-8941-3b174abbbbbb";
        let window_1 = "window:01a17344-b2bc-7368-8941-3b174a000001";
        let window_2 = "window:01a17344-b2bc-7368-8941-3b174a000002";
        assert_eq!(short_id(shell), "cd1fa8");
        assert_eq!(short_id(session_a), "c7167b");

        let mut blocks_a = IndexMap::new();
        blocks_a.insert(shell.to_string(), plain_block(shell, "shell"));
        blocks_a.insert(logs.to_string(), plain_block(logs, "logs"));
        let mut blocks_b = IndexMap::new();
        blocks_b.insert(other.to_string(), plain_block(other, "shell"));
        state.sessions.lock().unwrap().push(Session {
            id: session_a.into(),
            label: "t3".into(),
            revision: 1,
            windows: vec![
                leaf_window(window_1, "Window one", shell),
                leaf_window(window_2, "Window two", logs),
            ],
            active_window: Some(window_1.into()),
            blocks: blocks_a,
        });
        state.sessions.lock().unwrap().push(Session {
            id: session_b.into(),
            label: "other".into(),
            revision: 1,
            windows: vec![leaf_window(
                "window:01a17344-b2bc-7368-8941-3b174a000003",
                "Window three",
                other,
            )],
            active_window: None,
            blocks: blocks_b,
        });

        let block_query = |query: &str, extra: Value| {
            let mut payload = json!({
                "kinds": ["block"],
                "queries": [query],
            });
            if let Value::Object(extra) = extra {
                for (key, value) in extra {
                    payload[key] = value;
                }
            }
            payload
        };

        assert_eq!(resolved_block(&state, block_query(shell, json!({}))), shell);
        assert_eq!(
            resolved_block(&state, block_query(&shell.to_ascii_uppercase(), json!({}))),
            shell
        );
        assert_eq!(
            resolved_block(
                &state,
                block_query("01a17344-b2bc-7368-8941-3b174acd1fa8", json!({}))
            ),
            shell
        );
        assert_eq!(
            resolved_block(&state, block_query("cd1fa8", json!({}))),
            shell
        );
        assert_eq!(
            resolved_block(&state, block_query("CD1FA8", json!({}))),
            shell
        );
        assert_eq!(
            resolved_block(&state, block_query("1fa8", json!({}))),
            shell
        );
        assert_eq!(
            resolved_block(
                &state,
                block_query("logs", json!({ "scope": { "session": "t3" } }))
            ),
            logs
        );
        assert_eq!(
            resolved_block(
                &state,
                block_query("shell", json!({ "context": { "session_id": session_a } }))
            ),
            shell
        );

        let stale = target_resolve(
            &state,
            &block_query(
                shell,
                json!({ "context": { "session_id": "session:00000000-0000-7000-8000-000000000099" } }),
            ),
        );
        assert_eq!(stale["results"][0]["status"], "resolved", "{stale}");

        let other_session = target_resolve(
            &state,
            &block_query(shell, json!({ "context": { "session_id": session_b } })),
        );
        assert_eq!(other_session["results"][0]["status"], "not_found");
        assert_eq!(
            other_session["results"][0]["reason"],
            "no block matches block:01a17344-b2bc-7368-8941-3b174acd1fa8"
        );

        let session_short = target_resolve(&state, &block_query("c7167b", json!({})));
        assert_eq!(session_short["results"][0]["status"], "not_found");

        let ambiguous = target_resolve(&state, &block_query("shell", json!({})));
        assert_eq!(ambiguous["results"][0]["status"], "ambiguous");

        let by_window = resolved_block(
            &state,
            block_query(
                "logs",
                json!({ "scope": { "window": "2", "session": "t3" } }),
            ),
        );
        assert_eq!(by_window, logs);
        let wrong_window = target_resolve(
            &state,
            &block_query(
                "shell",
                json!({ "scope": { "window": "2", "session": "t3" } }),
            ),
        );
        assert_eq!(wrong_window["results"][0]["status"], "not_found");

        let window = target_resolve(
            &state,
            &json!({
                "kinds": ["window"],
                "queries": ["1"],
                "scope": { "session": "t3" },
            }),
        );
        assert_eq!(window["results"][0]["status"], "resolved");
        assert_eq!(window["results"][0]["target"]["window_id"], window_1);

        let completed = target_complete(&state, &json!({ "kinds": ["block"], "prefix": "cd1f" }));
        let values: Vec<&str> = completed["completions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["value"].as_str())
            .collect();
        assert!(values.contains(&"cd1fa8"), "{completed}");
        assert!(!values.iter().any(|value| *value == "c7167b"));

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (attached, _, _) = state.register_client(
            rux_proto::ClientInfo {
                kind: "cli".into(),
                name: "attached".into(),
                platform: "darwin".into(),
                version: "0".into(),
                label: None,
            },
            tx,
            json!({ "kind": "tailscale" }),
        );
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (stranger, _, _) = state.register_client(
            rux_proto::ClientInfo {
                kind: "cli".into(),
                name: "stranger".into(),
                platform: "darwin".into(),
                version: "0".into(),
                label: None,
            },
            tx,
            json!({ "kind": "tailscale" }),
        );
        state.subscribe(session_a, &attached);
        let clients = target_resolve(
            &state,
            &json!({
                "kinds": ["client"],
                "queries": ["stranger", "attached"],
                "scope": { "session": "t3" },
            }),
        );
        assert_eq!(clients["results"][0]["status"], "not_found");
        assert_eq!(clients["results"][1]["status"], "resolved");
        assert_eq!(clients["results"][1]["target"]["client_id"], attached);
        let _ = stranger;

        let _ = std::fs::remove_dir_all(dir);
    }
}
