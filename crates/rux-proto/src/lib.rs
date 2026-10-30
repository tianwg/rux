//! Wire types and view model for the Rex control protocol (`rex.control.v1`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod ids {
    use uuid::Uuid;

    pub fn new(prefix: &str) -> String {
        format!("{prefix}:{}", Uuid::now_v7())
    }

    pub fn session() -> String {
        new("session")
    }
    pub fn window() -> String {
        new("window")
    }
    pub fn layer() -> String {
        new("layer")
    }
    pub fn block() -> String {
        new("block")
    }
    pub fn split() -> String {
        new("split")
    }
    pub fn client() -> String {
        new("client")
    }
    pub fn host() -> String {
        new("host")
    }
}

pub const PROTOCOL: &str = "rex.control.v1";
pub const DATA_PROTOCOL: &str = "rex.data.terminal.v1";
pub const API_REVISION: u32 = 7;
pub const API_MIN_REVISION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// A client as described in the hello message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub client: ClientInfo,
    #[serde(default)]
    pub api_revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub status: u16,
}

impl ApiError {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, "bad_request", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "conflict", message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            404,
            "method_not_found",
            format!("method {method} not found"),
        )
    }

    pub fn session_not_found(id: &str) -> Self {
        Self::new(404, "session_not_found", format!("session {id} not found"))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (status={} code={})",
            self.message, self.status, self.code
        )
    }
}

impl std::error::Error for ApiError {}

/// Server → client messages. Built with constructors so the `type` tag is always right.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ServerMessage {
    Welcome(Welcome),
    Response(Response),
    Event(Event),
}

#[derive(Debug, Clone, Serialize)]
pub struct Welcome {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub protocol: &'static str,
    pub limits: Limits,
    pub client: WelcomeClient,
    pub api_revision: u32,
    pub api_server_revision: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Limits {
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WelcomeClient {
    pub id: String,
    pub reconnect_token: String,
}

impl Welcome {
    pub fn new(client_id: String, reconnect_token: String) -> Self {
        Self {
            kind: "welcome",
            protocol: PROTOCOL,
            limits: Limits {
                max_message_bytes: MAX_MESSAGE_BYTES,
            },
            client: WelcomeClient {
                id: client_id,
                reconnect_token,
            },
            api_revision: API_REVISION,
            api_server_revision: API_REVISION,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub id: String,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Response {
    pub fn ok(id: String, seq: u64, payload: Value) -> Self {
        Self {
            kind: "response",
            id,
            seq,
            payload: Some(payload),
            error: None,
        }
    }

    pub fn err(id: String, seq: u64, error: ApiError) -> Self {
        Self {
            kind: "response",
            id,
            seq,
            payload: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub seq: u64,
    pub payload: Value,
}

impl Event {
    pub fn new(seq: u64, payload: Value) -> Self {
        Self {
            kind: "event",
            seq,
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// Session view
// ---------------------------------------------------------------------------

pub type Rect = [f64; 4];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {
    pub revision: u64,
    pub session_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_window_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<WindowView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowView {
    pub window_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focused_block_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoomed_block_id: Option<String>,
    pub layers: Vec<LayerView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerView {
    pub layer_id: String,
    pub kind: String,
    pub bounds: Rect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutNode>,
    pub blocks: Vec<BlockSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutNode {
    pub rect: Rect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<Box<Split>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Split {
    pub split_id: String,
    pub direction: String,
    pub ratio: f64,
    pub before: LayoutNode,
    pub after: LayoutNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummary {
    pub block_id: String,
    pub label: String,
    pub creator_name: String,
    pub flavor: String,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Creation-time layout: a block to start, or a split of two creation layouts.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateLayout {
    Block(CreateBlock),
    Split(CreateSplit),
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateBlock {
    pub flavor: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSplit {
    pub direction: String,
    #[serde(default)]
    pub ratio: Option<f64>,
    pub before: Box<CreateLayout>,
    pub after: Box<CreateLayout>,
}

impl LayoutNode {
    pub fn leaf(rect: Rect, block_id: String) -> Self {
        Self {
            rect,
            block_id: Some(block_id),
            split: None,
        }
    }

    pub fn split(rect: Rect, split: Split) -> Self {
        Self {
            rect,
            block_id: None,
            split: Some(Box::new(split)),
        }
    }

    pub fn walk_blocks(&self, out: &mut Vec<String>) {
        if let Some(id) = &self.block_id {
            out.push(id.clone());
        }
        if let Some(s) = &self.split {
            s.before.walk_blocks(out);
            s.after.walk_blocks(out);
        }
    }
}

pub fn split_rect(rect: Rect, direction: &str, ratio: f64, before: bool) -> Rect {
    let [x, y, w, h] = rect;
    match direction {
        "vertical" => {
            let bh = h * ratio;
            if before {
                [x, y, w, bh]
            } else {
                [x, y + bh, w, h - bh]
            }
        }
        _ => {
            let bw = w * ratio;
            if before {
                [x, y, bw, h]
            } else {
                [x + bw, y, w - bw, h]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_horizontal_side_by_side() {
        let rect = [0.0, 0.0, 1.0, 1.0];
        assert_eq!(
            split_rect(rect, "horizontal", 0.25, true),
            [0.0, 0.0, 0.25, 1.0]
        );
        assert_eq!(
            split_rect(rect, "horizontal", 0.25, false),
            [0.25, 0.0, 0.75, 1.0]
        );
    }

    #[test]
    fn splits_vertical_top_and_bottom() {
        let rect = [0.1, 0.2, 0.8, 0.6];
        assert_eq!(
            split_rect(rect, "vertical", 0.5, true),
            [0.1, 0.2, 0.8, 0.3]
        );
        assert_eq!(
            split_rect(rect, "vertical", 0.5, false),
            [0.1, 0.5, 0.8, 0.3]
        );
    }

    #[test]
    fn layout_node_serializes_like_rex() {
        let leaf = LayoutNode::leaf([0.0, 0.0, 1.0, 1.0], "block:1".into());
        let v = serde_json::to_value(&leaf).unwrap();
        assert_eq!(v["block_id"], "block:1");
        assert_eq!(v["rect"], serde_json::json!([0.0, 0.0, 1.0, 1.0]));
        assert!(v.get("split").is_none());

        let node = LayoutNode::split(
            [0.0, 0.0, 1.0, 1.0],
            Split {
                split_id: "split:1".into(),
                direction: "horizontal".into(),
                ratio: 0.5,
                before: LayoutNode::leaf([0.0, 0.0, 0.5, 1.0], "block:1".into()),
                after: LayoutNode::leaf([0.5, 0.0, 0.5, 1.0], "block:2".into()),
            },
        );
        let v = serde_json::to_value(&node).unwrap();
        assert_eq!(v["split"]["split_id"], "split:1");
        assert_eq!(v["split"]["before"]["block_id"], "block:1");
        assert_eq!(v["split"]["after"]["block_id"], "block:2");
    }
}
