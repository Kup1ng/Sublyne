//! Typed wire messages exchanged with the Go control plane.
//!
//! The shape mirrors `.claude/skills/rust-go-ipc/SKILL.md`. Every
//! message on the socket is a length-prefixed JSON object of the form
//!
//! ```json
//! { "type": "<MessageName>", "id": "<uuid>", "payload": { ... } }
//! ```
//!
//! Replies echo the request `id` so Go can correlate. Events (Rust →
//! Go) carry a fresh UUID and are never replied to.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::spec::TunnelSpec;

/// On-wire envelope for every IPC frame.
///
/// `payload` is a free-form JSON value because the catalog is open at
/// the envelope level — handlers downcast to the per-command payload
/// after dispatching on `type`. Strict typing happens in `ipc.rs` once
/// the type tag is known.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "type")]
    pub ty: String,
    pub id: String,
    pub payload: Value,
}

/// Inbound command catalog. Every variant corresponds to one
/// `type` string the Go control plane may send. Unknown types are
/// logged at WARN and dropped (see protocol versioning in the skill).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Command {
    Ping,
    StartTunnel(TunnelSpec),
    StopTunnel { id: i64 },
    UpdateTunnel(TunnelSpec),
    ListTunnels,
    SetLogLevel { level: String },
    Shutdown,
}

/// Reply payload shape. `ok = true` carries an optional `value` body
/// for commands that return data (currently `ListTunnels`); errors
/// fill in `error` instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyPayload {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// Error code + human-readable message returned to Go. The codes are
/// stable strings — the Go side may switch on them.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct IpcError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl IpcError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            context: None,
        }
    }

    pub fn with_context(mut self, ctx: Value) -> Self {
        self.context = Some(ctx);
        self
    }
}

/// Stable error code strings used in `IpcError::code`. Keep in sync
/// with the table in the rust-go-ipc skill.
pub mod codes {
    pub const PORT_IN_USE: &str = "PORT_IN_USE";
    pub const RAW_SOCKET_FORBIDDEN: &str = "RAW_SOCKET_FORBIDDEN";
    pub const RESTART_REQUIRED: &str = "RESTART_REQUIRED";
    pub const TUNNEL_NOT_FOUND: &str = "TUNNEL_NOT_FOUND";
    pub const INVALID_TUNNEL_SPEC: &str = "INVALID_TUNNEL_SPEC";
    pub const INTERNAL: &str = "INTERNAL";
    pub const UNSUPPORTED_TRANSPORT: &str = "UNSUPPORTED_TRANSPORT";
}

/// Lifecycle states a tunnel can be in inside the dataplane. Surfaces
/// over `TunnelStateChanged` events and the `ListTunnels` reply so the
/// panel can render "Running" vs "Error" badges.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    Starting,
    Running,
    Stopped,
    Error,
}

/// One row in the `ListTunnels` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelListEntry {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub state: TunnelState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `Ready` is the first frame the dataplane emits after the IPC
/// connection is accepted. Go waits for it before sending any command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyPayload {
    pub version: String,
}

/// `TunnelStateChanged` event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStateChanged {
    pub tunnel_id: i64,
    pub state: TunnelState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let env = Envelope {
            ty: "Ping".into(),
            id: "abc".into(),
            payload: serde_json::json!({}),
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let back: Envelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.ty, "Ping");
        assert_eq!(back.id, "abc");
    }

    #[test]
    fn reply_error_serialises_with_code() {
        let r = ReplyPayload {
            ok: false,
            error: Some(IpcError::new(codes::PORT_IN_USE, "44443 already bound")),
            value: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"PORT_IN_USE\""));
        assert!(s.contains("\"44443 already bound\""));
    }
}
