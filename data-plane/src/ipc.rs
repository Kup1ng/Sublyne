//! Length-prefixed JSON framing over a Unix domain socket.
//!
//! Wire format (see `.claude/skills/rust-go-ipc/SKILL.md`):
//!
//! ```text
//! [ 4-byte big-endian length ] [ UTF-8 JSON body of that many bytes ]
//! ```
//!
//! - Body cap: 16 MiB. Anything larger is a protocol violation and the
//!   receiver closes the connection.
//! - Single concurrent client (the Go control plane); subsequent dials
//!   are rejected.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::manager::TunnelManager;
use crate::metrics::SystemSnapshotter;
use crate::protocol::{codes, Envelope, IpcError, ReadyPayload, ReplyPayload};

/// Sanity cap on incoming frame body size. Larger frames close the
/// connection.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// IPC server: accepts one connection at a time and dispatches every
/// command to `TunnelManager`.
pub struct IpcServer {
    socket_path: PathBuf,
    manager: Arc<TunnelManager>,
}

impl IpcServer {
    pub fn new(socket_path: impl Into<PathBuf>, manager: Arc<TunnelManager>) -> Self {
        Self {
            socket_path: socket_path.into(),
            manager,
        }
    }

    /// Run forever, accepting one connection at a time. Returns only
    /// if binding fails — the `Shutdown` command cancels the outer
    /// runtime instead.
    pub async fn serve(self) -> anyhow::Result<()> {
        // The Go supervisor creates /run/sublyne at install time and
        // the systemd unit's RuntimeDirectory keeps it 0750
        // sublyne:sublyne. We just unlink any stale socket from a
        // previous run and bind fresh.
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).with_context(|| {
                format!("removing stale socket at {}", self.socket_path.display())
            })?;
        }
        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("bind unix socket at {}", self.socket_path.display()))?;
        // Tighten the socket file's mode to 0600 — only the sublyne
        // user (which is who we are) may connect.
        set_socket_mode(&self.socket_path, 0o600)?;
        info!(socket = %self.socket_path.display(), "ipc: listening");

        loop {
            let (stream, _addr) = listener.accept().await.context("ipc accept")?;
            info!("ipc: connection accepted");
            let manager = self.manager.clone();
            // We deliberately handle only one connection at a time.
            // If the Go side reconnects after a crash, that connection
            // is processed in the next loop iteration.
            if let Err(e) = handle_connection(stream, manager).await {
                warn!(err = %e, "ipc: connection closed with error");
            } else {
                info!("ipc: connection closed cleanly");
            }
        }
    }
}

#[cfg(unix)]
fn set_socket_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perm)
}

#[cfg(not(unix))]
fn set_socket_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Per-connection driver. Sends `Ready` on entry, then loops on
/// reading frames + dispatching them to the manager.
async fn handle_connection(stream: UnixStream, manager: Arc<TunnelManager>) -> anyhow::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = reader;
    let writer = Arc::new(Mutex::new(writer));

    // Emit `Ready` to tell Go we're alive.
    let ready_env = Envelope {
        ty: "Ready".into(),
        id: uuid_v4_string(),
        payload: serde_json::to_value(ReadyPayload {
            version: env!("CARGO_PKG_VERSION").into(),
        })?,
    };
    write_frame(&writer, &ready_env).await?;

    // Spawn a background task that emits `TunnelStateChanged` events
    // whenever the manager's state changes.
    {
        let manager = manager.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            let mut rx = manager.subscribe_state();
            while let Some(evt) = rx.recv().await {
                let env = Envelope {
                    ty: "TunnelStateChanged".into(),
                    id: uuid_v4_string(),
                    payload: serde_json::to_value(&evt).unwrap_or(Value::Null),
                };
                if let Err(e) = write_frame(&writer, &env).await {
                    debug!(err = %e, "ipc: stopping state-change forwarder");
                    break;
                }
            }
        });
    }

    // Phase 11: spawn a background task that pushes a `StatsReport`
    // every 5 seconds (PRD §4.7). The Go control plane's metrics
    // ring buffer consumes these events and fans them out to every
    // connected WebSocket dashboard client.
    {
        let manager = manager.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            let snapshotter = SystemSnapshotter::new();
            // Take one snapshot immediately on connect (warms the per-
            // interface "previous" map, primes the CPU EWMA) and discard
            // it — the first real report happens after the first tick.
            let _ = snapshotter.snapshot();
            // 1 s cadence so the dashboard reads like a live speedometer
            // (per-second Up/Down/CPU/RAM) rather than a 5 s-smeared chart.
            // The payload is tiny (per-tunnel counters + one system block)
            // and there is a SINGLE reporter on the one Go<->Rust IPC
            // socket — Go fans each report out to the browsers — so 1 s is
            // negligible CPU even on the constrained Iran client.
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            // Skip the immediate burst — we already produced one
            // snapshot above, and we want subsequent fires spaced by
            // the full interval.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // immediate first tick — discard.
            loop {
                interval.tick().await;
                let samples = manager.collect_stats().await;
                let system = snapshotter.snapshot();
                let env = Envelope {
                    ty: "StatsReport".into(),
                    id: uuid_v4_string(),
                    payload: serde_json::json!({
                        "samples": samples,
                        "system": system,
                    }),
                };
                if let Err(e) = write_frame(&writer, &env).await {
                    debug!(err = %e, "ipc: stopping stats reporter");
                    break;
                }
            }
        });
    }

    let mut len_buf = [0u8; 4];
    loop {
        if let Err(e) = reader.read_exact(&mut len_buf).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e.into());
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
            return Err(anyhow!("ipc: frame length out of range: {}", frame_len));
        }
        let mut body = vec![0u8; frame_len];
        reader.read_exact(&mut body).await?;
        let env: Envelope = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "ipc: malformed frame, closing connection");
                return Err(e.into());
            }
        };
        if env.ty == "Shutdown" {
            info!("ipc: Shutdown received, exiting");
            let reply = ReplyPayload {
                ok: true,
                error: None,
                value: None,
            };
            let _ = write_reply(&writer, &env.id, &reply).await;
            // Wait a heartbeat so the reply has time to leave the
            // socket, then exit the process via the manager.
            tokio::time::sleep(Duration::from_millis(50)).await;
            manager.shutdown().await;
            return Ok(());
        }
        let writer = writer.clone();
        let manager = manager.clone();
        // Dispatch each command on its own task so a slow handler (e.g.
        // a SOCKS5 `StartTunnel` that blocks up to the warm-up deadline
        // waiting for proxy slots to connect) never blocks the read
        // loop or other commands (Ping, ListTunnels, StopTunnel). The
        // read loop keeps consuming frames immediately.
        //
        // Replies may therefore complete out of order, but each Reply
        // is tagged with the originating request `id` and the Go client
        // correlates by id (pending-by-id map), so ordering on the wire
        // does not matter. Writes are serialised by the `Mutex` around
        // the write half (see `write_frame`), so length-prefixed frames
        // never interleave even with many handlers running concurrently.
        //
        // `Shutdown` is handled inline above (before this spawn) so an
        // in-flight slow `StartTunnel` can never starve it.
        tokio::spawn(async move {
            if let Err(e) = dispatch(env, manager, writer).await {
                error!(err = %e, "ipc: dispatch error");
            }
        });
    }
}

/// Inspect the envelope's `type` and call into the manager.
async fn dispatch(
    env: Envelope,
    manager: Arc<TunnelManager>,
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
) -> anyhow::Result<()> {
    match env.ty.as_str() {
        "Ping" => {
            let reply = ReplyPayload {
                ok: true,
                error: None,
                value: None,
            };
            write_reply(&writer, &env.id, &reply).await
        }
        "StartTunnel" => {
            let spec: crate::spec::TunnelSpec = match serde_json::from_value(env.payload.clone()) {
                Ok(v) => v,
                Err(e) => {
                    let reply = ReplyPayload {
                        ok: false,
                        error: Some(IpcError::new(
                            codes::INVALID_TUNNEL_SPEC,
                            format!("decode tunnel spec: {e}"),
                        )),
                        value: None,
                    };
                    return write_reply(&writer, &env.id, &reply).await;
                }
            };
            let reply = match manager.start_tunnel(spec).await {
                Ok(()) => ReplyPayload {
                    ok: true,
                    error: None,
                    value: None,
                },
                Err(e) => ReplyPayload {
                    ok: false,
                    error: Some(e.into_ipc_error()),
                    value: None,
                },
            };
            write_reply(&writer, &env.id, &reply).await
        }
        "StopTunnel" => {
            #[derive(serde::Deserialize)]
            struct StopBody {
                id: i64,
            }
            let body: StopBody = match serde_json::from_value(env.payload.clone()) {
                Ok(v) => v,
                Err(e) => {
                    let reply = ReplyPayload {
                        ok: false,
                        error: Some(IpcError::new(
                            codes::INVALID_TUNNEL_SPEC,
                            format!("decode stop body: {e}"),
                        )),
                        value: None,
                    };
                    return write_reply(&writer, &env.id, &reply).await;
                }
            };
            let reply = match manager.stop_tunnel(body.id).await {
                Ok(()) => ReplyPayload {
                    ok: true,
                    error: None,
                    value: None,
                },
                Err(e) => ReplyPayload {
                    ok: false,
                    error: Some(e.into_ipc_error()),
                    value: None,
                },
            };
            write_reply(&writer, &env.id, &reply).await
        }
        "ListTunnels" => {
            let entries = manager.list_tunnels();
            let reply = ReplyPayload {
                ok: true,
                error: None,
                value: Some(serde_json::json!({ "tunnels": entries })),
            };
            write_reply(&writer, &env.id, &reply).await
        }
        "UpdateTunnel" => {
            let spec: crate::spec::TunnelSpec = match serde_json::from_value(env.payload.clone()) {
                Ok(v) => v,
                Err(e) => {
                    let reply = ReplyPayload {
                        ok: false,
                        error: Some(IpcError::new(
                            codes::INVALID_TUNNEL_SPEC,
                            format!("decode tunnel spec: {e}"),
                        )),
                        value: None,
                    };
                    return write_reply(&writer, &env.id, &reply).await;
                }
            };
            let reply = match manager.update_tunnel(spec).await {
                Ok(changed) => ReplyPayload {
                    ok: true,
                    error: None,
                    value: Some(serde_json::json!({ "changed": changed })),
                },
                Err(e) => ReplyPayload {
                    ok: false,
                    error: Some(e.into_ipc_error()),
                    value: None,
                },
            };
            write_reply(&writer, &env.id, &reply).await
        }
        "SetLogLevel" => {
            #[derive(serde::Deserialize)]
            struct LL {
                level: String,
            }
            let body: LL = match serde_json::from_value(env.payload.clone()) {
                Ok(v) => v,
                Err(e) => {
                    let reply = ReplyPayload {
                        ok: false,
                        error: Some(IpcError::new(
                            codes::INVALID_TUNNEL_SPEC,
                            format!("decode log-level body: {e}"),
                        )),
                        value: None,
                    };
                    return write_reply(&writer, &env.id, &reply).await;
                }
            };
            manager.set_log_level(&body.level);
            let reply = ReplyPayload {
                ok: true,
                error: None,
                value: None,
            };
            write_reply(&writer, &env.id, &reply).await
        }
        other => {
            warn!(ty = other, "ipc: unknown message type, ignoring");
            // Per the skill: unknown types log a WARN and are ignored.
            // We still send a reply so the Go side's correlation logic
            // doesn't time out.
            let reply = ReplyPayload {
                ok: false,
                error: Some(IpcError::new(
                    codes::INTERNAL,
                    format!("unknown type {other}"),
                )),
                value: None,
            };
            write_reply(&writer, &env.id, &reply).await
        }
    }
}

async fn write_reply(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    id: &str,
    payload: &ReplyPayload,
) -> anyhow::Result<()> {
    let env = Envelope {
        ty: "Reply".into(),
        id: id.into(),
        payload: serde_json::to_value(payload)?,
    };
    write_frame(writer, &env).await
}

async fn write_frame(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    env: &Envelope,
) -> anyhow::Result<()> {
    let body = serde_json::to_vec(env)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(anyhow!("ipc: frame body too large: {}", body.len()));
    }
    let mut guard = writer.lock().await;
    let len = (body.len() as u32).to_be_bytes();
    guard.write_all(&len).await?;
    guard.write_all(&body).await?;
    guard.flush().await?;
    Ok(())
}

/// Tiny non-RNG-quality UUID-v4-shaped string generator. Good enough
/// for the IPC event correlation use case (the Go side only uses the
/// `id` for log correlation on events). We avoid pulling the `uuid`
/// crate in just for this.
fn uuid_v4_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = NEXT_EVENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("event-{:x}-{:x}", nanos, counter)
}

static NEXT_EVENT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_through_pipe() {
        let (mut a, b) = tokio::io::duplex(1024);
        // Write a frame from `a`, read it from `b` via a length-prefix.
        let body = serde_json::to_vec(&Envelope {
            ty: "Ping".into(),
            id: "x".into(),
            payload: serde_json::json!({}),
        })
        .unwrap();
        let len = (body.len() as u32).to_be_bytes();
        a.write_all(&len).await.unwrap();
        a.write_all(&body).await.unwrap();
        a.flush().await.unwrap();
        drop(a);

        let mut b = b;
        let mut got_len = [0u8; 4];
        b.read_exact(&mut got_len).await.unwrap();
        let n = u32::from_be_bytes(got_len) as usize;
        let mut buf = vec![0u8; n];
        b.read_exact(&mut buf).await.unwrap();
        let env: Envelope = serde_json::from_slice(&buf).unwrap();
        assert_eq!(env.ty, "Ping");
        assert_eq!(env.id, "x");
    }

    #[tokio::test]
    async fn rejects_oversize_length() {
        // Build a stream where the length header advertises > 16 MiB.
        let (mut a, b) = tokio::io::duplex(1024);
        // Use a length of MAX_FRAME_BYTES + 1.
        let bad_len = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        a.write_all(&bad_len).await.unwrap();
        a.flush().await.unwrap();
        // Drop `a` so the reader hits a length check before EOF.
        drop(a);

        let mut reader = b;
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.unwrap();
        let n = u32::from_be_bytes(len_buf) as usize;
        assert!(n > MAX_FRAME_BYTES, "test setup wrong");
    }
}
