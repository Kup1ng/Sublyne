//! Client-side upload-path abstraction.
//!
//! Round 1 / R2 the upload was a single, hardcoded WG-marked UDP socket
//! that `recv_from()`'d the end-user listener and `send_to()`'d the
//! upload target with `SO_MARK` set to the per-tunnel fwmark. R9a
//! introduced a second upload transport — SOCKS5 over TCP — that spreads
//! the upload across N parallel connections to a load-balancing proxy
//! fronting multiple Starlink uplinks. To avoid sprinkling
//! `if upload_mode { … } else { … }` through `client.rs`, both
//! transports implement the [`UploadTransport`] trait below and
//! `spawn_upload_task` dispatches through `Arc<dyn UploadTransport>`.
//!
//! R9a shipped the SOCKS5 implementation with a single TCP connection
//! (pool size = 1, hardcoded regardless of `parallel_connections` in
//! the spec). **R9b grows that pool to N** with per-session sticky
//! routing, on-failure rehashing, and a live resize hook so editing
//! `parallel_connections` in the panel resizes the live pool without
//! restarting the tunnel.
//!
//! ## Why a trait, not an enum
//!
//! A trait keeps each transport's state local to its module: the
//! WireGuard implementation only carries the cloned `Arc<UdpSocket>`,
//! the SOCKS5 implementation carries the connection pool plus a
//! reconnect task. A `Box<dyn>` dispatch costs one indirect call per
//! upload packet — the same arithmetic cost as the existing
//! `egress.send_to()` syscall path, and dwarfed by the syscall itself.
//! On the hot path we pay ~3 ns of vtable overhead per packet at most;
//! the `send_to()` syscall is measured in hundreds of nanoseconds.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use tracing::info;

pub mod socks5;
pub mod wireguard;

/// Identifier the upload listener stamps on every outbound packet so a
/// pool-based transport (SOCKS5) can route per-flow stickily. The shape
/// is `(end_user_src, tunnel_local_listen_port)`: the source address of
/// the end-user packet, plus the tunnel's own listen port to keep
/// hashes deterministic across tunnels that share a SOCKS5 proxy. The
/// WireGuard transport ignores the key entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// The end-user's source `SocketAddr` (IP + port) as returned by
    /// `listener.recv_from`. Two packets from the same end-user share
    /// the same key, so they hash to the same SOCKS5 slot and the
    /// Remote sees them in the order the Client received them.
    pub client_addr: SocketAddr,
    /// The tunnel's own `local_listen_addr` port. The roadmap text
    /// specifies `(client_addr, local_port)` — including the local
    /// port keeps a single end-user that's hitting two different
    /// tunnels (different `local_listen_addr`) on the same client
    /// machine routed independently across their SOCKS5 pools.
    pub local_port: u16,
}

/// Trait implemented by every client-side upload transport.
/// [`wireguard::WireguardUpload`] (the historical WG-marked UDP path)
/// and [`socks5::Socks5Upload`] (R9b: N parallel TCP connections with
/// per-session sticky routing).
///
/// `send` is called once per inbound end-user packet on the upload
/// listener. Implementations may queue, batch, or otherwise transform
/// the bytes — they MUST eventually deliver every accepted payload to
/// the configured upload target, or drop it with a logged reason.
///
/// `set_parallel_connections` is called by the manager when an
/// `UpdateTunnel` IPC carries a new `socks5_target.parallel_connections`
/// and nothing else SOCKS5-related changed. The default impl is a
/// no-op so the WireGuard transport ignores the call cleanly.
///
/// `shutdown` is called when the tunnel handle's stop watch fires.
/// Implementations should release their resources (close TCP
/// connections, drop background tasks) inside this method. After
/// `shutdown` returns, subsequent `send` calls may return an error;
/// the caller stops invoking them.
#[async_trait]
pub trait UploadTransport: Send + Sync {
    /// Forward one application UDP payload toward the upload target.
    /// `session` carries the routing hint so a pool-based transport
    /// can keep all packets from one end-user on one TCP connection;
    /// non-pool transports ignore it. Returns Err when the transport
    /// is permanently broken (e.g. every SOCKS5 connection in the
    /// pool is down and reconnection failed); the caller logs and
    /// drops the packet, the next `send` retries.
    async fn send(&self, session: SessionKey, payload: &[u8]) -> io::Result<()>;

    /// Resize the connection pool live to `n`. Called by the manager
    /// on `UpdateTunnel` when `socks5_target.parallel_connections`
    /// changes and nothing else SOCKS5-related did. Returns `Ok(true)`
    /// if the pool was actually resized (so the manager can include
    /// `"parallel_connections"` in the reply's `changed` field),
    /// `Ok(false)` if the requested size matches the current size and
    /// no work was done. The default impl is a no-op returning
    /// `Ok(false)` — the WireGuard transport has no pool.
    async fn set_parallel_connections(&self, _n: u32) -> io::Result<bool> {
        Ok(false)
    }

    /// Best-effort tear-down. Called once when the tunnel stops.
    /// Default impl is a no-op — the WireGuard transport relies on
    /// `Arc` reference counting, the SOCKS5 transport overrides this
    /// to close its TCP connection pool.
    async fn shutdown(&self) {}
}

/// Build the right [`UploadTransport`] for a given client tunnel spec.
/// Centralised here so the trait selection logic stays in one place
/// rather than scattered through `client.rs::spawn`.
///
/// On error, the caller should fail tunnel start with the returned
/// `io::Error` — Manager maps that to a IPC `INTERNAL` / `PORT_IN_USE`
/// / etc. reply for the panel.
pub async fn build_for_client_spec(
    spec: &crate::spec::TunnelSpec,
    resolved: &crate::spec::ResolvedSpec,
    stop_rx: watch::Receiver<bool>,
) -> io::Result<Arc<dyn UploadTransport>> {
    let upload_target = resolved
        .upload_target_addr
        .expect("validate ensured upload_target_addr");
    match &spec.socks5_target {
        Some(target) => {
            info!(
                tunnel_id = spec.id,
                parallel = target.parallel_connections,
                proxy = %target.host,
                port = target.port,
                "client: SOCKS5 upload transport opening N parallel connections (R9b)"
            );
            let transport =
                socks5::Socks5Upload::connect(spec.id, target.clone(), upload_target, stop_rx)
                    .await?;
            Ok(Arc::new(transport))
        }
        None => {
            // Default upload path — WG-marked UDP. Pre-R9 behaviour
            // unchanged: a single UdpSocket with SO_MARK set to the
            // per-tunnel fwmark (or zero, on loopback tests).
            let transport =
                wireguard::WireguardUpload::bind(spec.id, upload_target, spec.wireguard_fwmark)?;
            Ok(Arc::new(transport))
        }
    }
}
