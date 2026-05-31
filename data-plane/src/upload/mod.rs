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
use tracing::{info, warn};

use crate::perf::Socks5KeepaliveProfile;
use crate::spec::Transport;

pub mod socks5;
pub mod wireguard;

/// The six concrete upload mechanisms — one per `(download transport,
/// upload substrate)` cell of the v2 matrix.
///
/// There are only two substrates that physically move bytes Client →
/// Remote: the WireGuard kernel-UDP egress and the SOCKS5 N-connection
/// TCP pool. A *mechanism* pairs a substrate with the download transport
/// it serves and selects a tuned [`Socks5Profile`] (for the SOCKS5 cells)
/// or the connected-egress WG path (for the WG cells). The enum exists so
/// the chosen cell is a first-class, named, logged value rather than an
/// implicit `socks5_target.is_some()` branch.
///
/// Matrix:
///
/// | download | substrate | mechanism      |
/// |----------|-----------|----------------|
/// | udp      | WireGuard | [`Self::UdpWg`]       |
/// | tcp_syn  | SOCKS5    | [`Self::TcpSocks5`]   |
/// | icmp     | WireGuard | [`Self::IcmpWg`]      |
/// | icmp     | SOCKS5    | [`Self::IcmpSocks5`]  |
/// | icmpv6   | WireGuard | [`Self::Icmpv6Wg`]    |
/// | icmpv6   | SOCKS5    | [`Self::Icmpv6Socks5`]|
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMechanism {
    /// download=udp → WireGuard, native UDP. The throughput lane.
    UdpWg,
    /// download=tcp_syn → SOCKS5, coalesced real-TCP-stream writes.
    TcpSocks5,
    /// download=icmp → WireGuard (v4), latency regime.
    IcmpWg,
    /// download=icmp → SOCKS5, per-frame flush + aggressive keepalive.
    IcmpSocks5,
    /// download=icmpv6 → WireGuard (v6), latency regime.
    Icmpv6Wg,
    /// download=icmpv6 → SOCKS5, per-frame flush + aggressive keepalive.
    Icmpv6Socks5,
}

impl UploadMechanism {
    /// Stable lower-kebab name for logs, metrics, and the panel.
    pub fn label(self) -> &'static str {
        match self {
            UploadMechanism::UdpWg => "udp-wg",
            UploadMechanism::TcpSocks5 => "tcp-socks5",
            UploadMechanism::IcmpWg => "icmp-wg",
            UploadMechanism::IcmpSocks5 => "icmp-socks5",
            UploadMechanism::Icmpv6Wg => "icmpv6-wg",
            UploadMechanism::Icmpv6Socks5 => "icmpv6-socks5",
        }
    }
}

/// Resolve the matrix cell for a `(download_transport, uses_socks5)`
/// pair. Returns `None` for the two off-matrix cells (`udp`+SOCKS5,
/// `tcp_syn`+WireGuard): the Go control plane rejects those on save, but
/// a legacy / imported row can still reach the dataplane, where the
/// caller logs a warning and runs with a sensible default rather than
/// dead-tunnelling on upgrade.
pub fn mechanism_for(download: Transport, uses_socks5: bool) -> Option<UploadMechanism> {
    Some(match (download, uses_socks5) {
        (Transport::Udp, false) => UploadMechanism::UdpWg,
        (Transport::TcpSyn, true) => UploadMechanism::TcpSocks5,
        (Transport::Icmp, false) => UploadMechanism::IcmpWg,
        (Transport::Icmp, true) => UploadMechanism::IcmpSocks5,
        (Transport::Icmpv6, false) => UploadMechanism::Icmpv6Wg,
        (Transport::Icmpv6, true) => UploadMechanism::Icmpv6Socks5,
        // Off-matrix — udp must pair with WireGuard, tcp_syn with SOCKS5.
        (Transport::Udp, true) | (Transport::TcpSyn, false) => return None,
    })
}

/// Client-side SOCKS5 write strategy. The application traffic is always
/// UDP, so a stream substrate must length-delimit datagrams either way
/// (`[u16 BE len][payload]` framing); the strategy only changes whether
/// we treat the hop as a real byte stream (coalesce) or as a
/// latency-critical packet relay (per-frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStrategy {
    /// **TCP-SOCKS5**: drain the slot queue and write all pending frames
    /// in one `write_all` per wake-up so TCP segments fill — real TCP
    /// byte-stream semantics over the SOCKS5 hop, instead of pinning one
    /// UDP datagram to one force-flushed TCP segment.
    Coalesce,
    /// **ICMP/ICMPv6-SOCKS5**: flush each frame as it arrives (Nagle off)
    /// so a low-rate trickle isn't delayed waiting for more bytes.
    PerFrame,
}

/// Tuning bundle handed to a SOCKS5 upload pool, derived from the
/// download transport: the write strategy + the kernel keepalive profile.
#[derive(Debug, Clone, Copy)]
pub struct Socks5Profile {
    pub write: WriteStrategy,
    pub keepalive: Socks5KeepaliveProfile,
}

impl Socks5Profile {
    /// The SOCKS5 profile for a given download transport. `tcp_syn` gets
    /// the bulk-stream regime (coalesce + Bulk keepalive); every other
    /// transport — `icmp`, `icmpv6`, and the off-matrix `udp`+SOCKS5
    /// fallback — gets the latency regime (per-frame + Latency keepalive),
    /// which is the proven pre-matrix behaviour.
    pub fn for_download(download: Transport) -> Self {
        match download {
            Transport::TcpSyn => Socks5Profile {
                write: WriteStrategy::Coalesce,
                keepalive: Socks5KeepaliveProfile::Bulk,
            },
            _ => Socks5Profile {
                write: WriteStrategy::PerFrame,
                keepalive: Socks5KeepaliveProfile::Latency,
            },
        }
    }
}

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
    /// non-pool transports ignore it.
    ///
    /// Returns `Ok(true)` when the payload was handed to the wire (or
    /// queued for it), `Ok(false)` when it was deliberately dropped
    /// before the wire (e.g. every SOCKS5 connection in the pool is
    /// down/full — UDP is best-effort and the inner protocol
    /// retransmits), and `Err` for a hard transport error. The caller
    /// meters delivered vs dropped so the dashboard's upload counter
    /// never counts a dropped frame as sent.
    async fn send(&self, session: SessionKey, payload: &[u8]) -> io::Result<bool>;

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
    let uses_socks5 = spec.socks5_target.is_some();

    // Resolve and log the v2 matrix cell. Off-matrix combinations
    // (udp+SOCKS5, tcp_syn+WireGuard) can't be authored in the panel but
    // a legacy / imported row can still reach here — warn loudly and run
    // with a sensible default rather than dead-tunnelling on upgrade.
    match mechanism_for(spec.download_transport, uses_socks5) {
        Some(mech) => info!(
            tunnel_id = spec.id,
            mechanism = mech.label(),
            "client: upload mechanism selected (v2 matrix)"
        ),
        None => warn!(
            tunnel_id = spec.id,
            download = ?spec.download_transport,
            uses_socks5,
            "client: upload mode is off-matrix for this download transport \
             (udp pairs with WireGuard, tcp_syn with SOCKS5) — running anyway; \
             edit the tunnel in the panel to clear this warning"
        ),
    }

    match &spec.socks5_target {
        Some(target) => {
            let profile = Socks5Profile::for_download(spec.download_transport);
            info!(
                tunnel_id = spec.id,
                parallel = target.parallel_connections,
                proxy = %target.host,
                port = target.port,
                write = ?profile.write,
                keepalive = ?profile.keepalive,
                "client: SOCKS5 upload transport opening N parallel connections"
            );
            let transport = socks5::Socks5Upload::connect(
                spec.id,
                target.clone(),
                upload_target,
                profile,
                stop_rx,
            )
            .await?;
            Ok(Arc::new(transport))
        }
        None => {
            // WireGuard substrate — WG-marked UDP egress, now `connect()`-ed
            // to the fixed upload target so the kernel caches the route and
            // each send skips a per-datagram route lookup. The R2 perf
            // tuning (enlarged SO_SNDBUF, SO_MARK = fwmark) is unchanged.
            let transport =
                wireguard::WireguardUpload::bind(spec.id, upload_target, spec.wireguard_fwmark)?;
            Ok(Arc::new(transport))
        }
    }
}
