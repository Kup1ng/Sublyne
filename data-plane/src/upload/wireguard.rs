//! WireGuard-marked UDP upload transport (Phase R9a refactor).
//!
//! This module wraps the **existing** WG-marked UDP egress path in the
//! [`UploadTransport`] trait. The runtime behaviour is byte-for-byte
//! unchanged from pre-R9: bind one tokio `UdpSocket`, set `SO_MARK` to
//! the per-tunnel fwmark, run `perf::tune_socket` for the enlarged
//! `SO_SNDBUF`. The R2 perf work all happens before the trait dispatch
//! is even called, so wrapping in a trait costs only ~3 ns of vtable
//! overhead per packet — see the rationale in [`super`].
//!
//! ## Flap recovery
//!
//! The seller's WireGuard interface is not stable for the life of the
//! tunnel: it renegotiates, the upstream NAT/CGNAT binding rebinds, and
//! after a box reboot the interface + policy `ip rule` are re-created.
//! Each of those invalidates the route the kernel cached at `connect()`
//! time, and the connected `send()` then fails with a route error
//! (`ENETUNREACH` / `EHOSTUNREACH` / `ENETDOWN` / `ENODEV`, or `EINVAL`
//! once the cached route is torn down). Pre-R9b that error was only
//! logged and the loop kept hammering the dead socket, so upload stayed
//! wedged for the rest of the tunnel's life.
//!
//! Now a route-class send error flips the socket to "needs reconnect";
//! the next send re-applies `SO_MARK` and re-`connect()`s (re-arming the
//! fwmark-steered route) under a bounded exponential backoff
//! (250 ms → capped at a few seconds) so a persistently-down interface
//! can't spin. A would-block / `EAGAIN` is *not* a flap — it is normal
//! backpressure and is propagated to the caller untouched.

use std::io;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{SessionKey, UploadTransport};

/// First backoff after a flap is detected. Subsequent attempts double
/// up to [`RECONNECT_BACKOFF_MAX`].
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(250);
/// Cap on the reconnect backoff so a persistently-down WG interface
/// doesn't cause a tight reconnect spin but still recovers within a few
/// seconds once it comes back.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(4);

/// How a `send()`/`send_to()` `io::Error` should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendErrKind {
    /// `EAGAIN` / `EWOULDBLOCK`: the socket send buffer is full. Normal
    /// backpressure — propagate to the caller, do NOT tear down.
    Transient,
    /// The cached route / interface is gone or the socket was never
    /// connected: `ENETUNREACH` / `EHOSTUNREACH` / `ENETDOWN` /
    /// `ENODEV` / `EINVAL` / `EDESTADDRREQ`. Trigger a (re)connect.
    DeadRoute,
    /// Anything else (e.g. `EMSGSIZE`, `EPERM`). Propagate to the caller
    /// unchanged; not something a reconnect would fix.
    Other,
}

/// Classify a send error into one of the [`SendErrKind`] buckets so a
/// benign would-block is never mistaken for a dead route, and vice
/// versa. Pure function of the error's `raw_os_error()` (plus the
/// portable `WouldBlock` kind), so it is unit-testable with no live WG
/// interface and no `CAP_NET_ADMIN`.
fn classify_send_err(err: &io::Error) -> SendErrKind {
    if err.kind() == io::ErrorKind::WouldBlock {
        return SendErrKind::Transient;
    }
    match err.raw_os_error() {
        Some(code) => match code {
            libc::EAGAIN => SendErrKind::Transient,
            libc::ENETUNREACH
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::ENODEV
            | libc::EINVAL
            | libc::EDESTADDRREQ => SendErrKind::DeadRoute,
            _ => SendErrKind::Other,
        },
        None => SendErrKind::Other,
    }
}

/// Mutable reconnect bookkeeping, guarded by a `Mutex` that is only
/// ever locked off the success fast path (i.e. when a send returns an
/// error, or during a reconnect attempt). The hot path reads
/// [`WireguardUpload::connected`] (an `AtomicBool`) lock-free.
struct ReconnectState {
    /// Earliest `Instant` at which the next reconnect attempt may run.
    /// `None` means "no backoff pending — attempt immediately".
    next_attempt_at: Option<Instant>,
    /// Current backoff duration, doubled on each failed attempt up to
    /// [`RECONNECT_BACKOFF_MAX`], reset to zero on success.
    backoff: Duration,
}

/// UDP-over-WireGuard upload transport. Owns one tokio `UdpSocket`
/// whose `SO_MARK` is the per-tunnel fwmark, and a fixed destination
/// `upload_target` `SocketAddr`. Cloning the inner `Arc<UdpSocket>` so
/// the existing recv loop in `client.rs::spawn_upload_task` can still
/// `recv_from` on the listener while we own the egress is no longer
/// necessary — the upload task moves the listener and the egress into
/// closures separately, and this transport just holds the egress.
pub struct WireguardUpload {
    /// Identifies this tunnel in log lines.
    tunnel_id: i64,
    /// Destination for every UDP send. Constant for the lifetime of
    /// the tunnel; a hot-reload of `upload_target_addr` is classified
    /// as an "internal restart" by the manager, which tears down the
    /// whole tunnel and rebuilds it — so this value never changes
    /// while the transport is alive.
    upload_target: SocketAddr,
    /// Per-tunnel fwmark, re-applied as `SO_MARK` before every
    /// (re)connect so the kernel re-caches the policy-routed path.
    fwmark: u32,
    egress: Arc<UdpSocket>,
    /// True when the egress socket is `connect()`-ed to `upload_target`
    /// so `send()` (no per-datagram route lookup) is used instead of
    /// `send_to()`. Goes false if `connect()` was refused at bind time
    /// or if a later send hit a dead-route error; a successful
    /// reconnect flips it back to true. Read lock-free on the hot path.
    connected: AtomicBool,
    /// Bounded-backoff reconnect bookkeeping. Locked only on the send
    /// error path / during a reconnect — never on the success path.
    reconnect: Mutex<ReconnectState>,
}

impl WireguardUpload {
    /// Bind a new egress UDP socket, set `SO_MARK = fwmark`, apply the
    /// `perf::tune_socket` knobs (enlarged buffers etc.), and wrap it
    /// as a tokio `UdpSocket`.
    pub fn bind(tunnel_id: i64, upload_target: SocketAddr, fwmark: u32) -> io::Result<Self> {
        let (egress_std, connected) = Self::bind_std(tunnel_id, upload_target, fwmark)?;
        let egress = Arc::new(UdpSocket::from_std(egress_std)?);
        info!(
            tunnel_id,
            target = %upload_target,
            fwmark = format!("0x{:x}", fwmark),
            connected,
            "client: WG-mode upload transport bound"
        );
        Ok(Self {
            tunnel_id,
            upload_target,
            fwmark,
            egress,
            connected: AtomicBool::new(connected),
            reconnect: Mutex::new(ReconnectState {
                next_attempt_at: None,
                backoff: Duration::ZERO,
            }),
        })
    }

    /// Bind a fresh `std::net::UdpSocket`, set `SO_MARK` (before
    /// connect, so the cached route is fwmark-steered), tune it, and
    /// attempt to `connect()` it to `upload_target`. Returns the socket
    /// plus whether the connect succeeded. Soft-fails the connect: a
    /// refused connect yields `(sock, false)` and the caller keeps the
    /// `send_to` fallback rather than failing tunnel bring-up.
    fn bind_std(
        tunnel_id: i64,
        upload_target: SocketAddr,
        fwmark: u32,
    ) -> io::Result<(std::net::UdpSocket, bool)> {
        // Bind on the same address family as the upload target — a v6
        // upload target needs a v6 socket. This mirrors the
        // pre-R9 path exactly (see `client.rs::spawn` before the
        // R9a refactor).
        let bind = if upload_target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let egress_std = std::net::UdpSocket::bind(bind)?;
        egress_std.set_nonblocking(true)?;
        // SO_MARK before connect() so the route the kernel caches at
        // connect time is the fwmark-steered one (the per-tunnel policy
        // route through the seller's WireGuard interface).
        set_so_mark_fd(&egress_std, fwmark)?;
        crate::perf::tune_socket(&egress_std, "client/egress");
        // `connect()` the egress to the fixed upload target. The
        // destination never changes for the life of this transport (an
        // `upload_target_addr` edit is an internal Stop+Start), so a
        // connected datagram socket lets every send be a plain `send()`
        // with no per-datagram destination resolution / route lookup —
        // a small but free win on the throughput-lane (UDP-WG) mechanism.
        // Soft-fail: if connect() is refused we keep the send_to path so
        // packet flow never depends on it. A later send that hits a
        // dead-route error will retry the connect (see `try_reconnect`).
        let connected = match egress_std.connect(upload_target) {
            Ok(()) => true,
            Err(e) => {
                warn!(
                    tunnel_id,
                    target = %upload_target,
                    err = %e,
                    "client: WG egress connect() refused; falling back to send_to"
                );
                false
            }
        };
        Ok((egress_std, connected))
    }

    /// Handle a dead-route send error: mark the socket not-connected and
    /// attempt to re-apply `SO_MARK` + re-`connect()` the *existing*
    /// egress fd to `upload_target`, under a bounded exponential
    /// backoff. The fd is reused (not re-bound) so the listener side and
    /// any cloned `Arc<UdpSocket>` references stay valid; only the
    /// kernel's cached route is re-armed.
    ///
    /// Called only off the hot path (after a send already failed). At
    /// most one reconnect runs at a time because the whole body holds
    /// the `reconnect` mutex.
    async fn try_reconnect(&self) {
        // Flip to send_to immediately so concurrent senders stop hitting
        // the dead connected fd while we recover.
        self.connected.store(false, Ordering::Relaxed);

        let mut state = self.reconnect.lock().await;
        // Honour the backoff: if we attempted recently, skip — the next
        // send (or this one's caller retry) will try again later.
        if let Some(at) = state.next_attempt_at {
            if Instant::now() < at {
                return;
            }
        }

        // Re-apply SO_MARK before connect so the re-cached route is once
        // again fwmark-steered, then re-connect the existing fd.
        let fd = self.egress.as_raw_fd();
        let result = (|| -> io::Result<()> {
            set_so_mark_raw(fd, self.fwmark)?;
            reconnect_fd(fd, self.upload_target)
        })();

        match result {
            Ok(()) => {
                self.connected.store(true, Ordering::Relaxed);
                state.next_attempt_at = None;
                state.backoff = Duration::ZERO;
                info!(
                    tunnel_id = self.tunnel_id,
                    target = %self.upload_target,
                    "client: WG egress reconnected after flap; resuming connected send()"
                );
            }
            Err(e) => {
                let next = if state.backoff.is_zero() {
                    RECONNECT_BACKOFF_MIN
                } else {
                    (state.backoff * 2).min(RECONNECT_BACKOFF_MAX)
                };
                state.backoff = next;
                state.next_attempt_at = Some(Instant::now() + next);
                warn!(
                    tunnel_id = self.tunnel_id,
                    target = %self.upload_target,
                    err = %e,
                    retry_in_ms = next.as_millis() as u64,
                    "client: WG egress reconnect failed (interface still down?); will retry with backoff"
                );
            }
        }
    }
}

#[async_trait]
impl UploadTransport for WireguardUpload {
    async fn send(&self, _session: SessionKey, payload: &[u8]) -> io::Result<()> {
        // One syscall per packet. On the connected socket (the normal
        // case) `send()` skips the per-datagram destination + route
        // resolution that `send_to()` repeats every call. The
        // `connected` flag is read lock-free; the reconnect machinery
        // only engages on the (rare) error path below.
        //
        // `_session` is ignored: the WG path has exactly one egress
        // socket, so there's no per-flow routing to do. SOCKS5 honours
        // it for sticky pool routing.
        if self.connected.load(Ordering::Relaxed) {
            match self.egress.send(payload).await {
                Ok(_) => Ok(()),
                Err(e) => match classify_send_err(&e) {
                    // Backpressure: leave the socket connected and let
                    // the caller retry, exactly as before this change.
                    SendErrKind::Transient => Err(e),
                    // Route/interface gone: a WG flap. Attempt recovery
                    // (bounded backoff) and report the error so the
                    // caller drops/retries this datagram. The next send
                    // takes the (now likely reconnected) fast path.
                    SendErrKind::DeadRoute => {
                        self.try_reconnect().await;
                        Err(e)
                    }
                    SendErrKind::Other => Err(e),
                },
            }
        } else {
            // Not connected (connect soft-failed at bind, or a prior
            // flap dropped us here). Use the correct unconnected
            // fallback, and opportunistically try to upgrade back to the
            // connected fast path so we don't latch send_to forever.
            let result = self.egress.send_to(payload, self.upload_target).await;
            // Whether the send_to succeeded or failed with a route
            // error, try to (re)connect so a transient bring-up race or
            // a healed interface restores the fast path. `try_reconnect`
            // is backoff-gated, so this is cheap when the interface is
            // genuinely still down.
            match &result {
                Ok(_) => {
                    self.try_reconnect().await;
                }
                Err(e) if classify_send_err(e) == SendErrKind::DeadRoute => {
                    self.try_reconnect().await;
                }
                Err(_) => {}
            }
            result.map(|_| ())
        }
    }
}

/// Apply `SO_MARK` to a `std::net::UdpSocket` (used at bind time).
#[cfg(target_os = "linux")]
fn set_so_mark_fd(sock: &std::net::UdpSocket, mark: u32) -> io::Result<()> {
    set_so_mark_raw(sock.as_raw_fd(), mark)
}

#[cfg(not(target_os = "linux"))]
fn set_so_mark_fd(_sock: &std::net::UdpSocket, _mark: u32) -> io::Result<()> {
    Ok(())
}

/// Apply `SO_MARK` to a raw fd. Lifted verbatim from `client.rs` so
/// the trait wrapper can stay self-contained. Shared by the bind-time
/// and reconnect paths so the SO_MARK-before-connect ordering holds on
/// every (re)connect.
#[cfg(target_os = "linux")]
fn set_so_mark_raw(fd: RawFd, mark: u32) -> io::Result<()> {
    if mark == 0 {
        return Ok(());
    }
    // SAFETY: `fd` is a valid open file descriptor owned by the caller's
    // socket for the duration of this call; SO_MARK reads a 4-byte int
    // from our buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_so_mark_raw(_fd: RawFd, _mark: u32) -> io::Result<()> {
    Ok(())
}

/// Re-`connect()` an existing UDP fd to `target`. Used by the reconnect
/// path to re-arm the kernel's cached (fwmark-steered) route on the
/// *same* fd, so cloned `Arc<UdpSocket>` references stay valid. The fd
/// stays non-blocking; `connect()` on a connected UDP socket re-points
/// it without a handshake.
///
/// We borrow the fd into a temporary `std::net::UdpSocket` purely to
/// reuse its safe, address-family-correct `connect()` (no manual
/// `sockaddr` marshalling). The wrapper is held in `ManuallyDrop` so it
/// does **not** close the fd when it goes out of scope — ownership stays
/// with the `Arc<UdpSocket>` in `self.egress`.
fn reconnect_fd(fd: RawFd, target: SocketAddr) -> io::Result<()> {
    // SAFETY: `fd` is a valid open file descriptor owned by the caller's
    // `Arc<UdpSocket>` for the duration of this call. `ManuallyDrop`
    // prevents the temporary `UdpSocket` from running its `Drop` (which
    // would `close()` the fd still owned elsewhere).
    let sock = ManuallyDrop::new(unsafe { std::net::UdpSocket::from_raw_fd(fd) });
    sock.connect(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_would_block_is_transient() {
        let e = io::Error::new(io::ErrorKind::WouldBlock, "would block");
        assert_eq!(classify_send_err(&e), SendErrKind::Transient);
    }

    #[test]
    fn classify_eagain_is_transient() {
        let e = io::Error::from_raw_os_error(libc::EAGAIN);
        assert_eq!(classify_send_err(&e), SendErrKind::Transient);
    }

    #[test]
    fn classify_route_errors_are_dead_route() {
        for code in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENETDOWN,
            libc::ENODEV,
            libc::EINVAL,
            libc::EDESTADDRREQ,
        ] {
            let e = io::Error::from_raw_os_error(code);
            assert_eq!(
                classify_send_err(&e),
                SendErrKind::DeadRoute,
                "os error {code} should classify as DeadRoute"
            );
        }
    }

    #[test]
    fn classify_other_errors_are_other() {
        let e = io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert_eq!(classify_send_err(&e), SendErrKind::Other);
        let e = io::Error::from_raw_os_error(libc::EPERM);
        assert_eq!(classify_send_err(&e), SendErrKind::Other);
    }

    #[tokio::test]
    async fn loopback_send_byte_for_byte() {
        // End-to-end smoke test: bind a WireguardUpload pointing at a
        // dummy UDP listener and verify the bytes arrive unchanged.
        // SO_MARK is zero so the test doesn't need CAP_NET_ADMIN.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().expect("local_addr");
        let upload = WireguardUpload::bind(1, server_addr, 0).expect("bind upload");

        let payload = b"hello loopback wireguard";
        let key = SessionKey {
            client_addr: "127.0.0.1:33333".parse().expect("test addr"),
            local_port: 0,
        };
        upload.send(key, payload).await.expect("send");
        let mut buf = vec![0u8; 1500];
        let (n, _from) = server.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], payload);
    }
}
