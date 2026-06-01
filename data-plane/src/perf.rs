//! Socket buffer tuning for the data path.
//!
//! Per-socket `SO_RCVBUF` / `SO_SNDBUF` is the single biggest knob for
//! sustaining the ≥ 200 Mbit/s per-tunnel target in PRD §7. Ubuntu
//! ships `net.core.rmem_max` / `wmem_max` at 208 KiB (212 992 bytes);
//! any plain `setsockopt(SO_RCVBUF)` above that gets silently clamped
//! and the kernel quietly drops packets at the UDP receive queue under
//! sustained load. Field measurement on the Iran client showed
//! `UdpRcvbufErrors = 22 %` of inbound at 200 Mbit/s offered, with all
//! three vCPUs sitting around 70 % idle — the limit was the queue, not
//! the CPU.
//!
//! Two complementary mitigations:
//!
//! 1. **In code (this module).** Use `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE`,
//!    which a `CAP_NET_ADMIN`-holding process (we have it; PRD §6.5)
//!    can use to bypass `rmem_max` / `wmem_max`. Fall back to the
//!    non-forced variants if for some reason `*BUFFORCE` is refused,
//!    so packet flow doesn't depend on a niche kernel feature.
//! 2. **In setup.sh.** Also raise `rmem_max` / `wmem_max` persistently
//!    via `/etc/sysctl.d/99-sublyne.conf`, so future tooling that
//!    doesn't know about `*BUFFORCE` still gets a sensible ceiling.
//!
//! The target buffer size is overridable per process via the
//! `SUBLYNE_SOCKET_BUF_BYTES` environment variable. Default is 4 MiB,
//! the empirical sweet spot from a separate proven spoof project that
//! sustained 200 Mbit/s on a 2-vCPU box.

use std::env;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::OnceLock;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tracing::{debug, info, warn};

/// Default per-socket buffer size: 4 MiB. Measured-good on the user's
/// other production spoof setup at 200 Mbit/s on 2 cores. 4 MiB also
/// gives ≈ 160 ms of buffered traffic at 200 Mbit/s with 1400-byte
/// packets, which covers a normal trans-continental RTT plus jitter.
const DEFAULT_BUF_BYTES: usize = 4 * 1024 * 1024;
/// Floor on the env-var override. Anything below 256 KiB barely beats
/// the Ubuntu default and almost certainly means a typo; refuse it
/// loudly rather than ship a regression.
const MIN_BUF_BYTES: usize = 256 * 1024;
/// Environment variable name for the override.
pub const ENV_BUF_BYTES: &str = "SUBLYNE_SOCKET_BUF_BYTES";

/// Env knob for the `recvmmsg` batch size. Default 16, clamped 1..=64
/// at read time so a typo can't blow up the syscall.
pub const ENV_RECV_BATCH: &str = "SUBLYNE_RECV_BATCH";
/// Env knob for the `sendmmsg` batch size. Same default + clamp as
/// [`ENV_RECV_BATCH`].
pub const ENV_SEND_BATCH: &str = "SUBLYNE_SEND_BATCH";
/// Env knob overriding the per-tunnel worker count (defaults to
/// `available_parallelism()`). Clamped 1..=64.
pub const ENV_PER_CORE_SOCKETS: &str = "SUBLYNE_PER_CORE_SOCKETS";
/// Env knob for the SOCKS5 bulk-coalesce soft cap, in bytes. The
/// TCP-SOCKS5 bulk mechanism drains its per-slot queue into a single
/// `write_all` up to this many bytes so TCP segments fill — bigger means
/// fewer `write()` syscalls per MB under burst, at the cost of a larger
/// transient per-slot buffer. Default 256 KiB; only the Coalesce
/// (TCP-SOCKS5) write strategy reads it, so the latency mechanisms are
/// unaffected.
pub const ENV_SOCKS5_COALESCE_BYTES: &str = "SUBLYNE_SOCKS5_COALESCE_BYTES";
/// Env knob: spread a SINGLE bulk (TCP-SOCKS5) flow across ALL N proxy
/// connections (round-robin) instead of pinning it to one. `1`/on (the
/// default) lets one heavy flow use every Starlink uplink behind the proxy
/// — the fix for the single-connection upload cap. `0`/off reverts to the
/// historical per-flow sticky routing (one flow → one connection), useful
/// if a path's uplinks differ enough in latency that the added reorder
/// hurts the inner protocol. Only the Coalesce (bulk) mechanism reads it;
/// the latency ICMP-SOCKS5 mechanisms always stay sticky.
pub const ENV_SOCKS5_STRIPE: &str = "SUBLYNE_SOCKS5_STRIPE";

const DEFAULT_BATCH: usize = 16;
const MIN_BATCH: usize = 1;
const MAX_BATCH: usize = 64;
const MIN_WORKERS: usize = 1;
const MAX_WORKERS: usize = 64;

/// Default SOCKS5 bulk-coalesce soft cap: 256 KiB (~180 MTU-sized frames
/// per write). Raised from the historical hard-coded 64 KiB so a bulk
/// burst fills fewer, larger TCP writes — fewer syscalls per MB.
const DEFAULT_COALESCE_BYTES: usize = 256 * 1024;
/// Floor on the coalesce cap — below 16 KiB the coalescing barely beats
/// per-frame writes; refuse smaller values as a likely typo.
const MIN_COALESCE_BYTES: usize = 16 * 1024;
/// Ceiling on the coalesce cap — a single drained write larger than a few
/// MiB just builds latency/memory for no extra segment-filling benefit.
const MAX_COALESCE_BYTES: usize = 4 * 1024 * 1024;

static CACHED: OnceLock<usize> = OnceLock::new();
static CACHED_RECV_BATCH: OnceLock<usize> = OnceLock::new();
static CACHED_SEND_BATCH: OnceLock<usize> = OnceLock::new();
static CACHED_PER_CORE_SOCKETS: OnceLock<usize> = OnceLock::new();
static CACHED_COALESCE_BYTES: OnceLock<usize> = OnceLock::new();
static CACHED_SOCKS5_STRIPE: OnceLock<bool> = OnceLock::new();

/// Resolve the configured per-socket buffer size. Reads
/// `$SUBLYNE_SOCKET_BUF_BYTES` once per process; subsequent calls
/// return the cached value. Falls back to 4 MiB when the env var is
/// missing, unparseable, or below the safety floor.
pub fn buf_bytes() -> usize {
    *CACHED.get_or_init(resolve_buf_bytes)
}

/// `recvmmsg` batch size, clamped to `[1, 64]`. Default 16.
pub fn recv_batch() -> usize {
    *CACHED_RECV_BATCH.get_or_init(|| resolve_batch(ENV_RECV_BATCH))
}

/// `sendmmsg` batch size, clamped to `[1, 64]`. Default 16.
pub fn send_batch() -> usize {
    *CACHED_SEND_BATCH.get_or_init(|| resolve_batch(ENV_SEND_BATCH))
}

/// Per-tunnel worker count for the SO_REUSEPORT upload listener fan-out
/// and the per-worker download verify/seal pools. Defaults to
/// `available_parallelism()`, clamped to `[1, 64]`. Operators set the
/// env knob to leave a core free for the control plane.
pub fn per_core_sockets() -> usize {
    *CACHED_PER_CORE_SOCKETS.get_or_init(resolve_per_core_sockets)
}

/// SOCKS5 bulk-coalesce soft cap in bytes, clamped to
/// `[16 KiB, 4 MiB]`. Default 256 KiB. Read once per process; only the
/// `WriteStrategy::Coalesce` (TCP-SOCKS5) drain loop consults it.
pub fn socks5_coalesce_bytes() -> usize {
    *CACHED_COALESCE_BYTES.get_or_init(resolve_coalesce_bytes)
}

fn resolve_coalesce_bytes() -> usize {
    match env::var(ENV_SOCKS5_COALESCE_BYTES) {
        Ok(s) => match s.parse::<usize>() {
            Ok(n) => {
                let clamped = n.clamp(MIN_COALESCE_BYTES, MAX_COALESCE_BYTES);
                if clamped != n {
                    warn!(
                        value = n,
                        min = MIN_COALESCE_BYTES,
                        max = MAX_COALESCE_BYTES,
                        env = ENV_SOCKS5_COALESCE_BYTES,
                        "perf: socks5 coalesce cap out of range, clamped"
                    );
                }
                clamped
            }
            Err(e) => {
                warn!(value = %s, err = %e, env = ENV_SOCKS5_COALESCE_BYTES,
                    "perf: socks5 coalesce env unparseable, using default 256 KiB");
                DEFAULT_COALESCE_BYTES
            }
        },
        Err(_) => DEFAULT_COALESCE_BYTES,
    }
}

/// Wrap a socket **bind** error so the operator-facing message names the
/// socket's purpose AND the exact address that failed, while preserving
/// the original [`std::io::ErrorKind`]. Preserving the kind is what keeps
/// the downstream classification in `manager.rs` intact: `AddrInUse` still
/// maps to `PORT_IN_USE` and `PermissionDenied` to `RAW_SOCKET_FORBIDDEN`.
///
/// Before this helper a bind collision surfaced only as
/// `"PORT_IN_USE: bind: Address in use (os error 98)"` — with no hint of
/// which port or which socket — which made the multi-port start collision
/// (a primary listener vs. a per-port listener on the same port) hard to
/// diagnose. With it, `manager.rs`'s `"bind: "` prefix plus this label
/// reads e.g.
/// `"PORT_IN_USE: bind: client/listen 0.0.0.0:51821: Address in use (os error 98)"`.
pub fn bind_err(e: std::io::Error, purpose: &str, addr: std::net::SocketAddr) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{purpose} {addr}: {e}"))
}

/// Wrap a raw-**socket open** error (raw sockets are not bound to an
/// address) with a purpose label, preserving the [`std::io::ErrorKind`] so
/// a `PermissionDenied` still classifies as `RAW_SOCKET_FORBIDDEN`. Lets a
/// "no CAP_NET_RAW" failure say which transport's socket was refused
/// instead of a bare `"raw socket: Permission denied"`.
pub fn socket_err(e: std::io::Error, purpose: &str) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{purpose}: {e}"))
}

/// Whether to stripe a single bulk (TCP-SOCKS5) flow across all N proxy
/// connections (default `true`). Read once per process. `0`/`false`/`off`/
/// `no` disable it (revert to per-flow sticky routing); anything else —
/// including an unset env — enables it.
pub fn socks5_stripe() -> bool {
    *CACHED_SOCKS5_STRIPE.get_or_init(resolve_socks5_stripe)
}

fn resolve_socks5_stripe() -> bool {
    match env::var(ENV_SOCKS5_STRIPE) {
        Ok(s) => {
            let v = s.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

fn resolve_batch(env_name: &str) -> usize {
    match env::var(env_name) {
        Ok(s) => match s.parse::<usize>() {
            Ok(n) => {
                let clamped = n.clamp(MIN_BATCH, MAX_BATCH);
                if clamped != n {
                    warn!(
                        value = n,
                        min = MIN_BATCH,
                        max = MAX_BATCH,
                        env = env_name,
                        "perf: batch size out of range, clamped"
                    );
                }
                clamped
            }
            Err(e) => {
                warn!(value = %s, err = %e, env = env_name,
                    "perf: batch env unparseable, using default");
                DEFAULT_BATCH
            }
        },
        Err(_) => DEFAULT_BATCH,
    }
}

fn resolve_per_core_sockets() -> usize {
    if let Ok(s) = env::var(ENV_PER_CORE_SOCKETS) {
        match s.parse::<usize>() {
            Ok(n) => return n.clamp(MIN_WORKERS, MAX_WORKERS),
            Err(e) => warn!(value = %s, err = %e, env = ENV_PER_CORE_SOCKETS,
                "perf: per-core-sockets env unparseable, falling back to available_parallelism"),
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(MIN_WORKERS, MAX_WORKERS))
        .unwrap_or(2)
}

fn resolve_buf_bytes() -> usize {
    match env::var(ENV_BUF_BYTES) {
        Ok(s) => match s.parse::<usize>() {
            Ok(n) if n >= MIN_BUF_BYTES => n,
            Ok(n) => {
                warn!(
                    value = n,
                    min = MIN_BUF_BYTES,
                    env = ENV_BUF_BYTES,
                    "perf: requested buffer size below safe minimum, using default 4 MiB"
                );
                DEFAULT_BUF_BYTES
            }
            Err(e) => {
                warn!(
                    value = %s,
                    err = %e,
                    env = ENV_BUF_BYTES,
                    "perf: env var unparseable, using default 4 MiB"
                );
                DEFAULT_BUF_BYTES
            }
        },
        Err(_) => DEFAULT_BUF_BYTES,
    }
}

/// Log the resolved target buffer size once at startup. Reading it
/// also primes the OnceLock so later `tune_socket` calls don't race
/// on first-resolve.
pub fn log_startup_settings() {
    info!(
        socket_buf_bytes = buf_bytes(),
        recv_batch = recv_batch(),
        send_batch = send_batch(),
        per_core_sockets = per_core_sockets(),
        socks5_coalesce_bytes = socks5_coalesce_bytes(),
        socks5_stripe = socks5_stripe(),
        "perf: data-plane runtime tuning resolved"
    );
}

/// Apply `SO_RCVBUF` and `SO_SNDBUF` to `sock`, preferring the
/// `*BUFFORCE` variants so we bypass `net.core.rmem_max` / `wmem_max`.
/// On CAP_NET_ADMIN-less or quirky kernels we fall back to plain
/// `SO_RCVBUF` / `SO_SNDBUF` (which the kernel will then clamp to
/// rmem_max — still better than nothing, especially with the sysctl
/// bump from setup.sh).
///
/// `label` shows up in debug logs only; pick something short and
/// human-readable like `"client/listen"` or `"remote/forward"`.
pub fn tune_socket<F: AsRawFd>(sock: &F, label: &str) {
    let want = buf_bytes() as libc::c_int;
    let fd = sock.as_raw_fd();
    set_buf(
        fd,
        libc::SO_RCVBUFFORCE,
        libc::SO_RCVBUF,
        want,
        label,
        "recv",
    );
    set_buf(
        fd,
        libc::SO_SNDBUFFORCE,
        libc::SO_SNDBUF,
        want,
        label,
        "send",
    );
    if tracing::enabled!(tracing::Level::DEBUG) {
        let (r, s) = effective_sizes(fd);
        debug!(
            label,
            want,
            eff_recv = r,
            eff_send = s,
            "perf: socket buffer applied"
        );
    }
}

/// Time-to-detect a dead SOCKS5 TCP connection (the user-visible "flaky
/// SOCKS5" symptom from Phase R9b live use): the proxy or an upstream
/// NAT silently times out an idle TCP socket, the next write_all
/// quietly buffers data the kernel will never get ACKed, and the
/// upload effectively black-holes until Linux's default RTO_MAX
/// (~120 s) fires. We layer two kernel options on every SOCKS5 socket
/// to bring that detection window down to seconds:
///
/// - `SO_KEEPALIVE = on` + `TCP_KEEPIDLE/INTVL/CNT` — sends probes
///   when idle so a NAT timeout drops the binding instead of just
///   freezing the socket. Probes also act as NAT-keepalive, refreshing
///   the binding so the connection rarely goes stale in the first place.
/// - `TCP_USER_TIMEOUT` — the case the keepalive can't catch: we ARE
///   writing (so the idle timer keeps getting reset), but the bytes
///   aren't being ACKed because the path is silently broken. The kernel
///   aborts the connection after the timeout of un-ACKed data, the next
///   `write_all` returns Err, and our pool marks the slot broken +
///   reconnects. Without this, the kernel retransmits for ~120 s and the
///   application sees nothing wrong.
///
/// ## Two profiles (v2 upload×download matrix)
///
/// The right timer values depend on which of the six upload mechanisms
/// owns the socket:
///
/// - [`Socks5KeepaliveProfile::Bulk`] — the **TCP-SOCKS5** mechanism. A
///   bulk TCP stream is almost always writing, so the keepalive idle
///   timer rarely fires; what matters is a USER_TIMEOUT long enough to
///   ride out a transient bulk-congestion stall without tearing down a
///   healthy-but-slow link (mirrors the 15 s `WRITE_BACKSTOP` on the
///   client driver). Idle 25 s, USER_TIMEOUT 15 s.
/// - [`Socks5KeepaliveProfile::Latency`] — the **ICMP / ICMPv6-SOCKS5**
///   mechanisms (and the historical default). A low-rate trickle leaves
///   the socket idle, so a short idle (10 s, below common CG-NAT idle
///   timeouts) keeps the binding fresh, and a short USER_TIMEOUT (10 s)
///   detects a silently-broken link within seconds. These are the proven
///   pre-matrix values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5KeepaliveProfile {
    /// Bulk TCP stream — TCP-SOCKS5. Longer idle + USER_TIMEOUT.
    Bulk,
    /// Latency-sensitive trickle — ICMP/ICMPv6-SOCKS5. Short timers.
    Latency,
}

struct KeepaliveTimers {
    idle: Duration,
    interval: Duration,
    retries: u32,
    user_timeout: Duration,
}

impl Socks5KeepaliveProfile {
    fn timers(self) -> KeepaliveTimers {
        match self {
            Socks5KeepaliveProfile::Bulk => KeepaliveTimers {
                idle: Duration::from_secs(25),
                interval: Duration::from_secs(5),
                retries: 3,
                user_timeout: Duration::from_secs(15),
            },
            Socks5KeepaliveProfile::Latency => KeepaliveTimers {
                idle: Duration::from_secs(10),
                interval: Duration::from_secs(5),
                retries: 3,
                user_timeout: Duration::from_secs(10),
            },
        }
    }
}

/// Apply the SOCKS5-specific TCP timers documented above to `sock`, using
/// the timer set for `profile`. Safe to call on either side of a SOCKS5
/// hop (Iran client → proxy outbound, or proxy → Remote inbound).
/// `label` shows up in WARN logs only if the kernel rejects a setsockopt
/// — pick something short like `"socks5/client-out"` or
/// `"socks5/remote-in"`.
pub fn tune_socks5_tcp_socket<F: AsFd>(sock: &F, label: &str, profile: Socks5KeepaliveProfile) {
    let r = SockRef::from(sock);
    let t = profile.timers();
    let keepalive = TcpKeepalive::new()
        .with_time(t.idle)
        .with_interval(t.interval)
        .with_retries(t.retries);
    if let Err(e) = r.set_tcp_keepalive(&keepalive) {
        warn!(label, err = %e, "perf: SOCKS5 set_tcp_keepalive failed (continuing)");
    }
    if let Err(e) = r.set_tcp_user_timeout(Some(t.user_timeout)) {
        warn!(label, err = %e, "perf: SOCKS5 set_tcp_user_timeout failed (continuing)");
    }
}

/// Read back the kernel's effective `SO_RCVBUF` / `SO_SNDBUF` for `fd`.
/// The values returned are the kernel's reported "doubled" sizes
/// (Linux returns 2× the requested value to account for skb overhead),
/// which is the right value to compare against `rmem_max` / `wmem_max`.
pub fn effective_sizes(fd: i32) -> (libc::c_int, libc::c_int) {
    (
        getsockopt_int(fd, libc::SO_RCVBUF),
        getsockopt_int(fd, libc::SO_SNDBUF),
    )
}

fn set_buf(
    fd: i32,
    force_opt: i32,
    normal_opt: i32,
    want: libc::c_int,
    label: &str,
    direction: &str,
) {
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is an open socket fd held by the caller for the
    // duration of this call; `want` is a 4-byte int we point at.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            force_opt,
            &want as *const libc::c_int as *const libc::c_void,
            len,
        )
    };
    if rc == 0 {
        return;
    }
    let force_err = std::io::Error::last_os_error();
    // SAFETY: same as above.
    let rc2 = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            normal_opt,
            &want as *const libc::c_int as *const libc::c_void,
            len,
        )
    };
    if rc2 == 0 {
        debug!(
            label, direction, want, force_err = %force_err,
            "perf: *BUFFORCE refused; fell back to non-forced setsockopt (kernel will clamp to rmem_max/wmem_max)"
        );
        return;
    }
    let normal_err = std::io::Error::last_os_error();
    warn!(
        label, direction, want,
        force_err = %force_err,
        normal_err = %normal_err,
        "perf: could not enlarge socket buffer; throughput may be limited"
    );
}

fn getsockopt_int(fd: i32, opt: i32) -> libc::c_int {
    let mut v: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is open for the duration; `v` is a writable 4-byte int.
    let _ = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut v as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn buf_bytes_returns_at_least_the_minimum() {
        // OnceLock means whichever test races first wins; we just
        // assert the floor holds regardless of caching.
        assert!(buf_bytes() >= MIN_BUF_BYTES);
    }

    #[test]
    fn resolve_buf_bytes_default_when_unset() {
        // Direct call to the inner resolver so we don't depend on
        // process-wide env state or the cache.
        let prev = std::env::var(ENV_BUF_BYTES).ok();
        std::env::remove_var(ENV_BUF_BYTES);
        assert_eq!(resolve_buf_bytes(), DEFAULT_BUF_BYTES);
        if let Some(p) = prev {
            std::env::set_var(ENV_BUF_BYTES, p);
        }
    }

    #[test]
    fn resolve_buf_bytes_honors_valid_override() {
        let prev = std::env::var(ENV_BUF_BYTES).ok();
        std::env::set_var(ENV_BUF_BYTES, "8388608"); // 8 MiB
        assert_eq!(resolve_buf_bytes(), 8 * 1024 * 1024);
        if let Some(p) = prev {
            std::env::set_var(ENV_BUF_BYTES, p);
        } else {
            std::env::remove_var(ENV_BUF_BYTES);
        }
    }

    #[test]
    fn resolve_buf_bytes_rejects_below_floor() {
        let prev = std::env::var(ENV_BUF_BYTES).ok();
        std::env::set_var(ENV_BUF_BYTES, "65536"); // 64 KiB — below floor
        assert_eq!(resolve_buf_bytes(), DEFAULT_BUF_BYTES);
        if let Some(p) = prev {
            std::env::set_var(ENV_BUF_BYTES, p);
        } else {
            std::env::remove_var(ENV_BUF_BYTES);
        }
    }

    #[test]
    fn resolve_buf_bytes_rejects_garbage() {
        let prev = std::env::var(ENV_BUF_BYTES).ok();
        std::env::set_var(ENV_BUF_BYTES, "definitely not a number");
        assert_eq!(resolve_buf_bytes(), DEFAULT_BUF_BYTES);
        if let Some(p) = prev {
            std::env::set_var(ENV_BUF_BYTES, p);
        } else {
            std::env::remove_var(ENV_BUF_BYTES);
        }
    }

    #[test]
    fn resolve_batch_defaults_clamps_and_parses() {
        let prev = std::env::var(ENV_RECV_BATCH).ok();
        std::env::remove_var(ENV_RECV_BATCH);
        assert_eq!(resolve_batch(ENV_RECV_BATCH), DEFAULT_BATCH);
        std::env::set_var(ENV_RECV_BATCH, "32");
        assert_eq!(resolve_batch(ENV_RECV_BATCH), 32);
        std::env::set_var(ENV_RECV_BATCH, "999");
        assert_eq!(resolve_batch(ENV_RECV_BATCH), MAX_BATCH);
        std::env::set_var(ENV_RECV_BATCH, "0");
        assert_eq!(resolve_batch(ENV_RECV_BATCH), MIN_BATCH);
        std::env::set_var(ENV_RECV_BATCH, "garbage");
        assert_eq!(resolve_batch(ENV_RECV_BATCH), DEFAULT_BATCH);
        if let Some(p) = prev {
            std::env::set_var(ENV_RECV_BATCH, p);
        } else {
            std::env::remove_var(ENV_RECV_BATCH);
        }
    }

    #[test]
    fn resolve_per_core_sockets_honors_env_or_falls_back() {
        let prev = std::env::var(ENV_PER_CORE_SOCKETS).ok();
        std::env::set_var(ENV_PER_CORE_SOCKETS, "4");
        assert_eq!(resolve_per_core_sockets(), 4);
        std::env::set_var(ENV_PER_CORE_SOCKETS, "0");
        assert_eq!(resolve_per_core_sockets(), MIN_WORKERS);
        std::env::set_var(ENV_PER_CORE_SOCKETS, "garbage");
        // Falls back to available_parallelism — just ensure it's in
        // range and non-zero.
        let n = resolve_per_core_sockets();
        assert!(
            (MIN_WORKERS..=MAX_WORKERS).contains(&n),
            "fallback {n} out of range"
        );
        if let Some(p) = prev {
            std::env::set_var(ENV_PER_CORE_SOCKETS, p);
        } else {
            std::env::remove_var(ENV_PER_CORE_SOCKETS);
        }
    }

    #[test]
    fn tune_loopback_udp_socket_grows_kernel_buffer() {
        // Unprivileged test — *BUFFORCE will be refused, but the
        // fallback SO_RCVBUF / SO_SNDBUF should still raise the buffer
        // above the Ubuntu rmem_max default (208 KiB) since CI runners
        // typically allow up to a few MiB. We assert "noticeably bigger
        // than 64 KiB" rather than an exact value because the kernel
        // applies a 2× multiplier and may clamp at rmem_max.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        tune_socket(&sock, "test/loopback");
        let (r, s) = effective_sizes(sock.as_raw_fd());
        assert!(r >= 128 * 1024, "effective recv buf too small: {r}");
        assert!(s >= 128 * 1024, "effective send buf too small: {s}");
    }

    #[test]
    fn tune_loopback_tcp_socket_grows_kernel_buffer() {
        // v2.2.0: the SOCKS5 substrate sockets are TCP and are now tuned
        // with the same forced-buffer path as every other data-path
        // socket (previously they were the ONLY data-path sockets left on
        // kernel defaults, which capped the SOCKS5 upload's TCP window).
        // Unprivileged here, so *BUFFORCE is refused and we exercise the
        // non-forced fallback; assert the effective buffer still grew
        // well past the ~64 KiB Ubuntu default.
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        tune_socket(&l, "test/loopback-tcp");
        let (r, s) = effective_sizes(l.as_raw_fd());
        assert!(r >= 128 * 1024, "effective recv buf too small: {r}");
        assert!(s >= 128 * 1024, "effective send buf too small: {s}");
    }

    #[test]
    fn resolve_coalesce_bytes_default_clamps_and_parses() {
        let prev = std::env::var(ENV_SOCKS5_COALESCE_BYTES).ok();
        std::env::remove_var(ENV_SOCKS5_COALESCE_BYTES);
        assert_eq!(resolve_coalesce_bytes(), DEFAULT_COALESCE_BYTES);
        std::env::set_var(ENV_SOCKS5_COALESCE_BYTES, "1048576"); // 1 MiB
        assert_eq!(resolve_coalesce_bytes(), 1024 * 1024);
        // Below floor → clamped up to the floor.
        std::env::set_var(ENV_SOCKS5_COALESCE_BYTES, "1024");
        assert_eq!(resolve_coalesce_bytes(), MIN_COALESCE_BYTES);
        // Above ceiling → clamped down to the cap.
        std::env::set_var(ENV_SOCKS5_COALESCE_BYTES, "999999999");
        assert_eq!(resolve_coalesce_bytes(), MAX_COALESCE_BYTES);
        // Garbage → default.
        std::env::set_var(ENV_SOCKS5_COALESCE_BYTES, "not-a-number");
        assert_eq!(resolve_coalesce_bytes(), DEFAULT_COALESCE_BYTES);
        if let Some(p) = prev {
            std::env::set_var(ENV_SOCKS5_COALESCE_BYTES, p);
        } else {
            std::env::remove_var(ENV_SOCKS5_COALESCE_BYTES);
        }
    }

    #[test]
    fn resolve_socks5_stripe_defaults_on_and_honors_off() {
        let prev = std::env::var(ENV_SOCKS5_STRIPE).ok();
        std::env::remove_var(ENV_SOCKS5_STRIPE);
        assert!(resolve_socks5_stripe(), "default must be ON");
        for off in ["0", "false", "OFF", "No", " off "] {
            std::env::set_var(ENV_SOCKS5_STRIPE, off);
            assert!(!resolve_socks5_stripe(), "{off:?} must disable striping");
        }
        for on in ["1", "true", "yes", "anything"] {
            std::env::set_var(ENV_SOCKS5_STRIPE, on);
            assert!(resolve_socks5_stripe(), "{on:?} must enable striping");
        }
        if let Some(p) = prev {
            std::env::set_var(ENV_SOCKS5_STRIPE, p);
        } else {
            std::env::remove_var(ENV_SOCKS5_STRIPE);
        }
    }
}
