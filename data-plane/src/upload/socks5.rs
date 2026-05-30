//! SOCKS5 upload transport — N parallel connections, decoupled writers.
//!
//! The operator's real-world setup is a SOCKS5 proxy that load-balances
//! across N Starlink uplinks: each new TCP connection to the proxy lands
//! on a different link, so opening N connections in parallel uses N
//! links concurrently. Per-session sticky routing keeps each end-user
//! UDP flow on one connection so the Remote sees that flow in order.
//!
//! ## Why the writer is decoupled from the recv loop (the stability fix)
//!
//! The upload listener (`tunnel/client.rs::spawn_upload_task`) is a
//! single task that, for every datagram, used to `await` the upload
//! transport's `send()` inline. For the WireGuard transport that is a
//! non-blocking `send_to`, so it was fine. For SOCKS5-over-TCP it was
//! the dominant cause of the user-visible "stalls then limps / sometimes
//! won't connect" symptom: a single congested Starlink link fills its
//! TCP send buffer, `write_all` blocks, and because it was awaited inline
//! the **whole tunnel's** recv loop froze — no `recv_from` ran, the
//! kernel UDP listener queue overflowed, and packets for *every* session
//! were dropped, not just the flow on the bad link. The old 1.5 s
//! write-timeout then tore down the healthy-but-congested connection and
//! triggered a reconnect storm.
//!
//! The fix: each pool slot owns a **bounded mpsc queue** drained by a
//! dedicated **driver task** that holds the `TcpStream` and is the only
//! thing that writes to it, reconnects it, or closes it. The hot-path
//! `send()` becomes a non-blocking `try_send` onto the target slot's
//! queue (rehashing to a healthy sibling when the primary is unhealthy
//! or its queue is full, dropping only when the whole pool is saturated —
//! UDP best-effort). The recv loop therefore never blocks on a TCP
//! write, one slow link can never stall good flows, and congestion
//! degrades gracefully (localized drops) instead of freezing the tunnel.
//!
//! Dead-peer detection is left to the kernel: `TCP_USER_TIMEOUT` (10 s)
//! plus keepalive (see `perf::tune_socks5_tcp_socket`) make a stuck
//! `write_all` return `Err` within seconds, which the driver turns into
//! a reconnect. A generous [`WRITE_BACKSTOP`] only guards the
//! pathological case where the kernel timer could not be set.
//!
//! ## Wire framing
//!
//! SOCKS5 carries TCP, not UDP. The proxy is a passthrough — anything we
//! write on the socket arrives at the Remote in order. So we re-segment
//! ourselves:
//!
//! ```text
//! [u16 BE length][payload bytes] ... repeat per UDP packet
//! ```
//!
//! The matching Remote-side decoder lives in `tunnel/remote.rs` and is
//! gated by `upload_listen_mode = Socks5Tcp` on the spec.
//!
//! ## RFC 1928 cheat sheet (just the bits we implement)
//!
//! 1. Greeting (C → S): `[0x05][nmethods][methods...]` — we send
//!    `[0x05, 0x02, 0x00, 0x02]` (no-auth + user/pass), or
//!    `[0x05, 0x01, 0x00]` when the operator didn't configure auth.
//! 2. Method selection (S → C): `[0x05][selected_method]`.
//! 3. (Conditional) user/pass auth subnegotiation per RFC 1929:
//!    `[0x01][ulen][user][plen][pass]` → `[0x01][status]`.
//! 4. CONNECT request (C → S):
//!    `[0x05][0x01][0x00][atyp][addr][u16 port_be]`. We use
//!    `atyp=0x01` (IPv4) or `0x04` (IPv6); never DNS (`0x03`) — the
//!    Go side already resolved the upload target to a literal IP.
//! 5. Reply (S → C):
//!    `[0x05][rep][0x00][atyp][addr][u16 port_be]`. `rep == 0x00`
//!    means success; any other value is a hard failure and we close
//!    the connection.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::spec::Socks5Target;

use super::{SessionKey, Socks5Profile, UploadTransport, WriteStrategy};

// ---- Sublyne tuning constants ------------------------------------------

/// How long the SOCKS5 handshake + TCP connect may take before a slot's
/// connect attempt is abandoned and retried under backoff. Generous
/// against a slow proxy hop yet short enough that a dead link doesn't
/// hang a reconnect for minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time `connect()` waits for `min_ready_slots` of the pool to
/// become healthy before failing Start with a clear "pool warm-up
/// failed" error. The single Start gate — every slot is non-fatal, so a
/// slow first link can't fail Start as long as `min_ready_slots`
/// eventually come up within this window.
const WARMUP_DEADLINE: Duration = Duration::from_secs(5);

/// Poll cadence inside the warm-up loop. Cheap; the driver tasks do the
/// real connect work concurrently.
const WARMUP_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Exponential backoff base + cap for a slot driver's reconnect loop.
/// After K consecutive failures the driver waits
/// `min(BACKOFF_BASE * 2^K, BACKOFF_CAP)` before retrying.
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(8);

/// Per-slot bounded send-queue depth, in frames. Deep enough to absorb
/// scheduler jitter between the single recv loop and a driver task, yet
/// shallow enough to bound added latency / memory: at a ~1400-byte MTU
/// this is ≈ 0.7 MiB of buffering per connection. When a slot's queue is
/// full the hot path rehashes to a sibling (or drops) instead of
/// blocking — that is the graceful-degradation backpressure point that
/// replaces the old recv-loop freeze.
const SLOT_QUEUE_CAP: usize = 512;

// The soft cap on how many bytes the `WriteStrategy::Coalesce` drain
// accumulates into a single `write_all` is no longer a hard-coded
// constant: it is the operator-tunable `crate::perf::socks5_coalesce_bytes()`
// (default 256 KiB, raised from the historical 64 KiB; env
// `SUBLYNE_SOCKS5_COALESCE_BYTES`). The whole point of coalescing is to
// fill TCP segments for the bulk TCP-SOCKS5 mechanism; a bigger cap means
// fewer `write()` syscalls per MB under burst, while the soft cap still
// bounds the transient per-slot buffer (a single oversized frame is still
// written whole). The cap is read once per slot driver below.

/// Backstop write timeout. Primary dead-peer detection is the kernel's
/// `TCP_USER_TIMEOUT` (10 s) + keepalive layered in
/// `perf::tune_socks5_tcp_socket`; this only guards the pathological
/// case where that setsockopt was refused. It is deliberately far larger
/// than the old 1.5 s value so a merely-congested-but-alive link is NOT
/// torn down — a write that blocks here for 15 s means the link can't
/// even drain the 4 MiB kernel send buffer, i.e. it is effectively dead
/// and rotating onto a fresh proxy connection is the right move.
const WRITE_BACKSTOP: Duration = Duration::from_secs(15);

/// RAII guard that force-clears a slot's `healthy` flag on drop.
///
/// The driver task sets `healthy = true` only while it holds a live,
/// handshaked stream and is actively draining it. If the driver ever
/// leaves that state — a normal `break`/`return`, an early exit, OR a
/// panic unwinding through the task — this guard's `Drop` runs and
/// clears the flag. Without it, a driver that exited or panicked while
/// `healthy == true` would strand the flag set forever, so the sticky
/// hash would keep steering a session into a slot whose driver is gone
/// and silently black-hole its traffic.
///
/// The driver flips the flag back on (via [`HealthGuard::set_healthy`])
/// every time it re-establishes a connection, and off again the instant
/// a write fails, so the steady-state cost is one relaxed atomic store
/// per connect/teardown — the guard only matters on the exit/panic
/// paths the explicit stores can't cover.
struct HealthGuard {
    healthy: Arc<AtomicBool>,
}

impl HealthGuard {
    fn new(healthy: Arc<AtomicBool>) -> Self {
        Self { healthy }
    }

    /// Mark the slot healthy (a fresh stream is live).
    fn set_healthy(&self) {
        self.healthy.store(true, Ordering::Release);
    }

    /// Mark the slot unhealthy (reconnecting / backing off).
    fn set_unhealthy(&self) {
        self.healthy.store(false, Ordering::Release);
    }
}

impl Drop for HealthGuard {
    fn drop(&mut self) {
        // Belt-and-suspenders: whatever path the driver leaves by —
        // return, break-then-loop-exit, or a panic — the slot ends up
        // unhealthy so the hot path stops routing to a dead driver.
        self.healthy.store(false, Ordering::Release);
    }
}

/// Compute the reconnect backoff for `consecutive_failures`. Exposed as
/// a free function so the curve is easy to unit-test.
fn backoff_for_failures(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.min(5);
    let base_ms = BACKOFF_BASE.as_millis() as u64;
    let candidate = base_ms.saturating_mul(1u64 << shift);
    let capped = candidate.min(BACKOFF_CAP.as_millis() as u64);
    Duration::from_millis(capped)
}

/// SOCKS5 upload-path transport with a live pool of N TCP connections to
/// one proxy. The proxy is itself a load-balancer across multiple
/// Starlink uplinks; each new TCP connection lands on a different link,
/// so the pool genuinely uses N links concurrently.
pub struct Socks5Upload {
    tunnel_id: i64,
    target: Socks5Target,
    upload_target: SocketAddr,
    /// Tuning derived from the download transport (v2 matrix): the write
    /// strategy (coalesce for TCP-SOCKS5, per-frame for ICMP-SOCKS5) and
    /// the kernel keepalive profile. Copied into every slot driver so a
    /// `resize_pool` grow uses the same regime as the initial pool.
    profile: Socks5Profile,
    /// The pool. Reads clone the inner `Vec<Arc<Slot>>` and release the
    /// lock immediately so the hot path never holds it across an await.
    /// Writes happen only on `resize_pool` / `shutdown`.
    slots: Arc<RwLock<Vec<Arc<Slot>>>>,
    /// Tunnel stop watch — propagated to each driver task so they wind
    /// down cleanly on `StopTunnel`.
    stop_rx: watch::Receiver<bool>,
    /// Count of frames dropped because the whole pool was saturated /
    /// unhealthy. Sampled into the log to avoid per-packet spam.
    drops: Arc<AtomicU64>,
}

/// One slot in the pool. The hot path only ever touches `tx` (a
/// non-blocking `try_send`) and `healthy` (a lock-free flag); everything
/// stream-related lives inside the slot's driver task.
struct Slot {
    /// Bounded queue feeding this slot's driver task. Each item is a
    /// fully framed `[u16 BE len][payload]` buffer ready to write.
    tx: mpsc::Sender<Vec<u8>>,
    /// `true` once the driver holds a live, handshaked connection;
    /// flipped to `false` the instant a write fails or a reconnect
    /// starts, so the hot path stops routing to a dead link immediately.
    healthy: Arc<AtomicBool>,
    /// Liveness latch. The driver task holds the paired
    /// [`watch::Receiver`] and selects on it in EVERY phase (connect,
    /// backoff, drain). When this slot leaves the pool (shrink /
    /// `shutdown` / warm-up failure) the `Slot` drops, this sender
    /// drops, and the driver's `changed()` resolves `Err`, so the driver
    /// exits promptly from any phase — not only when it next polls the
    /// queue. Without it a driver stuck retrying a dead proxy during
    /// `connect()` warm-up (where no tunnel stop signal is ever sent)
    /// would reconnect forever after Start already returned an error.
    ///
    /// Held purely for its `Drop` (an RAII liveness latch) — never read,
    /// so `dead_code` is explicitly allowed on it.
    #[allow(dead_code)]
    _alive: watch::Sender<bool>,
}

impl Socks5Upload {
    /// Build the pool: spawn one driver task per slot, then block until
    /// `min_ready_slots` are healthy or [`WARMUP_DEADLINE`] elapses. On
    /// timeout the whole transport is torn down and Start fails with a
    /// panel-readable error rather than handing back a limp tunnel.
    pub async fn connect(
        tunnel_id: i64,
        target: Socks5Target,
        upload_target: SocketAddr,
        profile: Socks5Profile,
        stop_rx: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        let n = target.parallel_connections.max(1) as usize;
        let min_ready = (target.min_ready_slots.max(1) as usize).min(n);

        let mut slots = Vec::with_capacity(n);
        for idx in 0..n {
            slots.push(make_slot(
                tunnel_id,
                target.clone(),
                upload_target,
                idx,
                profile,
                stop_rx.clone(),
            ));
        }

        let upload = Self {
            tunnel_id,
            target,
            upload_target,
            profile,
            slots: Arc::new(RwLock::new(slots)),
            stop_rx,
            drops: Arc::new(AtomicU64::new(0)),
        };

        // ---- Warm-up gate ------------------------------------------
        //
        // "pool reports ready with broken slots" was the dominant cause
        // of "WG client connects then immediately stalls". Block until
        // at least `min_ready` slots are healthy or the deadline fires.
        let deadline = Instant::now() + WARMUP_DEADLINE;
        loop {
            let healthy = upload.healthy_count();
            if healthy >= min_ready {
                info!(
                    tunnel_id,
                    healthy, min_ready, "client: SOCKS5 pool warm-up gate passed"
                );
                break;
            }
            if Instant::now() >= deadline {
                let total = upload.pool_snapshot().len();
                upload.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "SOCKS5 pool warm-up failed: only {healthy}/{total} slots healthy after {ms}ms (min_ready_slots={min_ready})",
                        ms = WARMUP_DEADLINE.as_millis() as u64
                    ),
                ));
            }
            sleep(WARMUP_POLL_INTERVAL).await;
        }

        Ok(upload)
    }

    /// Snapshot of the current pool. Cheap — clones the per-slot `Arc`s
    /// and releases the outer `RwLock` before any await.
    fn pool_snapshot(&self) -> Vec<Arc<Slot>> {
        self.slots.read().expect("slots read").clone()
    }

    /// How many slots currently hold a healthy connection (lock-free).
    fn healthy_count(&self) -> usize {
        self.slots
            .read()
            .expect("slots read")
            .iter()
            .filter(|s| s.healthy.load(Ordering::Acquire))
            .count()
    }

    /// Sampled drop accounting: bump the counter and log roughly once
    /// per 1000 drops so a saturated pool is visible without flooding
    /// the rotating app log on the hot path.
    fn record_drop(&self) {
        let prev = self.drops.fetch_add(1, Ordering::Relaxed);
        if prev % 1000 == 0 {
            warn!(
                tunnel_id = self.tunnel_id,
                dropped_total = prev + 1,
                "client: SOCKS5 upload dropping frames (every slot saturated or unhealthy)"
            );
        }
    }

    /// Resize the pool to `new_n` slots. Returns `Ok(true)` if the live
    /// pool changed size, `Ok(false)` if it was already `new_n`.
    pub async fn resize_pool(&self, new_n: usize) -> io::Result<bool> {
        let new_n = new_n.max(1);
        let current_n = self.slots.read().expect("slots read").len();
        if current_n == new_n {
            return Ok(false);
        }
        if new_n > current_n {
            // GROW: spawn fresh driver tasks for the new slots and append
            // them under a brief write lock. New slots come online live —
            // the hot path's next snapshot picks them up.
            let mut additions = Vec::with_capacity(new_n - current_n);
            for idx in current_n..new_n {
                additions.push(make_slot(
                    self.tunnel_id,
                    self.target.clone(),
                    self.upload_target,
                    idx,
                    self.profile,
                    self.stop_rx.clone(),
                ));
            }
            {
                let mut guard = self.slots.write().expect("slots write");
                guard.extend(additions);
            }
            info!(
                tunnel_id = self.tunnel_id,
                from = current_n,
                to = new_n,
                "client: SOCKS5 pool grown live"
            );
        } else {
            // SHRINK: drop the surplus slot `Arc`s. Each dropped `Slot`
            // releases its `tx`; once the last reference to it goes (any
            // in-flight `send` snapshot finishes), the driver's
            // `rx.recv()` returns `None`, it shuts its stream and exits.
            let removed: Vec<Arc<Slot>> = {
                let mut guard = self.slots.write().expect("slots write");
                guard.drain(new_n..).collect()
            };
            drop(removed);
            info!(
                tunnel_id = self.tunnel_id,
                from = current_n,
                to = new_n,
                "client: SOCKS5 pool shrunk live"
            );
        }
        Ok(true)
    }

    /// Current pool size — used by tests to assert post-resize state.
    #[cfg(test)]
    pub fn pool_len(&self) -> usize {
        self.slots.read().expect("slots read").len()
    }

    /// Total frames dropped due to a saturated/unhealthy pool — test hook.
    #[cfg(test)]
    pub fn drop_count(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }
}

/// Create a slot: a bounded queue, a shared health flag, and a spawned
/// driver task that owns the connection. Returns the `Arc<Slot>` the
/// pool holds; the driver keeps only the `Receiver` + health flag, so it
/// exits once the slot is dropped (queue closed) or the stop watch fires.
fn make_slot(
    tunnel_id: i64,
    target: Socks5Target,
    upload_target: SocketAddr,
    index: usize,
    profile: Socks5Profile,
    stop_rx: watch::Receiver<bool>,
) -> Arc<Slot> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(SLOT_QUEUE_CAP);
    let healthy = Arc::new(AtomicBool::new(false));
    let (alive_tx, alive_rx) = watch::channel(true);
    tokio::spawn(slot_driver(
        tunnel_id,
        target,
        upload_target,
        index,
        profile,
        rx,
        healthy.clone(),
        stop_rx,
        alive_rx,
    ));
    Arc::new(Slot {
        tx,
        healthy,
        _alive: alive_tx,
    })
}

/// Coalesce the just-received `first` frame with any frames ALREADY
/// waiting in `rx`, concatenating their bytes into one buffer until it
/// reaches `cap` (a soft cap — a frame that crosses the boundary is still
/// appended whole) or the queue drains. `try_recv` never blocks, so this
/// only pulls frames that are already queued and adds no latency of its
/// own; it just lets a bulk burst go out in one `write_all` so TCP
/// segments fill and the per-MB `write()` syscall count drops. The frames
/// are already `[u16 len][payload]`, so concatenating them is exactly the
/// byte stream the Remote's `read_exact` decoder expects.
///
/// Pulled out of `slot_driver` as a free function so the coalescing ratio
/// (writes per MB as a function of `cap`) is unit-testable without a live
/// TCP connection.
fn coalesce_drain(first: Vec<u8>, rx: &mut mpsc::Receiver<Vec<u8>>, cap: usize) -> Vec<u8> {
    let mut buf = first;
    while buf.len() < cap {
        match rx.try_recv() {
            Ok(more) => buf.extend_from_slice(&more),
            Err(_) => break,
        }
    }
    buf
}

/// One slot's lifecycle: connect (with backoff on failure), drain framed
/// payloads to the TCP stream, and reconnect on write error — forever,
/// until the queue closes (slot removed) or the stop watch fires.
#[allow(clippy::too_many_arguments)]
async fn slot_driver(
    tunnel_id: i64,
    target: Socks5Target,
    upload_target: SocketAddr,
    index: usize,
    profile: Socks5Profile,
    mut rx: mpsc::Receiver<Vec<u8>>,
    healthy: Arc<AtomicBool>,
    mut stop_rx: watch::Receiver<bool>,
    mut alive_rx: watch::Receiver<bool>,
) {
    // Mark the initial liveness value seen so `changed()` only ever
    // fires on sender-drop (slot removal), never spuriously on the first
    // poll. If the slot was already removed before the driver started,
    // the first `changed()` in a select returns `Err` and we exit.
    let _ = alive_rx.borrow_and_update();
    // RAII guard owning the health flag. Its `Drop` force-clears
    // `healthy` no matter how this task leaves — `return`, the loop
    // ending, or a panic — so a dead/exited/panicked driver can never
    // strand `healthy == true` and keep the hot path routing into a
    // black hole. `consecutive_failures > 0` and every error path below
    // call `health.set_unhealthy()` for promptness; the guard is the
    // backstop the explicit stores can't reach.
    let health = HealthGuard::new(healthy);
    let mut consecutive_failures: u32 = 0;
    // Operator-tunable bulk-coalesce soft cap (default 256 KiB), read once
    // per driver. Only consulted on the `WriteStrategy::Coalesce` path.
    let coalesce_cap = crate::perf::socks5_coalesce_bytes();
    loop {
        if *stop_rx.borrow() {
            return;
        }
        // Back off before a retry (not before the very first attempt).
        if consecutive_failures > 0 {
            health.set_unhealthy();
            let wait = backoff_for_failures(consecutive_failures);
            tokio::select! {
                biased;
                _ = stop_rx.changed() => { if *stop_rx.borrow() { return; } }
                _ = alive_rx.changed() => return,
                _ = sleep(wait) => {}
            }
            if *stop_rx.borrow() {
                return;
            }
        }

        // Connect + SOCKS5 handshake.
        let connect_fut = timeout(
            CONNECT_TIMEOUT,
            open_socks5_connection(tunnel_id, &target, upload_target, index, profile),
        );
        let mut stream = tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    return;
                }
                // Non-stop wakeup of the stop watch (it was marked
                // changed but is still `false`): re-enter the connect
                // loop, but count it as a failed attempt so backoff
                // accounting still advances. A bare `continue` here
                // would skip the backoff bookkeeping and let a flapping
                // proxy / spurious wakeup drive a tight reconnect storm.
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
            _ = alive_rx.changed() => return,
            res = connect_fut => match res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    warn!(
                        tunnel_id, slot = index, err = %e, consecutive_failures,
                        "client: SOCKS5 slot connect failed; will retry under backoff"
                    );
                    continue;
                }
                Err(_elapsed) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    warn!(
                        tunnel_id, slot = index,
                        timeout_ms = CONNECT_TIMEOUT.as_millis() as u64, consecutive_failures,
                        "client: SOCKS5 slot connect timed out; will retry under backoff"
                    );
                    continue;
                }
            }
        };

        consecutive_failures = 0;
        health.set_healthy();
        info!(
            tunnel_id,
            slot = index,
            "client: SOCKS5 slot connected (healthy)"
        );

        // Drain framed payloads until a write error, a closed queue, or
        // stop. `biased` checks stop first so shutdown is prompt.
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
                _ = alive_rx.changed() => {
                    let _ = stream.shutdown().await;
                    return;
                }
                maybe = rx.recv() => {
                    let first = match maybe {
                        Some(f) => f,
                        None => {
                            // Slot removed (pool shrunk / shutdown): no
                            // more senders. Close the stream and exit.
                            let _ = stream.shutdown().await;
                            return;
                        }
                    };
                    // Build the write buffer. For the bulk TCP-SOCKS5
                    // mechanism (Coalesce) we greedily drain whatever else
                    // is already queued and write it all in ONE `write_all`
                    // so TCP segments fill — real byte-stream semantics
                    // over the SOCKS5 hop. The frames are already
                    // `[u16 len][payload]`, so concatenating them is the
                    // exact wire the Remote's `read_exact` decoder expects.
                    // For the latency mechanisms (PerFrame) we write the
                    // single frame straight through so a trickle isn't held
                    // back. `try_recv` never blocks, so coalescing only
                    // pulls frames that are ALREADY waiting — it adds no
                    // latency of its own.
                    let writebuf = match profile.write {
                        WriteStrategy::PerFrame => first,
                        WriteStrategy::Coalesce => coalesce_drain(first, &mut rx, coalesce_cap),
                    };
                    // A write error OR a backstop timeout is treated as a
                    // FATAL stream error. `write_all` may have already put
                    // PART of `writebuf` on the wire before failing or
                    // being cancelled at the backstop, which leaves the
                    // framed `[u16 len][payload]` byte stream misaligned —
                    // the Remote's length-prefixed decoder would parse
                    // garbage from there on. So we never write another
                    // frame to this stream: mark unhealthy, abandon it,
                    // and `break` to reconnect. A brand-new TCP stream
                    // always starts frame-aligned, so a half-written frame
                    // can never be followed by the next frame on the same
                    // stream.
                    match timeout(WRITE_BACKSTOP, stream.write_all(&writebuf)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            health.set_unhealthy();
                            warn!(
                                tunnel_id, slot = index, err = %e,
                                "client: SOCKS5 slot write failed (stream desynced); reconnecting"
                            );
                            // Abandon the possibly half-written stream;
                            // ignore shutdown errors — it's being dropped.
                            let _ = stream.shutdown().await;
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            break;
                        }
                        Err(_elapsed) => {
                            health.set_unhealthy();
                            warn!(
                                tunnel_id, slot = index,
                                backstop_s = WRITE_BACKSTOP.as_secs(),
                                "client: SOCKS5 slot write backstop elapsed (link cannot drain, stream desynced); reconnecting"
                            );
                            // The backstop cancelled `write_all` mid-frame:
                            // this stream is desynced and must not carry
                            // another frame. Drop it and reconnect fresh.
                            let _ = stream.shutdown().await;
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            break;
                        }
                    }
                }
            }
        }
        // Fell out of the drain loop on a write failure → loop back to
        // the top, which backs off (consecutive_failures == 1) then
        // reconnects. Frames already queued stay buffered for the new
        // connection (up to SLOT_QUEUE_CAP); the hot path meanwhile sees
        // `healthy == false` and routes new frames to a sibling.
    }
}

/// Pick the primary slot for a session by hashing `(client_addr,
/// local_port)` modulo the pool size. Pure function so tests can pin
/// determinism (same key + same N → same index).
fn primary_slot(session: SessionKey, n: usize) -> usize {
    debug_assert!(n > 0, "primary_slot called with empty pool");
    let mut h = DefaultHasher::new();
    session.hash(&mut h);
    (h.finish() as usize) % n
}

#[async_trait]
impl UploadTransport for Socks5Upload {
    async fn send(&self, session: SessionKey, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            // Frame length cap. At MTU 1400 we'll never get close.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socks5 frame too large: {} bytes", payload.len()),
            ));
        }
        // Build the framed buffer once: [u16 BE len][payload].
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);

        // Snapshot the pool ONCE so a concurrent resize can't change the
        // index space mid-probe. Arc clones are cheap and the outer lock
        // is released immediately.
        let slots = self.pool_snapshot();
        let n = slots.len();
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "socks5 pool is empty",
            ));
        }
        let primary = primary_slot(session, n);

        // Try the sticky primary, then linear-probe healthy siblings.
        // `try_send` never blocks — the recv loop keeps reading no matter
        // how congested any single link is. On a full queue the frame is
        // handed back to us so we can try the next slot without a realloc.
        for offset in 0..n {
            let idx = (primary + offset) % n;
            let slot = &slots[idx];
            if !slot.healthy.load(Ordering::Acquire) {
                continue;
            }
            match slot.tx.try_send(frame) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    frame = returned;
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    frame = returned;
                    continue;
                }
            }
        }

        // Every slot was unhealthy or its queue full. Drop (UDP is
        // best-effort; the application/WireGuard will retransmit) and
        // account it. Returning Ok keeps the recv loop hot — the drop is
        // surfaced via the sampled counter, not a per-packet error.
        self.record_drop();
        Ok(())
    }

    async fn set_parallel_connections(&self, n: u32) -> io::Result<bool> {
        self.resize_pool(n as usize).await
    }

    async fn shutdown(&self) {
        // Drop every slot. That releases all `tx` senders, so each driver
        // task observes its queue closing (or the stop watch) and exits,
        // closing its TCP stream. Belt-and-suspenders with the tunnel's
        // stop watch, which the drivers also honour.
        let removed: Vec<Arc<Slot>> = {
            let mut guard = self.slots.write().expect("slots write");
            guard.drain(..).collect()
        };
        drop(removed);
    }
}

/// Open one TCP connection to the proxy and complete the SOCKS5 CONNECT
/// handshake. Returns a TCP stream ready to carry framed payloads.
/// `slot_index` is for log correlation only.
async fn open_socks5_connection(
    tunnel_id: i64,
    target: &Socks5Target,
    upload_target: SocketAddr,
    slot_index: usize,
    profile: Socks5Profile,
) -> io::Result<TcpStream> {
    let proxy_addr = format!("{}:{}", target.host, target.port);
    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("connect to SOCKS5 proxy {proxy_addr}: {e}"),
        )
    })?;
    // Nagle policy follows the mechanism's write strategy (v2 matrix):
    //
    // - PerFrame (ICMP/ICMPv6-SOCKS5): disable Nagle so each small UDP
    //   payload goes on the wire promptly — on a real Starlink link the
    //   ~40 ms TCP coalescing delay would add visible latency to a trickle.
    // - Coalesce (TCP-SOCKS5): leave Nagle ON. The driver already batches
    //   queued frames into one `write_all`, and Nagle then lets the kernel
    //   pack the bulk stream into full segments instead of emitting a
    //   small segment per wake-up — real TCP byte-stream behaviour.
    let want_nodelay = matches!(profile.write, WriteStrategy::PerFrame);
    if let Err(e) = stream.set_nodelay(want_nodelay) {
        warn!(tunnel_id, slot = slot_index, err = %e,
            "client: SOCKS5 set_nodelay failed (continuing)");
    }
    // Layer TCP keepalive + USER_TIMEOUT on the socket (timers from the
    // mechanism's keepalive profile) so a stale proxy / NAT binding is
    // noticed within seconds instead of hanging on the kernel default RTO
    // (~120 s). This is the PRIMARY dead-peer detector now that the
    // application no longer tears down a connection on a short write
    // timeout — see `perf::tune_socks5_tcp_socket`.
    crate::perf::tune_socks5_tcp_socket(&stream, "socks5/client-out", profile.keepalive);
    // v2.2.0: force-size the send/receive buffers on the SOCKS5 upload
    // socket exactly like every other data-path socket. Before this, the
    // SOCKS5 TCP sockets were the only data-path sockets left on kernel
    // defaults, so the upload's in-flight window could not open on a
    // high-bandwidth × high-RTT path (the "TCP RWIN" ceiling). With
    // CAP_NET_ADMIN the *BUFFORCE path pins the full size immediately so
    // the bulk upload window is available from the first byte rather than
    // waiting on TCP autotuning to ramp.
    crate::perf::tune_socket(&stream, "socks5/client-out");
    let has_auth = target.username.as_deref().is_some_and(|s| !s.is_empty())
        && target.password.as_deref().is_some_and(|s| !s.is_empty());
    handshake_greeting(&mut stream, has_auth).await?;
    if has_auth {
        handshake_auth(
            &mut stream,
            target.username.as_deref().unwrap_or(""),
            target.password.as_deref().unwrap_or(""),
        )
        .await?;
    }
    handshake_connect(&mut stream, upload_target).await?;
    info!(
        tunnel_id,
        slot = slot_index,
        proxy = %proxy_addr,
        target = %upload_target,
        auth = has_auth,
        "client: SOCKS5 CONNECT established"
    );
    Ok(stream)
}

/// Send the greeting and consume the server's method selection.
/// Methods we advertise:
///
/// - `0x00` (NO AUTHENTICATION REQUIRED) — always offered.
/// - `0x02` (USERNAME/PASSWORD) — offered iff `has_auth`.
///
/// The server picks one. We accept whichever fits our config; a
/// mismatch is a hard error.
async fn handshake_greeting(stream: &mut TcpStream, has_auth: bool) -> io::Result<()> {
    // Build greeting:  [VER=5][NMETHODS=1|2][METHODS...]
    let greeting: &[u8] = if has_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5 greeting: unexpected version 0x{:02x}", reply[0]),
        ));
    }
    match reply[1] {
        0x00 => Ok(()), // no-auth accepted
        0x02 if has_auth => Ok(()),
        0xff => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 proxy refused every offered auth method",
        )),
        m => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5 proxy selected unexpected method 0x{m:02x}"),
        )),
    }
}

/// RFC 1929 user/pass subnegotiation. Only used when the greeting
/// landed on method 0x02.
async fn handshake_auth(stream: &mut TcpStream, user: &str, pass: &str) -> io::Result<()> {
    if user.len() > 255 || pass.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 auth: username/password exceeds 255 bytes",
        ));
    }
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01); // VER for the auth subnegotiation
    msg.push(user.len() as u8);
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    stream.write_all(&msg).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5 auth: bad subnegotiation version 0x{:02x}", reply[0]),
        ));
    }
    if reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 auth: credentials rejected",
        ));
    }
    Ok(())
}

/// CONNECT request to `target`, plus reply parsing. We only ever ask
/// for `atyp=0x01` (IPv4) or `0x04` (IPv6); the Go side resolves
/// hostnames before save so the dataplane never sends `atyp=0x03`.
async fn handshake_connect(stream: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
    let mut req = Vec::with_capacity(22);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV
    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;

    // Reply: [VER=5][REP][RSV=0][ATYP][BND.ADDR][BND.PORT].
    // BND.ADDR length depends on ATYP — read the fixed prefix first,
    // then drain the address bytes.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5 connect reply: unexpected version 0x{:02x}", head[0]),
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 CONNECT refused with code 0x{:02x}", head[1]),
        ));
    }
    let atyp = head[3];
    let bnd_addr_len: usize = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            // Domain reply — read the length byte first, then domain.
            // We never request this, but a quirky proxy might still
            // return it. Drain so the stream stays aligned.
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            len_buf[0] as usize
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("socks5 connect reply: unexpected ATYP 0x{other:02x}"),
            ));
        }
    };
    // Drain the bound address + port, then we're ready for framed
    // payload traffic.
    let mut scratch = vec![0u8; bnd_addr_len + 2];
    stream.read_exact(&mut scratch).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    /// Per-test capture types. The framing tests want to inspect the
    /// payloads each TCP connection saw, so each connection writes into
    /// its own bag of `Vec<u8>` payloads; the outer Vec collects every
    /// connection's bag. Behind tokio mutexes so the stub server tasks
    /// and the test body can read/write without deadlocking on std::sync
    /// across awaits.
    type ConnFrameBag = Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>;
    type FramesPerConn = Arc<tokio::sync::Mutex<Vec<ConnFrameBag>>>;

    /// Tiny SOCKS5 server that accepts no-auth or user/pass plus a
    /// CONNECT, replies success, then drains the rest of the connection.
    /// Accepts any number of incoming connections (each on a fresh tokio
    /// task) and bumps `accepted` for the test to assert on.
    async fn run_stub_socks5_pool(
        listener: TcpListener,
        require_auth: Option<(&'static str, &'static str)>,
        accepted: Arc<AtomicUsize>,
    ) {
        loop {
            let (client, _addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_one_socks5(client, require_auth));
        }
    }

    async fn serve_one_socks5(
        mut client: tokio::net::TcpStream,
        require_auth: Option<(&'static str, &'static str)>,
    ) {
        // Greeting
        let mut head = [0u8; 2];
        if client.read_exact(&mut head).await.is_err() {
            return;
        }
        let n_methods = head[1] as usize;
        let mut methods = vec![0u8; n_methods];
        if client.read_exact(&mut methods).await.is_err() {
            return;
        }
        let want_method: u8 = if require_auth.is_some() { 0x02 } else { 0x00 };
        if !methods.contains(&want_method) {
            let _ = client.write_all(&[0x05, 0xff]).await;
            return;
        }
        if client.write_all(&[0x05, want_method]).await.is_err() {
            return;
        }
        if let Some((u, p)) = require_auth {
            let mut hdr = [0u8; 2];
            if client.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let mut user = vec![0u8; hdr[1] as usize];
            if client.read_exact(&mut user).await.is_err() {
                return;
            }
            let mut plen = [0u8; 1];
            if client.read_exact(&mut plen).await.is_err() {
                return;
            }
            let mut pass = vec![0u8; plen[0] as usize];
            if client.read_exact(&mut pass).await.is_err() {
                return;
            }
            let ok = user == u.as_bytes() && pass == p.as_bytes();
            let status = if ok { 0x00 } else { 0x01 };
            let _ = client.write_all(&[0x01, status]).await;
            if !ok {
                return;
            }
        }
        // CONNECT request: read header + atyp + addr + port.
        let mut req_head = [0u8; 4];
        if client.read_exact(&mut req_head).await.is_err() {
            return;
        }
        let atyp = req_head[3];
        let addr_len = match atyp {
            0x01 => 4,
            0x04 => 16,
            _ => return,
        };
        let mut addr = vec![0u8; addr_len + 2];
        if client.read_exact(&mut addr).await.is_err() {
            return;
        }
        // Accept; reply with 0.0.0.0:0 as the bound addr.
        if client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .is_err()
        {
            return;
        }
        // Drain framed traffic until EOF so the client can keep writing
        // without TCP backpressure stalling its write_all.
        let mut scratch = [0u8; 4096];
        loop {
            match client.read(&mut scratch).await {
                Ok(0) => return,
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    }

    fn make_target(port: u16, parallel: u32) -> Socks5Target {
        Socks5Target {
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            parallel_connections: parallel,
            // Tests rely on a stub SOCKS5 server that accepts every
            // connection; the warm-up gate only needs one healthy slot
            // to immediately pass, so the test pool never blocks here.
            min_ready_slots: 1,
        }
    }

    fn make_target_with_auth(port: u16, parallel: u32, user: &str, pass: &str) -> Socks5Target {
        Socks5Target {
            host: "127.0.0.1".into(),
            port,
            username: Some(user.into()),
            password: Some(pass.into()),
            parallel_connections: parallel,
            min_ready_slots: 1,
        }
    }

    fn dummy_target() -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 5201)
    }

    /// The latency regime (per-frame flush + short keepalive) — the
    /// historical pre-matrix behaviour and the default most tests want.
    fn latency_profile() -> Socks5Profile {
        Socks5Profile {
            write: WriteStrategy::PerFrame,
            keepalive: crate::perf::Socks5KeepaliveProfile::Latency,
        }
    }

    /// The bulk regime (coalesced writes + long keepalive) — the
    /// TCP-SOCKS5 mechanism.
    fn bulk_profile() -> Socks5Profile {
        Socks5Profile {
            write: WriteStrategy::Coalesce,
            keepalive: crate::perf::Socks5KeepaliveProfile::Bulk,
        }
    }

    fn key(client: SocketAddr) -> SessionKey {
        SessionKey {
            client_addr: client,
            local_port: 33333,
        }
    }

    /// Wait until at least `want` slots report healthy, or panic after a
    /// generous deadline. Replaces fixed sleeps so the async driver tasks
    /// have deterministically connected before assertions run.
    async fn await_healthy(upload: &Socks5Upload, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if upload.healthy_count() >= want {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "only {}/{} slots became healthy in time",
                    upload.healthy_count(),
                    want
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll until the stub captured at least `want` frames across all
    /// connections, or panic after a deadline — a deterministic
    /// alternative to a fixed sleep so the assertion never races the
    /// driver tasks on a loaded CI runner.
    async fn await_total_frames(frames: &FramesPerConn, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let total: usize = {
                let outer = frames.lock().await;
                let mut sum = 0usize;
                for bag in outer.iter() {
                    sum += bag.lock().await.len();
                }
                sum
            };
            if total >= want {
                return;
            }
            if Instant::now() >= deadline {
                panic!("only {total}/{want} frames captured in time");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn backoff_grows_then_caps() {
        // Curve: 500, 1000, 2000, 4000, 8000, then capped.
        assert_eq!(backoff_for_failures(0), Duration::from_millis(500));
        assert_eq!(backoff_for_failures(1), Duration::from_millis(1000));
        assert_eq!(backoff_for_failures(2), Duration::from_millis(2000));
        assert_eq!(backoff_for_failures(3), Duration::from_millis(4000));
        assert_eq!(backoff_for_failures(4), Duration::from_millis(8000));
        // Cap holds for any larger failure count.
        assert_eq!(backoff_for_failures(5), Duration::from_millis(8000));
        assert_eq!(backoff_for_failures(99), Duration::from_millis(8000));
    }

    #[test]
    fn coalesce_drain_cuts_writes_per_mb_with_a_bigger_cap() {
        // The point of the v2.2.0 coalesce-cap bump: under a bursty
        // producer, a bigger cap drains more queued frames into each
        // write_all, so the number of writes (≈ write() syscalls / TCP
        // segments) per MB drops. This is the deterministic, runner-
        // independent half of "measurably faster" — counted, not timed.
        fn writes_for(frame_len: usize, n_frames: usize, cap: usize) -> (usize, usize) {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(n_frames + 1);
            for _ in 0..n_frames {
                tx.try_send(vec![0u8; frame_len]).expect("prefill queue");
            }
            drop(tx);
            let mut writes = 0usize;
            let mut bytes = 0usize;
            while let Ok(first) = rx.try_recv() {
                let buf = coalesce_drain(first, &mut rx, cap);
                bytes += buf.len();
                writes += 1;
            }
            (writes, bytes)
        }
        let frame = 1400; // ~MTU-sized framed payload
        let n = 2000; // ~2.8 MB of bulk
        let (small_writes, small_bytes) = writes_for(frame, n, 64 * 1024); // historical cap
        let (big_writes, big_bytes) = writes_for(frame, n, 256 * 1024); // v2.2.0 default
        // No frame is ever dropped — both move the full byte count.
        assert_eq!(small_bytes, n * frame);
        assert_eq!(big_bytes, n * frame);
        // 4× the cap ⇒ ~4× fewer writes; assert a conservative ≥3×.
        assert!(
            small_writes >= 3 * big_writes,
            "expected the bigger coalesce cap to cut writes/MB ≥3×: small={small_writes} big={big_writes}"
        );
    }

    #[test]
    fn health_guard_clears_healthy_on_drop() {
        // The guard's whole job is finding [36]: whenever a slot driver
        // leaves its connected state — including via an unwinding panic —
        // the shared `healthy` flag must end up `false` so the hot path
        // stops routing into a dead/exited driver.
        let healthy = Arc::new(AtomicBool::new(false));
        {
            let guard = HealthGuard::new(healthy.clone());
            guard.set_healthy();
            assert!(
                healthy.load(Ordering::Acquire),
                "set_healthy should mark the slot live"
            );
            guard.set_unhealthy();
            assert!(
                !healthy.load(Ordering::Acquire),
                "set_unhealthy should clear the flag"
            );
            // Re-arm to healthy, then let the guard drop while "live".
            guard.set_healthy();
            assert!(healthy.load(Ordering::Acquire));
        }
        // Guard dropped (the analogue of the driver task returning or
        // panicking): the flag must be forced back to false.
        assert!(
            !healthy.load(Ordering::Acquire),
            "dropping the guard must clear healthy even when it was true"
        );
    }

    #[test]
    fn health_guard_clears_healthy_on_panic_unwind() {
        // A panic inside the driver must not strand `healthy == true`.
        // Simulate it: hold the guard healthy, then unwind through its
        // scope via `catch_unwind`. Drop still runs during unwind, so the
        // flag must be observed false afterwards.
        let healthy = Arc::new(AtomicBool::new(false));
        let probe = healthy.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = HealthGuard::new(probe);
            guard.set_healthy();
            panic!("driver task blew up while healthy");
        }));
        assert!(result.is_err(), "the closure should have panicked");
        assert!(
            !healthy.load(Ordering::Acquire),
            "panic unwind through HealthGuard must clear healthy"
        );
    }

    #[tokio::test]
    async fn warmup_gate_fails_when_proxy_is_dead() {
        // Bind a TCP listener and *immediately drop it* so every
        // outbound connect lands on a port with no listener. The warm-up
        // gate should bubble up an io::Error rather than returning a
        // half-built pool.
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = proxy.local_addr().unwrap().port();
        drop(proxy);

        let (_stop_tx, stop_rx) = watch::channel(false);
        let mut tgt = make_target(port, 2);
        tgt.min_ready_slots = 2;
        let res = Socks5Upload::connect(99, tgt, dummy_target(), latency_profile(), stop_rx).await;
        assert!(res.is_err(), "expected dead proxy to fail connect()");
    }

    #[test]
    fn primary_slot_is_deterministic() {
        // Same key + same N → same slot, always.
        let k = key("10.0.0.1:60000".parse().unwrap());
        for _ in 0..32 {
            assert_eq!(primary_slot(k, 8), primary_slot(k, 8));
        }
    }

    #[test]
    fn primary_slot_spreads_across_pool() {
        // Hash many distinct client addrs into a pool of 8; we should hit
        // every slot at least once. (Not a uniformity test — just a "no
        // degenerate all-one-slot" smoke test on DefaultHasher.)
        let mut seen: HashSet<usize> = HashSet::new();
        for i in 0..1024 {
            let addr: SocketAddr = format!("10.0.{}.{}:60000", (i / 256) & 0xff, i & 0xff)
                .parse()
                .unwrap();
            seen.insert(primary_slot(key(addr), 8));
        }
        assert_eq!(
            seen.len(),
            8,
            "expected hash to reach every slot, got {:?}",
            seen
        );
    }

    /// Pool of 4 against one shared stub; assert that the drivers opened
    /// exactly 4 inbound connections and that `pool_len()` reports 4.
    #[tokio::test]
    async fn pool_opens_n_connections() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            1,
            make_target(proxy_port, 4),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect pool");

        await_healthy(&upload, 4).await;
        assert_eq!(upload.pool_len(), 4);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "expected 4 inbound TCP connections to the proxy"
        );
        upload.shutdown().await;
    }

    /// Per-session sticky routing: consecutive sends from the same
    /// SessionKey must land on the same connection on the proxy side.
    #[tokio::test]
    async fn sticky_routing_keeps_flow_on_one_connection() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();

        let frames_per_conn: FramesPerConn = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let frames_for_stub = frames_per_conn.clone();
        tokio::spawn(async move {
            loop {
                let (client, _) = match proxy.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let bag: ConnFrameBag = Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
                {
                    let mut outer = frames_for_stub.lock().await;
                    outer.push(bag.clone());
                }
                tokio::spawn(serve_one_socks5_and_capture(client, None, bag));
            }
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            7,
            make_target(proxy_port, 4),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 4).await;
        assert_eq!(upload.pool_len(), 4);

        let key_a = key("10.1.1.1:50001".parse().unwrap());
        let key_b = key("10.1.1.2:50001".parse().unwrap());
        upload.send(key_a, b"a-1").await.expect("send a-1");
        upload.send(key_a, b"a-2").await.expect("send a-2");
        upload.send(key_a, b"a-3").await.expect("send a-3");
        upload.send(key_b, b"b-1").await.expect("send b-1");

        // Wait deterministically for all four frames to land on the stub.
        await_total_frames(&frames_per_conn, 4).await;

        let conns = frames_per_conn.lock().await;
        assert_eq!(conns.len(), 4, "expected 4 connections");
        let mut a_conn_idx: Option<usize> = None;
        for (i, conn) in conns.iter().enumerate() {
            let payloads = conn.lock().await;
            let a_count = payloads.iter().filter(|p| p.starts_with(b"a-")).count();
            if a_count == 3 {
                a_conn_idx = Some(i);
                assert!(
                    payloads.iter().any(|p| p == b"a-1"),
                    "sticky conn missing a-1"
                );
                assert!(
                    payloads.iter().any(|p| p == b"a-2"),
                    "sticky conn missing a-2"
                );
                assert!(
                    payloads.iter().any(|p| p == b"a-3"),
                    "sticky conn missing a-3"
                );
            } else {
                assert!(
                    a_count == 0,
                    "expected all 'a-*' frames on one conn; conn[{}] has {}",
                    i,
                    a_count
                );
            }
        }
        assert!(
            a_conn_idx.is_some(),
            "no single connection carried all of session A's frames"
        );

        upload.shutdown().await;
    }

    /// Re-hash on slot unhealth: force the slot a session hashes to
    /// unhealthy; the next send must still be delivered (rehashed to a
    /// healthy sibling, NOT dropped).
    #[tokio::test]
    async fn rehash_on_unhealthy_slot_keeps_flow_alive() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            3,
            make_target(proxy_port, 4),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 4).await;
        let session = key("10.2.2.2:50002".parse().unwrap());

        // First send establishes which slot the session is sticky to.
        upload.send(session, b"first").await.expect("send first");

        // Force the sticky slot unhealthy so the hot path must rehash.
        let primary_idx = primary_slot(session, upload.pool_len());
        upload.pool_snapshot()[primary_idx]
            .healthy
            .store(false, Ordering::SeqCst);

        // Next send must rehash to a healthy sibling and NOT be dropped.
        upload
            .send(session, b"after-break")
            .await
            .expect("send after-break");
        assert_eq!(
            upload.drop_count(),
            0,
            "frame should have rehashed to a healthy slot, not dropped"
        );
        upload.shutdown().await;
    }

    /// When the entire pool is unhealthy, sends drop (best-effort) and
    /// the drop counter advances — but the call still returns Ok so the
    /// recv loop is never blocked or errored per-packet.
    #[tokio::test]
    async fn all_unhealthy_drops_without_blocking() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            8,
            make_target(proxy_port, 3),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 3).await;

        // Force every slot unhealthy.
        for slot in upload.pool_snapshot() {
            slot.healthy.store(false, Ordering::SeqCst);
        }
        let session = key("10.5.5.5:50005".parse().unwrap());
        upload.send(session, b"into-the-void").await.expect("ok");
        assert!(
            upload.drop_count() >= 1,
            "expected the frame to be counted as dropped"
        );
        upload.shutdown().await;
    }

    /// Live pool grow: connect with N=2, resize to N=4, assert both the
    /// local pool_len and the proxy's inbound connection count reach 4.
    #[tokio::test]
    async fn resize_grow_opens_extra_connections() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            11,
            make_target(proxy_port, 2),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 2).await;
        assert_eq!(upload.pool_len(), 2);

        let changed = upload.set_parallel_connections(4).await.expect("resize");
        assert!(changed, "resize from 2->4 should report changed=true");
        await_healthy(&upload, 4).await;
        assert_eq!(upload.pool_len(), 4);
        assert_eq!(accepted.load(Ordering::SeqCst), 4);

        // No-op resize returns false.
        let again = upload
            .set_parallel_connections(4)
            .await
            .expect("noop resize");
        assert!(!again, "no-op resize must report changed=false");

        upload.shutdown().await;
    }

    /// Live pool shrink: connect with N=4, resize to N=2, assert pool_len
    /// drops and that subsequent sends still succeed.
    #[tokio::test]
    async fn resize_shrink_drops_surplus_slots() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            12,
            make_target(proxy_port, 4),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 4).await;
        assert_eq!(upload.pool_len(), 4);

        let changed = upload.set_parallel_connections(2).await.expect("shrink");
        assert!(changed);
        assert_eq!(upload.pool_len(), 2);
        await_healthy(&upload, 2).await;

        // Hash several sessions over the smaller pool; they should all
        // be accepted (not dropped).
        for i in 0..6 {
            let addr: SocketAddr = format!("10.3.{}.1:50003", i).parse().unwrap();
            upload
                .send(key(addr), b"after-shrink")
                .await
                .expect("post-shrink send");
        }
        assert_eq!(upload.drop_count(), 0, "post-shrink sends must not drop");
        upload.shutdown().await;
    }

    /// Auth path still works with N>1.
    #[tokio::test]
    async fn pool_with_auth_opens_n_connections() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, Some(("alice", "s3cret")), stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            13,
            make_target_with_auth(proxy_port, 3, "alice", "s3cret"),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect with auth");
        await_healthy(&upload, 3).await;
        assert_eq!(upload.pool_len(), 3);
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
        let session = key("10.4.4.4:50004".parse().unwrap());
        upload.send(session, b"authed pool").await.expect("send");
        upload.shutdown().await;
    }

    /// Framing across N connections: send into each of the 4 connections
    /// and verify the `[u16 BE length][bytes]` layout arrives intact on
    /// the wire (the stub captures bytes and the test parses them back).
    #[tokio::test]
    async fn framing_intact_across_n_connections() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();

        let frames_per_conn: FramesPerConn = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let frames_for_stub = frames_per_conn.clone();
        tokio::spawn(async move {
            loop {
                let (client, _) = match proxy.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let bag: ConnFrameBag = Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
                {
                    let mut outer = frames_for_stub.lock().await;
                    outer.push(bag.clone());
                }
                tokio::spawn(serve_one_socks5_and_capture(client, None, bag));
            }
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            14,
            make_target(proxy_port, 4),
            dummy_target(),
            latency_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 4).await;

        // Send many distinct payloads with distinct keys so they spread
        // across the pool.
        for i in 0..32u8 {
            let addr: SocketAddr = format!("10.9.{}.{}:50005", i, i).parse().unwrap();
            let payload = vec![i; (i as usize) + 1];
            upload.send(key(addr), &payload).await.expect("send");
        }
        assert_eq!(upload.drop_count(), 0, "no frame should have been dropped");
        await_total_frames(&frames_per_conn, 32).await;

        // Every byte recovered from every connection's frame stream must
        // match a payload we sent.
        let conns = frames_per_conn.lock().await;
        let mut all: Vec<Vec<u8>> = Vec::new();
        for conn in conns.iter() {
            let payloads = conn.lock().await;
            all.extend(payloads.iter().cloned());
        }
        assert_eq!(all.len(), 32, "expected to receive 32 frames total");
        let mut firsts: Vec<u8> = all.iter().map(|p| p[0]).collect();
        firsts.sort_unstable();
        firsts.dedup();
        assert_eq!(firsts.len(), 32, "got duplicates or missing payloads");
        upload.shutdown().await;
    }

    /// Coalesced (bulk / TCP-SOCKS5) writes must preserve framing. A
    /// single-slot pool on the Coalesce profile concatenates queued
    /// `[u16 len][payload]` frames into one `write_all`; the Remote-style
    /// capture stub decodes them back frame-by-frame, so every payload
    /// must reappear intact and in order regardless of how many were
    /// batched into a syscall. This is the test that proves the
    /// TCP-SOCKS5 "real byte stream" optimisation doesn't corrupt the
    /// length-delimited wire.
    #[tokio::test]
    async fn coalesced_writes_preserve_framing() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();

        let frames_per_conn: FramesPerConn = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let frames_for_stub = frames_per_conn.clone();
        tokio::spawn(async move {
            loop {
                let (client, _) = match proxy.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let bag: ConnFrameBag = Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
                {
                    let mut outer = frames_for_stub.lock().await;
                    outer.push(bag.clone());
                }
                tokio::spawn(serve_one_socks5_and_capture(client, None, bag));
            }
        });

        // Single slot + the bulk (Coalesce) profile so every frame from
        // the one sticky session funnels through the same driver and is
        // eligible to be batched into a shared write_all.
        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(
            20,
            make_target(proxy_port, 1),
            dummy_target(),
            bulk_profile(),
            stop_rx,
        )
        .await
        .expect("connect");
        await_healthy(&upload, 1).await;

        // Fire 64 distinct payloads on ONE session key as fast as the
        // try_send accepts them; many will be queued and coalesced.
        let session = key("10.7.7.7:50007".parse().unwrap());
        for i in 0..64u16 {
            let payload = i.to_be_bytes().to_vec(); // 2 distinct bytes each
            upload.send(session, &payload).await.expect("send");
        }
        assert_eq!(upload.drop_count(), 0, "coalesced sends must not drop");
        await_total_frames(&frames_per_conn, 64).await;

        let conns = frames_per_conn.lock().await;
        let mut all: Vec<Vec<u8>> = Vec::new();
        for conn in conns.iter() {
            all.extend(conn.lock().await.iter().cloned());
        }
        assert_eq!(all.len(), 64, "expected exactly 64 decoded frames");
        // Every frame must be a clean 2-byte value, and the full set
        // 0..64 must be present — proves no frame was split, merged, or
        // dropped by the coalescing drain.
        let mut seen: Vec<u16> = all
            .iter()
            .map(|p| {
                assert_eq!(p.len(), 2, "coalescing corrupted a frame boundary: {p:?}");
                u16::from_be_bytes([p[0], p[1]])
            })
            .collect();
        seen.sort_unstable();
        let want: Vec<u16> = (0..64).collect();
        assert_eq!(seen, want, "missing or duplicated frames after coalescing");
        upload.shutdown().await;
    }

    /// Stub server that captures decoded `[u16 BE][bytes]` frames into
    /// `bag`. Used by the sticky-routing and framing tests.
    async fn serve_one_socks5_and_capture(
        mut client: tokio::net::TcpStream,
        require_auth: Option<(&'static str, &'static str)>,
        bag: ConnFrameBag,
    ) {
        // Greeting
        let mut head = [0u8; 2];
        if client.read_exact(&mut head).await.is_err() {
            return;
        }
        let n_methods = head[1] as usize;
        let mut methods = vec![0u8; n_methods];
        if client.read_exact(&mut methods).await.is_err() {
            return;
        }
        let want_method: u8 = if require_auth.is_some() { 0x02 } else { 0x00 };
        if !methods.contains(&want_method) {
            let _ = client.write_all(&[0x05, 0xff]).await;
            return;
        }
        if client.write_all(&[0x05, want_method]).await.is_err() {
            return;
        }
        if let Some((u, p)) = require_auth {
            let mut hdr = [0u8; 2];
            if client.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let mut user = vec![0u8; hdr[1] as usize];
            if client.read_exact(&mut user).await.is_err() {
                return;
            }
            let mut plen = [0u8; 1];
            if client.read_exact(&mut plen).await.is_err() {
                return;
            }
            let mut pass = vec![0u8; plen[0] as usize];
            if client.read_exact(&mut pass).await.is_err() {
                return;
            }
            let ok = user == u.as_bytes() && pass == p.as_bytes();
            let status = if ok { 0x00 } else { 0x01 };
            let _ = client.write_all(&[0x01, status]).await;
            if !ok {
                return;
            }
        }
        // CONNECT request: read header + atyp + addr + port.
        let mut req_head = [0u8; 4];
        if client.read_exact(&mut req_head).await.is_err() {
            return;
        }
        let atyp = req_head[3];
        let addr_len = match atyp {
            0x01 => 4,
            0x04 => 16,
            _ => return,
        };
        let mut addr = vec![0u8; addr_len + 2];
        if client.read_exact(&mut addr).await.is_err() {
            return;
        }
        if client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .is_err()
        {
            return;
        }
        // Decode framed payload stream into the bag.
        let mut len_buf = [0u8; 2];
        loop {
            if client.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; n];
            if client.read_exact(&mut payload).await.is_err() {
                return;
            }
            let mut g = bag.lock().await;
            g.push(payload);
        }
    }
}
