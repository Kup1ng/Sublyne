//! SOCKS5 upload transport — Phase R9b (N parallel connections).
//!
//! Round 2 introduces SOCKS5 as an alternative upload path. The
//! operator's real-world setup is a SOCKS5 proxy that load-balances
//! across N Starlink uplinks: each new TCP connection to the proxy
//! lands on a different link, so opening N connections in parallel
//! uses N links concurrently. R9a built the single-connection
//! foundation; **R9b grows the pool to N** with per-session sticky
//! routing, rehash-on-failure, background reconnect, and a live
//! resize hook driven by the manager's hot-reload path.
//!
//! ## R9b scope (this module)
//!
//! - Pool of **N** TCP connections to `(target.host, target.port)`,
//!   each completing the SOCKS5 greeting + (optional) username/password
//!   subnegotiation + CONNECT to the Remote's `upload_target_addr`.
//! - **Per-session sticky** routing: hash
//!   `(client_addr, local_port) → slot_index ∈ [0, N)`. All packets
//!   from one end-user flow go through the same TCP connection so the
//!   Remote sees them in order.
//! - On a write failure: mark the slot broken, kick off a background
//!   reconnect that retries with backoff, and let the very-next send
//!   for that session **rehash to the next healthy slot** so no flow
//!   permanently dies because one Starlink link blipped.
//! - **Live resize** of the pool via [`Socks5Upload::resize_pool`]
//!   (wired through the [`super::UploadTransport`] trait so the
//!   manager's `UpdateTunnel` path can call it without coupling to the
//!   concrete type). Growing opens additional connections; shrinking
//!   simply drops the surplus slot `Arc`s — outstanding sends keep the
//!   underlying connection alive until they finish.
//! - **`[u16 BE length][payload bytes]`** framing on every connection,
//!   identical to R9a. The Remote-side decoder in `tunnel/remote.rs`
//!   accepts multiple concurrent inbound TCP connections (R9a spawned
//!   one task per `accept`), so it scales naturally to N.
//!
//! ## Wire framing
//!
//! SOCKS5 carries TCP, not UDP. The proxy is a passthrough — anything
//! we write on the socket arrives at the Remote in order. So we
//! re-segment ourselves:
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
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex, Notify};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::spec::Socks5Target;

use super::{SessionKey, UploadTransport};

// ---- Sublyne hardening constants ---------------------------------------
//
// The numbers are tuned against the user-visible symptoms reported on the
// predecessor's live tunnel — "WG client takes 10 s to connect / stalls
// then limps" with `upload_mode=socks5`. The three failure modes the
// constants address are documented next to each value.

/// How long we'll wait for the SOCKS5 handshake + TCP connect before
/// declaring a slot dead and parking it. Generous against a slow proxy
/// hop yet short enough that a truly dead Starlink link doesn't hang the
/// tunnel start for minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a single write_all to a slot is allowed to take before we
/// abort it, mark the slot broken, and rehash the session to a healthy
/// sibling. Picks an envelope wider than typical Starlink RTT (~100 ms)
/// but shorter than the kernel's silent-stall default. Without this an
/// idle proxy NAT binding that the kernel keepalive missed would let a
/// write_all park forever on the awaiting ACK.
const WRITE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Maximum time `connect()` waits for `min_ready_slots` of the pool to
/// complete their SOCKS5 handshake before bouncing Start with a clear
/// "pool warm-up failed" error. Set generously — a slow Starlink first
/// connect can take a couple of seconds — but short enough that an
/// honestly broken proxy fails fast.
const WARMUP_DEADLINE: Duration = Duration::from_secs(5);

/// Poll cadence inside the warm-up loop. Cheap; the loop is asleep most
/// of the time and the workers are doing the real work.
const WARMUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Exponential backoff base for the reconnect worker and the slot-park
/// cooldown. After K consecutive failures the slot is parked for
/// `min(BACKOFF_BASE * 2^K, BACKOFF_CAP)`.
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(8);

/// Compute the parking / reconnect backoff for `consecutive_failures`.
/// Exposed as a free function so it's easy to unit-test the curve.
fn backoff_for_failures(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.min(5);
    let base_ms = BACKOFF_BASE.as_millis() as u64;
    let candidate = base_ms.saturating_mul(1u64 << shift);
    let capped = candidate.min(BACKOFF_CAP.as_millis() as u64);
    Duration::from_millis(capped)
}

/// SOCKS5 upload-path transport with a live pool of N TCP connections
/// to one proxy. The proxy is itself a load-balancer across multiple
/// Starlink uplinks; each new TCP connection lands on a different link,
/// so the pool genuinely uses N links concurrently.
pub struct Socks5Upload {
    tunnel_id: i64,
    target: Socks5Target,
    upload_target: SocketAddr,
    /// The pool. Reads are cheap (clone the inner `Vec<Arc<Slot>>` and
    /// release the lock immediately so awaits don't hold it). Writes
    /// happen only on `resize_pool`. The inner `Vec` itself is owned by
    /// the `RwLock`; slot `Arc`s live as long as someone holds a
    /// reference, so a `resize_pool` that shrinks the pool doesn't
    /// yank a connection out from under an in-flight `send`.
    slots: Arc<RwLock<Vec<Arc<Slot>>>>,
    /// Snapshot of the tunnel's stop watch so background reconnect
    /// tasks abandon cleanly on shutdown.
    stop_rx: watch::Receiver<bool>,
}

/// One slot in the pool. Holds the TCP stream (when healthy) and a
/// `Notify` the background reconnect task waits on to gate retry
/// attempts. The slot mutex serialises concurrent writes from the hot
/// path AND any reconnect-install: a `send` that's mid-write will
/// finish before a reconnect can replace the stream, and vice versa.
struct Slot {
    /// Stable per-tunnel index for log lines and tests. Doesn't
    /// influence routing — the hash does.
    index: usize,
    /// `Some(stream)` = live TCP+SOCKS5-handshake'd connection.
    /// `None` = slot is broken; the background reconnect task is
    /// either already trying to fix it or about to. Either way, the
    /// hot path skips this slot and probes the next one.
    state: Mutex<SlotState>,
    /// Background reconnect task is parked on this until the next
    /// `notify_one()` call. The hot path nudges it when it detects a
    /// broken slot; the task also wakes itself on its own backoff
    /// timer if no one nudged.
    reconnect_kick: Notify,
}

struct SlotState {
    stream: Option<TcpStream>,
    /// True when a background reconnect task is in flight for this
    /// slot. Prevents a burst of write failures from spawning N
    /// duplicate reconnect tasks all racing on the same proxy.
    reconnecting: bool,
    /// Sublyne hardening: number of consecutive failures (handshake
    /// failures during reconnect or write failures during the hot
    /// path). Resets to 0 on the next successful reconnect or write.
    consecutive_failures: u32,
    /// When `Some(t)`, this slot is "parked" until `t` and the hot
    /// path skips it without holding the mutex. Parked slots are still
    /// woken by the background reconnect task which honours the same
    /// deadline. Cleared on successful reconnect.
    parked_until: Option<Instant>,
}

impl Socks5Upload {
    /// Open N connections (where N = `target.parallel_connections`),
    /// complete the SOCKS5 CONNECT handshake on each, and return a
    /// ready-to-use upload transport. If the **first** connection
    /// fails the call bubbles back to the manager as `io::Error` so
    /// Start surfaces a clear panel message ("could not reach SOCKS5
    /// proxy"). Subsequent connection failures during initial pool
    /// fill are logged and leave a hole that the background reconnect
    /// task fills in.
    pub async fn connect(
        tunnel_id: i64,
        target: Socks5Target,
        upload_target: SocketAddr,
        stop_rx: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        let n = target.parallel_connections.max(1) as usize;
        let min_ready = (target.min_ready_slots.max(1) as usize).min(n);
        let mut initial_slots: Vec<Arc<Slot>> = Vec::with_capacity(n);

        // Open the FIRST connection inline so an unreachable proxy
        // fails Start with a real error. Subsequent connection failures
        // during pool fill are non-fatal: we install the slot in a
        // broken state and let the background reconnect task heal it.
        let first_stream = timeout(
            CONNECT_TIMEOUT,
            open_socks5_connection(tunnel_id, &target, upload_target, 0),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "first SOCKS5 connect to {}:{} timed out",
                    target.host, target.port
                ),
            )
        })??;
        initial_slots.push(Arc::new(Slot::healthy(0, first_stream)));

        for idx in 1..n {
            match timeout(
                CONNECT_TIMEOUT,
                open_socks5_connection(tunnel_id, &target, upload_target, idx),
            )
            .await
            {
                Ok(Ok(stream)) => initial_slots.push(Arc::new(Slot::healthy(idx, stream))),
                Ok(Err(e)) => {
                    warn!(
                        tunnel_id,
                        slot = idx,
                        err = %e,
                        "client: SOCKS5 initial pool fill connection failed; slot will reconnect in background"
                    );
                    initial_slots.push(Arc::new(Slot::broken(idx)));
                }
                Err(_) => {
                    warn!(
                        tunnel_id,
                        slot = idx,
                        timeout_ms = CONNECT_TIMEOUT.as_millis() as u64,
                        "client: SOCKS5 initial pool fill timed out; slot will reconnect in background"
                    );
                    initial_slots.push(Arc::new(Slot::broken(idx)));
                }
            }
        }

        let initial_healthy = initial_slots
            .iter()
            .filter(|s| s.is_healthy_blocking())
            .count();
        info!(
            tunnel_id,
            requested = target.parallel_connections,
            initial_healthy,
            min_ready,
            "client: SOCKS5 initial pool fill complete"
        );

        let upload = Self {
            tunnel_id,
            target,
            upload_target,
            slots: Arc::new(RwLock::new(initial_slots)),
            stop_rx,
        };
        // Spawn one background reconnect task per slot up front. Slots
        // that come online later (via resize) get their own task started
        // in `resize_pool`.
        upload.spawn_reconnect_workers();

        // ---- Warm-up gate ------------------------------------------
        //
        // The predecessor's "pool reports ready with broken slots" was
        // the dominant cause of the user-visible "WG client connects
        // then immediately stalls" symptom. Block here until at least
        // `min_ready` slots are healthy or the deadline fires. If we
        // can't meet the threshold within the deadline, fail Start
        // with a clear panel-readable error rather than handing back a
        // limp tunnel.
        let deadline = Instant::now() + WARMUP_DEADLINE;
        // `initial_healthy` is the "X/N healthy" number we surface in
        // the warm-up failure message; it gets refreshed every loop
        // iteration so the error reflects the latest snapshot.
        let _ = initial_healthy;
        loop {
            let healthy = upload.healthy_slot_count().await;
            if healthy >= min_ready {
                info!(
                    tunnel_id,
                    healthy, min_ready, "client: SOCKS5 pool warm-up gate passed"
                );
                break;
            }
            if Instant::now() >= deadline {
                upload.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "SOCKS5 pool warm-up failed: only {healthy}/{n} slots healthy after {ms}ms (min_ready_slots={min_ready})",
                        ms = WARMUP_DEADLINE.as_millis() as u64
                    ),
                ));
            }
            sleep(WARMUP_POLL_INTERVAL).await;
        }

        Ok(upload)
    }

    /// Snapshot how many pool slots currently hold a healthy stream.
    /// Used by the warm-up gate and by tests asserting pool health.
    async fn healthy_slot_count(&self) -> usize {
        let snap = self.pool_snapshot();
        let mut count = 0usize;
        for slot in &snap {
            let g = slot.state.lock().await;
            if g.stream.is_some() {
                count += 1;
            }
        }
        count
    }

    /// Spawn a background reconnect task for every slot in the current
    /// pool snapshot. Idempotent inside each task — the task observes
    /// `reconnecting` to avoid stepping on itself.
    fn spawn_reconnect_workers(&self) {
        let slot_snapshot = {
            let guard = self.slots.read().expect("slots read");
            guard.clone()
        };
        for slot in slot_snapshot {
            self.spawn_reconnect_worker(slot);
        }
    }

    /// Spawn a single reconnect worker for `slot`. Holds an `Arc` on
    /// the slot so the worker outlives a pool shrink that drops the
    /// outer Vec's reference — when the last `Arc` drops, the worker's
    /// next wake-up will observe the stop watch firing OR the slot
    /// state becoming unobservable and exit.
    fn spawn_reconnect_worker(&self, slot: Arc<Slot>) {
        let tunnel_id = self.tunnel_id;
        let target = self.target.clone();
        let upload_target = self.upload_target;
        let mut stop_rx = self.stop_rx.clone();
        tokio::spawn(async move {
            loop {
                // Wait for someone to kick us (a send hit a broken
                // slot) or for an exponential-backoff timer to elapse
                // on its own.
                let wait = {
                    let g = slot.state.lock().await;
                    match g.parked_until {
                        Some(t) => t
                            .saturating_duration_since(Instant::now())
                            .max(Duration::from_millis(1)),
                        None => backoff_for_failures(g.consecutive_failures),
                    }
                };
                tokio::select! {
                    _ = stop_rx.changed() => return,
                    _ = slot.reconnect_kick.notified() => {}
                    _ = sleep(wait) => {}
                }
                if *stop_rx.borrow() {
                    return;
                }
                // Atomically check + claim the reconnect slot. If the
                // slot is already healthy or another worker is mid-
                // reconnect, just loop back to sleep.
                {
                    let mut guard = slot.state.lock().await;
                    if guard.stream.is_some() {
                        guard.reconnecting = false;
                        continue;
                    }
                    if guard.reconnecting {
                        continue;
                    }
                    // Respect the park deadline if a kick beat the
                    // timer — we don't want to hot-spin reconnects on
                    // a chronically broken slot.
                    if let Some(deadline) = guard.parked_until {
                        if Instant::now() < deadline {
                            continue;
                        }
                    }
                    guard.reconnecting = true;
                }
                // Drop the lock before the (potentially seconds-long)
                // connect+handshake await so a concurrent successful
                // `send` on a different slot doesn't block on us.
                let connect_result = timeout(
                    CONNECT_TIMEOUT,
                    open_socks5_connection(tunnel_id, &target, upload_target, slot.index),
                )
                .await;
                match connect_result {
                    Ok(Ok(stream)) => {
                        let mut guard = slot.state.lock().await;
                        guard.stream = Some(stream);
                        guard.reconnecting = false;
                        guard.consecutive_failures = 0;
                        guard.parked_until = None;
                        info!(
                            tunnel_id,
                            slot = slot.index,
                            "client: SOCKS5 slot reconnected (health reset)"
                        );
                    }
                    Ok(Err(e)) => {
                        let mut guard = slot.state.lock().await;
                        guard.reconnecting = false;
                        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
                        let cooldown = backoff_for_failures(guard.consecutive_failures);
                        guard.parked_until = Some(Instant::now() + cooldown);
                        warn!(
                            tunnel_id,
                            slot = slot.index,
                            err = %e,
                            consecutive_failures = guard.consecutive_failures,
                            park_ms = cooldown.as_millis() as u64,
                            "client: SOCKS5 slot reconnect failed; parked for exponential backoff"
                        );
                    }
                    Err(_elapsed) => {
                        let mut guard = slot.state.lock().await;
                        guard.reconnecting = false;
                        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
                        let cooldown = backoff_for_failures(guard.consecutive_failures);
                        guard.parked_until = Some(Instant::now() + cooldown);
                        warn!(
                            tunnel_id,
                            slot = slot.index,
                            timeout_ms = CONNECT_TIMEOUT.as_millis() as u64,
                            consecutive_failures = guard.consecutive_failures,
                            park_ms = cooldown.as_millis() as u64,
                            "client: SOCKS5 slot reconnect timed out; parked for exponential backoff"
                        );
                    }
                }
            }
        });
    }

    /// Take a snapshot of the current pool. Cheap — clones the
    /// per-slot `Arc`s, not the inner state, and releases the outer
    /// RwLock before any await.
    fn pool_snapshot(&self) -> Vec<Arc<Slot>> {
        let guard = self.slots.read().expect("slots read");
        guard.clone()
    }

    /// Resize the pool to `new_n` slots. Public via the trait method
    /// `set_parallel_connections`. Returns `Ok(true)` if the live
    /// pool was actually resized, `Ok(false)` if it was already at
    /// the requested size.
    pub async fn resize_pool(&self, new_n: usize) -> io::Result<bool> {
        let new_n = new_n.max(1);
        let current_n = self.slots.read().expect("slots read").len();
        if current_n == new_n {
            return Ok(false);
        }
        match new_n.cmp(&current_n) {
            std::cmp::Ordering::Greater => {
                // GROW: open additional connections, then append under
                // a brief write lock. The new slots come online live —
                // the hot path's snapshot picks them up on the next
                // send. We open every new slot SEQUENTIALLY so we
                // don't hammer the proxy with N concurrent SYNs; the
                // operator-edit path is rare and per-connection
                // handshake is ~50ms.
                let mut additions: Vec<Arc<Slot>> = Vec::with_capacity(new_n - current_n);
                for idx in current_n..new_n {
                    let slot = match open_socks5_connection(
                        self.tunnel_id,
                        &self.target,
                        self.upload_target,
                        idx,
                    )
                    .await
                    {
                        Ok(stream) => Arc::new(Slot::healthy(idx, stream)),
                        Err(e) => {
                            warn!(
                                tunnel_id = self.tunnel_id,
                                slot = idx,
                                err = %e,
                                "client: SOCKS5 grow-pool initial connect failed; slot will reconnect in background"
                            );
                            Arc::new(Slot::broken(idx))
                        }
                    };
                    additions.push(slot);
                }
                let new_arcs_for_workers: Vec<Arc<Slot>> = additions.clone();
                {
                    let mut guard = self.slots.write().expect("slots write");
                    guard.extend(additions);
                }
                // Spawn one reconnect worker per freshly-added slot so
                // a slot that came up broken (or fails later) gets
                // healed. Existing slots already have their workers
                // from `connect()`.
                for slot in new_arcs_for_workers {
                    self.spawn_reconnect_worker(slot);
                }
                info!(
                    tunnel_id = self.tunnel_id,
                    from = current_n,
                    to = new_n,
                    "client: SOCKS5 pool grown live"
                );
                Ok(true)
            }
            std::cmp::Ordering::Less => {
                // SHRINK: truncate the live Vec. Outstanding sends
                // that already cloned an Arc for one of the dropped
                // slots keep that slot alive until they finish; the
                // kernel's TCP connection stays open until the last
                // Arc drops. New sends see the smaller pool on their
                // next snapshot and rehash to a surviving slot. UDP
                // semantics tolerate the brief flow-rehoming.
                let removed: Vec<Arc<Slot>> = {
                    let mut guard = self.slots.write().expect("slots write");
                    guard.drain(new_n..).collect()
                };
                // Best-effort: nudge any in-flight reconnect tasks on
                // the dropped slots so they can wake, observe the
                // stream-is-None plus no-one-holding-the-slot-Arc-
                // outside-themselves, and exit cleanly via the stop
                // watch on the next iteration.
                for slot in &removed {
                    slot.reconnect_kick.notify_one();
                }
                // Drain the streams so the kernel closes the FDs
                // promptly even if a reconnect worker is still
                // holding a clone of the slot Arc.
                for slot in &removed {
                    let mut guard = slot.state.lock().await;
                    if let Some(mut stream) = guard.stream.take() {
                        let _ = stream.shutdown().await;
                    }
                }
                info!(
                    tunnel_id = self.tunnel_id,
                    from = current_n,
                    to = new_n,
                    "client: SOCKS5 pool shrunk live"
                );
                Ok(true)
            }
            std::cmp::Ordering::Equal => Ok(false),
        }
    }

    /// Current pool size — used by tests to assert post-resize state.
    #[cfg(test)]
    pub fn pool_len(&self) -> usize {
        self.slots.read().expect("slots read").len()
    }
}

impl Slot {
    fn healthy(index: usize, stream: TcpStream) -> Self {
        Self {
            index,
            state: Mutex::new(SlotState {
                stream: Some(stream),
                reconnecting: false,
                consecutive_failures: 0,
                parked_until: None,
            }),
            reconnect_kick: Notify::new(),
        }
    }

    fn broken(index: usize) -> Self {
        Self {
            index,
            state: Mutex::new(SlotState {
                stream: None,
                reconnecting: false,
                consecutive_failures: 1,
                parked_until: Some(Instant::now() + backoff_for_failures(0)),
            }),
            reconnect_kick: Notify::new(),
        }
    }

    /// Quick health probe that bypasses the async lock when nothing
    /// else is contending. Used at startup logging — the real hot path
    /// always grabs the lock before attempting a write.
    fn is_healthy_blocking(&self) -> bool {
        match self.state.try_lock() {
            Ok(g) => g.stream.is_some(),
            // If the lock is contended someone is mid-send → almost
            // certainly healthy.
            Err(_) => true,
        }
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
        // Build the frame in a stack-allocated header + zero-copy
        // payload slice. tokio's AsyncWriteExt only exposes the single
        // `write_all`/`write_all_vectored` shapes; we want a single
        // syscall per frame so concat into a small Vec.
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);

        // Snapshot the pool ONCE per send so a concurrent resize_pool
        // can never change the index space mid-probe. The Arc clones
        // are cheap; this releases the outer RwLock immediately.
        let slot_arcs = self.pool_snapshot();
        let n = slot_arcs.len();
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "socks5 pool is empty",
            ));
        }
        let primary = primary_slot(session, n);

        // Try the primary slot, then linear-probe through the pool to
        // find the next healthy one. Each probe locks the slot's
        // inner Mutex briefly, tries the write, and on failure marks
        // the slot broken + nudges its reconnect task before falling
        // through to the next slot. Worst case (every slot down) the
        // last probe surfaces a `BrokenPipe` to the caller, which
        // logs and drops the packet — UDP semantics, application
        // retransmits.
        let now = Instant::now();
        let mut last_err: Option<io::Error> = None;
        for offset in 0..n {
            let idx = (primary + offset) % n;
            let slot = &slot_arcs[idx];
            let mut guard = slot.state.lock().await;

            // Skip slots that are parked under exponential-backoff
            // cooldown. The reconnect worker will lift the park when
            // a fresh handshake succeeds; until then the hot path
            // must not keep slamming a known-bad slot.
            if let Some(deadline) = guard.parked_until {
                if now < deadline {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!(
                            "socks5 slot {idx} parked for {}ms",
                            deadline.saturating_duration_since(now).as_millis() as u64
                        ),
                    ));
                    continue;
                }
            }

            if let Some(stream) = guard.stream.as_mut() {
                match timeout(WRITE_TIMEOUT, stream.write_all(&frame)).await {
                    Ok(Ok(())) => {
                        // Successful write resets the failure counter so
                        // a previously parked slot starts each session
                        // fresh again.
                        guard.consecutive_failures = 0;
                        guard.parked_until = None;
                        if offset != 0 {
                            // Hot-path observation: an unhealthy primary
                            // forced a rehash. INFO breadcrumb for live
                            // link blips, only on the rehash path so the
                            // steady-state primary-hit path stays silent.
                            info!(
                                tunnel_id = self.tunnel_id,
                                primary,
                                landed = idx,
                                "client: SOCKS5 send rehashed to alternate slot"
                            );
                        }
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
                        let cooldown = backoff_for_failures(guard.consecutive_failures);
                        guard.parked_until = Some(Instant::now() + cooldown);
                        guard.stream = None;
                        warn!(
                            tunnel_id = self.tunnel_id,
                            slot = idx,
                            err = %e,
                            consecutive_failures = guard.consecutive_failures,
                            park_ms = cooldown.as_millis() as u64,
                            "client: SOCKS5 slot write failed; parked and rehashing"
                        );
                        last_err = Some(e);
                    }
                    Err(_elapsed) => {
                        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
                        let cooldown = backoff_for_failures(guard.consecutive_failures);
                        guard.parked_until = Some(Instant::now() + cooldown);
                        guard.stream = None;
                        warn!(
                            tunnel_id = self.tunnel_id,
                            slot = idx,
                            timeout_ms = WRITE_TIMEOUT.as_millis() as u64,
                            consecutive_failures = guard.consecutive_failures,
                            park_ms = cooldown.as_millis() as u64,
                            "client: SOCKS5 slot write timed out; parked and rehashing"
                        );
                        last_err = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "socks5 slot write_all exceeded WRITE_TIMEOUT",
                        ));
                    }
                }
            }
            drop(guard);
            // Kick the reconnect task on the slot we just gave up on.
            // The task races its own backoff timer with our nudge but
            // will still honour the parked_until deadline before it
            // attempts another handshake.
            slot.reconnect_kick.notify_one();
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "socks5 pool entirely unhealthy")
        }))
    }

    async fn set_parallel_connections(&self, n: u32) -> io::Result<bool> {
        self.resize_pool(n as usize).await
    }

    async fn shutdown(&self) {
        // Drain every slot's TCP stream and drop the Vec so any
        // background reconnect task sees the stop watch on its next
        // wake and exits.
        let drained: Vec<Arc<Slot>> = {
            let mut guard = self.slots.write().expect("slots write");
            guard.drain(..).collect()
        };
        for slot in &drained {
            slot.reconnect_kick.notify_one();
        }
        for slot in drained {
            let mut guard = slot.state.lock().await;
            if let Some(mut stream) = guard.stream.take() {
                // Best-effort shutdown — ignore errors, the kernel
                // cleans up the fd anyway when the stream drops.
                let _ = stream.shutdown().await;
            }
        }
    }
}

/// Open one TCP connection to the proxy and complete the SOCKS5
/// CONNECT handshake. Returns a TCP stream ready to carry framed
/// payloads. `slot_index` is for log correlation only — the kernel
/// picks the source port and the SOCKS5 protocol doesn't carry slot
/// numbers on the wire.
async fn open_socks5_connection(
    tunnel_id: i64,
    target: &Socks5Target,
    upload_target: SocketAddr,
    slot_index: usize,
) -> io::Result<TcpStream> {
    let proxy_addr = format!("{}:{}", target.host, target.port);
    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("connect to SOCKS5 proxy {proxy_addr}: {e}"),
        )
    })?;
    // Disable Nagle so each frame goes on the wire promptly. The
    // proxy passthrough preserves bytes either way, but on a real
    // Starlink link the 40 ms TCP coalescing delay would add visible
    // latency to small UDP payloads.
    if let Err(e) = stream.set_nodelay(true) {
        warn!(tunnel_id, slot = slot_index, err = %e, "client: SOCKS5 set_nodelay failed (continuing)");
    }
    // Layer aggressive TCP keepalive + USER_TIMEOUT on the socket so a
    // stale proxy / NAT binding is noticed within seconds instead of
    // hanging on the kernel default RTO (~120 s). Both options together
    // catch the two failure modes that produced the user-visible "WG
    // client takes 10 s to connect / stalls then limps" symptom on the
    // Phase R9b live tunnel — see `perf::tune_socks5_tcp_socket` for
    // the rationale and the chosen timer values.
    crate::perf::tune_socks5_tcp_socket(&stream, "socks5/client-out");
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
    /// payloads each TCP connection saw, so each connection writes
    /// into its own bag of `Vec<u8>` payloads; the outer Vec collects
    /// every connection's bag. Behind tokio mutexes so the stub server
    /// tasks and the test body can read/write without deadlocking on
    /// std::sync across awaits. Clippy's `type_complexity` lint
    /// otherwise fires on the four-level nested generic.
    type ConnFrameBag = Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>;
    type FramesPerConn = Arc<tokio::sync::Mutex<Vec<ConnFrameBag>>>;

    /// Tiny SOCKS5 server that accepts no-auth or user/pass plus a
    /// CONNECT, replies success, then drains the rest of the connection
    /// (the framed payloads from the client). Just enough RFC
    /// compliance to verify our client's handshake bytes are correct
    /// and that framed sends succeed.
    ///
    /// Accepts any number of incoming connections (each on a fresh
    /// tokio task) and bumps `accepted` for the test to assert on.
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
        // Drain framed traffic until EOF so the client can keep
        // writing without TCP backpressure stalling its write_all.
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

    fn key(client: SocketAddr) -> SessionKey {
        SessionKey {
            client_addr: client,
            local_port: 33333,
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

    #[tokio::test]
    async fn warmup_gate_fails_when_proxy_is_dead() {
        // Bind a TCP listener and *immediately drop it* so every
        // outbound connect lands on a port with no listener. The
        // warm-up gate should bubble up an io::Error rather than
        // returning a half-built pool.
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = proxy.local_addr().unwrap().port();
        drop(proxy);

        let (_stop_tx, stop_rx) = watch::channel(false);
        let mut tgt = make_target(port, 2);
        tgt.min_ready_slots = 2;
        let res = Socks5Upload::connect(99, tgt, dummy_target(), stop_rx).await;
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
        // Hash many distinct client addrs into a pool of 8; we should
        // hit every slot at least once. (Not a uniformity test —
        // just a "no degenerate all-one-slot" smoke test on
        // DefaultHasher.)
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

    /// Pool of 4 against one shared microsocks-stub; assert that
    /// `connect()` opened exactly 4 inbound connections, and that
    /// `pool_len()` reports 4.
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
        let upload = Socks5Upload::connect(1, make_target(proxy_port, 4), dummy_target(), stop_rx)
            .await
            .expect("connect pool");

        // Give the stub a heartbeat to finish each handshake — the
        // last one may have raced our pool_len check.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(upload.pool_len(), 4);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "expected 4 inbound TCP connections to the proxy"
        );
        upload.shutdown().await;
    }

    /// Per-session sticky routing: two consecutive sends from the
    /// same SessionKey must land on the same connection on the
    /// proxy side. We test this by tagging each accepted connection
    /// with an incrementing id (the stub's "connection number") and
    /// reading from the slot the SessionKey hashes to.
    #[tokio::test]
    async fn sticky_routing_keeps_flow_on_one_connection() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();

        // Custom stub that buffers per-connection received payloads
        // into ConnFrameBag so the test can read them back.
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
        let upload = Socks5Upload::connect(7, make_target(proxy_port, 4), dummy_target(), stop_rx)
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(upload.pool_len(), 4);

        let key_a = key("10.1.1.1:50001".parse().unwrap());
        let key_b = key("10.1.1.2:50001".parse().unwrap());
        upload.send(key_a, b"a-1").await.expect("send a-1");
        upload.send(key_a, b"a-2").await.expect("send a-2");
        upload.send(key_a, b"a-3").await.expect("send a-3");
        upload.send(key_b, b"b-1").await.expect("send b-1");

        // Give the proxy a heartbeat to drain.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // For each connection, collect the frame payloads. Find the
        // one that has all three "a-*" frames (proves stickiness).
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

    /// Re-hash on connection failure: kill the connection that
    /// session A hashes to mid-flight; the next send must still
    /// succeed (it lands on a healthy slot).
    #[tokio::test]
    async fn rehash_on_failure_keeps_flow_alive() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_port = proxy.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stub_accepted = accepted.clone();
        tokio::spawn(async move {
            run_stub_socks5_pool(proxy, None, stub_accepted).await;
        });

        let (_stop_tx, stop_rx) = watch::channel(false);
        let upload = Socks5Upload::connect(3, make_target(proxy_port, 4), dummy_target(), stop_rx)
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let session = key("10.2.2.2:50002".parse().unwrap());

        // First send establishes which slot session is sticky to.
        upload.send(session, b"first").await.expect("send first");

        // Forcibly break the slot session is sticky to by stealing
        // its stream and dropping it.
        let primary_idx = primary_slot(session, upload.pool_len());
        {
            let snap = upload.pool_snapshot();
            let mut guard = snap[primary_idx].state.lock().await;
            if let Some(mut s) = guard.stream.take() {
                let _ = s.shutdown().await;
            }
        }

        // Next send must succeed via rehash to another healthy slot.
        upload
            .send(session, b"after-break")
            .await
            .expect("send after-break must rehash and succeed");
        upload.shutdown().await;
    }

    /// Live pool grow: connect with N=2, resize to N=4, assert that
    /// both the local pool_len and the proxy's inbound connection
    /// count reach 4.
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
        let upload = Socks5Upload::connect(11, make_target(proxy_port, 2), dummy_target(), stop_rx)
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(upload.pool_len(), 2);
        assert_eq!(accepted.load(Ordering::SeqCst), 2);

        let changed = upload.set_parallel_connections(4).await.expect("resize");
        assert!(changed, "resize from 2→4 should report changed=true");
        tokio::time::sleep(Duration::from_millis(150)).await;
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

    /// Live pool shrink: connect with N=4, resize to N=2, assert
    /// pool_len drops and that subsequent sends still succeed.
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
        let upload = Socks5Upload::connect(12, make_target(proxy_port, 4), dummy_target(), stop_rx)
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(upload.pool_len(), 4);
        assert_eq!(accepted.load(Ordering::SeqCst), 4);

        let changed = upload.set_parallel_connections(2).await.expect("shrink");
        assert!(changed);
        assert_eq!(upload.pool_len(), 2);

        // Hash several sessions over the smaller pool; they should
        // all succeed.
        for i in 0..6 {
            let addr: SocketAddr = format!("10.3.{}.1:50003", i).parse().unwrap();
            upload
                .send(key(addr), b"after-shrink")
                .await
                .expect("post-shrink send");
        }
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
            stop_rx,
        )
        .await
        .expect("connect with auth");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(upload.pool_len(), 3);
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
        let session = key("10.4.4.4:50004".parse().unwrap());
        upload.send(session, b"authed pool").await.expect("send");
        upload.shutdown().await;
    }

    /// Framing across N connections: send into each of the 4
    /// connections and verify the `[u16 BE length][bytes]` layout
    /// arrives intact on the wire (the stub captures bytes and the
    /// test parses them back).
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
        let upload = Socks5Upload::connect(14, make_target(proxy_port, 4), dummy_target(), stop_rx)
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send many distinct payloads with distinct keys so they
        // spread across the pool.
        for i in 0..32u8 {
            let addr: SocketAddr = format!("10.9.{}.{}:50005", i, i).parse().unwrap();
            let payload = vec![i; (i as usize) + 1];
            upload.send(key(addr), &payload).await.expect("send");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Assert that every byte recovered from every connection's
        // frame stream matches a payload we sent. We don't pin which
        // payload went to which connection — just total reachability.
        let conns = frames_per_conn.lock().await;
        let mut all: Vec<Vec<u8>> = Vec::new();
        for conn in conns.iter() {
            let payloads = conn.lock().await;
            all.extend(payloads.iter().cloned());
        }
        assert_eq!(all.len(), 32, "expected to receive 32 frames total");
        // Each frame is `[i; i+1]` for distinct i — recover the set
        // of distinct first-bytes and confirm we got 0..32.
        let mut firsts: Vec<u8> = all.iter().map(|p| p[0]).collect();
        firsts.sort_unstable();
        firsts.dedup();
        assert_eq!(firsts.len(), 32, "got duplicates or missing payloads");
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
