//! KCP reliability engine for `forward_protocol=tcp`.
//!
//! Bridges a TCP byte stream across Sublyne's best-effort opaque-datagram
//! channel ([`super::channel`]) using KCP for reliability:
//!
//! ```text
//!   user TCP  ──►  Kcp::send  ──►  segments  ──►  DatagramSink  ──►  spoof/upload
//!   user TCP  ◄──  Kcp::recv  ◄──  segments  ◄──  inbound queue ◄──  spoof/upload
//! ```
//!
//! ## Multiplexing
//!
//! One **KCP conversation (conv id) per user TCP connection**. The conv
//! id lives in the first 4 bytes of every KCP segment, so the peer demuxes
//! by it — no smux needed. The Client allocates conv ids monotonically;
//! the Remote learns each from the first segment and dials `forward_target`.
//!
//! ## Ownership / tasks
//!
//! * One **driver task** owns the conv map and runs the KCP timer: it
//!   `update()`s every conv on a fixed interval and feeds inbound
//!   datagrams in via `input()`, draining decoded app bytes to each
//!   conv's TCP-write pump. All `Kcp::update`/`input`/`recv` calls happen
//!   here (plus `send` from the read pumps), each behind a brief
//!   `std::sync::Mutex` never held across `.await`.
//! * One **egress task** drains finished KCP segments and pushes them
//!   into the [`DatagramSink`].
//! * Per-connection **read pump** (TCP → `Kcp::send`, window-gated) and
//!   **write pump** (`Kcp::recv` → TCP) tasks.
//! * Client only: an **accept loop**; Remote only: a **dial task** per
//!   learned conv.
//!
//! KCP has no FIN, so a per-conv **idle watchdog** reaps conversations
//! whose TCP side closed or went quiet, and a recently-closed guard on
//! the Remote stops a late segment from resurrecting a reaped conv.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kcp::Kcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, info, warn};

use super::channel::{DatagramSink, InboundRx, EGRESS_CAP};
use crate::spec::KcpTuning;

/// KCP segment header length (conv + cmd + frg + wnd + ts + sn + una +
/// len = 24 bytes). The conv id is the first 4 bytes, little-endian.
const KCP_OVERHEAD: usize = 24;

/// Reusable scratch for draining `Kcp::recv`. Stream-mode recv returns up
/// to this many bytes per call.
const RECV_BUF: usize = 64 * 1024;

/// TCP read chunk handed to `Kcp::send` per syscall.
const TCP_READ_CHUNK: usize = 16 * 1024;

/// Per-conv app-delivery queue depth (KCP-decoded bytes awaiting the TCP
/// write pump). Bounded so a slow TCP consumer flow-controls back through
/// KCP's receive window rather than growing memory.
const APP_QUEUE: usize = 256;

/// Engine-local counters, surfaced to the tunnel's metrics by the
/// integration layer. Kept separate from `TunnelMetrics` so the engine is
/// testable in isolation.
#[derive(Debug, Default)]
pub struct EngineStats {
    pub active_conns: AtomicU64,
    pub conv_opens: AtomicU64,
    pub idle_teardowns: AtomicU64,
    /// New convs refused because the tunnel was at `max_connections` or the
    /// process was over the memory soft cap (`memory::pressure_active`).
    /// Best-effort drop — the peer's reliability layer retransmits / backs off.
    pub conv_rejects: AtomicU64,
    /// Segments dropped at the egress staging boundary (channel full).
    pub egress_drops: AtomicU64,
    /// Datagrams the sink dropped pre-wire (best-effort channel).
    pub sink_drops: AtomicU64,
}

/// What the engine forwards to/from at the TCP edge.
pub enum EngineRole {
    /// Iran side: accept user TCP connections on this (already-bound)
    /// listener and allocate a conv per connection.
    Client { listener: TcpListener },
    /// Foreign side: dial this TCP target for each conv learned from the
    /// peer's first segment.
    Remote { forward_target: SocketAddr },
}

/// Static configuration for one engine instance.
pub struct EngineConfig {
    pub tunnel_id: i64,
    /// Idle timeout (seconds) — a conv with no traffic for this long is
    /// reaped. Reuses the tunnel's `idle_timeout_sec`.
    pub idle_timeout_sec: u32,
    /// Per-tunnel connection ceiling (the tunnel's `max_connections`). A new
    /// conv is refused once the live conv count reaches this, mirroring the
    /// UDP path's session-table cap so a TCP tunnel honours the same limit.
    pub max_connections: u32,
    /// Resolved KCP tuning (preset + Advanced overrides) from the spec.
    pub tuning: KcpTuning,
}

/// `std::io::Write` sink each `Kcp` writes finished segments into. Every
/// `write()` is one KCP segment; we `try_send` it to the egress task and
/// drop on a full channel (best-effort — KCP retransmits).
struct OutSink {
    tx: mpsc::Sender<Vec<u8>>,
    stats: Arc<EngineStats>,
}

impl Write for OutSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.tx.try_send(buf.to_vec()).is_err() {
            self.stats.egress_drops.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type SharedKcp = Arc<Mutex<Kcp<OutSink>>>;

/// A snapshot of one conv's driver-facing handles, taken under the map
/// lock so the per-conv KCP work runs without holding it.
type ConvHandle = (SharedKcp, mpsc::Sender<Vec<u8>>, Arc<Notify>, usize);

/// Per-conversation state held in the driver's conv map.
struct Conv {
    kcp: SharedKcp,
    /// Driver → TCP-write pump (KCP-decoded app bytes).
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Driver pokes this when the send window drains so a paused read
    /// pump resumes.
    window: Arc<Notify>,
    /// Millis (engine clock) of the last input or TCP read for this conv.
    last_activity_ms: Arc<AtomicU64>,
    /// Set by a read pump on TCP EOF so the reaper closes the conv after
    /// a short linger even if the peer keeps it warm.
    closing: Arc<AtomicBool>,
    /// Fired (via `notify_one`, permit-storing) when this conv is reaped
    /// so its still-parked read pump unblocks, drops the TCP read half
    /// (closing the fd), and exits — instead of leaking forever on
    /// `window.notified()` and silently black-holing later user bytes
    /// into a no-longer-driven KCP. `notify_one` (not `notify_waiters`)
    /// so a reap that races the pump's brief between-await window still
    /// stores a permit the next `notified()` consumes.
    stop: Arc<Notify>,
    snd_wnd: usize,
}

/// The KCP engine. Construct with [`KcpEngine::new`], then drive with
/// [`KcpEngine::run`] (spawned into the tunnel's `JoinSet` or, in tests,
/// `tokio::spawn`).
pub struct KcpEngine {
    cfg: Arc<EngineConfig>,
    role: EngineRole,
    sink: Arc<dyn DatagramSink>,
    stats: Arc<EngineStats>,
}

impl KcpEngine {
    pub fn new(cfg: EngineConfig, role: EngineRole, sink: Arc<dyn DatagramSink>) -> Self {
        KcpEngine {
            cfg: Arc::new(cfg),
            role,
            sink,
            stats: Arc::new(EngineStats::default()),
        }
    }

    /// Shared handle to the engine's live counters.
    pub fn stats(&self) -> Arc<EngineStats> {
        self.stats.clone()
    }

    /// Run until `stop_rx` fires. Owns every sub-task; on stop the conv
    /// map is dropped, closing all per-conn channels and unwinding the
    /// pumps.
    pub async fn run(self, inbound_rx: InboundRx, stop_rx: watch::Receiver<bool>) {
        let KcpEngine {
            cfg,
            role,
            sink,
            stats,
        } = self;
        // One clock shared by the driver and every pump so `last_activity`
        // comparisons in the reaper use a single time base.
        let clock = Instant::now();
        let mtu = sink.max_payload().max(KCP_OVERHEAD + 1);

        // Egress: drain staged segments → the asymmetric channel.
        let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(EGRESS_CAP);
        {
            let sink = sink.clone();
            let stats = stats.clone();
            let mut stop = stop_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        seg = egress_rx.recv() => {
                            let Some(seg) = seg else { break };
                            match sink.send(&seg).await {
                                Ok(true) => {}
                                Ok(false) => { stats.sink_drops.fetch_add(1, Ordering::Relaxed); }
                                Err(e) => debug!(err = %e, "kcp: egress sink send failed"),
                            }
                        }
                    }
                }
            });
        }

        let convs: Arc<Mutex<HashMap<u32, Conv>>> = Arc::new(Mutex::new(HashMap::new()));
        let conv_counter = Arc::new(AtomicU32::new(1));
        // Recently-reaped conv ids (Remote): drop late segments for these
        // instead of re-dialing a dead conv. (id, reaped_ms).
        let mut recently_closed: VecDeque<(u32, u64)> = VecDeque::new();

        let forward_target = match &role {
            EngineRole::Remote { forward_target } => Some(*forward_target),
            EngineRole::Client { .. } => None,
        };
        if let EngineRole::Client { listener } = role {
            spawn_accept_loop(
                listener,
                cfg.clone(),
                mtu,
                clock,
                convs.clone(),
                conv_counter.clone(),
                egress_tx.clone(),
                stats.clone(),
                stop_rx.clone(),
            );
        }

        let interval_ms = u64::from(cfg.tuning.interval.max(10));
        let mut tick = tokio::time::interval(Duration::from_millis(interval_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut inbound_rx = inbound_rx;
        let mut stop = stop_rx.clone();
        let mut recv_buf = vec![0u8; RECV_BUF];
        let mut last_reap = 0u64;
        let reap_every_ms = (u64::from(cfg.idle_timeout_sec) * 1000 / 4).max(1000);

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    info!(tunnel_id = cfg.tunnel_id, "kcp: engine stopping");
                    break;
                }
                dg = inbound_rx.recv() => {
                    let Some(dg) = dg else { break };
                    let now = clock.elapsed().as_millis() as u64;
                    handle_inbound(
                        &dg, now, &cfg, mtu, clock, &convs, &egress_tx, &stats,
                        forward_target, &mut recently_closed, &mut recv_buf, &stop_rx,
                    );
                }
                _ = tick.tick() => {
                    let now = clock.elapsed().as_millis() as u64;
                    drive_all(now, &convs, &mut recv_buf);
                    if now.saturating_sub(last_reap) >= reap_every_ms {
                        last_reap = now;
                        reap_idle(now, &cfg, &convs, &stats, &mut recently_closed);
                    }
                }
            }
        }
    }
}

/// Peek the conv id (first 4 bytes, little-endian) of a KCP segment.
fn peek_conv(dg: &[u8]) -> Option<u32> {
    if dg.len() < KCP_OVERHEAD {
        return None;
    }
    Some(u32::from_le_bytes([dg[0], dg[1], dg[2], dg[3]]))
}

fn apply_tuning(kcp: &mut Kcp<OutSink>, t: &KcpTuning, mtu: usize, tunnel_id: i64) {
    kcp.set_nodelay(
        t.nodelay != 0,
        t.interval as i32,
        t.resend as i32,
        t.nc != 0,
    );
    let snd = t.snd_wnd.min(u32::from(u16::MAX)) as u16;
    let rcv = t.rcv_wnd.min(u32::from(u16::MAX)) as u16;
    kcp.set_wndsize(snd, rcv);
    if let Err(e) = kcp.set_mtu(mtu) {
        warn!(tunnel_id, mtu, err = %e, "kcp: set_mtu failed; using default");
    }
}

/// Build a fresh conv (Kcp + channels). Returns the conv handle to insert
/// into the map plus the app-bytes receiver for the TCP-write pump.
fn build_conv(
    conv_id: u32,
    cfg: &EngineConfig,
    mtu: usize,
    egress_tx: &mpsc::Sender<Vec<u8>>,
    stats: Arc<EngineStats>,
    now_ms: u64,
) -> (Conv, mpsc::Receiver<Vec<u8>>) {
    let sink = OutSink {
        tx: egress_tx.clone(),
        stats,
    };
    // Stream mode: KCP carries a pure byte stream (no artificial message
    // boundaries), matching the TCP semantics we bridge.
    let mut kcp = Kcp::new_stream(conv_id, sink);
    apply_tuning(&mut kcp, &cfg.tuning, mtu, cfg.tunnel_id);
    let snd_wnd = cfg.tuning.snd_wnd.max(1) as usize;
    let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(APP_QUEUE);
    let conv = Conv {
        kcp: Arc::new(Mutex::new(kcp)),
        app_tx,
        window: Arc::new(Notify::new()),
        // Seed last_activity with the current engine clock, NOT 0: on an
        // engine that has already been up longer than idle_timeout, a
        // fresh conv with last=0 has idle = now - 0 >= idle_ms and would
        // be reaped on the very next sweep before it ever carried traffic
        // (e.g. a client slow to send its first byte). Seeding `now` gives
        // every conv a full idle window from creation.
        last_activity_ms: Arc::new(AtomicU64::new(now_ms)),
        closing: Arc::new(AtomicBool::new(false)),
        stop: Arc::new(Notify::new()),
        snd_wnd,
    };
    (conv, app_rx)
}

/// Feed an inbound datagram into its conv, creating + dialing on the
/// Remote side when the conv is new.
#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    dg: &[u8],
    now: u64,
    cfg: &Arc<EngineConfig>,
    mtu: usize,
    clock: Instant,
    convs: &Arc<Mutex<HashMap<u32, Conv>>>,
    egress_tx: &mpsc::Sender<Vec<u8>>,
    stats: &Arc<EngineStats>,
    forward_target: Option<SocketAddr>,
    recently_closed: &mut VecDeque<(u32, u64)>,
    recv_buf: &mut [u8],
    stop_rx: &watch::Receiver<bool>,
) {
    let Some(conv_id) = peek_conv(dg) else {
        return;
    };

    // Fast path: existing conv.
    {
        let map = convs.lock().expect("conv map");
        if let Some(conv) = map.get(&conv_id) {
            let kcp = conv.kcp.clone();
            let app_tx = conv.app_tx.clone();
            let last = conv.last_activity_ms.clone();
            let window = conv.window.clone();
            let snd_wnd = conv.snd_wnd;
            drop(map);
            feed_conv(&kcp, dg, now, &app_tx, &last, &window, snd_wnd, recv_buf);
            return;
        }
    }

    // Unknown conv. On the Client this is a stale/late segment for a
    // reaped conv — drop it. On the Remote it's a brand-new connection.
    let Some(forward_target) = forward_target else {
        return;
    };
    if recently_closed.iter().any(|(id, _)| *id == conv_id) {
        return;
    }

    // Admission control, mirroring the UDP path's session-table gate
    // (session.rs insert_or_refresh): refuse a new conv when the tunnel is at
    // max_connections OR the process is over the memory soft cap. Without this
    // a TCP-forward Remote would keep minting convs and dialing forward_target
    // under pressure — violating the "RSS > ~70% → refuse new sessions, never
    // self-kill" invariant. Best-effort drop: the Client's KCP retransmits, so
    // the conv opens once headroom returns. (max_connections == 0 ⇒ no cap.)
    {
        let cap = cfg.max_connections as usize;
        let at_cap = cap > 0 && convs.lock().expect("conv map").len() >= cap;
        if at_cap || crate::memory::pressure_active() {
            stats.conv_rejects.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    let (conv, app_rx) = build_conv(conv_id, cfg, mtu, egress_tx, stats.clone(), now);
    let kcp = conv.kcp.clone();
    let app_tx = conv.app_tx.clone();
    let last = conv.last_activity_ms.clone();
    let window = conv.window.clone();
    let closing = conv.closing.clone();
    let stop = conv.stop.clone();
    let snd_wnd = conv.snd_wnd;
    convs.lock().expect("conv map").insert(conv_id, conv);
    stats.conv_opens.fetch_add(1, Ordering::Relaxed);
    stats.active_conns.fetch_add(1, Ordering::Relaxed);
    info!(
        tunnel_id = cfg.tunnel_id,
        conv = conv_id,
        target = %forward_target,
        "kcp: remote learned new conv; dialing forward_target"
    );
    // Feed the triggering segment so the handshake/ACK progresses; the
    // decoded bytes buffer in app_tx until the dial completes.
    feed_conv(&kcp, dg, now, &app_tx, &last, &window, snd_wnd, recv_buf);

    // Dial off-driver so a slow connect can't stall the timer loop.
    let convs = convs.clone();
    let stats = stats.clone();
    let stop_rx = stop_rx.clone();
    let tunnel_id = cfg.tunnel_id;
    tokio::spawn(async move {
        match TcpStream::connect(forward_target).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let (read, write) = stream.into_split();
                spawn_write_pump(write, app_rx);
                spawn_read_pump(
                    read, kcp, window, last, closing, stop, snd_wnd, clock, stop_rx,
                );
            }
            Err(e) => {
                warn!(tunnel_id, conv = conv_id, target = %forward_target, err = %e,
                    "kcp: dial forward_target failed; dropping conv");
                // Decrement active_conns ONLY if we actually evicted the
                // conv — a concurrent reap_idle may have removed it first
                // (and already decremented), and an unguarded fetch_sub
                // would underflow the AtomicU64. This keeps active_conns
                // from leaking upward on every failed forward_target dial.
                if convs.lock().expect("conv map").remove(&conv_id).is_some() {
                    stats.active_conns.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    });
}

/// Lock a conv's KCP, input one datagram, advance its timer, and drain
/// any decoded app bytes to the TCP-write pump.
#[allow(clippy::too_many_arguments)]
fn feed_conv(
    kcp: &SharedKcp,
    dg: &[u8],
    now: u64,
    app_tx: &mpsc::Sender<Vec<u8>>,
    last: &Arc<AtomicU64>,
    window: &Arc<Notify>,
    snd_wnd: usize,
    recv_buf: &mut [u8],
) {
    let mut k = kcp.lock().expect("kcp lock");
    if let Err(e) = k.input(dg) {
        debug!(err = %e, "kcp: input rejected segment");
        return;
    }
    // ACK / retransmit promptly rather than waiting for the next tick.
    let _ = k.update(now as u32);
    drain_recv(&mut k, app_tx, recv_buf);
    let room = k.wait_snd() < snd_wnd;
    drop(k);
    if room {
        window.notify_one();
    }
    last.store(now, Ordering::Relaxed);
}

/// Periodic timer: update every conv, drain decoded bytes, wake paused
/// read pumps whose window has room.
fn drive_all(now: u64, convs: &Arc<Mutex<HashMap<u32, Conv>>>, recv_buf: &mut [u8]) {
    // Snapshot handles so the map lock isn't held across per-conv work.
    let handles: Vec<ConvHandle> = {
        let map = convs.lock().expect("conv map");
        map.values()
            .map(|c| (c.kcp.clone(), c.app_tx.clone(), c.window.clone(), c.snd_wnd))
            .collect()
    };
    for (kcp, app_tx, window, snd_wnd) in handles {
        let mut k = kcp.lock().expect("kcp lock");
        let _ = k.update(now as u32);
        drain_recv(&mut k, &app_tx, recv_buf);
        let room = k.wait_snd() < snd_wnd;
        drop(k);
        if room {
            window.notify_one();
        }
    }
}

/// Move KCP-decoded bytes into the per-conv app queue, lossless: reserve
/// a queue slot first so we never `recv()` bytes we then can't enqueue.
fn drain_recv(kcp: &mut Kcp<OutSink>, app_tx: &mpsc::Sender<Vec<u8>>, recv_buf: &mut [u8]) {
    loop {
        let permit = match app_tx.try_reserve() {
            Ok(p) => p,
            Err(_) => break, // queue full (slow TCP consumer) or closed
        };
        match kcp.recv(recv_buf) {
            Ok(n) if n > 0 => permit.send(recv_buf[..n].to_vec()),
            _ => break, // nothing decodable now; permit released on drop
        }
    }
}

/// Reap conversations whose TCP side closed (after a short linger) or that
/// have seen no traffic for `idle_timeout`.
fn reap_idle(
    now: u64,
    cfg: &EngineConfig,
    convs: &Arc<Mutex<HashMap<u32, Conv>>>,
    stats: &EngineStats,
    recently_closed: &mut VecDeque<(u32, u64)>,
) {
    // Clamp idle_timeout to >= 1 s: a (mis)configured idle_timeout_sec = 0
    // would make idle_ms = 0 so EVERY conv reaps on the next sweep. Mirror
    // the >=1 clamp the other timeout consumers apply.
    let idle_ms = u64::from(cfg.idle_timeout_sec.max(1)) * 1000;
    // Linger a closing conv long enough to flush final ACKs.
    let linger_ms = (u64::from(cfg.tuning.interval) * 2).max(200);
    // Collect (id, stop-handle) of reaped convs so we can wake their
    // detached read pumps AFTER releasing the map lock — the read pump
    // is not a map entry and would otherwise stay parked on
    // window.notified() forever, leaking its task + TCP read-half fd and
    // silently swallowing any later user bytes into a no-longer-driven KCP.
    let mut removed: Vec<(u32, Arc<Notify>)> = Vec::new();
    {
        let mut map = convs.lock().expect("conv map");
        map.retain(|&id, c| {
            let last = c.last_activity_ms.load(Ordering::Relaxed);
            let idle = now.saturating_sub(last);
            let drop_it =
                (c.closing.load(Ordering::Relaxed) && idle >= linger_ms) || idle >= idle_ms;
            if drop_it {
                removed.push((id, c.stop.clone()));
            }
            !drop_it
        });
    }
    if !removed.is_empty() {
        stats
            .active_conns
            .fetch_sub(removed.len() as u64, Ordering::Relaxed);
        stats
            .idle_teardowns
            .fetch_add(removed.len() as u64, Ordering::Relaxed);
        for (id, stop) in removed {
            // Permit-storing wake: if the read pump is mid-iteration (not
            // currently parked on `notified()`), notify_one stores a permit
            // the next `notified()` consumes, so the wake can't be missed.
            stop.notify_one();
            recently_closed.push_back((id, now));
            debug!(
                tunnel_id = cfg.tunnel_id,
                conv = id,
                "kcp: reaped idle conv"
            );
        }
    }
    // Prune the recently-closed guard (keep ~2× idle window).
    let keep = idle_ms.saturating_mul(2).max(10_000);
    while let Some(&(_, ts)) = recently_closed.front() {
        if now.saturating_sub(ts) > keep {
            recently_closed.pop_front();
        } else {
            break;
        }
    }
}

/// Client accept loop: one conv per inbound TCP connection.
#[allow(clippy::too_many_arguments)]
fn spawn_accept_loop(
    listener: TcpListener,
    cfg: Arc<EngineConfig>,
    mtu: usize,
    clock: Instant,
    convs: Arc<Mutex<HashMap<u32, Conv>>>,
    conv_counter: Arc<AtomicU32>,
    egress_tx: mpsc::Sender<Vec<u8>>,
    stats: Arc<EngineStats>,
    mut stop_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                accept = listener.accept() => {
                    let stream = match accept {
                        Ok((s, _peer)) => s,
                        Err(e) => {
                            warn!(tunnel_id = cfg.tunnel_id, err = %e, "kcp: tcp accept failed");
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);
                    // Admission control before opening a conv: refuse a new
                    // user connection when the tunnel is at max_connections or
                    // the process is over the memory soft cap. Dropping
                    // `stream` here closes the user's TCP cleanly (a clear
                    // rejection) instead of opening a conv whose segments the
                    // Remote would just drop under the same pressure.
                    // (max_connections == 0 ⇒ no cap.)
                    let cap = cfg.max_connections as usize;
                    let at_cap = cap > 0 && convs.lock().expect("conv map").len() >= cap;
                    if at_cap || crate::memory::pressure_active() {
                        // Sample the warn off the reject counter so a sustained
                        // overload doesn't flood the log; every reject is still
                        // counted.
                        let prev = stats.conv_rejects.fetch_add(1, Ordering::Relaxed);
                        if prev % 1000 == 0 {
                            warn!(
                                tunnel_id = cfg.tunnel_id,
                                rejected_total = prev + 1,
                                at_cap,
                                "kcp: refusing new TCP connection (at max_connections or memory pressure)"
                            );
                        }
                        continue;
                    }
                    let conv_id = conv_counter.fetch_add(1, Ordering::Relaxed);
                    let (conv, app_rx) = build_conv(
                        conv_id,
                        &cfg,
                        mtu,
                        &egress_tx,
                        stats.clone(),
                        clock.elapsed().as_millis() as u64,
                    );
                    let kcp = conv.kcp.clone();
                    let window = conv.window.clone();
                    let last = conv.last_activity_ms.clone();
                    let closing = conv.closing.clone();
                    let stop = conv.stop.clone();
                    let snd_wnd = conv.snd_wnd;
                    convs.lock().expect("conv map").insert(conv_id, conv);
                    stats.conv_opens.fetch_add(1, Ordering::Relaxed);
                    stats.active_conns.fetch_add(1, Ordering::Relaxed);
                    debug!(tunnel_id = cfg.tunnel_id, conv = conv_id, "kcp: accepted TCP, opened conv");
                    let (read, write) = stream.into_split();
                    spawn_write_pump(write, app_rx);
                    spawn_read_pump(
                        read, kcp, window, last, closing, stop, snd_wnd, clock, stop_rx.clone(),
                    );
                }
            }
        }
    });
}

/// TCP → KCP: read user bytes and feed `Kcp::send`, gating on the send
/// window so a slow channel applies backpressure to the user's TCP via
/// the OS receive window instead of buffering unbounded in KCP.
#[allow(clippy::too_many_arguments)]
fn spawn_read_pump(
    mut read: tokio::net::tcp::OwnedReadHalf,
    kcp: SharedKcp,
    window: Arc<Notify>,
    last: Arc<AtomicU64>,
    closing: Arc<AtomicBool>,
    stop: Arc<Notify>,
    snd_wnd: usize,
    clock: Instant,
    mut stop_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_READ_CHUNK];
        'pump: loop {
            // BOTH await points race the stop signals so a reaped conv
            // (per-conv `stop`) or a stopping engine (`stop_rx`) unblocks
            // the pump promptly — dropping `read` closes the TCP read-half
            // fd. Without this the pump leaks and silently feeds later user
            // bytes into a KCP the driver no longer updates.
            let n = tokio::select! {
                _ = stop_rx.changed() => break,
                _ = stop.notified() => break,
                r = read.read(&mut buf) => match r {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(_) => break,
                },
            };
            // Window gate: wait until KCP has room before queuing more.
            loop {
                let queued = {
                    let mut k = kcp.lock().expect("kcp lock");
                    if k.wait_snd() < snd_wnd {
                        let _ = k.send(&buf[..n]);
                        true
                    } else {
                        false
                    }
                };
                if queued {
                    last.store(clock.elapsed().as_millis() as u64, Ordering::Relaxed);
                    break;
                }
                tokio::select! {
                    _ = stop_rx.changed() => break 'pump,
                    _ = stop.notified() => break 'pump,
                    _ = window.notified() => {}
                }
            }
        }
        // Signal the reaper to tear this conv down after a short linger.
        closing.store(true, Ordering::Relaxed);
    });
}

/// KCP → TCP: write decoded app bytes to the user's TCP socket, applying
/// natural backpressure via the bounded app queue.
fn spawn_write_pump(
    mut write: tokio::net::tcp::OwnedWriteHalf,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        while let Some(bytes) = app_rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    });
}

#[cfg(test)]
mod tests {
    //! Unit tests for the idle-reaper accounting and the fresh-conv grace
    //! window. `build_conv` and `reap_idle` are module-private free
    //! functions, so a same-file test can drive them without real sockets
    //! (the dial / pump tasks are never spawned here).

    use super::*;

    fn cfg(idle_timeout_sec: u32) -> EngineConfig {
        EngineConfig {
            tunnel_id: 1,
            idle_timeout_sec,
            // High cap so the reap/idle tests below aren't gated by admission
            // control; the cap itself is exercised by the dedicated test.
            max_connections: 10_000,
            tuning: KcpTuning::default(),
        }
    }

    fn empty_convs() -> Arc<Mutex<HashMap<u32, Conv>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// A4 regression: a conv created on an engine that has already been up
    /// far longer than idle_timeout must NOT be reaped on the very next
    /// sweep. Before the fix `last_activity_ms` started at 0, so
    /// `idle = now - 0 >= idle_ms` was instantly true and the brand-new
    /// connection was killed before it ever carried traffic.
    #[test]
    fn fresh_conv_survives_reap_on_long_lived_engine() {
        let c = cfg(10);
        let stats = Arc::new(EngineStats::default());
        let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(16);
        let convs = empty_convs();
        // Engine "now" ~1000 s of uptime, far exceeding the 10 s idle window.
        let now = 1_000_000u64;
        let (conv, _app_rx) = build_conv(5, &c, 1200, &egress_tx, stats.clone(), now);
        convs.lock().unwrap().insert(5, conv);
        stats.active_conns.fetch_add(1, Ordering::Relaxed);
        let mut rc = VecDeque::new();
        reap_idle(now, &c, &convs, &stats, &mut rc);
        assert_eq!(
            convs.lock().unwrap().len(),
            1,
            "a freshly-seeded conv must survive the first sweep on a long-lived engine"
        );
        assert_eq!(stats.active_conns.load(Ordering::Relaxed), 1);
        assert_eq!(stats.idle_teardowns.load(Ordering::Relaxed), 0);
    }

    /// Reap accounting is symmetric: an idle conv is removed, active_conns
    /// is decremented (so it can't drift upward), idle_teardowns is bumped,
    /// and the id is recorded in recently_closed (Remote resurrection guard).
    #[test]
    fn idle_conv_is_reaped_with_symmetric_accounting() {
        let c = cfg(10);
        let stats = Arc::new(EngineStats::default());
        let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(16);
        let convs = empty_convs();
        // last = 0; now = 11 s → idle 11 s >= the 10 s idle window.
        let (conv, _app_rx) = build_conv(7, &c, 1200, &egress_tx, stats.clone(), 0);
        convs.lock().unwrap().insert(7, conv);
        stats.active_conns.fetch_add(1, Ordering::Relaxed);
        let mut rc = VecDeque::new();
        reap_idle(11_000, &c, &convs, &stats, &mut rc);
        assert!(convs.lock().unwrap().is_empty(), "idle conv must be reaped");
        assert_eq!(
            stats.active_conns.load(Ordering::Relaxed),
            0,
            "active_conns must return to 0 after the only conv is reaped"
        );
        assert_eq!(stats.idle_teardowns.load(Ordering::Relaxed), 1);
        assert!(rc.iter().any(|(id, _)| *id == 7));
    }

    /// idle_timeout_sec = 0 must be clamped to >= 1 s so a fresh conv is not
    /// reaped on the very next sweep (a degenerate 0 would make every conv
    /// idle-out instantly).
    #[test]
    fn idle_timeout_zero_is_clamped() {
        let c = cfg(0);
        let stats = Arc::new(EngineStats::default());
        let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(16);
        let convs = empty_convs();
        let now = 100u64; // 100 ms of uptime; clamp gives a 1 s idle window
        let (conv, _app_rx) = build_conv(9, &c, 1200, &egress_tx, stats.clone(), now);
        convs.lock().unwrap().insert(9, conv);
        let mut rc = VecDeque::new();
        reap_idle(now, &c, &convs, &stats, &mut rc);
        assert_eq!(
            convs.lock().unwrap().len(),
            1,
            "idle_timeout_sec=0 must clamp to >=1 s, not reap a fresh conv immediately"
        );
    }

    /// v4-audit B1: the Remote refuses a brand-new conv once the tunnel is at
    /// max_connections, mirroring the UDP session-table cap, instead of minting
    /// convs without bound. (Memory-pressure is the other half of the gate; it
    /// is false on a normal test host so the cap path is what we exercise.)
    #[test]
    fn remote_refuses_new_conv_at_max_connections() {
        // Cap of 2; pre-fill the map to the cap with dummy convs.
        let c = Arc::new(EngineConfig {
            tunnel_id: 1,
            idle_timeout_sec: 300,
            max_connections: 2,
            tuning: KcpTuning::default(),
        });
        let stats = Arc::new(EngineStats::default());
        let (egress_tx, _egress_rx) = mpsc::channel::<Vec<u8>>(16);
        let convs = empty_convs();
        for id in [100u32, 101u32] {
            let (conv, _rx) = build_conv(id, &c, 1200, &egress_tx, stats.clone(), 0);
            convs.lock().unwrap().insert(id, conv);
        }

        // A valid-looking KCP segment for a NEW conv id (first 4 bytes = conv
        // id LE; padded to the header length so peek_conv accepts it).
        let mut dg = vec![0u8; KCP_OVERHEAD];
        dg[..4].copy_from_slice(&200u32.to_le_bytes());

        let clock = Instant::now();
        let (_stop_tx, stop_rx) = watch::channel(false);
        let forward_target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut recently_closed = VecDeque::new();
        let mut recv_buf = vec![0u8; RECV_BUF];

        handle_inbound(
            &dg,
            1_000,
            &c,
            1200,
            clock,
            &convs,
            &egress_tx,
            &stats,
            Some(forward_target),
            &mut recently_closed,
            &mut recv_buf,
            &stop_rx,
        );

        assert_eq!(
            convs.lock().unwrap().len(),
            2,
            "a new conv must be refused when the tunnel is at max_connections"
        );
        assert!(
            !convs.lock().unwrap().contains_key(&200),
            "the over-cap conv must not be inserted"
        );
        assert_eq!(stats.conv_rejects.load(Ordering::Relaxed), 1);
    }
}
