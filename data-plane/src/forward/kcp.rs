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
                        forward_target, &mut recently_closed, &mut recv_buf,
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
        last_activity_ms: Arc::new(AtomicU64::new(0)),
        closing: Arc::new(AtomicBool::new(false)),
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

    let (conv, app_rx) = build_conv(conv_id, cfg, mtu, egress_tx, stats.clone());
    let kcp = conv.kcp.clone();
    let app_tx = conv.app_tx.clone();
    let last = conv.last_activity_ms.clone();
    let window = conv.window.clone();
    let closing = conv.closing.clone();
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
    let tunnel_id = cfg.tunnel_id;
    tokio::spawn(async move {
        match TcpStream::connect(forward_target).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let (read, write) = stream.into_split();
                spawn_write_pump(write, app_rx);
                spawn_read_pump(read, kcp, window, last, closing, snd_wnd, clock);
            }
            Err(e) => {
                warn!(tunnel_id, conv = conv_id, target = %forward_target, err = %e,
                    "kcp: dial forward_target failed; dropping conv");
                convs.lock().expect("conv map").remove(&conv_id);
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
    let idle_ms = u64::from(cfg.idle_timeout_sec) * 1000;
    // Linger a closing conv long enough to flush final ACKs.
    let linger_ms = (u64::from(cfg.tuning.interval) * 2).max(200);
    let mut removed: Vec<u32> = Vec::new();
    {
        let mut map = convs.lock().expect("conv map");
        map.retain(|&id, c| {
            let last = c.last_activity_ms.load(Ordering::Relaxed);
            let idle = now.saturating_sub(last);
            let drop_it =
                (c.closing.load(Ordering::Relaxed) && idle >= linger_ms) || idle >= idle_ms;
            if drop_it {
                removed.push(id);
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
        for id in removed {
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
                    let conv_id = conv_counter.fetch_add(1, Ordering::Relaxed);
                    let (conv, app_rx) =
                        build_conv(conv_id, &cfg, mtu, &egress_tx, stats.clone());
                    let kcp = conv.kcp.clone();
                    let window = conv.window.clone();
                    let last = conv.last_activity_ms.clone();
                    let closing = conv.closing.clone();
                    let snd_wnd = conv.snd_wnd;
                    convs.lock().expect("conv map").insert(conv_id, conv);
                    stats.conv_opens.fetch_add(1, Ordering::Relaxed);
                    stats.active_conns.fetch_add(1, Ordering::Relaxed);
                    debug!(tunnel_id = cfg.tunnel_id, conv = conv_id, "kcp: accepted TCP, opened conv");
                    let (read, write) = stream.into_split();
                    spawn_write_pump(write, app_rx);
                    spawn_read_pump(read, kcp, window, last, closing, snd_wnd, clock);
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
    snd_wnd: usize,
    clock: Instant,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_READ_CHUNK];
        loop {
            let n = match read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
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
                window.notified().await;
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
