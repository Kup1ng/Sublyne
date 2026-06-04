//! Per-application-port KCP engine: owns the conv map for ONE forwarded
//! port, routes inbound segments by conv id, and (Client) accepts user
//! TCP connections or (Remote) dials `forward_target` on the first
//! segment of a new conv. A multi-port tcp tunnel runs one [`Engine`] per
//! port inside an [`EngineSet`], so a slow or busy port can't stall the
//! others — each engine has its own conv map, its own connection cap, and
//! its own per-conv backpressure.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::channel::{inbound_channel, DatagramSink, InboundRx, InboundTx};
use super::conv::{run_conv, ConvConfig, ConvSide};
use super::tuning;
use crate::metrics::TunnelMetrics;
use crate::multiport;
use crate::spec::KcpTuning;

/// Client-side conv ids start here; ids below this are reserved (the
/// keep-alive conv added in checkpoint 4 uses id 1).
const CLIENT_CONV_BASE: u32 = 1000;

/// How long a reaped conv id is remembered on the Remote so a late
/// segment drops instead of resurrecting a dead conv (and re-dialing
/// forward_target). Pruned opportunistically on each new-conv check.
const RECENTLY_CLOSED_KEEP: Duration = Duration::from_secs(120);

/// Sentinel map key for the single-port engine inside an [`EngineSet`].
const SINGLE_PORT_KEY: u16 = 0;

/// Process-wide sampled counter for unknown application-port tags on the
/// tcp-forward path (config drift between the two sides).
static UNKNOWN_PORT_TCP_DROPS: AtomicU64 = AtomicU64::new(0);

/// Shared map of live conversations for one engine.
pub(crate) type ConvMap = Arc<StdMutex<HashMap<u32, ConvHandle>>>;

/// Recently-reaped conv ids (id, reaped-at) so a late Remote segment
/// drops instead of resurrecting a dead conv.
pub(crate) type RecentlyClosed = Arc<StdMutex<VecDeque<(u32, Instant)>>>;

/// One conversation's engine-facing handle.
pub(crate) struct ConvHandle {
    pub inbound_tx: InboundTx,
}

/// Resources the conv task uses to clean itself out of the engine when it
/// closes. Removes the conv from the map, decrements the tunnel-wide
/// active-conv gauge, and (Remote) records the id in the recently-closed
/// guard.
pub(crate) struct ConvCleanup {
    pub convs: ConvMap,
    pub conv_id: u32,
    pub active: Arc<AtomicU64>,
    pub recently_closed: Option<RecentlyClosed>,
}

/// Which edge of the tunnel an engine terminates.
#[derive(Clone, Copy)]
pub enum EngineRole {
    /// Iran side: a TCP listener accepts user connections (bound by the
    /// caller and handed to [`Engine::accept_loop`]).
    Client,
    /// Foreign side: dial this target for each conv learned from the
    /// peer's first segment.
    Remote { forward_target: SocketAddr },
}

/// Static configuration for one engine instance.
pub struct EngineConfig {
    pub tunnel_id: i64,
    pub tuning: KcpTuning,
    pub kcp_mtu: usize,
    pub idle_timeout_sec: u32,
    /// Max concurrent conversations for this engine. New conns above the
    /// cap are refused (closed), never queued.
    pub max_conns: usize,
}

/// One application port's KCP engine.
pub struct Engine {
    role: EngineRole,
    cfg: EngineConfig,
    convs: ConvMap,
    sink: Arc<dyn DatagramSink>,
    /// Tunnel-wide active-conv counter, shared across every engine of a
    /// multi-port tunnel so the dashboard's session count is the sum.
    active: Arc<AtomicU64>,
    metrics: Arc<TunnelMetrics>,
    conv_counter: AtomicU32,
    recently_closed: RecentlyClosed,
    clock: Instant,
    stop_rx: watch::Receiver<bool>,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: EngineRole,
        cfg: EngineConfig,
        sink: Arc<dyn DatagramSink>,
        active: Arc<AtomicU64>,
        metrics: Arc<TunnelMetrics>,
        clock: Instant,
        stop_rx: watch::Receiver<bool>,
    ) -> Arc<Self> {
        Arc::new(Engine {
            role,
            cfg,
            convs: Arc::new(StdMutex::new(HashMap::new())),
            sink,
            active,
            metrics,
            conv_counter: AtomicU32::new(CLIENT_CONV_BASE),
            recently_closed: Arc::new(StdMutex::new(VecDeque::new())),
            clock,
            stop_rx,
        })
    }

    fn side(&self) -> ConvSide {
        match self.role {
            EngineRole::Client => ConvSide::Client,
            EngineRole::Remote { .. } => ConvSide::Remote,
        }
    }

    fn conv_config(&self, is_keepalive: bool) -> ConvConfig {
        ConvConfig {
            tuning: self.cfg.tuning,
            kcp_mtu: self.cfg.kcp_mtu,
            idle_timeout_sec: self.cfg.idle_timeout_sec,
            is_keepalive,
            side: self.side(),
            tunnel_id: self.cfg.tunnel_id,
        }
    }

    fn publish_active(&self) {
        let n = self.active.load(Ordering::Relaxed).min(u32::MAX as u64) as u32;
        self.metrics.set_active_sessions(n);
    }

    fn at_capacity(&self) -> bool {
        self.active.load(Ordering::Relaxed) as usize >= self.cfg.max_conns
    }

    /// True if `conv_id` was reaped recently (Remote guard). Prunes
    /// expired entries while scanning.
    fn is_recently_closed(&self, conv_id: u32) -> bool {
        let mut q = self.recently_closed.lock().expect("recently_closed");
        while let Some(&(_, ts)) = q.front() {
            if ts.elapsed() > RECENTLY_CLOSED_KEEP {
                q.pop_front();
            } else {
                break;
            }
        }
        q.iter().any(|&(id, _)| id == conv_id)
    }

    /// Route one inbound KCP segment to its conversation. On the Remote an
    /// unknown conv id means a new connection — dial forward_target and
    /// spawn the conv. On the Client an unknown conv id is a stale segment
    /// for a reaped conv and is dropped. Non-blocking: never awaits, so it
    /// is safe to call from the shared download-verify worker.
    pub fn route_inbound(self: &Arc<Self>, seg: &[u8]) {
        let Some(conv_id) = tuning::peek_conv(seg) else {
            return;
        };
        // The lock block yields the inbound receiver of a freshly-created
        // Remote conv (so we can spawn its dial task AFTER releasing the
        // map lock); every other path returns from the function.
        let rx: InboundRx = {
            let mut map = self.convs.lock().expect("conv map");
            if let Some(h) = map.get(&conv_id) {
                let _ = h.inbound_tx.try_send(seg.to_vec());
                return;
            }
            // Unknown conv.
            match self.role {
                EngineRole::Client => return, // late segment for a reaped conv
                EngineRole::Remote { .. } => {
                    if self.is_recently_closed(conv_id) || self.at_capacity() {
                        return;
                    }
                    if crate::memory::pressure_active() {
                        return;
                    }
                    let (tx, rx) = inbound_channel();
                    let _ = tx.try_send(seg.to_vec());
                    map.insert(conv_id, ConvHandle { inbound_tx: tx });
                    self.active.fetch_add(1, Ordering::Relaxed);
                    rx
                }
            }
        };
        self.publish_active();
        self.clone().spawn_remote_conv(conv_id, rx);
    }

    /// Dial forward_target for a newly-learned Remote conv, then run it.
    /// On dial failure, undo the conv insertion + active count (A5 fix).
    fn spawn_remote_conv(self: Arc<Self>, conv_id: u32, rx: InboundRx) {
        let forward_target = match self.role {
            EngineRole::Remote { forward_target } => forward_target,
            EngineRole::Client => return,
        };
        tokio::spawn(async move {
            match TcpStream::connect(forward_target).await {
                Ok(stream) => {
                    let cleanup = ConvCleanup {
                        convs: self.convs.clone(),
                        conv_id,
                        active: self.active.clone(),
                        recently_closed: Some(self.recently_closed.clone()),
                    };
                    debug!(
                        tunnel_id = self.cfg.tunnel_id,
                        conv = conv_id,
                        target = %forward_target,
                        "forward/remote: dialed forward_target, conv up"
                    );
                    run_conv(
                        conv_id,
                        stream,
                        rx,
                        self.sink.clone(),
                        self.conv_config(false),
                        self.metrics.clone(),
                        self.clock,
                        self.stop_rx.clone(),
                        cleanup,
                    )
                    .await;
                }
                Err(e) => {
                    self.convs.lock().expect("conv map").remove(&conv_id);
                    let prev = self.active.fetch_sub(1, Ordering::Relaxed);
                    self.metrics
                        .set_active_sessions(prev.saturating_sub(1).min(u32::MAX as u64) as u32);
                    self.recently_closed
                        .lock()
                        .expect("recently_closed")
                        .push_back((conv_id, Instant::now()));
                    warn!(
                        tunnel_id = self.cfg.tunnel_id,
                        conv = conv_id,
                        target = %forward_target,
                        err = %e,
                        "forward/remote: dial forward_target failed; dropping conv"
                    );
                }
            }
        });
    }

    /// Client accept loop: one conv per inbound user TCP connection.
    /// Spawned into the tunnel's task set; exits on tunnel stop.
    pub async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        let mut stop_rx = self.stop_rx.clone();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    info!(tunnel_id = self.cfg.tunnel_id, "forward/client: accept loop stopping");
                    return;
                }
                accept = listener.accept() => {
                    let stream = match accept {
                        Ok((s, _peer)) => s,
                        Err(e) => {
                            warn!(tunnel_id = self.cfg.tunnel_id, err = %e,
                                "forward/client: tcp accept failed");
                            continue;
                        }
                    };
                    if self.at_capacity() || crate::memory::pressure_active() {
                        // Refuse rather than queue: a per-conn KCP session
                        // pileup under burst would OOM a small VPS.
                        drop(stream);
                        continue;
                    }
                    let conv_id = self.conv_counter.fetch_add(1, Ordering::Relaxed);
                    let (tx, rx) = inbound_channel();
                    self.convs
                        .lock()
                        .expect("conv map")
                        .insert(conv_id, ConvHandle { inbound_tx: tx });
                    self.active.fetch_add(1, Ordering::Relaxed);
                    self.publish_active();
                    let cleanup = ConvCleanup {
                        convs: self.convs.clone(),
                        conv_id,
                        active: self.active.clone(),
                        recently_closed: None,
                    };
                    debug!(tunnel_id = self.cfg.tunnel_id, conv = conv_id,
                        "forward/client: accepted user TCP, opened conv");
                    tokio::spawn(run_conv(
                        conv_id,
                        stream,
                        rx,
                        self.sink.clone(),
                        self.conv_config(false),
                        self.metrics.clone(),
                        self.clock,
                        self.stop_rx.clone(),
                        cleanup,
                    ));
                }
            }
        }
    }
}

/// The set of per-port engines backing one tcp-forward tunnel. Single-port
/// tunnels hold exactly one engine under [`SINGLE_PORT_KEY`]; multi-port
/// tunnels hold one per application port, demuxed by the 2-byte tag.
pub struct EngineSet {
    engines: HashMap<u16, Arc<Engine>>,
    multiport: bool,
    tunnel_id: i64,
}

impl EngineSet {
    pub fn single(engine: Arc<Engine>, tunnel_id: i64) -> Arc<Self> {
        let mut engines = HashMap::with_capacity(1);
        engines.insert(SINGLE_PORT_KEY, engine);
        Arc::new(EngineSet {
            engines,
            multiport: false,
            tunnel_id,
        })
    }

    pub fn multi(engines: HashMap<u16, Arc<Engine>>, tunnel_id: i64) -> Arc<Self> {
        Arc::new(EngineSet {
            engines,
            multiport: true,
            tunnel_id,
        })
    }

    /// Route a (possibly port-tagged) inbound datagram to the right
    /// engine. Multi-port decodes the 2-byte application-port tag; single-
    /// port routes the whole datagram. Non-blocking.
    pub fn route_tagged(&self, datagram: &[u8]) {
        if self.multiport {
            let Some((port, body)) = multiport::decode_tag(datagram) else {
                debug!(
                    tunnel_id = self.tunnel_id,
                    "forward: tcp upload datagram too short for port tag"
                );
                return;
            };
            match self.engines.get(&port) {
                Some(e) => e.route_inbound(body),
                None => {
                    let prev = UNKNOWN_PORT_TCP_DROPS.fetch_add(1, Ordering::Relaxed);
                    if prev % 1000 == 0 {
                        warn!(
                            tunnel_id = self.tunnel_id,
                            port,
                            dropped_total = prev + 1,
                            "forward: tcp datagram tagged with a port not in this tunnel's \
                             configured set — the two sides have different port lists; align them"
                        );
                    }
                }
            }
        } else if let Some(e) = self.engines.get(&SINGLE_PORT_KEY) {
            e.route_inbound(datagram);
        }
    }
}
