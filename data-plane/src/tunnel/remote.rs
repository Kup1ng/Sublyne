//! Remote-side tunnel actor.
//!
//! Three concurrent flows mirror the Client side:
//!
//! 1. **Upload listener.** Bind a regular UDP socket on
//!    `upload_listen_addr`. When traffic arrives (already through the
//!    seller's WG path), forward the payload to `forward_target`
//!    using a second UDP socket. Record the upload peer in the
//!    session table.
//!
//! 2. **Forward-target listener (download recv).** The same egress
//!    socket also receives the reply traffic from `forward_target`.
//!    On receive, hand the reply payload to one of N seal-and-spoof-
//!    send workers via a bounded `mpsc` channel. Each worker seals
//!    the payload with the per-tunnel HMAC envelope (using a
//!    pre-derived key) and `sendmmsg`s the spoofed packet through its
//!    own raw send socket — source = (`download_spoof_source_ip`,
//!    `download_spoof_source_port`), destination = (`client_real_ip`,
//!    `download_send_port`).
//!
//! 3. **Idle sweeper.** Same eviction loop as the Client.
//!
//! ## Why fan out workers, not the recv socket (R2)
//!
//! Same reason as the Client side: the recv pipeline drains kernel
//! buffers with `recvmmsg(16)` from a single socket; the per-packet
//! HMAC seal + raw `sendto` is what costs CPU, so the fan-out lives
//! on the worker side. Each worker owns its OWN raw send socket
//! because raw socket send queues are per-fd, so N independent fds
//! parallelise the kernel-side send path; sharing one Arc<RawSocket>
//! across workers would serialise on the kernel socket lock.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

use async_trait::async_trait;

use crate::batch::{self, SendBatch};
use crate::forward::{self, DatagramSink};
use crate::hmac;
use crate::manager::SpawnError;
use crate::metrics::TunnelMetrics;
use crate::multiport;
use crate::session::{InsertOutcome, SessionTable};
use crate::spec::{
    ForwardProtocol, ResolvedSpec, TcpReliabilityEngine, Transport, TunnelSpec, UploadListenMode,
};
use crate::time_util::now_unix;
use crate::transport::udp::MAX_UDP_DATAGRAM;
use crate::transport::{icmp, icmpv6, tcp_syn, udp};

use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpListener;

use crate::perf::Socks5KeepaliveProfile;
use crate::upload::Socks5Profile;

use super::{sampled, sleep_or_stopped, MutableConfigSlot, ReasonSlot, StateSlot};

// Steady-state per-packet upload-path drop counters, sampled via
// super::sampled so a persistent fault (MTU misconfig, capacity ceiling,
// downed forward target) doesn't flood the log. Per-tunnel exact counts
// still flow to the dashboard via the metrics recorder.
static OVERSIZED_UPLOAD_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SESSION_FULL_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FORWARD_FAILS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// TCP-forward upload frames dropped because the engine inbox was full
/// (a slow/stalled reliability engine). Sampled like the UDP-path drop
/// counters so a sustained stall doesn't flood the log; counted as an
/// upload drop so it isn't also recorded as a delivered upload.
static TCP_UPLOAD_INBOX_FULL_DROPS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Per-seal-worker input channel cap. Bounds how far a slow seal
/// worker can fall behind its peers: at most `SEAL_WORKER_CHANNEL_CAP`
/// jobs of its own arithmetic subset, which is
/// `SEAL_WORKER_CHANNEL_CAP * n_workers` wire-seqs of potential
/// reorder when its sealed output finally reaches the send worker.
///
/// Raised from 64 to 256 in the perf-seal-pipeline-headroom pass after
/// the production Remote logged 75 000+ "seal channel full" drops over
/// 24 h with peaks of 450/sec under 30 Mbit/s tunnel load. At cap=64
/// a single scheduler hiccup was enough to fill the queue. Cap=256
/// gives ~4× more burst absorption and keeps the worst-case wire
/// reorder (`256 * n_workers` = 1024 with 4 workers) at exactly Iran's
/// 1024-slot `SeqWindow` — see `hmac.rs::SEQ_WINDOW_WORDS`, which was
/// simultaneously expanded from `u128` (128 effective slots) to a
/// `[u64; 16]` so the docstring contract and the actual replay window
/// now match.
///
/// Don't raise further without also bumping `SEQ_WINDOW_WORDS`: the
/// downstream replay protection on Iran would start dropping the
/// trailing burst.
const SEAL_WORKER_CHANNEL_CAP: usize = 256;
/// Shared sealed-packet queue between seal workers and the send
/// worker. Sized to absorb several sendmmsg batches' worth of packets
/// so the send worker can always fill a full batch without blocking
/// while the seal workers stay ahead.
const SEND_QUEUE_CAP: usize = 1024;

/// One queued reply payload + per-packet HMAC sequence. The seq is
/// captured by the recv task (single producer, monotonic AtomicU64
/// fetch_add) so workers don't fight on it.
struct DownloadSpoofJob {
    /// Bytes received from `forward_target`. Will be sealed by the
    /// worker (HMAC envelope + IP/L4 header + spoof source).
    payload: Vec<u8>,
    /// HMAC sequence number assigned at recv time so the seq stays
    /// strictly monotonic at the wire regardless of which worker
    /// happens to send first.
    hmac_seq: u64,
    /// ICMP 16-bit sequence (separate counter, only meaningful for
    /// ICMP transports). Same monotonic property as `hmac_seq`.
    icmp_seq: u16,
}

/// A spoof packet that's been HMAC-sealed and serialised into its
/// final IP + L4 + envelope bytes. Produced by the seal workers,
/// consumed by the single send worker — owning the bytes makes the
/// hand-off a move through the channel.
struct SealedPacket {
    /// Complete IP + L4 + HMAC envelope + payload bytes, ready for
    /// `sendmmsg`.
    bytes: Vec<u8>,
    /// Destination address for `sendto`. v4 carries the client + send
    /// port; v6 zeroes the port (the AF_INET6 raw socket rejects a
    /// non-zero `sin6_port`).
    dest: SocketAddr,
}

/// How the upload-ingest tasks route a received datagram to the forward
/// target. `Single` is the legacy path — ONE forward socket, ONE target,
/// opaque bytes. `Multi` decodes the 2-byte application-port tag and
/// forwards the untagged body via that port's own forward socket to
/// `(forward_host, port)`. See [`crate::multiport`].
#[derive(Clone)]
enum UploadForwarder {
    Single {
        sock: Arc<UdpSocket>,
        target: SocketAddr,
    },
    Multi(Arc<std::collections::HashMap<u16, (Arc<UdpSocket>, SocketAddr)>>),
}

/// Process-wide sampled counter for multi-port upload datagrams whose
/// application-port tag is not in the tunnel's configured set (config
/// drift between the two sides). Sampled so a wholesale-misconfigured peer
/// doesn't flood the app log.
static UNKNOWN_PORT_UPLOAD_DROPS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn(
    spec: &TunnelSpec,
    resolved: &ResolvedSpec,
    _state: StateSlot,
    _error_reason: ReasonSlot,
    tasks: &mut JoinSet<()>,
    stop_rx: watch::Receiver<bool>,
    mutable_config: MutableConfigSlot,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), SpawnError> {
    let upload_listen = resolved
        .upload_listen_addr
        .expect("validate ensured upload_listen_addr");
    let forward_target = resolved
        .forward_target
        .expect("validate ensured forward_target");
    let send_port = resolved
        .download_send_port
        .expect("validate ensured download_send_port");
    let client_ip = resolved
        .client_real_ip
        .expect("validate ensured client_real_ip");

    // Validate the address family matches the chosen transport.
    let family_check = check_address_family(spec.download_transport, resolved.spoof_ip, client_ip);
    let initial_send_target = family_check?;

    let id = spec.id;
    let name = Arc::new(spec.name.clone());
    let seq_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let icmp_seq_counter = Arc::new(std::sync::atomic::AtomicU32::new(1));
    // Random non-zero u64 read from /dev/urandom once per tunnel start.
    // Sealed into every spoofed download packet's HMAC envelope (see
    // hmac.rs). When the Remote restarts this changes, which is the
    // Client's signal to reset its sliding seq window — that replaced
    // the old wall-clock `ts` check, so a skewed Iran box no longer
    // silently drops every download.
    let session_id = hmac::random_session_id().map_err(SpawnError::Io)?;
    info!(
        tunnel_id = id,
        session_id = format!("0x{session_id:016x}"),
        "remote: spoof session_id generated"
    );
    // Phase R4: pick a random per-tunnel ICMP identifier so a concurrent
    // local `ping` can't collide. The value is logged at INFO so an
    // operator running `tcpdump -nn icmp` can correlate the on-wire
    // identifier with the tunnel it belongs to. For non-ICMP transports
    // we still compute one so the value is available if hot-reload
    // flips the transport later — the Remote side hot-reload triggers
    // an internal restart, but the field stays meaningful.
    let icmp_identifier = crate::icmp_id::pick_identifier(spec.id);
    if matches!(spec.download_transport, Transport::Icmp | Transport::Icmpv6) {
        info!(
            tunnel_id = id,
            transport = match spec.download_transport {
                Transport::Icmp => "icmp",
                Transport::Icmpv6 => "icmpv6",
                _ => unreachable!(),
            },
            echo_mode = ?spec.icmp_echo_mode,
            icmp_identifier,
            "remote: ICMP identifier picked for this tunnel; will appear in tcpdump output"
        );
    }
    let icmp_echo_mode = spec.icmp_echo_mode;

    // v4.0.0 TCP forwarding (single- AND multi-port). Replace the UDP
    // forward/recv flows entirely: client uploads feed the reliability engine
    // (KCP or QUIC), the engine dials forward_target over TCP, and the
    // engine's outbound datagrams are sealed + spoofed down to the Client
    // through the same seal pipeline (one seq stream, one session_id).
    // `spawn_tcp_forward_remote` builds one engine per app port in multi-port
    // mode; all per-port engines share that one seal/send pipeline.
    if resolved.forward_protocol == ForwardProtocol::Tcp {
        return spawn_tcp_forward_remote(
            spec,
            resolved,
            tasks,
            stop_rx,
            mutable_config,
            session_table,
            metrics,
            id,
            name,
            seq_counter,
            icmp_seq_counter,
            session_id,
            icmp_identifier,
            icmp_echo_mode,
            initial_send_target,
            send_port,
            client_ip,
            forward_target,
            upload_listen,
        )
        .await;
    }

    // (2) Forward-target socket. Bind on the same family as the forward
    // target so v6 forward_target works. The download path uses this
    // socket for both directions: send to forward_target on upload,
    // recv from forward_target on download. Bind it first so we have a
    // single shared destination for either upload-listen mode below.
    let forward_bind = if forward_target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let forward_sock = UdpSocket::bind(forward_bind)
        .await
        .map_err(|e| SpawnError::Io(crate::perf::bind_err(e, "remote/forward", forward_target)))?;
    // The forward socket is the busiest one on the Remote — it both
    // sends to forward_target and receives the reply stream. Tune it
    // so a momentary spike doesn't lose reply packets at the kernel.
    crate::perf::tune_socket(&forward_sock, "remote/forward");
    let forward_sock = Arc::new(forward_sock);

    // Multi-port: bind one forward socket PER application port, each
    // targeting `(forward_host, port)`. All sockets share the single seal
    // + send download pipeline (one seq stream, one session_id). The
    // single-port path keeps using the one `forward_sock` above,
    // byte-for-byte unchanged. See [`crate::multiport`].
    //
    // `recv_sources` is the list of `(port, sock)` the download recv side
    // reads replies from; in multi-port each recv loop tags its replies
    // with its port. `forwarder` is how the upload-ingest tasks route a
    // (possibly tagged) datagram to the right forward socket.
    let forward_host = forward_target.ip();
    let (forwarder, recv_sources): (UploadForwarder, Vec<(u16, Arc<UdpSocket>)>) =
        if resolved.multiport() {
            let mut map: std::collections::HashMap<u16, (Arc<UdpSocket>, SocketAddr)> =
                std::collections::HashMap::with_capacity(resolved.ports.len());
            let mut sources: Vec<(u16, Arc<UdpSocket>)> = Vec::with_capacity(resolved.ports.len());
            for &port in &resolved.ports {
                if map.contains_key(&port) {
                    continue;
                }
                let target = SocketAddr::new(forward_host, port);
                let bind = if target.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let sock = UdpSocket::bind(bind).await.map_err(|e| {
                    SpawnError::Io(crate::perf::bind_err(e, "remote/forward", target))
                })?;
                crate::perf::tune_socket(&sock, "remote/forward");
                let sock = Arc::new(sock);
                info!(tunnel_id = id, target = %target,
                    "remote: multi-port forward socket bound");
                map.insert(port, (sock.clone(), target));
                sources.push((port, sock));
            }
            (UploadForwarder::Multi(Arc::new(map)), sources)
        } else {
            (
                UploadForwarder::Single {
                    sock: forward_sock.clone(),
                    target: forward_target,
                },
                vec![(0u16, forward_sock.clone())],
            )
        };

    // (1) Upload listener — UDP (historical default) or SOCKS5/TCP
    // (Phase R9a, paired with the Client's upload_mode='socks5').
    // The UDP path is byte-for-byte unchanged from pre-R9. The TCP
    // path decodes `[u16 BE length][bytes]` frames into UDP payloads
    // and forwards them to forward_target through `forward_sock`.
    match spec.upload_listen_mode {
        UploadListenMode::Udp => {
            let upload_sock = bind_dualstack_udp(upload_listen).map_err(|e| {
                SpawnError::Io(crate::perf::bind_err(e, "remote/upload", upload_listen))
            })?;
            // Enlarge SO_RCVBUF/SO_SNDBUF beyond the 208 KiB Ubuntu
            // default so the upload listener doesn't drop packets at
            // the kernel queue when a tunnel pushes hundreds of
            // Mbit/s. See the `perf` module.
            crate::perf::tune_socket(&upload_sock, "remote/upload");
            let upload_sock = Arc::new(upload_sock);
            info!(tunnel_id = id, addr = %upload_listen,
                family = address_family_label(upload_listen),
                "remote: upload_listen bound (UDP)");

            spawn_upload_task(
                tasks,
                id,
                name.clone(),
                upload_sock.clone(),
                forwarder.clone(),
                session_table.clone(),
                mutable_config.clone(),
                metrics.clone(),
                stop_rx.clone(),
            );
        }
        UploadListenMode::Socks5Tcp => {
            let tcp_listener = TcpListener::bind(upload_listen).await.map_err(|e| {
                SpawnError::Io(crate::perf::bind_err(e, "remote/upload", upload_listen))
            })?;
            // v2.2.0: force-size the LISTENER's buffers BEFORE it accepts.
            // On Linux an accepted socket inherits the listener's
            // SO_RCVBUF/SO_SNDBUF, and — critically — the receive window
            // scale advertised in the SYN-ACK is derived from the receive
            // buffer at accept time. Tuning each accepted socket *after*
            // the handshake (as the keepalive tuning does) is too late to
            // widen the window scale. Sizing the listener here is what lets
            // the Remote advertise a large receive window so the SOCKS5
            // upload's in-flight data isn't capped on a high-RTT path.
            crate::perf::tune_socket(&tcp_listener, "socks5/remote-listen");
            // Pick the inbound SOCKS5 keepalive regime from the download
            // transport so the Remote's accepted sockets mirror the
            // Client's outbound mechanism (v2 matrix): tcp_syn → Bulk
            // timers, icmp/icmpv6 → Latency timers. Single source of truth
            // is `Socks5Profile::for_download`.
            let keepalive = Socks5Profile::for_download(spec.download_transport).keepalive;
            info!(tunnel_id = id, addr = %upload_listen,
                family = address_family_label(upload_listen),
                keepalive = ?keepalive,
                "remote: upload_listen bound (SOCKS5/TCP)");
            spawn_socks5_upload_listener(
                tasks,
                id,
                name.clone(),
                tcp_listener,
                forwarder.clone(),
                session_table.clone(),
                mutable_config.clone(),
                metrics.clone(),
                keepalive,
                stop_rx.clone(),
            );
        }
    }

    // Download-side: forward_sock recv → bounded channel → N seal +
    // spoof-send workers. Each worker owns its own raw send socket so
    // sendmmsg traffic parallelises at the kernel-socket layer. In
    // multi-port mode there is one recv loop per port (each tagging its
    // replies) all feeding the SAME shared seal pipeline — ONE seq
    // stream, ONE session_id.
    let multiport_active = resolved.multiport();
    spawn_download_pipeline(
        tasks,
        spec.download_transport,
        icmp_echo_mode,
        icmp_identifier,
        id,
        name.clone(),
        recv_sources,
        multiport_active,
        session_table.clone(),
        mutable_config.clone(),
        metrics.clone(),
        seq_counter,
        icmp_seq_counter,
        session_id,
        initial_send_target,
        send_port,
        client_ip,
        stop_rx.clone(),
    )?;

    // (4) Idle sweeper.
    spawn_idle_sweeper(
        tasks,
        id,
        spec.idle_timeout_sec,
        session_table.clone(),
        metrics.clone(),
        stop_rx.clone(),
    );

    Ok(())
}

fn address_family_label(addr: SocketAddr) -> &'static str {
    if addr.is_ipv6() {
        "ipv6"
    } else {
        "ipv4"
    }
}

/// Remote-side [`DatagramSink`]: the reliability engine's outbound
/// datagrams (KCP segments / QUIC packets produced from `forward_target`'s
/// reply stream) are sealed + spoofed down to the Client through the same
/// seal pipeline the UDP path uses. Each datagram is assigned the next
/// monotonic `hmac_seq` and routed to `seal_txs[seq % N]`, identical to the
/// UDP recv loop, so wire FIFO and the single send socket are preserved.
///
/// On a multi-port tunnel `tag` is `Some(port)` and each datagram is
/// prefixed with the 2-byte application-port tag (inside the seal, so the
/// tag is HMAC-authenticated for free) before it enters the shared seal
/// pipeline — that is what lets the Client demux this engine's segments to
/// the right port. Single-port leaves `tag` `None` and seals the datagram
/// opaque, wire-identical to before. Every port's engine shares the SAME
/// `seal_txs` + `seq_counter`, so there is ONE seq stream + ONE session_id +
/// ONE send socket for the whole tunnel regardless of port count.
struct RemoteForwardSink {
    seal_txs: Vec<mpsc::Sender<DownloadSpoofJob>>,
    seq_counter: Arc<std::sync::atomic::AtomicU64>,
    icmp_seq_counter: Arc<std::sync::atomic::AtomicU32>,
    max_payload: usize,
    metrics: Arc<TunnelMetrics>,
    tag: Option<u16>,
}

#[async_trait]
impl DatagramSink for RemoteForwardSink {
    async fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        use std::sync::atomic::Ordering;
        let seq = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        let icmp_seq = self.icmp_seq_counter.fetch_add(1, Ordering::Relaxed) as u16;
        let n = self.seal_txs.len().max(1);
        let worker = (seq as usize) % n;
        // Multi-port: prepend the 2-byte application-port tag so the Client
        // can demux this engine's segments after HMAC verify. The tag rides
        // INSIDE the sealed payload (authenticated for free, since the seal
        // hashes the whole payload). Single-port ships it opaque.
        let payload = match self.tag {
            Some(port) => {
                let mut buf = Vec::with_capacity(multiport::PORT_TAG_LEN + datagram.len());
                multiport::encode_tag(port, datagram, &mut buf);
                buf
            }
            None => datagram.to_vec(),
        };
        let job = DownloadSpoofJob {
            payload,
            hmac_seq: seq,
            icmp_seq,
        };
        match self.seal_txs[worker].try_send(job) {
            Ok(()) => {
                self.metrics.record_download(datagram.len(), now_unix());
                Ok(true)
            }
            // Seal channel full — drop; the inner KCP layer retransmits.
            Err(_) => Ok(false),
        }
    }
    fn max_payload(&self) -> usize {
        self.max_payload
    }
}

/// How the TCP-forward upload listeners route a received datagram to a
/// per-port reliability-engine inbox. `Single` is the single-port path —
/// the whole datagram is the one engine's inbound. `Multi` decodes the
/// 2-byte application-port tag and routes the untagged body to that port's
/// engine inbox. Mirrors [`UploadForwarder`] for the UDP forward path.
#[derive(Clone)]
enum TcpUploadRouter {
    Single(forward::InboundTx),
    Multi(Arc<std::collections::HashMap<u16, forward::InboundTx>>),
}

impl TcpUploadRouter {
    /// Resolve which engine inbox a received upload datagram feeds, and the
    /// (possibly untagged) body to deliver. Returns `None` on a too-short or
    /// unknown-port datagram (dropped + sampled-warn, mirroring the UDP
    /// `resolve_upload_forward` path).
    fn route<'a>(
        &'a self,
        datagram: &'a [u8],
        id: i64,
    ) -> Option<(&'a forward::InboundTx, &'a [u8])> {
        match self {
            TcpUploadRouter::Single(inbox) => Some((inbox, datagram)),
            TcpUploadRouter::Multi(map) => {
                let (port, body) = match multiport::decode_tag(datagram) {
                    Some(v) => v,
                    None => {
                        debug!(
                            tunnel_id = id,
                            "remote: multi-port tcp-forward upload datagram too short for port tag"
                        );
                        return None;
                    }
                };
                match map.get(&port) {
                    Some(inbox) => Some((inbox, body)),
                    None => {
                        let prev = UNKNOWN_PORT_UPLOAD_DROPS
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if prev % 1000 == 0 {
                            warn!(
                                tunnel_id = id,
                                port,
                                dropped_total = prev + 1,
                                "remote: multi-port tcp-forward upload tagged with a port that is \
                                 not in this tunnel's configured set — the two sides have different \
                                 port lists; align them"
                            );
                        }
                        None
                    }
                }
            }
        }
    }
}

/// Spawn the chosen reliability engine (KCP or QUIC) for the Remote role
/// over a shared sink + inbox. Used by both the single- and multi-port
/// TCP-forward paths so the engine-selection match lives in one place. Each
/// engine instance is self-contained: its own conv map / connection, its
/// own idle reaper (KCP) or native idle timeout (QUIC), and its own per-conn
/// backpressure — so one slow port can never stall another.
#[allow(clippy::too_many_arguments)]
fn spawn_remote_forward_engine(
    engine: TcpReliabilityEngine,
    tunnel_id: i64,
    idle_timeout_sec: u32,
    max_connections: u32,
    kcp_tuning: crate::spec::KcpTuning,
    quic_tuning: &crate::spec::QuicTuning,
    forward_target: SocketAddr,
    sink: Arc<dyn DatagramSink>,
    inbox_rx: forward::InboundRx,
    tasks: &mut JoinSet<()>,
    stop_rx: &watch::Receiver<bool>,
) {
    let role = forward::EngineRole::Remote { forward_target };
    match engine {
        TcpReliabilityEngine::Kcp => {
            let e = forward::KcpEngine::new(
                forward::EngineConfig {
                    tunnel_id,
                    idle_timeout_sec,
                    max_connections,
                    tuning: kcp_tuning,
                },
                role,
                sink,
            );
            tasks.spawn(e.run(inbox_rx, stop_rx.clone()));
        }
        TcpReliabilityEngine::Quic => {
            let e = forward::QuicEngine::new(
                forward::QuicConfig {
                    tunnel_id,
                    idle_timeout_sec,
                    max_connections,
                    tuning: quic_tuning.clone(),
                },
                role,
                sink,
            );
            tasks.spawn(e.run(inbox_rx, stop_rx.clone()));
        }
    }
}

/// Spin up the seal + single-send pipeline (workers + raw send socket)
/// and return the seal-worker senders. This mirrors the seal/send half of
/// `spawn_download_pipeline` but without the UDP recv loops — the TCP
/// forward engine feeds the returned senders via [`RemoteForwardSink`]
/// instead. The n_workers clamp keeps `SEAL_WORKER_CHANNEL_CAP * workers`
/// within Iran's `SeqWindow`, exactly as the UDP path.
#[allow(clippy::too_many_arguments)]
fn spawn_seal_workers(
    tasks: &mut JoinSet<()>,
    transport: Transport,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    icmp_identifier: u16,
    id: i64,
    name: Arc<String>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    session_id: u64,
    initial_send_target: SendTarget,
    send_port: u16,
    client_ip_for_log: IpAddr,
    stop_rx: watch::Receiver<bool>,
) -> Result<Vec<mpsc::Sender<DownloadSpoofJob>>, SpawnError> {
    let label: &'static str = match transport {
        Transport::Udp => "udp",
        Transport::TcpSyn => "tcp_syn",
        Transport::Icmp => "icmp",
        Transport::Icmpv6 => "icmpv6",
    };
    let send_batch_size = crate::perf::send_batch();
    let requested_workers = crate::perf::per_core_sockets().max(1);
    let max_seal_workers = (hmac::SEQ_WINDOW_SIZE as usize / SEAL_WORKER_CHANNEL_CAP).max(1);
    let n_workers = requested_workers.min(max_seal_workers);

    let mut seal_txs: Vec<mpsc::Sender<DownloadSpoofJob>> = Vec::with_capacity(n_workers);
    let mut seal_rxs: Vec<mpsc::Receiver<DownloadSpoofJob>> = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let (tx, rx) = mpsc::channel::<DownloadSpoofJob>(SEAL_WORKER_CHANNEL_CAP);
        seal_txs.push(tx);
        seal_rxs.push(rx);
    }

    let (sealed_tx, sealed_rx) = mpsc::channel::<SealedPacket>(SEND_QUEUE_CAP);
    let raw_send = open_send_socket_for_transport(transport)?;
    let raw_send_fd = std::os::fd::OwnedFd::from(raw_send);
    let send_sock = Arc::new(AsyncFd::new(raw_send_fd).map_err(SpawnError::Io)?);

    info!(
        tunnel_id = id,
        transport = label,
        dst = %client_ip_for_log,
        port = send_port,
        seal_workers = n_workers,
        "remote: TCP-forward seal + serial send pipeline spinning up"
    );

    for (worker_id, rx) in seal_rxs.into_iter().enumerate() {
        tasks.spawn(download_seal_worker(
            rx,
            sealed_tx.clone(),
            initial_send_target,
            send_port,
            transport,
            icmp_echo_mode,
            icmp_identifier,
            session_id,
            label,
            mutable_config.clone(),
            metrics.clone(),
            id,
            worker_id,
            name.clone(),
            stop_rx.clone(),
        ));
    }
    drop(sealed_tx);
    tasks.spawn(download_send_worker(
        sealed_rx,
        send_sock,
        label,
        metrics.clone(),
        mutable_config.clone(),
        id,
        name.clone(),
        stop_rx.clone(),
        send_batch_size,
    ));
    Ok(seal_txs)
}

/// Bring up the Remote half of a `forward_protocol=tcp` tunnel: one
/// reliability engine (KCP or QUIC) that dials `forward_target` per learned
/// connection, fed by the upload listener and draining its sealed segments
/// to the Client. In multi-port mode there is ONE engine per application
/// port, each dialing its own `(forward_host, port)` and tagging its
/// download datagrams; all engines share the single seal + send pipeline
/// (one seq stream, one session_id, one raw send socket), so the wire-order
/// and anti-replay invariants hold regardless of port count.
#[allow(clippy::too_many_arguments)]
async fn spawn_tcp_forward_remote(
    spec: &TunnelSpec,
    resolved: &ResolvedSpec,
    tasks: &mut JoinSet<()>,
    stop_rx: watch::Receiver<bool>,
    mutable_config: MutableConfigSlot,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
    id: i64,
    name: Arc<String>,
    seq_counter: Arc<std::sync::atomic::AtomicU64>,
    icmp_seq_counter: Arc<std::sync::atomic::AtomicU32>,
    session_id: u64,
    icmp_identifier: u16,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    initial_send_target: SendTarget,
    send_port: u16,
    client_ip_for_log: IpAddr,
    forward_target: SocketAddr,
    upload_listen: SocketAddr,
) -> Result<(), SpawnError> {
    let transport = spec.download_transport;
    let seal_txs = spawn_seal_workers(
        tasks,
        transport,
        icmp_echo_mode,
        icmp_identifier,
        id,
        name.clone(),
        mutable_config.clone(),
        metrics.clone(),
        session_id,
        initial_send_target,
        send_port,
        client_ip_for_log,
        stop_rx.clone(),
    )?;

    let max_payload = (spec.mtu as usize).saturating_sub(multiport::PORT_TAG_LEN);
    let engine = spec.tcp_reliability_engine;
    let kcp_tuning = resolved.forward_kcp.unwrap_or_default();
    let quic_tuning = resolved.forward_quic.clone().unwrap_or_default();

    // Build one reliability engine per application port (multi-port) or a
    // single engine (single-port). Every engine shares the ONE seal pipeline
    // built above, so there is one seq stream + one session_id + one send
    // socket for the whole tunnel; each multi-port engine dials its own
    // `(forward_host, port)` and tags its download datagrams so the Client
    // demuxes them per port. The single-port branch is wire-identical to
    // pre-multi-port (no tag).
    let router = if resolved.multiport() {
        let forward_host = forward_target.ip();
        let mut map: std::collections::HashMap<u16, forward::InboundTx> =
            std::collections::HashMap::with_capacity(resolved.ports.len());
        for &port in &resolved.ports {
            if map.contains_key(&port) {
                continue;
            }
            let target = SocketAddr::new(forward_host, port);
            let (inbox_tx, inbox_rx) = forward::inbound_channel();
            let sink: Arc<dyn DatagramSink> = Arc::new(RemoteForwardSink {
                seal_txs: seal_txs.clone(),
                seq_counter: seq_counter.clone(),
                icmp_seq_counter: icmp_seq_counter.clone(),
                max_payload,
                metrics: metrics.clone(),
                tag: Some(port),
            });
            spawn_remote_forward_engine(
                engine,
                id,
                spec.idle_timeout_sec,
                spec.max_connections,
                kcp_tuning,
                &quic_tuning,
                target,
                sink,
                inbox_rx,
                tasks,
                &stop_rx,
            );
            info!(tunnel_id = id, target = %target, engine = ?engine,
                "remote: multi-port TCP-forward engine spun up");
            map.insert(port, inbox_tx);
        }
        TcpUploadRouter::Multi(Arc::new(map))
    } else {
        let (inbox_tx, inbox_rx) = forward::inbound_channel();
        let sink: Arc<dyn DatagramSink> = Arc::new(RemoteForwardSink {
            seal_txs,
            seq_counter,
            icmp_seq_counter,
            max_payload,
            metrics: metrics.clone(),
            tag: None,
        });
        spawn_remote_forward_engine(
            engine,
            id,
            spec.idle_timeout_sec,
            spec.max_connections,
            kcp_tuning,
            &quic_tuning,
            forward_target,
            sink,
            inbox_rx,
            tasks,
            &stop_rx,
        );
        TcpUploadRouter::Single(inbox_tx)
    };
    info!(tunnel_id = id, engine = ?engine, multiport = resolved.multiport(),
        "remote: TCP-forward engine(s) ready");

    // Upload listener: client→remote datagrams feed the engine inbox(es)
    // (single-port: the one inbox; multi-port: routed by the 2-byte
    // application-port tag) instead of being forwarded to a UDP target.
    match spec.upload_listen_mode {
        UploadListenMode::Udp => {
            let upload_sock = bind_dualstack_udp(upload_listen).map_err(|e| {
                SpawnError::Io(crate::perf::bind_err(e, "remote/upload", upload_listen))
            })?;
            crate::perf::tune_socket(&upload_sock, "remote/upload");
            let upload_sock = Arc::new(upload_sock);
            info!(tunnel_id = id, addr = %upload_listen,
                "remote: TCP-forward upload_listen bound (UDP)");
            spawn_tcp_upload_udp(
                tasks,
                id,
                upload_sock,
                router,
                session_table.clone(),
                metrics.clone(),
                mutable_config.clone(),
                stop_rx.clone(),
            );
        }
        UploadListenMode::Socks5Tcp => {
            let tcp_listener = TcpListener::bind(upload_listen).await.map_err(|e| {
                SpawnError::Io(crate::perf::bind_err(e, "remote/upload", upload_listen))
            })?;
            crate::perf::tune_socket(&tcp_listener, "socks5/remote-listen");
            let keepalive = crate::upload::Socks5Profile::for_download(transport).keepalive;
            info!(tunnel_id = id, addr = %upload_listen,
                "remote: TCP-forward upload_listen bound (SOCKS5/TCP)");
            spawn_tcp_upload_socks5(
                tasks,
                id,
                tcp_listener,
                router,
                session_table.clone(),
                metrics.clone(),
                mutable_config.clone(),
                keepalive,
                stop_rx.clone(),
            );
        }
    }

    spawn_idle_sweeper(
        tasks,
        id,
        spec.idle_timeout_sec,
        session_table,
        metrics,
        stop_rx,
    );
    Ok(())
}

/// UDP upload listener for the TCP-forward path: every received datagram is
/// fed into the engine inbox (single-port) or routed by its 2-byte
/// application-port tag to the matching port's engine inbox (multi-port),
/// instead of being forwarded to a UDP target. Mirrors `spawn_upload_task`'s
/// MTU cap + session accounting.
#[allow(clippy::too_many_arguments)]
fn spawn_tcp_upload_udp(
    tasks: &mut JoinSet<()>,
    id: i64,
    upload_sock: Arc<UdpSocket>,
    router: TcpUploadRouter,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
    mutable_config: MutableConfigSlot,
    mut stop_rx: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            tokio::select! {
                _ = stop_rx.changed() => return,
                res = upload_sock.recv_from(&mut buf) => {
                    let (n, src) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(tunnel_id = id, err = %e, "remote: tcp-forward upload recv");
                            continue;
                        }
                    };
                    // Resolve the engine inbox (stripping the application-port
                    // tag in multi-port mode) BEFORE the MTU cap so the cap
                    // applies to the UNTAGGED body, exactly as the UDP path.
                    let (inbox, body) = match router.route(&buf[..n], id) {
                        Some(v) => v,
                        None => continue,
                    };
                    let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                    if body.len() > mtu.max(64) {
                        continue;
                    }
                    let outcome = session_table.insert_or_refresh(src, src);
                    if matches!(outcome, InsertOutcome::Rejected) {
                        metrics.record_session_reject();
                        continue;
                    }
                    let body_len = body.len();
                    if inbox.try_send(body.to_vec()).is_ok() {
                        metrics.record_upload(body_len, now_unix());
                    } else {
                        metrics.record_upload_drop();
                        if let Some(total) = sampled(&TCP_UPLOAD_INBOX_FULL_DROPS) {
                            warn!(tunnel_id = id, dropped_total = total,
                                "remote: tcp-forward upload dropped — engine inbox full (slow reliability engine)");
                        }
                    }
                }
            }
        }
    });
}

/// SOCKS5/TCP upload listener for the TCP-forward path: accept connections
/// and decode `[u16 BE length][payload]` frames into engine-inbox datagrams,
/// routed per-port by the application-port tag in multi-port mode. Mirrors
/// the framing of `drive_socks5_upload_connection`.
#[allow(clippy::too_many_arguments)]
fn spawn_tcp_upload_socks5(
    tasks: &mut JoinSet<()>,
    id: i64,
    listener: TcpListener,
    router: TcpUploadRouter,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
    mutable_config: MutableConfigSlot,
    keepalive: Socks5KeepaliveProfile,
    mut stop_rx: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => return,
                accept = listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(tunnel_id = id, err = %e, "remote: tcp-forward socks5 accept");
                            continue;
                        }
                    };
                    crate::perf::tune_socks5_tcp_socket(&stream, "socks5/remote-in", keepalive);
                    let router = router.clone();
                    let session_table = session_table.clone();
                    let metrics = metrics.clone();
                    let mutable_config = mutable_config.clone();
                    let conn_stop = stop_rx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = drive_socks5_upload_to_inbox(
                            id, stream, peer, router, session_table, metrics, mutable_config,
                            conn_stop,
                        )
                        .await
                        {
                            warn!(tunnel_id = id, %peer, err = %e,
                                "remote: tcp-forward socks5 upload connection ended with error");
                        }
                    });
                }
            }
        }
    });
}

/// Decode `[u16 len][payload]` frames off one accepted SOCKS5 connection and
/// feed each payload into the engine inbox (single-port) or the matching
/// port's inbox by application-port tag (multi-port).
#[allow(clippy::too_many_arguments)]
async fn drive_socks5_upload_to_inbox(
    id: i64,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: TcpUploadRouter,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
    mutable_config: MutableConfigSlot,
    mut stop_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut stream = BufReader::with_capacity(4 * MAX_UDP_DATAGRAM, stream);
    let mut len_buf = [0u8; 2];
    let mut payload = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => return Ok(()),
            len_res = stream.read_exact(&mut len_buf) => {
                if let Err(e) = len_res {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(e);
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socks5_tcp tcp-forward upload: zero-length frame",
                    ));
                }
                if n > payload.len() {
                    payload.resize(n, 0);
                }
                stream.read_exact(&mut payload[..n]).await?;
                // Resolve the engine inbox (stripping the application-port
                // tag in multi-port mode) BEFORE the MTU cap so the cap
                // applies to the UNTAGGED body.
                let (inbox, body) = match router.route(&payload[..n], id) {
                    Some(v) => v,
                    None => continue,
                };
                let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                if body.len() > mtu.max(64) {
                    continue;
                }
                let outcome = session_table.insert_or_refresh(peer, peer);
                if matches!(outcome, InsertOutcome::Rejected) {
                    metrics.record_session_reject();
                    continue;
                }
                let body_len = body.len();
                if inbox.try_send(body.to_vec()).is_ok() {
                    metrics.record_upload(body_len, now_unix());
                } else {
                    metrics.record_upload_drop();
                    if let Some(total) = sampled(&TCP_UPLOAD_INBOX_FULL_DROPS) {
                        warn!(tunnel_id = id, dropped_total = total,
                            "remote: tcp-forward socks5 upload dropped — engine inbox full (slow reliability engine)");
                    }
                }
            }
        }
    }
}

/// Bind a UDP socket on `addr`, explicitly enabling dual-stack
/// behaviour for IPv6 wildcards so a single tunnel can carry both v4
/// and v6 inbound traffic without depending on the host's
/// /proc/sys/net/ipv6/bindv6only sysctl.
fn bind_dualstack_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Per-transport address-family enforcement. ICMPv6 needs IPv6 on
/// both spoof IP and client real IP; every other transport needs IPv4
/// on both. Returning a single `SendTarget` lets the spawn caller hand
/// the right sockaddr to `sendto` without re-matching at runtime.
fn check_address_family(
    transport: Transport,
    spoof_ip: IpAddr,
    client_ip: IpAddr,
) -> Result<SendTarget, SpawnError> {
    match transport {
        Transport::Udp | Transport::TcpSyn | Transport::Icmp => match (spoof_ip, client_ip) {
            (IpAddr::V4(s), IpAddr::V4(c)) => Ok(SendTarget::V4 {
                spoof: s,
                client: c,
            }),
            _ => Err(SpawnError::Io(io::Error::other(
                "udp/tcp_syn/icmp transports require IPv4 spoof and client addresses",
            ))),
        },
        Transport::Icmpv6 => match (spoof_ip, client_ip) {
            (IpAddr::V6(s), IpAddr::V6(c)) => Ok(SendTarget::V6 {
                spoof: s,
                client: c,
            }),
            _ => Err(SpawnError::Io(io::Error::other(
                "icmpv6 transport requires IPv6 spoof and client addresses",
            ))),
        },
    }
}

#[derive(Clone, Copy)]
enum SendTarget {
    V4 { spoof: Ipv4Addr, client: Ipv4Addr },
    V6 { spoof: Ipv6Addr, client: Ipv6Addr },
}

impl SendTarget {
    /// Rebuild a SendTarget with a new spoof IP while keeping the same
    /// client real IP. Returns `None` if the families don't match
    /// (defensive — the apply_updates path on the tunnel handle
    /// rejects such a spoof-IP family swap, but we double-check here
    /// since this is the actual outbound code path).
    fn with_spoof(self, new_spoof: IpAddr) -> Option<Self> {
        match (self, new_spoof) {
            (SendTarget::V4 { client, .. }, IpAddr::V4(spoof)) => {
                Some(SendTarget::V4 { spoof, client })
            }
            (SendTarget::V6 { client, .. }, IpAddr::V6(spoof)) => {
                Some(SendTarget::V6 { spoof, client })
            }
            _ => None,
        }
    }
}

fn open_send_socket_for_transport(t: Transport) -> Result<socket2::Socket, SpawnError> {
    match t {
        Transport::Udp => udp::open_raw_udp_send_socket().map_err(SpawnError::Io),
        Transport::TcpSyn => tcp_syn::open_raw_tcp_send_socket().map_err(SpawnError::Io),
        Transport::Icmp => icmp::open_raw_icmp_send_socket().map_err(SpawnError::Io),
        Transport::Icmpv6 => icmpv6::open_raw_icmpv6_send_socket().map_err(SpawnError::Io),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_upload_task(
    tasks: &mut JoinSet<()>,
    id: i64,
    name: Arc<String>,
    upload_sock: Arc<UdpSocket>,
    forwarder: UploadForwarder,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    mut stop_rx: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        // See PR #15 for why this is MAX_UDP_DATAGRAM, not mtu.
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    info!(tunnel_id = id, name = %name, "remote: upload task stopping");
                    return;
                }
                res = upload_sock.recv_from(&mut buf) => {
                    let (n, src) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(tunnel_id = id, err = %e, "remote: upload recv");
                            continue;
                        }
                    };
                    // Resolve the forward socket + target (and strip the
                    // application-port tag in multi-port mode) BEFORE the
                    // MTU cap check, so the cap applies to the UNTAGGED
                    // body exactly as on the single-port path.
                    let (fwd_sock, fwd_target, body) =
                        match resolve_upload_forward(&forwarder, &buf[..n], id) {
                            Some(v) => v,
                            None => continue,
                        };
                    // Sample mtu fresh so hot-reload of mtu takes effect
                    // on the next packet.
                    let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                    let payload_cap = mtu.max(64);
                    if body.len() > payload_cap {
                        if let Some(total) = sampled(&OVERSIZED_UPLOAD_DROPS) {
                            warn!(tunnel_id = id, n = body.len(), max = payload_cap, dropped_total = total,
                                "remote: dropping oversized upload packet (raise tunnel MTU or shrink app packet)");
                        }
                        continue;
                    }
                    let outcome = session_table.insert_or_refresh(src, src);
                    if matches!(outcome, InsertOutcome::Rejected) {
                        if let Some(total) = sampled(&SESSION_FULL_DROPS) {
                            warn!(tunnel_id = id, %src, dropped_total = total,
                                "remote: session table full, dropping new session (at max_connections)");
                        }
                        metrics.record_session_reject();
                        continue;
                    }
                    if let Err(e) = fwd_sock.send_to(body, fwd_target).await {
                        if let Some(total) = sampled(&FORWARD_FAILS) {
                            warn!(tunnel_id = id, target = %fwd_target, err = %e, dropped_total = total,
                                "remote: forward to target failed");
                        }
                    } else {
                        // From the Remote's perspective the upstream
                        // direction (toward the forward target) carries
                        // the user's request — that's "upload-ish" in
                        // the Client's framing. Record it on the same
                        // counter so both sides' dashboards report a
                        // symmetric bytes-out number.
                        metrics.record_upload(body.len(), now_unix());
                    }
                }
            }
        }
    });
}

/// Resolve which forward socket + target a received upload datagram goes
/// to, returning the (possibly untagged) body to forward.
///
/// - `Single`: the whole datagram is the body; forward via the one socket
///   to the one target (byte-for-byte the legacy path).
/// - `Multi`: decode the 2-byte application-port tag; the body is the
///   remainder. An unknown / unconfigured port is dropped + warned
///   (sampled), returning `None`.
fn resolve_upload_forward<'a>(
    forwarder: &'a UploadForwarder,
    datagram: &'a [u8],
    id: i64,
) -> Option<(&'a Arc<UdpSocket>, SocketAddr, &'a [u8])> {
    match forwarder {
        UploadForwarder::Single { sock, target } => Some((sock, *target, datagram)),
        UploadForwarder::Multi(map) => {
            let (port, body) = match multiport::decode_tag(datagram) {
                Some(v) => v,
                None => {
                    debug!(
                        tunnel_id = id,
                        "remote: multi-port upload datagram too short for port tag"
                    );
                    return None;
                }
            };
            match map.get(&port) {
                Some((sock, target)) => Some((sock, *target, body)),
                None => {
                    let prev = UNKNOWN_PORT_UPLOAD_DROPS
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if prev % 1000 == 0 {
                        warn!(
                            tunnel_id = id,
                            port,
                            dropped_total = prev + 1,
                            "remote: multi-port upload tagged with a port that is not in this \
                             tunnel's configured set — the two sides have different port lists; \
                             align them"
                        );
                    }
                    None
                }
            }
        }
    }
}

/// SOCKS5 upload-listen path: accept TCP connections on
/// `upload_listen_addr`, decode each `[u16 BE length][payload bytes]`
/// frame, and forward the payload to `forward_target` exactly the way
/// the UDP listener does.
///
/// R9a opened one SOCKS5 TCP connection on the Client side; R9b grew
/// the Client to **N parallel connections**, and the Remote handles
/// every accepted connection as its own independent tokio task. So
/// this listener already scales to N inbound connections — no
/// per-connection capacity bound — and the per-task `forward_sock`
/// is a clone of the shared `Arc<UdpSocket>` so the merged payloads
/// arrive at `forward_target` from one consistent UDP source.
///
/// As of the striping change, a single bulk flow is spread round-robin
/// across all N connections (so one flow uses every uplink), so the
/// merged stream is no longer per-flow in-order — frames from one flow
/// interleave across connections. That is intentional and safe: the
/// forwarded payload is UDP, whose inner protocol (WireGuard, etc.)
/// tolerates reordering. No reassembly is performed or needed here; each
/// `[u16 len][payload]` frame is whole and is forwarded as one datagram.
#[allow(clippy::too_many_arguments)]
fn spawn_socks5_upload_listener(
    tasks: &mut JoinSet<()>,
    id: i64,
    name: Arc<String>,
    listener: TcpListener,
    forwarder: UploadForwarder,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    keepalive: Socks5KeepaliveProfile,
    mut stop_rx: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    info!(tunnel_id = id, name = %name, "remote: socks5 upload listener stopping");
                    return;
                }
                accept = listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(tunnel_id = id, err = %e, "remote: socks5 upload accept");
                            continue;
                        }
                    };
                    // Same SOCKS5 TCP keepalive / USER_TIMEOUT regime as
                    // the Client outbound side (chosen from the download
                    // transport) so an upstream NAT timeout (proxy egress
                    // NAT, transit middlebox) is detected here in seconds
                    // rather than ~120 s.
                    crate::perf::tune_socks5_tcp_socket(&stream, "socks5/remote-in", keepalive);
                    info!(tunnel_id = id, %peer, "remote: socks5 upload connection accepted");
                    let forwarder = forwarder.clone();
                    let session_table = session_table.clone();
                    let mutable_config = mutable_config.clone();
                    let metrics = metrics.clone();
                    let conn_stop_rx = stop_rx.clone();
                    let name = name.clone();
                    tokio::spawn(async move {
                        if let Err(e) = drive_socks5_upload_connection(
                            id,
                            name,
                            stream,
                            peer,
                            forwarder,
                            session_table,
                            mutable_config,
                            metrics,
                            conn_stop_rx,
                        )
                        .await
                        {
                            warn!(tunnel_id = id, %peer, err = %e,
                                "remote: socks5 upload connection ended with error");
                        }
                    });
                }
            }
        }
    });
}

/// Pump frames off one accepted TCP connection. Reads `[u16 length]
/// [payload]` pairs in a loop and forwards each payload to
/// `forward_target` via `forward_sock`. Honours the same mtu cap,
/// session-table insert, and metrics recording as the UDP path so
/// dashboard counters look identical.
#[allow(clippy::too_many_arguments)]
async fn drive_socks5_upload_connection(
    id: i64,
    name: Arc<String>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    forwarder: UploadForwarder,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    mut stop_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    // Wrap the read side in a BufReader so one kernel `read()` can fill a
    // buffer that serves many framed payloads. This complements the
    // Client's TCP-SOCKS5 coalescing: when the Client batches N frames
    // into one TCP segment, the naked `read_exact(2)`+`read_exact(n)` per
    // frame would still cost two syscalls each; the BufReader amortizes
    // those to roughly one `read()` per segment. Correctness is unchanged
    // for the per-frame (latency) mechanisms — `read_exact` reassembles
    // frames across reads either way.
    //
    // v2.2.0: sized to 4× MAX_UDP_DATAGRAM (256 KiB) to match the Client's
    // raised 256 KiB coalesce cap, so one `read()` can absorb a whole
    // coalesced bulk burst instead of ~4 — fewer read syscalls per MB on
    // the bulk TCP-SOCKS5 path. Bounded per connection, so memory stays
    // modest even at high pool sizes.
    let mut stream = BufReader::with_capacity(4 * MAX_UDP_DATAGRAM, stream);
    let mut len_buf = [0u8; 2];
    let mut payload = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, name = %name, %peer,
                    "remote: socks5 upload connection stopping");
                return Ok(());
            }
            len_res = stream.read_exact(&mut len_buf) => {
                if let Err(e) = len_res {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        info!(tunnel_id = id, %peer,
                            "remote: socks5 upload connection closed by peer");
                        return Ok(());
                    }
                    return Err(e);
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                if n == 0 {
                    // Zero-length frames are a protocol violation —
                    // they'd hang the reader. Close the connection so
                    // the Client reconnects fresh.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socks5_tcp upload: zero-length frame",
                    ));
                }
                if n > payload.len() {
                    // Defensive: should never happen because the
                    // Client caps frames at u16::MAX which is
                    // already > MAX_UDP_DATAGRAM. But keep the buf
                    // dynamic so a future framing change can't UB.
                    payload.resize(n, 0);
                }
                stream.read_exact(&mut payload[..n]).await?;
                // Resolve the forward socket + target (and strip the
                // application-port tag in multi-port mode) BEFORE the MTU
                // cap check so the cap applies to the UNTAGGED body.
                let (fwd_sock, fwd_target, body) =
                    match resolve_upload_forward(&forwarder, &payload[..n], id) {
                        Some(v) => v,
                        None => continue,
                    };
                let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                let payload_cap = mtu.max(64);
                if body.len() > payload_cap {
                    if let Some(total) = sampled(&OVERSIZED_UPLOAD_DROPS) {
                        warn!(tunnel_id = id, n = body.len(), max = payload_cap, dropped_total = total,
                            "remote: dropping oversized socks5_tcp upload frame (raise tunnel MTU)");
                    }
                    continue;
                }
                // The SOCKS5 upload doesn't carry a real source
                // peer per frame — every frame from this TCP
                // connection is logically the same upstream session
                // from the operator's perspective. Use the TCP peer
                // as the session key so insert/refresh increments
                // sessions sensibly and idle eviction can sweep when
                // the connection drops.
                let outcome = session_table.insert_or_refresh(peer, peer);
                if matches!(outcome, InsertOutcome::Rejected) {
                    if let Some(total) = sampled(&SESSION_FULL_DROPS) {
                        warn!(tunnel_id = id, %peer, dropped_total = total,
                            "remote: session table full, dropping new socks5 upload session (at max_connections)");
                    }
                    metrics.record_session_reject();
                    continue;
                }
                if let Err(e) = fwd_sock.send_to(body, fwd_target).await {
                    if let Some(total) = sampled(&FORWARD_FAILS) {
                        warn!(tunnel_id = id, target = %fwd_target, err = %e, dropped_total = total,
                            "remote: socks5_tcp forward to target failed");
                    }
                } else {
                    metrics.record_upload(body.len(), now_unix());
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_download_pipeline(
    tasks: &mut JoinSet<()>,
    transport: Transport,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    icmp_identifier: u16,
    id: i64,
    name: Arc<String>,
    recv_sources: Vec<(u16, Arc<UdpSocket>)>,
    multiport: bool,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    seq_counter: Arc<std::sync::atomic::AtomicU64>,
    icmp_seq_counter: Arc<std::sync::atomic::AtomicU32>,
    session_id: u64,
    initial_send_target: SendTarget,
    send_port: u16,
    client_ip_for_log: IpAddr,
    stop_rx: watch::Receiver<bool>,
) -> Result<(), SpawnError> {
    let label: &'static str = match transport {
        Transport::Udp => "udp",
        Transport::TcpSyn => "tcp_syn",
        Transport::Icmp => "icmp",
        Transport::Icmpv6 => "icmpv6",
    };
    let send_batch_size = crate::perf::send_batch();
    // Seal fan-out reorder budget. Each seal worker can fall at most
    // `SEAL_WORKER_CHANNEL_CAP` jobs of its own seq-subset behind its
    // peers, so the worst-case wire reorder when its sealed output
    // reaches the single send worker is `SEAL_WORKER_CHANNEL_CAP *
    // n_workers` seqs. Iran's anti-replay `SeqWindow` is exactly
    // `hmac::SEQ_WINDOW_SIZE` (1024) slots wide; a sealed packet that
    // lands more than that many seqs late is dropped there as
    // replay/too-old — silent legit-traffic loss. We therefore cap the
    // seal-worker count so `SEAL_WORKER_CHANNEL_CAP * n_workers <=
    // hmac::SEQ_WINDOW_SIZE`. Referencing `hmac::SEQ_WINDOW_SIZE`
    // directly keeps the two constants from silently drifting apart.
    //
    // This clamps ONLY the Remote's seal fan-out. The Client's verify
    // workers (client.rs) each own a full independent 1024-slot window,
    // so they scale freely and are unaffected.
    let requested_workers = crate::perf::per_core_sockets().max(1);
    let max_seal_workers = (hmac::SEQ_WINDOW_SIZE as usize / SEAL_WORKER_CHANNEL_CAP).max(1);
    let n_workers = requested_workers.min(max_seal_workers);
    if n_workers < requested_workers {
        info!(
            tunnel_id = id,
            transport = label,
            requested = requested_workers,
            seal_workers = n_workers,
            seal_channel_cap = SEAL_WORKER_CHANNEL_CAP,
            seq_window = hmac::SEQ_WINDOW_SIZE,
            "remote: seal pool capped below SUBLYNE_PER_CORE_SOCKETS to keep the \
             seal fan-out reorder budget (SEAL_WORKER_CHANNEL_CAP * workers) \
             within Iran's SeqWindow"
        );
    }

    // Pipeline shape: recv → N seal workers → 1 send worker → wire.
    //
    // Recv loop assigns each reply a monotonic `hmac_seq` and routes
    // the job to `seal_workers[hmac_seq % N]`. Each seal worker does
    // HMAC-SHA256 + IP/L4 build into a fresh `Vec<u8>` and pushes a
    // `SealedPacket` to the shared `sealed_tx`. The single send
    // worker drains `sealed_rx` greedily up to `send_batch_size` and
    // makes one `sendmmsg` per batch, preserving wire FIFO at the
    // socket level.
    //
    // Why parallelise the seal but not the send: HMAC + checksum is
    // the CPU-bound step (measurable on the new 4-vCPU Xeon). The
    // sendmmsg syscall itself is cheap (16 packets per call) and a
    // single-task sender keeps wire order monotonic enough for
    // Iran's per-worker `SeqWindow` to absorb. Earlier round 2 tried
    // fan-out at the SEND socket (each worker emitting through its
    // own raw socket) and that produced wire-skew >128 seqs because
    // workers' send timing was unrelated. This design keeps the
    // single send socket so the wire is FIFO from the kernel's
    // perspective; the only reorder source is seal-completion
    // disparity, which `SEAL_WORKER_CHANNEL_CAP` bounds.
    //
    // n_workers comes from `SUBLYNE_PER_CORE_SOCKETS` (defaults to
    // `available_parallelism()`). Setting it to 1 reverts to the
    // historical single-seal-task behaviour without code changes.
    let mut seal_txs: Vec<mpsc::Sender<DownloadSpoofJob>> = Vec::with_capacity(n_workers);
    let mut seal_rxs: Vec<mpsc::Receiver<DownloadSpoofJob>> = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let (tx, rx) = mpsc::channel::<DownloadSpoofJob>(SEAL_WORKER_CHANNEL_CAP);
        seal_txs.push(tx);
        seal_rxs.push(rx);
    }

    let (sealed_tx, sealed_rx) = mpsc::channel::<SealedPacket>(SEND_QUEUE_CAP);

    // One raw send socket — exclusively owned by the send worker so
    // wire FIFO is preserved at the syscall layer.
    let raw_send = open_send_socket_for_transport(transport)?;
    let raw_send_fd = std::os::fd::OwnedFd::from(raw_send);
    let send_sock = Arc::new(AsyncFd::new(raw_send_fd).map_err(SpawnError::Io)?);

    info!(
        tunnel_id = id,
        transport = label,
        dst = %client_ip_for_log,
        port = send_port,
        send_batch = send_batch_size,
        seal_workers = n_workers,
        seal_channel_cap = SEAL_WORKER_CHANNEL_CAP,
        send_queue_cap = SEND_QUEUE_CAP,
        "remote: spoof send socket ready, parallel seal + serial send pipeline spinning up"
    );

    // One recv loop per forward source. Single-port has exactly one
    // source (port tag = 0, unused); multi-port has one per app port,
    // each tagging its replies with that port. All recv loops feed the
    // SAME `seal_txs` via the SHARED `seq_counter`, so there is ONE seq
    // stream + ONE session_id for the whole tunnel regardless of port
    // count. The seal/send pipeline below is unchanged.
    for (port, forward_sock) in recv_sources {
        tasks.spawn(spawn_download_recv_loop(
            forward_sock,
            port,
            multiport,
            seal_txs.clone(),
            session_table.clone(),
            mutable_config.clone(),
            metrics.clone(),
            seq_counter.clone(),
            icmp_seq_counter.clone(),
            id,
            name.clone(),
            label,
            stop_rx.clone(),
        ));
    }

    for (worker_id, rx) in seal_rxs.into_iter().enumerate() {
        tasks.spawn(download_seal_worker(
            rx,
            sealed_tx.clone(),
            initial_send_target,
            send_port,
            transport,
            icmp_echo_mode,
            icmp_identifier,
            session_id,
            label,
            mutable_config.clone(),
            metrics.clone(),
            id,
            worker_id,
            name.clone(),
            stop_rx.clone(),
        ));
    }
    // Drop the spawner's clone so the channel closes after every seal
    // worker has dropped its `sealed_tx`, which lets the send worker
    // exit cleanly on tunnel stop.
    drop(sealed_tx);

    tasks.spawn(download_send_worker(
        sealed_rx,
        send_sock,
        label,
        metrics.clone(),
        mutable_config.clone(),
        id,
        name.clone(),
        stop_rx.clone(),
        send_batch_size,
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn spawn_download_recv_loop(
    forward_sock: Arc<UdpSocket>,
    port: u16,
    multiport: bool,
    seal_txs: Vec<mpsc::Sender<DownloadSpoofJob>>,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    seq_counter: Arc<std::sync::atomic::AtomicU64>,
    icmp_seq_counter: Arc<std::sync::atomic::AtomicU32>,
    id: i64,
    name: Arc<String>,
    label: &'static str,
    mut stop_rx: watch::Receiver<bool>,
) {
    // Drain the forward-reply stream with `recvmmsg` (one syscall per
    // batch) instead of `recv_from` (one syscall per datagram). This is the
    // busiest socket on the Remote — it both sends to forward_target and
    // receives the entire reply stream that becomes the spoofed download —
    // and the old single-datagram loop could not empty SO_RCVBUF fast
    // enough under a bursty 1 Gbps reply stream, so the kernel silently
    // dropped the overflow before the dataplane ever saw it. This matches
    // the already-batched send side and the Client raw-recv loop. The batch
    // size is the existing `SUBLYNE_RECV_BATCH` knob (default 16); set it to
    // 1 to recover the historical one-at-a-time drain.
    let mut batch = batch::RecvBatch::for_udp(crate::perf::recv_batch());
    let raw_fd = forward_sock.as_raw_fd();
    // Per-task scratch reused for the tagged reply on the multi-port path.
    // Never allocated on the single-port path.
    let mut tagged: Vec<u8> = Vec::new();
    let n_workers = seal_txs.len().max(1);
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, name = %name, transport = label,
                    "remote: download recv stopping");
                return;
            }
            ready = forward_sock.readable() => {
                if let Err(e) = ready {
                    warn!(tunnel_id = id, err = %e, "remote: forward readable");
                    continue;
                }
                let received = match forward_sock
                    .try_io(Interest::READABLE, || batch::recvmmsg(raw_fd, &mut batch))
                {
                    Ok(n) => n,
                    // Spurious wake / buffer already drained — re-arm.
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        warn!(tunnel_id = id, err = %e, "remote: forward recvmmsg");
                        continue;
                    }
                };
                // Sample mtu fresh once per batch so a hot-reload of mtu
                // takes effect on the next batch.
                let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                let payload_cap = mtu.max(64);
                for i in 0..received {
                    let n = batch.slots[i].len;
                    let data = &batch.slots[i].buf[..n];
                    // Reply from the forward target is an "ingress" event
                    // on the download direction — record it before any
                    // further work so even a drop-by-no-session is counted.
                    metrics.record_download(n, now_unix());
                    if n > payload_cap {
                        warn!(tunnel_id = id, n, max = payload_cap,
                            "remote: dropping oversized forward reply (raise tunnel MTU)");
                        continue;
                    }
                    if session_table.any_session().is_none() {
                        // Per-packet hot-path log: until the first upload
                        // establishes a session, every forward-target reply
                        // hits this branch. trace! (not debug!) so flipping
                        // the panel to DEBUG doesn't flood the log with one
                        // line per spoofed download attempt.
                        trace!(tunnel_id = id, transport = label,
                            "remote: dropped reply with no live session");
                        continue;
                    }
                    let seq = seq_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let icmp_seq16 = icmp_seq_counter
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        as u16;
                    // Single-port: seal the reply opaque (wire-identical).
                    // Multi-port: prepend the 2-byte application-port tag so
                    // the Client can demux it after HMAC verify. The tag is
                    // inside the sealed payload, so it is authenticated for
                    // free (the seal hashes SHA256(payload)).
                    let payload = if multiport {
                        multiport::encode_tag(port, data, &mut tagged);
                        tagged.clone()
                    } else {
                        data.to_vec()
                    };
                    let job = DownloadSpoofJob {
                        payload,
                        hmac_seq: seq,
                        icmp_seq: icmp_seq16,
                    };
                    // Route by `seq % N` so each seal worker sees a
                    // strictly-monotonic subset of seqs. Combined with the
                    // small `SEAL_WORKER_CHANNEL_CAP`, this bounds the
                    // wire-order skew that reaches Iran's per-worker
                    // `SeqWindow`. Batching the recv does not change this:
                    // seqs are still assigned one-per-datagram in arrival
                    // order and the single send socket preserves wire FIFO.
                    let worker = (seq as usize) % n_workers;
                    if let Err(e) = seal_txs[worker].try_send(job) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                metrics.record_seal_drop();
                                warn!(tunnel_id = id, transport = label, worker,
                                    "remote: seal channel full, dropping spoof reply");
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                info!(tunnel_id = id, transport = label, worker,
                                    "remote: seal channel closed, recv exiting");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One of N parallel HMAC-seal + packet-build workers. Drains its own
/// bounded input channel, computes the HMAC envelope and assembles the
/// full IP + L4 + envelope bytes into a fresh `Vec<u8>`, then moves a
/// [`SealedPacket`] through `sealed_tx` to the single send worker.
///
/// The per-packet `Vec<u8>` allocation is intentional — the bytes have
/// to leave this task by value through the channel, so a reusable
/// scratch wouldn't help. The HMAC clone + SHA-256 + checksum work
/// dwarfs the allocation cost.
#[allow(clippy::too_many_arguments)]
async fn download_seal_worker(
    mut rx: mpsc::Receiver<DownloadSpoofJob>,
    sealed_tx: mpsc::Sender<SealedPacket>,
    initial_send_target: SendTarget,
    send_port: u16,
    transport: Transport,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    icmp_identifier: u16,
    session_id: u64,
    label: &'static str,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    id: i64,
    worker_id: usize,
    name: Arc<String>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let initial_mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
    // Reuse one scratch buffer for the HMAC envelope across packets in
    // this worker; the per-packet `packet_buf` has to be freshly
    // allocated because it moves through the channel to the send
    // worker.
    // +PORT_TAG_LEN so a full-MTU multi-port reply (tag + body, sealed)
    // fits without a one-time per-worker realloc; harmless for single-port.
    let mut sealed_scratch: Vec<u8> =
        Vec::with_capacity(initial_mtu + crate::hmac::OVERHEAD + crate::multiport::PORT_TAG_LEN);
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, worker = worker_id, name = %name, transport = label,
                    "remote: seal worker stopping");
                return;
            }
            job = rx.recv() => {
                let job = match job {
                    Some(j) => j,
                    None => {
                        info!(tunnel_id = id, worker = worker_id,
                            "remote: seal channel closed, worker exiting");
                        return;
                    }
                };
                // Snapshot mutable config so hot-reload of PSK / spoof
                // IP / spoof port takes effect on the next packet.
                let (psk, spoof_ip, spoof_src_port) = {
                    let cfg = mutable_config.read().expect("mutable_config read");
                    (cfg.psk.clone(), cfg.spoof_ip, cfg.spoof_port)
                };
                let send_target = match initial_send_target.with_spoof(spoof_ip) {
                    Some(t) => t,
                    None => {
                        warn!(tunnel_id = id, worker = worker_id, transport = label, %spoof_ip,
                            "remote: hot-reloaded spoof_ip family does not match transport, dropping");
                        continue;
                    }
                };
                hmac::seal_with(&psk, session_id, job.hmac_seq, &job.payload, &mut sealed_scratch);
                let mut packet_buf: Vec<u8> = Vec::with_capacity(initial_mtu + 128);
                build_for_transport(
                    transport,
                    icmp_echo_mode,
                    icmp_identifier,
                    spoof_src_port,
                    send_port,
                    send_target,
                    job.hmac_seq,
                    job.icmp_seq,
                    &sealed_scratch,
                    &mut packet_buf,
                );
                let dest = match send_target {
                    SendTarget::V4 { client, .. } => {
                        SocketAddr::V4(std::net::SocketAddrV4::new(client, send_port))
                    }
                    SendTarget::V6 { client, .. } => {
                        SocketAddr::V6(std::net::SocketAddrV6::new(client, 0, 0, 0))
                    }
                };
                let sealed = SealedPacket { bytes: packet_buf, dest };
                if let Err(e) = sealed_tx.try_send(sealed) {
                    match e {
                        mpsc::error::TrySendError::Full(_) => {
                            metrics.record_send_drop(1);
                            warn!(tunnel_id = id, worker = worker_id, transport = label,
                                "remote: send queue full, dropping sealed packet");
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            info!(tunnel_id = id, worker = worker_id,
                                "remote: send queue closed, seal worker exiting");
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Single send worker. Drains the shared sealed-packet queue, packs
/// up to `send_batch_size` packets into a `SendBatch`, and issues one
/// `sendmmsg` per batch. Wire order = queue pop order ≈ seal-
/// completion order ≈ HMAC-seq order with `n_workers`-bounded skew.
#[allow(clippy::too_many_arguments)]
async fn download_send_worker(
    mut sealed_rx: mpsc::Receiver<SealedPacket>,
    raw_send: Arc<AsyncFd<std::os::fd::OwnedFd>>,
    label: &'static str,
    metrics: Arc<TunnelMetrics>,
    mutable_config: MutableConfigSlot,
    id: i64,
    name: Arc<String>,
    mut stop_rx: watch::Receiver<bool>,
    send_batch_size: usize,
) {
    let initial_mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
    // Slot buf must hold IP (20 v4 / 40 v6) + L4 (TCP 20, UDP 8, ICMP
    // 8) + HMAC envelope (32 B) + payload (up to mtu). 128 B headroom
    // covers worst case; if a sealed packet pushes past capacity the
    // slot's Vec just grows.
    let slot_buf_size = initial_mtu + 128;
    let mut send_batch = SendBatch::new(send_batch_size, slot_buf_size);
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, name = %name, transport = label,
                    "remote: send worker stopping");
                return;
            }
            sealed = sealed_rx.recv() => {
                let first = match sealed {
                    Some(s) => s,
                    None => {
                        info!(tunnel_id = id, transport = label,
                            "remote: send queue closed, send worker exiting");
                        return;
                    }
                };
                send_batch.reset();
                stage_sealed(&first, &mut send_batch.slots[0]);
                let mut count = 1;
                // Greedy drain more sealed packets without awaiting so
                // we fill the batch up to `send_batch_size`.
                while count < send_batch.capacity() {
                    match sealed_rx.try_recv() {
                        Ok(s) => {
                            stage_sealed(&s, &mut send_batch.slots[count]);
                            count += 1;
                        }
                        Err(_) => break,
                    }
                }
                // Drain the staged prefix `[0..count]` to the wire,
                // treating transient back-pressure as BOUNDED back-
                // pressure rather than loss — without ever reordering.
                //
                //  * Partial accept (kernel took n < count): keep the
                //    un-sent tail [n..count], compact it to the front
                //    via `shift_unsent_to_front`, and re-send THOSE
                //    first on the next attempt. Wire FIFO is preserved
                //    because the tail keeps its order and goes out
                //    ahead of any newly-drained packet.
                //  * WouldBlock: await socket writability and retry the
                //    SAME un-sent prefix; we never drain new packets
                //    until the current prefix is fully on the wire.
                //  * Hard send error: that prefix is genuinely lost —
                //    count it and warn! (visible at INFO), then move on.
                //
                // Upstream `SEND_QUEUE_CAP` bounds memory: while this
                // loop spins on a stalled socket, `sealed_rx` simply
                // fills and seal workers apply natural back-pressure.
                // `MAX_WOULD_BLOCK_RETRIES` caps a truly dead socket so
                // a single batch can't wedge the worker forever.
                const MAX_WOULD_BLOCK_RETRIES: u32 = 64;
                let mut would_block_retries: u32 = 0;
                while count > 0 {
                    // Abort the drain promptly if a stop arrives mid-batch
                    // (operator Stop / internal restart) instead of parking on
                    // a wedged kernel send queue for up to
                    // MAX_WOULD_BLOCK_RETRIES writable() cycles — which made
                    // tunnel shutdown appear to hang under a stalled link.
                    let writable = tokio::select! {
                        biased;
                        _ = stop_rx.changed() => {
                            metrics.record_send_drop(count as u64);
                            return;
                        }
                        w = raw_send.writable() => w,
                    };
                    let result = match writable {
                        Ok(mut guard) => guard.try_io(|fd| {
                            batch::sendmmsg(fd.get_ref().as_raw_fd(), &mut send_batch, count)
                        }),
                        Err(e) => {
                            metrics.record_send_drop(count as u64);
                            warn!(tunnel_id = id, err = %e, transport = label, dropped = count,
                                "remote: raw writable awaiter failed, dropping batch");
                            break;
                        }
                    };
                    match result {
                        Ok(Ok(n)) => {
                            for _ in 0..n {
                                metrics.record_transport_packet(label);
                            }
                            would_block_retries = 0;
                            if n >= count {
                                // Whole prefix accepted — done.
                                break;
                            }
                            // Partial accept: requeue the unsent tail to
                            // the front and re-send it first next round.
                            count = send_batch.shift_unsent_to_front(n, count);
                        }
                        Ok(Err(e)) => {
                            metrics.record_send_drop(count as u64);
                            warn!(tunnel_id = id, err = %e, transport = label, dropped = count,
                                "remote: sendmmsg failed, dropping batch");
                            break;
                        }
                        Err(_would_block) => {
                            // The AsyncFd readiness guard said writable
                            // but the syscall still returned EAGAIN
                            // (kernel send queue full). Loop: the next
                            // `writable().await` parks until the kernel
                            // drains, so this is bounded back-pressure,
                            // not a busy spin.
                            would_block_retries += 1;
                            if would_block_retries >= MAX_WOULD_BLOCK_RETRIES {
                                metrics.record_send_drop(count as u64);
                                warn!(tunnel_id = id, transport = label, dropped = count,
                                    retries = would_block_retries,
                                    "remote: sendmmsg persistently blocked, dropping batch");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Copy a `SealedPacket` into a `SendBatch` slot. The seal + build
/// work is already done by the seal worker; this only memcpy's the
/// bytes and sets the destination sockaddr.
fn stage_sealed(sealed: &SealedPacket, slot: &mut crate::batch::SendSlot) {
    slot.buf.clear();
    slot.buf.extend_from_slice(&sealed.bytes);
    slot.len = sealed.bytes.len();
    slot.set_dest(sealed.dest);
    slot.active = true;
}

#[allow(clippy::too_many_arguments)]
fn build_for_transport(
    transport: Transport,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    icmp_identifier: u16,
    src_port: u16,
    dst_port: u16,
    send_target: SendTarget,
    hmac_seq: u64,
    icmp_seq: u16,
    sealed: &[u8],
    out: &mut Vec<u8>,
) {
    match (transport, send_target) {
        (Transport::Udp, SendTarget::V4 { spoof, client }) => {
            udp::build_packet(spoof, src_port, client, dst_port, sealed, out);
        }
        (Transport::TcpSyn, SendTarget::V4 { spoof, client }) => {
            tcp_syn::build_packet(spoof, src_port, client, dst_port, hmac_seq, sealed, out);
        }
        (Transport::Icmp, SendTarget::V4 { spoof, client }) => {
            icmp::build_packet(
                spoof,
                icmp_identifier,
                client,
                dst_port,
                icmp_seq,
                icmp_echo_mode,
                sealed,
                out,
            );
        }
        (Transport::Icmpv6, SendTarget::V6 { spoof, client }) => {
            icmpv6::build_packet(
                spoof,
                icmp_identifier,
                client,
                dst_port,
                icmp_seq,
                icmp_echo_mode,
                sealed,
                out,
            );
        }
        // The address-family check in `check_address_family` rules out
        // every other combination before we reach this builder; an
        // assertion here would panic at runtime under misuse.
        _ => unreachable!("address family mismatch escaped validate()"),
    }
}

fn spawn_idle_sweeper(
    tasks: &mut JoinSet<()>,
    id: i64,
    idle_timeout_sec: u32,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let timeout = idle_timeout_sec.max(1);
    tasks.spawn(async move {
        let tick = Duration::from_secs((timeout / 4).max(1) as u64);
        loop {
            if sleep_or_stopped(tick, &mut stop_rx).await {
                return;
            }
            let n = session_table.evict_idle(std::time::Instant::now());
            if n > 0 {
                debug!(
                    tunnel_id = id,
                    evicted = n,
                    remaining = session_table.len(),
                    "remote: evicted idle sessions"
                );
            }
            metrics.set_active_sessions(session_table.len() as u32);
        }
    });
}

#[cfg(test)]
mod tests {
    //! Deterministic coverage of the production multi-port TCP-forward upload
    //! routing (`TcpUploadRouter::route`). The loopback integration tests use
    //! their own routing pipe and run separate QUIC endpoints per port, so a
    //! misroute there only ever surfaces as a timeout (v4.0.0 caveat). This
    //! exercises the REAL router decode directly, so a tag/route regression
    //! fails loudly and instantly instead of as a slow timeout.

    use super::*;
    use std::collections::HashMap;

    /// Single-port: the whole datagram is the body and goes to the one inbox.
    #[test]
    fn router_single_delivers_whole_datagram() {
        let (tx, mut rx) = forward::inbound_channel();
        let router = TcpUploadRouter::Single(tx);
        let dg = b"opaque-kcp-or-quic-bytes";
        let (inbox, body) = router.route(dg, 1).expect("single must route");
        assert_eq!(body, dg, "single-port body is the whole datagram (no tag)");
        inbox.try_send(b"probe".to_vec()).unwrap();
        assert_eq!(rx.try_recv().unwrap(), b"probe".to_vec());
    }

    /// Multi-port: a correctly-tagged datagram strips the 2-byte tag and routes
    /// to exactly that port's inbox — and to no other.
    #[test]
    fn router_multi_routes_by_tag_to_the_right_inbox() {
        let (tx_a, mut rx_a) = forward::inbound_channel();
        let (tx_b, mut rx_b) = forward::inbound_channel();
        let mut map: HashMap<u16, forward::InboundTx> = HashMap::new();
        map.insert(8001, tx_a);
        map.insert(8002, tx_b);
        let router = TcpUploadRouter::Multi(Arc::new(map));

        // Port 8001 payload.
        let mut dg_a = Vec::new();
        multiport::encode_tag(8001, b"alpha", &mut dg_a);
        let (inbox_a, body_a) = router.route(&dg_a, 1).expect("port 8001 must route");
        assert_eq!(body_a, b"alpha", "tag must be stripped, leaving the body");
        inbox_a.try_send(b"to-a".to_vec()).unwrap();
        assert_eq!(
            rx_a.try_recv().unwrap(),
            b"to-a".to_vec(),
            "routed to A's inbox"
        );
        assert!(rx_b.try_recv().is_err(), "must NOT cross-deliver to B");

        // Port 8002 payload.
        let mut dg_b = Vec::new();
        multiport::encode_tag(8002, b"bravo", &mut dg_b);
        let (inbox_b, body_b) = router.route(&dg_b, 1).expect("port 8002 must route");
        assert_eq!(body_b, b"bravo");
        inbox_b.try_send(b"to-b".to_vec()).unwrap();
        assert_eq!(
            rx_b.try_recv().unwrap(),
            b"to-b".to_vec(),
            "routed to B's inbox"
        );
        assert!(rx_a.try_recv().is_err(), "must NOT cross-deliver to A");
    }

    /// Multi-port: a datagram tagged with a port not in the configured set is
    /// dropped (config drift between the two sides), not misrouted.
    #[test]
    fn router_multi_drops_unknown_port() {
        let (tx_a, _rx_a) = forward::inbound_channel();
        let mut map: HashMap<u16, forward::InboundTx> = HashMap::new();
        map.insert(8001, tx_a);
        let router = TcpUploadRouter::Multi(Arc::new(map));
        let mut dg = Vec::new();
        multiport::encode_tag(9999, b"orphan", &mut dg);
        assert!(
            router.route(&dg, 1).is_none(),
            "unknown port must be dropped"
        );
    }

    /// Multi-port: a datagram too short to carry the 2-byte tag is dropped.
    #[test]
    fn router_multi_drops_too_short() {
        let (tx_a, _rx_a) = forward::inbound_channel();
        let mut map: HashMap<u16, forward::InboundTx> = HashMap::new();
        map.insert(8001, tx_a);
        let router = TcpUploadRouter::Multi(Arc::new(map));
        assert!(
            router.route(&[0u8], 1).is_none(),
            "too-short must be dropped"
        );
        assert!(router.route(&[], 1).is_none(), "empty must be dropped");
    }
}
