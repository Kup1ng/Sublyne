//! Client-side tunnel actor.
//!
//! Three concurrent flows run inside one tunnel:
//!
//! 1. **Upload listener.** Bind a regular UDP socket on
//!    `local_listen_addr`. When an end-user packet arrives, record the
//!    sender in the session table and forward the payload to
//!    `upload_target_addr` via a second UDP socket whose SO_MARK is
//!    set to the per-tunnel fwmark (so it egresses through WG).
//!
//! 2. **Download receiver.** Open a raw socket whose IP-protocol
//!    matches the configured `download_transport` (UDP, TCP, ICMP, or
//!    ICMPv6), read every matching packet on the host via batched
//!    `recvmmsg`, filter by destination port / ICMP identifier and
//!    source IP/port, then hand the sealed body to one of N HMAC
//!    verify-and-deliver workers via a bounded `mpsc` channel. Each
//!    worker takes a brief shared `Mutex<SeqWindow>` for replay
//!    protection and delivers the inner payload back to the end user
//!    via the listener socket.
//!
//! 3. **Idle sweeper.** Every `idle_timeout / 4` seconds, evict
//!    sessions whose `last_seen` is older than `idle_timeout`.
//!
//! ## Why fan out verify workers, not raw recv sockets (R2)
//!
//! Linux raw sockets bound to `IPPROTO_{UDP,TCP,ICMP,ICMPV6}` deliver a
//! copy of every matching packet to **every** raw socket of the same
//! protocol on the host — see `net/ipv4/raw.c::raw_local_deliver`.
//! `SO_REUSEPORT` on raw sockets does not shard delivery (its hashing
//! kicks in only for port-bound `SOCK_DGRAM` listeners). Opening N raw
//! recv sockets therefore costs N× the kernel→user copies for the same
//! traffic, the opposite of what we want.
//!
//! Instead we keep **one** raw recv socket per transport and fan out
//! the CPU-heavy work — HMAC verify + payload SHA-256 + replay check —
//! across N tokio worker tasks via a bounded `mpsc` channel. The
//! single recv loop drains the kernel buffer with `recvmmsg(16)`, so
//! kernel-side throughput is not the bottleneck even at 200 Mbit/s.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, trace, warn};

use crate::batch::{self, RecvBatch};
use crate::hmac::{self, HmacKey, OpenError, SeqWindow};
use crate::manager::SpawnError;
use crate::metrics::TunnelMetrics;
use crate::multiport;
use crate::protocol::TunnelState;
use crate::session::{InsertOutcome, SessionTable};
use crate::spec::{ResolvedSpec, Transport, TunnelSpec};
use crate::time_util::now_unix;
use crate::transport::udp::MAX_UDP_DATAGRAM;
use crate::transport::{icmp, icmpv6, tcp_syn, udp, ParsedInbound};
use crate::upload::{SessionKey, UploadTransport};

use super::{sleep_or_stopped, MutableConfigSlot, ReasonSlot, StateSlot};

/// Bounded-channel capacity for the download verify pipeline. Matches
/// `spoof-tunnel`'s 4096 default. On overflow, the recv task drops the
/// new packet with a WARN.
const DOWNLOAD_CHANNEL_CAP: usize = 4096;

/// Process-wide sampled counter for download packets dropped because the
/// peer Remote speaks a different envelope protocol version (the v2
/// `proto_ver` prefix doesn't match this build's [`hmac::PROTO_VERSION`]).
/// Sampled so a fully version-mismatched peer — where *every* packet is
/// wrong — logs roughly once per 1000 instead of flooding the rotating
/// app log on the hot path.
static VERSION_MISMATCH_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One sealed body queued for HMAC verify + deliver. The recv task does
/// the cheap filtering (source IP/port + dst port for UDP/TCP) and
/// peeks the seq purely to route the job to `worker = seq % N`; the
/// workers re-extract the seq inside `hmac::open_with` so the job
/// itself only needs to carry the sealed body and the transport label.
///
/// The seq-modulo routing means each worker only ever sees seqs from
/// its own arithmetic subset, so each worker can own a private
/// `SeqWindow` without locking and without any chance of one worker
/// advancing the window past another worker's in-flight seq (the
/// symptom that caused the v1 fan-out attempt to drop ~60 % of
/// inbound packets as "replay" under load).
struct DownloadVerifyJob {
    /// Sealed HMAC envelope from the spoof packet's payload.
    sealed: Vec<u8>,
    /// Transport label for log lines.
    transport: &'static str,
}

/// One application port's delivery resources on a multi-port Client
/// tunnel: the UDP listener bound on `(local_host, port)` and the
/// per-port session table tracking that port's end-user peers. Mirrors
/// the single-port `(listener, session_table)` pair, replicated per port
/// and keyed by the decoded application-port tag.
#[derive(Clone)]
struct PortBinding {
    listener: Arc<UdpSocket>,
    sessions: Arc<SessionTable>,
}

/// How a download-verify worker delivers a verified payload back to the
/// end user.
///
/// - `Single` is the legacy single-port path: ONE listener + ONE session
///   table, delivering the whole (untagged) payload exactly as before.
/// - `Multi` is the multi-port path: the worker decodes the 2-byte
///   application-port tag from the verified payload, looks the port up in
///   the binding map, and delivers the untagged body via that port's
///   listener. Unknown ports are dropped + warned (rate-limited).
///
/// All workers share ONE seq stream and each owns ONE [`SeqWindow`]
/// (keyed by `seq % N`); the application port is demuxed from the
/// authenticated payload tag AFTER the HMAC check, never by sharding the
/// replay window per port.
#[derive(Clone)]
enum PortRouter {
    Single {
        listener: Arc<UdpSocket>,
        sessions: Arc<SessionTable>,
    },
    Multi(Arc<HashMap<u16, PortBinding>>),
}

/// Process-wide sampled counter for multi-port download packets whose
/// decoded application-port tag is not in the tunnel's configured set
/// (config drift between the two sides). Sampled like the version-mismatch
/// counter so a wholesale-misconfigured peer doesn't flood the app log.
static UNKNOWN_PORT_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Parser function pointer for an IPv4 raw-socket download transport.
/// Each transport supplies an implementation that peels its specific
/// L4 header (UDP, TCP-SYN, or ICMP) off the IPv4 packet. UDP and
/// TCP-SYN ignore the `IcmpEchoMode` parameter; ICMP uses it to pick
/// between echo-reply (type 0) and echo-request (type 8) wire shapes.
type V4Parser = fn(&[u8], crate::spec::IcmpEchoMode) -> Option<ParsedInbound<'_>>;

/// Adapter so `udp::parse_inbound`'s `(&[u8])` signature matches the
/// uniform `V4Parser` type. The mode argument is irrelevant for UDP.
fn udp_parse_adapter(pkt: &[u8], _mode: crate::spec::IcmpEchoMode) -> Option<ParsedInbound<'_>> {
    udp::parse_inbound(pkt)
}

/// Adapter so `tcp_syn::parse_inbound` matches the uniform `V4Parser`
/// type. The mode argument is irrelevant for TCP-SYN.
fn tcp_syn_parse_adapter(
    pkt: &[u8],
    _mode: crate::spec::IcmpEchoMode,
) -> Option<ParsedInbound<'_>> {
    tcp_syn::parse_inbound(pkt)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn(
    spec: &TunnelSpec,
    resolved: &ResolvedSpec,
    state: StateSlot,
    error_reason: ReasonSlot,
    tasks: &mut JoinSet<()>,
    stop_rx: watch::Receiver<bool>,
    mutable_config: MutableConfigSlot,
    session_table: Arc<SessionTable>,
    metrics: Arc<TunnelMetrics>,
) -> Result<Arc<dyn UploadTransport>, SpawnError> {
    let local = resolved
        .local_listen_addr
        .expect("validate ensured local_listen_addr");
    let download_port = resolved
        .download_receive_port
        .expect("validate ensured download_receive_port");

    let id = spec.id;
    let name = Arc::new(spec.name.clone());

    // (1) Upload listener. The bind respects whatever address family
    // the operator's `local_listen_addr` parsed to. For `[::]:port`
    // we explicitly clear IPV6_V6ONLY so the socket accepts both v4
    // and v6 inbound packets — PRD §8.3 ("a single tunnel can carry
    // dual-stack traffic"). For `0.0.0.0:port` the kernel only ever
    // delivers v4 packets, so v6 clients would need to use a v6
    // listen address.
    let listener = bind_dualstack_udp(local).map_err(SpawnError::Io)?;
    // Enlarge SO_RCVBUF/SO_SNDBUF beyond the 208 KiB Ubuntu default so
    // a normal RTT × 200 Mbit/s burst fits without the kernel dropping
    // packets at the listener queue (see `perf` module for the rationale
    // and the diagnostic that motivated it).
    crate::perf::tune_socket(&listener, "client/listen");
    let listener = Arc::new(listener);
    info!(tunnel_id = id, addr = %local, family = address_family_label(local), "client: local_listen bound");

    // R9a: pick the upload transport based on the spec. WireGuard mode
    // (the default) wraps the historical WG-marked UDP egress socket
    // inside a thin `UploadTransport` so the recv loop below dispatches
    // through the same trait regardless of upload path. SOCKS5 mode
    // opens one TCP connection to the proxy and CONNECTs to
    // upload_target_addr. The wireguard.rs wrapper's behaviour is
    // byte-for-byte identical to the pre-R9 inline path; R2 perf is
    // preserved because `perf::tune_socket` is still applied to the
    // egress UDP socket and there's no extra hop on the hot path.
    let upload_transport = crate::upload::build_for_client_spec(spec, resolved, stop_rx.clone())
        .await
        .map_err(SpawnError::Io)?;

    // Multi-port vs single-port routing. A multi-port tunnel binds one
    // listener + one session table PER application port (all sharing the
    // single `upload_transport` egress) and tags every datagram with the
    // 2-byte application-port tag; the single-port path is left
    // byte-for-byte identical to before. See [`crate::multiport`].
    let router = if resolved.multiport() {
        let local_host = local.ip();
        let mut bindings: HashMap<u16, PortBinding> = HashMap::with_capacity(resolved.ports.len());
        for &port in &resolved.ports {
            if bindings.contains_key(&port) {
                continue;
            }
            let addr = SocketAddr::new(local_host, port);
            let port_listener = bind_dualstack_udp(addr).map_err(SpawnError::Io)?;
            crate::perf::tune_socket(&port_listener, "client/listen");
            let port_listener = Arc::new(port_listener);
            let port_sessions =
                Arc::new(SessionTable::new(spec.max_connections, spec.idle_timeout_sec));
            info!(tunnel_id = id, addr = %addr, family = address_family_label(addr),
                "client: multi-port local_listen bound");
            // One upload task per port: stamps SessionKey.local_port = P
            // and prepends the port tag before handing bytes to the shared
            // upload transport.
            spawn_upload_task_tagged(
                tasks,
                id,
                name.clone(),
                port_listener.clone(),
                port,
                Some(port),
                upload_transport.clone(),
                port_sessions.clone(),
                mutable_config.clone(),
                metrics.clone(),
                stop_rx.clone(),
            );
            // One idle sweeper per port session table.
            spawn_idle_sweeper(
                tasks,
                id,
                spec.idle_timeout_sec,
                port_sessions.clone(),
                metrics.clone(),
                stop_rx.clone(),
            );
            bindings.insert(
                port,
                PortBinding {
                    listener: port_listener,
                    sessions: port_sessions,
                },
            );
        }
        // The primary listener bound on `local` is unused on the multi-
        // port path (each port has its own listener). Dropping the Arc
        // here closes it.
        drop(listener);
        PortRouter::Multi(Arc::new(bindings))
    } else {
        // Upload-side task: end-user → forward to upload_target via the
        // selected upload transport (WG-marked UDP or SOCKS5 TCP). The
        // listener port travels into the upload task so it can stamp each
        // `SessionKey` with `(client_addr, local_port)` for SOCKS5 sticky
        // routing — the WG transport ignores it.
        spawn_upload_task_tagged(
            tasks,
            id,
            name.clone(),
            listener.clone(),
            local.port(),
            None,
            upload_transport.clone(),
            session_table.clone(),
            mutable_config.clone(),
            metrics.clone(),
            stop_rx.clone(),
        );

        // (3) Idle sweeper.
        spawn_idle_sweeper(
            tasks,
            id,
            spec.idle_timeout_sec,
            session_table.clone(),
            metrics.clone(),
            stop_rx.clone(),
        );

        PortRouter::Single {
            listener: listener.clone(),
            sessions: session_table.clone(),
        }
    };

    // Download-side: per-transport raw recv → bounded channel → N HMAC
    // verify-and-deliver workers. See module-doc for why fan-out is on
    // the worker side, not the socket side.
    spawn_download_pipeline(
        tasks,
        spec,
        resolved,
        id,
        name.clone(),
        router,
        mutable_config.clone(),
        metrics.clone(),
        download_port,
        state.clone(),
        error_reason.clone(),
        stop_rx.clone(),
    )
    .await?;

    // (4) Phase 13: cosmetic ping smoothing. The responder task is
    // always spawned for Client tunnels so flipping the toggle via
    // UpdateTunnel takes effect without an operator-visible restart.
    // The hot path checks `mutable_config.ping_smoothing_enabled` per
    // packet and early-returns when off — overhead when the toggle is
    // off is one raw socket + an idle await on its readable fd.
    let listen_ip_for_smooth = spec
        .local_listen_addr
        .as_deref()
        .and_then(crate::ping_smoothing::parse_listen_ip);
    crate::ping_smoothing::spawn(
        tasks,
        id,
        listen_ip_for_smooth,
        mutable_config.clone(),
        stop_rx.clone(),
    );

    // Return the upload transport so the caller (`spawn_tunnel`) can
    // park it on the `TunnelHandle` for the manager's hot-reload path
    // to reach (Phase R9b live SOCKS5 pool resize).
    Ok(upload_transport)
}

fn address_family_label(addr: SocketAddr) -> &'static str {
    if addr.is_ipv6() {
        "ipv6"
    } else {
        "ipv4"
    }
}

/// Bind a UDP socket on `addr`, explicitly enabling dual-stack
/// behaviour for IPv6 wildcards so the listener accepts both v4 and v6
/// peers without depending on /proc/sys/net/ipv6/bindv6only. Returns a
/// tokio-compatible UdpSocket via `from_std`.
fn bind_dualstack_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        // Reject the v4-only-but-bound-via-v6 case by being explicit.
        sock.set_only_v6(false)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Upload listener task. When `tag_port` is `None` (single-port) the
/// payload is shipped opaque, byte-for-byte as before. When `tag_port` is
/// `Some(P)` (multi-port) the body is prefixed with the 2-byte
/// application-port tag (`encode_tag`) before being handed to the shared
/// upload transport; the per-task scratch `Vec` is reused across packets.
///
/// The MTU cap check (PR #15) is always applied to the UNTAGGED body `n`,
/// so multi-port effectively reduces usable app payload by `PORT_TAG_LEN`
/// bytes — the same cap applies to both paths.
#[allow(clippy::too_many_arguments)]
fn spawn_upload_task_tagged(
    tasks: &mut JoinSet<()>,
    id: i64,
    name: Arc<String>,
    listener: Arc<UdpSocket>,
    local_port: u16,
    tag_port: Option<u16>,
    upload_transport: Arc<dyn UploadTransport>,
    session_table: Arc<SessionTable>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    mut stop_rx: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        // Sized to MAX_UDP_DATAGRAM (not `mtu`) so a >MTU datagram is
        // read whole and rejected by the cap check below. A buffer the
        // size of `mtu` lets the kernel silently truncate the tail; the
        // cap check would then see n==mtu and accept the corrupted
        // packet — see PR #15.
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
        // Per-task scratch reused for the tagged payload on the multi-port
        // path. Never allocated on the single-port path.
        let mut tagged: Vec<u8> = Vec::new();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    info!(tunnel_id = id, name = %name, "client: upload task stopping");
                    // Let the transport release its resources (close
                    // the SOCKS5 TCP connection if any). Dropping the
                    // Arc wouldn't run async cleanup.
                    upload_transport.shutdown().await;
                    return;
                }
                res = listener.recv_from(&mut buf) => {
                    let (n, src) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(tunnel_id = id, err = %e, "client: upload recv");
                            continue;
                        }
                    };
                    // Fresh MTU read so a hot-reload of `mtu` applies on the
                    // next packet without restarting the task.
                    let mtu = mutable_config.read().expect("mutable_config read").mtu as usize;
                    let upload_payload_cap = mtu.max(64);
                    if n > upload_payload_cap {
                        warn!(tunnel_id = id, n, max = upload_payload_cap,
                            "client: dropping oversized upload packet (raise tunnel MTU or shrink app packet)");
                        continue;
                    }
                    let outcome = session_table.insert_or_refresh(src, src);
                    if matches!(outcome, InsertOutcome::Rejected) {
                        warn!(tunnel_id = id, %src,
                            "client: session table full, dropping new session");
                        metrics.record_session_reject();
                        continue;
                    }
                    let session = SessionKey {
                        client_addr: src,
                        local_port,
                    };
                    // Single-port: ship the body opaque (wire-identical).
                    // Multi-port: prepend the 2-byte application-port tag.
                    let out: &[u8] = match tag_port {
                        Some(p) => {
                            multiport::encode_tag(p, &buf[..n], &mut tagged);
                            &tagged
                        }
                        None => &buf[..n],
                    };
                    if let Err(e) = upload_transport.send(session, out).await {
                        warn!(tunnel_id = id, err = %e,
                            "client: upload forward failed");
                    } else {
                        metrics.record_upload(n, now_unix());
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn spawn_download_pipeline(
    tasks: &mut JoinSet<()>,
    spec: &TunnelSpec,
    resolved: &ResolvedSpec,
    id: i64,
    name: Arc<String>,
    router: PortRouter,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    download_port: u16,
    state: StateSlot,
    error_reason: ReasonSlot,
    stop_rx: watch::Receiver<bool>,
) -> Result<(), SpawnError> {
    let workers = crate::perf::per_core_sockets();
    let recv_batch_size = crate::perf::recv_batch();
    // One bounded channel per worker. The recv task routes jobs by
    // `seq % workers` so each worker only ever sees seqs from its own
    // arithmetic subset — each worker therefore owns a private
    // `SeqWindow` with NO cross-worker lock, AND the 128-bit bitmap
    // covers `128 * workers` consecutive wire-seqs of reordering
    // headroom (more than enough at our packet rate).
    let mut worker_txs: Vec<mpsc::Sender<DownloadVerifyJob>> = Vec::with_capacity(workers);
    let mut worker_rxs: Vec<mpsc::Receiver<DownloadVerifyJob>> = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = mpsc::channel::<DownloadVerifyJob>(DOWNLOAD_CHANNEL_CAP);
        worker_txs.push(tx);
        worker_rxs.push(rx);
    }

    match spec.download_transport {
        Transport::Udp | Transport::TcpSyn | Transport::Icmp => {
            // IPv4 transports — open the matching raw socket and run
            // a uniform recv loop. The parser pointer chooses which L4
            // header to peel.
            // Cross-check the spawn-time spoof IP for IPv4 — a hot-
            // reload of `download_spoof_source_ip` to a v6 address on an
            // IPv4 transport would be a configuration error caught here
            // before the task starts.
            match resolved.spoof_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(_) => {
                    return Err(SpawnError::Io(io::Error::other(
                        "transport requires IPv4 download_spoof_source_ip",
                    )));
                }
            };
            let (raw, parse, label): (socket2::Socket, V4Parser, &'static str) =
                match spec.download_transport {
                    Transport::Udp => (
                        udp::open_raw_udp_recv_socket().map_err(SpawnError::Io)?,
                        udp_parse_adapter,
                        "udp",
                    ),
                    Transport::TcpSyn => (
                        tcp_syn::open_raw_tcp_recv_socket().map_err(SpawnError::Io)?,
                        tcp_syn_parse_adapter,
                        "tcp_syn",
                    ),
                    Transport::Icmp => (
                        icmp::open_raw_icmp_recv_socket().map_err(SpawnError::Io)?,
                        icmp::parse_inbound,
                        "icmp",
                    ),
                    Transport::Icmpv6 => unreachable!(),
                };
            raw.set_nonblocking(true).map_err(SpawnError::Io)?;
            let raw_fd = std::os::fd::OwnedFd::from(raw);
            let raw = Arc::new(AsyncFd::new(raw_fd).map_err(SpawnError::Io)?);

            let transport = spec.download_transport;
            let icmp_echo_mode = spec.icmp_echo_mode;
            tasks.spawn(spawn_v4_recv_loop(
                raw,
                parse,
                label,
                transport,
                icmp_echo_mode,
                worker_txs.clone(),
                mutable_config.clone(),
                metrics.clone(),
                download_port,
                id,
                name.clone(),
                state,
                error_reason,
                stop_rx.clone(),
                recv_batch_size,
            ));
            info!(
                tunnel_id = id,
                transport = label,
                workers,
                recv_batch = recv_batch_size,
                channel_cap = DOWNLOAD_CHANNEL_CAP,
                "client: download recv socket bound, verify workers spinning up"
            );
        }
        Transport::Icmpv6 => {
            // Sanity-check the address family for the same reason as
            // the v4 branch — a misconfigured spec should not silently
            // start with the wrong filter.
            match resolved.spoof_ip {
                IpAddr::V6(_) => {}
                IpAddr::V4(_) => {
                    return Err(SpawnError::Io(io::Error::other(
                        "icmpv6 transport requires IPv6 download_spoof_source_ip",
                    )));
                }
            };
            let raw = icmpv6::open_raw_icmpv6_recv_socket().map_err(SpawnError::Io)?;
            raw.set_nonblocking(true).map_err(SpawnError::Io)?;
            let raw_fd = std::os::fd::OwnedFd::from(raw);
            let raw = Arc::new(AsyncFd::new(raw_fd).map_err(SpawnError::Io)?);

            let icmp_echo_mode = spec.icmp_echo_mode;
            tasks.spawn(spawn_v6_recv_loop(
                raw,
                worker_txs.clone(),
                mutable_config.clone(),
                metrics.clone(),
                id,
                name.clone(),
                state,
                error_reason,
                icmp_echo_mode,
                stop_rx.clone(),
                recv_batch_size,
            ));
            info!(
                tunnel_id = id,
                transport = "icmpv6",
                workers,
                recv_batch = recv_batch_size,
                channel_cap = DOWNLOAD_CHANNEL_CAP,
                "client: download recv socket bound, verify workers spinning up"
            );
        }
    }

    // Spawn N verify-and-deliver workers, each consuming from its own
    // per-worker channel with its own per-worker SeqWindow. All workers
    // share ONE seq stream + ONE SeqWindow each (keyed by `seq % N`); the
    // application port is demuxed from the verified payload tag AFTER the
    // HMAC check, never by sharding the window per port.
    for (worker_id, rx) in worker_rxs.into_iter().enumerate() {
        let router = router.clone();
        let mutable_config = mutable_config.clone();
        let metrics = metrics.clone();
        let name = name.clone();
        let stop_rx = stop_rx.clone();
        tasks.spawn(download_verify_worker(
            rx,
            router,
            mutable_config,
            metrics,
            id,
            worker_id,
            name,
            stop_rx,
        ));
    }
    Ok(())
}

/// IPv4 raw-socket recv loop: batch via recvmmsg, parse + cheap-filter
/// per packet, round-robin sealed bodies across the N worker channels.
#[allow(clippy::too_many_arguments)]
async fn spawn_v4_recv_loop(
    raw: Arc<AsyncFd<std::os::fd::OwnedFd>>,
    parse: V4Parser,
    label: &'static str,
    transport: Transport,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    worker_txs: Vec<mpsc::Sender<DownloadVerifyJob>>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    download_port: u16,
    id: i64,
    name: Arc<String>,
    state: StateSlot,
    error_reason: ReasonSlot,
    mut stop_rx: watch::Receiver<bool>,
    recv_batch_size: usize,
) {
    let mut batch = RecvBatch::for_udp(recv_batch_size);
    let n_workers = worker_txs.len().max(1);
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, name = %name, transport = label,
                    "client: download recv stopping");
                return;
            }
            guard_res = raw.readable() => {
                let mut guard = match guard_res {
                    Ok(g) => g,
                    Err(e) => {
                        error!(tunnel_id = id, err = %e,
                            "client: raw readable awaiter failed");
                        *state.lock().expect("state mutex") = TunnelState::Error;
                        *error_reason.lock().expect("reason mutex") =
                            Some(format!("raw recv: {e}"));
                        return;
                    }
                };
                let n_res = guard.try_io(|fd| {
                    batch::recvmmsg(fd.get_ref().as_raw_fd(), &mut batch)
                });
                let received = match n_res {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(e)) => {
                        warn!(tunnel_id = id, err = %e, "client: recvmmsg");
                        continue;
                    }
                    Err(_would_block) => continue,
                };
                // Snapshot the spoof tuple ONCE per batch so a hot-reload
                // of those fields applies on the next batch without a
                // lock per packet.
                let (spoof_ip, spoof_port) = {
                    let cfg = mutable_config.read().expect("mutable_config read");
                    (cfg.spoof_ip, cfg.spoof_port)
                };
                for i in 0..received {
                    let pkt = batch.slots[i].data();
                    let parsed = match parse(pkt, icmp_echo_mode) {
                        Some(p) => p,
                        None => continue,
                    };
                    let is_icmp = matches!(transport, Transport::Icmp);
                    // Per-transport destination filter: UDP and TCP-SYN
                    // carry a real destination port that must match our
                    // configured `download_receive_port`. ICMP echoes
                    // have no destination port on the wire — the parser
                    // surfaces the ICMP identifier as both `src_id` and
                    // `dst_id`, but Phase R4 randomises the identifier
                    // per tunnel start, so we deliberately skip that
                    // check for ICMP. HMAC verification is the
                    // authentication.
                    if matches!(transport, Transport::Udp | Transport::TcpSyn)
                        && parsed.dst_id != download_port
                    {
                        continue;
                    }
                    // Source filter (PRD §3.4) — `src_ip` always
                    // matters. The `src_id == spoof_port` identifier
                    // check applies to UDP/TCP-SYN (real ports) but is
                    // skipped for ICMP because the identifier is
                    // intentionally random per tunnel start.
                    if parsed.src_ip != spoof_ip {
                        continue;
                    }
                    if !is_icmp && parsed.src_id != spoof_port {
                        continue;
                    }
                    let seq = match peek_seq(parsed.payload) {
                        Some(s) => s,
                        None => continue,
                    };
                    let job = DownloadVerifyJob {
                        sealed: parsed.payload.to_vec(),
                        transport: label,
                    };
                    // Route by seq so each worker only sees its own
                    // arithmetic subset → per-worker SeqWindow with no
                    // cross-worker contention.
                    let worker = (seq as usize) % n_workers;
                    if let Err(e) = worker_txs[worker].try_send(job) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                warn!(tunnel_id = id, transport = label, worker,
                                    "client: verify channel full, dropping spoof packet");
                                metrics.record_auth_drop();
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                info!(tunnel_id = id, transport = label, worker,
                                    "client: verify channel closed, recv exiting");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Peek at the 8-byte seq field for fan-out routing. Returns `None` if
/// the body is too short to contain the envelope header — those get
/// dropped anyway. Cheap (8 bytes BE → u64).
///
/// The seq sits AFTER `ver(1) || tag(16) || session_id(8)`, i.e. at
/// offset [`hmac::VER_LEN`] + [`hmac::HMAC_LEN`] + [`hmac::SESSION_ID_LEN`].
/// A prior version of this function read at `HMAC_LEN..` — which is the
/// **session_id**, not the seq — so `seq % n_workers` was actually
/// `session_id % n_workers`, a constant for a given Remote session. That
/// silently pinned the entire download-verify fan-out to one worker and
/// defeated the parallelism this pipeline's module doc describes. Reading
/// the true seq offset spreads packets across all workers as intended.
fn peek_seq(sealed: &[u8]) -> Option<u64> {
    if sealed.len() < hmac::OVERHEAD {
        return None;
    }
    let off = hmac::VER_LEN + hmac::HMAC_LEN + hmac::SESSION_ID_LEN;
    Some(u64::from_be_bytes(
        sealed[off..off + hmac::SEQ_LEN].try_into().ok()?,
    ))
}

/// ICMPv6 raw-socket recv loop. Same shape as v4 but uses the v6
/// parser (which pulls the IPv6 header out of the recv buffer).
#[allow(clippy::too_many_arguments)]
async fn spawn_v6_recv_loop(
    raw: Arc<AsyncFd<std::os::fd::OwnedFd>>,
    worker_txs: Vec<mpsc::Sender<DownloadVerifyJob>>,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    id: i64,
    name: Arc<String>,
    state: StateSlot,
    error_reason: ReasonSlot,
    icmp_echo_mode: crate::spec::IcmpEchoMode,
    mut stop_rx: watch::Receiver<bool>,
    recv_batch_size: usize,
) {
    let mut batch = RecvBatch::for_udp(recv_batch_size);
    let n_workers = worker_txs.len().max(1);
    let label = "icmpv6";
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, name = %name, transport = label,
                    "client: download recv stopping");
                return;
            }
            guard_res = raw.readable() => {
                let mut guard = match guard_res {
                    Ok(g) => g,
                    Err(e) => {
                        error!(tunnel_id = id, err = %e,
                            "client: raw readable awaiter failed");
                        *state.lock().expect("state mutex") = TunnelState::Error;
                        *error_reason.lock().expect("reason mutex") =
                            Some(format!("raw recv: {e}"));
                        return;
                    }
                };
                let n_res = guard.try_io(|fd| {
                    batch::recvmmsg(fd.get_ref().as_raw_fd(), &mut batch)
                });
                let received = match n_res {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(e)) => {
                        warn!(tunnel_id = id, err = %e, "client: recvmmsg");
                        continue;
                    }
                    Err(_would_block) => continue,
                };
                let spoof_ip = {
                    let cfg = mutable_config.read().expect("mutable_config read");
                    cfg.spoof_ip
                };
                for i in 0..received {
                    let pkt = batch.slots[i].data();
                    // On Linux, AF_INET6 SOCK_RAW IPPROTO_ICMPV6 sockets
                    // DO include the IPv6 header in the receive buffer.
                    let parsed = match icmpv6::parse_inbound(pkt, icmp_echo_mode) {
                        Some(p) => p,
                        None => continue,
                    };
                    // ICMP identifier is random per tunnel start (Phase
                    // R4); skip the identifier check and rely on HMAC +
                    // src_ip filter.
                    if parsed.src_ip != spoof_ip {
                        continue;
                    }
                    let seq = match peek_seq(parsed.payload) {
                        Some(s) => s,
                        None => continue,
                    };
                    let job = DownloadVerifyJob {
                        sealed: parsed.payload.to_vec(),
                        transport: label,
                    };
                    let worker = (seq as usize) % n_workers;
                    if let Err(e) = worker_txs[worker].try_send(job) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                warn!(tunnel_id = id, transport = label, worker,
                                    "client: verify channel full, dropping spoof packet");
                                metrics.record_auth_drop();
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                info!(tunnel_id = id, transport = label, worker,
                                    "client: verify channel closed, recv exiting");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// HMAC verify + replay-window check + deliver-to-end-user worker.
/// One per `SUBLYNE_PER_CORE_SOCKETS`; each worker owns a PRIVATE
/// [`SeqWindow`] tracking only the seqs `seq % N == worker_id`, so
/// there is no cross-worker contention and the 1024-slot bitmap stays
/// adequate (it covers 1024 of the worker's own seqs ≡ `1024 * N`
/// consecutive wire seqs of reordering tolerance — see
/// `hmac::SEQ_WINDOW_WORDS`).
#[allow(clippy::too_many_arguments)]
async fn download_verify_worker(
    mut rx: mpsc::Receiver<DownloadVerifyJob>,
    router: PortRouter,
    mutable_config: MutableConfigSlot,
    metrics: Arc<TunnelMetrics>,
    id: i64,
    worker_id: usize,
    name: Arc<String>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut window = SeqWindow::new();
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id = id, worker = worker_id, name = %name,
                    "client: download verify worker stopping");
                return;
            }
            job = rx.recv() => {
                let job = match job {
                    Some(j) => j,
                    None => {
                        info!(tunnel_id = id, worker = worker_id,
                            "client: verify channel closed, worker exiting");
                        return;
                    }
                };
                let (psk, pacing_delay) = {
                    let cfg = mutable_config.read().expect("mutable_config read");
                    (
                        cfg.psk.clone(),
                        if cfg.pacing_enabled { cfg.pacing_target_ms } else { 0 },
                    )
                };
                deliver_verified_job(
                    psk.as_ref(),
                    &job.sealed,
                    &mut window,
                    &router,
                    &metrics,
                    id,
                    job.transport,
                    pacing_delay,
                )
                .await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn deliver_verified_job(
    psk: &HmacKey,
    sealed: &[u8],
    window: &mut SeqWindow,
    router: &PortRouter,
    metrics: &TunnelMetrics,
    id: i64,
    transport_label: &'static str,
    pacing_delay_ms: u32,
) {
    // Per-worker `SeqWindow`; no lock needed because the recv task
    // routes by `seq % N` so only this worker ever sees this seq.
    let verify_result = hmac::open_with(psk, sealed, window);
    match verify_result {
        Ok(payload) => {
            // Resolve the delivery target. Single-port: deliver the whole
            // verified payload via the one listener (wire-identical to
            // before). Multi-port: decode the authenticated 2-byte
            // application-port tag, validate it against the configured
            // set, and deliver the untagged body via that port's listener.
            let (listener, session_table, body): (&UdpSocket, &SessionTable, &[u8]) = match router {
                PortRouter::Single { listener, sessions } => (listener, sessions, payload),
                PortRouter::Multi(bindings) => {
                    let (port, body) = match multiport::decode_tag(payload) {
                        Some(v) => v,
                        None => {
                            debug!(
                                tunnel_id = id,
                                transport = transport_label,
                                "client: multi-port download payload too short for port tag"
                            );
                            return;
                        }
                    };
                    match bindings.get(&port) {
                        Some(b) => (b.listener.as_ref(), b.sessions.as_ref(), body),
                        None => {
                            // Authenticated but the port isn't in our set —
                            // config drift between the two sides. Count it
                            // as an auth/seq drop so the dashboard moves,
                            // and warn (sampled) so the operator looks.
                            let prev = UNKNOWN_PORT_DROPS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if prev % 1000 == 0 {
                                warn!(
                                    tunnel_id = id,
                                    transport = transport_label,
                                    port,
                                    dropped_total = prev + 1,
                                    "client: multi-port download tagged with a port that is \
                                     not in this tunnel's configured set — the two sides have \
                                     different port lists; align them"
                                );
                            }
                            metrics.record_auth_drop();
                            return;
                        }
                    }
                }
            };
            deliver_to_end_user(
                listener,
                session_table,
                body,
                metrics,
                id,
                transport_label,
                pacing_delay_ms,
            )
            .await;
        }
        Err(OpenError::TooShort) => {
            debug!(
                tunnel_id = id,
                n = sealed.len(),
                transport = transport_label,
                "client: download body too short for HMAC envelope"
            );
        }
        Err(OpenError::Version) => {
            // The peer Remote sealed this packet with a different envelope
            // protocol version — it's running an incompatible Sublyne
            // release. Sampled so a wholesale-mismatched peer doesn't
            // flood the log; counted as an auth drop so the dashboard's
            // drop counter still moves and the operator goes looking.
            let prev = VERSION_MISMATCH_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if prev % 1000 == 0 {
                warn!(
                    tunnel_id = id,
                    transport = transport_label,
                    dropped_total = prev + 1,
                    "client: download packet carries a different Sublyne wire-protocol \
                     version — the foreign (Remote) server is running an incompatible \
                     release; upgrade BOTH servers to the same Sublyne version"
                );
            }
            metrics.record_auth_drop();
        }
        Err(OpenError::Auth) => {
            warn!(
                tunnel_id = id,
                transport = transport_label,
                "client: HMAC verification failed (wrong PSK or tampered packet)"
            );
            metrics.record_auth_drop();
        }
        Err(OpenError::Replay) => {
            warn!(
                tunnel_id = id,
                transport = transport_label,
                "client: dropped replayed download packet (seq window)"
            );
            metrics.record_auth_drop();
        }
    }
}

/// Deliver one (untagged) verified body back to the end user via
/// `listener`, picking the freshest peer from `session_table`. This is the
/// historical single-port delivery logic, extracted verbatim so both the
/// single-port and per-port multi-port paths share it. Metrics, pacing,
/// and the per-packet TRACE diagnostics are byte-for-byte the same as
/// before.
#[allow(clippy::too_many_arguments)]
async fn deliver_to_end_user(
    listener: &UdpSocket,
    session_table: &SessionTable,
    body: &[u8],
    metrics: &TunnelMetrics,
    id: i64,
    transport_label: &'static str,
    pacing_delay_ms: u32,
) {
    // Stamp `last_packet_received_at_unix` and the per-transport packet
    // counter as soon as a HMAC-verified packet arrives, BEFORE the
    // delivery step. PRD §2.4 derives the dashboard health badge from
    // "observed packet activity"; a verified packet is observed activity
    // even if `any_session` later returns no peer to deliver it to.
    // Mirrors the Remote side in `tunnel::remote::spawn_download_recv_loop`,
    // which also records the metric on recv rather than on send.
    //
    // Without this, a tunnel that's receiving spoofed packets but has no
    // live upstream session (e.g., right after idle eviction, before the
    // next end-user packet creates a fresh session) would show the Idle /
    // Down badge despite real download activity reaching the box.
    metrics.record_download(body.len(), now_unix());
    metrics.record_transport_packet(transport_label);
    let peer_opt = session_table.any_session();
    if let Some(peer) = peer_opt {
        // Phase 13: pacing. When pacing_enabled the operator has told us
        // to artificially defer the download so the perceived round-trip
        // rises toward `pacing_target_ms`. EXPERIMENTAL — PRD §3.3 warns
        // this reduces bandwidth. Delay = 0 (the default and the
        // non-pacing path) is a no-op zero-cost branch.
        if pacing_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(pacing_delay_ms as u64)).await;
        }
        if let Err(e) = listener.send_to(body, peer).await {
            warn!(tunnel_id = id, %peer, err = %e,
                transport = transport_label,
                "client: deliver to end user failed");
        } else {
            // trace! (not debug!) — this fires per packet on the download
            // success path. At INFO/DEBUG level the tracing macro skips
            // arg evaluation, but the level check + dispatch is still
            // ~tens of ns per packet, and an operator who flips the panel
            // to DEBUG would otherwise drown in N×pps lines. TRACE is the
            // right level: the diagnostic is still reachable, but never
            // formatted at default filtering.
            trace!(tunnel_id = id, %peer, n = body.len(),
                transport = transport_label,
                "client: delivered download payload");
        }
    } else {
        // Same per-packet hot-path concern: until the first upload
        // establishes a session, every spoofed download packet hits this
        // branch. trace! keeps the diagnostic available without flooding
        // DEBUG logs.
        trace!(
            tunnel_id = id,
            transport = transport_label,
            "client: download arrived but no upstream session yet"
        );
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
        // The tick is captured at spawn time. A live edit of the timeout
        // changes the eviction threshold immediately (sweeper consults
        // the atomic each sweep) but the tick interval keeps the
        // spawn-time cadence — drastic changes to idle_timeout settle
        // after the next sweep, which is good enough for an
        // operator-edit-rare field.
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
                    "client: evicted idle sessions"
                );
            }
            // Publish the live session count into the metrics block
            // every sweep so the stats reporter doesn't have to lock the
            // session table itself. The cast is safe — `len()` is
            // bounded by `max_connections` which is a u32.
            metrics.set_active_sessions(session_table.len() as u32);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_dualstack_v4_works() {
        let s = bind_dualstack_udp("127.0.0.1:0".parse().unwrap()).expect("bind v4");
        let local = s.local_addr().expect("local_addr");
        assert!(local.is_ipv4());
    }

    #[tokio::test]
    async fn bind_dualstack_v6_works_and_clears_v6only() {
        // Loopback v6 — must succeed on any Linux/macOS test host that
        // has IPv6 enabled (CI runners do). The explicit `set_only_v6
        // = false` is what enables dual-stack reception; this test
        // mostly proves the call path doesn't blow up. The full dual-
        // stack receive behaviour is exercised in the loopback tests.
        let s = bind_dualstack_udp("[::1]:0".parse().unwrap()).expect("bind v6");
        let local = s.local_addr().expect("local_addr");
        assert!(local.is_ipv6());
    }
}
