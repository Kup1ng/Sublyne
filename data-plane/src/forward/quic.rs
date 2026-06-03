//! QUIC reliability engine for `forward_protocol=tcp` (v4.0.0).
//!
//! Like the KCP engine, this bridges a TCP byte stream across Sublyne's
//! best-effort opaque-datagram channel — but using `quinn` (QUIC) instead
//! of KCP. QUIC's native stream multiplexing means one QUIC **connection**
//! per tunnel carries one bidirectional **stream** per user TCP connection,
//! so there's no per-connection conv bookkeeping to do ourselves.
//!
//! The trick is driving quinn over our channel rather than a kernel UDP
//! socket: [`ChannelUdpSocket`] implements [`quinn::AsyncUdpSocket`], turning
//! every QUIC packet into an opaque datagram on the [`DatagramSink`] and
//! feeding inbound datagrams back into quinn via `poll_recv`. The seal /
//! spoof / anti-replay pipeline keeps treating those datagrams as opaque
//! ≤MTU payloads.
//!
//! Roles: the Client runs the QUIC *client* endpoint (it initiates the
//! handshake — its Initial leaves via the upload path, the server's reply
//! via the spoof download path); the Remote runs the QUIC *server* endpoint
//! and dials `forward_target` per accepted stream.
//!
//! ## Crypto / build note
//!
//! quinn + rustls + rcgen are all pinned to the `ring` provider (see
//! Cargo.toml) so the fully-static musl build needs no C toolchain. TLS is
//! encryption-only here: peer authenticity is already guaranteed by the
//! HMAC seal (download) and WG/SOCKS5 (upload), so the client accepts any
//! server certificate and the server presents a fresh self-signed one.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, ServerConfig,
    TokioRuntime, TransportConfig, UdpPoller, VarInt,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use super::channel::{DatagramSink, InboundRx, EGRESS_CAP};
use super::kcp::{EngineRole, EngineStats};
use crate::spec::QuicTuning;

/// QUIC's minimum datagram size (an Initial packet must be paddable to
/// 1200 bytes). The tunnel MTU for a QUIC-forwarding tunnel is validated to
/// leave at least this much room.
const QUIC_MIN_MTU: u16 = 1200;

/// ALPN for the private forwarding tunnel.
const ALPN: &[u8] = b"sublyne-fwd";

/// Fixed nominal peer address. The channel has exactly one peer, so quinn's
/// addressing is cosmetic — every datagram goes to/comes from this.
fn peer_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)
}

/// Static configuration for one QUIC engine instance.
pub struct QuicConfig {
    pub tunnel_id: i64,
    pub idle_timeout_sec: u32,
    /// Per-tunnel connection ceiling (the tunnel's `max_connections`). A new
    /// stream is refused once `active_conns` reaches it. `0` ⇒ no cap. NOTE:
    /// this cap is *approximate* — `active_conns` is incremented only after a
    /// stream fully opens, so a burst of simultaneous accepts can briefly
    /// overshoot by the number of in-flight opens. KCP's equivalent cap is
    /// exact (it gates on the live conv-map length under lock). The overshoot
    /// is bounded by in-flight accepts and the gate is best-effort by design.
    pub max_connections: u32,
    pub tuning: QuicTuning,
}

/// `quinn::AsyncUdpSocket` over the asymmetric datagram channel. Outbound
/// QUIC packets are staged to an mpsc the engine's egress task drains into
/// the sink; inbound datagrams are pulled from the engine's inbox.
#[derive(Debug)]
struct ChannelUdpSocket {
    egress_tx: mpsc::Sender<Vec<u8>>,
    inbound: Mutex<InboundRx>,
    stats: Arc<EngineStats>,
    local: SocketAddr,
}

impl quinn::AsyncUdpSocket for ChannelUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // try_send never reports WouldBlock (it drops on a full channel and
        // QUIC retransmits), so the socket is always "writable".
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let data = transmit.contents;
        match transmit.segment_size {
            // GSO batch: split into individual datagrams (we report
            // max_transmit_segments=1, so this is belt-and-suspenders).
            Some(seg) if seg > 0 && seg < data.len() => {
                for chunk in data.chunks(seg) {
                    if self.egress_tx.try_send(chunk.to_vec()).is_err() {
                        self.stats.egress_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            _ => {
                if self.egress_tx.try_send(data.to_vec()).is_err() {
                    self.stats.egress_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Pending;
        }
        let mut rx = self.inbound.lock().expect("inbound lock");
        match rx.poll_recv(cx) {
            Poll::Ready(Some(dg)) => {
                let n = dg.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&dg[..n]);
                meta[0] = RecvMeta {
                    addr: peer_addr(),
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            // Channel closed only happens on tunnel shutdown, when the
            // endpoint is being dropped anyway.
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Certificate verifier that accepts any server cert. Justified: this is a
/// private point-to-point tunnel whose peer is already authenticated by the
/// HMAC seal (download) and WG/SOCKS5 (upload); QUIC's TLS provides
/// encryption + framing only. Adapted from quinn's `insecure_connection`
/// example; uses the ring provider for signature verification.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn congestion_factory(
    name: &str,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync + 'static> {
    match name {
        "newreno" => Arc::new(quinn::congestion::NewRenoConfig::default()),
        "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
        _ => Arc::new(quinn::congestion::CubicConfig::default()),
    }
}

fn transport(t: &QuicTuning, mtu: u16, max_streams: u32) -> TransportConfig {
    let mut tc = TransportConfig::default();
    // Fixed MTU = the channel budget; PMTUD off so QUIC never emits a
    // datagram the seal cap would drop.
    tc.initial_mtu(mtu);
    tc.min_mtu(QUIC_MIN_MTU);
    tc.mtu_discovery_config(None);
    if let Ok(it) = quinn::IdleTimeout::try_from(Duration::from_millis(u64::from(t.max_idle_ms))) {
        tc.max_idle_timeout(Some(it));
    }
    tc.keep_alive_interval(Some(Duration::from_millis(u64::from(
        t.keep_alive_ms.max(1),
    ))));
    tc.initial_rtt(Duration::from_millis(u64::from(t.initial_rtt_ms.max(1))));
    if let Ok(v) = VarInt::try_from(t.stream_recv_window) {
        tc.stream_receive_window(v);
    }
    if let Ok(v) = VarInt::try_from(t.conn_recv_window) {
        tc.receive_window(v);
    }
    tc.send_window(t.conn_recv_window);
    tc.max_concurrent_bidi_streams(VarInt::from_u32(max_streams));
    tc.max_concurrent_uni_streams(VarInt::from_u32(0));
    tc.congestion_controller_factory(congestion_factory(&t.congestion));
    tc
}

fn build_client_config(t: &QuicTuning, mtu: u16, max_streams: u32) -> io::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .dangerous()
    .with_custom_certificate_verifier(SkipServerVerification::new())
    .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(io::Error::other)?;
    let mut cfg = ClientConfig::new(Arc::new(quic));
    cfg.transport_config(Arc::new(transport(t, mtu, max_streams)));
    Ok(cfg)
}

fn build_server_config(t: &QuicTuning, mtu: u16, max_streams: u32) -> io::Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["sublyne".to_string()])
        .map_err(io::Error::other)?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.cert.into();

    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key.into())
    .map_err(io::Error::other)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(io::Error::other)?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
    cfg.transport_config(Arc::new(transport(t, mtu, max_streams)));
    Ok(cfg)
}

/// The QUIC engine. Construct with [`QuicEngine::new`], drive with
/// [`QuicEngine::run`].
pub struct QuicEngine {
    cfg: Arc<QuicConfig>,
    role: EngineRole,
    sink: Arc<dyn DatagramSink>,
    stats: Arc<EngineStats>,
}

impl QuicEngine {
    pub fn new(cfg: QuicConfig, role: EngineRole, sink: Arc<dyn DatagramSink>) -> Self {
        QuicEngine {
            cfg: Arc::new(cfg),
            role,
            sink,
            stats: Arc::new(EngineStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<EngineStats> {
        self.stats.clone()
    }

    pub async fn run(self, inbound_rx: InboundRx, stop_rx: watch::Receiver<bool>) {
        let QuicEngine {
            cfg,
            role,
            sink,
            stats,
        } = self;
        let mtu = sink
            .max_payload()
            .clamp(QUIC_MIN_MTU as usize, u16::MAX as usize) as u16;
        // Roomy bidi-stream ceiling; one stream per user TCP connection.
        let max_streams: u32 = 100_000;

        // Egress: drain staged QUIC packets → the asymmetric channel.
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
                                Err(e) => debug!(err = %e, "quic: egress sink send failed"),
                            }
                        }
                    }
                }
            });
        }

        let socket = Arc::new(ChannelUdpSocket {
            egress_tx,
            inbound: Mutex::new(inbound_rx),
            stats: stats.clone(),
            local: peer_addr(),
        });

        let server_config = match &role {
            EngineRole::Remote { .. } => match build_server_config(&cfg.tuning, mtu, max_streams) {
                Ok(c) => Some(c),
                Err(e) => {
                    error!(tunnel_id = cfg.tunnel_id, err = %e, "quic: server config build failed");
                    return;
                }
            },
            EngineRole::Client { .. } => None,
        };

        let endpoint = match Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            server_config,
            socket,
            Arc::new(TokioRuntime),
        ) {
            Ok(e) => e,
            Err(e) => {
                error!(tunnel_id = cfg.tunnel_id, err = %e, "quic: endpoint build failed");
                return;
            }
        };

        match role {
            EngineRole::Client { listener } => {
                run_client(endpoint, listener, &cfg, mtu, max_streams, stats, stop_rx).await;
            }
            EngineRole::Remote { forward_target } => {
                run_remote(endpoint, forward_target, &cfg, stats, stop_rx).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_client(
    mut endpoint: Endpoint,
    listener: TcpListener,
    cfg: &QuicConfig,
    mtu: u16,
    max_streams: u32,
    stats: Arc<EngineStats>,
    mut stop: watch::Receiver<bool>,
) {
    let client_cfg = match build_client_config(&cfg.tuning, mtu, max_streams) {
        Ok(c) => c,
        Err(e) => {
            error!(tunnel_id = cfg.tunnel_id, err = %e, "quic: client config build failed");
            return;
        }
    };
    endpoint.set_default_client_config(client_cfg);
    let peer = peer_addr();

    'outer: loop {
        if *stop.borrow() {
            break;
        }
        // (Re)connect, retrying on failure until stop.
        let conn = loop {
            let connecting = match endpoint.connect(peer, "sublyne") {
                Ok(c) => c,
                Err(e) => {
                    warn!(tunnel_id = cfg.tunnel_id, err = %e, "quic: connect setup failed");
                    if sleep_or_stopped(Duration::from_millis(1000), &mut stop).await {
                        break 'outer;
                    }
                    continue;
                }
            };
            tokio::select! {
                _ = stop.changed() => break 'outer,
                res = connecting => match res {
                    Ok(c) => break c,
                    Err(e) => {
                        warn!(tunnel_id = cfg.tunnel_id, err = %e, "quic: handshake failed; retrying");
                        if sleep_or_stopped(Duration::from_millis(1000), &mut stop).await {
                            break 'outer;
                        }
                    }
                },
            }
        };
        info!(tunnel_id = cfg.tunnel_id, "quic: connected to remote");

        loop {
            tokio::select! {
                _ = stop.changed() => break 'outer,
                _ = conn.closed() => {
                    warn!(tunnel_id = cfg.tunnel_id, "quic: connection closed; reconnecting");
                    break;
                }
                accept = listener.accept() => {
                    let (tcp, _) = match accept {
                        Ok(v) => v,
                        Err(e) => { warn!(tunnel_id = cfg.tunnel_id, err = %e, "quic: tcp accept"); continue; }
                    };
                    let _ = tcp.set_nodelay(true);
                    // Admission control before opening a stream: refuse when the
                    // tunnel is at max_connections or the process is over the
                    // memory soft cap. Dropping `tcp` closes the user's TCP
                    // cleanly. (max_connections == 0 ⇒ no cap.)
                    let cap = cfg.max_connections as usize;
                    let at_cap = cap > 0 && stats.active_conns.load(Ordering::Relaxed) as usize >= cap;
                    if at_cap || crate::memory::pressure_active() {
                        let prev = stats.conv_rejects.fetch_add(1, Ordering::Relaxed);
                        if prev % 1000 == 0 {
                            warn!(tunnel_id = cfg.tunnel_id, rejected_total = prev + 1, at_cap,
                                "quic: refusing new TCP connection (at max_connections or memory pressure)");
                        }
                        continue;
                    }
                    let conn = conn.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        match conn.open_bi().await {
                            Ok((send, recv)) => {
                                stats.conv_opens.fetch_add(1, Ordering::Relaxed);
                                stats.active_conns.fetch_add(1, Ordering::Relaxed);
                                bridge_stream(tcp, send, recv).await;
                                stats.active_conns.fetch_sub(1, Ordering::Relaxed);
                            }
                            Err(e) => debug!(err = %e, "quic: open_bi failed"),
                        }
                    });
                }
            }
        }
    }
    endpoint.close(0u32.into(), b"stop");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
}

async fn run_remote(
    endpoint: Endpoint,
    forward_target: SocketAddr,
    cfg: &QuicConfig,
    stats: Arc<EngineStats>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let stats = stats.clone();
                let stop = stop.clone();
                let tunnel_id = cfg.tunnel_id;
                let max_connections = cfg.max_connections;
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            info!(tunnel_id, "quic: connection accepted");
                            handle_remote_conn(conn, forward_target, max_connections, stats, stop).await;
                        }
                        Err(e) => debug!(tunnel_id, err = %e, "quic: incoming handshake failed"),
                    }
                });
            }
        }
    }
    endpoint.close(0u32.into(), b"stop");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
}

async fn handle_remote_conn(
    conn: Connection,
    forward_target: SocketAddr,
    max_connections: u32,
    stats: Arc<EngineStats>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = conn.closed() => break,
            res = conn.accept_bi() => {
                let (send, recv) = match res {
                    Ok(v) => v,
                    Err(_) => break,
                };
                // Admission control before dialing forward_target: refuse a new
                // stream when the tunnel is at max_connections or the process is
                // over the memory soft cap. Dropping `send`/`recv` resets the
                // stream so the Client's bridge sees it refused. (0 ⇒ no cap.)
                let cap = max_connections as usize;
                let at_cap = cap > 0 && stats.active_conns.load(Ordering::Relaxed) as usize >= cap;
                if at_cap || crate::memory::pressure_active() {
                    stats.conv_rejects.fetch_add(1, Ordering::Relaxed);
                    drop((send, recv));
                    continue;
                }
                let stats = stats.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(forward_target).await {
                        Ok(tcp) => {
                            let _ = tcp.set_nodelay(true);
                            stats.conv_opens.fetch_add(1, Ordering::Relaxed);
                            stats.active_conns.fetch_add(1, Ordering::Relaxed);
                            bridge_stream(tcp, send, recv).await;
                            stats.active_conns.fetch_sub(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            warn!(target = %forward_target, err = %e, "quic: dial forward_target failed");
                        }
                    }
                });
            }
        }
    }
}

/// Bidirectionally copy between a TCP connection and a QUIC bidi stream:
/// TCP read → QUIC send, QUIC recv → TCP write. Symmetric for both roles.
async fn bridge_stream(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let up = async move {
        let _ = tokio::io::copy(&mut tcp_read, &mut send).await;
        let _ = send.finish();
    };
    let down = async move {
        let _ = tokio::io::copy(&mut recv, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
    };
    tokio::join!(up, down);
}

/// Sleep for `dur`, or return early if stop fires. Returns true if stopped.
async fn sleep_or_stopped(dur: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = stop.changed() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}
