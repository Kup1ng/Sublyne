//! Multi-port QUIC engine loopback — the QUIC counterpart to
//! `forward_kcp_multiport_loopback.rs`. Two application ports share ONE
//! lossy, reordering datagram channel, demuxed only by the 2-byte
//! application-port tag.
//!
//! Each port runs its own Client + Remote `QuicEngine` pair. Both Client
//! engines connect to the same cosmetic QUIC peer address, but each engine
//! owns a separate endpoint + inbox, so the ONLY routing that keeps one
//! port's packets reaching the other's engine is the port tag. We stream a
//! DISTINCT payload on each port concurrently and assert each reads back its
//! own bytes.
//!
//! NOTE — weaker isolation proof than the KCP test: QUIC negotiates its own
//! random connection IDs per handshake, so a misrouted packet delivered to
//! the wrong engine is dropped as an unknown-DCID packet rather than
//! corrupting the other port's stream. To compensate, this test instruments
//! the channel: it asserts BOTH ports carried correctly-tagged traffic and
//! that ZERO datagrams were untagged / tagged for an unknown port — so an
//! engine that emits a missing/garbage tag fails loudly here instead of as a
//! slow timeout. The *production* per-port routing decode
//! (`TcpUploadRouter::route`) is itself covered deterministically by a unit
//! test in `data-plane/src/tunnel/remote.rs` (correct port → right inbox,
//! unknown port / too-short → dropped), which is the byte-level
//! no-cross-talk proof this end-to-end test can't give on its own.
//!
//! Needs NO CAP_NET_RAW and no real sockets beyond loopback TCP.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{
    inbound_channel, DatagramSink, EngineRole, InboundRx, InboundTx, QuicConfig, QuicEngine,
};
use sublyne_dataplane::multiport::{decode_tag, encode_tag, PORT_TAG_LEN};
use sublyne_dataplane::spec::QuicTuning;

const PORT_A: u16 = 8001;
const PORT_B: u16 = 8002;

struct TaggingSink {
    tx: mpsc::Sender<Vec<u8>>,
    port: u16,
    max: usize,
}

#[async_trait]
impl DatagramSink for TaggingSink {
    async fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        let mut buf = Vec::with_capacity(PORT_TAG_LEN + datagram.len());
        encode_tag(self.port, datagram, &mut buf);
        Ok(self.tx.try_send(buf).is_ok())
    }
    fn max_payload(&self) -> usize {
        self.max
    }
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Per-port delivery counter + a `bad` counter for any datagram that is
/// untagged (too short) or tagged for a port not in the route set — i.e. a
/// sender that emitted a missing/garbage tag. Shared across both directions.
struct TagStats {
    per_port: HashMap<u16, AtomicU64>,
    bad: AtomicU64,
}

async fn deliver(routes: &HashMap<u16, InboundTx>, pkt: Vec<u8>, stats: &TagStats) {
    match decode_tag(&pkt) {
        Some((port, body)) => match routes.get(&port) {
            Some(tx) => {
                if let Some(c) = stats.per_port.get(&port) {
                    c.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Decoded a port we route by but didn't pre-register a
                    // counter for — treat as unexpected.
                    stats.bad.fetch_add(1, Ordering::Relaxed);
                }
                let _ = tx.send(body.to_vec()).await;
            }
            // Tagged for a port outside the configured set: a misroute the
            // engine should never produce here.
            None => {
                stats.bad.fetch_add(1, Ordering::Relaxed);
            }
        },
        // Too short to carry the 2-byte tag — a malformed/untagged datagram.
        None => {
            stats.bad.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn routing_lossy_pipe(
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    routes: HashMap<u16, InboundTx>,
    stats: Arc<TagStats>,
    drop_pct: u64,
    reorder_pct: u64,
    seed: u64,
) {
    let mut s = seed;
    let mut held: Option<Vec<u8>> = None;
    while let Some(pkt) = in_rx.recv().await {
        if (lcg(&mut s) >> 33) % 100 < drop_pct {
            continue;
        }
        if held.is_none() && (lcg(&mut s) >> 33) % 100 < reorder_pct {
            held = Some(pkt);
            continue;
        }
        deliver(&routes, pkt, &stats).await;
        if let Some(h) = held.take() {
            deliver(&routes, h, &stats).await;
        }
    }
    if let Some(h) = held.take() {
        deliver(&routes, h, &stats).await;
    }
}

fn balanced_tuning() -> QuicTuning {
    QuicTuning {
        congestion: "cubic".to_string(),
        initial_rtt_ms: 100,
        max_idle_ms: 30_000,
        keep_alive_ms: 5_000,
        stream_recv_window: 8 * 1024 * 1024,
        conn_recv_window: 32 * 1024 * 1024,
    }
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[allow(clippy::too_many_arguments)]
async fn spawn_port_pair(
    port: u16,
    echo_addr: SocketAddr,
    c2r_tx: mpsc::Sender<Vec<u8>>,
    r2c_tx: mpsc::Sender<Vec<u8>>,
    client_inbox_rx: InboundRx,
    remote_inbox_rx: InboundRx,
    max_payload: usize,
    stop_rx: watch::Receiver<bool>,
) -> SocketAddr {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let client_engine = QuicEngine::new(
        QuicConfig {
            tunnel_id: port as i64,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: balanced_tuning(),
        },
        EngineRole::Client {
            listener: client_listener,
        },
        Arc::new(TaggingSink {
            tx: c2r_tx,
            port,
            max: max_payload,
        }),
    );
    tokio::spawn(client_engine.run(client_inbox_rx, stop_rx.clone()));

    let remote_engine = QuicEngine::new(
        QuicConfig {
            tunnel_id: 1000 + port as i64,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: balanced_tuning(),
        },
        EngineRole::Remote {
            forward_target: echo_addr,
        },
        Arc::new(TaggingSink {
            tx: r2c_tx,
            port,
            max: max_payload,
        }),
    );
    tokio::spawn(remote_engine.run(remote_inbox_rx, stop_rx.clone()));

    client_addr
}

async fn drive_and_check(client_addr: SocketAddr, payload: Vec<u8>, port: u16) {
    let len = payload.len();
    let stream = TcpStream::connect(client_addr).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&to_send).await.unwrap();
        write.flush().await.unwrap();
        write
    });
    let mut got = vec![0u8; len];
    read.read_exact(&mut got).await.unwrap();
    let _w = writer.await.unwrap();
    assert_eq!(got.len(), len, "port {port}: echoed length mismatch");
    assert!(
        got == payload,
        "port {port}: echoed bytes differ — QUIC did not preserve the stream, \
         or cross-talk leaked another port's bytes into this one"
    );
}

fn make_payload(len: usize, mut seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for b in v.iter_mut() {
        *b = (lcg(&mut seed) >> 40) as u8;
    }
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_multiport_streams_survive_without_crosstalk() {
    let payload_len = 128 * 1024;
    // QUIC needs >= 1200-byte datagrams; tunnel mtu 1400 leaves 1398.
    let max_payload = 1398;

    let payload_a = make_payload(payload_len, 0x0bad_f00d_dead_beef);
    let payload_b = make_payload(payload_len, 0xfeed_face_cafe_d00d);

    let echo_a = spawn_echo().await;
    let echo_b = spawn_echo().await;

    let (c2r_tx, c2r_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_tx, r2c_rx) = mpsc::channel::<Vec<u8>>(16_384);

    let (remote_in_a_tx, remote_in_a_rx) = inbound_channel();
    let (remote_in_b_tx, remote_in_b_rx) = inbound_channel();
    let (client_in_a_tx, client_in_a_rx) = inbound_channel();
    let (client_in_b_tx, client_in_b_rx) = inbound_channel();

    // Shared tag-fidelity stats across both directions: every datagram either
    // routes to PORT_A or PORT_B, and `bad` must stay 0 (no untagged / unknown
    // tag from either engine).
    let stats = Arc::new(TagStats {
        per_port: [(PORT_A, AtomicU64::new(0)), (PORT_B, AtomicU64::new(0))]
            .into_iter()
            .collect(),
        bad: AtomicU64::new(0),
    });

    // Lighter loss than KCP: QUIC's loss-based congestion control backs off
    // harder, so 4%/3% keeps two concurrent streams brisk while still
    // exercising retransmission + reordering recovery.
    let mut c2r_routes = HashMap::new();
    c2r_routes.insert(PORT_A, remote_in_a_tx);
    c2r_routes.insert(PORT_B, remote_in_b_tx);
    tokio::spawn(routing_lossy_pipe(
        c2r_rx,
        c2r_routes,
        stats.clone(),
        4,
        3,
        0xaaaa,
    ));

    let mut r2c_routes = HashMap::new();
    r2c_routes.insert(PORT_A, client_in_a_tx);
    r2c_routes.insert(PORT_B, client_in_b_tx);
    tokio::spawn(routing_lossy_pipe(
        r2c_rx,
        r2c_routes,
        stats.clone(),
        4,
        3,
        0x5555,
    ));

    let (stop_tx, stop_rx) = watch::channel(false);

    let addr_a = spawn_port_pair(
        PORT_A,
        echo_a,
        c2r_tx.clone(),
        r2c_tx.clone(),
        client_in_a_rx,
        remote_in_a_rx,
        max_payload,
        stop_rx.clone(),
    )
    .await;
    let addr_b = spawn_port_pair(
        PORT_B,
        echo_b,
        c2r_tx.clone(),
        r2c_tx.clone(),
        client_in_b_rx,
        remote_in_b_rx,
        max_payload,
        stop_rx.clone(),
    )
    .await;

    tokio::time::timeout(Duration::from_secs(50), async move {
        tokio::join!(
            drive_and_check(addr_a, payload_a, PORT_A),
            drive_and_check(addr_b, payload_b, PORT_B),
        )
    })
    .await
    .expect("timed out waiting for both port streams");

    // Tag fidelity: both ports carried correctly-tagged traffic, and no
    // datagram was untagged or tagged for an unknown port. This turns an
    // engine that emits a missing/garbage tag into a loud assertion instead of
    // a silent unknown-DCID drop that would only show up as a timeout.
    assert_eq!(
        stats.bad.load(Ordering::Relaxed),
        0,
        "every engine datagram must carry a valid PORT_A/PORT_B tag"
    );
    assert!(
        stats.per_port[&PORT_A].load(Ordering::Relaxed) > 0
            && stats.per_port[&PORT_B].load(Ordering::Relaxed) > 0,
        "both ports must have carried tagged datagrams (each engine pair ran)"
    );

    let _ = stop_tx.send(true);
}
