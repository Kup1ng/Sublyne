//! Multi-port KCP engine loopback: two application ports share ONE lossy,
//! reordering datagram channel, demuxed only by the 2-byte application-port
//! tag — the v4.0.0 multi-port TCP-forwarding correctness proof.
//!
//! This wires two independent `KcpEngine` pairs (Client + Remote per port)
//! whose sinks feed a SHARED per-direction channel. A routing pipe DROPS and
//! REORDERS a fraction of datagrams (exactly the abuse the spoof download
//! path inflicts), then decodes the port tag with the SAME
//! `multiport::{encode_tag,decode_tag}` wire contract the dataplane uses and
//! routes the untagged body to the matching port's engine inbox — the test's
//! stand-in for the production `RemoteForwardSink`/`ClientForwardSink` tag +
//! `TcpUploadRouter`/`PortRouter::TcpMulti` demux.
//!
//! Why this catches cross-talk: every Client engine starts its KCP
//! `conv_counter` at 1, so port A and port B BOTH carry a "conv 1". The only
//! thing keeping A's bytes out of B's engine is the port tag. We stream a
//! DISTINCT pseudo-random payload on each port, concurrently, and assert each
//! port reads back exactly its own bytes — a dropped/misrouted tag would feed
//! A's conv-1 segments into B's conv-1 stream and corrupt it.
//!
//! Needs NO CAP_NET_RAW and no real sockets beyond loopback TCP, so it runs
//! on stock CI runners.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{
    inbound_channel, DatagramSink, EngineConfig, EngineRole, InboundRx, InboundTx, KcpEngine,
};
use sublyne_dataplane::multiport::{decode_tag, encode_tag, PORT_TAG_LEN};
use sublyne_dataplane::spec::KcpTuning;

const PORT_A: u16 = 8001;
const PORT_B: u16 = 8002;

/// Sink that prepends the 2-byte application-port tag to every engine
/// datagram and forwards it into the shared per-direction channel — exactly
/// what `ClientForwardSink`/`RemoteForwardSink` do in multi-port mode.
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

/// Deterministic LCG so the test is reproducible without a `rand` dep.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Decode the port tag and forward the untagged body to the matching port's
/// engine inbox. An unknown / untagged datagram is dropped (it must never
/// happen in this test — every sink tags).
async fn deliver(routes: &HashMap<u16, InboundTx>, pkt: Vec<u8>) {
    if let Some((port, body)) = decode_tag(&pkt) {
        if let Some(tx) = routes.get(&port) {
            let _ = tx.send(body.to_vec()).await;
        }
    }
}

/// Drain the shared channel, dropping `drop_pct`% and reordering
/// `reorder_pct`% of datagrams, then tag-route the survivors to per-port
/// inboxes.
async fn routing_lossy_pipe(
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    routes: HashMap<u16, InboundTx>,
    drop_pct: u64,
    reorder_pct: u64,
    seed: u64,
) {
    let mut s = seed;
    let mut held: Option<Vec<u8>> = None;
    while let Some(pkt) = in_rx.recv().await {
        if (lcg(&mut s) >> 33) % 100 < drop_pct {
            continue; // dropped on the wire
        }
        if held.is_none() && (lcg(&mut s) >> 33) % 100 < reorder_pct {
            held = Some(pkt); // hold this one back; release after the next
            continue;
        }
        deliver(&routes, pkt).await;
        if let Some(h) = held.take() {
            deliver(&routes, h).await;
        }
    }
    if let Some(h) = held.take() {
        deliver(&routes, h).await;
    }
}

fn lossy_tuning() -> KcpTuning {
    KcpTuning {
        nodelay: 1,
        interval: 10,
        resend: 1,
        nc: 1,
        snd_wnd: 512,
        rcv_wnd: 512,
    }
}

/// Streaming TCP echo server: copies every byte straight back, so the test
/// doesn't depend on FIN propagation through KCP.
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

/// Bring up one port's Client + Remote engine pair over the shared channels,
/// returning the Client engine's listen address (where the user connects).
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

    // Client engine: accept user TCP, tag its upload segments with `port`.
    let client_engine = KcpEngine::new(
        EngineConfig {
            tunnel_id: port as i64,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: lossy_tuning(),
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

    // Remote engine: dial this port's echo server, tag its download segments.
    let remote_engine = KcpEngine::new(
        EngineConfig {
            tunnel_id: 1000 + port as i64,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: lossy_tuning(),
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

/// Connect to one port's Client engine, stream `payload`, and read it back,
/// asserting an exact round-trip (any cross-talk corrupts the comparison).
async fn drive_and_check(client_addr: SocketAddr, payload: Vec<u8>, port: u16) {
    let len = payload.len();
    let stream = TcpStream::connect(client_addr).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&to_send).await.unwrap();
        write.flush().await.unwrap();
        write // keep the connection open until the reader has everything
    });
    let mut got = vec![0u8; len];
    read.read_exact(&mut got).await.unwrap();
    let _w = writer.await.unwrap();
    assert_eq!(got.len(), len, "port {port}: echoed length mismatch");
    assert!(
        got == payload,
        "port {port}: echoed bytes differ — KCP did not preserve the stream, \
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
async fn kcp_multiport_streams_survive_without_crosstalk() {
    let payload_len = 128 * 1024;
    let max_payload = 1398; // tunnel mtu 1400 minus the 2-byte tag

    // Distinct payloads per port so a misrouted tag corrupts the comparison.
    let payload_a = make_payload(payload_len, 0x1111_2222_3333_4444);
    let payload_b = make_payload(payload_len, 0xaaaa_bbbb_cccc_dddd);

    let echo_a = spawn_echo().await;
    let echo_b = spawn_echo().await;

    // One shared lossy channel per direction; both ports' sinks feed it.
    let (c2r_tx, c2r_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_tx, r2c_rx) = mpsc::channel::<Vec<u8>>(16_384);

    // Per-engine inboxes.
    let (remote_in_a_tx, remote_in_a_rx) = inbound_channel();
    let (remote_in_b_tx, remote_in_b_rx) = inbound_channel();
    let (client_in_a_tx, client_in_a_rx) = inbound_channel();
    let (client_in_b_tx, client_in_b_rx) = inbound_channel();

    // Upload (Client→Remote): tag → remote engine inbox.
    let mut c2r_routes = HashMap::new();
    c2r_routes.insert(PORT_A, remote_in_a_tx);
    c2r_routes.insert(PORT_B, remote_in_b_tx);
    tokio::spawn(routing_lossy_pipe(c2r_rx, c2r_routes, 10, 5, 0xaaaa));

    // Download (Remote→Client): tag → client engine inbox.
    let mut r2c_routes = HashMap::new();
    r2c_routes.insert(PORT_A, client_in_a_tx);
    r2c_routes.insert(PORT_B, client_in_b_tx);
    tokio::spawn(routing_lossy_pipe(r2c_rx, r2c_routes, 10, 5, 0x5555));

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

    // Drive BOTH ports concurrently so the shared channel carries both
    // streams at once — the worst case for cross-talk.
    tokio::time::timeout(Duration::from_secs(40), async move {
        tokio::join!(
            drive_and_check(addr_a, payload_a, PORT_A),
            drive_and_check(addr_b, payload_b, PORT_B),
        )
    })
    .await
    .expect("timed out waiting for both port streams");

    let _ = stop_tx.send(true);
}
