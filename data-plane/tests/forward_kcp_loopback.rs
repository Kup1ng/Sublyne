//! In-process KCP engine loopback under a lossy, reordering datagram
//! channel.
//!
//! This is the core correctness proof for `forward_protocol=tcp` + KCP:
//! it wires two engines (Client + Remote) together through an in-process
//! pipe that DROPS and REORDERS a configurable fraction of datagrams —
//! exactly the abuse the spoof download path inflicts — and asserts a
//! multi-hundred-KB byte stream survives intact end to end.
//!
//! It needs NO CAP_NET_RAW and no real sockets beyond loopback TCP, so it
//! runs on stock CI runners (unlike the raw-socket tunnel loopback tests).

use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{self, DatagramSink, Engine, EngineConfig, EngineRole, EngineSet};
use sublyne_dataplane::metrics::TunnelMetrics;
use sublyne_dataplane::spec::KcpTuning;

/// Best-effort datagram sink that forwards each KCP segment into an mpsc
/// the lossy pipe drains. Mirrors the real channel's drop-on-full
/// semantics via `try_send`.
struct PipeSink {
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl DatagramSink for PipeSink {
    async fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        Ok(self.tx.try_send(datagram.to_vec()).is_ok())
    }
}

/// Deterministic LCG so the test is reproducible without a `rand` dep.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Drain `in_rx`, dropping `drop_pct`% of datagrams and reordering
/// `reorder_pct`% (by holding one back and releasing it after the next),
/// routing the rest into the peer engine set (which demuxes by conv id).
async fn lossy_pipe(
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    peer: Arc<EngineSet>,
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
        peer.route_tagged(&pkt);
        if let Some(h) = held.take() {
            peer.route_tagged(&h);
        }
    }
    if let Some(h) = held.take() {
        peer.route_tagged(&h);
    }
}

/// Aggressive-recovery tuning so the test converges quickly under loss.
fn test_tuning() -> KcpTuning {
    KcpTuning {
        nodelay: 1,
        interval: 10,
        resend: 1,
        nc: 1,
        snd_wnd: 512,
        rcv_wnd: 512,
        mtu: 0,
    }
}

/// Streaming TCP echo server: copies every byte it reads straight back,
/// so the loopback test doesn't depend on FIN propagation through KCP.
async fn spawn_echo() -> std::net::SocketAddr {
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

fn make_engine(
    role: EngineRole,
    tunnel_id: i64,
    sink: Arc<dyn DatagramSink>,
    active: Arc<AtomicU64>,
    metrics: Arc<TunnelMetrics>,
    clock: Instant,
    stop_rx: watch::Receiver<bool>,
) -> Arc<Engine> {
    let tuning = test_tuning();
    Engine::new(
        role,
        EngineConfig {
            tunnel_id,
            tuning,
            kcp_mtu: forward::kcp_mtu(1400, &tuning),
            idle_timeout_sec: 300,
            max_conns: 1000,
        },
        sink,
        active,
        metrics,
        clock,
        stop_rx,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_stream_survives_lossy_reordering_channel() {
    let payload_len = 256 * 1024;

    // A pseudo-random byte stream: easy to verify, hard to pass by accident.
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut payload = vec![0u8; payload_len];
    for b in payload.iter_mut() {
        *b = (lcg(&mut seed) >> 40) as u8;
    }

    let echo_addr = spawn_echo().await;
    let clock = Instant::now();
    let (stop_tx, stop_rx) = watch::channel(false);

    // Two lossy pipes: Client→Remote and Remote→Client.
    let (c2r_tx, c2r_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_tx, r2c_rx) = mpsc::channel::<Vec<u8>>(16_384);

    // Client engine: accept user TCP on an ephemeral port.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_metrics = Arc::new(TunnelMetrics::new(1, "client", "udp"));
    let client_engine = make_engine(
        EngineRole::Client,
        1,
        Arc::new(PipeSink { tx: c2r_tx }),
        Arc::new(AtomicU64::new(0)),
        client_metrics,
        clock,
        stop_rx.clone(),
    );
    let client_set = EngineSet::single(client_engine.clone(), 1);
    tokio::spawn(client_engine.accept_loop(client_listener));

    // Remote engine: dial the echo server per learned conv. No run loop —
    // route_tagged lazily creates + dials convs.
    let remote_metrics = Arc::new(TunnelMetrics::new(2, "remote", "udp"));
    let remote_engine = make_engine(
        EngineRole::Remote {
            forward_target: echo_addr,
        },
        2,
        Arc::new(PipeSink { tx: r2c_tx }),
        Arc::new(AtomicU64::new(0)),
        remote_metrics,
        clock,
        stop_rx.clone(),
    );
    let remote_set = EngineSet::single(remote_engine, 2);

    tokio::spawn(lossy_pipe(c2r_rx, remote_set.clone(), 10, 5, 0xaaaa));
    tokio::spawn(lossy_pipe(r2c_rx, client_set.clone(), 10, 5, 0x5555));

    // User connects to the Client engine, streams the payload, and reads
    // the echoed bytes back concurrently (no EOF dependency).
    let body = tokio::time::timeout(Duration::from_secs(30), async move {
        let stream = TcpStream::connect(client_addr).await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let to_send = payload.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&to_send).await.unwrap();
            write.flush().await.unwrap();
            write // keep the connection open until the reader has everything
        });
        let mut got = vec![0u8; payload_len];
        read.read_exact(&mut got).await.unwrap();
        let _w = writer.await.unwrap();
        (payload, got)
    })
    .await
    .expect("timed out waiting for the echoed stream");

    let (sent, got) = body;
    assert_eq!(got.len(), sent.len(), "echoed length mismatch");
    assert!(
        got == sent,
        "echoed bytes differ from sent — KCP did not preserve the stream over the lossy channel"
    );

    let _ = stop_tx.send(true);
}
