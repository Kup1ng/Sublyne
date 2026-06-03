//! In-process QUIC engine loopback under a lossy, reordering datagram
//! channel — the QUIC counterpart to `forward_kcp_loopback.rs`.
//!
//! Wires two `QuicEngine`s (Client + Remote) through an in-process pipe that
//! DROPS and REORDERS a fraction of datagrams and asserts a multi-hundred-KB
//! byte stream survives intact end to end. No CAP_NET_RAW or real sockets
//! beyond loopback TCP, so it runs on stock CI runners.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{
    inbound_channel, DatagramSink, EngineRole, InboundTx, QuicConfig, QuicEngine,
};
use sublyne_dataplane::spec::QuicTuning;

struct PipeSink {
    tx: mpsc::Sender<Vec<u8>>,
    max: usize,
}

#[async_trait]
impl DatagramSink for PipeSink {
    async fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        Ok(self.tx.try_send(datagram.to_vec()).is_ok())
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

async fn lossy_pipe(
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: InboundTx,
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
        let _ = out_tx.send(pkt).await;
        if let Some(h) = held.take() {
            let _ = out_tx.send(h).await;
        }
    }
    if let Some(h) = held.take() {
        let _ = out_tx.send(h).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_stream_survives_lossy_reordering_channel() {
    let payload_len = 256 * 1024;
    // QUIC needs >= 1200-byte datagrams; tunnel mtu 1400 leaves 1398.
    let max_payload = 1398;

    let mut seed = 0x0bad_f00d_dead_beefu64;
    let mut payload = vec![0u8; payload_len];
    for b in payload.iter_mut() {
        *b = (lcg(&mut seed) >> 40) as u8;
    }

    let echo_addr = spawn_echo().await;

    let (c2r_sink_tx, c2r_in_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_sink_tx, r2c_in_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (remote_inbound_tx, remote_inbound_rx) = inbound_channel();
    let (client_inbound_tx, client_inbound_rx) = inbound_channel();

    // Lighter loss than the KCP test: QUIC's loss-based congestion control
    // backs off harder, so 4% keeps the test brisk while still exercising
    // retransmission + reordering recovery.
    tokio::spawn(lossy_pipe(c2r_in_rx, remote_inbound_tx, 4, 3, 0xaaaa));
    tokio::spawn(lossy_pipe(r2c_in_rx, client_inbound_tx, 4, 3, 0x5555));

    let (stop_tx, stop_rx) = watch::channel(false);

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_engine = QuicEngine::new(
        QuicConfig {
            tunnel_id: 1,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: balanced_tuning(),
        },
        EngineRole::Client {
            listener: client_listener,
        },
        Arc::new(PipeSink {
            tx: c2r_sink_tx,
            max: max_payload,
        }),
    );
    tokio::spawn(client_engine.run(client_inbound_rx, stop_rx.clone()));

    let remote_engine = QuicEngine::new(
        QuicConfig {
            tunnel_id: 2,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: balanced_tuning(),
        },
        EngineRole::Remote {
            forward_target: echo_addr,
        },
        Arc::new(PipeSink {
            tx: r2c_sink_tx,
            max: max_payload,
        }),
    );
    tokio::spawn(remote_engine.run(remote_inbound_rx, stop_rx.clone()));

    let body = tokio::time::timeout(Duration::from_secs(40), async move {
        let stream = TcpStream::connect(client_addr).await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let to_send = payload.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&to_send).await.unwrap();
            write.flush().await.unwrap();
            write
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
        "echoed bytes differ from sent — QUIC did not preserve the stream over the lossy channel"
    );

    let _ = stop_tx.send(true);
}
