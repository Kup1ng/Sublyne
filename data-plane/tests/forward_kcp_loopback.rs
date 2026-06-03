//! In-process KCP engine loopback under a lossy, reordering datagram
//! channel.
//!
//! This is the core correctness proof for `forward_protocol=tcp` + KCP:
//! it wires two `KcpEngine`s (Client + Remote) together through an
//! in-process pipe that DROPS and REORDERS a configurable fraction of
//! datagrams — exactly the abuse the spoof download path inflicts — and
//! asserts a multi-hundred-KB byte stream survives intact end to end.
//!
//! It needs NO CAP_NET_RAW and no real sockets beyond loopback TCP, so it
//! runs on stock CI runners (unlike the raw-socket tunnel loopback tests).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{
    inbound_channel, DatagramSink, EngineConfig, EngineRole, InboundTx, KcpEngine,
};
use sublyne_dataplane::spec::KcpTuning;

/// Best-effort datagram sink that forwards into an mpsc the lossy pipe
/// drains. Mirrors the real channel's drop-on-full semantics via
/// `try_send`.
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

/// Deterministic LCG so the test is reproducible without a `rand` dep.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Drain `in_rx`, dropping `drop_pct`% of datagrams and reordering
/// `reorder_pct`% (by holding one back and releasing it after the next),
/// forwarding the rest into `out_tx`.
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
            continue; // dropped on the wire
        }
        if held.is_none() && (lcg(&mut s) >> 33) % 100 < reorder_pct {
            held = Some(pkt); // hold this one back; release after the next
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

fn lossy_tuning() -> KcpTuning {
    // "Lossy / aggressive recovery" preset: fast retransmit, congestion
    // off, moderate windows.
    KcpTuning {
        nodelay: 1,
        interval: 10,
        resend: 1,
        nc: 1,
        snd_wnd: 512,
        rcv_wnd: 512,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_stream_survives_lossy_reordering_channel() {
    let payload_len = 256 * 1024;
    let max_payload = 1398; // tunnel mtu 1400 minus the 2-byte tag reserve

    // Build a value that's easy to verify and hard to "accidentally" pass:
    // a pseudo-random byte stream.
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut payload = vec![0u8; payload_len];
    for b in payload.iter_mut() {
        *b = (lcg(&mut seed) >> 40) as u8;
    }

    let echo_addr = spawn_echo().await;

    // Two lossy pipes: Client→Remote and Remote→Client.
    let (c2r_sink_tx, c2r_in_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_sink_tx, r2c_in_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (remote_inbound_tx, remote_inbound_rx) = inbound_channel();
    let (client_inbound_tx, client_inbound_rx) = inbound_channel();

    tokio::spawn(lossy_pipe(c2r_in_rx, remote_inbound_tx, 10, 5, 0xaaaa));
    tokio::spawn(lossy_pipe(r2c_in_rx, client_inbound_tx, 10, 5, 0x5555));

    let (stop_tx, stop_rx) = watch::channel(false);

    // Client engine: accept user TCP on an ephemeral port.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_engine = KcpEngine::new(
        EngineConfig {
            tunnel_id: 1,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: lossy_tuning(),
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

    // Remote engine: dial the echo server per learned conv.
    let remote_engine = KcpEngine::new(
        EngineConfig {
            tunnel_id: 2,
            idle_timeout_sec: 300,
            max_connections: 10_000,
            tuning: lossy_tuning(),
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

    // User connects to the Client engine, streams the payload, and reads
    // the echoed bytes back concurrently (no EOF dependency).
    let body = tokio::time::timeout(Duration::from_secs(30), async move {
        let stream = TcpStream::connect(client_addr).await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let to_send = payload.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&to_send).await.unwrap();
            write.flush().await.unwrap();
            // Keep the connection open until the reader has everything.
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
        "echoed bytes differ from sent — KCP did not preserve the stream over the lossy channel"
    );

    let _ = stop_tx.send(true);
}
