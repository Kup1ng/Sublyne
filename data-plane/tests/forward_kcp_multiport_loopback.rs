//! Multi-port KCP loopback: two application ports, each with its own KCP
//! engine, demuxed by the 2-byte application-port tag, over a lossy
//! reordering channel.
//!
//! Proves per-port isolation: concurrent streams on port A and port B
//! both survive byte-exact and never cross-route (each forwards to its
//! own echo target). No raw sockets — runs on stock CI.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use sublyne_dataplane::forward::{self, DatagramSink, Engine, EngineConfig, EngineRole, EngineSet};
use sublyne_dataplane::metrics::TunnelMetrics;
use sublyne_dataplane::multiport;
use sublyne_dataplane::spec::KcpTuning;

/// Sink that prepends the 2-byte application-port tag before handing the
/// KCP segment to the shared lossy channel — exactly what the real
/// multi-port Client/Remote sinks do.
struct TagSink {
    tx: mpsc::Sender<Vec<u8>>,
    port: u16,
}

#[async_trait]
impl DatagramSink for TagSink {
    async fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        let mut tagged = Vec::with_capacity(multiport::PORT_TAG_LEN + datagram.len());
        multiport::encode_tag(self.port, datagram, &mut tagged);
        Ok(self.tx.try_send(tagged).is_ok())
    }
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Drain `in_rx`, dropping/reordering a fraction, routing the rest into
/// the peer engine set (which decodes the port tag and demuxes by conv id).
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
            continue;
        }
        if held.is_none() && (lcg(&mut s) >> 33) % 100 < reorder_pct {
            held = Some(pkt);
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
fn make_engine(
    role: EngineRole,
    tunnel_id: i64,
    port: u16,
    tx: mpsc::Sender<Vec<u8>>,
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
        Arc::new(TagSink { tx, port }),
        active,
        metrics,
        clock,
        stop_rx,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kcp_multiport_streams_are_isolated() {
    let ports = [8001u16, 8002u16];
    let payload_len = 128 * 1024;
    let clock = Instant::now();
    let (stop_tx, stop_rx) = watch::channel(false);

    // Distinct echo target per port — so a mis-routed segment can't
    // accidentally round-trip on the wrong port.
    let echo = [spawn_echo().await, spawn_echo().await];

    // One lossy channel per direction; the port tag disambiguates ports.
    let (c2r_tx, c2r_rx) = mpsc::channel::<Vec<u8>>(16_384);
    let (r2c_tx, r2c_rx) = mpsc::channel::<Vec<u8>>(16_384);

    // Client engines (one per port), each accepting on its own TCP port.
    let client_active = Arc::new(AtomicU64::new(0));
    let client_metrics = Arc::new(TunnelMetrics::new(1, "client", "udp"));
    let mut client_engines: HashMap<u16, Arc<Engine>> = HashMap::new();
    let mut client_addrs: HashMap<u16, SocketAddr> = HashMap::new();
    for &port in &ports {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        client_addrs.insert(port, listener.local_addr().unwrap());
        let engine = make_engine(
            EngineRole::Client,
            1,
            port,
            c2r_tx.clone(),
            client_active.clone(),
            client_metrics.clone(),
            clock,
            stop_rx.clone(),
        );
        tokio::spawn(engine.clone().accept_loop(listener));
        client_engines.insert(port, engine);
    }
    let client_set = EngineSet::multi(client_engines, 1);

    // Remote engines (one per port), each dialing its own echo target.
    let remote_active = Arc::new(AtomicU64::new(0));
    let remote_metrics = Arc::new(TunnelMetrics::new(2, "remote", "udp"));
    let mut remote_engines: HashMap<u16, Arc<Engine>> = HashMap::new();
    for (i, &port) in ports.iter().enumerate() {
        let engine = make_engine(
            EngineRole::Remote {
                forward_target: echo[i],
            },
            2,
            port,
            r2c_tx.clone(),
            remote_active.clone(),
            remote_metrics.clone(),
            clock,
            stop_rx.clone(),
        );
        remote_engines.insert(port, engine);
    }
    let remote_set = EngineSet::multi(remote_engines, 2);

    tokio::spawn(lossy_pipe(c2r_rx, remote_set.clone(), 10, 5, 0xaaaa));
    tokio::spawn(lossy_pipe(r2c_rx, client_set.clone(), 10, 5, 0x5555));

    // Drive both ports concurrently, each with its own distinct stream.
    let mut handles = Vec::new();
    for &port in &ports {
        let addr = client_addrs[&port];
        let mut seed = 0x1111_2222_3333_4444u64 ^ u64::from(port);
        let mut payload = vec![0u8; payload_len];
        for b in payload.iter_mut() {
            *b = (lcg(&mut seed) >> 40) as u8;
        }
        handles.push(tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
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
            assert!(
                got == payload,
                "port {port} stream corrupted or cross-routed"
            );
        }));
    }

    for h in handles {
        tokio::time::timeout(Duration::from_secs(30), h)
            .await
            .expect("a per-port stream timed out")
            .expect("a per-port stream task panicked");
    }

    let _ = stop_tx.send(true);
}
