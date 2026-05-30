//! Upload-throughput DIAGNOSTIC benchmark (ASK 2 evidence — not a fix).
//!
//! The live boxes show two paradoxes on the UPLOAD direction:
//!   * udp-wg upload: 0.32 Mbit/s on Speedtest vs 9 Mbit/s on LibreSpeed
//!     through the SAME tunnel (~28x), and
//!   * tcp-socks5 upload: ~4-8 Mbit/s while the SOCKS5 proxy itself can
//!     do ~80 Mbit/s (~10x gap).
//!
//! Neither is a Sublyne throughput cap per se (the audit confirmed the
//! sockets are buffer-tuned). They are explained by TCP dynamics on a
//! high-RTT (~87 ms) lossy path interacting with HOW MANY parallel TCP
//! streams / connections carry the bytes:
//!   * A SINGLE TCP stream on a lossy high-RTT path collapses (every loss
//!     halves cwnd; recovery takes RTTs) — the Speedtest /
//!     single-SOCKS5-connection regime.
//!   * Several PARALLEL streams aggregate far better — the LibreSpeed /
//!     multi-link regime.
//!   * BBR congestion control (vs the default CUBIC) is far less
//!     loss-sensitive on such a path — the "add bbr+fq to setup.sh" lever.
//!
//! This test MEASURES those three effects over a localhost TCP path so the
//! diagnosis is backed by CI numbers, not just prose. It changes no
//! product behaviour. The CI job injects ~87 ms RTT + ~0.5% loss with
//! `tc netem`; locally (no netem) it just runs and prints without
//! asserting (a zero-loss loopback saturates either way, nothing to
//! compare). Each run is DURATION-bounded so the very different rates take
//! comparable wall-clock time.

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

/// Seconds each measurement sends for. 8 s under the netem harness (the
/// real diagnosis); a quick 2 s otherwise so the plain `cargo test` run in
/// the main CI job stays fast (it only prints — no assertion). Overridable
/// via SUBLYNE_BENCH_SECS.
fn bench_secs() -> u64 {
    let default = if std::env::var("SUBLYNE_BENCH_RTT").as_deref() == Ok("1") {
        8
    } else {
        2
    };
    std::env::var("SUBLYNE_BENCH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| (1..=30).contains(n))
        .unwrap_or(default)
}

/// Try to pin a socket's TCP congestion control (e.g. "bbr" / "cubic")
/// before connect. Returns false if the algorithm isn't available (module
/// not loaded) so the caller can skip that comparison gracefully.
fn set_congestion(fd: i32, algo: &str) -> bool {
    // SAFETY: fd is an open socket for the duration; we pass a valid
    // pointer + length for the algorithm name.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algo.as_ptr() as *const libc::c_void,
            algo.len() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Push as much as possible across `streams` parallel TCP connections to a
/// localhost sink for `bench_secs()` seconds and return the aggregate
/// throughput in Mbit/s. Each connection is opened with the requested
/// congestion control. Returns None if `cc` could not be set (module
/// missing) so the caller can skip that comparison.
async fn measure(streams: usize, cc: &str) -> Option<f64> {
    let dur = Duration::from_secs(bench_secs());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Sink: accept `streams` connections, drain each, total the bytes.
    let recv_total = received.clone();
    let sink = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..streams {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let total = recv_total.clone();
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            total.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });

    let start = Instant::now();
    let mut senders = Vec::new();
    for i in 0..streams {
        let s = TcpSocket::new_v4().expect("socket");
        let cc_ok = set_congestion(s.as_raw_fd(), cc);
        if i == 0 && !cc_ok {
            return None; // cc unavailable on this kernel — skip comparison
        }
        let stop = stop.clone();
        senders.push(tokio::spawn(async move {
            let mut stream = match s.connect(addr).await {
                Ok(st) => st,
                Err(_) => return,
            };
            let chunk = vec![0u8; 256 * 1024];
            while !stop.load(Ordering::Relaxed) {
                if stream.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            stream.flush().await.ok();
            stream.shutdown().await.ok();
        }));
    }

    tokio::time::sleep(dur).await;
    stop.store(true, Ordering::Relaxed);
    for h in senders {
        let _ = h.await;
    }
    let _ = sink.await;
    let elapsed = start.elapsed().as_secs_f64();
    let bytes = received.load(Ordering::Relaxed) as f64;
    Some(bytes * 8.0 / elapsed / 1_000_000.0)
}

#[tokio::test]
async fn upload_stream_count_and_cc_diagnosis() {
    let one_cubic = measure(1, "cubic").await;
    let four_cubic = measure(4, "cubic").await;
    let one_bbr = measure(1, "bbr").await;

    let f = |o: Option<f64>| o.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".into());
    eprintln!(
        "upload stream diagnosis: 1-stream/cubic={} Mbit/s  4-stream/cubic={} Mbit/s  1-stream/bbr={} Mbit/s",
        f(one_cubic),
        f(four_cubic),
        f(one_bbr),
    );

    // Only assert under the netem harness (RTT + loss), where stream count
    // and CC actually matter; on a clean loopback both saturate and the
    // ratios are meaningless. Guard on the single cubic stream being
    // genuinely throttled so a misconfigured runner can't fail spuriously.
    if std::env::var("SUBLYNE_BENCH_RTT").as_deref() == Ok("1") {
        let (Some(one), Some(four)) = (one_cubic, four_cubic) else {
            eprintln!("upload stream diagnosis: cubic unavailable, skipping assertion");
            return;
        };
        if one < 80.0 {
            // Parallel streams aggregate far better than a single stream on
            // a lossy high-RTT path — the core of the ASK 2 diagnosis
            // (Speedtest few-stream vs LibreSpeed multi-stream; one SOCKS5
            // connection vs striping across N).
            assert!(
                four >= 2.0 * one,
                "expected 4 parallel streams to beat 1 stream >=2x on the lossy high-RTT \
                 harness: 1-stream={one:.1} Mbit/s 4-stream={four:.1} Mbit/s"
            );
            if let Some(bbr) = one_bbr {
                eprintln!(
                    "upload stream diagnosis: single-stream BBR/CUBIC ratio = {:.2}x \
                     (BBR is far less loss-sensitive — the 'add bbr+fq' lever)",
                    bbr / one.max(0.001)
                );
            }
        } else {
            eprintln!(
                "upload stream diagnosis: single stream not throttled ({one:.1} Mbit/s) — \
                 netem harness likely inactive; skipping ratio assertion"
            );
        }
    }
}
