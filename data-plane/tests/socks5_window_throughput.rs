//! SOCKS5 upload window/buffer benchmark — the v2.2.0 "TCP RWIN" fix.
//!
//! Before v2.2.0 the SOCKS5 substrate sockets were the only data-path
//! sockets left on kernel defaults: the Remote upload listener was never
//! buffer-tuned, so accepted upload connections advertised a small TCP
//! receive window and a bulk SOCKS5 upload could not fill a
//! high-bandwidth × high-RTT path. v2.2.0 applies `perf::tune_socket`
//! (the same forced-buffer path every other data-path socket already
//! uses) to the listener *before it accepts* — which is what sets the
//! advertised window scale — and to the Client's outbound stream.
//!
//! This test measures the achieved throughput of a localhost TCP upload
//! with the listener/socket buffers TUNED vs left on kernel DEFAULTS.
//!
//! - In the dedicated CI job (`.github/workflows/ci.yml`) the runner
//!   injects a loopback RTT with `tc netem` and shrinks `tcp_rmem` /
//!   `tcp_wmem` so the untuned (autotuned) path is window-limited. There
//!   `SUBLYNE_BENCH_RTT=1` is set and the test ASSERTS the tuned path is
//!   ≥ 3× faster — the headline "measurably faster" number.
//! - In ordinary `cargo test` (zero-RTT loopback) the window size is
//!   irrelevant: both runs saturate the loopback, so the ratio assertion
//!   is skipped and the test only verifies every byte arrives. This keeps
//!   it a cheap, always-green correctness check off the netem path.

use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Floor on the overridable payload size — at least 1 MiB so a typo can't
/// shrink the transfer to a meaningless few bytes.
const MIN_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Bytes pushed per measurement. Overridable so the CI job can shrink it
/// if the runner is slow (the untuned, window-limited run is the long
/// pole under injected RTT). Default 8 MiB.
fn payload_bytes() -> usize {
    std::env::var("SUBLYNE_BENCH_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n >= MIN_PAYLOAD_BYTES)
        .unwrap_or(8 * 1024 * 1024)
}

/// Push `payload` bytes from a localhost client to a localhost sink and
/// return the achieved throughput in megabits/sec. When `tuned`, the
/// listener (before accept) and the client stream are sized with the same
/// `perf::tune_socket` the dataplane now applies to the SOCKS5 sockets;
/// otherwise both are left on kernel defaults — the pre-v2.2.0 behaviour.
async fn measure_throughput_mbps(tuned: bool) -> f64 {
    let payload = payload_bytes();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    if tuned {
        // Size the LISTENER before it accepts so accepted sockets inherit
        // the buffer and a large advertised window scale — the exact call
        // remote.rs makes on the SOCKS5 upload listener.
        sublyne_dataplane::perf::tune_socket(&listener, "bench/listener");
    }
    let addr = listener.local_addr().expect("addr");

    // Sink: accept one connection, drain it to EOF, count bytes.
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0usize;
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        total
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    if tuned {
        sublyne_dataplane::perf::tune_socket(&client, "bench/client");
    }
    let chunk = vec![0u8; 256 * 1024];
    let start = Instant::now();
    let mut sent = 0usize;
    while sent < payload {
        let n = (payload - sent).min(chunk.len());
        client.write_all(&chunk[..n]).await.expect("write");
        sent += n;
    }
    client.flush().await.ok();
    // FIN so the sink's read returns 0 and we can read the total.
    client.shutdown().await.ok();
    let elapsed = start.elapsed();
    let received = server.await.expect("join sink");
    assert_eq!(received, payload, "sink must receive every byte ({tuned})");
    (received as f64) * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
}

#[tokio::test]
async fn tuned_buffers_lift_socks5_upload_throughput_under_rtt() {
    // Untuned first (the long pole under RTT), then tuned.
    let default_mbps = measure_throughput_mbps(false).await;
    let tuned_mbps = measure_throughput_mbps(true).await;
    let ratio = tuned_mbps / default_mbps.max(0.001);
    eprintln!(
        "socks5 window bench: default(autotuned)={default_mbps:.1} Mbit/s  \
         tuned(forced buffers)={tuned_mbps:.1} Mbit/s  ratio={ratio:.2}x"
    );

    // Only the netem CI job (injected RTT + shrunk tcp_rmem) makes window
    // size the binding constraint; there the tuned path must win clearly.
    // Guard the assertion on the harness actually being active: if the
    // untuned path is NOT window-limited (throughput already high), the
    // netem/sysctl setup didn't take effect on this runner, so we print
    // and skip rather than fail spuriously. At 50 ms RTT a small (≤64 KiB)
    // window caps the untuned path well under 50 Mbit/s, so this threshold
    // reliably distinguishes "harness active" from "no real constraint".
    if std::env::var("SUBLYNE_BENCH_RTT").as_deref() == Ok("1") {
        if default_mbps < 50.0 {
            assert!(
                tuned_mbps >= 3.0 * default_mbps,
                "under injected RTT, forced socket buffers must lift SOCKS5 upload \
                 throughput >=3x: default={default_mbps:.1} Mbit/s tuned={tuned_mbps:.1} Mbit/s"
            );
        } else {
            eprintln!(
                "socks5 window bench: skipping ratio assertion — untuned path is not \
                 window-limited ({default_mbps:.1} Mbit/s); netem/sysctl harness appears \
                 inactive on this runner"
            );
        }
    }
}
