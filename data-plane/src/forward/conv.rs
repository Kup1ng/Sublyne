//! One KCP conversation = one user TCP connection, driven by a single
//! lock-free task that **owns** its `Kcp`.
//!
//! This is the structural fix over the rolled-back v4, which wrapped the
//! same `kcp` crate in `Arc<Mutex<Kcp>>` shared between a central driver
//! and per-conn pumps, pushed every output segment through an extra
//! `to_vec()` + mpsc hop drained by one engine-wide egress task, and
//! dropped KCP output under load (triggering retransmit storms). Here:
//!
//! * the conv task is the **only** caller of every `Kcp` method, so there
//!   is no mutex on the hot path;
//! * the sync `output` callback ([`StagingSink`]) appends finished
//!   segments into a **reused** length-prefixed buffer (no per-segment
//!   heap churn after warm-up);
//! * the task forwards those segments **inline** to the [`DatagramSink`]
//!   with real backpressure (`send().await`) — KCP output is never
//!   dropped;
//! * the flush cadence is **adaptive**: a busy conv flushes on the KCP
//!   interval, an idle one sleeps long and wakes immediately on the next
//!   TCP byte or inbound segment;
//! * a small dedicated write-pump task drains decoded bytes to the TCP
//!   socket so a slow consumer can't stall the upload direction.

use std::io::{self, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use kcp::Kcp;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::channel::{DatagramSink, InboundRx};
use super::engine::ConvCleanup;
use super::tuning::{self, RECV_BUF, TCP_READ_CHUNK, WRITE_QUEUE};
use crate::metrics::TunnelMetrics;
use crate::spec::KcpTuning;
use crate::time_util::now_unix;

/// Which side of the asymmetric pair this conv runs on — selects how
/// bytes map onto the upload/download metric counters (and thus which
/// direction refreshes the panel health badge).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConvSide {
    /// Iran side: TCP read = user request bytes (upload egress).
    Client,
    /// Foreign side: TCP read = forward_target reply bytes (download
    /// ingress — stamps `last_packet_received`).
    Remote,
}

/// Static per-conv configuration.
pub(crate) struct ConvConfig {
    pub tuning: KcpTuning,
    pub kcp_mtu: usize,
    pub idle_timeout_sec: u32,
    /// Keep-alive convs are exempt from idle reaping (v4.0.0 checkpoint 4
    /// uses this; always `false` until then).
    pub is_keepalive: bool,
    pub side: ConvSide,
    pub tunnel_id: i64,
}

/// `std::io::Write` sink each `Kcp` writes finished segments into. Every
/// `write()` is one KCP segment; we append it length-prefixed into a
/// reused buffer the owning conv task drains right after the KCP call.
/// The mutex is only ever taken by this task (the `Kcp` output callback
/// and the task's drain are sequential), so it is always uncontended.
struct StagingSink {
    buf: Arc<StdMutex<Vec<u8>>>,
}

impl Write for StagingSink {
    fn write(&mut self, seg: &[u8]) -> io::Result<usize> {
        let mut b = self.buf.lock().expect("kcp staging lock");
        b.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        b.extend_from_slice(seg);
        Ok(seg.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// How long an idle conv sleeps between `update()`s when it has nothing
/// in flight (`wait_snd() == 0`). It still wakes instantly on inbound
/// segments or TCP bytes, so ACKs stay prompt; this only bounds the
/// pure-timer wakeups of a quiet conv to ~1/s instead of ~50/s.
const IDLE_POLL: Duration = Duration::from_millis(1000);

/// Grace period after TCP EOF before reaping a quiet half-closed conv.
/// KCP has no FIN, so a finished connection is detected by silence; this
/// reaps it faster than the full idle timeout while still letting an
/// active half-close (e.g. a long download after the request closed)
/// keep flowing — any byte either direction refreshes `last_activity`.
const EOF_GRACE: Duration = Duration::from_secs(10);

/// Drive one conversation until it closes (idle / EOF / engine stop).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_conv(
    conv_id: u32,
    stream: TcpStream,
    mut inbound_rx: InboundRx,
    sink: Arc<dyn DatagramSink>,
    cfg: ConvConfig,
    metrics: Arc<TunnelMetrics>,
    clock: Instant,
    mut stop_rx: watch::Receiver<bool>,
    cleanup: ConvCleanup,
) {
    let _ = stream.set_nodelay(true);
    let (mut rd, wr) = stream.into_split();

    // Dedicated write pump: decoded bytes → TCP, so a slow consumer
    // backpressures via KCP's receive window instead of stalling the
    // conv task's upload direction.
    let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);
    tokio::spawn(write_pump(wr, write_rx));

    let staging = Arc::new(StdMutex::new(Vec::<u8>::with_capacity(64 * 1024)));
    let mut kcp = Kcp::new_stream(
        conv_id,
        StagingSink {
            buf: staging.clone(),
        },
    );
    tuning::apply_tuning(&mut kcp, &cfg.tuning, cfg.kcp_mtu, cfg.tunnel_id);

    let snd_wnd = cfg.tuning.snd_wnd.max(1) as usize;
    let flush = Duration::from_millis(cfg.tuning.interval.max(1) as u64);
    let idle = Duration::from_secs(cfg.idle_timeout_sec.max(1) as u64);
    let eof_grace = idle.min(EOF_GRACE);

    let mut rbuf = vec![0u8; TCP_READ_CHUNK];
    let mut recv_buf = vec![0u8; RECV_BUF];
    let mut out_scratch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut tcp_eof = false;
    let mut write_closed = false;
    let mut last_activity = Instant::now();

    loop {
        let wait_snd = kcp.wait_snd();
        let can_read = !tcp_eof && wait_snd < snd_wnd;
        let sleep_dur = if wait_snd > 0 { flush } else { IDLE_POLL };

        tokio::select! {
            _ = stop_rx.changed() => break,
            r = rd.read(&mut rbuf), if can_read => {
                match r {
                    Ok(0) => tcp_eof = true,
                    Ok(n) => {
                        let _ = kcp.send(&rbuf[..n]);
                        if cfg.side == ConvSide::Client {
                            metrics.record_upload(n, now_unix());
                        } else {
                            metrics.record_download(n, now_unix());
                        }
                        last_activity = Instant::now();
                    }
                    Err(_) => tcp_eof = true,
                }
            }
            seg = inbound_rx.recv() => {
                match seg {
                    Some(dg) => {
                        if kcp.input(&dg).is_ok() {
                            last_activity = Instant::now();
                        }
                    }
                    None => break, // engine dropped our inbound sender (stop/reap)
                }
            }
            _ = tokio::time::sleep(sleep_dur) => {}
        }

        // Advance the KCP timer (also flushes pending ACKs / output).
        let now_ms = clock.elapsed().as_millis() as u32;
        let _ = kcp.update(now_ms);

        // Drain decoded bytes → TCP write pump, losslessly: reserve a
        // queue slot before `recv()` so we never pull bytes we can't
        // enqueue. On `Remote` the decoded bytes are the user's request
        // headed to forward_target (upload egress).
        loop {
            match write_tx.try_reserve() {
                Ok(permit) => match kcp.recv(&mut recv_buf) {
                    Ok(n) if n > 0 => {
                        if cfg.side == ConvSide::Remote {
                            metrics.record_upload(n, now_unix());
                        }
                        permit.send(recv_buf[..n].to_vec());
                        last_activity = Instant::now();
                    }
                    _ => break, // nothing decodable now; permit released on drop
                },
                Err(mpsc::error::TrySendError::Full(())) => break, // slow consumer
                Err(mpsc::error::TrySendError::Closed(())) => {
                    write_closed = true;
                    break;
                }
            }
        }

        // Forward staged KCP output segments inline, with real
        // backpressure (no drop). Swap the staging buffer out under the
        // (uncontended) lock so the next iteration's output lands in the
        // now-empty scratch — both buffers are reused, zero steady-state
        // allocation.
        {
            let mut s = staging.lock().expect("kcp staging lock");
            std::mem::swap(&mut *s, &mut out_scratch);
        }
        if !out_scratch.is_empty() {
            let mut off = 0usize;
            while off + 4 <= out_scratch.len() {
                let len = u32::from_le_bytes([
                    out_scratch[off],
                    out_scratch[off + 1],
                    out_scratch[off + 2],
                    out_scratch[off + 3],
                ]) as usize;
                off += 4;
                if off + len > out_scratch.len() {
                    break;
                }
                let seg = &out_scratch[off..off + len];
                off += len;
                match sink.send(seg).await {
                    Ok(_) => {}
                    Err(e) => debug!(
                        tunnel_id = cfg.tunnel_id,
                        conv = conv_id,
                        err = %e,
                        "kcp: sink send failed"
                    ),
                }
            }
            out_scratch.clear();
        }

        if write_closed {
            break;
        }
        if !cfg.is_keepalive {
            let quiet = last_activity.elapsed();
            if tcp_eof {
                if quiet >= eof_grace {
                    break;
                }
            } else if quiet >= idle {
                break;
            }
        }
    }

    // Dropping `write_tx` here closes the write pump's channel, which
    // shuts down the TCP write half. Cleanup removes the conv from the
    // engine map and updates the active-session gauge.
    drop(write_tx);
    cleanup.run(metrics.as_ref());
}

/// KCP → TCP: write decoded app bytes to the socket. Exits (and
/// half-closes the write side) when the conv task drops `write_tx`.
async fn write_pump(mut wr: tokio::net::tcp::OwnedWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(bytes) = rx.recv().await {
        if wr.write_all(&bytes).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

impl ConvCleanup {
    /// Remove the conv from the engine map and decrement the shared
    /// active-conv gauge, republishing it to the tunnel metrics. On the
    /// Remote, record the id in the recently-closed guard so a late
    /// segment doesn't resurrect a reaped conv.
    pub(crate) fn run(self, metrics: &TunnelMetrics) {
        {
            let mut map = self.convs.lock().expect("conv map");
            map.remove(&self.conv_id);
        }
        let prev = self.active.fetch_sub(1, Ordering::Relaxed);
        let remaining = prev.saturating_sub(1);
        metrics.set_active_sessions(remaining.min(u32::MAX as u64) as u32);
        if let Some(rc) = self.recently_closed {
            let mut q = rc.lock().expect("recently_closed");
            q.push_back((self.conv_id, Instant::now()));
        }
    }
}
