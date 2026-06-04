//! Per-tunnel and system metrics collected by the data plane.
//!
//! Phase 11 (Live monitoring): the dataplane keeps a small bag of
//! atomic counters per running tunnel, plus a `/proc`-derived view of
//! the host. Every 5 s the IPC layer drains both into a `StatsReport`
//! event so the Go control plane can fan it out to the dashboard.
//!
//! Design choices:
//!
//! - **No allocation in the hot path.** Every counter is an atomic
//!   `u64`/`AtomicU64`/`AtomicU32`; the upload-listener and download-
//!   receiver loops call `record_*` once per packet with a single
//!   `Ordering::Relaxed` increment.
//! - **EWMA RTT samples are seconds-of-monotonic-clock-as-`Instant`.**
//!   The schema mandates `upload_rtt_ms_ewma` + `download_rtt_ms_ewma`
//!   per direction (PRD §3.3). We measure each direction as the local
//!   time gap between the most recent outbound packet on that flow and
//!   the most recent inbound matching packet — an honest proxy for
//!   one-way latency given the asymmetric path. The two sides see
//!   complementary halves, so the dashboard shows whichever side is
//!   running each tunnel.
//! - **Packet-loss estimate.** A rolling ratio of HMAC/auth drops to
//!   verified deliveries (or upload table-full rejections to upload
//!   accepts). Resets every report so it tracks recent badness, not
//!   lifetime.
//! - **System stats** come from straight `/proc` reads. We diff the
//!   per-interface bytes against the previous snapshot to compute
//!   instantaneous rates — the Go side doesn't have file-system access
//!   to do this at our cadence.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

/// One per running tunnel. Lives inside `Arc<>` and is read/written by
/// every receive and send task of the tunnel. All counters are
/// monotonically-increasing `u64` so the Go ring buffer can compute
/// deltas without worrying about wraparound (a 64-bit byte counter at
/// 100 Gbit/s rolls every ~46 years).
pub struct TunnelMetrics {
    pub tunnel_id: i64,
    pub role: String,
    pub transport: String,

    /// Bytes received on the *download* path (Client recv after HMAC
    /// verify; Remote recv on the forward-target socket).
    pub bytes_in: AtomicU64,
    /// Bytes sent on the *upload* path (Client → upload target; Remote
    /// → spoofed download to Client).
    pub bytes_out: AtomicU64,

    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,

    /// HMAC verify failures / packets dropped by source-IP filter etc.
    /// Visible to the operator as `packet_loss_estimate`.
    pub auth_drops: AtomicU64,
    /// Session-table-full rejections of new upload sessions.
    pub session_rejects: AtomicU64,
    /// Download egress shed on the Remote under burst: seal-worker channel
    /// full (`record_seal_drop`) or send-queue full (`record_send_drop`).
    /// Folded into `packet_loss_estimate` so the panel surfaces bursty
    /// download-path shedding that used to be only a log line.
    pub seal_drops: AtomicU64,
    pub send_drops: AtomicU64,
    /// Client upload frames dropped before the wire (SOCKS5 pool saturated
    /// or a forward send error). Counted so a dropped frame is not also
    /// recorded as a delivered upload byte.
    pub upload_drops: AtomicU64,

    /// Last packet-received Unix timestamp. PRD §2.4: drives
    /// Healthy/Idle/Down badges (≤60 s healthy, 60-300 idle, >300 down).
    pub last_packet_received_at_unix: AtomicU64,
    pub last_packet_sent_at_unix: AtomicU64,

    /// Upload-path EWMA latency in microseconds × 1000 (fits 1ms-1000s
    /// in 30 bits — we store the EWMA in micros for resolution and emit
    /// it as `ms_f64` over IPC).
    upload_rtt_us_ewma_micros: AtomicU64,
    /// Download-path EWMA latency in microseconds.
    download_rtt_us_ewma_micros: AtomicU64,
    /// Sample counts so a stats reporter can decide whether an
    /// EWMA is meaningful yet (≥1 sample) — kept separate from the
    /// EWMA itself to avoid CAS.
    upload_rtt_samples: AtomicU64,
    download_rtt_samples: AtomicU64,

    /// Per-spoof-transport packet counters. Only the variant matching
    /// the configured `download_transport` increments; the other three
    /// stay at zero. Keeping all four lets the dashboard surface "this
    /// tunnel ran ICMP last hour, switched to UDP" without us having to
    /// reset between hot-reloads.
    pub udp_packets: AtomicU64,
    pub tcp_syn_packets: AtomicU64,
    pub icmp_packets: AtomicU64,
    pub icmpv6_packets: AtomicU64,

    /// Active session count published into the metric stream. Filled
    /// from the session table at report time, not maintained on the
    /// hot path.
    pub active_sessions: AtomicU32,

    /// v4.0.0 keep-alive: true while the per-tunnel keep-alive is
    /// actively pinging (Client: the heartbeat task is running; Remote: a
    /// keep-alive datagram arrived recently). Reported separately from
    /// `active_sessions` so the panel can show a distinct badge and the
    /// operator can tell a tunnel held warm by keep-alive from one with
    /// real user sessions.
    pub keep_alive_active: AtomicBool,

    /// Pair-matching state used to compute the EWMA RTTs cheaply. We
    /// remember the wall-clock at which the most recent up/down event
    /// fired; the next event in the opposite direction subtracts to
    /// produce a one-way latency sample.
    rtt_inner: Mutex<RttInner>,
}

#[derive(Debug, Default)]
struct RttInner {
    /// Most recent moment we observed an outgoing-upload packet (Client
    /// side) or a forward-target-bound send (Remote side). Used as the
    /// "send" timestamp for the upload-direction RTT pairing.
    last_upload_egress_at: Option<Instant>,
    /// Most recent moment we observed a verified download arriving
    /// (Client side) or a forward-target reply (Remote side). Used as
    /// the "receive" timestamp for the download-direction RTT pairing.
    last_download_ingress_at: Option<Instant>,
}

impl TunnelMetrics {
    /// Build a fresh metric block for the supplied tunnel. The transport
    /// label is duplicated into the metric block (rather than referenced
    /// from the live spec) so a hot-reload that swaps transport via
    /// internal restart cleanly resets per-transport counters.
    pub fn new(tunnel_id: i64, role: &str, transport: &str) -> Self {
        Self {
            tunnel_id,
            role: role.to_string(),
            transport: transport.to_string(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            auth_drops: AtomicU64::new(0),
            session_rejects: AtomicU64::new(0),
            seal_drops: AtomicU64::new(0),
            send_drops: AtomicU64::new(0),
            upload_drops: AtomicU64::new(0),
            last_packet_received_at_unix: AtomicU64::new(0),
            last_packet_sent_at_unix: AtomicU64::new(0),
            upload_rtt_us_ewma_micros: AtomicU64::new(0),
            download_rtt_us_ewma_micros: AtomicU64::new(0),
            upload_rtt_samples: AtomicU64::new(0),
            download_rtt_samples: AtomicU64::new(0),
            udp_packets: AtomicU64::new(0),
            tcp_syn_packets: AtomicU64::new(0),
            icmp_packets: AtomicU64::new(0),
            icmpv6_packets: AtomicU64::new(0),
            active_sessions: AtomicU32::new(0),
            keep_alive_active: AtomicBool::new(false),
            rtt_inner: Mutex::new(RttInner::default()),
        }
    }

    /// Called once per upload egress (Client→Remote `upload_target` send
    /// or Remote→`forward_target` send). Counts bytes/packets, stamps
    /// the last_sent time, and records the moment so the next download
    /// arrival can produce a paired RTT sample.
    pub fn record_upload(&self, bytes: usize, now_unix: u64) {
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_out.fetch_add(1, Ordering::Relaxed);
        self.last_packet_sent_at_unix
            .store(now_unix, Ordering::Relaxed);
        if let Ok(mut g) = self.rtt_inner.lock() {
            let now = Instant::now();
            g.last_upload_egress_at = Some(now);
            // If there was a pending download ingress, treat the gap
            // (now - last_download_ingress) as a download-direction
            // sample (the time it took from "data came back to us" to
            // "we sent the next upload" — a lower bound on the
            // download path latency from the operator's perspective).
            if let Some(prev) = g.last_download_ingress_at.take() {
                let dt = now.saturating_duration_since(prev).as_micros() as u64;
                if dt < 30_000_000 {
                    // sanity cap at 30 s
                    update_ewma(&self.download_rtt_us_ewma_micros, dt);
                    self.download_rtt_samples.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Called once per verified download ingress (Client recv of an
    /// HMAC-verified spoof packet, OR Remote recv on the forward-target
    /// socket). Counts bytes/packets and produces the upload-direction
    /// RTT sample.
    pub fn record_download(&self, bytes: usize, now_unix: u64) {
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_in.fetch_add(1, Ordering::Relaxed);
        self.last_packet_received_at_unix
            .store(now_unix, Ordering::Relaxed);
        if let Ok(mut g) = self.rtt_inner.lock() {
            let now = Instant::now();
            g.last_download_ingress_at = Some(now);
            if let Some(prev) = g.last_upload_egress_at.take() {
                let dt = now.saturating_duration_since(prev).as_micros() as u64;
                if dt < 30_000_000 {
                    update_ewma(&self.upload_rtt_us_ewma_micros, dt);
                    self.upload_rtt_samples.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Increment the per-spoof-transport packet counter. Called by the
    /// receive path after HMAC verification (Client) or by the send
    /// path after a successful raw send (Remote).
    pub fn record_transport_packet(&self, transport: &str) {
        match transport {
            "udp" => self.udp_packets.fetch_add(1, Ordering::Relaxed),
            "tcp_syn" => self.tcp_syn_packets.fetch_add(1, Ordering::Relaxed),
            "icmp" => self.icmp_packets.fetch_add(1, Ordering::Relaxed),
            "icmpv6" => self.icmpv6_packets.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Count an HMAC failure / source-IP mismatch / replay etc. Becomes
    /// the numerator of `packet_loss_estimate` in the next report.
    pub fn record_auth_drop(&self) {
        self.auth_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a session table backpressure reject. Surfaces in the
    /// dashboard as another contributor to "things were dropped".
    pub fn record_session_reject(&self) {
        self.session_rejects.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a Remote download-egress drop caused by a full seal-worker
    /// channel under burst. Folded into `packet_loss_estimate`.
    pub fn record_seal_drop(&self) {
        self.seal_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Count `n` Remote download-egress drops: a full seal→send queue
    /// (1 packet) or a send-worker batch dropped on a hard `sendmmsg`
    /// error / writability failure / persistent-EAGAIN exhaustion (a
    /// whole staged batch). Folded into `packet_loss_estimate`.
    pub fn record_send_drop(&self, n: u64) {
        self.send_drops.fetch_add(n, Ordering::Relaxed);
    }

    /// Count a Client upload frame dropped before reaching the wire (every
    /// SOCKS5 connection down/full, or a WireGuard forward send error).
    /// Kept separate from the download loss estimate so a dropped frame is
    /// not also counted as a delivered upload.
    pub fn record_upload_drop(&self) {
        self.upload_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the current session-table size for the next report.
    pub fn set_active_sessions(&self, n: u32) {
        self.active_sessions.store(n, Ordering::Relaxed);
    }

    /// Set the v4.0.0 keep-alive indicator for the next report.
    pub fn set_keep_alive_active(&self, active: bool) {
        self.keep_alive_active.store(active, Ordering::Relaxed);
    }

    /// Snapshot every counter into a `PerTunnelStats` ready to ship over
    /// IPC. Reads are `Relaxed` because a stats sample is by definition
    /// approximate.
    pub fn snapshot(&self) -> PerTunnelStats {
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        let packets_in = self.packets_in.load(Ordering::Relaxed);
        let packets_out = self.packets_out.load(Ordering::Relaxed);
        let auth = self.auth_drops.load(Ordering::Relaxed);
        let rejects = self.session_rejects.load(Ordering::Relaxed);
        // Remote download-egress shedding under burst (seal / send queues
        // full) is real download packet loss, so fold it into the same
        // estimate. Upload-path drops live in `upload_drops` and are NOT
        // download loss, so they stay out of this ratio.
        let egress_drops =
            self.seal_drops.load(Ordering::Relaxed) + self.send_drops.load(Ordering::Relaxed);
        // packet_loss_estimate as a 0..1 ratio of "lost"-style events to
        // "delivered" events over the lifetime of the dataplane. Go-side
        // ring computes deltas for the chart; the absolute ratio is what
        // the dashboard's gauge shows.
        let delivered = packets_in.max(1);
        let lost = auth + rejects + egress_drops;
        let loss = lost as f64 / (delivered + lost) as f64;
        PerTunnelStats {
            tunnel_id: self.tunnel_id,
            role: self.role.clone(),
            transport: self.transport.clone(),
            bytes_in,
            bytes_out,
            packets_in,
            packets_out,
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            keep_alive_active: self.keep_alive_active.load(Ordering::Relaxed),
            last_packet_received_at_unix: self.last_packet_received_at_unix.load(Ordering::Relaxed),
            last_packet_sent_at_unix: self.last_packet_sent_at_unix.load(Ordering::Relaxed),
            upload_rtt_ms_ewma: ewma_micros_to_ms(
                self.upload_rtt_us_ewma_micros.load(Ordering::Relaxed),
                self.upload_rtt_samples.load(Ordering::Relaxed),
            ),
            download_rtt_ms_ewma: ewma_micros_to_ms(
                self.download_rtt_us_ewma_micros.load(Ordering::Relaxed),
                self.download_rtt_samples.load(Ordering::Relaxed),
            ),
            packet_loss_estimate: clamp01(loss),
            auth_drops: auth,
            session_rejects: rejects,
            transport_packets: TransportPackets {
                udp: self.udp_packets.load(Ordering::Relaxed),
                tcp_syn: self.tcp_syn_packets.load(Ordering::Relaxed),
                icmp: self.icmp_packets.load(Ordering::Relaxed),
                icmpv6: self.icmpv6_packets.load(Ordering::Relaxed),
            },
        }
    }
}

/// EWMA update in fixed-point microseconds. Alpha = 1/8 (3-bit shift)
/// gives a smoothing factor sympathetic to the 5-second report cadence:
/// new samples noticeably move the line, sudden spikes don't dominate.
fn update_ewma(slot: &AtomicU64, sample_us: u64) {
    // CAS loop: load → blend → store. This is the only mutating
    // operation on the EWMA atomic, so there's no ABA worry.
    let mut prev = slot.load(Ordering::Relaxed);
    loop {
        let next = if prev == 0 {
            sample_us
        } else {
            // new = prev * 7/8 + sample * 1/8
            (prev / 8) * 7 + sample_us / 8
        };
        match slot.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => prev = actual,
        }
    }
}

fn ewma_micros_to_ms(us: u64, samples: u64) -> f64 {
    if samples == 0 {
        return 0.0;
    }
    us as f64 / 1000.0
}

fn clamp01(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    x.clamp(0.0, 1.0)
}

/// One per-tunnel row in a `StatsReport`. Mirrors the JSON schema in
/// `.claude/skills/rust-go-ipc/SKILL.md`.
#[derive(Debug, Clone, Serialize)]
pub struct PerTunnelStats {
    pub tunnel_id: i64,
    pub role: String,
    pub transport: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub active_sessions: u32,
    pub keep_alive_active: bool,
    pub last_packet_received_at_unix: u64,
    pub last_packet_sent_at_unix: u64,
    pub upload_rtt_ms_ewma: f64,
    pub download_rtt_ms_ewma: f64,
    pub packet_loss_estimate: f64,
    pub auth_drops: u64,
    pub session_rejects: u64,
    pub transport_packets: TransportPackets,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportPackets {
    pub udp: u64,
    pub tcp_syn: u64,
    pub icmp: u64,
    pub icmpv6: u64,
}

/// One per-interface row in `SystemStats.net_interfaces`.
#[derive(Debug, Clone, Serialize)]
pub struct NetInterfaceStats {
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemStats {
    pub cpu_percent: f64,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub net_interfaces: HashMap<String, NetInterfaceStats>,
    pub load_avg_1min: f64,
    /// Resident set size of *this* dataplane process. Distinct from
    /// `mem_used_bytes` which is the host-wide figure. Phase 15 (PRD
    /// §7): the memory soft cap is `proc_rss_bytes / mem_total_bytes >
    /// 0.70`. Populated by the `crate::memory` sampler.
    pub proc_rss_bytes: u64,
    /// True when the dataplane is currently refusing new sessions
    /// because process RSS exceeded the soft cap. The panel renders a
    /// banner; existing sessions continue to flow.
    pub memory_pressure: bool,
}

/// Snapshotter that polls `/proc` for CPU + mem + disk + nic counters
/// and diffs against the previous read to produce per-second rates.
pub struct SystemSnapshotter {
    last: Mutex<SnapshotterState>,
}

#[derive(Debug, Default)]
struct SnapshotterState {
    last_at: Option<Instant>,
    last_cpu: Option<CpuTotals>,
    last_net: HashMap<String, (u64, u64)>,
}

#[derive(Debug, Clone, Copy, Default)]
struct CpuTotals {
    total: u64,
    idle: u64,
}

impl Default for SystemSnapshotter {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemSnapshotter {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(SnapshotterState::default()),
        }
    }

    /// Read `/proc` and compute the next system snapshot. On platforms
    /// other than Linux every field comes back zero — the IPC layer
    /// still produces a well-formed message so the panel can render
    /// "no data" gracefully on a developer's macOS box.
    pub fn snapshot(&self) -> SystemStats {
        let now = Instant::now();
        let cpu_percent = self.read_cpu_percent();
        let (mem_used, mem_total) = self.read_meminfo();
        let (disk_used, disk_total) = self.read_disk();
        let load_avg = self.read_loadavg();
        let interfaces = self.read_net(now);
        SystemStats {
            cpu_percent,
            mem_used_bytes: mem_used,
            mem_total_bytes: mem_total,
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            net_interfaces: interfaces,
            load_avg_1min: load_avg,
            proc_rss_bytes: crate::memory::current_rss_bytes(),
            memory_pressure: crate::memory::pressure_active(),
        }
    }

    fn read_cpu_percent(&self) -> f64 {
        let path = Path::new("/proc/stat");
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return 0.0,
        };
        let first = match content.lines().next() {
            Some(l) => l,
            None => return 0.0,
        };
        // Lines like: `cpu  user nice system idle iowait irq softirq steal guest guest_nice`
        let mut parts = first.split_whitespace();
        if parts.next() != Some("cpu") {
            return 0.0;
        }
        let mut idle = 0u64;
        let mut total = 0u64;
        for (idx, tok) in parts.enumerate() {
            let n: u64 = tok.parse().unwrap_or(0);
            total = total.saturating_add(n);
            // idx 3 = idle, idx 4 = iowait — both count as "not busy"
            if idx == 3 || idx == 4 {
                idle = idle.saturating_add(n);
            }
        }
        let new = CpuTotals { total, idle };
        let mut g = match self.last.lock() {
            Ok(g) => g,
            Err(_) => return 0.0,
        };
        let pct = match g.last_cpu {
            Some(prev) => {
                let dt_total = new.total.saturating_sub(prev.total);
                let dt_idle = new.idle.saturating_sub(prev.idle);
                if dt_total == 0 {
                    0.0
                } else {
                    let busy = dt_total.saturating_sub(dt_idle);
                    (busy as f64 * 100.0) / dt_total as f64
                }
            }
            None => 0.0,
        };
        g.last_cpu = Some(new);
        pct
    }

    fn read_meminfo(&self) -> (u64, u64) {
        let content = match std::fs::read_to_string("/proc/meminfo") {
            Ok(s) => s,
            Err(_) => return (0, 0),
        };
        let mut total_kb: u64 = 0;
        let mut available_kb: u64 = 0;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total_kb = parse_kb(rest);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                available_kb = parse_kb(rest);
            }
        }
        let total = total_kb.saturating_mul(1024);
        let used = total.saturating_sub(available_kb.saturating_mul(1024));
        (used, total)
    }

    fn read_loadavg(&self) -> f64 {
        match std::fs::read_to_string("/proc/loadavg") {
            Ok(s) => s
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
                .unwrap_or(0.0),
            Err(_) => 0.0,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_disk(&self) -> (u64, u64) {
        use std::ffi::CString;
        let path = CString::new("/var/lib/sublyne").unwrap_or_else(|_| {
            // Fall back to "/" if /var/lib/sublyne doesn't exist yet
            CString::new("/").unwrap()
        });
        let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a valid C string; `buf` is a zero-initialised
        // libc::statvfs we hand to statvfs(2). Returns 0 on success.
        let rc = unsafe { libc::statvfs(path.as_ptr(), &mut buf) };
        if rc != 0 {
            // Try `/` as a fallback so the panel still shows non-zero
            // disk numbers on early-boot / dev installs.
            let root = CString::new("/").unwrap();
            // SAFETY: same shape as above.
            let rc2 = unsafe { libc::statvfs(root.as_ptr(), &mut buf) };
            if rc2 != 0 {
                return (0, 0);
            }
        }
        // statvfs fields on Linux amd64-musl are already u64 — drop
        // the legacy `as u64` casts that newer clippy flags as
        // unnecessary_cast. (We pin the build to linux-musl so the
        // platform-conditional helper above only ever runs here.)
        let frsize = buf.f_frsize;
        let total = buf.f_blocks * frsize;
        let avail = buf.f_bavail * frsize;
        let used = total.saturating_sub(avail);
        (used, total)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_disk(&self) -> (u64, u64) {
        (0, 0)
    }

    fn read_net(&self, now: Instant) -> HashMap<String, NetInterfaceStats> {
        let content = match std::fs::read_to_string("/proc/net/dev") {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };
        let mut g = match self.last.lock() {
            Ok(g) => g,
            Err(_) => return HashMap::new(),
        };
        let dt = match g.last_at {
            Some(prev) => now.saturating_duration_since(prev).as_secs_f64(),
            None => 0.0,
        };
        let mut out = HashMap::new();
        let mut next_state: HashMap<String, (u64, u64)> = HashMap::new();
        for line in content.lines().skip(2) {
            // Format: `   eth0: <rx_bytes> ... <tx_bytes> ...`
            let mut parts = line.split(':');
            let name = match parts.next() {
                Some(n) => n.trim().to_string(),
                None => continue,
            };
            if name.is_empty() {
                continue;
            }
            // Skip the loopback so the chart focuses on real wire traffic
            // — operators can still see real-traffic interfaces and the
            // `lo` numbers would dwarf them otherwise on a localhost test.
            if name == "lo" {
                continue;
            }
            let stats = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let nums: Vec<u64> = stats
                .split_whitespace()
                .map(|t| t.parse::<u64>().unwrap_or(0))
                .collect();
            // Index 0 = rx_bytes, 8 = tx_bytes in /proc/net/dev's layout.
            if nums.len() < 16 {
                continue;
            }
            let rx = nums[0];
            let tx = nums[8];
            next_state.insert(name.clone(), (rx, tx));
            let (rx_rate, tx_rate) = if dt > 0.0 {
                let prev = g.last_net.get(&name).copied().unwrap_or((rx, tx));
                let drx = rx.saturating_sub(prev.0);
                let dtx = tx.saturating_sub(prev.1);
                ((drx as f64 / dt) as u64, (dtx as f64 / dt) as u64)
            } else {
                (0, 0)
            };
            out.insert(
                name,
                NetInterfaceStats {
                    rx_bytes_per_sec: rx_rate,
                    tx_bytes_per_sec: tx_rate,
                    rx_bytes_total: rx,
                    tx_bytes_total: tx,
                },
            );
        }
        g.last_net = next_state;
        g.last_at = Some(now);
        out
    }
}

fn parse_kb(s: &str) -> u64 {
    let mut tok = s.split_whitespace();
    tok.next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_upload_counts_bytes_and_packets() {
        let m = TunnelMetrics::new(1, "client", "udp");
        m.record_upload(100, 1700000000);
        m.record_upload(200, 1700000001);
        let s = m.snapshot();
        assert_eq!(s.bytes_out, 300);
        assert_eq!(s.packets_out, 2);
        assert_eq!(s.last_packet_sent_at_unix, 1700000001);
    }

    #[test]
    fn record_download_counts_and_pairs_rtt() {
        let m = TunnelMetrics::new(1, "client", "udp");
        // upload first to seed the rtt pairing
        m.record_upload(100, 1700000000);
        // small sleep so the rtt sample is non-zero
        std::thread::sleep(std::time::Duration::from_millis(2));
        m.record_download(150, 1700000001);
        let s = m.snapshot();
        assert_eq!(s.bytes_in, 150);
        assert_eq!(s.packets_in, 1);
        assert!(
            s.upload_rtt_ms_ewma > 0.0,
            "upload RTT EWMA should be set after pair"
        );
    }

    #[test]
    fn ewma_averages_two_samples() {
        let slot = AtomicU64::new(0);
        update_ewma(&slot, 10_000); // 10 ms in micros
        let v1 = slot.load(Ordering::Relaxed);
        assert_eq!(v1, 10_000);
        update_ewma(&slot, 50_000); // 50 ms
        let v2 = slot.load(Ordering::Relaxed);
        // (10_000 * 7/8) + (50_000 / 8) = 8750 + 6250 = 15_000
        assert_eq!(v2, 15_000);
    }

    #[test]
    fn loss_estimate_zero_until_drops() {
        let m = TunnelMetrics::new(1, "client", "udp");
        m.record_download(100, 0);
        m.record_download(100, 0);
        let s = m.snapshot();
        assert!(s.packet_loss_estimate < 0.001);
    }

    #[test]
    fn loss_estimate_reflects_drops() {
        let m = TunnelMetrics::new(1, "client", "udp");
        m.record_download(100, 0);
        m.record_auth_drop();
        let s = m.snapshot();
        // 1 delivered, 1 drop → 0.5 ratio
        assert!((s.packet_loss_estimate - 0.5).abs() < 0.01);
    }

    #[test]
    fn transport_counters_isolate_by_label() {
        let m = TunnelMetrics::new(1, "remote", "icmp");
        m.record_transport_packet("icmp");
        m.record_transport_packet("icmp");
        m.record_transport_packet("udp");
        let s = m.snapshot();
        assert_eq!(s.transport_packets.icmp, 2);
        assert_eq!(s.transport_packets.udp, 1);
        assert_eq!(s.transport_packets.tcp_syn, 0);
        assert_eq!(s.transport_packets.icmpv6, 0);
    }

    #[test]
    fn snapshotter_runs_without_panicking_on_any_platform() {
        let s = SystemSnapshotter::new();
        // First snapshot — rates are zero everywhere because there's
        // no previous baseline.
        let snap1 = s.snapshot();
        // mem_total > 0 is a soft positive signal: linux gives a real
        // number, non-linux gives 0.
        let _ = snap1;
    }

    #[test]
    fn parse_kb_extracts_first_token() {
        assert_eq!(parse_kb("  12345 kB"), 12345);
        assert_eq!(parse_kb("0"), 0);
        assert_eq!(parse_kb(""), 0);
    }
}
