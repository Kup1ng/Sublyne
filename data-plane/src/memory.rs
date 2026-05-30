//! Memory soft-cap (PRD §7).
//!
//! When the dataplane's resident set exceeds ~70 % of system RAM, new
//! sessions are rejected. The process never self-kills — that would
//! send systemd into a restart loop and the operator would see the
//! tunnel flap. Instead, this module exposes a single
//! `pressure_active()` boolean that the session table consults on
//! every new-session insert, and a periodic sampler that flips the
//! flag with hysteresis.
//!
//! Hysteresis prevents the flag from flapping right at the threshold:
//! - **Set** when RSS / total > [`PRESSURE_ON_RATIO`] (0.70).
//! - **Clear** when RSS / total < [`PRESSURE_OFF_RATIO`] (0.65).
//!
//! On non-Linux platforms (developer macOS, Windows) the sampler is
//! a no-op and the flag stays false — the production path is
//! Linux-only per PRD §1.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tracing::{info, warn};

/// Ratio of process RSS to system MemTotal above which the gate trips.
pub const PRESSURE_ON_RATIO: f64 = 0.70;
/// Ratio below which the gate releases. The gap to [`PRESSURE_ON_RATIO`]
/// is the hysteresis band.
pub const PRESSURE_OFF_RATIO: f64 = 0.65;
/// How often the sampler polls `/proc`. PRD §4.7 sets the dashboard
/// push cadence at 5 s; matching it here keeps log noise low and means
/// the operator sees the flag flip within one dashboard tick.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

static PRESSURE: AtomicBool = AtomicBool::new(false);
static LAST_RSS_BYTES: AtomicU64 = AtomicU64::new(0);
static LAST_TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);

/// Returns true if the dataplane is currently in memory-pressure mode.
/// Cheap atomic load on every new-session path.
#[inline]
pub fn pressure_active() -> bool {
    PRESSURE.load(Ordering::Acquire)
}

/// Most recent process RSS observed by the sampler, in bytes. Surfaced
/// via the IPC `StatsReport.system.proc_rss_bytes` field.
pub fn last_rss_bytes() -> u64 {
    LAST_RSS_BYTES.load(Ordering::Relaxed)
}

/// Freshly-read process RSS in bytes for the live dashboard RAM tile.
///
/// Unlike [`last_rss_bytes`] (which returns the value cached by the 5 s
/// pressure sampler), this reads `/proc/self/status` on the spot so the
/// panel's RAM tile tracks the 1 s stats cadence instead of stepping once
/// every 5 s. The read is one small `/proc` file per second — negligible.
/// Falls back to the sampler's cached value if the on-the-spot read fails
/// (non-Linux dev box / transient), so it is never spuriously zero once
/// the sampler has run at least once.
pub fn current_rss_bytes() -> u64 {
    read_proc_self_rss_bytes().unwrap_or_else(last_rss_bytes)
}

/// Most recent system MemTotal observed by the sampler, in bytes.
pub fn last_total_bytes() -> u64 {
    LAST_TOTAL_BYTES.load(Ordering::Relaxed)
}

/// Force-set the pressure flag. Tests use this to drive the gate
/// without spawning the sampler.
#[doc(hidden)]
pub fn set_pressure_for_test(active: bool) {
    PRESSURE.store(active, Ordering::Release);
}

/// Spawn the sampler task. Returns immediately; the task lives for
/// the lifetime of the runtime. Calling this twice is harmless — the
/// second sampler just adds redundant log noise.
pub fn spawn_sampler() {
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        // Don't fire the first tick immediately — wait one cycle so a
        // freshly-booted dataplane doesn't trip the flag before tunnels
        // even open.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            sample_once();
        }
    });
}

/// One iteration of the sampler — read `/proc/self/status` and
/// `/proc/meminfo`, compute the ratio, and update the flag. Pulled
/// out of `spawn_sampler` so tests can drive a single step
/// synchronously.
pub fn sample_once() {
    let rss = read_proc_self_rss_bytes().unwrap_or(0);
    let total = read_proc_meminfo_total_bytes().unwrap_or(0);
    LAST_RSS_BYTES.store(rss, Ordering::Relaxed);
    LAST_TOTAL_BYTES.store(total, Ordering::Relaxed);
    if total == 0 {
        return;
    }
    let ratio = rss as f64 / total as f64;
    let was_active = PRESSURE.load(Ordering::Acquire);
    if was_active {
        if ratio < PRESSURE_OFF_RATIO {
            PRESSURE.store(false, Ordering::Release);
            info!(
                rss_bytes = rss,
                total_bytes = total,
                ratio_pct = (ratio * 100.0) as u32,
                "memory: pressure cleared — new sessions accepted again"
            );
        }
    } else if ratio > PRESSURE_ON_RATIO {
        PRESSURE.store(true, Ordering::Release);
        warn!(
            rss_bytes = rss,
            total_bytes = total,
            ratio_pct = (ratio * 100.0) as u32,
            "memory: pressure active — refusing new sessions until RSS drops below {}%",
            (PRESSURE_OFF_RATIO * 100.0) as u32
        );
    }
}

/// Read `/proc/self/status` and pluck `VmRSS` in bytes. Returns
/// `None` on parse failure or non-Linux.
fn read_proc_self_rss_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return Some(parse_kb_to_bytes(rest));
        }
    }
    None
}

/// Read `/proc/meminfo` and pluck `MemTotal` in bytes. Returns `None`
/// on parse failure or non-Linux.
fn read_proc_meminfo_total_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return Some(parse_kb_to_bytes(rest));
        }
    }
    None
}

/// Parse a `/proc` value line tail like `   12345 kB` into bytes. The
/// kernel always emits values in KiB regardless of the `kB` suffix,
/// so 1 KiB = 1024 B.
fn parse_kb_to_bytes(rest: &str) -> u64 {
    let trimmed = rest.trim();
    let num: u64 = trimmed
        .split_whitespace()
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    num.saturating_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_starts_false() {
        // Reset to a known state — other tests in this module mutate
        // the static.
        set_pressure_for_test(false);
        assert!(!pressure_active());
    }

    #[test]
    fn set_for_test_round_trips() {
        set_pressure_for_test(true);
        assert!(pressure_active());
        set_pressure_for_test(false);
        assert!(!pressure_active());
    }

    #[test]
    fn parse_kb_handles_kernel_format() {
        // Real /proc/self/status line shapes.
        assert_eq!(parse_kb_to_bytes("   12345 kB"), 12_345 * 1024);
        assert_eq!(parse_kb_to_bytes("0 kB"), 0);
        assert_eq!(parse_kb_to_bytes("\t42 kB\n"), 42 * 1024);
        // Malformed input returns 0 rather than panicking.
        assert_eq!(parse_kb_to_bytes(""), 0);
        assert_eq!(parse_kb_to_bytes("garbage"), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_self_rss_returns_nonzero_on_linux() {
        // The test binary itself has a non-trivial RSS the moment it
        // runs cargo test. We don't care about the exact value, just
        // that the read works and produces a plausible number.
        let rss = read_proc_self_rss_bytes().expect("VmRSS present on linux");
        assert!(rss > 0);
        let total = read_proc_meminfo_total_bytes().expect("MemTotal present on linux");
        assert!(total > rss, "MemTotal must dwarf the test binary's RSS");
    }
}
