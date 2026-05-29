//! Per-tunnel ICMP identifier picker.
//!
//! Phase 8b used `download_spoof_source_port` (typically `443`) as the
//! ICMP `identifier` field so the Client filter could check
//! `parsed.src_id == spoof_source_port` uniformly across all four
//! transports. Two problems with that:
//!
//! 1. A static `443` identifier collides with any concurrent local
//!    `ping` that happens to pick the same id. The kernel's raw socket
//!    sees both streams of ICMP packets and our parser would have to
//!    rely on HMAC alone — which works, but produces noisy "auth_drops"
//!    counters that hide real attacks.
//! 2. Iranian DPI middleboxes sometimes inspect ICMP identifiers for
//!    plausibility. A repeated `0x01BB` across hours of traffic looks
//!    less natural than a random per-tunnel-start value.
//!
//! Phase R4 picks a random identifier on every tunnel spawn. The value
//! is logged on bring-up and surfaced in the IPC tunnel-list reply so
//! operators can correlate `tcpdump` output against the tunnel they
//! care about.
//!
//! Randomness quality: this is **not** a security boundary. The HMAC
//! envelope (PSK + sliding seq window) handles authentication; the
//! identifier is purely for kernel demux and DPI plausibility. A weak
//! PRNG seeded from the wall clock + tunnel id is sufficient. We avoid
//! pulling in the `rand` crate just for this.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic counter that nudges successive identifier draws apart
/// even if two tunnels start in the same nanosecond.
static SEED_TICK: AtomicU64 = AtomicU64::new(0);

/// Pick a 16-bit ICMP identifier for a tunnel. Avoids `0` (which some
/// middleboxes treat as "no identifier" and may scrub) and any value
/// that's an obvious well-known port (`53`, `80`, `443`, `8080`) so a
/// glance at `tcpdump` output makes "is this our spoofed traffic or a
/// real ping?" easier to answer.
pub fn pick_identifier(tunnel_id: i64) -> u16 {
    // Splitmix-style finalize over the seed bits.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let tick = SEED_TICK.fetch_add(1, Ordering::Relaxed);
    let mut x = nanos
        ^ (tunnel_id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ tick.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let mut id = (x & 0xFFFF) as u16;
    // Avoid easily-confusable values.
    const BAD: &[u16] = &[0, 1, 53, 80, 443, 1024, 8080, 0xFFFF];
    while BAD.contains(&id) {
        id = id.wrapping_add(1);
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn returns_non_reserved_values() {
        for tid in 1..50 {
            let id = pick_identifier(tid);
            assert_ne!(id, 0);
            assert_ne!(id, 443);
            assert_ne!(id, 53);
            assert_ne!(id, 80);
            assert_ne!(id, 0xFFFF);
        }
    }

    #[test]
    fn varies_across_calls() {
        // Not a strict uniqueness guarantee — but a sample of 100
        // calls should yield > 50 distinct values.
        let mut seen = HashSet::new();
        for tid in 1..=100 {
            seen.insert(pick_identifier(tid));
        }
        assert!(
            seen.len() > 50,
            "expected diverse identifiers; got {} distinct values out of 100",
            seen.len()
        );
    }
}
