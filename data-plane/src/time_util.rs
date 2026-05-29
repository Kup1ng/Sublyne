//! Small wall-clock helper.
//!
//! The HMAC envelope embeds the sender's `timestamp_seconds`; the
//! receiver rejects packets whose timestamp is outside a 60-second
//! window. We use the real wall clock everywhere in production. Tests
//! that need to inject a fixed time call the explicit `with_now`
//! variants on each helper instead of redefining this function.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix time (seconds since 1970). Saturates at 0
/// if the system clock is somehow before the epoch — that should never
/// happen on a real Linux box, but we don't want a panic on a CI VM
/// with a broken clock.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
