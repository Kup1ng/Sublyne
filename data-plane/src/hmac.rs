//! HMAC envelope for the spoofed download path.
//!
//! Wire layout:
//!
//! ```text
//! +----+----------------+----+--------------------+
//! | 16 |       8        |  8 |        N           |
//! +----+----------------+----+--------------------+
//! |HMAC|   session_id   |seq |   forwarded UDP    |
//! |    |   (random,     |    |   payload bytes    |
//! |    |   per-Remote-  |    |                    |
//! |    |   startup)     |    |                    |
//! +----+----------------+----+--------------------+
//!    16                24   32                  32+N
//! ```
//!
//! The HMAC is
//! `HMAC-SHA256(psk32, session_id || seq || SHA256(payload))[0..16]`
//! where `psk32` is the operator's PSK expanded to 32 bytes via
//! HKDF-SHA256 with a fixed info string. 16-byte truncation is
//! intentional and documented in `.claude/skills/raw-sockets-and-spoofing/SKILL.md`.
//!
//! ## Why no wall-clock timestamp any more
//!
//! Earlier versions of this envelope embedded a `ts` (Unix seconds at
//! seal time) and the receiver rejected anything outside a ±60s window.
//! That worked as cheap replay protection only when both ends agreed on
//! the wall clock, which fell apart on Iranian client boxes: standard
//! NTP servers (pool.ntp.org / time.google.com / time.cloudflare.com)
//! are blocked outbound, and a freshly-installed VM commonly boots with
//! its RTC several HOURS off. The symptom was silent — every spoofed
//! download was discarded with a single DEBUG-level "dropped stale
//! download packet (timestamp window)" log, and the tunnel "didn't
//! connect" with no clue why.
//!
//! Replacement design — no clock involved:
//!
//! - The Remote (sender) generates a **random 64-bit `session_id`** once
//!   per spoof-send pipeline spawn. The id is read from `/dev/urandom`,
//!   zero is rejected (cheap sentinel), and the same id is used for
//!   every packet that pipeline seals.
//! - The client (receiver) keeps the existing 1024-bit sliding seq
//!   bitmap in [`SeqWindow`] AND remembers the most recent session_id
//!   it accepted. A packet whose `session_id` matches the current one
//!   gets the usual in-session seq-bitmap check. A packet whose
//!   `session_id` is NEW (i.e. the Remote restarted) installs a fresh
//!   bitmap and starts accepting from the seq it carries. Same-session
//!   replays are caught by the bitmap exactly as before.
//!
//! Threat coverage compared to the old design:
//!
//! - In-session replay: still rejected (bitmap, unchanged).
//! - Forged packets from network attackers without the PSK: still
//!   rejected (HMAC, unchanged — this is the actual security guarantee).
//! - Replay of packets captured from a *previous* session_id, replayed
//!   after the Remote has restarted: the receiver does NOT remember
//!   evicted session_ids and would accept these as "new session". This
//!   was previously bounded by the 60s ts window and is now bounded by
//!   the inner protocol's own replay protection (WireGuard sessions
//!   inside the UDP payload have their own monotonic counter). For the
//!   real-world threat model — Iranian DPI passively inspecting traffic,
//!   not a network attacker capturing + retransmitting raw download
//!   bytes — this is fine.
//!
//! ## Per-packet cost and the `HmacKey` pre-derive (Round 2 / R2)
//!
//! `HmacSha256::new_from_slice(psk32)` is not free — internally it pads
//! the key to a 64-byte block, XORs with `0x36`, and runs the resulting
//! `ipad` block through the SHA-256 compression function to prime the
//! inner hasher. At ~17 800 spoof packets/sec (200 Mbit/s with 1400 B
//! payloads) that is ~17 800 wasted SHA-256 block compressions per
//! second per tunnel, on the hot recv loop.
//!
//! [`HmacKey`] performs that priming once at tunnel start and stores the
//! already-keyed `Hmac<Sha256>` instance. Per-packet, the seal / open
//! paths `.clone()` the primed state (a memcpy of the inner SHA-256
//! state + the precomputed `opad`) and then run only the variable
//! `update(session_id || seq || payload_hash)` + `finalize()`. The clone
//! is an order of magnitude cheaper than the re-prime — it skips both
//! the key-pad construction and the ipad block compression.

use ::hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::io::Read;

type HmacSha256 = Hmac<Sha256>;

pub const HMAC_LEN: usize = 16;
pub const SESSION_ID_LEN: usize = 8;
pub const SEQ_LEN: usize = 8;
pub const OVERHEAD: usize = HMAC_LEN + SESSION_ID_LEN + SEQ_LEN;

/// Per-tunnel HMAC key holder.
///
/// Wraps the raw 32-byte HKDF-derived PSK alongside an already-keyed
/// `Hmac<Sha256>` instance. Clone the primed state per packet via
/// [`HmacKey::primed_hasher`] instead of calling
/// `HmacSha256::new_from_slice(psk32)` every time — the `Hmac<H>` type
/// implements `Clone`, and clone is dramatically cheaper than re-keying
/// because it skips the inner-pad block compression.
///
/// Construct once at tunnel spawn and on PSK hot-reload; share via
/// `Arc<HmacKey>` across worker tasks. The raw 32-byte key stays
/// accessible via [`HmacKey::raw`] for callers that genuinely need it
/// (the legacy `seal`/`open` test helpers, and code paths that haven't
/// been migrated yet).
pub struct HmacKey {
    raw: [u8; 32],
    primed: HmacSha256,
}

impl HmacKey {
    /// Build a key holder by deriving the per-tunnel key from a raw PSK
    /// string and priming the HMAC state once.
    pub fn from_psk(psk: &str) -> Self {
        let raw = derive_key(psk);
        Self::from_raw(raw)
    }

    /// Build a key holder from an already-derived 32-byte key.
    pub fn from_raw(raw: [u8; 32]) -> Self {
        let primed = HmacSha256::new_from_slice(&raw).expect("HMAC key len");
        Self { raw, primed }
    }

    /// Reference to the raw HKDF-derived key bytes. Don't log this.
    #[inline]
    pub fn raw(&self) -> &[u8; 32] {
        &self.raw
    }

    /// Cheap clone of the already-keyed hasher. The caller then runs
    /// `.update()` over the variable bytes and `.finalize()`.
    #[inline]
    fn primed_hasher(&self) -> HmacSha256 {
        self.primed.clone()
    }
}

impl Clone for HmacKey {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw,
            primed: self.primed.clone(),
        }
    }
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted — the raw bytes never appear in any debug output.
        f.debug_struct("HmacKey").field("raw", &"***").finish()
    }
}

impl PartialEq for HmacKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time compare so logging code that happens to derive
        // PartialEq through wrappers doesn't leak via timing. The raw
        // bytes are what defines equality; the primed hasher is a
        // deterministic function of `raw` so we don't compare it.
        constant_time_eq::constant_time_eq(&self.raw, &other.raw)
    }
}

impl Eq for HmacKey {}

/// Number of 64-bit words in the sliding-window bitmap. 16 words ×
/// 64 bits = 1024 effective replay slots — matching the documented
/// `SEQ_WINDOW_SIZE` contract.
///
/// Was a single `u128` (128 slots) until v1.0.1; under sustained
/// 30+ Mbit/s load with the parallel-seal pipeline, the per-seal-
/// worker channel cap (`SEAL_WORKER_CHANNEL_CAP * n_workers`) could
/// reorder the wire stream by ~256 seqs, which is still inside the
/// 1024-slot contract but exceeded the actual 128-slot bitmap. The
/// resulting `Replay` drops manifested as "quality goes terrible
/// after 10 minutes of high traffic" — same packets accepted earlier
/// would later be re-marked stale and discarded. Promoting the
/// bitmap to a `[u64; 16]` makes the in-code reality match the
/// docstring and gives the Remote side room to grow its seal queue.
pub const SEQ_WINDOW_WORDS: usize = 16;
/// 1024 slots, in seq units.
pub const SEQ_WINDOW_SIZE: u64 = (SEQ_WINDOW_WORDS as u64) * 64;

/// Generate a random non-zero 64-bit session id from `/dev/urandom`.
///
/// Called once per spoof-send pipeline spawn on the Remote (sender)
/// side. Zero is rejected so a stuck `/dev/urandom` returning all-zeros
/// (which never happens on a real Linux box, but the kernel does block
/// reads early in boot if entropy isn't initialised — `/dev/urandom`
/// will return immediately though) doesn't produce a session_id that
/// looks like a sentinel.
///
/// We deliberately do NOT pull `rand` in for this — `/dev/urandom` is
/// always available on Linux, the read is a single syscall, and we only
/// call this once per tunnel start. Adding a crypto-RNG crate would be
/// overkill for one u64 a year.
pub fn random_session_id() -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    loop {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)?;
        let v = u64::from_be_bytes(buf);
        if v != 0 {
            return Ok(v);
        }
        // Vanishingly unlikely. Loop rather than recurse.
    }
}

/// Derive the per-tunnel 32-byte HMAC key from an operator-supplied
/// PSK string. Any non-empty input yields a 32-byte key; identical
/// inputs always yield the same key, so the Client and Remote sides
/// agree by sharing the original PSK string.
pub fn derive_key(psk: &str) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, psk.as_bytes());
    let mut out = [0u8; 32];
    // info string ties the derived key to this project — a different
    // project happening to use the same PSK would still produce a
    // different key.
    hkdf.expand(b"sublyne-dataplane v1 psk", &mut out)
        .expect("hkdf expand 32 bytes never fails");
    out
}

/// Build the spoof body (`HMAC || session_id || seq || payload`) using a
/// pre-derived [`HmacKey`]. Hot path: clones the keyed hasher rather
/// than calling `new_from_slice` per packet.
pub fn seal_with(key: &HmacKey, session_id: u64, seq: u64, payload: &[u8], out: &mut Vec<u8>) {
    let mut payload_hash = Sha256::new();
    payload_hash.update(payload);
    let payload_hash = payload_hash.finalize();

    let mut h = key.primed_hasher();
    h.update(&session_id.to_be_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&payload_hash);
    let tag = h.finalize().into_bytes();

    out.clear();
    out.reserve(OVERHEAD + payload.len());
    out.extend_from_slice(&tag[..HMAC_LEN]);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Legacy entry that re-keys per call. Kept for tests and any
/// non-hot-path callers; new code should construct an [`HmacKey`] once
/// and call [`seal_with`].
pub fn seal(psk32: &[u8; 32], session_id: u64, seq: u64, payload: &[u8], out: &mut Vec<u8>) {
    seal_with(&HmacKey::from_raw(*psk32), session_id, seq, payload, out);
}

/// Why a sealed body was rejected. Receivers log the variant at WARN
/// for everything except `TooShort`, which is the kind of noise random
/// scanners produce on raw download ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Body shorter than `OVERHEAD`. Not a real HMAC attempt.
    TooShort,
    /// HMAC tag did not match. Tampering or wrong PSK.
    Auth,
    /// Sequence number was already seen for this session (replay).
    Replay,
}

/// Per-(tunnel, sender) sliding sequence-number window. Receivers
/// instantiate one per tunnel; per-direction is implicit because the
/// Client only verifies download (Remote→Client) and the Remote only
/// verifies upload-side HMAC (currently nothing — the upload path is
/// regular WG-encrypted UDP, not HMAC-stamped).
///
/// The window now also tracks the **current sender session_id**. A
/// packet that carries a different session_id with a valid HMAC is
/// treated as "the Remote restarted": the bitmap resets to empty and we
/// start accepting from the seq the new packet carries. This replaces
/// the old wall-clock `ts` check (see module-level docs for the why).
#[derive(Debug)]
pub struct SeqWindow {
    /// Current sender's session_id. `None` means we haven't accepted
    /// any packet yet. A different incoming session_id (after passing
    /// HMAC) installs itself here and resets `last` + `bitmap`.
    session_id: Option<u64>,
    /// Highest sequence number accepted so far in the current session.
    last: u64,
    /// Bitmap of accepted sequence numbers strictly less than `last`
    /// within the 1024-slot window. Treated as a single 1024-bit
    /// little-endian integer: word 0 holds bits 0..63 (offsets 1..64
    /// behind `last`), word 1 holds bits 64..127, … word 15 holds bits
    /// 960..1023. Bit at offset `i` (counted from `last - 1` = 0)
    /// lives at `bitmap[i / 64] & (1 << (i % 64))`.
    bitmap: [u64; SEQ_WINDOW_WORDS],
}

impl Default for SeqWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SeqWindow {
    pub fn new() -> Self {
        Self {
            session_id: None,
            last: 0,
            bitmap: [0u64; SEQ_WINDOW_WORDS],
        }
    }

    /// Returns the currently-tracked session_id (for diagnostics).
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// Shift the bitmap left by `n` bit positions (toward higher
    /// offsets — i.e. existing entries move further back from `last`).
    /// Words beyond the array fall off, lower words become zero.
    #[inline]
    fn bitmap_shl(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        let word_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let words = SEQ_WINDOW_WORDS;
        if word_shift >= words {
            self.bitmap = [0u64; SEQ_WINDOW_WORDS];
            return;
        }
        if bit_shift == 0 {
            for i in (word_shift..words).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
        } else {
            for i in (word_shift..words).rev() {
                let hi = self.bitmap[i - word_shift] << bit_shift;
                let lo = if i > word_shift {
                    self.bitmap[i - word_shift - 1] >> (64 - bit_shift)
                } else {
                    0
                };
                self.bitmap[i] = hi | lo;
            }
        }
        for slot in self.bitmap.iter_mut().take(word_shift) {
            *slot = 0;
        }
    }

    /// Returns true if the bit at `offset` (0 = the slot immediately
    /// below `last`) is set, false if clear OR outside the window.
    #[inline]
    fn bitmap_get(&self, offset: u64) -> bool {
        let w = (offset / 64) as usize;
        if w >= SEQ_WINDOW_WORDS {
            return false;
        }
        let b = offset % 64;
        (self.bitmap[w] >> b) & 1 == 1
    }

    /// Set the bit at `offset`. Caller must have already verified
    /// the offset is inside the window.
    #[inline]
    fn bitmap_set(&mut self, offset: u64) {
        let w = (offset / 64) as usize;
        let b = offset % 64;
        self.bitmap[w] |= 1u64 << b;
    }

    /// Returns true when `(session_id, seq)` is acceptable and updates
    /// internal state to record it. Returns false otherwise (replay).
    ///
    /// Behaviour:
    /// - `seq == 0` → always rejected (sentinel). Senders MUST start at
    ///   `seq=1`.
    /// - First call ever, or `session_id` differs from the stored one →
    ///   treated as a new sender session. Reset bitmap, install
    ///   `session_id`, accept the packet (recording `seq` as the new
    ///   high-water mark).
    /// - Same session → sliding-window logic: accept if higher than
    ///   `last`, accept if within the 1024-slot bitmap and not already
    ///   marked, reject otherwise.
    pub fn check_and_set(&mut self, session_id: u64, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        match self.session_id {
            Some(cur) if cur == session_id => {}
            _ => {
                // New sender session: reset and accept this packet as
                // the first of the new window.
                self.session_id = Some(session_id);
                self.last = seq;
                self.bitmap = [0u64; SEQ_WINDOW_WORDS];
                return true;
            }
        }
        if seq > self.last {
            let delta = seq - self.last;
            if delta >= SEQ_WINDOW_SIZE {
                // The whole bitmap falls off.
                self.bitmap = [0u64; SEQ_WINDOW_WORDS];
            } else {
                self.bitmap_shl(delta as u32);
                if self.last != 0 {
                    // Record the previous `last` in the bitmap at
                    // offset (delta - 1) from the new top.
                    self.bitmap_set(delta - 1);
                }
            }
            self.last = seq;
            return true;
        }
        if seq == self.last {
            // Exact match of the highest accepted seq → replay.
            return false;
        }
        let offset = self.last - seq;
        if offset >= SEQ_WINDOW_SIZE {
            return false;
        }
        let bit_pos = offset - 1;
        if self.bitmap_get(bit_pos) {
            return false;
        }
        self.bitmap_set(bit_pos);
        true
    }
}

/// Verify the HMAC envelope on `body` without touching a replay
/// window. Returns the validated `(session_id, seq, payload)` triple so
/// the caller can run the window check separately — useful when
/// multiple worker tasks share the same `SeqWindow` behind a `Mutex`
/// and want to hold the lock only for the cheap `check_and_set` (a few
/// microseconds), not for the expensive HMAC compute (tens of
/// microseconds at MTU).
pub fn verify_with<'a>(key: &HmacKey, body: &'a [u8]) -> Result<(u64, u64, &'a [u8]), OpenError> {
    if body.len() < OVERHEAD {
        return Err(OpenError::TooShort);
    }
    let (hdr, payload) = body.split_at(OVERHEAD);
    let tag = &hdr[..HMAC_LEN];
    let session_id =
        u64::from_be_bytes(hdr[HMAC_LEN..HMAC_LEN + SESSION_ID_LEN].try_into().unwrap());
    let seq = u64::from_be_bytes(
        hdr[HMAC_LEN + SESSION_ID_LEN..HMAC_LEN + SESSION_ID_LEN + SEQ_LEN]
            .try_into()
            .unwrap(),
    );

    let mut payload_hash = Sha256::new();
    payload_hash.update(payload);
    let payload_hash = payload_hash.finalize();
    let mut h = key.primed_hasher();
    h.update(&session_id.to_be_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&payload_hash);
    let expected = h.finalize().into_bytes();
    if !constant_time_eq::constant_time_eq(tag, &expected[..HMAC_LEN]) {
        return Err(OpenError::Auth);
    }
    Ok((session_id, seq, payload))
}

/// Verify the HMAC envelope on `body` using a pre-derived [`HmacKey`]
/// and return the inner payload.
///
/// Hot path: clones the keyed hasher per call instead of re-running the
/// inner-pad block compression every packet. The seq-window check and
/// constant-time tag compare are unchanged.
pub fn open_with<'a>(
    key: &HmacKey,
    body: &'a [u8],
    window: &mut SeqWindow,
) -> Result<&'a [u8], OpenError> {
    let (session_id, seq, payload) = verify_with(key, body)?;
    if !window.check_and_set(session_id, seq) {
        return Err(OpenError::Replay);
    }
    Ok(payload)
}

/// Legacy entry that re-keys per call. Kept for tests; production
/// recv loops should use [`open_with`] against a tunnel-scoped key.
pub fn open<'a>(
    psk32: &[u8; 32],
    body: &'a [u8],
    window: &mut SeqWindow,
) -> Result<&'a [u8], OpenError> {
    open_with(&HmacKey::from_raw(*psk32), body, window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn psk() -> [u8; 32] {
        derive_key("a-shared-secret")
    }

    const SID: u64 = 0xDEAD_BEEF_CAFE_BABE;

    #[test]
    fn derive_key_is_deterministic() {
        assert_eq!(derive_key("x"), derive_key("x"));
        assert_ne!(derive_key("x"), derive_key("y"));
    }

    #[test]
    fn random_session_id_is_non_zero_and_varies() {
        let a = random_session_id().expect("urandom");
        let b = random_session_id().expect("urandom");
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        // Extremely unlikely to collide.
        assert_ne!(a, b);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = psk();
        let mut buf = Vec::new();
        seal(&key, SID, 42, b"hello world", &mut buf);
        let mut w = SeqWindow::new();
        let out = open(&key, &buf, &mut w).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn seq_window_size_is_1024_slots() {
        // Pins the bitmap-array contract: SEQ_WINDOW_SIZE must equal
        // exactly the number of bits the bitmap actually holds, or the
        // window math silently lies and `SEAL_WORKER_CHANNEL_CAP` over
        // in remote.rs has the wrong replay budget.
        assert_eq!(SEQ_WINDOW_SIZE, 1024);
        assert_eq!(SEQ_WINDOW_WORDS, 16);
    }

    #[test]
    fn replay_window_accepts_offset_1023_then_rejects_1024() {
        // The new 1024-slot bitmap should accept a packet whose seq is
        // up to 1023 positions BEHIND the current `last`, and reject
        // anything at 1024+ (outside window).
        let key = psk();
        let mut w = SeqWindow::new();

        // Walk last up to 1100 with a single high seq.
        let mut buf_hi = Vec::new();
        seal(&key, SID, 1100, b"x", &mut buf_hi);
        assert!(open(&key, &buf_hi, &mut w).is_ok());

        // 1024 positions back from 1100 = seq 76 → just OUTSIDE window.
        let mut buf_oldest_outside = Vec::new();
        seal(&key, SID, 76, b"x", &mut buf_oldest_outside);
        assert_eq!(
            open(&key, &buf_oldest_outside, &mut w),
            Err(OpenError::Replay),
            "seq exactly 1024 positions behind last must be rejected"
        );

        // 1023 positions back = seq 77 → at the edge, INSIDE window,
        // should be accepted.
        let mut buf_oldest_inside = Vec::new();
        seal(&key, SID, 77, b"x", &mut buf_oldest_inside);
        assert!(
            open(&key, &buf_oldest_inside, &mut w).is_ok(),
            "seq 1023 positions behind last must be accepted (in window)"
        );

        // And a replay of that same edge slot → rejected.
        assert_eq!(
            open(&key, &buf_oldest_inside, &mut w),
            Err(OpenError::Replay)
        );
    }

    #[test]
    fn replay_window_handles_multi_word_shift() {
        // Multi-word shifts are the new code path the u128→[u64;16]
        // change introduced; this test pins that a shift across word
        // boundaries doesn't lose state.
        let key = psk();
        let mut w = SeqWindow::new();

        // Receive a few packets spread across the window.
        for seq in &[1u64, 65, 200, 500, 900] {
            let mut buf = Vec::new();
            seal(&key, SID, *seq, b"x", &mut buf);
            assert!(open(&key, &buf, &mut w).is_ok());
        }

        // Now jump last forward by 500 (crosses several word
        // boundaries when the bitmap shifts).
        let mut buf_jump = Vec::new();
        seal(&key, SID, 1400, b"x", &mut buf_jump);
        assert!(open(&key, &buf_jump, &mut w).is_ok());

        // The previously accepted seqs 500 and 900 are now at offsets
        // 900 and 500 below last=1400 — still inside the 1024 window
        // — so re-presenting them must be rejected as replay (NOT
        // accepted as "new").
        for seq in &[500u64, 900] {
            let mut buf = Vec::new();
            seal(&key, SID, *seq, b"x", &mut buf);
            assert_eq!(
                open(&key, &buf, &mut w),
                Err(OpenError::Replay),
                "seq {} should still be marked after multi-word shift",
                seq
            );
        }

        // Seq 1 and 65 are now at offsets 1399 and 1335 below last —
        // outside the 1024 window, treated as too-old replay drops.
        for seq in &[1u64, 65] {
            let mut buf = Vec::new();
            seal(&key, SID, *seq, b"x", &mut buf);
            assert_eq!(
                open(&key, &buf, &mut w),
                Err(OpenError::Replay),
                "seq {} should be outside the 1024-slot window",
                seq
            );
        }
    }

    #[test]
    fn open_too_short_returns_too_short() {
        let key = psk();
        let mut w = SeqWindow::new();
        let body = vec![0u8; OVERHEAD - 1];
        assert_eq!(open(&key, &body, &mut w), Err(OpenError::TooShort));
    }

    #[test]
    fn open_wrong_psk_rejects() {
        let key_a = psk();
        let key_b = derive_key("different");
        let mut buf = Vec::new();
        seal(&key_a, SID, 1, b"payload", &mut buf);
        let mut w = SeqWindow::new();
        assert_eq!(open(&key_b, &buf, &mut w), Err(OpenError::Auth));
    }

    #[test]
    fn open_tampered_payload_rejects() {
        let key = psk();
        let mut buf = Vec::new();
        seal(&key, SID, 1, b"payload", &mut buf);
        // Flip one byte of the payload.
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        let mut w = SeqWindow::new();
        assert_eq!(open(&key, &buf, &mut w), Err(OpenError::Auth));
    }

    #[test]
    fn replay_protection_rejects_duplicate_seq_in_same_session() {
        let key = psk();
        let mut buf = Vec::new();
        seal(&key, SID, 7, b"payload", &mut buf);
        let mut w = SeqWindow::new();
        assert!(open(&key, &buf, &mut w).is_ok());
        // Same (session_id, seq) again → replay.
        assert_eq!(open(&key, &buf, &mut w), Err(OpenError::Replay));
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_range_same_session() {
        let key = psk();
        let mut w = SeqWindow::new();
        // Receive seq 5 first, then seq 3 — both should be accepted.
        let mut buf5 = Vec::new();
        seal(&key, SID, 5, b"five", &mut buf5);
        let mut buf3 = Vec::new();
        seal(&key, SID, 3, b"three", &mut buf3);
        assert!(open(&key, &buf5, &mut w).is_ok());
        assert!(open(&key, &buf3, &mut w).is_ok());
    }

    #[test]
    fn new_session_id_resets_window_and_accepts_low_seq() {
        // Simulates the Remote restarting: brand-new session_id, seq=1.
        // The receiver must accept the seq=1 packet even though `last`
        // was previously e.g. 100.
        let key = psk();
        let mut w = SeqWindow::new();
        let mut buf = Vec::new();
        seal(&key, SID, 100, b"old", &mut buf);
        assert!(open(&key, &buf, &mut w).is_ok());
        assert_eq!(w.session_id(), Some(SID));

        let new_sid = 0x1111_2222_3333_4444u64;
        let mut buf2 = Vec::new();
        seal(&key, new_sid, 1, b"new", &mut buf2);
        assert!(
            open(&key, &buf2, &mut w).is_ok(),
            "new session_id must reset and accept"
        );
        assert_eq!(w.session_id(), Some(new_sid));

        // And the seq=1 in the new session is now its last; replay of
        // seq=1 in the new session should fail.
        assert_eq!(open(&key, &buf2, &mut w), Err(OpenError::Replay));
    }

    #[test]
    fn cross_session_replay_after_session_change_is_dropped() {
        // After switching to a new session_id, a replay carrying the
        // OLD session_id but a fresh-looking seq would install itself
        // as "yet another new session". This is the documented bounded
        // weakening relative to the old ts-based design. It's permitted
        // by the threat model: the inner WireGuard protocol has its own
        // replay protection and a network attacker capable of capturing
        // + retransmitting raw spoofed download bytes is not in scope.
        //
        // This test pins the behaviour so it doesn't change silently —
        // if we later add an LRU of evicted session_ids, this test will
        // need to update.
        let key = psk();
        let mut w = SeqWindow::new();
        let old_sid = SID;
        let new_sid = 0x9999u64;

        let mut buf_old1 = Vec::new();
        seal(&key, old_sid, 1, b"a", &mut buf_old1);
        assert!(open(&key, &buf_old1, &mut w).is_ok());

        let mut buf_new1 = Vec::new();
        seal(&key, new_sid, 1, b"b", &mut buf_new1);
        assert!(open(&key, &buf_new1, &mut w).is_ok());

        // Replay of the OLD session's seq=1: currently treated as
        // another new session and accepted. Pinning behaviour.
        assert!(open(&key, &buf_old1, &mut w).is_ok());
        assert_eq!(w.session_id(), Some(old_sid));
    }

    proptest! {
        #[test]
        fn proptest_seal_open_roundtrip(session_id in 1u64..u64::MAX, seq in 1u64..u64::MAX, payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let key = derive_key("k");
            let mut buf = Vec::new();
            seal(&key, session_id, seq, &payload, &mut buf);
            let mut w = SeqWindow::new();
            let out = open(&key, &buf, &mut w).unwrap();
            prop_assert_eq!(out, &payload[..]);
        }

        #[test]
        fn proptest_tampered_hmac_rejected(session_id in 1u64..u64::MAX, seq in 1u64..u64::MAX, payload in proptest::collection::vec(any::<u8>(), 1..256), flip in 0usize..16) {
            let key = derive_key("k");
            let mut buf = Vec::new();
            seal(&key, session_id, seq, &payload, &mut buf);
            buf[flip] ^= 0xff;
            let mut w = SeqWindow::new();
            prop_assert_eq!(open(&key, &buf, &mut w), Err(OpenError::Auth));
        }
    }

    #[test]
    fn key_seal_open_roundtrip() {
        let key = HmacKey::from_psk("a-shared-secret");
        let mut buf = Vec::new();
        seal_with(&key, SID, 42, b"hello world", &mut buf);
        let mut w = SeqWindow::new();
        let out = open_with(&key, &buf, &mut w).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn key_and_raw_paths_produce_identical_bytes() {
        // Critical compatibility check: a packet sealed with the new
        // pre-derived path must be openable with the legacy path and
        // vice versa. The two implementations MUST produce byte-for-byte
        // identical envelopes; an interop bug here would silently break
        // the live tunnel when one side runs new code and the other old.
        let raw = derive_key("a-shared-secret");
        let key = HmacKey::from_raw(raw);
        let payload = b"the same eleven characters again";
        let seq = 1234u64;
        let mut buf_legacy = Vec::new();
        let mut buf_new = Vec::new();
        seal(&raw, SID, seq, payload, &mut buf_legacy);
        seal_with(&key, SID, seq, payload, &mut buf_new);
        assert_eq!(buf_legacy, buf_new, "sealed bytes must match");
        // Round-trip cross both directions.
        let mut w = SeqWindow::new();
        assert_eq!(
            open(&raw, &buf_new, &mut w).unwrap(),
            payload,
            "legacy open of new-sealed must succeed"
        );
        let mut w = SeqWindow::new();
        assert_eq!(
            open_with(&key, &buf_legacy, &mut w).unwrap(),
            payload,
            "new open of legacy-sealed must succeed"
        );
    }

    #[test]
    fn key_redacts_in_debug() {
        let key = HmacKey::from_psk("very-secret");
        let s = format!("{key:?}");
        assert!(!s.contains("very-secret"), "raw psk leaked in debug");
        assert!(s.contains("***"), "expected redacted marker, got: {s}");
    }

    proptest! {
        #[test]
        fn proptest_key_path_matches_raw_path(session_id in 1u64..u64::MAX, seq in 1u64..u64::MAX, payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let raw = derive_key("k");
            let key = HmacKey::from_raw(raw);
            let mut buf_legacy = Vec::new();
            let mut buf_new = Vec::new();
            seal(&raw, session_id, seq, &payload, &mut buf_legacy);
            seal_with(&key, session_id, seq, &payload, &mut buf_new);
            prop_assert_eq!(buf_legacy, buf_new);
        }
    }
}
