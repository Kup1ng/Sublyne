//! Per-tunnel session table.
//!
//! On both Client and Remote sides we keep a small bookkeeping record
//! for every active "session" — a session is uniquely identified by
//! the end-user's (IP, port) on the Client side, and by the forward
//! target's (IP, port) on the Remote side. The table maps that key
//! back to the socket address we should reply to.
//!
//! Two invariants this module enforces and that the rest of the
//! dataplane depends on:
//!
//! 1. **Backpressure.** When the table reaches `max_connections`,
//!    `insert` returns `InsertOutcome::Rejected` rather than crashing
//!    or growing without bound. The caller drops the packet and logs.
//! 2. **Idle eviction.** A periodic sweep evicts entries whose
//!    `last_seen` is older than `idle_timeout`. The dataplane runs
//!    one sweep task per tunnel so this work is bounded by the number
//!    of tunnels, not the number of sessions.
//!
//! ## Sharding (Round 2 / R2)
//!
//! The table is split into [`SHARDS`] independent `Mutex<HashMap>`
//! buckets, keyed by `hash(session_key) % SHARDS`. Every per-packet
//! operation (`insert_or_refresh`, `touch`) locks only one shard, so
//! N workers running concurrent recv loops collide on average only
//! 1/SHARDS of the time. The total entry count is tracked in an
//! `AtomicUsize` outside the shards so the `max_connections` cap stays
//! a single atomic load instead of an O(SHARDS) walk.
//!
//! The shard count is a power of two (16) chosen as a sweet spot
//! between memory overhead (one HashMap header per shard) and lock
//! contention at 8 worker cores (the Remote box). 16 keeps contention
//! under ~6 % even at peak send rates, while still fitting in two cache
//! lines per shard pointer table.
//!
//! ## Most-recently-active session (idle-resume bug fix)
//!
//! `any_session` is what the Client side calls when it has an HMAC-
//! verified download payload and needs to pick a local peer to deliver
//! it to. Until this fix it walked shards in iteration order and
//! returned the FIRST non-empty entry — deterministic by hash, so the
//! OLDEST session would consistently win even after a newer one was
//! inserted.
//!
//! That broke the "disconnect + idle + reconnect" path. If the
//! operator's end-user device disconnects and reconnects within the
//! `idle_timeout_sec` window (PRD default 300 s), the old session
//! still sits in the table. With shard-iteration order, every spoofed
//! download reply would be addressed to the dead peer (the old
//! ephemeral port the kernel had freed) and the new session would
//! never receive anything — until a manual Stop+Start cleared the
//! table.
//!
//! The fix is a tiny [`Mutex<Option<SocketAddr>>`] field updated on
//! every successful insert_or_refresh. `any_session` consults it
//! first, falling back to the legacy shard walk only when the
//! tracked key has since been evicted. The eviction path clears the
//! tracker when it drops the targeted key, so a stale pointer cannot
//! survive a sweep.

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One row in the session table.
#[derive(Debug, Clone, Copy)]
pub struct SessionEntry {
    /// Address to send replies to. On the Client side this is the
    /// end-user's address; on the Remote side it's the forward
    /// target's source address.
    pub peer: SocketAddr,
    /// Wall-time monotonic stamp of the most recent activity. Reset on
    /// every observed packet in either direction.
    pub last_seen: Instant,
}

/// Outcome of `insert` / `touch`. Lets the caller distinguish "this is
/// a brand new session, account for it" from "we already knew about
/// this session" from "the table is full, drop the packet".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// New session created.
    Created,
    /// Existing session refreshed.
    Refreshed,
    /// Table is full and the key was not present. Caller must drop
    /// the packet and log at WARN. PRD §7 says "never crash".
    Rejected,
}

/// Number of independent shards. Power of two so the index is a cheap
/// mask. 16 is enough to keep lock contention under control on the
/// 8-core Remote box without burning memory on shard headers.
pub const SHARDS: usize = 16;
const SHARD_MASK: u64 = (SHARDS as u64) - 1;

/// Hasher used for shard selection. `BuildHasherDefault<DefaultHasher>`
/// gives us a deterministic-per-process hash without per-table
/// randomization overhead.
type ShardHasher = BuildHasherDefault<std::collections::hash_map::DefaultHasher>;

/// Concurrent session table.
///
/// Sharded into [`SHARDS`] independent `Mutex<HashMap>` buckets keyed by
/// `hash(session_key) % SHARDS`. Per-packet operations lock only one
/// shard, so the hot path's contention drops to ~1/SHARDS of the
/// single-lock baseline. Total entry count is maintained in an
/// `AtomicUsize` so the `max_connections` check stays a single atomic
/// load on every insert.
///
/// `max_connections` and `idle_timeout` live in atomics so the IPC
/// `UpdateTunnel` hot-reload path can flip them without touching any
/// shard mutex. Existing sessions over a newly-lowered cap drain
/// naturally via the idle sweeper rather than being yanked.
pub struct SessionTable {
    shards: Vec<Mutex<HashMap<SocketAddr, SessionEntry>>>,
    /// Global session count — sum of all shards. Updated atomically by
    /// every insert (Created → +1) and every removal (eviction → -N,
    /// clear → resets to 0). Lets `len()` and the `max_connections`
    /// check stay O(1).
    total: AtomicUsize,
    max_connections: AtomicU32,
    idle_timeout_sec: AtomicU64,
    hasher: ShardHasher,
    /// Most-recently-active session key. Bumped on every successful
    /// [`SessionTable::insert_or_refresh`]; consulted by
    /// [`SessionTable::any_session`] so spoofed downloads land on the
    /// freshest peer instead of an arbitrary shard-iteration winner.
    /// Cleared by [`SessionTable::evict_idle`] when the targeted key is
    /// the one being evicted, and by [`SessionTable::clear`] on tunnel
    /// stop. See the module doc-comment for the bug history.
    current: Mutex<Option<SocketAddr>>,
}

impl SessionTable {
    pub fn new(max_connections: u32, idle_timeout_sec: u32) -> Self {
        let max = max_connections.max(1);
        // Pre-size each shard for an even split of the per-tunnel cap;
        // a small floor avoids degenerate cases on tiny tunnels.
        let per_shard_hint = (max as usize / SHARDS).clamp(8, 4096);
        let mut shards = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            shards.push(Mutex::new(HashMap::with_capacity(per_shard_hint)));
        }
        Self {
            shards,
            total: AtomicUsize::new(0),
            max_connections: AtomicU32::new(max),
            idle_timeout_sec: AtomicU64::new(idle_timeout_sec.max(1) as u64),
            hasher: ShardHasher::default(),
            current: Mutex::new(None),
        }
    }

    /// Live-replace the connection cap. Existing sessions in excess of
    /// the new cap are NOT evicted — they drain naturally via idle
    /// sweep, which preserves in-flight traffic on a downward edit.
    pub fn set_max_connections(&self, n: u32) {
        self.max_connections.store(n.max(1), Ordering::Relaxed);
    }

    /// Live-replace the idle timeout. The next sweep uses the new
    /// value; in-flight sessions younger than the new timeout are
    /// kept. The sweeper tick interval stays at its spawn-time value
    /// (about timeout/4 seconds) — a drastic decrease takes effect on
    /// the next tick rather than instantly. Acceptable for hot-reload.
    pub fn set_idle_timeout(&self, secs: u32) {
        self.idle_timeout_sec
            .store(secs.max(1) as u64, Ordering::Relaxed);
    }

    /// Current connection cap. Cheap atomic read for callers that want
    /// to log it.
    pub fn max_connections(&self) -> u32 {
        self.max_connections.load(Ordering::Relaxed)
    }

    /// Current idle timeout in seconds.
    pub fn idle_timeout_sec(&self) -> u64 {
        self.idle_timeout_sec.load(Ordering::Relaxed)
    }

    #[inline]
    fn shard_for(&self, key: &SocketAddr) -> &Mutex<HashMap<SocketAddr, SessionEntry>> {
        let mut h = self.hasher.build_hasher();
        std::hash::Hash::hash(key, &mut h);
        let idx = (h.finish() & SHARD_MASK) as usize;
        // SAFETY by construction: idx < SHARDS == shards.len().
        &self.shards[idx]
    }

    /// Insert a new session keyed by `key`, or refresh an existing
    /// entry's `last_seen`. The `peer` argument is recorded only for
    /// the create path — refresh keeps the prior peer value (it
    /// should be identical, the key is the peer in practice).
    ///
    /// New sessions are rejected when EITHER the per-tunnel
    /// `max_connections` cap is reached OR the process is in
    /// memory-pressure mode (see [`crate::memory`], PRD §7).
    /// Existing sessions always refresh — backpressure only affects
    /// the create path so in-flight traffic survives a spike.
    pub fn insert_or_refresh(&self, key: SocketAddr, peer: SocketAddr) -> InsertOutcome {
        let shard = self.shard_for(&key);
        let mut guard = shard.lock().unwrap();
        if let Some(entry) = guard.get_mut(&key) {
            entry.last_seen = Instant::now();
            drop(guard);
            self.mark_current(key);
            return InsertOutcome::Refreshed;
        }
        let cap = self.max_connections.load(Ordering::Relaxed) as usize;
        if self.total.load(Ordering::Relaxed) >= cap {
            return InsertOutcome::Rejected;
        }
        // PRD §7: the process-level memory soft cap rejects new
        // sessions to avoid an OOM kill / systemd restart loop.
        if crate::memory::pressure_active() {
            return InsertOutcome::Rejected;
        }
        guard.insert(
            key,
            SessionEntry {
                peer,
                last_seen: Instant::now(),
            },
        );
        self.total.fetch_add(1, Ordering::Relaxed);
        drop(guard);
        self.mark_current(key);
        InsertOutcome::Created
    }

    /// Record `key` as the most-recently-active session so the next
    /// [`SessionTable::any_session`] call prefers it over older entries
    /// that linger in the table during the idle-eviction window.
    #[inline]
    fn mark_current(&self, key: SocketAddr) {
        if let Ok(mut guard) = self.current.lock() {
            *guard = Some(key);
        }
    }

    /// Return the entry matching `key`, refreshing its `last_seen`
    /// stamp as a side effect. Returns `None` if the key is unknown.
    pub fn touch(&self, key: &SocketAddr) -> Option<SessionEntry> {
        let shard = self.shard_for(key);
        let mut guard = shard.lock().unwrap();
        if let Some(entry) = guard.get_mut(key) {
            entry.last_seen = Instant::now();
            return Some(*entry);
        }
        None
    }

    /// Return one session's peer address, refreshing its last_seen
    /// stamp. Used by the Client-side actor as the "deliver this
    /// verified download to whoever started talking to us" hook;
    /// Phase 10 will replace it with explicit session-id demultiplexing.
    ///
    /// Selection rule (idle-resume bug fix):
    /// 1. If [`SessionTable::insert_or_refresh`] recorded a
    ///    most-recently-active key in `current` AND that key is still
    ///    in the table, return it. This keeps the freshest end-user
    ///    session as the delivery target even when older sessions
    ///    still linger pre-eviction.
    /// 2. Otherwise fall back to a shard-iteration walk so a
    ///    still-live older session can still receive replies — useful
    ///    if `current` got cleared by an idle sweep before any new
    ///    upload arrived.
    /// 3. Otherwise return `None`.
    ///
    /// For tunnels with a single live end-user (the common dev /
    /// loopback case) the result is deterministic.
    pub fn any_session(&self) -> Option<SocketAddr> {
        let current_key = self.current.lock().ok().and_then(|g| *g);
        if let Some(key) = current_key {
            let shard = self.shard_for(&key);
            let mut guard = shard.lock().unwrap();
            if let Some(entry) = guard.get_mut(&key) {
                entry.last_seen = Instant::now();
                return Some(key);
            }
            // Tracked key got evicted between `mark_current` and now.
            // Clear the pointer so future calls don't keep paying the
            // shard lookup before falling back.
            drop(guard);
            if let Ok(mut g) = self.current.lock() {
                if *g == Some(key) {
                    *g = None;
                }
            }
        }
        for shard in &self.shards {
            let mut guard = shard.lock().unwrap();
            if let Some((k, v)) = guard.iter_mut().next() {
                v.last_seen = Instant::now();
                return Some(*k);
            }
        }
        None
    }

    /// Number of currently-tracked sessions. O(1) — backed by the
    /// global `total` atomic. May lag by a handful of inserts under
    /// concurrent writers; that's fine for the metrics reporter and
    /// for the `max_connections` admission gate.
    pub fn len(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// True when the table holds zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry whose `last_seen` is older than the current
    /// `idle_timeout` from `now`. Returns the number evicted so the
    /// caller can log a summary. The timeout is loaded fresh from the
    /// atomic so a recent `set_idle_timeout` applies on this sweep.
    pub fn evict_idle(&self, now: Instant) -> usize {
        let timeout = Duration::from_secs(self.idle_timeout_sec.load(Ordering::Relaxed));
        let cutoff = match now.checked_sub(timeout) {
            Some(c) => c,
            None => return 0,
        };
        let current_key = self.current.lock().ok().and_then(|g| *g);
        let mut current_evicted = false;
        let mut evicted = 0usize;
        for shard in &self.shards {
            let mut guard = shard.lock().unwrap();
            let before = guard.len();
            guard.retain(|k, e| {
                let keep = e.last_seen >= cutoff;
                if !keep && current_key == Some(*k) {
                    current_evicted = true;
                }
                keep
            });
            evicted += before - guard.len();
        }
        if evicted > 0 {
            self.total.fetch_sub(evicted, Ordering::Relaxed);
        }
        if current_evicted {
            if let Ok(mut g) = self.current.lock() {
                if *g == current_key {
                    *g = None;
                }
            }
        }
        evicted
    }

    /// Empty the table. Used on tunnel stop.
    ///
    /// Counts removed entries under each shard lock and `fetch_sub`s them
    /// (rather than a blind `store(0)`), so a concurrent `insert_or_refresh`
    /// into an already-cleared shard — its `fetch_add(1)` — survives instead
    /// of being clobbered to a phantom-positive `total`. A blind reset would
    /// leave `total` permanently undercounting and could let the table grow
    /// past `max_connections`.
    pub fn clear(&self) {
        let mut removed: usize = 0;
        for shard in &self.shards {
            let mut g = shard.lock().unwrap();
            removed += g.len();
            g.clear();
        }
        self.total.fetch_sub(removed, Ordering::Relaxed);
        if let Ok(mut g) = self.current.lock() {
            *g = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn insert_then_get_refreshes() {
        let t = SessionTable::new(4, 60);
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Created
        );
        assert_eq!(t.len(), 1);
        assert!(t.touch(&addr(1000)).is_some());
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Refreshed
        );
    }

    #[test]
    fn backpressure_rejects_when_full() {
        let t = SessionTable::new(2, 60);
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Created
        );
        assert_eq!(
            t.insert_or_refresh(addr(1001), addr(1001)),
            InsertOutcome::Created
        );
        assert_eq!(
            t.insert_or_refresh(addr(1002), addr(1002)),
            InsertOutcome::Rejected
        );
        assert_eq!(t.len(), 2);
        // But touching an existing key still works — backpressure
        // only applies to brand-new sessions.
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Refreshed
        );
    }

    #[test]
    fn evict_idle_drops_old_entries() {
        let t = SessionTable::new(4, 1);
        t.insert_or_refresh(addr(1000), addr(1000));
        // Sleep a hair longer than the timeout, then sweep.
        std::thread::sleep(Duration::from_millis(1100));
        let now = Instant::now();
        let evicted = t.evict_idle(now);
        assert_eq!(evicted, 1);
        assert!(t.is_empty());
    }

    #[test]
    fn evict_idle_keeps_recent_entries() {
        let t = SessionTable::new(4, 60);
        t.insert_or_refresh(addr(1000), addr(1000));
        let evicted = t.evict_idle(Instant::now());
        assert_eq!(evicted, 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn clear_empties_table() {
        let t = SessionTable::new(4, 60);
        t.insert_or_refresh(addr(1000), addr(1000));
        t.insert_or_refresh(addr(1001), addr(1001));
        assert_eq!(t.len(), 2);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn any_session_returns_one_when_present() {
        let t = SessionTable::new(4, 60);
        assert!(t.any_session().is_none());
        t.insert_or_refresh(addr(1000), addr(1000));
        assert_eq!(t.any_session(), Some(addr(1000)));
    }

    // Regression test for the idle-resume bug: when an end-user
    // disconnects and reconnects within the idle-eviction window
    // (≤ idle_timeout_sec), the old session still lingers in the
    // table. The previous shard-iteration `any_session` could pick
    // the OLD session deterministically, sending every spoofed
    // download reply to the dead peer and starving the new one.
    //
    // The fix tracks the most-recently-active key in `current` so
    // the new session wins as soon as it's created. This test
    // exercises the precise scenario: insert A, insert B, expect
    // `any_session` to consistently return B until it's evicted or
    // until a newer insert overrides it.
    #[test]
    fn any_session_prefers_most_recently_inserted_during_overlap() {
        let t = SessionTable::new(4, 60);
        let a = addr(1000);
        let b = addr(1001);
        let c = addr(1002);

        // First session: A is the only candidate, so it wins.
        assert_eq!(t.insert_or_refresh(a, a), InsertOutcome::Created);
        assert_eq!(t.any_session(), Some(a));

        // New session B arrives while A is still live (no idle
        // eviction yet). B is fresher → B must win.
        assert_eq!(t.insert_or_refresh(b, b), InsertOutcome::Created);
        for _ in 0..10 {
            assert_eq!(
                t.any_session(),
                Some(b),
                "with A and B both live, any_session must return the freshest (B)"
            );
        }

        // Touch A to make it the most-recently-active — A wins now.
        assert_eq!(t.insert_or_refresh(a, a), InsertOutcome::Refreshed);
        assert_eq!(t.any_session(), Some(a));

        // Yet another fresh session C — C wins.
        assert_eq!(t.insert_or_refresh(c, c), InsertOutcome::Created);
        assert_eq!(t.any_session(), Some(c));
    }

    #[test]
    fn any_session_falls_back_when_current_was_evicted() {
        // `current` is just a Mutex<Option<SocketAddr>> hint. If the
        // tracked key gets evicted (idle sweep, manual clear of the
        // shard), the fall-through must still surface a live session
        // so spoofed downloads continue to flow.
        let t = SessionTable::new(4, 1);
        let a = addr(1000);
        t.insert_or_refresh(a, a);
        assert_eq!(t.any_session(), Some(a));

        // Wait past the timeout, sweep, and confirm A is gone.
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(t.evict_idle(Instant::now()), 1);
        assert!(t.is_empty());
        // No sessions left — `any_session` returns None, and the
        // stale `current` pointer is cleaned up on the way.
        assert_eq!(t.any_session(), None);

        // A fresh insert reseeds `current`, and `any_session` finds it.
        let b = addr(1001);
        t.insert_or_refresh(b, b);
        assert_eq!(t.any_session(), Some(b));
    }

    #[test]
    fn evict_idle_clears_current_when_targeted_key_is_evicted() {
        let t = SessionTable::new(4, 1);
        let a = addr(1000);
        t.insert_or_refresh(a, a);
        // A is `current`. Wait past the timeout and sweep.
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(t.evict_idle(Instant::now()), 1);
        // After eviction, `current` must be cleared so a stale pointer
        // doesn't survive into the next reconnect.
        let guard = t.current.lock().unwrap();
        assert!(
            guard.is_none(),
            "current must be cleared once its targeted session is evicted"
        );
    }

    #[test]
    fn clear_resets_current() {
        let t = SessionTable::new(4, 60);
        t.insert_or_refresh(addr(1000), addr(1000));
        assert!(t.current.lock().unwrap().is_some());
        t.clear();
        assert!(
            t.current.lock().unwrap().is_none(),
            "clear must drop the current pointer along with the table"
        );
    }

    #[test]
    fn set_max_connections_takes_effect_on_next_insert() {
        let t = SessionTable::new(2, 60);
        // Fill the table to its initial cap.
        t.insert_or_refresh(addr(1000), addr(1000));
        t.insert_or_refresh(addr(1001), addr(1001));
        assert_eq!(
            t.insert_or_refresh(addr(1002), addr(1002)),
            InsertOutcome::Rejected,
            "third session must be rejected at the initial cap"
        );
        // Raise the cap.
        t.set_max_connections(4);
        assert_eq!(t.max_connections(), 4);
        assert_eq!(
            t.insert_or_refresh(addr(1002), addr(1002)),
            InsertOutcome::Created,
            "next insert after raising cap must succeed"
        );
        // Lower the cap below the live count — existing entries kept,
        // new ones rejected.
        t.set_max_connections(1);
        assert_eq!(t.len(), 3);
        assert_eq!(
            t.insert_or_refresh(addr(1003), addr(1003)),
            InsertOutcome::Rejected
        );
    }

    #[test]
    fn memory_pressure_rejects_new_sessions_but_refreshes_existing() {
        // Hold the shared pressure lock for the whole test so our
        // set_pressure_for_test(true) window can't contaminate another
        // test's inserts running in parallel.
        let _g = crate::memory::PRESSURE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let t = SessionTable::new(10, 60);
        // First session lands while memory is fine.
        crate::memory::set_pressure_for_test(false);
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Created
        );
        // Pressure trips — new sessions get rejected.
        crate::memory::set_pressure_for_test(true);
        assert_eq!(
            t.insert_or_refresh(addr(1001), addr(1001)),
            InsertOutcome::Rejected,
            "new session must be rejected under memory pressure"
        );
        // But the existing session still refreshes under pressure;
        // PRD §7 says drop NEW sessions, not in-flight ones.
        assert_eq!(
            t.insert_or_refresh(addr(1000), addr(1000)),
            InsertOutcome::Refreshed,
            "existing session must still refresh under memory pressure"
        );
        // Once pressure clears, new sessions are accepted again.
        crate::memory::set_pressure_for_test(false);
        assert_eq!(
            t.insert_or_refresh(addr(1001), addr(1001)),
            InsertOutcome::Created
        );
    }

    #[test]
    fn set_idle_timeout_takes_effect_on_next_sweep() {
        let t = SessionTable::new(4, 3600);
        t.insert_or_refresh(addr(1000), addr(1000));
        // With a long timeout the entry survives a fresh sweep.
        assert_eq!(t.evict_idle(Instant::now()), 0);
        // Drop the timeout to 1 s, then sweep again with a faked
        // future Instant — entry must evict.
        t.set_idle_timeout(1);
        assert_eq!(t.idle_timeout_sec(), 1);
        let future = Instant::now() + Duration::from_secs(2);
        assert_eq!(t.evict_idle(future), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn shards_distribute_keys() {
        // Insert SHARDS * 4 distinct keys; at least 2 shards should
        // hold a non-zero share. (Worst case the hasher pathologically
        // collides, but DefaultHasher + SocketAddr should not.)
        let t = SessionTable::new(SHARDS as u32 * 8, 3600);
        for port in 30_000..(30_000 + (SHARDS as u16) * 4) {
            t.insert_or_refresh(addr(port), addr(port));
        }
        assert_eq!(t.len(), SHARDS * 4);
        let mut non_empty = 0;
        for shard in &t.shards {
            if !shard.lock().unwrap().is_empty() {
                non_empty += 1;
            }
        }
        assert!(
            non_empty >= 2,
            "expected keys spread across shards, only {non_empty} non-empty"
        );
    }

    #[test]
    fn concurrent_inserts_stay_consistent() {
        // 4 threads, each insert+touch on a distinct key range,
        // simultaneously. The final `len()` must equal the total number
        // of distinct keys inserted regardless of interleaving.
        //
        // Hold the shared pressure lock + force pressure off: the exact
        // count assertion is invalid if a parallel test flips the global
        // memory-pressure flag true and our brand-new keys get rejected.
        let _g = crate::memory::PRESSURE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::memory::set_pressure_for_test(false);
        use std::sync::Arc;
        use std::thread;
        let t = Arc::new(SessionTable::new(10_000, 3600));
        let mut handles = Vec::new();
        for thread_id in 0u16..4 {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                for i in 0..500u16 {
                    let port = 40_000 + thread_id * 1000 + i;
                    t.insert_or_refresh(addr(port), addr(port));
                    // Re-touch — must NOT bump the count past distinct
                    // key count.
                    t.insert_or_refresh(addr(port), addr(port));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(t.len(), 4 * 500, "len must equal distinct keys inserted");
    }
}
