-- 0008_socks5_hardening: per-proxy warm-up threshold for the SOCKS5 pool.
--
-- The predecessor project's TCP keepalive + TCP_USER_TIMEOUT (Phase R9b)
-- caught dead idle connections within seconds but didn't address two
-- separate failure modes the user kept seeing on the live tunnel:
--
--   1. **Partial pool start.** `connect()` happily returned Ok with
--      0/N or N/2 healthy slots, the manager marked the tunnel Running,
--      bytes started flowing, and a sticky-hash to a still-broken slot
--      immediately failed. User-visible: "WG client takes 10 s to
--      connect, then limps."
--
--   2. **Chronic slot churn.** A slot whose underlying Starlink link
--      stayed broken for minutes kept getting picked, marked broken,
--      and re-tried in a tight 500 ms loop. The hot path's
--      linear-probe found nothing useful.
--
-- `min_ready_slots` fixes (1): the dataplane refuses to mark the
-- tunnel up until at least this many slots are healthy. Default 2 lets
-- single-link operators get away with a partial pool while a tight
-- min_ready_slots = parallel_connections / 2 (rounded up) is what we
-- recommend in the panel inline help.
--
-- The remaining hardening (per-slot exponential backoff parking,
-- write timeouts that bound how long a slow slot can stall a sticky
-- session) is constants-baked into `data-plane/src/upload/socks5.rs`
-- and does not need operator-visible knobs.
--
-- ALTER TABLE ... ADD COLUMN keeps existing rows working without a
-- backfill — every existing socks5_proxies row gets the default 2 and
-- can be raised by editing the proxy in the panel.

ALTER TABLE socks5_proxies
    ADD COLUMN min_ready_slots INTEGER NOT NULL DEFAULT 2
    CHECK (min_ready_slots >= 1);
