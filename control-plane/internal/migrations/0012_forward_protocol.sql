-- 0012_forward_protocol.sql
-- v4.0.0 per-tunnel TCP forwarding (via a KCP reliability layer) plus a
-- per-tunnel keep-alive.
--
-- forward_protocol selects what the tunnel carries at the application
-- layer:
--   'udp' (the DEFAULT, and the value backfilled onto every existing
--          row) is the historical behaviour — opaque UDP datagrams pass
--          through byte-for-byte. Existing tunnels are untouched.
--   'tcp' accepts user TCP connections on the Client, frames them into
--          KCP segments carried over the same upload + sealed-download
--          pipeline, and re-originates TCP to forward_target on the
--          Remote. It is orthogonal to download_transport / upload_mode:
--          any of the 6 matrix rows can forward udp or tcp.
--
-- keep_alive (off by default) keeps one artificial internal session warm
-- at all times so the dataplane stays primed and the panel keeps showing
-- the tunnel running even with zero real users. keep_alive_interval_sec
-- is how often the heartbeat fires (must be < idle_timeout).
--
-- forward_engine_preset / forward_engine_tuning configure the KCP engine
-- for tcp tunnels: a named baseline ('balanced' = the production-proven
-- defaults) plus an optional JSON object of per-knob overrides
-- ('' = use the preset verbatim). Both are ignored for udp tunnels.
--
-- No column is dropped or rewritten, so this migration is fully backward
-- compatible: existing single-port udp tunnels keep working with zero
-- operator action.

ALTER TABLE tunnels ADD COLUMN forward_protocol TEXT NOT NULL DEFAULT 'udp'
    CHECK (forward_protocol IN ('udp', 'tcp'));
ALTER TABLE tunnels ADD COLUMN keep_alive INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tunnels ADD COLUMN keep_alive_interval_sec INTEGER NOT NULL DEFAULT 20;
ALTER TABLE tunnels ADD COLUMN forward_engine_preset TEXT NOT NULL DEFAULT 'balanced'
    CHECK (forward_engine_preset IN ('balanced', 'interactive', 'lossy'));
ALTER TABLE tunnels ADD COLUMN forward_engine_tuning TEXT NOT NULL DEFAULT '';
