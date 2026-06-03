-- 0012_forward_protocol: per-tunnel TCP-forwarding engine (v4.0.0).
--
-- Until v4 every tunnel forwarded UDP only: a datagram in at the listen
-- address was relayed as a UDP datagram out. That forced operators to
-- hand end-users WireGuard / Hysteria (UDP) configs. v4 adds a
-- per-tunnel `forward_protocol`:
--
--   'udp'  — historical behaviour, unchanged. Every existing row is
--            migrated to this value, so the upgrade is a no-op for any
--            tunnel already in the table.
--   'tcp'  — the tunnel terminates the user's TCP connection and carries
--            it reliably over the best-effort spoof/upload channel using
--            a reliability engine (KCP or QUIC), then re-originates TCP
--            to forward_target on the Remote. Lets operators distribute
--            VLESS-TCP / VLESS-WS configs.
--
-- `tcp_reliability_engine` selects KCP (default) or QUIC when
-- forward_protocol='tcp'; it is ignored for 'udp' tunnels but always
-- carries a valid value so the CHECK constraint holds.
--
-- `forward_engine_preset` is one of three tuning profiles per engine
-- (interactive / balanced / lossy). `forward_engine_tuning` is an
-- optional JSON blob of per-field Advanced overrides ('' = pure preset).
-- The concrete numbers live in Go (tunnels/forward.go) and are mirrored
-- in the panel; this row stores only the operator's choices.
--
-- These four columns are SHARED by both roles: the Client and the Remote
-- must agree on protocol + engine + tuning (no inter-server control
-- plane, PRD §2.3 — the operator copies the choice to both boxes).
--
-- Wire compatibility: the seal/spoof envelope is unchanged, so a 'udp'
-- tunnel on v4 stays interoperable with a v3.x peer. Only a 'tcp' tunnel
-- requires BOTH ends on v4.0.0+. A downgraded v3 binary never SELECTs
-- these columns (the repo lists columns explicitly), so the migration is
-- additive and safe to leave in place across a rollback.

ALTER TABLE tunnels ADD COLUMN forward_protocol TEXT NOT NULL DEFAULT 'udp'
    CHECK (forward_protocol IN ('udp', 'tcp'));

ALTER TABLE tunnels ADD COLUMN tcp_reliability_engine TEXT NOT NULL DEFAULT 'kcp'
    CHECK (tcp_reliability_engine IN ('kcp', 'quic'));

ALTER TABLE tunnels ADD COLUMN forward_engine_preset TEXT NOT NULL DEFAULT 'balanced'
    CHECK (forward_engine_preset IN ('interactive', 'balanced', 'lossy'));

ALTER TABLE tunnels ADD COLUMN forward_engine_tuning TEXT NOT NULL DEFAULT '';
