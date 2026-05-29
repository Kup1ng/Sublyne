-- 0002_tunnels: union table for client- and remote-side tunnels.
-- Created in Phase 6.
--
-- PRD §3.1 lists 17 client-side fields; PRD §3.2 lists 12 remote-side
-- fields. Five fields are shared (psk, mtu, max_connections,
-- idle_timeout, plus the three download-spoof descriptors). The rest
-- belong to exactly one role. We model the union in a single table:
--
--   * shared columns are NOT NULL with sensible defaults from the PRD
--   * role-specific columns are nullable; role-aware validation in the
--     tunnels package (validation.go) enforces "required when role X"
--   * the role column is constrained to the same two values the rest
--     of the codebase already uses ("client" / "remote") so a backup
--     restored on a mismatched server can be detected before any
--     tunnel start is attempted
--
-- Phase 6 only persists and validates tunnels; no data-plane bring-up
-- happens here. The `enabled` flag is flipped via /api/tunnels/:id/start
-- and /stop and is the source of truth for the dashboard's status
-- badge until Phase 10 wires real health probes.
--
-- The `wireguard_config` column is here only to round-trip pasted text
-- for Phase 6's create/edit forms. Phase 7 replaces it with a foreign
-- key to a new `wireguard_configs` table; that migration will keep the
-- column nullable so existing rows don't break.

CREATE TABLE IF NOT EXISTS tunnels (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    name                       TEXT    NOT NULL UNIQUE,
    role                       TEXT    NOT NULL CHECK (role IN ('client', 'remote')),
    enabled                    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),

    -- Shared between roles. PSK is the HMAC key for the download path
    -- and must match the paired tunnel on the other server exactly.
    psk                        TEXT    NOT NULL,
    download_spoof_source_ip   TEXT    NOT NULL,
    download_spoof_source_port INTEGER NOT NULL
                                CHECK (download_spoof_source_port BETWEEN 1 AND 65535),
    download_transport         TEXT    NOT NULL
                                CHECK (download_transport IN ('udp', 'tcp_syn', 'icmp', 'icmpv6')),
    mtu                        INTEGER NOT NULL DEFAULT 1400
                                CHECK (mtu BETWEEN 576 AND 9000),
    max_connections            INTEGER NOT NULL DEFAULT 50000
                                CHECK (max_connections > 0),
    idle_timeout               INTEGER NOT NULL DEFAULT 300
                                CHECK (idle_timeout > 0),

    -- Client-only fields. NULL when role='remote'. The where-end-users-
    -- connect address, the local port that receives spoofed download
    -- packets, the upstream upload target on the Remote, and the pasted
    -- WireGuard config text (Phase 7 will move this to its own table).
    local_listen_addr          TEXT,
    download_receive_port      INTEGER
                                CHECK (download_receive_port IS NULL
                                       OR download_receive_port BETWEEN 1 AND 65535),
    upload_target_addr         TEXT,
    wireguard_config           TEXT,
    ping_smoothing_enabled     INTEGER NOT NULL DEFAULT 0
                                CHECK (ping_smoothing_enabled IN (0, 1)),
    ping_smoothing_target_ms   INTEGER NOT NULL DEFAULT 60
                                CHECK (ping_smoothing_target_ms >= 0),
    pacing_enabled             INTEGER NOT NULL DEFAULT 0
                                CHECK (pacing_enabled IN (0, 1)),
    pacing_target_ms           INTEGER NOT NULL DEFAULT 100
                                CHECK (pacing_target_ms >= 0),

    -- Remote-only fields. NULL when role='client'. The incoming-upload
    -- listener, the upstream forward target (e.g. a 3x-ui server), the
    -- port the Remote sends spoofed packets to, and the Client's public
    -- IP that those packets are destined for.
    upload_listen_addr         TEXT,
    forward_target             TEXT,
    download_send_port         INTEGER
                                CHECK (download_send_port IS NULL
                                       OR download_send_port BETWEEN 1 AND 65535),
    client_real_ip             TEXT,

    created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sparse indexes keep the list-by-role and start-on-boot scans cheap
-- even when one role dominates the table.
CREATE INDEX IF NOT EXISTS idx_tunnels_role    ON tunnels(role);
CREATE INDEX IF NOT EXISTS idx_tunnels_enabled ON tunnels(enabled);
