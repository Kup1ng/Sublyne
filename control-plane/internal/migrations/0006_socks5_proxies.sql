-- 0006_socks5_proxies: storage for SOCKS5 upload proxies + per-tunnel
-- upload-mode selector.
-- Created in Phase R8.
--
-- Round 2 introduces a second upload path alongside WireGuard. A
-- single SOCKS5 proxy fronting multiple Starlink uplinks is the
-- user's real-world setup: each new TCP connection to the proxy lands
-- on a random Starlink link, so opening N parallel connections uses
-- N links concurrently. Phase R9 will build the dataplane SOCKS5
-- client that opens those N parallel connections; this migration is
-- the storage half (R8 — schema + REST + panel + tunnel-form picker).
--
-- Shape mirrors wireguard_configs (0003) so the operator's mental
-- model transfers cleanly: same name UNIQUE constraint, same
-- created_at / updated_at columns, same Delete-refused-while-
-- referenced pattern in the repo. A tunnel may pick exactly one
-- upload path — either a WireGuard config (`upload_mode='wireguard'`)
-- or a SOCKS5 proxy (`upload_mode='socks5'`); the validator in
-- control-plane/internal/tunnels/validation.go rejects rows that set
-- both or neither for client tunnels.
--
-- Secrets: `password` is held at rest and the API redacts it as `***`
-- on every list / get response. Only an explicit `?reveal=1` GET
-- returns the bytes, mirroring how wireguard_configs.raw_text and
-- tunnels.psk are handled (CLAUDE.md §5).
--
-- `parallel_connections` (default 4) is the knob R9's dataplane reads
-- to size the per-tunnel connection pool. Storing it on the proxy row
-- (not the tunnel row) lets one proxy serve many tunnels with a
-- consistent fan-out, and lets the operator tune the fan-out without
-- editing every tunnel that uses the proxy. Validation caps it at 64
-- so a stray typo can't accidentally fork-bomb the TCP socket pool.
--
-- Existing tunnels survive untouched. `upload_mode` defaults to
-- `'wireguard'` so every pre-R8 row keeps its existing upload path
-- with no operator action; `socks5_proxy_id` stays NULL until the
-- operator explicitly switches a tunnel over.
--
-- Like 0003_wg_configs.sql, we deliberately do NOT add a
-- `REFERENCES socks5_proxies(id)` constraint to the new tunnels
-- column. SQLite's ALTER TABLE ADD COLUMN can in principle accept a
-- FK clause, but the constraint is unenforced for pre-existing rows
-- and the repo layer already enforces "delete refused while
-- referenced" the same way wg/repo.go does. Keeping the column a
-- plain INTEGER keeps the migration portable across the SQLite
-- versions our musl static build pins and the modernc.org/sqlite
-- pure-Go driver tests run against.

CREATE TABLE IF NOT EXISTS socks5_proxies (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT    NOT NULL UNIQUE,
    host                 TEXT    NOT NULL,            -- IPv4 / IPv6 / hostname; resolved at start
    port                 INTEGER NOT NULL
                            CHECK (port BETWEEN 1 AND 65535),

    -- SOCKS5 username/password auth. Both NULL = no-auth proxy. The
    -- panel and repo treat (NULL, NULL) and ('','') equivalently for
    -- "no auth"; validation rejects "username without password" or
    -- vice versa so a half-configured row can't reach the dataplane.
    username             TEXT,
    password             TEXT,

    -- R9 reads this to size the per-tunnel connection pool. Capped at
    -- 64 in code (validation.go) to keep "Parallel connections = 1000"
    -- typos from spawning a thousand TCP connections per tunnel.
    parallel_connections INTEGER NOT NULL DEFAULT 4
                            CHECK (parallel_connections BETWEEN 1 AND 64),

    notes                TEXT,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Lookup by name covers both the panel's list page (ORDER BY id keeps
-- creation order; name index is cheap to maintain) and the tunnel-form
-- picker that resolves the operator's chosen proxy name → id on save.
CREATE INDEX IF NOT EXISTS socks5_proxies_name ON socks5_proxies(name);

-- Per-tunnel upload mode. Default 'wireguard' keeps every existing
-- tunnel on its existing upload path; the CHECK matches the closed
-- set the validator and dataplane both know about.
ALTER TABLE tunnels ADD COLUMN upload_mode TEXT NOT NULL DEFAULT 'wireguard'
    CHECK (upload_mode IN ('wireguard', 'socks5'));

-- FK-by-convention into socks5_proxies. NULL when upload_mode is
-- 'wireguard' (the wg_config_id column carries the link instead);
-- required when upload_mode is 'socks5'. See note in the file header
-- for why this is a plain INTEGER rather than a REFERENCES column.
ALTER TABLE tunnels ADD COLUMN socks5_proxy_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_tunnels_socks5_proxy_id ON tunnels(socks5_proxy_id);
