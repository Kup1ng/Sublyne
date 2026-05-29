-- 0003_wg_configs: per-tunnel WireGuard configuration storage.
-- Created in Phase 7.
--
-- Operators paste a standard wg-quick-style config into the panel and
-- give it a name. The pasted text is held verbatim in raw_text because
-- bringing up the interface uses the original PrivateKey/PresharedKey
-- bytes; the parsed summary columns exist so the list view doesn't
-- have to re-parse on every render and so we can show the operator
-- "yes, the seller actually pointed at 198.51.100.20:81" without
-- revealing the secret bytes.
--
-- raw_text is treated as a secret (see CLAUDE.md §5). The API never
-- emits it unless the caller asks with ?reveal=1. Log lines never
-- contain it.
--
-- Multiple tunnels may reference the same row; Phase 7's interface
-- manager reference-counts the kernel device. Phase 10 hot-reload will
-- treat any change to raw_text as a full tear-down + bring-up because
-- the WG identity (PrivateKey) is part of the device, not a knob we
-- can replace in place.

CREATE TABLE IF NOT EXISTS wireguard_configs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL UNIQUE,
    raw_text            TEXT    NOT NULL,

    -- Parsed summary, populated by the Go-side parser before insert.
    -- Storing the parsed shape lets the list view render without
    -- re-parsing and lets the API surface "yes the config is sane"
    -- without leaking raw_text.
    interface_address   TEXT    NOT NULL,   -- comma-joined CIDRs from [Interface] Address
    endpoint            TEXT    NOT NULL,   -- "host:port" of the first peer's Endpoint
    public_key_self     TEXT    NOT NULL,   -- base64 pubkey derived from [Interface] PrivateKey
    mtu                 INTEGER,            -- NULL if the config did not specify MTU=
    listen_port         INTEGER,            -- NULL if the config did not specify ListenPort=
    peer_count          INTEGER NOT NULL DEFAULT 1 CHECK (peer_count > 0),

    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Each Client-role tunnel may reference one WG config. SQLite's
-- ALTER TABLE ADD COLUMN cannot create a FK constraint after the fact,
-- so the column is added as a plain INTEGER and the API/repo layer
-- enforces referential integrity on its own (Phase 7's wg.Repo refuses
-- to delete a row that any tunnel still points at). Existing rows
-- pre-Phase-7 stay NULL by default; the column is purely additive.
ALTER TABLE tunnels ADD COLUMN wg_config_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_tunnels_wg_config_id ON tunnels(wg_config_id);
