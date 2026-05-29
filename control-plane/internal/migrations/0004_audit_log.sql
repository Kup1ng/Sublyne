-- 0004_audit_log: admin action audit trail (PRD §4.3 / §4.2).
-- Created in Phase 12.
--
-- One row per admin action: login (success or failure with IP),
-- logout, tunnel create/update/delete/start/stop, WireGuard config
-- create/update/delete, settings change (password, log level),
-- backup download, restore upload. A background pruner deletes rows
-- older than 7 days; the panel's Audit page reads the rest.
--
-- Why a single flat table and not per-action tables? The schema needs
-- to surface a unified time-ordered list in the UI, and the actions
-- share enough columns (ts/actor/ip/target) that splitting just
-- multiplies UNIONs. `details` is a JSON blob for the per-action bits
-- so we don't grow the schema each time a new tracked action lands.
--
-- Secret-handling: PSKs, password hashes, JWT signing key, and WG
-- private keys must NEVER appear in `details`. Helpers in
-- internal/audit/ build the JSON with explicit allow-lists; an
-- accidental %v of a tunnel struct would smuggle a PSK in.

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,                            -- unix seconds
    action  TEXT NOT NULL,                               -- e.g. "login_success", "tunnel_start"
    actor   TEXT NOT NULL,                               -- "admin" (the single admin) or "system"
    ip      TEXT NOT NULL DEFAULT '',                    -- source IP for actions that have one; empty for system
    target  TEXT NOT NULL DEFAULT '',                    -- short human name of the affected object (tunnel name, wg config name, settings key)
    details TEXT NOT NULL DEFAULT '{}'                   -- JSON object with redacted action-specific context
);

-- Reads are time-ordered descending. The (ts DESC) index keeps the
-- 7-day window read scan tight even after many login attempts.
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
