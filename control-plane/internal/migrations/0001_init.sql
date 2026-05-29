-- 0001_init: bootstrap schema for admin, settings, and brute-force lockout.
-- Created in Phase 2.
--
-- The four tables here are the minimum the control plane needs to boot
-- and pass its acceptance test. Later phases add `tunnels`,
-- `wireguard_configs`, `audit_log`, and `metrics_*` tables in their own
-- migration files.

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Single admin user. There is only ever one row in this table — the
-- CHECK constraint enforces that. Phase 3 will populate it the first
-- time the service starts after setup.sh runs.
CREATE TABLE IF NOT EXISTS admin (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    username            TEXT NOT NULL,
    password_hash       TEXT NOT NULL,                      -- Argon2id encoded form
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    password_changed_at TIMESTAMP
);

-- Settings is a key/value store for values that don't earn their own
-- table: panel_port (override), web_path (override), log_level
-- (runtime tweak), role (echoed from config), and the JWT signing key
-- generated at first start.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Brute-force lockout state. Each row is a single login attempt.
-- Phase 3's rate limiter queries by (ip, ts) to count recent attempts;
-- a background pruner drops rows older than a day.
CREATE TABLE IF NOT EXISTS login_attempts (
    ip      TEXT NOT NULL,
    ts      INTEGER NOT NULL,                                -- unix seconds
    success INTEGER NOT NULL CHECK (success IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts
    ON login_attempts(ip, ts);
