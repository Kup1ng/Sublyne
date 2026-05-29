---
name: db-migrations
description: SQLite schema versioning for the control plane — how migrations are stored, embedded into the Go binary, applied on service start, and how to add a new migration safely.
when_to_use: Phase 2 creates the migration framework and `0001_init.sql`. Any later phase that adds or changes tables (auth, tunnels, WG configs, audit, etc.) must add a new migration file. Read this before touching any `.sql` file under `control-plane/internal/migrations/`.
---

## Where migrations live

```
control-plane/internal/migrations/
├── migrations.go          # //go:embed + applier
├── 0001_init.sql
├── 0002_tunnels.sql       # added in Phase 6
├── 0003_wg_configs.sql    # added in Phase 7
├── 0004_audit_log.sql     # added in Phase 12
└── … (each phase that needs a schema change)
```

All `*.sql` files are embedded into the Go binary via `//go:embed`.
At runtime, the applier reads them out of the embedded FS, in numeric
order, and applies any whose version is greater than the row in
`schema_version`.

## File naming

- `NNNN_description.sql` — `NNNN` is a zero-padded 4-digit integer.
- The integer must be **strictly monotonically increasing**. Don't
  re-use a number. Don't squeeze a new migration between two existing
  ones — append.
- The description after the underscore is `snake_case`, max ~40 chars,
  human-readable.
- One concern per file. If a feature needs two tables, that's one
  migration file with both `CREATE TABLE` statements — they go in
  together transactionally.

## File content rules

- **One transaction per file.** The applier wraps every file in
  `BEGIN; … COMMIT;` automatically — don't add explicit
  `BEGIN/COMMIT` inside.
- **Idempotent where possible.** Use `CREATE TABLE IF NOT EXISTS`,
  `CREATE INDEX IF NOT EXISTS`. This lets reruns of a partial apply
  not blow up. (The transaction wrapping makes this less critical,
  but it's still good practice.)
- **No `DROP COLUMN`.** SQLite supported it from 3.35 onward, but
  the migration must still work on hosts with older `libsqlite3` if
  we ever statically link a particular version. Use the copy-rename
  pattern instead (see "SQLite gotchas" below).
- **No data migrations in the same file as schema migrations** for
  anything non-trivial. If you need to backfill a column with computed
  values, put the schema change in one file (`0010_add_foo.sql`) and
  the backfill in the next (`0011_backfill_foo.sql`). Keeps each
  transaction small and reversible-by-rerun-from-scratch.
- **No `IF` statements** — SQLite's SQL dialect doesn't support
  procedural blocks. If you need conditional logic, do it in Go
  around the migration apply, not inside the SQL.
- **Comment liberally.** SQL files are read by future Claude chats
  with no prior context. Explain *why* a non-obvious column or index
  exists.

## Example: `0001_init.sql`

```sql
-- 0001_init: bootstrap schema for admin, settings, and audit log.
-- Created in Phase 2.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Single admin user. There is only ever one row in this table.
CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,           -- Argon2id encoded form
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    password_changed_at TIMESTAMP
);

-- Settings is a key/value store for things that don't deserve their own
-- table: panel_port, web_path, log_level, role, jwt_signing_key.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Brute-force lockout state. Pruned periodically.
CREATE TABLE IF NOT EXISTS login_attempts (
    ip TEXT NOT NULL,
    ts INTEGER NOT NULL,                   -- unix seconds
    success INTEGER NOT NULL CHECK (success IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts
    ON login_attempts(ip, ts);
```

## Applier (`migrations.go`)

```go
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// Apply applies any not-yet-applied migrations in numeric order.
// Must be called once at service start, after DB open, before any
// other query.
func Apply(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	current, err := currentVersion(ctx, db)
	if err != nil {
		return err
	}

	ms, err := load()
	if err != nil {
		return err
	}

	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := applyOne(ctx, db, m); err != nil {
			return fmt.Errorf("apply %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func currentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v)
	if err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

func load() ([]migration, error) {
	entries, err := migrationFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// e.Name() like "0001_init.sql"
		parts := strings.SplitN(strings.TrimSuffix(e.Name(), ".sql"), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed migration filename: %s", e.Name())
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("bad version in %s: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: parts[1], sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

func applyOne(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_version (version) VALUES (?)`, m.version); err != nil {
		return err
	}
	return tx.Commit()
}
```

## Connection pragmas

When opening the DB in `control-plane/internal/db/db.go`, set these
pragmas once before applying migrations:

```go
db, err := sql.Open("sqlite", "/var/lib/sublyne/sublyne.db?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on&_synchronous=normal")
```

- `_journal_mode=WAL` — concurrent readers + one writer; far better
  for a server workload than the default rollback journal.
- `_synchronous=normal` — durable enough for our use case (small,
  bounded writes), faster than `full`.
- `_foreign_keys=on` — SQLite's default is **off**. Always turn it on.
- `_busy_timeout=5000` — 5 s before SQLITE_BUSY error.

Driver: `modernc.org/sqlite` (pure-Go, no cgo). Avoid `mattn/go-sqlite3`
(cgo, complicates the cross-musl build).

## SQLite gotchas

### Renaming or dropping a column

SQLite supported `DROP COLUMN` only from 3.35. Don't assume the build
environment has it. The portable pattern:

```sql
-- Old: tunnels.deprecated_field exists.
-- New: tunnels.deprecated_field gone.

CREATE TABLE tunnels_new (...all columns except the dropped one...);
INSERT INTO tunnels_new SELECT col1, col2, ... FROM tunnels;
DROP TABLE tunnels;
ALTER TABLE tunnels_new RENAME TO tunnels;
-- Re-create any indexes that were on tunnels.
CREATE INDEX IF NOT EXISTS idx_tunnels_role ON tunnels(role);
```

This whole sequence in one migration file = one transaction = safe.

### `ALTER TABLE … ADD COLUMN`

Works, with these constraints:
- No `NOT NULL` without a default (SQLite has to fill existing rows).
- No `PRIMARY KEY` or `UNIQUE` (use a separate `CREATE UNIQUE INDEX`).
- The column is added at the end.

```sql
ALTER TABLE tunnels ADD COLUMN mtu INTEGER NOT NULL DEFAULT 1400;
```

### Foreign keys

`PRAGMA foreign_keys=ON` must be set per-connection (it doesn't
persist). Our pool option above takes care of it for every connection.

### Datetime storage

Store as ISO-8601 strings (`TIMESTAMP DEFAULT CURRENT_TIMESTAMP`) or
unix seconds (`INTEGER`). Pick one *per column purpose*: timestamps
read by humans (audit log, `created_at`) → ISO strings; high-frequency
or comparison-heavy fields (login_attempts.ts, metric samples) → unix
seconds. Never store as binary `BLOB`; SQLite type affinity tooling
won't help.

## Adding a new migration — the safe procedure

1. **Look at the highest existing `NNNN`.** Use `NNNN + 1` for the new file.
2. **Name it descriptively.** `0007_add_wg_handshake_columns.sql`.
3. **Write the SQL.** Use `IF NOT EXISTS` guards. Add comments.
4. **If you're modifying an existing table**, use `ALTER TABLE … ADD COLUMN`
   when possible; use the copy-rename pattern only when dropping/renaming.
5. **Test locally.** Delete `/var/lib/sublyne/sublyne.db` (or the dev
   DB), start the service, watch the log for "applied migration N". Then
   query the schema with `sqlite3 sublyne.db .schema` and verify.
6. **Test the upgrade path.** Take a real DB at the previous migration
   level (e.g., a backup taken before your branch), apply your migration
   on top, verify no data loss and that all rows look sane.
7. **Commit the .sql file along with the Go code that uses the new
   columns.** Never merge a migration without the code that depends on
   it (or the next merge will hit a half-migrated state).
8. **Never edit a merged migration file.** Even a typo fix requires a
   new migration file (or, if it's safe, leave the typo and document it
   — backing out a merged migration is destructive).

## Rolling back

There's intentionally no `down.sql` mechanism. SQLite doesn't have
mature DDL transactions across multiple files, and the simpler model
("forward-only migrations; roll back by restoring a backup") matches
the user's mental model and our backup feature.

When something goes wrong:
- If the migration fails mid-apply, the transaction wrapping rolls it
  back automatically. Service refuses to start; user fixes the SQL.
- If the migration succeeded but the resulting state is wrong, write
  a *next* migration that corrects the situation.
- Catastrophic case: restore from a backup taken before the failed
  upgrade.

## Backup / restore interaction

When the user uses Settings → Backup, we stream `sublyne.db` as-is.
When they Restore, we:
1. Read three preserved values out of the *running* DB:
   `admin.username`, `admin.password_hash`, `settings(panel_port)`,
   `settings(web_path)`.
2. Replace the DB file on disk with the uploaded one.
3. Open the new DB, apply migrations (in case the backup was taken
   from an older version of the project — forward migrations only).
4. Overwrite the four preserved values with the values from step 1.

The four-value preservation is the **only** thing that survives a
restore. Everything else (tunnels, WG configs, audit log, login
attempts, settings other than panel_port/web_path) comes from the
uploaded backup. See `PROJECT_REQUIREMENTS.md` §4.4.
