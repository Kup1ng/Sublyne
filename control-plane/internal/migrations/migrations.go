// Package migrations applies the embedded SQL migration files to the
// control-plane database at service start.
//
// All *.sql files in this directory are bundled into the binary via
// the embed package (see the //go:embed directive below). Each file
// is named NNNN_description.sql with a strictly increasing 4-digit
// version. Apply executes the files in version order inside
// individual transactions, recording each in the schema_version
// table. See .claude/skills/db-migrations/SKILL.md for the full
// conventions (file naming, idempotency rules, rollback strategy,
// SQLite gotchas).
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
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

// Apply runs every embedded migration whose version is greater than
// the highest version already recorded in schema_version. It is safe
// to call repeatedly: previously applied migrations are skipped.
//
// Each migration is wrapped in its own transaction. If one fails,
// the transaction is rolled back and Apply returns the error; the
// service should refuse to start with a partially migrated DB.
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
		slog.Info("applied migration", "version", m.version, "name", m.name)
	}
	return nil
}

func currentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read current schema version: %w", err)
	}
	return int(v.Int64), nil
}

func load() ([]migration, error) {
	entries, err := migrationFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migration FS: %w", err)
	}
	var ms []migration
	seen := make(map[int]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(strings.TrimSuffix(e.Name(), ".sql"), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed migration filename %q (want NNNN_description.sql)", e.Name())
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("bad version in %q: %w", e.Name(), err)
		}
		if dup, ok := seen[v]; ok {
			return nil, fmt.Errorf("duplicate migration version %d: %q and %q", v, dup, e.Name())
		}
		seen[v] = e.Name()
		body, err := migrationFS.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", e.Name(), err)
		}
		ms = append(ms, migration{version: v, name: parts[1], sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

func applyOne(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("exec migration body: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_version (version) VALUES (?)`, m.version); err != nil {
		return fmt.Errorf("record schema_version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
