// Package db opens the control plane's SQLite database with the
// pragmas required for our workload.
//
// We use the pure-Go driver modernc.org/sqlite (no cgo) so the
// release binary stays statically linkable on musl. The pragmas
// (WAL journaling, foreign-key enforcement, 5 s busy timeout,
// NORMAL synchronous) are passed via the DSN so they apply to
// every connection acquired from the pool — see the db-migrations
// skill for the rationale.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open opens (creating if missing) the SQLite database at path.
// The returned *sql.DB has the standard pragmas applied via the
// DSN and is pinged to verify it works. The file is chmod'd to
// 0600 so only the owning user can read it.
//
// The caller owns the returned handle and must Close() it.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + path + "?" + q.Encode()

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite %q: %w", path, err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("chmod %q: %w", path, err)
	}

	return sqlDB, nil
}
