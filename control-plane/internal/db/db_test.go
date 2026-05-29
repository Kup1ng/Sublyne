package db

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpen_CreatesFileAndAppliesPragmas(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	conn, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var fk int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}

	var journal string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journal != "wal" {
		t.Errorf("journal_mode = %q, want wal", journal)
	}

	var busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busy != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busy)
	}

	var sync int
	if err := conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil {
		t.Fatalf("query synchronous: %v", err)
	}
	// SQLite reports synchronous as integer: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA.
	if sync != 1 {
		t.Errorf("synchronous = %d, want 1 (NORMAL)", sync)
	}
}

func TestOpen_ChmodsFileTo0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes not meaningful on Windows")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	conn, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("db file mode = %#o, want 0600", mode)
	}
}
