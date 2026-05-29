package auth

import (
	"context"
	"database/sql"
	"net/url"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
)

// newTestDB returns an in-memory SQLite database with the production
// migrations applied. The DB is closed via t.Cleanup.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// modernc.org/sqlite uses "file::memory:?cache=shared" with a
	// per-test name to avoid pool-level sharing between tests.
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "journal_mode(MEMORY)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared&" + q.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Pin the pool to a single conn so the in-memory DB survives.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db
}
