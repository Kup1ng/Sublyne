package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return db
}

func TestRecorder_RecordAndList(t *testing.T) {
	db := newTestDB(t)
	r := NewRecorder(db)
	ctx := context.Background()

	r.Record(ctx, ActionLoginSuccess, ActorAdmin, "1.2.3.4", "admin", map[string]any{"username": "admin"})
	r.Record(ctx, ActionTunnelStart, ActorAdmin, "1.2.3.4", "tunnel-A", map[string]any{"tunnel_id": int64(7)})
	r.Record(ctx, ActionLogout, ActorAdmin, "1.2.3.4", "admin", nil)

	entries, err := r.List(ctx, time.Time{}, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Newest first ordering — logout was the most recent insert.
	if entries[0].Action != ActionLogout {
		t.Errorf("expected newest=logout, got %q", entries[0].Action)
	}
	if entries[0].Details != "{}" {
		t.Errorf("expected nil details to serialise as {}, got %q", entries[0].Details)
	}
	if entries[1].Action != ActionTunnelStart {
		t.Errorf("expected second entry tunnel_start, got %q", entries[1].Action)
	}
	if entries[1].Target != "tunnel-A" {
		t.Errorf("expected target tunnel-A, got %q", entries[1].Target)
	}
}

func TestRecorder_ListSinceFiltersOlderRows(t *testing.T) {
	db := newTestDB(t)
	old := time.Now().Add(-2 * time.Hour)
	now := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&old)
	r := NewRecorder(db, WithClock(func() time.Time { return *clock.Load() }))
	ctx := context.Background()

	r.Record(ctx, ActionLoginSuccess, ActorAdmin, "1.1.1.1", "", nil)
	clock.Store(&now)
	r.Record(ctx, ActionTunnelStart, ActorAdmin, "1.1.1.1", "tunnel-B", nil)

	cutoff := time.Now().Add(-time.Hour)
	entries, err := r.List(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry past cutoff, got %d", len(entries))
	}
	if entries[0].Action != ActionTunnelStart {
		t.Errorf("expected tunnel_start, got %q", entries[0].Action)
	}
}

func TestRecorder_PruneDropsOldRows(t *testing.T) {
	db := newTestDB(t)
	old := time.Now().Add(-30 * 24 * time.Hour)
	now := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&old)
	r := NewRecorder(db, WithClock(func() time.Time { return *clock.Load() }), WithRetention(7*24*time.Hour))
	ctx := context.Background()

	r.Record(ctx, ActionLoginSuccess, ActorAdmin, "1.1.1.1", "", nil)
	clock.Store(&now)
	r.Record(ctx, ActionTunnelStart, ActorAdmin, "1.1.1.1", "tunnel-C", nil)

	n, err := r.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("expected to prune 1 row, got %d", n)
	}
	entries, err := r.List(ctx, time.Time{}, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != ActionTunnelStart {
		t.Errorf("unexpected entries after prune: %+v", entries)
	}
}

func TestRecorder_NilNoOps(t *testing.T) {
	var r *Recorder
	r.Record(context.Background(), ActionLoginSuccess, ActorAdmin, "", "", nil)
	if _, err := r.List(context.Background(), time.Time{}, 0); err == nil {
		t.Error("expected error from nil receiver List")
	}
	if _, err := r.Prune(context.Background()); err == nil {
		t.Error("expected error from nil receiver Prune")
	}
	r.Close()
}
