package auth

import (
	"context"
	"testing"
	"time"
)

// TestAdminStore_GetTolerates_int64PasswordChangedAt is the
// regression test for the bug that broke login on the foreign install
// in Phase 8a. A hand-typed `UPDATE admin SET password_changed_at =
// unixepoch()` left an INTEGER in a column the Go scan expected to be
// TEXT, and every subsequent Get() returned "Scan error ... unsupported
// Scan, storing driver.Value type int64 into type *time.Time" — which
// surfaced to the operator only as a generic 500 "internal error".
//
// AdminStore.Get is now defensive: any timestamp shape SQLite can
// produce parses or is treated as NULL. Login must keep working even
// after the corrupted UPDATE.
func TestAdminStore_GetTolerates_int64PasswordChangedAt(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s.Upsert(context.Background(), "ping", hash); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Simulate the bad UPDATE that broke the foreign install.
	if _, err := db.ExecContext(context.Background(),
		`UPDATE admin SET password_changed_at = unixepoch() WHERE id = 1`); err != nil {
		t.Fatalf("corrupt password_changed_at: %v", err)
	}

	a, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get after int64 corruption: %v", err)
	}
	if a.Username != "ping" {
		t.Errorf("Username = %q, want ping", a.Username)
	}
	if !a.PasswordChangedAt.Valid {
		t.Error("PasswordChangedAt should be valid (parsed from int64)")
	}
	if time.Since(a.PasswordChangedAt.Time) > time.Minute {
		t.Errorf("parsed timestamp drift too large: %v", a.PasswordChangedAt.Time)
	}
	if err := VerifyPassword(a.PasswordHash, "hunter2"); err != nil {
		t.Errorf("login still fails after Get: %v", err)
	}
}

// TestAdminStore_UpsertResetsPasswordChangedAt confirms the recovery
// path: a subsequent Upsert (e.g. via `sublyne --reset-admin`) MUST
// NULL out any prior password_changed_at value. Otherwise the bad
// int64 would survive the reset and Get would still tolerate-fall-
// through to Valid=false; better to be deterministic.
func TestAdminStore_UpsertResetsPasswordChangedAt(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	h1, _ := HashPassword("first")
	if err := s.Upsert(context.Background(), "ping", h1); err != nil {
		t.Fatal(err)
	}
	// Corrupt the column with an int64 (the exact failure shape).
	if _, err := db.ExecContext(context.Background(),
		`UPDATE admin SET password_changed_at = unixepoch() WHERE id = 1`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	// Now re-upsert (the --reset-admin path).
	h2, _ := HashPassword("second")
	if err := s.Upsert(context.Background(), "ping", h2); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	a, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get after re-upsert: %v", err)
	}
	if a.PasswordChangedAt.Valid {
		t.Errorf("PasswordChangedAt should be NULL after Upsert, got %v",
			a.PasswordChangedAt.Time)
	}
}

// TestTolerantTime_AllShapes locks in the formats we accept so future
// changes don't accidentally drop one.
func TestTolerantTime_AllShapes(t *testing.T) {
	cases := []struct {
		name string
		src  any
		want bool // Valid=true expected?
	}{
		{"nil", nil, false},
		{"empty string", "", false},
		{"int64-seconds", int64(1717000000), true},
		{"sqlite-text", "2024-05-29 12:00:00", true},
		{"rfc3339", "2024-05-29T12:00:00Z", true},
		{"rfc3339-nano", "2024-05-29T12:00:00.123456789Z", true},
		{"rfc3339-tz-offset", "2024-05-29T12:00:00-07:00", true},
		{"date-only", "2024-05-29", true},
		{"numeric-string", "1717000000", true},
		{"time-zero", time.Time{}, false},
		{"time-now", time.Now(), true},
		{"garbage", "this is not a time", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tt tolerantTime
			if err := tt.Scan(c.src); err != nil {
				t.Fatalf("Scan(%v): %v", c.src, err)
			}
			if tt.Valid != c.want {
				t.Errorf("Scan(%v): Valid=%v, want %v (parsed=%v)",
					c.src, tt.Valid, c.want, tt.Time)
			}
		})
	}
}
