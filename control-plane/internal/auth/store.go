package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Admin represents the single admin row (PRD §4.1: there is exactly
// one admin user per server, enforced at the schema level by the
// CHECK(id = 1) constraint on the admin table).
type Admin struct {
	ID                int64
	Username          string
	PasswordHash      string
	CreatedAt         time.Time
	PasswordChangedAt sql.NullTime
}

// AdminStore is the DB-backed source of truth for the admin row.
type AdminStore struct {
	db *sql.DB
}

// NewAdminStore wraps a *sql.DB. The DB must have migration 0001
// applied so the admin table exists.
func NewAdminStore(db *sql.DB) *AdminStore {
	return &AdminStore{db: db}
}

// ErrAdminNotFound is returned by Get when the admin row has not been
// created yet (i.e. bootstrap-admin.toml has not been consumed). The
// auth handlers turn this into a 503 instead of a 401 — failing
// closed and visible — because hitting login before bootstrap is
// always an operational problem, not user error.
var ErrAdminNotFound = errors.New("auth: admin row not present (bootstrap not yet consumed)")

// Get fetches the (only) admin row. Returns ErrAdminNotFound when
// the table is empty.
//
// The TIMESTAMP columns (`created_at`, `password_changed_at`) are
// scanned through `tolerantTime` so any operator who hand-patched
// the row — for example, with `unixepoch()` instead of
// `CURRENT_TIMESTAMP` — can still log in. SQLite's dynamic typing
// means the column can legitimately hold either a TEXT timestamp or
// an integer Unix-seconds value, and the default Go scanner only
// accepts TEXT. Without this tolerance, a single bad UPDATE on the
// DB silently breaks login forever — which is exactly the failure
// that motivated this commit.
func (s *AdminStore) Get(ctx context.Context) (Admin, error) {
	var a Admin
	var createdAt, passwordChangedAt tolerantTime
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at, password_changed_at
		 FROM admin WHERE id = 1`)
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &createdAt, &passwordChangedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Admin{}, ErrAdminNotFound
		}
		return Admin{}, fmt.Errorf("auth: read admin: %w", err)
	}
	if createdAt.Valid {
		a.CreatedAt = createdAt.Time
	}
	a.PasswordChangedAt = sql.NullTime{Time: passwordChangedAt.Time, Valid: passwordChangedAt.Valid}
	return a, nil
}

// tolerantTime is a sql.Scanner that accepts anything SQLite's
// dynamic typing can legitimately produce for a TIMESTAMP column:
// NULL, RFC3339 / RFC3339Nano, the sqlite default TEXT format
// (`2006-01-02 15:04:05[.fffffffff][±hh:mm]`), or an INTEGER (Unix
// seconds — what `unixepoch()` and a careless operator UPDATE emit).
//
// We deliberately do NOT fail Scan on an un-parseable value: a
// garbage stamp on the admin row's `password_changed_at` would
// otherwise block login, which is the exact regression this code
// was written to prevent. An unparseable value falls through as
// Valid=false; the caller treats it as "never changed" and login
// continues.
type tolerantTime struct {
	Time  time.Time
	Valid bool
}

// Scan implements sql.Scanner.
func (t *tolerantTime) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		t.Valid = false
		return nil
	case time.Time:
		t.Time = v
		t.Valid = !v.IsZero()
		return nil
	case int64:
		// SQLite `unixepoch()` returns seconds; `unixepoch('subsec')`
		// returns seconds with fractional precision but we receive
		// the integer form from `unixepoch()`. Treat the value as
		// seconds.
		t.Time = time.Unix(v, 0).UTC()
		t.Valid = true
		return nil
	case float64:
		// `julianday(...)` returns a float; treat as seconds with
		// fractional precision.
		secs := int64(v)
		nsecs := int64((v - float64(secs)) * float64(time.Second))
		t.Time = time.Unix(secs, nsecs).UTC()
		t.Valid = true
		return nil
	case []byte:
		return t.scanString(string(v))
	case string:
		return t.scanString(v)
	default:
		// Last-ditch: try to coerce via driver.Value semantics so we
		// pick up types we didn't anticipate.
		if dv, ok := src.(driver.Valuer); ok {
			if val, err := dv.Value(); err == nil && val != nil && val != src {
				return t.Scan(val)
			}
		}
		// Don't fail — leave Valid=false. See the type doc.
		t.Valid = false
		return nil
	}
}

func (t *tolerantTime) scanString(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		t.Valid = false
		return nil
	}
	// Formats are tried in order of likelihood for our codebase:
	// CURRENT_TIMESTAMP yields the sqlite default; restored backups
	// or hand-typed values may use RFC3339.
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02",
	}
	for _, f := range formats {
		if tt, err := time.ParseInLocation(f, s, time.UTC); err == nil {
			t.Time = tt
			t.Valid = true
			return nil
		}
	}
	// Last-ditch: maybe the column holds a numeric string from a
	// bogus UPDATE. Try Unix-seconds.
	var secs int64
	if _, err := fmt.Sscanf(s, "%d", &secs); err == nil {
		t.Time = time.Unix(secs, 0).UTC()
		t.Valid = true
		return nil
	}
	// Don't fail — see type doc.
	t.Valid = false
	return nil
}

// Upsert writes or updates the admin row in place. The CHECK(id = 1)
// constraint and the WHERE clause guarantee we never accidentally
// create a second admin.
//
// password_changed_at is explicitly NULL'd on every Upsert. Two
// callers exercise this:
//
//   - bootstrap-admin.toml consumption on a fresh DB. The column is
//     already NULL in that case; the explicit NULL is a no-op.
//   - `sublyne --reset-admin`. This is the operator recovery path
//     and may be replacing credentials in a row whose
//     password_changed_at was corrupted by a hand-typed UPDATE
//     (the exact failure mode that broke login on the foreign
//     install in Phase 8a). Resetting the column guarantees the
//     post-reset Get won't trip the same scan error.
func (s *AdminStore) Upsert(ctx context.Context, username, passwordHash string) error {
	if username == "" {
		return errors.New("auth: username must not be empty")
	}
	if passwordHash == "" {
		return errors.New("auth: password_hash must not be empty")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin (id, username, password_hash, password_changed_at)
		VALUES (1, ?, ?, NULL)
		ON CONFLICT(id) DO UPDATE SET
			username = excluded.username,
			password_hash = excluded.password_hash,
			password_changed_at = NULL
	`, username, passwordHash)
	if err != nil {
		return fmt.Errorf("auth: upsert admin: %w", err)
	}
	return nil
}

// UpdatePassword changes the admin password and stamps
// password_changed_at. The supplied hash must already be Argon2id-
// encoded — see HashPassword. The caller is responsible for verifying
// the *current* password first (done in the password-change handler).
func (s *AdminStore) UpdatePassword(ctx context.Context, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("auth: password_hash must not be empty")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE admin
		SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`, passwordHash)
	if err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrAdminNotFound
	}
	return nil
}
