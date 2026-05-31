package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB opens a fresh SQLite file under t.TempDir(). It does not
// import internal/db on purpose — that package depends on these
// migrations indirectly via the binary, and keeping this test
// self-contained means it can validate the raw applier behaviour
// without coupling to db.Open's quirks (chmod, dir creation, etc.).
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	conn, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(on)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := conn.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestApply_CreatesExpectedTables(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)

	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got := listTables(t, conn)
	want := []string{"admin", "audit_log", "login_attempts", "schema_version", "settings", "socks5_proxies", "tunnels", "wireguard_configs"}
	if !sliceEq(got, want) {
		t.Errorf("tables = %v, want %v", got, want)
	}
}

func TestApply_RecordsVersionRow(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)

	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var max sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_version").Scan(&max); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	// Bumped to 10 when v2.5.0 multi-port tunnels added
	// 0010_multiport.sql (adds tunnels.ports). Future phases that add a
	// migration should bump this in lockstep.
	if !max.Valid || max.Int64 != 10 {
		t.Errorf("max(version) = %v valid=%v, want 10", max.Int64, max.Valid)
	}
}

func TestApply_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)

	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		t.Fatalf("count schema_version: %v", err)
	}
	// One row per applied migration. The second Apply must add no new
	// rows — it is the idempotence assertion.
	wantCount := numMigrations(t)
	if count != wantCount {
		t.Errorf("schema_version row count = %d after two applies, want %d", count, wantCount)
	}
}

// numMigrations returns the count of embedded migration files so the
// idempotence test stays correct as new migrations land.
func numMigrations(t *testing.T) int {
	t.Helper()
	ms, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return len(ms)
}

func TestApply_AdminTableShape(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)

	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cols := tableColumns(t, conn, "admin")
	wantCols := map[string]bool{
		"id":                  false,
		"username":            false,
		"password_hash":       false,
		"created_at":          false,
		"password_changed_at": false,
	}
	for _, c := range cols {
		if _, ok := wantCols[c]; ok {
			wantCols[c] = true
		}
	}
	for name, seen := range wantCols {
		if !seen {
			t.Errorf("admin table missing column %q (got %v)", name, cols)
		}
	}

	// Phase 2's CHECK (id = 1) means inserting id=2 must fail.
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO admin (id, username, password_hash) VALUES (2, 'x', 'y')`); err == nil {
		t.Error("admin table accepted id=2; CHECK constraint not in force")
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO admin (id, username, password_hash) VALUES (1, 'admin', 'hash')`); err != nil {
		t.Errorf("admin table rejected legitimate id=1 insert: %v", err)
	}
}

func TestApply_LoginAttemptsIndex(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)

	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rows, err := conn.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='login_attempts'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name == "idx_login_attempts_ip_ts" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("idx_login_attempts_ip_ts missing")
	}
}

func TestLoad_DiscoversEmbeddedFiles(t *testing.T) {
	ms, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("expected at least one embedded migration file")
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].version <= ms[i-1].version {
			t.Errorf("versions not strictly increasing: %d then %d", ms[i-1].version, ms[i].version)
		}
	}
}

func listTables(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func tableColumns(t *testing.T, conn *sql.DB, table string) []string {
	t.Helper()
	rows, err := conn.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
