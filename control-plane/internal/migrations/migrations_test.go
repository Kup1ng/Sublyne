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
	// Bumped to 12 when v4.0.0 added per-tunnel forward_protocol +
	// keep_alive + KCP engine preset/tuning columns
	// (0012_forward_protocol.sql). Future phases that add a migration
	// should bump this in lockstep.
	if !max.Valid || max.Int64 != 12 {
		t.Errorf("max(version) = %v valid=%v, want 12", max.Int64, max.Valid)
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

// migrationSQL returns the raw SQL body of the embedded migration with
// the given version, so a test can replay it against rows seeded in the
// PRE-migration shape. Apply() runs all migrations up front, so we can't
// observe a data migration's effect on rows inserted afterwards — instead
// we seed v2.6.0-shaped rows and replay the data migration's body.
func migrationSQL(t *testing.T, version int) string {
	t.Helper()
	ms, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, m := range ms {
		if m.version == version {
			return m.sql
		}
	}
	t.Fatalf("migration version %d not found", version)
	return ""
}

// TestApply_UnifiedPorts_FoldsMainPortAndStripsAddr verifies the v2.7.0
// data migration (0011): the port embedded in local_listen_addr (Client) /
// forward_target (Remote) is folded into the `ports` CSV and stripped off
// the address, across IPv4 / bracketed-IPv6 / hostname and single- /
// multi-port shapes. This is the "existing tunnels migrate silently" test.
func TestApply_UnifiedPorts_FoldsMainPortAndStripsAddr(t *testing.T) {
	ctx := context.Background()
	conn := openTestDB(t)
	if err := Apply(ctx, conn); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Seed rows in the v2.6.0 shape: the app port lives inside the address
	// string, `ports` is empty for single-port and the full set (including
	// the canonical port) for multi-port.
	seedClient := func(name, localListen, ports string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, `INSERT INTO tunnels
			(name, role, psk, download_spoof_source_ip, download_spoof_source_port,
			 download_transport, local_listen_addr, download_receive_port, ports)
			VALUES (?, 'client', 'psk-example-32-chars-aaaaaaaaaa', '203.0.113.5', 443,
			        'udp', ?, 8443, ?)`, name, localListen, ports); err != nil {
			t.Fatalf("seed client %s: %v", name, err)
		}
	}
	seedRemote := func(name, forwardTarget, ports string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, `INSERT INTO tunnels
			(name, role, psk, download_spoof_source_ip, download_spoof_source_port,
			 download_transport, upload_listen_addr, forward_target, download_send_port,
			 client_real_ip, ports)
			VALUES (?, 'remote', 'psk-example-32-chars-bbbbbbbbbb', '203.0.113.5', 443,
			        'udp', '0.0.0.0:55555', ?, 8443, '198.51.100.20', ?)`,
			name, forwardTarget, ports); err != nil {
			t.Fatalf("seed remote %s: %v", name, err)
		}
	}

	seedClient("c-v4-single", "0.0.0.0:44443", "")
	seedClient("c-v6-single", "[::]:44443", "")
	seedClient("c-v4-multi", "0.0.0.0:44443", "44443,8001,8002")
	seedRemote("r-v4-single", "127.0.0.1:5201", "")
	seedRemote("r-v6-single", "[2001:db8::1]:5201", "")
	seedRemote("r-host-single", "example.com:443", "")
	seedRemote("r-v4-multi", "192.0.2.10:443", "443,8443")

	// Replay the 0011 data migration against the seeded rows.
	if _, err := conn.ExecContext(ctx, migrationSQL(t, 11)); err != nil {
		t.Fatalf("replay 0011: %v", err)
	}

	type want struct {
		role  string
		addr  string // local_listen_addr (client) or forward_target (remote)
		ports string
	}
	cases := map[string]want{
		"c-v4-single":   {"client", "0.0.0.0", "44443"},
		"c-v6-single":   {"client", "::", "44443"},
		"c-v4-multi":    {"client", "0.0.0.0", "44443,8001,8002"},
		"r-v4-single":   {"remote", "127.0.0.1", "5201"},
		"r-v6-single":   {"remote", "2001:db8::1", "5201"},
		"r-host-single": {"remote", "example.com", "443"},
		"r-v4-multi":    {"remote", "192.0.2.10", "443,8443"},
	}
	for name, w := range cases {
		var addr, ports string
		col := "local_listen_addr"
		if w.role == "remote" {
			col = "forward_target"
		}
		if err := conn.QueryRowContext(ctx,
			"SELECT "+col+", ports FROM tunnels WHERE name = ?", name).Scan(&addr, &ports); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if addr != w.addr {
			t.Errorf("%s: %s = %q, want %q", name, col, addr, w.addr)
		}
		if ports != w.ports {
			t.Errorf("%s: ports = %q, want %q", name, ports, w.ports)
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
