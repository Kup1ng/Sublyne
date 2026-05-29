package main

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
)

func TestVersionIsSet(t *testing.T) {
	if version == "" {
		t.Fatal("version must not be empty")
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"trace":  slog.LevelDebug,
		"debug":  slog.LevelDebug,
		"info":   slog.LevelInfo,
		"warn":   slog.LevelWarn,
		"error":  slog.LevelError,
		"":       slog.LevelInfo,
		"banana": slog.LevelInfo,
		"INFO":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLogLevel(in); got != want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRun_VersionFlag(t *testing.T) {
	if code := run([]string{"--version"}); code != 0 {
		t.Errorf("run(--version) = %d, want 0", code)
	}
}

func TestRun_TearDownStub(t *testing.T) {
	if code := run([]string{"--tear-down"}); code != 0 {
		t.Errorf("run(--tear-down) = %d, want 0", code)
	}
}

func TestRun_MissingConfigFails(t *testing.T) {
	if code := run([]string{"--config", "/does/not/exist.toml"}); code == 0 {
		t.Error("run with missing config should fail")
	}
}

// TestDataplaneBinaryPath_NotUnderRun guards against the regression
// that shipped Phase 8a: extracting the dataplane to /run/sublyne/
// silently fails on every recent Ubuntu because systemd mounts /run
// with the `noexec` option. The binary lives in main.go as a string
// literal supplied to the supervisor; this test reads main.go itself
// and asserts the literal does not live under /run.
//
// We use a source-grep test rather than a runtime assertion because
// the path is set inside the `if dataplaneasset.Embedded` branch
// that doesn't run under `go test` (no embed tag → no real supervisor
// startup).
func TestDataplaneBinaryPath_NotUnderRun(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(src), "BinaryPath = \"/var/lib/sublyne/dataplane\"") {
		t.Errorf("main.go does not pin BinaryPath under /var/lib; if you intentionally moved it, update this test and verify the new path is on an exec-able filesystem under the systemd sandbox")
	}
	if strings.Contains(string(src), "BinaryPath = \"/run/") {
		t.Errorf("main.go points BinaryPath under /run/ — that filesystem is mounted noexec by systemd on Ubuntu and fork/exec will fail with EACCES at runtime")
	}
}

// TestResetAdmin_HappyPath exercises the operator recovery path that
// rescues installs where the admin login is broken. We write a
// minimal config + a fresh DB, pipe new credentials over stdin, run
// runResetAdmin, and assert (a) the admin row holds the new username
// + verifies the new password, (b) login_attempts is empty so an
// active lockout can't keep the operator out.
func TestResetAdmin_HappyPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sublyne.db")
	logPath := filepath.Join(dir, "app.log")
	cfgPath := filepath.Join(dir, "config.toml")

	cfg := "role = \"client\"\n" +
		"panel_port = 18080\n" +
		"web_path = \"abc\"\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_path = \"" + filepath.ToSlash(logPath) + "\"\n" +
		"log_level = \"info\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Pre-seed the DB so we know the row gets *replaced*, not
	// freshly created. We also drop a stale lockout row so the
	// assertion that login_attempts is cleared bites.
	preseed := preseedDBForResetAdmin(t, dbPath)
	if _, err := preseed.ExecContext(context.Background(),
		`INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)`,
		"oldname", "$argon2id$v=19$m=65536,t=3,p=2$AAAA$BBBB"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := preseed.ExecContext(context.Background(),
		`INSERT INTO login_attempts (ip, ts, success) VALUES (?, 1, 0)`,
		"1.2.3.4"); err != nil {
		t.Fatalf("seed lockout: %v", err)
	}
	_ = preseed.Close()

	stdin := strings.NewReader("newadmin\nstrong-pass-123\nstrong-pass-123\n")
	var stdout, stderr bytes.Buffer
	if code := runResetAdmin(cfgPath, stdin, &stdout, &stderr); code != 0 {
		t.Fatalf("runResetAdmin = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// Reopen the DB and confirm the new credentials work.
	check := preseedDBForResetAdmin(t, dbPath)
	defer func() { _ = check.Close() }()
	admin, err := auth.NewAdminStore(check).Get(context.Background())
	if err != nil {
		t.Fatalf("Get admin: %v", err)
	}
	if admin.Username != "newadmin" {
		t.Errorf("Username = %q, want newadmin", admin.Username)
	}
	if err := auth.VerifyPassword(admin.PasswordHash, "strong-pass-123"); err != nil {
		t.Errorf("new password did not verify: %v", err)
	}
	var attempts int
	if err := check.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM login_attempts`).Scan(&attempts); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if attempts != 0 {
		t.Errorf("login_attempts = %d, want 0 (lockout should be cleared)", attempts)
	}
}

// TestShowAdminUsername_HappyPath exercises the Phase 14 Status-menu
// support flag. setup.sh shells out to `sublyne --show-admin-username`
// so an operator running option 5 (Status) sees their panel login
// without us having to embed sqlite3-CLI knowledge into setup.sh. The
// flag MUST print the username and only the username — no hash, no
// other admin columns — so the test asserts the exact stdout shape.
func TestShowAdminUsername_HappyPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sublyne.db")
	logPath := filepath.Join(dir, "app.log")
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := "role = \"client\"\n" +
		"panel_port = 18080\n" +
		"web_path = \"abc\"\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_path = \"" + filepath.ToSlash(logPath) + "\"\n" +
		"log_level = \"info\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	seed := preseedDBForResetAdmin(t, dbPath)
	if _, err := seed.ExecContext(context.Background(),
		`INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)`,
		"operator-1", "$argon2id$v=19$m=65536,t=3,p=2$AAAA$BBBB"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	_ = seed.Close()

	var stdout, stderr bytes.Buffer
	if code := runShowAdminUsername(cfgPath, &stdout, &stderr); code != 0 {
		t.Fatalf("runShowAdminUsername = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got != "operator-1" {
		t.Errorf("stdout = %q, want %q", got, "operator-1")
	}
	if strings.Contains(stdout.String(), "argon2") {
		t.Errorf("stdout leaked password hash material: %q", stdout.String())
	}
}

// TestShowAdminUsername_NoAdminRow returns non-zero (so setup.sh can
// render "(unknown)" instead of an empty line) when the bootstrap
// hasn't been consumed yet. We assert the exit code so a future
// refactor that swallows ErrAdminNotFound trips this test.
func TestShowAdminUsername_NoAdminRow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sublyne.db")
	logPath := filepath.Join(dir, "app.log")
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := "role = \"client\"\n" +
		"panel_port = 18080\n" +
		"web_path = \"abc\"\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_path = \"" + filepath.ToSlash(logPath) + "\"\n" +
		"log_level = \"info\"\n"
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o600)
	// Apply migrations but DON'T insert an admin row so Get returns
	// ErrAdminNotFound.
	seed := preseedDBForResetAdmin(t, dbPath)
	_ = seed.Close()

	var stdout, stderr bytes.Buffer
	if code := runShowAdminUsername(cfgPath, &stdout, &stderr); code == 0 {
		t.Fatalf("runShowAdminUsername should have returned non-zero with no admin row; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestResetAdmin_RejectsMismatchedConfirm asserts the confirm-password
// gate fires — without it a typo at the keyboard could lock the
// operator out a *second* time.
func TestResetAdmin_RejectsMismatchedConfirm(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sublyne.db")
	logPath := filepath.Join(dir, "app.log")
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := "role = \"client\"\n" +
		"panel_port = 18080\n" +
		"web_path = \"abc\"\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_path = \"" + filepath.ToSlash(logPath) + "\"\n" +
		"log_level = \"info\"\n"
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o600)

	stdin := strings.NewReader("admin\nfirst-pass-1234\nsecond-pass-1234\n")
	var stdout, stderr bytes.Buffer
	if code := runResetAdmin(cfgPath, stdin, &stdout, &stderr); code == 0 {
		t.Fatalf("runResetAdmin should have returned non-zero; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "passwords do not match") {
		t.Errorf("stderr should mention mismatched confirmation, got %q", stderr.String())
	}
}

// preseedDBForResetAdmin opens the supplied DB path with migrations
// applied, so the reset-admin tests can seed rows before invoking
// the CLI. Uses the same DSN shape as internal/db/db.go.
func preseedDBForResetAdmin(t *testing.T, path string) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("migrate seed db: %v", err)
	}
	return db
}

func TestBootstrapAdminPath(t *testing.T) {
	cases := map[string]string{
		"/etc/sublyne/config.toml":         "/etc/sublyne/bootstrap-admin.toml",
		"/var/lib/sublyne/dev-config.toml": "/var/lib/sublyne/bootstrap-admin.toml",
		// A path without any directory separator should fall through
		// to the default location, so that an operator running
		// `./sublyne --config config.toml` from /etc/sublyne gets a
		// sensible bootstrap target rather than a sibling file in
		// the working directory.
		"config.toml": auth.DefaultBootstrapPath,
	}
	for in, want := range cases {
		got := bootstrapAdminPath(in)
		// Normalize the separator so the test passes on Windows
		// (where os.PathSeparator is "\\") and Linux ("/").
		gotNorm := strings.ReplaceAll(got, "\\", "/")
		if gotNorm != want {
			t.Errorf("bootstrapAdminPath(%q) = %q, want %q", in, got, want)
		}
	}
}
