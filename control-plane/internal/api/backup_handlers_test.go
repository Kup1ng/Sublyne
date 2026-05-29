package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// newFileBackedDB returns a *sql.DB pointed at a fresh file under t.TempDir().
// Backup/restore can't be exercised with an in-memory DB (VACUUM INTO needs
// a real path, and the swap relies on a path-on-disk file).
func newFileBackedDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sublyne.db")
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite at %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db, path
}

// seedAdmin writes one admin row with the supplied username + password.
// Returns the password-hash so tests can later assert preservation.
func seedAdmin(t *testing.T, db *sql.DB, username, password string) string {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.NewAdminStore(db).Upsert(context.Background(), username, hash); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return hash
}

// seedBackupClientTunnel inserts one client tunnel into db with the supplied
// name (so tests can verify both presence and absence after a restore).
func seedBackupClientTunnel(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	repo := tunnels.NewRepo(db)
	tn := tunnels.Tunnel{
		Name:                    name,
		Role:                    tunnels.RoleClient,
		Enabled:                 false,
		PSK:                     "psk-for-" + name,
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{String: "0.0.0.0:44443", Valid: true},
		DownloadReceivePort:     sql.NullInt64{Int64: 8443, Valid: true},
		UploadTargetAddr:        sql.NullString{String: "198.51.100.10:55555", Valid: true},
		WireguardConfig:         sql.NullString{String: "stub", Valid: true},
		PingSmoothingEnabled:    false,
		PingSmoothingTargetMS:   60,
		PacingEnabled:           false,
		PacingTargetMS:          100,
	}
	out, err := repo.Create(context.Background(), tn)
	if err != nil {
		t.Fatalf("seed tunnel %s: %v", name, err)
	}
	return out.ID
}

// backupTestRouter wires JUST the backup/restore routes (no auth) so
// the tests can issue requests without the JWT dance. Mounted under a
// bare /api prefix.
func backupTestRouter(t *testing.T, deps BackupRestoreDeps) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		MountBackupRoutes(api, deps)
	})
	return r
}

func TestBackupHandler_StreamsValidSQLite(t *testing.T) {
	db, path := newFileBackedDB(t)
	seedAdmin(t, db, "admin", "correct horse")
	seedBackupClientTunnel(t, db, "tunnel-a")

	deps := BackupRestoreDeps{
		DB:     db,
		DBPath: path,
		Logger: slog.Default(),
	}
	srv := httptest.NewServer(backupTestRouter(t, deps))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/settings/backup")
	if err != nil {
		t.Fatalf("GET backup: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", res.StatusCode)
	}
	disp := res.Header.Get("Content-Disposition")
	if !strings.Contains(disp, "attachment;") || !strings.Contains(disp, "sublyne-") {
		t.Errorf("Content-Disposition: %q does not look like a download header", disp)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) < 16 || string(body[:16]) != string(sqliteMagic) {
		t.Fatalf("first 16 bytes do not match SQLite magic: %q", body[:min(16, len(body))])
	}

	// Sanity-check the downloaded file by opening it as a SQLite DB
	// and confirming the seeded tunnel landed there.
	tmpPath := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(tmpPath, body, 0o600); err != nil {
		t.Fatalf("write snap: %v", err)
	}
	checkDB, err := sql.Open("sqlite", "file:"+tmpPath+"?_pragma=foreign_keys(on)")
	if err != nil {
		t.Fatalf("open snap: %v", err)
	}
	defer func() { _ = checkDB.Close() }()
	var count int
	if err := checkDB.QueryRow(`SELECT COUNT(*) FROM tunnels`).Scan(&count); err != nil {
		t.Fatalf("count tunnels in snap: %v", err)
	}
	if count != 1 {
		t.Errorf("snapshot tunnels count: got %d want 1", count)
	}
}

func TestRestoreHandler_PreservesAdminAndReplacesTunnels(t *testing.T) {
	// Running install has admin "running-admin" with password "running-pw"
	// and a tunnel named "live-tunnel". The backup will carry a different
	// admin (old-admin/old-pw) and a different tunnel (backup-tunnel).
	// After restore: tunnel list == [backup-tunnel] AND admin still
	// allows logging in as "running-admin" with "running-pw".
	runDB, runPath := newFileBackedDB(t)
	runHash := seedAdmin(t, runDB, "running-admin", "running-pw")
	seedBackupClientTunnel(t, runDB, "live-tunnel")

	backupBytes := buildBackupBytes(t, "old-admin", "old-pw", []string{"backup-tunnel"})

	auditRec := audit.NewRecorder(runDB)
	defer auditRec.Close()
	deps := BackupRestoreDeps{
		DB:         runDB,
		DBPath:     runPath,
		TunnelRepo: tunnels.NewRepo(runDB),
		WGRepo:     wg.NewRepo(runDB),
		Logger:     slog.Default(),
		Audit:      auditRec,
	}
	srv := httptest.NewServer(backupTestRouter(t, deps))
	defer srv.Close()

	body, contentType := buildMultipart(t, "backup", "old.db", backupBytes)
	res, err := http.Post(srv.URL+"/api/settings/restore", contentType, body)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", res.StatusCode, string(respBody))
	}
	var out restoreResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !out.Restored {
		t.Errorf("restored=false in response: %+v", out)
	}

	// 1. Tunnels: only "backup-tunnel" should remain. "live-tunnel" must
	//    be gone.
	rows, err := runDB.QueryContext(context.Background(), `SELECT name FROM tunnels ORDER BY name`)
	if err != nil {
		t.Fatalf("query tunnels: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	if len(names) != 1 || names[0] != "backup-tunnel" {
		t.Errorf("post-restore tunnels: got %v want [backup-tunnel]", names)
	}

	// 2. Admin row: username, password_hash preserved.
	var (
		preservedUser string
		preservedHash string
	)
	if err := runDB.QueryRow(`SELECT username, password_hash FROM admin WHERE id = 1`).
		Scan(&preservedUser, &preservedHash); err != nil {
		t.Fatalf("query admin: %v", err)
	}
	if preservedUser != "running-admin" {
		t.Errorf("admin username: got %q want %q", preservedUser, "running-admin")
	}
	if preservedHash != runHash {
		t.Errorf("admin password_hash was rewritten: got %q want %q", preservedHash, runHash)
	}
	// 3. The preserved password must still verify against the original
	//    plaintext — this is what proves "you can still log in".
	if err := auth.VerifyPassword(preservedHash, "running-pw"); err != nil {
		t.Errorf("preserved password no longer verifies: %v", err)
	}
}

func TestRestoreHandler_RejectsNonSQLite(t *testing.T) {
	runDB, runPath := newFileBackedDB(t)
	seedAdmin(t, runDB, "running-admin", "running-pw")

	deps := BackupRestoreDeps{
		DB:         runDB,
		DBPath:     runPath,
		TunnelRepo: tunnels.NewRepo(runDB),
		WGRepo:     wg.NewRepo(runDB),
		Logger:     slog.Default(),
	}
	srv := httptest.NewServer(backupTestRouter(t, deps))
	defer srv.Close()

	// 200-byte ZIP-ish payload — definitely not a SQLite header.
	junk := make([]byte, 200)
	junk[0] = 'P'
	junk[1] = 'K'
	junk[2] = 0x03
	junk[3] = 0x04
	body, ct := buildMultipart(t, "backup", "evil.zip", junk)
	res, err := http.Post(srv.URL+"/api/settings/restore", ct, body)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", res.StatusCode)
	}
	// The running tunnels and admin should be untouched.
	var n int
	if err := runDB.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&n); err != nil {
		t.Fatalf("count admin: %v", err)
	}
	if n != 1 {
		t.Errorf("admin row count: got %d want 1", n)
	}
}

func TestRestoreHandler_MigratesOlderBackup(t *testing.T) {
	// Build a backup file with only the 0001 migration applied —
	// schema_version sits at 1 and the tunnel table doesn't exist.
	// After restore, the running DB should have the tunnel table (from
	// 0002+) but with no rows (because the backup carried none and the
	// running install's tunnels were replaced).
	oldBackupPath := filepath.Join(t.TempDir(), "ancient.db")
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "journal_mode(WAL)")
	dsn := "file:" + oldBackupPath + "?" + q.Encode()
	oldDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open ancient: %v", err)
	}
	// Apply only the 0001 migration by hand so we simulate an older
	// backup that doesn't know about tunnels yet.
	if _, err := oldDB.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("schema_version: %v", err)
	}
	if _, err := oldDB.Exec(`INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}
	if _, err := oldDB.Exec(`CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, password_changed_at TIMESTAMP)`); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, err := oldDB.Exec(`INSERT INTO admin (id, username, password_hash) VALUES (1, 'ancient', 'ancient-hash')`); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := oldDB.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if _, err := oldDB.Exec(`CREATE TABLE login_attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL, success INTEGER NOT NULL)`); err != nil {
		t.Fatalf("login_attempts: %v", err)
	}
	if err := oldDB.Close(); err != nil {
		t.Fatalf("close ancient: %v", err)
	}
	backupBytes, err := os.ReadFile(oldBackupPath)
	if err != nil {
		t.Fatalf("read ancient: %v", err)
	}

	runDB, runPath := newFileBackedDB(t)
	seedAdmin(t, runDB, "current-admin", "current-pw")
	seedBackupClientTunnel(t, runDB, "to-be-replaced")

	deps := BackupRestoreDeps{
		DB:         runDB,
		DBPath:     runPath,
		TunnelRepo: tunnels.NewRepo(runDB),
		WGRepo:     wg.NewRepo(runDB),
		Logger:     slog.Default(),
	}
	srv := httptest.NewServer(backupTestRouter(t, deps))
	defer srv.Close()

	body, ct := buildMultipart(t, "backup", "ancient.db", backupBytes)
	res, err := http.Post(srv.URL+"/api/settings/restore", ct, body)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", res.StatusCode, string(respBody))
	}

	// tunnels table should exist (migrations applied) and be empty
	// (older backup had nothing in it).
	var n int
	if err := runDB.QueryRow(`SELECT COUNT(*) FROM tunnels`).Scan(&n); err != nil {
		t.Fatalf("count tunnels: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 tunnels after restoring an older backup, got %d", n)
	}
	// And the preserved admin still wins.
	var who string
	if err := runDB.QueryRow(`SELECT username FROM admin WHERE id = 1`).Scan(&who); err != nil {
		t.Fatalf("query admin: %v", err)
	}
	if who != "current-admin" {
		t.Errorf("preserved admin lost: got %q want %q", who, "current-admin")
	}
}

func TestRestoreHandler_RejectsOversizedUpload(t *testing.T) {
	runDB, runPath := newFileBackedDB(t)
	seedAdmin(t, runDB, "admin", "pw")
	deps := BackupRestoreDeps{
		DB:         runDB,
		DBPath:     runPath,
		TunnelRepo: tunnels.NewRepo(runDB),
		WGRepo:     wg.NewRepo(runDB),
		Logger:     slog.Default(),
	}
	srv := httptest.NewServer(backupTestRouter(t, deps))
	defer srv.Close()

	// Build a request whose Content-Length advertises > maxBackupBytes
	// even though we send a small body. The handler should refuse based
	// on FileHeader.Size.
	big := make([]byte, 256)
	copy(big, sqliteMagic)
	body, ct := buildMultipartWithSize(t, "backup", "huge.db", big, maxBackupBytes+10)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/settings/restore", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", ct)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status: got %d want 413", res.StatusCode)
	}
}

// buildBackupBytes returns the raw bytes of a SQLite file containing a
// single admin row and the supplied tunnel names. Built by opening a
// fresh DB, seeding it, then `VACUUM INTO` to a snapshot path we slurp.
func buildBackupBytes(t *testing.T, admin, pw string, tunnelNames []string) []byte {
	t.Helper()
	db, path := newFileBackedDB(t)
	seedAdmin(t, db, admin, pw)
	for _, n := range tunnelNames {
		seedBackupClientTunnel(t, db, n)
	}
	// Use VACUUM INTO so the backup is identical to what the BackupHandler
	// would emit — full schema + indexes + all rows in one tidy file.
	snapPath := filepath.Join(t.TempDir(), "snap.db")
	quoted := "'" + strings.ReplaceAll(snapPath, "'", "''") + "'"
	if _, err := db.Exec(`VACUUM INTO ` + quoted); err != nil {
		t.Fatalf("vacuum into: %v", err)
	}
	_ = path
	out, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snap: %v", err)
	}
	return out
}

// buildMultipart wraps the supplied bytes in a multipart form body with
// the field name "backup". Returns the body + Content-Type header.
func buildMultipart(t *testing.T, field, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	w, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close mw: %v", err)
	}
	return buf, mw.FormDataContentType()
}

// buildMultipartWithSize forges a multipart envelope whose nested file
// header claims `claimedSize` bytes. Used to verify the size cap path —
// the handler consults FileHeader.Size, not the on-wire length.
func buildMultipartWithSize(t *testing.T, field, filename string, content []byte, claimedSize int64) (*bytes.Buffer, string) {
	t.Helper()
	// Multipart's FileHeader.Size = total bytes the parser saw in the
	// part. Pad the content out to that many bytes so we don't have to
	// re-implement the parser.
	if int64(len(content)) >= claimedSize {
		return buildMultipart(t, field, filename, content)
	}
	padded := make([]byte, claimedSize)
	copy(padded, content)
	return buildMultipart(t, field, filename, padded)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
