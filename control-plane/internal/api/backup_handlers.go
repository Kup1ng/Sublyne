package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplane"
	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// BackupRestoreDeps bundles the pieces the backup and restore endpoints
// need. It is built once at router construction and shared by both
// handlers.
//
// The handlers reach into the running DB, the dataplane manager, and
// the WireGuard manager because a restore must atomically swap on-disk
// state, stop every running tunnel, replay the new DB into the
// dataplane, and bring up any kernel WG interfaces the restored tunnels
// reference. Backup only needs DB + DBPath; the other fields are nil-
// safe when only Backup is wired.
type BackupRestoreDeps struct {
	DB         *sql.DB
	DBPath     string
	TunnelRepo *tunnels.Repo
	WGRepo     *wg.Repo
	WGManager  wg.Manager
	// SOCKS5Repo lets restore re-resolve socks5_proxies rows for any
	// SOCKS5-mode tunnel that was enabled in the uploaded backup
	// (Phase R9a). May be nil — SOCKS5 tunnels then surface as
	// "skipped" in the restore log and the operator clicks Start once
	// the panel comes back.
	SOCKS5Repo *socks5.Repo
	Dataplane  *dataplane.Manager
	Logger     *slog.Logger
	Audit      *audit.Recorder
	// TunnelCache, when set, has its Invalidate() called after a
	// successful restore so the dashboard's cached snapshot picks up
	// the new tunnel set on the next refresh. May be nil — restore
	// still works without the cache wired.
	TunnelCache *tunnels.Cache
}

// logger returns d.Logger or slog.Default() so call sites don't need
// to nil-check.
func (d BackupRestoreDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// actorOf names the authenticated admin in audit rows.
func (d BackupRestoreDeps) actorOf(r *http.Request) string {
	if a, ok := AdminFromContext(r.Context()); ok {
		return a.Username
	}
	return audit.ActorAdmin
}

// sqliteMagic is the 16-byte header every valid SQLite database starts
// with (per SQLite file format documentation §1.3). We check the prefix
// before we touch anything else on the restore path so a stray ZIP or
// random binary gets rejected with a clear error instead of corrupting
// the running install.
var sqliteMagic = []byte("SQLite format 3\x00")

// maxBackupBytes caps the upload size at 100 MiB. PRD §7 expects
// installations on small VPSes; a backup that big would mean the
// audit_log table is wildly out of retention and the operator has
// other problems. 100 MiB is generous and still safe inside the
// request handler's memory budget.
const maxBackupBytes = 100 << 20

// BackupHandler streams a consistent snapshot of the SQLite DB to the
// operator. We use `VACUUM INTO` so the snapshot reflects every
// committed write up to the call moment and excludes any WAL pages
// that aren't yet checkpointed back into the main file.
//
// PRD §4.4: the file *is* the backup. There's no separate manifest;
// the operator's only artifact is the .db file they save.
func BackupHandler(deps BackupRestoreDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.DB == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "backup not available: database not configured")
			return
		}
		// Snapshot into a temp file next to the live DB so VACUUM INTO
		// doesn't cross filesystems (rename / read costs stay local).
		snapDir := filepath.Dir(deps.DBPath)
		if snapDir == "" || snapDir == "." {
			snapDir = os.TempDir()
		}
		f, err := os.CreateTemp(snapDir, "sublyne-backup-*.db")
		if err != nil {
			deps.logger().Error("backup: create temp file", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not create backup")
			return
		}
		snapPath := f.Name()
		_ = f.Close()
		// VACUUM INTO writes to the path we created above. If the path
		// already existed VACUUM INTO would refuse, so we remove the
		// empty placeholder first (CreateTemp + Close already left the
		// inode there). The defer cleans up after we're done streaming.
		_ = os.Remove(snapPath)
		defer func() { _ = os.Remove(snapPath) }()

		// `?` parameters don't substitute into VACUUM INTO's literal —
		// the file path goes inline. Quote with SQLite's string-literal
		// syntax (single-quoted, doubling embedded single quotes) so a
		// pathological install path can't break out into other SQL.
		// The path itself comes from os.CreateTemp, not user input.
		quoted := "'" + strings.ReplaceAll(snapPath, "'", "''") + "'"
		stmt := "VACUUM INTO " + quoted //nolint:gosec // path is locally-created temp file, escaped above
		if _, err := deps.DB.ExecContext(r.Context(), stmt); err != nil {
			deps.logger().Error("backup: vacuum into", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not snapshot database")
			return
		}

		stat, err := os.Stat(snapPath)
		if err != nil {
			deps.logger().Error("backup: stat snapshot", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not stat snapshot")
			return
		}

		filename := fmt.Sprintf("sublyne-%s.db", time.Now().UTC().Format("20060102-150405"))
		w.Header().Set("Content-Type", "application/x-sqlite3")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)

		src, err := os.Open(snapPath)
		if err != nil {
			deps.logger().Error("backup: open snapshot for streaming", "err", err)
			// Headers already committed; nothing useful to say.
			return
		}
		defer func() { _ = src.Close() }()
		if _, err := io.Copy(w, src); err != nil {
			deps.logger().Warn("backup: stream to client interrupted", "err", err)
			return
		}

		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionBackupDownload, deps.actorOf(r), ClientIP(r), "sublyne.db", map[string]any{
				"bytes": stat.Size(),
			})
		}
	}
}

// restoreResult is the JSON body returned on a successful restore.
type restoreResult struct {
	Restored      bool `json:"restored"`
	TunnelsTotal  int  `json:"tunnels_total"`
	TunnelsActive int  `json:"tunnels_active"`
}

// RestoreHandler accepts a multipart upload of a previous backup file
// and atomically swaps the running install's tables in from that file.
//
// PRD §4.4 pins the safety contract: everything is replaced EXCEPT the
// admin username, admin password hash, panel port, and web path —
// preserved from the *running* DB so the operator can't lock themselves
// out by uploading a backup taken before the credentials rotated.
//
// In this project the panel port and web path live in
// /etc/sublyne/config.toml (not in SQLite), so they are naturally
// preserved by the file-only DB swap. The admin row is the one piece
// of DB state we explicitly carry over.
//
// Order of operations:
//
//  1. Sanity-check the upload (size cap, magic header).
//  2. Save to a sibling temp file (so the rename happens on one fs).
//  3. Capture the preserved admin row from the running DB.
//  4. Open the temp file as a fresh *sql.DB and apply forward migrations
//     on it. This is what makes older backups safe to restore — any
//     schema additions made since the backup was taken land on the temp
//     DB BEFORE we copy from it.
//  5. Stop every running tunnel (dataplane Stop + WG Down). We do this
//     BEFORE the swap so listeners release their ports and stale WG
//     interfaces tear down cleanly; the post-swap Sync brings them back
//     up against the restored tunnel rows.
//  6. ATTACH the temp DB and DELETE+INSERT every domain table from it.
//  7. Re-write the preserved admin row.
//  8. DETACH the temp DB.
//  9. Re-sync the dataplane from the restored DB.
//  10. Return 200 with counts. Existing JWT cookies were signed with the
//     pre-restore signing key and now fail at the next request; the
//     panel logs the operator out and they re-login with the
//     preserved username + password.
func RestoreHandler(deps BackupRestoreDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.DB == nil || deps.TunnelRepo == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "restore not available: server not fully configured")
			return
		}

		// Multipart with a single "backup" file field. 32 MiB memory
		// budget for parsing headers; the body itself spools to disk via
		// http.Request.ParseMultipartForm.
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeJSONError(w, http.StatusBadRequest, "malformed multipart upload: "+err.Error())
			return
		}
		file, fh, err := r.FormFile("backup")
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "the upload must include a 'backup' file field")
			return
		}
		defer func() { _ = file.Close() }()
		if fh.Size <= 0 {
			writeJSONError(w, http.StatusBadRequest, "the uploaded file is empty")
			return
		}
		if fh.Size > maxBackupBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("backup is too large (%d bytes; cap is %d)", fh.Size, maxBackupBytes))
			return
		}

		// Probe the first 16 bytes against the SQLite magic header
		// BEFORE we copy a single byte to disk. A 200 MB ZIP isn't going
		// to make it past this guard.
		var header [16]byte
		if _, err := io.ReadFull(file, header[:]); err != nil {
			writeJSONError(w, http.StatusBadRequest, "could not read the start of the upload: "+err.Error())
			return
		}
		if string(header[:]) != string(sqliteMagic) {
			writeJSONError(w, http.StatusBadRequest, "this file is not a SQLite database (wrong magic header)")
			return
		}

		// Save to a sibling temp file so the rest of the routine works
		// against a real file on the same filesystem as the live DB. The
		// `LimitReader` adds belt-and-braces protection in case the
		// multipart parser miscounted.
		snapDir := filepath.Dir(deps.DBPath)
		if snapDir == "" || snapDir == "." {
			snapDir = os.TempDir()
		}
		tmp, err := os.CreateTemp(snapDir, "sublyne-restore-*.db")
		if err != nil {
			deps.logger().Error("restore: create temp file", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not save upload to disk")
			return
		}
		tmpPath := tmp.Name()
		defer func() { _ = os.Remove(tmpPath) }()
		// Write the 16-byte header back first so the temp file is a
		// faithful copy of the uploaded bytes.
		if _, err := tmp.Write(header[:]); err != nil {
			_ = tmp.Close()
			deps.logger().Error("restore: write header to temp", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not save upload to disk")
			return
		}
		if _, err := io.Copy(tmp, io.LimitReader(file, maxBackupBytes)); err != nil {
			_ = tmp.Close()
			deps.logger().Error("restore: spool upload", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not save upload to disk")
			return
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			deps.logger().Error("restore: sync temp", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not finalise upload")
			return
		}
		if err := tmp.Close(); err != nil {
			deps.logger().Error("restore: close temp", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not finalise upload")
			return
		}

		// Pull the preserved admin row out of the running DB so we can
		// re-stamp it after the swap. PRD §4.4: this row is what keeps
		// the operator able to log back in.
		preserved, err := capturePreservedAdmin(r.Context(), deps.DB)
		if err != nil {
			deps.logger().Error("restore: capture preserved admin", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not read current admin row: "+err.Error())
			return
		}

		// Open the uploaded file as a fresh *sql.DB and apply forward
		// migrations on it. After this call the temp file is at the
		// same schema version as the running DB — copying from it can
		// rely on identical column lists in every domain table.
		tempDB, err := openTempBackup(r.Context(), tmpPath)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "the uploaded file is not a usable sublyne backup: "+err.Error())
			return
		}
		if err := migrations.Apply(r.Context(), tempDB); err != nil {
			_ = tempDB.Close()
			deps.logger().Error("restore: migrate temp DB", "err", err)
			writeJSONError(w, http.StatusBadRequest, "could not bring the uploaded backup up to the current schema: "+err.Error())
			return
		}
		if err := tempDB.Close(); err != nil {
			deps.logger().Warn("restore: close temp DB after migrate", "err", err)
		}

		// Snapshot the running tunnels and tear them down so listeners
		// release ports and WG interfaces clear up before the swap.
		runningBefore, err := deps.TunnelRepo.List(r.Context())
		if err != nil {
			deps.logger().Error("restore: list current tunnels", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not enumerate current tunnels: "+err.Error())
			return
		}
		stopAllTunnels(r.Context(), deps, runningBefore)

		// Atomically copy every domain table from the temp file into
		// the running DB and re-write the preserved admin row.
		if err := swapTablesFromBackup(r.Context(), deps.DB, tmpPath, preserved); err != nil {
			deps.logger().Error("restore: table swap", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not apply restore: "+err.Error())
			return
		}
		// The tunnels table just got rewritten — drop the dashboard's
		// cached snapshot so the next List re-reads from the restored
		// state instead of returning the pre-restore list.
		if deps.TunnelCache != nil {
			deps.TunnelCache.Invalidate()
		}

		// Bring the dataplane back in line with the restored DB.
		restoredTunnels, err := deps.TunnelRepo.List(r.Context())
		if err != nil {
			deps.logger().Warn("restore: list tunnels post-swap", "err", err)
			restoredTunnels = nil
		}
		active := startEnabledTunnels(r.Context(), deps, restoredTunnels)

		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionRestoreUpload, deps.actorOf(r), ClientIP(r), fh.Filename, map[string]any{
				"bytes":          fh.Size,
				"tunnels_total":  len(restoredTunnels),
				"tunnels_active": active,
			})
		}

		writeJSON(w, http.StatusOK, restoreResult{
			Restored:      true,
			TunnelsTotal:  len(restoredTunnels),
			TunnelsActive: active,
		})
	}
}

// preservedAdmin is the slice of the running DB's `admin` row that
// survives a restore. Holding the values in Go memory means we can
// re-write them onto whatever shape the backup's admin row has
// (including timestamps in different time zones).
type preservedAdmin struct {
	username          string
	passwordHash      string
	createdAt         sql.NullString
	passwordChangedAt sql.NullString
}

func capturePreservedAdmin(ctx context.Context, db *sql.DB) (preservedAdmin, error) {
	var p preservedAdmin
	err := db.QueryRowContext(ctx,
		`SELECT username, password_hash, created_at, password_changed_at
		   FROM admin
		  WHERE id = 1`).
		Scan(&p.username, &p.passwordHash, &p.createdAt, &p.passwordChangedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// No admin row in the running DB yet (very early in install).
		// We can still proceed — the restored DB's admin row stands.
		return p, nil
	}
	return p, err
}

// openTempBackup opens the uploaded file as a writeable *sql.DB so we
// can run migrations on it. We use the same DSN options as the main
// store (modernc.org/sqlite with foreign keys + WAL). The caller is
// responsible for Close().
func openTempBackup(ctx context.Context, path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping uploaded file: %w", err)
	}
	return db, nil
}

// stopAllTunnels tears down every tunnel that the running DB lists as
// enabled so the listeners release their ports and WG interfaces are
// torn down before the file swap. Errors are logged but never fail the
// restore — the swap is the point of no return, not the teardown.
func stopAllTunnels(ctx context.Context, deps BackupRestoreDeps, ts []tunnels.Tunnel) {
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		if deps.Dataplane != nil {
			if err := deps.Dataplane.Stop(ctx, t.ID); err != nil {
				deps.logger().Warn("restore: dataplane stop failed (continuing)",
					"tunnel_id", t.ID, "err", err)
			}
		}
		if t.Role == tunnels.RoleClient && deps.WGManager != nil {
			if err := deps.WGManager.Down(ctx, t.ID); err != nil && !errors.Is(err, wg.ErrManagerUnsupported) {
				deps.logger().Warn("restore: wg down failed (continuing)",
					"tunnel_id", t.ID, "err", err)
			}
		}
	}
}

// startEnabledTunnels reproduces the per-row Start sequence (WG Up +
// Dataplane Start) for every enabled tunnel in the restored DB. Returns
// how many actually started successfully; failures are logged but not
// counted, so the JSON response gives the operator an honest "how
// many of these are forwarding right now" number.
func startEnabledTunnels(ctx context.Context, deps BackupRestoreDeps, ts []tunnels.Tunnel) int {
	active := 0
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		var socks5Proxy *socks5.Proxy
		switch {
		case t.Role == tunnels.RoleClient && t.UploadMode == tunnels.UploadModeSocks5:
			// SOCKS5 upload path (Phase R9a). Resolve the proxy row from
			// the restored DB; if it's missing the tunnel can't start
			// and we surface the skip.
			if deps.SOCKS5Repo == nil || !t.Socks5ProxyID.Valid {
				deps.logger().Warn("restore: SOCKS5 tunnel skipped — no proxy repo or no FK",
					"tunnel_id", t.ID)
				continue
			}
			p, err := deps.SOCKS5Repo.Get(ctx, t.Socks5ProxyID.Int64)
			if err != nil {
				deps.logger().Warn("restore: SOCKS5 proxy missing for tunnel",
					"tunnel_id", t.ID, "socks5_proxy_id", t.Socks5ProxyID.Int64, "err", err)
				continue
			}
			socks5Proxy = &p
		case t.Role == tunnels.RoleClient && t.WGConfigID.Valid && deps.WGRepo != nil && deps.WGManager != nil:
			cfg, err := deps.WGRepo.Get(ctx, t.WGConfigID.Int64)
			if err != nil {
				deps.logger().Warn("restore: cannot bring up tunnel — WG config missing",
					"tunnel_id", t.ID, "wg_config_id", t.WGConfigID.Int64, "err", err)
				continue
			}
			parsed, err := wg.ParseConfig(cfg.RawText)
			if err != nil {
				deps.logger().Warn("restore: cannot bring up tunnel — WG config malformed",
					"tunnel_id", t.ID, "err", err)
				continue
			}
			if _, err := deps.WGManager.Up(ctx, t.ID, parsed); err != nil && !errors.Is(err, wg.ErrManagerUnsupported) {
				deps.logger().Warn("restore: WG up failed (skipping tunnel)",
					"tunnel_id", t.ID, "err", err)
				continue
			}
		}
		if deps.Dataplane != nil {
			if err := deps.Dataplane.Start(ctx, t, socks5Proxy); err != nil {
				deps.logger().Warn("restore: dataplane start failed (skipping tunnel)",
					"tunnel_id", t.ID, "err", err)
				continue
			}
		}
		active++
	}
	return active
}

// restoreTables is the closed set of domain tables we copy from the
// uploaded backup. Listing them explicitly (rather than discovering via
// sqlite_master) lets us be precise about ordering — children before
// parents on DELETE, parents before children on INSERT — and avoid
// touching internal SQLite tables (sqlite_sequence, sqlite_master).
//
// Order rules:
//   - DELETE in REVERSE order (most-referenced child first) so foreign
//     keys never trip mid-clear.
//   - INSERT in the natural order below (parents first).
//
// Keep this list in sync with the migrations. New tables added in
// later phases must be appended below.
//
// Order matters: parents first on INSERT (the natural order below),
// children first on DELETE (we iterate in reverse). socks5_proxies
// is a parent of tunnels (tunnels.socks5_proxy_id references it) so
// it sits next to wireguard_configs ahead of tunnels.
var restoreTables = []string{
	"settings",
	"login_attempts",
	"wireguard_configs",
	"socks5_proxies",
	"tunnels",
	"audit_log",
}

// swapTablesFromBackup is the core of the restore path. Steps:
//
//  1. ATTACH the temp file as "src" on the running connection.
//  2. BEGIN IMMEDIATE so we hold the write lock for the entire swap.
//  3. For each table: DELETE FROM main.x, then INSERT INTO main.x
//     SELECT * FROM src.x.
//  4. Re-write the preserved admin row.
//  5. COMMIT, then DETACH (must be outside the transaction).
//
// Why no schema reapply here: openTempBackup + migrations.Apply already
// brought the uploaded file up to the running install's schema version,
// so every table referenced below exists with the same column shape on
// both sides.
func swapTablesFromBackup(ctx context.Context, db *sql.DB, srcPath string, preserved preservedAdmin) error {
	// `?` parameters aren't accepted in ATTACH; quote with SQLite
	// string-literal rules.
	quotedPath := "'" + strings.ReplaceAll(srcPath, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "ATTACH DATABASE "+quotedPath+" AS src"); err != nil {
		return fmt.Errorf("attach backup: %w", err)
	}
	// Best-effort detach happens at the end (and on every error path).
	detach := func() {
		if _, err := db.ExecContext(ctx, "DETACH DATABASE src"); err != nil {
			slog.Warn("restore: detach failed", "err", err)
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		detach()
		return fmt.Errorf("begin tx: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			_ = tx.Rollback()
		}
	}()

	// Drop child rows before parent rows so foreign keys can't reject
	// the DELETE. The slice itself goes parents-first; iterate in
	// reverse for the DELETE pass. Table names come from the
	// restoreTables literal — no user input.
	for i := len(restoreTables) - 1; i >= 0; i-- {
		t := restoreTables[i]
		stmt := "DELETE FROM main." + quoteIdent(t) //nolint:gosec // table name is from a whitelist
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			detach()
			return fmt.Errorf("clear %s: %w", t, err)
		}
	}

	// schema_version is special — we want the version that matches the
	// (post-migration) running schema. After migrations.Apply ran on the
	// temp file, schema_version in src already reflects the same set of
	// migrations as main, so the simplest correct rule is "replace
	// schema_version from src verbatim". We do the same DELETE+INSERT
	// dance as the domain tables.
	if _, err := tx.ExecContext(ctx, "DELETE FROM main.schema_version"); err != nil {
		detach()
		return fmt.Errorf("clear schema_version: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO main.schema_version (version, applied_at) SELECT version, applied_at FROM src.schema_version"); err != nil {
		detach()
		return fmt.Errorf("copy schema_version: %w", err)
	}

	// Copy the domain tables parents-first. We SELECT * which depends
	// on column order matching between main and src; openTempBackup +
	// migrations.Apply already aligned them.
	for _, t := range restoreTables {
		// Table names come from the restoreTables whitelist literal,
		// not request input.
		stmt := "INSERT INTO main." + quoteIdent(t) + " SELECT * FROM src." + quoteIdent(t) //nolint:gosec
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			detach()
			return fmt.Errorf("copy %s: %w", t, err)
		}
	}

	// admin is preserved end-to-end. We rewrite it from in-memory values
	// captured before the transaction. The CHECK (id = 1) constraint
	// means there is at most one row.
	if _, err := tx.ExecContext(ctx, "DELETE FROM main.admin"); err != nil {
		detach()
		return fmt.Errorf("clear admin for preservation: %w", err)
	}
	if preserved.username != "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO main.admin (id, username, password_hash, created_at, password_changed_at)
			 VALUES (1, ?, ?, ?, ?)`,
			preserved.username, preserved.passwordHash, preserved.createdAt, preserved.passwordChangedAt); err != nil {
			detach()
			return fmt.Errorf("restore preserved admin: %w", err)
		}
	} else {
		// No preserved admin (running DB had no row yet — unusual but
		// possible during early setup). Fall back to whatever the
		// backup carried.
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO main.admin (id, username, password_hash, created_at, password_changed_at) SELECT id, username, password_hash, created_at, password_changed_at FROM src.admin"); err != nil {
			detach()
			return fmt.Errorf("copy admin from backup: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		detach()
		return fmt.Errorf("commit swap: %w", err)
	}
	commit = true
	detach()
	return nil
}

// quoteIdent quotes a SQLite identifier (table or column name) with
// double quotes, doubling any embedded double quotes. None of the
// restoreTables literals carry special characters today, but quoting
// keeps the SQL machine-checkable if a future phase adds one.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// MountBackupRoutes installs the backup and restore endpoints under
// the supplied chi router. Caller is responsible for wrapping these
// routes in RequireAuth before calling.
//
// The routes live under /api/settings/* (e.g. /api/settings/backup,
// /api/settings/restore) — the router mounts them on the same prefix
// as SettingsHandler so the panel's "Settings → Backup" UI talks to
// one tidy namespace.
func MountBackupRoutes(r chi.Router, deps BackupRestoreDeps) {
	r.Get("/settings/backup", BackupHandler(deps))
	r.Post("/settings/restore", RestoreHandler(deps))
}
