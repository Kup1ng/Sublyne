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
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
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
	// ServerRole is this box's configured role (client/remote). Restore
	// rejects a backup whose tunnels were authored for the other role,
	// since a box hosts exactly one role and starting cross-role tunnels
	// would mis-bind listeners and confuse the operator. Empty disables
	// the check (used by older tests that don't wire a role).
	ServerRole tunnels.Role
	// Level, when set, is re-applied from the restored DB's
	// log_level_runtime row after a successful restore so the live
	// process (and, via its OnChange hook, the Rust dataplane) tracks the
	// log level the backup carried instead of silently diverging until
	// the next service restart. May be nil.
	Level *logging.LevelControl
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

// panelIdentitySettingKeys names the `settings` rows that identify THIS
// box's panel + login and must therefore NEVER travel inside a backup
// nor overwrite the target box on restore. Everything else in
// `settings` — the tunable_* performance knobs and log_level_runtime —
// is portable operator tunnel work and rides along with a backup as the
// operator expects.
//
// v3.0.0 contract: a backup moves the operator's tunnels + resources to
// another panel WITHOUT touching that panel's login or addressing.
//   - jwt_signing_key is the load-bearing one. If a backup carried it,
//     restoring CLIENT-1's backup onto CLIENT-2 would make CLIENT-2
//     validate session cookies with CLIENT-1's key — cross-box session
//     survival, exactly what the contract forbids.
//   - panel_port / web_path / role live in /etc/sublyne/config.toml
//     today (so the file-only DB swap already preserves them), but the
//     0001 schema reserves settings rows for them, so we exclude them
//     here too as belt-and-braces against a future phase persisting an
//     override into the DB.
//
// Keep jwt_signing_key in sync with auth.settingsKeyJWTSigningKey.
var panelIdentitySettingKeys = []string{
	"jwt_signing_key",
	"panel_port",
	"web_path",
	"role",
}

// settingsKeyPlaceholders builds the "?,?,?,…" placeholder list and the
// matching []any args for panelIdentitySettingKeys, so the IN / NOT IN
// filters bind the keys instead of splicing them into SQL.
func settingsKeyPlaceholders() (string, []any) {
	ph := make([]byte, 0, len(panelIdentitySettingKeys)*2)
	args := make([]any, len(panelIdentitySettingKeys))
	for i, k := range panelIdentitySettingKeys {
		if i > 0 {
			ph = append(ph, ',')
		}
		ph = append(ph, '?')
		args[i] = k
	}
	return string(ph), args
}

// scrubBackupSnapshot strips this box's panel identity + live login
// state out of a VACUUM INTO snapshot before it streams to the operator,
// then VACUUMs so the freed pages — which physically still hold the
// secret bytes — are dropped from the file rather than merely marked
// reusable. A backup must carry the operator's tunnels + resources, but
// NEVER the admin credentials, the JWT signing key, or the brute-force
// lockout counters.
//
// journal_mode=DELETE (not WAL) keeps the snapshot a single self-
// contained file with no -wal/-shm sidecars to clean up after.
func scrubBackupSnapshot(ctx context.Context, snapPath string) error {
	dsn := "file:" + snapPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open snapshot for scrub: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "DELETE FROM admin"); err != nil {
		return fmt.Errorf("scrub admin: %w", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM login_attempts"); err != nil {
		return fmt.Errorf("scrub login_attempts: %w", err)
	}
	ph, args := settingsKeyPlaceholders()
	// The interpolated part is only literal "?" placeholders; the keys
	// themselves are bound as args, so there is no injection surface.
	delIdentity := "DELETE FROM settings WHERE key IN (" + ph + ")" //nolint:gosec // placeholders only, keys bound as args
	if _, err := db.ExecContext(ctx, delIdentity, args...); err != nil {
		return fmt.Errorf("scrub panel-identity settings: %w", err)
	}
	// VACUUM rewrites the file from scratch so the deleted secret bytes
	// are gone, not just unlinked from the b-tree.
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("compact scrubbed snapshot: %w", err)
	}
	return nil
}

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
		defer func() {
			_ = os.Remove(snapPath)
			// Defensive: scrubBackupSnapshot uses journal_mode=DELETE so
			// these shouldn't exist, but remove any sidecars just in case a
			// future change reintroduces WAL.
			_ = os.Remove(snapPath + "-wal")
			_ = os.Remove(snapPath + "-shm")
			_ = os.Remove(snapPath + "-journal")
		}()

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

		// Strip this box's panel identity (admin creds, JWT signing key,
		// lockout state) out of the snapshot BEFORE we size or stream it,
		// so Content-Length matches the bytes we actually send and the
		// secret bytes are physically gone from the file.
		if err := scrubBackupSnapshot(r.Context(), snapPath); err != nil {
			deps.logger().Error("backup: scrub snapshot", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not prepare backup")
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
// PRD §4.4 / v3.0.0 contract: a restore brings the operator's tunnels
// and resources onto another panel but NEVER overwrites that panel's
// own login or addressing. Concretely, the following are preserved from
// the *running* DB rather than taken from the backup:
//   - the admin row (username + Argon2id password hash);
//   - the JWT signing key and the other panel-identity settings rows
//     (see panelIdentitySettingKeys) — so old sessions from the box the
//     backup came from can never validate here, and the operator on
//     THIS box stays logged in across the restore;
//   - panel port + web path, which live in /etc/sublyne/config.toml
//     (not SQLite) and so survive the file-only DB swap for free.
//
// Everything else — tunnels, WireGuard configs, SOCKS5 proxies,
// per-tunnel settings, the performance tunables, and the runtime log
// level — is the operator's portable work and is replaced from the
// backup.
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
//     up against the restored tunnel rows. We capture the pre-restore
//     tunnel set first so that, if the swap fails, we can restart the
//     exact tunnels that were running and return the box to its prior
//     working state (the transaction rolls back, so the DB is unchanged).
//  6. ATTACH the temp DB and DELETE+INSERT every domain table from it.
//  7. Re-write the preserved admin row.
//  8. DETACH the temp DB.
//  9. Re-sync the dataplane from the restored DB.
//  10. Return 200 with counts. The JWT signing key is preserved from the
//     running box, so the operator's current session stays valid and
//     they are NOT logged out by the restore.
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

		// Reject a backup created by a NEWER Sublyne build BEFORE we tear
		// anything down. migrations.Apply only moves forward, so a backup
		// whose schema_version exceeds this binary's highest embedded
		// migration would otherwise be a no-op here and then either fail
		// deep in the table swap with a cryptic SQLite column-count error
		// (after the box is already dark) or, worse, succeed and stamp the
		// live DB with a version that makes this binary skip its own
		// migrations forever.
		backupVer, verr := maxSchemaVersion(r.Context(), tempDB)
		if verr != nil {
			_ = tempDB.Close()
			writeJSONError(w, http.StatusBadRequest, "could not read the backup's schema version: "+verr.Error())
			return
		}
		if head := migrations.MaxEmbeddedVersion(); backupVer > head {
			_ = tempDB.Close()
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf(
				"this backup was created by a newer version of Sublyne (database schema v%d; this server supports up to v%d). Upgrade this server before restoring.",
				backupVer, head))
			return
		}

		if err := migrations.Apply(r.Context(), tempDB); err != nil {
			_ = tempDB.Close()
			deps.logger().Error("restore: migrate temp DB", "err", err)
			writeJSONError(w, http.StatusBadRequest, "could not bring the uploaded backup up to the current schema: "+err.Error())
			return
		}

		// Refuse a cross-role backup before any teardown: a box hosts
		// exactly one role, so importing the other role's tunnels would
		// mis-bind listeners and surface a pile of confusing start
		// failures. The check is skipped when ServerRole is unset.
		if deps.ServerRole != "" {
			mismatch, foreign, merr := backupHasForeignRole(r.Context(), tempDB, deps.ServerRole)
			if merr != nil {
				deps.logger().Warn("restore: role check failed (continuing)", "err", merr)
			} else if mismatch {
				_ = tempDB.Close()
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf(
					"this backup was taken on a %q server; this one is configured as %q. Restore it on a matching box.",
					foreign, deps.ServerRole))
				return
			}
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
		//
		// On failure the transaction inside swapTablesFromBackup rolls
		// back, so the running DB still holds the ORIGINAL config. But we
		// already stopped every previously-running tunnel above, so the
		// box is now fully dark even though its on-disk state is
		// unchanged. Bring the original set back up from the unchanged DB
		// so a mid-restore error returns the box to its prior working
		// state instead of leaving a healthy install dead.
		if err := swapTablesFromBackup(r.Context(), deps.DB, tmpPath, preserved); err != nil {
			deps.logger().Error("restore: table swap", "err", err)
			recovered := startEnabledTunnels(r.Context(), deps, runningBefore)
			if recovered < countEnabled(runningBefore) {
				// At least one tunnel that was running before the restore
				// did not come back. The DB is still the original, so the
				// operator can retry, but flag the degraded state. No
				// secrets: only counts and IDs are logged by the helper.
				deps.logger().Error("restore: swap failed and not all prior tunnels restarted",
					"restarted", recovered, "were_running", countEnabled(runningBefore))
			} else {
				deps.logger().Warn("restore: swap failed; prior tunnels restarted from unchanged DB",
					"restarted", recovered)
			}
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

		// Re-apply the restored runtime log level so the live process — and
		// the Rust dataplane via the LevelControl OnChange hook — tracks the
		// level the backup carried instead of silently diverging until the
		// next service restart.
		if deps.Level != nil {
			if lvl := ReadRuntimeLogLevel(r.Context(), deps.DB); lvl != "" {
				deps.Level.Set(logging.ParseLevel(lvl))
			}
		}

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

// maxSchemaVersion returns the highest version recorded in the supplied
// DB's schema_version table (0 if empty). Used to reject a backup taken
// under a newer Sublyne build before any teardown happens.
func maxSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// backupHasForeignRole reports whether the uploaded backup contains any
// tunnel whose role differs from this server's role. A box hosts exactly
// one role, so a Client backup on a Remote box (or vice versa) is a
// restore-on-the-wrong-machine mistake we reject up front rather than
// importing tunnels that can never start here.
func backupHasForeignRole(ctx context.Context, db *sql.DB, want tunnels.Role) (bool, tunnels.Role, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT role FROM tunnels`)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return false, "", err
		}
		if role != "" && tunnels.Role(role) != want {
			return true, tunnels.Role(role), nil
		}
	}
	return false, "", rows.Err()
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

// countEnabled returns how many tunnels in the slice are enabled. The
// restore failure path uses it to tell "all prior tunnels came back"
// apart from "the box is degraded" without re-deriving the set.
func countEnabled(ts []tunnels.Tunnel) int {
	n := 0
	for _, t := range ts {
		if t.Enabled {
			n++
		}
	}
	return n
}

// startEnabledTunnels reproduces the per-row Start sequence (WG Up +
// Dataplane Start) for every enabled tunnel in the restored DB. Returns
// how many actually started successfully; failures are logged but not
// counted, so the JSON response gives the operator an honest "how
// many of these are forwarding right now" number.
//
// It is also reused on the restore FAILURE path to restart the
// previously-running tunnels from the unchanged (original) DB. Because
// it resolves WG / SOCKS5 config per row at call time, feeding it the
// pre-restore tunnel slice brings the box back to its prior state.
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
//
// login_attempts is deliberately NOT in this list. It holds the live
// brute-force lockout state (failed-login counters and IP lockouts).
// Copying it from the backup would re-import whatever stale lockout
// state the snapshot happened to capture and could lock the operator
// out of the panel immediately after a restore. The swap iterates
// this slice symmetrically (DELETE in reverse, INSERT forward), so
// dropping the entry leaves the live login_attempts table untouched
// rather than half-swapped.
//
// `settings` is ALSO not in this list — it gets bespoke handling in
// swapTablesFromBackup (copy the operator's portable tunable_* /
// log_level_runtime rows, but never the panel-identity keys; see
// panelIdentitySettingKeys). It has no foreign-key ties, so handling it
// outside this ordered slice is safe.
//
// `audit_log` is ALSO deliberately excluded (v3.0.0). It is per-box
// forensic state — who logged in here, from which IP, when. Swapping it
// in from a backup would erase THIS box's login/operational trail and
// stamp another box's IPs and timestamps onto it as if they happened
// locally. Like login_attempts, it stays untouched by a restore: the
// live box keeps its own audit history (including the restore event
// itself, recorded just below).
var restoreTables = []string{
	"wireguard_configs",
	"socks5_proxies",
	"tunnels",
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

	// settings is the one mixed table: the operator's PORTABLE tunnel
	// work (tunable_* perf knobs + log_level_runtime) sits next to THIS
	// box's panel identity (jwt_signing_key + the panel_port/web_path/
	// role reserves). Copy only the portable rows from the backup and
	// never touch the target's identity rows. Effect:
	//   - restoring CLIENT-1's backup onto CLIENT-2 imports CLIENT-1's
	//     tunables but keeps CLIENT-2's own JWT key (so CLIENT-1's
	//     sessions can't validate on CLIENT-2, and CLIENT-2's operator
	//     stays logged in);
	//   - a legacy v2.x backup that still carries jwt_signing_key is
	//     silently ignored by the same NOT IN filter (per the v3.0.0
	//     contract: don't fail, just don't apply it).
	settingsPH, settingsArgs := settingsKeyPlaceholders()
	// The interpolated part is only literal "?" placeholders; the keys are
	// bound as args, so there is no injection surface.
	clearPortable := "DELETE FROM main.settings WHERE key NOT IN (" + settingsPH + ")"                                                                         //nolint:gosec // placeholders only, keys bound as args
	copyPortable := "INSERT INTO main.settings (key, value, updated_at) SELECT key, value, updated_at FROM src.settings WHERE key NOT IN (" + settingsPH + ")" //nolint:gosec // placeholders only, keys bound as args
	if _, err := tx.ExecContext(ctx, clearPortable, settingsArgs...); err != nil {
		detach()
		return fmt.Errorf("clear portable settings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, copyPortable, settingsArgs...); err != nil {
		detach()
		return fmt.Errorf("copy portable settings: %w", err)
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
