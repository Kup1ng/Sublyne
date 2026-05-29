package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
)

// LogsDeps carries everything the Phase 12 logs/level/crash routes
// need. The router mounts these only when Bus is non-nil so unit
// tests that don't care about logs can leave the whole bundle zero.
type LogsDeps struct {
	// Bus is the in-memory ring buffer the panel reads from for both
	// the initial tail dump (GET /api/logs) and the WebSocket stream
	// (frames of type "log" pushed by the metrics WS handler).
	Bus *logging.LogBus

	// Level is the shared LevelControl. PUT /api/settings/log-level
	// calls Set on it; the bus, file, and stdout handlers all see the
	// change on the next record. main.go installs an OnChange callback
	// that propagates the change to the Rust dataplane via IPC.
	Level *logging.LevelControl

	// DB is used to persist the operator's runtime log-level choice in
	// the `settings` table under key "log_level_runtime". On the next
	// service restart main.go reads this value back so the choice
	// survives reboots without rewriting /etc/sublyne/config.toml.
	DB *sql.DB

	// Audit is the recorder where log_level_change and (eventually)
	// crash-report-viewing actions land. May be nil; the handlers
	// degrade gracefully by skipping the audit write.
	Audit *audit.Recorder

	// CrashDir is the directory the crash-report endpoints serve from.
	// Defaults to logging.CrashDir() (set by main from cfg.LogPath's
	// parent) when this field is empty.
	CrashDir string

	// FileSink lets tests force-rotate the app.log without writing
	// 10 MB of synthetic data. Production code never uses this — main
	// hands the sink in only so the test endpoint can fire Rotate().
	// Surfaced on Setup struct so an integration test can drive it.
	FileSink *lumberjack.Logger

	// Logger is the slog handle used for diagnostic emissions inside
	// the handlers themselves. Defaults to slog.Default().
	Logger *slog.Logger
}

// settingsKeyLogLevelRuntime is the key the runtime-changed log level
// is persisted under. Distinct from any read-only config-file echo so
// loading order is predictable: config TOML first, settings override
// second.
const settingsKeyLogLevelRuntime = "log_level_runtime"

func (d LogsDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// MountLogsRoutes installs every Phase 12 panel route onto the
// supplied subrouter. Caller wraps the parent group in RequireAuth.
//
//	/api/logs                       GET — recent in-memory tail
//	/api/audit                      GET — recent audit_log rows
//	/api/crash-reports              GET — list of crash files
//	/api/crash-reports/{filename}   GET — full body of one crash file
//	/api/settings/log-level         PUT — change live log level
//
// The Logs page subscribes to the existing /api/ws for the live
// stream; the new endpoints above handle the initial pre-seed plus
// crash-report exploration.
func MountLogsRoutes(r chi.Router, deps LogsDeps, auditDeps AuditDeps) {
	r.Get("/logs", ListLogsHandler(deps))
	r.Get("/crash-reports", ListCrashReportsHandler(deps))
	r.Get("/crash-reports/{filename}", GetCrashReportHandler(deps))
	r.Put("/settings/log-level", SetLogLevelHandler(deps))
	r.Get("/audit", ListAuditHandler(auditDeps))
}

// LogResponse is the shape returned by GET /api/logs. Keeps the
// frontend trivial: render `entries` chronologically; show the
// current `level` in the dropdown.
type LogResponse struct {
	Level   string             `json:"level"`
	Entries []logging.LogEntry `json:"entries"`
}

// ListLogsHandler returns the most recent log entries in the in-memory
// ring buffer. Query parameters:
//
//   - level=trace|debug|info|warn|error — client-side filter hint
//     (the bus stores every record, the panel filters in-browser to
//     keep the endpoint cheap).
//   - limit=N — cap on returned entries; default 500, max 2000.
//   - since=<RFC3339> — only return entries strictly newer than this
//     timestamp. Used by the panel to incrementally pull when the WS
//     misses a reconnect.
func ListLogsHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Bus == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "log bus not configured")
			return
		}
		limit := 500
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				if n > 2000 {
					n = 2000
				}
				limit = n
			}
		}
		var since time.Time
		if raw := r.URL.Query().Get("since"); raw != "" {
			if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				since = ts
			} else if ts, err := time.Parse(time.RFC3339, raw); err == nil {
				since = ts
			}
		}
		// Apply level filter server-side when the operator asked for it.
		// Cheaper than shipping the whole buffer to the panel and
		// trimming on the client.
		levelFilter := strings.ToUpper(r.URL.Query().Get("level"))
		entries := deps.Bus.Snapshot(0)
		filtered := make([]logging.LogEntry, 0, len(entries))
		for _, e := range entries {
			if !since.IsZero() {
				if ts, err := time.Parse(time.RFC3339Nano, e.Ts); err != nil {
					continue
				} else if !ts.After(since) {
					continue
				}
			}
			if levelFilter != "" && !levelAtLeast(e.Level, levelFilter) {
				continue
			}
			filtered = append(filtered, e)
		}
		if len(filtered) > limit {
			filtered = filtered[len(filtered)-limit:]
		}
		current := "info"
		if deps.Level != nil {
			current = logging.LevelString(deps.Level.Get())
		}
		writeJSON(w, http.StatusOK, LogResponse{Level: current, Entries: filtered})
	}
}

// levelAtLeast returns true when `entry` (e.g. "WARN") is at or above
// the operator's selected `min` (e.g. "INFO"). The Logs page filter
// behaves like the kernel's: "show me INFO and above".
func levelAtLeast(entry, min string) bool {
	order := map[string]int{"TRACE": 0, "DEBUG": 1, "INFO": 2, "WARN": 3, "ERROR": 4}
	e, ok1 := order[entry]
	m, ok2 := order[min]
	if !ok1 || !ok2 {
		return true
	}
	return e >= m
}

// ListCrashReportsHandler returns metadata for every crash-<ts>.log
// file under the configured crash dir.
func ListCrashReportsHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir := resolveCrashDir(deps)
		if dir == "" {
			writeJSON(w, http.StatusOK, map[string]any{"reports": []any{}})
			return
		}
		reports, err := logging.ListCrashReports(dir)
		if err != nil {
			deps.logger().Warn("crash-reports: list failed", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not list crash reports")
			return
		}
		if reports == nil {
			reports = []logging.CrashReport{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
	}
}

// GetCrashReportHandler returns the full body of one crash file.
//
// Content-Type is text/plain so the panel can either render it as
// preformatted text or save it via the browser's Save-As.
func GetCrashReportHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir := resolveCrashDir(deps)
		if dir == "" {
			writeJSONError(w, http.StatusNotFound, "crash reports unavailable")
			return
		}
		name := chi.URLParam(r, "filename")
		body, err := logging.ReadCrashReport(dir, name)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	}
}

func resolveCrashDir(deps LogsDeps) string {
	if deps.CrashDir != "" {
		return deps.CrashDir
	}
	return logging.CrashDir()
}

// setLogLevelRequest is the body the panel posts. `propagate=false`
// is reserved for future single-side toggles; today every change
// fires the OnChange callback unconditionally.
type setLogLevelRequest struct {
	Level string `json:"level"`
}

// setLogLevelResponse echoes back the now-active level so the panel
// doesn't have to re-fetch /api/settings.
type setLogLevelResponse struct {
	Level string `json:"level"`
}

// SetLogLevelHandler changes the running service's log verbosity
// (both Go and the Rust dataplane via the LevelControl OnChange hook)
// and persists the choice to the settings table.
//
// The handler accepts only the five PRD-listed levels. Unknown values
// return 400 with a clear message so a typo from the panel surfaces
// loudly. Audit emission is best-effort.
func SetLogLevelHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Level == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "log control not configured")
			return
		}
		var body setLogLevelRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		level := strings.ToLower(strings.TrimSpace(body.Level))
		if !validLevel(level) {
			writeJSONError(w, http.StatusBadRequest, "level must be one of trace, debug, info, warn, error")
			return
		}
		previous := logging.LevelString(deps.Level.Get())
		deps.Level.Set(logging.ParseLevel(level))

		// Persist so the operator's choice survives a service restart.
		// Failure here is non-fatal: the live runtime is already
		// changed, and the worst case is the level reverts on next
		// boot — which the operator can re-toggle.
		if deps.DB != nil {
			if err := upsertSetting(r.Context(), deps.DB, settingsKeyLogLevelRuntime, level); err != nil {
				deps.logger().Warn("log-level: persist failed (live change still applied)",
					"err", err)
			}
		}
		actor := audit.ActorAdmin
		if admin, ok := AdminFromContext(r.Context()); ok {
			actor = admin.Username
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionLogLevelChange, actor, ClientIP(r), "log_level", map[string]any{
				"previous": previous,
				"new":      level,
			})
		}
		writeJSON(w, http.StatusOK, setLogLevelResponse{Level: level})
	}
}

func validLevel(s string) bool {
	switch s {
	case "trace", "debug", "info", "warn", "error":
		return true
	}
	return false
}

// upsertSetting writes a settings row. Mirrors the helper in the auth
// package; we inline rather than export to keep package boundaries
// clean.
func upsertSetting(ctx context.Context, db *sql.DB, key, value string) error {
	if db == nil {
		return errors.New("settings: nil db")
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO settings (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value)
	return err
}

// ReadRuntimeLogLevel returns the persisted runtime log level from the
// settings table, or "" if absent. Exported so main.go can layer it
// on top of the config-file default at startup.
func ReadRuntimeLogLevel(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return ""
	}
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, settingsKeyLogLevelRuntime).Scan(&v)
	if err != nil {
		return ""
	}
	return v
}
