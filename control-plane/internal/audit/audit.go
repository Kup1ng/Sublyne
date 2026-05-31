// Package audit records admin actions (PRD §4.2 / §4.3) and surfaces
// the recent history to the panel's Audit page.
//
// The table is populated by helpers called from each protected
// handler — login success/failure, logout, tunnel CRUD + start/stop,
// WireGuard config CRUD, settings changes (password + log level),
// and the backup/restore endpoints. A background pruner runs every
// hour and drops rows older than 7 days so the table doesn't grow
// without bound.
//
// Recording is best-effort: a failure to persist an audit row never
// fails the underlying admin action. The operator's intent matters
// more than the record-keeping.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Retention bounds the audit table. PRD §4.3 pins it at 7 days; we
// expose the constant so the pruner test can override it.
const Retention = 7 * 24 * time.Hour

// Stable action codes. Strings are persisted so renaming requires a
// migration. New actions go at the end of this block. The Audit page
// renders them via a friendly-name map on the frontend.
const (
	ActionLoginSuccess      = "login_success"
	ActionLoginFailure      = "login_failure"
	ActionLogout            = "logout"
	ActionPasswordChange    = "password_change"
	ActionLogLevelChange    = "log_level_change"
	ActionTunnelCreate      = "tunnel_create"
	ActionTunnelUpdate      = "tunnel_update"
	ActionTunnelDelete      = "tunnel_delete"
	ActionTunnelStart       = "tunnel_start"
	ActionTunnelStop        = "tunnel_stop"
	ActionTunnelImport      = "tunnel_import"
	ActionTunnelExport      = "tunnel_export"
	ActionWGConfigCreate    = "wg_config_create"
	ActionWGConfigUpdate    = "wg_config_update"
	ActionWGConfigDelete    = "wg_config_delete"
	ActionSocks5ProxyCreate = "socks5_proxy_create"
	ActionSocks5ProxyUpdate = "socks5_proxy_update"
	ActionSocks5ProxyDelete = "socks5_proxy_delete"
	ActionBackupDownload    = "backup_download"
	ActionRestoreUpload     = "restore_upload"
	ActionCrashRecovered    = "crash_recovered"
	ActionTunnelClone       = "tunnel_clone"
)

// ActorAdmin is the actor string for actions performed by the single
// admin user. ActorSystem is used for things the service did on its
// own (background pruner, crash recovery).
const (
	ActorAdmin  = "admin"
	ActorSystem = "system"
)

// Entry mirrors one row of audit_log. Returned by List for the panel.
type Entry struct {
	ID      int64     `json:"id"`
	Ts      time.Time `json:"ts"`
	Action  string    `json:"action"`
	Actor   string    `json:"actor"`
	IP      string    `json:"ip"`
	Target  string    `json:"target"`
	Details string    `json:"details"`
}

// Recorder writes audit_log rows. Holds a reference to the DB plus an
// optional logger so a write failure surfaces in journald.
//
// All public methods are safe for concurrent use — the underlying *sql.DB
// is already concurrent-safe and we don't keep any in-memory state.
type Recorder struct {
	db     *sql.DB
	logger *slog.Logger

	// pruneInterval lets tests run the pruner on a tight loop without
	// editing the const. Defaults to 1 h in production.
	pruneInterval time.Duration

	// retention lets tests shorten the retention window so the prune
	// path can be exercised against rows that wouldn't otherwise be
	// stale. Defaults to Retention.
	retention time.Duration

	// now lets tests freeze the clock. Defaults to time.Now.
	now func() time.Time

	// stopOnce guards Close so callers can defer it without worrying
	// about double-closes from teardown races.
	stopOnce sync.Once
	stop     chan struct{}
}

// Option mutates a Recorder during construction. The exported
// configuration knobs are intentionally minimal — Recorder's defaults
// fit production; tests use these to compress time.
type Option func(*Recorder)

// WithLogger overrides the default slog.Default() destination. Use this
// when you want audit-write failures to land on a test logger.
func WithLogger(l *slog.Logger) Option {
	return func(r *Recorder) { r.logger = l }
}

// WithPruneInterval overrides the prune cadence. Production uses 1 h.
func WithPruneInterval(d time.Duration) Option {
	return func(r *Recorder) {
		if d > 0 {
			r.pruneInterval = d
		}
	}
}

// WithRetention overrides the row max age. Production uses Retention
// (7 days).
func WithRetention(d time.Duration) Option {
	return func(r *Recorder) {
		if d > 0 {
			r.retention = d
		}
	}
}

// WithClock injects a deterministic time source for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Recorder) {
		if now != nil {
			r.now = now
		}
	}
}

// NewRecorder builds a Recorder bound to db.
func NewRecorder(db *sql.DB, opts ...Option) *Recorder {
	r := &Recorder{
		db:            db,
		logger:        slog.Default(),
		pruneInterval: time.Hour,
		retention:     Retention,
		now:           time.Now,
		stop:          make(chan struct{}),
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}
	return r
}

// auditWriteTimeout bounds how long an audit DB insert is allowed to
// take. Used for the detached write context — short enough to bound a
// wedged DB, long enough that a normal SQLite write never trips it.
const auditWriteTimeout = 5 * time.Second

// Record inserts a single audit_log row.
//
// Why this signature: the caller owns the action + target strings, and
// passes a map[string]any for details. The map is JSON-encoded with
// an explicit allow-list of keys per call site — no struct introspection,
// so a PSK can't sneak in via a forgotten field.
//
// A nil details map is encoded as the empty object `{}` so SELECTs
// always get back valid JSON.
//
// A nil Recorder is a no-op so handlers that didn't get one wired
// (dev builds, tests) don't have to nil-check.
//
// The DB write itself runs on a context that inherits values from `ctx`
// but ignores its cancellation: the audited action already happened
// (a tunnel was started, a login succeeded), so a client that closed
// the HTTP connection mid-response shouldn't make the action invisible
// in the audit log. Without this detach the log was riddled with
// benign "audit: insert failed err=context canceled" lines on every
// healthcheck poll the panel made.
func (r *Recorder) Record(ctx context.Context, action, actor, ip, target string, details map[string]any) {
	if r == nil || r.db == nil {
		return
	}
	body := []byte("{}")
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err != nil {
			r.logger.Warn("audit: marshal details failed (recording without context)",
				"action", action, "err", err)
		} else {
			body = b
		}
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if _, err := r.db.ExecContext(writeCtx,
		`INSERT INTO audit_log (ts, action, actor, ip, target, details)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.now().Unix(), action, actor, ip, target, string(body)); err != nil {
		// Audit failures must not break the underlying flow. We log
		// loudly so the operator can fix the disk-full / corrupted-DB
		// case offline.
		r.logger.Warn("audit: insert failed",
			"action", action, "actor", actor, "target", target, "err", err)
	}
}

// List returns the most recent entries newer than `since` (zero =
// unbounded), capped at `limit` (zero → 200, max 1000).
//
// Entries are ordered newest-first so the panel can paginate from the
// top without keeping a cursor.
func (r *Recorder) List(ctx context.Context, since time.Time, limit int) ([]Entry, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("audit: recorder not configured")
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case since.IsZero():
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, ts, action, actor, ip, target, details
			 FROM audit_log
			 ORDER BY ts DESC, id DESC
			 LIMIT ?`, limit)
	default:
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, ts, action, actor, ip, target, details
			 FROM audit_log
			 WHERE ts >= ?
			 ORDER BY ts DESC, id DESC
			 LIMIT ?`, since.Unix(), limit)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.Actor, &e.IP, &e.Target, &e.Details); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		e.Ts = time.Unix(ts, 0).UTC()
		if strings.TrimSpace(e.Details) == "" {
			e.Details = "{}"
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rows: %w", err)
	}
	return out, nil
}

// Prune deletes rows older than r.retention. Returns the number of rows
// removed. Safe to call from a background goroutine.
func (r *Recorder) Prune(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("audit: recorder not configured")
	}
	cutoff := r.now().Add(-r.retention).Unix()
	res, err := r.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("audit: prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// StartPruner runs Prune every pruneInterval until ctx is cancelled or
// Close is called. Errors are logged at WARN — the audit log filling
// disk is bad, but crashing the service over it is worse.
//
// The initial sweep runs at startup (modulo a one-second jitter) so a
// long-running install doesn't accumulate a tail before the first tick.
func (r *Recorder) StartPruner(ctx context.Context) {
	if r == nil || r.db == nil {
		return
	}
	go func() {
		// One-shot at startup. Even on a brand-new DB this is cheap.
		if n, err := r.Prune(ctx); err != nil {
			r.logger.Warn("audit: initial prune failed", "err", err)
		} else if n > 0 {
			r.logger.Info("audit: pruned old entries on startup", "removed", n)
		}
		ticker := time.NewTicker(r.pruneInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stop:
				return
			case <-ticker.C:
				if n, err := r.Prune(ctx); err != nil {
					r.logger.Warn("audit: prune failed", "err", err)
				} else if n > 0 {
					r.logger.Debug("audit: pruned old entries", "removed", n)
				}
			}
		}
	}()
}

// Close stops the background pruner. Idempotent.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stop) })
}
