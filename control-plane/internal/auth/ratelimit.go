package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Brute-force defaults from PROJECT_REQUIREMENTS §4.2:
//   - 5 failed attempts within 5 minutes → 15-minute IP lockout.
//   - Global per-IP cap of 60 attempts/hour (success or failure).
//
// All three values are exposed so that Phase 15 can move them into
// the settings table for runtime tuning without changing the
// rate-limiter API.
const (
	DefaultLockoutThreshold = 5
	DefaultLockoutWindow    = 5 * time.Minute
	DefaultLockoutDuration  = 15 * time.Minute
	DefaultGlobalWindow     = time.Hour
	DefaultGlobalCap        = 60
)

// LockoutDecision describes what the rate limiter wants the caller to
// do for an incoming login. When Allowed is false the handler must
// stop before checking credentials and return 429 with RetryAfter as
// the Retry-After header.
type LockoutDecision struct {
	Allowed    bool
	Reason     string
	RetryAfter time.Duration
}

// Limiter is the login_attempts-backed brute-force gate. The state
// table is shared across processes (we run a single process today,
// but a future deployment with N workers behind a load balancer can
// add a database constraint without changing this API).
//
// Limiter is safe for concurrent use.
type Limiter struct {
	db     *sql.DB
	cfg    LimiterConfig
	now    func() time.Time
	logger *slog.Logger

	prunerOnce sync.Once
	prunerStop chan struct{}
}

// LimiterConfig is the runtime configuration of the rate limiter.
// New defaults to the PRD values.
type LimiterConfig struct {
	Threshold       int           // failures within Window that trigger a lockout
	Window          time.Duration // sliding window used to count failures
	LockoutDuration time.Duration // how long an IP stays locked after threshold
	GlobalWindow    time.Duration // global per-IP cap window (success + failure)
	GlobalCap       int           // attempts allowed in GlobalWindow per IP
	PruneInterval   time.Duration // how often the background pruner runs
	PruneOlderThan  time.Duration // pruner deletes rows older than this
}

// DefaultLimiterConfig returns the PRD-mandated configuration.
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		Threshold:       DefaultLockoutThreshold,
		Window:          DefaultLockoutWindow,
		LockoutDuration: DefaultLockoutDuration,
		GlobalWindow:    DefaultGlobalWindow,
		GlobalCap:       DefaultGlobalCap,
		PruneInterval:   10 * time.Minute,
		PruneOlderThan:  24 * time.Hour,
	}
}

// NewLimiter constructs a rate limiter. Pass now=nil for the
// production clock.
func NewLimiter(db *sql.DB, cfg LimiterConfig, now func() time.Time, logger *slog.Logger) *Limiter {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Limiter{
		db:         db,
		cfg:        cfg,
		now:        now,
		logger:     logger,
		prunerStop: make(chan struct{}),
	}
}

// Check decides whether the supplied IP is allowed to attempt a
// login right now. It does *not* record the attempt — call Record
// after the credential check, regardless of outcome.
//
// Check is intentionally cheap: it issues two indexed range scans
// against login_attempts. Under attack, the table is bounded by the
// pruner (24-hour retention) and the index on (ip, ts), so the cost
// stays flat as the attacker pounds the endpoint.
func (l *Limiter) Check(ctx context.Context, ip string) (LockoutDecision, error) {
	now := l.now()

	// Global cap first — it bounds resource use under a distributed
	// attempt-spray from a single source.
	globalSince := now.Add(-l.cfg.GlobalWindow).Unix()
	var globalCount int
	if err := l.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND ts >= ?`,
		ip, globalSince,
	).Scan(&globalCount); err != nil {
		return LockoutDecision{}, fmt.Errorf("auth: query global count: %w", err)
	}
	if globalCount >= l.cfg.GlobalCap {
		// Pick a retry-after that pushes the user past the oldest
		// in-window attempt; conservative fallback is GlobalWindow.
		var oldestTS int64
		err := l.db.QueryRowContext(ctx,
			`SELECT MIN(ts) FROM login_attempts WHERE ip = ? AND ts >= ?`,
			ip, globalSince,
		).Scan(&oldestTS)
		retryAfter := l.cfg.GlobalWindow
		if err == nil && oldestTS > 0 {
			if d := time.Until(time.Unix(oldestTS, 0).Add(l.cfg.GlobalWindow)); d > 0 {
				retryAfter = d
			}
		}
		return LockoutDecision{
			Allowed:    false,
			Reason:     "global rate cap exceeded",
			RetryAfter: retryAfter,
		}, nil
	}

	// Lockout detection. PRD §4.2: "Threshold failures within Window →
	// LockoutDuration lockout." The lockout must hold for the FULL
	// LockoutDuration measured from the triggering failure, EVEN AFTER the
	// failing rows age out of Window. Counting failures only inside Window
	// (the previous approach) let an attacker simply wait out the 5-minute
	// window and retry, making the effective lockout equal to Window (5
	// min) instead of LockoutDuration (15 min) — a brute-force bypass.
	//
	// So we look back over the whole LockoutDuration, pull the recent
	// failures (bounded by the global cap + 24 h pruner), and slide a
	// Window-wide frame over them: any frame holding Threshold failures
	// arms a lockout that lasts until that frame's Threshold-th failure +
	// LockoutDuration.
	lookbackSince := now.Add(-l.cfg.LockoutDuration).Unix()
	rows, err := l.db.QueryContext(ctx,
		`SELECT ts FROM login_attempts WHERE ip = ? AND success = 0 AND ts >= ? ORDER BY ts ASC`,
		ip, lookbackSince)
	if err != nil {
		return LockoutDecision{}, fmt.Errorf("auth: query failures: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var fails []int64
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return LockoutDecision{}, fmt.Errorf("auth: scan failure ts: %w", err)
		}
		fails = append(fails, ts)
	}
	if cerr := rows.Err(); cerr != nil {
		return LockoutDecision{}, fmt.Errorf("auth: iterate failures: %w", cerr)
	}

	windowSec := int64(l.cfg.Window / time.Second)
	durSec := int64(l.cfg.LockoutDuration / time.Second)
	var lockUntil int64
	for i := 0; i+l.cfg.Threshold-1 < len(fails); i++ {
		j := i + l.cfg.Threshold - 1
		if fails[j]-fails[i] <= windowSec {
			if u := fails[j] + durSec; u > lockUntil {
				lockUntil = u
			}
		}
	}
	if lockUntil > now.Unix() {
		return LockoutDecision{
			Allowed:    false,
			Reason:     "ip locked out after repeated failures",
			RetryAfter: time.Until(time.Unix(lockUntil, 0)),
		}, nil
	}

	return LockoutDecision{Allowed: true}, nil
}

// Record persists the outcome of a login attempt. success is true
// for a credential match, false otherwise. The IP comes from the
// caller (extracted from the request once, so the same value lands
// in audit logs).
func (l *Limiter) Record(ctx context.Context, ip string, success bool) error {
	successFlag := 0
	if success {
		successFlag = 1
	}
	_, err := l.db.ExecContext(ctx,
		`INSERT INTO login_attempts (ip, ts, success) VALUES (?, ?, ?)`,
		ip, l.now().Unix(), successFlag,
	)
	if err != nil {
		return fmt.Errorf("auth: record attempt: %w", err)
	}
	return nil
}

// StartPruner kicks off a background goroutine that drops login
// attempts older than PruneOlderThan every PruneInterval. It returns
// immediately. Call Stop on the limiter to halt the pruner before
// shutting down.
//
// Calling StartPruner more than once is a no-op.
func (l *Limiter) StartPruner(ctx context.Context) {
	l.prunerOnce.Do(func() {
		go l.prunerLoop(ctx)
	})
}

func (l *Limiter) prunerLoop(ctx context.Context) {
	t := time.NewTicker(l.cfg.PruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.prunerStop:
			return
		case <-t.C:
			cutoff := l.now().Add(-l.cfg.PruneOlderThan).Unix()
			if _, err := l.db.ExecContext(ctx,
				`DELETE FROM login_attempts WHERE ts < ?`,
				cutoff,
			); err != nil && !errors.Is(err, context.Canceled) {
				l.logger.Warn("ratelimit: prune", "err", err)
			}
		}
	}
}

// Stop terminates the background pruner. Safe to call even if the
// pruner never started.
func (l *Limiter) Stop() {
	select {
	case <-l.prunerStop:
		// already closed
	default:
		close(l.prunerStop)
	}
}
