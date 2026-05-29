package logging

import (
	"log/slog"
	"sync/atomic"
)

// LevelControl owns a slog.LevelVar shared by every handler in the
// fanout, plus a callback the controller can fire to propagate level
// changes downstream (e.g. to the Rust dataplane via the IPC client).
//
// The PRD's "log level toggle from the panel" (§12) requires changes
// to take effect live in both the Go control plane AND the dataplane
// without restarting either. The level var handles the Go side
// (every text handler in the fanout reads it on every Enabled
// check). The on-change callback handles the dataplane side; main.go
// installs one that sends `SetLogLevel` over IPC.
//
// LevelControl is safe for concurrent use; both Set and Get are
// lock-free reads of the atomic level var, and the callback slot is
// guarded by an atomic.Value so installation is goroutine-safe.
type LevelControl struct {
	v        *slog.LevelVar
	callback atomic.Pointer[func(slog.Level)]
}

// NewLevelControl returns a control initialised to `initial`.
func NewLevelControl(initial slog.Level) *LevelControl {
	v := &slog.LevelVar{}
	v.Set(initial)
	return &LevelControl{v: v}
}

// LevelVar returns the underlying slog.LevelVar; handler constructors
// pass this to slog.HandlerOptions.Level so every record check goes
// through one shared value.
func (c *LevelControl) LevelVar() *slog.LevelVar {
	if c == nil {
		return nil
	}
	return c.v
}

// Get returns the current level. A nil receiver returns INFO so
// callers don't need to nil-check.
func (c *LevelControl) Get() slog.Level {
	if c == nil || c.v == nil {
		return slog.LevelInfo
	}
	return c.v.Level()
}

// Set switches the level and fires the on-change callback, if any.
// Safe to call from any goroutine.
func (c *LevelControl) Set(l slog.Level) {
	if c == nil || c.v == nil {
		return
	}
	c.v.Set(l)
	if cb := c.callback.Load(); cb != nil && *cb != nil {
		(*cb)(l)
	}
}

// OnChange installs (or replaces) the callback fired after every Set.
// Pass nil to clear.
func (c *LevelControl) OnChange(cb func(slog.Level)) {
	if c == nil {
		return
	}
	if cb == nil {
		c.callback.Store(nil)
		return
	}
	f := cb
	c.callback.Store(&f)
}
