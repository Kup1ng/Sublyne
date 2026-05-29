package tunnels

import (
	"context"
	"sync/atomic"
)

// Cache is a tiny in-process snapshot of the tunnel list, served to
// the dashboard hot path. It exists because pre-R3 every WS push and
// every panel request that needed the tunnel list re-ran the same
// `SELECT … FROM tunnels ORDER BY id` against SQLite — that query is
// cheap individually but on a busy dashboard the cumulative load is
// real (every WS subscriber, every 5 s, plus per-render handlers).
//
// Lifecycle: API handlers that mutate the tunnels table (Create,
// Update, Delete, SetEnabled, Import, Restore) must call Invalidate
// after the underlying Repo write succeeds. Reads served from the
// cached pointer are then re-populated on the next List call. The
// atomic.Pointer makes List lock-free in the cache-hit case.
//
// Concurrency: single-writer (the API mutation handler running per
// request) plus N concurrent readers (every WS push + every dashboard
// poll). Two concurrent first-fills could race; they both write the
// same snapshot bytes, so the winner-loser distinction is harmless.
type Cache struct {
	repo    *Repo
	current atomic.Pointer[[]Tunnel]
}

// NewCache wraps repo with the snapshot cache. The cache starts empty;
// the first List call populates it.
func NewCache(repo *Repo) *Cache {
	if repo == nil {
		return nil
	}
	return &Cache{repo: repo}
}

// List returns the cached snapshot if present, otherwise reloads from
// the underlying Repo and caches the result for subsequent calls.
// `ctx` is only used on the cache-miss path.
func (c *Cache) List(ctx context.Context) ([]Tunnel, error) {
	if c == nil {
		return nil, nil
	}
	if p := c.current.Load(); p != nil {
		return *p, nil
	}
	fresh, err := c.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	c.current.Store(&fresh)
	return fresh, nil
}

// Invalidate marks the cache as stale. Cheap (atomic store of nil);
// the next List call re-reads from the Repo. Safe to call from any
// goroutine; safe to call when the cache is empty.
func (c *Cache) Invalidate() {
	if c == nil {
		return
	}
	c.current.Store(nil)
}
