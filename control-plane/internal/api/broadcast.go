package api

import (
	"log/slog"
	"sync"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
)

// SnapshotRenderer converts one raw StatsReport into the bytes of a
// WebSocket "snapshot" frame. The bus invokes the renderer ONCE per
// Publish so N connected dashboards share a single render's worth of
// JSON-marshal + buildLiveSnapshot work, instead of paying N × that
// cost on every 5-s push. The renderer is set up after the
// MetricsDeps it depends on are built (a closure that captures the
// deps is the typical shape — see main.go and testdb_test.go).
type SnapshotRenderer func(ipc.StatsReport) ([]byte, error)

// Broadcast is a tiny one-to-many publish bus that fans every IPC
// StatsReport — pre-rendered into the WebSocket frame bytes — out to
// every connected dashboard. The IPC client already drops slow
// subscribers; we mirror that here so a stalled browser tab can't
// back-pressure the whole control plane.
//
// Concurrency model: a slice of channels protected by a mutex. The
// number of subscribers tops out at "open browser tabs", so we don't
// need anything fancier than O(n) per publish.
type Broadcast struct {
	mu     sync.Mutex
	subs   []chan []byte
	render SnapshotRenderer
	logger *slog.Logger
}

// NewBroadcast returns an empty bus. The renderer is nil at
// construction; call SetRenderer once the MetricsDeps are wired so the
// bus can start emitting actual frame bytes. While the renderer is
// nil, Publish is a no-op (subscribers receive nothing) — that lets
// tests that don't care about WS rendering still exercise
// subscribe/unsubscribe semantics without a fake renderer.
func NewBroadcast() *Broadcast {
	return &Broadcast{}
}

// SetRenderer installs the snapshot renderer the bus uses on every
// Publish. Safe to call after Subscribe — subscriber channels keep
// their identities across a SetRenderer call.
func (b *Broadcast) SetRenderer(render SnapshotRenderer, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.render = render
	b.logger = logger
}

// Subscribe returns a channel that receives every published rendered
// frame. `buffer` controls how many frames can queue before drops
// start; 4 is plenty given the 5-second cadence.
func (b *Broadcast) Subscribe(buffer int) <-chan []byte {
	if buffer < 1 {
		buffer = 4
	}
	ch := make(chan []byte, buffer)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a previously-subscribed channel. Idempotent:
// passing an unknown channel is a no-op. Close happens here so the
// caller doesn't have to worry about double-close races.
func (b *Broadcast) Unsubscribe(ch <-chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, sub := range b.subs {
		if (<-chan []byte)(sub) == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(sub)
			return
		}
	}
}

// Publish renders the report ONCE (under the renderer set via
// SetRenderer) and fans the resulting bytes out to every subscriber.
// Slow subscribers have their oldest queued frame dropped to make
// room — the dashboard always cares about the latest snapshot, never
// about an out-of-date one. If no renderer is set yet (early startup
// or test path), Publish silently drops.
func (b *Broadcast) Publish(report ipc.StatsReport) {
	b.mu.Lock()
	render := b.render
	logger := b.logger
	b.mu.Unlock()
	if render == nil {
		return
	}
	payload, err := render(report)
	if err != nil {
		if logger != nil {
			logger.Warn("ws: snapshot render failed", "err", err)
		}
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- payload:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- payload:
			default:
			}
		}
	}
}

// PublishChan is a convenience that lets the caller hand the IPC
// stats channel directly to a goroutine that pumps it into the bus.
// Used in main.go for the wiring between the IPC client and the
// dashboard.
func (b *Broadcast) PublishChan() chan<- ipc.StatsReport {
	ch := make(chan ipc.StatsReport, 16)
	go func() {
		for r := range ch {
			b.Publish(r)
		}
	}()
	return ch
}
