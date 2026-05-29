// Package metrics implements the Phase 11 in-memory metrics ring
// buffer. The dataplane pushes a StatsReport every 5 s over IPC;
// `Recorder.Append` writes the event into a per-minute ring buffer
// covering the last 24 hours per tunnel and per system metric (PRD
// §5.2). The dashboard's WebSocket fan-out re-emits whatever the
// latest snapshot is, and the chart endpoint pulls the historical
// series.
//
// Memory budget: 24 h × 60 minutes = 1440 samples. Each sample is a
// PerTunnelStats plus a SystemStats — both small structs. At 10
// tunnels that's ~14k samples in RAM; well under any sensible budget.
//
// **Why per-minute, not per-5-seconds.** A 24-h ring at 5-s resolution
// is 17 280 entries; per-minute is 1440. The dashboard's charts can
// only show a few hundred points anyway (canvas pixels), so we
// downsample on write rather than on read. The latest sample inside
// the current minute is what the live view shows; the minute "bucket"
// gets the most-recent value when the next 5-s tick lands inside the
// same minute. Bandwidth is computed as a rate from successive bytes-
// counters so a single-bucket-per-minute granularity still gives an
// honest Mbps reading at 60-second resolution.
package metrics

import (
	"sync"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
)

// MaxSamples is the per-tunnel and per-system ring length: 24 hours at
// 1-minute resolution.
const MaxSamples = 24 * 60

// SampleInterval is the bucket size of the ring buffer. Samples that
// arrive inside the same bucket overwrite the previous value — by the
// time the next tick fires the bucket holds the most-recent observation
// inside that minute. PRD §5.2 mandates "per-minute samples".
const SampleInterval = time.Minute

// TunnelSample is one row in the per-tunnel ring buffer. It pairs a
// wall-clock timestamp (set when the Recorder ingested the StatsReport)
// with the dataplane's raw counters so the chart endpoint can compute
// deltas itself without us having to store a separate "delta" series.
type TunnelSample struct {
	At    time.Time          `json:"at"`
	Stats ipc.PerTunnelStats `json:"stats"`
}

// SystemSample is one row in the system ring buffer. Same shape as
// TunnelSample but with the host-wide block.
type SystemSample struct {
	At     time.Time       `json:"at"`
	System ipc.SystemStats `json:"system"`
}

// Snapshot is what the HTTP polling fallback / WebSocket "latest"
// frame serializes. The schema matches the on-wire StatsReport plus an
// added `at` field so the panel can show "last updated 3 s ago" without
// recomputing it.
type Snapshot struct {
	At      time.Time            `json:"at"`
	Samples []ipc.PerTunnelStats `json:"samples"`
	System  ipc.SystemStats      `json:"system"`
}

// HistoryResponse is the body returned by the chart polling endpoint.
// Per-tunnel and system slices are time-aligned: index 0 is the oldest
// sample, index N-1 the freshest. Missing minutes are simply absent
// (the chart code interpolates visually).
type HistoryResponse struct {
	Tunnels map[int64][]TunnelSample `json:"tunnels"`
	System  []SystemSample           `json:"system"`
}

// Recorder is the in-memory metrics store. Goroutine-safe.
type Recorder struct {
	mu      sync.RWMutex
	tunnels map[int64][]TunnelSample
	system  []SystemSample
	latest  Snapshot
	now     func() time.Time
}

// NewRecorder constructs an empty Recorder. The `now` knob lets unit
// tests inject a controlled clock; production callers pass nil and get
// `time.Now`.
func NewRecorder(now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{
		tunnels: make(map[int64][]TunnelSample),
		system:  make([]SystemSample, 0, 64),
		now:     now,
	}
}

// Append stores one report. Tunnels that disappeared from the dataplane
// (e.g. operator clicked Stop) are NOT pruned here — their historical
// data stays in the ring so the dashboard can render the last 24 h of a
// tunnel the operator just disabled. Stale series age out naturally as
// they fall off the back of the ring without further appends.
func (r *Recorder) Append(report ipc.StatsReport) {
	now := r.now()
	// Clone the "latest" sample slice OUTSIDE the lock — the slice copy
	// is the single most expensive op in this function (O(tunnel-count)
	// allocation) and there's no reason a Latest()/History() reader has
	// to wait on it. The per-tunnel/per-system appendToMinuteBucket calls
	// below are cheap (one or two slice ops each) and stay under the
	// write lock so concurrent readers see a consistent ring state.
	newLatest := Snapshot{
		At:      now,
		Samples: append([]ipc.PerTunnelStats(nil), report.Samples...),
		System:  report.System,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range report.Samples {
		series := r.tunnels[s.TunnelID]
		series = appendToMinuteBucket(series, TunnelSample{At: now, Stats: s}, now, sameTunnelMinute)
		r.tunnels[s.TunnelID] = series
	}
	r.system = appendToMinuteBucket(r.system, SystemSample{At: now, System: report.System}, now, sameSystemMinute)
	r.latest = newLatest
}

// Latest returns the most recently observed snapshot. Used by the
// polling fallback endpoint and by the WebSocket handler when a new
// client connects (so they get something before the next 5 s tick).
// Returns an empty Snapshot with a zero `At` if no reports have landed
// yet.
func (r *Recorder) Latest() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneSnapshot(r.latest)
}

// History returns the per-tunnel and system ring buffers.
func (r *Recorder) History() HistoryResponse {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tunnels := make(map[int64][]TunnelSample, len(r.tunnels))
	for id, series := range r.tunnels {
		tunnels[id] = append([]TunnelSample(nil), series...)
	}
	return HistoryResponse{
		Tunnels: tunnels,
		System:  append([]SystemSample(nil), r.system...),
	}
}

// Len returns the per-tunnel and system buffer lengths. Used by tests
// to assert eviction.
func (r *Recorder) Len(tunnelID int64) (perTunnel, system int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tunnels[tunnelID]), len(r.system)
}

// SubscribeIPC is a convenience helper that wires a Recorder up to an
// IPC client's StatsReport channel. Returns immediately; the goroutine
// runs until ctx is cancelled or the channel closes (the client
// reconnects on dataplane restart, so dropping the goroutine is the
// right response to channel close).
//
// Call this once per Client lifetime — typically right after the
// dataplane supervisor reports Ready.
func SubscribeIPC(stop <-chan struct{}, src <-chan ipc.StatsReport, sink *Recorder, watchers ...chan<- ipc.StatsReport) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case report, ok := <-src:
				if !ok {
					return
				}
				sink.Append(report)
				// Fan out to additional watchers (WebSocket clients,
				// metrics-broadcast bus, etc.). Slow watchers are
				// dropped — same policy as the IPC client itself.
				for _, w := range watchers {
					select {
					case w <- report:
					default:
					}
				}
			}
		}
	}()
}

// minuteKey is the storage key for the per-minute bucket. Wall-clock
// minutes are stable across system suspends — Time.Round(time.Minute)
// produces the same bucket for two samples 3 s apart even if one of
// them landed across an NTP step.
func minuteKey(t time.Time) time.Time {
	return t.Truncate(time.Minute)
}

func sameTunnelMinute(s TunnelSample, t time.Time) bool {
	return minuteKey(s.At).Equal(minuteKey(t))
}

func sameSystemMinute(s SystemSample, t time.Time) bool {
	return minuteKey(s.At).Equal(minuteKey(t))
}

// appendToMinuteBucket adds `sample` to `series`, overwriting the last
// entry if it belongs to the same wall-clock minute. After append the
// series is trimmed to MaxSamples by dropping its oldest entries.
func appendToMinuteBucket[T any](series []T, sample T, now time.Time, sameBucket func(T, time.Time) bool) []T {
	if n := len(series); n > 0 && sameBucket(series[n-1], now) {
		series[n-1] = sample
		return series
	}
	series = append(series, sample)
	if len(series) > MaxSamples {
		// Drop the oldest sample. We do this via a slice over the
		// existing backing array; the slice header tracks the new
		// length but the dropped element's memory stays until the
		// backing array gets reallocated (next time we exceed cap).
		// That's fine — the dropped entries are not referenced anywhere.
		series = series[len(series)-MaxSamples:]
	}
	return series
}

func cloneSnapshot(s Snapshot) Snapshot {
	out := Snapshot{
		At:     s.At,
		System: s.System,
	}
	if len(s.Samples) > 0 {
		out.Samples = append([]ipc.PerTunnelStats(nil), s.Samples...)
	}
	return out
}
