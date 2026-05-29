package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// LogEntry is the JSON shape that ships to the panel — both via the
// /api/logs GET endpoint (recent buffer dump) and the WebSocket fanout
// (one frame per new line). Stable; the Logs page deserializes
// directly into this.
type LogEntry struct {
	// Ts is RFC3339 UTC. Easier for the Vue dashboard to parse than
	// a unix integer.
	Ts string `json:"ts"`
	// Level is one of "TRACE" / "DEBUG" / "INFO" / "WARN" / "ERROR"
	// uppercased so the panel filter can do a literal string compare.
	Level string `json:"level"`
	// Msg is the slog Record's Message — short, human-readable.
	Msg string `json:"msg"`
	// Fields holds the structured attrs, JSON-encoded. The frontend
	// pretty-prints them under each line on expand. We keep them as a
	// flat map (slog groups are flattened by dotted prefix in our
	// fanout, which already mirrors the file/stdout textual format).
	Fields map[string]any `json:"fields,omitempty"`
}

// LogBus is a tiny ring buffer + fanout used by the panel's Logs page.
// Two responsibilities:
//
//  1. Keep the last `capacity` entries in memory so a freshly-loaded
//     Logs page can render history without re-reading the rotating
//     file. The PRD-mandated rotation already trims the on-disk file
//     to the last 7 days; this in-memory buffer is just the short
//     "what happened in the last few minutes" view.
//
//  2. Fan every new entry out to every Subscribe()'d channel. The WS
//     handler subscribes once per dashboard tab and drops the oldest
//     queued line per subscriber when the consumer falls behind —
//     same backpressure policy as metrics.
//
// Capacity defaults to 2000 lines if the caller passes 0, which is
// roughly the last hour of typical traffic.
type LogBus struct {
	capacity int

	mu     sync.Mutex
	ring   []LogEntry
	head   int
	length int
	subs   []chan LogEntry
}

// NewLogBus returns a fresh bus with the supplied ring capacity. A
// capacity ≤ 0 defaults to 2000.
func NewLogBus(capacity int) *LogBus {
	if capacity <= 0 {
		capacity = 2000
	}
	return &LogBus{capacity: capacity, ring: make([]LogEntry, capacity)}
}

// Publish appends an entry to the ring and fans it out to subscribers.
// Subscribers that can't keep up have their oldest queued entry
// dropped to make room — the panel cares about the latest tail, not
// the perfect history, and a misbehaving WS client must never block
// the logger.
func (b *LogBus) Publish(e LogEntry) {
	if b == nil {
		return
	}
	b.mu.Lock()
	// Append to ring.
	b.ring[b.head] = e
	b.head = (b.head + 1) % b.capacity
	if b.length < b.capacity {
		b.length++
	}
	subs := append([]chan LogEntry(nil), b.subs...)
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e:
		default:
			// Slow consumer: drop the oldest queued entry then retry.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- e:
			default:
			}
		}
	}
}

// Snapshot returns a copy of the most recent entries in chronological
// order. Cheap (one slice allocation) and safe for the API handler's
// returned-to-user path because it copies the data out of the ring
// before releasing the lock.
//
// If limit ≤ 0, every retained entry is returned.
func (b *LogBus) Snapshot(limit int) []LogEntry {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	count := b.length
	if limit > 0 && limit < count {
		count = limit
	}
	out := make([]LogEntry, count)
	// Walk backwards from the head pointer to produce chronological
	// order. The ring stores in insertion order; head points at the
	// next write slot.
	start := (b.head - b.length + b.capacity) % b.capacity
	skip := b.length - count
	idx := (start + skip) % b.capacity
	for i := 0; i < count; i++ {
		out[i] = b.ring[idx]
		idx = (idx + 1) % b.capacity
	}
	return out
}

// Subscribe returns a channel that receives every future Publish. The
// channel is buffered (`buffer`, default 64) and is dropped-from on
// overflow as described above.
//
// Callers must Unsubscribe before discarding the channel; otherwise
// the bus retains a reference and slow-consumer drops accumulate.
func (b *LogBus) Subscribe(buffer int) <-chan LogEntry {
	if b == nil {
		return nil
	}
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan LogEntry, buffer)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a previously-subscribed channel and closes it.
// Idempotent.
func (b *LogBus) Unsubscribe(ch <-chan LogEntry) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, sub := range b.subs {
		if (<-chan LogEntry)(sub) == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(sub)
			return
		}
	}
}

// busHandler is a slog.Handler that converts every record into a
// LogEntry and forwards it to a LogBus. Wrapped alongside the stdout
// and file handlers inside the fanout so the bus sees everything the
// other sinks see.
//
// slog semantics: attrs added via WithAttrs *before* a WithGroup are
// rendered without the group prefix; attrs added after (or via the
// record itself) inherit every currently-open group. The handler
// stores already-prefixed attrs in preAttrs and tracks the currently-
// open groups in groups; Handle merges both onto the LogEntry.
type busHandler struct {
	bus      *LogBus
	level    slog.Leveler
	groups   []string
	preAttrs []renderedAttr
}

// renderedAttr holds an attribute whose key has already been
// qualified with the WithGroup prefix that was in effect when it was
// added. This decouples the WithAttrs-then-WithGroup ordering from
// the Handle-time render so we don't re-prefix attrs that should
// have stayed outside the group.
type renderedAttr struct {
	key   string
	value any
}

func newBusHandler(bus *LogBus, level slog.Leveler) *busHandler {
	return &busHandler{bus: bus, level: level}
}

func (h *busHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	if h.level == nil {
		return true
	}
	return lvl >= h.level.Level()
}

func (h *busHandler) Handle(_ context.Context, r slog.Record) error {
	if h.bus == nil {
		return nil
	}
	entry := LogEntry{
		Ts:    r.Time.UTC().Format(time.RFC3339Nano),
		Level: levelString(r.Level),
		Msg:   r.Message,
	}
	if len(h.preAttrs) > 0 || r.NumAttrs() > 0 {
		entry.Fields = make(map[string]any, len(h.preAttrs)+r.NumAttrs())
		for _, p := range h.preAttrs {
			entry.Fields[p.key] = p.value
		}
		r.Attrs(func(a slog.Attr) bool {
			addAttr(entry.Fields, h.groups, a)
			return true
		})
	}
	h.bus.Publish(entry)
	return nil
}

func (h *busHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	cp := *h
	// Resolve each new attr against the *current* group prefix; that
	// way a later WithGroup call doesn't retroactively shift it.
	cp.preAttrs = append([]renderedAttr(nil), h.preAttrs...)
	for _, a := range attrs {
		cp.preAttrs = appendRendered(cp.preAttrs, h.groups, a)
	}
	return &cp
}

func (h *busHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cp := *h
	cp.groups = append(append([]string(nil), h.groups...), name)
	return &cp
}

// addAttr flattens a single slog.Attr into a map under the running
// group path. Used at Handle time for the record's own attrs.
func addAttr(out map[string]any, groups []string, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	prefix := ""
	if len(groups) > 0 {
		prefix = stringJoin(groups, ".") + "."
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, sub := range a.Value.Group() {
			addAttr(out, append(append([]string(nil), groups...), a.Key), sub)
		}
		return
	}
	out[prefix+a.Key] = renderValue(a.Value)
}

// appendRendered resolves one attr (potentially a nested group attr)
// into one or more pre-rendered entries under the supplied group
// prefix.
func appendRendered(dst []renderedAttr, groups []string, a slog.Attr) []renderedAttr {
	if a.Equal(slog.Attr{}) {
		return dst
	}
	prefix := ""
	if len(groups) > 0 {
		prefix = stringJoin(groups, ".") + "."
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, sub := range a.Value.Group() {
			dst = appendRendered(dst, append(append([]string(nil), groups...), a.Key), sub)
		}
		return dst
	}
	return append(dst, renderedAttr{key: prefix + a.Key, value: renderValue(a.Value)})
}

// renderValue produces JSON-safe values from slog.Value. slog Records
// can carry any.Value, including durations and times that the panel
// shouldn't have to introspect.
func renderValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindAny:
		// Try to JSON-marshal the underlying value; fall back to a
		// stringified form on failure (panels can render anything).
		if b, err := json.Marshal(v.Any()); err == nil {
			var dest any
			if json.Unmarshal(b, &dest) == nil {
				return dest
			}
		}
		return v.String()
	default:
		return v.Any()
	}
}

// levelString turns slog levels into the uppercase strings the panel
// filter expects. slog has no native TRACE level — we collapse very-
// negative levels to TRACE so the filter UI can still distinguish.
func levelString(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug-4:
		return "TRACE"
	case l <= slog.LevelDebug:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO"
	case l < slog.LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

// stringJoin is a tiny implementation that avoids pulling in strings
// just for the bus handler. Mirrors strings.Join.
func stringJoin(parts []string, sep string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	n := len(sep) * (len(parts) - 1)
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, parts[0]...)
	for _, p := range parts[1:] {
		out = append(out, sep...)
		out = append(out, p...)
	}
	return string(out)
}

// ParseLevel converts a panel-supplied string into an slog.Level. Empty
// or unrecognised values return slog.LevelInfo. "trace" maps to
// slog.LevelDebug-4 so the bus handler tags it correctly while slog's
// own filtering still uses the closest standard level.
func ParseLevel(s string) slog.Level {
	switch s {
	case "trace", "TRACE":
		return slog.LevelDebug - 4
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "info", "INFO":
		return slog.LevelInfo
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// LevelString is the inverse of ParseLevel — given a level, return the
// lowercase name the panel expects in JSON payloads.
func LevelString(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug-4:
		return "trace"
	case l <= slog.LevelDebug:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// LevelInt is a fmt-helper exposed for tests / debugging that want to
// stringify a level as a signed integer.
func LevelInt(l slog.Level) string { return strconv.Itoa(int(l)) }
