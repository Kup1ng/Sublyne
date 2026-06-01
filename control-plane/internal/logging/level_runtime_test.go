package logging

import (
	"log/slog"
	"testing"
)

// msgInBus returns the first bus entry whose message equals msg.
func msgInBus(bus *LogBus, msg string) (LogEntry, bool) {
	for _, e := range bus.Snapshot(0) {
		if e.Msg == msg {
			return e, true
		}
	}
	return LogEntry{}, false
}

// TestRuntimeLevelChange_ReachesBus is the Go half of the end-to-end
// "set DEBUG → DEBUG lines surface" contract. The panel's Logs page reads
// from the LogBus; a Debug record must be dropped while the shared level is
// INFO and captured (tagged DEBUG) once an operator flips the level to
// DEBUG via the same LevelControl the PUT /api/settings/log-level handler
// mutates.
func TestRuntimeLevelChange_ReachesBus(t *testing.T) {
	control := NewLevelControl(slog.LevelInfo)
	bus := NewLogBus(0)
	// One bus handler wired to the shared LevelVar — exactly how
	// SetupDefaultLogger composes the fanout's bus sink.
	logger := slog.New(newBusHandler(bus, control.LevelVar()))

	logger.Debug("before-change")
	if _, ok := msgInBus(bus, "before-change"); ok {
		t.Fatalf("a DEBUG record must NOT reach the bus while the level is INFO")
	}

	// The PUT /api/settings/log-level handler calls exactly this.
	control.Set(slog.LevelDebug)

	logger.Debug("after-change")
	e, ok := msgInBus(bus, "after-change")
	if !ok {
		t.Fatalf("a DEBUG record must reach the bus after Set(DEBUG)")
	}
	if e.Level != "DEBUG" {
		t.Errorf("bus entry should be tagged DEBUG, got %q", e.Level)
	}
}

// TestRuntimeLevelChange_FiresOnChange proves Set fires the OnChange
// callback exactly once with the new level. main.go installs a callback
// there that pushes SetLogLevel to the Rust dataplane over IPC, so this
// guards the trigger for the dataplane half of the propagation.
func TestRuntimeLevelChange_FiresOnChange(t *testing.T) {
	control := NewLevelControl(slog.LevelInfo)
	var got slog.Level
	calls := 0
	control.OnChange(func(l slog.Level) {
		got = l
		calls++
	})

	control.Set(slog.LevelDebug)

	if calls != 1 {
		t.Fatalf("OnChange should fire exactly once per Set, fired %d", calls)
	}
	if got != slog.LevelDebug {
		t.Errorf("OnChange received level %v, want DEBUG", got)
	}
}
