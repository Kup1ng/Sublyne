package logging

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogBus_SnapshotPreservesOrder(t *testing.T) {
	bus := NewLogBus(4)
	for i := 0; i < 6; i++ {
		bus.Publish(LogEntry{Ts: time.Now().UTC().Format(time.RFC3339Nano), Level: "INFO", Msg: itoa(i)})
	}
	got := bus.Snapshot(0)
	if len(got) != 4 {
		t.Fatalf("expected 4 entries (capacity), got %d", len(got))
	}
	want := []string{"2", "3", "4", "5"}
	for i, e := range got {
		if e.Msg != want[i] {
			t.Errorf("position %d: got %q, want %q (full snapshot: %v)", i, e.Msg, want[i], got)
		}
	}
}

func TestLogBus_SnapshotLimit(t *testing.T) {
	bus := NewLogBus(8)
	for i := 0; i < 8; i++ {
		bus.Publish(LogEntry{Msg: itoa(i), Level: "INFO"})
	}
	got := bus.Snapshot(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	want := []string{"5", "6", "7"}
	for i, e := range got {
		if e.Msg != want[i] {
			t.Errorf("limit slice mismatch at %d: %q != %q", i, e.Msg, want[i])
		}
	}
}

func TestLogBus_Subscribe(t *testing.T) {
	bus := NewLogBus(0)
	ch := bus.Subscribe(2)
	bus.Publish(LogEntry{Msg: "first", Level: "INFO"})
	bus.Publish(LogEntry{Msg: "second", Level: "INFO"})
	select {
	case got := <-ch:
		if got.Msg != "first" {
			t.Errorf("first receive: %q", got.Msg)
		}
	case <-time.After(time.Second):
		t.Fatal("first publish did not arrive")
	}
	select {
	case got := <-ch:
		if got.Msg != "second" {
			t.Errorf("second receive: %q", got.Msg)
		}
	case <-time.After(time.Second):
		t.Fatal("second publish did not arrive")
	}
	bus.Unsubscribe(ch)
}

func TestLogBus_SlowConsumerDrops(t *testing.T) {
	bus := NewLogBus(0)
	ch := bus.Subscribe(1)
	defer bus.Unsubscribe(ch)
	bus.Publish(LogEntry{Msg: "a"})
	bus.Publish(LogEntry{Msg: "b"})
	bus.Publish(LogEntry{Msg: "c"})
	// We expect the last published entry to win; consumer never drained.
	got := <-ch
	if got.Msg == "" || got.Msg == "a" {
		t.Errorf("expected newer entry to win, got %q", got.Msg)
	}
}

func TestBusHandler_FlattensAttrsAndGroups(t *testing.T) {
	bus := NewLogBus(0)
	h := newBusHandler(bus, slog.LevelInfo)
	logger := slog.New(h.WithAttrs([]slog.Attr{slog.String("svc", "sublyne")}).WithGroup("auth"))
	logger.Info("login failed", "username", "admin", "ip", "1.2.3.4")

	snap := bus.Snapshot(0)
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap))
	}
	e := snap[0]
	if e.Msg != "login failed" {
		t.Errorf("msg %q", e.Msg)
	}
	if e.Fields["svc"] != "sublyne" {
		t.Errorf("svc attr missing: %+v", e.Fields)
	}
	if e.Fields["auth.username"] != "admin" {
		t.Errorf("expected auth.username=admin, got %v", e.Fields["auth.username"])
	}
	if e.Fields["auth.ip"] != "1.2.3.4" {
		t.Errorf("expected auth.ip=1.2.3.4, got %v", e.Fields["auth.ip"])
	}
}

func TestParseLevelRoundTrip(t *testing.T) {
	cases := []struct {
		in    string
		level slog.Level
		out   string
	}{
		{"trace", slog.LevelDebug - 4, "trace"},
		{"debug", slog.LevelDebug, "debug"},
		{"info", slog.LevelInfo, "info"},
		{"warn", slog.LevelWarn, "warn"},
		{"error", slog.LevelError, "error"},
		{"???", slog.LevelInfo, "info"},
	}
	for _, c := range cases {
		l := ParseLevel(c.in)
		if l != c.level {
			t.Errorf("ParseLevel(%q) = %v, want %v", c.in, l, c.level)
		}
		if got := LevelString(l); got != c.out {
			t.Errorf("LevelString(ParseLevel(%q)) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestBusHandler_HonorsLeveler(t *testing.T) {
	bus := NewLogBus(0)
	v := &slog.LevelVar{}
	v.Set(slog.LevelWarn)
	h := newBusHandler(bus, v)
	logger := slog.New(h)
	logger.Info("quiet info")
	logger.Warn("loud warn")
	snap := bus.Snapshot(0)
	if len(snap) != 1 || !strings.HasPrefix(snap[0].Msg, "loud") {
		t.Fatalf("expected only WARN, got %+v", snap)
	}
	// Verify Enabled() respects the level too.
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected DEBUG to be disabled when leveler=WARN")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	negative := false
	if i < 0 {
		negative = true
		i = -i
	}
	for i > 0 {
		buf = append([]byte{byte('0' + i%10)}, buf...)
		i /= 10
	}
	if negative {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
