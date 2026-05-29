package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupDefaultLogger_DualSink(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	var stdoutBuf bytes.Buffer
	setup, err := SetupDefaultLogger(&stdoutBuf, slog.LevelInfo, DefaultFileSinkConfig(logPath), FormatText)
	if err != nil {
		t.Fatalf("SetupDefaultLogger: %v", err)
	}
	if setup == nil {
		t.Fatal("expected non-nil setup")
	}
	if setup.Closer == nil {
		t.Fatal("expected non-nil closer when file sink is configured")
	}
	if setup.Level == nil {
		t.Fatal("expected non-nil LevelControl")
	}
	if setup.Bus == nil {
		t.Fatal("expected non-nil LogBus")
	}
	t.Cleanup(func() { _ = setup.Closer.Close() })

	slog.Info("hello world", "k", "v")

	if !strings.Contains(stdoutBuf.String(), "hello world") {
		t.Errorf("stdout sink missing record; got %q", stdoutBuf.String())
	}
	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(contents), "hello world") {
		t.Errorf("file sink missing record; got %q", contents)
	}
	snap := setup.Bus.Snapshot(0)
	if len(snap) != 1 {
		t.Fatalf("expected 1 bus entry, got %d", len(snap))
	}
	if snap[0].Msg != "hello world" {
		t.Errorf("bus entry msg = %q, want %q", snap[0].Msg, "hello world")
	}
	if snap[0].Level != "INFO" {
		t.Errorf("bus entry level = %q, want INFO", snap[0].Level)
	}
	if snap[0].Fields["k"] != "v" {
		t.Errorf("bus entry fields = %v, want k=v", snap[0].Fields)
	}
}

// TestSetupDefaultLogger_JSONMode is the R5 acceptance pin: with
// FormatJSON, each stdout/file line is one self-describing JSON
// object carrying time, level, msg, and any structured attrs. The
// in-memory bus stays structured regardless.
func TestSetupDefaultLogger_JSONMode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	var stdoutBuf bytes.Buffer
	setup, err := SetupDefaultLogger(&stdoutBuf, slog.LevelInfo, DefaultFileSinkConfig(logPath), FormatJSON)
	if err != nil {
		t.Fatalf("SetupDefaultLogger: %v", err)
	}
	t.Cleanup(func() { _ = setup.Closer.Close() })

	slog.Info("dataplane up", "pid", 4242, "target", "sublyne_dataplane::ipc")

	// Stdout sink: every non-empty line must parse as JSON with the
	// minimum schema. (Other tests in the file may share the slog
	// default logger; only inspect the bytes we just wrote.)
	for _, line := range strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("stdout line is not JSON: %v\n%s", err, line)
		}
		for _, k := range []string{"time", "level", "msg"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("JSON record missing %q key: %v", k, rec)
			}
		}
	}

	// File sink mirrors stdout — same JSON shape.
	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("file line is not JSON: %v\n%s", err, line)
		}
	}

	// Bus stays structured: a JSON wire format must not change the
	// in-memory record shape the panel consumes.
	snap := setup.Bus.Snapshot(0)
	if len(snap) == 0 {
		t.Fatal("bus did not receive entry under JSON format")
	}
	if snap[len(snap)-1].Msg != "dataplane up" {
		t.Errorf("bus entry msg = %q, want %q", snap[len(snap)-1].Msg, "dataplane up")
	}
}

func TestParseFormat(t *testing.T) {
	// Slice instead of map so gocritic's `mapKey` check doesn't flag
	// the deliberately whitespace-padded inputs (we test trimming).
	cases := []struct {
		in   string
		want Format
	}{
		{"", FormatText},
		{"text", FormatText},
		{"garbage", FormatText},
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"Json", FormatJSON},
		{" json ", FormatJSON},
		{"\tjson\t", FormatJSON},
	}
	for _, c := range cases {
		if got := ParseFormat(c.in); got != c.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSetupDefaultLogger_NoFilePath(t *testing.T) {
	var stdoutBuf bytes.Buffer
	setup, err := SetupDefaultLogger(&stdoutBuf, slog.LevelInfo, FileSinkConfig{}, FormatText)
	if err != nil {
		t.Fatalf("SetupDefaultLogger: %v", err)
	}
	if setup.Closer != nil {
		t.Errorf("expected nil closer when no file path supplied")
	}
	slog.Info("dev mode")
	if !strings.Contains(stdoutBuf.String(), "dev mode") {
		t.Error("stdout sink missing record in no-file-path mode")
	}
	if len(setup.Bus.Snapshot(0)) == 0 {
		t.Error("bus did not receive dev mode entry")
	}
}

func TestLevelControl_RuntimeChangeAffectsAllSinks(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	var stdoutBuf bytes.Buffer
	setup, err := SetupDefaultLogger(&stdoutBuf, slog.LevelInfo, DefaultFileSinkConfig(logPath), FormatText)
	if err != nil {
		t.Fatalf("SetupDefaultLogger: %v", err)
	}
	t.Cleanup(func() { _ = setup.Closer.Close() })

	// At INFO, DEBUG records must not land.
	slog.Debug("quiet debug")
	if strings.Contains(stdoutBuf.String(), "quiet debug") {
		t.Fatal("expected DEBUG to be suppressed before level change")
	}
	if len(setup.Bus.Snapshot(0)) != 0 {
		t.Fatalf("bus saw DEBUG record before level change")
	}

	setup.Level.Set(slog.LevelDebug)
	if got := setup.Level.Get(); got != slog.LevelDebug {
		t.Fatalf("Level.Get = %v, want DEBUG", got)
	}
	slog.Debug("loud debug")
	if !strings.Contains(stdoutBuf.String(), "loud debug") {
		t.Error("DEBUG missing from stdout after level change")
	}
	contents, _ := os.ReadFile(logPath)
	if !strings.Contains(string(contents), "loud debug") {
		t.Error("DEBUG missing from file after level change")
	}
	snap := setup.Bus.Snapshot(0)
	if len(snap) == 0 || snap[len(snap)-1].Msg != "loud debug" {
		t.Errorf("bus missing DEBUG entry; got %+v", snap)
	}
}

func TestLevelControl_OnChangeFiresOnSet(t *testing.T) {
	c := NewLevelControl(slog.LevelInfo)
	var fired slog.Level
	c.OnChange(func(l slog.Level) { fired = l })
	c.Set(slog.LevelError)
	if fired != slog.LevelError {
		t.Errorf("OnChange callback fired with %v, want ERROR", fired)
	}
	c.OnChange(nil) // clearing must not panic
	c.Set(slog.LevelWarn)
}

func TestFanout_PreservesAttrsAndGroup(t *testing.T) {
	var a, b bytes.Buffer
	h := &fanout{handlers: []slog.Handler{
		slog.NewTextHandler(&a, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}}
	logger := slog.New(h.WithAttrs([]slog.Attr{slog.String("svc", "sublyne")}).WithGroup("auth"))
	logger.Info("login failed", "username", "ping")
	for name, buf := range map[string]*bytes.Buffer{"sink-A": &a, "sink-B": &b} {
		s := buf.String()
		if !strings.Contains(s, "svc=sublyne") {
			t.Errorf("%s missing svc attr: %q", name, s)
		}
		if !strings.Contains(s, "auth.username=ping") {
			t.Errorf("%s missing grouped username: %q", name, s)
		}
	}
}

func TestFanout_OneSinkErrorDoesNotSilenceOther(t *testing.T) {
	var good bytes.Buffer
	bad := errorHandler{}
	h := &fanout{handlers: []slog.Handler{
		bad,
		slog.NewTextHandler(&good, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}}
	err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0))
	if err == nil {
		t.Error("expected error to propagate from bad sink")
	}
	if !strings.Contains(good.String(), "msg") {
		t.Error("good sink missed the record because bad sink errored")
	}
}

// errorHandler is a slog.Handler that always returns an error from
// Handle. Used to verify fanout doesn't short-circuit on the first
// failure.
type errorHandler struct{}

func (errorHandler) Enabled(context.Context, slog.Level) bool { return true }
func (errorHandler) Handle(context.Context, slog.Record) error {
	return errBadSink
}
func (errorHandler) WithAttrs([]slog.Attr) slog.Handler { return errorHandler{} }
func (errorHandler) WithGroup(string) slog.Handler      { return errorHandler{} }

var errBadSink = badSinkError("simulated sink failure")

type badSinkError string

func (e badSinkError) Error() string { return string(e) }
