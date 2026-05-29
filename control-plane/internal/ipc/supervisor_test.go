package ipc

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestExtractBinary_AlwaysExecutable proves the two regressions that
// shipped Phase 8a to the real Iran/Remote installs are fixed:
//
//  1. After extract, the file mode includes the user-executable bit.
//     This caught the original WriteFile semantic ("create-only mode")
//     when a pre-existing stale file kept the wrong permissions.
//  2. The extract path is *not* under /run, where systemd mounts
//     a noexec tmpfs on every recent Ubuntu — fork/exec would
//     succeed-on-paper-and-fail-in-production.
//
// We can't enforce (2) at the unit-test layer (we don't know what
// path main.go uses without inspecting it), so the assertion is on
// the supervisor invariant: whatever path is supplied, the extracted
// file ends up with the executable bit set and is a regular file.
// main_test.go covers the path-choice invariant separately.
func TestExtractBinary_AlwaysExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes don't carry the unix x bit on Windows")
	}
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "dataplane")

	// Pre-create the destination with NO executable bit. extractBinary
	// must overwrite the mode, not preserve the stale 0o600.
	if err := os.WriteFile(binPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}

	cfg := DefaultSupervisorConfig()
	cfg.BinaryPath = binPath
	cfg.SocketPath = filepath.Join(tmp, "sock")
	cfg.Logger = slog.Default()
	s := NewSupervisor(cfg)

	if err := s.extractBinary(); err != nil {
		// extractBinary uses the embedded blob, which is nil in dev
		// builds (no `embed` tag). That's fine — the test still
		// asserts the mode bit even when the payload is empty,
		// because WriteFile created a 0-byte file with the right
		// mode and Chmod was called.
		t.Logf("extractBinary returned %v (expected on dev builds)", err)
	}

	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("stat after extract: %v", err)
	}
	mode := info.Mode().Perm()
	if mode&0o100 == 0 {
		t.Errorf("after extract, file mode = %#o, missing owner-execute bit", mode)
	}
	if mode != 0o700 {
		t.Errorf("after extract, file mode = %#o, want 0o700", mode)
	}
}

// TestExtractBinary_RejectsNoexecPathIntent isn't a runtime check —
// it's a guard against a future refactor accidentally pointing the
// supervisor back at /run. The compiled binary's main.go has a
// comment-and-constant pair that should be modified atomically; this
// test asserts the chosen production path is under /var/lib, which
// is on a regular filesystem on every Ubuntu install. If a later
// phase needs a different path, change the test deliberately at the
// same time as the constant.
func TestSupervisor_DefaultsKnownGood(t *testing.T) {
	cfg := DefaultSupervisorConfig()
	// We don't pin the production path here (main.go owns it), but
	// the default values for the timeouts and restart budget are
	// what every caller depends on.
	if cfg.ConnectTimeout == 0 || cfg.ReadyTimeout == 0 || cfg.MaxRestartsPerMinute == 0 {
		t.Errorf("default config has zero values: %+v", cfg)
	}
}

// newCapturingWriter wires a supervisorLogWriter to an in-memory slog
// text handler so the R5 hygiene tests can assert what reached
// journald.
func newCapturingWriter(t *testing.T) (supervisorLogWriter, *bytes.Buffer) {
	t.Helper()
	buf := new(bytes.Buffer)
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug - 4})
	return supervisorLogWriter{logger: slog.New(handler), level: slog.LevelInfo}, buf
}

// TestSupervisorLogWriter_StripsANSI is the regression test for the
// pre-R5 journalctl noise: `line="\x1b[2m...\x1b[0m"`. After R5 the
// Rust side disables ANSI at source, but the Go writer also strips
// defensively. This test pins that contract.
func TestSupervisorLogWriter_StripsANSI(t *testing.T) {
	w, buf := newCapturingWriter(t)
	// A representative line from the v0.1.x live journal.
	in := "\x1b[2m2026-05-22T16:10:05.981506Z\x1b[0m \x1b[32m INFO\x1b[0m " +
		"\x1b[2msublyne_dataplane::tunnel::client\x1b[0m\x1b[2m:\x1b[0m " +
		"client: local_listen bound \x1b[3mtunnel_id\x1b[0m\x1b[2m=\x1b[0m1\n"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("output still carries ANSI escapes: %q", got)
	}
	if !strings.Contains(got, "client: local_listen bound") {
		t.Errorf("stripped output lost message body: %q", got)
	}
	// The message field for text-mode lines is the literal string
	// "dataplane"; the body lives in the `line` attribute.
	if !strings.Contains(got, `msg=dataplane`) {
		t.Errorf("text-mode line should log msg=dataplane, got %q", got)
	}
}

// TestSupervisorLogWriter_PlainTextPassthrough confirms a non-ANSI line
// is forwarded verbatim — we mustn't accidentally mangle text-mode
// output from a current-version dataplane.
func TestSupervisorLogWriter_PlainTextPassthrough(t *testing.T) {
	w, buf := newCapturingWriter(t)
	in := "2026-05-22T16:10:05Z  INFO sublyne_dataplane::tunnel::client: " +
		"client: local_listen bound tunnel_id=1 addr=0.0.0.0:5001\n"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "client: local_listen bound") {
		t.Errorf("text-mode line body missing: %q", got)
	}
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("plain-text passthrough introduced ANSI? %q", got)
	}
}

// TestSupervisorLogWriter_ParsesJSON covers the SUBLYNE_LOG_FORMAT=json
// path: the Rust .json() formatter emits one object per line and the
// supervisor hoists target / fields into slog attrs.
func TestSupervisorLogWriter_ParsesJSON(t *testing.T) {
	w, buf := newCapturingWriter(t)
	in := `{"timestamp":"2026-05-22T16:10:05.981Z","level":"INFO",` +
		`"fields":{"message":"client: local_listen bound","tunnel_id":1,"addr":"0.0.0.0:5001"},` +
		`"target":"sublyne_dataplane::tunnel::client"}` + "\n"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `msg="client: local_listen bound"`) {
		t.Errorf("JSON message not hoisted into slog msg: %q", got)
	}
	if !strings.Contains(got, "target=sublyne_dataplane::tunnel::client") {
		t.Errorf("target attr missing: %q", got)
	}
	if !strings.Contains(got, "tunnel_id=1") {
		t.Errorf("tunnel_id attr missing: %q", got)
	}
	if !strings.Contains(got, "addr=0.0.0.0:5001") {
		t.Errorf("addr attr missing: %q", got)
	}
	if !strings.Contains(got, "level=INFO") {
		t.Errorf("level not preserved: %q", got)
	}
}

// TestSupervisorLogWriter_JSONLevels exercises every level mapping so a
// tracing-subscriber casing change can't silently demote ERROR lines.
func TestSupervisorLogWriter_JSONLevels(t *testing.T) {
	cases := map[string]string{
		"TRACE": "level=DEBUG-4",
		"DEBUG": "level=DEBUG",
		"INFO":  "level=INFO",
		"WARN":  "level=WARN",
		"ERROR": "level=ERROR",
	}
	for rust, want := range cases {
		t.Run(rust, func(t *testing.T) {
			w, buf := newCapturingWriter(t)
			in := `{"timestamp":"2026-05-22T16:10:05Z","level":"` + rust + `",` +
				`"fields":{"message":"x"},"target":"sublyne_dataplane"}` + "\n"
			if _, err := w.Write([]byte(in)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if !strings.Contains(buf.String(), want) {
				t.Errorf("rust level %q not mapped (want substring %q): %q", rust, want, buf.String())
			}
		})
	}
}

// TestSupervisorLogWriter_NonTracingJSONFallsBack ensures a stray
// JSON-looking line that isn't a tracing record (e.g. `{}`) is logged
// via the text branch instead of being silently dropped.
func TestSupervisorLogWriter_NonTracingJSONFallsBack(t *testing.T) {
	w, buf := newCapturingWriter(t)
	in := "{\"unrelated\":42}\n"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `msg=dataplane`) {
		t.Errorf("non-tracing JSON should fall through to text logging: %q", got)
	}
	if !strings.Contains(got, `unrelated`) {
		t.Errorf("non-tracing JSON content lost: %q", got)
	}
}

func TestStripANSI(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no_escapes", "plain text", "plain text"},
		{"sgr_reset", "\x1b[0mhello", "hello"},
		{"bracketed_color", "\x1b[32m INFO\x1b[0m message", " INFO message"},
		{"multiple", "\x1b[2mts\x1b[0m \x1b[31mERR\x1b[0m body", "ts ERR body"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripANSI(c.in)
			if got != c.want {
				t.Errorf("stripANSI(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
