package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplaneasset"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
)

// shutdownGrace is how long the supervisor lets the dataplane child run
// its SIGTERM handler (stop_all → drop the per-tunnel iptables
// RST-suppression chain and icmp_echo_ignore_all sysctl guards) on a
// graceful shutdown before falling back to SIGKILL. Without this grace
// window a `systemctl stop/restart` SIGKILLs the child and orphans that
// kernel state.
const shutdownGrace = 5 * time.Second

// SupervisorConfig configures the per-process dataplane supervisor.
type SupervisorConfig struct {
	// SocketPath is the Unix domain socket the dataplane will bind.
	// systemd's RuntimeDirectory keeps the parent directory
	// 0750 sublyne:sublyne; we don't create it ourselves.
	SocketPath string

	// BinaryPath is where the extracted dataplane is written. Inside
	// production this is /run/sublyne/dataplane (RuntimeDirectory),
	// so the file is wiped on every service start. Tests pass a
	// temp file path.
	BinaryPath string

	// ConnectTimeout caps how long Dial waits for the socket file to
	// appear and accept the first connection. Default 5 s.
	ConnectTimeout time.Duration

	// ReadyTimeout caps how long we wait for the Rust Ready event
	// after a successful dial. Default 5 s.
	ReadyTimeout time.Duration

	// MaxRestartsPerMinute caps the dataplane respawn rate. Exceeding
	// it leaves the dataplane down so the panel can surface an alert.
	// Default 5.
	MaxRestartsPerMinute int

	Logger *slog.Logger
}

// DefaultSupervisorConfig returns a config populated with the values
// the production binary uses. The socket and binary paths must still
// be supplied by the caller — those depend on /run/sublyne.
func DefaultSupervisorConfig() SupervisorConfig {
	return SupervisorConfig{
		ConnectTimeout:       5 * time.Second,
		ReadyTimeout:         5 * time.Second,
		MaxRestartsPerMinute: 5,
	}
}

// Supervisor owns the lifecycle of the dataplane child process plus
// the IPC connection to it.
//
// Run is the entry point: it extracts the binary, execs the child,
// dials the socket, waits for Ready, exposes the resulting Client via
// the Client() accessor, and respawns on child exit with backoff.
//
// Phase 8a only restarts the child on its own exit; we do not yet
// re-dial after a transient socket error. If the child stays up but
// the socket dies, the Client closes and downstream callers will see
// "client closed" errors — at that point the panel surfaces the
// error and the operator can take action manually.
type Supervisor struct {
	cfg SupervisorConfig

	mu         sync.Mutex
	cmd        *exec.Cmd
	client     *Client
	restarts   []time.Time
	stopCalled bool

	// readyOnce signals the first successful Ready handshake so
	// callers can block on it rather than poll Client().
	readyCh chan struct{}

	wg sync.WaitGroup
}

// NewSupervisor returns a Supervisor with the supplied config.
// Run() is called separately so the caller can register the
// Supervisor in their dependency graph first.
func NewSupervisor(cfg SupervisorConfig) *Supervisor {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.ReadyTimeout == 0 {
		cfg.ReadyTimeout = 5 * time.Second
	}
	if cfg.MaxRestartsPerMinute == 0 {
		cfg.MaxRestartsPerMinute = 5
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Supervisor{
		cfg:     cfg,
		readyCh: make(chan struct{}),
	}
}

// Run loops until ctx is cancelled or the restart budget is
// exhausted. The first successful Ready signals readyCh; subsequent
// restarts re-use the same channel (callers may receive multiple
// closure signals on the same struct).
func (s *Supervisor) Run(ctx context.Context) error {
	if !dataplaneasset.Embedded || len(dataplaneasset.Bytes()) == 0 {
		return errors.New("ipc: this build does not embed the dataplane binary (build with -tags=embed)")
	}
	if err := s.extractBinary(); err != nil {
		return fmt.Errorf("extract dataplane: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.recordRestartAndCheck() {
			// Restart budget exhausted: the child crash-looped faster than
			// MaxRestartsPerMinute. Returning here would leave the dataplane
			// DOWN forever — the supervisor goroutine exits but the Go
			// process keeps running, so systemd never restarts us and the
			// outage is silent. Instead, back off for a cooldown window
			// (interruptible by ctx), reset the restart window, and keep
			// retrying. Self-healing: a transient crash-loop recovers on
			// its own once the underlying cause clears.
			s.cfg.Logger.Warn("ipc: dataplane restart budget exhausted; backing off",
				"max_per_minute", s.cfg.MaxRestartsPerMinute, "cooldown", "60s")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(60 * time.Second):
			}
			s.mu.Lock()
			s.restarts = nil
			s.mu.Unlock()
			continue
		}
		if err := s.startOnce(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			s.cfg.Logger.Warn("ipc: dataplane attempt failed", "err", err)
		}
		// Wait briefly before retrying so we don't spin on a fast
		// crash loop. The MaxRestartsPerMinute check ahead caps the
		// total damage.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// Stop signals an orderly shutdown: SIGTERM to the child, close the
// IPC client. Safe to call multiple times.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	if s.stopCalled {
		s.mu.Unlock()
		return
	}
	s.stopCalled = true
	client := s.client
	cmd := s.cmd
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if cmd != nil && cmd.Process != nil {
		// Best-effort SIGTERM. We don't wait here — Run is already
		// reaping the child.
		_ = cmd.Process.Signal(os.Interrupt)
	}
	s.wg.Wait()
}

// Client returns the live IPC client, or nil if the dataplane is not
// up. Callers should retry briefly on nil after a fresh start.
//
// Safe to call on a nil receiver — returns nil, matching the
// "dataplane isn't up yet" semantics. The dataplane Manager treats a
// nil client as "supervisor still starting" and surfaces a clean
// error to the caller; without this guard, unit tests that pass a
// nil supervisor to NewManager (e.g. the transport-acceptance tests)
// would deref-panic instead of hitting that error path.
func (s *Supervisor) Client() *Client {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}

// WaitReady blocks until the dataplane has emitted Ready or ctx fires.
// Returns nil on success.
//
// startOnce reassigns s.readyCh under s.mu after a restart, so we snapshot
// the current channel under the same lock before selecting on it. Reading
// the field lock-free here races with that reassignment (go test -race).
func (s *Supervisor) WaitReady(ctx context.Context) error {
	s.mu.Lock()
	ch := s.readyCh
	s.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startOnce runs one fork→wait cycle and respects ctx.
func (s *Supervisor) startOnce(ctx context.Context) error {
	// Remove any stale socket file before the child binds. Without
	// this, an unclean previous exit leaves the file in place and
	// bind() fails.
	_ = os.Remove(s.cfg.SocketPath)

	// BinaryPath and SocketPath are set by main.go from constants
	// (/run/sublyne/{dataplane,dataplane.sock}); they aren't user
	// input. gosec's G204 fires on every exec with a variable path,
	// but the value here is trusted.
	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, //nolint:gosec // trusted internal path
		"--ipc-socket", s.cfg.SocketPath)
	cmd.Stdout = &supervisorLogWriter{logger: s.cfg.Logger, level: slog.LevelInfo}
	cmd.Stderr = &supervisorLogWriter{logger: s.cfg.Logger, level: slog.LevelWarn}
	// On context cancellation (systemctl stop/restart) send SIGTERM, not
	// SIGKILL, so the Rust child runs its signal handler and tears down
	// the iptables RST chain + icmp sysctl guards. WaitDelay bounds the
	// grace window before exec falls back to SIGKILL. (Without an explicit
	// Cancel, exec.CommandContext SIGKILLs on ctx-done, orphaning that
	// kernel state.)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = shutdownGrace
	// On Unix systems we want the child to die with the parent — set
	// PR_SET_PDEATHSIG via syscall.SysProcAttr.Pdeathsig. The struct
	// is Linux-only; gate via build tags would normally be the answer
	// but Go uses unix-syscalls behind interfaces. For now we rely
	// on the existing context-cancellation to kill the child on exit.

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dataplane: %w", err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	// Reap the child in a goroutine so we can detect exit and trigger
	// the outer respawn loop.
	exitCh := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		exitCh <- cmd.Wait()
	}()

	// Dial the socket. The child may not have bound it yet so we
	// retry every 100 ms up to ConnectTimeout.
	conn, err := dialWithRetry(ctx, s.cfg.SocketPath, s.cfg.ConnectTimeout)
	if err != nil {
		// Could not dial; kill the child so it doesn't hang around.
		_ = cmd.Process.Kill()
		<-exitCh
		return fmt.Errorf("dial dataplane socket: %w", err)
	}

	client := NewClient(conn, s.cfg.Logger)

	// Wait for Ready.
	readyCtx, readyCancel := context.WithTimeout(ctx, s.cfg.ReadyTimeout)
	_, err = client.WaitReady(readyCtx)
	readyCancel()
	if err != nil {
		_ = client.Close()
		_ = cmd.Process.Kill()
		<-exitCh
		return fmt.Errorf("dataplane ready: %w", err)
	}

	s.mu.Lock()
	s.client = client
	// First-time readyCh close. Subsequent restarts after a child
	// crash re-create the chan so the *next* WaitReady caller still
	// gets a fresh signal.
	select {
	case <-s.readyCh:
		// Already closed — make a new channel for future restarts.
		s.readyCh = make(chan struct{})
		close(s.readyCh)
	default:
		close(s.readyCh)
	}
	s.mu.Unlock()
	s.cfg.Logger.Info("ipc: dataplane up", "pid", cmd.Process.Pid)

	// Note when this child reached Ready. recordRestartAndCheck counts
	// spawn ATTEMPTS, so a child that bound fine and ran for a long time
	// would still burn budget on its eventual restart. We compensate
	// below: if this child ran for a healthy duration before exiting, we
	// clear the restart window so a slow, occasional restart never trips
	// the per-minute cap — only genuine rapid crash-loops do.
	readyAt := time.Now()
	const healthyRunDuration = 30 * time.Second

	// Block until the child exits, the IPC client/socket dies, or ctx is
	// cancelled. The client.Closed() arm covers the case where the child
	// process stays alive but its IPC socket drops (Client read loop
	// returns / EOF): without it the supervisor would wait on a child
	// that can no longer be reached and downstream calls fail forever.
	select {
	case err := <-exitCh:
		s.mu.Lock()
		s.client = nil
		s.cmd = nil
		if time.Since(readyAt) >= healthyRunDuration {
			// Ran healthily before exiting — not a crash-loop. Reset the
			// restart window so this restart doesn't count against the cap.
			s.restarts = nil
		}
		s.mu.Unlock()
		_ = client.Close()
		if err != nil {
			// Dataplane died with a non-zero exit. The Rust panic hook
			// writes its own crash-<ts>.log file when the cause was a
			// Rust panic; but signals (SIGABRT, SIGSEGV, OOM-kill) and
			// hard aborts skip the panic hook entirely, so the panel
			// would never see a record. Write a supervisor-side note
			// here so every crash leaves a readable trail. Best-effort:
			// failure to write must not stop the respawn loop.
			if dir := logging.CrashDir(); dir != "" {
				body := fmt.Sprintf(
					"sublyne supervisor: dataplane child exited abnormally\n"+
						"time: %s\nexit_error: %v\npid: %d\n",
					time.Now().UTC().Format(time.RFC3339Nano), err, cmd.Process.Pid)
				if name, werr := logging.WriteCrashReport(dir, body); werr != nil {
					s.cfg.Logger.Warn("supervisor: write crash report failed", "err", werr)
				} else {
					s.cfg.Logger.Warn("supervisor: dataplane crashed; report written",
						"file", name, "err", err)
				}
			}
			return fmt.Errorf("dataplane exited: %w", err)
		}
		return errors.New("dataplane exited cleanly; respawning")
	case <-client.Closed():
		// The child is still alive but its IPC socket died (Client read
		// loop returned / EOF). The Client is now closed, so every
		// downstream call would fail forever. Kill the child and return
		// so the outer loop respawns a fresh child + socket. This counts
		// as a normal restart (the loop's recordRestartAndCheck runs on
		// the next iteration). Killing the child makes exitCh fire — we
		// drain it so the reaper goroutine completes.
		s.cfg.Logger.Warn("ipc: dataplane IPC socket died while child alive; respawning",
			"pid", cmd.Process.Pid)
		s.mu.Lock()
		s.client = nil
		s.cmd = nil
		s.mu.Unlock()
		_ = client.Close()
		_ = cmd.Process.Kill()
		<-exitCh
		return errors.New("dataplane IPC client closed; respawning")
	case <-ctx.Done():
		// Graceful shutdown (systemctl stop/restart). ctx cancellation
		// triggers cmd.Cancel (SIGTERM) + WaitDelay grace + SIGKILL
		// fallback wired in startOnce, so the Rust child runs its SIGTERM
		// handler (stop_all → drop the iptables RST chain and the
		// icmp_echo_ignore_all sysctl guards) before it dies. Just reap.
		_ = client.Close()
		<-exitCh
		return ctx.Err()
	}
}

// extractBinary copies the embedded blob to disk and makes it
// executable for the `sublyne` user.
//
// Two non-obvious things this method has to get right:
//
//  1. **Don't extract into /run.** Systemd mounts /run as
//     `tmpfs ... noexec` on every recent Ubuntu, which means exec()ing
//     a binary stored there fails with EACCES *even when the file
//     itself has 0o700*. Callers must point BinaryPath at a path on
//     a regular filesystem (we use /var/lib/sublyne/ in production).
//  2. **Force the mode on re-extract.** `os.WriteFile` only sets the
//     mode the FIRST time it creates the file; subsequent calls
//     truncate and rewrite *without changing permissions*. If a
//     previous install left a stale file with the wrong mode, fork/exec
//     would silently keep failing. We always Chmod after writing.
//
// The write itself goes to `<path>.tmp` then atomic-renames into
// place so a crash mid-extract can't leave a half-written binary the
// supervisor would then try to exec.
func (s *Supervisor) extractBinary() error {
	if err := os.MkdirAll(filepath.Dir(s.cfg.BinaryPath), 0o755); err != nil {
		return err
	}
	tmp := s.cfg.BinaryPath + ".tmp"
	// 0o700 here is the create mode (subject to umask); the explicit
	// Chmod below is what guarantees the final mode regardless of
	// whether the tmp file existed beforehand.
	if err := os.WriteFile(tmp, dataplaneasset.Bytes(), 0o700); err != nil { //nolint:gosec // executable bit is required to exec the child
		return err
	}
	if err := os.Chmod(tmp, 0o700); err != nil { //nolint:gosec // executable bit is required
		return fmt.Errorf("chmod tmp dataplane: %w", err)
	}
	if err := os.Rename(tmp, s.cfg.BinaryPath); err != nil {
		return fmt.Errorf("rename dataplane into place: %w", err)
	}
	return nil
}

func (s *Supervisor) recordRestartAndCheck() bool {
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	trimmed := s.restarts[:0]
	for _, t := range s.restarts {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	s.restarts = trimmed
	if len(s.restarts) >= s.cfg.MaxRestartsPerMinute {
		return false
	}
	s.restarts = append(s.restarts, now)
	return true
}

func dialWithRetry(ctx context.Context, path string, total time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout dialing %s", path)
	}
	return nil, lastErr
}

// supervisorLogWriter is the io.Writer behind cmd.Stdout / cmd.Stderr.
// Each line written becomes one slog entry at the configured level so
// dataplane logs end up in the same journal as the Go control plane.
//
// Two formats arrive on this writer:
//
//  1. Plain text (default; tracing-subscriber fmt layer). The Rust
//     side disables ANSI as of R5, but a stripper still runs here for
//     defence-in-depth: an older dataplane build paired with a newer
//     control plane shouldn't dump `\x1b[2m...` escapes into the
//     panel's Logs page.
//  2. One JSON object per line (SUBLYNE_LOG_FORMAT=json). Parsed into
//     structured slog attrs so target / tunnel_id / transport / etc.
//     survive into the panel and `journalctl -o json`.
type supervisorLogWriter struct {
	logger *slog.Logger
	level  slog.Level
	// buf carries bytes after the last newline across Write calls so a
	// log line split across two pipe-read chunks (a long line, a JSON
	// record, or a panic backtrace exceeding the pipe buffer) is
	// reassembled before parsing. Without this a split JSON line fails
	// json.Unmarshal and falls back to text at the wrong level, losing
	// its structured target/tunnel_id/transport fields.
	buf []byte
}

// supervisorLineCap bounds an unterminated line so a child that never
// emits a newline can't grow the carry buffer without limit.
const supervisorLineCap = 1 << 20 // 1 MiB

func (w *supervisorLogWriter) Write(p []byte) (int, error) {
	if w.logger == nil {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emitLine(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	// Safety valve: never let an unterminated line grow without bound.
	if len(w.buf) > supervisorLineCap {
		w.emitLine(string(w.buf))
		w.buf = w.buf[:0]
	}
	// Release a large backing array once the carry is drained.
	if len(w.buf) == 0 && cap(w.buf) > 4096 {
		w.buf = nil
	}
	return len(p), nil
}

// emitLine forwards one complete (newline-stripped) dataplane log line to
// slog, honoring the line's own level and stripping any stray ANSI.
func (w *supervisorLogWriter) emitLine(line string) {
	if line == "" {
		return
	}
	// SUBLYNE_LOG_FORMAT=json: tracing-subscriber's .json() formatter
	// emits one self-describing object per line. The cheap leading-brace
	// check keeps the text-mode hot path zero-overhead.
	if line[0] == '{' && w.emitJSON(line) {
		return
	}
	// Plain text: defensively strip any ANSI escape that snuck in before
	// forwarding so journald, the rotating file, and the panel never see
	// raw `\x1b[...m` bytes.
	clean := stripANSI(line)
	// Honor the dataplane's OWN level. tracing-subscriber's text format
	// places the level right after the timestamp ("<ts>  DEBUG target:
	// msg …"); parse it so a DEBUG / WARN / ERROR line reaches journald,
	// the rotating file, and the panel tagged with its real level instead
	// of this writer's fixed fallback. A line with no recognisable level
	// token — e.g. a panic backtrace on stderr — keeps the fallback.
	lvl := w.level
	if parsed, ok := parseTextLevel(clean); ok {
		lvl = parsed
	}
	w.logger.Log(context.Background(), lvl, "dataplane", "line", clean)
}

// rustTracingRecord mirrors the JSON object tracing-subscriber's
// .json() formatter emits, populated only with the fields we actually
// hoist. `Fields` carries the application-level structured fields
// including the `"message"` key — we lift that into the slog message
// and forward the rest as attrs.
type rustTracingRecord struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Target    string         `json:"target"`
	Fields    map[string]any `json:"fields"`
}

// emitJSON parses a single dataplane line as a Rust tracing-subscriber
// JSON record and emits it via slog with structured attrs preserved.
// Returns true if the record was recognised; false otherwise so the
// caller can fall back to plain-text handling.
func (w *supervisorLogWriter) emitJSON(line string) bool {
	var rec rustTracingRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return false
	}
	// A genuine tracing-subscriber JSON line always carries a non-empty
	// level. Anything else (a JSON literal that happened to start with
	// '{', a half-formed line) is rejected so the caller falls back to
	// the plain-text path.
	if rec.Level == "" {
		return false
	}
	lvl := parseRustLevel(rec.Level, w.level)
	msg := "dataplane"
	attrs := make([]slog.Attr, 0, len(rec.Fields)+1)
	if rec.Target != "" {
		attrs = append(attrs, slog.String("target", rec.Target))
	}
	for k, v := range rec.Fields {
		if k == "message" {
			if m, ok := v.(string); ok && m != "" {
				msg = m
			}
			continue
		}
		attrs = append(attrs, slog.Any(k, v))
	}
	w.logger.LogAttrs(context.Background(), lvl, msg, attrs...)
	return true
}

// parseRustLevel maps a Rust tracing level string ("INFO", "WARN", …)
// to an slog.Level. Falls back to `fallback` for anything unrecognised
// so a future tracing-subscriber casing tweak never silently drops a
// record.
func parseRustLevel(s string, fallback slog.Level) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return slog.LevelError
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "INFO":
		return slog.LevelInfo
	case "DEBUG":
		return slog.LevelDebug
	case "TRACE":
		// slog has no native TRACE level; the LogBus handler in
		// internal/logging maps anything ≤ Debug-4 back to "TRACE".
		return slog.LevelDebug - 4
	}
	return fallback
}

// parseTextLevel extracts the level from a tracing-subscriber TEXT-format
// line ("<timestamp>  LEVEL  <target>: <message> <fields>"). The level
// token sits among the first few whitespace-separated fields, right after
// the RFC3339 timestamp, so we scan only the leading fields — a level word
// that happens to appear inside a message body can't be mistaken for the
// record's level. Returns false when no level token is present (e.g. a
// panic backtrace on stderr), so the caller keeps its fallback level.
func parseTextLevel(line string) (slog.Level, bool) {
	fields := strings.Fields(line)
	n := len(fields)
	if n > 4 {
		n = 4
	}
	for i := 0; i < n; i++ {
		switch fields[i] {
		case "TRACE":
			return slog.LevelDebug - 4, true
		case "DEBUG":
			return slog.LevelDebug, true
		case "INFO":
			return slog.LevelInfo, true
		case "WARN", "WARNING":
			return slog.LevelWarn, true
		case "ERROR":
			return slog.LevelError, true
		}
	}
	return 0, false
}

// ansiEscapeRE matches the CSI / SGR escape sequences tracing-subscriber
// emits when its fmt layer is colour-aware (`\x1b[2m`, `\x1b[32m`,
// `\x1b[0m`, …). The Rust side disables ANSI as of R5, but we strip
// here as belt-and-suspenders against an older dataplane build, an
// out-of-tree tool writing to stdout, or a future regression. Kept as
// a small hand-rolled regex — no external dep for one helper.
var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// stripANSI removes every ANSI CSI escape sequence from s. Returns s
// unchanged when there is no ESC byte to start with so the common
// no-escape path skips the regex allocation entirely.
func stripANSI(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	return ansiEscapeRE.ReplaceAllString(s, "")
}
