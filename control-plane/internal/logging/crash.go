package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// CrashFilePrefix is the on-disk prefix for every crash log file the
// project writes. The panel's "Crash reports" tab filters by this
// prefix so unrelated files in /var/lib/sublyne/logs/ (the rotating
// app.log) don't appear.
const CrashFilePrefix = "crash-"

// CrashReport describes one crash-<unix>.log file. Returned by
// ListCrashReports for the panel's Crash reports tab.
type CrashReport struct {
	Filename   string    `json:"filename"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
	// Preview is the first ~512 bytes of the file so the panel can
	// render a one-line teaser without fetching the full body. Useful
	// when the log directory contains a few minutes' worth of dataplane
	// retries and the operator wants to see which is which.
	Preview string `json:"preview,omitempty"`
}

// WriteCrashReport persists a crash log to <dir>/crash-<unix>.log and
// returns the filename. The body is whatever the caller hands in —
// typically the panic value plus debug.Stack().
//
// The function never panics — if it can't write the file (disk full,
// directory missing) it returns the error and lets the caller log to
// journald. A best-effort discipline: a failure here must not stop
// the recovery code from completing.
func WriteCrashReport(dir, body string) (string, error) {
	if dir == "" {
		return "", errors.New("logging: crash dir is empty")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("logging: mkdir crash dir: %w", err)
	}
	name := fmt.Sprintf("%s%d.log", CrashFilePrefix, time.Now().Unix())
	full := filepath.Join(dir, name)
	// 0o640 matches the app.log permissions (CLAUDE.md §4); root can
	// read by virtue of belonging to the sublyne group. gosec warns
	// about anything wider than 0o600 here — the group-readable mode
	// is deliberate so the operator (root) can `cat crash-*.log`
	// without su'ing to sublyne.
	if err := os.WriteFile(full, []byte(body), 0o640); err != nil { //nolint:gosec // group-readable on purpose
		return "", fmt.Errorf("logging: write crash file: %w", err)
	}
	return name, nil
}

// FormatPanic builds the standard crash body string from a recovered
// panic value and goroutine stack. Used by both the HTTP recover
// middleware and the top-level main() recover. Output mirrors what
// runtime/panic prints to stderr so the operator's mental model
// matches.
//
// The panic value is rendered through SafePanicMessage so a future
// handler that accidentally panics on a struct carrying a secret
// (PSK, password hash, JWT key, WireGuard private key) doesn't dump
// the secret bytes into the on-disk crash file. Strings and `error`
// implementations render verbatim — those are what Go's runtime
// panics use for nil dereferences, divide-by-zero, etc. Anything
// else collapses to its type name only.
func FormatPanic(recovered any, where string) string {
	var sb strings.Builder
	sb.WriteString("sublyne control plane: recovered panic\n")
	if where != "" {
		sb.WriteString("location: ")
		sb.WriteString(where)
		sb.WriteString("\n")
	}
	sb.WriteString("time: ")
	sb.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	sb.WriteString("\n")
	sb.WriteString("panic: ")
	sb.WriteString(SafePanicMessage(recovered))
	sb.WriteString("\n\n")
	sb.Write(debug.Stack())
	sb.WriteString("\n")
	return sb.String()
}

// SafePanicMessage renders a recovered panic value in a way that
// cannot leak secret bytes from a struct field. Defense in depth —
// no current handler panics with a credential-bearing struct, but a
// future one could, and the crash file is world-readable for
// administrators.
//
//   - string → the string itself
//   - error  → err.Error() (covers every runtime.Error variant Go's
//     own panics produce, plus any wrapped error)
//   - anything else → the type name only (e.g. "*auth.Admin")
func SafePanicMessage(recovered any) string {
	switch v := recovered.(type) {
	case nil:
		return "<nil>"
	case string:
		return v
	case error:
		return v.Error()
	default:
		return fmt.Sprintf("<panic of type %T (value omitted to avoid leaking secrets)>", recovered)
	}
}

// ListCrashReports walks `dir` and returns metadata for every file
// whose name begins with CrashFilePrefix, newest first.
//
// Errors reading individual files are skipped — the panel needs the
// best-effort list, not an all-or-nothing failure when one file is
// momentarily locked or missing.
func ListCrashReports(dir string) ([]CrashReport, error) {
	if dir == "" {
		return nil, errors.New("logging: crash dir is empty")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("logging: read crash dir: %w", err)
	}
	out := make([]CrashReport, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, CrashFilePrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rep := CrashReport{
			Filename:   name,
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime().UTC(),
		}
		// Read a small preview (first line, max ~512 bytes) so the panel
		// can show "panic: foo" next to each row.
		f, err := os.Open(filepath.Join(dir, name))
		if err == nil {
			buf := make([]byte, 512)
			n, _ := f.Read(buf)
			_ = f.Close()
			rep.Preview = firstLine(buf[:n])
		}
		out = append(out, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt.After(out[j].ModifiedAt) })
	return out, nil
}

// ReadCrashReport returns the full contents of one crash file. The
// filename argument is validated to start with CrashFilePrefix and
// to not contain path separators, so a malicious panel call can't
// be tricked into reading arbitrary files.
func ReadCrashReport(dir, filename string) ([]byte, error) {
	if !strings.HasPrefix(filename, CrashFilePrefix) {
		return nil, fmt.Errorf("logging: crash report name must start with %q", CrashFilePrefix)
	}
	if strings.ContainsAny(filename, "/\\") {
		return nil, errors.New("logging: crash report name must not contain path separators")
	}
	full := filepath.Join(dir, filename)
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("logging: read crash report: %w", err)
	}
	return b, nil
}

// firstLine returns the first newline-terminated line of buf, or the
// entire buffer if no newline appears.
func firstLine(buf []byte) string {
	for i, b := range buf {
		if b == '\n' {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// crashDir is set once by main() and read by HTTP middleware that
// needs to record panic crashes. The atomic.Pointer-free design works
// because main writes once before any handler runs.
var (
	crashDirOnce sync.Once
	crashDir     string
)

// SetCrashDir installs the directory crash files should land in. main
// calls this with cfg.LogPath's parent dir right after SetupDefaultLogger.
// Idempotent: only the first call wins so repeated installs in tests
// don't race.
func SetCrashDir(dir string) {
	crashDirOnce.Do(func() { crashDir = dir })
}

// CrashDir returns the directory previously installed via SetCrashDir.
// Returns "" if SetCrashDir was never called — callers should treat
// that as "feature disabled".
func CrashDir() string { return crashDir }
