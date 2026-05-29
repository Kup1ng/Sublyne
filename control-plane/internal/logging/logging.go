// Package logging wires the project's structured logger.
//
// PROJECT_REQUIREMENTS §8.1 requires *dual* sinks: stdout (so the
// systemd unit's journald drain captures every record) AND a rotating
// file at /var/lib/sublyne/logs/app.log (so operators can read the
// last 7 days without depending on journald being installed).
//
// Phase 12 added a third internal sink: an in-memory LogBus that the
// panel's Logs page reads (recent buffer dump) and streams from (one
// frame per new line over the existing WebSocket). The bus mirrors
// every record the other sinks see, so the panel can't fall behind
// what an operator would see in journald.
//
// We use slog as the front-end and write to all sinks through a small
// fan-out handler. The file sink uses lumberjack so rotation is
// in-process and the operator does not have to install logrotate.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

// FileSinkConfig mirrors the PRD-mandated retention shape. Defaults
// match §8.1: "max 100 MB total, 7-day retention".
type FileSinkConfig struct {
	// Path is the active log file. lumberjack writes here and rotates
	// to <Path>.<timestamp> when MaxSizeMB is reached.
	Path string
	// MaxSizeMB is the per-file rotation threshold.
	MaxSizeMB int
	// MaxBackups caps the number of rotated files kept. The PRD's "max
	// 100 MB total" is achieved by keeping a small number of backups
	// near MaxSizeMB each.
	MaxBackups int
	// MaxAgeDays bounds retention in days, regardless of file count.
	MaxAgeDays int
	// Compress controls gzip-on-rotate.
	Compress bool
}

// DefaultFileSinkConfig returns the PRD's §8.1 values: 10 MB per
// rotation, 9 backups kept (≈100 MB total), 7-day age cap, no
// compression so the panel's future Logs page can tail without
// shelling out to zcat.
func DefaultFileSinkConfig(path string) FileSinkConfig {
	return FileSinkConfig{
		Path:       path,
		MaxSizeMB:  10,
		MaxBackups: 9,
		MaxAgeDays: 7,
		Compress:   false,
	}
}

// Setup is the bundle returned by SetupDefaultLogger. Callers stash
// the LevelControl + Bus so handlers can mutate the live level and
// the Logs page can subscribe to new lines. Closer must be Close()d
// on shutdown so the file sink flushes.
type Setup struct {
	// Closer flushes and releases the file sink. Nil when no file path
	// was supplied (dev runs with just stdout).
	Closer io.Closer
	// Level is the shared LevelVar wrapper. Mutating it updates every
	// handler in the fanout (stdout + file + bus) on the next record.
	Level *LevelControl
	// Bus is the in-memory ring + subscriber bus the Logs page reads
	// from. Always non-nil — even in dev runs without a file sink we
	// want the bus so the panel works.
	Bus *LogBus
	// FileSink is the underlying lumberjack rotator. Exposed so callers
	// (and tests) can force a rotation tick by calling
	// FileSink.Rotate().
	FileSink *lumberjack.Logger
}

// Format selects the on-disk and journald wire format of the slog
// handlers. The in-memory LogBus is unaffected — the panel always sees
// structured records regardless.
//
// FormatText (default) is the human-readable key=value layout slog ships.
// FormatJSON emits one JSON object per line so log-shipping tools and
// operators running `journalctl -u sublyne` can parse fields directly.
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

// ParseFormat maps the SUBLYNE_LOG_FORMAT env-var values onto Format.
// Empty / unrecognised values fall through to FormatText so a typo can
// never silently turn on JSON.
func ParseFormat(raw string) Format {
	switch {
	case raw == "":
		return FormatText
	default:
		// Case-insensitive, trim whitespace so a systemd Environment=
		// drop-in with stray padding still works.
		v := raw
		// strings.TrimSpace + ToLower without importing strings — we
		// only need ascii.
		start, end := 0, len(v)
		for start < end && (v[start] == ' ' || v[start] == '\t') {
			start++
		}
		for end > start && (v[end-1] == ' ' || v[end-1] == '\t') {
			end--
		}
		v = v[start:end]
		if len(v) == 4 &&
			(v[0] == 'j' || v[0] == 'J') &&
			(v[1] == 's' || v[1] == 'S') &&
			(v[2] == 'o' || v[2] == 'O') &&
			(v[3] == 'n' || v[3] == 'N') {
			return FormatJSON
		}
		return FormatText
	}
}

// newSlogHandler returns the slog handler matching the requested
// Format. Centralises so both stdout and file sinks pick up the same
// encoding.
func newSlogHandler(w io.Writer, opts *slog.HandlerOptions, format Format) slog.Handler {
	if format == FormatJSON {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// SetupDefaultLogger builds the dual-sink slog.Logger plus the
// in-memory bus, installs it as the default, and returns a Setup the
// caller can wire into the API layer.
//
// fileCfg.Path == "" disables the file sink — callers fall back to
// stdout+bus, which is what dev runs (`go run`) want. Errors creating
// the log directory are logged to stderr and the file sink is then
// disabled rather than failing the process boot; the operator gets
// the panel up, the journal still has every record, and the file
// sink can be fixed without re-installing.
//
// `format` controls the wire encoding of both the stdout (→ journald)
// and the rotating file sinks. SUBLYNE_LOG_FORMAT=json (parsed via
// ParseFormat) flips both to JSON so `journalctl -u sublyne` lines are
// one self-describing object each, with `time / level / msg /
// target / …` keys ready for downstream tooling. The LogBus is always
// structured.
func SetupDefaultLogger(stdout io.Writer, level slog.Level, fileCfg FileSinkConfig, format Format) (*Setup, error) {
	if stdout == nil {
		stdout = os.Stdout
	}
	control := NewLevelControl(level)
	leveler := control.LevelVar()
	bus := NewLogBus(0)

	handlers := []slog.Handler{
		newSlogHandler(stdout, &slog.HandlerOptions{Level: leveler}, format),
	}
	var closer io.Closer
	var fileSink *lumberjack.Logger

	if fileCfg.Path != "" {
		// Ensure the directory exists with the project's standard
		// 0750 mode. Failing this is non-fatal — see doc comment.
		if err := os.MkdirAll(filepath.Dir(fileCfg.Path), 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "logging: create log dir %q failed (file sink disabled): %v\n", filepath.Dir(fileCfg.Path), err)
		} else {
			fileSink = &lumberjack.Logger{
				Filename:   fileCfg.Path,
				MaxSize:    fileCfg.MaxSizeMB,
				MaxBackups: fileCfg.MaxBackups,
				MaxAge:     fileCfg.MaxAgeDays,
				Compress:   fileCfg.Compress,
				// LocalTime=false to match the stdout handler's UTC
				// stamps and journald's wall-clock format.
				LocalTime: false,
			}
			handlers = append(handlers, newSlogHandler(fileSink, &slog.HandlerOptions{Level: leveler}, format))
			closer = fileSink
		}
	}

	// The bus handler always runs; the panel's Logs page is one of the
	// PRD's deliverables and a dev run without the file sink still
	// wants to surface live log lines through it.
	handlers = append(handlers, newBusHandler(bus, leveler))

	var handler slog.Handler
	if len(handlers) == 1 {
		handler = handlers[0]
	} else {
		handler = &fanout{handlers: handlers}
	}
	slog.SetDefault(slog.New(handler))
	return &Setup{Closer: closer, Level: control, Bus: bus, FileSink: fileSink}, nil
}

// fanout is a tiny slog.Handler that mirrors every record to a fixed
// set of sub-handlers. The PRD's two sinks (journald via stdout, file
// via lumberjack) plus the in-memory bus are configured at startup;
// we never add/remove handlers at runtime so a slice + no locks is
// sufficient.
type fanout struct {
	handlers []slog.Handler
}

// Enabled returns true if *any* of the underlying handlers would emit
// at the supplied level. This keeps slog's optimistic short-circuit
// in place — every handler we configure uses the same level filter so
// the answer is uniform in practice.
func (f *fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle dispatches the record to every sub-handler. A failure in one
// sink does not abort the others — that's the whole point of the
// dual-sink design (the file disk filling up must not silence
// journald, and vice versa).
func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	clones := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		clones[i] = h.WithAttrs(attrs)
	}
	return &fanout{handlers: clones}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	clones := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		clones[i] = h.WithGroup(name)
	}
	return &fanout{handlers: clones}
}
