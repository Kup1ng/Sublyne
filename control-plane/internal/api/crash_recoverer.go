package api

import (
	"log/slog"
	"net/http"

	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
)

// CrashRecoverer is the HTTP middleware that catches a panic from
// any downstream handler, writes a crash-<unix>.log file to the
// logging.CrashDir() directory, logs to journald, and replies 500.
//
// Why a custom one and not chi/middleware.Recoverer? chi's recoverer
// only writes the stack to its own logger; we need the disk file
// because PROJECT_REQUIREMENTS §8.2 demands one-per-crash so the
// panel's Crash reports tab can list them. Wrapping `chi.Recoverer`
// would still miss the file write, so we install ours at the same
// position in the chain.
func CrashRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// http.ErrAbortHandler is the documented "abort without
			// stack trace" path. Don't write a crash log for it.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			body := logging.FormatPanic(rec, r.Method+" "+r.URL.Path)
			// SafePanicMessage strips struct bodies — see FormatPanic
			// for why. slog's text handler would otherwise %+v the
			// raw recovered value, which could include secret fields
			// (PSK, JWT key, WG private key) if a future handler
			// panics with a credential-bearing struct.
			panicMsg := logging.SafePanicMessage(rec)
			if dir := logging.CrashDir(); dir != "" {
				if name, err := logging.WriteCrashReport(dir, body); err != nil {
					slog.Error("crash: write report failed",
						"path", r.URL.Path, "err", err)
				} else {
					slog.Error("crash: handler panicked; crash log written",
						"file", name, "path", r.URL.Path, "panic", panicMsg)
				}
			} else {
				slog.Error("crash: handler panicked; crash dir not configured",
					"path", r.URL.Path, "panic", panicMsg)
			}
			// Don't trust the in-flight headers — the handler may have
			// already partially-written the response. Best-effort 500.
			defer func() { _ = recover() }()
			w.WriteHeader(http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}
