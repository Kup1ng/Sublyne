// Package api wires the control-plane HTTP routes for Phase 3:
// login, logout, session lookup, and password change. It is a thin
// glue layer between chi handlers and the auth package; later phases
// will add tunnel, WireGuard, metrics, and WebSocket routes here.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
)

// SessionCookieName is the cookie the panel sets after a successful
// login. The name is deliberately project-specific so an admin who
// uses the panel from a browser that already has other cookies on
// the same origin doesn't collide.
const SessionCookieName = "sublyne_token"

type contextKey string

const adminContextKey contextKey = "admin"

// AdminFromContext returns the authenticated admin attached by
// RequireAuth. ok is false if RequireAuth was not in the chain or
// rejected the request.
func AdminFromContext(ctx context.Context) (auth.Admin, bool) {
	a, ok := ctx.Value(adminContextKey).(auth.Admin)
	return a, ok
}

// RequireAuth is the middleware that all protected routes mount
// behind. It accepts a JWT in either:
//   - the sublyne_token cookie, or
//   - the Authorization: Bearer <token> header.
//
// On success the admin row is loaded once and attached to the
// request context. On failure the request is terminated with 401
// and a JSON error body. The middleware never reveals which check
// failed (missing token vs invalid signature vs expired) to keep
// the surface area minimal for attackers.
func RequireAuth(issuer *auth.Issuer, admins *auth.AdminStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractToken(r)
			if !ok {
				writeUnauthorized(w)
				return
			}
			claims, err := issuer.Validate(r.Context(), raw)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			admin, err := admins.Get(r.Context())
			if err != nil {
				if errors.Is(err, auth.ErrAdminNotFound) {
					slog.Warn("auth-middleware: admin row missing",
						"ip", ClientIP(r), "path", r.URL.Path)
					writeJSONError(w, http.StatusServiceUnavailable, "admin not yet provisioned")
					return
				}
				slog.Error("auth-middleware: admin store read failed",
					"ip", ClientIP(r), "path", r.URL.Path, "err", err)
				writeJSONError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if claims.AdminID != admin.ID {
				writeUnauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), adminContextKey, admin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken returns the bearer token from the request, preferring
// the cookie (browser session) over the Authorization header (API
// clients). Both are accepted because PROJECT_REQUIREMENTS §4.2
// requires it.
func extractToken(r *http.Request) (string, bool) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value, true
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		v := strings.TrimSpace(h[len(prefix):])
		if v != "" {
			return v, true
		}
	}
	return "", false
}

// ClientIP returns the network IP of the requesting client. We rely
// on net/http's RemoteAddr because the PRD pins the panel to direct
// HTTP (no reverse proxy/TLS terminator), so X-Forwarded-For is not
// trusted. If a future phase adds a trusted proxy this is the single
// place to teach.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeUnauthorized(w http.ResponseWriter) {
	writeJSONError(w, http.StatusUnauthorized, "unauthorized")
}
