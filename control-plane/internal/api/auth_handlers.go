package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
)

// AuthDeps bundles everything the auth handlers need from the rest of
// the program. It keeps the handler constructors small and lets tests
// substitute fakes (notably a fake clock for lockout windows).
type AuthDeps struct {
	DB       *sql.DB
	Admins   *auth.AdminStore
	Issuer   *auth.Issuer
	Limiter  *auth.Limiter
	Role     string // "client" or "remote"; surfaced via /api/session
	CookieFn func(token string, expiresAt time.Time) *http.Cookie
	// Logger is used for every server-side error in the auth path.
	// The first version of these handlers silently returned 500 with
	// the body "internal error" and logged nothing — that mistake hid
	// a real production-blocking bug for an entire phase. Always set
	// this; tests pass slog.Default() if they don't need to inspect
	// the output.
	Logger *slog.Logger
	// Audit records login outcomes, logout, and password changes.
	// May be nil — handlers degrade silently when audit is disabled.
	Audit *audit.Recorder
}

// logger returns d.Logger or slog.Default() so call sites don't have
// to nil-check.
func (d AuthDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// DefaultCookie builds the session cookie with the PRD-required flags:
// HttpOnly, SameSite=Strict, Path=/. We never set Secure because
// PRD §4.1 pins the panel to plain HTTP.
func DefaultCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   false, // PRD §4.1: HTTP only
		SameSite: http.SameSiteStrictMode,
	}
}

// clearedCookie is what /api/logout sends to evict the session.
func clearedCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionResponse struct {
	Username          string     `json:"username"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	ServerRole        string     `json:"server_role"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// LoginHandler validates the supplied credentials, persists the
// attempt, and issues a JWT on success.
func LoginHandler(d AuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)

		// Brute-force gate first. We don't want to consume CPU on
		// Argon2 verification for an IP that's already locked out.
		decision, err := d.Limiter.Check(r.Context(), ip)
		if err != nil {
			d.logger().Error("login: rate-limiter check failed",
				"ip", ip, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "rate limiter unavailable")
			return
		}
		if !decision.Allowed {
			secs := int(decision.RetryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			if d.Audit != nil {
				d.Audit.Record(r.Context(), audit.ActionLoginFailure, audit.ActorSystem, ip, "admin", map[string]any{
					"reason": "rate_limited",
				})
			}
			writeJSONError(w, http.StatusTooManyRequests, "too many login attempts; try again later")
			return
		}

		var req loginRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			recordAttempt(r.Context(), d.Limiter, ip, false)
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Username == "" || req.Password == "" {
			recordAttempt(r.Context(), d.Limiter, ip, false)
			writeJSONError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		admin, err := d.Admins.Get(r.Context())
		if err != nil {
			if errors.Is(err, auth.ErrAdminNotFound) {
				d.logger().Warn("login: admin row missing — bootstrap-admin.toml never consumed?",
					"ip", ip, "username", req.Username)
				writeJSONError(w, http.StatusServiceUnavailable, "admin not yet provisioned")
				return
			}
			// THIS is the line that produced the silent 500 in Phase
			// 8a. Always log the wrapped DB error before responding.
			d.logger().Error("login: admin store read failed",
				"ip", ip, "username", req.Username, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Constant-time username comparison so an attacker can't
		// timing-probe which username belongs to the admin row.
		usernameOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(admin.Username)) == 1
		var passwordOK bool
		if usernameOK {
			passwordOK = auth.VerifyPassword(admin.PasswordHash, req.Password) == nil
		} else {
			// Run a dummy verify so the timing of the failure path
			// approximates the success path. We discard the result.
			_ = auth.VerifyPassword(admin.PasswordHash, req.Password)
		}

		if !usernameOK || !passwordOK {
			recordAttempt(r.Context(), d.Limiter, ip, false)
			if d.Audit != nil {
				d.Audit.Record(r.Context(), audit.ActionLoginFailure, audit.ActorSystem, ip, req.Username, map[string]any{
					"reason": "bad_credentials",
				})
			}
			writeJSONError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}

		token, expiresAt, err := d.Issuer.Issue(r.Context(), admin.ID)
		if err != nil {
			d.logger().Error("login: jwt issue failed",
				"ip", ip, "username", req.Username, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not issue token")
			return
		}
		recordAttempt(r.Context(), d.Limiter, ip, true)
		if d.Audit != nil {
			d.Audit.Record(r.Context(), audit.ActionLoginSuccess, admin.Username, ip, admin.Username, map[string]any{
				"username": admin.Username,
			})
		}

		cookie := d.CookieFn(token, expiresAt)
		http.SetCookie(w, cookie)
		writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: expiresAt})
	}
}

// LogoutHandler clears the session cookie. It does not invalidate
// the JWT (we have no per-token denylist in v0.1.0); to force a
// global logout the operator rotates the signing key (future feature).
//
// Audit-aware variant: when the AuthDeps Audit recorder is non-nil
// every logout produces a row so the panel's Audit page shows the
// admin's full session lifecycle.
func LogoutHandler(d AuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, clearedCookie())
		if d.Audit != nil {
			actor := audit.ActorAdmin
			if admin, ok := AdminFromContext(r.Context()); ok {
				actor = admin.Username
			}
			d.Audit.Record(r.Context(), audit.ActionLogout, actor, ClientIP(r), actor, nil)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// SessionHandler returns the authenticated admin's identity and the
// server role. RequireAuth guarantees the context has an admin.
func SessionHandler(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin, ok := AdminFromContext(r.Context())
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		resp := sessionResponse{
			Username:   admin.Username,
			ServerRole: role,
		}
		if admin.PasswordChangedAt.Valid {
			t := admin.PasswordChangedAt.Time
			resp.PasswordChangedAt = &t
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// PasswordChangeHandler validates the current password and rotates it
// to the new one. The handler does not issue a fresh JWT — existing
// tokens remain valid for the rest of their TTL, which matches the
// "single admin, single device" model the PRD describes. If we wanted
// to force a global logout, we'd rotate the signing key here.
func PasswordChangeHandler(d AuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin, ok := AdminFromContext(r.Context())
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var req passwordChangeRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.CurrentPassword == "" || req.NewPassword == "" {
			writeJSONError(w, http.StatusBadRequest, "current_password and new_password are required")
			return
		}
		if req.CurrentPassword == req.NewPassword {
			writeJSONError(w, http.StatusBadRequest, "new password must differ from current password")
			return
		}
		if len(req.NewPassword) < 8 {
			writeJSONError(w, http.StatusBadRequest, "new password must be at least 8 characters")
			return
		}
		if err := auth.VerifyPassword(admin.PasswordHash, req.CurrentPassword); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "current password incorrect")
			return
		}
		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			d.logger().Error("password-change: hash failed",
				"admin", admin.Username, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not hash new password")
			return
		}
		if err := d.Admins.UpdatePassword(r.Context(), newHash); err != nil {
			d.logger().Error("password-change: db update failed",
				"admin", admin.Username, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not update password")
			return
		}
		if d.Audit != nil {
			d.Audit.Record(r.Context(), audit.ActionPasswordChange, admin.Username, ClientIP(r), admin.Username, nil)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func recordAttempt(ctx context.Context, lim *auth.Limiter, ip string, success bool) {
	// We deliberately discard the error; recording is best-effort
	// and the operator already gets the failure via the actual login
	// response. The pruner reclaims any orphaned rows.
	_ = lim.Record(ctx, ip, success)
}
