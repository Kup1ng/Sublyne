package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
)

// SOCKS5Deps bundles everything the SOCKS5 proxy handlers need. The
// router constructor only mounts /api/socks5-proxies when Repo is set
// so tests that don't care about SOCKS5 can leave the field zero.
//
// No Manager analog (unlike WGDeps) — R8 is config + storage only;
// R9 adds the dataplane SOCKS5 client and the IPC payload extension.
type SOCKS5Deps struct {
	Repo   *socks5.Repo
	Logger *slog.Logger

	// Audit records socks5_proxy_create/update/delete actions. May be
	// nil — handlers skip the record on nil.
	Audit *audit.Recorder
}

func (d SOCKS5Deps) actorOf(r *http.Request) string {
	if a, ok := AdminFromContext(r.Context()); ok {
		return a.Username
	}
	return audit.ActorAdmin
}

// RedactedPassword is the placeholder string the API substitutes for
// password on every list / get / update response. PRD §5 pins the
// SOCKS5 password alongside PSKs and WG private keys as a secret
// that must never leave the process by default; reveal=1 is the
// explicit opt-in (mirrors wireguard_configs.raw_text + tunnels.psk).
const RedactedPassword = "***"

// socks5ProxyDTO is the wire shape the panel consumes. Optional
// fields are *string / *int so the form can tell "set to empty" from
// "not set" (NULL in the DB).
type socks5ProxyDTO struct {
	ID                  int64   `json:"id"`
	Name                string  `json:"name"`
	Host                string  `json:"host"`
	Port                int     `json:"port"`
	Username            *string `json:"username"`
	Password            *string `json:"password"`
	ParallelConnections int     `json:"parallel_connections"`
	MinReadySlots       int     `json:"min_ready_slots"`
	Notes               *string `json:"notes"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

func socks5ToDTO(p socks5.Proxy, reveal bool) socks5ProxyDTO {
	dto := socks5ProxyDTO{
		ID:                  p.ID,
		Name:                p.Name,
		Host:                p.Host,
		Port:                p.Port,
		ParallelConnections: p.ParallelConnections,
		MinReadySlots:       p.MinReadySlots,
		CreatedAt:           p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:           p.UpdatedAt.Format(time.RFC3339),
	}
	if p.Username.Valid {
		s := p.Username.String
		dto.Username = &s
	}
	if p.Password.Valid {
		if reveal {
			s := p.Password.String
			dto.Password = &s
		} else {
			s := RedactedPassword
			dto.Password = &s
		}
	}
	if p.Notes.Valid {
		s := p.Notes.String
		dto.Notes = &s
	}
	return dto
}

// socks5ProxyInput is the body the panel posts on create / update.
// password is a pointer so PUT-without-password keeps the existing
// secret (same convention as tunnels.psk and wireguard_configs.raw_text).
type socks5ProxyInput struct {
	Name                string  `json:"name"`
	Host                string  `json:"host"`
	Port                int     `json:"port"`
	Username            *string `json:"username"`
	Password            *string `json:"password"`
	ParallelConnections int     `json:"parallel_connections"`
	MinReadySlots       int     `json:"min_ready_slots"`
	Notes               *string `json:"notes"`
}

func (in *socks5ProxyInput) applyDefaults() {
	if in.ParallelConnections == 0 {
		in.ParallelConnections = 4
	}
	if in.MinReadySlots == 0 {
		// Default warm-up gate: half the pool, rounded up, clamped to
		// at least 1 and at most ParallelConnections.
		half := (in.ParallelConnections + 1) / 2
		if half < 1 {
			half = 1
		}
		if half > in.ParallelConnections {
			half = in.ParallelConnections
		}
		in.MinReadySlots = half
	}
}

// MountSOCKS5Routes wires every SOCKS5 proxy endpoint onto the
// supplied subrouter. Caller is responsible for wrapping the parent
// group in RequireAuth — these handlers do not authenticate.
func MountSOCKS5Routes(r chi.Router, deps SOCKS5Deps) {
	r.Get("/", ListSOCKS5ProxiesHandler(deps))
	r.Post("/", CreateSOCKS5ProxyHandler(deps))
	r.Get("/{id}", GetSOCKS5ProxyHandler(deps))
	r.Put("/{id}", UpdateSOCKS5ProxyHandler(deps))
	r.Delete("/{id}", DeleteSOCKS5ProxyHandler(deps))
}

// ListSOCKS5ProxiesHandler returns every stored proxy with the
// password redacted. Used by the panel's SOCKS5 page and by the
// tunnel edit form's SOCKS5 picker dropdown.
func ListSOCKS5ProxiesHandler(deps SOCKS5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := deps.Repo.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load SOCKS5 proxies")
			return
		}
		out := make([]socks5ProxyDTO, 0, len(rows))
		for _, p := range rows {
			out = append(out, socks5ToDTO(p, false))
		}
		writeJSON(w, http.StatusOK, map[string]any{"proxies": out})
	}
}

// GetSOCKS5ProxyHandler returns one proxy by id. Password is redacted
// unless the request carries `?reveal=1`, in which case the caller
// gets the stored bytes. The single-user, single-admin model makes
// this a low-risk affordance — the explicit query parameter prevents
// accidental copy-paste exposure.
func GetSOCKS5ProxyHandler(deps SOCKS5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := socks5ProxyIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		p, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, socks5.ErrProxyNotFound) {
			writeJSONError(w, http.StatusNotFound, "SOCKS5 proxy not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load SOCKS5 proxy")
			return
		}
		reveal := r.URL.Query().Get("reveal") == "1"
		writeJSON(w, http.StatusOK, socks5ToDTO(p, reveal))
	}
}

// CreateSOCKS5ProxyHandler validates the body, then inserts the row.
// The response is the freshly-persisted proxy with password redacted.
func CreateSOCKS5ProxyHandler(deps SOCKS5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in socks5ProxyInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.applyDefaults()

		if ve := validateSOCKS5Input(&in, false); ve != nil {
			writeSOCKS5Validation(w, ve)
			return
		}

		proxy := socks5Proxy(in)
		out, err := deps.Repo.Create(r.Context(), proxy)
		if errors.Is(err, socks5.ErrProxyNameTaken) {
			writeJSONError(w, http.StatusConflict, "A SOCKS5 proxy with that name already exists.")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not store SOCKS5 proxy")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionSocks5ProxyCreate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"socks5_proxy_id":      out.ID,
				"host":                 out.Host,
				"port":                 out.Port,
				"parallel_connections": out.ParallelConnections,
				"has_auth":             out.Username.Valid,
			})
		}
		writeJSON(w, http.StatusCreated, map[string]any{"proxy": socks5ToDTO(out, false)})
	}
}

// UpdateSOCKS5ProxyHandler updates an existing proxy. If `password`
// is omitted (JSON null) the existing secret is preserved; otherwise
// the supplied value replaces it. Empty string clears the password
// (operator switched from authed to no-auth).
func UpdateSOCKS5ProxyHandler(deps SOCKS5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := socks5ProxyIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := deps.Repo.Get(r.Context(), id); err != nil {
			if errors.Is(err, socks5.ErrProxyNotFound) {
				writeJSONError(w, http.StatusNotFound, "SOCKS5 proxy not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "could not load SOCKS5 proxy")
			return
		}

		var in socks5ProxyInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.applyDefaults()

		keepPassword := in.Password == nil
		if ve := validateSOCKS5Input(&in, keepPassword); ve != nil {
			writeSOCKS5Validation(w, ve)
			return
		}

		proxy := socks5Proxy(in)
		proxy.ID = id

		out, err := deps.Repo.Update(r.Context(), proxy, keepPassword)
		if errors.Is(err, socks5.ErrProxyNameTaken) {
			writeJSONError(w, http.StatusConflict, "A SOCKS5 proxy with that name already exists.")
			return
		}
		if errors.Is(err, socks5.ErrProxyNotFound) {
			writeJSONError(w, http.StatusNotFound, "SOCKS5 proxy not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not update SOCKS5 proxy")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionSocks5ProxyUpdate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"socks5_proxy_id":  out.ID,
				"password_changed": !keepPassword,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"proxy": socks5ToDTO(out, false)})
	}
}

// DeleteSOCKS5ProxyHandler refuses to delete a proxy that any tunnel
// references via socks5_proxy_id. The 409 body lists the tunnel
// names so the operator knows where to detach the link first.
func DeleteSOCKS5ProxyHandler(deps SOCKS5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := socks5ProxyIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Capture the name BEFORE delete so the audit row has a target.
		var name string
		if p, err := deps.Repo.Get(r.Context(), id); err == nil {
			name = p.Name
		}
		err = deps.Repo.Delete(r.Context(), id)
		if errors.Is(err, socks5.ErrProxyNotFound) {
			writeJSONError(w, http.StatusNotFound, "SOCKS5 proxy not found")
			return
		}
		if errors.Is(err, socks5.ErrProxyReferenced) {
			names, _ := deps.Repo.ReferencingTunnels(r.Context(), id)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "This SOCKS5 proxy is in use by one or more tunnels. Detach the link first.",
				"tunnels": names,
			})
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not delete SOCKS5 proxy")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionSocks5ProxyDelete, deps.actorOf(r), ClientIP(r), name, map[string]any{
				"socks5_proxy_id": id,
			})
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// socks5ValidationError mirrors tunnels.ValidationError so the
// response shape is consistent across the panel.
type socks5ValidationError struct {
	Fields map[string]string
}

// validateSOCKS5Input enforces field rules from the R8 deliverables
// and the socks5-upload skill. keepPassword=true on update means we
// don't require the password field to be present (the operator left
// the secret untouched on the form).
func validateSOCKS5Input(in *socks5ProxyInput, keepPassword bool) *socks5ValidationError {
	ve := &socks5ValidationError{Fields: map[string]string{}}

	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "":
		ve.Fields["name"] = "Name is required."
	case len(in.Name) > 64:
		ve.Fields["name"] = "Name must be 64 characters or fewer."
	}

	in.Host = strings.TrimSpace(in.Host)
	if in.Host == "" {
		ve.Fields["host"] = "Proxy host is required (IPv4, IPv6, or hostname)."
	}

	if in.Port < 1 || in.Port > 65535 {
		ve.Fields["port"] = "Port must be between 1 and 65535."
	}

	// Username + password: both NULL or both non-NULL — see skill's
	// "Validation gotchas". An empty-string username with a set
	// password (or vice versa) is treated as half-configured.
	hasUsername := in.Username != nil && strings.TrimSpace(*in.Username) != ""
	hasPasswordField := in.Password != nil
	hasPasswordValue := hasPasswordField && strings.TrimSpace(*in.Password) != ""
	if hasUsername && !hasPasswordValue && !keepPassword {
		ve.Fields["password"] = "Password is required when a username is set."
	}
	if hasPasswordValue && !hasUsername {
		ve.Fields["username"] = "Username is required when a password is set."
	}

	if in.ParallelConnections < 1 || in.ParallelConnections > 64 {
		ve.Fields["parallel_connections"] = "Parallel connections must be between 1 and 64."
	}

	if in.MinReadySlots < 1 {
		ve.Fields["min_ready_slots"] = "Minimum ready slots must be at least 1."
	} else if in.MinReadySlots > in.ParallelConnections {
		ve.Fields["min_ready_slots"] = "Minimum ready slots cannot exceed parallel connections."
	}

	if len(ve.Fields) == 0 {
		return nil
	}
	return ve
}

// socks5Proxy converts validated input into the persistence struct.
// Empty optional fields land as sql.NullString{Valid: false}; the
// password is left at the input's literal value (the repo's
// keepPassword path is responsible for preserving the secret on
// update when the operator didn't supply one).
func socks5Proxy(in socks5ProxyInput) socks5.Proxy {
	p := socks5.Proxy{
		Name:                in.Name,
		Host:                in.Host,
		Port:                in.Port,
		ParallelConnections: in.ParallelConnections,
		MinReadySlots:       in.MinReadySlots,
	}
	if in.Username != nil {
		s := strings.TrimSpace(*in.Username)
		if s != "" {
			p.Username = sql.NullString{String: s, Valid: true}
		}
	}
	if in.Password != nil {
		s := *in.Password
		if s != "" {
			p.Password = sql.NullString{String: s, Valid: true}
		}
	}
	if in.Notes != nil {
		s := strings.TrimSpace(*in.Notes)
		if s != "" {
			p.Notes = sql.NullString{String: s, Valid: true}
		}
	}
	return p
}

func socks5ProxyIDFromURL(r *http.Request) (int64, error) {
	raw := chi.URLParam(r, "id")
	if raw == "" {
		return 0, errors.New("missing proxy id")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid proxy id")
	}
	return id, nil
}

func writeSOCKS5Validation(w http.ResponseWriter, ve *socks5ValidationError) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":  "Some fields need attention.",
		"fields": ve.Fields,
	})
}
