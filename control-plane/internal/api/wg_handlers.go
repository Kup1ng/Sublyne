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
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// WGDeps bundles everything the WireGuard config handlers need. The
// router constructor only mounts /api/wg-configs when both Repo and
// Manager are set — there's no useful behaviour for a panel where
// configs can be stored but not brought up.
type WGDeps struct {
	Repo    *wg.Repo
	Manager wg.Manager
	Logger  *slog.Logger

	// TunnelRepo is consulted by the per-config handshake handler to
	// find which kernel interfaces this config drives. Phase 11 added
	// this when fixing the "No handshake yet" display bug: the old
	// code only resolved a handshake when the caller passed
	// ?tunnel_id=N, which the panel never did. With the repo on hand
	// we now look up every tunnel that references the config and ask
	// the kernel about its peer state.
	TunnelRepo *tunnels.Repo

	// Audit records wg-config create/update/delete actions. May be
	// nil — handlers skip the record on nil.
	Audit *audit.Recorder
}

// actorOf returns the audit actor for the request (admin username,
// falling back to "admin" when the context has no admin attached).
func (d WGDeps) actorOf(r *http.Request) string {
	if a, ok := AdminFromContext(r.Context()); ok {
		return a.Username
	}
	return audit.ActorAdmin
}

func (d WGDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// RedactedRawText is the placeholder string the API substitutes for
// raw_text on every list / get / update response. PRD §5 pins
// WireGuard private keys as one of the four secret values that must
// never leave the process by default; reveal=1 is the explicit opt-in.
const RedactedRawText = "***"

// wgConfigDTO is the wire shape the panel consumes. raw_text is
// included unconditionally but is the RedactedRawText placeholder
// unless the caller asked for reveal=1 (and even then, only for Get
// by id).
type wgConfigDTO struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	RawText          string `json:"raw_text"`
	InterfaceAddress string `json:"interface_address"`
	Endpoint         string `json:"endpoint"`
	PublicKeySelf    string `json:"public_key_self"`
	MTU              *int   `json:"mtu"`
	ListenPort       *int   `json:"listen_port"`
	PeerCount        int    `json:"peer_count"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

func wgToDTO(c wg.Config, reveal bool) wgConfigDTO {
	dto := wgConfigDTO{
		ID:               c.ID,
		Name:             c.Name,
		InterfaceAddress: c.InterfaceAddress,
		Endpoint:         c.Endpoint,
		PublicKeySelf:    c.PublicKeySelf,
		PeerCount:        c.PeerCount,
		CreatedAt:        c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        c.UpdatedAt.Format(time.RFC3339),
	}
	if reveal {
		dto.RawText = c.RawText
	} else {
		dto.RawText = RedactedRawText
	}
	if c.MTU.Valid {
		v := int(c.MTU.Int64)
		dto.MTU = &v
	}
	if c.ListenPort.Valid {
		v := int(c.ListenPort.Int64)
		dto.ListenPort = &v
	}
	return dto
}

// wgConfigInput is the body the panel posts on create / update. The
// name is mandatory; raw_text is mandatory on create but optional on
// update (omitted means "rename only — keep the existing bytes").
type wgConfigInput struct {
	Name    string  `json:"name"`
	RawText *string `json:"raw_text"`
}

// MountWGRoutes wires every WG-config endpoint onto the supplied
// subrouter. Caller is responsible for wrapping the parent group in
// RequireAuth — the handlers themselves do not authenticate.
func MountWGRoutes(r chi.Router, deps WGDeps) {
	r.Get("/", ListWGConfigsHandler(deps))
	r.Post("/", CreateWGConfigHandler(deps))
	r.Get("/{id}", GetWGConfigHandler(deps))
	r.Put("/{id}", UpdateWGConfigHandler(deps))
	r.Delete("/{id}", DeleteWGConfigHandler(deps))
	r.Get("/{id}/handshake", HandshakeWGConfigHandler(deps))
}

// ListWGConfigsHandler returns every stored config with raw_text
// redacted. Used by the panel's WireGuard page and by the tunnel
// edit form's picker dropdown.
func ListWGConfigsHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := deps.Repo.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load WireGuard configs")
			return
		}
		out := make([]wgConfigDTO, 0, len(rows))
		for _, c := range rows {
			out = append(out, wgToDTO(c, false))
		}
		writeJSON(w, http.StatusOK, map[string]any{"configs": out})
	}
}

// GetWGConfigHandler returns one config by id. raw_text is redacted
// unless the request carries `?reveal=1`, in which case the caller
// gets the original pasted bytes. The single-user, single-admin model
// makes this a low-risk affordance — the explicit query parameter
// prevents accidental copy-paste exposure.
func GetWGConfigHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := wgConfigIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		c, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, wg.ErrConfigNotFound) {
			writeJSONError(w, http.StatusNotFound, "WireGuard config not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load WireGuard config")
			return
		}
		reveal := r.URL.Query().Get("reveal") == "1"
		writeJSON(w, http.StatusOK, wgToDTO(c, reveal))
	}
}

// CreateWGConfigHandler parses the pasted text, derives the summary
// columns, and inserts the row. The response is the freshly-persisted
// config with raw_text redacted. Parser warnings ride along in a
// separate field so the operator can see what the project did with
// any DNS / PostUp / unknown directives it found.
func CreateWGConfigHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in wgConfigInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" {
			writeWGValidation(w, "name", "Give this WireGuard config a short, memorable name.")
			return
		}
		if in.RawText == nil || strings.TrimSpace(*in.RawText) == "" {
			writeWGValidation(w, "raw_text", "Paste the WireGuard config text.")
			return
		}
		parsed, err := wg.ParseConfig(*in.RawText)
		if err != nil {
			writeWGValidation(w, "raw_text", err.Error())
			return
		}
		c := buildConfigFromParsed(in.Name, *in.RawText, parsed)
		out, err := deps.Repo.Create(r.Context(), c)
		if errors.Is(err, wg.ErrConfigNameTaken) {
			writeJSONError(w, http.StatusConflict, "A WireGuard config with that name already exists.")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not store WireGuard config")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionWGConfigCreate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"wg_config_id": out.ID,
				"endpoint":     out.Endpoint,
				"peer_count":   out.PeerCount,
			})
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"config":   wgToDTO(out, false),
			"warnings": parsed.Warnings,
		})
	}
}

// UpdateWGConfigHandler updates an existing config. If raw_text is
// omitted the caller is renaming the row — the parser is not re-run.
// If raw_text is supplied the new bytes are parsed and the summary
// columns are recomputed.
func UpdateWGConfigHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := wgConfigIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		var in wgConfigInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" {
			writeWGValidation(w, "name", "Name is required.")
			return
		}

		existing, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, wg.ErrConfigNotFound) {
			writeJSONError(w, http.StatusNotFound, "WireGuard config not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load WireGuard config")
			return
		}

		keepRaw := in.RawText == nil
		var warnings []string
		c := wg.Config{ID: existing.ID, Name: in.Name}
		if !keepRaw {
			if strings.TrimSpace(*in.RawText) == "" {
				writeWGValidation(w, "raw_text", "Paste the WireGuard config text or omit raw_text to keep the existing bytes.")
				return
			}
			parsed, err := wg.ParseConfig(*in.RawText)
			if err != nil {
				writeWGValidation(w, "raw_text", err.Error())
				return
			}
			c = buildConfigFromParsed(in.Name, *in.RawText, parsed)
			c.ID = existing.ID
			warnings = parsed.Warnings
		}

		out, err := deps.Repo.Update(r.Context(), c, keepRaw)
		if errors.Is(err, wg.ErrConfigNameTaken) {
			writeJSONError(w, http.StatusConflict, "A WireGuard config with that name already exists.")
			return
		}
		if errors.Is(err, wg.ErrConfigNotFound) {
			writeJSONError(w, http.StatusNotFound, "WireGuard config not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not update WireGuard config")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionWGConfigUpdate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"wg_config_id":  out.ID,
				"raw_text_kept": keepRaw,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"config":   wgToDTO(out, false),
			"warnings": warnings,
		})
	}
}

// DeleteWGConfigHandler refuses to delete a config that any tunnel
// references via wg_config_id. The 409 body lists the tunnel names so
// the operator knows where to detach the link first.
func DeleteWGConfigHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := wgConfigIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Capture the name BEFORE delete so the audit row has a target.
		var name string
		if c, err := deps.Repo.Get(r.Context(), id); err == nil {
			name = c.Name
		}
		err = deps.Repo.Delete(r.Context(), id)
		if errors.Is(err, wg.ErrConfigNotFound) {
			writeJSONError(w, http.StatusNotFound, "WireGuard config not found")
			return
		}
		if errors.Is(err, wg.ErrConfigReferenced) {
			names, _ := deps.Repo.ReferencingTunnels(r.Context(), id)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "This WireGuard config is in use by one or more tunnels. Detach the link first.",
				"tunnels": names,
			})
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not delete WireGuard config")
			return
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionWGConfigDelete, deps.actorOf(r), ClientIP(r), name, map[string]any{
				"wg_config_id": id,
			})
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// HandshakeWGConfigHandler reports the most-recent handshake for the
// config's currently-up interface. The endpoint is keyed by config id
// rather than tunnel id because the panel's WireGuard page renders
// the status next to the config row (a config may not be linked to a
// running tunnel — the response then says "no interface up").
//
// Phase 11 bug fix: the Phase 7 version only resolved a handshake when
// the caller passed `?tunnel_id=N`, which the panel never did. The
// dashboard therefore stayed at "No handshake yet" even when
// `wg show` on the host reported a fresh handshake. The fix walks
// every tunnel that references this config (via tunnels.wg_config_id)
// and asks wgctrl about its peer state, picking the freshest. If the
// caller still passes ?tunnel_id= explicitly we use that as a
// shortcut.
func HandshakeWGConfigHandler(deps WGDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := wgConfigIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := deps.Repo.Get(r.Context(), id); err != nil {
			if errors.Is(err, wg.ErrConfigNotFound) {
				writeJSONError(w, http.StatusNotFound, "WireGuard config not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "could not load WireGuard config")
			return
		}
		status := freshestHandshake(r, deps, id)
		out := map[string]any{
			"interface_name":     status.InterfaceName,
			"has_ever_connected": status.HasEverConnected,
			"stale":              status.Stale(),
		}
		if !status.LastHandshake.IsZero() {
			out["last_handshake"] = status.LastHandshake.Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// freshestHandshake resolves the freshest handshake observed across
// every tunnel that references `cfgID`. Returns an empty status when:
//
//   - the WG manager is the non-Linux stub (`Supported()==false`);
//   - the tunnel repo is unavailable (handler wired without it);
//   - no tunnel references the config.
//
// A `?tunnel_id=N` query parameter remains supported as an explicit
// shortcut for callers that already know which tunnel they want — the
// panel's wireguard page passes it on the WG card.
func freshestHandshake(r *http.Request, deps WGDeps, cfgID int64) wg.HandshakeStatus {
	if deps.Manager == nil || !deps.Manager.Supported() {
		return wg.HandshakeStatus{}
	}
	// Explicit per-tunnel lookup remains an option — useful when the
	// caller already knows the id (e.g. the tunnel-detail page).
	if tunnelIDStr := r.URL.Query().Get("tunnel_id"); tunnelIDStr != "" {
		tid, err := strconv.ParseInt(tunnelIDStr, 10, 64)
		if err == nil && tid > 0 {
			st, err := deps.Manager.Handshake(r.Context(), tid)
			if err != nil {
				deps.logger().Debug("wg: handshake lookup failed", "tunnel_id", tid, "err", err)
				return wg.HandshakeStatus{InterfaceName: wg.InterfaceNameFor(tid)}
			}
			return st
		}
	}
	if deps.TunnelRepo == nil {
		return wg.HandshakeStatus{}
	}
	allTunnels, err := deps.TunnelRepo.List(r.Context())
	if err != nil {
		deps.logger().Debug("wg: list tunnels for handshake failed", "err", err)
		return wg.HandshakeStatus{}
	}
	var best wg.HandshakeStatus
	for _, t := range allTunnels {
		if !linksConfig(t, cfgID) {
			continue
		}
		st, err := deps.Manager.Handshake(r.Context(), t.ID)
		if err != nil {
			deps.logger().Debug("wg: handshake lookup failed", "tunnel_id", t.ID, "err", err)
			continue
		}
		if best.InterfaceName == "" {
			best.InterfaceName = st.InterfaceName
		}
		if st.HasEverConnected && st.LastHandshake.After(best.LastHandshake) {
			best = st
		}
	}
	return best
}

// linksConfig returns true when a tunnel references the given WG
// config. Centralised so the handshake handler and the metrics handler
// agree on what "uses this config" means.
func linksConfig(t tunnels.Tunnel, cfgID int64) bool {
	return t.WGConfigID.Valid && t.WGConfigID.Int64 == cfgID
}

func buildConfigFromParsed(name, rawText string, parsed *wg.ParsedConfig) wg.Config {
	c := wg.Config{
		Name:             name,
		RawText:          rawText,
		InterfaceAddress: parsed.AddressesAsString(),
		Endpoint:         parsed.FirstEndpoint(),
		PublicKeySelf:    parsed.PublicKeySelf(),
		PeerCount:        len(parsed.Peers),
	}
	if parsed.Interface.MTU > 0 {
		c.MTU = sql.NullInt64{Int64: int64(parsed.Interface.MTU), Valid: true}
	}
	if parsed.Interface.ListenPort > 0 {
		c.ListenPort = sql.NullInt64{Int64: int64(parsed.Interface.ListenPort), Valid: true}
	}
	return c
}

func wgConfigIDFromURL(r *http.Request) (int64, error) {
	raw := chi.URLParam(r, "id")
	if raw == "" {
		return 0, errors.New("missing config id")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid config id")
	}
	return id, nil
}

func writeWGValidation(w http.ResponseWriter, field, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":  "Some fields need attention.",
		"fields": map[string]string{field: msg},
	})
}
