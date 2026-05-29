package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplane"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// TunnelDeps bundles everything the tunnel handlers need. The handler
// constructors take it by value so a router can build the closure set
// once at startup.
//
// Phase 7 adds the WireGuard repo and manager pair: when a Client
// tunnel with wg_config_id is started, the handler fetches the
// pasted config from WGRepo, parses it, and asks WGManager to bring
// the sub-wg-<id> interface up. WGRepo / WGManager may be nil — the
// router only mounts the WG-aware paths when both are set.
//
// Phase 8a adds Dataplane: the manager wrapping the IPC client to
// the Rust dataplane. nil → tunnel start returns an explanatory error
// (used in dev builds without -tags=embed).
type TunnelDeps struct {
	Repo       *tunnels.Repo
	ServerRole tunnels.Role
	WGRepo     *wg.Repo
	WGManager  wg.Manager
	// SOCKS5Repo (Phase R8): consulted by the tunnel handlers to verify
	// that a referenced socks5_proxy_id actually exists before save.
	// May be nil in tests / dev builds that don't exercise the SOCKS5
	// upload path.
	SOCKS5Repo *socks5.Repo
	Dataplane  *dataplane.Manager
	Logger     *slog.Logger
	// Audit records create/update/delete/start/stop/import actions.
	// May be nil — handlers skip the record on nil.
	Audit *audit.Recorder
	// TunnelCache, when set, has its Invalidate() called after every
	// successful mutation (Create/Update/Delete/Start/Stop/Import) so the
	// metrics hot path's cached snapshot picks up the change on the next
	// dashboard refresh. May be nil — handlers no-op the invalidation.
	TunnelCache *tunnels.Cache
}

// invalidateCache is a small nil-checked helper so each mutating
// handler doesn't have to repeat the guard.
func (d TunnelDeps) invalidateCache() {
	if d.TunnelCache != nil {
		d.TunnelCache.Invalidate()
	}
}

// actorOf returns the authenticated admin's username for audit
// purposes, or the bare "admin" placeholder when the context has no
// admin (shouldn't happen in production — protected routes wrap
// every entry through RequireAuth).
func (d TunnelDeps) actorOf(r *http.Request) string {
	if a, ok := AdminFromContext(r.Context()); ok {
		return a.Username
	}
	return audit.ActorAdmin
}

// logger returns d.Logger or slog.Default() so callers don't have to
// branch on the nil case.
func (d TunnelDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// RedactedPSK is the placeholder string returned in every list / get /
// update response in place of the real PSK. PRD §13.4-style handling:
// secrets never leave the process except via the dedicated export
// endpoint (which the operator explicitly requests).
const RedactedPSK = "***"

// tunnelDTO is the wire shape the panel consumes. It carries every
// PRD §3.1 / §3.2 field; null pointers in the model translate to JSON
// nulls so the form on the panel can tell "unset" apart from "zero".
type tunnelDTO struct {
	ID                      int64  `json:"id"`
	Name                    string `json:"name"`
	Role                    string `json:"role"`
	Enabled                 bool   `json:"enabled"`
	PSK                     string `json:"psk"`
	DownloadSpoofSourceIP   string `json:"download_spoof_source_ip"`
	DownloadSpoofSourcePort int    `json:"download_spoof_source_port"`
	DownloadTransport       string `json:"download_transport"`
	MTU                     int    `json:"mtu"`
	MaxConnections          int    `json:"max_connections"`
	IdleTimeout             int    `json:"idle_timeout"`
	IcmpEchoMode            string `json:"icmp_echo_mode"`

	LocalListenAddr     *string `json:"local_listen_addr"`
	DownloadReceivePort *int    `json:"download_receive_port"`
	UploadTargetAddr    *string `json:"upload_target_addr"`
	WireguardConfig     *string `json:"wireguard_config"`
	WGConfigID          *int64  `json:"wg_config_id"`
	// UploadMode (Phase R8): 'wireguard' (default) or 'socks5'.
	// Socks5ProxyID is the FK companion when UploadMode is 'socks5'.
	UploadMode            string `json:"upload_mode"`
	Socks5ProxyID         *int64 `json:"socks5_proxy_id"`
	PingSmoothingEnabled  bool   `json:"ping_smoothing_enabled"`
	PingSmoothingTargetMS int    `json:"ping_smoothing_target_ms"`
	PacingEnabled         bool   `json:"pacing_enabled"`
	PacingTargetMS        int    `json:"pacing_target_ms"`

	UploadListenAddr *string `json:"upload_listen_addr"`
	ForwardTarget    *string `json:"forward_target"`
	DownloadSendPort *int    `json:"download_send_port"`
	ClientRealIP     *string `json:"client_real_ip"`
	// UploadListenMode (Phase R9a): 'udp' (default) or 'socks5_tcp'.
	// Surfaced on every tunnel DTO but only meaningful on Remote rows;
	// Client tunnels carry the default value untouched.
	UploadListenMode string `json:"upload_listen_mode"`

	// RuntimeState reflects the dataplane's view of this tunnel:
	// "stopped" (no traffic), "running" (forwarding traffic),
	// "starting" (mid-bring-up), or "error". The enabled flag above
	// is the *intent*; this is the actual state. nil if no dataplane
	// is configured (dev builds without -tags=embed).
	RuntimeState  *string `json:"runtime_state,omitempty"`
	RuntimeReason *string `json:"runtime_reason,omitempty"`
}

// toDTO converts the persistence struct into the API view. If
// redactPSK is true (the default for everything except /export) the
// PSK is replaced by RedactedPSK.
func toDTO(t tunnels.Tunnel, redactPSK bool) tunnelDTO {
	d := tunnelDTO{
		ID:                      t.ID,
		Name:                    t.Name,
		Role:                    string(t.Role),
		Enabled:                 t.Enabled,
		DownloadSpoofSourceIP:   t.DownloadSpoofSourceIP,
		DownloadSpoofSourcePort: t.DownloadSpoofSourcePort,
		DownloadTransport:       string(t.DownloadTransport),
		MTU:                     t.MTU,
		MaxConnections:          t.MaxConnections,
		IdleTimeout:             t.IdleTimeout,
		IcmpEchoMode:            string(t.IcmpEchoMode),
		UploadMode:              string(t.UploadMode),
		UploadListenMode:        string(t.UploadListenMode),
		PingSmoothingEnabled:    t.PingSmoothingEnabled,
		PingSmoothingTargetMS:   t.PingSmoothingTargetMS,
		PacingEnabled:           t.PacingEnabled,
		PacingTargetMS:          t.PacingTargetMS,
	}
	if d.UploadMode == "" {
		d.UploadMode = string(tunnels.UploadModeWireguard)
	}
	if d.UploadListenMode == "" {
		d.UploadListenMode = string(tunnels.UploadListenModeUDP)
	}
	if redactPSK {
		d.PSK = RedactedPSK
	} else {
		d.PSK = t.PSK
	}
	if t.LocalListenAddr.Valid {
		s := t.LocalListenAddr.String
		d.LocalListenAddr = &s
	}
	if t.DownloadReceivePort.Valid {
		p := int(t.DownloadReceivePort.Int64)
		d.DownloadReceivePort = &p
	}
	if t.UploadTargetAddr.Valid {
		s := t.UploadTargetAddr.String
		d.UploadTargetAddr = &s
	}
	if t.WireguardConfig.Valid {
		s := t.WireguardConfig.String
		d.WireguardConfig = &s
	}
	if t.WGConfigID.Valid {
		v := t.WGConfigID.Int64
		d.WGConfigID = &v
	}
	if t.Socks5ProxyID.Valid {
		v := t.Socks5ProxyID.Int64
		d.Socks5ProxyID = &v
	}
	if t.UploadListenAddr.Valid {
		s := t.UploadListenAddr.String
		d.UploadListenAddr = &s
	}
	if t.ForwardTarget.Valid {
		s := t.ForwardTarget.String
		d.ForwardTarget = &s
	}
	if t.DownloadSendPort.Valid {
		p := int(t.DownloadSendPort.Int64)
		d.DownloadSendPort = &p
	}
	if t.ClientRealIP.Valid {
		s := t.ClientRealIP.String
		d.ClientRealIP = &s
	}
	return d
}

// withRuntime overlays the dataplane manager's runtime state onto the
// DTO so the panel can render the live "Running" / "Error" badge
// alongside the configured enabled flag. Pass nil deps to leave the
// runtime fields unset (dev builds).
func withRuntime(d tunnelDTO, mgr *dataplane.Manager) tunnelDTO {
	if mgr == nil {
		return d
	}
	st := mgr.State(d.ID)
	state := st.State
	d.RuntimeState = &state
	if st.Reason != "" {
		reason := st.Reason
		d.RuntimeReason = &reason
	}
	return d
}

// tunnelInput is the body the panel posts on create / update. It is
// the DTO shape minus id and role (role comes from the server) plus a
// "psk omitted means keep" convention for updates.
type tunnelInput struct {
	Name                    string  `json:"name"`
	Enabled                 bool    `json:"enabled"`
	PSK                     *string `json:"psk"`
	DownloadSpoofSourceIP   string  `json:"download_spoof_source_ip"`
	DownloadSpoofSourcePort int     `json:"download_spoof_source_port"`
	DownloadTransport       string  `json:"download_transport"`
	MTU                     int     `json:"mtu"`
	MaxConnections          int     `json:"max_connections"`
	IdleTimeout             int     `json:"idle_timeout"`
	IcmpEchoMode            string  `json:"icmp_echo_mode"`

	LocalListenAddr     *string `json:"local_listen_addr"`
	DownloadReceivePort *int    `json:"download_receive_port"`
	UploadTargetAddr    *string `json:"upload_target_addr"`
	WireguardConfig     *string `json:"wireguard_config"`
	WGConfigID          *int64  `json:"wg_config_id"`
	// Phase R8: upload-mode selector + SOCKS5 FK. Omit upload_mode (or
	// send empty string) and applyDefaults coerces to 'wireguard' so
	// pre-R8 panel builds posting the same JSON shape keep working.
	UploadMode            string `json:"upload_mode"`
	Socks5ProxyID         *int64 `json:"socks5_proxy_id"`
	PingSmoothingEnabled  bool   `json:"ping_smoothing_enabled"`
	PingSmoothingTargetMS int    `json:"ping_smoothing_target_ms"`
	PacingEnabled         bool   `json:"pacing_enabled"`
	PacingTargetMS        int    `json:"pacing_target_ms"`

	UploadListenAddr *string `json:"upload_listen_addr"`
	ForwardTarget    *string `json:"forward_target"`
	DownloadSendPort *int    `json:"download_send_port"`
	ClientRealIP     *string `json:"client_real_ip"`
	// Phase R9a: Remote-side upload-listen mode. 'udp' (default) keeps
	// the historical UDP listener; 'socks5_tcp' switches to a TCP
	// listener that decodes [u16][bytes] frames from the paired SOCKS5
	// Client. Mirrors UploadMode's defaulting in applyDefaults.
	UploadListenMode string `json:"upload_listen_mode"`
}

// applyDefaults fills in PRD-documented defaults for any field the
// panel left at the zero value. Phase 6's create form populates these
// up-front, but the API path runs from import-tunnel JSON too and
// can't assume the caller did.
func (in *tunnelInput) applyDefaults() {
	if in.MTU == 0 {
		in.MTU = 1400
	}
	if in.MaxConnections == 0 {
		in.MaxConnections = 50_000
	}
	if in.IdleTimeout == 0 {
		in.IdleTimeout = 300
	}
	if in.PingSmoothingTargetMS == 0 {
		in.PingSmoothingTargetMS = 60
	}
	if in.PacingTargetMS == 0 {
		in.PacingTargetMS = 100
	}
	if in.IcmpEchoMode == "" {
		in.IcmpEchoMode = string(tunnels.IcmpEchoModeReply)
	}
	// v2 matrix-aware defaults: when the caller omits the upload mode /
	// listen mode, pick the sensible default FOR THE CHOSEN DOWNLOAD
	// TRANSPORT (tcp_syn → socks5 / socks5_tcp; everything else →
	// wireguard / udp) rather than a blanket wireguard/udp. Keeps a
	// minimal create body (or an import) landing on a matrix-valid row.
	dt := tunnels.Transport(in.DownloadTransport)
	if in.UploadMode == "" {
		in.UploadMode = string(tunnels.DefaultUploadMode(dt))
	}
	if in.UploadListenMode == "" {
		in.UploadListenMode = string(tunnels.DefaultListenMode(dt))
	}
}

// toTunnel converts the wire input into the persistence struct. The
// role is supplied separately because the server is the source of
// truth — a caller can't claim a different role.
func (in *tunnelInput) toTunnel(role tunnels.Role, psk string) tunnels.Tunnel {
	t := tunnels.Tunnel{
		Name:                    in.Name,
		Role:                    role,
		Enabled:                 in.Enabled,
		PSK:                     psk,
		DownloadSpoofSourceIP:   in.DownloadSpoofSourceIP,
		DownloadSpoofSourcePort: in.DownloadSpoofSourcePort,
		DownloadTransport:       tunnels.Transport(in.DownloadTransport),
		MTU:                     in.MTU,
		MaxConnections:          in.MaxConnections,
		IdleTimeout:             in.IdleTimeout,
		IcmpEchoMode:            tunnels.IcmpEchoMode(in.IcmpEchoMode),
		UploadMode:              tunnels.UploadMode(in.UploadMode),
		UploadListenMode:        tunnels.UploadListenMode(in.UploadListenMode),
		PingSmoothingEnabled:    in.PingSmoothingEnabled,
		PingSmoothingTargetMS:   in.PingSmoothingTargetMS,
		PacingEnabled:           in.PacingEnabled,
		PacingTargetMS:          in.PacingTargetMS,
	}
	if in.LocalListenAddr != nil {
		t.LocalListenAddr = sql.NullString{String: *in.LocalListenAddr, Valid: true}
	}
	if in.DownloadReceivePort != nil {
		t.DownloadReceivePort = sql.NullInt64{Int64: int64(*in.DownloadReceivePort), Valid: true}
	}
	if in.UploadTargetAddr != nil {
		t.UploadTargetAddr = sql.NullString{String: *in.UploadTargetAddr, Valid: true}
	}
	if in.WireguardConfig != nil {
		t.WireguardConfig = sql.NullString{String: *in.WireguardConfig, Valid: true}
	}
	if in.WGConfigID != nil {
		t.WGConfigID = sql.NullInt64{Int64: *in.WGConfigID, Valid: true}
	}
	if in.Socks5ProxyID != nil {
		t.Socks5ProxyID = sql.NullInt64{Int64: *in.Socks5ProxyID, Valid: true}
	}
	if in.UploadListenAddr != nil {
		t.UploadListenAddr = sql.NullString{String: *in.UploadListenAddr, Valid: true}
	}
	if in.ForwardTarget != nil {
		t.ForwardTarget = sql.NullString{String: *in.ForwardTarget, Valid: true}
	}
	if in.DownloadSendPort != nil {
		t.DownloadSendPort = sql.NullInt64{Int64: int64(*in.DownloadSendPort), Valid: true}
	}
	if in.ClientRealIP != nil {
		t.ClientRealIP = sql.NullString{String: *in.ClientRealIP, Valid: true}
	}
	return t
}

// MountTunnelRoutes installs every Phase 6 tunnel endpoint onto the
// supplied chi.Router. Caller is responsible for wrapping these routes
// in RequireAuth before calling — they have no auth of their own.
func MountTunnelRoutes(r chi.Router, deps TunnelDeps) {
	r.Get("/", ListTunnelsHandler(deps))
	r.Post("/", CreateTunnelHandler(deps))
	r.Get("/{id}", GetTunnelHandler(deps))
	r.Put("/{id}", UpdateTunnelHandler(deps))
	r.Delete("/{id}", DeleteTunnelHandler(deps))
	r.Post("/{id}/start", StartTunnelHandler(deps))
	r.Post("/{id}/stop", StopTunnelHandler(deps))
	r.Get("/{id}/export", ExportTunnelHandler(deps))
	r.Post("/import", ImportTunnelHandler(deps))
}

// ListTunnelsHandler returns every tunnel with the PSK redacted.
func ListTunnelsHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := deps.Repo.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnels")
			return
		}
		out := make([]tunnelDTO, 0, len(rows))
		for _, t := range rows {
			out = append(out, withRuntime(toDTO(t, true), deps.Dataplane))
		}
		writeJSON(w, http.StatusOK, map[string]any{"tunnels": out})
	}
}

// GetTunnelHandler returns one tunnel by id with the PSK redacted.
func GetTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		t, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnel")
			return
		}
		writeJSON(w, http.StatusOK, withRuntime(toDTO(t, true), deps.Dataplane))
	}
}

// CreateTunnelHandler validates the body, runs port-conflict detection,
// and inserts the row. The response body is the freshly-persisted
// tunnel with its PSK redacted.
func CreateTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in tunnelInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.applyDefaults()
		psk := ""
		if in.PSK != nil {
			psk = *in.PSK
		}
		t := in.toTunnel(deps.ServerRole, psk)

		if err := tunnels.Validate(r.Context(), deps.Repo, deps.ServerRole, &t, 0); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureWGConfigExists(r.Context(), deps, t.WGConfigID); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureSOCKS5ProxyExists(r.Context(), deps, t.Socks5ProxyID); err != nil {
			writeValidationError(w, err)
			return
		}
		// Newly created tunnels are always Stopped per PRD §3.6.
		t.Enabled = false

		out, err := deps.Repo.Create(r.Context(), t)
		if errors.Is(err, tunnels.ErrNameTaken) {
			writeJSONError(w, http.StatusConflict, "A tunnel with that name already exists.")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not create tunnel")
			return
		}
		deps.invalidateCache()
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelCreate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"tunnel_id": out.ID,
				"role":      string(out.Role),
				"transport": string(out.DownloadTransport),
			})
		}
		writeJSON(w, http.StatusCreated, withRuntime(toDTO(out, true), deps.Dataplane))
	}
}

// UpdateTunnelHandler accepts the same body shape as create. If the
// body's PSK field is null/missing the existing PSK is preserved.
//
// PRD §3.6 lifecycle: for live tunnels, edits to any field except
// local_listen_addr / upload_listen_addr must hot-reload without a
// stop+start. Those two fields require an explicit Stop + Start;
// when the panel saves such a change, the response carries
// `restart_required: true` and a `restart_required_message` so the
// panel can show a banner pointing at the Stop and Start buttons.
//
// The DB is updated unconditionally — the operator's intent persists
// even when the dataplane refuses to apply it live, so a subsequent
// Stop + Start picks the new values up.
func UpdateTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnel")
			return
		}

		var in tunnelInput
		if err := decodeJSON(r.Body, &in); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.applyDefaults()

		keepPSK := in.PSK == nil
		psk := existing.PSK
		if !keepPSK {
			psk = *in.PSK
		}
		t := in.toTunnel(existing.Role, psk)
		t.ID = existing.ID

		if err := tunnels.Validate(r.Context(), deps.Repo, deps.ServerRole, &t, existing.ID); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureWGConfigExists(r.Context(), deps, t.WGConfigID); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureSOCKS5ProxyExists(r.Context(), deps, t.Socks5ProxyID); err != nil {
			writeValidationError(w, err)
			return
		}

		out, err := deps.Repo.Update(r.Context(), t, keepPSK)
		if errors.Is(err, tunnels.ErrNameTaken) {
			writeJSONError(w, http.StatusConflict, "A tunnel with that name already exists.")
			return
		}
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not update tunnel")
			return
		}
		deps.invalidateCache()

		// Build the response — flat DTO (preserving the frontend's
		// existing TunnelDTO shape) plus optional hot-reload outcome
		// fields. The panel reads `restart_required` to decide whether
		// to surface a "click Stop / Start to apply" banner.
		resp := tunnelUpdateResponse{tunnelDTO: withRuntime(toDTO(out, true), deps.Dataplane)}
		if existing.Enabled && deps.Dataplane != nil {
			applyDataplaneOutcome(r.Context(), &resp, out, deps)
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelUpdate, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"tunnel_id":         out.ID,
				"role":              string(out.Role),
				"restart_required":  resp.RestartRequired,
				"dataplane_applied": resp.DataplaneApplied,
				"changed_fields":    resp.DataplaneChangedFields,
				"psk_changed":       !keepPSK,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// applyDataplaneOutcome calls the dataplane manager's Update and
// mirrors the result onto resp. Split out of UpdateTunnelHandler so the
// branches stay readable.
func applyDataplaneOutcome(ctx context.Context, resp *tunnelUpdateResponse, out tunnels.Tunnel, deps TunnelDeps) {
	var socks5Proxy *socks5.Proxy
	if out.Role == tunnels.RoleClient && out.UploadMode == tunnels.UploadModeSocks5 {
		p, err := resolveSOCKS5Proxy(ctx, deps, out)
		if err != nil {
			resp.DataplaneError = err.Error()
			return
		}
		socks5Proxy = p
	}
	outcome, derr := deps.Dataplane.Update(ctx, out, socks5Proxy)
	switch {
	case derr != nil:
		deps.logger().Warn("dataplane: update failed",
			"tunnel_id", out.ID, "err", derr)
		resp.DataplaneError = derr.Error()
	case outcome.RestartRequired:
		resp.RestartRequired = true
		if outcome.Reason != "" {
			resp.RestartRequiredMessage = outcome.Reason
		} else {
			resp.RestartRequiredMessage = "Changes to listen addresses need a brief Stop and Start to apply."
		}
	case outcome.Applied:
		resp.DataplaneApplied = true
		resp.DataplaneChangedFields = outcome.Changed
	}
}

// tunnelUpdateResponse is the JSON shape returned by PUT /api/tunnels/:id.
// Anonymous embed of `tunnelDTO` keeps the panel's existing `TunnelDTO`
// interface working — every flat field stays at the top level. The
// optional fields are populated only when a hot-reload was attempted
// (`existing.Enabled && deps.Dataplane != nil`).
type tunnelUpdateResponse struct {
	tunnelDTO
	// RestartRequired = the dataplane rejected the update because a
	// listen-address field changed. Operator must Stop then Start the
	// tunnel manually to apply.
	RestartRequired        bool   `json:"restart_required,omitempty"`
	RestartRequiredMessage string `json:"restart_required_message,omitempty"`
	// DataplaneApplied = the dataplane accepted the update (either as
	// a true hot-reload or via an internal stop+start). The list of
	// field names that actually changed is in DataplaneChangedFields.
	DataplaneApplied       bool     `json:"dataplane_applied,omitempty"`
	DataplaneChangedFields []string `json:"dataplane_changed_fields,omitempty"`
	// DataplaneError = a non-RESTART_REQUIRED failure surfaced from
	// the IPC layer. Persistence still happened — the operator's
	// intent is recorded.
	DataplaneError string `json:"dataplane_error,omitempty"`
}

// StartTunnelHandler flips enabled to true, brings up the kernel
// WireGuard interface for client tunnels with a linked WG config, and
// then dispatches the IPC StartTunnel to the Rust dataplane so
// application traffic actually flows.
//
// Order matters: WG first so the upload egress path is ready before
// the dataplane tries to send through it; then the DB flip; then
// the dataplane Start so the API returns a tunnel marked
// `runtime_state=running` only when traffic is genuinely flowing.
func StartTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		t, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnel")
			return
		}
		// SOCKS5 upload (Phase R9a: framing + single conn; R9b: pool
		// of N parallel connections, one per Starlink uplink behind
		// the proxy). When the tunnel is in SOCKS5 mode we resolve
		// the referenced proxy here so the dataplane Start sees the
		// host/port/credentials/parallel-count it needs, and we skip
		// WG bring-up — the SOCKS5 path replaces it.
		var socks5Proxy *socks5.Proxy
		if t.Role == tunnels.RoleClient && t.UploadMode == tunnels.UploadModeSocks5 {
			p, err := resolveSOCKS5Proxy(r.Context(), deps, t)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			socks5Proxy = p
		} else if t.Role == tunnels.RoleClient && t.WGConfigID.Valid && deps.WGRepo != nil && deps.WGManager != nil {
			if err := bringUpClientTunnel(r.Context(), deps, t); err != nil {
				writeJSONError(w, http.StatusBadGateway, "could not bring up WireGuard interface: "+err.Error())
				return
			}
		}
		out, err := deps.Repo.SetEnabled(r.Context(), id, true)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not enable tunnel")
			return
		}
		deps.invalidateCache()
		if deps.Dataplane != nil {
			if err := deps.Dataplane.Start(r.Context(), out, socks5Proxy); err != nil {
				// Surface the error but leave the DB row enabled so
				// the operator can see it failed; the runtime_state
				// in the response carries the explanation.
				deps.logger().Warn("dataplane: start failed",
					"tunnel_id", out.ID, "err", err)
				if deps.Audit != nil {
					deps.Audit.Record(r.Context(), audit.ActionTunnelStart, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
						"tunnel_id": out.ID,
						"ok":        false,
						"error":     err.Error(),
					})
				}
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error":  "Could not start tunnel: " + err.Error(),
					"tunnel": withRuntime(toDTO(out, true), deps.Dataplane),
				})
				return
			}
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelStart, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"tunnel_id": out.ID,
				"ok":        true,
			})
		}
		writeJSON(w, http.StatusOK, withRuntime(toDTO(out, true), deps.Dataplane))
	}
}

// StopTunnelHandler tears down dataplane forwarding for the tunnel,
// flips the DB flag to false, and tears down the kernel
// sub-wg-<id> interface for Client tunnels. Order matters: stop the
// dataplane first so it doesn't try to send through a WG interface
// we're about to remove.
func StopTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		t, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnel")
			return
		}
		if deps.Dataplane != nil {
			if err := deps.Dataplane.Stop(r.Context(), t.ID); err != nil {
				deps.logger().Warn("dataplane: stop failed (continuing)",
					"tunnel_id", t.ID, "err", err)
			}
		}
		out, err := deps.Repo.SetEnabled(r.Context(), id, false)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not disable tunnel")
			return
		}
		deps.invalidateCache()
		if t.Role == tunnels.RoleClient && deps.WGManager != nil {
			if err := deps.WGManager.Down(r.Context(), t.ID); err != nil && !errors.Is(err, wg.ErrManagerUnsupported) {
				deps.logger().Warn("wg: down failed (continuing)", "tunnel_id", t.ID, "err", err)
			}
		}
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelStop, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"tunnel_id": out.ID,
			})
		}
		writeJSON(w, http.StatusOK, withRuntime(toDTO(out, true), deps.Dataplane))
	}
}

// bringUpClientTunnel fetches the WG config row, parses it, and asks
// the manager to materialise the kernel device. ErrManagerUnsupported
// is mapped to a user-facing message that names the platform — the
// happy path is Linux, and the VM acceptance test runs there.
func bringUpClientTunnel(ctx context.Context, deps TunnelDeps, t tunnels.Tunnel) error {
	cfg, err := deps.WGRepo.Get(ctx, t.WGConfigID.Int64)
	if errors.Is(err, wg.ErrConfigNotFound) {
		return errors.New("the linked WireGuard config no longer exists")
	}
	if err != nil {
		return err
	}
	parsed, err := wg.ParseConfig(cfg.RawText)
	if err != nil {
		return errors.New("stored WireGuard config is malformed: " + err.Error())
	}
	res, err := deps.WGManager.Up(ctx, t.ID, parsed)
	if errors.Is(err, wg.ErrManagerUnsupported) {
		// On non-Linux builds we still flip enabled=true so the panel
		// reflects operator intent; the user explicitly opted into
		// running a developer-mode binary on an unsupported OS.
		deps.logger().Info("wg: manager unsupported on this platform; recording intent only",
			"tunnel_id", t.ID, "iface", res.InterfaceName)
		return nil
	}
	if err != nil {
		return err
	}
	deps.logger().Info("wg: tunnel started",
		"tunnel_id", t.ID, "iface", res.InterfaceName,
		"fwmark", res.Fwmark, "table", res.Table)
	return nil
}

// ensureWGConfigExists verifies the supplied id (when set) points at a
// real wireguard_configs row. Returns a per-field validation error
// formatted the same way the rest of the validator does so the panel
// can surface it under the wg_config_id picker.
func ensureWGConfigExists(ctx context.Context, deps TunnelDeps, id sql.NullInt64) error {
	if !id.Valid || id.Int64 == 0 || deps.WGRepo == nil {
		return nil
	}
	if _, err := deps.WGRepo.Get(ctx, id.Int64); err != nil {
		if errors.Is(err, wg.ErrConfigNotFound) {
			return &tunnels.ValidationError{Fields: map[string]string{
				"wg_config_id": "The selected WireGuard config no longer exists. Pick another or paste a new one.",
			}}
		}
		return err
	}
	return nil
}

// resolveSOCKS5Proxy fetches the SOCKS5 proxy referenced by a client
// tunnel whose upload_mode is 'socks5'. Returns a user-facing error if
// the FK is unset, the repo is nil, or the row no longer exists —
// every condition the operator can recover from by editing the tunnel.
func resolveSOCKS5Proxy(ctx context.Context, deps TunnelDeps, t tunnels.Tunnel) (*socks5.Proxy, error) {
	if deps.SOCKS5Repo == nil {
		return nil, errors.New("SOCKS5 mode is configured but no SOCKS5 repo is available on this server")
	}
	if !t.Socks5ProxyID.Valid || t.Socks5ProxyID.Int64 == 0 {
		return nil, errors.New("SOCKS5 mode is selected but no proxy is linked. Pick one on the tunnel edit form.")
	}
	p, err := deps.SOCKS5Repo.Get(ctx, t.Socks5ProxyID.Int64)
	if errors.Is(err, socks5.ErrProxyNotFound) {
		return nil, errors.New("the linked SOCKS5 proxy no longer exists. Pick another on the tunnel edit form.")
	}
	if err != nil {
		return nil, fmt.Errorf("load SOCKS5 proxy: %w", err)
	}
	return &p, nil
}

// ensureSOCKS5ProxyExists is the SOCKS5 counterpart to
// ensureWGConfigExists (Phase R8). Verifies the FK before save so a
// stale picker selection surfaces as a per-field error under the
// SOCKS5 picker instead of as a generic 500 later in the flow.
func ensureSOCKS5ProxyExists(ctx context.Context, deps TunnelDeps, id sql.NullInt64) error {
	if !id.Valid || id.Int64 == 0 || deps.SOCKS5Repo == nil {
		return nil
	}
	if _, err := deps.SOCKS5Repo.Get(ctx, id.Int64); err != nil {
		if errors.Is(err, socks5.ErrProxyNotFound) {
			return &tunnels.ValidationError{Fields: map[string]string{
				"socks5_proxy_id": "The selected SOCKS5 proxy no longer exists. Pick another or add a new one.",
			}}
		}
		return err
	}
	return nil
}

// DeleteTunnelHandler refuses while enabled=true (PRD §3.6) and
// otherwise removes the row.
func DeleteTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Capture the name BEFORE delete so the audit row has a target.
		var name string
		if t, err := deps.Repo.Get(r.Context(), id); err == nil {
			name = t.Name
		}
		err = deps.Repo.Delete(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if errors.Is(err, tunnels.ErrEnabled) {
			writeJSONError(w, http.StatusConflict, "Stop the tunnel before deleting it.")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not delete tunnel")
			return
		}
		deps.invalidateCache()
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelDelete, deps.actorOf(r), ClientIP(r), name, map[string]any{
				"tunnel_id": id,
			})
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ExportTunnelHandler returns a single tunnel as JSON, with the real
// PSK present. The operator is downloading their own config; the panel
// already requires a session to reach this endpoint. The exported
// shape is wrapped as {"tunnel": …} so import can accept the same
// document round-trip.
func ExportTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := tunnelIDFromURL(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		t, err := deps.Repo.Get(r.Context(), id)
		if errors.Is(err, tunnels.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "tunnel not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load tunnel")
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\"tunnel-"+strconv.FormatInt(t.ID, 10)+".json\"")
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelExport, deps.actorOf(r), ClientIP(r), t.Name, map[string]any{
				"tunnel_id": t.ID,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"tunnel": withRuntime(toDTO(t, false), deps.Dataplane)})
	}
}

// ImportTunnelHandler accepts a previously-exported single-tunnel JSON
// document and inserts it as a new tunnel. The name must not already
// exist; the role must match the server's role.
func ImportTunnelHandler(deps TunnelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tunnel tunnelDTO `json:"tunnel"`
		}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Convert DTO → input → tunnel. We don't trust the exported id
		// or enabled flag.
		in := tunnelInput{
			Name:                    body.Tunnel.Name,
			Enabled:                 false,
			PSK:                     ptr(body.Tunnel.PSK),
			DownloadSpoofSourceIP:   body.Tunnel.DownloadSpoofSourceIP,
			DownloadSpoofSourcePort: body.Tunnel.DownloadSpoofSourcePort,
			DownloadTransport:       body.Tunnel.DownloadTransport,
			MTU:                     body.Tunnel.MTU,
			MaxConnections:          body.Tunnel.MaxConnections,
			IdleTimeout:             body.Tunnel.IdleTimeout,
			IcmpEchoMode:            body.Tunnel.IcmpEchoMode,
			LocalListenAddr:         body.Tunnel.LocalListenAddr,
			DownloadReceivePort:     body.Tunnel.DownloadReceivePort,
			UploadTargetAddr:        body.Tunnel.UploadTargetAddr,
			WireguardConfig:         body.Tunnel.WireguardConfig,
			UploadMode:              body.Tunnel.UploadMode,
			Socks5ProxyID:           body.Tunnel.Socks5ProxyID,
			PingSmoothingEnabled:    body.Tunnel.PingSmoothingEnabled,
			PingSmoothingTargetMS:   body.Tunnel.PingSmoothingTargetMS,
			PacingEnabled:           body.Tunnel.PacingEnabled,
			PacingTargetMS:          body.Tunnel.PacingTargetMS,
			UploadListenAddr:        body.Tunnel.UploadListenAddr,
			ForwardTarget:           body.Tunnel.ForwardTarget,
			DownloadSendPort:        body.Tunnel.DownloadSendPort,
			ClientRealIP:            body.Tunnel.ClientRealIP,
			UploadListenMode:        body.Tunnel.UploadListenMode,
		}
		in.applyDefaults()
		t := in.toTunnel(deps.ServerRole, *in.PSK)
		if err := tunnels.Validate(r.Context(), deps.Repo, deps.ServerRole, &t, 0); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureWGConfigExists(r.Context(), deps, t.WGConfigID); err != nil {
			writeValidationError(w, err)
			return
		}
		if err := ensureSOCKS5ProxyExists(r.Context(), deps, t.Socks5ProxyID); err != nil {
			writeValidationError(w, err)
			return
		}
		t.Enabled = false
		out, err := deps.Repo.Create(r.Context(), t)
		if errors.Is(err, tunnels.ErrNameTaken) {
			writeJSONError(w, http.StatusConflict, "A tunnel named \""+t.Name+"\" already exists. Rename the import or delete the existing tunnel first.")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not import tunnel")
			return
		}
		deps.invalidateCache()
		if deps.Audit != nil {
			deps.Audit.Record(r.Context(), audit.ActionTunnelImport, deps.actorOf(r), ClientIP(r), out.Name, map[string]any{
				"tunnel_id": out.ID,
				"role":      string(out.Role),
			})
		}
		writeJSON(w, http.StatusCreated, withRuntime(toDTO(out, true), deps.Dataplane))
	}
}

// decodeJSON is a small helper that locks the decoder down with
// DisallowUnknownFields so the panel can't accidentally rely on
// undeclared keys.
func decodeJSON(body io.Reader, target any) error {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return errors.New("invalid request body: " + err.Error())
	}
	return nil
}

// writeValidationError ships the per-field map back as JSON so the
// frontend can drop each message under its corresponding input.
func writeValidationError(w http.ResponseWriter, err error) {
	var ve *tunnels.ValidationError
	if errors.As(err, &ve) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "Some fields need attention.",
			"fields": ve.Fields,
		})
		return
	}
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

func tunnelIDFromURL(r *http.Request) (int64, error) {
	raw := chi.URLParam(r, "id")
	if raw == "" {
		return 0, errors.New("missing tunnel id")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid tunnel id")
	}
	return id, nil
}

func ptr[T any](v T) *T { return &v }
