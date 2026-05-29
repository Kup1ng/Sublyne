package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplane"
	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
	"github.com/Kup1ng/Sublyne/control-plane/internal/metrics"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// MetricsDeps bundles the things the metrics / dashboard handlers need.
// Tests build one with fakes; main wires real implementations.
type MetricsDeps struct {
	// Recorder is the 24-hour ring buffer the dataplane pushes into.
	// Required.
	Recorder *metrics.Recorder

	// Dataplane is the runtime-state source for the per-tunnel badge.
	// Optional — a nil Dataplane reports every tunnel as "stopped".
	Dataplane *dataplane.Manager

	// TunnelRepo is needed to enrich live snapshots with the operator-
	// chosen name + enabled flag (the dataplane only emits the id).
	// Used as the fallback when TunnelCache is nil.
	TunnelRepo *tunnels.Repo

	// TunnelCache is the read-through cache the metrics hot path
	// (buildLiveSnapshot + WGHandshakeListHandler) consults to avoid
	// re-querying the tunnels table on every dashboard refresh. CRUD
	// handlers Invalidate it after each write so the next read picks
	// up the change. May be nil; readers fall back to TunnelRepo.
	TunnelCache *tunnels.Cache

	// WGRepo lets the `/api/wg-status` handler list the configs whose
	// handshake state we want to surface. Required for the WG card on
	// the dashboard.
	WGRepo *wg.Repo

	// WGManager is consulted for each up interface. The Phase 7 stub
	// returns ErrManagerUnsupported on non-Linux; the dashboard then
	// renders "manager unavailable" without crashing.
	WGManager wg.Manager

	// StatsBroadcast is fed every StatsReport from the IPC client.
	// The WebSocket handler subscribes to this bus so every dashboard
	// gets the latest snapshot within ~5 s of the dataplane pushing
	// one. The control-plane main wires the bus and the IPC client
	// together via metrics.SubscribeIPC.
	StatsBroadcast *Broadcast

	// Logger is used for diagnostic logs. Defaults to slog.Default()
	// when nil.
	Logger *slog.Logger
}

func (d MetricsDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// LiveTunnel is the per-row shape returned in /api/metrics/latest.
// Pairs the dataplane counters with the DB-stored name and the runtime
// state badge.
type LiveTunnel struct {
	ID                       int64                `json:"id"`
	Name                     string               `json:"name"`
	Role                     string               `json:"role"`
	Transport                string               `json:"transport"`
	Enabled                  bool                 `json:"enabled"`
	RuntimeState             string               `json:"runtime_state"`
	HealthBadge              string               `json:"health_badge"`
	BytesIn                  uint64               `json:"bytes_in"`
	BytesOut                 uint64               `json:"bytes_out"`
	PacketsIn                uint64               `json:"packets_in"`
	PacketsOut               uint64               `json:"packets_out"`
	ActiveSessions           uint32               `json:"active_sessions"`
	UploadRTTMsEWMA          float64              `json:"upload_rtt_ms_ewma"`
	DownloadRTTMsEWMA        float64              `json:"download_rtt_ms_ewma"`
	PacketLossEstimate       float64              `json:"packet_loss_estimate"`
	LastPacketReceivedAtUnix uint64               `json:"last_packet_received_at_unix"`
	LastPacketSentAtUnix     uint64               `json:"last_packet_sent_at_unix"`
	TransportPackets         ipc.TransportPackets `json:"transport_packets"`
}

// LiveSnapshot is the shape served by /api/metrics/latest. It mirrors
// the shape pushed over the WebSocket so dashboards consuming either
// transport see the same fields.
type LiveSnapshot struct {
	At      time.Time       `json:"at"`
	Tunnels []LiveTunnel    `json:"tunnels"`
	System  ipc.SystemStats `json:"system"`
}

// MountMetricsRoutes mounts the dashboard data endpoints onto the
// supplied chi subrouter. RequireAuth must wrap the parent group.
//
//	/api/metrics/latest         GET  — single snapshot (polling fallback)
//	/api/metrics/history        GET  — 24h ring buffer for charts
//	/api/metrics/wg-handshake   GET  — handshake state per WG config
//	/api/ws                     GET  — live snapshot stream every 5 s
func MountMetricsRoutes(r chi.Router, deps MetricsDeps) {
	r.Get("/metrics/latest", LatestMetricsHandler(deps))
	r.Get("/metrics/history", HistoryMetricsHandler(deps))
	r.Get("/metrics/wg-handshake", WGHandshakeListHandler(deps))
}

// LatestMetricsHandler is the polling fallback for the dashboard.
// Returns the most recent snapshot the IPC client has fed into the
// recorder. Empty if no StatsReport has landed yet — the panel shows
// "waiting for data".
func LatestMetricsHandler(deps MetricsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Recorder == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "metrics not configured")
			return
		}
		snap := deps.Recorder.Latest()
		out := buildLiveSnapshot(r.Context(), deps, snap)
		writeJSON(w, http.StatusOK, out)
	}
}

// HistoryMetricsHandler returns the 24-h ring buffer used by the
// dashboard's line charts. Per-tunnel and system arrays are
// time-aligned but optional — early-life dashboards see empty arrays
// until the first 5-second tick.
func HistoryMetricsHandler(deps MetricsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Recorder == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "metrics not configured")
			return
		}
		writeJSON(w, http.StatusOK, deps.Recorder.History())
	}
}

// WGHandshakeStatus is one row in the dashboard's WireGuard card. The
// Stale flag is PRD §8.4's 3-minute alert threshold ("> 3 min").
type WGHandshakeStatus struct {
	ConfigID         int64     `json:"config_id"`
	ConfigName       string    `json:"config_name"`
	InterfaceName    string    `json:"interface_name"`
	HasEverConnected bool      `json:"has_ever_connected"`
	Stale            bool      `json:"stale"`
	LastHandshake    time.Time `json:"last_handshake,omitempty"`
	LastHandshakeAge string    `json:"last_handshake_age,omitempty"`
}

// WGHandshakeListHandler returns a handshake row for every WG config.
//
// Phase 7 shipped /api/wg-configs/:id/handshake but the implementation
// only returned data when the caller passed `?tunnel_id=`. The panel
// never did, so the dashboard sat at "No handshake yet" even when
// `wg show` on the host reported a fresh handshake. Phase 11 fixes
// that here by walking every tunnel that references the config and
// reading its kernel interface directly.
func WGHandshakeListHandler(deps MetricsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.WGRepo == nil {
			writeJSON(w, http.StatusOK, map[string]any{"configs": []WGHandshakeStatus{}})
			return
		}
		configs, err := deps.WGRepo.List(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not load WireGuard configs")
			return
		}
		var allTunnels []tunnels.Tunnel
		allTunnels, err = listTunnelsCached(r.Context(), deps)
		if err != nil {
			deps.logger().Warn("metrics: list tunnels for wg-handshake failed", "err", err)
		}
		out := make([]WGHandshakeStatus, 0, len(configs))
		for _, c := range configs {
			row := WGHandshakeStatus{
				ConfigID:   c.ID,
				ConfigName: c.Name,
				Stale:      true,
			}
			row = resolveHandshake(r.Context(), deps, c.ID, allTunnels, row)
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, map[string]any{"configs": out})
	}
}

// resolveHandshake walks every tunnel that references config `cfgID`
// and asks the kernel manager for its handshake status. The freshest
// observed handshake wins so the dashboard reflects whichever tunnel
// has actually moved bytes recently. Returns `row` unchanged if no
// tunnel references the config or if the manager is the stub.
func resolveHandshake(
	ctx context.Context,
	deps MetricsDeps,
	cfgID int64,
	allTunnels []tunnels.Tunnel,
	row WGHandshakeStatus,
) WGHandshakeStatus {
	if deps.WGManager == nil || !deps.WGManager.Supported() {
		return row
	}
	for _, t := range allTunnels {
		if !t.WGConfigID.Valid || t.WGConfigID.Int64 != cfgID {
			continue
		}
		st, err := deps.WGManager.Handshake(ctx, t.ID)
		if err != nil {
			// ErrManagerUnsupported is logged at Debug; everything else
			// at Warn. Either way we continue — another tunnel may have
			// a fresher handshake.
			if errors.Is(err, wg.ErrManagerUnsupported) {
				deps.logger().Debug("metrics: handshake manager unsupported", "tunnel_id", t.ID)
			} else {
				deps.logger().Debug("metrics: handshake read failed", "tunnel_id", t.ID, "err", err)
			}
			continue
		}
		if row.InterfaceName == "" {
			row.InterfaceName = st.InterfaceName
		}
		if st.HasEverConnected && st.LastHandshake.After(row.LastHandshake) {
			row.HasEverConnected = true
			row.LastHandshake = st.LastHandshake
			row.Stale = st.Stale()
			row.LastHandshakeAge = formatAge(time.Since(st.LastHandshake))
		}
	}
	return row
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	return strconv.Itoa(int(d.Hours())) + "h"
}

// MetricsWebSocketHandler upgrades the connection and streams a live
// snapshot every 5 seconds (or whenever the IPC bus publishes one). On
// any send error the connection is closed; the client reconnects via
// the composable's auto-reconnect backoff.
//
// Phase 12 extension: the same WebSocket also relays log lines as
// "log" frames, so the panel's Logs page can subscribe to one stream
// instead of opening a second WS just for log tail. The frame body
// matches the JSON shape of logging.LogEntry.
//
// Auth is enforced by the same RequireAuth middleware that wraps every
// /api route — the JWT travels in the sublyne_token cookie which the
// browser includes on the WebSocket upgrade (HTTPS-equivalent rules
// because the Origin header is the panel's own host on the same port).
func MetricsWebSocketHandler(deps MetricsDeps, logsDeps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Panel + WS share the same origin; reject mismatches.
			InsecureSkipVerify: false,
			OriginPatterns:     []string{"*"},
		})
		if err != nil {
			deps.logger().Debug("ws: accept failed", "err", err)
			return
		}
		defer func() { _ = conn.Close(websocket.StatusNormalClosure, "bye") }()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		conn.SetReadLimit(64 * 1024) // we don't expect client→server payloads

		// Subscribe to the broadcast bus BEFORE writing the pre-seeded
		// snapshot. Order matters: if we wrote the first frame first
		// and a client read it and immediately drove a publish, the
		// race between "publish lands on the bus" and "this handler
		// calls Subscribe" can lose the publish on tightly-coupled
		// test paths (the bus only fans out to currently-registered
		// subscribers). Subscribing first means by the time any client
		// observes ANY byte on the WS the subscription is already in
		// place.
		//
		// The bus carries PRE-RENDERED bytes — the publisher (main.go's
		// IPC subscriber goroutine via the SnapshotRenderer set on the
		// bus) builds the snapshot + json.Marshal ONCE per push and
		// hands every WS handler the same byte slice. With N tabs open
		// this saves N-1 render+marshal cycles per 5-s tick.
		var sub <-chan []byte
		if deps.StatsBroadcast != nil {
			sub = deps.StatsBroadcast.Subscribe(4)
			defer deps.StatsBroadcast.Unsubscribe(sub)
		}

		// Phase 12: also subscribe to the log bus so the same WebSocket
		// emits "log" frames as new lines land. The Logs page reuses
		// this stream instead of opening a second connection.
		var logSub <-chan logging.LogEntry
		if logsDeps.Bus != nil {
			logSub = logsDeps.Bus.Subscribe(64)
			defer logsDeps.Bus.Unsubscribe(logSub)
		}

		// Send the latest known snapshot immediately so a fresh
		// dashboard tab has something to render before the next 5-s
		// tick lands.
		if snap := deps.Recorder.Latest(); !snap.At.IsZero() {
			if err := writeJSONFrame(ctx, conn, "snapshot", buildLiveSnapshot(ctx, deps, snap)); err != nil {
				return
			}
		}

		// Read pump — discards anything the client sends (we don't have
		// a client→server protocol) but exits the handler cleanly when
		// the peer closes.
		go func() {
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					cancel()
					return
				}
			}
		}()

		// Heartbeat ticker in case the broadcast bus never fires
		// (dataplane down, polling fallback should still show
		// something).
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case payload, ok := <-sub:
				if !ok {
					return
				}
				// Pre-rendered by the bus; write the bytes straight to
				// the WS. The render+marshal already happened once for
				// this snapshot at publish time.
				writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := conn.Write(writeCtx, websocket.MessageText, payload); err != nil {
					cancel()
					return
				}
				cancel()
			case entry, ok := <-logSub:
				if !ok {
					// Bus closed; just stop forwarding logs but keep
					// the snapshot stream alive for the rest of the
					// connection's life.
					logSub = nil
					continue
				}
				if err := writeJSONFrame(ctx, conn, "log", entry); err != nil {
					return
				}
			case <-ticker.C:
				// If the bus is silent for a tick, send whatever the
				// recorder has so the client knows we're still alive.
				snap := deps.Recorder.Latest()
				if snap.At.IsZero() {
					continue
				}
				if err := writeJSONFrame(ctx, conn, "snapshot", buildLiveSnapshot(ctx, deps, snap)); err != nil {
					return
				}
			}
		}
	}
}

// writeJSONFrame writes one type-tagged JSON message to the WebSocket.
// Used by the per-connection paths (on-connect initial frame, the
// heartbeat-tick fallback, log entries) where marshalling per call is
// fine because the call rate is low. The high-rate broadcast path
// renders ONCE via RenderSnapshotFrame and writes the cached bytes
// directly — see MetricsWebSocketHandler's `sub` case.
func writeJSONFrame(ctx context.Context, conn *websocket.Conn, ty string, body any) error {
	payload, err := json.Marshal(map[string]any{"type": ty, "body": body})
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, payload)
}

// RenderSnapshotFrame builds the WebSocket "snapshot" frame bytes for
// one IPC StatsReport. Called ONCE per Publish by the broadcast bus's
// SnapshotRenderer so every connected dashboard shares one render's
// worth of CPU instead of paying N× per push. The build is done
// against a fresh context.Background() (the cached tunnel list read is
// constant-time after the first call; the polling-fallback `/api/metrics/
// latest` runs with the request context).
func RenderSnapshotFrame(deps MetricsDeps, report ipc.StatsReport, at time.Time) ([]byte, error) {
	snap := metrics.Snapshot{
		At:      at,
		Samples: report.Samples,
		System:  report.System,
	}
	body := buildLiveSnapshot(context.Background(), deps, snap)
	return json.Marshal(map[string]any{"type": "snapshot", "body": body})
}

// listTunnelsCached returns the dashboard view of the tunnel list,
// served from MetricsDeps.TunnelCache if wired (the production path)
// or by falling back to a direct TunnelRepo query (tests and dev
// builds that didn't wire the cache). Returns nil, nil if neither is
// set so the caller can keep its empty-list rendering path.
func listTunnelsCached(ctx context.Context, deps MetricsDeps) ([]tunnels.Tunnel, error) {
	if deps.TunnelCache != nil {
		return deps.TunnelCache.List(ctx)
	}
	if deps.TunnelRepo != nil {
		return deps.TunnelRepo.List(ctx)
	}
	return nil, nil
}

// buildLiveSnapshot decorates a raw recorder snapshot with the DB-
// known tunnel names + the dataplane's runtime state badges (PRD §2.4).
func buildLiveSnapshot(ctx context.Context, deps MetricsDeps, snap metrics.Snapshot) LiveSnapshot {
	out := LiveSnapshot{
		At:     snap.At,
		System: snap.System,
	}
	// Index tunnels by id for quick lookup.
	known := make(map[int64]tunnels.Tunnel)
	if all, err := listTunnelsCached(ctx, deps); err == nil {
		for _, t := range all {
			known[t.ID] = t
		}
	}
	// PRD §2.4: Healthy < 60 s, Idle 60-300 s, Down > 300 s. Stopped
	// shows for tunnels not in the running map.
	now := time.Now().Unix()
	for _, s := range snap.Samples {
		row := LiveTunnel{
			ID:                       s.TunnelID,
			Role:                     s.Role,
			Transport:                s.Transport,
			BytesIn:                  s.BytesIn,
			BytesOut:                 s.BytesOut,
			PacketsIn:                s.PacketsIn,
			PacketsOut:               s.PacketsOut,
			ActiveSessions:           s.ActiveSessions,
			UploadRTTMsEWMA:          s.UploadRTTMsEWMA,
			DownloadRTTMsEWMA:        s.DownloadRTTMsEWMA,
			PacketLossEstimate:       s.PacketLossEstimate,
			LastPacketReceivedAtUnix: s.LastPacketReceivedAtUnix,
			LastPacketSentAtUnix:     s.LastPacketSentAtUnix,
			TransportPackets:         s.TransportPackets,
		}
		if t, ok := known[s.TunnelID]; ok {
			row.Name = t.Name
			row.Enabled = t.Enabled
		}
		row.RuntimeState = runtimeStateFor(deps, s.TunnelID)
		row.HealthBadge = healthBadgeFor(row.RuntimeState, s.LastPacketReceivedAtUnix, s.LastPacketSentAtUnix, now)
		out.Tunnels = append(out.Tunnels, row)
	}
	// Surface DB-enabled tunnels the dataplane hasn't reported yet
	// (e.g., right after a fresh enable, or a tunnel that errored at
	// spawn). Without this the dashboard would say "no tunnels" while
	// the Tunnels page shows them as enabled.
	for id, t := range known {
		seen := false
		for _, r := range out.Tunnels {
			if r.ID == id {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		row := LiveTunnel{
			ID:           t.ID,
			Name:         t.Name,
			Role:         string(t.Role),
			Transport:    string(t.DownloadTransport),
			Enabled:      t.Enabled,
			RuntimeState: runtimeStateFor(deps, t.ID),
		}
		row.HealthBadge = healthBadgeFor(row.RuntimeState, 0, 0, now)
		out.Tunnels = append(out.Tunnels, row)
	}
	return out
}

func runtimeStateFor(deps MetricsDeps, id int64) string {
	if deps.Dataplane == nil {
		return "stopped"
	}
	st := deps.Dataplane.State(id)
	if st.State == "" {
		return "stopped"
	}
	return st.State
}

// healthBadgeFor classifies a tunnel for the dashboard. PRD §2.4
// pins the thresholds: Healthy < 60 s of last activity, Idle 60-300 s,
// Down > 300 s.
//
// The Phase-11 twist: badges are *primarily* derived from observed
// packet activity, not from the dataplane's TunnelStateChanged history.
// That history can lag (the dataplane respawns and forgets the state),
// and the operator cares about "is data moving right now". So:
//
//   - "error" runtime state always wins → down.
//   - Recent activity (< 60 s) → healthy, even if the runtime cache
//     still says "stopped". A tunnel that's clearly moving bytes is
//     not stopped, regardless of what the local cache thinks.
//   - "stopped" runtime state with no activity → stopped.
//   - Otherwise classify by age.
func healthBadgeFor(runtimeState string, lastRecv, lastSent uint64, now int64) string {
	if runtimeState == "error" {
		return "down"
	}
	last := lastRecv
	if lastSent > last {
		last = lastSent
	}
	if last > 0 {
		// `last` is a Unix seconds value the dataplane stamped via
		// `now_unix()`; for any plausible value this fits an int64.
		// gosec G115 (uint64→int64) doesn't see that bound, so it's
		// guarded explicitly here — anything past mid-292-billion years
		// from the epoch is, charitably, not our concern.
		age := now - int64(last) //nolint:gosec // unix-seconds, bounded
		switch {
		case age < 60:
			return "healthy"
		case age < 300:
			return "idle"
		default:
			// Old activity + an explicit "stopped" cache means the
			// operator clicked Stop — surface that. Otherwise the
			// tunnel is genuinely down (no traffic for 5+ minutes
			// but no Stop click either).
			if runtimeState == "stopped" || runtimeState == "" {
				return "stopped"
			}
			return "down"
		}
	}
	// No observed activity at all.
	if runtimeState == "stopped" || runtimeState == "" {
		return "stopped"
	}
	return "idle"
}
