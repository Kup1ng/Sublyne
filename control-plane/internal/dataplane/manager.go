// Package dataplane wraps the IPC client behind a higher-level
// "start this tunnel" / "stop this tunnel" surface that the HTTP
// handlers call into.
//
// Phase 8a only handles UDP — the dataplane refuses other transports
// with UNSUPPORTED_TRANSPORT. Phase 9 expands the catalog.
package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// Manager bridges the database-shaped Tunnel record to the
// IPC-shaped TunnelSpec and tracks per-tunnel runtime state.
type Manager struct {
	supervisor *ipc.Supervisor
	logger     *slog.Logger

	mu     sync.Mutex
	states map[int64]RuntimeState
}

// RuntimeState is the manager's view of a tunnel's live status. It
// lives in memory only; on service restart it is rebuilt from the
// DB (every enabled tunnel is restarted) by Sync().
type RuntimeState struct {
	State  string // "starting" | "running" | "stopped" | "error"
	Reason string
	Since  time.Time
}

// NewManager constructs a Manager backed by the supplied supervisor.
// The supervisor must already be in Run() — Manager calls into it but
// does not own its lifecycle.
func NewManager(sup *ipc.Supervisor, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		supervisor: sup,
		logger:     logger,
		states:     make(map[int64]RuntimeState),
	}
}

// Start asks the dataplane to bring up the supplied tunnel. The
// runtime state for the id transitions to "running" on success and
// "error" on failure (with the error reason recorded for the panel).
//
// `proxy` carries the resolved SOCKS5 proxy row (host, port, optional
// credentials, parallel_connections) when the tunnel's UploadMode is
// 'socks5'. The handler layer resolves it before calling — this lets
// the dataplane stay ignorant of the SOCKS5 repo and keeps the secret
// (the password) on the request-scoped path rather than embedded on
// the manager. Pass nil for wireguard-mode tunnels and remote tunnels.
func (m *Manager) Start(ctx context.Context, t tunnels.Tunnel, proxy *socks5.Proxy) error {
	if m == nil {
		return errors.New("dataplane: manager not configured")
	}
	switch t.DownloadTransport {
	case tunnels.TransportUDP, tunnels.TransportTCPSYN, tunnels.TransportICMP, tunnels.TransportICMPv6:
		// All four download transports are supported as of Phase 8b.
	default:
		return &TransportUnsupportedError{Transport: string(t.DownloadTransport)}
	}
	client := m.supervisor.Client()
	if client == nil {
		return errors.New("dataplane: not ready (supervisor still starting)")
	}
	spec, err := buildSpec(t, proxy)
	if err != nil {
		return fmt.Errorf("dataplane: build spec: %w", err)
	}
	m.recordState(t.ID, "starting", "")
	reply, err := client.Send(ctx, "StartTunnel", spec)
	if err != nil {
		m.recordState(t.ID, "error", err.Error())
		return err
	}
	if !reply.OK {
		msg := "unknown"
		if reply.Error != nil {
			msg = reply.Error.Error()
		}
		m.recordState(t.ID, "error", msg)
		if reply.Error != nil {
			return reply.Error
		}
		return errors.New(msg)
	}
	m.recordState(t.ID, "running", "")
	return nil
}

// Update sends an `UpdateTunnel` IPC command to the dataplane with
// the new spec. The dataplane decides whether the change is a true
// hot-reload (PSK / MTU / spoof params / max_connections /
// idle_timeout — applied with no listener interruption) or whether it
// requires an internal restart (transport / other-side addresses /
// fwmark — the dataplane performs the Stop + Start itself), or
// whether it cannot be applied at all without operator-visible
// Stop + Start (local_listen_addr / upload_listen_addr — RESTART_REQUIRED).
//
// On RESTART_REQUIRED the caller (the HTTP handler) is responsible
// for surfacing the explanation to the panel so the operator clicks
// the Stop / Start buttons themselves.
func (m *Manager) Update(ctx context.Context, t tunnels.Tunnel, proxy *socks5.Proxy) (UpdateOutcome, error) {
	if m == nil {
		return UpdateOutcome{}, errors.New("dataplane: manager not configured")
	}
	switch t.DownloadTransport {
	case tunnels.TransportUDP, tunnels.TransportTCPSYN, tunnels.TransportICMP, tunnels.TransportICMPv6:
	default:
		return UpdateOutcome{}, &TransportUnsupportedError{Transport: string(t.DownloadTransport)}
	}
	client := m.supervisor.Client()
	if client == nil {
		return UpdateOutcome{}, errors.New("dataplane: not ready (supervisor still starting)")
	}
	spec, err := buildSpec(t, proxy)
	if err != nil {
		return UpdateOutcome{}, fmt.Errorf("dataplane: build spec: %w", err)
	}
	reply, err := client.Send(ctx, "UpdateTunnel", spec)
	if err != nil {
		m.recordState(t.ID, "error", err.Error())
		return UpdateOutcome{}, err
	}
	if !reply.OK {
		if reply.Error != nil && reply.Error.Code == ipc.CodeRestartRequired {
			// The dataplane keeps running the OLD config until the
			// operator clicks Stop/Start, so the tunnel is still
			// "running" — the handler surfaces the restart banner.
			m.recordState(t.ID, "running", "")
			return UpdateOutcome{RestartRequired: true, Reason: reply.Error.Message}, nil
		}
		if reply.Error != nil {
			m.recordState(t.ID, "error", reply.Error.Error())
			return UpdateOutcome{}, reply.Error
		}
		m.recordState(t.ID, "error", "dataplane: update failed")
		return UpdateOutcome{}, errors.New("dataplane: update failed")
	}
	out := UpdateOutcome{Applied: true}
	if len(reply.Value) > 0 {
		var body struct {
			Changed []string `json:"changed"`
		}
		if err := json.Unmarshal(reply.Value, &body); err == nil {
			out.Changed = body.Changed
		}
	}
	m.recordState(t.ID, "running", "")
	return out, nil
}

// UpdateOutcome describes what happened in an Update call. Exactly one
// of `RestartRequired` and `Applied` is true on success. The HTTP
// handler uses these to either continue the response normally or
// surface a "restart this tunnel to apply" banner to the panel.
type UpdateOutcome struct {
	// Applied is true if the dataplane accepted the update — either as
	// a true hot-reload or via internal Stop+Start.
	Applied bool
	// RestartRequired is true if the dataplane rejected the update
	// because a listen-addr field changed. The operator must click
	// Stop then Start to apply the change.
	RestartRequired bool
	// Changed lists the field names the dataplane reported as actually
	// modified. Useful for the panel to show "PSK live-rotated" vs
	// "restarted" feedback.
	Changed []string
	// Reason carries the dataplane's human message when
	// RestartRequired is true.
	Reason string
}

// Stop asks the dataplane to tear down the tunnel. Idempotent —
// stopping a tunnel that isn't running returns nil after the
// dataplane replies with TUNNEL_NOT_FOUND.
func (m *Manager) Stop(ctx context.Context, id int64) error {
	if m == nil {
		return nil
	}
	client := m.supervisor.Client()
	if client == nil {
		// Dataplane is already down — treat as success.
		m.recordState(id, "stopped", "")
		return nil
	}
	reply, err := client.Send(ctx, "StopTunnel", ipc.StopTunnelPayload{ID: id})
	if err != nil {
		return err
	}
	if !reply.OK {
		if reply.Error != nil && reply.Error.Code == ipc.CodeTunnelNotFound {
			m.recordState(id, "stopped", "")
			return nil
		}
		if reply.Error != nil {
			return reply.Error
		}
		return errors.New("dataplane: stop failed")
	}
	m.recordState(id, "stopped", "")
	return nil
}

// SetLogLevel pushes a `SetLogLevel` IPC command at the dataplane.
// Called both by the LevelControl OnChange hook (when an operator flips
// the panel's log-level dropdown) and by main's reconcile loop on every
// dataplane (re)connect. A nil manager or a not-yet-connected supervisor
// is a soft no-op — the reconcile loop re-pushes the current level the
// moment the next child reaches Ready, so a respawned dataplane always
// converges on the operator's chosen level.
func (m *Manager) SetLogLevel(ctx context.Context, level string) error {
	if m == nil {
		return nil
	}
	client := m.supervisor.Client()
	if client == nil {
		return nil
	}
	reply, err := client.Send(ctx, "SetLogLevel", ipc.SetLogLevelPayload{Level: level})
	if err != nil {
		return err
	}
	if !reply.OK {
		if reply.Error != nil {
			return reply.Error
		}
		return errors.New("dataplane: SetLogLevel failed")
	}
	return nil
}

// State returns the current runtime state for the tunnel, or
// ("stopped", "", zero) if the manager has no record. The DTO layer
// uses this to surface a runtime badge alongside the configuration's
// enabled flag.
func (m *Manager) State(id int64) RuntimeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.states[id]; ok {
		return s
	}
	return RuntimeState{State: "stopped"}
}

// AllStates returns a snapshot of every tracked runtime state.
func (m *Manager) AllStates() map[int64]RuntimeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int64]RuntimeState, len(m.states))
	for k, v := range m.states {
		out[k] = v
	}
	return out
}

// SOCKS5Resolver returns the stored proxy row referenced by a tunnel.
// Implemented by *socks5.Repo in production; tests substitute an
// in-memory stub. Used by Sync to re-resolve proxies on boot without
// teaching the dataplane Manager about the SOCKS5 repo's full surface.
type SOCKS5Resolver interface {
	Get(ctx context.Context, id int64) (socks5.Proxy, error)
}

// Sync starts every tunnel from `enabled` rows in the supplied list
// that isn't already running. Called once on boot (after migrations,
// before the HTTP server starts taking traffic) so the dataplane
// reflects DB state after a process restart.
//
// `resolver` may be nil — Sync then logs a warn and skips any SOCKS5-
// mode tunnel (the operator can click Start manually once the panel
// loads).
func (m *Manager) Sync(ctx context.Context, all []tunnels.Tunnel, resolver SOCKS5Resolver) {
	if m == nil {
		return
	}
	for _, t := range all {
		if !t.Enabled {
			continue
		}
		// All four download transports (UDP, TCP-SYN, ICMP, ICMPv6)
		// are supported as of Phase 8b. Unsupported variants fall
		// through to Start() and surface as a TransportUnsupportedError.
		var proxy *socks5.Proxy
		if t.Role == tunnels.RoleClient && t.UploadMode == tunnels.UploadModeSocks5 {
			if resolver == nil || !t.Socks5ProxyID.Valid {
				m.logger.Warn("dataplane: sync skipping SOCKS5 tunnel; no proxy resolver or no FK",
					"tunnel_id", t.ID)
				continue
			}
			p, err := resolver.Get(ctx, t.Socks5ProxyID.Int64)
			if err != nil {
				m.logger.Warn("dataplane: sync resolve SOCKS5 proxy failed",
					"tunnel_id", t.ID, "err", err)
				continue
			}
			proxy = &p
		}
		if err := m.Start(ctx, t, proxy); err != nil {
			m.logger.Warn("dataplane: sync start failed", "tunnel_id", t.ID, "err", err)
		}
	}
}

// ListenStateChanges subscribes to the supervisor's underlying IPC
// client and keeps Manager's `states` map in sync with what the
// dataplane reports. Spawn this once at startup; it returns when ctx
// is cancelled.
func (m *Manager) ListenStateChanges(ctx context.Context) {
	if m == nil || m.supervisor == nil {
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		client := m.supervisor.Client()
		if client == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		ch := client.SubscribeStateChanges(256)
		// Consume events until the channel closes (dataplane
		// restarted) or ctx fires.
	inner:
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-ch:
				if !ok {
					break inner
				}
				reason := ""
				if evt.Reason != nil {
					reason = *evt.Reason
				}
				m.recordState(evt.TunnelID, string(evt.State), reason)
			}
		}
	}
}

func (m *Manager) recordState(id int64, state, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = RuntimeState{State: state, Reason: reason, Since: time.Now()}
}

// TransportUnsupportedError is returned by Start when the tunnel
// asks for a transport the dataplane doesn't yet understand.
type TransportUnsupportedError struct {
	Transport string
}

// Error implements error.
func (e *TransportUnsupportedError) Error() string {
	return fmt.Sprintf("dataplane: transport %q is not recognized", e.Transport)
}

// buildSpec converts the DB-shaped tunnel into the IPC-shaped spec
// the Rust dataplane consumes. `proxy` carries the resolved SOCKS5
// proxy row when t.UploadMode is 'socks5'; nil otherwise.
func buildSpec(t tunnels.Tunnel, proxy *socks5.Proxy) (ipc.TunnelSpec, error) {
	// MTU / max_connections / idle_timeout are stored as Go int but the
	// IPC wire types are uint32; the validator in tunnels/validation.go
	// rejects negatives and absurd ranges on the CRUD path, so the
	// narrowing here is always within range.
	if t.MTU < 0 || t.MaxConnections < 0 || t.IdleTimeout < 0 {
		return ipc.TunnelSpec{}, errors.New("tunnel fields must be non-negative")
	}
	if t.DownloadSpoofSourcePort < 0 || t.DownloadSpoofSourcePort > 65535 {
		return ipc.TunnelSpec{}, errors.New("download_spoof_source_port out of range")
	}
	if t.PingSmoothingTargetMS < 0 || t.PacingTargetMS < 0 {
		return ipc.TunnelSpec{}, errors.New("latency knobs must be non-negative")
	}
	spec := ipc.TunnelSpec{
		ID:                      t.ID,
		Role:                    string(t.Role),
		Name:                    t.Name,
		MTU:                     uint32(t.MTU), //nolint:gosec // bounded above
		PSK:                     t.PSK,
		MaxConnections:          uint32(t.MaxConnections), //nolint:gosec // bounded above
		IdleTimeoutSec:          uint32(t.IdleTimeout),    //nolint:gosec // bounded above
		DownloadTransport:       string(t.DownloadTransport),
		DownloadSpoofSourceIP:   t.DownloadSpoofSourceIP,
		DownloadSpoofSourcePort: uint16(t.DownloadSpoofSourcePort), //nolint:gosec // bounded above
		IcmpEchoMode:            string(t.IcmpEchoMode),
		PingSmoothingEnabled:    t.PingSmoothingEnabled,
		PingSmoothingTargetMS:   uint32(t.PingSmoothingTargetMS), //nolint:gosec // bounded above
		PacingEnabled:           t.PacingEnabled,
		PacingTargetMS:          uint32(t.PacingTargetMS), //nolint:gosec // bounded above
	}
	// Multi-port (v2.5.0): carry the app-port list to the dataplane only
	// when the tunnel is genuinely multi-port (>= 2 ports). A 0- or
	// 1-element list is single-port — leave spec.Ports empty so the
	// dataplane takes the byte-for-byte-identical v2.4.0 path. The list is
	// shared by both roles. The validator already bounds each port to
	// 1..65535, so the uint16 narrowing here is always in range.
	if len(t.Ports) >= 2 {
		ports := make([]uint16, 0, len(t.Ports))
		for _, p := range t.Ports {
			if p < 0 || p > 65535 {
				return ipc.TunnelSpec{}, fmt.Errorf("port out of range: %d", p)
			}
			ports = append(ports, uint16(p)) //nolint:gosec // bounded above
		}
		spec.Ports = ports
	}
	switch t.Role {
	case tunnels.RoleClient:
		if !t.LocalListenAddr.Valid {
			return spec, errors.New("client tunnel missing local_listen_addr")
		}
		if !t.UploadTargetAddr.Valid {
			return spec, errors.New("client tunnel missing upload_target_addr")
		}
		if !t.DownloadReceivePort.Valid {
			return spec, errors.New("client tunnel missing download_receive_port")
		}
		if t.DownloadReceivePort.Int64 < 0 || t.DownloadReceivePort.Int64 > 65535 {
			return spec, errors.New("download_receive_port out of range")
		}
		listenAddr, err := appAddr(t.LocalListenAddr.String, t.Ports)
		if err != nil {
			return spec, fmt.Errorf("client tunnel local_listen_addr: %w", err)
		}
		spec.LocalListenAddr = listenAddr
		spec.UploadTargetAddr = t.UploadTargetAddr.String
		spec.DownloadReceivePort = uint16(t.DownloadReceivePort.Int64) //nolint:gosec // bounded above
		// Mutually exclusive upload paths: a Client tunnel either
		// carries a WireGuard fwmark (egress through the kernel WG
		// interface) or a Socks5Target (egress through N SOCKS5 TCP
		// connections — Phase R9b opens N parallel connections, one
		// per Starlink uplink behind the proxy). The validator already
		// prevents both being set in the DB.
		switch t.UploadMode {
		case tunnels.UploadModeSocks5:
			if proxy == nil {
				return spec, errors.New("client tunnel upload_mode=socks5 but no proxy provided")
			}
			if proxy.Port < 1 || proxy.Port > 65535 {
				return spec, fmt.Errorf("socks5 proxy port out of range: %d", proxy.Port)
			}
			if proxy.ParallelConnections < 1 || proxy.ParallelConnections > 64 {
				return spec, fmt.Errorf("socks5 proxy parallel_connections out of range: %d", proxy.ParallelConnections)
			}
			// Clamp into a local — never mutate the caller's *proxy,
			// which is a request-scoped row the handler may reuse.
			minReadySlots := proxy.MinReadySlots
			if minReadySlots < 1 {
				minReadySlots = 1
			}
			if minReadySlots > proxy.ParallelConnections {
				minReadySlots = proxy.ParallelConnections
			}
			target := &ipc.Socks5Target{
				Host:                proxy.Host,
				Port:                uint16(proxy.Port),                //nolint:gosec // bounded above
				ParallelConnections: uint32(proxy.ParallelConnections), //nolint:gosec // bounded above
				MinReadySlots:       uint32(minReadySlots),             //nolint:gosec // bounded above
			}
			if proxy.Username.Valid {
				target.Username = proxy.Username.String
			}
			if proxy.Password.Valid {
				target.Password = proxy.Password.String
			}
			spec.Socks5Target = target
		default:
			// 'wireguard' mode (the default) — carry the fwmark when a
			// WG config is linked. Empty wg_config_id leaves the mark
			// at zero, which the dataplane treats as "no SO_MARK" and
			// is useful for loopback tests.
			if t.WGConfigID.Valid {
				// fwmark uses the canonical scheme from wg.FwmarkFor so
				// the per-tunnel SO_MARK the dataplane sets matches the
				// `ip rule fwmark X` the wg policy layer installs. The
				// 12-bit mask in FwmarkFor keeps the value in 16 bits.
				spec.WireguardFwmark = wg.FwmarkFor(t.ID)
			}
		}
	case tunnels.RoleRemote:
		if !t.UploadListenAddr.Valid {
			return spec, errors.New("remote tunnel missing upload_listen_addr")
		}
		if !t.ForwardTarget.Valid {
			return spec, errors.New("remote tunnel missing forward_target")
		}
		if !t.DownloadSendPort.Valid {
			return spec, errors.New("remote tunnel missing download_send_port")
		}
		if !t.ClientRealIP.Valid {
			return spec, errors.New("remote tunnel missing client_real_ip")
		}
		if t.DownloadSendPort.Int64 < 0 || t.DownloadSendPort.Int64 > 65535 {
			return spec, errors.New("download_send_port out of range")
		}
		spec.UploadListenAddr = t.UploadListenAddr.String
		forwardAddr, err := appAddr(t.ForwardTarget.String, t.Ports)
		if err != nil {
			return spec, fmt.Errorf("remote tunnel forward_target: %w", err)
		}
		spec.ForwardTarget = forwardAddr
		spec.DownloadSendPort = uint16(t.DownloadSendPort.Int64) //nolint:gosec // bounded above
		spec.ClientRealIP = t.ClientRealIP.String
		// Default to 'udp' so a Remote row without an explicit value
		// (everything pre-R9) keeps the historical UDP listener.
		mode := string(t.UploadListenMode)
		if mode == "" {
			mode = string(tunnels.UploadListenModeUDP)
		}
		spec.UploadListenMode = mode
	default:
		return spec, fmt.Errorf("unknown role %q", t.Role)
	}
	return spec, nil
}
