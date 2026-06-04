package tunnels

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxPortsPerTunnel is the hard cap on how many application ports a single
// tunnel may carry (PRD / IMPL_SPEC §1: typical 5–10, hard cap 32). Since
// v2.7.0 the list is the single source of truth for the tunnel's ports —
// local_listen_addr / forward_target carry only a host.
const MaxPortsPerTunnel = 32

// ValidationError carries a flat list of per-field problems so the API
// layer can ship them straight back to the form. The message text is
// user-facing and surfaces in the panel exactly as written.
type ValidationError struct {
	Fields map[string]string
}

// Error implements the error interface. The output is debug-grade; the
// API handler formats Fields for the response body.
func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "validation failed"
	}
	parts := make([]string, 0, len(e.Fields))
	for k, v := range e.Fields {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// HasErrors reports whether Fields is non-empty.
func (e *ValidationError) HasErrors() bool { return len(e.Fields) > 0 }

func newValidationError() *ValidationError {
	return &ValidationError{Fields: map[string]string{}}
}

// Validate enforces all field-level rules from PRD §3.1 / §3.2 plus the
// port-conflict rule from §3.5. `serverRole` is the role of the server
// running this code; the tunnel's own role must match it, since the
// PRD pins one role per server.
//
// `existingID` is the row id being updated (0 for create); rows with
// that id are excluded from the port-conflict scan so a no-op save
// doesn't false-positive against itself.
//
// The supplied Repo is used to read the current port-set across all
// other tunnels. Pass a real Repo backed by the live DB; tests use a
// minimal in-memory implementation.
func Validate(ctx context.Context, repo *Repo, serverRole Role, t *Tunnel, existingID int64) error {
	ve := newValidationError()

	// Name is the only globally unique handle the operator sees.
	t.Name = strings.TrimSpace(t.Name)
	switch {
	case t.Name == "":
		ve.Fields["name"] = "Name is required."
	case len(t.Name) > 64:
		ve.Fields["name"] = "Name must be 64 characters or fewer."
	}

	// Role must match the server's role. This is the "one role per
	// server" PRD invariant — a Client server can only own Client
	// tunnels and vice versa.
	if !t.Role.IsValid() {
		ve.Fields["role"] = "Role must be either client or remote."
	} else if t.Role != serverRole {
		ve.Fields["role"] = fmt.Sprintf("This server is configured as %q; it can only host %q tunnels.", serverRole, serverRole)
	}

	// Shared fields.
	if t.PSK == "" {
		ve.Fields["psk"] = "PSK is required. Must match the paired tunnel on the other server exactly."
	} else if len(t.PSK) < 8 {
		ve.Fields["psk"] = "PSK must be at least 8 characters."
	}
	if !t.DownloadTransport.IsValid() {
		ve.Fields["download_transport"] = "Transport must be one of udp, tcp_syn, icmp, or icmpv6."
	}
	// icmp_echo_mode applies only to ICMP / ICMPv6 transports; we still
	// CHECK the column against the same enum on every save so a stale
	// value can't sneak in via import/restore.
	if t.IcmpEchoMode == "" {
		t.IcmpEchoMode = IcmpEchoModeReply
	}
	if !t.IcmpEchoMode.IsValid() {
		ve.Fields["icmp_echo_mode"] = "ICMP echo mode must be either 'reply' or 'request'."
	}
	if err := checkIP(t.DownloadSpoofSourceIP); err != nil {
		ve.Fields["download_spoof_source_ip"] = "Spoof source IP " + err.Error()
	} else if t.DownloadTransport.IsValid() {
		if err := checkIPFamily(t.DownloadSpoofSourceIP, t.DownloadTransport); err != nil {
			ve.Fields["download_spoof_source_ip"] = "Spoof source IP " + err.Error()
		}
	}
	if t.DownloadSpoofSourcePort < 1 || t.DownloadSpoofSourcePort > 65535 {
		ve.Fields["download_spoof_source_port"] = "Spoof source port must be between 1 and 65535."
	}
	if t.MTU < 576 || t.MTU > 9000 {
		ve.Fields["mtu"] = "MTU must be between 576 and 9000."
	}
	if t.MaxConnections <= 0 {
		ve.Fields["max_connections"] = "Max connections must be greater than zero."
	}
	if t.IdleTimeout <= 0 {
		ve.Fields["idle_timeout"] = "Idle timeout must be greater than zero seconds."
	}

	// Forward protocol (v4.0.0). 'udp' (default) is byte-identical legacy
	// behaviour; 'tcp' activates the KCP forwarding engine. It works with
	// every download transport / upload mode, so there is no matrix gate
	// here — only the closed-enum guard.
	if t.ForwardProtocol == "" {
		t.ForwardProtocol = ForwardProtocolUDP
	}
	if !t.ForwardProtocol.IsValid() {
		ve.Fields["forward_protocol"] = "Forward protocol must be either 'udp' or 'tcp'."
	}

	// KCP engine preset + per-knob override JSON (only meaningful for tcp,
	// but validated on every save so a stale value can't slip in via
	// import/restore).
	if t.ForwardEnginePreset == "" {
		t.ForwardEnginePreset = DefaultForwardEnginePreset
	}
	if !t.ForwardEnginePreset.IsValid() {
		ve.Fields["forward_engine_preset"] = "Engine preset must be 'balanced', 'interactive', or 'lossy'."
	} else if _, err := ResolveKcpTuning(t.ForwardEnginePreset, t.ForwardEngineTuning); err != nil {
		ve.Fields["forward_engine_tuning"] = "Advanced KCP tuning: " + err.Error() + "."
	}

	// Keep-alive interval (v4.0.0). Default 20 s. When keep-alive is on it
	// must be < idle_timeout so the synthetic session is refreshed before
	// the reaper would ever consider it — and the dataplane also exempts
	// the keep-alive session from reaping as defence-in-depth.
	if t.KeepAliveIntervalSec == 0 {
		t.KeepAliveIntervalSec = 20
	}
	if t.KeepAlive {
		switch {
		case t.KeepAliveIntervalSec < 5:
			ve.Fields["keep_alive_interval_sec"] = "Keep-alive interval must be at least 5 seconds."
		case t.IdleTimeout > 0 && t.KeepAliveIntervalSec >= t.IdleTimeout:
			ve.Fields["keep_alive_interval_sec"] = "Keep-alive interval must be less than the idle timeout."
		}
	}

	// Default the Remote-side upload-listen mode from the v2 matrix so a
	// row that omits it lands on the right listener for its download
	// transport (udp→udp, tcp_syn→socks5_tcp, icmp/icmpv6→udp);
	// validateRemoteFields enforces IsValid() + the matrix once a Remote
	// tunnel reaches its branch. DefaultListenMode returns 'udp' for an
	// unknown transport, so a bad transport still defaults cleanly and
	// fails on the separate enum guard above.
	if t.UploadListenMode == "" {
		t.UploadListenMode = DefaultListenMode(t.DownloadTransport)
	}

	switch t.Role {
	case RoleClient:
		validateClientFields(t, ve)
	case RoleRemote:
		validateRemoteFields(t, ve)
	}

	// Unified application-port list (v2.7.0). Every tunnel carries at least
	// one port; all ports live together in t.Ports with a fixed 1:1
	// same-number mapping between Client and Remote. validatePorts sorts the
	// list in place so storage and the rebuilt IPC address are deterministic.
	validatePorts(t, ve)

	// Port-conflict scan. This is best-effort even when the field-level
	// validation above flagged the IP:port — if local_listen_addr is
	// malformed the conflict scan simply skips it.
	if ve.HasErrors() {
		return ve
	}
	if err := checkPortConflicts(ctx, repo, t, existingID, ve); err != nil {
		return err
	}
	if ve.HasErrors() {
		return ve
	}
	return nil
}

func validateClientFields(t *Tunnel, ve *ValidationError) {
	// local_listen_addr — required, host:port; host is the bind
	// interface (0.0.0.0 means "all"), port is what the end-user
	// device connects to.
	if !t.LocalListenAddr.Valid || strings.TrimSpace(t.LocalListenAddr.String) == "" {
		ve.Fields["local_listen_addr"] = "Local listen address is required for client tunnels (e.g. 0.0.0.0)."
	} else if err := validateHost(t.LocalListenAddr.String); err != nil {
		ve.Fields["local_listen_addr"] = "Local listen address " + err.Error()
	}

	if !t.DownloadReceivePort.Valid {
		ve.Fields["download_receive_port"] = "Download receive port is required for client tunnels."
	} else if p := t.DownloadReceivePort.Int64; p < 1 || p > 65535 {
		ve.Fields["download_receive_port"] = "Download receive port must be between 1 and 65535."
	}

	if !t.UploadTargetAddr.Valid || strings.TrimSpace(t.UploadTargetAddr.String) == "" {
		ve.Fields["upload_target_addr"] = "Upload target address is required for client tunnels (the Remote server's host:port)."
	} else if host, _, err := splitHostPort(t.UploadTargetAddr.String); err != nil {
		ve.Fields["upload_target_addr"] = "Upload target address must be host:port, e.g. 198.51.100.10:55555."
	} else if _, perr := netip.ParseAddr(host); perr != nil {
		// The dataplane parses this with a numeric SocketAddr, so a DNS
		// hostname (which net.SplitHostPort accepts) would pass here then
		// fail opaquely in Rust. Require a literal IP up front.
		ve.Fields["upload_target_addr"] = "Upload target address must use a literal IP (resolve any hostname and paste the IP), e.g. 198.51.100.10:55555."
	}

	// Upload-mode mutual exclusion (Phase R8). A Client tunnel uploads
	// through exactly one of two paths:
	//
	//   - upload_mode='wireguard' (default): needs wg_config_id set
	//     (Phase 7+) OR the legacy pasted text in wireguard_config
	//     (Phase 6); socks5_proxy_id must be NULL.
	//   - upload_mode='socks5' (Phase R8): needs socks5_proxy_id set;
	//     wg_config_id and wireguard_config must both be empty so a
	//     misclick on the picker can't double-link the tunnel.
	//
	// The Start handler returns NOT_IMPLEMENTED for socks5-mode tunnels
	// in R8; R9 adds the dataplane client.
	if t.UploadMode == "" {
		t.UploadMode = DefaultUploadMode(t.DownloadTransport)
	}
	if !t.UploadMode.IsValid() {
		ve.Fields["upload_mode"] = "Upload mode must be either 'wireguard' or 'socks5'."
	} else {
		hasWGRef := t.WGConfigID.Valid && t.WGConfigID.Int64 > 0
		hasLegacyText := t.WireguardConfig.Valid && strings.TrimSpace(t.WireguardConfig.String) != ""
		hasSocks5 := t.Socks5ProxyID.Valid && t.Socks5ProxyID.Int64 > 0
		switch t.UploadMode {
		case UploadModeWireguard:
			if !hasWGRef && !hasLegacyText {
				ve.Fields["wg_config_id"] = "Select a WireGuard config — paste one on the WireGuard page first if none exists yet."
			}
			if hasSocks5 {
				ve.Fields["socks5_proxy_id"] = "Clear the SOCKS5 proxy or switch upload mode to 'socks5'."
			}
		case UploadModeSocks5:
			if !hasSocks5 {
				ve.Fields["socks5_proxy_id"] = "Pick a SOCKS5 proxy — add one on the SOCKS5 page first if none exists yet."
			}
			if hasWGRef {
				ve.Fields["wg_config_id"] = "Clear the WireGuard config or switch upload mode to 'wireguard'."
			}
			if hasLegacyText {
				ve.Fields["wireguard_config"] = "Clear the legacy WireGuard text or switch upload mode to 'wireguard'."
			}
		}
	}

	// v2 upload × download matrix: the chosen upload mode must be valid
	// for the download transport (udp→wireguard, tcp_syn→socks5,
	// icmp/icmpv6→either). The panel restricts the picker so this only
	// fires on a hand-crafted, imported, or pre-v2 off-matrix row — and
	// when it does, it forces the operator to fix the pairing on their
	// next edit. We only flag it when both enums are otherwise valid so
	// the operator isn't shown two overlapping errors for one bad field.
	if t.DownloadTransport.IsValid() && t.UploadMode.IsValid() &&
		!UploadModeAllowed(t.DownloadTransport, t.UploadMode) {
		ve.Fields["upload_mode"] = uploadMatrixMessage(t.DownloadTransport)
	}

	// The ping_smoothing_target_ms / pacing_target_ms fields only
	// matter when their toggle is on, but we still cap them so a
	// nonsense value can't slip in via the API.
	if t.PingSmoothingTargetMS < 0 || t.PingSmoothingTargetMS > 60_000 {
		ve.Fields["ping_smoothing_target_ms"] = "Ping smoothing target must be between 0 and 60000 ms."
	}
	if t.PacingTargetMS < 0 || t.PacingTargetMS > 60_000 {
		ve.Fields["pacing_target_ms"] = "Pacing target must be between 0 and 60000 ms."
	}
}

func validateRemoteFields(t *Tunnel, ve *ValidationError) {
	if !t.UploadListenAddr.Valid || strings.TrimSpace(t.UploadListenAddr.String) == "" {
		ve.Fields["upload_listen_addr"] = "Upload listen address is required for remote tunnels (e.g. 0.0.0.0:55555)."
	} else if host, _, err := splitHostPort(t.UploadListenAddr.String); err != nil {
		ve.Fields["upload_listen_addr"] = "Upload listen address must be host:port, e.g. 0.0.0.0:55555."
	} else if _, perr := netip.ParseAddr(host); perr != nil {
		ve.Fields["upload_listen_addr"] = "Upload listen address must use a literal IP host, e.g. 0.0.0.0:55555."
	}

	if !t.ForwardTarget.Valid || strings.TrimSpace(t.ForwardTarget.String) == "" {
		ve.Fields["forward_target"] = "Forward target is required for remote tunnels (the proxy panel's host/IP, e.g. 127.0.0.1)."
	} else if err := validateHost(t.ForwardTarget.String); err != nil {
		ve.Fields["forward_target"] = "Forward target " + err.Error()
	}

	if !t.DownloadSendPort.Valid {
		ve.Fields["download_send_port"] = "Download send port is required for remote tunnels and must equal the client's download_receive_port."
	} else if p := t.DownloadSendPort.Int64; p < 1 || p > 65535 {
		ve.Fields["download_send_port"] = "Download send port must be between 1 and 65535."
	}

	if !t.ClientRealIP.Valid || strings.TrimSpace(t.ClientRealIP.String) == "" {
		ve.Fields["client_real_ip"] = "Client real IP is required (the public IP of the Iran-side Client server)."
	} else if err := checkIP(t.ClientRealIP.String); err != nil {
		ve.Fields["client_real_ip"] = "Client real IP " + err.Error()
	} else if t.DownloadTransport.IsValid() {
		if err := checkIPFamily(t.ClientRealIP.String, t.DownloadTransport); err != nil {
			ve.Fields["client_real_ip"] = "Client real IP " + err.Error()
		}
	}

	// Upload-listen mode (Phase R9a). 'udp' is the historical default
	// for every pre-R9 tunnel. 'socks5_tcp' is required when the paired
	// Client uses upload_mode='socks5' — the Remote then binds a TCP
	// listener that decodes [u16][bytes] frames instead of UDP. We can't
	// cross-check against the Client (no inter-server channel, PRD §2.3)
	// but we still enforce the closed enum so an unrecognised value
	// can't reach the dataplane via import/restore.
	if t.UploadListenMode == "" {
		t.UploadListenMode = DefaultListenMode(t.DownloadTransport)
	}
	if !t.UploadListenMode.IsValid() {
		ve.Fields["upload_listen_mode"] = "Upload listen mode must be either 'udp' or 'socks5_tcp'."
	} else if t.DownloadTransport.IsValid() &&
		!ListenModeAllowed(t.DownloadTransport, t.UploadListenMode) {
		// v2 matrix: the Remote's listen mode must match the download
		// transport (udp→udp, tcp_syn→socks5_tcp, icmp/icmpv6→either),
		// mirroring the Client-side upload-mode matrix.
		ve.Fields["upload_listen_mode"] = listenMatrixMessage(t.DownloadTransport)
	}
}

// uploadMatrixMessage is the per-field error for a Client tunnel whose
// upload_mode is off-matrix for its download transport. Only udp and
// tcp_syn are restrictive (icmp/icmpv6 allow either mode, so they never
// reach here).
func uploadMatrixMessage(t Transport) string {
	switch t {
	case TransportUDP:
		return "UDP download requires WireGuard upload (native UDP). Switch the upload mode to WireGuard, or change the download transport."
	case TransportTCPSYN:
		return "TCP-SYN download requires SOCKS5 upload (real TCP stream). Switch the upload mode to SOCKS5, or change the download transport."
	default:
		return "This upload mode isn't valid for the selected download transport."
	}
}

// listenMatrixMessage is the Remote-side counterpart to
// uploadMatrixMessage for the upload_listen_mode field.
func listenMatrixMessage(t Transport) string {
	switch t {
	case TransportUDP:
		return "UDP download requires the UDP upload-listen mode. Switch the listen mode to UDP, or change the download transport."
	case TransportTCPSYN:
		return "TCP-SYN download requires the SOCKS5-TCP upload-listen mode. Switch the listen mode to SOCKS5-TCP, or change the download transport."
	default:
		return "This upload-listen mode isn't valid for the selected download transport."
	}
}

// validatePorts enforces the unified application-port list rules (v2.7.0):
// the list is REQUIRED (every tunnel carries at least one port), each port
// is in 1..65535, no duplicates, and at most MaxPortsPerTunnel. It sorts
// the list in place so storage and the rebuilt IPC address are
// deterministic — order is irrelevant to forwarding (every port is a
// first-class peer, identically optimised).
func validatePorts(t *Tunnel, ve *ValidationError) {
	if len(t.Ports) == 0 {
		ve.Fields["ports"] = "At least one port is required."
		return
	}
	if len(t.Ports) > MaxPortsPerTunnel {
		ve.Fields["ports"] = fmt.Sprintf("A tunnel can carry at most %d ports; you listed %d.", MaxPortsPerTunnel, len(t.Ports))
		return
	}
	seen := make(map[int]struct{}, len(t.Ports))
	for _, p := range t.Ports {
		if p < 1 || p > 65535 {
			ve.Fields["ports"] = fmt.Sprintf("Each port must be between 1 and 65535; %d is out of range.", p)
			return
		}
		if _, dup := seen[p]; dup {
			ve.Fields["ports"] = fmt.Sprintf("Port %d is listed more than once. Each port may appear only once.", p)
			return
		}
		seen[p] = struct{}{}
	}
	sort.Ints(t.Ports)
}

func checkPortConflicts(ctx context.Context, repo *Repo, t *Tunnel, existingID int64, ve *ValidationError) error {
	occupied, err := collectOccupiedPorts(ctx, repo, existingID)
	if err != nil {
		return err
	}

	switch t.Role {
	case RoleClient:
		// download_receive_port is a bind port too: it must be free across
		// tunnels and must differ from this tunnel's own application ports.
		if t.DownloadReceivePort.Valid {
			port := int(t.DownloadReceivePort.Int64)
			if owner, taken := occupied[port]; taken {
				ve.Fields["download_receive_port"] = fmt.Sprintf("Port %d is already used by tunnel %q (%s).", port, owner.name, owner.field)
			}
			for _, p := range t.Ports {
				if p == port {
					ve.Fields["download_receive_port"] = "Download receive port must differ from the application ports."
					break
				}
			}
		}
	case RoleRemote:
		if port, ok := portFromAddr(t.UploadListenAddr.String); ok {
			if owner, taken := occupied[port]; taken {
				ve.Fields["upload_listen_addr"] = fmt.Sprintf("Port %d is already used by tunnel %q (%s).", port, owner.name, owner.field)
			}
		}
	}

	// Application ports. On a Client these are bind listeners (one UDP
	// socket per port), so they must be unique across tunnels; a clash is
	// reported on the `ports` field. On a Remote the application ports are
	// FORWARD destinations — several tunnels may legitimately forward to the
	// same upstream port — so they are not treated as exclusive, matching
	// pre-v2.7.0 single-port behaviour where forward_target's port was never
	// conflict-scanned.
	if t.Role == RoleClient {
		for _, port := range t.Ports {
			if owner, taken := occupied[port]; taken {
				ve.Fields["ports"] = fmt.Sprintf("Port %d is already used by tunnel %q (%s).", port, owner.name, owner.field)
				break
			}
		}
	}
	return nil
}

type occupiedPort struct {
	name  string
	field string
}

// collectOccupiedPorts builds a map of every UDP port already claimed
// by a tunnel on this server, keyed by port number, to which tunnel
// (and on which field) it belongs. `excludeID` is the tunnel being
// updated; its own ports are not considered conflicts with itself.
func collectOccupiedPorts(ctx context.Context, repo *Repo, excludeID int64) (map[int]occupiedPort, error) {
	rows, err := repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnels: list for port-conflict scan: %w", err)
	}
	occupied := make(map[int]occupiedPort, len(rows)*2)
	for _, row := range rows {
		if row.ID == excludeID {
			continue
		}
		if row.DownloadReceivePort.Valid {
			p := int(row.DownloadReceivePort.Int64)
			if _, exists := occupied[p]; !exists {
				occupied[p] = occupiedPort{name: row.Name, field: "download receive port"}
			}
		}
		if row.UploadListenAddr.Valid {
			if p, ok := portFromAddr(row.UploadListenAddr.String); ok {
				if _, exists := occupied[p]; !exists {
					occupied[p] = occupiedPort{name: row.Name, field: "upload listen port"}
				}
			}
		}
		// Application ports occupy a bind port only on a CLIENT (one
		// listener per port). A Remote's ports are forward destinations and
		// may be shared between tunnels, so they are not registered as
		// occupied. Since each server hosts one role, this naturally scans
		// client app ports on a Client box and skips them on a Remote box.
		if row.Role == RoleClient {
			for _, p := range row.Ports {
				if _, exists := occupied[p]; !exists {
					occupied[p] = occupiedPort{name: row.Name, field: "tunnel port"}
				}
			}
		}
	}
	return occupied, nil
}

func checkIP(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("is required.")
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return errors.New("must be a valid IPv4 or IPv6 address.")
	}
	return nil
}

// checkIPFamily enforces that an IP's address family matches the download
// transport: icmpv6 rides IPv6, every other transport (udp / tcp_syn /
// icmp) rides an IPv4 spoof envelope. Without this guard an IPv6 spoof IP
// on a udp tunnel (or an IPv4 IP on icmpv6) passes validation and then
// silently fails to build a valid spoofed packet in the dataplane. The
// caller only invokes this once checkIP has confirmed the string parses.
func checkIPFamily(s string, transport Transport) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return nil // checkIP already reported the parse error
	}
	isV6 := addr.Is6() && !addr.Is4In6()
	if transport == TransportICMPv6 {
		if !isV6 {
			return errors.New("must be an IPv6 address for the icmpv6 transport.")
		}
		return nil
	}
	if isV6 {
		return errors.New("must be an IPv4 address for this transport (use the icmpv6 transport for IPv6).")
	}
	return nil
}

// validateHost checks a bare host/IP address that carries NO port.
// local_listen_addr (Client) and forward_target (Remote) hold only a host
// since v2.7.0 — the application ports live in the unified Ports list. The
// host must be a literal IP (the dataplane binds / forwards with a numeric
// SocketAddr) or the wildcard 0.0.0.0 / ::. Including a port is the most
// common post-refactor mistake, so it gets a teaching message that points
// at the Ports field.
func validateHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("is required.")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return errors.New("must not include a port — list the port(s) in the Ports field.")
	}
	return errors.New("must be a valid IP address, e.g. 0.0.0.0 or 127.0.0.1.")
}

// splitHostPort accepts either bracketed IPv6 (`[::1]:443`) or
// host:port for IPv4/hostnames. We use net.SplitHostPort because it
// handles both shapes; the host is then validated as either an IP or
// the wildcard "0.0.0.0" / "::". Hostname-style hosts are accepted (we
// don't resolve here — DNS is a runtime concern handled in Phase 7+).
func splitHostPort(s string) (host string, port int, err error) {
	s = strings.TrimSpace(s)
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("malformed host:port: %w", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("port is not a number: %w", err)
	}
	if p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return host, p, nil
}

// portFromAddr extracts the port from a host:port string, returning
// ok=false if the input is empty or malformed. Used by the conflict
// scan, which deliberately ignores invalid addresses (the field
// validator will already have flagged them).
func portFromAddr(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	_, port, err := splitHostPort(s)
	if err != nil {
		return 0, false
	}
	return port, true
}
