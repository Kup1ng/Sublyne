// Package tunnels persists, validates, and surfaces port-conflict
// information for the Phase 6 tunnel CRUD path.
//
// Phase 6 does not start any data plane. The handlers in
// control-plane/internal/api/tunnel_handlers.go flip the `enabled`
// flag and the dashboard's status badge reflects that flag directly;
// Phase 10 will replace that with the real liveness signal coming back
// from the Rust dataplane over IPC.
package tunnels

import "database/sql"

// Transport is the spoof-envelope L4 used to carry download payloads
// past Iran's DPI. PRD §3.1 / §3.2 list the four valid values; the
// SQLite CHECK constraint in 0002_tunnels.sql enforces the same set.
type Transport string

// Transport values mirror the wire-level identifiers used by the
// dataplane and the migration's CHECK constraint. Keep this list and
// the migration in sync.
const (
	TransportUDP    Transport = "udp"
	TransportTCPSYN Transport = "tcp_syn"
	TransportICMP   Transport = "icmp"
	TransportICMPv6 Transport = "icmpv6"
)

// IsValid returns true when t is one of the four PRD-pinned transports.
func (t Transport) IsValid() bool {
	switch t {
	case TransportUDP, TransportTCPSYN, TransportICMP, TransportICMPv6:
		return true
	}
	return false
}

// IsICMP returns true when t is icmp or icmpv6 — the two transports for
// which IcmpEchoMode is meaningful.
func (t Transport) IsICMP() bool {
	return t == TransportICMP || t == TransportICMPv6
}

// IcmpEchoMode is the wire-direction selector for the ICMP / ICMPv6
// download transport (Phase R4). Reply = ICMP type 0 / 129 (the
// default; what Phase 8b shipped). Request = ICMP type 8 / 128, with
// the kernel's auto-reply suppressed for the receiver's lifetime.
// Documented in 0005_icmp_echo_mode.sql.
type IcmpEchoMode string

// IcmpEchoMode values mirror the migration's CHECK constraint.
const (
	IcmpEchoModeReply   IcmpEchoMode = "reply"
	IcmpEchoModeRequest IcmpEchoMode = "request"
)

// IsValid reports whether m is one of the two supported modes.
func (m IcmpEchoMode) IsValid() bool {
	return m == IcmpEchoModeReply || m == IcmpEchoModeRequest
}

// UploadMode is the upload-path selector (Phase R8). 'wireguard' is
// the default and the only mode v0.1.x supported: upload egresses
// through the kernel WireGuard interface named by wg_config_id.
// 'socks5' (Phase R8 + R9) routes upload through one of the SOCKS5
// proxies in socks5_proxies; Phase R9 builds the dataplane client
// that opens N parallel TCP connections to spread upload across
// multiple Starlink uplinks. R9a wires the dataplane for the single-
// connection path; R9b grows it to N parallel connections.
type UploadMode string

// UploadMode values mirror the migration's CHECK constraint
// (0006_socks5_proxies.sql).
const (
	UploadModeWireguard UploadMode = "wireguard"
	UploadModeSocks5    UploadMode = "socks5"
)

// IsValid reports whether m is one of the two supported modes.
func (m UploadMode) IsValid() bool {
	return m == UploadModeWireguard || m == UploadModeSocks5
}

// UploadListenMode is the Remote-side counterpart to UploadMode
// (Phase R9a). 'udp' is the historical default and matches every
// pre-R9 tunnel — the Remote binds a UDP listener on
// upload_listen_addr. 'socks5_tcp' is the SOCKS5 case: the Remote
// accepts a TCP connection on upload_listen_addr and decodes
// `[u16 BE length][bytes]` frames into UDP payloads it forwards to
// forward_target. The paired Client must set upload_mode='socks5'.
type UploadListenMode string

// UploadListenMode values mirror the migration's CHECK constraint
// (0007_upload_listen_mode.sql).
const (
	UploadListenModeUDP       UploadListenMode = "udp"
	UploadListenModeSocks5TCP UploadListenMode = "socks5_tcp"
)

// IsValid reports whether m is one of the two supported modes.
func (m UploadListenMode) IsValid() bool {
	return m == UploadListenModeUDP || m == UploadListenModeSocks5TCP
}

// --- v2 upload × download matrix -------------------------------------
//
// The upload path is a function of the download transport, not an
// independent choice. The download transport encodes the operator's
// regime; the upload substrate is chosen to suit it:
//
//	download  │ allowed upload modes      │ default
//	──────────┼───────────────────────────┼───────────
//	udp       │ wireguard                 │ wireguard
//	tcp_syn   │ socks5                    │ socks5
//	icmp      │ wireguard, socks5         │ wireguard
//	icmpv6    │ wireguard, socks5         │ wireguard
//
// The Remote side mirrors this via upload_listen_mode (udp pairs with
// wireguard upload; socks5_tcp pairs with socks5 upload). These pure
// helpers are the single source of truth the validator, the API
// defaulting, and the panel's TypeScript mirror all agree with.

// AllowedUploadModes returns the Client-side upload modes valid for a
// download transport under the v2 matrix. Returns nil for an unknown
// transport (the transport enum guard rejects those separately).
func AllowedUploadModes(t Transport) []UploadMode {
	switch t {
	case TransportUDP:
		return []UploadMode{UploadModeWireguard}
	case TransportTCPSYN:
		return []UploadMode{UploadModeSocks5}
	case TransportICMP, TransportICMPv6:
		return []UploadMode{UploadModeWireguard, UploadModeSocks5}
	}
	return nil
}

// DefaultUploadMode returns the sensible default upload mode for a
// download transport: SOCKS5 for tcp_syn, WireGuard for everything else
// (including unknown transports, which fail the enum guard anyway).
func DefaultUploadMode(t Transport) UploadMode {
	if t == TransportTCPSYN {
		return UploadModeSocks5
	}
	return UploadModeWireguard
}

// UploadModeAllowed reports whether upload mode m is valid for download
// transport t under the matrix.
func UploadModeAllowed(t Transport, m UploadMode) bool {
	for _, a := range AllowedUploadModes(t) {
		if a == m {
			return true
		}
	}
	return false
}

// AllowedListenModes returns the Remote-side upload-listen modes valid
// for a download transport under the v2 matrix.
func AllowedListenModes(t Transport) []UploadListenMode {
	switch t {
	case TransportUDP:
		return []UploadListenMode{UploadListenModeUDP}
	case TransportTCPSYN:
		return []UploadListenMode{UploadListenModeSocks5TCP}
	case TransportICMP, TransportICMPv6:
		return []UploadListenMode{UploadListenModeUDP, UploadListenModeSocks5TCP}
	}
	return nil
}

// DefaultListenMode returns the sensible default Remote-side listen mode
// for a download transport: socks5_tcp for tcp_syn, udp otherwise.
func DefaultListenMode(t Transport) UploadListenMode {
	if t == TransportTCPSYN {
		return UploadListenModeSocks5TCP
	}
	return UploadListenModeUDP
}

// ListenModeAllowed reports whether listen mode m is valid for download
// transport t under the matrix.
func ListenModeAllowed(t Transport, m UploadListenMode) bool {
	for _, a := range AllowedListenModes(t) {
		if a == m {
			return true
		}
	}
	return false
}

// Role identifies which side of the asymmetric pair a tunnel runs on.
// The set is closed: each server is either a Client (Iran-side end-user
// listener) or a Remote (foreign-side forward target).
type Role string

// Role values match the role column's CHECK constraint and the config
// file's role field.
const (
	RoleClient Role = "client"
	RoleRemote Role = "remote"
)

// IsValid reports whether r is one of the two supported roles.
func (r Role) IsValid() bool { return r == RoleClient || r == RoleRemote }

// Tunnel is the in-memory representation of one row in `tunnels`. Both
// client- and remote-only fields are present; the ones that don't apply
// for the row's role are zero/sql.Null* values.
//
// The PSK is held as a plain string in this struct because that's the
// shape the SQLite driver hands back. The API layer redacts it before
// it leaves the process; see API_RedactedPSK in api/tunnel_handlers.go.
type Tunnel struct {
	ID                      int64
	Name                    string
	Role                    Role
	Enabled                 bool
	PSK                     string
	DownloadSpoofSourceIP   string
	DownloadSpoofSourcePort int
	DownloadTransport       Transport
	MTU                     int
	MaxConnections          int
	IdleTimeout             int
	IcmpEchoMode            IcmpEchoMode

	// Client-only fields. Pointers carry the SQL NULL distinction
	// because some are strings (NULL vs empty) and the validator
	// needs to tell them apart on update.
	LocalListenAddr       sql.NullString
	DownloadReceivePort   sql.NullInt64
	UploadTargetAddr      sql.NullString
	WireguardConfig       sql.NullString // Phase 6 legacy: pasted text round-tripped on the tunnel row
	WGConfigID            sql.NullInt64  // Phase 7+: FK into wireguard_configs; preferred over WireguardConfig
	UploadMode            UploadMode     // Phase R8: 'wireguard' (default) or 'socks5'
	Socks5ProxyID         sql.NullInt64  // Phase R8: FK-by-convention into socks5_proxies when UploadMode='socks5'
	PingSmoothingEnabled  bool
	PingSmoothingTargetMS int
	PacingEnabled         bool
	PacingTargetMS        int

	// Remote-only fields.
	UploadListenAddr sql.NullString
	ForwardTarget    sql.NullString
	DownloadSendPort sql.NullInt64
	ClientRealIP     sql.NullString
	// UploadListenMode (Phase R9a): 'udp' (default) or 'socks5_tcp'.
	// Remote-only — Client tunnels ignore the field. Pairs with the
	// Client's UploadMode: a Client tunnel with upload_mode='socks5'
	// must point at a Remote tunnel with upload_listen_mode='socks5_tcp'.
	UploadListenMode UploadListenMode
}
