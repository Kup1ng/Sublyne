// Package ipc implements the Go side of the control-plane ↔
// data-plane protocol described in
// .claude/skills/rust-go-ipc/SKILL.md.
//
// The wire format is length-prefixed JSON: every frame starts with a
// 4-byte big-endian length followed by exactly that many bytes of
// JSON body. The envelope shape is
//
//	{ "type": "<MessageName>", "id": "<uuid>", "payload": { … } }
//
// where commands (Go → Rust) get a Reply that echoes the same id,
// and events (Rust → Go) carry their own fresh id and are not replied
// to.
package ipc

import (
	"encoding/json"
)

// MaxFrameBytes mirrors the Rust side's cap. Frames larger than this
// indicate a protocol violation and close the connection.
const MaxFrameBytes = 16 * 1024 * 1024

// Envelope is the unparsed wire shape. The payload is held as
// json.RawMessage so the dispatcher can downcast based on Type.
type Envelope struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

// ReplyPayload is the shape of the payload object inside every
// Reply frame.
type ReplyPayload struct {
	OK    bool            `json:"ok"`
	Error *IPCError       `json:"error,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// IPCError mirrors the Rust IpcError struct. Code is a stable string
// (the constants in the Codes block below); Message is for humans.
type IPCError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Context json.RawMessage `json:"context,omitempty"`
}

// Error implements the error interface so callers can `errors.Is` /
// `errors.As` against IPCError.
func (e *IPCError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

// Stable error codes returned by the dataplane. Mirrors Rust's
// `sublyne_dataplane::protocol::codes`.
const (
	CodePortInUse            = "PORT_IN_USE"
	CodeRawSocketForbidden   = "RAW_SOCKET_FORBIDDEN"
	CodeRestartRequired      = "RESTART_REQUIRED"
	CodeTunnelNotFound       = "TUNNEL_NOT_FOUND"
	CodeInvalidTunnelSpec    = "INVALID_TUNNEL_SPEC"
	CodeInternal             = "INTERNAL"
	CodeUnsupportedTransport = "UNSUPPORTED_TRANSPORT"
)

// TunnelState mirrors the Rust enum so the panel can render badges
// without re-translating string values.
type TunnelState string

const (
	StateStarting TunnelState = "starting"
	StateRunning  TunnelState = "running"
	StateStopped  TunnelState = "stopped"
	StateError    TunnelState = "error"
)

// TunnelStateChanged is the event payload pushed by the dataplane
// whenever a tunnel's lifecycle state changes asynchronously.
type TunnelStateChanged struct {
	TunnelID int64       `json:"tunnel_id"`
	State    TunnelState `json:"state"`
	Reason   *string     `json:"reason,omitempty"`
}

// TunnelSpec is the payload for StartTunnel / UpdateTunnel. Field
// names mirror the JSON tags in
// .claude/skills/rust-go-ipc/SKILL.md §"Tunnel spec schema".
type TunnelSpec struct {
	ID                      int64  `json:"id"`
	Role                    string `json:"role"`
	Name                    string `json:"name"`
	MTU                     uint32 `json:"mtu"`
	PSK                     string `json:"psk"`
	MaxConnections          uint32 `json:"max_connections"`
	IdleTimeoutSec          uint32 `json:"idle_timeout_sec"`
	DownloadTransport       string `json:"download_transport"`
	DownloadSpoofSourceIP   string `json:"download_spoof_source_ip"`
	DownloadSpoofSourcePort uint16 `json:"download_spoof_source_port"`

	// IcmpEchoMode = "reply" (Phase 8b default — ICMP type 0 / 129) or
	// "request" (Phase R4 — ICMP type 8 / 128 with the kernel's
	// auto-reply suppressed for the receiver's lifetime). Ignored when
	// DownloadTransport is not icmp or icmpv6.
	IcmpEchoMode string `json:"icmp_echo_mode,omitempty"`

	// Ports (v2.5.0 multi-port) — shared by both roles. The full
	// authoritative list of application ports this tunnel carries, with a
	// fixed 1:1 same-number mapping (client :8000 <-> remote :8000).
	// Omitted (empty) means single-port: the data plane takes the
	// byte-for-byte-identical v2.4.0 path and binds only the one port in
	// local_listen_addr / forward_target. When present (>= 2 entries) the
	// per-port app-tag wire format activates; the bind host is taken from
	// local_listen_addr (Client) / forward_target (Remote).
	Ports []uint16 `json:"ports,omitempty"`

	// Client-only.
	LocalListenAddr     string `json:"local_listen_addr,omitempty"`
	DownloadReceivePort uint16 `json:"download_receive_port,omitempty"`
	UploadTargetAddr    string `json:"upload_target_addr,omitempty"`
	WireguardFwmark     uint32 `json:"wireguard_fwmark,omitempty"`
	// Socks5Target is set instead of WireguardFwmark on Client tunnels
	// whose UploadMode is 'socks5' (Phase R9a). Mutually exclusive
	// with the fwmark: the Go side never sets both. The Rust dataplane
	// validates the same invariant on receive.
	Socks5Target *Socks5Target `json:"socks5_target,omitempty"`

	// Remote-only.
	UploadListenAddr string `json:"upload_listen_addr,omitempty"`
	ForwardTarget    string `json:"forward_target,omitempty"`
	DownloadSendPort uint16 `json:"download_send_port,omitempty"`
	ClientRealIP     string `json:"client_real_ip,omitempty"`
	// UploadListenMode (Phase R9a) — Remote-only. "udp" (default) keeps
	// the historical UDP listener; "socks5_tcp" switches the listener
	// to TCP and decodes [u16 BE length][bytes] frames. Empty string
	// is accepted by the Rust side as the default. The matching Client
	// tunnel must carry a Socks5Target for the pair to actually move
	// traffic; we can't cross-check that here (PRD §2.3 — no inter-
	// server control plane).
	UploadListenMode string `json:"upload_listen_mode,omitempty"`

	// Phase 13: cosmetic latency knobs. Client-only in practice; carried
	// on the shared spec so the Rust deserialiser doesn't need a role-
	// aware variant. All four default to "off" / "PRD default" semantics.
	PingSmoothingEnabled  bool   `json:"ping_smoothing_enabled,omitempty"`
	PingSmoothingTargetMS uint32 `json:"ping_smoothing_target_ms,omitempty"`
	PacingEnabled         bool   `json:"pacing_enabled,omitempty"`
	PacingTargetMS        uint32 `json:"pacing_target_ms,omitempty"`

	// ForwardProtocol (v4.0.0) — "udp" (default) or "tcp". Shared by both
	// roles. Omitted (empty) means "udp": the dataplane takes the
	// byte-for-byte-identical legacy path. "tcp" activates the KCP
	// forwarding engine and KcpTuning carries the resolved knobs.
	ForwardProtocol string `json:"forward_protocol,omitempty"`
	// KeepAlive + KeepAliveIntervalSec (v4.0.0). When KeepAlive is true the
	// dataplane maintains one artificial internal session so the tunnel
	// never goes idle. The interval is how often the heartbeat fires
	// (seconds). Both default to off / 20 s on the Rust side.
	KeepAlive            bool   `json:"keep_alive,omitempty"`
	KeepAliveIntervalSec uint32 `json:"keep_alive_interval_sec,omitempty"`
	// KcpTuning carries the fully-resolved KCP knobs; set only when
	// ForwardProtocol is "tcp". nil for udp tunnels.
	KcpTuning *KcpTuning `json:"kcp_tuning,omitempty"`
}

// KcpTuning carries the resolved KCP knobs for a tcp-forwarding tunnel.
// The Go side resolves them from the preset + per-knob overrides before
// they reach the wire; the dataplane applies them verbatim. Mirrors the
// Rust `KcpTuning` struct in data-plane/src/spec.rs.
type KcpTuning struct {
	NoDelay  uint32 `json:"nodelay"`
	Interval uint32 `json:"interval"`
	Resend   uint32 `json:"resend"`
	NC       uint32 `json:"nc"`
	SndWnd   uint32 `json:"snd_wnd"`
	RcvWnd   uint32 `json:"rcv_wnd"`
	// MTU caps the KCP segment size; 0 tells the dataplane to derive it
	// from the tunnel MTU (clamped to ≤1280).
	MTU uint32 `json:"mtu,omitempty"`
}

// Socks5Target carries everything the Rust dataplane needs to open
// SOCKS5 TCP connections for a Client tunnel whose UploadMode is
// 'socks5' (Phase R9a). ParallelConnections is honoured by R9b; R9a
// hardcodes pool size = 1 and emits a startup info line so the
// operator knows N>1 has been deferred.
type Socks5Target struct {
	Host                string `json:"host"`
	Port                uint16 `json:"port"`
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	ParallelConnections uint32 `json:"parallel_connections"`
	// MinReadySlots is the Sublyne hardening pass's warm-up gate. The
	// dataplane delays reporting the tunnel as Up until at least this
	// many SOCKS5 slots complete their handshakes, so the first packets
	// never hit a still-broken slot. Field is omitted on the wire when
	// zero; the Rust deserialiser defaults to a sane value (2).
	MinReadySlots uint32 `json:"min_ready_slots,omitempty"`
}

// StopTunnelPayload is the body of a StopTunnel command.
type StopTunnelPayload struct {
	ID int64 `json:"id"`
}

// SetLogLevelPayload is the body of a SetLogLevel command.
type SetLogLevelPayload struct {
	Level string `json:"level"`
}

// ListTunnelsEntry is one row in the ListTunnels reply.
type ListTunnelsEntry struct {
	ID     int64       `json:"id"`
	Name   string      `json:"name"`
	Role   string      `json:"role"`
	State  TunnelState `json:"state"`
	Reason *string     `json:"reason,omitempty"`
}

// ListTunnelsReply is the value carried by a Reply to ListTunnels.
type ListTunnelsReply struct {
	Tunnels []ListTunnelsEntry `json:"tunnels"`
}

// ReadyPayload is the first event the dataplane emits on connect.
type ReadyPayload struct {
	Version string `json:"version"`
}

// TransportPackets mirrors the per-spoof-transport counters the Rust
// dataplane emits inside every PerTunnelStats sample. Only the field
// corresponding to the tunnel's configured `download_transport` is ever
// non-zero in a single sample; the others stay at 0 so the panel can
// render "this tunnel has run on transport X for the last N minutes"
// without us having to reset on hot-reload.
type TransportPackets struct {
	UDP    uint64 `json:"udp"`
	TCPSYN uint64 `json:"tcp_syn"`
	ICMP   uint64 `json:"icmp"`
	ICMPv6 uint64 `json:"icmpv6"`
}

// PerTunnelStats is one row inside the StatsReport event. Mirrors the
// JSON schema in .claude/skills/rust-go-ipc/SKILL.md §"Stats payload
// schema".
type PerTunnelStats struct {
	TunnelID                 int64            `json:"tunnel_id"`
	Role                     string           `json:"role"`
	Transport                string           `json:"transport"`
	BytesIn                  uint64           `json:"bytes_in"`
	BytesOut                 uint64           `json:"bytes_out"`
	PacketsIn                uint64           `json:"packets_in"`
	PacketsOut               uint64           `json:"packets_out"`
	ActiveSessions           uint32           `json:"active_sessions"`
	LastPacketReceivedAtUnix uint64           `json:"last_packet_received_at_unix"`
	LastPacketSentAtUnix     uint64           `json:"last_packet_sent_at_unix"`
	UploadRTTMsEWMA          float64          `json:"upload_rtt_ms_ewma"`
	DownloadRTTMsEWMA        float64          `json:"download_rtt_ms_ewma"`
	PacketLossEstimate       float64          `json:"packet_loss_estimate"`
	AuthDrops                uint64           `json:"auth_drops"`
	SessionRejects           uint64           `json:"session_rejects"`
	TransportPackets         TransportPackets `json:"transport_packets"`
}

// NetInterfaceStats mirrors the per-interface section of the system
// stats block.
type NetInterfaceStats struct {
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	RxBytesTotal  uint64 `json:"rx_bytes_total"`
	TxBytesTotal  uint64 `json:"tx_bytes_total"`
}

// SystemStats is the system-wide block inside every StatsReport.
type SystemStats struct {
	CPUPercent     float64                      `json:"cpu_percent"`
	MemUsedBytes   uint64                       `json:"mem_used_bytes"`
	MemTotalBytes  uint64                       `json:"mem_total_bytes"`
	DiskUsedBytes  uint64                       `json:"disk_used_bytes"`
	DiskTotalBytes uint64                       `json:"disk_total_bytes"`
	NetInterfaces  map[string]NetInterfaceStats `json:"net_interfaces"`
	LoadAvg1Min    float64                      `json:"load_avg_1min"`
	// ProcRSSBytes is the resident set of the dataplane process
	// itself (Phase 15, PRD §7). Distinct from MemUsedBytes which is
	// the host-wide figure. Older dataplane binaries don't emit this
	// field; the decoder leaves it as zero.
	ProcRSSBytes uint64 `json:"proc_rss_bytes,omitempty"`
	// MemoryPressure is true when the dataplane is refusing new
	// sessions because its RSS exceeded ~70% of system RAM. PRD §7:
	// the process never self-kills; existing sessions continue to
	// flow. The panel renders a banner.
	MemoryPressure bool `json:"memory_pressure,omitempty"`
}

// StatsReport is the full event body the dataplane pushes every 5 s.
// Phase 11's metrics ring buffer subscribes to this stream; the panel
// WebSocket fanout re-emits the same shape (plus a wall-clock
// timestamp the Go layer stamps on receive).
type StatsReport struct {
	Samples []PerTunnelStats `json:"samples"`
	System  SystemStats      `json:"system"`
}
