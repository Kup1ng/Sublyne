package tunnels

import (
	"encoding/json"
	"fmt"
)

// --- v4.0.0 TCP forwarding -------------------------------------------
//
// A tunnel forwards UDP datagrams by default (forward_protocol='udp',
// the historical and only pre-v4 behaviour). Setting forward_protocol
// to 'tcp' layers a reliable transport — KCP or QUIC — between the
// user's TCP socket and the existing best-effort seal/spoof datagram
// pipeline, so raw TCP (e.g. VLESS-TCP / VLESS-WS) survives the lossy
// download path. The reliability engine treats the asymmetric channel
// as an opaque "deliver-or-drop datagram" pipe; the seal/spoof layer
// never learns the datagrams now carry KCP/QUIC framing.
//
// forward_protocol is a SHARED field: both the Client (which terminates
// the user's TCP) and the Remote (which re-originates TCP to
// forward_target) must agree on the protocol and engine. There is no
// inter-server control plane (PRD §2.3) so the operator copies the same
// choice to both boxes, exactly as for the PSK and download_transport.
//
// The concrete engine tuning numbers below are the SINGLE SOURCE OF
// TRUTH; the panel mirrors them in TypeScript for the preset cards and
// the Advanced override form, the same way it mirrors the upload×download
// matrix helpers above. dataplane/manager.go resolves preset + override
// into the concrete IPC tuning the Rust dataplane consumes.

// ForwardProtocol selects how a tunnel forwards application traffic.
type ForwardProtocol string

// ForwardProtocol values mirror the 0012 migration's CHECK constraint.
const (
	ForwardProtocolUDP ForwardProtocol = "udp"
	ForwardProtocolTCP ForwardProtocol = "tcp"
)

// IsValid reports whether p is one of the two supported protocols.
func (p ForwardProtocol) IsValid() bool {
	return p == ForwardProtocolUDP || p == ForwardProtocolTCP
}

// TCPEngine selects the reliable transport used when forward_protocol
// is 'tcp'. KCP is the default (simpler, predictable, best on
// lossy/ICMP paths); QUIC adds native stream multiplexing and built-in
// encryption at the cost of a heavier handshake.
type TCPEngine string

// TCPEngine values mirror the 0012 migration's CHECK constraint.
const (
	TCPEngineKCP  TCPEngine = "kcp"
	TCPEngineQUIC TCPEngine = "quic"
)

// IsValid reports whether e is one of the two supported engines.
func (e TCPEngine) IsValid() bool {
	return e == TCPEngineKCP || e == TCPEngineQUIC
}

// ForwardEnginePreset names one of the three tuning profiles offered per
// engine. The operator picks a preset and may then override individual
// fields via the Advanced section (stored as the forward_engine_tuning
// JSON blob).
type ForwardEnginePreset string

// ForwardEnginePreset values mirror the 0012 migration's CHECK constraint.
const (
	PresetInteractive ForwardEnginePreset = "interactive"
	PresetBalanced    ForwardEnginePreset = "balanced"
	PresetLossy       ForwardEnginePreset = "lossy"
)

// IsValid reports whether p is one of the three supported presets.
func (p ForwardEnginePreset) IsValid() bool {
	return p == PresetInteractive || p == PresetBalanced || p == PresetLossy
}

// KcpTuning is the concrete KCP parameter set sent to the dataplane.
// nodelay/interval/resend/nc map 1:1 onto ikcp_nodelay(); snd_wnd /
// rcv_wnd are the send/receive windows in packets. The MTU is derived
// from the tunnel MTU in the dataplane, not carried here.
type KcpTuning struct {
	NoDelay  uint32 `json:"nodelay"`
	Interval uint32 `json:"interval"`
	Resend   uint32 `json:"resend"`
	NC       uint32 `json:"nc"`
	SndWnd   uint32 `json:"snd_wnd"`
	RcvWnd   uint32 `json:"rcv_wnd"`
}

// QuicTuning is the concrete QUIC parameter set sent to the dataplane.
// Congestion is one of "cubic" | "newreno" | "bbr"; the windows are in
// bytes; the timings are in milliseconds.
type QuicTuning struct {
	Congestion       string `json:"congestion"`
	InitialRTTMs     uint32 `json:"initial_rtt_ms"`
	MaxIdleMs        uint32 `json:"max_idle_ms"`
	KeepAliveMs      uint32 `json:"keep_alive_ms"`
	StreamRecvWindow uint64 `json:"stream_recv_window"`
	ConnRecvWindow   uint64 `json:"conn_recv_window"`
}

const mib = 1024 * 1024

// QuicMinMTU is the smallest tunnel MTU that can carry QUIC forwarding.
// QUIC requires >=1200-byte datagrams (its Initial pads to 1200); the
// dataplane sizes the engine MTU to tunnel_mtu - 2 (the multiport tag), so
// the tunnel MTU must clear 1200 + the tag + a small margin. KCP has no
// such floor. Mirrors data-plane/src/spec.rs QUIC_MIN_TUNNEL_MTU.
const QuicMinMTU = 1252

// kcpPresets holds the three KCP profiles. See the v4.0.0 plan §3.
var kcpPresets = map[ForwardEnginePreset]KcpTuning{
	// Tight loop, aggressive ACK, small windows — snappy for VLESS-WS,
	// SSH, gaming. nc=1 disables KCP's congestion backoff.
	PresetInteractive: {NoDelay: 1, Interval: 10, Resend: 2, NC: 1, SndWnd: 256, RcvWnd: 256},
	// Larger windows for BDP, congestion control on (nc=0) for smoother
	// sharing — the default for VLESS-TCP, web, bulk downloads.
	PresetBalanced: {NoDelay: 1, Interval: 20, Resend: 2, NC: 0, SndWnd: 1024, RcvWnd: 1024},
	// Fast retransmit at one duplicate ACK, congestion off, moderate
	// windows to bound bufferbloat — for high packet-loss paths.
	PresetLossy: {NoDelay: 1, Interval: 10, Resend: 1, NC: 1, SndWnd: 512, RcvWnd: 512},
}

// quicPresets holds the three QUIC profiles. See the v4.0.0 plan §4.
var quicPresets = map[ForwardEnginePreset]QuicTuning{
	PresetInteractive: {Congestion: "newreno", InitialRTTMs: 150, MaxIdleMs: 30_000, KeepAliveMs: 10_000, StreamRecvWindow: 2 * mib, ConnRecvWindow: 8 * mib},
	PresetBalanced:    {Congestion: "cubic", InitialRTTMs: 200, MaxIdleMs: 60_000, KeepAliveMs: 20_000, StreamRecvWindow: 8 * mib, ConnRecvWindow: 32 * mib},
	PresetLossy:       {Congestion: "bbr", InitialRTTMs: 200, MaxIdleMs: 90_000, KeepAliveMs: 20_000, StreamRecvWindow: 8 * mib, ConnRecvWindow: 32 * mib},
}

// kcpOverride is the partial, all-pointers shape parsed from the
// forward_engine_tuning JSON blob so an absent key keeps the preset's
// value while a present key (even zero) overrides it.
type kcpOverride struct {
	NoDelay  *uint32 `json:"nodelay"`
	Interval *uint32 `json:"interval"`
	Resend   *uint32 `json:"resend"`
	NC       *uint32 `json:"nc"`
	SndWnd   *uint32 `json:"snd_wnd"`
	RcvWnd   *uint32 `json:"rcv_wnd"`
}

type quicOverride struct {
	Congestion       *string `json:"congestion"`
	InitialRTTMs     *uint32 `json:"initial_rtt_ms"`
	MaxIdleMs        *uint32 `json:"max_idle_ms"`
	KeepAliveMs      *uint32 `json:"keep_alive_ms"`
	StreamRecvWindow *uint64 `json:"stream_recv_window"`
	ConnRecvWindow   *uint64 `json:"conn_recv_window"`
}

// ResolveKcpTuning merges the override blob over the named preset and
// range-checks the result. An empty blob returns the pure preset.
func ResolveKcpTuning(preset ForwardEnginePreset, overrideJSON string) (KcpTuning, error) {
	base, ok := kcpPresets[preset]
	if !ok {
		base = kcpPresets[PresetBalanced]
	}
	if s := trimBlank(overrideJSON); s != "" {
		var o kcpOverride
		if err := json.Unmarshal([]byte(s), &o); err != nil {
			return KcpTuning{}, fmt.Errorf("KCP tuning overrides are not valid JSON: %w", err)
		}
		if o.NoDelay != nil {
			base.NoDelay = *o.NoDelay
		}
		if o.Interval != nil {
			base.Interval = *o.Interval
		}
		if o.Resend != nil {
			base.Resend = *o.Resend
		}
		if o.NC != nil {
			base.NC = *o.NC
		}
		if o.SndWnd != nil {
			base.SndWnd = *o.SndWnd
		}
		if o.RcvWnd != nil {
			base.RcvWnd = *o.RcvWnd
		}
	}
	if err := validateKcpTuning(base); err != nil {
		return KcpTuning{}, err
	}
	return base, nil
}

// ResolveQuicTuning merges the override blob over the named preset and
// range-checks the result. An empty blob returns the pure preset.
func ResolveQuicTuning(preset ForwardEnginePreset, overrideJSON string) (QuicTuning, error) {
	base, ok := quicPresets[preset]
	if !ok {
		base = quicPresets[PresetBalanced]
	}
	if s := trimBlank(overrideJSON); s != "" {
		var o quicOverride
		if err := json.Unmarshal([]byte(s), &o); err != nil {
			return QuicTuning{}, fmt.Errorf("QUIC tuning overrides are not valid JSON: %w", err)
		}
		if o.Congestion != nil {
			base.Congestion = *o.Congestion
		}
		if o.InitialRTTMs != nil {
			base.InitialRTTMs = *o.InitialRTTMs
		}
		if o.MaxIdleMs != nil {
			base.MaxIdleMs = *o.MaxIdleMs
		}
		if o.KeepAliveMs != nil {
			base.KeepAliveMs = *o.KeepAliveMs
		}
		if o.StreamRecvWindow != nil {
			base.StreamRecvWindow = *o.StreamRecvWindow
		}
		if o.ConnRecvWindow != nil {
			base.ConnRecvWindow = *o.ConnRecvWindow
		}
	}
	if err := validateQuicTuning(base); err != nil {
		return QuicTuning{}, err
	}
	return base, nil
}

func validateKcpTuning(t KcpTuning) error {
	if t.NoDelay > 1 {
		return fmt.Errorf("KCP nodelay must be 0 or 1, got %d", t.NoDelay)
	}
	if t.Interval < 10 || t.Interval > 1000 {
		return fmt.Errorf("KCP interval must be between 10 and 1000 ms, got %d", t.Interval)
	}
	if t.Resend > 10 {
		return fmt.Errorf("KCP resend must be between 0 and 10, got %d", t.Resend)
	}
	if t.NC > 1 {
		return fmt.Errorf("KCP nc must be 0 or 1, got %d", t.NC)
	}
	if t.SndWnd < 16 || t.SndWnd > 8192 {
		return fmt.Errorf("KCP snd_wnd must be between 16 and 8192 packets, got %d", t.SndWnd)
	}
	if t.RcvWnd < 16 || t.RcvWnd > 8192 {
		return fmt.Errorf("KCP rcv_wnd must be between 16 and 8192 packets, got %d", t.RcvWnd)
	}
	return nil
}

func validateQuicTuning(t QuicTuning) error {
	switch t.Congestion {
	case "cubic", "newreno", "bbr":
	default:
		return fmt.Errorf("QUIC congestion must be cubic, newreno, or bbr, got %q", t.Congestion)
	}
	if t.InitialRTTMs < 10 || t.InitialRTTMs > 10_000 {
		return fmt.Errorf("QUIC initial_rtt_ms must be between 10 and 10000, got %d", t.InitialRTTMs)
	}
	if t.MaxIdleMs < 1_000 || t.MaxIdleMs > 600_000 {
		return fmt.Errorf("QUIC max_idle_ms must be between 1000 and 600000, got %d", t.MaxIdleMs)
	}
	if t.KeepAliveMs > 300_000 {
		return fmt.Errorf("QUIC keep_alive_ms must be at most 300000, got %d", t.KeepAliveMs)
	}
	if t.StreamRecvWindow < 64*1024 || t.StreamRecvWindow > 256*mib {
		return fmt.Errorf("QUIC stream_recv_window must be between 64 KiB and 256 MiB, got %d", t.StreamRecvWindow)
	}
	if t.ConnRecvWindow < 64*1024 || t.ConnRecvWindow > 1024*mib {
		return fmt.Errorf("QUIC conn_recv_window must be between 64 KiB and 1 GiB, got %d", t.ConnRecvWindow)
	}
	if t.ConnRecvWindow < t.StreamRecvWindow {
		return fmt.Errorf("QUIC conn_recv_window (%d) must be >= stream_recv_window (%d)", t.ConnRecvWindow, t.StreamRecvWindow)
	}
	return nil
}

// trimBlank trims ASCII whitespace; a tiny helper kept local so this
// file doesn't pull in strings just for TrimSpace at call sites that
// already import it elsewhere.
func trimBlank(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
