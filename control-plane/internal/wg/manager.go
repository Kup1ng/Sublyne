package wg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrManagerUnsupported is returned by the stub Manager on every
// non-Linux build. The control plane still compiles and the API tree
// still mounts; only the actual bring-up call fails. This lets the
// developer working on Windows run gofmt / go vet / unit tests
// against the rest of the codebase without needing a Linux box.
var ErrManagerUnsupported = errors.New("wg: kernel WireGuard bring-up is only supported on Linux")

// BringUpResult is what the manager hands back after a successful
// Up() call. The control plane stores nothing from it — the same
// information can be recomputed from the tunnel id at any time — but
// the API surface returns it so the operator can see exactly what
// landed on the host.
type BringUpResult struct {
	InterfaceName string // e.g. "sub-wg-0000002a"
	Fwmark        uint32 // e.g. 0x102a
	Table         uint32 // route-table number, equal to Fwmark
}

// HandshakeStatus mirrors the parts of wgtypes.Device the dashboard
// cares about. The data plane never sees this — Phase 11 will poll
// wgctrl directly from Go and push the result to the panel over the
// WebSocket. Phase 7 only needs a one-shot "what's the current
// handshake age?" call so the API can render a status badge.
type HandshakeStatus struct {
	InterfaceName    string
	LastHandshake    time.Time // zero if never connected
	HasEverConnected bool
}

// Stale reports whether the last handshake is older than the PRD's
// 3-minute threshold. A zero timestamp counts as stale.
func (h HandshakeStatus) Stale() bool {
	if h.LastHandshake.IsZero() {
		return true
	}
	return time.Since(h.LastHandshake) > 3*time.Minute
}

// Manager is the lifecycle interface for per-tunnel WireGuard
// interfaces. The control plane holds exactly one Manager, configured
// at startup; Linux builds get the netlink-backed implementation,
// other OSes get a stub that returns ErrManagerUnsupported.
//
// Methods take the tunnel id rather than the full Tunnel struct so
// the data flow stays decoupled from the tunnels package — the API
// layer is the only place that knows about both.
type Manager interface {
	// Up brings up the kernel device for the supplied tunnel id and
	// pasted config. It is idempotent: calling Up twice in a row
	// with the same arguments updates the existing device rather
	// than failing.
	Up(ctx context.Context, tunnelID int64, cfg *ParsedConfig) (BringUpResult, error)

	// Down removes the kernel device, the per-tunnel ip rule, and
	// the per-tunnel route table. Safe to call on a tunnel that
	// was never brought up.
	Down(ctx context.Context, tunnelID int64) error

	// Handshake returns the most recent handshake state for the
	// tunnel. ErrManagerUnsupported on non-Linux builds.
	Handshake(ctx context.Context, tunnelID int64) (HandshakeStatus, error)

	// TearDownAll removes every sub-wg-* interface and every
	// fwmark-based ip rule / route table the project owns. Used by
	// `sublyne --tear-down` on uninstall and by the integration
	// tests so a previous run doesn't leak state into the next.
	TearDownAll(ctx context.Context) error

	// Supported reports whether this Manager can actually bring up
	// kernel WG interfaces. False on the stub.
	Supported() bool
}

// BuildDeviceConfig translates a ParsedConfig into the wgctrl-go
// shape that ConfigureDevice consumes. It is platform-portable
// (wgctrl/wgtypes is pure Go data types; the netlink call lives in
// manager_linux.go's configureDevice) so the surrounding tests can
// pin its behaviour on Windows too.
//
// **Why FirewallMark is intentionally NOT set on the device.**
//
// The first version of this code set FirewallMark to the per-tunnel
// fwmark so wg-quick's "all traffic through WG" pattern would work.
// We don't use that pattern: the dataplane explicitly sets SO_MARK on
// its upload UDP socket, and our `ip rule fwmark X table NNNN` directs
// only THAT marked traffic into the tunnel.
//
// Setting FirewallMark on the device also makes the kernel mark every
// outbound underlay packet — including the WG handshake initiation
// destined for the configured Endpoint — with the same fwmark. The
// handshake packet then matches our own ip rule, gets re-routed back
// into the WG interface, loops, and never reaches the wire. The
// interface comes up, the endpoint is pingable, but no handshake
// completes. That was the production failure on the Iran client.
//
// Leaving FirewallMark unset on the device means WG's handshake and
// re-key packets use the normal main routing table, which is exactly
// what we want.
func BuildDeviceConfig(cfg *ParsedConfig) wgtypes.Config {
	peers := make([]wgtypes.PeerConfig, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		pc := wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  PrefixesToIPNets(p.AllowedIPs),
			PresharedKey:                p.PresharedKey,
			PersistentKeepaliveInterval: durationPtr(p.PersistentKeepalive),
		}
		if p.Endpoint != nil {
			pc.Endpoint = &net.UDPAddr{
				IP:   net.IP(p.Endpoint.Addr().AsSlice()),
				Port: int(p.Endpoint.Port()),
			}
		}
		peers = append(peers, pc)
	}
	priv := cfg.Interface.PrivateKey
	out := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        peers,
		// FirewallMark deliberately omitted — see doc comment above.
	}
	if cfg.Interface.ListenPort > 0 {
		port := cfg.Interface.ListenPort
		out.ListenPort = &port
	}
	return out
}

// PrefixesToIPNets is exported for the test in this package and the
// netlink implementation in manager_linux.go.
func PrefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, 0, len(prefixes))
	for _, p := range prefixes {
		ip := net.IP(p.Addr().AsSlice())
		mask := net.CIDRMask(p.Bits(), len(ip)*8)
		out = append(out, net.IPNet{IP: ip, Mask: mask})
	}
	return out
}

// durationPtr returns nil for a zero Duration so wgctrl interprets it
// as "do not set" rather than "set to zero".
func durationPtr(d time.Duration) *time.Duration {
	if d == 0 {
		return nil
	}
	return &d
}
