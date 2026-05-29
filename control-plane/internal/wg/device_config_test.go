package wg

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// realConfig returns the parsed shape of a representative WireGuard
// config built from throwaway test keys. Used by every test below so
// any one of them failing pinpoints the exact field that drifted.
func realConfig(t *testing.T) *ParsedConfig {
	t.Helper()
	priv, err := wgtypes.ParseKey("Hb6vPeiw+1PCmYfvxN6V1S7qcTWqRTPy7G5eb7slmcY=")
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	pub, err := wgtypes.ParseKey("kBAoTH86bXlmi+r72ZtpAzLWUY7YtfAPoOIgAurVpxQ=")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	psk, err := wgtypes.ParseKey("Iwqc+P0tiwZtA6VLb52x8Wp+H3iLSxSyC45Ch/CyM9A=")
	if err != nil {
		t.Fatalf("preshared key: %v", err)
	}
	ep := netip.MustParseAddrPort("198.51.100.10:82")
	return &ParsedConfig{
		Interface: InterfaceSection{
			PrivateKey: priv,
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.200.2.15/32")},
			MTU:        1380,
		},
		Peers: []PeerSection{
			{
				PublicKey:           pub,
				PresharedKey:        &psk,
				AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
				Endpoint:            &ep,
				PersistentKeepalive: 25 * time.Second,
			},
		},
	}
}

// TestBuildDeviceConfig_FirewallMarkIsNeverSet is the regression
// guard for the bug that broke the Iran client install. Setting
// FirewallMark on the device tells the kernel to mark WG's own
// outbound underlay packets (handshake initiations, keepalives, the
// encrypted tunnel UDP). Our `ip rule fwmark X table NNNN` then
// re-routes those marked packets back into the same WG interface,
// the handshake never reaches the wire, and the panel sits at "no
// handshake yet" forever even though the underlay is reachable.
//
// If a future refactor sets FirewallMark again — including via
// wgctrl's wg-quick-style helper — this test must fail loudly so
// the regression can't ship.
func TestBuildDeviceConfig_FirewallMarkIsNeverSet(t *testing.T) {
	cfg := BuildDeviceConfig(realConfig(t))
	if cfg.FirewallMark != nil {
		t.Fatalf("FirewallMark must be nil on the WG device (was %d)", *cfg.FirewallMark)
	}
}

// TestBuildDeviceConfig_PeerFidelity asserts that every field the
// kernel needs to complete a handshake is round-tripped from the
// pasted config into wgtypes.Config. The original investigation
// ruled out a missing-PSK or missing-Endpoint cause; this test makes
// sure that conclusion stays true under future edits.
func TestBuildDeviceConfig_PeerFidelity(t *testing.T) {
	src := realConfig(t)
	got := BuildDeviceConfig(src)

	if got.PrivateKey == nil {
		t.Fatal("PrivateKey must be set")
	}
	if *got.PrivateKey != src.Interface.PrivateKey {
		t.Error("PrivateKey was not copied through")
	}
	if !got.ReplacePeers {
		t.Error("ReplacePeers must be true so re-Up converges to the operator's pasted config")
	}
	if len(got.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(got.Peers))
	}
	p := got.Peers[0]
	if p.PublicKey != src.Peers[0].PublicKey {
		t.Error("Peer.PublicKey did not match")
	}
	if p.PresharedKey == nil || *p.PresharedKey != *src.Peers[0].PresharedKey {
		t.Error("Peer.PresharedKey missing or wrong — a wrong/missing PSK is a classic 'no handshake' cause")
	}
	if !p.ReplaceAllowedIPs {
		t.Error("Peer.ReplaceAllowedIPs must be true; otherwise a re-Up keeps stale AllowedIPs")
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("Peer.AllowedIPs len = %d, want 2 (0.0.0.0/0 + ::/0)", len(p.AllowedIPs))
	}
	if p.Endpoint == nil {
		t.Fatal("Peer.Endpoint must be set so the kernel knows where to send handshake initiations")
	}
	if p.Endpoint.IP.String() != "198.51.100.10" || p.Endpoint.Port != 82 {
		t.Errorf("Peer.Endpoint = %v, want 198.51.100.10:82", p.Endpoint)
	}
	if p.PersistentKeepaliveInterval == nil || *p.PersistentKeepaliveInterval != 25*time.Second {
		t.Errorf("Peer.PersistentKeepaliveInterval = %v, want 25s", p.PersistentKeepaliveInterval)
	}
}

// TestBuildDeviceConfig_ListenPortUnsetByDefault asserts that an
// absent ListenPort in the pasted config does not become an
// explicit port=0 on the wire. ConfigureDevice would refuse port=0.
func TestBuildDeviceConfig_ListenPortUnsetByDefault(t *testing.T) {
	src := realConfig(t)
	src.Interface.ListenPort = 0
	got := BuildDeviceConfig(src)
	if got.ListenPort != nil {
		t.Errorf("ListenPort must be nil when the pasted config omits it, got %d", *got.ListenPort)
	}
}

// TestBuildDeviceConfig_ListenPortRoundTripped covers the rare case
// where the operator pinned a port in the pasted config.
func TestBuildDeviceConfig_ListenPortRoundTripped(t *testing.T) {
	src := realConfig(t)
	src.Interface.ListenPort = 51820
	got := BuildDeviceConfig(src)
	if got.ListenPort == nil || *got.ListenPort != 51820 {
		t.Errorf("ListenPort = %v, want 51820", got.ListenPort)
	}
}

// TestPrefixesToIPNets_DualStack confirms a v4+v6 AllowedIPs pair
// becomes two distinct net.IPNets with the right masks. A bug here
// would silently drop one of the routes, which would make some
// traffic loop-fall-through to the wrong path.
func TestPrefixesToIPNets_DualStack(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	nets := PrefixesToIPNets(prefixes)
	if len(nets) != 2 {
		t.Fatalf("len = %d, want 2", len(nets))
	}
	if ones, _ := nets[0].Mask.Size(); ones != 0 {
		t.Errorf("v4 mask = /%d, want /0", ones)
	}
	if len(nets[0].IP) != 4 {
		t.Errorf("v4 IP byte len = %d, want 4", len(nets[0].IP))
	}
	if ones, _ := nets[1].Mask.Size(); ones != 0 {
		t.Errorf("v6 mask = /%d, want /0", ones)
	}
	if len(nets[1].IP) != 16 {
		t.Errorf("v6 IP byte len = %d, want 16", len(nets[1].IP))
	}
}
