package wg

import (
	"errors"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// genTestKey returns a deterministically-derived base64 key string by
// generating a fresh curve25519 private key. We don't reuse the same
// hard-coded bytes across tests because doing so would mean two tests
// could clobber each other's [Interface] PrivateKey if we ever wired
// them to a real device.
func genTestKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return k
}

// prdExampleConfig mirrors the wg-quick paste in
// .claude/skills/wireguard-config-handling/SKILL.md "What a user
// pastes". Keys are generated at runtime so the test does not depend
// on any baked-in private bytes that would be a maintenance footgun.
func prdExampleConfig(t *testing.T) string {
	priv := genTestKey(t).String()
	peerPub := genTestKey(t).PublicKey().String()
	psk := genTestKey(t).String()
	return strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.66.66.2/32, fd00:42::2/128",
		"DNS = 1.1.1.1, 1.0.0.1",
		"MTU = 1280",
		"ListenPort = 51820",
		"",
		"[Peer]",
		"PublicKey = " + peerPub,
		"PresharedKey = " + psk,
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = 198.51.100.20:81",
		"PersistentKeepalive = 25",
	}, "\n")
}

func TestParseConfig_PRDExample(t *testing.T) {
	cfg, err := ParseConfig(prdExampleConfig(t))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Interface.MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", cfg.Interface.MTU)
	}
	if cfg.Interface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", cfg.Interface.ListenPort)
	}
	if len(cfg.Interface.Addresses) != 2 {
		t.Errorf("Addresses len = %d, want 2", len(cfg.Interface.Addresses))
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.Endpoint == nil || p.Endpoint.String() != "198.51.100.20:81" {
		t.Errorf("Endpoint = %v, want 198.51.100.20:81", p.Endpoint)
	}
	if p.PresharedKey == nil {
		t.Errorf("PresharedKey should be set")
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs len = %d, want 2", len(p.AllowedIPs))
	}
	if p.PersistentKeepalive.Seconds() != 25 {
		t.Errorf("PersistentKeepalive = %v, want 25s", p.PersistentKeepalive)
	}

	// FirstEndpoint / AddressesAsString / PublicKeySelf are convenience
	// helpers used by the panel summary.
	if cfg.FirstEndpoint() != "198.51.100.20:81" {
		t.Errorf("FirstEndpoint = %q", cfg.FirstEndpoint())
	}
	if !strings.Contains(cfg.AddressesAsString(), "10.66.66.2/32") {
		t.Errorf("AddressesAsString missing v4: %q", cfg.AddressesAsString())
	}
	if cfg.PublicKeySelf() == "" {
		t.Error("PublicKeySelf should not be empty")
	}

	// DNS must be parsed-but-ignored per PRD §8.4 — surfaced as a
	// warning so the operator can see the project saw it.
	gotDNSWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(strings.ToLower(w), "dns") {
			gotDNSWarn = true
			break
		}
	}
	if !gotDNSWarn {
		t.Errorf("expected a DNS warning, got %v", cfg.Warnings)
	}
}

func TestParseConfig_HandlesCRLF(t *testing.T) {
	text := strings.ReplaceAll(prdExampleConfig(t), "\n", "\r\n")
	if _, err := ParseConfig(text); err != nil {
		t.Fatalf("ParseConfig CRLF: %v", err)
	}
}

func TestParseConfig_StripsComments(t *testing.T) {
	cfg := prdExampleConfig(t) + "\n# trailing comment\n"
	parsed, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(parsed.Peers) != 1 {
		t.Errorf("comments should not introduce ghost peers: %+v", parsed.Peers)
	}
}

func TestParseConfig_MultiplePeers(t *testing.T) {
	priv := genTestKey(t).String()
	a := genTestKey(t).PublicKey().String()
	b := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = " + a,
		"AllowedIPs = 10.0.0.0/24",
		"Endpoint = 198.51.100.10:51820",
		"",
		"[Peer]",
		"PublicKey = " + b,
		"AllowedIPs = 10.0.1.0/24",
		"Endpoint = 198.51.100.11:51820",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("Peers len = %d, want 2", len(cfg.Peers))
	}
	if cfg.Peers[0].Endpoint.String() != "198.51.100.10:51820" {
		t.Errorf("peer[0] endpoint = %v", cfg.Peers[0].Endpoint)
	}
}

func TestParseConfig_DNSIgnored(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"DNS = 9.9.9.9",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// We don't store DNS anywhere on ParsedConfig — that's the whole
	// point of PRD §8.4's "DNS lines are ignored" rule. The presence
	// of the warning is the only observable signal.
	dns := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "DNS") {
			dns = true
		}
	}
	if !dns {
		t.Errorf("expected a DNS warning, got %v", cfg.Warnings)
	}
}

func TestParseConfig_RejectsMissingInterface(t *testing.T) {
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	_, err := ParseConfig(body)
	if err == nil {
		t.Fatal("expected error for missing [Interface]")
	}
	if !strings.Contains(err.Error(), "[Interface]") {
		t.Errorf("error should mention [Interface], got %v", err)
	}
}

func TestParseConfig_RejectsMissingPrivateKey(t *testing.T) {
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	_, err := ParseConfig(body)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Field != "PrivateKey" {
		t.Fatalf("err = %v, want ParseError with Field=PrivateKey", err)
	}
}

func TestParseConfig_RejectsMissingAddress(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	_, err := ParseConfig(body)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Field != "Address" {
		t.Fatalf("err = %v, want ParseError with Field=Address", err)
	}
}

func TestParseConfig_RejectsMissingPeer(t *testing.T) {
	priv := genTestKey(t).String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
	}, "\n")
	_, err := ParseConfig(body)
	if err == nil {
		t.Fatal("expected error for missing [Peer]")
	}
	if !strings.Contains(err.Error(), "[Peer]") {
		t.Errorf("error should mention [Peer], got %v", err)
	}
}

func TestParseConfig_RejectsBadKey(t *testing.T) {
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = totally-not-base64",
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = " + genTestKey(t).PublicKey().String(),
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	_, err := ParseConfig(body)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Field != "PrivateKey" {
		t.Fatalf("err = %v, want ParseError with Field=PrivateKey", err)
	}
}

func TestParseConfig_RejectsHostnameEndpoint(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = vpn.example.com:51820",
	}, "\n")
	_, err := ParseConfig(body)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Field != "Endpoint" {
		t.Fatalf("err = %v, want ParseError with Field=Endpoint", err)
	}
}

func TestParseConfig_RejectsBadMTU(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"MTU = 99999",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	_, err := ParseConfig(body)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Field != "MTU" {
		t.Fatalf("err = %v, want ParseError with Field=MTU", err)
	}
}

func TestParseConfig_RejectsMalformedLine(t *testing.T) {
	priv := genTestKey(t).String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address 10.0.0.2/32", // missing '='
	}, "\n")
	_, err := ParseConfig(body)
	if err == nil {
		t.Fatal("expected error for malformed key=value line")
	}
}

func TestParseConfig_AllowedIPsIPv6(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = fd00::2/128",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = ::/0",
		"Endpoint = [2001:db8::1]:51820",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig v6: %v", err)
	}
	if cfg.Peers[0].Endpoint.String() != "[2001:db8::1]:51820" {
		t.Errorf("v6 endpoint = %v", cfg.Peers[0].Endpoint)
	}
}

func TestParseConfig_AllowedIPsBareIP(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 10.0.0.1", // bare IP, no /N
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig bare IP: %v", err)
	}
	got := cfg.Peers[0].AllowedIPs
	if len(got) != 1 || got[0].String() != "10.0.0.1/32" {
		t.Errorf("AllowedIPs = %v, want [10.0.0.1/32]", got)
	}
}

func TestParseConfig_UnknownKeyWarns(t *testing.T) {
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"WeirdField = whatever",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
		"AnotherWeird = nothing",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Warnings) < 2 {
		t.Errorf("expected at least 2 warnings for unknown keys, got %v", cfg.Warnings)
	}
}

func TestParseConfig_PostUpWarnsButDoesNotError(t *testing.T) {
	// wg-quick configs sometimes carry PostUp / PreUp scripts. We
	// ignore them entirely because the project drives its own
	// fwmark-based routing. The operator should still see we did so.
	priv := genTestKey(t).String()
	pub := genTestKey(t).PublicKey().String()
	body := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.0.0.2/32",
		"PostUp = iptables -A FORWARD -i %i -j ACCEPT",
		"",
		"[Peer]",
		"PublicKey = " + pub,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.10:51820",
	}, "\n")
	cfg, err := ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	postup := false
	for _, w := range cfg.Warnings {
		if strings.Contains(strings.ToLower(w), "postup") {
			postup = true
		}
	}
	if !postup {
		t.Errorf("expected a PostUp warning, got %v", cfg.Warnings)
	}
}
