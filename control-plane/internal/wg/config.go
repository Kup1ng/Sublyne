package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ParsedConfig is the structured form of a wg-quick text file. It
// holds exactly what the bring-up code needs to call wgctrl's
// ConfigureDevice and what the panel needs to render a summary.
//
// DNS directives are deliberately omitted — PRD §8.4 documents that
// uploads carry raw IP packets and need no in-tunnel resolution.
// Unknown keys generate a warning and are dropped.
type ParsedConfig struct {
	Interface InterfaceSection
	Peers     []PeerSection
	// Warnings carries non-fatal observations (unknown directives,
	// ignored DNS lines, multiple [Interface] sections collapsed).
	// The API surface bubbles these up so the operator can see what
	// the project did with the config they pasted.
	Warnings []string
}

// InterfaceSection captures the [Interface] block. PrivateKey is the
// only required field per wg-quick semantics; Address must also be
// present or the kernel device has no L3 identity.
type InterfaceSection struct {
	PrivateKey wgtypes.Key
	Addresses  []netip.Prefix // parsed from "Address ="
	MTU        int            // 0 = unset
	ListenPort int            // 0 = unset
}

// PeerSection captures a [Peer] block. WG supports multiple peers per
// device; the parser preserves the order they appear in the config.
type PeerSection struct {
	PublicKey           wgtypes.Key
	PresharedKey        *wgtypes.Key   // nil if absent
	AllowedIPs          []netip.Prefix // parsed from "AllowedIPs ="
	Endpoint            *netip.AddrPort
	PersistentKeepalive time.Duration // 0 = unset
}

// ParseError carries a per-field problem so the API layer can ship it
// straight back to the form. The message text is user-facing and
// surfaces in the panel exactly as written. Line is 1-indexed; 0 means
// "no specific line, applies to the whole config" (e.g. "missing
// [Interface] block").
type ParseError struct {
	Line   int
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Line > 0 && e.Field != "" {
		return fmt.Sprintf("line %d (%s): %s", e.Line, e.Field, e.Reason)
	}
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
	}
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Reason)
	}
	return e.Reason
}

// FirstEndpoint returns the first peer's Endpoint in "host:port" form,
// or "" if no peer has one. The panel's list view uses this as the
// summary value so operators can tell their configs apart.
func (c *ParsedConfig) FirstEndpoint() string {
	for _, p := range c.Peers {
		if p.Endpoint != nil {
			return p.Endpoint.String()
		}
	}
	return ""
}

// AddressesAsString joins the InterfaceSection addresses as a
// comma-separated list of CIDRs. Returns "" if no addresses were
// parsed (Parse rejects that case so this is best-effort defensive).
func (c *ParsedConfig) AddressesAsString() string {
	if len(c.Interface.Addresses) == 0 {
		return ""
	}
	parts := make([]string, 0, len(c.Interface.Addresses))
	for _, a := range c.Interface.Addresses {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// PublicKeySelf returns the public key derived from the [Interface]
// PrivateKey. The panel displays this so the operator can confirm
// they pasted the right config without ever surfacing the private
// half.
func (c *ParsedConfig) PublicKeySelf() string {
	return c.Interface.PrivateKey.PublicKey().String()
}

// ParseConfig parses a wg-quick-style text blob into ParsedConfig.
// It enforces the rules documented in
// .claude/skills/wireguard-config-handling/SKILL.md:
//
//   - At least one [Interface] block with exactly one PrivateKey and
//     at least one Address.
//   - At least one [Peer] block with a PublicKey and at least one
//     AllowedIPs.
//   - PrivateKey / PublicKey / PresharedKey base64-decode to 32 bytes.
//   - Endpoint is a literal IP:port (no DNS hostnames; we never
//     resolve at runtime).
//   - DNS directives are silently dropped (with a warning).
//   - Unknown keys generate a warning but are otherwise ignored.
//
// The returned error is always a *ParseError so callers can extract
// the field/line cleanly.
func ParseConfig(text string) (*ParsedConfig, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")

	cfg := &ParsedConfig{}
	currentSection := "" // "interface", "peer", or empty
	var currentPeer *PeerSection
	interfaceSeen := false
	var ifacePrivateKeySet bool

	for i, raw := range lines {
		lineNum := i + 1
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if interfaceSeen {
					cfg.Warnings = append(cfg.Warnings,
						fmt.Sprintf("line %d: multiple [Interface] sections — the later one is ignored", lineNum))
					currentSection = "ignore"
					continue
				}
				interfaceSeen = true
				currentSection = "interface"
			case "peer":
				if currentPeer != nil {
					cfg.Peers = append(cfg.Peers, *currentPeer)
				}
				currentPeer = &PeerSection{}
				currentSection = "peer"
			default:
				return nil, &ParseError{
					Line:   lineNum,
					Reason: fmt.Sprintf("unknown section %q (expected [Interface] or [Peer])", section),
				}
			}
			continue
		}

		key, value, ok := splitKV(line)
		if !ok {
			return nil, &ParseError{
				Line:   lineNum,
				Reason: "expected `Key = Value`",
			}
		}
		key = strings.ToLower(key)

		switch currentSection {
		case "":
			return nil, &ParseError{
				Line:   lineNum,
				Reason: "directive outside any [Interface] or [Peer] section",
			}
		case "ignore":
			// Inside a duplicate [Interface] — drop quietly with the
			// section-level warning already recorded.
			continue
		case "interface":
			if err := applyInterfaceField(&cfg.Interface, key, value, lineNum, cfg); err != nil {
				return nil, err
			}
			if key == "privatekey" {
				ifacePrivateKeySet = true
			}
		case "peer":
			if currentPeer == nil {
				return nil, &ParseError{Line: lineNum, Reason: "internal: peer section without state"}
			}
			if err := applyPeerField(currentPeer, key, value, lineNum, cfg); err != nil {
				return nil, err
			}
		}
	}

	if currentPeer != nil {
		cfg.Peers = append(cfg.Peers, *currentPeer)
	}

	if !interfaceSeen {
		return nil, &ParseError{Reason: "config must contain an [Interface] section"}
	}
	if !ifacePrivateKeySet {
		return nil, &ParseError{Field: "PrivateKey", Reason: "[Interface] section is missing PrivateKey"}
	}
	if len(cfg.Interface.Addresses) == 0 {
		return nil, &ParseError{Field: "Address", Reason: "[Interface] section must declare at least one Address"}
	}
	if len(cfg.Peers) == 0 {
		return nil, &ParseError{Reason: "config must contain at least one [Peer] section"}
	}
	for idx, p := range cfg.Peers {
		zero := wgtypes.Key{}
		if p.PublicKey == zero {
			return nil, &ParseError{
				Field:  "PublicKey",
				Reason: fmt.Sprintf("[Peer] #%d is missing PublicKey", idx+1),
			}
		}
		if len(p.AllowedIPs) == 0 {
			return nil, &ParseError{
				Field:  "AllowedIPs",
				Reason: fmt.Sprintf("[Peer] #%d must declare at least one AllowedIPs entry", idx+1),
			}
		}
	}

	return cfg, nil
}

func applyInterfaceField(s *InterfaceSection, key, value string, lineNum int, cfg *ParsedConfig) error {
	switch key {
	case "privatekey":
		k, err := parseKey(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "PrivateKey", Reason: err.Error()}
		}
		s.PrivateKey = k
	case "address":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "Address", Reason: err.Error()}
		}
		s.Addresses = append(s.Addresses, prefixes...)
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 || n > 9000 {
			return &ParseError{Line: lineNum, Field: "MTU", Reason: "MTU must be a positive integer ≤ 9000"}
		}
		s.MTU = n
	case "listenport":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 {
			return &ParseError{Line: lineNum, Field: "ListenPort", Reason: "ListenPort must be between 1 and 65535"}
		}
		s.ListenPort = n
	case "dns":
		// PRD §8.4: uploads carry raw IP packets, so DNS is not needed
		// inside the tunnel. We record the fact and move on.
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("line %d: DNS directive ignored (Phase 8 sends raw IP packets, no resolution)", lineNum))
	case "table", "preup", "postup", "predown", "postdown", "saveconfig":
		// wg-quick-only knobs; the project manages routing itself via
		// fwmark + per-tunnel route table (see SKILL.md "killswitch").
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("line %d: wg-quick directive %q is ignored — the project manages its own routing", lineNum, key))
	default:
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("line %d: unknown [Interface] key %q ignored", lineNum, key))
	}
	return nil
}

func applyPeerField(p *PeerSection, key, value string, lineNum int, cfg *ParsedConfig) error {
	switch key {
	case "publickey":
		k, err := parseKey(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "PublicKey", Reason: err.Error()}
		}
		p.PublicKey = k
	case "presharedkey":
		k, err := parseKey(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "PresharedKey", Reason: err.Error()}
		}
		p.PresharedKey = &k
	case "allowedips":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "AllowedIPs", Reason: err.Error()}
		}
		p.AllowedIPs = append(p.AllowedIPs, prefixes...)
	case "endpoint":
		ap, err := parseEndpoint(value)
		if err != nil {
			return &ParseError{Line: lineNum, Field: "Endpoint", Reason: err.Error()}
		}
		p.Endpoint = &ap
	case "persistentkeepalive":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return &ParseError{Line: lineNum, Field: "PersistentKeepalive", Reason: "PersistentKeepalive must be a non-negative integer ≤ 65535"}
		}
		p.PersistentKeepalive = time.Duration(n) * time.Second
	default:
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("line %d: unknown [Peer] key %q ignored", lineNum, key))
	}
	return nil
}

// parseKey trims surrounding whitespace and rejects empty/blank input
// before handing the rest to wgtypes.ParseKey. wgtypes' own error
// messages are too cryptic for the UI; we wrap them so the panel can
// just splice the result under the offending field.
func parseKey(value string) (wgtypes.Key, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return wgtypes.Key{}, errors.New("key is empty")
	}
	k, err := wgtypes.ParseKey(value)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("not a valid 44-character base64-encoded key: %w", err)
	}
	return k, nil
}

// parsePrefixList splits a comma list of CIDR-or-IP strings into
// netip.Prefix values. Bare IPs are accepted and treated as host
// routes — the same behaviour wg-quick exhibits.
func parsePrefixList(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR", raw)
			}
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", raw)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	if len(out) == 0 {
		return nil, errors.New("value must declare at least one CIDR or IP")
	}
	return out, nil
}

// parseEndpoint accepts a literal IP:port (v4 or bracketed v6). The
// PRD pins this restriction so we never resolve DNS at runtime; if
// the seller's config has a hostname the operator must resolve once
// and paste the IP themselves.
func parseEndpoint(value string) (netip.AddrPort, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.AddrPort{}, errors.New("endpoint is empty")
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, errors.New("endpoint must be a literal IP:port — hostnames are not resolved; resolve once and paste the IP (e.g. 198.51.100.20:81 or [2001:db8::1]:51820)")
	}
	if !ap.IsValid() || ap.Port() == 0 {
		return netip.AddrPort{}, errors.New("endpoint port must be greater than zero")
	}
	return ap, nil
}

// splitKV separates a line into key and value at the first '='.
// Surrounding whitespace is trimmed; comments are removed earlier by
// stripComment.
func splitKV(line string) (string, string, bool) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// stripComment removes any trailing '#'-prefixed comment from line,
// preserving content before it. wg-quick uses '#' as the comment
// marker inside INI-ish files.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}
