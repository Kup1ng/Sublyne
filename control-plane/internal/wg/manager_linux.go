//go:build linux

package wg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// NewManager returns the production Manager on Linux. It dials
// `wgctrl.New()` to talk to the kernel WG module over netlink and
// uses vishvananda/netlink for `ip link / addr / route / rule`
// operations.
//
// The caller is expected to be running with CAP_NET_ADMIN —
// systemd's AmbientCapabilities line in the project's unit file
// supplies that without making the service root.
func NewManager(logger *slog.Logger) (Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: open wgctrl: %w", err)
	}
	return &netlinkManager{client: client, logger: logger}, nil
}

type netlinkManager struct {
	client *wgctrl.Client
	logger *slog.Logger
}

// Up implements Manager. The sequence mirrors the SKILL.md "Per-tunnel
// interface" diagram: add the link, configure WG, add the address,
// bring the link up, then install the policy-routing pieces.
//
// Each step is idempotent on its own — a re-run after a partial failure
// will skip the bits already in place — so retries are safe.
func (m *netlinkManager) Up(ctx context.Context, tunnelID int64, cfg *ParsedConfig) (BringUpResult, error) {
	if cfg == nil {
		return BringUpResult{}, errors.New("wg: Up requires a parsed config")
	}
	ifname := InterfaceNameFor(tunnelID)
	fwmark := FwmarkFor(tunnelID)
	// Keep the route-table number as a uint32 for downstream use and
	// only widen to int once at the netlink boundary — netlink.Route
	// declares Table as int. Storing both saves us from a second
	// narrowing cast that gosec G115 (correctly) flags.
	table := TableFor(tunnelID)
	tableInt := int(table)

	link, err := m.ensureLink(ifname)
	if err != nil {
		return BringUpResult{}, fmt.Errorf("wg: ensure link %s: %w", ifname, err)
	}

	if err := m.configureDevice(ifname, cfg, fwmark); err != nil {
		return BringUpResult{}, fmt.Errorf("wg: configure device %s: %w", ifname, err)
	}

	if err := m.ensureAddresses(link, cfg); err != nil {
		return BringUpResult{}, fmt.Errorf("wg: set addresses on %s: %w", ifname, err)
	}

	if cfg.Interface.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.Interface.MTU); err != nil {
			return BringUpResult{}, fmt.Errorf("wg: set MTU on %s: %w", ifname, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return BringUpResult{}, fmt.Errorf("wg: bring up %s: %w", ifname, err)
	}

	priority := RulePriority(tunnelID)
	if err := m.ensurePolicyRouting(link, fwmark, tableInt, priority); err != nil {
		return BringUpResult{}, fmt.Errorf("wg: policy routing for %s: %w", ifname, err)
	}

	m.logger.Info("wg: tunnel up",
		"tunnel_id", tunnelID,
		"iface", ifname,
		"fwmark", fmt.Sprintf("0x%x", fwmark),
		"table", tableInt,
		"rule_priority", priority,
	)
	return BringUpResult{
		InterfaceName: ifname,
		Fwmark:        fwmark,
		Table:         table,
	}, nil
}

// Down implements Manager. The teardown order is the reverse of Up:
// rules and route tables come down before the kernel device so the
// kernel never holds dangling references.
func (m *netlinkManager) Down(ctx context.Context, tunnelID int64) error {
	ifname := InterfaceNameFor(tunnelID)
	fwmark := FwmarkFor(tunnelID)
	table := int(TableFor(tunnelID))

	if err := flushRoutesTable(table); err != nil {
		m.logger.Warn("wg: flush table (ignoring)", "table", table, "err", err)
	}
	if err := deleteRulesForFwmark(fwmark); err != nil {
		m.logger.Warn("wg: delete rules (ignoring)", "fwmark", fmt.Sprintf("0x%x", fwmark), "err", err)
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		// If the link is already gone we're done — Down is safe to
		// call repeatedly even on a tunnel that never came up.
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("wg: lookup %s: %w", ifname, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("wg: delete %s: %w", ifname, err)
	}
	m.logger.Info("wg: tunnel down", "tunnel_id", tunnelID, "iface", ifname)
	return nil
}

// Handshake implements Manager.
func (m *netlinkManager) Handshake(ctx context.Context, tunnelID int64) (HandshakeStatus, error) {
	ifname := InterfaceNameFor(tunnelID)
	dev, err := m.client.Device(ifname)
	if err != nil {
		return HandshakeStatus{InterfaceName: ifname}, fmt.Errorf("wg: device %s: %w", ifname, err)
	}
	out := HandshakeStatus{InterfaceName: ifname}
	for _, p := range dev.Peers {
		if !p.LastHandshakeTime.IsZero() && p.LastHandshakeTime.After(out.LastHandshake) {
			out.LastHandshake = p.LastHandshakeTime
			out.HasEverConnected = true
		}
	}
	return out, nil
}

// TearDownAll implements Manager. It walks every link on the host,
// keeping only those whose names parse as our `sub-wg-<id>` pattern,
// and calls Down on each. Best-effort: errors are logged but do not
// abort the sweep so a single broken device can't block a clean
// uninstall.
func (m *netlinkManager) TearDownAll(ctx context.Context) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("wg: list links: %w", err)
	}
	var firstErr error
	for _, link := range links {
		name := link.Attrs().Name
		id, ok := ParseInterfaceName(name)
		if !ok {
			continue
		}
		if err := m.Down(ctx, int64(id)); err != nil {
			m.logger.Warn("wg: teardown link (continuing)", "iface", name, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Supported implements Manager. Real kernel-backed manager → true.
func (m *netlinkManager) Supported() bool { return true }

// ensureLink looks up or creates the sub-wg-<id> kernel interface.
func (m *netlinkManager) ensureLink(ifname string) (netlink.Link, error) {
	if l, err := netlink.LinkByName(ifname); err == nil {
		return l, nil
	} else if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	la := netlink.NewLinkAttrs()
	la.Name = ifname
	wg := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
	if err := netlink.LinkAdd(wg); err != nil {
		return nil, fmt.Errorf("add: %w", err)
	}
	return netlink.LinkByName(ifname)
}

// configureDevice runs the wgctrl ConfigureDevice call. The actual
// translation of ParsedConfig to wgtypes.Config lives in manager.go's
// BuildDeviceConfig — that's where the FirewallMark-must-NOT-be-set
// invariant is documented and unit-tested.
//
// The fwmark argument is intentionally unused on the device-level
// configure call (see BuildDeviceConfig's doc for the long form);
// fwmark still feeds the ip-rule + route-table layer in
// ensurePolicyRouting.
func (m *netlinkManager) configureDevice(ifname string, cfg *ParsedConfig, _ uint32) error {
	return m.client.ConfigureDevice(ifname, BuildDeviceConfig(cfg))
}

// ensureAddresses adds every [Interface] Address to the link.
// AddrAdd silently fails when the address is already on the link, so
// we treat the "exists" error as success.
func (m *netlinkManager) ensureAddresses(link netlink.Link, cfg *ParsedConfig) error {
	for _, p := range cfg.Interface.Addresses {
		ip := net.IP(p.Addr().AsSlice())
		mask := net.CIDRMask(p.Bits(), len(ip)*8)
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: mask}}
		if err := netlink.AddrAdd(link, addr); err != nil {
			if !errors.Is(err, syscall.EEXIST) && !strings.Contains(err.Error(), "file exists") {
				return err
			}
		}
	}
	return nil
}

// ensurePolicyRouting installs the per-tunnel ip rule + default
// route. Both operations are idempotent: a duplicate rule add is
// silently ignored, a duplicate route add reuses the existing entry.
//
// `priority` MUST be below 32766 (Linux's main-table lookup
// priority); see RulePriority's doc for why. The caller in Up()
// computes it via RulePriority(tunnelID) so this method doesn't
// have to know about the formula.
func (m *netlinkManager) ensurePolicyRouting(link netlink.Link, fwmark uint32, table int, priority int) error {
	rule := netlink.NewRule()
	rule.Mark = uint32(fwmark)
	rule.Table = table
	rule.Priority = priority
	if err := netlink.RuleAdd(rule); err != nil {
		if !errors.Is(err, syscall.EEXIST) && !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("add rule: %w", err)
		}
	}
	v6rule := netlink.NewRule()
	v6rule.Family = netlink.FAMILY_V6
	v6rule.Mark = uint32(fwmark)
	v6rule.Table = table
	v6rule.Priority = priority
	if err := netlink.RuleAdd(v6rule); err != nil {
		if !errors.Is(err, syscall.EEXIST) && !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("add v6 rule: %w", err)
		}
	}
	idx := link.Attrs().Index
	v4Route := &netlink.Route{
		LinkIndex: idx,
		Table:     table,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(v4Route); err != nil {
		return fmt.Errorf("add v4 default route: %w", err)
	}
	v6Route := &netlink.Route{
		LinkIndex: idx,
		Table:     table,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(v6Route); err != nil {
		// IPv6 may be disabled on the host; that's the operator's
		// choice and not a hard error for v4-only deployments.
		m.logger.Warn("wg: add v6 default route (ignoring)", "err", err)
	}
	return nil
}

// flushRoutesTable removes every route from the supplied table. It
// is called by Down and by TearDownAll.
func flushRoutesTable(table int) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: table},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		_ = netlink.RouteDel(&r)
	}
	return nil
}

// deleteRulesForFwmark walks every rule on the system and removes any
// that match our fwmark — both v4 and v6 sides. Idempotent: removing
// a rule that's already gone returns an error which we ignore.
func deleteRulesForFwmark(fwmark uint32) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Mark == uint32(fwmark) {
				rr := r
				_ = netlink.RuleDel(&rr)
			}
		}
	}
	return nil
}
