package wg

import (
	"fmt"
	"strings"
)

// fwmark and route-table allocation scheme per
// .claude/skills/wireguard-config-handling/SKILL.md §"fwmark scheme".
//
// We use 0x1000 + (tunnel_id & 0x0fff) for both. 4096 possible values
// fits well past the realistic number of tunnels on a single VPS and
// keeps the 16-bit fwmark space tidy.
//
// Phase 7 only places one tunnel per WG interface (no shared
// interfaces yet — the SKILL describes how to add reference-counting
// in Phase 10), so tunnel_id is the only input.

const (
	// fwmarkBase is the high nibble that marks "this fwmark belongs
	// to forward". Anything above 0x1000 in the kernel's mark space
	// is ours; anything below it is left alone. The kernel's
	// `mark` semantics treat fwmark as opaque, so the choice of
	// base value is only convention — but having one stable bit
	// pattern makes `ip rule` listings easy to grep for.
	fwmarkBase uint32 = 0x1000

	// tableOffset matches fwmarkBase so the per-tunnel route table
	// number equals the fwmark. The kernel supports up to 2^32-1
	// route tables, so collision with reserved tables (main, local,
	// default) is trivially avoided by staying above 1024.
	tableOffset = fwmarkBase

	// mainTableLookupPriority is the priority of the kernel's
	// standard `from all lookup main` rule. Any of our fwmark-based
	// policy rules MUST sit numerically below this value — `ip
	// rule` evaluation is in ascending priority order and `from all`
	// at 32766 catches every packet that reached it. A rule above
	// 32766 is dead code.
	//
	// Exported as a check-anchor for the regression test that pins
	// this invariant; the value itself is fixed in the Linux kernel
	// (see net/ipv4/fib_rules.c).
	mainTableLookupPriority = 32766

	// rulePriorityBase keeps our per-tunnel rule priorities clear
	// of well-known low-numbered ranges that other tooling uses
	// (Docker, NetworkManager, sshuttle, etc. typically register
	// rules with priorities under 100). 100..4195 is the resulting
	// range for tunnel IDs 0..4095, which is plenty of headroom
	// under main's 32766.
	rulePriorityBase = 100
)

// RulePriority returns the `ip rule` priority used for a tunnel's
// fwmark match. Two invariants this function exists to protect:
//
//  1. **Below `from all lookup main` (32766).** Without this, the
//     rule is unreachable and the dataplane's SO_MARK'd upload
//     packets fall through to main routing and egress as plain UDP
//     instead of being encapsulated by WireGuard. The original
//     production code used `32000 + table` which landed at 36097
//     for tunnel 1 — above main, silently dead.
//  2. **Deterministic per tunnel.** A tunnel that goes Stop→Start
//     must reuse the same priority so deleteRulesForFwmark catches
//     any stale rule from before. The 12-bit mask matches the same
//     scheme FwmarkFor / TableFor use, so all three values share
//     the same per-tunnel identity bits.
//
// The 4096-tunnel ceiling is a soft cap; tunnels beyond that
// collide on priority (just like they collide on fwmark + table),
// which is documented as out of scope until Phase 10 introduces
// shared WG interfaces.
func RulePriority(tunnelID int64) int {
	// The 12-bit mask bounds the int64→uint64 cast (and the
	// subsequent uint64→int) so gosec G115's narrowing warning is a
	// false positive here, the same way it is in FwmarkFor/TableFor
	// just above.
	return rulePriorityBase + int(uint64(tunnelID)&0x0fff) //nolint:gosec // 12-bit mask makes the narrowing safe
}

// FwmarkFor returns the firewall mark used to route a tunnel's
// upload-side traffic through its WG interface. The mark is set by
// the data plane on its upload socket via SO_MARK; an `ip rule fwmark
// 0xNNNN lookup table_NNNN` then steers the packet into the per-
// tunnel route table.
//
// The result is deterministic given the same tunnel id, so the
// fwmark survives a service restart without bookkeeping.
func FwmarkFor(tunnelID int64) uint32 {
	// The mask deliberately keeps only the bottom 12 bits — overflow
	// from the int64→uint32 cast is impossible because the masked
	// value fits in a uint16. gosec G115 doesn't see that, so we
	// silence it with a comment instead of restructuring callers.
	return fwmarkBase | uint32(uint64(tunnelID)&0x0fff) //nolint:gosec // 12-bit mask makes the narrowing safe
}

// TableFor returns the per-tunnel route table number that contains
// the `default via dev sub-wg-<id>` route. Numerically equal to
// FwmarkFor, but kept as a separate function so the call site reads
// like prose at the policy-routing layer.
func TableFor(tunnelID int64) uint32 {
	return tableOffset | uint32(uint64(tunnelID)&0x0fff) //nolint:gosec // see FwmarkFor
}

// InterfaceNameFor returns the kernel interface name for a tunnel.
// Linux interface names are capped at 15 chars; "sub-wg-" (7 chars)
// plus an 8-hex slice leaves room for a few more characters if a
// future phase wants them. We use the low 32 bits of the tunnel id —
// it round-trips uniquely back to one tunnel on the same DB.
func InterfaceNameFor(tunnelID int64) string {
	// %08x of the low 32 bits is intentional; gosec G115 flags the
	// narrowing but the truncation is the documented design choice.
	return fmt.Sprintf("sub-wg-%08x", uint32(uint64(tunnelID))) //nolint:gosec // low-32-bit identifier by design
}

// ParseInterfaceName extracts a tunnel id from an interface name the
// way InterfaceNameFor formats it. Returns false if the name does not
// match the `sub-wg-<8 hex>` shape. Used by the tear-down logic so
// we don't accidentally remove a device with a similar-looking name.
func ParseInterfaceName(name string) (uint32, bool) {
	const prefix = "sub-wg-"
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	tail := name[len(prefix):]
	if len(tail) != 8 {
		return 0, false
	}
	var v uint32
	if _, err := fmt.Sscanf(tail, "%08x", &v); err != nil {
		return 0, false
	}
	return v, true
}
