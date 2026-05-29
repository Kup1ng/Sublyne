package wg

import "testing"

// TestRulePriority_AlwaysBelowMainLookup is the regression guard for
// the bug that shipped to the Iran client: the original computation
// `32000 + table` produced 36097 for tunnel 1, which sits ABOVE
// `from all lookup main` (priority 32766) in the kernel's rule list.
// An above-main rule is unreachable — the kernel matches the
// catch-all main rule first — so the dataplane's SO_MARK'd upload
// packets fell through to main routing and egressed as plain UDP to
// the upload_target_addr instead of being encapsulated by WireGuard.
//
// Every priority this function returns MUST be < 32766 so the rule
// is actually evaluated before the catch-all.
func TestRulePriority_AlwaysBelowMainLookup(t *testing.T) {
	for _, id := range []int64{
		0, 1, 42, 100, 4095, 4096, 8191,
		99999, 1 << 20, 1 << 30, 1 << 40,
	} {
		p := RulePriority(id)
		if p >= mainTableLookupPriority {
			t.Errorf("tunnel id=%d → priority %d, must be < %d (main lookup)",
				id, p, mainTableLookupPriority)
		}
		if p <= 0 {
			t.Errorf("tunnel id=%d → priority %d, must be > 0 (reserved-low range)", id, p)
		}
	}
}

// TestRulePriority_UniqueAcrossTunnels asserts that distinct tunnel
// ids in the 12-bit address space produce distinct priorities — so
// two simultaneous tunnels never overwrite each other's policy rule.
// (Determinism is an implicit property of a pure int64→int function;
// staticcheck SA4000 correctly objects to a `f(x) != f(x)` check.)
func TestRulePriority_UniqueAcrossTunnels(t *testing.T) {
	seen := make(map[int]int64)
	for id := int64(0); id <= 0x0fff; id++ {
		p := RulePriority(id)
		if prev, dup := seen[p]; dup {
			t.Fatalf("priority collision: tunnel %d and tunnel %d both produce priority %d",
				prev, id, p)
		}
		seen[p] = id
	}
}

// TestRulePriority_StaysAboveZero is a defence-in-depth check: a
// priority of 0 would collide with `from all lookup local` and a
// negative priority is rejected by the kernel. The base 100 sits
// well above either pitfall.
func TestRulePriority_StaysAboveZero(t *testing.T) {
	for id := int64(0); id <= 0x0fff; id++ {
		if p := RulePriority(id); p < 1 {
			t.Fatalf("tunnel id=%d → priority %d, must be ≥ 1", id, p)
		}
	}
}

func TestFwmarkAndTable_StableForSameTunnel(t *testing.T) {
	for _, id := range []int64{1, 42, 4095, 4096, 99999} {
		f := FwmarkFor(id)
		tbl := TableFor(id)
		if f != tbl {
			t.Errorf("id=%d: fwmark %#x != table %#x", id, f, tbl)
		}
		if f < fwmarkBase {
			t.Errorf("id=%d: fwmark %#x below base", id, f)
		}
	}
}

func TestInterfaceNameRoundTrip(t *testing.T) {
	for _, id := range []int64{1, 42, 4095, 4096, 0xdeadbeef} {
		name := InterfaceNameFor(id)
		got, ok := ParseInterfaceName(name)
		if !ok {
			t.Errorf("ParseInterfaceName(%q) returned ok=false", name)
			continue
		}
		if uint32(got) != uint32(id) {
			t.Errorf("round-trip id=%d → %s → %d", id, name, got)
		}
		if len(name) > 15 {
			t.Errorf("interface name %q exceeds Linux 15-char cap", name)
		}
	}
}

func TestParseInterfaceName_RejectsForeignNames(t *testing.T) {
	for _, n := range []string{
		"eth0",
		"wg0",
		"sub-wg-",          // too short
		"sub-wg-1234567",   // 7 chars
		"sub-wg-123456789", // 9 chars
		"sub-wg-zzzzzzzz",  // non-hex
		"forward-wg-12345678",
	} {
		if _, ok := ParseInterfaceName(n); ok {
			t.Errorf("ParseInterfaceName(%q) returned ok=true, want false", n)
		}
	}
}
