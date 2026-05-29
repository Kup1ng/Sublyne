---
name: wireguard-config-handling
description: Parsing user-pasted WireGuard config text, materializing per-tunnel kernel interfaces via `wgctrl-go` (netlink), per-tunnel policy routing with `fwmark`, and clean tear-down. Covers the multi-tunnel case where each tunnel may have its own WG endpoint and route table.
when_to_use: Phase 7 (storage + parsing + bring-up) and any later phase that touches WG state. Read before changing anything in `control-plane/internal/wg/`.
---

## What a user pastes

Users paste a standard `wg-quick`-style config they got from a seller:

```
[Interface]
PrivateKey = oK8E…base64…=
Address = 10.66.66.2/32, fd00:42::2/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
ListenPort = 51820

[Peer]
PublicKey = SfMSL…base64…=
PresharedKey = wQq…base64…=    # optional
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.20:81
PersistentKeepalive = 25
```

We **support multiple `[Peer]` blocks** (rare, but valid). We **ignore
`DNS = …`** because the dataplane sends raw IP packets — no resolution
is needed inside the tunnel.

## Parser

`control-plane/internal/wg/parser.go`. Hand-rolled (INI-like, but
`AllowedIPs` and `Address` are comma-lists). Output structure:

```go
type ParsedConfig struct {
    Interface InterfaceSection
    Peers     []PeerSection
}

type InterfaceSection struct {
    PrivateKey wgtypes.Key
    Addresses  []netip.Prefix    // parsed from "Address ="
    MTU        int               // 0 = unset
    ListenPort int               // 0 = unset
    // DNS deliberately omitted
}

type PeerSection struct {
    PublicKey           wgtypes.Key
    PresharedKey        *wgtypes.Key       // nil if absent
    AllowedIPs          []netip.Prefix
    Endpoint            *netip.AddrPort    // nil if absent
    PersistentKeepalive time.Duration      // 0 = unset
}
```

Validation rules:
- `[Interface]` must have exactly one `PrivateKey`. Reject otherwise.
- `[Interface]` must have at least one `Address`.
- `[Peer]` must have a `PublicKey` and at least one `AllowedIPs` entry.
- Unknown keys log a WARN but don't reject (some sellers add
  proprietary fields).
- `PrivateKey`, `PublicKey`, `PresharedKey` must be valid base64
  decoding to exactly 32 bytes.

Use `golang.zx2c4.com/wireguard/wgctrl/wgtypes` for the `Key` type
(handles base64 ↔ 32 bytes).

## Per-tunnel interface

Each tunnel that uses a WG config gets **its own kernel interface**:
`sub-wg-<8-hex>` where the hex comes from the first 4 bytes of the
tunnel UUID. (Linux interface names cap at 15 chars — leave headroom.)

Interface lifecycle:

```
                                              ┌────────────┐
StartTunnel command arrives on Go side  ─────►│ wg.Up(ctx) │
                                              └────┬───────┘
                                                   │
                  ┌────────────────────────────────┘
                  ▼
1. netlink: ip link add name sub-wg-<id> type wireguard
2. wgctrl-go: ConfigureDevice
       - PrivateKey
       - ListenPort (random if unset)
       - Peers (PublicKey, PresharedKey?, Endpoint, AllowedIPs, PersistentKeepalive)
       - **NOT** FirewallMark — see the "fwmark loop" gotcha below.
3. netlink: addr add <Address> dev sub-wg-<id>
4. netlink: link set up dev sub-wg-<id>
5. ip rule  add fwmark 0xNNNN lookup table_NNNN
6. ip route add default dev sub-wg-<id> table_NNNN
7. (if address has IPv6) ip -6 route add default dev sub-wg-<id> table_NNNN
```

Tear-down is the inverse, idempotent on missing pieces:

```
1. ip route flush table_NNNN
2. ip rule  del fwmark 0xNNNN lookup table_NNNN
3. netlink: link del sub-wg-<id>
```

## fwmark scheme

Each tunnel using a WG interface gets a unique `fwmark` value. We use
`0x1000 + (tunnel_short_id & 0x0FFF)` where `tunnel_short_id` is the
first 12 bits of the tunnel UUID's first 2 bytes. With 4096 possible
values that's well past any realistic tunnel count.

The route table number matches the fwmark: `table 0x1NNN` (decimal
4096+N). Linux supports 2^32-1 route tables, so collision concerns are
nonexistent.

The dataplane sets `SO_MARK` on the upload-side socket so its outgoing
packets carry the fwmark, get matched by the `ip rule`, and exit through
the right WG interface. The download-side raw socket is **not** marked
— spoofed download packets ride on the main interface, unaffected by
WG policy routing.

### ip rule priority MUST sit below 32766

The kernel walks `ip rule` in ascending priority order and the
default `from all lookup main` rule sits at priority **32766**. That
rule matches every packet that reaches it. Any of our fwmark-based
rules numerically above 32766 is dead code — `main` catches the
packet first, the dataplane's SO_MARK'd upload egresses through the
host's default route as plain UDP, and WireGuard is bypassed entirely.

The original Phase 7 code used `32000 + table` (≈ 36097 for tunnel 1),
which silently shipped to the Iran client and made every "upload via
WG" actually go out as plain UDP — invisible until tcpdump showed the
unencapsulated packets on the wire. The fix lives in
`internal/wg/policy.go::RulePriority`: priorities sit at `100 + (id &
0xFFF)` (range 100..4195), well below main, well above other tools'
common ranges (Docker / NetworkManager / sshuttle typically register
priorities under 100).

When adding new policy rules of any kind in this project, **assert
the computed priority is `< 32766`** in a unit test the same way
`policy_test.go::TestRulePriority_AlwaysBelowMainLookup` does. The
"is the rule even reachable?" check belongs in CI, not in a sysadmin's
tcpdump weeks after deploy.

## Library: `wgctrl-go`

```go
import (
    "golang.zx2c4.com/wireguard/wgctrl"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

client, err := wgctrl.New()
// …
fwmark := 0x1000 | uint32(shortID&0xfff)
peers := make([]wgtypes.PeerConfig, 0, len(parsed.Peers))
for _, p := range parsed.Peers {
    peers = append(peers, wgtypes.PeerConfig{
        PublicKey:                   p.PublicKey,
        PresharedKey:                p.PresharedKey,
        Endpoint:                    udpAddr(p.Endpoint),
        AllowedIPs:                  ipnets(p.AllowedIPs),
        PersistentKeepaliveInterval: durPtr(p.PersistentKeepalive),
        ReplaceAllowedIPs:           true,
    })
}
cfg := wgtypes.Config{
    PrivateKey:   &parsed.Interface.PrivateKey,
    ListenPort:   maybeInt(parsed.Interface.ListenPort),
    // DO NOT set FirewallMark here — see the "fwmark loop" gotcha
    // below for the full story. TL;DR: it makes the kernel mark WG's
    // own handshake packets with our fwmark, our ip rule then re-
    // routes them back into the same WG interface, and the handshake
    // never reaches the wire even though the underlay endpoint is
    // reachable from the host.
    ReplacePeers: true,
    Peers:        peers,
}
if err := client.ConfigureDevice(ifname, cfg); err != nil { /* … */ }
```

For the `ip link add … type wireguard` and `ip addr/route/rule`
operations, use `vishvananda/netlink`:

```go
import "github.com/vishvananda/netlink"

la := netlink.NewLinkAttrs()
la.Name = ifname
wg := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
if err := netlink.LinkAdd(wg); err != nil { /* … */ }
// netlink.AddrAdd, netlink.RouteAdd, netlink.RuleAdd …
```

Both libs work without root if the process has `CAP_NET_ADMIN`. systemd
gives us that ambient.

## Hot-reload (Phase 10)

`UpdateTunnel` IPC commands that change WG-relevant fields hot-reload
the interface:

| Changed field | Effect |
|---------------|--------|
| `mtu` | `netlink.LinkSetMTU(link, mtu)` — live, no flap |
| `psk` (the tunnel HMAC PSK, **not** the WG PresharedKey) | Dataplane swap, no WG touch |
| `wireguard_config` content | Full tear-down + bring-up (we can't safely replace `PrivateKey` in place; the peer would see a new identity) |
| `upload_target_addr` | No WG change; only the dataplane's UDP destination updates |

Adding/removing peers on an existing config: use
`wgctrl.ConfigureDevice` with `ReplacePeers: false` and the delta.

## Handshake status (Phase 11 dashboard)

`client.Device(ifname)` returns a `wgtypes.Device` with per-peer
`LastHandshakeTime`. We surface:

- **Connected**: `LastHandshakeTime` within the last 2 min.
- **Stale**: 2–5 min ago.
- **Stale > 3 min**: alert badge in panel (PRD §8.4 — surface but don't
  auto-restart).
- **Never connected**: `LastHandshakeTime.IsZero()`.

Poll every 5 s along with the IPC stats push (Go side queries `wgctrl`
directly — the dataplane doesn't need to forward this).

## Multi-tunnel + shared WG

Two tunnels with **identical pasted configs** share an interface (we
hash the config bytes and reuse the existing `sub-wg-<hash>` if one
exists). Each tunnel still gets its own fwmark and route table, even
when the interface is shared — that's how the dataplane keeps
per-tunnel upload egress correct.

Reference-count interfaces:
- On `StartTunnel`, increment refcount for the interface; create if 0.
- On `StopTunnel`, decrement; tear down if refcount drops to 0.

Implementation: a map[interfaceName]*ifaceState in
`control-plane/internal/wg/manager.go`.

## Gotchas

### **fwmark loop: never set `FirewallMark` on the WG device**

This one cost the project an entire deploy cycle on the real Iran
client. wg-quick sets the device's `FirewallMark` so its companion
`ip rule not fwmark <mark> table NNNN` rule can steer *application*
traffic into the tunnel while letting *WG's own* underlay packets
(handshake initiations, keepalives, encrypted UDP) bypass the rule
and reach the endpoint through main routing.

Our architecture does the opposite: we mark the application's upload
socket explicitly via `SO_MARK` from the Rust dataplane, and our ip
rule is the **positive** form `fwmark X table NNNN`. If we ALSO set
`FirewallMark` on the WG device, the kernel marks WG's underlay
packets with the same fwmark; those packets then match our positive
rule and get re-routed into the WG interface that produced them.
The interface stays UP, the endpoint stays pingable, and the
handshake never reaches the wire. Symptom in the panel: "no
handshake yet" forever.

Concrete failure observed in production with this exact paste:
```
[Interface]
PrivateKey = …
Address    = 10.200.2.15/32
[Peer]
PublicKey  = …
PresharedKey = …
Endpoint   = 198.51.100.10:82
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```
`wg show sub-wg-00000001 latest-handshakes` → `0`. `tcpdump host
198.51.100.10 and udp` → silence.

**Rule:** `wgtypes.Config.FirewallMark` stays `nil` for this project.
The per-tunnel fwmark only feeds the `ip rule` + route-table layer
in `ensurePolicyRouting` and the Rust dataplane's `SO_MARK`. The
regression test
`internal/wg/device_config_test.go::TestBuildDeviceConfig_FirewallMarkIsNeverSet`
fails loudly if a future refactor sets it again.

### Sellers sometimes paste configs with CRLF line endings

Normalize: `strings.ReplaceAll(input, "\r\n", "\n")` before parsing.

### `PrivateKey` validation

Some sellers paste keys with trailing whitespace or invisible
characters. Trim and validate base64 strictly. If `wgtypes.ParseKey`
returns an error, surface a UI message like "Private key is not a
valid 44-character base64-encoded value" — don't dump the raw error.

### Endpoint resolution

`Endpoint = host.example.com:51820` is technically allowed by
wg-quick, but we **only accept literal IP:port** (PRD §8.4: DNS lines
ignored, and resolving an endpoint introduces a DNS dep we don't
want). If the parser sees a non-IP endpoint, reject the config with
"Endpoint must be a literal IP:port. Resolve your host name to an IP
first."

### MTU clamping

If the pasted config has `MTU = 1420` but the tunnel's user-configured
`mtu` is `1400`, the **tunnel** MTU (1400) wins — that's the value the
dataplane uses for upload framing. The WG interface MTU is set to the
config's value (or default 1420 from kernel) so the kernel can fit
encrypted packets; our 1400 is just the inner payload cap.

### Tearing down on uninstall

The uninstall path in `setup.sh` calls `sublyne --tear-down` which
removes all `sub-wg-*` interfaces and our `ip rule` / `ip route` entries
before stopping the service. Don't leave WG interfaces hanging — they
survive process exit and break repeat installs.

### `ListenPort`

If the config doesn't specify `ListenPort`, the kernel picks a random
ephemeral port. That's fine for upload (we're the client side of WG)
because the seller's peer learns the source port from the first
handshake. If multiple tunnels use random ports, no conflict.

### `AllowedIPs = 0.0.0.0/0, ::/0` and "killswitch"

`wg-quick` adds a routing rule that sends *everything* through WG when
AllowedIPs is a default route. We **do not** want that — only the
upload traffic for this specific tunnel should go through this WG
interface. That's exactly why we use `fwmark` + per-tunnel route table
instead of letting the WG `AllowedIPs` drive routing. Skip the
wg-quick rule-setup logic entirely; we set our own.

## Don't do

- Don't shell out to `wg` or `wg-quick`. Use `wgctrl-go` + `netlink`.
- Don't trust pasted configs blindly — validate keys, addresses,
  endpoints.
- Don't share an interface between tunnels with *different* configs.
  Hash-and-share is for byte-identical pastes only.
- Don't forget tear-down on tunnel delete. Leftover interfaces leak
  fwmarks and confuse the next bring-up.
- Don't expose WG private keys in API responses. `GET /wg-configs/:id`
  returns redacted raw text by default; only `?reveal=1` returns the
  real bytes.
