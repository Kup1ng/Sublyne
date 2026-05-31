# Release notes

## v2.5.0 — Multi-port tunnels

A single Sublyne tunnel can now carry **several application ports** (up to
32) through the one secure download-spoof / upload pipeline, with a fixed 1:1
same-number mapping: Client `:51820` ↔ Remote `:51820`, Client `:443` ↔
Remote `:443`, and so on. An operator who wants to run WireGuard (`:51820`),
a VLESS/Reality service (`:443`), and a third UDP service through one tunnel
no longer needs three separate tunnels — one tunnel, one PSK, one session
table, several ports.

Full design: [`docs/multiport.md`](docs/multiport.md).

### What's new

- **Multi-port tunnels.** Configure a comma-separated port list per tunnel.
  The dataplane binds one app socket per port and routes each datagram to the
  right port using a 2-byte big-endian **app-port tag** carried *inside* the
  HMAC-authenticated payload (download) and inside the existing upload frame.
- **All six mechanisms supported.** `UDP-WG`, `TCP-SOCKS5`, `ICMP-WG`,
  `ICMP-SOCKS5`, `ICMPv6-WG`, `ICMPv6-SOCKS5` all carry the tag with no new
  ports, no new ICMP identifiers, and no extra packets.
- **Panel.** The tunnel form gains an optional *"Additional ports"* field;
  the tunnel card shows a `Ports:` badge for multi-port tunnels. Stats stay
  aggregate.
- **API + IPC.** Tunnel create/update/get/list round-trip a `ports` array;
  the `StartTunnel`/`TunnelSpec` IPC payload gains an optional `ports` list.
  The PSK is still returned as `"***"` everywhere.

### Why this is v2.5.0 (a minor release), not v3.0.0

This release is **backward-compatible** with **no wire break**:

- **`PROTO_VERSION` stays `2`.** It is bumped only when the framing of an
  *existing* configuration changes on the wire. It does not here.
- **Single-port tunnels are byte-identical to v2.4.0.** The 2-byte tag is
  added *only* for tunnels an operator has explicitly reconfigured to carry
  multiple ports — tunnels that did not exist before this release, so no peer
  can misinterpret them. Every tag add/strip is gated on "is multi-port".
- **No negotiation.** Both ends derive multi-port-ness from the same shared
  static config (the `ports` list, distributed out of band exactly like the
  PSK). There is no capability byte or probe on the wire.
- **Mixed versions interoperate.** A v2.4.0 box and a v2.5.0 box work
  together perfectly for every single-port tunnel, so the two servers can be
  upgraded one at a time. Multi-port requires both ends ≥ v2.5.0, but there
  is no pre-existing multi-port peer to break.

By semver, a backward-compatible feature addition is a **minor** bump.
(Contrast v2.0.0, which *did* change the envelope framing for existing
tunnels and was correctly a major bump.)

### Migration

- Migration `0010_multiport.sql` adds
  `tunnels.ports TEXT NOT NULL DEFAULT ''`.
- **Existing single-port tunnels are untouched** and need **zero operator
  action** — an empty `ports` is treated as single-port via the existing
  `local_listen_addr` / `forward_target` port.
- No downtime or coordinated upgrade is required for single-port tunnels.

### Notes & caveats

- The tag costs 2 bytes of usable application MTU on every row. On the
  low-rate **ICMP / ICMPv6 stealth-fallback** rows this is the most
  noticeable, and running many high-bandwidth services over that fallback is
  rarely useful — but it works correctly and all latency tuning is preserved.
  There is no correctness impact. See `docs/multiport.md` §4.1.
- The wire diagrams and the worked 3-port example
  (WireGuard `:51820` + VLESS `:443` + a third service `:9993`, on white IP
  `203.0.113.10` ↔ `198.51.100.20`) use RFC 5737 placeholder addresses only.

### Invariants preserved

Single-port wire byte-identical to v2.4.0; `PROTO_VERSION` unchanged (`2`);
HMAC covers the whole sealed payload including the tag; anti-replay
`SeqWindow` is one stream/one window per tunnel (not per port); random
`session_id`; DF-bit cleared on spoof egress; fwmark/ip-rule WG steering;
64 KiB recv-buffer floor + per-core verify fan-out; SOCKS5 keepalive +
`TCP_USER_TIMEOUT`; PSK never leaks; no inter-server control plane.
