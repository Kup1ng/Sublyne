# Release notes

## v2.7.0 — Unified port list (2026-06-01)

**What changed for you**

The tunnel form no longer asks for ports in two places. Before, you typed the
"main" port inside the address (e.g. `0.0.0.0:443`) and any extra ports in a
separate "Additional ports" box. Now:

- **Local listen address** (Iran side) and **Forward target address** (foreign
  side) take a host/IP only — e.g. `0.0.0.0` or `127.0.0.1`. No port.
- **Ports** is a single list where you type every port for the tunnel,
  comma-separated — e.g. `443, 8001, 8002`. One port is a normal single-service
  tunnel; list several to carry multiple services over the one tunnel.

Every port in the list is forwarded identically — same speed, same path, same
security. There is no "main port" that gets special treatment.

**Your existing tunnels keep working with zero action.** On upgrade, each
tunnel's old main port is automatically folded into its new port list and its
address is trimmed to a host. Open any tunnel afterward and you'll see one
unified Ports list already filled in correctly.

**No flag-day.** This is a single-box update. The packets on the wire are
unchanged — a one-port tunnel is byte-for-byte identical to v2.6.0, and
multi-port tunnels use the same 2-byte port tag as v2.5.0/v2.6.0. You can
upgrade the two servers independently.

**Under the hood:** the data plane already treated every port identically (one
shared seal/upload pipeline, per-port sockets bound from the same code path);
this release removes the last place the control plane and UI treated a "main"
port as special. Schema migration `0011` performs the one-time fold. Not yet
validated on the live hardware pair.

## v2.6.0 — Drop-visibility + download-ingest batching + dashboard controls

A performance, packet-loss-hardening, and panel-usability release. **No wire
change** — a v2.6.0 box interoperates with a v2.5.0 box on every row, so the
two servers can be upgraded one at a time (single-box update, no flag-day).
`PROTO_VERSION` stays `2`; the HMAC envelope, anti-replay `SeqWindow` (1024
slots), random `session_id`, DF-clear, fwmark steering, SOCKS5 framing, and
the multi-port app-port tag are all byte-identical to v2.5.0.

### Data-plane: stop silent packet loss, batch the busiest socket

- **Remote forward-reply ingest now drains with `recvmmsg`.** The socket that
  receives the entire download payload stream (the busiest on the Remote) was
  reading one datagram per syscall while its own docstring claimed batched
  draining. Under a bursty ≥1 Gbps reply stream the single-syscall loop could
  not empty the kernel buffer fast enough, so the kernel silently dropped the
  overflow. It now drains a whole `recvmmsg` batch per wake-up — matching the
  already-batched send side — sized by the existing `SUBLYNE_RECV_BATCH` knob
  (set it to `1` to recover the old one-at-a-time behaviour). Sequence numbers
  are still assigned one-per-datagram in arrival order and the single send
  socket still serialises wire FIFO, so the anti-replay window is unaffected.
- **Download- and upload-path drops are now visible on the panel.** Several
  bounded-drop points (seal-channel full, send-queue full, the send-worker
  dropping a staged batch on a hard `sendmmsg` error / writability failure /
  persistent back-pressure, and SOCKS5 pool saturation) previously only wrote
  a log line. Download-egress shedding now folds into the existing
  `packet_loss_estimate` so the dashboard's loss gauge reflects it, and a
  SOCKS5 frame dropped because every connection is down/full is no longer
  miscounted as a *delivered* upload byte.
- **Raw ICMP / ICMPv6 / ping-smoothing send sockets get the drop-all BPF
  filter** the UDP/TCP send sockets already carry. Without it the kernel
  copies every host ICMP packet onto these never-read sockets, pinning the
  forced 4 MiB receive buffer and dropping unrelated inbound ICMP.
- **Zero-allocation ICMPv6 checksum.** The ICMPv6 builder no longer copies the
  whole message into a fresh per-packet `Vec` for the pseudo-header checksum;
  it streams the pieces like the UDP/TCP builders (byte-identical result).

### Panel

- **Start/Stop buttons on the Dashboard tunnel tiles.** Each tile gains the
  same primary action the Tunnels page has — Start when stopped, Stop when
  running — reusing one shared action so the two pages can never drift. The
  button disables with a spinner during the transition, a toast reports
  failure, and the tile reflects the new state immediately.
- **Redesigned live bandwidth chart.** The 30-second canvas sparkline now
  renders the intended theme colours (the previous version drew black because
  a canvas cannot resolve CSS `var()` in a colour string), with monotone-cubic
  smoothing over a light moving average, soft gradient fills, a stable
  "nice-rounded" auto-scaled Y axis with a unit label, and a current-value pill
  riding each line. Still a single dependency-free canvas repaint per frame.

### Why this is v2.6.0 (a minor release)

Backward-compatible feature additions (dashboard controls, drop metering) plus
performance fixes, with no wire-format change. By semver that is a minor bump.

### Invariants preserved

HMAC auth + 1024-slot anti-replay `SeqWindow`; parallel-seal → single-send wire
ordering (PR #36); random `session_id` (no wall-clock); DF-clear on spoof
egress; fwmark / ip-rule steering; 4 MiB forced socket buffers (v2.2.0); SOCKS5
keepalive + `TCP_USER_TIMEOUT`, per-slot driver + bounded queue, striping +
BBR (v2.1.0/v2.2.0/v2.4.0); multi-port app-port tag inside the sealed payload
(v2.5.0). PSK never leaks; no inter-server control plane.

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
