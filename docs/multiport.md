# Multi-port tunnels (v2.5.0)

> Status: implemented in the `feat-multiport-tunnels` branch.
> **Backward compatible** — a single-port tunnel is wire-identical to
> v2.4.0, so a v2.5.0 box interoperates with a v2.4.0 peer for every
> single-port tunnel and the two servers can be upgraded one at a time.
> See [§6 Migration & peer compatibility](#6-migration--peer-compatibility).

## 1. Motivation

Until v2.4.x a tunnel carried exactly **one** application port end to end:
the Client listened on one local UDP port and the Remote forwarded to one
`forward_target` port. To run two services through the same white-IP spoof
path — say WireGuard on one port and a VLESS/Reality service on another — an
operator had to stand up **two** tunnels: two PSKs, two session tables, two
dashboard rows, two seller-WireGuard egress paths.

v2.5.0 lets a single tunnel carry **several** application ports through the
one secure download-spoof / upload pipeline, with a **fixed 1:1 same-number
mapping**: Client `:51820` ↔ Remote `:51820`, Client `:443` ↔ Remote `:443`,
and so on. The operator enters **one** list of ports; both sides hold the
same list (shared static config, exactly like the PSK). Each port pair is
independent and predictable — no dynamic remapping, no per-flow mapping
state. Typical 5–10 ports; **hard cap 32**.

One PSK, one session table, one download spoof path, one upload egress,
several application ports.

## 2. The wire design — the "app-port tag"

For **multi-port tunnels only**, every forwarded UDP datagram is prefixed
with a 2-byte big-endian application-port tag:

```
PORT-TAGGED PAYLOAD =  [u16 BE app_port] ‖ [original UDP datagram body]
```

This tagged blob is what travels as the *payload* in **both** directions.
**Single-port tunnels carry no tag** — byte-for-byte identical to v2.4.0.

### 2.1 Download (Remote → Client) — tag inside the HMAC seal

The tag lives **inside** the HMAC-sealed envelope payload, above the HMAC
layer. The Remote prepends the tag *before* `seal_with`; the Client strips
it *after* `open_with`. Because the seal already hashes `SHA256(payload)`,
the port tag is **authenticated and tamper-proof for free** — a man in the
middle cannot rewrite the destination port without breaking the HMAC.

```
v2.4.0 (single-port) sealed envelope:
  [1 ver][16 HMAC][8 session_id][8 seq][N app payload]

v2.5.0 (multi-port) sealed envelope — tag is part of the sealed payload:
  [1 ver][16 HMAC][8 session_id][8 seq][2 app_port][N-2 app payload]
                                        \__________________________/
                                          the "payload" the HMAC covers
  HMAC = HMAC-SHA256(psk, ver ‖ session_id ‖ seq ‖ SHA256(payload))[..16]
```

`hmac.rs`, `OVERHEAD`, `SeqWindow`, `session_id`, and `PROTO_VERSION` are all
**unchanged**. The only difference is that, for a multi-port tunnel, the
first 2 bytes of the already-hashed payload are the port tag.

### 2.2 Upload (Client → Remote) — tag is the first 2 bytes

The tag is the first 2 bytes of the datagram the Client hands to the upload
substrate:

- **WireGuard** — the tag is simply the first 2 bytes of the UDP payload
  (WG encrypts the whole thing). No framing change.
- **SOCKS5** — the tag sits **inside** the existing `[u16 BE len][payload]`
  frame, so on the wire it is `[u16 len][u16 app_port][body]` with
  `len = 2 + body.len()`. The SOCKS5 framing, per-session sticky routing,
  and coalescing code are **unchanged** — they ship opaque bytes; only the
  bytes' content gains a 2-byte prefix.

### 2.3 Why a full 2-byte port, not a 1-byte index

Self-describing **and** validated. The receiver maps the tag *directly* to a
socket and **drops + warns** if the port is not in the tunnel's configured
set, so config drift can never silently misroute traffic to the wrong
service. A 1-byte ordinal index would couple the two sides to an exact
list-ordering and offer no validation. The cost is 2 bytes per packet
(~0.14 % at a 1400-byte MTU — negligible), and on the download path those 2
bytes are HMAC-authenticated.

## 3. Why `PROTO_VERSION` stays at 2 (and this is v2.5.0, not v3.0.0)

`PROTO_VERSION` is the 1-byte version folded into the download HMAC envelope
(see [`upload-download-matrix.md` §4.1](upload-download-matrix.md#41-download-hmac-envelope--proto_ver-prefix)).
It is bumped only when the framing of an **existing configuration** changes
on the wire. Multi-port does **not** do that:

- A **single-port** tunnel — which is *every* tunnel that exists today —
  emits and expects exactly the same bytes as v2.4.0. No tag, no envelope
  change, `OVERHEAD` unchanged.
- The 2-byte tag appears **only** for a tunnel an operator has *explicitly*
  reconfigured to carry multiple ports. Such a tunnel did not exist before
  this release, so there is no pre-existing peer that could misinterpret it.

Multi-port-ness is known from **shared static config** (the port list both
sides hold), exactly like PSK / transport / channel ports are today (PRD
§2.3: no inter-server control plane). There is **no negotiation**, no
capability byte, no probe on the wire: if the two sides' config agrees, the
framing agrees. This is what makes the change backward-compatible:

- A v2.5.0 box running a single-port tunnel is wire-identical to v2.4.0, so
  single-port tunnels keep working across a one-box-at-a-time upgrade.
- Multi-port **requires both ends ≥ v2.5.0** (a v2.4.0 box has no multi-port
  concept) — but there is no pre-existing multi-port peer to break.

By semver, a backward-compatible feature addition is a **MINOR** bump:
**v2.4.0 → v2.5.0**, not v3.0.0. (Contrast v2.0.0, which *did* change the
envelope framing for existing tunnels and was correctly a MAJOR bump.)

## 4. Which matrix rows support multi-port — all six

All six `(download, upload)` mechanisms from
[`upload-download-matrix.md`](upload-download-matrix.md) support multi-port,
because the app-port tag rides **inside** the already-existing sealed
payload (download) / framed payload (upload). It needs **no** new L4 port,
**no** new ICMP identifier, **no** extra packets, and **no** extra round
trips.

| # | Mechanism       | Download   | Upload  | Multi-port behaviour                          |
|---|-----------------|------------|---------|-----------------------------------------------|
| 1 | `UDP-WG`        | UDP spoof  | WG      | tag in sealed payload; unchanged egress       |
| 2 | `TCP-SOCKS5`    | TCP-SYN    | SOCKS5  | tag inside `[u16 len]` frame; coalescing intact |
| 3 | `ICMP-WG`       | ICMP echo  | WG      | tag in sealed payload; see ICMP caveat        |
| 4 | `ICMP-SOCKS5`   | ICMP echo  | SOCKS5  | tag inside frame; per-frame flush intact; see caveat |
| 5 | `ICMPv6-WG`     | ICMPv6     | WG      | tag in sealed payload; see ICMP caveat        |
| 6 | `ICMPv6-SOCKS5` | ICMPv6     | SOCKS5  | tag inside frame; per-frame flush intact; see caveat |

ICMP/ICMPv6 are **not** compromised: their latency tuning lives in the
SOCKS5 per-frame-flush and the WG `connect()`-ed egress — none of which a
2-byte payload prefix touches. All ports still share **one** ICMP flow (one
identifier), demuxed from the tag after verification.

### 4.1 Honest ICMP caveat

Running many high-bandwidth services over a **low-rate ICMP stealth
fallback** is rarely useful — ICMP is the path of last resort when both UDP
and TCP are filtered, and it is deliberately throttled. Multi-port still
works *correctly* on the ICMP rows and all latency tuning is preserved, but
the aggregate of several services is bounded by the same low ICMP rate as a
single service. Additionally, on every row the tag costs 2 bytes of usable
application MTU (the drop check still measures the *untagged* body). On the
already-tight ICMP path that 2 bytes is the most noticeable, though still
negligible against a ~1400-byte payload — and there is **no correctness
impact**. We document it; we do not pretend it is free.

## 5. Data model / config contract

### 5.1 DB (SQLite) — migration `0010_multiport.sql`

A single new column on the `tunnels` table:

```sql
ALTER TABLE tunnels ADD COLUMN ports TEXT NOT NULL DEFAULT '';
```

- Stores a comma-separated list of port numbers, e.g. `'51820,443,9993'`.
- **Empty string = legacy single-port.** The one port stays in
  `local_listen_addr` (Client) / `forward_target` (Remote) exactly as today;
  the data plane behaves identically to v2.4.0.
- **Non-empty = multi-port.** It is the *full authoritative list* of app
  ports, **including** the primary port that also appears in
  `local_listen_addr` / `forward_target`. The bind host is taken from
  `local_listen_addr` (Client) / `forward_target` (Remote). The list applies
  identically on both roles (1:1 same-number).

The tunnel **channel** (`download_send_port` / `download_receive_port` /
spoof ports) is **unchanged** and shared by all app ports. Only the app
traffic ports multiply.

### 5.2 API JSON (frontend ↔ Go) — field `ports`

```json
"ports": [51820, 443, 9993]
```

An array of integers. Absent or `[]` = single-port. On read the Go API
returns the parsed array (or `[]`); on create/update it accepts the array.
The PSK is still returned as the literal `"***"`; the port list carries no
secrets.

### 5.3 IPC `TunnelSpec` (Go → Rust) — field `ports`

```json
"ports": [51820, 443, 9993]
```

`omitempty`. Go type `[]uint16`; Rust type `Vec<u16>` (serde `default` →
empty). Absent/empty = single-port.

### 5.4 Semantics shared by every layer

- `len(ports) == 0` ⇒ single-port legacy path, **no tag**, wire-identical.
- `len(ports) >= 2` ⇒ multi-port: tag active, one app socket bound per port.
- The panel never produces a 1-element `ports` (one port = single-port ⇒
  empty `ports`). The dataplane defensively treats `len <= 1` as
  single-port.

### 5.5 Validation (Go, source of truth)

When `len(ports) > 0`:

- Each port in `1..=65535`; **no duplicates**; `len(ports) <= 32`
  (`MaxPortsPerTunnel = 32`); friendly per-field error messages.
- The **canonical** port (the port of `local_listen_addr` for the Client
  role / of `forward_target` for the Remote role) **must** be a member of
  `ports`.
- The existing cross-tunnel, same-role port-overlap check is generalised
  from one port to the *set* of ports a tunnel occupies (canonical port ∪
  `ports`): two enabled tunnels of the same role may not share **any** port.
- The matrix rules (`download_transport × upload_mode/listen_mode`) are
  unchanged and still apply to multi-port tunnels.

## 6. Panel UX

`TunnelForm.vue` keeps the existing single-port fields (`local_listen_addr`
/ `forward_target`) **as-is** for the common case, and adds one **optional**
field — *"Additional ports (multi-port)"* — a single comma-separated text
input (e.g. `443, 9993`). Inline plain-language helper text:

> Leave blank for a normal single-port tunnel. To carry several services
> over this one tunnel, list the **extra** port numbers here,
> comma-separated. The same port numbers are used on both the Iran and
> foreign side (client `:443` ↔ remote `:443`). The main port above is
> always included automatically.

Client-side validation mirrors the backend: each entry an integer
`1..65535`, no duplicates, not equal to the main port, total ports
(main + extras) `<= 32`; a friendly inline error disables submit on invalid
input. On submit, if the extras field is non-empty the form sends
`ports = sorted-unique([mainPort, ...extras])`; otherwise it omits `ports`
(single-port). On edit, the extras input is derived as
`tunnel.ports` minus the main port (blank if `tunnel.ports` is empty).

`TunnelCard.vue` (and the detail page) show a small badge such as
`Ports: 51820, 443, 9993` for a multi-port tunnel, using the existing badge
styling. **Stats stay aggregate** — there are no per-port stats.

## 7. Migration & peer compatibility

- **Schema:** `0010_multiport.sql` adds the one column with a safe default
  (`ports TEXT NOT NULL DEFAULT ''`). No backfill is required — an empty
  `ports` is treated as single-port via the legacy `local_listen_addr` /
  `forward_target` port.
- **Existing single-port tunnels are untouched** and require **zero operator
  action.** They keep the exact same wire framing.
- **No wire break.** A v2.5.0 ↔ v2.4.0 mixed pair interoperates perfectly
  for every single-port tunnel, so the two ends may be upgraded
  independently. Multi-port simply requires both ends to be ≥ v2.5.0 before
  a tunnel is reconfigured to carry multiple ports.
- **Version:** `v2.5.0` — a backward-compatible feature addition is a MINOR
  bump.

## 8. Worked example — a 3-port tunnel

An operator runs a Client box on a white IP `203.0.113.10` and a Remote box
`198.51.100.20`, and wants one tunnel to carry three services with the fixed
1:1 same-number mapping:

| Service                | App port | Tag bytes (BE u16) |
|------------------------|----------|--------------------|
| WireGuard              | `51820`  | `0xCA 0x6C`        |
| VLESS / Reality (TLS)  | `443`    | `0x01 0xBB`        |
| A third UDP service    | `9993`   | `0x27 0x09`        |

Config (shared out of band, exactly like the PSK):

```
tunnels.ports = "51820,443,9993"     # same list on Client and Remote
```

On download, the Remote crafts a spoof packet (UDP / TCP-SYN / ICMP per the
tunnel's `download_transport`) from white source `203.0.113.10`, sealing the
payload `[2 app_port][body]` inside the HMAC envelope. The Client verifies
the HMAC, reads the 2-byte tag, confirms the port is in `{51820, 443, 9993}`
(otherwise drop + rate-limited warn), and delivers `body` to the app socket
bound to that port. On upload, the Client prepends the tag for the
originating app port before the bytes cross the WireGuard or SOCKS5 upload
substrate; the Remote decodes the tag, validates it, and forwards `body` to
`forward_target`'s host on that same port. Replies from services on
`example.com`'s side flow back over whichever of the six mechanisms the
tunnel is configured for.

A single-port tunnel on the same pair of boxes emits **no tag** and is
byte-identical to v2.4.0.

## 9. Invariants preserved (checklist)

- [x] **HMAC authentication** on every download packet — unchanged; the tag
      is inside the hashed payload, so it is authenticated for free.
- [x] **`PROTO_VERSION` stays 2** — no envelope-framing change for any
      existing configuration; `OVERHEAD` unchanged.
- [x] **Single-port wire byte-identical to v2.4.0** — every tag add/strip is
      gated on "is multi-port".
- [x] **Anti-replay `SeqWindow` (1024 slots)** — one seq stream + one window
      per *tunnel*, not per port. All ports multiplex onto the single
      monotonic `seq`; the port is demuxed *after* verify. No per-port
      windows or per-port `session_id`s.
- [x] **Parallel-seal → single `sendmmsg`** (PR#36) — seal workers seal the
      already-tagged payload; the single send worker preserves wire order.
- [x] **Random `session_id`** (not wall clock) — one `session_id` per
      tunnel, unchanged.
- [x] **DF-bit cleared on spoofed egress** — transports untouched.
- [x] **fwmark + ip-rule priority for WG** — one fwmark per tunnel; all
      ports share the one WG upload egress.
- [x] **64 KiB recv-buffer floor + per-core verify fan-out** — fan-out still
      routes by `seq % n_workers`; the tag is read after verify.
- [x] **TCP keepalive + `TCP_USER_TIMEOUT` on SOCKS5** — unchanged.
- [x] **PSK never leaks** — REST returns `"***"`; logs and the audit log
      never print it; the port list carries no secrets.
- [x] **No inter-server control plane** — multi-port is derived from shared
      static config; nothing negotiated on the wire.
- [x] All v2.1.0 stability, v2.2.0 buffers, v2.3.0 dashboard, v2.4.0
      striping — unchanged.
