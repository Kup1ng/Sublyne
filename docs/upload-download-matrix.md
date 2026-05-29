# Upload × Download mechanism matrix (v2.0.0)

> Status: implemented in the `upload-download-matrix` branch. Wire-format
> breaking — Client and Remote must both run v2.0.0+. See
> [§7 Migration](#7-migration--peer-compatibility).

## 1. Motivation

Until v1.0.x the **upload** path (Client → Remote) and the **download**
path (Remote → Client) were fully orthogonal:

- Download transport ∈ `{udp, tcp_syn, icmp, icmpv6}` — the spoof envelope
  the Remote forges on the return path.
- Upload mode ∈ `{wireguard, socks5}` — how the Client ferries the
  end-user's UDP to the Remote's `forward_target`.

Any combination was accepted, and the upload path was "one size fits
all": the SOCKS5 path always force-flushed one datagram per TCP write
(`TCP_NODELAY=on`, one `write_all` per frame) regardless of whether the
inner traffic was a latency-sensitive trickle or a bulk stream. That is
correct for a low-rate ICMP fallback but **wrong for a bulk TCP tunnel**,
where it pins one UDP datagram to one TCP segment and wastes the stream.

v2.0.0 makes the **upload path a function of the download transport**. The
download transport encodes the operator's *regime*:

| download | regime | upload should be |
|----------|--------|------------------|
| `udp`    | max throughput, lowest overhead | **WireGuard**, native UDP |
| `tcp_syn`| most DPI-resilient, bulk reliable | **SOCKS5**, real TCP stream |
| `icmp`   | stealth fallback (UDP+TCP filtered), low-rate, latency-fragile | **WireGuard or SOCKS5**, latency-tuned |
| `icmpv6` | same as ICMP, IPv6 path | **WireGuard or SOCKS5**, latency-tuned |

## 2. The matrix

```
 download transport │ allowed upload modes        │ default
────────────────────┼─────────────────────────────┼──────────
 udp                │ wireguard                   │ wireguard
 tcp_syn            │ socks5                      │ socks5
 icmp               │ wireguard, socks5           │ wireguard
 icmpv6             │ wireguard, socks5           │ wireguard
```

Remote side mirrors via `upload_listen_mode`:

```
 download transport │ allowed listen modes        │ default
────────────────────┼─────────────────────────────┼──────────
 udp                │ udp                         │ udp
 tcp_syn            │ socks5_tcp                  │ socks5_tcp
 icmp               │ udp, socks5_tcp             │ udp
 icmpv6             │ udp, socks5_tcp             │ udp
```

`wireguard` upload pairs with `udp` listen; `socks5` upload pairs with
`socks5_tcp` listen. The operator is responsible for symmetry (PRD §2.3,
no inter-server control plane); each panel enforces its own half.

## 3. The six mechanisms

There are two upload **substrates** — they are the only two ways to move
bytes Client → Remote, so "six mechanisms" means six *named, tuned
configurations*, not six transports:

- **WG substrate** — kernel UDP egress, `SO_MARK = fwmark`, routed through
  the seller's WireGuard interface. Native UDP, no framing.
- **SOCKS5 substrate** — N parallel TCP connections to a load-balancing
  proxy, per-session sticky routing, decoupled per-slot driver tasks.

Each `(download, upload)` cell selects a substrate **plus** a
`MechanismProfile` that changes real runtime behaviour:

| # | Mechanism      | Substrate | Wire            | Profile knobs (the real differences) |
|---|----------------|-----------|-----------------|--------------------------------------|
| 1 | `UDP-WG`       | WG        | native UDP      | `connect()`-ed egress, max `SO_SNDBUF`, single send — the throughput lane |
| 2 | `TCP-SOCKS5`   | SOCKS5    | length-framed **stream** | **Nagle ON + drain-queue coalesced write** (fills TCP segments), standard keepalive |
| 3 | `ICMP-WG`      | WG (v4)   | native UDP      | `connect()`-ed egress, single send, latency regime |
| 4 | `ICMP-SOCKS5`  | SOCKS5    | length-framed   | **Nagle OFF + per-frame flush** (latency), **aggressive keepalive** |
| 5 | `ICMPv6-WG`    | WG (v6)   | native UDP      | as `ICMP-WG`, IPv6 egress |
| 6 | `ICMPv6-SOCKS5`| SOCKS5    | length-framed   | as `ICMP-SOCKS5`, IPv6 |

The substantial, load-bearing tuning lives on the SOCKS5 substrate
(**coalesce vs per-frame**, **keepalive aggressiveness**) where it
genuinely moves the needle, and on the WG substrate's `connect()`
optimization. The WG pairs (`UDP-WG`, `ICMP-WG`, `ICMPv6-WG`) share the
proven kernel-UDP egress because WireGuard is already optimal for all
three; the matrix's job there is **correctness + pairing**, and the
mechanisms remain first-class (named, validated, surfaced, logged) so the
operator always sees exactly which of the six is running.

### 3.1 Why coalescing is "real TCP semantics"

The application traffic is always UDP (PRD invariant), so a stream
transport MUST length-delimit datagrams to recover them on the far side —
the `[u16 BE len][payload]` framing is unavoidable and stays. What was
*wrong* for the TCP case is treating each datagram as an
independently-flushed, latency-critical unit (`TCP_NODELAY=on`, one write
per frame). `TCP-SOCKS5` instead lets the hop behave like a real TCP
byte-stream: Nagle is left **on**, and the slot driver **drains its whole
queue and writes all pending frames in one `write_all` per wake-up**, so
TCP segments fill. The Remote decoder is unchanged — `read_exact` already
reads frames across segment boundaries — so coalescing is a pure
Client-side win that needs no Remote change.

This preserves the SOCKS5 stability invariants verbatim: the hot path
still does a non-blocking `try_send` onto the slot queue (recv loop never
blocks on a write), per-session sticky routing keeps each flow on one
slot in order, and `TCP_USER_TIMEOUT` + keepalive remain the dead-peer
detector.

## 4. Wire format (v2)

### 4.1 Download HMAC envelope — `proto_ver` prefix

The only authenticated channel that crosses servers is the spoofed
download path. To make a version mismatch **detectable** (there is no
control plane to ask the peer its version), v2 prepends a 1-byte
`proto_ver` to the sealed envelope and folds it into the HMAC:

```
v1:  [16 HMAC][8 session_id][8 seq][N payload]
v2:  [1 ver][16 HMAC][8 session_id][8 seq][N payload]
     HMAC = HMAC-SHA256(psk, ver ‖ session_id ‖ seq ‖ SHA256(payload))[..16]
```

`OVERHEAD` grows 32 → 33. `ver` is cleartext (so a receiver can read it
before HMAC) **and** authenticated (so it can't be forged to downgrade).
On the Client open path:

- `ver != PROTO_VERSION` → `OpenError::Version`, logged WARN once-per-rate
  ("download packets carry protocol vN; this build speaks vM — upgrade
  both Sublyne servers to the same release"), packet dropped.
- otherwise → existing HMAC + SeqWindow checks, unchanged.

Anti-replay (`SeqWindow`, 1024 slots) and the random-`session_id` design
are untouched — only the bytes the HMAC covers grew by one.

### 4.2 SOCKS5 upload framing

Unchanged on the wire (`[u16 BE len][payload]`); only the Client write
*strategy* differs per mechanism (coalesce vs per-frame). No Remote
decoder change.

### 4.3 Why the peer check lives in the HMAC byte, not IPC `Ready`

The version mismatch that actually matters is **between the two servers**
(Client ↔ Remote) — and those never share a control channel (PRD §2.3),
so the only place to detect it is in the bytes that cross between them:
the download HMAC envelope's `proto_ver` byte (§4.1). The Go↔Rust IPC
`Ready` event is a *within-binary* hello — Go and Rust are compiled and
shipped together in one artifact, so they can never legitimately
disagree on the protocol version, and there is no scenario where one
upgrades without the other. Adding a refuse-on-mismatch gate there would
guard nothing real, so v2 deliberately does **not** touch the IPC `Ready`
path. The cross-server check is the HMAC byte, full stop.

## 5. Enforcement & policy split

Policy lives in Go; the dataplane stays migration-tolerant.

- **Go `tunnels.Validate` (source of truth, hard error on create/update).**
  Rejects any tunnel whose `(download_transport, upload_mode)` (Client) or
  `(download_transport, upload_listen_mode)` (Remote) is not in the matrix,
  with a per-field message the panel renders under the offending input. An
  operator can no longer *author* an off-matrix tunnel.
- **Go Start / Sync — unchanged, no matrix gate.** A row that predates v2
  and happens to be off-matrix still starts after an upgrade, so a deploy
  never dead-tunnels a working pair. The operator fixes it on the next
  edit, guided by the panel.
- **Rust dataplane — computes the mechanism and *warns* if off-matrix, but
  runs.** The dataplane never hard-refuses on the matrix (that would break
  the Sync-of-legacy-rows path above); its existing internal-consistency
  checks (`ConflictingUploadPaths`, half-configured auth, family/transport
  match) are unchanged.

## 6. Panel UX

`TunnelForm.vue`:

- A pure `uploadMatrix` helper (unit-tested) maps download → allowed
  upload modes + default.
- Picking a download transport restricts the upload-mode select to the
  allowed set, auto-selects the row default if the current choice is no
  longer valid, and disables (grays out) invalid options with a tooltip.
- A compact matrix legend + inline helper text explains the rule
  ("UDP → WireGuard · TCP-SYN → SOCKS5 · ICMP/ICMPv6 → either").
- The Remote form restricts `upload_listen_mode` the same way.

## 7. Migration & peer compatibility

- **Schema:** `0009_upload_matrix.sql` — adds no columns (the matrix is a
  constraint *between* existing columns). It performs only the single
  provably-safe normalization: a Remote row whose `download_transport='udp'`
  can only ever pair with a UDP listener, so any such row is set to
  `upload_listen_mode='udp'`. It deliberately does **not** rewrite a
  Client's `upload_mode` (flipping `socks5`→`wireguard` would silently
  strip a proxy link; flipping `wireguard`→`socks5` has no proxy to point
  at) — those are surfaced to the operator by the panel + Go validator on
  the next edit. No working tunnel is reassigned.
- **Wire break:** the `proto_ver` envelope byte means a v1 Remote's
  download packets fail to validate on a v2 Client (and now with a
  *diagnosable* WARN, not a silent drop). Both sides must upgrade
  together.
- **Version:** `v2.0.0` — a post-1.0 wire-format break is a MAJOR bump.

## 8. Invariants preserved (checklist)

- [x] Anti-replay `SeqWindow` (1024 slots) — unchanged logic, +1 HMAC byte.
- [x] HMAC authentication — `ver` folded into the tag.
- [x] Parallel-seal → single-send wire ordering (PR#36) — download side
      untouched.
- [x] SOCKS5 stability (per-slot queue, decoupled driver, write backstop,
      keepalive + `TCP_USER_TIMEOUT`, warm-up gate) — coalescing lives
      inside the existing driver drain loop.
- [x] Clock-independent HMAC (`session_id`) — unchanged.
- [x] DF-bit cleared on spoof packets — transports untouched.
- [x] fwmark / ip-rule priority — WG egress untouched; `connect()` is
      applied *after* `SO_MARK`, so the cached route is still the
      fwmark-steered one.
- [x] Per-session sticky routing — unchanged.

## 9. Bug fixed in passing

`client.rs::peek_seq` read the **session_id** (`[16..24]`) instead of the
**seq** (`[24..32]`), so the download-verify fan-out routed every packet
to one worker (`session_id % N` is constant). v2 fixes the offset (now
accounting for the `proto_ver` prefix) so the fan-out actually parallelises
across workers as its design comment always claimed.
