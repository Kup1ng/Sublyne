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

## 10. v2.2.0 — SOCKS5 upload window & coalescing (perf, no wire change)

v2.2.0 makes the **bulk TCP-SOCKS5 upload faster** without changing the
model, the matrix, or the wire format. It is a pure performance + tunables
release: a v2.2.0 box interoperates with a v2.1.0 peer and the two servers
can be upgraded independently.

The forwarded payload is **still UDP** for every row (PRD invariant
unchanged), the download still arrives as spoofed white-IP packets, and
the SOCKS5 framing is byte-identical (`[u16 BE len][payload]`). What
changed is purely *how fast the existing SOCKS5 upload moves bytes*:

1. **Socket-buffer / TCP-window sizing (the headline).** The SOCKS5
   substrate sockets were the **only** data-path sockets left on kernel
   defaults — `tune_socks5_tcp_socket` set keepalive + `TCP_USER_TIMEOUT`
   but never `SO_SNDBUF`/`SO_RCVBUF`, and the Remote upload **listener**
   was never tuned at all. Because a TCP socket's advertised receive
   window scale is fixed from its receive buffer **at SYN time**, an
   un-tuned listener could not open a large window no matter the
   bandwidth — the "TCP RWIN" ceiling. v2.2.0 applies the existing forced
   buffer tuning (`perf::tune_socket`, 4 MiB, `SUBLYNE_SOCKET_BUF_BYTES`)
   to the Remote listener **before it accepts** and to the Client's
   outbound stream, so the bulk upload window is large and available from
   the first byte. With `CAP_NET_ADMIN` the `*BUFFORCE` path pins it
   immediately; otherwise it falls back to the `setup.sh`-raised ceiling.

2. **Bulk coalescing is bigger and tunable.** The Coalesce drain's soft
   cap moved from a hard-coded 64 KiB to `perf::socks5_coalesce_bytes()`
   (default **256 KiB**, env `SUBLYNE_SOCKS5_COALESCE_BYTES`, also a panel
   knob). A bursty bulk upload now drains ~4× more queued frames into each
   `write_all`, cutting `write()` syscalls per MB (unit-tested,
   deterministic). The Remote's per-connection `BufReader` grew to 256 KiB
   to match. Only `WriteStrategy::Coalesce` (the TCP-SOCKS5 mechanism)
   reads the cap; the per-frame ICMP/ICMPv6 latency mechanisms are
   untouched.

**Proof.** `data-plane/tests/socks5_window_throughput.rs` runs in a
dedicated CI job under `tc netem` injected RTT with a constrained
`tcp_rmem`: at 50 ms RTT a ~64 KiB autotuned window throttles the un-tuned
path to ~10 Mbit/s while the tuned 4 MiB window sustains hundreds of
Mbit/s. The coalescing win is a separate deterministic unit test
(`coalesce_drain_cuts_writes_per_mb_with_a_bigger_cap`).

**Honest caveat.** The window/buffer win scales with *bandwidth × RTT*:
on a low-latency, well-configured box where TCP autotuning already reaches
a large window, the gain is small. It matters most on high-latency
(Starlink) paths and boxes left on conservative kernel TCP defaults —
which is exactly where the SOCKS5 upload runs. The knobs are exposed so
the operator can tune and measure on real hardware.

### 10.1 Invariants preserved (checklist)

- [x] UDP forwarded payload — every row still forwards UDP; no TCP
      end-to-end forwarding was added.
- [x] Download via white-IP spoof — unchanged on every row.
- [x] SOCKS5 framing `[u16 BE len][payload]` — byte-identical; no wire
      break; independent upgrade.
- [x] SOCKS5 stability (per-slot queue, decoupled driver, warm-up gate,
      sticky routing, `TCP_USER_TIMEOUT`/keepalive, fatal-on-partial-write
      reconnect) — buffer tuning and the larger cap live inside the
      existing driver; the framing-desync reconnect logic is unchanged.
- [x] Anti-replay `SeqWindow`, HMAC, `session_id`, DF-clear, fwmark —
      download path untouched.
- [x] ICMP/ICMPv6-SOCKS5 latency regime (per-frame flush, Nagle off,
      Latency keepalive) — untouched; only the bulk Coalesce path changed.
