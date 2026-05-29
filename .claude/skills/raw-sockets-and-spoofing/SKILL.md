---
name: raw-sockets-and-spoofing
description: Crafting and sending spoofed UDP / TCP-SYN / ICMP / ICMPv6 packets in the Rust data plane, parsing them on receive, computing checksums, verifying the HMAC envelope, and handling kernel capability requirements. Covers the four download transports.
when_to_use: Phase 8 (UDP transport + HMAC), Phase 9 (TCP-SYN / ICMP / ICMPv6 transports), Phase 10 (multi-tunnel dual-stack). Read before touching anything in `data-plane/src/transport/` or `data-plane/src/hmac.rs`.
---

## What "download spoofing" means here

The PRD's anti-censorship trick:

1. The end user's device sends a request packet via Client → WG upload
   → Remote → real proxy target. This part is normal — encrypted WG
   on the way out of Iran.
2. The proxy responds. Remote receives the response and re-encapsulates
   it as a **spoofed packet**: source IP = the operator-configured
   "white IP" (an IP whitelisted by Iran's central firewall), source
   port = configured, destination = the Client server's real IP and a
   pre-arranged download port, transport = one of {UDP, TCP-SYN, ICMP,
   ICMPv6}.
3. The Iranian DPI sees an incoming packet "from a trusted source" and
   forwards it to Client.
4. Client's raw socket on the download port receives the packet,
   verifies the HMAC envelope, and delivers the payload back to the
   end user's original UDP socket.

**This requires raw sockets that can forge the source IP.** Linux
allows this when the process has `CAP_NET_RAW`. Some hypervisors
silently drop egress packets with a foreign source IP — see "VPS
reachability" below.

## Capabilities

The systemd unit grants both capabilities ambient:

```
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
```

- `CAP_NET_RAW` — open raw sockets, set `IP_HDRINCL`, forge headers.
- `CAP_NET_ADMIN` — needed for `wgctrl`, `netlink`, and setting
  `SO_MARK`. Not strictly needed for raw sockets, but the same
  process needs it anyway.

We do **not** run as root. Capabilities are dropped to just these two.

## HMAC envelope

Every download payload — regardless of transport — is prefixed with a
**16-byte HMAC** computed as:

```
hmac_full = HMAC-SHA256(psk, session_id || sequence_number || payload_hash)
hmac      = hmac_full[0..16]                            // first 16 bytes
```

Where:
- `session_id` — `u64` big-endian, random non-zero value read from
  `/dev/urandom` **once per Remote spoof-pipeline spawn** and reused for
  every packet that pipeline seals. The Client (receiver) uses this to
  detect that the Remote restarted (`session_id` changes → reset the
  sliding seq window).
- `sequence_number` — `u64` big-endian, monotonic per (tunnel, sender direction).
- `payload_hash` — SHA-256 of the unencrypted forwarded payload.
- `psk` — the per-tunnel pre-shared key, exactly 32 bytes (we expand
  user-supplied PSKs to 32 bytes via HKDF-SHA256 if they're shorter).

Wire layout of the **inner spoof body** (what rides inside the L4
envelope):

```
+----+----------------+----+--------------------+
| 16 |       8        |  8 |        N           |
+----+----------------+----+--------------------+
|HMAC|   session_id   |seq |   forwarded UDP    |
|    |   (random,     |    |   payload bytes    |
|    |   per-Remote-  |    |                    |
|    |   startup)     |    |                    |
+----+----------------+----+--------------------+
   16                24   32                  32+N

Total overhead: 32 bytes (16 HMAC + 8 session_id + 8 seq).
```

The receiver:
1. Drops packet if source IP / port don't match the configured spoof
   source.
2. Reads session_id, seq, payload.
3. Computes `expected = HMAC-SHA256(psk, session_id || seq || SHA256(payload))[0..16]`
   and constant-time-compares with the received HMAC.
4. If the receiver's stored session_id for this tunnel differs from
   the incoming one (first packet ever, OR Remote restarted): reset
   the sliding seq window and accept this packet as the new
   high-water mark. The internal session_id is updated.
5. If session_id matches the stored one: drop if
   `seq <= last_seq_for_this_sender - window` (replay slide window;
   1024 logical slots backed by a 128-bit bitmap). Drop if seq
   already marked.
6. Updates `last_seq`, hands payload to the session demux.

This matches PRD §3.4 with one deliberate evolution: **wall-clock
`ts` is no longer in the envelope.** Earlier rounds used a
±60s timestamp window for replay protection; that silently broke every
Iranian client whose NTP was blocked (RTC drifted ~hours, every
download dropped at INFO/DEBUG with no operator-visible log). Replacing
`ts` with a per-startup random `session_id` decouples the protocol
from the wall clock entirely. See `data-plane/src/hmac.rs` module docs
for the threat-model rationale; the short version is that HMAC + PSK
remains the actual security guarantee, replay protection only prevents
bandwidth waste, and a cross-session replay window (which the new
design has and the old one didn't) is bounded by the inner WireGuard
session's own replay counter.

The 16-byte truncation is intentional — HMAC-SHA256 has 256 bits of
security and we only need ~80 effective bits for our threat model
(forged packet injection by network-level attackers), so 128-bit
truncation is plenty.

Reference implementation in `data-plane/src/hmac.rs`:

```rust
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const HMAC_LEN: usize = 16;
pub const SESSION_ID_LEN: usize = 8;
pub const SEQ_LEN: usize = 8;
pub const OVERHEAD: usize = HMAC_LEN + SESSION_ID_LEN + SEQ_LEN;

pub fn seal(psk: &[u8; 32], session_id: u64, seq: u64, payload: &[u8], out: &mut Vec<u8>) {
    let mut h = HmacSha256::new_from_slice(psk).expect("psk len");
    let mut payload_hash = Sha256::new();
    payload_hash.update(payload);
    let payload_hash = payload_hash.finalize();

    h.update(&session_id.to_be_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&payload_hash);
    let tag = h.finalize().into_bytes();

    out.clear();
    out.reserve(OVERHEAD + payload.len());
    out.extend_from_slice(&tag[..HMAC_LEN]);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
}

pub fn open<'a>(
    psk: &[u8; 32],
    body: &'a [u8],
    seq_window: &mut SeqWindow,
) -> Option<&'a [u8]> {
    if body.len() < OVERHEAD { return None; }
    let (hdr, payload) = body.split_at(OVERHEAD);
    let tag = &hdr[..HMAC_LEN];
    let session_id = u64::from_be_bytes(hdr[HMAC_LEN..HMAC_LEN+SESSION_ID_LEN].try_into().unwrap());
    let seq = u64::from_be_bytes(hdr[HMAC_LEN+SESSION_ID_LEN..].try_into().unwrap());

    let mut h = HmacSha256::new_from_slice(psk).ok()?;
    let mut ph = Sha256::new();
    ph.update(payload);
    h.update(&session_id.to_be_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&ph.finalize());
    let expected = h.finalize().into_bytes();
    if !constant_time_eq::constant_time_eq(tag, &expected[..HMAC_LEN]) {
        return None;
    }

    // Switches windows on new session_id (Remote restart); otherwise
    // checks the 128-bit sliding seq bitmap.
    if !seq_window.check_and_set(session_id, seq) { return None; }
    Some(payload)
}
```

`SeqWindow` is a 1024-logical-slot (128-bit bitmap) sliding window per
(tunnel, current session_id). When the receiver sees a packet with a
different session_id that passes HMAC, the window resets to the new
session's seq — that is the "Remote restarted" signal that used to come
from the timestamp going forward.

## Transport 1 — UDP envelope

Simplest. Send:

```
+--------+--------+--------+----------------+
| IPv4/v6| UDP    | seal(  | forwarded UDP  |
| header | header | psk,   | payload        |
| (forged|        | seq,ts,|                |
| src=WL)|        | hash)  |                |
+--------+--------+--------+----------------+
```

Open a raw socket with `IP_HDRINCL` and write the IPv4 header
ourselves; or use the `socket2` crate's `Socket::new(Domain::IPV4,
Type::RAW, Some(Protocol::UDP))` with `set_header_included(true)`.

UDP header layout (RFC 768):

```
+--------+--------+--------+--------+
| sport  | dport  | length | check  |
+--------+--------+--------+--------+
```

Checksums:
- IPv4 header checksum (header bytes only, 16-bit one's-complement
  sum).
- UDP checksum is **computed over a pseudo-header** (src, dst, proto,
  UDP length) + UDP header + payload. IPv4 UDP checksum may be 0
  (meaning "not computed") but we always compute it — some Iranian DPI
  drops zero-checksum UDP.
- IPv6 UDP checksum is **mandatory** (RFC 8200) and uses the IPv6
  pseudo-header.

Use the `pnet` / `pnet_packet` crate for header building, or hand-roll
— the layout is small.

## Transport 2 — TCP-SYN envelope

The download payload rides as a **fake TCP SYN** packet. No real
handshake; the receiver just parses the payload out of TCP
options/payload region.

Wire layout we use:

```
+--------+----------------------+--------+----------+
| IP hdr | TCP hdr (SYN flag,   | TCP    | payload  |
|        | sport=spoof_src_port,| options| (seal()) |
|        | dport=download_port) | (NOPs) |          |
+--------+----------------------+--------+----------+
```

Specifically:
- TCP `data_offset` (4-bit) set to point past the header into the
  payload region.
- `flags = SYN`. The seq number in the TCP header is **not** our HMAC
  seq — it's a random TCP-looking value (DPI heuristic: SYN with
  seq=0 is suspicious). Our HMAC seq is inside the payload.
- The payload follows the TCP header directly. DPI sees "TCP SYN with
  some data after the header" which is unusual but not rejected.

TCP checksum is mandatory and uses the same pseudo-header construction
as UDP.

Why SYN, not ACK or PSH-ACK? SYN is the smallest stateful-looking
packet; firewalls allow new SYNs from whitelisted IPs without needing
a matching SYN-ACK from us. PSH-ACK would expect a TCP session in
progress.

On the receive side: open `SOCK_RAW` with protocol = `IPPROTO_TCP`.
The kernel delivers every TCP packet to us (and *also* to its own
stack, which sees an unsolicited SYN and would normally reply with
RST). To prevent the kernel RST, install an `iptables` / `nftables`
rule on install:

```
iptables -t raw -A PREROUTING -p tcp --dport <download_port> -j NOTRACK
iptables -A INPUT -p tcp --dport <download_port> -j DROP
```

(The DROP is fine; we've already received via raw socket. We just
don't want the kernel ACKing back.)

Document the firewall rule in the install path. Phase 9 ships the
script.

## ICMP echo direction — `icmp_echo_mode` (Phase R4)

Phase 8b shipped ICMP as a single wire shape: type 0 (echo-reply) on
v4, type 129 on v6. That works on loopback (the cargo loopback tests
pass) but **fails completely on the real Iran ↔ foreign path** —
Iranian inbound filters drop unsolicited echo-replies before they ever
reach the host. Phase R4 adds a per-tunnel `icmp_echo_mode` field with
two values:

- `reply` (Phase 8b default, kept for back-compat): type 0 / 129.
- `request` (Phase R4): type 8 / 128, with `net.ipv4.icmp_echo_ignore_all=1`
  flipped on the **Client** side for the receiver's lifetime so the
  kernel doesn't auto-reply to every incoming spoofed echo-request.

Plumbing:

- DB column `tunnels.icmp_echo_mode` (`0005_icmp_echo_mode.sql`).
- IPC `TunnelSpec.icmp_echo_mode` (`omitempty`; Rust side defaults to
  `Reply` via serde).
- `data-plane/src/transport/icmp.rs::{build_packet,parse_inbound}` and
  the ICMPv6 equivalents both take an `IcmpEchoMode` argument; the
  parser rejects packets whose wire type doesn't match.
- `data-plane/src/icmp_sysctl.rs` is the reference-counted Drop guard.
  Installed only when (role=Client AND transport in {icmp, icmpv6} AND
  mode=Request). Restores the original value on Stop. Sharing the guard
  across overlapping tunnels is handled by the refcount.
- `data-plane/src/icmp_id.rs::pick_identifier(tunnel_id)` returns a
  16-bit value picked per tunnel start. It's logged at INFO and shows
  up in `tcpdump` as `id <NNNN>` so an operator can correlate on-wire
  traffic with a specific tunnel.
- The Client filter at `tunnel/client.rs::spawn_v4_recv_loop` and
  `spawn_v6_recv_loop` **skips** the `src_id == spoof_port` check for
  ICMP / ICMPv6 transports because the identifier is randomised — the
  HMAC envelope is the authentication, the spoof IP filter still
  applies.
- Switching `icmp_echo_mode` on a live tunnel does an **internal
  restart** (`SpecSnapshot::internal_restart_field_differs`) so the
  sysctl guard cleanly drops and re-installs.

Tests + evidence:

- `cargo test -p sublyne-dataplane transport::icmp::` and
  `transport::icmpv6::` cover both modes + reject-cross-wire-type.
- `tests/perf/icmp-on-real-path.md` — packet-capture evidence that
  type-0 echo-replies are dropped upstream of Iran.
- `tests/perf/icmp-comparison.md` — A/B numbers on the live link.
  Reply mode = 0 % delivered; Request mode = 99.3 % delivered at the
  5 Mbit/s test rate.

## Transport 3 — ICMP echo (v4)

Wire layout (R4: either echo-reply type 0 OR echo-request type 8;
the type byte is the only on-wire difference between modes):

```
+--------+-----------+----------+
| IP hdr | ICMP hdr  | payload  |
|        | type=0    | (seal()) |
|        | code=0    |          |
|        | id=spoof  |          |
|        | seq=...   |          |
+--------+-----------+----------+
```

ICMP header (RFC 792):

```
+--------+--------+--------+
| type=0 | code=0 | check  |
+--------+--------+--------+
|       id        |  seq   |
+--------+--------+--------+
```

`id` is set to `spoof_source_port` (so the field doubles as a
"identifier" the receiver can sanity-check). `seq` is unused by ICMP
semantics but Iranian DPI sometimes inspects it; we set a sequential
value (separate counter from the HMAC seq).

ICMP checksum is one's-complement over the entire ICMP message
(header + payload).

Receiver opens `SOCK_RAW` with `IPPROTO_ICMP`.

Kernel suppression: similar to TCP, the kernel may respond to ICMP
echo-requests with replies on its own. We're sending replies (type 0),
so this is less of an issue — but disable kernel echo-reply for the
download port range anyway via:

```
sysctl net.ipv4.icmp_echo_ignore_all=1   # too aggressive; do not use
```

Don't actually set that — it breaks regular ping. Instead, we accept
that the kernel sees our spoofed echo-replies as orphan (no matching
echo-request) and ignores them. The raw socket gets them either way.

## Transport 4 — ICMPv6 echo-reply

Same as v4 but type 129 and `AF_INET6`. The ICMPv6 checksum is
mandatory and includes an IPv6 pseudo-header (RFC 4443).

ICMPv6 raw socket:

```rust
let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
sock.set_header_included_v6(true)?;
```

ICMPv6 headers are functionally similar (type, code, checksum, identifier,
sequence) but the encoding rules and pseudo-header are different — be
careful not to copy v4 logic by accident.

## Checksum routines

Internet checksum (one's-complement 16-bit sum) reference:

```rust
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
```

Pseudo-header for UDP/TCP IPv4 checksum:

```
+-------------+-------------+
| src IP (4)  | dst IP (4)  |
+--+----------+-------------+
| 0| protocol |  length     |
+--+----------+-------------+
```

For IPv6, the pseudo-header swaps in 16-byte addresses and a 32-bit
length.

Don't rewrite checksums for every packet from scratch in the hot
path — for outbound spoofing, pre-compute the IP+UDP header bytes
once at session start, then only update the variable fields (length,
checksum) per packet.

## Performance hot-path

> See `tests/perf/baseline-v0.1.x.md` for the live evidence — which
> dataplane fd ends up where in `ss -anpem`, what `Recv-Q` looks like
> on the undrained raw `IPPROTO_UDP` socket (fd=15), and the
> per-direction throughput ceiling we're trying to lift. The capture
> script + the Python UDP tool the perf phases use live in
> `tests/perf/`. Re-run with `tests/perf/capture_baseline.sh` against
> any new build.

- **`SO_REUSEPORT`** on the raw receive socket: open N sockets
  (N = number of cores), each gets a kernel-load-balanced share of
  incoming packets. Per-core thread, no cross-thread synchronization
  on the hot path.
- **`recvmmsg` / `sendmmsg`**: batch 32 messages at a time. Halves
  syscall overhead at 1 Gbps.
- **Per-core session table shard**: hash `(client_addr, local_port)`
  → shard index; each shard is owned by one core, no locking.
- **Zero-copy outbound**: build the full packet into a reusable buffer
  (`bytes::BytesMut`), keep header bytes pre-built, only patch the
  variable fields per packet.
- **`io_uring` and `AF_XDP` deferred to post-v0.1.0.** The combination
  of REUSEPORT + recvmmsg should hit 1 Gbps on a 4-vCPU box.
  Re-evaluate after we have real numbers.

## MTU and fragmentation

- The tunnel's `mtu` (default 1400) is the **inner UDP payload cap**
  enforced by the dataplane. End-user packets larger than this are
  rejected on the upload path with an ICMP fragmentation-needed
  response.
- The 32-byte HMAC envelope eats into the MTU. The actual end-to-end
  payload room is `mtu - 32`.

### Don't set DF on spoofed packets

Earlier drafts of this skill said "always set the DF bit on IPv4".
**Don't.** Production showed it's a silent-black-hole footgun:

- A router along the path with `MTU < wire_size` drops the DF=1
  packet and sends an ICMP "fragmentation needed" reply.
- That reply goes back to the **spoofed source IP** — i.e. the white
  IP, not us. We never see it.
- Result: small payloads survive (Telegram works), anything that
  crosses a low-MTU hop disappears, and operators see throughput
  collapsing under load with no log signal.

Leave the IP flags zero on spoofed packets. Fragmentation costs a
fraction of a percent in throughput and removes the entire failure
mode. The receive side uses `IPPROTO_UDP` raw sockets, which see
fully reassembled datagrams.

### Recv buffer size: never use `mtu` as the buffer length

The kernel's UDP `recv_from` truncates oversized datagrams to
`buf.len()` and returns the **truncated** length — there's no error
flag (Rust's std-lib doesn't surface `MSG_TRUNC`). Sizing the recv
buffer to the tunnel's `mtu` (e.g. 1400) silently corrupts every
WireGuard packet: the WG AEAD tag sits at the tail of the datagram,
gets clipped, and the downstream server drops the packet.

Production symptom: tiny messages survived, full Google search
pages disappeared, speed-test collapsed to ~4 Mbit/s. Fixed by
sizing every recv buffer to `MAX_UDP_DATAGRAM = 65536` (the IPv4
UDP payload ceiling). Same rule applies on both sides for both the
upload listener and the forward-target socket.

## Receive-side filtering

A raw socket on the download port receives **every** packet on that
port regardless of source. Most will be junk (scans, mistakes,
attackers). The drop filter, in order:

1. Source IP != configured `download_spoof_source_ip` → drop, no log.
2. Source port != configured `download_spoof_source_port` → drop, no log.
3. Transport != configured `download_transport` → drop, no log.
4. Body too short for HMAC envelope → drop, log at DEBUG.
5. HMAC mismatch → drop, log at WARN (real attack signal).
6. New session_id (Remote restart) → reset window, accept (this is
   the path the old timestamp check used to gate; now intrinsic to
   the seq-window).
7. Seq replay within current session_id → drop, log at WARN.
8. Payload accepted → forward to session.

Don't log every drop at INFO; the channel is noisy.

## VPS reachability

Some hypervisors (rare in 2026 but extant) drop egress packets whose
source IP doesn't match the VM's NIC IP — they call this "anti-spoof"
or "MAC-IP binding". Symptoms: the Remote sends spoofed download
packets, but the Client never receives them, and `tcpdump` on Remote
shows the egress packets leaving normally.

Detection: in Phase 15 hardening, add a `sublyne diagnose --spoof`
subcommand that asks Client to listen on the download port, has
Remote send a few test spoofed packets, and reports whether they
arrived. Surface in the panel as a one-click "Test spoof egress"
button.

Mitigation: there isn't one inside our project — the operator must
switch VPS providers or ask the provider to disable anti-spoof. Many
do on request.

## ECN and DSCP

Don't touch these bits in the IP header. Some firewalls inspect DSCP
and our spoofing should match whatever a real connection from the
"white IP" would look like. Set DSCP=0, ECN=0 unless we have a
specific reason to differ.

## Don't do

- **Don't open the raw socket as root.** We have `CAP_NET_RAW` — that's
  enough.
- **Don't use the std-lib `UdpSocket`** for the spoof send path. It
  won't let you forge the source IP. Use raw sockets via `socket2`.
- **Don't trust the source IP** of received packets. Verify against
  configured spoof source AND verify HMAC.
- **Don't log payload bytes.** They're customer traffic. Log only
  metadata (length, src/dst, decision).
- **Don't compute the HMAC over the ciphertext-only or seq-only;
  always include all three components (`seq`, `ts`, `payload_hash`).**
- **Don't reduce the HMAC truncation below 16 bytes** without a
  cryptography review. 16 bytes is the documented minimum.
- **Don't drop the 60-second replay window** to "be more forgiving" —
  60 s is already generous for clock skew across continents.
