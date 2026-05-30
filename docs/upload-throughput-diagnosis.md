# Upload-throughput diagnosis (ASK 2) + fixes

> Status: diagnosis below; **both fixes are now implemented** (operator
> chose "do both") — see [§6](#6-fixes--both-implemented-operator-chose-do-both).
> Backed by the CI benchmark `data-plane/tests/upload_stream_diag.rs`
> (job: *upload stream diagnosis (netem RTT+loss)*) and the deterministic
> `select_primary_stripes_round_robin_vs_sticky` unit test.

## 1. The two anomalies (measured on the live pair)

Iran client 4 vCPU + foreign remote 4 vCPU; Starlink upload ~93 Mbit/s,
RTT ~87 ms via seller WG; SOCKS5 proxy independently ~80 Mbit/s up.

| | udp-wg | tcp-socks5 |
|---|---|---|
| Speedtest UL | **0.32 Mbit/s** | 4 Mbit/s |
| LibreSpeed UL | 9 Mbit/s | 8 Mbit/s |
| (download, for reference) | ~200 / ~120 | ~60 / ~45 |

Two paradoxes: (a) udp-wg upload differs **~28×** between two tools on the
same tunnel; (b) tcp-socks5 upload sits **~10×** below the proxy's own
upload ceiling.

## 2. What it is NOT (ruled out by reading the code)

- **Not the socket buffers.** Every data-path socket — the WG-marked UDP
  egress (`upload/wireguard.rs:189`) and the SOCKS5 TCP sockets incl. the
  listener-before-accept (`socks5.rs`, `remote.rs`, v2.2.0) — is
  force-sized to 4 MiB. The TCP window is not the cap at these rates.
- **Not Sublyne mistreating ACKs.** For an upload, the inner TCP's ACKs
  return over the spoofed download channel. The Remote seal→spoof pipeline
  sends a lone packet **promptly** — no batch-fill wait, no pacing
  (default off), no Nagle on the raw send path; drops are size-agnostic
  (`remote.rs:1034-1056`, verified). So there is no ACK-specific throttle
  inside Sublyne. (ACK loss can still happen on the live *network* — that
  is not a Sublyne defect.)
- **Not (apparently) the MTU oversized-drop — but verify.** The upload
  path silently drops any datagram larger than the tunnel MTU
  (`client.rs:312-317`, `n > mtu.max(64) → warn + continue`; default MTU
  1400). A WG inner MTU of 1420 yields a ~1452-byte datagram that would be
  dropped — which *would* wreck an upload. **However** the same cap guards
  the download path (`remote.rs:854`), and the operator's **download works
  at 200 Mbit/s**, which means their inner packets already fit ≤ MTU — so
  the drop is most likely *not* firing. Treat as a **must-verify**, not a
  confirmed cause: check the app log for `dropping oversized upload packet`.

## 3. Root cause — tcp-socks5 (~4–8 vs ~80 Mbit/s): CONFIRMED structural cap

**A single inner flow is pinned to a single SOCKS5 connection = a single
Starlink uplink.** Verified end-to-end in code:

- The upload listener builds `SessionKey { client_addr: src, local_port }`
  per packet, where `src` is the end-user's source address
  (`client.rs:325-328`).
- For the common case — the inner protocol is **one WireGuard client**, a
  single UDP source — that key is **constant** for all upload packets.
- `primary_slot(session, n)` hashes the key mod N and the send loop tries
  that slot first, only skipping it when unhealthy/full
  (`socks5.rs:670-726`). A healthy single flow therefore lands on **one**
  slot = **one** TCP connection, every packet.
- The N-connection pool parallelises **across distinct flows, never within
  one flow** (`socks5.rs:6-7,198-201`; test
  `sticky_routing_keeps_flow_on_one_connection`).

Since the proxy reaches ~80 Mbit/s by **aggregating multiple Starlink
uplinks** (each new TCP connection lands on a different uplink), a single
flow that uses one connection gets **one uplink's upload share** — and a
single Starlink uplink's upload is roughly the 4–8 Mbit/s observed. The
other N-1 connections sit idle for a single-tunnel user.

**Compounding factor:** the SOCKS5 hop is real TCP over ~87 ms RTT with
Starlink loss, and the boxes run the kernel default **CUBIC** congestion
control (`setup.sh` sets no `tcp_congestion_control`). CUBIC collapses cwnd
hard on loss; a single CUBIC stream on this path is throttled well below
the link rate even ignoring the uplink-share issue.

## 4. Root cause — udp-wg (0.32 vs 9 Mbit/s): TCP dynamics, not a Sublyne cap

udp-wg upload is pure UDP datagram forwarding; Sublyne applies no window
or per-connection rate. The egress socket is buffer-tuned and the single
recv loop is nowhere near its pps ceiling at 9 Mbit/s. So the **28× gap is
not a Sublyne cap** — it is the user's inner TCP flow reacting to the
underlying Starlink seller-WG uplink:

- **Speedtest** drives few (often effectively one dominant) upload
  streams. A single TCP stream on a lossy, bufferbloated, ~87 ms uplink
  collapses — every loss halves cwnd and recovery takes many RTTs — landing
  near **0.32 Mbit/s**.
- **LibreSpeed** drives several parallel streams, which aggregate around
  the **real uplink ceiling (~9 Mbit/s)** — i.e. 9 is likely close to the
  honest single-Starlink-uplink upload capacity, and 0.32 is a
  single-stream pathology, not the pipe's true size.

## 5. The CI evidence

`upload_stream_diag.rs` reproduces these dynamics over localhost under
`tc netem delay 43ms loss 0.5%` (≈ the live path):

- **1 stream vs 4 streams (CUBIC):** parallel streams aggregate far better
  — the asserted `4-stream ≥ 2× 1-stream` is the same effect as
  LibreSpeed-vs-Speedtest and as striping a SOCKS5 flow across N
  connections.
- **1 stream CUBIC vs BBR:** BBR sustains far more throughput than CUBIC
  under loss — the quantified case for adding BBR.

(The exact CI numbers print in the job log; they are illustrative of the
dynamic, not a prediction of live throughput, which depends on the real
uplink and proxy.)

## 6. Fixes — BOTH IMPLEMENTED (operator chose "do both")

### tcp-socks5
1. **BBR + fq in `setup.sh` — DONE.** The installer's sysctl conf now sets
   `net.ipv4.tcp_congestion_control = bbr` and `net.core.default_qdisc = fq`
   (and `modprobe tcp_bbr`). BBR takes effect on new SOCKS5 connections
   immediately; it is far less loss-sensitive than CUBIC on the high-RTT
   path. No code/invariant impact; ~0 effect on udp-wg.
2. **Per-flow multi-connection striping — DONE.** For the bulk (Coalesce)
   mechanism, a single flow is now spread **round-robin across all N SOCKS5
   connections** (`socks5.rs::select_primary`), so one heavy flow uses
   every uplink → approaches the aggregate ~80 Mbit/s. The Remote needed
   **no change and no reassembly**: each `[u16 len][payload]` frame is
   whole and forwarded as one UDP datagram, and the forwarded payload is
   UDP, whose inner protocol (WireGuard) tolerates the cross-connection
   reorder. The latency ICMP-SOCKS5 mechanisms stay sticky. Gated by the
   `SUBLYNE_SOCKS5_STRIPE` panel tunable (default ON); flip it OFF if a
   path's uplinks differ enough in latency that the reorder hurts the inner
   TCP. All v2.1.0 SOCKS5 stability invariants are preserved (the per-slot
   driver / bounded queue / warm-up / health-rehash / keepalive machinery
   is untouched — only the *starting slot* selection changed).

### udp-wg
3. There is **no Sublyne-side structural fix** — the cap is the real
   Starlink uplink + the inner TCP's single-stream behaviour. Options are
   (a) operator guidance (multi-stream inner config, or BBR on the user's
   own endpoints), and (b) optionally the **upload-ingress recvmmsg +
   SO_REUSEPORT** headroom item (backlog A1) which raises Sublyne's pps
   ceiling but will **not** change the 0.32-vs-9 tool difference.

### Both
4. Confirm the MTU oversized-drop is not firing (check the app log) before
   anything else — it is a silent black-hole if the inner MTU is too large.

## 7. What to check on the live boxes (to harden the diagnosis)

- App log for `dropping oversized upload packet` (MTU) and `seal channel
  full` (download-side).
- `ss -tin` on the SOCKS5 connections during an upload: cwnd, rwnd,
  retransmits, congestion algo.
- `sysctl net.ipv4.tcp_congestion_control` (expect `cubic` today).
- How many parallel streams Speedtest vs LibreSpeed open (browser devtools
  / `ss` connection count) — confirms the stream-count hypothesis.
- One single-stream `iperf3 -c` vs `iperf3 -P 4` upload through each tunnel.
