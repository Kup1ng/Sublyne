# Performance backlog — ranked improvement inventory

> Snapshot at v2.2.0, upload-focused. Each item: realistic gain / effort /
> risk / invariant impact, with the specific code or sysctl that is (or
> isn't) doing it today. Companion to
> [upload-throughput-diagnosis.md](./upload-throughput-diagnosis.md).

Current good state (so we don't redo it): per-socket `SO_*BUFFORCE` to
4 MiB on every data-path socket incl. TCP listener/connect (v2.2.0);
`recvmmsg`/`sendmmsg` batching on the spoof download path; download
seal/verify fan-out across cores with per-worker `SeqWindow`s; 16-way
sharded session table; `setup.sh` tunes rmem/wmem/backlog/rp_filter.

## A. Quick wins (low effort, low risk)

- **A1 — Upload-ingress `recvmmsg` + `SO_REUSEPORT` shard.** The upload
  listener on both sides is a *single* `recv_from` per datagram with no
  batching and no shard (`client.rs:301`, `remote.rs:428`), while the
  download path already batches. A port-bound `SOCK_DGRAM` listener *can*
  be reuseport-sharded (unlike raw sockets), and `RecvBatch` already
  exists (`batch.rs:129`). **Gain:** large on upload *pps* headroom (1 Gbps
  regime); **does not** fix the current low upload numbers (those are
  stream-count/uplink/CC, not pps). **Effort:** medium-low. **Risk:**
  low-medium (reuseport hashes by 4-tuple, so a flow stays on one shard →
  SOCKS5 sticky routing preserved). **Invariant:** none.
- **A2 — BBR + fq in `setup.sh` (no `tcp_congestion_control`/`default_qdisc`
  today, `setup.sh:454-468`).** Two sysctl lines. CUBIC collapses on the
  lossy high-RTT Iran↔foreign path; BBR sustains. **Gain:** significant on
  the tcp-socks5 upload; ~0 on udp-wg. **Effort:** trivial. **Risk:** low
  (BBR in-tree on Ubuntu 22/24; guard for module availability).
  **Invariant:** none. *(The top quick lever for ASK 3.)*
- **A3 — CPU governor pin + NIC offload tuning in `setup.sh` (none today).**
  Default `powersave`/`ondemand` throttles the bursty seal/verify cores;
  `ethtool` GRO/GSO/ring sizing cuts per-packet cost. **Gain:** modest,
  free (few % headroom, fewer `seal channel full` drops). **Effort:**
  trivial. **Risk:** low-medium (many VPS don't expose cpufreq/ethtool →
  must no-op gracefully like `SUBLYNE_TEST_SKIP_SYSCTL`). **Invariant:**
  none.
- **A4 — Raise recv/send batch default 16 → 32–64** (`perf.rs:67`,
  `RecvBatch` already clamps to 256). **Gain:** marginal now, more at
  1 Gbps; download path only. **Effort:** trivial (or just set
  `SUBLYNE_RECV_BATCH`/`SUBLYNE_SEND_BATCH`). **Risk:** very low.

## B. Medium effort

- **B1 — Cut per-packet heap allocs on the download hot path.**
  `parsed.payload.to_vec()` per packet (`client.rs:604`, v6 loop too),
  `buf[..n].to_vec()` per reply (`remote.rs:873`), plus the send-worker
  staging copy (`remote.rs:1137`). A buffer pool / ownership pass-through
  would cut allocator pressure at 17.8k+ pps/tunnel. **Gain:** moderate CPU
  on the download lane (helps aggregate Gbps, not upload). **Effort:**
  medium (lifetimes through the mpsc channels). **Risk:** medium.
- **B2 — Per-flow multi-connection SOCKS5 striping.** The confirmed
  tcp-socks5 root cause: one flow → one connection → one uplink
  (`socks5.rs:670-726`). Round-robin a flow across N connections + a
  reorder-tolerant Remote reassembly would let one heavy flow use N
  uplinks (~80 Mbit/s). **Gain:** large for the single-flow upload case.
  **Effort:** high. **Risk:** high — breaks the per-flow in-order contract
  (`remote.rs:480-483`); needs a sequence/reassembly layer and must keep
  the v2.1.0 SOCKS5 stability invariants. *(The big ASK 3 lever.)*
- **B3 — Widen the anti-replay window to unclamp seal workers.**
  `SEQ_WINDOW_SIZE = 1024` (`hmac.rs:210`) hard-clamps Remote seal workers
  to `1024/256 = 4` (`remote.rs:695-696`); on the 8-vCPU Remote half the
  cores can't seal. Bumping `SEQ_WINDOW_WORDS` 16 → 32 (2048 slots) safely
  permits 8 seal workers. **Gain:** meaningful on the download seal lane on
  the 8-core Remote (1 Gbps aggregate). **Effort:** low-medium (keep the
  two constants linked; update the pinning test `hmac.rs:572-579`).
  **Risk:** medium — changes a CLAUDE.md load-bearing invariant (the
  1024-slot window); both ends are the same binary so they stay
  consistent, but it is a wire-relevant behavioural change to document.

## C. Big architectural

- **C1 — io_uring / AF_XDP / tokio-uring.** None present (`Cargo.toml`);
  the architecture deliberately chose `recvmmsg/sendmmsg + sharded tables`
  to hit 1 Gbps without them (CLAUDE.md §9). **Gain:** high at multi-Gbps,
  low at the current ≤1 Gbps target (batching already amortises the
  syscalls io_uring would cut; AF_XDP helps the spoof path but adds a
  kernel/NIC-driver dependency that conflicts with the single-static-musl,
  any-VPS invariant). **Effort:** very high. **Risk:** high. **Verdict:**
  defer past a real >1 Gbps need.

## D. Considered & rejected (with why)

- **D1 — UDP GSO (`UDP_SEGMENT`) on the spoof send path.** Non-viable: the
  spoof sockets are `AF_INET SOCK_RAW` with `IP_HDRINCL`, we build the IP+L4
  headers and checksums ourselves, and DF is deliberately cleared
  (`udp.rs:73-76,184-185`). GSO needs a kernel-owned datagram socket. On
  the WG-UDP *upload* egress GSO *could* apply but there is no batchable
  same-destination segment train, so the benefit is marginal. Correctly
  not done.
- **D2 — Per-core fan-out of RAW download recv sockets.** Would *multiply*
  kernel copies: `IPPROTO_*` raw sockets deliver a copy to every matching
  raw socket and `SO_REUSEPORT` does not shard raw delivery
  (`client.rs:24-38`). The chosen one-raw-socket + recvmmsg + worker
  fan-out is correct. (This is about RAW sockets only; it does **not**
  apply to the `SOCK_DGRAM` upload listener in A1, where reuseport *does*
  shard.)
- **D3 — Parallelise the spoof SEND across multiple raw sockets.** Tried in
  round 2, reverted: independent worker send timing produced wire-skew
  >128 seqs, blowing past the Client's `SeqWindow` (`remote.rs:725-731`,
  CLAUDE.md §4 "Don't parallelise the send side"). The right lever for more
  send throughput is B3 (more seal workers behind the single send socket),
  not more send sockets.

## Bottom line for the upload numbers

The current low upload throughput is **not** an allocation or syscall
problem (A1/A4/B1 are headroom, not the fix). It is **stream-count ×
uplink-share × congestion-control**: **A2 (BBR+fq)** is the safe immediate
win and **B2 (per-flow striping)** is the structural one for tcp-socks5;
udp-wg is bounded by the real Starlink uplink and the inner TCP's
behaviour, not by Sublyne.
