---
name: perf-and-profiling
description: Measuring and tuning real-world throughput on the live tunnel for BOTH upload and download — how to capture per-core load (`mpstat`), socket buffer drops (`ss -anpem`, `Udp:RcvbufErrors` in `/proc/net/snmp`), three-direction iperf3 baselines (download via tunnel, upload via tunnel, upload direct-over-WG as the comparison number), and `perf record` flamegraphs of the Rust dataplane. Documents the env knobs (`SUBLYNE_SOCKET_BUF_BYTES`, `SUBLYNE_RECV_BATCH`, `SUBLYNE_SEND_BATCH`, `SUBLYNE_PER_CORE_SOCKETS`) and the live boxes' hardware (Iran 3 vCPU, Remote 8 vCPU). Round-2 introduction.
when_to_use: Phase R1 (baseline capture), R2 (the 50→200 Mbit/s fan-out/batching fix — verify each change actually moved the needle), R3 (flamegraph the hot path), R7 (Chrome DevTools recipe for dashboard jank), R10 (final "before vs after" for v1.0.0). Any time someone asks "is it faster?" or "where is the CPU going?", start here.
---

# Skill — Perf and profiling

## When to use this skill

- Phase R1 (capture baseline) — you'll run every command in this
  file at least once.
- Phase R2 (per-core fan-out + recvmmsg/sendmmsg) — to verify each
  change actually moved the needle, not just the test rig.
- Phase R3 (code-review cleanup) — to flamegraph the hot path and
  prove a "regression" is real.
- Phase R7 (dashboard smoothness) — for the Chrome DevTools recipe.
- Phase R10 (acceptance) — to produce the final "before vs after"
  number that gates the v1.0.0 release.
- Any time someone says "is it faster?" or "where is the CPU
  going?" — start here.

## Ground truth: where the real-world ceiling comes from

The Sublyne project's stated target is **≥ 1 Gbps aggregate
and ≥ 200 Mbit/s per tunnel** on a 2–4 vCPU VPS (PRD §1.3). The
live tunnel through Iran ↔ foreign falls well short in **both**
directions:

| Direction | Through tunnel | Comparison | Drop |
|-----------|---------------:|-----------:|-----:|
| Download (Iran ← foreign) | ~100 Mbit/s (was 50) | target 200 | ~4 % loss (was 24.6 %) |
| **Upload (Iran → foreign)** | **~5 Mbit/s** | **WG link standalone: 30+ Mbit/s** | ~4 % loss |

The download cap, from `/proc/net/snmp` on the Iran box during the
planning capture, was driven by kernel UDP RcvbufErrors
(`Udp:InErrors == Udp:RcvbufErrors`, 24.6 % of InDatagrams). That
number has moved (better link, link variance, partial fix); the
**root cause is unchanged**: single-thread recv on a 3-core box.

The upload cap was discovered later: the WG link itself does
30+ Mbit/s via plain `iperf3 -u -B <wg-iface-ip>`, but routed
through our project it collapses to ~5 Mbit/s. **We are wasting
~83 % of available upload capacity.**

| Box | CPUs | Role | Hardware |
|-----|-----:|------|----------|
| ssh-iran (198.51.100.30:1313) | 3 | Client | Intel E5-2697 v2 (VMware) |
| ssh-remote (198.51.100.40:22) | 8 | Remote | AMD EPYC 7302 (qemu) |

**Same root cause both directions.** Read of the upload code
(`data-plane/src/tunnel/client.rs:199-257` and
`data-plane/src/tunnel/remote.rs:252-312`) confirmed: one Tokio
task per upload direction per tunnel, `recv_from` + `send_to` per
packet, no `recvmmsg`/`sendmmsg`, no `SO_REUSEPORT`, no recv/send
split. Same pattern as download. Phase 10's perf work touched the
download recv socket; it never touched upload. Phase R2 fixes both.

Bigger buffers alone don't help either direction — the consumer
side has to drain in parallel (per-core fan-out + batched syscalls
+ recv/send split via a 4096-cap channel).

## Baseline capture (Phase R1 + repeated for every perf phase)

Run the snapshot script on **both** boxes before, during, and after
each of **three** iperf3 runs (download, upload, upload-direct-over-WG).
Treat the deltas as the actual measurement.

### Why three runs

- **Download** (`-R`): the original 50/100 Mbit/s ceiling.
- **Upload** (no `-R`): the ~5 Mbit/s ceiling discovered after the
  original plan landed.
- **Upload-direct-over-WG**: the comparison number. Bypasses our
  project entirely by binding iperf3 to the WG interface IP on the
  Client and pointing at the Remote's WG-side address. Shows what
  the WG link itself can do without our code in the path. Phase R2
  is required to reach ≥ 80 % of this number through the tunnel.

### One-shot snapshot script

`tests/perf/capture_snapshot.sh` (the perf phase creates this; here
is what it must collect — same content for all three runs):

```bash
#!/usr/bin/env bash
# Capture a perf snapshot. Run before, during, and after a known load.
set -euo pipefail
out=${1:-/tmp/perf-snap-$(date +%s).txt}
exec > "$out"
echo "=== timestamp ===" && date -u --iso=ns
echo "=== uname ===" && uname -a
echo "=== nproc ===" && nproc
echo "=== meminfo ===" && head -5 /proc/meminfo
echo "=== sysctl (network) ===" && \
  sysctl net.core.rmem_default net.core.rmem_max \
         net.core.wmem_default net.core.wmem_max \
         net.core.netdev_max_backlog net.ipv4.icmp_msgs_per_sec \
         net.ipv4.icmp_echo_ignore_all 2>/dev/null || true
echo "=== ulimit ===" && ulimit -n
echo "=== sublyne proc ===" && \
  ps -eo pid,ppid,rss,vsz,pcpu,user,comm | grep -E 'sublyne|dataplane|PID'
echo "=== dataplane fd sockets (skmem!) ==="
ss -anpem 2>/dev/null | grep -E 'dataplane|^Netid' | head -40
echo "=== /proc/net/snmp UDP ==="
cat /proc/net/snmp | grep -E '^Udp(Lite)?:'
echo "=== top -H per-thread (1s sample) ==="
top -bn1 -H -p $(pgrep -d, -f 'sublyne|dataplane') 2>/dev/null | tail -40
echo "=== ip link / wg ==="
ip -br link show
which wg && wg show 2>/dev/null || true
```

### Driver script — `tests/perf/capture_baseline.sh`

Runs the three iperf3 directions with snapshots around each. Reads
addresses from env vars so the same script works for every box pair.

```bash
#!/usr/bin/env bash
# tests/perf/capture_baseline.sh
# Required env vars:
#   CLIENT_PUBLIC_IP        the Iran box's public IP
#   LOCAL_LISTEN_PORT       the tunnel's local_listen_addr port
#   WG_FOREIGN_IP           the foreign side's WG-interface IP
#   WG_LOCAL_BIND_IP        the Iran side's WG-interface IP (for -B)
#   DURATION                seconds, default 60
set -euo pipefail
mkdir -p tests/perf/captures
D=${DURATION:-60}

run() {
  local label="$1" iperf_args="$2"
  echo "=== $label ==="
  ./tests/perf/capture_snapshot.sh "tests/perf/captures/${label}_pre.txt"
  echo "--- iperf3: ${iperf_args}"
  iperf3 $iperf_args | tee "tests/perf/captures/${label}_iperf.txt" &
  local pid=$!
  sleep $((D / 2))
  ./tests/perf/capture_snapshot.sh "tests/perf/captures/${label}_mid.txt"
  wait $pid
  ./tests/perf/capture_snapshot.sh "tests/perf/captures/${label}_post.txt"
}

run "1_download_via_tunnel" \
    "-u -c $CLIENT_PUBLIC_IP -p $LOCAL_LISTEN_PORT -b 200M -R -t $D"

run "2_upload_via_tunnel" \
    "-u -c $CLIENT_PUBLIC_IP -p $LOCAL_LISTEN_PORT -b 50M -t $D"

run "3_upload_direct_over_wg" \
    "-u -c $WG_FOREIGN_IP -B $WG_LOCAL_BIND_IP -b 50M -t $D"

echo "All three runs complete. See tests/perf/captures/."
```

For each run, extract: **Mbit/s sustained**, **% packet loss**, and
**peak per-core CPU** on the dataplane PID. Run 3's number is the
upload target for R2 (multiplied by 0.8 — we accept 80 % of WG
standalone as "tunnel is no longer the bottleneck"). Stitch into
`tests/perf/baseline-v0.1.x.md`.

### What to look at in the diff

1. **`Udp:InDatagrams` delta** = packets the kernel UDP layer
   processed. Divided by the wall-clock seconds gives packets/sec.
2. **`Udp:RcvbufErrors` delta** = packets dropped because the per-
   socket receive buffer was full. **This is the headline number for
   Round 2 perf work.** Phase R2 must drive this < 0.5 % of
   InDatagrams under 200 Mbit/s load.
3. **`Udp:NoPorts` delta** — packets arriving at a port no UDP socket
   is bound to. Raw sockets receive copies regardless of port, so
   this can be high without affecting our data path. Note it but
   don't chase it.
4. **`top -H` per-thread CPU%** — if one thread is at 95–100 % and
   the others idle, single-core saturation. Phase R2 fixes that.
5. **`ss -anpem` `skmem rb=…`** — actual configured receive buffer.
   Kernel doubles the requested value (request 4 MiB → see 8 MiB).
   If `rb` is much smaller than `net.core.rmem_max` the dataplane
   didn't successfully apply its tuning.
6. **`ss -anpem` `Recv-Q`** — current depth of the socket queue. A
   non-zero value means the kernel is buffering for the user-space
   reader; growing depth across snapshots = back-pressure.

### per-core load picture

```bash
mpstat -P ALL 1 30 > /tmp/mpstat-during.txt   # 30 s sample
# Look for one core at low %idle and others high %idle.
# After R2 lands, all N cores should drop to similar %idle.
```

### Flamegraph for the dataplane (Phase R3 + R7 sanity)

```bash
# On the box, as root:
apt-get install -y linux-tools-generic
perf record -F 99 -p $(pgrep -f sublyne-dataplane) -g -- sleep 30
perf script > /tmp/perf-script.txt
# Pull /tmp/perf-script.txt to a dev machine, then:
git clone --depth 1 https://github.com/brendangregg/FlameGraph /tmp/fg
/tmp/fg/stackcollapse-perf.pl /tmp/perf-script.txt | /tmp/fg/flamegraph.pl > out.svg
# Open out.svg — wide bars are hot paths. Expect HMAC, recvfrom,
# socket_write to dominate. Anything else wide is a regression.
```

For the Rust side, `cargo flamegraph -p sublyne-dataplane --release`
is the dev-loop equivalent (uses `perf` under the hood).

### Frontend perf (Phase R7)

In Chrome DevTools → Performance tab:
1. Open the panel's dashboard with live load running.
2. Click record. Let it run 30 s. Stop.
3. Look at the main-thread flame chart. Any task > 50 ms is a jank
   stall. Any `chart.update` > 16 ms drops below 60 fps perception.
4. The "Scripting" total over the 30 s sample / 30 s = average JS
   load. Should be << 5 % on a 4 vCPU box.

## Tuning knobs we already ship

These exist in v0.1.x and the perf phases should reuse them, not
re-invent:

- `SUBLYNE_SOCKET_BUF_BYTES` — per-socket `SO_RCVBUF`/`SO_SNDBUF`
  target. Default 4 MiB, floor 256 KiB. Set via systemd
  `Environment=` (already wired through `setup.sh`).
- `/etc/sysctl.d/99-sublyne.conf` — raises `rmem_max` /
  `wmem_max` / defaults / `netdev_max_backlog`. Already installed
  by `setup.sh`. Don't fight it; if a phase needs different values,
  rewrite the file via `setup.sh` and document the why.
- `LimitNOFILE=524288` in the systemd unit. Plenty of headroom for
  hundreds of sockets per tunnel × dozens of tunnels.

## New tuning knobs Round 2 introduces (R2)

Apply to **both** upload and download paths (R2 fixes both). Resolved
in `data-plane/src/perf.rs` once per process via `OnceLock`; pass via
the systemd unit's `Environment=` lines if you want non-defaults.

- `SUBLYNE_RECV_BATCH` — `recvmmsg` batch size. Default 16, clamp
  1..=64. Set 1 to disable batching (debug fallback). The
  performance increase between 1 and 16 is dramatic; between 16
  and 64 it's marginal (measured on synthetic load — re-confirm on
  the live tunnel during R2 acceptance).
- `SUBLYNE_SEND_BATCH` — `sendmmsg` batch size. Same default and
  clamp as `SUBLYNE_RECV_BATCH`. Send-side batching matters on the
  upload egress (WG-marked socket) and on the Remote forward-target
  send, in addition to the download spoof send.
- `SUBLYNE_PER_CORE_SOCKETS` — overrides
  `std::thread::available_parallelism()` for the per-tunnel worker
  count. On the **Client upload path** this controls the number of
  SO_REUSEPORT listen sockets + WG-marked egress sockets (the kernel
  hashes end-user 4-tuples across them). On the **Remote upload
  path** this controls the SO_REUSEPORT listen-socket count + the
  number of forward-target send sockets. On the **download path**
  (raw sockets) it controls how many verify/seal worker tasks share
  the single raw recv socket via a bounded `mpsc` channel — raw
  sockets DON'T load-balance via SO_REUSEPORT (the kernel delivers
  every matching packet to every raw socket on the same protocol),
  so we fan out the CPU-heavy HMAC work across N workers instead of
  opening N raw sockets that would each receive a duplicate copy of
  every packet. Default = number of online CPUs (3 on Iran, 8 on
  Remote). Useful when an operator wants to leave a core free for
  the control plane. Clamp 1..=64.

### Batching implementation

`recvmmsg`/`sendmmsg` live in `data-plane/src/batch.rs` as
`recvmmsg(fd, &mut RecvBatch)` and `sendmmsg(fd, &mut SendBatch,
count)`. Each batch owns its own `Vec<Slot>` + `Vec<iovec>` +
`Vec<mmsghdr>` and **re-stitches the raw pointers every call** so the
struct stays freely movable in Rust. Allocate once at task start;
reuse forever. Loopback tests in `batch::tests::sendmmsg_recvmmsg_loopback_roundtrip`
cover both directions end-to-end.

## Pitfalls and gotchas

- **Don't `iperf3 -t 5`.** Short runs ride on CPU caches and don't
  fill the receive buffers. Use `-t 30` minimum, `-t 60` preferred.
- **`iperf3 -u` without `-b` sends at 1 Mbit/s by default.** Always
  set `-b 200M` (or whatever target).
- **`iperf3` from a 1 Gbps link to a 100 Mbit/s link inflates loss
  numbers.** Measure the slowest hop first.
- **The Iran box has 3 cores total**, one of which is doing the
  panel and one is doing kernel I/O. Real available cores for the
  dataplane are ~2. R2's fan-out should expect that.
- **VMware vmxnet3 NICs on the Iran box** don't support `ethtool -g`
  ring resize and have one RX queue. Don't plan AF_XDP for that box.
- **`Udp:NoPorts` is normal for spoof traffic** when the raw socket
  consumes packets the kernel UDP layer also processes. Don't chase
  it unless it correlates with InErrors.
- **`Recv-Q 8390272` on the dataplane's raw `IPPROTO_UDP` send-side
  socket on Remote** is a known issue (fd 13 in `ss -anpem`). It's
  the Remote's send socket also receiving copies of incoming
  protocol packets and never draining them. Phase R3 fixes this.

## Cross-references

- `raw-sockets-and-spoofing/SKILL.md` — the socket setup these
  measurements look at.
- `tests/perf/` (created in R1) — the place to land captured
  snapshots, not in commit messages.
