# v4.0.0 — hardware test guide (TCP forwarding)

A practical, copy-paste checklist for validating **TCP forwarding** on your
two real boxes before you rely on it. ~20 minutes. You need:

- Two boxes on **v4.0.0+** (TCP tunnels need BOTH ends on v4 — the
  reliability engine doesn't exist on v3).
- The panel open on each box.
- A throwaway TCP service on the **foreign (Remote)** box to forward to.

> All IPs/ports/secrets below are **placeholders** (RFC-5737 ranges). Replace
> the `<...>` tokens with your real values. Nothing here should ever contain a
> production white IP, seller endpoint, or PSK.

---

## 0. The values you'll fill in (and which MUST match on both sides)

| Token | Meaning | Example placeholder |
|-------|---------|---------------------|
| `<WHITE_IP>` | Your whitelisted "white" source IP the Remote spoofs **from** | `203.0.113.42` |
| `<IRAN_BOX_IP>` | Public IP of the Iran-side (Client) box | `198.51.100.30` |
| `<FOREIGN_BOX_IP>` | Public IP of the foreign (Remote) box | `198.51.100.40` |
| `<UPLOAD_TARGET>` | Where the Client sends upload (the Remote's upload listener, reached over your WG/SOCKS5 path) | `198.51.100.40:51820` |
| `<SERVICE_HOST>` | Host of your real TCP service (forward_target), **host only** | `192.0.2.10` |
| `<PSK>` | The shared pre-shared key | `psk-example` |
| `<WG_CONFIG_NAME>` | Name of the WireGuard config you already added in the panel | `seller-wg` |

**Must be identical on Client and Remote:** `psk`, `ports`, `forward_protocol`,
`tcp_reliability_engine`, `forward_engine_preset`, `forward_engine_tuning`,
`download_spoof_source_ip`, `mtu`. **Must pair up:** the Client's
`download_receive_port` == the Remote's `download_send_port`; the Remote's
`client_real_ip` == `<IRAN_BOX_IP>`.

You can import these JSON files straight into the panel: **Tunnels → Import**.
Each file is one tunnel; import the **client** file on the Iran box and the
**remote** file on the foreign box.

---

## 1. Put a TCP service behind `forward_target`

On the **foreign box** (or wherever `<SERVICE_HOST>` points), run one of:

```sh
# Simplest echo service on port 443 (Nmap's ncat). Echoes every byte back.
ncat -lk <SERVICE_HOST> 443 --exec /bin/cat
# or, equivalently, with socat:
socat TCP-LISTEN:443,fork,reuseaddr EXEC:/bin/cat
```

For a real VLESS-TCP / VLESS-WS test, point `forward_target` at your actual
inbound (e.g. Xray/sing-box on `:443`) instead of the echo service.

---

## 2a. tcp + KCP, single port — import JSON

**Client (Iran box):**

```json
{
  "type": "sublyne-tunnel-export",
  "schema_version": 2,
  "secrets_included": true,
  "tunnel": {
    "name": "test-tcp-kcp",
    "role": "client",
    "forward_protocol": "tcp",
    "tcp_reliability_engine": "kcp",
    "forward_engine_preset": "balanced",
    "forward_engine_tuning": "",
    "ports": [443],
    "download_transport": "udp",
    "icmp_echo_mode": "request",
    "mtu": 1400,
    "max_connections": 50000,
    "idle_timeout": 300,
    "local_listen_addr": "0.0.0.0",
    "download_receive_port": 50000,
    "download_spoof_source_ip": "<WHITE_IP>",
    "download_spoof_source_port": 443,
    "upload_target_addr": "<UPLOAD_TARGET>",
    "upload_mode": "wireguard",
    "wireguard_config_name": "<WG_CONFIG_NAME>",
    "upload_listen_mode": "udp",
    "ping_smoothing_enabled": false,
    "ping_smoothing_target_ms": 60,
    "pacing_enabled": false,
    "pacing_target_ms": 60,
    "psk": "<PSK>"
  }
}
```

**Remote (foreign box):**

```json
{
  "type": "sublyne-tunnel-export",
  "schema_version": 2,
  "secrets_included": true,
  "tunnel": {
    "name": "test-tcp-kcp",
    "role": "remote",
    "forward_protocol": "tcp",
    "tcp_reliability_engine": "kcp",
    "forward_engine_preset": "balanced",
    "forward_engine_tuning": "",
    "ports": [443],
    "download_transport": "udp",
    "icmp_echo_mode": "request",
    "mtu": 1400,
    "max_connections": 50000,
    "idle_timeout": 300,
    "upload_listen_addr": "0.0.0.0:51820",
    "forward_target": "<SERVICE_HOST>",
    "download_send_port": 50000,
    "client_real_ip": "<IRAN_BOX_IP>",
    "download_spoof_source_ip": "<WHITE_IP>",
    "download_spoof_source_port": 443,
    "upload_listen_mode": "udp",
    "psk": "<PSK>"
  }
}
```

> Note: `download_receive_port` (Client, 50000) == `download_send_port`
> (Remote, 50000). `local_listen_addr` and `forward_target` are **host only** —
> the port comes from `ports`.

## 2b. tcp + QUIC, single port

Identical to 2a on **both** files, but change:

```json
"tcp_reliability_engine": "quic",
"mtu": 1400
```

QUIC needs `mtu >= 1252` (its datagrams are ≥1200 bytes); the panel enforces
this. KCP has no MTU floor.

## 2c. tcp + KCP, multi-port (2 ports)

Same as 2a on **both** files, but change `ports` (identical list on both
sides) and run a service on **each** port:

```json
"ports": [443, 8443]
```

Then run a second echo service on the foreign box:

```sh
ncat -lk <SERVICE_HOST> 8443 --exec /bin/cat
```

Sublyne runs **one independent reliability engine per port** — port `443` and
port `8443` get separate KCP conversations, separate idle reapers, and
separate backpressure, all sharing the one seal/spoof pipeline. A busy `443`
never stalls `8443`.

---

## 3. Verify

Run these from a **user machine** that points at the Iran box's listen port
(`<IRAN_BOX_IP>:443`, and `:8443` for the multi-port test).

**Interactive echo (sanity):**

```sh
ncat <IRAN_BOX_IP> 443
# type a line, press enter — you should see it echoed straight back
```

**File round-trip with md5 (integrity):** put a **sink** behind the service
instead of echo, then push a file and compare:

```sh
# foreign box: write what arrives to a file
ncat -lk <SERVICE_HOST> 443 > /tmp/received.bin
# user: send a file through the tunnel
head -c 50M </dev/urandom > /tmp/sent.bin
ncat <IRAN_BOX_IP> 443 < /tmp/sent.bin     # Ctrl-C once it's sent
# compare:
md5sum /tmp/sent.bin            # on the user box
md5sum /tmp/received.bin        # on the foreign box  → must match
```

**Sustained throughput (stability under load):** run `iperf3 -s` as the
service and drive it through the tunnel:

```sh
# foreign box (as the forward_target service):
iperf3 -s -p 443
# user:
iperf3 -c <IRAN_BOX_IP> -p 443 -t 60
```

For the **multi-port** test, run the same checks on `:443` and `:8443`
**at the same time** and confirm both stay healthy independently.

---

## 4. What to watch — and the honest truth about it

v4.0.0 surfaces **tunnel-level** signals, not per-engine internals. Watch
these on each box's panel and logs:

**Panel (Dashboard / tunnel detail):**

- **Bytes up / down** climbing on both the Client and Remote tunnel while you
  transfer — this is the primary "it's working" signal.
- **Active sessions** > 0 once a TCP connection is open.
- **Drop counters** (auth drops, session rejects, seal drops, send drops)
  staying **near zero**. A steady climb here is the main warning sign.

**Logs (panel Logs page, or `journalctl -u sublyne`):** look for these lines.

| You want to see (good) | Meaning |
|------------------------|---------|
| `client: TCP-forward listener(s) bound` | Client engine(s) started |
| `remote: TCP-forward engine(s) ready` / `remote: multi-port TCP-forward engine spun up` | Remote engine(s) started (one log per port in multi-port) |
| `kcp: remote learned new conv; dialing forward_target` / `quic: connection accepted` | A user connection reached the Remote and it dialed your service |
| `kcp: reaped idle conv` (debug) | Normal cleanup of finished connections |

| Warning signs (bad) | Likely cause |
|---------------------|--------------|
| `kcp/quic: dial forward_target failed` | Your service isn't up / wrong `forward_target` |
| `... tagged with a port that is not in this tunnel's configured set` | **Port lists differ between the two boxes** — make `ports` identical |
| `seal channel full` / `send queue full` (sustained) | The download path is saturated; check MTU and link capacity |
| Bytes up climbs but **bytes down stays flat** | The spoofed download isn't arriving — check `<WHITE_IP>`, `download_send_port`/`download_receive_port` pairing, and firewall |

### Honest caveat on metrics

The reliability engines keep internal counters (active conversations,
conversation opens, idle teardowns, egress/sink drops), but **v4.0.0 does not
surface these per-engine counters to the panel**, and there is **no
retransmit/loss counter**. So you cannot watch `engine_segments_retransmitted`
or `engine_segments_lost` directly — they don't exist as panel metrics yet.
Infer engine health instead from: **sustained throughput** (iperf3 holding a
stable rate), **bytes down tracking bytes up**, **drop counters near zero**,
and the **engine log lines** above. Wiring the per-engine counters through to
the panel is a sensible follow-up, deferred so v4.0.0 stays focused on the
forwarding capability itself.

---

## 5. "Good" vs "bad" — success criteria

**Good (ship it):**

- Echo round-trips; md5 of `sent.bin` == `received.bin`.
- `iperf3` holds a steady rate for the full 60 s with no stall.
- Bytes down tracks bytes up on both tunnels; drop counters stay near zero.
- Multi-port: both ports pass independently and concurrently.
- Logs show engines starting and dialing; no repeated `dial ... failed` or
  port-mismatch warnings.

**Bad (don't rely on it yet):**

- md5 mismatch, or the transfer hangs/stalls partway.
- `iperf3` rate collapses or the connection drops mid-transfer.
- Bytes up climbs but bytes down stays flat (download path broken).
- Repeated `... port that is not in this tunnel's configured set` (the two
  boxes disagree on `ports`) or `dial forward_target failed`.

If something's off, the fastest checks: confirm `ports`/`psk`/`mtu` match
exactly on both boxes, confirm the `download_receive_port`↔`download_send_port`
pairing, confirm the service is actually listening on `<SERVICE_HOST>:<port>`,
and confirm `<WHITE_IP>` is correct and routable to the Iran box.
