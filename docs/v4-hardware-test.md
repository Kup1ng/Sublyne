# v4.0.0 — hardware test guide (TCP forwarding + keep-alive)

A practical, copy-paste checklist for validating **TCP forwarding** and the
**keep-alive** on your two real boxes before you rely on them. Budget ~20–30
minutes. You will need:

- **Both** boxes upgraded to **v4.0.0+**. A `tcp` tunnel needs the KCP engine
  on *both* ends — a v3 box can't carry one. (`udp` tunnels keep working
  across a v3/v4 mix, byte-for-byte as before.)
- The panel open on each box.
- A throwaway **TCP** service on the foreign (Remote) box to forward to
  (e.g. a VLESS-TCP / Trojan / a plain `python3 -m http.server`).

> Every IP / port / secret below is a **placeholder** (RFC-5737 ranges).
> Replace the `<…>` tokens with your real values. Nothing you paste into a
> commit, screenshot, or issue should contain a real white IP, seller
> endpoint, or PSK.

---

## 0. Values you'll fill in (and which MUST match on both sides)

| Token | Meaning | Example placeholder |
|-------|---------|---------------------|
| `<WHITE_IP>` | Your whitelisted "white" source IP the Remote spoofs **from** | `203.0.113.42` |
| `<IRAN_BOX_IP>` | Public IP of the Iran-side (Client) box | `198.51.100.30` |
| `<FOREIGN_BOX_IP>` | Public IP of the foreign (Remote) box | `198.51.100.40` |
| `<UPLOAD_LISTEN>` | The Remote's upload listener `host:port` (where the Client uploads) | `198.51.100.40:51820` |
| `<SERVICE_HOST>` | Host of your real TCP service (`forward_target`), **host only** | `192.0.2.10` |
| `<APP_PORT>` | The application port (e.g. your VLESS inbound port) | `443` |
| `<PSK>` | The shared pre-shared key | `psk-example` |
| `<WG_CONFIG_NAME>` | Name of the WireGuard config you already added in the panel | `seller-wg` |

**Must be identical on Client and Remote:** `psk`, `ports`,
`forward_protocol`, `forward_engine_preset`, `forward_engine_tuning`,
`keep_alive`, `keep_alive_interval_sec`, `download_spoof_source_ip`, `mtu`.
**Must pair up:** the Client's `download_receive_port` == the Remote's
`download_send_port`; the Remote's `client_real_ip` == `<IRAN_BOX_IP>`.

---

## 1. Upgrade both boxes to v4.0.0

On each box, install the v4.0.0 `sublyne-linux-amd64` the way you normally do
(`setup.sh` → Update, or replace `/usr/local/bin/sublyne` and
`systemctl restart sublyne`). Confirm the panel footer shows **v4.0.0**.

The v4 database migration (0012) runs automatically on first start and is a
**no-op for your existing tunnels** — every current tunnel becomes
`forward_protocol = udp` and behaves exactly as before. Nothing breaks by
upgrading; TCP forwarding is opt-in per tunnel.

---

## 2. Make ONE tcp tunnel work end-to-end

Pick your normal matrix row first (most operators: **download = udp, upload =
WireGuard**). On the **Remote (foreign)** box, **Tunnels → New**:

- **Forwarding** card → **Forward protocol = TCP**, **Engine preset =
  Balanced**. Leave Advanced KCP tuning closed.
- Download transport `udp`, upload-listen mode `udp`, `upload_listen_addr =
  <UPLOAD_LISTEN>`, `forward_target = <SERVICE_HOST>`, `ports = <APP_PORT>`,
  `download_send_port` = (the Client's receive port), `client_real_ip =
  <IRAN_BOX_IP>`, `download_spoof_source_ip = <WHITE_IP>`, `psk = <PSK>`.
- Save, then **Start**.

On the **Client (Iran)** box, create the mirror tunnel:

- **Forward protocol = TCP**, **Engine preset = Balanced** (same as Remote).
- Download transport `udp`, upload mode `wireguard` (`<WG_CONFIG_NAME>`),
  `local_listen_addr = 0.0.0.0`, `ports = <APP_PORT>`,
  `download_receive_port` = (the Remote's send port), `upload_target_addr =
  <UPLOAD_LISTEN>`, `download_spoof_source_ip = <WHITE_IP>`, `psk = <PSK>`.
- Save, then **Start**.

**Verify a real TCP app flows:** point a VLESS-TCP / Trojan / WebSocket
client at the **Client box** on `<APP_PORT>` and connect. A web page should
load. Then run a **speedtest** through it and watch the **Client dashboard**:
Upload/Download should climb and the **status badge** should read **Healthy**
while traffic flows. Let it run for a minute — throughput should be steady,
not collapsing in waves (a collapsing sawtooth means loss the engine can't
keep up with; see Troubleshooting).

> Server-speaks-first protocols (SMTP/IMAP/FTP/SSH that send a banner before
> the client speaks) are **not** carried by tcp forwarding in v4.0.0 — the
> Remote dials `forward_target` only after the client's first bytes. VLESS,
> Trojan, Reality, WS and every other client-speaks-first proxy are fine.

---

## 3. The six matrix rows

`forward_protocol = tcp` is independent of the spoof envelope, so it works on
**all six** download × upload combinations. Re-run the §2 check for each row
you actually use (you don't need all six — just the ones you'd deploy):

| Download transport | Upload (Client) | Remote upload-listen | Notes |
|---|---|---|---|
| `udp`      | WireGuard | `udp`        | the common row |
| `tcp_syn`  | SOCKS5    | `socks5_tcp` | most robust on aggressive paths |
| `icmp`     | WireGuard | `udp`        | when UDP+TCP are filtered |
| `icmp`     | SOCKS5    | `socks5_tcp` | |
| `icmpv6`   | WireGuard | `udp`        | needs IPv6 spoof IP + client IP |
| `icmpv6`   | SOCKS5    | `socks5_tcp` | |

For each: create the tcp tunnel pair, connect your TCP app, confirm a page
loads and a short speedtest is stable, then Stop.

---

## 4. Multi-port tcp

Put **two** application ports in the `ports` list on **both** sides (e.g.
`443, 8443`), `forward_protocol = tcp`, Start both. Each port gets its **own**
KCP engine; a slow or busy port can't stall the other.

- Connect a TCP app on port `443` and a second on `8443` **at the same time**.
- Confirm **both** flow independently (run two speedtests at once if you can).
- The dashboard **Ports** badge should list both, and the session count is the
  sum across ports.

---

## 5. Keep-alive

On the **Client** tunnel, edit it → **Capacity** card → **Keep-alive = On**,
interval `20` (seconds). Set the **same** on the Remote. Save (the tunnel
restarts) and Start.

Now with **no client app connected at all**:

1. The Client dashboard tile shows a distinct **⚡ keep-alive** badge and the
   **status stays Healthy** instead of aging to Idle.
2. **Sessions reads 0** (the keep-alive is *not* counted as a user session —
   that's the point of the separate badge: 0 real users, held warm).
3. On the **Remote**, confirm the keep-alive **never reaches your service**:
   watch `forward_target` (e.g. `tcpdump -nni any host <SERVICE_HOST>` or your
   service's access log) — you should see **no** connections from the
   keep-alive. It is absorbed at the Remote's upload ingress.

Connect a real app and confirm **Sessions** rises while the **⚡ keep-alive**
badge stays — so you can always tell "held warm" apart from "real users".

Turn keep-alive **Off** again on both ends if you don't want the (tiny,
~a-few-bytes-every-20s) background traffic.

---

## 6. Rolling back a tunnel

To return any tunnel to plain UDP forwarding: edit it → **Forward protocol =
UDP** → Save. It restarts on the unchanged spoof/upload path and is once again
byte-for-byte compatible with v3.x. No data migration, no re-keying.

---

## 7. What "good" looks like / troubleshooting

- **Healthy throughput:** steady Upload/Download on a speedtest, status
  **Healthy**, low/zero drops on the dashboard.
- **Page loads but speedtest collapses in waves:** the path is lossier than
  Balanced expects. Edit the tunnel → Engine preset **Lossy**, or open
  **Advanced KCP tuning** and raise **Send/Receive window** (e.g. 4096). Both
  ends must match.
- **App won't connect at all:** the two sides disagree somewhere. Re-check the
  "must match / must pair up" list in §0 — most failures are a mismatched
  `psk`, `ports`, `forward_protocol`, or a `download_receive_port` ↔
  `download_send_port` that doesn't line up.
- **Connects then stalls after a few seconds:** confirm both ends are actually
  on v4.0.0 (a v3 Remote silently can't speak KCP).
- **Editing engine/MTU "did nothing":** v4 treats a forward-protocol, KCP
  tuning, or MTU edit on a running tcp tunnel as a clean **Stop + Start** — the
  badge blips briefly; that's expected, the change is applied.

This guide can't run in CI (the spoof path needs `CAP_NET_RAW` and two real
hosts). The in-process Rust loopback tests already prove the KCP engine
recovers a byte-exact stream over a 10%-loss / 5%-reorder channel; this
checklist is the on-the-wire confirmation only you can run.
