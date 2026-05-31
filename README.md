# Sublyne

> Quiet lifeline. Stealth in, daylight out.

**Sublyne** is a single-binary, anti-censorship UDP port-forwarding
system. It bypasses Iran's DPI by splitting traffic into two
asymmetric paths:

- **Upload** travels through a pre-purchased WireGuard tunnel (or
  through N parallel TCP connections to a SOCKS5 proxy fronting
  multiple Starlink uplinks) — standard, encrypted, kernel-handled.
- **Download** arrives as crafted packets whose source IP is one of
  the addresses Iran's central firewall has whitelisted. Every
  download packet carries a 16-byte HMAC-SHA256 prefix keyed by a
  shared PSK; packets that fail HMAC, have the wrong source IP/port,
  carry a replayed sequence number, or carry an unknown session ID
  are silently dropped.

Sublyne is a clean fork of the
[Port-Forwarding](https://github.com/Kup1ng/Port-Forwarding) project.
It carries the same proven Rust data plane and Go control plane, with
a brand-new Nuxt 3 panel and a hardened SOCKS5 upload pool.

Two servers run the same single binary:

- **Client** — the Iran-side server. Accepts UDP from the end user,
  uploads through WireGuard or SOCKS5, receives spoofed download
  packets, and hands payload back to the original UDP socket.
- **Remote** — the foreign server. Receives the uploaded traffic,
  forwards it to the real destination (e.g. a 3x-ui proxy panel),
  and sends every response back as spoofed packets through one of
  four envelopes: UDP, TCP-SYN, ICMP, or ICMPv6.

The two servers never talk to each other on any management channel.
All coordination is via shared static configuration — identical PSK,
matching IPs, ports, transport, MTU. Each server is managed through
its own web panel; there is no master, no inter-server control plane,
and no automatic discovery.

Target scale: **≥ 1 Gbps aggregate, ≥ 200 000 concurrent UDP sessions
per server** on a 2–4 vCPU VPS.

---

## Prerequisites

| Requirement | Why |
|-------------|-----|
| Ubuntu 22.04 LTS or 24.04 LTS, **amd64 only** | The installer refuses to run elsewhere. |
| Root access (or `sudo`) | The installer writes `/usr/local/bin/`, `/etc/sublyne/`, `/var/lib/sublyne/`, and registers a systemd unit. |
| Kernel WireGuard (`modprobe wireguard`) | The control plane brings up per-tunnel WireGuard interfaces via netlink. Built in on Ubuntu 22/24. |
| A "white IP" you trust as the download source | The whole point. Your Iran-side hosting seller usually has one. |
| A VPS provider that does **not** apply BCP38 / strict reverse-path filtering on egress | The Remote forges the source IP of download packets. Some providers drop forged-source packets at the hypervisor. See [Troubleshooting](#troubleshooting). |
| Two servers | One in Iran (Client role) and one abroad (Remote role). |

The web panel is HTTP only — no TLS, no ACME. It is protected by an
obfuscated 16-character random URL path plus a 5-digit random port,
both generated at install time. Brute-force login protection blocks
five failed attempts within five minutes for fifteen minutes; the
global cap is sixty attempts per hour per source IP.

---

## Quick start

On a fresh Ubuntu 22.04 or 24.04 amd64 host, as root:

```sh
wget -O /tmp/sublyne-linux-amd64 \
  https://github.com/Kup1ng/Sublyne/releases/latest/download/sublyne-linux-amd64
wget -O /root/setup.sh \
  https://github.com/Kup1ng/Sublyne/releases/latest/download/setup.sh
chmod +x /root/setup.sh
/root/setup.sh
```

Pick **1) Fresh install**, choose the role (`client` on the Iran-side
server, `remote` on the foreign server), pick an admin username and
password — the installer prints the panel URL, port, web path, and
credentials at the end.

Repeat on the second server with the opposite role.

After both panels are up, log into each and create a matching
tunnel pair. The PSK, ports, IPs, transport, and MTU must be
identical on both sides; there is no automatic synchronisation.

### Setup menu

`setup.sh` is interactive:

```
1) Fresh install   — first-time install on a clean host.
2) Update          — replace /usr/local/bin/sublyne with a newer
                     /tmp/sublyne-linux-amd64 and restart the
                     service. Keeps all tunnels, credentials,
                     WG configs, and SOCKS5 proxies.
3) Reinstall       — replace binary + recreate the systemd unit.
                     Data preserved.
4) Uninstall       — stop and remove the service. Prompts before
                     deleting tunnels and credentials.
5) Show status     — prints the panel URL, role, version, and
                     systemd state.
6) Exit
```

### If you lose the admin password

```sh
systemctl stop sublyne
/usr/local/bin/sublyne --config /etc/sublyne/config.toml --reset-admin
systemctl start sublyne
```

The command prompts for a new username and password, re-hashes via
Argon2id, replaces the admin row, and clears any active brute-force
lockout. Existing JWT session cookies stay valid for the remainder
of their 31-day TTL — the reset only changes the credentials, not
the signing key.

---

## Architecture overview

```
              end-user device
                    │  UDP
                    ▼
┌─────────────── Iran Client ──────────────────────────────────────┐
│  local_listen_addr  ← end user packets                           │
│                    │                                              │
│        ┌───────────┴───────────┐                                 │
│        ▼                       ▼                                  │
│  WireGuard mode          SOCKS5 mode                              │
│  (per-tunnel             (N parallel TCP                          │
│  fwmark+policy           connections to one                       │
│  routing, kernel WG)     proxy fronting N                         │
│                          Starlink uplinks)                        │
└────────────────────│──────────────────────────────────────────────┘
                     │  encrypted upload via WG, or framed UDP
                     │  carried inside SOCKS5 CONNECT
                     ▼
            seller infrastructure
                     │
                     ▼
┌─────────────── Foreign Remote ───────────────────────────────────┐
│  upload_listen_addr (UDP or socks5_tcp) ← seller exit            │
│                    │                                              │
│                    ▼                                              │
│              forward_target (the real destination —              │
│              3x-ui, Hysteria, WireGuard server, …)               │
│                    │                                              │
│                    ▼                                              │
│  download response — raw socket, source = white IP,              │
│  payload = HMAC-SHA256(PSK, seq, session_id) ‖ data              │
└────────────────────│──────────────────────────────────────────────┘
                     │  spoofed via UDP / TCP-SYN / ICMP / ICMPv6
                     ▼
┌─────────────── Iran Client ──────────────────────────────────────┐
│  download_receive_port → HMAC verify → forward to end user       │
└──────────────────────────────────────────────────────────────────┘
```

The split exists because Iran's DPI inspects egress aggressively but
trusts ingress from whitelisted IPs. WireGuard encrypts the upload
so DPI can't read it; the download side disguises itself as traffic
from a trusted source.

---

## Spoof transports

The download path can travel in any of four envelopes. Pick one per
tunnel; both sides must agree. Switching is a save in the panel — no
restart.

| Transport | When it's useful | Caveats |
|-----------|------------------|---------|
| **UDP** | Default. Lowest overhead, easiest to reason about. | Some networks rate-limit unsolicited UDP. |
| **TCP-SYN** | Looks like an unsolicited TCP handshake from the white IP. DPI usually doesn't track it statefully. We install firewall rules so the kernel doesn't ACK or RST the SYN. | The Client's iptables/nftables must include the rule set the installer adds. |
| **ICMP** | Cheap, hard to filter by port. Sublyne sends echo-**requests** (not echo-replies) and suppresses the kernel auto-reply for the tunnel's lifetime. | Some real paths drop ICMP end-to-end; try UDP or TCP-SYN if 100 % loss appears. |
| **ICMPv6** | IPv6 counterpart, same shape, same trade-offs. | Verify with `mtr -6` first. |

Every transport uses the same HMAC envelope — 16-byte HMAC-SHA256
prefix over `(seq, session_id, payload_hash)` keyed by the PSK.
`session_id` is a random 32-bit word stamped at tunnel start so the
verifier no longer depends on wall-clock skew between Iran and the
foreign box.

---

## Upload modes

A Client tunnel's upload path can run in one of two modes, picked in
the panel via the **Upload mode** selector:

- **WireGuard** — single per-tunnel WireGuard interface. One link;
  upload bandwidth is capped at whatever that link does.
- **SOCKS5** — N parallel TCP connections to a SOCKS5 proxy that is
  itself a load-balancer across multiple uplinks (typically multiple
  Starlink modems behind a single LB). N connections land on N
  uplinks, scaling upload bandwidth linearly until you hit the
  proxy's ceiling.

Sublyne hardens the SOCKS5 mode beyond the predecessor project:

- Pool warm-up gating — the tunnel does not report ready and starts
  forwarding only after every slot completes its SOCKS5 handshake (or
  the operator-configured `min_ready_slots` threshold is met).
- Aggressive reconnect on TCP death — keep-alive + `TCP_USER_TIMEOUT`
  catches stalled connections in seconds instead of the kernel's
  120 s default, and the slot reconnects immediately with bounded
  exponential backoff.
- Per-slot health counters with rotation — a chronically failing slot
  is parked and the pool re-hashes flows to healthier siblings.
- Bounded backpressure queue (default 4096 frames) — a transient
  blip queues briefly instead of immediately dropping, so the WG
  client session at the proxy doesn't tear down on every micro-fault.

---

## Multi-port tunnels

A single tunnel can carry **several application ports** at once (up to
32), with a fixed 1:1 same-number mapping — Client `:51820` ↔ Remote
`:51820`, Client `:443` ↔ Remote `:443`, and so on. This lets you run,
for example, WireGuard on one port, a VLESS/Reality service on another,
and a third service through the **one** tunnel — one PSK, one session
table, one download spoof path, one upload egress.

Each forwarded datagram of a multi-port tunnel carries a 2-byte
app-port tag *inside* the HMAC-authenticated payload, so the receiver
can demultiplex it to the right service (and drop anything addressed to
a port not in the configured set). Enter the extra ports in the tunnel
form; the same list is used on both the Iran and foreign side.

This is **backward compatible**: a single-port tunnel is wire-identical
to before (no tag), `PROTO_VERSION` is unchanged, and existing tunnels
need no changes. See [`docs/multiport.md`](docs/multiport.md) for the
wire design, the all-six-transport matrix, and the migration story.

---

## Documentation

- [`.claude/CLAUDE.md`](./.claude/CLAUDE.md) — orientation for any
  Claude Code chat or human contributor opening this repo. Includes
  the **OPSEC ban list** and the hard-won v1.0.x lessons.
- [`.claude/skills/`](./.claude/skills/) — per-topic procedural
  references (building, linting, IPC, raw sockets, WireGuard, db
  migrations, web panel components, SOCKS5).
- [`docs/multiport.md`](./docs/multiport.md) — multi-port tunnels: the
  2-byte app-port tag, why `PROTO_VERSION` stays 2, and the
  `tunnels.ports` data model.

---

## Troubleshooting

### I can't reach the panel

- Confirm the port and web path:
  `grep -E 'panel_port|web_path' /etc/sublyne/config.toml`
- Confirm the service is running: `systemctl status sublyne`.
- Confirm the firewall isn't blocking the port:
  `ss -lntp | grep <panel_port>` should show the `sublyne` process bound.
- The panel URL is `http://<server-ip>:<port>/<web_path>/`. The
  trailing slash matters.

### WireGuard handshake stays "stale"

- Re-paste the config in the panel. A trailing whitespace difference
  is enough to make the parser unhappy.
- Verify the seller endpoint is reachable from the Client:
  `ping -W 1 -c 3 <endpoint-ip>` — if the IP is unreachable, the
  problem is your transit, not Sublyne.

### iperf3 shows 100 % loss

In order:

1. **PSK mismatch.** Copy the value into both forms from the same
   source.
2. **Transport mismatch.** Both ends must use the same
   `download_transport`.
3. **Spoof source IP / port mismatch.** Client drops every packet
   whose source doesn't exactly match its configured
   `download_spoof_source_ip:download_spoof_source_port`.
4. **MTU mismatch.** Default `1400` is conservative.

### VPS provider drops spoofed egress

The Remote forges the source IP of every download packet. Some
hosting providers run BCP38 (anti-spoofing) at the hypervisor or
upstream switch and silently drop egress packets whose source isn't
one of your assigned IPs. From Sublyne's perspective this looks like
100 % download loss with no error in the logs.

Ask the provider:

> *Do you apply BCP38 / strict reverse-path filtering on egress?*

If yes, you'll need a different provider for the Remote.

### NTP gotcha on Iran boxes

Iran boxes routinely can't reach `ntp.ubuntu.com`, Cloudflare, or
Google NTP. Use `ntp.day.ir` instead. Sublyne does not depend on
wall-clock time for HMAC verification (the envelope uses a random
session_id), but the panel timestamps and audit log do.

---

## License

[MIT](./LICENSE) © Sublyne contributors.
