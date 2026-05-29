---
name: socks5-upload
description: SOCKS5 as an alternative upload transport that opens N parallel TCP connections to a proxy fronting multiple Starlink links — schema (`socks5_proxies` table, `tunnels.upload_mode`/`socks5_proxy_id`), panel pages mirroring the WireGuard section, REST API, validation rules, dataplane connection-pool design (`data-plane/src/upload/socks5.rs`), per-session sticky routing vs round-robin, SOCKS5 wire framing (`[u16][payload]`) for UDP-over-TCP, IPC `StartTunnel` payload extension, and hot-reload semantics. Round-2 introduction.
when_to_use: Phase R8 (schema + REST + panel + tunnel-form picker, no dataplane yet) and Phase R9 (Rust dataplane SOCKS5 client with N parallel connections). Any later phase that touches `upload_mode`, `upload_listen_mode`, the `socks5_proxies` table, or the SOCKS5 portion of the `StartTunnel` IPC payload.
---

# Skill — SOCKS5 upload (parallel-connection mode)

## When to use this skill

- Phase R8 — designing the storage (`socks5_proxies` table),
  validation, REST API, and the panel pages and tunnel-form picker.
- Phase R9 — building the Rust dataplane SOCKS5 client with
  N parallel TCP connections to one proxy.
- Any later phase that touches `upload_mode` on a tunnel, the
  Remote's `upload_listen_mode`, or the IPC `StartTunnel` payload
  shape.

## The problem this feature solves

The user's setup includes a SOCKS5 proxy that fronts **several
Starlink uplinks**. A new TCP connection to the proxy lands on a
random link. The project's existing WireGuard upload path uses **one**
upload tunnel and therefore **one** Starlink link. To use the
aggregate bandwidth of multiple links, the dataplane must open
**multiple parallel TCP connections** to the proxy, and spread
upload traffic across them.

This is an **upload-path** feature only. The download path
(spoofed UDP/TCP-SYN/ICMP/ICMPv6) is unchanged.

## Architectural shape (mirrors WireGuard)

The panel and storage are shaped exactly like the existing WireGuard
section so the operator's mental model transfers:

| WireGuard side | SOCKS5 side |
|---------------|-------------|
| `wireguard_configs` table | `socks5_proxies` table |
| `/api/wg-configs` REST | `/api/socks5-proxies` REST |
| `frontend/pages/wireguard/{index,new,[id]}.vue` | `frontend/pages/socks5/{index,new,[id]}.vue` |
| sidebar "WireGuard" entry | sidebar "SOCKS5" entry |
| `tunnel.wg_config_id` FK | `tunnel.socks5_proxy_id` FK |
| `tunnel.upload_mode='wireguard'` (default) | `tunnel.upload_mode='socks5'` |

When `upload_mode='wireguard'`, `socks5_proxy_id` must be NULL.
When `upload_mode='socks5'`, `wg_config_id` must be NULL.
Validation enforces this server-side; the form hides the unused
picker client-side.

## Storage shape (Phase R8)

Migration `control-plane/internal/migrations/0006_socks5_proxies.sql`:

```sql
CREATE TABLE socks5_proxies (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT NOT NULL UNIQUE,
  host                 TEXT NOT NULL,          -- IPv4, IPv6, or hostname
  port                 INTEGER NOT NULL,
  username             TEXT,                   -- optional SOCKS5 auth (NULL = no auth)
  password             TEXT,                   -- stored at rest; redacted in API
  parallel_connections INTEGER NOT NULL DEFAULT 4,
  notes                TEXT,
  created_at           TIMESTAMP DEFAULT (datetime('now')),
  updated_at           TIMESTAMP DEFAULT (datetime('now'))
);
CREATE INDEX socks5_proxies_name ON socks5_proxies(name);

ALTER TABLE tunnels
  ADD COLUMN upload_mode TEXT NOT NULL DEFAULT 'wireguard'
    CHECK (upload_mode IN ('wireguard', 'socks5'));
ALTER TABLE tunnels
  ADD COLUMN socks5_proxy_id INTEGER REFERENCES socks5_proxies(id);

-- Remote-side counterpart: when the matching Client sends via
-- SOCKS5, the Remote must accept SOCKS5-framed TCP, not raw UDP.
ALTER TABLE tunnels
  ADD COLUMN upload_listen_mode TEXT NOT NULL DEFAULT 'udp'
    CHECK (upload_listen_mode IN ('udp', 'socks5_tcp'));
```

## Secret handling

`password` follows the same rules as the existing PSK / WG private
key (`.claude/CLAUDE.md` §5):

- Never appears in logs.
- API list/get returns `"***"` for password unless `?reveal=1`
  (admin only).
- Excluded from audit-log details on create/update.
- Included in backup file as-is (the operator is the only one who
  can download it).

## REST API (Phase R8)

Pattern matches `control-plane/internal/api/wg_handlers.go`.

```
GET    /api/socks5-proxies          → list (password "***")
POST   /api/socks5-proxies          → create
GET    /api/socks5-proxies/:id      → get (password "***", or raw if ?reveal=1)
PUT    /api/socks5-proxies/:id      → update (omit password to keep existing)
DELETE /api/socks5-proxies/:id      → refuses if any tunnel references it
```

Server role gating: SOCKS5 proxies are useful on the Client (which
needs them for upload) only. The Remote never originates SOCKS5
connections. **Show the SOCKS5 page on both roles** for now (a single
panel install lets the operator copy proxy details around); deferring
remote-side hiding until it actually causes confusion.

## Frontend (Phase R8)

The tunnel-form picker in `frontend/components/tunnel/TunnelForm.vue`:

```
Upload mode:  [ WireGuard ▼ ]
              ┌─────────────────────────────────────┐
              │ ⓘ "SOCKS5 spreads upload across      │
              │   multiple Starlink links behind a   │
              │   single proxy. Pick N parallel      │
              │   connections per proxy."            │
              └─────────────────────────────────────┘

WireGuard config: [ pick-one ▼ ]   <-- shown only if upload_mode=wireguard
SOCKS5 proxy:     [ pick-one ▼ ]   <-- shown only if upload_mode=socks5
```

Use the same `LabeledField` + `Select` pattern as the rest of the
form (see `.claude/skills/web-panel-components/SKILL.md`). The
inline help mentions Starlink because that's the user's actual use
case; keep it concrete.

## Dataplane (Phase R9)

### Connection pool

For each Client tunnel with `upload_mode='socks5'`:

```
struct Socks5Pool {
    proxy: Socks5Target,                          // host, port, username, password
    parallel: usize,                              // N
    conns: Vec<Arc<Mutex<Socks5Conn>>>,           // N healthy connections
    next: AtomicUsize,                            // for round-robin or stickiness
}

struct Socks5Conn {
    stream: TcpStream,                            // CONNECT'd to upload_target_addr
    write_buf: BytesMut,                          // reused per send
}
```

On `StartTunnel`:
1. Open N TCP connections to `(proxy.host, proxy.port)`.
2. Each does the SOCKS5 handshake (greeting + auth + CONNECT to the
   Remote's `upload_target_addr`).
3. Park each connection in the pool. Send a periodic keepalive
   (`tcp_keepalive_time=60s` is enough).
4. On any single connection failure, reconnect in the background;
   sessions on that connection re-hash to a healthy one.

### Spreading strategy

Two options; pick **per-session stickiness** for first delivery:

- **Per-session sticky:** hash `(client_addr, local_port)` to a slot
  `0..N`. All packets for that UDP flow go through the same TCP
  connection. Prevents out-of-order delivery within a flow.
  Trade-off: skewed flow sizes can imbalance the pool.
- **Per-packet round-robin:** packet i goes to connection
  `i % N`. Perfect spread but the Remote sees out-of-order
  packets per flow; harmless for UDP semantics but may upset
  latency-sensitive applications.

Implementation lives in `data-plane/src/upload/socks5.rs`. Cross-
reference `wireguard.rs` (sibling module) for the trait shape; both
implement `UploadTransport`.

### Wire framing

SOCKS5 carries TCP, not UDP. The proxy is a passthrough — anything we
write on the TCP socket arrives at the Remote in order. So we have to
re-segment ourselves:

```
[u16 BE length][payload bytes]  ... repeat per UDP packet
```

The Remote's `upload_listen_mode='socks5_tcp'` mode opens a TCP
listener instead of a UDP one, reads `[u16][payload]` frames, and
hands each payload to the rest of the pipeline as if it had arrived
on UDP. Reuse the existing `data-plane/src/tunnel/remote.rs`
forward path; only the input side differs.

### IPC

Extend the `StartTunnel` payload (see
`.claude/skills/rust-go-ipc/SKILL.md`) with an optional
`socks5_target` block:

```jsonc
{
  "type": "StartTunnel",
  "payload": {
    // existing fields...
    "upload_mode": "socks5",                  // "wireguard" | "socks5"
    "socks5_target": {                        // present iff upload_mode='socks5'
      "host": "192.0.2.10",
      "port": 1080,
      "username": "alice",                    // optional
      "password": "secret",                   // optional
      "parallel_connections": 8
    },
    "upload_listen_mode": "socks5_tcp"        // remote-side only
  }
}
```

Old dataplanes that don't know about the field can be forced to
reject with `RESTART_REQUIRED` if the new field is set; alternatively
the Go side refuses to start a SOCKS5 tunnel against a dataplane
that didn't return SOCKS5 in its `Ready` event capability list. Plan
for capability negotiation in R9.

### Hot-reload

| Field | Behaviour |
|-------|-----------|
| `parallel_connections` | Live: open additional / drain extras |
| `host`, `port` | `RESTART_REQUIRED` |
| `username`, `password` | `RESTART_REQUIRED` (must redo handshake) |
| Switching `upload_mode` | `RESTART_REQUIRED` (different transport entirely) |

## Validation gotchas

- A Client tunnel with `upload_mode='socks5'` must have a matching
  Remote tunnel with `upload_listen_mode='socks5_tcp'` and the same
  `upload_target_addr`. Server-side validation can't enforce the
  match (no inter-server channel — PRD invariant) but the panel
  inline help must call it out.
- `parallel_connections >= 1`. Default 4. Cap at 64 (defence
  against accidental fork bomb of TCP connections).
- SOCKS5 auth: username + password are both NULL or both non-NULL.
- Hostnames as `host` are allowed, but resolve to a fixed IP at
  start to avoid DNS-injection of unwanted egress.

## Testing strategy

For CI without a real Starlink LB: use **`microsocks`** or
**`dante-server`** as a local SOCKS5 proxy:

```bash
# microsocks (single-binary, easy):
apt-get install microsocks
microsocks -i 127.0.0.1 -p 1080
```

Configure a tunnel against `127.0.0.1:1080` with
`parallel_connections=4`. Verify with `ss -tnp | grep microsocks`
that 4 connections are open. Drive UDP through the tunnel; assert
identical bytes round-trip.

Live (the user's real LB): set `parallel_connections=8`; verify on
the proxy's `ss -tnp` that 8 connections from the dataplane are
present. Run `iperf3 -u -b 250M -t 60`; expect sustained
≥ 150 Mbit/s with < 5 % loss (Starlink links are higher variance
than fixed-line; 75 % of WG-mode throughput is the acceptance bar).

## What this skill does NOT cover

- The SOCKS5 protocol bytes themselves (RFC 1928). Use the
  `socks5` or `tokio-socks` crate; don't hand-roll.
- UDP-over-SOCKS5 (UDP ASSOCIATE). We're tunneling UDP payloads
  inside a TCP SOCKS5 CONNECT, not asking the proxy for UDP relay.
- HTTP-CONNECT proxies. Different protocol, not in scope.
- Authentication beyond username/password (GSS-API, etc.). Not in
  scope for v1.0.0.

## Cross-references

- `.claude/skills/wireguard-config-handling/SKILL.md` — sibling
  upload abstraction; the SOCKS5 implementation mirrors its panel
  + lifecycle patterns.
- `.claude/skills/db-migrations/SKILL.md` — for adding migration
  0006 safely.
- `.claude/skills/web-panel-components/SKILL.md` — for the form
  pattern and the role-aware sidebar entry.
- `.claude/skills/rust-go-ipc/SKILL.md` — for extending the
  `StartTunnel` payload with the SOCKS5 block.
