---
name: rust-go-ipc
description: The IPC contract between the Go control plane and the Rust data plane — Unix domain socket transport, wire format, message catalog, lifecycle, error handling, and backpressure rules.
when_to_use: Phase 8a builds this protocol. Any phase that adds a new command from Go to Rust (e.g., new tunnel field that needs hot-reload in Phase 10, new metric in Phase 11, log-level change in Phase 12) must extend the message catalog here. Read before touching `control-plane/internal/ipc/` or `data-plane/src/ipc.rs`.
---

## Transport

- **Socket type:** `AF_UNIX`, `SOCK_STREAM` (Unix domain socket, stream).
- **Path:** `/run/sublyne/dataplane.sock`.
- **Permissions:** Mode `0600`, owned by `sublyne:sublyne`. Set by the
  Rust process when it `bind()`s. The `sublyne` user is the only one
  who can talk to it.
- **Direction:** Rust is the server, Go is the client. Go dials the
  socket; Rust accepts a single concurrent connection (one Go process).
  If Rust crashes and respawns, Go reconnects.

### Why a stream socket, not a datagram socket?

Stream gives us ordering and reliable delivery within the connection,
and lets us frame messages of any size without worrying about
`SOCK_DGRAM` per-message size limits. The connection lifecycle (single
client, single server) makes the connection-oriented model natural.

## Wire format

Length-prefixed JSON frames. Every message on the wire is:

```
+----------------+----------------------------------+
| 4-byte big-end | UTF-8 JSON body of exactly that  |
| length (uint32)| many bytes                       |
+----------------+----------------------------------+
```

- Length is the byte count of the JSON body (does **not** include the
  4-byte header itself).
- Max body size: **16 MiB** (sanity cap, enforced on both sides;
  exceeding it is a protocol violation and the receiver closes the
  connection).
- JSON is UTF-8, parsed strictly (no trailing commas, no comments).

### Why JSON, not protobuf / msgpack / capnp?

The control↔data IPC is **low-rate** — commands are user-driven (a
human clicking "Start tunnel"), and metrics push at most every 5
seconds with a fully-batched payload. There's no per-packet IPC. JSON
makes debugging trivial (`socat - UNIX-CONNECT:/run/sublyne/dataplane.sock`
and you can read the traffic). If we ever profile and find the codec
matters, swapping to MessagePack is a one-day change (same envelope,
binary body) — but we'll be surprised if it ever does.

## Message envelope

Every JSON body has this shape:

```json
{
  "type": "StartTunnel",
  "id": "9b3e8b3a-...-uuid",
  "payload": { /* type-specific */ }
}
```

- `type` — the message name from the catalog below (PascalCase).
- `id` — a UUIDv4 string. Required on commands so replies can be
  correlated. Required on events too (server picks one); Go uses it
  only for log correlation.
- `payload` — the body. Always an object (never a bare array or
  scalar), even if empty: `"payload": {}`.

### Reply correlation

Commands (Go → Rust) get a `Reply` from Rust echoing the same `id`:

```json
{ "type": "Reply", "id": "9b3e8b3a-...", "payload": { "ok": true } }
```

Errors:

```json
{
  "type": "Reply",
  "id": "9b3e8b3a-...",
  "payload": {
    "ok": false,
    "error": {
      "code": "PORT_IN_USE",
      "message": "UDP port 443 is already bound by another process"
    }
  }
}
```

Events (Rust → Go, unsolicited) carry their own fresh `id` and never
get replied to.

## Message catalog (v1)

Authoritative list. Adding a new message: add it here first, then
update the Go and Rust types. Don't ad-hoc invent new types.

### Commands (Go → Rust)

| Type | Payload | Description |
|------|---------|-------------|
| `Ping` | `{}` | Health check. Reply: `{ "ok": true }`. |
| `StartTunnel` | full tunnel spec — see schema below | Bring up listener, raw socket, WG interface (Client side) for this tunnel. |
| `StopTunnel` | `{ "id": <tunnel_id> }` | Tear down listeners and per-tunnel state. |
| `UpdateTunnel` | partial tunnel spec including `id` | Hot-reload any editable field. Restart-required fields (`local_listen_addr`, `upload_listen_addr`) return error `RESTART_REQUIRED`. |
| `GetStats` | `{ "tunnel_id": <id> \| null }` | Synchronous metrics fetch (null = all tunnels). Used on dashboard refresh; the 5-second push is separate. |
| `SetLogLevel` | `{ "level": "trace"\|"debug"\|"info"\|"warn"\|"error" }` | Change dataplane log level live. |
| `ListTunnels` | `{}` | Returns the dataplane's view of running tunnels (sanity check vs. DB). |
| `Shutdown` | `{}` | Graceful exit. Used by Go supervisor on SIGTERM. |

### Events (Rust → Go)

| Type | Payload | Description |
|------|---------|-------------|
| `Ready` | `{ "version": "..." }` | Sent once after dataplane finishes init and is ready for commands. |
| `StatsReport` | `{ "samples": [PerTunnelStats, ...], "system": SystemStats }` | Pushed every 5 s. |
| `TunnelStateChanged` | `{ "tunnel_id": ..., "state": "running" \| "starting" \| "stopped" \| "error", "reason": "..." \| null }` | Whenever a tunnel's lifecycle state changes asynchronously (e.g., WG handshake established, raw socket error). |
| `LogLine` | `{ "level": "...", "ts": "...", "msg": "...", "fields": {...} }` | Streamed log lines from the dataplane. Go writes them to the same log file as its own. |
| `Error` | `{ "code": "...", "message": "...", "context": {...} }` | Unrecoverable internal error. Followed by the dataplane exiting; Go supervisor restarts it. |

### Tunnel spec schema (used by Start/Update)

```json
{
  "id": "uuid",
  "role": "client" | "remote",
  "name": "tunnel-1",
  "enabled": true,
  "mtu": 1400,
  "psk": "base64-32-bytes",
  "max_connections": 50000,
  "idle_timeout_sec": 300,
  "download_transport": "udp" | "tcp_syn" | "icmp" | "icmpv6",
  "ping_smoothing_enabled": false,
  "ping_smoothing_target_ms": 60,
  "pacing_enabled": false,
  "pacing_target_ms": 100,

  // Client-only:
  "local_listen_addr": "0.0.0.0:443",
  "download_receive_port": 8443,
  "download_spoof_source_ip": "1.2.3.4",
  "download_spoof_source_port": 443,
  "upload_target_addr": "5.6.7.8:55555",
  "wireguard_interface": "sub-wg-0",
  "wireguard_fwmark": 4097,

  // Remote-only:
  "upload_listen_addr": "0.0.0.0:55555",
  "forward_target": "10.0.0.1:1080",
  "download_send_port": 8443,
  "client_real_ip": "9.8.7.6"
}
```

Fields irrelevant to the tunnel's role are omitted (not present, not
`null`). The Rust side validates required fields per role.

### Stats payload schema

```json
{
  "samples": [
    {
      "tunnel_id": "uuid",
      "bytes_in": 1234567890,
      "bytes_out": 9876543210,
      "packets_in": 12345,
      "packets_out": 67890,
      "active_sessions": 42,
      "last_packet_received_at_unix": 1717000000,
      "last_packet_sent_at_unix": 1717000001,
      "upload_rtt_ms_ewma": 42.7,
      "download_rtt_ms_ewma": 60.3,
      "packet_loss_estimate": 0.001,
      "wg_handshake_at_unix": 1717000000
    }
  ],
  "system": {
    "cpu_percent": 23.4,
    "mem_used_bytes": 1234567890,
    "mem_total_bytes": 4294967296,
    "disk_used_bytes": 12345678901,
    "disk_total_bytes": 53687091200,
    "net_interfaces": {
      "eth0": { "rx_bytes_per_sec": 1000000, "tx_bytes_per_sec": 500000 }
    }
  }
}
```

Stats are **cumulative since dataplane start** for `bytes_*`/`packets_*`
counters (Go computes deltas in the metrics ring buffer). The
`*_per_sec` fields under `net_interfaces` are pre-computed
instantaneous rates (Rust runs the diff itself for OS counters because
the Go side doesn't have access to `/proc/net/dev` reads at the same
cadence).

## Connection lifecycle (Go client)

```
1. Service start. Go supervisor extracts and execs the dataplane child.
2. Go dials /run/sublyne/dataplane.sock with retry (10 attempts, 200 ms
   apart) — gives the dataplane time to bind.
3. Connect succeeds → Go waits for a `Ready` event (max 10 s) before
   sending commands.
4. Steady state: Go sends commands and receives events on the same
   connection.
5. If Rust exits (crash, OOM, etc.):
   - The TCP-like read returns EOF.
   - Go logs the disconnect, marks all tunnels as "stopped" in its
     in-memory state, and notifies WebSocket subscribers.
   - The Go supervisor detects the child exit (waitpid / cmd.Wait) and
     respawns it within 1 s (max 5 respawns/minute; exceed that and
     surface a panel error).
   - Go re-dials, waits for `Ready`, and re-sends `StartTunnel` for
     every tunnel marked `enabled` in DB.
6. On SIGTERM, Go sends `Shutdown`, waits up to 5 s for a clean exit,
   then SIGKILL.
```

## Concurrency model

### Go side (`control-plane/internal/ipc/client.go`)

- One goroutine reads frames off the socket and dispatches by `type`
  to channels keyed on `id` (for replies) or fan-out subscribers (for
  events).
- A bounded `chan IPCCommand` is the write side; one goroutine drains
  it and writes frames.
- `Send(ctx, cmd) (Reply, error)` is the public API: it pushes the
  command on the write channel, then waits for a reply on the
  per-`id` channel, or returns when `ctx` is done.
- Subscribe API: `SubscribeStats() <-chan StatsReport`,
  `SubscribeLogs() <-chan LogLine`, etc.

### Rust side (`data-plane/src/ipc.rs`)

- Tokio task per connection (only one active connection at a time;
  if a second client appears, close it with an `Error`-coded
  `MULTIPLE_CONNECTIONS` and exit the new connection).
- One task reads frames; commands are dispatched to a tunnel
  controller (per-tunnel actor pattern via mpsc channels).
- One task aggregates per-tunnel stats every second into a cumulative
  view and emits `StatsReport` every 5 s.

## Backpressure

- **Go → Rust write side:** bounded `chan IPCCommand` of capacity
  256. If a caller would block (e.g., user clicks Start on 300
  tunnels simultaneously), the call returns `ErrCommandQueueFull` and
  the UI shows a "panel is busy, try again" toast. This will basically
  never happen in practice.
- **Rust → Go read side:** bounded subscriber channels, default
  capacity 16. If the stats subscriber is slow, drop the oldest
  sample (the dashboard only cares about the latest anyway). Log
  drops at DEBUG.

Never block in the IPC read or write loops. Drops are preferable to
backpressure-blocking the IPC connection.

## Error codes (initial set)

| Code | Meaning |
|------|---------|
| `PORT_IN_USE` | The requested `local_listen_addr` / `upload_listen_addr` is already bound. |
| `RAW_SOCKET_FORBIDDEN` | Couldn't open `AF_INET/SOCK_RAW` — capability missing. |
| `RESTART_REQUIRED` | `UpdateTunnel` carried a field that can only be applied via Stop+Start. |
| `WG_BRINGUP_FAILED` | netlink call to create/configure the WG interface failed. Context includes the syscall errno. |
| `TUNNEL_NOT_FOUND` | The `tunnel_id` in a Stop/Update isn't known to the dataplane. |
| `MULTIPLE_CONNECTIONS` | A second IPC client tried to connect; the second is closed. |
| `INVALID_TUNNEL_SPEC` | Missing or malformed field on Start/Update. Context lists the bad fields. |
| `INTERNAL` | Catch-all for unrecoverable internal errors. Followed by dataplane exit. |

Error codes are stable strings; the Go side may branch on them. The
`message` is for humans; never branch on it.

## Versioning

The current protocol version is **v1**. There's no version-negotiation
handshake yet (Go and Rust always ship together inside the same binary
release, so version skew can't happen at runtime). The protocol bumps
to v2 only if we change the on-wire envelope; new message types are
fine within v1 (the receiver ignores unknown `type` strings with a
WARN log).

If we ever introduce decoupled releases, add `Hello` / `HelloAck`
frames that exchange protocol versions before any real traffic.

## Debugging

- **Watch the wire:**
  `sudo socat - UNIX-CONNECT:/run/sublyne/dataplane.sock`
  But — only one client at a time, and you'll disrupt the real Go
  client. Better:
- **Tee approach (dev only):** start a `socat`
  `UNIX-LISTEN:/tmp/dp-tee.sock,fork` that forwards to the real
  socket and prints to stderr. Useful for debugging early phases.
- **Per-message logging:** Set `RUST_LOG=sublyne_dataplane::ipc=trace`
  in dev to see every parsed message. Production INFO level skips
  per-message detail.

## Don't do

- Don't bypass the envelope to send a "naked" JSON blob — every
  message has `type` + `id` + `payload`.
- Don't add length headers to the `payload` separately. The 4-byte
  outer length is the *only* length.
- Don't share the socket with anything else. Use `RuntimeDirectory`
  in systemd to keep `/run/sublyne/` exclusive.
- Don't try to make the dataplane queryable from outside the Go
  process. The IPC is internal.
