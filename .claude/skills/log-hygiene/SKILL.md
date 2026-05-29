---
name: log-hygiene
description: How log lines flow from the Rust dataplane through the Go supervisor to `journald`, the rotating file at `/var/lib/sublyne/logs/app.log`, and the panel's Logs page — and how to keep them human-readable. Covers disabling Rust's `tracing-subscriber` ANSI colour output (`with_ansi(false)`), the optional `SUBLYNE_LOG_FORMAT=json` mode for structured logs, ANSI stripping on the Go side, and rendering clean level-tagged lines in `frontend/pages/logs.vue`. Round-2 introduction.
when_to_use: Phase R5 (logging hygiene end-to-end). Any later phase that adds a new log line on the hot path, changes the supervisor's log capture (`control-plane/internal/ipc/supervisor.go`), modifies `data-plane/src/main.rs` tracing setup, or touches `frontend/pages/logs.vue`.
---

# Skill — Log hygiene end-to-end

## The problem this skill solves

In v0.1.x the live `journalctl -u sublyne` output looks like this:

```
sublyne[42239]: time=…Z level=INFO msg=dataplane line="\x1b[2m2026-05-22T16:10:05.981506Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2msublyne_dataplane::tunnel::client\x1b[0m\x1b[2m:\x1b[0m client: local_listen bound \x1b[3mtunnel_id\x1b[0m\x1b[2m=\x1b[0m1 \x1b[3maddr\x1b[0m\x1b[2m=\x1b[0m0.0.0.0:5001 …"
```

The `\x1b[…m` sequences are ANSI colour escapes emitted by Rust's
`tracing-subscriber` fmt layer (`data-plane/src/main.rs:52` — the
default of `tracing_subscriber::fmt::layer()` enables colour
unconditionally regardless of TTY). The Go supervisor captures the
line **verbatim** and embeds it as the value of slog's `line` field;
journald and the file sink and the panel's Logs page all see the
escapes. They make the logs visually unreadable in everything that
isn't a colour-aware terminal — which is everything, in production.

## How log lines actually flow today

Reading the v0.1.x code (Round-1 audit notes; verify before touching):

1. **Rust dataplane** (`data-plane/src/main.rs:50-53`) initialises
   `tracing_subscriber::registry().with(filter_layer).with(fmt::layer().with_target(true)).init()`.
   The fmt layer writes coloured text to stdout.
2. **Go supervisor** (`control-plane/internal/ipc/supervisor.go`)
   forks the dataplane with stdout + stderr piped to a
   `supervisorLogWriter` (around line 209). That writer
   splits the byte stream on `\n` and calls
   `w.logger.Log(ctx, INFO, "dataplane", "line", lineText)` —
   the raw text, ANSI bytes and all, becomes the value of the
   `line` field in slog.
3. **slog text handler** (`control-plane/internal/logging/`) writes
   the structured record to stdout (→ journald) and to a fanout
   that also writes to the rotating file and the in-memory LogBus.
   Neither sink strips ANSI.
4. **Panel's Logs page** (`frontend/pages/logs.vue`) subscribes to
   the LogBus over WebSocket and renders each entry. ANSI bytes
   render as garbage; level badges parse fine from the slog record
   itself, so only the `line=…` body is corrupted.

The IPC `LogLine` event type was defined in Phase 12 but is **not
currently wired up** — the supervisor only piggybacks on stdout.

## The fix (Phase R5)

Three small changes, no schema or wire-format changes:

### 1. Rust: disable ANSI by default

`data-plane/src/main.rs`:

```rust
let fmt_format = std::env::var("SUBLYNE_LOG_FORMAT")
    .unwrap_or_else(|_| "text".to_string());

let fmt_layer = tracing_subscriber::fmt::layer()
    .with_target(true)
    .with_ansi(false);                       // <-- the key line

let registry = tracing_subscriber::registry().with(filter_layer);

if fmt_format == "json" {
    registry.with(fmt_layer.json()).init();
} else {
    registry.with(fmt_layer).init();
}
```

`with_ansi(false)` strips the colour escapes at the source.
`SUBLYNE_LOG_FORMAT=json` is an optional structured-log mode (see
§3).

### 2. Go supervisor: strip ANSI defensively

If the dataplane the supervisor is running is an *older* binary
that still emits ANSI (or any other tool writes coloured output to
stdout), strip on receive:

```go
// control-plane/internal/ipc/supervisor.go
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (w *supervisorLogWriter) Write(p []byte) (int, error) {
    n := len(p)
    for _, raw := range bytes.Split(p, []byte{'\n'}) {
        line := strings.TrimSpace(string(raw))
        if line == "" {
            continue
        }
        line = ansiRE.ReplaceAllString(line, "")
        w.logger.Log(context.Background(), w.level, "dataplane",
            "line", line)
    }
    return n, nil
}
```

Belt-and-suspenders: the Rust side won't emit ANSI any more, but
this protects the user from a hand-rolled debug build or future
regression.

### 3. Go supervisor: parse JSON if Rust is in JSON mode

When `SUBLYNE_LOG_FORMAT=json`, dataplane lines look like:

```json
{"timestamp":"2026-05-22T16:10:05.981Z","level":"INFO","target":"sublyne_dataplane::tunnel::client","fields":{"message":"client: local_listen bound","tunnel_id":1,"addr":"0.0.0.0:5001","family":"ipv4"}}
```

Detect by leading `{` and parse:

```go
if len(line) > 0 && line[0] == '{' {
    var rec map[string]any
    if err := json.Unmarshal([]byte(line), &rec); err == nil {
        level := slog.LevelInfo
        switch strings.ToUpper(getStr(rec, "level")) {
        case "ERROR": level = slog.LevelError
        case "WARN":  level = slog.LevelWarn
        case "DEBUG": level = slog.LevelDebug
        case "TRACE": level = slog.LevelDebug - 4
        }
        msg := "dataplane"
        if fields, ok := rec["fields"].(map[string]any); ok {
            if m, ok := fields["message"].(string); ok { msg = m }
        }
        attrs := []slog.Attr{slog.String("target", getStr(rec, "target"))}
        // Hoist top-level fields (tunnel_id, addr, etc.) into attrs:
        if fields, ok := rec["fields"].(map[string]any); ok {
            for k, v := range fields {
                if k == "message" { continue }
                attrs = append(attrs, slog.Any(k, v))
            }
        }
        w.logger.LogAttrs(context.Background(), level, msg, attrs...)
        continue
    }
}
// fallback: treat as plain text (with ANSI stripped above).
```

Result: `journalctl -u sublyne` looks like:

```
sublyne[42239]: time=…Z level=INFO target=sublyne_dataplane::tunnel::client msg="client: local_listen bound" tunnel_id=1 addr=0.0.0.0:5001 family=ipv4
```

Same shape on the panel's Logs page: the level badge comes from
slog's level, the message is clean, and structured fields render as
chips beside the line.

## Operator-facing toggles

| Knob | Default | Effect |
|------|--------:|--------|
| `SUBLYNE_LOG_FORMAT=text` | (default) | Rust emits plain text (no ANSI); Go logs as `line="…"`. |
| `SUBLYNE_LOG_FORMAT=json` | off | Rust emits one JSON object per line; Go parses + hoists fields. |
| Existing `--log-level` (settings → log level) | `INFO` | Unchanged. Live-reloadable via the panel; the IPC `SetLogLevel` command swaps the Rust filter and the Go slog level together. |

Set via systemd drop-in:

```ini
# /etc/systemd/system/sublyne.service.d/log-format.conf
[Service]
Environment=SUBLYNE_LOG_FORMAT=json
```

## Pitfalls

- **`with_ansi(false)` is *not* the same as detecting a TTY.** The
  `tracing-subscriber` `ansi` feature defaults to `true` and the
  fmt layer's default is `with_ansi(true)` regardless of whether
  stdout is a pipe. You must call `with_ansi(false)` explicitly
  for production builds. We do this unconditionally because the
  dataplane stdout is **always** piped (it's spawned by the Go
  supervisor — never run interactively).
- **`tracing-subscriber`'s `json()` mode requires the `json` feature.**
  Add `json` to the `tracing-subscriber` dependency in
  `data-plane/Cargo.toml` if it's not already there.
- **Don't parse JSON every line if the format is text.** The cheap
  `line[0] == '{'` check at the top of the Go branch keeps the
  hot path zero-overhead in the default text mode.
- **The slog *level* field is what colours the panel badge**, not
  any ANSI in the message. Keep level mapping consistent across
  the two formats: ERROR/WARN/INFO/DEBUG/TRACE on both sides.
- **The rotating file at `/var/lib/sublyne/logs/app.log`** is read
  by tooling (`grep`, `less`, `tail -F`) that doesn't understand
  ANSI. Even if some future feature adds TTY-aware colour to the
  Go side, the file sink should always be plain.
- **Crash logs (`crash-<ts>.log`)** are unaffected — `install_panic_hook`
  in `data-plane/src/main.rs:124` writes plain text via `eprintln!`
  and direct file I/O. No ANSI involved.

## Cross-references

- `.claude/skills/web-panel-components/SKILL.md` — for the Logs
  page level-badge rendering.
- `.claude/skills/rust-go-ipc/SKILL.md` — for the (currently
  unused) `LogLine` event type; if a future phase wants to route
  dataplane logs through structured IPC instead of stdout, this
  is the wire format to extend.
- `data-plane/src/main.rs` — the one place ANSI is emitted today.
- `control-plane/internal/ipc/supervisor.go` — the one place
  stdout is captured today.
