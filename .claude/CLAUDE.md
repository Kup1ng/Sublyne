# CLAUDE.md — Sublyne

This file orients every fresh Claude Code chat that opens this repo.
Read it in full before touching anything. Sublyne is a clean fork of
the [Port-Forwarding](https://github.com/Kup1ng/Port-Forwarding)
project carrying the same proven Rust data plane + Go control plane,
re-branded under the **Sublyne** identity, with a brand-new Nuxt 3
panel and a hardened SOCKS5 upload pool.

---

## 1. What Sublyne is

A multi-tunnel UDP port-forwarding system that bypasses Iran's DPI by
splitting traffic across two asymmetric paths:

- **Upload** travels through a pre-purchased WireGuard tunnel (or, in
  the new SOCKS5 mode, through N parallel TCP connections to a
  load-balancing proxy fronting multiple Starlink uplinks) — standard,
  encrypted, kernel-handled.
- **Download** arrives as **crafted spoofed packets** whose source IP
  is a "white" IP whitelisted by Iran's central firewall. The
  receiving Client verifies an HMAC-SHA256 prefix and forwards the
  payload to the original end-user UDP socket.

Two server roles run the same binary: **Client** (Iran-side) and
**Remote** (foreign). They share static config (PSK, ports, IPs,
transport, MTU) and never talk to each other on any management
channel.

Target scale: **≥ 1 Gbps aggregate, ≥ 200 000 concurrent UDP sessions
per server** on a 2–4 vCPU VPS.

---

## 2. Architectural invariants (do not violate)

Load-bearing. If a change seems to require breaking one of these,
stop and surface it to the user — don't quietly work around it.

- **Asymmetric data path.** Upload via WireGuard or SOCKS5,
  download via raw-socket spoofing. The two paths share nothing
  but the PSK and tunnel config.
- **Forward protocol is an orthogonal layer (v4.0.0).** A tunnel's
  `forward_protocol` (`udp` default | `tcp`) is independent of
  download_transport and upload_mode. When `tcp`, a reliability engine
  (KCP or QUIC, in `data-plane/src/forward/`) sits BETWEEN the user's
  TCP socket and the existing seal/spoof/anti-replay pipeline — which
  keeps carrying opaque ≤MTU datagrams and never learns they hold
  KCP/QUIC framing. Do not push the engine below the seal layer or
  parallelise the Remote send side; the single send socket + 1024-slot
  SeqWindow invariants still hold. Engine datagrams are sized like a
  user UDP payload (≤ mtu − 2). Single-port only so far; multi-port TCP
  (one engine per port) is gated off in `spec::validate`.
- **No inter-server control plane.** Client and Remote never
  exchange management messages. All coordination is via shared static
  config.
- **Single admin user per server.** No RBAC, no multi-user. One
  username + password set at install time.
- **HTTP only on the panel.** No TLS, no ACME. The panel runs on
  `0.0.0.0:<random-5-digit-port>/<random-16-char-path>/` with rate
  limiting and brute-force lockout (5 fails / 5 min → 15-min IP
  lockout, 60 attempts/hr/IP cap).
- **HMAC-authenticated download path.** Every download payload
  carries a 16-byte HMAC-SHA256 prefix over `(session_id, seq,
  payload_hash)` keyed by the PSK. `session_id` is a random 64-bit
  word stamped at tunnel start so the verifier no longer depends on
  wall-clock skew between Iran and the foreign box. Anti-replay is
  a 1024-slot sliding window keyed by `seq`. Client drops any packet
  with wrong source IP/port, bad HMAC, replayed seq, or unknown
  session_id.
- **Single binary deployment.** End user runs `setup.sh` against a
  single `sublyne-linux-amd64` artifact. No external apt deps. The
  Rust dataplane is `go:embed`-bundled inside the Go binary and
  extracted at startup.
- **UDP payloads only.** TCP-SYN appears only as a *spoof envelope*
  for the download path, never as real TCP transport. The forwarded
  application traffic is always UDP.
- **No active health checks.** Tunnel status is derived from
  observed packet activity (Healthy < 60 s, Idle 60 s–5 min, Down
  > 5 min). systemd handles process-crash restart; the application
  never restarts itself based on health.
- **Linux-amd64 / Ubuntu 22.04 + 24.04 only.** `setup.sh` refuses
  to run on anything else.
- **End user is not a programmer.** Communicate in plain language,
  default to explaining, surface decisions not internals.

---

## 3. OPSEC — values that MUST NOT appear in this repo

This repo is **public**. The following classes of value must never
land in source, docs, tests, configs, comments, commit messages, or
history. Use placeholder ranges instead:

| Class | Use placeholder | Never use |
|-------|-----------------|-----------|
| White / spoof source IP | `203.0.113.42` (RFC 5737 TEST-NET-3) | The operator's actual whitelisted IP |
| Seller WireGuard endpoint | `198.51.100.10:51820` (RFC 5737 TEST-NET-2) | The seller's real WG endpoint |
| Iran-side box IP | `198.51.100.30` / `198.51.100.50` | Any real `185.x.x.x`, `46.x.x.x`, etc. |
| Foreign-side box IP | `198.51.100.40` / `198.51.100.60` | Any real public IP |
| `forward_target` example | `192.0.2.10:443` (RFC 5737 TEST-NET-1) | The operator's real proxy panel |
| Operator email in commits | `Kup1ng@users.noreply.github.com` | any real personal inbox (e.g. a personal gmail address) |
| PSK / password / API token | `psk-example`, `<your-psk>` | Any production secret bytes |
| Domain names | `example.com`, `example.org` | Any real production hostname |

If a value above slips into a commit, the fix is to scrub *and*
rewrite history before pushing. If it has already been pushed,
treat the value as burned and rotate it on the operator's side.

Logs, panel API responses, and audit-log details follow the same
rule: never echo a PSK, never log a password, redact WG private
keys, return `"***"` for the PSK field on tunnel reads, return the
SOCKS5 proxy password only when `?reveal=1` is set (admin only).

The Sublyne git identity for commits made by tooling in this repo:

```sh
git -C ./sublyne config user.name  "Kup1ng"
git -C ./sublyne config user.email "Kup1ng@users.noreply.github.com"
```

`@users.noreply.github.com` is a GitHub-issued no-reply alias that
links commits to the `Kup1ng` account without leaking a real
inbox. Change it to any other no-reply address you prefer.

---

## 4. Lessons embedded in this codebase (read before you "improve" anything)

These are not preferences — they are bug fixes paid for in real
operator outages on the predecessor project. Anywhere the code looks
"weird" it is probably one of these. Don't undo them without
understanding the failure they prevent.

- **DF bit cleared on every spoofed download packet.** Otherwise
  Iranian middleboxes return ICMP "fragmentation needed" and the
  flow stalls. See `data-plane/src/transport/*.rs`.
- **64 KiB socket recv buffers, doubled by the kernel.** The
  defaults silently drop ~20 % of packets at 200 Mbit/s; the bumped
  values keep `Udp:RcvbufErrors` near zero. See `data-plane/src/perf.rs`
  and `setup.sh` (writes `/etc/sysctl.d/99-sublyne.conf`).
- **WireGuard `ip rule` priority below 32766.** Sits above the
  kernel's default `main` rule so the per-tunnel fwmark actually
  steers the upload. See `control-plane/internal/wg/policy.go`.
- **`fwmark` per tunnel, set as `SO_MARK` on the upload socket** (not
  on every send) so the kernel routes packets without per-syscall
  cost. See `data-plane/src/tunnel/client.rs`.
- **Remote seal pipeline: N parallel seal workers, single send
  socket via `sendmmsg`.** Parallel HMAC compute, serial wire order.
  Don't parallelise the send side — it reintroduces the anti-replay
  skew bug fixed in PR #36 of the predecessor.
- **Anti-replay `SeqWindow`: 1024 slots wide, atomic CAS per slot.**
  Big enough to absorb real-world reordering on the Iran path.
  Smaller windows silently drop packets that arrive within a normal
  fan-out spread.
- **ICMP transport sends `echo-request` (type 8), not
  `echo-reply` (type 0).** Iranian middleboxes drop unsolicited
  echo-replies more aggressively. The receive side suppresses the
  kernel's auto-reply via `sysctl net.ipv4.icmp_echo_ignore_all`
  scoped to the tunnel's lifetime. See
  `data-plane/src/icmp_sysctl.rs` and `transport/icmp.rs`.
- **HMAC envelope uses a random 32-bit `session_id`, not a
  timestamp.** Iran boxes can't reach Cloudflare / Google /
  ntp.ubuntu.com — only `ntp.day.ir`. A wall-clock-based envelope
  silently dies the first time NTP drifts. See `data-plane/src/hmac.rs`.
- **TCP keepalive + `TCP_USER_TIMEOUT` on every SOCKS5 socket.**
  Without this a stale proxy/NAT binding takes Linux's default
  RTO_MAX (~120 s) to be noticed; the panel-visible symptom is "WG
  client takes 10 s to connect / stalls then limps". See
  `data-plane/src/perf.rs::tune_socks5_tcp_socket`.
- **Memory soft cap.** If RSS > ~70 % of system RAM, reject new
  sessions and surface a panel alert. Never self-kill — systemd will
  restart-loop. See `data-plane/src/memory.rs`.
- **Logs: ANSI off, optional JSON via `SUBLYNE_LOG_FORMAT=json`.**
  The dataplane writes to a pipe captured by the Go supervisor —
  never a TTY — so ANSI escapes always come out as junk. See
  `data-plane/src/main.rs` and `control-plane/internal/ipc/supervisor.go`.

---

## 5. Tech stack and commands

### 5.1 Data plane (Rust)

- Toolchain: stable Rust, **1.88.0** (bumped from 1.85 in v4.0.0 for the
  QUIC deps' MSRV). Pinned via `data-plane/rust-toolchain.toml`; keep
  CI (`ci.yml`, `release.yml`) in lockstep.
- Target: `x86_64-unknown-linux-musl` (static binary, no glibc dep).
- **Crypto provider = `ring`, never `aws-lc-rs`.** The v4 QUIC engine
  pulls quinn + rustls + rcgen, all of which default to `aws-lc-rs`
  (needs cmake/C++, breaks the static musl build). They're pinned to
  `ring`; the CI gate `cargo tree -i aws-lc-rs` must stay empty. The
  `kcp` engine is pure-Rust and adds no such constraint.

Commands (run from `data-plane/`):

```sh
cargo fmt --all
cargo fmt --all -- --check          # CI form
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-unknown-linux-musl
cargo audit                          # dependency CVE scan
```

### 5.2 Control plane (Go)

- Toolchain: Go 1.23 or newer (pinned in `control-plane/go.mod`).
- Layout: `control-plane/cmd/sublyne/main.go` +
  `control-plane/internal/...`.
- Frontend dist is embedded via `go:embed frontend_dist/*`; the Rust
  dataplane binary is embedded via
  `go:embed dataplane/sublyne-dataplane`.

Commands (run from `control-plane/`):

```sh
gofmt -l .                            # must print nothing
gofmt -w .                            # auto-format
go vet ./...
golangci-lint run
go test ./...
govulncheck ./...
go build -tags=embed -o ../sublyne-linux-amd64 ./cmd/sublyne
```

### 5.3 Frontend (Nuxt 3 SPA)

- Toolchain: Node 20 LTS, pnpm 9+.
- Layout: `frontend/` (separate from Go; built artifacts are copied
  to `control-plane/internal/webassets/frontend_dist/` before
  `go build`).
- Stack: **Vue 3 + Nuxt 3 + Tailwind only** — no shadcn-vue, no
  third-party component library. UI primitives (button, input,
  card, dialog, toast, badge, switch, …) are hand-built under
  `frontend/components/ui/` against Tailwind tokens. The visual
  language stays consistent because every primitive draws from the
  same `assets/css/main.css` design tokens (CSS custom properties
  for both light and dark themes).
- Icons: `lucide-vue-next`. No emoji as icons.
- Charts: `vue-chartjs` (Chart.js v4) with animations disabled.
- Nuxt is configured in **SPA mode** (`ssr: false`) — no Node server
  in production; the Go binary serves the static dist.

Commands (run from `frontend/`):

```sh
pnpm install --frozen-lockfile
pnpm dev                              # dev server with HMR
pnpm lint                             # eslint
pnpm typecheck                        # vue-tsc --noEmit
pnpm test                             # vitest run
pnpm build                            # → .output/public/
```

### 5.4 End-to-end build

```sh
./scripts/build.sh        # frontend → Rust → Go, produces sublyne-linux-amd64
```

---

## 6. Filesystem layout of the running service

The installer (`scripts/setup.sh`) lays out the host as:

| Path | Purpose | Owner | Mode |
|------|---------|-------|------|
| `/usr/local/bin/sublyne` | Go control-plane binary (embeds Rust + frontend) | root | 0755 |
| `/etc/sublyne/config.toml` | Bootstrap config (role, panel port, web path, log paths) | sublyne | 0640 |
| `/var/lib/sublyne/sublyne.db` | SQLite — tunnels, WG, SOCKS5, admin, audit, JWT key | sublyne | 0600 |
| `/var/lib/sublyne/logs/app.log` | Rotating app log (max 100 MB total, 7-day retention) | sublyne | 0640 |
| `/var/lib/sublyne/logs/crash-*.log` | Per-crash stack traces | sublyne | 0640 |
| `/var/lib/sublyne/dataplane` | Extracted-at-startup Rust dataplane binary | sublyne | 0700 |
| `/run/sublyne/dataplane.sock` | Unix socket for Rust↔Go IPC | sublyne | 0600 |
| `/etc/systemd/system/sublyne.service` | systemd unit | root | 0644 |

systemd unit highlights:

- `User=sublyne`, `Group=sublyne`
- `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`
- `Restart=on-failure`, `RestartSec=3`
- `RuntimeDirectory=sublyne`, `RuntimeDirectoryMode=0750`
- `ReadWritePaths=/var/lib/sublyne /run/sublyne /etc/sublyne`

### Why the dataplane binary lives under /var/lib, not /run

`/run` is mounted `tmpfs,noexec` on every recent Ubuntu, so a binary
extracted into `/run/sublyne/dataplane` would have the right mode but
`execve()` would still fail with `EACCES`. The Unix socket can stay
under `/run/sublyne/` (sockets don't need the exec bit); the binary
itself is extracted to `/var/lib/sublyne/dataplane`, on the regular
root filesystem (ext4, exec allowed).

### Operator recovery: `sublyne --reset-admin`

When the panel login is broken or the password has been lost, run
this on the box as root after stopping the service:

```sh
systemctl stop sublyne
/usr/local/bin/sublyne --config /etc/sublyne/config.toml --reset-admin
systemctl start sublyne
```

The command prompts for a new username + password (with
confirmation), re-hashes via Argon2id, replaces the single admin
row, and clears every active brute-force lockout. It does NOT
regenerate the JWT signing key — sessions issued before the reset
stay valid until their natural 31-day expiry.

---

## 7. Secret-handling rules

| Secret | Lives in | Never appears in |
|--------|----------|------------------|
| Admin password hash (Argon2id) | `admin` table | logs, API responses, audit log |
| Per-tunnel PSK | `tunnels.psk` column | logs, API responses (return `"***"`), audit log details |
| WireGuard private keys (inside pasted config) | `wireguard_configs.raw_text` | logs, API responses (return parsed pub fields + redacted raw text; cleartext only via `?reveal=1`), audit log |
| SOCKS5 proxy password | `socks5_proxies.password` | logs, API responses (return `"***"`; cleartext only via `?reveal=1`), audit log |
| JWT signing key (HS256, 32 random bytes) | `settings` row | logs, anywhere outside the signing routine |

API conventions:

- `GET /api/tunnels/:id` returns the PSK as the literal string `"***"`.
- `GET /api/wg-configs/:id` returns `raw_text` only when the
  explicit query param `?reveal=1` is set.
- `GET /api/socks5-proxies/:id` returns `password` only when
  `?reveal=1` is set.
- Backup downloads stream the SQLite file as-is.

Log lines must never contain secret bytes. If you're tempted to
`logger.Debug("tunnel %v", t)` where `t` includes the PSK, redact
first.

---

## 8. Git workflow

- `main` is always releasable. CI must be green before merging.
- Each focused change goes on a short-lived branch and lands via
  PR (`gh pr create`). The bootstrap commits and the initial
  Sublyne import skipped this and went direct to `main` — every
  subsequent change uses the branch-and-PR flow.
- Commit message style: **Conventional Commits**:
  - `feat(scope): subject` for new functionality
  - `fix(scope): subject` for bug fixes
  - `chore(scope): subject` for housekeeping
  - `docs(scope): subject` for docs-only changes
  - `refactor(scope): subject`, `test(scope): subject`, `ci(scope): subject`
  - Body: one short paragraph explaining *why*; bullet the *what*
    if needed.
- `release.yml` parses commit messages between the previous tag
  and `HEAD` to generate the changelog, so commit hygiene matters.
- **Never** force-push to `main`. Never use `--no-verify`. Never
  bypass signing. If a hook fails, fix the cause.
- When the user says "release X" or "release", compute the next
  semver based on the commits since the last tag (`fix:` → patch,
  `feat:` → minor, `feat!:` / `BREAKING CHANGE:` → major), tag,
  push the tag, and let `release.yml` do the rest. Initial release
  is `v0.1.0`.

---

## 9. Open decisions (inherited and re-confirmed for Sublyne)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Rust↔Go IPC | Unix socket at `/run/sublyne/dataplane.sock`, length-prefixed JSON frames | Easy to debug, low-rate traffic, both langs have stdlib support |
| Repo layout | Multi-folder single repo (`control-plane/`, `data-plane/`, `frontend/`) | Clean per-language tooling, single CI matrix |
| Migration tool | Plain SQL files in `control-plane/internal/migrations/`, embedded via `go:embed`, applied in order | Zero external deps |
| HTTP router (Go) | `chi` | Small, idiomatic |
| Kernel APIs for perf | `SO_REUSEPORT` + `recvmmsg`/`sendmmsg` + sharded session tables | Hits 1 Gbps without io_uring/XDP complexity |
| Chart library | `vue-chartjs` (Chart.js v4) | Smaller bundle, animations disabled to keep CPU flat |
| Component library | None — Vue 3 + Nuxt 3 + Tailwind only, primitives hand-built under `frontend/components/ui/` | Avoids the "generic shadcn AI look" and gives Sublyne a distinctive panel |
| WireGuard bring-up | `wgctrl-go` (kernel WG via netlink) | No userspace WG dep; kernel WG is built-in on Ubuntu 22/24 |
| Single vs two binaries | Single user-facing artifact, two processes at runtime (Go supervises extracted Rust child) | One file to ship; clean capability and crash isolation |
| Frontend package manager | `pnpm` | Fast, deterministic |
| JWT algo | HS256, 32-byte signing key generated at first start, stored in `settings` | No asymmetric key management; single-server scope |

---

## 10. For every new chat

1. **Read this `.claude/CLAUDE.md`** (the file you're reading now).
2. **Read the listed skills** under `.claude/skills/<name>/SKILL.md`
   *for the area you're touching*. Don't read all skills — only the
   ones the task references.
3. **Verify preconditions.** Check the actual repo state
   (`git status`, `ls`, `gh pr list`). The state you read in
   training data may be older than the current tree.
4. **Do the task. Only that task.** Don't reach forward into
   unrelated work; don't add features the user didn't ask for. If
   you find a gap, note it but defer it.
5. **Branch, commit, push, open PR** (unless the user explicitly
   wants direct-to-main, like during this bootstrap).
6. **Verify the acceptance test** in the PR description. If you
   can't run it locally (e.g., needs two real VPS hosts), say so
   explicitly and describe what the user should run instead.
7. **Stop.** Summarize what landed in plain language. The user is
   not a programmer.

If the user asks something ambiguous, ask first — never silently
invent requirements.
