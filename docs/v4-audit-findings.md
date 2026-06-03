# Sublyne v4.0.0 — deep audit findings

**Date:** 2026-06-03 · **Base:** `v4.0.0` (`origin/main`, commit `58a3dd0`) · **Audit branch:** `audit/v4-hardening`

This is the Checkpoint-1 deliverable of a hardening pass on the freshly-released
v4.0.0 (TCP forwarding via KCP/QUIC reliability engines). It records **what the
audit found**, not yet what was fixed. Fixes land in later checkpoints.

## How the audit was run

- **Local checks (all green):** Go `build`/`vet`/`test`, frontend
  `typecheck`/`lint`/`test`, Rust `cargo fmt --check`. CI is green on the
  `v4.0.0` tag and `origin/main`.
- The Rust dataplane targets static-musl/Linux and **cannot be compiled on the
  Windows dev host**, so — per the project's working model — code reasoning +
  a multi-agent adversarial review stand in for the local Rust compiler, and
  **GitHub CI is the final compiler** for every pushed change.
- **Method:** the whole codebase (Rust dataplane, Go control plane, Nuxt
  frontend, IPC contract, all 12 migrations, CI, installer, systemd) was read
  end-to-end by 9 parallel layer reviewers, producing 50 candidate findings;
  5 more were seeded from a hand audit of the hot paths. **Every one of the 55
  candidates was then independently, adversarially re-verified** against the
  real code (confirm / refute / refine severity + fix).

## Result at a glance

| | Count |
|---|---|
| Candidates raised | 55 |
| **Confirmed** | 44 |
| Partially confirmed (real core, narrowed) | 8 |
| Refuted (no bug) | 2 + 1 verify-timeout |

After de-duplication (the headline issue was found independently by 6
reviewers), the confirmed findings collapse to **7 must-fix bugs (bucket a)**,
**~15 smells (bucket b)**, and **~12 polish items (bucket c)**, plus 5
explicit "verified correct, no change needed" confirmations.

### Headline issues (plain language)

1. **Editing a *running* TCP tunnel's engine settings does nothing — silently.**
   If an operator changes the reliability engine (KCP↔QUIC), the tuning preset,
   the Advanced overrides, or even flips a tunnel from UDP to TCP forwarding
   while it is running, the panel says "saved" and the database is updated — but
   the live dataplane keeps running the **old** settings. The worst case is
   UDP→TCP: the panel now shows TCP and the operator hands end-users TCP
   (VLESS-TCP/WS) configs, but the box is still running the old UDP listener, so
   **nothing connects and no error is shown** until the operator manually Stops
   and Starts the tunnel. *(bucket a, high — fix in Checkpoint 2)*

2. **A KCP connection that goes idle while still open can leak and silently
   black-hole data.** When the idle-reaper retires a KCP connection, one of its
   two background tasks isn't told to stop: it keeps a file descriptor open, and
   any bytes the user sends afterward are fed into a connection that no longer
   exists — dropped into a void. Over a long-running box with reconnects this
   slowly leaks file descriptors. *(bucket a, high — fix in Checkpoint 2)*

3. **TCP forwarding needs the client to "speak first."** Both engines only wire
   up the far-side connection once the user's app sends its first byte. This is
   true for the intended use (VLESS-TCP / VLESS-WS, where the client always
   sends a handshake first) — but a "server-speaks-first" protocol (raw SMTP,
   FTP control, a MySQL greeting, an SSH banner) would hang until idle-reap.
   This was never a stated requirement; a proper fix changes the inner engine
   wire format and is risky this close to release, so the recommendation is to
   **document it as a known limitation now and fix it in a later release.**
   *(bucket a, high — **deferred with documentation**, see decision below)*

---

## Bucket (a) — real bugs, must-fix

| # | Severity | Title | Where | Fix summary | Found by |
|---|----------|-------|-------|-------------|----------|
| A1 | **high** | Forward-protocol / engine / preset / tuning edit on a running tunnel is silently classified as a hot-reload no-op; panel + DB report success while the old engine keeps running. UDP→TCP flip leaves the box running UDP. | `data-plane/src/tunnel/mod.rs` (`SpecSnapshot`, `from_spec`, `internal_restart_field_differs`); `data-plane/src/manager.rs` (`update_tunnel`) | Add `forward_protocol`, `tcp_reliability_engine`, `forward_kcp`, `forward_quic` (and `ports`) to `SpecSnapshot`/`from_spec`, and to `internal_restart_field_differs`, so a forward-field change routes through the **existing** internal Stop+Start (with rollback). These fields are spawn-time-only — keep them OUT of `MutableConfig`/`apply_updates`. Also fixes the matching `matches_spec` idempotency gap (CLI-3/GOI-3). | CLI-1, REM-1, SPEC-1, GOT-1, GOI-1, SEED |
| A2 | medium | Lowering MTU on a running TCP tunnel desyncs the engine: the engine's segment size is frozen at spawn, but the seal/upload caps read the live (hot-reloaded) MTU, so the Remote's TCP-forward upload listener **silently drops** every now-oversized engine datagram → the upload direction stalls. Also bypasses the QUIC ≥1252 floor that `validate()` enforces. | `data-plane/src/tunnel/mod.rs`; `client.rs:334`; `remote.rs:746,912`; `forward/{kcp,quic}.rs` | Track `mtu` + `forward_protocol` in `SpecSnapshot`; in `internal_restart_field_differs`, treat an MTU change as an internal restart **only for `forward_protocol=tcp`** tunnels (UDP keeps MTU hot-reloadable). The restart re-runs `validate()`, restoring the QUIC floor check. (Bundles with A1.) | CLI-2, GOI-2, REM-2, SEED |
| A3 | **high** | KCP per-connection read pump has no stop/close signal: on tunnel stop with an idle-open user conn, or on idle-reap of a still-open conn, the read pump task + TCP read-half fd leak; post-reap user bytes feed a no-longer-driven KCP and are silently black-holed. | `data-plane/src/forward/kcp.rs:575-613` (`spawn_read_pump`), `reap_idle`, `run` | Add a per-conv stop `Notify` to `Conv`; thread it (plus the engine `stop_rx`) into `spawn_read_pump` and `select!` on it at both await points (`read.read` and `window.notified`); fire it in `reap_idle` (and rely on `stop_rx` on engine stop). On wake the `OwnedReadHalf` drops → fd closes, task exits. (Write pump already unwinds correctly.) | ENG-2, SEED |
| A4 | medium | KCP fresh conv reaped on the very next tick once the engine has been up longer than `idle_timeout`: `last_activity_ms` starts at 0, so `idle = now − 0 ≥ idle_ms` is instantly true for a just-accepted conn that hasn't sent yet. | `data-plane/src/forward/kcp.rs:314` (`build_conv`), `reap_idle` | Initialize `last_activity_ms` to the current engine clock in `build_conv` (pass `now_ms` in) instead of 0, giving each fresh conv a full idle window. | ENG-6 |
| A5 | medium | KCP Remote `active_conns` over-counts on every failed `forward_target` dial: the new-conv path increments, but the dial-failure path removes the conv without decrementing (and doesn't mark it recently-closed, so retransmits re-create+re-leak it). | `data-plane/src/forward/kcp.rs:373-399,499` | On dial failure, decrement `active_conns` **only if** `remove()` returned `Some` (guards against a concurrent reap double-decrementing the atomic). Capture `stats` into the dial task. Latent today (stats not surfaced); must be correct before A-metrics surface them. | ENG-1, SEED |
| A6 | high *(deferred)* | TCP forwarding cannot carry **server-speaks-first** protocols: the Remote only dials `forward_target` after it receives the client's first engine datagram, which KCP/QUIC only emit once the user app writes. Fine for VLESS (client-speaks-first); hangs until idle-reap otherwise. | `data-plane/src/forward/kcp.rs:324,388`; `data-plane/src/forward/quic.rs:466,525` | A correct fix needs an explicit out-of-band "conv-open" control datagram from the Client on TCP accept — this **changes the inner engine wire format** and is risky this close to release. **Decision: document as a known limitation (recommend it's only used for client-speaks-first proxied protocols, which is the product's stated use) and schedule the proper fix for a later release.** Verifier flagged `invariant_safe=false`. | ENG-7 |
| A7 | medium | The QUIC MTU-floor validation error (`mtu ≥ 1252`) is returned per-field by the backend but the MTU input is the one form field that never binds `:error`/`:invalid`, so the operator sees only a generic toast with no inline red field. | `frontend/components/tunnel/TunnelForm.vue:561-563` | Bind `:error="err('mtu')"` on the MTU `FieldGroup` and `:invalid="!!err('mtu')"` on the input (every other field already does this). Optional: a client-side pre-submit hint when `tcp+quic && mtu<1252`. | FE-1 |

**Checkpoint-2 plan:** fix A1, A2, A3, A4, A5, A7 with regression tests; **defer
A6 with explicit documentation** (called out for operator sign-off).

---

## Bucket (b) — smells / risky patterns, should-fix

| # | Severity | Title | Where | Fix summary |
|---|----------|-------|-------|-------------|
| B1 | medium | TCP reliability engines ignore the memory soft-cap **and** `max_connections` — a Remote under memory pressure keeps minting convs/streams and dialing `forward_target` (CLAUDE.md §4 memory invariant not honored on the TCP path; both KCP and QUIC). | `forward/kcp.rs` (`handle_inbound`), `forward/quic.rs` (`handle_remote_conn`), `remote.rs` engine spawn | Thread `max_connections` + a `memory::pressure_active()` check into both Remote new-conv paths as a **best-effort silent drop** (never an error — the reliability layer retransmits). Add a `conv_rejects` counter and route it to `record_session_reject()`. |
| B2 | medium | PR-level CI never compiles the musl target — a ring/QUIC static-link breakage surfaces only at release tag time, not on the PR. | `.github/workflows/ci.yml` | Add a `x86_64-unknown-linux-musl` `cargo check` (or build) gate to the per-PR Rust job. |
| B3 | medium | CI installs frontend deps with `--no-frozen-lockfile` while `build.sh`/`release.yml` use `--frozen-lockfile`, so lockfile drift is invisible until release. | `.github/workflows/ci.yml` | Switch the frontend CI job to `--frozen-lockfile` (lockfile is now committed); drop the stale comment. |
| B4 | medium | A forward TCP listener on a privileged local port (<1024) fails with `EACCES`, which the manager maps to the misleading `RAW_SOCKET_FORBIDDEN` ("CAP_NET_RAW missing") instead of a port-permission message. | `data-plane/src/perf.rs` bind helpers, `manager.rs` `SpawnError` mapping | Disambiguate a bind-`EACCES` on a privileged port from a raw-socket `EACCES` so the operator gets an actionable message. |
| B5 | low | KCP `reap_idle` doesn't clamp `idle_timeout_sec` to ≥1, so a (mis)configured `idle_timeout_sec=0` reaps every conv immediately. | `data-plane/src/forward/kcp.rs:480` | `cfg.idle_timeout_sec.max(1)` in the reaper (and cadence), mirroring the other consumers. |
| B6 | low | `forward_engine_tuning` overrides are parsed without `DisallowUnknownFields`, so a typo'd key is silently ignored and the operator gets the preset value, not their override. | `control-plane/internal/tunnels/forward.go` (`ResolveKcpTuning`/`ResolveQuicTuning`) | Use a strict JSON decoder that rejects unknown keys, mirroring `decodeJSON`. |
| B7 | low | QUIC `keep_alive_ms` may be validated ≥ `max_idle_ms` (and `=0` is allowed), producing a connection that idles out despite keepalive (or floods 1 ms PINGs). | `control-plane/internal/tunnels/forward.go` (`validateQuicTuning`) | Add a cross-field check: `keep_alive_ms` ≥ a sane floor and comfortably below `max_idle_ms`. |
| B8 | low | `max_connections` and `idle_timeout` have no upper bound, so a huge value silently narrows when cast to `uint32`/seconds in the dataplane. | `control-plane/internal/tunnels/validation.go` | Add explicit upper bounds with teaching error messages. |
| B9 | low | TCP-forward upload inbox-full drops are silent (no metric, no sampled warn) — unlike the UDP forward path, which counts + sampled-warns. | `data-plane/src/tunnel/remote.rs:922,1037` | Add a shared sampled drop counter + metric, mirroring the UDP path. |
| B10 | low | KCP closing-conv linger (~200 ms) is dominated by the coarse reap cadence (≥1 s, up to `idle_timeout/4`), so a cleanly-closed conn's tasks/buffers linger far longer than intended. | `data-plane/src/forward/kcp.rs:238-261` | Decouple the closing-conv sweep onto a short fixed cadence, leaving the idle policy unchanged. |
| B11 | low | Two browser tabs editing the same tunnel: last-write-wins, no optimistic-concurrency check (silent lost update). | `frontend` (`TunnelFormModal.vue`, `useTunnels.update`) | Capture `updated_at` on open; re-check before PUT (the DTO already carries it). Frontend-only. |
| B12 | low | Switching Forward protocol TCP→UDP leaves a stale `forward_engine_tuning` JSON blob persisted on the (now-UDP) tunnel. | `frontend/components/tunnel/TunnelForm.vue` | Add a `watch` on `forward_protocol` that clears the tuning blob when it leaves `tcp`, mirroring the preset/engine reset. |
| B13 | low | `Cargo.toml` `rust-version="1.83"` understates the true 1.88 MSRV (doc drift vs `rust-toolchain.toml`/CI). | `data-plane/Cargo.toml` | Bump to `1.88` and fix the stale async-trait comment. |
| B14 | low | On the TCP-forward path the Remote `session_table` is keyed by upload source, so `max_connections` is effectively unenforced there and the "active sessions" panel number doesn't reflect real connections (pre-existing Remote property, surfaced by TCP). | `data-plane/src/tunnel/remote.rs:916,1031` | Drive the TCP-tunnel connection count from engine `active_conns` (see metrics work) and/or document the session table's role; keep enforcing `max_connections` on the Client. |
| B15 | low | `Supervisor.Stop` is dead code (never called; production teardown is context-cancellation which is robust) and sends `os.Interrupt` rather than `SIGTERM`, bypassing exec's `WaitDelay`/SIGKILL fallback. | `control-plane/internal/ipc/supervisor.go` | Make `Stop` delegate to context cancellation (single teardown path) or remove it. |

---

## Bucket (c) — polish / improvements (opportunistic)

| # | Title | Where | Fix |
|---|-------|-------|-----|
| C1 | Multi-port TCP download throughput metric counts the 2-byte port tag (diverges from UDP path) | `client.rs:1237` | Move `record_download` to after tag decode. |
| C2 | Multi-port TCP: `hmac_seq`/`icmp_seq` are two independent atomics — can de-pair under concurrent seal (ICMP transport only) | `remote.rs:470` | Derive `icmp_seq` from `hmac_seq` so the pairing is correct by construction. |
| C3 | `RemoteForwardSink::send` has no oversized-payload guard (unlike UDP recv cap) | `remote.rs:468` | Add a length backstop returning `Ok(false)` + bump `sink_drops`. |
| C4 | Rust `validate()` has no **upper** MTU bound (Go clamps; dataplane should be self-consistent) | `data-plane/src/spec.rs:398` | Add `MtuTooLarge` (e.g. > 9000). |
| C5 | `forward_engine_tuning` is stored unvalidated for `udp` tunnels (malformed blob persists, only rejected if later switched to tcp) | `control-plane/internal/tunnels/validation.go` | Validate the blob whenever non-empty, independent of protocol. |
| C6 | Malformed `?edit=<non-numeric>` deep link silently opens an empty Create modal | `frontend/pages/tunnels/index.vue` | Validate the id; toast on invalid. |
| C7 | KCP `recently_closed` LRU is populated on the Client but never consulted there (dead state) | `forward/kcp.rs` | Gate the push on the Remote role. |
| C8 | QUIC `poll_recv` returns `Poll::Pending` without a waker on channel close (safe only because it's shutdown-only) | `forward/quic.rs:136` | Make the closed case observable/terminating instead of conflating it with "no data yet". |
| C9 | Per-connection IPC background tasks (state forwarder + stats reporter) outlive the read loop on disconnect (small leak per dataplane reconnect) | `data-plane/src/ipc.rs` | Tie both tasks' lifetime to the connection via a cancellation token / abort on exit. |
| C10 | `release.yml` lets a `-dirty` version string through as a warning | `.github/workflows/release.yml` | Fail closed on `-dirty` for a real tag push. |
| C11 | The `aws-lc-rs`-absence crypto gate lives only in CI, not in the release build | `.github/workflows/release.yml` | Mirror the `cargo tree -i aws-lc-rs` gate as an early release step. |
| C12 | Required CI bench jobs assert hard throughput ratios on shared runners (flaky) | `.github/workflows/ci.yml` | Keep byte-correctness as the hard gate; make the relative-ratio asserts informational/non-blocking. |

---

## Engine observability (the deferred v4.1.0 item) — decision pending Checkpoint 3

`EngineStats` (`active_conns`, `conv_opens`, `idle_teardowns`, `egress_drops`,
`sink_drops`) exists per engine but has **no IPC surface** — `PerTunnelStats`
can't report it, so an operator can't see at a glance whether a TCP tunnel's
engine is healthy (SPEC-4; also the root of B14's misleading session count).

**Tentative decision:** because Checkpoint 2 makes these counters *correct*
(fixes A5's `active_conns` drift and adds B1's `conv_rejects`), surfacing a
**minimal, observability-only** subset (aggregated `active_conns` + `conv_opens`
+ `idle_teardowns` per tunnel) is the natural, low-risk feature that justifies a
**v4.1.0** rather than a v4.0.1. It is an *additive* IPC field + an extension of
the existing per-tunnel stats display — **no DB schema change, no new dashboard
panel.** Final go/no-go is made in Checkpoint 3 after the bug fixes are CI-green;
if it grows or risks the release, it is deferred and the release is **v4.0.1**.

---

## Verified correct — no change needed

These were specifically checked and **hold up** (recorded so they aren't
re-litigated):

- **Seal-pipeline invariants intact on the TCP path** (REM-5): `RemoteForwardSink`
  shares the one `seq_counter` / `session_id` / `seal_txs` / single send socket;
  parallel-seal + single-send wire-FIFO (PR#36) and `session_id`-not-wall-clock
  (PR#38) are **not** regressed by v4. The `SEQ_WINDOW_SIZE == 1024` and
  seal-worker clamp invariants hold.
- **`TcpUploadRouter` Single/Multi tag decode + MTU-before-cap ordering** correct
  across all matrix combos (REM-6).
- **Migration 0012** is additive, defaulted (`udp`/`kcp`/`balanced`),
  CHECK-constrained, and rollback-safe; v2/v3→v4 upgrade is a no-op for existing
  rows (GOI-4, refuted as a concern).
- **Crypto pin correct** (OPS-1): `aws-lc-rs` absent, `ring` wired through
  quinn/rustls/rcgen; the CI `cargo tree -i aws-lc-rs` gate is real and would
  catch a regression.
- **`setup.sh` + systemd unit need no change** for TCP forwarding — same
  capabilities, ports, and paths (OPS-5).
- **MTU hot-reload can't shrink a *running* QUIC engine below its 1200-byte
  floor** (SPEC-3, refuted): the engine MTU is a spawn-time snapshot; the
  divergence is cosmetic and is removed entirely by the A1/A2 restart fix.

---

## Release-version recommendation (preliminary)

- If only bug fixes ship (buckets a/b/c) → **v4.0.1** (patch).
- If engine observability is added (the SPEC-4 feature) → **v4.1.0** (minor).

Leaning **v4.1.0**, contingent on the Checkpoint-3 observability work landing
cleanly. Justified in the release notes at Checkpoint 4.

> **Caveat (carried to the final report):** none of this is a substitute for
> the operator's hardware validation on the two real VPS hosts — these are
> code-level findings verified by reading + CI, not by running traffic through a
> live tunnel. Hardware validation remains the next step after release.
