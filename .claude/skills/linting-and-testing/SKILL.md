---
name: linting-and-testing
description: Format, lint, typecheck, and test commands for the three components (Rust dataplane, Go control plane, Nuxt 3 frontend), plus the CI workflow shape and how to interpret failures.
when_to_use: Before committing any code change, when CI fails on a PR, when adding new tests, or when adjusting `ci.yml`. Read this whenever you're about to push.
---

## Components and tooling overview

The repo has three independently-toolchained components:

| Component | Path | Language | Package manager | Test framework |
|-----------|------|----------|-----------------|----------------|
| Data plane | `data-plane/` | Rust (stable) | Cargo | `cargo test` |
| Control plane | `control-plane/` | Go 1.22+ | go modules | `go test` |
| Frontend | `frontend/` | TypeScript / Vue 3 | pnpm | vitest |

CI runs each component in its own job, in parallel. Every check must
pass for a PR to be mergeable.

## Rust (`data-plane/`)

### Local commands

```
cd data-plane

cargo fmt --all                          # auto-format
cargo fmt --all -- --check               # CI form (fails if not formatted)
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit                              # CVE scan; `cargo install cargo-audit` if missing
cargo build --release --target x86_64-unknown-linux-musl
```

### Gotchas

- **`cargo clippy` warns are CI failures.** `-D warnings` promotes
  every warning to an error. Fix the warning; don't `#[allow(...)]`
  unless you have a justified reason and add a comment explaining it.
- **`unsafe` blocks** are common in the dataplane (raw socket FFI,
  zero-copy parsing). Each `unsafe` block must be commented with a
  `// SAFETY:` line explaining the invariant being upheld. Clippy
  warns on uncommented `unsafe`.
- **Tests in modules using raw sockets** can't run unprivileged in
  CI. Gate them with `#[cfg_attr(not(feature = "integration"), ignore)]`
  or move them to `tests/integration/` and skip in CI for v0.1.0.
- **`cargo audit`** fails the build on any RUSTSEC advisory. If a
  dependency has an unpatched advisory, file an issue and use
  `cargo audit --ignore RUSTSEC-XXXX-NNNN` *only* with a comment in
  `.cargo/audit.toml` explaining why.

### Test layout

- Unit tests live `#[cfg(test)] mod tests { ... }` inline.
- Integration tests for crafted-packet parsers live in `tests/`.
- Property tests via `proptest` are encouraged for the checksum and
  HMAC routines.

## Go (`control-plane/`)

### Local commands

```
cd control-plane

gofmt -l .              # CI form: must print nothing
gofmt -w .              # auto-format
goimports -w .          # also re-orders imports (recommended)
go vet ./...
golangci-lint run       # configured via .golangci.yml at repo root
go test ./...
go test -race ./...     # run with race detector (CI runs this on non-integration tests)
govulncheck ./...
```

### `.golangci.yml` baseline

Enabled linters: `errcheck`, `gosimple`, `govet`, `ineffassign`,
`staticcheck`, `unused`, `gofmt`, `goimports`, `revive`, `gocritic`,
`bodyclose`, `gosec`, `sqlclosecheck`.

Disabled: `lll` (line length — we use gofmt's wrap point), `funlen`
(no arbitrary function-length cap; review judgment instead).

### Gotchas

- **`gofmt -l .` must print nothing.** If it prints a filename, that
  file is unformatted. Run `gofmt -w .` and re-stage.
- **`go test -race`** catches data races. Tunnel lifecycle code is the
  most likely place to introduce one (concurrent map access, channel
  close races). Always run with race in CI.
- **`bodyclose`** flags unclosed HTTP response bodies. Use
  `defer resp.Body.Close()` even on error paths.
- **`gosec`** flags `crypto/md5`, `crypto/sha1`, `net/http` without
  timeouts, `os.Chmod 0666`, etc. Address every finding — most are
  real.
- **Embedded resources** (frontend dist, dataplane binary) are needed
  for the build but not for tests. Use the `embed` build tag pattern
  (see `building-and-releasing/SKILL.md`) so `go test ./...` works
  without staging artifacts first.
- **`govulncheck`** is stricter than `gosec`; it actually traces
  whether your code calls the vulnerable function. If it finds a
  reachable vuln, the fix is to upgrade the dep or refactor away
  from the call site — never silence it.

### Test layout

- `*_test.go` next to the code it tests.
- HTTP handler tests use `httptest.NewServer` + a real `chi` router.
- DB tests use an in-memory SQLite (`:memory:`) seeded by the same
  migrations the production code runs. **Do not mock SQLite.**
  See `db-migrations/SKILL.md` for the helper.

## Frontend (`frontend/`)

### Local commands

```
cd frontend

pnpm install --frozen-lockfile
pnpm dev                        # dev server with HMR, http://localhost:3000
pnpm lint                       # eslint
pnpm format:check               # prettier --check
pnpm format                     # prettier --write
pnpm typecheck                  # vue-tsc --noEmit
pnpm test                       # vitest run
pnpm test:watch                 # vitest in watch mode
pnpm build                      # production build → .output/public/
```

### Gotchas

- **Prettier and eslint can disagree.** Configure eslint with
  `eslint-config-prettier` (already in `package.json`) so prettier
  wins on formatting and eslint focuses on code quality. If they
  conflict mid-PR, run `pnpm format` then `pnpm lint --fix`.
- **`vue-tsc`** is the type-checker for `.vue` files. It catches
  more than `tsc` alone because it understands SFC `<script>` blocks.
- **shadcn-vue components** are copied into `components/ui/` — they
  are not a dependency. When upgrading, re-copy from the upstream
  repo; don't hand-edit unless you mean to fork.
- **Tailwind** runs through Nuxt's build pipeline. Custom theme tokens
  live in `tailwind.config.ts` — see `web-panel-components/SKILL.md`
  for the purple-theme values.
- **No `any`** without justification. `eslint`'s
  `@typescript-eslint/no-explicit-any` is at error level.

### Test layout

- Component tests use `@vue/test-utils` + vitest.
- Page-level tests stub out the API via `msw` (mock service worker).

## CI workflow (`.github/workflows/ci.yml`)

Triggers: every PR, every push to `main`. Runs three jobs in parallel
(plus an aggregate `ci-pass` job for branch protection):

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

jobs:
  rust:
    runs-on: ubuntu-24.04
    defaults: { run: { working-directory: data-plane } }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
      - run: cargo install cargo-audit --locked && cargo audit

  go:
    runs-on: ubuntu-24.04
    defaults: { run: { working-directory: control-plane } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: test -z "$(gofmt -l .)"
      - run: go vet ./...
      - uses: golangci/golangci-lint-action@v6
        with: { version: latest, working-directory: control-plane }
      - run: go test -race ./...
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...

  frontend:
    runs-on: ubuntu-24.04
    defaults: { run: { working-directory: frontend } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: corepack enable && corepack prepare pnpm@latest --activate
      - uses: actions/setup-node@v4
        with: { cache: pnpm, cache-dependency-path: frontend/pnpm-lock.yaml }
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm format:check
      - run: pnpm typecheck
      - run: pnpm test

  ci-pass:
    needs: [rust, go, frontend]
    runs-on: ubuntu-24.04
    steps:
      - run: echo "All checks passed"
```

Set branch protection on `main` to require `ci-pass` (not the individual
jobs, so we can add/remove components without re-configuring branch
protection each time).

## When CI fails

1. **Click into the failing job in the GitHub Actions UI.** Read the
   actual error — don't guess.
2. **Reproduce locally** with the exact command CI ran. The whole
   point of running these commands locally before pushing is to never
   surprise yourself.
3. **Fix the root cause.** If a test is flaky, file it as a real bug
   — don't skip with `t.Skip` unless you have an issue tracking the
   underlying problem.
4. **If formatting CI fails**, run the auto-format command for that
   language and amend the PR. Never argue with the formatter.
5. **If a CVE-scanner CI fails** (`cargo audit`, `govulncheck`),
   bump the offending dependency in a *separate* PR before continuing
   feature work — easier to review.
6. **Never bypass** with `--no-verify` or by disabling a CI job.
7. **Communicate to the user** in plain language: "CI failed because
   the dataplane has an unhandled `Result` in `transport/udp.rs` line
   42 — fixing now." Don't dump the raw log.

## Cross-component checks (added in Phase 15)

Phase 15 adds a single integration job that builds the full artifact
and runs a smoke test:

```yaml
  smoke:
    needs: [rust, go, frontend]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - …toolchain setup…
      - run: ./scripts/build.sh
      - run: ./sublyne-linux-amd64 --version
      - run: ./scripts/smoke.sh        # exercises setup.sh in a Docker container
```

Don't add this in earlier phases — it's slow and the per-component CI
catches almost everything.

## Shell scripts

`setup.sh`, `build.sh`, `changelog.sh`, the `tests/acceptance/*.sh`
scripts, and the sandbox menu tester are all part of CI:

- **shellcheck** runs on each in the `release-validate` CI job. Treat
  any warning as a failure — the runner is `set -e` so a silently
  shrug-it-off bug surfaces only when an operator runs the script
  for real.
- **`bash -n` syntax check** runs in addition to shellcheck.
- **Sandbox menu test** (`scripts/test-setup-menus.sh`) exercises
  every `setup.sh` menu path against a `/tmp` sandbox tree using a
  fake `sublyne` binary. Run it locally before pushing if you touch
  setup.sh.

### Commit shell scripts as mode 0755 in git

Every shell script invoked by a CI or release workflow must be
**committed as 0755 in the git index**, not 0644 with a `chmod +x`
step inside the workflow. Reason: `chmod +x` modifies the worktree,
and `git describe --dirty` then reports `-dirty`. On a tagged build
that's how `sublyne v0.1.0-dirty` ends up in the published release.

Set the bit in the index:

```sh
git update-index --chmod=+x scripts/foo.sh tests/acceptance/bar.sh
git ls-files --stage scripts/foo.sh   # confirm 100755
git commit -m "chore: mark scripts/foo.sh executable"
```

`release.yml` now hard-fails the release if `--version` contains
`-dirty`, so this won't slip through silently again.
