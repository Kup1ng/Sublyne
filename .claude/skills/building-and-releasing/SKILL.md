---
name: building-and-releasing
description: Cross-language build process for the Sublyne project — compiling the Rust dataplane, building the Nuxt 3 frontend, embedding both into the Go control-plane binary, producing the single `sublyne-linux-amd64` artifact, generating `setup.sh`, and running the tag-driven GitHub Actions release workflow.
when_to_use: Read this skill any time you need to build locally, debug a build failure, prepare a release, or modify `release.yml`. Especially relevant to Phase 1 (CI skeleton) and Phase 14 (full release workflow + first v0.1.0 tag).
---

## Pipeline at a glance

```
                ┌──────────────────────────────────────────────┐
                │ 1. frontend/  →  pnpm build  →  .output/public │
                └────────────────────────┬─────────────────────┘
                                         │
                  copy to:               ▼
   control-plane/internal/webassets/frontend_dist/  (gitignored)
                                         │
                ┌────────────────────────┼─────────────────────┐
                │ 2. data-plane/  →  cargo build --release      │
                │    --target x86_64-unknown-linux-musl         │
                │    →  data-plane/target/.../sublyne-dataplane │
                └────────────────────────┬─────────────────────┘
                                         │
                  copy to:               ▼
   control-plane/internal/dataplaneasset/sublyne-dataplane (gitignored)
                                         │
                ┌────────────────────────┼─────────────────────┐
                │ 3. control-plane/  →  go build -tags=embed    │
                │    -o ../sublyne-linux-amd64 ./cmd/sublyne    │
                │    (go:embed pulls in frontend_dist + dataplane) │
                └──────────────────────────────────────────────┘

Outputs shipped: sublyne-linux-amd64   +   scripts/setup.sh
```

The user only ever downloads two files. Everything else (Rust, frontend
JS, source) lives inside the Go binary as embedded resources.

## Prerequisites on a builder host

The release workflow runs on `ubuntu-latest` (currently Ubuntu 24.04).
Local developers on macOS or Windows must reproduce the same toolchain.

| Tool | Pinned version | Install |
|------|----------------|---------|
| Rust toolchain | stable (`rust-toolchain.toml` in `data-plane/`) | `rustup install stable && rustup target add x86_64-unknown-linux-musl` |
| `musl-tools` (for static linking on Linux builders) | latest | `apt install musl-tools` |
| Go | 1.22+ (matches `go.mod`) | https://go.dev/dl/ |
| Node | 20 LTS | https://nodejs.org/ |
| pnpm | 9+ | `corepack enable && corepack prepare pnpm@latest --activate` |

macOS/Windows developers: cross-compile to linux-amd64. Easiest path is
to use the GitHub Actions builder (push a branch, let CI build) or run
the whole build inside a Linux container:

```
docker run --rm -v "$(pwd)":/src -w /src ubuntu:24.04 bash -c '
  apt-get update && apt-get install -y curl build-essential musl-tools git
  # … install Rust, Go, Node via the official installers, then run ./scripts/build.sh
'
```

## Step 1 — Build the frontend

```
cd frontend
pnpm install --frozen-lockfile
pnpm build
# Output: frontend/.output/public/
```

`nuxt.config.ts` must have `ssr: false` and `app.baseURL: '/'` (the
runtime path obfuscation is handled by the Go server, not by Nuxt; the
SPA is served from whatever obfuscated prefix the Go server is on).

Copy the dist into the embed staging directory:

```
rm -rf ../control-plane/internal/webassets/frontend_dist
mkdir -p ../control-plane/internal/webassets/frontend_dist
cp -r .output/public/* ../control-plane/internal/webassets/frontend_dist/
```

`control-plane/internal/webassets/frontend_dist/` is in `.gitignore`.
The directory is populated freshly on every build.

## Step 2 — Build the Rust dataplane

```
cd data-plane
cargo build --release --target x86_64-unknown-linux-musl
# Output: data-plane/target/x86_64-unknown-linux-musl/release/sublyne-dataplane
```

If on a non-Linux host without `musl-tools` configured, this will fail
with linker errors. Either set up musl cross-compilation
(`brew install FiloSottile/musl-cross/musl-cross` on macOS, set
`CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc`) or build in
a Linux container as shown above.

Copy the binary into the embed staging directory:

```
mkdir -p ../control-plane/internal/dataplaneasset
cp target/x86_64-unknown-linux-musl/release/sublyne-dataplane \
   ../control-plane/internal/dataplaneasset/sublyne-dataplane
chmod +x ../control-plane/internal/dataplaneasset/sublyne-dataplane
```

This path is in `.gitignore` too.

## Step 3 — Build the Go control plane

The Go build uses the `embed` build tag so dev builds (`go run`) without
the tag skip the embed and serve files from disk for iteration speed.
The release build always passes the tag.

```
cd control-plane
go build -tags=embed -ldflags="-s -w -X main.version=$(git describe --tags --dirty --always)" \
   -o ../sublyne-linux-amd64 ./cmd/sublyne
```

`-ldflags="-s -w"` strips debug symbols and DWARF sections. The version
string is injected via `-X` so `sublyne --version` prints something
useful.

Resulting `sublyne-linux-amd64` is typically ~25–40 MB (Go runtime +
Rust musl binary ~3 MB compressed + frontend dist ~1–3 MB).

### The embed pattern (reference)

`control-plane/internal/webassets/embed.go`:

```go
//go:build embed

package webassets

import "embed"

//go:embed frontend_dist
var FrontendFS embed.FS

//go:embed dataplane/sublyne-dataplane
var DataplaneBinary []byte
```

`control-plane/internal/webassets/embed_dev.go`:

```go
//go:build !embed

package webassets

import (
	"embed"
	"os"
)

// In dev builds, serve from disk so changes are picked up on every reload.
var FrontendFS embed.FS // empty; HTTP handler falls back to os.DirFS("frontend/.output/public")

// In dev builds, expect the dataplane binary on disk at this relative path.
var DataplaneBinary []byte // empty sentinel; supervisor uses DataplaneBinaryDevPath

const DataplaneBinaryDevPath = "../data-plane/target/x86_64-unknown-linux-musl/release/sublyne-dataplane"

func init() { _ = os.DirFS }
```

The supervisor in `control-plane/internal/ipc/supervisor.go`:
- In embed builds, writes `DataplaneBinary` to
  **`/var/lib/sublyne/dataplane`** (mode 0700), then execs it.
- In dev builds, just execs `DataplaneBinaryDevPath`.

### Why `/var/lib`, not `/run`

Recent Ubuntu (22.04 and 24.04) mounts `/run` as `tmpfs,noexec`. A
binary extracted into `/run/sublyne/dataplane` would have the correct
file mode but `fork`/`exec` would fail with `EACCES` regardless. The
Unix socket can still live under `/run/sublyne/dataplane.sock`
(sockets don't need the exec bit); only the **executable** has to be
on a regular filesystem. `/var/lib/sublyne` is on ext4 with `exec`
allowed, owned by the `sublyne` user via the install layout.

Visible symptom if this regresses: `sublyne.service` flaps with
`permission denied` lines in the journal, the panel still serves
because the Go control plane is up, but every tunnel start returns an
IPC error. `scripts/check_systemd_install.sh` catches it explicitly
by checking the mount options on `/var/lib/sublyne/dataplane`.

## Step 4 — `scripts/setup.sh`

`setup.sh` is shipped as a separate file, *not* embedded into the
binary. It's small (~10 KB) and operators inspect it before running, so
shipping it separately is the right call.

`setup.sh` is hand-maintained in `scripts/setup.sh` and copied to the
release artifact during `release.yml`.

`scripts/setup.sh` is responsible for:
- Verifying Ubuntu 22.04 or 24.04 + amd64 + root.
- Creating the `sublyne` user/group.
- Creating `/etc/sublyne`, `/var/lib/sublyne/logs`, `/run/sublyne`.
- Moving `/tmp/sublyne-linux-amd64` → `/usr/local/bin/sublyne`.
- Prompting for role, admin user, password.
- Auto-generating panel port (5-digit, 10000–65535) and web path
  (16 URL-safe chars).
- Writing `/etc/sublyne/config.toml`.
- Installing `/etc/systemd/system/sublyne.service`.
- Starting + enabling the service.
- Printing the panel URL + credentials.

Full menu (Fresh install, Update, Reinstall, Uninstall, Status, Exit) is
delivered in Phase 14. Phase 2 only ships the Fresh-install path with
the other menu items stubbed to "coming soon".

## Step 5 — Local convenience: `scripts/build.sh`

A thin shell wrapper that runs steps 1–3 in order. The authoritative
script lives in the repo at `scripts/build.sh`; the shape:

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Snapshot the version BEFORE any build step. `git describe --dirty`
# walks the tracked tree; if a build step modifies a tracked file
# (mode bits, generated code, …) the version string silently grows a
# "-dirty" suffix on tagged releases. Capturing up-front pins the
# release binary to the tag verbatim.
VERSION="$(git describe --tags --dirty --always)"

echo "==> Building frontend"
( cd "$REPO_ROOT/frontend" && pnpm install --frozen-lockfile && pnpm build )

echo "==> Staging frontend dist"
rm -rf "$REPO_ROOT/control-plane/internal/webassets/frontend_dist"
mkdir -p "$REPO_ROOT/control-plane/internal/webassets/frontend_dist"
cp -r "$REPO_ROOT/frontend/.output/public/." \
      "$REPO_ROOT/control-plane/internal/webassets/frontend_dist/"

echo "==> Building Rust dataplane (musl)"
( cd "$REPO_ROOT/data-plane" && cargo build --release --target x86_64-unknown-linux-musl )

echo "==> Staging dataplane binary"
mkdir -p "$REPO_ROOT/control-plane/internal/dataplaneasset"
cp "$REPO_ROOT/data-plane/target/x86_64-unknown-linux-musl/release/sublyne-dataplane" \
   "$REPO_ROOT/control-plane/internal/dataplaneasset/sublyne-dataplane"

echo "==> Building Go control plane"
( cd "$REPO_ROOT/control-plane" && \
  go build -tags=embed -ldflags="-s -w -X main.version=$VERSION" \
    -o "$REPO_ROOT/sublyne-linux-amd64" ./cmd/sublyne )

echo "==> Done. Artifact: $REPO_ROOT/sublyne-linux-amd64"
ls -lh "$REPO_ROOT/sublyne-linux-amd64"
```

### Script mode bits and the `-dirty` trap

Every shell script that `release.yml` or `ci.yml` invokes must be
committed as **mode 0755 in git**, not 0644 with a `chmod +x` step
in the workflow. The `chmod` modifies the worktree, `git describe
--dirty` notices, and the tagged binary's `--version` reports
`v0.1.0-dirty`. To set the bit in the index:

```sh
git update-index --chmod=+x scripts/foo.sh
git commit -m "chore: mark scripts/foo.sh executable"
```

`release.yml` also has a hard check: a `-dirty` version line **fails
the release** rather than uploading a misleadingly-versioned binary.

## Step 6 — Tag-driven release (Phase 14)

`.github/workflows/release.yml` triggers on `push` of any tag matching
`v*.*.*` and produces a GitHub Release with `sublyne-linux-amd64` and
`setup.sh` attached. Shape:

```yaml
name: release
on:
  push:
    tags: ['v*.*.*']
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # need full history for changelog
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: x86_64-unknown-linux-musl }
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: corepack enable && corepack prepare pnpm@latest --activate
      - run: sudo apt-get update && sudo apt-get install -y musl-tools
      - run: ./scripts/build.sh
      - name: Generate changelog
        run: ./scripts/changelog.sh > /tmp/changelog.md
      - uses: softprops/action-gh-release@v2
        with:
          body_path: /tmp/changelog.md
          files: |
            sublyne-linux-amd64
            scripts/setup.sh
```

### Tagging a release

The user says "release" or "release X" → compute the next version
(`fix:` commits since last tag = patch, `feat:` = minor,
`feat!:`/`BREAKING CHANGE:` = major). Then:

```
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Watch the workflow:

```
gh run watch
```

Don't pre-create the release; the workflow does it. Don't push the tag
to a branch that hasn't been merged to `main` — releases only come
from `main`.

### Changelog generation

`scripts/changelog.sh` (Phase 14) walks `git log <prev-tag>..HEAD` and
buckets commits by Conventional Commit type:

```
## Features
- feat(api): add tunnel import/export endpoints (#42)

## Fixes
- fix(dataplane): correct ICMPv6 checksum on multi-fragment payloads (#47)

## Maintenance
- chore(deps): bump tokio to 1.40
```

If a commit doesn't follow the convention, it lands in an "Other" bucket
with the raw subject — that's a nudge to PR authors but not a blocker.

## Common build failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `embed: no matching files found` | Forgot to run frontend build before Go build | Run `scripts/build.sh`, not `go build` directly |
| `cannot find -lc` (Rust musl) | `musl-tools` not installed | `apt install musl-tools` (Linux) or use a Linux container |
| `unsupported os/arch` on `go build` | Cross-compiling without `GOOS=linux GOARCH=amd64` from non-Linux dev box | Set those env vars, or build in container |
| Binary runs but panel shows blank page | Frontend dist staging path wrong; embed.FS empty | Re-check `control-plane/internal/webassets/frontend_dist/` exists and contains `index.html` before `go build` |
| `permission denied` extracting dataplane at runtime | `/run/sublyne/` not owned by `sublyne` user | Check systemd unit's `RuntimeDirectory=sublyne` |

## Don't do

- Don't ship the Rust binary or frontend dist as separate artifacts.
  One file: `sublyne-linux-amd64`.
- Don't commit `control-plane/internal/webassets/frontend_dist/` or
  `…/dataplane/sublyne-dataplane` — they're build outputs, gitignored.
- Don't tag from a feature branch. Tags come from `main` only.
- Don't use `--no-verify` to push a tag. If pre-push hooks fail, the
  release was going to fail anyway.
