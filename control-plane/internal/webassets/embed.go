//go:build embed

// Package webassets exposes the built SPA dist to the rest of the
// control plane. Two build tags select between modes:
//
//   - With `-tags=embed` (the production / `scripts/build.sh` path),
//     this file is included and the SPA dist is pulled in via
//     `go:embed`. The release binary therefore contains every byte of
//     the panel UI and needs nothing from disk at runtime.
//   - Without the tag (the default for `go run`, `go test`, IDE
//     tooling), `embed_dev.go` is included instead and the SPA is
//     read from disk so frontend changes don't require a Go rebuild.
//
// The Rust dataplane binary will be embedded here too once Phase 8a
// lands the dataplane crate — see `building-and-releasing/SKILL.md`.
package webassets

import (
	"embed"
	"io/fs"
)

// frontendDistFS holds the Nuxt build output. `all:` is required
// because Nuxt emits assets under `_nuxt/`, and `go:embed` excludes
// underscore-prefixed entries by default.
//
//go:embed all:frontend_dist
var frontendDistFS embed.FS

// FrontendFS returns the SPA file system rooted at the dist top-level
// (so callers can fetch `index.html`, `_nuxt/...`, etc. directly).
func FrontendFS() (fs.FS, error) {
	return fs.Sub(frontendDistFS, "frontend_dist")
}

// Embedded reports that the binary ships the SPA assets inside. The
// dev build sets this to false so the operator can be warned.
const Embedded = true
