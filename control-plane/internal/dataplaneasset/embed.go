//go:build embed

// Package dataplaneasset embeds the compiled Rust data-plane binary
// into the Go control-plane binary so the operator only ever has to
// drop a single artifact into /tmp/sublyne-linux-amd64.
//
// Two build tags select between modes (same shape as
// internal/webassets):
//
//   - With `-tags=embed` (the production / `scripts/build.sh` path),
//     this file is compiled and the binary is pulled in via go:embed.
//   - Without the tag (the default for `go test`, `go vet`, IDE
//     tooling), `embed_dev.go` is compiled instead and Bytes() returns
//     nil. The supervisor refuses to start in that case.
package dataplaneasset

import _ "embed"

// rawBinary holds the compiled `sublyne-dataplane` ELF. The release
// build statically links it via x86_64-unknown-linux-musl so the
// extracted binary needs no glibc at runtime.
//
//go:embed sublyne-dataplane
var rawBinary []byte

// Bytes returns the embedded data-plane binary. A non-nil slice
// guarantees the supervisor can extract and exec the child.
func Bytes() []byte { return rawBinary }

// Embedded reports that this build ships the dataplane binary.
const Embedded = true
