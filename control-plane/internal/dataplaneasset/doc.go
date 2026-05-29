// Package dataplaneasset surfaces the embedded Rust data-plane
// binary to the supervisor in internal/ipc/.
//
// The embed.go variant (build tag `embed`) pulls in the binary via
// the embed package; the embed_dev.go variant returns nil so unit
// tests and `go vet` work without a built Rust artifact in the tree.
//
// Phase 14 (release.yml) builds the Rust binary, copies it into this
// directory under the name `sublyne-dataplane`, and runs
// `go build -tags=embed`.
package dataplaneasset
