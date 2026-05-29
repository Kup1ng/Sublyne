//go:build !embed

// Package dataplaneasset stub for dev builds. See embed.go for the
// production variant.
package dataplaneasset

// Bytes returns nil in the dev build — there is no embedded binary.
// The supervisor logs and refuses to start so unit tests still pass
// without staging a Rust binary into the tree.
func Bytes() []byte { return nil }

// Embedded reports that this build does NOT ship the dataplane.
const Embedded = false
