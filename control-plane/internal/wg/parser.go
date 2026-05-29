// Package wg parses pasted WireGuard configuration text, persists it
// in SQLite, and (on Linux) materialises per-tunnel kernel interfaces
// with per-tunnel policy routing.
//
// Phase 7 lays the groundwork for the upload path: the panel can
// accept a wg-quick-style config, validate it, store it as a secret,
// and bring the corresponding sub-wg-<id> interface up when a Client
// tunnel is enabled. The data plane that actually moves bytes through
// the interface lands in Phase 8 — for now, "Start" creates the
// kernel device and sets fwmark + ip rule + ip route, and that's it.
//
// The parser in this file is platform-neutral and runs on every OS
// the CI matrix touches. The platform-specific bring-up code lives in
// manager_linux.go (real implementation) and manager_stub.go (other
// OSes return ErrUnsupported so unit tests still compile and the
// fresh chat working on Windows can run gofmt / go vet locally).
package wg
