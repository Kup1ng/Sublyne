//go:build !linux

package wg

import (
	"context"
	"log/slog"
)

// NewManager returns a stub Manager on every non-Linux build. The
// control plane still compiles — gofmt, go vet, and unit tests for
// unrelated packages all keep working on a developer's Windows or
// macOS box — but any attempt to Up a tunnel returns
// ErrManagerUnsupported. Production builds target linux-amd64, where
// manager_linux.go provides the real implementation.
func NewManager(logger *slog.Logger) (Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("wg: stub manager active — kernel bring-up disabled on this platform")
	return &stubManager{}, nil
}

type stubManager struct{}

// Up implements Manager. Always returns ErrManagerUnsupported.
func (s *stubManager) Up(_ context.Context, tunnelID int64, _ *ParsedConfig) (BringUpResult, error) {
	return BringUpResult{InterfaceName: InterfaceNameFor(tunnelID), Fwmark: FwmarkFor(tunnelID), Table: TableFor(tunnelID)}, ErrManagerUnsupported
}

// Down implements Manager. Returns ErrManagerUnsupported so callers
// can see at a glance that nothing was torn down.
func (s *stubManager) Down(_ context.Context, _ int64) error {
	return ErrManagerUnsupported
}

// Handshake implements Manager. Returns ErrManagerUnsupported.
func (s *stubManager) Handshake(_ context.Context, tunnelID int64) (HandshakeStatus, error) {
	return HandshakeStatus{InterfaceName: InterfaceNameFor(tunnelID)}, ErrManagerUnsupported
}

// TearDownAll implements Manager. Returns nil so `sublyne --tear-down`
// remains exit-0 on non-Linux builds — the binary can't have
// created any state to clean up.
func (s *stubManager) TearDownAll(_ context.Context) error { return nil }

// Supported implements Manager. Stub → false.
func (s *stubManager) Supported() bool { return false }
