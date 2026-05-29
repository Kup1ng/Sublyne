//go:build !embed

package webassets

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// FrontendDevPath is the on-disk SPA dist used when the binary is
// compiled without the `embed` tag. The path is relative to the
// control-plane working directory and points at the Nuxt output of
// `pnpm build`. It is `var` rather than `const` so tests can redirect
// it to a temp dir.
var FrontendDevPath = "../frontend/.output/public"

// ErrFrontendUnavailable is returned by FrontendFS in dev builds when
// the on-disk SPA dist is missing. Callers should treat the panel as
// unavailable and surface a clear message to the operator instead of
// crashing — the API is still useful for `curl` smoke tests even
// without the UI.
var ErrFrontendUnavailable = errors.New("webassets: frontend dist not found on disk; run `pnpm build` in frontend/ or build with -tags=embed")

// FrontendFS returns an fs.FS rooted at FrontendDevPath, or
// ErrFrontendUnavailable if the directory doesn't exist.
func FrontendFS() (fs.FS, error) {
	abs, err := filepath.Abs(FrontendDevPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFrontendUnavailable
		}
		return nil, err
	}
	return os.DirFS(abs), nil
}

// Embedded reports that the binary does NOT ship the SPA assets and
// expects them on disk.
const Embedded = false
