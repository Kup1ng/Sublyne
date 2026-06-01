package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/BurntSushi/toml"
)

// DefaultBootstrapPath is the on-disk location setup.sh writes the
// plaintext install credentials to. The file is mode 0600 owned by
// the service user; we consume it on first start and delete it so
// the plaintext password never lingers on disk.
const DefaultBootstrapPath = "/etc/sublyne/bootstrap-admin.toml"

// BootstrapFile is the on-disk schema of bootstrap-admin.toml.
// setup.sh writes:
//
//	username = "admin"
//	password = "<plaintext>"
//
// Phase 3 consumes it on the next service start.
type BootstrapFile struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// ConsumeBootstrap reads path, hashes the password with Argon2id,
// upserts the admin row, and removes the file. The function is a
// no-op (returning nil, false) when the file does not exist — the
// expected steady-state for any restart after the very first one.
//
// Returns (true, nil) when the bootstrap was consumed successfully
// so callers can log it (a security-relevant transition that should
// always be visible in journalctl).
func ConsumeBootstrap(ctx context.Context, db *sql.DB, path string, logger *slog.Logger) (consumed bool, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-managed install path; setup.sh writes 0600
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("auth: read %s: %w", path, err)
	}

	// If an admin already exists, this bootstrap file is stale — a failed
	// os.Remove on a prior start, or a data-preserving reinstall that
	// re-wrote it. Re-consuming it would call Upsert, whose ON CONFLICT
	// clause overwrites username + password_hash and resets
	// password_changed_at to NULL, silently reverting any password the
	// operator changed from the panel back to the install-time value.
	// Discard the stale file instead of consuming it.
	exists, err := adminExists(ctx, db)
	if err != nil {
		return false, fmt.Errorf("auth: check existing admin: %w", err)
	}
	if exists {
		for i := range data {
			data[i] = 0
		}
		if rmErr := os.Remove(path); rmErr != nil {
			logger.Warn("bootstrap: admin already provisioned; could not remove stale bootstrap file — REMOVE IT BY HAND",
				"path", path, "err", rmErr)
		} else {
			logger.Info("bootstrap: admin already provisioned; discarded stale bootstrap file",
				"path", path)
		}
		return false, nil
	}

	var bf BootstrapFile
	if err := toml.Unmarshal(data, &bf); err != nil {
		return false, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	if bf.Username == "" || bf.Password == "" {
		return false, fmt.Errorf("auth: %s missing username or password", path)
	}

	hash, err := HashPassword(bf.Password)
	if err != nil {
		return false, fmt.Errorf("auth: hash bootstrap password: %w", err)
	}

	if err := NewAdminStore(db).Upsert(ctx, bf.Username, hash); err != nil {
		return false, fmt.Errorf("auth: upsert admin: %w", err)
	}

	// Best-effort wipe of the in-memory plaintext before we touch the
	// disk file. The garbage collector will release the slice eventually
	// either way, but zeroing here narrows the window further.
	for i := range data {
		data[i] = 0
	}

	if err := os.Remove(path); err != nil {
		// We have already written the hashed row; failing the boot
		// because the OS won't unlink the file would be self-defeating.
		// Log loudly so the operator notices and removes it by hand.
		logger.Error("bootstrap: failed to remove bootstrap-admin.toml after consumption — REMOVE IT BY HAND",
			"path", path, "err", err)
		return true, nil
	}
	logger.Info("bootstrap: consumed bootstrap-admin.toml and removed plaintext from disk",
		"path", path, "username", bf.Username)
	return true, nil
}

// adminExists reports whether the single admin row (id = 1) is already
// present. Used to make bootstrap consumption idempotent: once an admin
// exists, a lingering bootstrap file must never overwrite it.
func adminExists(ctx context.Context, db *sql.DB) (bool, error) {
	var one int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM admin WHERE id = 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
