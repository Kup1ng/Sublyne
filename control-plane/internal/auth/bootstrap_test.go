package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeBootstrap(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-admin.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}
	return path
}

func TestConsumeBootstrap_InsertsAdminAndRemovesFile(t *testing.T) {
	db := newTestDB(t)
	path := writeBootstrap(t, `username = "admin"
password = "tr0ub4dor"
`)

	consumed, err := ConsumeBootstrap(context.Background(), db, path, nil)
	if err != nil {
		t.Fatalf("ConsumeBootstrap: %v", err)
	}
	if !consumed {
		t.Fatal("expected consumed=true")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("bootstrap file still present after consume: err=%v", err)
	}

	admin, err := NewAdminStore(db).Get(context.Background())
	if err != nil {
		t.Fatalf("Get admin: %v", err)
	}
	if admin.Username != "admin" {
		t.Errorf("Username = %q, want %q", admin.Username, "admin")
	}
	if admin.PasswordHash == "tr0ub4dor" {
		t.Error("password stored in plaintext — must be Argon2id-encoded")
	}
	if err := VerifyPassword(admin.PasswordHash, "tr0ub4dor"); err != nil {
		t.Errorf("stored hash does not verify the original password: %v", err)
	}
}

func TestConsumeBootstrap_NoFileIsNotAnError(t *testing.T) {
	db := newTestDB(t)
	consumed, err := ConsumeBootstrap(context.Background(), db, filepath.Join(t.TempDir(), "absent.toml"), nil)
	if err != nil {
		t.Fatalf("ConsumeBootstrap with missing file: %v", err)
	}
	if consumed {
		t.Error("consumed=true for a missing file")
	}
	if _, err := NewAdminStore(db).Get(context.Background()); err == nil {
		t.Error("expected ErrAdminNotFound when bootstrap was never consumed")
	}
}

func TestConsumeBootstrap_RejectsEmptyCreds(t *testing.T) {
	db := newTestDB(t)
	path := writeBootstrap(t, "username = \"\"\npassword = \"x\"\n")
	if _, err := ConsumeBootstrap(context.Background(), db, path, nil); err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestConsumeBootstrap_RejectsMalformed(t *testing.T) {
	db := newTestDB(t)
	path := writeBootstrap(t, "this is not = = valid toml\n")
	if _, err := ConsumeBootstrap(context.Background(), db, path, nil); err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

// TestConsumeBootstrap_DoesNotRevertChangedPassword guards the
// idempotency fix: once an admin exists, a lingering bootstrap file (a
// failed os.Remove on a prior start, or a data-preserving reinstall)
// must NOT re-provision the admin and clobber a panel-changed password.
func TestConsumeBootstrap_DoesNotRevertChangedPassword(t *testing.T) {
	db := newTestDB(t)
	body := "username = \"admin\"\npassword = \"install-pw\"\n"
	path := writeBootstrap(t, body)

	// First start: provision the admin from the bootstrap file.
	if _, err := ConsumeBootstrap(context.Background(), db, path, nil); err != nil {
		t.Fatalf("first consume: %v", err)
	}

	// Operator changes the password via the panel.
	newHash, err := HashPassword("panel-pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := NewAdminStore(db).UpdatePassword(context.Background(), newHash); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	// Simulate the file lingering (prior os.Remove failure / reinstall).
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("rewrite bootstrap: %v", err)
	}

	consumed, err := ConsumeBootstrap(context.Background(), db, path, nil)
	if err != nil {
		t.Fatalf("second consume: %v", err)
	}
	if consumed {
		t.Error("second consume must NOT re-provision an existing admin")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("stale bootstrap file should have been removed, err=%v", err)
	}

	admin, err := NewAdminStore(db).Get(context.Background())
	if err != nil {
		t.Fatalf("Get admin: %v", err)
	}
	if err := VerifyPassword(admin.PasswordHash, "panel-pw"); err != nil {
		t.Errorf("panel-changed password was reverted by stale bootstrap: %v", err)
	}
	if VerifyPassword(admin.PasswordHash, "install-pw") == nil {
		t.Error("install-time password was wrongly restored from a stale bootstrap file")
	}
}
