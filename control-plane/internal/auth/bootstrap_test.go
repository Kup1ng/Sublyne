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
