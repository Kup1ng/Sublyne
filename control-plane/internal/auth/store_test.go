package auth

import (
	"context"
	"errors"
	"testing"
)

func TestAdminStore_GetReturnsNotFoundWhenEmpty(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	if _, err := s.Get(context.Background()); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("err = %v, want ErrAdminNotFound", err)
	}
}

func TestAdminStore_UpsertThenGet(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s.Upsert(context.Background(), "admin", hash); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	a, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.ID != 1 {
		t.Errorf("ID = %d, want 1", a.ID)
	}
	if a.Username != "admin" {
		t.Errorf("Username = %q, want admin", a.Username)
	}
	if a.PasswordChangedAt.Valid {
		t.Errorf("PasswordChangedAt should be NULL after initial upsert")
	}
}

func TestAdminStore_UpsertReplacesUsername(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	h, _ := HashPassword("x")
	if err := s.Upsert(context.Background(), "admin", h); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(context.Background(), "operator", h); err != nil {
		t.Fatal(err)
	}
	a, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "operator" {
		t.Errorf("Username after second Upsert = %q, want operator", a.Username)
	}
}

func TestAdminStore_UpdatePassword(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	h1, _ := HashPassword("old")
	if err := s.Upsert(context.Background(), "admin", h1); err != nil {
		t.Fatal(err)
	}
	h2, _ := HashPassword("new")
	if err := s.UpdatePassword(context.Background(), h2); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	a, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.PasswordHash != h2 {
		t.Error("password hash was not updated")
	}
	if !a.PasswordChangedAt.Valid {
		t.Error("PasswordChangedAt should be set after UpdatePassword")
	}
}

func TestAdminStore_UpdatePasswordRefusesEmptyHash(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	if err := s.UpdatePassword(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty hash")
	}
}

func TestAdminStore_UpdatePasswordReportsMissingAdmin(t *testing.T) {
	db := newTestDB(t)
	s := NewAdminStore(db)
	h, _ := HashPassword("x")
	if err := s.UpdatePassword(context.Background(), h); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("err = %v, want ErrAdminNotFound", err)
	}
}
