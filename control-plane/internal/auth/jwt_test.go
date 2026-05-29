package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSigningKeyStore_PersistsAcrossCalls(t *testing.T) {
	db := newTestDB(t)
	store := NewSigningKeyStore(db)

	k1, err := store.Key(context.Background())
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if len(k1) != jwtSigningKeyBytes {
		t.Errorf("first key is %d bytes, want %d", len(k1), jwtSigningKeyBytes)
	}
	k2, err := store.Key(context.Background())
	if err != nil {
		t.Fatalf("second Key: %v", err)
	}
	if string(k1) != string(k2) {
		t.Errorf("second call returned a different key (should be persisted across calls)")
	}
}

func TestIssuer_ValidateRoundTrip(t *testing.T) {
	db := newTestDB(t)
	store := NewSigningKeyStore(db)
	issuer := NewIssuer(store, nil)

	tok, expiresAt, err := issuer.Issue(context.Background(), 1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	want := time.Now().Add(SessionTokenTTL)
	delta := expiresAt.Sub(want)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Errorf("expires_at = %v, want within 2s of %v", expiresAt, want)
	}

	claims, err := issuer.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.AdminID != 1 {
		t.Errorf("AdminID = %d, want 1", claims.AdminID)
	}
}

func TestIssuer_ExpiredTokenRejected(t *testing.T) {
	db := newTestDB(t)
	store := NewSigningKeyStore(db)

	// Issue a token at time T-32d.
	past := time.Now().Add(-32 * 24 * time.Hour)
	issuer := NewIssuer(store, func() time.Time { return past })
	tok, _, err := issuer.Issue(context.Background(), 1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Validate at the current moment with a clock far past expiry.
	now := NewIssuer(store, time.Now)
	if _, err := now.Validate(context.Background(), tok); err == nil {
		t.Fatal("expected validation failure for expired token")
	}
}

func TestIssuer_RejectsTamperedToken(t *testing.T) {
	db := newTestDB(t)
	store := NewSigningKeyStore(db)
	issuer := NewIssuer(store, nil)
	tok, _, err := issuer.Issue(context.Background(), 7)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Flip a character in the signature segment.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	parts[2] = flipFirstByte(parts[2])
	tampered := strings.Join(parts, ".")
	if _, err := issuer.Validate(context.Background(), tampered); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestIssuer_RejectsAlgNone(t *testing.T) {
	db := newTestDB(t)
	store := NewSigningKeyStore(db)
	issuer := NewIssuer(store, nil)
	// "alg":"none" header + same payload + empty signature.
	tok := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OSwiYWRtaW5faWQiOjF9."
	if _, err := issuer.Validate(context.Background(), tok); err == nil {
		t.Fatal("alg=none token accepted")
	}
}

func flipFirstByte(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}
