package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("hash %q has unexpected prefix", hash)
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("VerifyPassword on correct password: %v", err)
	}
	if err := VerifyPassword(hash, "wrong password"); err == nil {
		t.Errorf("VerifyPassword should reject wrong password")
	}
}

func TestHashPassword_DistinctSalts(t *testing.T) {
	h1, err := HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	h2, err := HashPassword("password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if h1 == h2 {
		t.Errorf("two hashes of the same password collided — salt likely not random:\n h1=%s\n h2=%s", h1, h2)
	}
}

func TestHashPassword_RejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected error hashing empty password")
	}
}

func TestVerifyPassword_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyfoursegments",
		"$argon2i$v=19$m=65536,t=3,p=2$YWFhYQ$YWFhYQ",  // wrong algo
		"$argon2id$v=18$m=65536,t=3,p=2$YWFhYQ$YWFhYQ", // wrong version
		"$argon2id$v=19$m=bad,t=3,p=2$YWFhYQ$YWFhYQ",
		"$argon2id$v=19$m=65536,t=3,p=2$bad-base64!$YWFhYQ",
		"$argon2id$v=19$m=65536,t=3,p=2$YWFhYQ$bad-base64!",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if err := VerifyPassword(c, "irrelevant"); err == nil {
				t.Errorf("malformed hash %q accepted", c)
			}
		})
	}
}

func TestVerifyPassword_HandlesUnicodeAndLongInputs(t *testing.T) {
	pw := strings.Repeat("ünı©ödé✓", 8)
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(hash, pw); err != nil {
		t.Errorf("VerifyPassword for unicode password: %v", err)
	}
}
