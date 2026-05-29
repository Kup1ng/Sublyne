// Package auth implements the control-plane's authentication layer:
// Argon2id password hashing, JWT issue/verify with a DB-persisted
// signing key, brute-force rate limiting backed by the login_attempts
// table, and HTTP middleware that pulls the admin out of a request.
//
// There is exactly one admin user per server (see PROJECT_REQUIREMENTS
// §4.1). The bootstrap row is created on first start from the
// plaintext credentials in /etc/sublyne/bootstrap-admin.toml, which is
// then deleted; thereafter the password lives only as an Argon2id hash
// in the admin table.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. The values are taken from
// IMPLEMENTATION_ROADMAP.md Phase 3 deliverables:
//   - memory:      64 MiB  (resistance to GPU attacks)
//   - iterations:  3       (RFC 9106 recommended minimum)
//   - parallelism: 2       (matches a small-VPS CPU)
//   - salt:        16 B    (>= 16 B per RFC 9106)
//   - hash output: 32 B    (sized for a 256-bit key)
//
// The encoded form is the standard PHC string
// "$argon2id$v=19$m=65536,t=3,p=2$<salt-b64>$<hash-b64>".
const (
	argonMemoryKiB    uint32 = 64 * 1024
	argonIterations   uint32 = 3
	argonParallelism  uint8  = 2
	argonSaltLength   uint32 = 16
	argonKeyLength    uint32 = 32
	argonVersion             = argon2.Version // 0x13 == 19
	argonAlgoLabel           = "argon2id"
	argonEncodedParts        = 6 // "", "argon2id", "v=19", "m=,t=,p=", "<salt>", "<hash>"
)

// ErrPasswordMismatch is returned by VerifyPassword when the supplied
// password does not match the encoded hash. Callers should not
// distinguish this from "encoded hash malformed" in user-facing
// responses: leak nothing about which case fired.
var ErrPasswordMismatch = errors.New("auth: password does not match")

// HashPassword derives an Argon2id encoded hash for the supplied
// plaintext using the parameters declared above. The salt is read
// fresh from crypto/rand for every call.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: password must not be empty")
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(password),
		salt,
		argonIterations,
		argonMemoryKiB,
		argonParallelism,
		argonKeyLength,
	)
	encoded := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonAlgoLabel,
		argonVersion,
		argonMemoryKiB,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return encoded, nil
}

// VerifyPassword returns nil when password matches the Argon2id
// encoded hash. It uses a constant-time comparison so timing cannot
// be used to discriminate "wrong password" from "no admin row".
//
// The function tolerates re-encoded hashes whose Argon2id parameters
// differ from the project defaults — callers may upgrade params over
// time; we just need to verify against whatever the stored row says.
func VerifyPassword(encoded, password string) error {
	params, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return err
	}
	// Bound check so the uint32 conversion below cannot overflow. A
	// legitimate Argon2 hash output is dozens of bytes; anything past
	// 4 KiB is a malformed input we should not pass to the KDF.
	if len(want) == 0 || len(want) > 4096 {
		return fmt.Errorf("auth: hash output length %d is out of range", len(want))
	}
	keyLen := uint32(len(want)) //nolint:gosec // bounded by the check above
	got := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memoryKiB,
		params.parallelism,
		keyLen,
	)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

type argon2Params struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
}

func decodeArgon2id(encoded string) (argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != argonEncodedParts {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: malformed argon2id encoding (got %d segments, want %d)", len(parts), argonEncodedParts)
	}
	if parts[1] != argonAlgoLabel {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: unsupported algorithm %q (want %q)", parts[1], argonAlgoLabel)
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: malformed version segment %q: %w", parts[2], err)
	}
	if version != argonVersion {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: unsupported argon2 version %d (want %d)", version, argonVersion)
	}
	var p argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.iterations, &p.parallelism); err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: malformed params segment %q: %w", parts[3], err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: malformed salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("auth: malformed hash: %w", err)
	}
	return p, salt, key, nil
}
