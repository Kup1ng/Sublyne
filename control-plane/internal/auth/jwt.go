package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionTokenTTL is the lifetime of a control-plane JWT.
// PROJECT_REQUIREMENTS §4.2: "Token TTL 31 days. Persist across
// server reboot."
const SessionTokenTTL = 31 * 24 * time.Hour

// settingsKeyJWTSigningKey is the row in `settings` that stores the
// base64-encoded HS256 key. We persist the key (instead of generating
// fresh bytes on every restart) so tokens issued before a restart
// remain valid after it — that's what gives users a 31-day session
// across `systemctl restart sublyne`.
const settingsKeyJWTSigningKey = "jwt_signing_key"

// jwtSigningKeyBytes is the size of the random HS256 key, in bytes.
// 32 bytes (256 bits) matches the HMAC-SHA256 output size and is
// conventional for HS256.
const jwtSigningKeyBytes = 32

// JWTClaims is what we sign into every session token. We use the
// project-specific structure on top of jwt.RegisteredClaims so we can
// add fields later (e.g. token version after a forced-logout feature)
// without breaking the signature scheme.
type JWTClaims struct {
	jwt.RegisteredClaims
	AdminID int64 `json:"admin_id"`
}

// SigningKeyStore loads the JWT signing key from `settings`, generating
// and persisting a fresh 32-byte key on the first call after install.
// The same key is reused across restarts; rotating it invalidates
// every outstanding session (intentional — surfaced as a future
// admin action).
type SigningKeyStore struct {
	db *sql.DB
}

// NewSigningKeyStore constructs a store bound to the supplied DB
// handle. The DB must already be migrated (settings table present).
func NewSigningKeyStore(db *sql.DB) *SigningKeyStore {
	return &SigningKeyStore{db: db}
}

// Key returns the active signing key, generating one if the settings
// row does not yet exist. Calls after the first one read the cached
// row directly; we do not memoize in-process so that a restore-from-
// backup picks up the restored key immediately.
func (s *SigningKeyStore) Key(ctx context.Context) ([]byte, error) {
	encoded, err := readSetting(ctx, s.db, settingsKeyJWTSigningKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("auth: read jwt key: %w", err)
	}
	if err == nil && encoded != "" {
		raw, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			return nil, fmt.Errorf("auth: decode jwt key: %w", decodeErr)
		}
		if len(raw) < 16 {
			return nil, fmt.Errorf("auth: stored jwt key is too short (%d bytes)", len(raw))
		}
		return raw, nil
	}
	// No key yet — generate and persist.
	raw := make([]byte, jwtSigningKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("auth: generate jwt key: %w", err)
	}
	if err := writeSetting(ctx, s.db, settingsKeyJWTSigningKey, base64.StdEncoding.EncodeToString(raw)); err != nil {
		return nil, fmt.Errorf("auth: persist jwt key: %w", err)
	}
	return raw, nil
}

// Issuer issues HS256 JWTs against a key supplied by SigningKeyStore.
type Issuer struct {
	store *SigningKeyStore
	now   func() time.Time
}

// NewIssuer returns a JWT issuer backed by store. The clock parameter
// is exposed for unit tests that need to fast-forward expiry; pass nil
// in production to use time.Now.
func NewIssuer(store *SigningKeyStore, now func() time.Time) *Issuer {
	if now == nil {
		now = time.Now
	}
	return &Issuer{store: store, now: now}
}

// Issue signs and returns a token for the supplied admin ID. The
// caller decides what to do with the resulting string — the auth
// handlers wrap it in a Set-Cookie header and also return it in the
// JSON body for `Authorization: Bearer` clients.
func (i *Issuer) Issue(ctx context.Context, adminID int64) (token string, expiresAt time.Time, err error) {
	key, err := i.store.Key(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	now := i.now().UTC().Truncate(time.Second)
	expiresAt = now.Add(SessionTokenTTL)
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "admin",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		AdminID: adminID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// Validate parses and validates a JWT against the active signing key.
// It accepts only HS256 tokens (algorithm confusion attacks are
// rejected at parse time). The returned claims are guaranteed to have
// passed `exp` / `nbf` validation.
func (i *Issuer) Validate(ctx context.Context, raw string) (*JWTClaims, error) {
	key, err := i.store.Key(ctx)
	if err != nil {
		return nil, err
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithTimeFunc(i.now),
	)
	var claims JWTClaims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("auth: token rejected")
	}
	return &claims, nil
}

// readSetting fetches a value from the settings key/value table.
// Returns sql.ErrNoRows when the key is absent.
func readSetting(ctx context.Context, db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, err
}

// writeSetting upserts a value in the settings table.
func writeSetting(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO settings (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value)
	return err
}
