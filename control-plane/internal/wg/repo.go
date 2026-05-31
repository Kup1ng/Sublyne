package wg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrConfigNotFound is returned by Get / Update / Delete when the
// requested wireguard_configs row is not present.
var ErrConfigNotFound = errors.New("wg: config not found")

// ErrConfigNameTaken is returned by Create / Update when the new name
// collides with an existing row. The API layer translates this into
// HTTP 409.
var ErrConfigNameTaken = errors.New("wg: config name already in use")

// ErrConfigReferenced is returned by Delete when at least one tunnel
// row references this config via tunnels.wg_config_id. The API layer
// uses this to surface a 409 with the dependent tunnels listed.
var ErrConfigReferenced = errors.New("wg: config is referenced by one or more tunnels; remove the link first")

// Config is the in-memory representation of one wireguard_configs
// row. RawText is the secret half; everywhere except the dedicated
// "?reveal=1" endpoint, callers should treat it as opaque bytes that
// must not be logged or shipped over the API.
type Config struct {
	ID               int64
	Name             string
	RawText          string
	InterfaceAddress string
	Endpoint         string
	PublicKeySelf    string
	MTU              sql.NullInt64
	ListenPort       sql.NullInt64
	PeerCount        int
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Repo is the persistence layer for wireguard_configs. Like
// tunnels.Repo, all callers should use it instead of touching the
// *sql.DB directly so the column list stays in one place.
type Repo struct {
	db *sql.DB
}

// NewRepo wraps a *sql.DB. The DB must have migrations through 0003
// applied so the wireguard_configs table and the tunnels.wg_config_id
// column exist.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

const configColumns = `
id,
name,
raw_text,
interface_address,
endpoint,
public_key_self,
mtu,
listen_port,
peer_count,
created_at,
updated_at
`

func scanConfig(row interface {
	Scan(dest ...any) error
}) (Config, error) {
	var c Config
	if err := row.Scan(
		&c.ID,
		&c.Name,
		&c.RawText,
		&c.InterfaceAddress,
		&c.Endpoint,
		&c.PublicKeySelf,
		&c.MTU,
		&c.ListenPort,
		&c.PeerCount,
		&c.CreatedAt,
		&c.UpdatedAt,
	); err != nil {
		return Config{}, err
	}
	return c, nil
}

// List returns every config, ordered by id (creation order).
func (r *Repo) List(ctx context.Context) ([]Config, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+configColumns+` FROM wireguard_configs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("wg: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Config
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, fmt.Errorf("wg: scan list row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("wg: rows iterate: %w", err)
	}
	return out, nil
}

// Get returns the config with the given id, or ErrConfigNotFound.
func (r *Repo) Get(ctx context.Context, id int64) (Config, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+configColumns+` FROM wireguard_configs WHERE id = ?`, id)
	c, err := scanConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, ErrConfigNotFound
	}
	if err != nil {
		return Config{}, fmt.Errorf("wg: get %d: %w", id, err)
	}
	return c, nil
}

// GetByName returns the config with the given name, or ErrConfigNotFound.
// Used by the by-name tunnel-import/export path so an exported tunnel can
// reference a WireGuard config by its stable name rather than a per-panel
// id (ids differ between the two boxes). The `name` column carries a
// UNIQUE constraint, so at most one row matches.
func (r *Repo) GetByName(ctx context.Context, name string) (Config, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+configColumns+` FROM wireguard_configs WHERE name = ?`, name)
	c, err := scanConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, ErrConfigNotFound
	}
	if err != nil {
		return Config{}, fmt.Errorf("wg: get by name %q: %w", name, err)
	}
	return c, nil
}

// Create inserts a new config and returns the freshly-persisted row.
// The caller is responsible for parsing the raw text first and
// supplying the derived summary fields (InterfaceAddress, Endpoint,
// etc.) — the repo does not re-parse.
func (r *Repo) Create(ctx context.Context, c Config) (Config, error) {
	res, err := r.db.ExecContext(ctx, `
INSERT INTO wireguard_configs (
  name, raw_text, interface_address, endpoint, public_key_self,
  mtu, listen_port, peer_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Name, c.RawText, c.InterfaceAddress, c.Endpoint, c.PublicKeySelf,
		c.MTU, c.ListenPort, c.PeerCount,
	)
	if err != nil {
		if isUniqueConstraint(err, "wireguard_configs.name") {
			return Config{}, ErrConfigNameTaken
		}
		return Config{}, fmt.Errorf("wg: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Config{}, fmt.Errorf("wg: last insert id: %w", err)
	}
	return r.Get(ctx, id)
}

// Update writes every settable column on the existing row. If
// keepRaw is true the row's existing raw_text and parsed summary are
// preserved (used when the API caller submits a PUT without a
// raw_text field — they only renamed the config). Otherwise the
// supplied parsed summary is written verbatim and raw_text is replaced.
func (r *Repo) Update(ctx context.Context, c Config, keepRaw bool) (Config, error) {
	if keepRaw {
		// The caller did not paste new text; only the name (or
		// nothing) changed. We read the existing parsed summary +
		// raw_text once and write them back so the SQL statement
		// stays static and gosec/G202 stays happy.
		existing, err := r.Get(ctx, c.ID)
		if err != nil {
			return Config{}, err
		}
		c.RawText = existing.RawText
		c.InterfaceAddress = existing.InterfaceAddress
		c.Endpoint = existing.Endpoint
		c.PublicKeySelf = existing.PublicKeySelf
		c.MTU = existing.MTU
		c.ListenPort = existing.ListenPort
		c.PeerCount = existing.PeerCount
	}
	res, err := r.db.ExecContext(ctx, `
UPDATE wireguard_configs SET
  name = ?, raw_text = ?, interface_address = ?, endpoint = ?, public_key_self = ?,
  mtu = ?, listen_port = ?, peer_count = ?,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?`,
		c.Name, c.RawText, c.InterfaceAddress, c.Endpoint, c.PublicKeySelf,
		c.MTU, c.ListenPort, c.PeerCount,
		c.ID,
	)
	if err != nil {
		if isUniqueConstraint(err, "wireguard_configs.name") {
			return Config{}, ErrConfigNameTaken
		}
		return Config{}, fmt.Errorf("wg: update %d: %w", c.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Config{}, ErrConfigNotFound
	}
	return r.Get(ctx, c.ID)
}

// Delete removes a config from the table. The roadmap requires that
// configs in use by a tunnel cannot be deleted; ReferencingTunnels
// reports the dependent rows so the API can surface them.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("wg: begin tx for delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM wireguard_configs WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConfigNotFound
	}
	if err != nil {
		return fmt.Errorf("wg: read row for delete: %w", err)
	}

	var refCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnels WHERE wg_config_id = ?`, id).Scan(&refCount); err != nil {
		return fmt.Errorf("wg: scan referencing tunnels: %w", err)
	}
	if refCount > 0 {
		return ErrConfigReferenced
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM wireguard_configs WHERE id = ?`, id); err != nil {
		return fmt.Errorf("wg: delete %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("wg: commit delete: %w", err)
	}
	return nil
}

// ReferencingTunnels returns the names of every tunnel that points
// at this config via wg_config_id. Used by the API layer to build the
// error body for a refused delete.
func (r *Repo) ReferencingTunnels(ctx context.Context, id int64) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT name FROM tunnels WHERE wg_config_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("wg: query referencing tunnels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("wg: scan reference: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("wg: iterate references: %w", err)
	}
	return names, nil
}

// isUniqueConstraint mirrors the helper in tunnels/repo.go so the wg
// package doesn't have to import its sibling for a one-liner check.
func isUniqueConstraint(err error, qualifiedColumn string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, qualifiedColumn)
}
