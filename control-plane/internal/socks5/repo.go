// Package socks5 persists the SOCKS5 proxies referenced by Client
// tunnels with upload_mode='socks5' (Round 2 Phase R8). The dataplane
// half of the feature lands in Phase R9; this package is the storage
// and validation layer only.
//
// Shape mirrors control-plane/internal/wg/repo.go on purpose so the
// API handlers (control-plane/internal/api/socks5_handlers.go) can
// reuse the same response/redaction/conflict patterns the WireGuard
// pages already use. See .claude/skills/socks5-upload/SKILL.md for the
// motivation: SOCKS5 lets one tunnel spread upload across multiple
// Starlink uplinks behind a load-balancing proxy.
package socks5

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrProxyNotFound is returned by Get / Update / Delete when the
// requested socks5_proxies row is not present.
var ErrProxyNotFound = errors.New("socks5: proxy not found")

// ErrProxyNameTaken is returned by Create / Update when the new name
// collides with an existing row. The API layer translates this into
// HTTP 409.
var ErrProxyNameTaken = errors.New("socks5: proxy name already in use")

// ErrProxyReferenced is returned by Delete when at least one tunnel
// row references this proxy via tunnels.socks5_proxy_id. The API
// layer uses this to surface a 409 with the dependent tunnels listed.
var ErrProxyReferenced = errors.New("socks5: proxy is referenced by one or more tunnels; remove the link first")

// Proxy is the in-memory representation of one socks5_proxies row.
// Password is the secret half; everywhere except the dedicated
// "?reveal=1" endpoint, callers should treat it as opaque bytes that
// must not be logged or shipped over the API.
type Proxy struct {
	ID                  int64
	Name                string
	Host                string
	Port                int
	Username            sql.NullString
	Password            sql.NullString
	ParallelConnections int
	// MinReadySlots is the warm-up gate: the dataplane refuses to
	// mark a SOCKS5-mode tunnel up until at least this many pool slots
	// complete the SOCKS5 handshake. Introduced in migration 0008
	// (Sublyne hardening pass). Default 2 is generous; for high-N pools
	// the panel hints at half-of-N.
	MinReadySlots int
	Notes         sql.NullString
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Repo is the persistence layer for socks5_proxies. Like
// wg.Repo / tunnels.Repo, all callers should use it instead of
// touching the *sql.DB directly so the column list stays in one
// place.
type Repo struct {
	db *sql.DB
}

// NewRepo wraps a *sql.DB. The DB must have migrations through 0006
// applied so the socks5_proxies table and the tunnels.socks5_proxy_id
// column exist.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

const proxyColumns = `
id,
name,
host,
port,
username,
password,
parallel_connections,
min_ready_slots,
notes,
created_at,
updated_at
`

func scanProxy(row interface {
	Scan(dest ...any) error
}) (Proxy, error) {
	var p Proxy
	if err := row.Scan(
		&p.ID,
		&p.Name,
		&p.Host,
		&p.Port,
		&p.Username,
		&p.Password,
		&p.ParallelConnections,
		&p.MinReadySlots,
		&p.Notes,
		&p.CreatedAt,
		&p.UpdatedAt,
	); err != nil {
		return Proxy{}, err
	}
	return p, nil
}

// List returns every proxy, ordered by id (creation order).
func (r *Repo) List(ctx context.Context) ([]Proxy, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+proxyColumns+` FROM socks5_proxies ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("socks5: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, fmt.Errorf("socks5: scan list row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("socks5: rows iterate: %w", err)
	}
	return out, nil
}

// Get returns the proxy with the given id, or ErrProxyNotFound.
func (r *Repo) Get(ctx context.Context, id int64) (Proxy, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+proxyColumns+` FROM socks5_proxies WHERE id = ?`, id)
	p, err := scanProxy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrProxyNotFound
	}
	if err != nil {
		return Proxy{}, fmt.Errorf("socks5: get %d: %w", id, err)
	}
	return p, nil
}

// Create inserts a new proxy and returns the freshly-persisted row.
// The caller is responsible for running validation first; this method
// does not re-check semantics. A UNIQUE constraint violation on
// `name` is translated to ErrProxyNameTaken so the API can map it to
// 409.
func (r *Repo) Create(ctx context.Context, p Proxy) (Proxy, error) {
	if p.MinReadySlots < 1 {
		p.MinReadySlots = 1
	}
	res, err := r.db.ExecContext(ctx, `
INSERT INTO socks5_proxies (
  name, host, port, username, password, parallel_connections, min_ready_slots, notes
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Host, p.Port, p.Username, p.Password, p.ParallelConnections, p.MinReadySlots, p.Notes,
	)
	if err != nil {
		if isUniqueConstraint(err, "socks5_proxies.name") {
			return Proxy{}, ErrProxyNameTaken
		}
		return Proxy{}, fmt.Errorf("socks5: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Proxy{}, fmt.Errorf("socks5: last insert id: %w", err)
	}
	return r.Get(ctx, id)
}

// Update writes every settable column on the existing row. If
// keepPassword is true the row's existing password is preserved (used
// when the API caller submits a PUT without a password field — they
// only renamed the proxy or rotated other fields). Otherwise the
// supplied p.Password is written verbatim. Mirrors the keepRaw /
// keepPSK convention from wg.Repo and tunnels.Repo so the SQL
// statement stays static (gosec/G202 happy) regardless of which
// fields the operator left untouched.
func (r *Repo) Update(ctx context.Context, p Proxy, keepPassword bool) (Proxy, error) {
	password := p.Password
	if keepPassword {
		var existing sql.NullString
		err := r.db.QueryRowContext(ctx, `SELECT password FROM socks5_proxies WHERE id = ?`, p.ID).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			return Proxy{}, ErrProxyNotFound
		}
		if err != nil {
			return Proxy{}, fmt.Errorf("socks5: read existing password for update: %w", err)
		}
		password = existing
	}
	if p.MinReadySlots < 1 {
		p.MinReadySlots = 1
	}
	res, err := r.db.ExecContext(ctx, `
UPDATE socks5_proxies SET
  name = ?, host = ?, port = ?, username = ?, password = ?,
  parallel_connections = ?, min_ready_slots = ?, notes = ?,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?`,
		p.Name, p.Host, p.Port, p.Username, password,
		p.ParallelConnections, p.MinReadySlots, p.Notes,
		p.ID,
	)
	if err != nil {
		if isUniqueConstraint(err, "socks5_proxies.name") {
			return Proxy{}, ErrProxyNameTaken
		}
		return Proxy{}, fmt.Errorf("socks5: update %d: %w", p.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Proxy{}, ErrProxyNotFound
	}
	return r.Get(ctx, p.ID)
}

// Delete removes a proxy from the table. The roadmap requires that
// proxies in use by a tunnel cannot be deleted; ReferencingTunnels
// reports the dependent rows so the API can surface them.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("socks5: begin tx for delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM socks5_proxies WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProxyNotFound
	}
	if err != nil {
		return fmt.Errorf("socks5: read row for delete: %w", err)
	}

	var refCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnels WHERE socks5_proxy_id = ?`, id).Scan(&refCount); err != nil {
		return fmt.Errorf("socks5: scan referencing tunnels: %w", err)
	}
	if refCount > 0 {
		return ErrProxyReferenced
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM socks5_proxies WHERE id = ?`, id); err != nil {
		return fmt.Errorf("socks5: delete %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("socks5: commit delete: %w", err)
	}
	return nil
}

// ReferencingTunnels returns the names of every tunnel that points
// at this proxy via socks5_proxy_id. Used by the API layer to build
// the error body for a refused delete.
func (r *Repo) ReferencingTunnels(ctx context.Context, id int64) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT name FROM tunnels WHERE socks5_proxy_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("socks5: query referencing tunnels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("socks5: scan reference: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("socks5: iterate references: %w", err)
	}
	return names, nil
}

// isUniqueConstraint mirrors the helper in wg/repo.go / tunnels/repo.go
// so the socks5 package doesn't have to import either sibling for a
// one-liner check.
func isUniqueConstraint(err error, qualifiedColumn string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, qualifiedColumn)
}
