package tunnels

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is returned by Get / Update / Delete when the requested
// tunnel id is not present in the table.
var ErrNotFound = errors.New("tunnels: not found")

// ErrNameTaken is returned by Create / Update when the new name collides
// with an existing row. The API layer translates this into a 409.
var ErrNameTaken = errors.New("tunnels: name already in use")

// ErrEnabled is returned by Delete when called against a tunnel whose
// `enabled` flag is true. PRD §3.6 mandates Stop-before-Delete.
var ErrEnabled = errors.New("tunnels: cannot delete an enabled tunnel; stop it first")

// Repo is the persistence layer for tunnels. All callers should use it
// instead of touching the *sql.DB directly so the column list stays in
// one place.
type Repo struct {
	db *sql.DB
}

// NewRepo wraps a *sql.DB. The DB must have migrations through 0002
// applied so the tunnels table exists.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

const tunnelColumns = `
id,
name,
role,
enabled,
psk,
download_spoof_source_ip,
download_spoof_source_port,
download_transport,
mtu,
max_connections,
idle_timeout,
icmp_echo_mode,
local_listen_addr,
download_receive_port,
upload_target_addr,
wireguard_config,
wg_config_id,
upload_mode,
socks5_proxy_id,
ping_smoothing_enabled,
ping_smoothing_target_ms,
pacing_enabled,
pacing_target_ms,
upload_listen_addr,
forward_target,
download_send_port,
client_real_ip,
upload_listen_mode,
ports,
forward_protocol,
tcp_reliability_engine,
forward_engine_preset,
forward_engine_tuning
`

// scanTunnel reads one row in the order the SELECT above lays them out.
// It is the inverse of the parameter list used by Create and Update.
func scanTunnel(row interface {
	Scan(dest ...any) error
}) (Tunnel, error) {
	var t Tunnel
	var enabled, pingSmoothing, pacing int
	var portsCSV string
	err := row.Scan(
		&t.ID,
		&t.Name,
		&t.Role,
		&enabled,
		&t.PSK,
		&t.DownloadSpoofSourceIP,
		&t.DownloadSpoofSourcePort,
		&t.DownloadTransport,
		&t.MTU,
		&t.MaxConnections,
		&t.IdleTimeout,
		&t.IcmpEchoMode,
		&t.LocalListenAddr,
		&t.DownloadReceivePort,
		&t.UploadTargetAddr,
		&t.WireguardConfig,
		&t.WGConfigID,
		&t.UploadMode,
		&t.Socks5ProxyID,
		&pingSmoothing,
		&t.PingSmoothingTargetMS,
		&pacing,
		&t.PacingTargetMS,
		&t.UploadListenAddr,
		&t.ForwardTarget,
		&t.DownloadSendPort,
		&t.ClientRealIP,
		&t.UploadListenMode,
		&portsCSV,
		&t.ForwardProtocol,
		&t.TCPReliabilityEngine,
		&t.ForwardEnginePreset,
		&t.ForwardEngineTuning,
	)
	if err != nil {
		return Tunnel{}, err
	}
	t.Enabled = enabled == 1
	t.PingSmoothingEnabled = pingSmoothing == 1
	t.PacingEnabled = pacing == 1
	ports, err := ParsePortsCSV(portsCSV)
	if err != nil {
		return Tunnel{}, err
	}
	t.Ports = ports
	return t, nil
}

// List returns every tunnel, ordered by id (the order rows were
// created — stable across restarts and the order the panel renders).
func (r *Repo) List(ctx context.Context) ([]Tunnel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+tunnelColumns+` FROM tunnels ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("tunnels: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tunnel
	for rows.Next() {
		t, err := scanTunnel(rows)
		if err != nil {
			return nil, fmt.Errorf("tunnels: scan list row: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tunnels: rows iterate: %w", err)
	}
	return out, nil
}

// Get returns the tunnel with the given id, or ErrNotFound.
func (r *Repo) Get(ctx context.Context, id int64) (Tunnel, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+tunnelColumns+` FROM tunnels WHERE id = ?`, id)
	t, err := scanTunnel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Tunnel{}, ErrNotFound
	}
	if err != nil {
		return Tunnel{}, fmt.Errorf("tunnels: get %d: %w", id, err)
	}
	return t, nil
}

// Create inserts a new tunnel and returns the freshly-persisted row.
// The caller is responsible for running Validate(...) first; this
// method does not re-check semantics. A UNIQUE constraint violation on
// `name` is translated to ErrNameTaken so the API can map it to 409.
func (r *Repo) Create(ctx context.Context, t Tunnel) (Tunnel, error) {
	echoMode := string(t.IcmpEchoMode)
	if echoMode == "" {
		echoMode = string(IcmpEchoModeReply)
	}
	uploadMode := string(t.UploadMode)
	if uploadMode == "" {
		uploadMode = string(UploadModeWireguard)
	}
	uploadListenMode := string(t.UploadListenMode)
	if uploadListenMode == "" {
		uploadListenMode = string(UploadListenModeUDP)
	}
	forwardProto, engine, preset := forwardDefaults(t)
	res, err := r.db.ExecContext(ctx, `
INSERT INTO tunnels (
  name, role, enabled, psk,
  download_spoof_source_ip, download_spoof_source_port, download_transport,
  mtu, max_connections, idle_timeout, icmp_echo_mode,
  local_listen_addr, download_receive_port, upload_target_addr,
  wireguard_config, wg_config_id,
  upload_mode, socks5_proxy_id,
  ping_smoothing_enabled, ping_smoothing_target_ms,
  pacing_enabled, pacing_target_ms,
  upload_listen_addr, forward_target, download_send_port, client_real_ip,
  upload_listen_mode,
  ports,
  forward_protocol, tcp_reliability_engine, forward_engine_preset, forward_engine_tuning
) VALUES (
  ?, ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?,
  ?, ?,
  ?, ?,
  ?, ?,
  ?, ?,
  ?, ?, ?, ?,
  ?,
  ?,
  ?, ?, ?, ?
)`,
		t.Name, string(t.Role), boolToInt(t.Enabled), t.PSK,
		t.DownloadSpoofSourceIP, t.DownloadSpoofSourcePort, string(t.DownloadTransport),
		t.MTU, t.MaxConnections, t.IdleTimeout, echoMode,
		t.LocalListenAddr, t.DownloadReceivePort, t.UploadTargetAddr,
		t.WireguardConfig, t.WGConfigID,
		uploadMode, t.Socks5ProxyID,
		boolToInt(t.PingSmoothingEnabled), t.PingSmoothingTargetMS,
		boolToInt(t.PacingEnabled), t.PacingTargetMS,
		t.UploadListenAddr, t.ForwardTarget, t.DownloadSendPort, t.ClientRealIP,
		uploadListenMode,
		PortsToCSV(t.Ports),
		forwardProto, engine, preset, t.ForwardEngineTuning,
	)
	if err != nil {
		if isUniqueConstraint(err, "tunnels.name") {
			return Tunnel{}, ErrNameTaken
		}
		return Tunnel{}, fmt.Errorf("tunnels: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Tunnel{}, fmt.Errorf("tunnels: last insert id: %w", err)
	}
	return r.Get(ctx, id)
}

// Update writes every settable column on the existing row. The id and
// role columns are immutable; the caller must read the row first to
// preserve those. Like Create, callers are expected to Validate first.
//
// If keepPSK is true the row's existing PSK is preserved (used when
// the API caller submits a PUT without a psk field); otherwise the
// supplied t.PSK is written verbatim. The implementation reads the
// existing PSK once and writes it back so the SQL statement stays
// static — keeping golangci-lint's gosec/G202 happy.
func (r *Repo) Update(ctx context.Context, t Tunnel, keepPSK bool) (Tunnel, error) {
	psk := t.PSK
	if keepPSK {
		var existing string
		err := r.db.QueryRowContext(ctx, `SELECT psk FROM tunnels WHERE id = ?`, t.ID).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			return Tunnel{}, ErrNotFound
		}
		if err != nil {
			return Tunnel{}, fmt.Errorf("tunnels: read existing psk for update: %w", err)
		}
		psk = existing
	}

	echoMode := string(t.IcmpEchoMode)
	if echoMode == "" {
		echoMode = string(IcmpEchoModeReply)
	}
	uploadMode := string(t.UploadMode)
	if uploadMode == "" {
		uploadMode = string(UploadModeWireguard)
	}
	uploadListenMode := string(t.UploadListenMode)
	if uploadListenMode == "" {
		uploadListenMode = string(UploadListenModeUDP)
	}
	forwardProto, engine, preset := forwardDefaults(t)
	res, err := r.db.ExecContext(ctx, `
UPDATE tunnels SET
  name = ?, enabled = ?,
  download_spoof_source_ip = ?, download_spoof_source_port = ?, download_transport = ?,
  mtu = ?, max_connections = ?, idle_timeout = ?, icmp_echo_mode = ?,
  local_listen_addr = ?, download_receive_port = ?, upload_target_addr = ?,
  wireguard_config = ?, wg_config_id = ?,
  upload_mode = ?, socks5_proxy_id = ?,
  ping_smoothing_enabled = ?, ping_smoothing_target_ms = ?,
  pacing_enabled = ?, pacing_target_ms = ?,
  upload_listen_addr = ?, forward_target = ?, download_send_port = ?, client_real_ip = ?,
  upload_listen_mode = ?,
  ports = ?,
  forward_protocol = ?, tcp_reliability_engine = ?, forward_engine_preset = ?, forward_engine_tuning = ?,
  psk = ?,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?`,
		t.Name, boolToInt(t.Enabled),
		t.DownloadSpoofSourceIP, t.DownloadSpoofSourcePort, string(t.DownloadTransport),
		t.MTU, t.MaxConnections, t.IdleTimeout, echoMode,
		t.LocalListenAddr, t.DownloadReceivePort, t.UploadTargetAddr,
		t.WireguardConfig, t.WGConfigID,
		uploadMode, t.Socks5ProxyID,
		boolToInt(t.PingSmoothingEnabled), t.PingSmoothingTargetMS,
		boolToInt(t.PacingEnabled), t.PacingTargetMS,
		t.UploadListenAddr, t.ForwardTarget, t.DownloadSendPort, t.ClientRealIP,
		uploadListenMode,
		PortsToCSV(t.Ports),
		forwardProto, engine, preset, t.ForwardEngineTuning,
		psk,
		t.ID,
	)
	if err != nil {
		if isUniqueConstraint(err, "tunnels.name") {
			return Tunnel{}, ErrNameTaken
		}
		return Tunnel{}, fmt.Errorf("tunnels: update %d: %w", t.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Tunnel{}, ErrNotFound
	}
	return r.Get(ctx, t.ID)
}

// SetEnabled flips the enabled flag and returns the updated row. Used
// by the start/stop handlers (Phase 6 does not bring up any data plane;
// the flag is the sole source of truth for the status badge until
// Phase 10 lands).
func (r *Repo) SetEnabled(ctx context.Context, id int64, enabled bool) (Tunnel, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE tunnels SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		boolToInt(enabled), id)
	if err != nil {
		return Tunnel{}, fmt.Errorf("tunnels: set enabled %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Tunnel{}, ErrNotFound
	}
	return r.Get(ctx, id)
}

// Delete removes a tunnel from the table. The tunnel must be disabled
// first per PRD §3.6; otherwise ErrEnabled is returned and the row is
// left untouched.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("tunnels: begin tx for delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var enabled int
	err = tx.QueryRowContext(ctx, `SELECT enabled FROM tunnels WHERE id = ?`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("tunnels: read enabled for delete: %w", err)
	}
	if enabled == 1 {
		return ErrEnabled
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tunnels WHERE id = ?`, id); err != nil {
		return fmt.Errorf("tunnels: delete %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tunnels: commit delete: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// forwardDefaults coerces the three enum-backed TCP-forwarding columns to
// valid non-empty values so the 0012 CHECK constraints hold even when the
// caller left them blank (an older API body, an import, a clone of a
// pre-v4 row). The tuning blob defaults to "" and needs no coercion.
func forwardDefaults(t Tunnel) (forwardProto, engine, preset string) {
	forwardProto = string(t.ForwardProtocol)
	if forwardProto == "" {
		forwardProto = string(ForwardProtocolUDP)
	}
	engine = string(t.TCPReliabilityEngine)
	if engine == "" {
		engine = string(TCPEngineKCP)
	}
	preset = t.ForwardEnginePreset
	if preset == "" {
		preset = string(PresetBalanced)
	}
	return forwardProto, engine, preset
}

// isUniqueConstraint reports whether err is a SQLite UNIQUE
// constraint failure on the given column. modernc.org/sqlite surfaces
// these as `&sqlite.Error` whose Error() string matches
// "UNIQUE constraint failed: tunnels.name". We pattern-match on the
// substring to stay driver-agnostic.
func isUniqueConstraint(err error, qualifiedColumn string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, qualifiedColumn)
}
