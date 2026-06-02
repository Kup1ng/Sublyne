// Wire types — mirror the JSON shapes the Go control plane emits. The
// names match the field names in the API responses, not the Go struct
// names, so a quick `curl … | jq` lines up with what TypeScript sees.

export type ServerRole = 'client' | 'remote'

export interface SessionView {
  username: string
  // Backend returns server_role (matching the SettingsView shape) —
  // useAuth.role exposes the same value as a computed for code that
  // wants to read it as `role`.
  server_role: ServerRole
}

export interface SettingsView {
  server_role: ServerRole
  panel_port: number
  web_path: string
  log_level: string
  version: string
}

// A single performance tunable as the Go control plane reports it on
// GET /settings/tunables. `value` is the operator's override, or null
// when nothing is set (the dataplane falls back to `default` — and for
// per_core_sockets a null default means "auto: one worker per CPU
// core"). The bounds are inclusive; the panel validates against them
// before save and the Go validator re-checks on PUT.
export interface Tunable {
  key: string
  // The matching environment variable, surfaced for operators who
  // prefer to set it via systemd. Not present on every tunable.
  env?: string
  value: number | null
  default: number | null
  min: number
  max: number
  unit: string
  label: string
  help: string
}

// GET /settings/tunables response. `applies_on_restart` is always true
// today (these knobs are read once at dataplane start) — the panel uses
// it to render the "changes apply on next restart" notice.
export interface TunablesView {
  applies_on_restart: boolean
  tunables: Tunable[]
}

// PUT /settings/tunables body: a number sets an override, null clears it
// back to the default, an omitted key is left unchanged.
export type TunablesUpdate = Record<string, number | null>

export type DownloadTransport = 'udp' | 'tcp_syn' | 'icmp' | 'icmpv6'
export type IcmpEchoMode = 'reply' | 'request'
export type UploadMode = 'wireguard' | 'socks5'
export type UploadListenMode = 'udp' | 'socks5_tcp'
// v4.0.0 TCP forwarding. forward_protocol 'udp' (default) is the historical
// UDP relay; 'tcp' carries the user's TCP stream reliably over the spoof
// channel using a reliability engine.
export type ForwardProtocol = 'udp' | 'tcp'
export type TcpReliabilityEngine = 'kcp' | 'quic'
export type ForwardEnginePreset = 'interactive' | 'balanced' | 'lossy'

export interface Tunnel {
  id: number
  name: string
  enabled: boolean
  role: ServerRole

  // Client side
  local_listen_addr?: string
  download_receive_port?: number
  download_spoof_source_ip?: string
  download_spoof_source_port?: number
  download_transport?: DownloadTransport
  icmp_echo_mode?: IcmpEchoMode
  upload_target_addr?: string
  upload_mode?: UploadMode
  wg_config_id?: number | null
  socks5_proxy_id?: number | null
  ping_smoothing_enabled?: boolean
  ping_smoothing_target_ms?: number
  pacing_enabled?: boolean
  pacing_target_ms?: number

  // Remote side
  upload_listen_addr?: string
  upload_listen_mode?: UploadListenMode
  forward_target?: string
  download_send_port?: number
  client_real_ip?: string

  // Shared
  psk?: string
  mtu?: number
  max_connections?: number
  idle_timeout?: number
  // TCP forwarding (v4.0.0), shared by both roles. forward_protocol 'udp'
  // (default) leaves the other three inert. forward_engine_tuning is an
  // optional JSON blob of Advanced overrides ('' = pure preset).
  forward_protocol?: ForwardProtocol
  tcp_reliability_engine?: TcpReliabilityEngine
  forward_engine_preset?: ForwardEnginePreset
  forward_engine_tuning?: string
  // Multi-port: the full authoritative list of application ports this
  // tunnel carries (INCLUDING the main port from local_listen_addr /
  // forward_target), with a fixed 1:1 same-number mapping on both sides.
  // Absent or [] = single-port (wire-identical to legacy tunnels). The
  // panel never produces a 1-element list (1 port = single-port). Sent on
  // create/update and returned on read.
  ports?: number[]

  // Bookkeeping
  state?: TunnelState
  created_at?: string
  updated_at?: string
}

export type TunnelState = 'stopped' | 'starting' | 'running' | 'stopping' | 'error'

export interface WireguardConfig {
  id: number
  name: string
  raw_text?: string
  // Field names mirror the Go wgConfigDTO exactly (wg_handlers.go):
  // interface_address / public_key_self / peer_count, NOT the older
  // address / public_key / reference_count the panel used to assume.
  interface_address?: string
  endpoint?: string
  public_key_self?: string
  mtu?: number | null
  listen_port?: number | null
  peer_count?: number
  created_at?: string
  updated_at?: string
}

export interface Socks5Proxy {
  id: number
  name: string
  host: string
  port: number
  username?: string | null
  password?: string | null
  parallel_connections: number
  notes?: string
  reference_count?: number
  min_ready_slots?: number
  created_at?: string
  updated_at?: string
}

export interface AuditEntry {
  id: number
  // Timestamps come back as RFC 3339 strings from the audit_log
  // table.
  ts: string
  // The signed-in admin who performed the action.
  actor: string
  // Optional target (e.g. the tunnel name a start/stop acted on).
  target?: string
  ip: string
  action: string
  // Structured payload the handler attached. Sometimes empty, often
  // a flat string→value map — render via JSON.stringify in the panel.
  details?: Record<string, unknown>
}

export interface LogEntry {
  ts: string
  level: 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
  target?: string
  msg: string
  fields?: Record<string, string | number | boolean>
}

// MetricsSnapshot mirrors the LiveSnapshot the Go control plane writes
// into every /api/ws "snapshot" frame and serves on /api/metrics/latest.
export interface MetricsSnapshot {
  at: string
  system: SystemStats
  tunnels: LiveTunnel[]
}

export interface SystemStats {
  cpu_percent: number
  mem_used_bytes: number
  mem_total_bytes: number
  disk_used_bytes: number
  disk_total_bytes: number
  // Resident memory of the sublyne process itself (RSS), in bytes. The
  // dashboard RAM tile reads this. `omitempty` on the Go side means a 0
  // value is absent from the JSON, so it is optional and defaults to 0.
  proc_rss_bytes?: number
  net_interfaces?: Record<string, NetInterfaceStats>
  memory_pressure?: boolean
}

export interface NetInterfaceStats {
  rx_bytes: number
  tx_bytes: number
}

// LiveTunnel is the per-tunnel block inside a snapshot. Byte and
// packet counters are CUMULATIVE — useMetrics derives bps deltas
// between successive frames.
export interface LiveTunnel {
  id: number
  name: string
  role: 'client' | 'remote'
  transport: string
  enabled: boolean
  runtime_state: string
  health_badge: 'healthy' | 'idle' | 'down' | 'stopped'
  bytes_in: number
  bytes_out: number
  packets_in: number
  packets_out: number
  active_sessions: number
  upload_rtt_ms_ewma: number
  download_rtt_ms_ewma: number
  packet_loss_estimate: number
  last_packet_received_at_unix: number
  last_packet_sent_at_unix: number
}

// TunnelRate is the per-tunnel derived block useMetrics maintains
// (rate-of-change snapshot). UI components bind to this for the
// "live throughput" numbers and bypass the raw counters.
export interface TunnelRate {
  bps_up: number
  bps_down: number
  sessions: number
  status: 'healthy' | 'idle' | 'down' | 'stopped'
  // The authoritative enabled flag from the live snapshot, so a tunnel
  // stopped in another tab reflects here without waiting for this tab to
  // refresh its REST list (or for health_badge to age to "stopped").
  enabled: boolean
}

export interface HandshakeRow {
  config_id: number
  config_name: string
  interface_name: string
  has_ever_connected: boolean
  stale: boolean
  last_handshake?: string
  last_handshake_age?: string
}
