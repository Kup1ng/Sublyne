import { useApi, apiFetch, type ApiError } from '~/composables/useApi'
import type { Tunnel } from '~/types/api'
import { pickAllowed } from '~/utils/pick'
import { sanitizeTunnelFilename } from '~/utils/clientFile'

// TunnelUpdateResult is the PUT /tunnels/:id response: the saved Tunnel
// plus a small envelope. restart_required (+ message) is set when the
// change only takes effect after a Stop/Start of the running tunnel;
// dataplane_error is set when a live hot-reload was attempted and failed.
// Both are omitted (undefined) on a clean hot-applied save.
export type TunnelUpdateResult = Tunnel & {
  restart_required?: boolean
  restart_required_message?: string
  dataplane_error?: string
}

// TunnelExportEnvelope is the versioned wrapper the backend produces on export
// and accepts on import (see control-plane tunnelExportEnvelope). It is its OWN
// strict shape — NOT the tunnel-input whitelist — so every field is forwarded
// verbatim. `tunnel.psk` is null unless the file was exported with ?secrets=1;
// the operator supplies it at import time when missing. WG/SOCKS5 are
// referenced by name (wireguard_config_name / socks5_proxy_name), never by
// their secret bytes.
export interface TunnelExportEnvelope {
  type: string
  schema_version: number
  secrets_included: boolean
  tunnel: Record<string, unknown> & {
    name?: string
    psk?: string | null
  }
}

// Backend tunnelInput field set — id / role / state / created_at /
// updated_at / runtime_state etc. come back on GETs but are rejected
// on POST/PUT by DisallowUnknownFields().
const TUNNEL_INPUT_FIELDS = [
  'name',
  'enabled',
  'psk',
  'download_spoof_source_ip',
  'download_spoof_source_port',
  'download_transport',
  'mtu',
  'max_connections',
  'idle_timeout',
  'icmp_echo_mode',
  'ports',
  // TCP forwarding (v4.0.0), shared by both roles.
  'forward_protocol',
  'tcp_reliability_engine',
  'forward_engine_preset',
  'forward_engine_tuning',
  // client-side optional
  'local_listen_addr',
  'download_receive_port',
  'upload_target_addr',
  'wg_config_id',
  'upload_mode',
  'socks5_proxy_id',
  'ping_smoothing_enabled',
  'ping_smoothing_target_ms',
  'pacing_enabled',
  'pacing_target_ms',
  // remote-side optional
  'upload_listen_addr',
  'forward_target',
  'download_send_port',
  'client_real_ip',
  'upload_listen_mode',
] as const

export function useTunnels() {
  const api = useApi()
  const list = useState<Tunnel[]>('sublyne-tunnels', () => [])
  const loading = useState<boolean>('sublyne-tunnels-loading', () => false)

  async function refresh() {
    loading.value = true
    try {
      const res = await api.get<{ tunnels: Tunnel[] }>('/tunnels')
      list.value = res.tunnels ?? []
    } finally {
      loading.value = false
    }
    return list.value
  }

  async function get(id: number) {
    return api.get<Tunnel>(`/tunnels/${id}`)
  }

  async function create(input: Partial<Tunnel>) {
    const t = await api.post<Tunnel>('/tunnels', pickAllowed(input, TUNNEL_INPUT_FIELDS))
    await refresh()
    return t
  }

  async function update(id: number, input: Partial<Tunnel>) {
    // PSK comes back redacted on GET; without this guard a "rename
    // only" save would echo "***" back as the literal new PSK and
    // brick the paired tunnel.
    const body = pickAllowed(input, TUNNEL_INPUT_FIELDS) as Partial<Tunnel>
    if (body.psk === '***') delete body.psk
    // Keep the restart_required / dataplane_error envelope so the edit
    // page can tell the operator when a change needs a Stop/Start or a
    // hot-reload failed, instead of always reporting a bare "Saved".
    const t = await api.put<TunnelUpdateResult>(`/tunnels/${id}`, body)
    await refresh()
    return t
  }

  async function remove(id: number) {
    await api.del(`/tunnels/${id}`)
    list.value = list.value.filter((t) => t.id !== id)
  }

  async function start(id: number) {
    await api.post(`/tunnels/${id}/start`)
    await refresh()
  }

  async function stop(id: number) {
    await api.post(`/tunnels/${id}/stop`)
    await refresh()
  }

  // exportOne fetches a tunnel's portable envelope and returns the raw text
  // (for clipboard/download), the parsed envelope, and a derived download
  // filename. Side-effect-free: the caller decides download vs copy. Pass
  // { secrets: true } to include the PSK (?secrets=1). Uses the shared
  // apiFetch so the obfuscated web-path prefix + session cookie are handled.
  async function exportOne(
    id: number,
    opts?: { secrets?: boolean },
  ): Promise<{ filename: string; text: string; envelope: TunnelExportEnvelope }> {
    const query = opts?.secrets ? '?secrets=1' : ''
    const res = await apiFetch(`/tunnels/${id}/export${query}`, { method: 'GET' })
    if (!res.ok) {
      const err = new Error(`export failed: ${res.status}`) as ApiError
      err.code = 'export_failed'
      err.status = res.status
      throw err
    }
    const text = await res.text()
    const envelope = JSON.parse(text) as TunnelExportEnvelope
    const name = envelope?.tunnel?.name ?? ''
    return { filename: sanitizeTunnelFilename(name), text, envelope }
  }

  // importOne parses an export envelope (raw text), applies optional operator
  // overrides (name on clash, psk when the file carries no secret), and POSTs
  // the WHOLE envelope. The backend envelope is its own strict shape, so we do
  // NOT run pickAllowed here. ApiError (with .fields) propagates to the caller.
  async function importOne(
    envelopeText: string,
    overrides?: { name?: string; psk?: string },
  ): Promise<Tunnel> {
    let obj: unknown
    try {
      obj = JSON.parse(envelopeText)
    } catch {
      throw new Error('That doesn’t look like a valid Sublyne export file (not JSON).')
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      throw new Error('That doesn’t look like a valid Sublyne export file.')
    }
    const env = obj as TunnelExportEnvelope
    if (!env.tunnel || typeof env.tunnel !== 'object') {
      throw new Error('That export file is missing its tunnel section.')
    }
    if (overrides?.name) {
      env.tunnel.name = overrides.name
    }
    if (overrides?.psk && overrides.psk.length > 0) {
      env.tunnel.psk = overrides.psk
    }
    const t = await api.post<Tunnel>('/tunnels/import', env)
    await refresh()
    return t
  }

  // clone duplicates a tunnel server-side (new name "<orig> (copy)", disabled,
  // all config + links + ports copied) and refreshes the list.
  async function clone(id: number): Promise<Tunnel> {
    const t = await api.post<Tunnel>(`/tunnels/${id}/clone`)
    await refresh()
    return t
  }

  return {
    list,
    loading,
    refresh,
    get,
    create,
    update,
    remove,
    start,
    stop,
    exportOne,
    importOne,
    clone,
  }
}
