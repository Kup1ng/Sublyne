import { useApi } from '~/composables/useApi'
import type { Tunnel } from '~/types/api'
import { pickAllowed } from '~/utils/pick'

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
    const t = await api.put<Tunnel>(`/tunnels/${id}`, body)
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

  async function exportOne(id: number): Promise<string> {
    const blob = await fetch(`${webPathPrefix()}/api/tunnels/${id}/export`, {
      credentials: 'include',
    }).then((r) => r.text())
    return blob
  }

  async function importOne(payload: string) {
    const t = await api.post<Tunnel>('/tunnels/import', JSON.parse(payload))
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
  }
}
