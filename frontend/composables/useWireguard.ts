import { useApi } from '~/composables/useApi'
import type { WireguardConfig } from '~/types/api'
import { pickAllowed } from '~/utils/pick'

// Backend wgConfigInput accepts ONLY these — anything else is
// rejected by DisallowUnknownFields().
const WG_INPUT_FIELDS = ['name', 'raw_text'] as const

export function useWireguard() {
  const api = useApi()
  const list = useState<WireguardConfig[]>('sublyne-wg', () => [])
  const loading = useState<boolean>('sublyne-wg-loading', () => false)

  async function refresh() {
    loading.value = true
    try {
      const res = await api.get<{ configs: WireguardConfig[] }>('/wg-configs')
      list.value = res.configs ?? []
    } finally {
      loading.value = false
    }
    return list.value
  }

  async function get(id: number, reveal = false) {
    return api.get<WireguardConfig>(`/wg-configs/${id}${reveal ? '?reveal=1' : ''}`)
  }

  async function create(input: Partial<WireguardConfig> & { raw_text: string }) {
    // POST /wg-configs responds with {config: {...}, warnings: ...}.
    const res = await api.post<{ config: WireguardConfig }>(
      '/wg-configs',
      pickAllowed(input, WG_INPUT_FIELDS),
    )
    await refresh()
    return res.config
  }

  async function update(id: number, input: Partial<WireguardConfig>) {
    // PUT response is ALSO wrapped in {config, warnings}.
    // Strip the "***" redaction sentinel before sending — without
    // this a "rename only" save would re-write the literal three
    // asterisks back into raw_text and clobber the seller's real
    // config text.
    const body = pickAllowed(input, WG_INPUT_FIELDS) as Partial<WireguardConfig>
    if (body.raw_text === '***') delete body.raw_text
    const res = await api.put<{ config: WireguardConfig }>(`/wg-configs/${id}`, body)
    await refresh()
    return res.config
  }

  async function remove(id: number) {
    await api.del(`/wg-configs/${id}`)
    list.value = list.value.filter((c) => c.id !== id)
  }

  return { list, loading, refresh, get, create, update, remove }
}
