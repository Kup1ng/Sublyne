import { useApi } from '~/composables/useApi'
import type { Socks5Proxy } from '~/types/api'
import { pickAllowed } from '~/utils/pick'

// Backend socks5ProxyInput accepts ONLY these.
const SOCKS5_INPUT_FIELDS = [
  'name',
  'host',
  'port',
  'username',
  'password',
  'parallel_connections',
  'min_ready_slots',
  'notes',
] as const

export function useSocks5() {
  const api = useApi()
  const list = useState<Socks5Proxy[]>('sublyne-socks5', () => [])
  const loading = useState<boolean>('sublyne-socks5-loading', () => false)

  async function refresh() {
    loading.value = true
    try {
      const res = await api.get<{ proxies: Socks5Proxy[] }>('/socks5-proxies')
      list.value = res.proxies ?? []
    } finally {
      loading.value = false
    }
    return list.value
  }

  async function get(id: number, reveal = false) {
    return api.get<Socks5Proxy>(`/socks5-proxies/${id}${reveal ? '?reveal=1' : ''}`)
  }

  async function create(input: Partial<Socks5Proxy>) {
    // POST /socks5-proxies responds with {proxy: {...}}.
    const res = await api.post<{ proxy: Socks5Proxy }>(
      '/socks5-proxies',
      pickAllowed(input, SOCKS5_INPUT_FIELDS),
    )
    await refresh()
    return res.proxy
  }

  async function update(id: number, input: Partial<Socks5Proxy>) {
    // Same "***" guard as WG: if the form was opened without the
    // explicit Reveal click, the password field shows "***" and we
    // must not echo it back as the literal new password.
    const body = pickAllowed(input, SOCKS5_INPUT_FIELDS) as Partial<Socks5Proxy>
    if (body.password === '***') delete body.password
    const res = await api.put<{ proxy: Socks5Proxy }>(`/socks5-proxies/${id}`, body)
    await refresh()
    return res.proxy
  }

  async function remove(id: number) {
    await api.del(`/socks5-proxies/${id}`)
    list.value = list.value.filter((p) => p.id !== id)
  }

  return { list, loading, refresh, get, create, update, remove }
}
