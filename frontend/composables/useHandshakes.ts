import { useApi } from '~/composables/useApi'
import type { HandshakeRow } from '~/types/api'

// useHandshakes drives the Dashboard's WireGuard card. The Go side
// keeps the handshake list out of the WebSocket snapshot (it would
// cost a netlink walk on every push) and exposes it at
// /api/metrics/wg-handshake. We poll it on an interval the panel
// can absorb without breaking the "CPU stays flat with dashboard
// open" PRD invariant.

const POLL_MS = 15_000

let pollTimer: ReturnType<typeof setInterval> | null = null

export function useHandshakes() {
  const api = useApi()
  const rows = useState<HandshakeRow[]>('sublyne-handshakes', () => [])

  async function refresh() {
    try {
      const res = await api.get<{ configs: HandshakeRow[] }>('/metrics/wg-handshake')
      rows.value = res.configs ?? []
    } catch {
      // 404 on Remote-role panels (WG hidden) is expected; just leave
      // the list empty rather than spamming toast errors.
      rows.value = []
    }
  }

  function start() {
    if (typeof window === 'undefined') return
    if (pollTimer) return
    refresh()
    pollTimer = setInterval(refresh, POLL_MS)
  }

  function stop() {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  return { rows, refresh, start, stop }
}
