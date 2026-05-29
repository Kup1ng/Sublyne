import { buildWsUrl, useApi } from '~/composables/useApi'
import type { LogEntry, MetricsSnapshot, TunnelRate } from '~/types/api'

export interface MetricsHistory {
  ts: string[]
  bps_up: number[]
  bps_down: number[]
  cpu_percent: number[]
}

interface WsFrame {
  type: 'snapshot' | 'log' | string
  body: unknown
}

// useMetrics opens (lazily) a single WebSocket panel-wide, shares it
// across all subscribers, and exposes:
//
//   - `snapshot`:  the most recent raw snapshot the server pushed (every
//                  ~5 s in production).
//   - `rates`:     a Map<tunnel_id, TunnelRate> with per-tunnel bps
//                  derived from successive snapshot deltas. UI components
//                  bind here for the live "Mbps" numbers.
//   - `history`:   60-entry rolling buffer for the dashboard chart of
//                  total up/down bps + system CPU.
//   - `logs`:      ring buffer of live log frames; the Logs page tails
//                  this directly.
//
// The composable is a true singleton: only one WebSocket per page
// session, even when several pages call useMetrics().

const MAX_HISTORY = 60
const MAX_LOGS = 800

let socket: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

// Previous tunnel counter snapshot, used to compute bps deltas. Lives
// at module scope so it persists across navigations without
// re-instantiating per page.
let prevTunnelBytes = new Map<number, { in: number; out: number; at: number }>()

export function useMetrics() {
  const api = useApi()
  const snapshot = useState<MetricsSnapshot | null>('sublyne-snapshot', () => null)
  const rates = useState<Map<number, TunnelRate>>('sublyne-rates', () => new Map())
  const history = useState<MetricsHistory>('sublyne-history', () => ({
    ts: [],
    bps_up: [],
    bps_down: [],
    cpu_percent: [],
  }))
  const logs = useState<LogEntry[]>('sublyne-logs', () => [])
  const status = useState<'idle' | 'open' | 'closed' | 'error'>(
    'sublyne-ws-status',
    () => 'idle',
  )

  function pushHistory(totalUp: number, totalDown: number, cpu: number, atIso: string) {
    // Replace the whole ref value with a freshly-built object instead
    // of mutating the existing arrays in place. Mutation through
    // useState's reactive proxy triggered a write effect that
    // re-entered ingestSnapshot() and blew the call stack on every
    // WebSocket frame — see the "Maximum call stack size exceeded"
    // crash captured during the v0.1.1 panel audit.
    const prev = history.value
    history.value = {
      ts: [...prev.ts, atIso].slice(-MAX_HISTORY),
      bps_up: [...prev.bps_up, totalUp].slice(-MAX_HISTORY),
      bps_down: [...prev.bps_down, totalDown].slice(-MAX_HISTORY),
      cpu_percent: [...prev.cpu_percent, cpu].slice(-MAX_HISTORY),
    }
  }

  function ingestSnapshot(s: MetricsSnapshot) {
    const now = Date.now()
    const next = new Map<number, TunnelRate>()
    let totalUp = 0
    let totalDown = 0
    for (const t of s.tunnels ?? []) {
      const prev = prevTunnelBytes.get(t.id)
      let bps_up = 0
      let bps_down = 0
      if (prev) {
        const dtSec = Math.max(0.001, (now - prev.at) / 1000)
        const dOut = Math.max(0, t.bytes_out - prev.out)
        const dIn = Math.max(0, t.bytes_in - prev.in)
        // "Up" for the operator is end-user→remote = bytes_out on the
        // tunnel's egress; "Down" is the spoofed reply = bytes_in.
        // Multiply bytes by 8 for bps.
        bps_up = (dOut * 8) / dtSec
        bps_down = (dIn * 8) / dtSec
      }
      prevTunnelBytes.set(t.id, { in: t.bytes_in, out: t.bytes_out, at: now })
      next.set(t.id, {
        bps_up,
        bps_down,
        sessions: t.active_sessions,
        status: t.health_badge,
      })
      totalUp += bps_up
      totalDown += bps_down
    }
    // Drop tunnels that disappeared from the snapshot so a deleted
    // tunnel's last rate doesn't linger.
    for (const id of Array.from(prevTunnelBytes.keys())) {
      if (!s.tunnels?.find((t) => t.id === id)) prevTunnelBytes.delete(id)
    }
    rates.value = next
    pushHistory(totalUp, totalDown, s.system?.cpu_percent ?? 0, s.at)
  }

  function onMessage(raw: string) {
    let msg: WsFrame
    try {
      msg = JSON.parse(raw) as WsFrame
    } catch {
      return
    }
    if (msg.type === 'snapshot') {
      const s = msg.body as MetricsSnapshot
      snapshot.value = s
      ingestSnapshot(s)
    } else if (msg.type === 'log') {
      const e = msg.body as LogEntry
      // Same out-of-place pattern as pushHistory: replace the array
      // instead of mutating it.
      const arr = logs.value
      const next = arr.length >= MAX_LOGS ? arr.slice(arr.length - MAX_LOGS + 1) : arr.slice()
      next.push(e)
      logs.value = next
    }
  }

  function connect() {
    if (typeof window === 'undefined') return
    if (socket && socket.readyState <= 1) return // OPEN or CONNECTING

    const url = buildWsUrl('/ws')
    socket = new WebSocket(url)
    status.value = 'idle'
    socket.onopen = () => {
      status.value = 'open'
    }
    socket.onmessage = (ev) => onMessage(ev.data)
    socket.onerror = () => {
      status.value = 'error'
    }
    socket.onclose = () => {
      status.value = 'closed'
      socket = null
      if (reconnectTimer) clearTimeout(reconnectTimer)
      reconnectTimer = setTimeout(connect, 1500)
    }
  }

  function disconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (socket) {
      socket.onclose = null
      socket.close()
      socket = null
    }
    status.value = 'closed'
  }

  /** One-shot pull of the most recent snapshot (no WebSocket needed). */
  async function fetchLatest() {
    try {
      const s = await api.get<MetricsSnapshot>('/metrics/latest')
      snapshot.value = s
      ingestSnapshot(s)
      return s
    } catch {
      return null
    }
  }

  return { snapshot, rates, history, logs, status, connect, disconnect, fetchLatest }
}
