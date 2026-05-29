import { useApi, webPathPrefix } from '~/composables/useApi'
import type { LogEntry } from '~/types/api'

export interface CrashReport {
  // Backend shape (control-plane/internal/logging/crash.go):
  filename: string
  size_bytes: number
  modified_at: string
  preview?: string
}

export function useLogs() {
  const api = useApi()

  async function recent(limit = 200): Promise<LogEntry[]> {
    // Backend response shape is { level: string, entries: LogEntry[] }.
    // The Logs page only consumes the entries; the runtime level is
    // already surfaced via /api/settings.
    const res = await api.get<{ level: string; entries: LogEntry[] }>(
      `/logs?limit=${encodeURIComponent(limit)}`,
    )
    return res.entries ?? []
  }

  async function crashes(): Promise<CrashReport[]> {
    const res = await api.get<{ reports: CrashReport[] }>('/crash-reports')
    return res.reports ?? []
  }

  async function crashBody(name: string): Promise<string> {
    const r = await fetch(`${webPathPrefix()}/api/crash-reports/${encodeURIComponent(name)}`, {
      credentials: 'include',
    })
    return r.text()
  }

  return { recent, crashes, crashBody }
}
