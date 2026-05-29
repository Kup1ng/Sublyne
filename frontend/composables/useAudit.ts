import { useApi } from '~/composables/useApi'
import type { AuditEntry } from '~/types/api'

export function useAudit() {
  const api = useApi()
  async function recent(limit = 200): Promise<AuditEntry[]> {
    const res = await api.get<{ entries: AuditEntry[] }>(`/audit?limit=${encodeURIComponent(limit)}`)
    return res.entries ?? []
  }
  return { recent }
}
