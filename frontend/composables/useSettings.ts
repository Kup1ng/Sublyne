import { useApi } from '~/composables/useApi'
import type { SettingsView } from '~/types/api'

export function useSettings() {
  const api = useApi()
  const view = useState<SettingsView | null>('sublyne-settings', () => null)

  async function refresh() {
    view.value = await api.get<SettingsView>('/settings')
    return view.value
  }

  async function setLogLevel(level: string) {
    // Real path is PUT /api/settings/log-level. The handler accepts
    // any case; we store whatever the server echoes back so the
    // dropdown stays in sync with the truth on the box.
    const res = await api.put<{ level: string }>('/settings/log-level', { level })
    if (view.value) view.value = { ...view.value, log_level: res.level }
  }

  return { view, refresh, setLogLevel }
}
