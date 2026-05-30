import { useApi } from '~/composables/useApi'
import type { TunablesUpdate, TunablesView } from '~/types/api'

// Performance tunables — the same fetch+save shape as useSettings, but
// kept in its own composable because the Performance card has its own
// draft/validation lifecycle on the Settings page.
export function useTunables() {
  const api = useApi()
  const view = useState<TunablesView | null>('sublyne-tunables', () => null)

  async function refresh() {
    view.value = await api.get<TunablesView>('/settings/tunables')
    return view.value
  }

  // PUT only the changed fields. A value of `null` clears the override
  // (revert to default); an omitted key is left untouched. The server
  // echoes back the full TunablesView so the card re-seeds from truth.
  async function save(changes: TunablesUpdate) {
    view.value = await api.put<TunablesView>('/settings/tunables', changes)
    return view.value
  }

  return { view, refresh, save }
}
