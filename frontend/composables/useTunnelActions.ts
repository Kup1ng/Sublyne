import { useTunnels } from '~/composables/useTunnels'
import { useToast } from '~/composables/useToast'
import type { Tunnel } from '~/types/api'

// useTunnelActions is the single shared home for "start / stop a tunnel
// from the UI". Both the Tunnels page and the Dashboard tunnel tiles call
// it, so the API call, the success/failure toast, and the per-tunnel
// in-flight ("busy") state stay identical and in sync no matter where the
// operator clicks. The actual REST calls + auto-refresh live in
// useTunnels().start/stop — this layer only adds the human feedback and
// the transition guard.
//
// `busy` is a panel-wide useState map keyed by tunnel id, so a Start
// clicked on the Dashboard also disables that tunnel's button on the
// Tunnels page (and vice-versa) while the request is in flight.
export function useTunnelActions() {
  const tunnels = useTunnels()
  const toast = useToast()
  const busy = useState<Record<number, boolean>>('sublyne-tunnel-busy', () => ({}))

  function isBusy(id: number): boolean {
    return busy.value[id] === true
  }

  function setBusy(id: number, value: boolean) {
    // Replace the object rather than mutate so every reactive reader
    // (button :disabled / :loading) updates.
    busy.value = { ...busy.value, [id]: value }
  }

  async function start(id: number, name: string) {
    if (isBusy(id)) return
    setBusy(id, true)
    try {
      await tunnels.start(id)
      toast.success(`Started ${name}`)
    } catch (e) {
      toast.error('Failed to start', (e as Error).message)
    } finally {
      setBusy(id, false)
    }
  }

  async function stop(id: number, name: string) {
    if (isBusy(id)) return
    setBusy(id, true)
    try {
      await tunnels.stop(id)
      toast.success(`Stopped ${name}`)
    } catch (e) {
      toast.error('Failed to stop', (e as Error).message)
    } finally {
      setBusy(id, false)
    }
  }

  /** Start or stop based on the tunnel's current enabled state. */
  async function toggle(id: number, name: string, enabled: boolean) {
    return enabled ? stop(id, name) : start(id, name)
  }

  // clone duplicates a tunnel (server-side; lands stopped) and returns the new
  // tunnel, or null on failure. Reuses the same per-id busy guard + toast
  // pattern as start/stop so the card button shows a consistent busy state.
  async function clone(id: number): Promise<Tunnel | null> {
    if (isBusy(id)) return null
    setBusy(id, true)
    try {
      const created = await tunnels.clone(id)
      toast.success('Cloned', `Created “${created.name}” (stopped).`)
      return created
    } catch (e) {
      toast.error('Failed to clone', (e as Error).message)
      return null
    } finally {
      setBusy(id, false)
    }
  }

  return { start, stop, toggle, clone, isBusy }
}
