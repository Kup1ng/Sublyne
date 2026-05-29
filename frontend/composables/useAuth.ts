import { useApi, ApiError } from '~/composables/useApi'
import type { SessionView, ServerRole } from '~/types/api'

interface LoginResult {
  ok: boolean
  error?: string
  retry_after_seconds?: number
}

export function useAuth() {
  const api = useApi()
  const session = useState<SessionView | null>('sublyne-session', () => null)
  const ready = useState<boolean>('sublyne-session-ready', () => false)

  async function refresh(): Promise<SessionView | null> {
    try {
      const s = await api.get<SessionView>('/session')
      session.value = s
      return s
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        session.value = null
        return null
      }
      throw e
    } finally {
      ready.value = true
    }
  }

  async function login(username: string, password: string): Promise<LoginResult> {
    // The Go handler returns {token, expires_at}; the cookie is set
    // server-side via Set-Cookie, so we don't actually need anything
    // from the body. A 2xx means we're in — refresh fetches the role
    // and we're done.
    try {
      await api.post('/login', { username, password })
      const s = await refresh()
      return { ok: s !== null }
    } catch (e) {
      if (e instanceof ApiError) {
        return { ok: false, error: e.message }
      }
      throw e
    }
  }

  async function logout(): Promise<void> {
    try {
      await api.post('/logout')
    } catch {
      // Even if the server rejected, clear local state.
    }
    session.value = null
  }

  async function changePassword(current: string, next: string): Promise<{ ok: boolean; error?: string }> {
    try {
      await api.post('/password', { current_password: current, new_password: next })
      return { ok: true }
    } catch (e) {
      if (e instanceof ApiError) return { ok: false, error: e.message }
      throw e
    }
  }

  const isAuthed = computed(() => session.value !== null)
  const role = computed<ServerRole | null>(() => session.value?.server_role ?? null)

  return {
    session,
    ready,
    isAuthed,
    role,
    refresh,
    login,
    logout,
    changePassword,
  }
}
