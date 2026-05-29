// Typed fetch client for the Sublyne control-plane REST API.
//
// In production the Go server serves the SPA at the obfuscated
// `/<web_path>/` prefix and the API at `/<web_path>/api/`. The SPA
// itself is path-agnostic — it learns its own prefix from a
// `<meta name="sublyne-web-path">` tag the Go server injects into
// `index.html` at serve time. Every fetch call goes out as
// `/<web_path>/api/...` so the panel never speaks to a route outside
// the prefix.
//
// In dev (`pnpm dev`) the SPA runs on Nuxt's dev server and the meta
// tag is absent. `webPathPrefix()` falls back to an empty string and
// the Vite proxy (see nuxt.config.ts) rewrites `/api/*` to the local
// Go panel.

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
    public fields: Record<string, string> = {},
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

interface ApiClient {
  get: <T>(path: string) => Promise<T>
  post: <T>(path: string, body?: unknown) => Promise<T>
  put: <T>(path: string, body: unknown) => Promise<T>
  del: <T>(path: string) => Promise<T>
}

/** Reads the runtime web-path prefix injected by the Go server. */
export function webPathPrefix(): string {
  if (typeof document === 'undefined') return ''
  const meta = document.querySelector('meta[name="sublyne-web-path"]')
  const raw = meta?.getAttribute('content') ?? ''
  // The placeholder ("__SUBLYNE_WEB_PATH__") is what an un-substituted
  // build still carries — treat it as "no prefix" so the dev proxy
  // path keeps working.
  if (raw.includes('__SUBLYNE_WEB_PATH__')) return ''
  return raw.replace(/\/$/, '')
}

/** Builds the full URL for an API call. Exported for tests. */
export function buildApiUrl(path: string): string {
  const p = path.startsWith('/') ? path : `/${path}`
  return `${webPathPrefix()}/api${p}`
}

/** WebSocket URL for the live metrics + log stream channel. */
export function buildWsUrl(path: string): string {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const prefix = webPathPrefix()
  const p = path.startsWith('/') ? path : `/${path}`
  return `${proto}//${window.location.host}${prefix}/api${p}`
}

/**
 * Low-level fetch helper that resolves the runtime web-path prefix
 * and carries the session cookie, but DOES NOT serialise the body or
 * assume a JSON response. Used by backup (binary stream) and restore
 * (multipart upload) endpoints. Returns the raw Response so the caller
 * can call `.blob()`, `.json()`, inspect headers, etc.
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(buildApiUrl(path), {
    credentials: 'include',
    ...init,
  })
}

interface ApiErrorBody {
  error?: string
  message?: string
  fields?: Record<string, string>
}

export function useApi(): ApiClient {
  async function call<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(buildApiUrl(path), {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      ...init,
    })

    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as ApiErrorBody
      const msg = body.error ?? body.message ?? res.statusText
      const code = res.status === 401 ? 'unauthorized' : 'http_error'
      throw new ApiError(code, msg, res.status, body.fields ?? {})
    }
    if (res.status === 204) return undefined as T
    return (await res.json()) as T
  }

  return {
    get: <T>(p: string) => call<T>(p),
    post: <T>(p: string, body?: unknown) =>
      call<T>(p, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
    put: <T>(p: string, body: unknown) =>
      call<T>(p, { method: 'PUT', body: JSON.stringify(body) }),
    del: <T>(p: string) => call<T>(p, { method: 'DELETE' }),
  }
}
