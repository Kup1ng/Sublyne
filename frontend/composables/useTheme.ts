// Two-mode theme (light / dark). Resolves the initial value from
// localStorage, or — if the user hasn't picked yet — from the system
// `prefers-color-scheme` media query. Sublyne defaults to **dark**
// for first-time users because the audience is technical and the
// brand reads better on midnight.

type Mode = 'light' | 'dark'

const STORAGE_KEY = 'sublyne.theme'

function readStored(): Mode | null {
  if (typeof localStorage === 'undefined') return null
  const v = localStorage.getItem(STORAGE_KEY)
  return v === 'light' || v === 'dark' ? v : null
}

function systemPref(): Mode {
  // Sublyne defaults to dark unconditionally — the brand is built for
  // it and the anti-censorship audience tends to live there. Users who
  // want light can toggle in the sidebar; we persist their choice to
  // localStorage and honour it on the next visit.
  return 'dark'
}

function apply(mode: Mode): void {
  if (typeof document === 'undefined') return
  const html = document.documentElement
  html.classList.toggle('dark', mode === 'dark')
  html.style.colorScheme = mode
}

export function useTheme() {
  // useState is Nuxt's SSR-safe shared state hook; we're an SPA, so
  // it just behaves as a module-singleton ref.
  const mode = useState<Mode>('sublyne-theme', () => readStored() ?? systemPref())

  function set(next: Mode) {
    mode.value = next
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, next)
    }
    apply(next)
  }

  function toggle() {
    set(mode.value === 'dark' ? 'light' : 'dark')
  }

  function mount() {
    // Apply the resolved mode on first paint. We do this in app.vue's
    // setup so it runs before any component renders — avoids the
    // "wrong theme flash" on first load.
    apply(mode.value)
  }

  return { mode, set, toggle, mount }
}
