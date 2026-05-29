---
name: web-panel-components
description: UI patterns for the Nuxt 3 + shadcn-vue + Tailwind admin panel — purple theme tokens, layout structure, form components with inline tooltips, dark/light mode, responsive rules, the WebSocket composable, and chart conventions.
when_to_use: Read this in Phase 4 (frontend skeleton), Phase 5 (settings page rendering), Phase 6 (tunnel CRUD UI), and any later phase that adds or changes a panel page or component. Anchor for "what does our purple theme look like" and "how do we render a form field with inline help".
---

## Project shape

```
frontend/
├── nuxt.config.ts
├── tailwind.config.ts
├── tsconfig.json
├── package.json
├── app.vue                    # root, mounts layout + <Toaster />
├── components/
│   ├── ui/                    # shadcn-vue copies (Button, Input, …)
│   ├── form/                  # our domain form helpers (LabeledField, TooltipHint)
│   ├── tunnel/                # tunnel-specific (TunnelStatusBadge, …)
│   └── chart/                 # Chart.js wrappers
├── composables/
│   ├── useApi.ts              # typed fetch client to control-plane REST
│   ├── useAuth.ts             # session state, login/logout
│   ├── useWebSocket.ts        # auto-reconnecting WS subscriber
│   └── useTheme.ts            # light/dark toggle, persists to localStorage
├── layouts/
│   ├── default.vue            # logged-in layout (nav + sidebar + main)
│   └── auth.vue               # logged-out (centered card on a neutral bg)
├── pages/
│   ├── index.vue              # redirect to /dashboard or /login
│   ├── login.vue
│   ├── dashboard.vue
│   ├── tunnels/
│   │   ├── index.vue          # list
│   │   ├── new.vue
│   │   └── [id].vue           # edit
│   ├── wireguard/
│   │   ├── index.vue
│   │   ├── new.vue
│   │   └── [id].vue
│   ├── settings.vue
│   ├── logs.vue
│   └── audit.vue
├── assets/
│   └── css/main.css
└── server/                    # empty — Nuxt SPA mode has no server runtime
```

## Nuxt config (`nuxt.config.ts`)

```ts
export default defineNuxtConfig({
  ssr: false,                         // SPA mode — no Node server in prod
  modules: ['@nuxtjs/tailwindcss', 'shadcn-nuxt', '@vueuse/nuxt'],
  shadcn: { prefix: '', componentDir: './components/ui' },
  css: ['~/assets/css/main.css'],
  app: {
    // PRODUCTION baseURL is the runtime placeholder; the Go server
    // substitutes it for the real /<web_path>/ when serving any
    // text/html, JS, or CSS file from the embedded dist. DEV builds
    // (`pnpm dev`) leave NUXT_APP_BASE_URL unset and the SPA runs at
    // '/' with Vite's proxy rewriting `/api/*` to the dev panel
    // prefix. See "Path obfuscation and the runtime baseURL" below
    // for the full flow.
    baseURL: process.env.NUXT_APP_BASE_URL || '/',
    head: {
      title: 'sublyne',
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
    },
  },
  vite: {
    server: {
      proxy: {
        // Dev only — proxy /api to the local Go server, rewriting
        // under the dev web_path so the proxy hits the prefixed
        // route the Phase 5 router mounts.
        '/api': {
          target: 'http://127.0.0.1:18080',
          rewrite: (p) => `/${process.env.NUXT_DEV_WEB_PATH || 'panel'}${p}`,
        },
        '/ws':  {
          target: 'ws://127.0.0.1:18080',
          ws: true,
          rewrite: (p) => `/${process.env.NUXT_DEV_WEB_PATH || 'panel'}${p}`,
        },
      },
    },
  },
  typescript: { strict: true, typeCheck: false },  // typecheck runs in CI via vue-tsc
})
```

## Path obfuscation and the runtime baseURL

The panel is served at `/<web_path>/` (a 16-char random prefix chosen
by `setup.sh` at install time). The runtime web path can't be known
when `pnpm build` runs — but Nuxt bakes `app.baseURL` into both the
asset references in `index.html` AND the `window.__NUXT__.config`
block the JS bundle reads to find `app.baseURL` on boot. Get this
wrong and the bundle crashes with
`Cannot read properties of undefined (reading 'baseURL')` before any
component renders.

The flow is a single placeholder threaded through three stages:

1. **Build (`pnpm build`)** —
   `scripts/build.sh` sets `NUXT_APP_BASE_URL=/__SUBLYNE_WEB_PATH__/`
   before `nuxt build`. Every `app.baseURL`-derived value Nuxt emits
   carries this exact string: asset URLs in the manifest, the runtime
   config script in the rendered HTML, and the entry chunk's lazy
   imports.

2. **Capture (`frontend/scripts/build-spa-index.mjs`)** — `nuxt build`
   with `ssr: false` writes `"Redirecting..."` stubs in place of
   real prerendered HTML. The script spins the produced Nitro server
   up on a free localhost port, fetches the SPA shell at
   `/__SUBLYNE_WEB_PATH__/login`, and saves the response as
   `.output/public/index.html`. The captured shell contains the
   `<script>window.__NUXT__={};window.__NUXT__.config={…
   app:{baseURL:"/__SUBLYNE_WEB_PATH__/",…}}</script>` block, the
   `<script id="__NUXT_DATA__">` payload, and the entry-chunk script
   tag — everything the bundle needs to boot.

3. **Serve (`control-plane/internal/webassets/spa.go`)** — The Go
   handler reads `/etc/sublyne/config.toml`'s `web_path`, replaces
   every occurrence of `/__SUBLYNE_WEB_PATH__/` in served HTML, JS,
   CSS, and JSON with `/<web_path>/`, and injects a
   `<meta name="sublyne-web-path">` tag (so `useApi.ts` can prefix
   its fetch calls) and an empty-data-URL favicon link (so the
   browser doesn't auto-request `/favicon.ico` outside the prefix and
   trip the obfuscation 404).

**When adding new globals or scripts that need to know the runtime
prefix:** route them through the meta tag (the canonical runtime
signal). Don't add new placeholders unless absolutely necessary; the
single-placeholder design keeps the substitution surface area tiny
and reviewable.

**Test guardrails** —
`control-plane/internal/webassets/spa_test.go::TestSPAHandler_PreservesRuntimeConfigBlock`
locks down the substitution end of the contract.
`frontend/scripts/build-spa-index.mjs` aborts if the captured shell
is missing `window.__NUXT__`, the `__NUXT_DATA__` block, or the
expected baseURL. Don't disable either guardrail.

## Purple theme tokens (`tailwind.config.ts`)

Built on shadcn-vue's HSL-token system. The primary is purple at
`hsl(262, 83%, 58%)` (per PRD §4.5). Dark mode shifts brightness, not
hue.

```ts
import type { Config } from 'tailwindcss'

export default {
  darkMode: 'class',
  content: ['./components/**/*.{vue,ts}', './pages/**/*.vue', './layouts/**/*.vue', './app.vue'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
} satisfies Config
```

CSS variables in `assets/css/main.css`:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 240 10% 3.9%;
    --card: 0 0% 100%;
    --card-foreground: 240 10% 3.9%;
    --primary: 262 83% 58%;          /* purple */
    --primary-foreground: 0 0% 100%;
    --secondary: 240 4.8% 95.9%;
    --secondary-foreground: 240 5.9% 10%;
    --muted: 240 4.8% 95.9%;
    --muted-foreground: 240 3.8% 46.1%;
    --accent: 262 80% 96%;           /* very light purple tint */
    --accent-foreground: 262 83% 30%;
    --destructive: 0 84% 60%;
    --destructive-foreground: 0 0% 100%;
    --border: 240 5.9% 90%;
    --input: 240 5.9% 90%;
    --ring: 262 83% 58%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 240 10% 3.9%;
    --foreground: 0 0% 98%;
    --card: 240 10% 5.9%;
    --card-foreground: 0 0% 98%;
    --primary: 262 83% 68%;          /* slightly brighter purple in dark mode */
    --primary-foreground: 240 10% 3.9%;
    --secondary: 240 3.7% 15.9%;
    --secondary-foreground: 0 0% 98%;
    --muted: 240 3.7% 15.9%;
    --muted-foreground: 240 5% 64.9%;
    --accent: 262 30% 18%;
    --accent-foreground: 0 0% 98%;
    --destructive: 0 62.8% 50%;
    --destructive-foreground: 0 0% 98%;
    --border: 240 3.7% 15.9%;
    --input: 240 3.7% 15.9%;
    --ring: 262 83% 68%;
  }
}
```

## Layout (`layouts/default.vue`)

```
+------------------------------------------------------+
| Top bar: brand (left) + theme toggle + user (right) |
+--------+---------------------------------------------+
| Side   |                                             |
| nav    |  <slot />  (page content, max-w-7xl mx-auto)|
|        |                                             |
| Dash   |                                             |
| Tunnel |                                             |
| WG     |                                             |
| Logs   |                                             |
| Audit  |                                             |
| Set..  |                                             |
+--------+---------------------------------------------+
```

- Sidebar collapses to a Sheet (drawer) under `md`.
- Top bar is sticky.
- Main content uses `<div class="mx-auto max-w-7xl px-4 py-6">`.
- `<Toaster />` mounted once at the layout root.

## Form pattern: every field has inline help

PRD §4.5 mandates inline help/tooltips on every config field. Shape:

```vue
<!-- components/form/LabeledField.vue -->
<template>
  <div class="space-y-1.5">
    <div class="flex items-center gap-1.5">
      <Label :for="id">{{ label }}</Label>
      <Tooltip>
        <TooltipTrigger as="button" type="button" tabindex="-1">
          <Icon name="lucide:help-circle" class="h-3.5 w-3.5 text-muted-foreground" />
        </TooltipTrigger>
        <TooltipContent class="max-w-xs">
          <p>{{ help }}</p>
          <p v-if="example" class="mt-1 font-mono text-xs text-muted-foreground">
            e.g. {{ example }}
          </p>
        </TooltipContent>
      </Tooltip>
    </div>
    <slot :id="id" />
    <p v-if="error" class="text-xs text-destructive">{{ error }}</p>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  label: string
  help: string
  example?: string
  error?: string
  id: string
}>()
</script>
```

Usage:

```vue
<LabeledField
  id="local-listen"
  label="Local listen address"
  help="Where the end-user device connects. UDP only. Use 0.0.0.0 to listen on all interfaces."
  example="0.0.0.0:443"
  :error="errors.localListenAddr"
>
  <Input v-model="form.localListenAddr" placeholder="0.0.0.0:443" />
</LabeledField>
```

**Rule:** if you're adding a new field anywhere in the panel, write the
`help` and `example` props at the same time. Don't ship a tooltip-less
field.

## Tunnel status badge

```vue
<!-- components/tunnel/TunnelStatusBadge.vue -->
<template>
  <Badge :variant="variant">
    <span
      class="mr-1.5 h-1.5 w-1.5 rounded-full"
      :class="dotClass"
    />
    {{ label }}
  </Badge>
</template>

<script setup lang="ts">
const props = defineProps<{ status: 'healthy' | 'idle' | 'down' | 'stopped' }>()

const map = {
  healthy: { label: 'Healthy', variant: 'default' as const, dotClass: 'bg-emerald-500' },
  idle:    { label: 'Idle',    variant: 'secondary' as const, dotClass: 'bg-amber-500' },
  down:    { label: 'Down',    variant: 'destructive' as const, dotClass: 'bg-red-500' },
  stopped: { label: 'Stopped', variant: 'outline' as const, dotClass: 'bg-muted-foreground' },
}
const { label, variant, dotClass } = computed(() => map[props.status]).value
</script>
```

## Theme toggle (`composables/useTheme.ts`)

```ts
type Theme = 'light' | 'dark' | 'system'

export function useTheme() {
  const theme = useState<Theme>('theme', () => 'system')

  function apply(t: Theme) {
    const root = document.documentElement
    const effective = t === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : t
    root.classList.toggle('dark', effective === 'dark')
  }

  function set(t: Theme) {
    theme.value = t
    localStorage.setItem('theme', t)
    apply(t)
  }

  function init() {
    const saved = (localStorage.getItem('theme') as Theme | null) ?? 'system'
    theme.value = saved
    apply(saved)
    if (saved === 'system') {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => apply('system'))
    }
  }

  return { theme, set, init }
}
```

Call `useTheme().init()` once from `app.vue` `onMounted`.

## WebSocket composable (`composables/useWebSocket.ts`)

```ts
type WsState = 'connecting' | 'open' | 'closed'

export function useWebSocket<T = unknown>(path: string) {
  const messages = ref<T | null>(null)
  const state = ref<WsState>('connecting')
  let ws: WebSocket | null = null
  let retry = 0
  let timer: ReturnType<typeof setTimeout> | null = null

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${proto}//${location.host}${path}`)
    ws.onopen = () => { state.value = 'open'; retry = 0 }
    ws.onmessage = (ev) => {
      try { messages.value = JSON.parse(ev.data) as T } catch { /* ignore garbage */ }
    }
    ws.onclose = () => {
      state.value = 'closed'
      ws = null
      timer = setTimeout(connect, Math.min(1000 * (2 ** retry++), 30000))
    }
    ws.onerror = () => { ws?.close() }
  }

  onMounted(connect)
  onBeforeUnmount(() => {
    if (timer) clearTimeout(timer)
    ws?.close()
  })

  return { messages, state }
}
```

Cookie-based auth (HttpOnly JWT) carries through automatically on the
WS upgrade. No need to ferry the token in a query string.

## Charts (Chart.js)

Wrapper component pattern:

```vue
<!-- components/chart/LineChart.vue -->
<template>
  <canvas ref="canvas" />
</template>

<script setup lang="ts">
import { Chart, registerables } from 'chart.js'
Chart.register(...registerables)

const props = defineProps<{
  labels: string[]
  datasets: { label: string; data: number[]; color: string }[]
  height?: number
}>()

const canvas = ref<HTMLCanvasElement | null>(null)
let chart: Chart | null = null

watchEffect(() => {
  if (!canvas.value) return
  const data = {
    labels: props.labels,
    datasets: props.datasets.map(d => ({
      label: d.label,
      data: d.data,
      borderColor: d.color,
      backgroundColor: d.color + '33',
      tension: 0.2,
      pointRadius: 0,
    })),
  }
  if (chart) {
    chart.data = data
    chart.update('none')          // 'none' = no animation; CPU-friendly
  } else {
    chart = new Chart(canvas.value, {
      type: 'line',
      data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { position: 'bottom' } },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true },
        },
      },
    })
  }
})

onBeforeUnmount(() => chart?.destroy())
</script>
```

**Animation is off everywhere.** The dashboard must not noticeably
increase CPU when open (PRD §5.3). Updates use `chart.update('none')`.

## Responsive rules

- Mobile (< 768 px): sidebar becomes a drawer (`<Sheet>`). All forms
  collapse to single-column. Tables become stacked cards (one row per
  card, label : value pairs).
- Tablet (768–1024 px): sidebar visible but narrower; two-column form
  layout.
- Desktop (≥ 1024 px): full sidebar + multi-column dashboards.

Use Tailwind responsive prefixes (`md:`, `lg:`) — don't write custom
media queries.

## API client (`composables/useApi.ts`)

```ts
export function useApi() {
  async function call<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`/api${path}`, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      ...init,
    })
    if (res.status === 401) {
      navigateTo('/login')
      throw new Error('unauthorized')
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new ApiError(body.error?.code ?? 'unknown', body.error?.message ?? res.statusText, res.status)
    }
    return res.json() as Promise<T>
  }
  return {
    get:    <T>(p: string)             => call<T>(p),
    post:   <T>(p: string, body: any)  => call<T>(p, { method: 'POST', body: JSON.stringify(body) }),
    put:    <T>(p: string, body: any)  => call<T>(p, { method: 'PUT',  body: JSON.stringify(body) }),
    del:    <T>(p: string)             => call<T>(p, { method: 'DELETE' }),
  }
}

export class ApiError extends Error {
  constructor(public code: string, message: string, public status: number) {
    super(message)
  }
}
```

`useApi` reads the runtime prefix from the
`<meta name="sublyne-web-path">` tag the Go server's SPA handler
injects into `index.html`, and stamps every fetch with it. In dev
the meta tag is absent so calls go to `/api/...` and Vite's proxy
rewrites them under the dev panel prefix. See "Path obfuscation and
the runtime baseURL" above for the full lifecycle.

## Headless mount check (post-deploy smoke test)

`curl` can confirm the panel returns HTTP 200 but can't tell that the
SPA actually mounted — a missing runtime-config block makes the page
crash on JS execution while still serving a 200 HTML response. Phase
5 shipped exactly that bug once; the cure is a real browser load.

`frontend/scripts/check-spa-mount.mjs` is the reusable headless
check. It uses Playwright (devDep) to:

1. Launch headless Chromium.
2. Navigate to `PANEL_URL` and wait for `[data-testid="login-username"]`.
3. Optionally log in if `PANEL_USERNAME` + `PANEL_PASSWORD` are set,
   then re-assert the dashboard + settings pages mount cleanly.
4. Fail if any `pageerror` fired or any console error appeared that
   is not in the documented allow-list (today: the deliberate
   `/api/session 401` first-load probe).

Usage (run on any developer's machine — does not need to be on the
VM):

```
cd frontend
pnpm install                            # picks up playwright devDep
npx playwright install chromium         # one-time browser download
PANEL_URL=http://VM:62167/<web_path>/ \
  PANEL_USERNAME=admin PANEL_PASSWORD=… \
  node scripts/check-spa-mount.mjs
```

Phase 6+ should call this after every deploy that touches the
frontend dist, the SPA handler, or the build pipeline. CI does not
run it today (browser installs are too heavy for the existing CI
matrix); Phase 14 may revisit when the release workflow is built.

## Don't do

- Don't introduce a second UI library (Element Plus, PrimeVue,
  Quasar) alongside shadcn-vue. shadcn-vue is the only one.
- Don't write ad-hoc Tailwind classes for colors — use the CSS
  variables (`bg-primary`, `text-foreground`, etc.) so dark mode just
  works.
- Don't reach outside the obfuscated base path. All API calls go
  through `/api/...`. No third-party CDN, no Google Fonts, no analytics.
- Don't add animations that re-render every frame (auto-tweening
  gauges, marquees, animated loaders that spin forever). Skeleton
  loaders are fine; perpetual motion is not.
- Don't add new fields without `LabeledField` + tooltip.
