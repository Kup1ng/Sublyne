<script setup lang="ts">
import {
  LayoutDashboard,
  Cable,
  Shield,
  Network,
  Settings,
  ScrollText,
  History,
  LogOut,
} from 'lucide-vue-next'
import { computed } from 'vue'
import { useAuth } from '~/composables/useAuth'

const auth = useAuth()
const router = useRouter()

defineProps<{ onNavigate?: () => void }>()

interface Item {
  to: string
  label: string
  icon: unknown
  clientOnly?: boolean
}

const allItems: Item[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/tunnels', label: 'Tunnels', icon: Cable },
  { to: '/wireguard', label: 'WireGuard', icon: Shield, clientOnly: true },
  { to: '/socks5', label: 'SOCKS5', icon: Network, clientOnly: true },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/logs', label: 'Logs', icon: ScrollText },
  { to: '/audit', label: 'Audit', icon: History },
]

const items = computed(() => {
  const isRemote = auth.role.value === 'remote'
  return allItems.filter((i) => !(i.clientOnly && isRemote))
})

async function onLogout() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <aside class="flex h-full w-full flex-col bg-surface">
    <div class="px-5 pt-5 pb-3">
      <NuxtLink to="/dashboard" class="inline-flex" @click="onNavigate?.()">
        <BrandMark size="md" />
      </NuxtLink>
    </div>

    <div
      v-if="auth.session.value"
      class="mx-3 mb-4 rounded-2xl border border-line/70 bg-elevated/50 px-3.5 py-3"
    >
      <p class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">Signed in</p>
      <div class="mt-1.5 flex items-center justify-between gap-3">
        <p class="truncate text-[13.5px] font-semibold text-ink">
          {{ auth.session.value.username }}
        </p>
        <AppBadge :tone="auth.role.value === 'client' ? 'brand' : 'accent'" :soft="true">
          {{ auth.role.value === 'client' ? 'Client' : 'Remote' }}
        </AppBadge>
      </div>
    </div>

    <nav class="flex-1 px-2.5">
      <ul class="space-y-0.5">
        <li v-for="item in items" :key="item.to">
          <NuxtLink
            :to="item.to"
            class="group nav-item relative flex items-center gap-2.5 rounded-xl px-3 py-2 text-[13.5px] font-medium text-subtle transition hover:text-ink hover:bg-elevated/70"
            @click="onNavigate?.()"
          >
            <component :is="item.icon" class="nav-icon size-4 shrink-0 text-faint transition" />
            <span>{{ item.label }}</span>
          </NuxtLink>
        </li>
      </ul>
    </nav>

    <div class="border-t border-line/70 p-3 space-y-2">
      <div class="flex items-center justify-between gap-2 px-1">
        <p class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">Theme</p>
        <ThemeToggle />
      </div>
      <button
        type="button"
        class="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13.5px] font-medium text-subtle transition hover:text-danger hover:bg-danger/10"
        @click="onLogout"
      >
        <LogOut class="size-4" />
        <span>Sign out</span>
      </button>
    </div>
  </aside>
</template>

<style scoped>
/* NuxtLink applies `.router-link-active` / `.router-link-exact-active`
 * to the rendered <a>. Active state: stronger background, a 2-px
 * brand-coloured left rail (the affordance Linear/Vercel use), and a
 * brand-coloured icon to anchor the eye. */
.nav-item.router-link-active {
  color: rgb(var(--ink));
  background-color: rgb(var(--elevated));
}
.nav-item.router-link-active::before {
  content: '';
  position: absolute;
  left: -2px;
  top: 8px;
  bottom: 8px;
  width: 2.5px;
  border-radius: 2px;
  background: linear-gradient(180deg, rgb(var(--brand-edge)), rgb(var(--brand)));
}
.nav-item.router-link-active .nav-icon {
  color: rgb(var(--brand));
}
</style>
