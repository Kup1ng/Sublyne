<script setup lang="ts">
import { Network, Plus, Pencil } from 'lucide-vue-next'
import { onMounted } from 'vue'
import { useDrawer } from '~/composables/useDrawer'
import { useSocks5 } from '~/composables/useSocks5'
import { formatRelative } from '~/utils/format'

const socks = useSocks5()
const drawer = useDrawer()
onMounted(() => socks.refresh())
</script>

<template>
  <Topbar
    title="SOCKS5 proxies"
    subtitle="Multi-link upload via N parallel TCP connections."
    @open-menu="drawer.show"
  >
    <template #actions>
      <NuxtLink to="/socks5/new">
        <AppButton size="sm">
          <Plus class="size-4" />
          Add proxy
        </AppButton>
      </NuxtLink>
    </template>
  </Topbar>

  <EmptyState
    v-if="!socks.loading.value && socks.list.value.length === 0"
    :icon="Network"
    title="No SOCKS5 proxies yet"
    description="A proxy fronting multiple Starlink links lets one tunnel use the aggregate upload bandwidth of every link."
  >
    <template #actions>
      <NuxtLink to="/socks5/new">
        <AppButton>
          <Plus class="size-4" />
          Add your first proxy
        </AppButton>
      </NuxtLink>
    </template>
  </EmptyState>

  <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
    <NuxtLink
      v-for="p in socks.list.value"
      :key="p.id"
      :to="`/socks5/${p.id}`"
      class="surface-card group block p-5 transition hover:border-line/100 hover:shadow-glow"
    >
      <div class="flex items-start gap-3">
        <div class="grid size-9 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
          <Network class="size-4" />
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center justify-between gap-3">
            <p class="truncate text-[14.5px] font-semibold tracking-[-0.005em] text-ink">
              {{ p.name }}
            </p>
            <AppBadge tone="accent">{{ p.parallel_connections }}× parallel</AppBadge>
          </div>
          <p class="mt-0.5 truncate font-mono text-[12px] text-subtle">
            {{ p.host }}:{{ p.port }}
          </p>
          <p class="mt-2 text-[11.5px] text-faint">
            Updated {{ p.updated_at ? formatRelative(p.updated_at) : '—' }}
          </p>
        </div>
        <Pencil class="size-3.5 shrink-0 self-start text-faint transition group-hover:text-ink" />
      </div>
    </NuxtLink>
  </div>
</template>
