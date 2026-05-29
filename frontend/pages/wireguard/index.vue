<script setup lang="ts">
import { Plus, Shield, Pencil } from 'lucide-vue-next'
import { onMounted } from 'vue'
import { useDrawer } from '~/composables/useDrawer'
import { useWireguard } from '~/composables/useWireguard'
import { formatRelative } from '~/utils/format'

const wg = useWireguard()
const drawer = useDrawer()
onMounted(() => wg.refresh())
</script>

<template>
  <Topbar title="WireGuard" subtitle="Configs pasted from your seller." @open-menu="drawer.show">
    <template #actions>
      <NuxtLink to="/wireguard/new">
        <AppButton size="sm">
          <Plus class="size-4" />
          Add config
        </AppButton>
      </NuxtLink>
    </template>
  </Topbar>

  <EmptyState
    v-if="!wg.loading.value && wg.list.value.length === 0"
    :icon="Shield"
    title="No WireGuard configs yet"
    description="Paste the seller's WireGuard config to bring a kernel WG interface up. Multiple tunnels may share one config."
  >
    <template #actions>
      <NuxtLink to="/wireguard/new">
        <AppButton>
          <Plus class="size-4" />
          Add your first config
        </AppButton>
      </NuxtLink>
    </template>
  </EmptyState>

  <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
    <NuxtLink
      v-for="c in wg.list.value"
      :key="c.id"
      :to="`/wireguard/${c.id}`"
      class="surface-card group block p-5 transition hover:border-line/100 hover:shadow-glow"
    >
      <div class="flex items-start gap-3">
        <div class="grid size-9 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
          <Shield class="size-4" />
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center justify-between gap-3">
            <p class="truncate text-[14.5px] font-semibold tracking-[-0.005em] text-ink">
              {{ c.name }}
            </p>
            <AppBadge tone="brand" v-if="(c.reference_count ?? 0) > 0">
              {{ c.reference_count }} in use
            </AppBadge>
          </div>
          <p class="mt-0.5 truncate font-mono text-[12px] text-subtle">
            {{ c.endpoint || '—' }}
          </p>
          <p class="mt-2 text-[11.5px] text-faint">
            Updated {{ c.updated_at ? formatRelative(c.updated_at) : '—' }}
          </p>
        </div>
        <Pencil class="size-3.5 shrink-0 self-start text-faint transition group-hover:text-ink" />
      </div>
    </NuxtLink>
  </div>
</template>
