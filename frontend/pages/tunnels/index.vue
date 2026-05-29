<script setup lang="ts">
import { Cable, Plus, Play, Square, Pencil } from 'lucide-vue-next'
import { onMounted } from 'vue'
import { useDrawer } from '~/composables/useDrawer'
import { useMetrics } from '~/composables/useMetrics'
import { useTunnels } from '~/composables/useTunnels'
import { useToast } from '~/composables/useToast'
import { formatBitsPerSecond, formatNumber } from '~/utils/format'

const tunnels = useTunnels()
const metrics = useMetrics()
const toast = useToast()
const drawer = useDrawer()

onMounted(async () => {
  metrics.connect()
  metrics.fetchLatest()
  await tunnels.refresh()
})

const rates = metrics.rates

async function start(id: number, name: string) {
  try {
    await tunnels.start(id)
    toast.success(`Started ${name}`)
  } catch (e) {
    toast.error('Failed to start', (e as Error).message)
  }
}
async function stop(id: number, name: string) {
  try {
    await tunnels.stop(id)
    toast.success(`Stopped ${name}`)
  } catch (e) {
    toast.error('Failed to stop', (e as Error).message)
  }
}
</script>

<template>
  <Topbar title="Tunnels" subtitle="One row per port mapping." @open-menu="drawer.show">
    <template #actions>
      <NuxtLink to="/tunnels/new">
        <AppButton size="sm">
          <Plus class="size-4" />
          New tunnel
        </AppButton>
      </NuxtLink>
    </template>
  </Topbar>

  <EmptyState
    v-if="!tunnels.loading.value && tunnels.list.value.length === 0"
    :icon="Cable"
    title="No tunnels configured"
    description="Add a Client or Remote tunnel and pair it with the matching server."
  >
    <template #actions>
      <NuxtLink to="/tunnels/new">
        <AppButton>
          <Plus class="size-4" />
          Create tunnel
        </AppButton>
      </NuxtLink>
    </template>
  </EmptyState>

  <AppCard v-else no-pad>
    <div class="overflow-x-auto">
      <table class="w-full text-[13.5px]">
        <thead class="border-b border-line text-left text-[11.5px] uppercase tracking-[0.12em] text-faint">
          <tr>
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Listener</th>
            <th class="px-5 py-3">Transport</th>
            <th class="px-5 py-3 text-right">Upload</th>
            <th class="px-5 py-3 text-right">Download</th>
            <th class="px-5 py-3 text-right">Sessions</th>
            <th class="px-5 py-3">Status</th>
            <th class="px-5 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="t in tunnels.list.value"
            :key="t.id"
            class="border-b border-line/60 last:border-b-0 hover:bg-elevated/50"
          >
            <td class="px-5 py-3.5 font-medium text-ink">
              <NuxtLink :to="`/tunnels/${t.id}`" class="hover:text-brand">{{ t.name }}</NuxtLink>
            </td>
            <td class="px-5 py-3.5 font-mono text-[12.5px] text-subtle">
              {{ t.role === 'client' ? t.local_listen_addr : t.upload_listen_addr }}
            </td>
            <td class="px-5 py-3.5 text-subtle">{{ t.download_transport ?? '—' }}</td>
            <td class="px-5 py-3.5 text-right tabular text-ink">
              {{ rates.get(t.id) ? formatBitsPerSecond(rates.get(t.id)!.bps_up) : '—' }}
            </td>
            <td class="px-5 py-3.5 text-right tabular text-ink">
              {{ rates.get(t.id) ? formatBitsPerSecond(rates.get(t.id)!.bps_down) : '—' }}
            </td>
            <td class="px-5 py-3.5 text-right tabular text-subtle">
              {{ rates.get(t.id) ? formatNumber(rates.get(t.id)!.sessions) : '—' }}
            </td>
            <td class="px-5 py-3.5">
              <TunnelStatusBadge :status="t.enabled ? (rates.get(t.id)?.status ?? null) : null" />
            </td>
            <td class="px-5 py-3.5 text-right">
              <div class="inline-flex items-center gap-1.5">
                <AppButton
                  v-if="!t.enabled"
                  size="sm"
                  variant="secondary"
                  @click="start(t.id, t.name)"
                >
                  <Play class="size-3.5" />
                  Start
                </AppButton>
                <AppButton
                  v-else
                  size="sm"
                  variant="secondary"
                  @click="stop(t.id, t.name)"
                >
                  <Square class="size-3.5" />
                  Stop
                </AppButton>
                <NuxtLink :to="`/tunnels/${t.id}`">
                  <AppButton size="sm" variant="ghost">
                    <Pencil class="size-3.5" />
                  </AppButton>
                </NuxtLink>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </AppCard>
</template>
