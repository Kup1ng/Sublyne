<script setup lang="ts">
import { Cable, Plus, Play, Square, Pencil, Download, Copy, Upload } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useDrawer } from '~/composables/useDrawer'
import { useMetrics } from '~/composables/useMetrics'
import { useTunnels } from '~/composables/useTunnels'
import { useTunnelActions } from '~/composables/useTunnelActions'
import type { Tunnel } from '~/types/api'
import TunnelExportDialog from '~/components/tunnel/TunnelExportDialog.vue'
import TunnelImportDialog from '~/components/tunnel/TunnelImportDialog.vue'
import { formatBitsPerSecond, formatNumber } from '~/utils/format'

const router = useRouter()
const tunnels = useTunnels()
const metrics = useMetrics()
const actions = useTunnelActions()
const drawer = useDrawer()

onMounted(async () => {
  metrics.connect()
  metrics.fetchLatest()
  await tunnels.refresh()
})

const rates = metrics.rates

const showImport = ref(false)
// One export dialog for the whole table; the row buttons set its target.
const exportTarget = ref<Tunnel | null>(null)
const showExport = ref(false)

function openExport(t: Tunnel) {
  exportTarget.value = t
  showExport.value = true
}

async function onClone(t: Tunnel) {
  const created = await actions.clone(t.id)
  if (created) router.push(`/tunnels/${created.id}`)
}

async function onImported(tunnel: Tunnel) {
  await tunnels.refresh()
  router.push(`/tunnels/${tunnel.id}`)
}
</script>

<template>
  <Topbar title="Tunnels" subtitle="One row per port mapping." @open-menu="drawer.show">
    <template #actions>
      <AppButton size="sm" variant="secondary" @click="showImport = true">
        <Upload class="size-4" />
        Import
      </AppButton>
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
              <TunnelStatusBadge :status="t.enabled ? (rates.get(t.id)?.status ?? null) : 'stopped'" />
            </td>
            <td class="px-5 py-3.5 text-right">
              <div class="inline-flex items-center gap-1.5">
                <AppButton
                  v-if="!t.enabled"
                  size="sm"
                  variant="secondary"
                  :loading="actions.isBusy(t.id)"
                  :disabled="actions.isBusy(t.id)"
                  @click="actions.start(t.id, t.name)"
                >
                  <Play v-if="!actions.isBusy(t.id)" class="size-3.5" />
                  Start
                </AppButton>
                <AppButton
                  v-else
                  size="sm"
                  variant="secondary"
                  :loading="actions.isBusy(t.id)"
                  :disabled="actions.isBusy(t.id)"
                  @click="actions.stop(t.id, t.name)"
                >
                  <Square v-if="!actions.isBusy(t.id)" class="size-3.5" />
                  Stop
                </AppButton>
                <AppButton
                  size="sm"
                  variant="ghost"
                  aria-label="Export tunnel"
                  title="Export tunnel"
                  @click="openExport(t)"
                >
                  <Download class="size-3.5" />
                </AppButton>
                <AppButton
                  size="sm"
                  variant="ghost"
                  aria-label="Clone tunnel"
                  title="Clone tunnel"
                  :loading="actions.isBusy(t.id)"
                  :disabled="actions.isBusy(t.id)"
                  @click="onClone(t)"
                >
                  <Copy v-if="!actions.isBusy(t.id)" class="size-3.5" />
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

  <TunnelImportDialog v-model:open="showImport" @imported="onImported" />
  <TunnelExportDialog v-if="exportTarget" v-model:open="showExport" :tunnel="exportTarget" />
</template>
