<script setup lang="ts">
import { Cable, Plus, Play, Square, Pencil, Download, Copy, Upload } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useDrawer } from '~/composables/useDrawer'
import { useMetrics } from '~/composables/useMetrics'
import { useTunnels } from '~/composables/useTunnels'
import { useTunnelActions } from '~/composables/useTunnelActions'
import type { Tunnel } from '~/types/api'
import TunnelExportDialog from '~/components/tunnel/TunnelExportDialog.vue'
import TunnelImportDialog from '~/components/tunnel/TunnelImportDialog.vue'
import TunnelFormModal from '~/components/tunnel/TunnelFormModal.vue'
import { formatBitsPerSecond, formatNumber } from '~/utils/format'

const route = useRoute()
const router = useRouter()
const tunnels = useTunnels()
const metrics = useMetrics()
const actions = useTunnelActions()
const drawer = useDrawer()

// The create/edit form is a modal hosted on this page (popup-only since
// v4.0.0 — the standalone /tunnels/new and /tunnels/[id] pages are gone).
const showForm = ref(false)
const editId = ref<number | null>(null)

function openCreate() {
  editId.value = null
  showForm.value = true
}
function openEdit(id: number) {
  editId.value = id
  showForm.value = true
}
async function onSaved() {
  await tunnels.refresh()
}

onMounted(async () => {
  metrics.connect()
  metrics.fetchLatest()
  await tunnels.refresh()
  // Deep links from the dashboard (TunnelCard edit / "new tunnel") arrive
  // as ?edit=<id> or ?new=1; open the modal, then strip the query so a
  // refresh doesn't reopen it.
  const editQ = route.query.edit
  const newQ = route.query.new
  if (typeof editQ === 'string' && editQ) {
    // Validate the id: a malformed ?edit=abc would otherwise become
    // openEdit(NaN) and pop a confusing empty/Create-looking modal. Only open
    // the edit modal for a real positive integer id; ignore garbage links.
    const id = Number(editQ)
    if (Number.isInteger(id) && id > 0) openEdit(id)
  } else if (newQ) openCreate()
  if (editQ || newQ) router.replace({ query: {} })
})

const rates = metrics.rates

// Status badge source. Prefer the live WS snapshot's own `enabled` flag
// over the REST list's `t.enabled`, which is only refreshed by this tab's
// own actions — so a tunnel stopped from another tab (or the dashboard)
// reflects as "stopped" here instead of lingering as healthy/idle.
function badgeStatus(t: { id: number; enabled: boolean }) {
  const live = rates.value.get(t.id)
  const enabled = live ? live.enabled : t.enabled
  if (!enabled) return 'stopped'
  return live?.status ?? null
}

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
  if (created) openEdit(created.id)
}

async function onImported(tunnel: Tunnel) {
  await tunnels.refresh()
  openEdit(tunnel.id)
}
</script>

<template>
  <Topbar title="Tunnels" subtitle="One row per port mapping." @open-menu="drawer.show">
    <template #actions>
      <AppButton size="sm" variant="secondary" @click="showImport = true">
        <Upload class="size-4" />
        Import
      </AppButton>
      <AppButton size="sm" @click="openCreate">
        <Plus class="size-4" />
        New tunnel
      </AppButton>
    </template>
  </Topbar>

  <EmptyState
    v-if="!tunnels.loading.value && tunnels.list.value.length === 0"
    :icon="Cable"
    title="No tunnels configured"
    description="Add a Client or Remote tunnel and pair it with the matching server."
  >
    <template #actions>
      <AppButton @click="openCreate">
        <Plus class="size-4" />
        Create tunnel
      </AppButton>
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
              <button type="button" class="text-left hover:text-brand" @click="openEdit(t.id)">
                {{ t.name }}
              </button>
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
              <TunnelStatusBadge :status="badgeStatus(t)" />
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
                <AppButton
                  size="sm"
                  variant="ghost"
                  aria-label="Edit tunnel"
                  title="Edit tunnel"
                  @click="openEdit(t.id)"
                >
                  <Pencil class="size-3.5" />
                </AppButton>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </AppCard>

  <TunnelImportDialog v-model:open="showImport" @imported="onImported" />
  <TunnelExportDialog v-if="exportTarget" v-model:open="showExport" :tunnel="exportTarget" />
  <TunnelFormModal v-model:open="showForm" :tunnel-id="editId" @saved="onSaved" />
</template>
