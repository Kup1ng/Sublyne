<script setup lang="ts">
import { ArrowDown, ArrowUp, Activity, Cable, Play, Square, Pencil, Download, Copy } from 'lucide-vue-next'
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useTunnelActions } from '~/composables/useTunnelActions'
import type { Tunnel, TunnelRate } from '~/types/api'
import { formatBitsPerSecond, formatNumber } from '~/utils/format'
import TunnelExportDialog from '~/components/tunnel/TunnelExportDialog.vue'

const props = defineProps<{ tunnel: Tunnel; rate?: TunnelRate | null }>()

const router = useRouter()
const actions = useTunnelActions()
const showExport = ref(false)

async function onClone() {
  const created = await actions.clone(props.tunnel.id)
  // Created stopped — open it on the Tunnels page (where the edit modal
  // lives) so the operator can resolve port clashes / edit.
  if (created) router.push(`/tunnels?edit=${created.id}`)
}

// A disabled tunnel reads "Stopped" (pairs with the Start button); an
// enabled one shows its live health badge, or "Unknown" until the first
// stats frame arrives (≈1 s after Start).
const status = computed<TunnelRate['status'] | null>(() => {
  if (!props.tunnel.enabled) return 'stopped'
  return props.rate?.status ?? null
})

const upLabel = computed(() => (props.rate ? formatBitsPerSecond(props.rate.bps_up) : '—'))
const downLabel = computed(() => (props.rate ? formatBitsPerSecond(props.rate.bps_down) : '—'))
const sessionsLabel = computed(() => (props.rate ? formatNumber(props.rate.sessions) : '—'))

// Surface the tunnel's application ports as a small badge. Since v2.7.0 the
// address no longer carries the port, so show it for every tunnel (one or
// many). Stats stay aggregate across all ports — every port is forwarded
// identically.
const portsLabel = computed(() => {
  const ports = props.tunnel.ports
  return ports && ports.length >= 1 ? ports.join(', ') : null
})
</script>

<template>
  <div class="surface-card group p-5 transition hover:border-line/100">
    <div class="flex items-start justify-between gap-3">
      <NuxtLink
        :to="`/tunnels?edit=${tunnel.id}`"
        class="flex min-w-0 items-center gap-3 outline-none"
      >
        <div class="grid size-9 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
          <Cable class="size-4" />
        </div>
        <div class="min-w-0">
          <p
            class="truncate text-[14.5px] font-semibold tracking-[-0.005em] text-ink transition group-hover:text-brand"
          >
            {{ tunnel.name }}
          </p>
          <p class="truncate text-[12px] text-subtle">
            {{ tunnel.role === 'client' ? tunnel.local_listen_addr : tunnel.upload_listen_addr }}
          </p>
        </div>
      </NuxtLink>
      <TunnelStatusBadge :status="status" />
    </div>

    <div v-if="portsLabel" class="mt-3">
      <AppBadge tone="brand">Ports: {{ portsLabel }}</AppBadge>
    </div>

    <dl class="mt-4 grid grid-cols-3 gap-2 text-[12px]">
      <div class="rounded-lg bg-elevated/40 px-2.5 py-2">
        <dt class="flex items-center gap-1 text-faint">
          <ArrowUp class="size-3" /> Upload
        </dt>
        <dd class="tabular mt-0.5 text-[13.5px] font-medium text-ink">{{ upLabel }}</dd>
      </div>
      <div class="rounded-lg bg-elevated/40 px-2.5 py-2">
        <dt class="flex items-center gap-1 text-faint">
          <ArrowDown class="size-3" /> Download
        </dt>
        <dd class="tabular mt-0.5 text-[13.5px] font-medium text-ink">{{ downLabel }}</dd>
      </div>
      <div class="rounded-lg bg-elevated/40 px-2.5 py-2">
        <dt class="flex items-center gap-1 text-faint">
          <Activity class="size-3" /> Sessions
        </dt>
        <dd class="tabular mt-0.5 text-[13.5px] font-medium text-ink">{{ sessionsLabel }}</dd>
      </div>
    </dl>

    <!-- Primary action: Start when stopped, Stop when running. Reuses the
         exact same handler/API/role-gating as the Tunnels page via
         useTunnelActions, so the two pages can never drift apart. The
         button disables + shows a spinner during the transition and the
         tile reflects the new state from the action's own refresh + the
         live metrics WebSocket. -->
    <div class="mt-4 flex items-center gap-2">
      <AppButton
        v-if="!tunnel.enabled"
        class="flex-1"
        size="sm"
        variant="secondary"
        :loading="actions.isBusy(tunnel.id)"
        :disabled="actions.isBusy(tunnel.id)"
        @click="actions.start(tunnel.id, tunnel.name)"
      >
        <Play v-if="!actions.isBusy(tunnel.id)" class="size-3.5" />
        Start
      </AppButton>
      <AppButton
        v-else
        class="flex-1"
        size="sm"
        variant="secondary"
        :loading="actions.isBusy(tunnel.id)"
        :disabled="actions.isBusy(tunnel.id)"
        @click="actions.stop(tunnel.id, tunnel.name)"
      >
        <Square v-if="!actions.isBusy(tunnel.id)" class="size-3.5" />
        Stop
      </AppButton>
      <AppButton
        size="sm"
        variant="ghost"
        aria-label="Export tunnel"
        title="Export tunnel"
        @click="showExport = true"
      >
        <Download class="size-3.5" />
      </AppButton>
      <AppButton
        size="sm"
        variant="ghost"
        aria-label="Clone tunnel"
        title="Clone tunnel"
        :loading="actions.isBusy(tunnel.id)"
        :disabled="actions.isBusy(tunnel.id)"
        @click="onClone"
      >
        <Copy v-if="!actions.isBusy(tunnel.id)" class="size-3.5" />
      </AppButton>
      <NuxtLink :to="`/tunnels?edit=${tunnel.id}`" aria-label="Edit tunnel">
        <AppButton size="sm" variant="ghost" aria-label="Edit tunnel">
          <Pencil class="size-3.5" />
        </AppButton>
      </NuxtLink>
    </div>

    <TunnelExportDialog v-model:open="showExport" :tunnel="tunnel" />
  </div>
</template>
