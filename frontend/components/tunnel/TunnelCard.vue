<script setup lang="ts">
import { ArrowDown, ArrowUp, Activity, Cable } from 'lucide-vue-next'
import { computed } from 'vue'
import type { Tunnel, TunnelRate } from '~/types/api'
import { formatBitsPerSecond, formatNumber } from '~/utils/format'

const props = defineProps<{ tunnel: Tunnel; rate?: TunnelRate | null }>()

const status = computed<TunnelRate['status'] | null>(() => {
  if (!props.tunnel.enabled) return null
  return props.rate?.status ?? null
})

const upLabel = computed(() => (props.rate ? formatBitsPerSecond(props.rate.bps_up) : '—'))
const downLabel = computed(() => (props.rate ? formatBitsPerSecond(props.rate.bps_down) : '—'))
const sessionsLabel = computed(() => (props.rate ? formatNumber(props.rate.sessions) : '—'))

// Multi-port tunnels carry several application ports (1 element would be a
// single-port tunnel). Surface the full list as a small badge; stats stay
// aggregate across all ports.
const portsLabel = computed(() => {
  const ports = props.tunnel.ports
  return ports && ports.length >= 2 ? ports.join(', ') : null
})
</script>

<template>
  <NuxtLink
    :to="`/tunnels/${tunnel.id}`"
    class="surface-card group block p-5 transition hover:border-line/100 hover:shadow-glow"
  >
    <div class="flex items-start justify-between gap-3">
      <div class="flex min-w-0 items-center gap-3">
        <div class="grid size-9 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
          <Cable class="size-4" />
        </div>
        <div class="min-w-0">
          <p class="truncate text-[14.5px] font-semibold tracking-[-0.005em] text-ink">{{ tunnel.name }}</p>
          <p class="truncate text-[12px] text-subtle">
            {{ tunnel.role === 'client' ? tunnel.local_listen_addr : tunnel.upload_listen_addr }}
          </p>
        </div>
      </div>
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
  </NuxtLink>
</template>
