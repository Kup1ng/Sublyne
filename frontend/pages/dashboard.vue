<script setup lang="ts">
import { Cpu, ArrowDown, ArrowUp, MemoryStick, Sparkles } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { useAuth } from '~/composables/useAuth'
import { useDrawer } from '~/composables/useDrawer'
import { useHandshakes } from '~/composables/useHandshakes'
import { useMetrics } from '~/composables/useMetrics'
import { useTunnels } from '~/composables/useTunnels'
import { formatBitsPerSecond, formatBytes, formatPercent } from '~/utils/format'

const tunnels = useTunnels()
const metrics = useMetrics()
const handshakes = useHandshakes()
const auth = useAuth()
const drawer = useDrawer()

onMounted(async () => {
  metrics.connect()
  metrics.fetchLatest()
  if (auth.role.value !== 'remote') handshakes.start()
  await tunnels.refresh()
})
onBeforeUnmount(() => {
  metrics.disconnect()
  handshakes.stop()
})

const snapshot = metrics.snapshot
const rates = metrics.rates
const history = metrics.history

const totalUp = computed(() => {
  let s = 0
  for (const r of rates.value.values()) s += r.bps_up
  return s
})
const totalDown = computed(() => {
  let s = 0
  for (const r of rates.value.values()) s += r.bps_down
  return s
})
const cpu = computed(() => snapshot.value?.system.cpu_percent ?? 0)
const memUsed = computed(() => snapshot.value?.system.mem_used_bytes ?? 0)
const memTotal = computed(() => snapshot.value?.system.mem_total_bytes ?? 0)
// Resident memory of the sublyne process itself (RSS) — the RAM tile.
const procRss = computed(() => snapshot.value?.system.proc_rss_bytes ?? 0)
</script>

<template>
  <Topbar
    title="Dashboard"
    subtitle="Live view of every tunnel on this server."
    @open-menu="drawer.show"
  />

  <section class="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
    <StatCard
      label="Upload"
      :value="formatBitsPerSecond(totalUp)"
      hint="Aggregate across enabled tunnels"
      tone="brand"
      :icon="ArrowUp"
    />
    <StatCard
      label="Download"
      :value="formatBitsPerSecond(totalDown)"
      hint="Spoofed return path"
      tone="accent"
      :icon="ArrowDown"
    />
    <StatCard
      label="RAM"
      :value="formatBytes(procRss)"
      :hint="
        memTotal
          ? `${formatPercent((procRss / memTotal) * 100, 1)} of ${formatBytes(memTotal)}`
          : 'sublyne process'
      "
      tone="ok"
      :icon="MemoryStick"
    />
    <StatCard
      label="CPU"
      :value="formatPercent(cpu, 1)"
      :hint="memTotal ? `System memory ${formatPercent((memUsed / memTotal) * 100, 0)}` : undefined"
      tone="warn"
      :icon="Cpu"
    />
  </section>

  <section
    :class="[
      'mt-8 grid gap-5',
      auth.role.value === 'remote' ? '' : 'lg:grid-cols-3',
    ]"
  >
    <AppCard
      :class="auth.role.value === 'remote' ? '' : 'lg:col-span-2'"
      title="Bandwidth"
      description="Live upload + download — last 30 seconds."
    >
      <div class="mb-3 flex flex-wrap items-center gap-x-6 gap-y-1.5">
        <div class="flex items-center gap-2">
          <span class="inline-block size-2 rounded-full bg-brand" />
          <span class="text-[12px] text-subtle">Upload</span>
          <span class="tabular text-[13px] font-semibold text-ink">{{
            formatBitsPerSecond(totalUp)
          }}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="inline-block size-2 rounded-full bg-accent" />
          <span class="text-[12px] text-subtle">Download</span>
          <span class="tabular text-[13px] font-semibold text-ink">{{
            formatBitsPerSecond(totalDown)
          }}</span>
        </div>
      </div>
      <Sparkline
        :series="[
          { data: history.bps_up, tone: 'brand' },
          { data: history.bps_down, tone: 'accent' },
        ]"
        :window="30"
        :height="140"
      />
    </AppCard>

    <HandshakeCard v-if="auth.role.value !== 'remote'" :handshakes="handshakes.rows.value" />
  </section>

  <section class="mt-8">
    <div class="mb-4 flex items-end justify-between gap-3">
      <div>
        <h2 class="text-[17px] font-semibold tracking-[-0.008em] text-ink">Tunnels</h2>
        <p class="mt-0.5 text-[12.5px] text-subtle">
          {{ tunnels.list.value.length }} configured
        </p>
      </div>
      <NuxtLink to="/tunnels">
        <AppButton variant="secondary" size="sm">Manage</AppButton>
      </NuxtLink>
    </div>

    <EmptyState
      v-if="!tunnels.list.value.length"
      :icon="Sparkles"
      title="No tunnels yet"
      description="Add a matching pair on this and the other server to start forwarding traffic."
    >
      <template #actions>
        <NuxtLink to="/tunnels/new">
          <AppButton>Create your first tunnel</AppButton>
        </NuxtLink>
      </template>
    </EmptyState>

    <div v-else class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <TunnelCard
        v-for="t in tunnels.list.value"
        :key="t.id"
        :tunnel="t"
        :rate="rates.get(t.id) ?? null"
      />
    </div>
  </section>

  <p class="mt-8 flex items-center gap-2 text-[12px] text-faint">
    <span
      class="inline-block size-2 rounded-full"
      :class="{
        'bg-ok animate-pulseSoft': metrics.status.value === 'open',
        'bg-warn': metrics.status.value === 'idle',
        'bg-danger': metrics.status.value === 'closed' || metrics.status.value === 'error',
      }"
    />
    <span class="tracking-tight">
      {{
        metrics.status.value === 'open'
          ? 'Live metrics streaming'
          : metrics.status.value === 'idle'
            ? 'Connecting…'
            : 'Reconnecting…'
      }}
    </span>
  </p>
</template>
