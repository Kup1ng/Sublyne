<script setup lang="ts">
import { ScrollText, RefreshCw } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useDrawer } from '~/composables/useDrawer'
import { useLogs, type CrashReport } from '~/composables/useLogs'
import { useMetrics } from '~/composables/useMetrics'
import { formatBytes, formatRelative } from '~/utils/format'

const drawer = useDrawer()
const metrics = useMetrics()
const logs = useLogs()

const levelFilter = ref<string>('ALL')
const search = ref('')
const crashes = ref<CrashReport[]>([])
const crashOpen = ref<{ name: string; body: string } | null>(null)

const levelOptions = [
  { value: 'ALL', label: 'All levels' },
  { value: 'TRACE', label: 'TRACE' },
  { value: 'DEBUG', label: 'DEBUG' },
  { value: 'INFO', label: 'INFO' },
  { value: 'WARN', label: 'WARN' },
  { value: 'ERROR', label: 'ERROR' },
]

onMounted(async () => {
  metrics.connect()
  try {
    const recent = await logs.recent(200)
    metrics.logs.value = [...recent]
  } catch {
    /* leave empty */
  }
  await reloadCrashes()
})
onBeforeUnmount(() => metrics.disconnect())

async function reloadCrashes() {
  try {
    crashes.value = await logs.crashes()
  } catch {
    crashes.value = []
  }
}

async function openCrash(name: string) {
  try {
    const body = await logs.crashBody(name)
    crashOpen.value = { name, body }
  } catch {
    crashOpen.value = { name, body: 'Could not read crash log.' }
  }
}

// Dataplane log lines come in nested under `fields.line` (the Go
// supervisor relays the Rust child's stdout verbatim and lifts only
// the level out). Control-plane lines have `msg` populated directly.
// Either way we render the most informative string per row.
function lineFor(e: { msg: string; fields?: Record<string, unknown> }) {
  const fieldLine = e.fields && typeof e.fields.line === 'string' ? (e.fields.line as string) : ''
  return fieldLine || e.msg
}

function timeFor(ts: string): string {
  // The Logs page tails the most recent buffer; show clock-time only.
  // The full date is preserved in the audit page where it matters.
  return ts.slice(11, 19)
}

const filtered = computed(() => {
  const lvl = levelFilter.value
  const q = search.value.toLowerCase()
  return metrics.logs.value.filter((e) => {
    if (lvl !== 'ALL' && e.level !== lvl) return false
    if (!q) return true
    const hay = `${e.msg} ${lineFor(e)} ${e.target ?? ''}`.toLowerCase()
    return hay.includes(q)
  })
})

const toneOf = (l: string) =>
  l === 'ERROR'
    ? 'danger'
    : l === 'WARN'
      ? 'warn'
      : l === 'INFO'
        ? 'brand'
        : l === 'DEBUG'
          ? 'accent'
          : 'neutral'
</script>

<template>
  <Topbar
    title="Logs"
    subtitle="Live tail of recent control-plane and dataplane lines. Older crashes are listed below."
    @open-menu="drawer.show"
  >
    <template #actions>
      <AppButton variant="secondary" size="sm" @click="reloadCrashes">
        <RefreshCw class="size-4" />
        Refresh crashes
      </AppButton>
    </template>
  </Topbar>

  <AppCard no-pad>
    <div class="flex flex-wrap items-center gap-3 border-b border-line/70 p-4">
      <div class="w-44">
        <AppSelect v-model="levelFilter" :options="levelOptions" />
      </div>
      <div class="flex-1 min-w-[200px]">
        <AppInput v-model="search" placeholder="Filter by message or target…" />
      </div>
    </div>

    <EmptyState
      v-if="!filtered.length"
      :icon="ScrollText"
      title="No log lines yet"
      description="Start a tunnel, the live stream will populate here within seconds."
    />

    <ul v-else class="max-h-[60vh] overflow-y-auto divide-y divide-line/60">
      <li
        v-for="(e, i) in filtered"
        :key="i"
        class="grid items-baseline gap-3 px-5 py-2 sm:grid-cols-[72px_64px_1fr] hover:bg-elevated/40"
      >
        <span class="font-mono text-[11.5px] tabular text-faint">{{ timeFor(e.ts) }}</span>
        <span>
          <AppBadge :tone="toneOf(e.level)">{{ e.level }}</AppBadge>
        </span>
        <span class="break-words text-[13px] leading-snug text-ink">
          <span v-if="e.target" class="text-subtle">{{ e.target }} · </span>{{ lineFor(e) }}
        </span>
      </li>
    </ul>
  </AppCard>

  <AppCard title="Crash reports" description="Stack traces written when the supervisor or dataplane panicked." class="mt-6">
    <EmptyState
      v-if="!crashes.length"
      :icon="ScrollText"
      title="No crash reports"
      description="The supervisor writes a crash-<unix>.log here whenever it observes a panic."
    />
    <ul v-else class="divide-y divide-line">
      <li
        v-for="c in crashes"
        :key="c.filename"
        class="flex items-center justify-between py-3"
      >
        <div>
          <p class="font-mono text-[13px] text-ink">{{ c.filename }}</p>
          <p class="text-[12px] text-subtle">
            {{ formatRelative(c.modified_at) }} · {{ formatBytes(c.size_bytes) }}
          </p>
        </div>
        <AppButton size="sm" variant="secondary" @click="openCrash(c.filename)">View</AppButton>
      </li>
    </ul>
  </AppCard>

  <AppDialog v-if="crashOpen" :open="true" :title="crashOpen.name" @update:open="crashOpen = null">
    <pre class="max-h-[60vh] overflow-auto whitespace-pre-wrap font-mono text-[12px] leading-5 text-ink">{{ crashOpen.body }}</pre>
  </AppDialog>
</template>
