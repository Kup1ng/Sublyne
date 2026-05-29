<script setup lang="ts">
import { History } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useAudit } from '~/composables/useAudit'
import { useDrawer } from '~/composables/useDrawer'
import type { AuditEntry } from '~/types/api'

function shortTime(ts: string): string {
  // The full Date toString takes too much horizontal space on the
  // audit table; use a short locale-aware "Jan 12 · 14:23" format
  // instead so the columns line up on narrower screens too.
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  const date = d.toLocaleString(undefined, { month: 'short', day: '2-digit' })
  const time = d.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })
  return `${date} · ${time}`
}

const audit = useAudit()
const drawer = useDrawer()

const entries = ref<AuditEntry[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    entries.value = await audit.recent(200)
  } finally {
    loading.value = false
  }
})

function detailString(e: AuditEntry): string {
  const d = e.details
  if (!d) return ''
  const pairs = Object.entries(d).filter(([k, v]) => {
    // Suppress payload fields that just echo the target (e.g. the
    // login handler stamps {"username": "ping"} on top of target:
    // "ping"). They add visual noise without informing the operator.
    if (e.target && typeof v === 'string' && v === e.target) return false
    return true
  })
  if (pairs.length === 0) return ''
  return pairs.map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(' · ')
}

function actionTone(action: string): 'brand' | 'ok' | 'warn' | 'danger' | 'accent' {
  if (action.includes('fail') || action.includes('lock')) return 'danger'
  if (action.includes('login') || action.includes('start')) return 'ok'
  if (action.includes('stop') || action.includes('delete')) return 'warn'
  if (action.includes('change') || action.includes('update')) return 'accent'
  return 'brand'
}
</script>

<template>
  <Topbar
    title="Audit"
    subtitle="Admin actions over the last seven days."
    @open-menu="drawer.show"
  />

  <EmptyState
    v-if="!loading && !entries.length"
    :icon="History"
    title="No audit entries yet"
    description="Logins, tunnel start/stop, and settings changes show up here as soon as they happen."
  />

  <AppCard v-else no-pad>
    <div class="overflow-x-auto">
      <table class="w-full text-[13.5px]">
        <thead
          class="sticky top-0 z-10 border-b border-line/70 bg-surface text-left text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint"
        >
          <tr>
            <th class="px-5 py-3">Time</th>
            <th class="px-5 py-3">User</th>
            <th class="px-5 py-3">IP</th>
            <th class="px-5 py-3">Action</th>
            <th class="px-5 py-3">Details</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-line/60">
          <tr v-for="e in entries" :key="e.id" class="hover:bg-elevated/40">
            <td class="whitespace-nowrap px-5 py-3 text-[12.5px] text-subtle">
              {{ shortTime(e.ts) }}
            </td>
            <td class="px-5 py-3 font-medium text-ink">{{ e.actor }}</td>
            <td class="px-5 py-3 font-mono text-[12.5px] text-subtle">{{ e.ip }}</td>
            <td class="px-5 py-3">
              <AppBadge :tone="actionTone(e.action)">{{ e.action }}</AppBadge>
            </td>
            <td class="px-5 py-3 text-subtle">
              <span v-if="e.target" class="mr-1.5 text-faint">→</span>
              <span v-if="e.target" class="font-mono text-[12.5px] text-ink">{{ e.target }}</span>
              <span class="ml-2 font-mono text-[12px] text-subtle">{{ detailString(e) }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </AppCard>
</template>
