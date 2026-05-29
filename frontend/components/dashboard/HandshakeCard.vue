<script setup lang="ts">
import { Shield } from 'lucide-vue-next'
import type { HandshakeRow } from '~/types/api'

defineProps<{ handshakes: HandshakeRow[] }>()

function toneFor(h: HandshakeRow): 'ok' | 'warn' | 'danger' {
  if (!h.has_ever_connected) return 'danger'
  return h.stale ? 'warn' : 'ok'
}

function labelFor(h: HandshakeRow): string {
  if (!h.has_ever_connected) return 'never'
  return h.stale ? 'stale' : 'fresh'
}

function ageLabel(h: HandshakeRow): string {
  if (h.last_handshake_age) return `${h.last_handshake_age} ago`
  if (!h.has_ever_connected) return 'no handshake yet'
  return ''
}
</script>

<template>
  <AppCard title="WireGuard handshakes" description="Per-config liveness from kernel netlink">
    <EmptyState
      v-if="!handshakes.length"
      :icon="Shield"
      title="No WireGuard configs in use"
      description="When a Client tunnel uses a WG config, the latest handshake age shows here."
    />
    <ul v-else class="divide-y divide-line">
      <li
        v-for="h in handshakes"
        :key="h.config_id"
        class="flex items-center justify-between py-3"
      >
        <div class="flex min-w-0 items-center gap-3">
          <Shield class="size-4 shrink-0 text-faint" />
          <div class="min-w-0">
            <p class="truncate text-[13.5px] font-medium text-ink">
              {{ h.config_name }}
              <span v-if="h.interface_name" class="ml-1 font-mono text-[11.5px] text-faint">
                ({{ h.interface_name }})
              </span>
            </p>
            <p class="text-[12px] text-subtle">{{ ageLabel(h) }}</p>
          </div>
        </div>
        <AppBadge :tone="toneFor(h)" :pulse="!h.stale && h.has_ever_connected">
          {{ labelFor(h) }}
        </AppBadge>
      </li>
    </ul>
  </AppCard>
</template>
