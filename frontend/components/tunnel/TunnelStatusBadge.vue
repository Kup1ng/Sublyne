<script setup lang="ts">
import type { TunnelRate } from '~/types/api'

defineProps<{ status: TunnelRate['status'] | null }>()

const toneMap: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  healthy: 'ok',
  idle: 'warn',
  down: 'danger',
  stopped: 'neutral',
}
const labelMap: Record<string, string> = {
  healthy: 'Healthy',
  idle: 'Idle',
  down: 'Down',
  stopped: 'Stopped',
}
</script>

<template>
  <AppBadge
    :tone="status ? toneMap[status] : 'neutral'"
    :pulse="status === 'healthy'"
  >
    {{ status ? labelMap[status] : 'Unknown' }}
  </AppBadge>
</template>
