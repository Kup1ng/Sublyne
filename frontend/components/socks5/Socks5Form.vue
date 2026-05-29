<script setup lang="ts">
import { Save, Trash2 } from 'lucide-vue-next'
import { ref, watchEffect } from 'vue'
import type { Socks5Proxy } from '~/types/api'

const props = defineProps<{
  initial?: Partial<Socks5Proxy>
  submitting?: boolean
  errors?: Record<string, string>
  onDelete?: (() => void) | null
}>()
const emit = defineEmits<{ (e: 'submit', value: Partial<Socks5Proxy>): void }>()

const draft = ref<Partial<Socks5Proxy>>({
  port: 1080,
  parallel_connections: 4,
  min_ready_slots: 2,
  ...props.initial,
})
watchEffect(() => {
  if (props.initial) draft.value = { ...draft.value, ...props.initial }
})

function err(field: string) {
  return props.errors?.[field] ?? null
}
</script>

<template>
  <form @submit.prevent="emit('submit', draft)" class="space-y-6">
    <AppCard title="Proxy endpoint" description="Where to dial and (optionally) credentials.">
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup label="Name" :error="err('name')" required help="Free-form label, unique on this server.">
          <AppInput v-model="draft.name" :invalid="!!err('name')" placeholder="starlink-LB-1" />
        </FieldGroup>
        <FieldGroup
          label="Parallel connections"
          help="The dataplane opens this many TCP connections to the proxy. Each lands on a different uplink behind the LB."
          :error="err('parallel_connections')"
        >
          <AppInput
            v-model="draft.parallel_connections"
            type="number"
            :invalid="!!err('parallel_connections')"
            monospace
            placeholder="4"
          />
        </FieldGroup>
        <FieldGroup label="Host" :error="err('host')" required help="IPv4, IPv6, or hostname.">
          <AppInput v-model="draft.host" :invalid="!!err('host')" placeholder="203.0.113.20" monospace />
        </FieldGroup>
        <FieldGroup label="Port" :error="err('port')" required>
          <AppInput v-model="draft.port" type="number" :invalid="!!err('port')" placeholder="1080" monospace />
        </FieldGroup>
        <FieldGroup label="Username" help="Optional (leave blank for no auth).">
          <AppInput v-model="draft.username" placeholder="alice" />
        </FieldGroup>
        <FieldGroup label="Password" help="Optional. The list endpoint returns *** on read; the detail page can reveal with the explicit Reveal action.">
          <AppInput v-model="draft.password" type="password" placeholder="••••••••" />
        </FieldGroup>
        <FieldGroup
          label="Minimum ready slots"
          help="Pool warm-up gate: the tunnel waits for at least this many slots to complete the SOCKS5 handshake before reporting Up. Catches the partial-pool 'limp' symptom on first connect."
        >
          <AppInput v-model="draft.min_ready_slots" type="number" monospace placeholder="2" />
        </FieldGroup>
      </div>
      <FieldGroup label="Notes" help="Free-form. Useful for naming which physical LB or Starlink site this is." class="mt-5">
        <AppTextarea v-model="draft.notes" :rows="3" />
      </FieldGroup>
    </AppCard>

    <div
      class="sticky bottom-0 -mx-6 flex items-center justify-between gap-2 border-t border-line/70 bg-bg/90 px-6 py-4 backdrop-blur-md md:-mx-10 md:px-10"
    >
      <AppButton v-if="onDelete" type="button" variant="ghost" @click="onDelete">
        <Trash2 class="size-4" />
        Delete proxy
      </AppButton>
      <span v-else />
      <div class="flex items-center gap-2">
        <NuxtLink to="/socks5">
          <AppButton type="button" variant="secondary">Cancel</AppButton>
        </NuxtLink>
        <AppButton type="submit" :loading="submitting">
          <Save class="size-4" />
          Save proxy
        </AppButton>
      </div>
    </div>
  </form>
</template>
