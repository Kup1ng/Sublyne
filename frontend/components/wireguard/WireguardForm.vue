<script setup lang="ts">
import { Save, Trash2 } from 'lucide-vue-next'
import { ref, watchEffect } from 'vue'
import type { WireguardConfig } from '~/types/api'

const props = defineProps<{
  initial?: Partial<WireguardConfig>
  submitting?: boolean
  errors?: Record<string, string>
  onDelete?: (() => void) | null
}>()
const emit = defineEmits<{ (e: 'submit', value: Partial<WireguardConfig>): void }>()

const draft = ref<Partial<WireguardConfig>>({ ...props.initial })
watchEffect(() => {
  if (props.initial) draft.value = { ...draft.value, ...props.initial }
})

function err(field: string) {
  return props.errors?.[field] ?? null
}
</script>

<template>
  <form @submit.prevent="emit('submit', draft)" class="space-y-6">
    <AppCard title="WireGuard config" description="Paste the seller's full WireGuard config text exactly as given.">
      <div class="space-y-5">
        <FieldGroup
          label="Name"
          help="Free-form label. Must be unique on this server."
          :error="err('name')"
          required
        >
          <AppInput v-model="draft.name" :invalid="!!err('name')" placeholder="seller-starlink-A" />
        </FieldGroup>
        <FieldGroup
          label="Config text"
          help="Endpoint must be a literal IP:port — DNS hostnames aren't resolved inside the tunnel. Any DNS = ... lines are ignored."
          :error="err('raw_text')"
          required
        >
          <AppTextarea
            v-model="draft.raw_text"
            :invalid="!!err('raw_text')"
            :rows="14"
            monospace
            placeholder="[Interface]
PrivateKey = ...
Address = 10.0.0.2/24

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820"
          />
        </FieldGroup>
      </div>
    </AppCard>

    <div
      class="sticky bottom-0 -mx-6 flex items-center justify-between gap-2 border-t border-line/70 bg-bg/90 px-6 py-4 backdrop-blur-md md:-mx-10 md:px-10"
    >
      <AppButton v-if="onDelete" type="button" variant="ghost" @click="onDelete">
        <Trash2 class="size-4" />
        Delete config
      </AppButton>
      <span v-else />
      <div class="flex items-center gap-2">
        <NuxtLink to="/wireguard">
          <AppButton type="button" variant="secondary">Cancel</AppButton>
        </NuxtLink>
        <AppButton type="submit" :loading="submitting">
          <Save class="size-4" />
          Save config
        </AppButton>
      </div>
    </div>
  </form>
</template>
