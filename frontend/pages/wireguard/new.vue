<script setup lang="ts">
import { ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useToast } from '~/composables/useToast'
import { useWireguard } from '~/composables/useWireguard'
import type { WireguardConfig } from '~/types/api'

const wg = useWireguard()
const toast = useToast()
const router = useRouter()
const drawer = useDrawer()

const submitting = ref(false)
const errors = ref<Record<string, string>>({})

async function onSubmit(value: Partial<WireguardConfig>) {
  submitting.value = true
  errors.value = {}
  try {
    const created = await wg.create(value as Partial<WireguardConfig> & { raw_text: string })
    toast.success('WireGuard config saved', created.name)
    router.push(`/wireguard/${created.id}`)
  } catch (e) {
    if (e instanceof ApiError) {
      errors.value = e.fields
      toast.error('Save failed', e.message)
    } else {
      toast.error('Save failed', (e as Error).message)
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Topbar
    title="Add WireGuard config"
    subtitle="Paste the seller's config text. DNS lines are ignored, Endpoint must be IP:port."
    @open-menu="drawer.show"
  />
  <WireguardForm :submitting="submitting" :errors="errors" @submit="onSubmit" />
</template>
