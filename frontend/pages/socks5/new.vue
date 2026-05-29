<script setup lang="ts">
import { ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useSocks5 } from '~/composables/useSocks5'
import { useToast } from '~/composables/useToast'
import type { Socks5Proxy } from '~/types/api'

const socks = useSocks5()
const toast = useToast()
const router = useRouter()
const drawer = useDrawer()

const submitting = ref(false)
const errors = ref<Record<string, string>>({})

async function onSubmit(value: Partial<Socks5Proxy>) {
  submitting.value = true
  errors.value = {}
  try {
    const created = await socks.create(value)
    toast.success('Proxy saved', created.name)
    router.push(`/socks5/${created.id}`)
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
    title="Add SOCKS5 proxy"
    subtitle="N parallel TCP connections, one per Starlink uplink behind the load balancer."
    @open-menu="drawer.show"
  />
  <Socks5Form :submitting="submitting" :errors="errors" @submit="onSubmit" />
</template>
