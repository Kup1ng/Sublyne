<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useSocks5 } from '~/composables/useSocks5'
import { useToast } from '~/composables/useToast'
import type { Socks5Proxy } from '~/types/api'

const route = useRoute()
const router = useRouter()
const socks = useSocks5()
const toast = useToast()
const drawer = useDrawer()

const id = Number(route.params.id)
const current = ref<Socks5Proxy | null>(null)
const revealed = ref(false)
const submitting = ref(false)
const errors = ref<Record<string, string>>({})
const confirmDelete = ref(false)

async function load(reveal = false) {
  try {
    current.value = await socks.get(id, reveal)
    revealed.value = reveal
  } catch (e) {
    toast.error('Proxy not found', (e as Error).message)
    router.push('/socks5')
  }
}
onMounted(() => load(false))

async function onSubmit(value: Partial<Socks5Proxy>) {
  submitting.value = true
  errors.value = {}
  try {
    current.value = await socks.update(id, value)
    toast.success('Saved')
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

async function doDelete() {
  try {
    await socks.remove(id)
    toast.success('Proxy deleted')
    router.push('/socks5')
  } catch (e) {
    toast.error('Delete failed', (e as Error).message)
  } finally {
    confirmDelete.value = false
  }
}
</script>

<template>
  <Topbar
    :title="current?.name || 'SOCKS5 proxy'"
    subtitle="Editing parallel_connections live-resizes the pool on every tunnel using this proxy."
    @open-menu="drawer.show"
  >
    <template #actions>
      <AppButton v-if="!revealed" variant="secondary" size="sm" @click="load(true)">
        Reveal password
      </AppButton>
    </template>
  </Topbar>

  <Socks5Form
    v-if="current"
    :initial="current"
    :submitting="submitting"
    :errors="errors"
    :on-delete="() => (confirmDelete = true)"
    @submit="onSubmit"
  />

  <AppDialog v-model:open="confirmDelete" title="Delete SOCKS5 proxy?">
    <p class="text-[13px] text-subtle">
      Tunnels currently using
      <span class="font-semibold text-ink">{{ current?.name }}</span>
      must be detached or switched to WireGuard first.
    </p>
    <template #footer>
      <AppButton variant="secondary" @click="confirmDelete = false">Cancel</AppButton>
      <AppButton variant="danger" @click="doDelete">Delete</AppButton>
    </template>
  </AppDialog>
</template>
