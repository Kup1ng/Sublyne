<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useToast } from '~/composables/useToast'
import { useWireguard } from '~/composables/useWireguard'
import type { WireguardConfig } from '~/types/api'

const route = useRoute()
const router = useRouter()
const wg = useWireguard()
const toast = useToast()
const drawer = useDrawer()

const id = Number(route.params.id)
const current = ref<WireguardConfig | null>(null)
const revealed = ref(false)
const submitting = ref(false)
const errors = ref<Record<string, string>>({})
const confirmDelete = ref(false)

async function load(reveal = false) {
  try {
    current.value = await wg.get(id, reveal)
    revealed.value = reveal
  } catch (e) {
    toast.error('Config not found', (e as Error).message)
    router.push('/wireguard')
  }
}
onMounted(() => load(false))

async function onSubmit(value: Partial<WireguardConfig>) {
  submitting.value = true
  errors.value = {}
  try {
    current.value = await wg.update(id, value)
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
    await wg.remove(id)
    toast.success('Config deleted')
    router.push('/wireguard')
  } catch (e) {
    toast.error('Delete failed', (e as Error).message)
  } finally {
    confirmDelete.value = false
  }
}
</script>

<template>
  <Topbar
    :title="current?.name || 'WireGuard config'"
    subtitle="Edit or replace the pasted text. Active tunnels using this config will be re-keyed."
    @open-menu="drawer.show"
  >
    <template #actions>
      <AppButton v-if="!revealed" variant="secondary" size="sm" @click="load(true)">
        Reveal raw config
      </AppButton>
    </template>
  </Topbar>

  <WireguardForm
    v-if="current"
    :initial="current"
    :submitting="submitting"
    :errors="errors"
    :on-delete="() => (confirmDelete = true)"
    @submit="onSubmit"
  />

  <AppDialog
    v-model:open="confirmDelete"
    title="Delete WireGuard config?"
  >
    <p class="text-[13px] text-subtle">
      Tunnels currently referencing
      <span class="font-semibold text-ink">{{ current?.name }}</span>
      must be detached or deleted first.
    </p>
    <template #footer>
      <AppButton variant="secondary" @click="confirmDelete = false">Cancel</AppButton>
      <AppButton variant="danger" @click="doDelete">Delete</AppButton>
    </template>
  </AppDialog>
</template>
