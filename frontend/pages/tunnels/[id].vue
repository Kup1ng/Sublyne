<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useToast } from '~/composables/useToast'
import { useTunnels } from '~/composables/useTunnels'
import type { Tunnel } from '~/types/api'

const route = useRoute()
const router = useRouter()
const tunnels = useTunnels()
const toast = useToast()
const drawer = useDrawer()

const id = Number(route.params.id)
const current = ref<Tunnel | null>(null)
const submitting = ref(false)
const errors = ref<Record<string, string>>({})
const confirmDelete = ref(false)

onMounted(async () => {
  try {
    current.value = await tunnels.get(id)
  } catch (e) {
    toast.error('Tunnel not found', (e as Error).message)
    router.push('/tunnels')
  }
})

async function onSubmit(value: Partial<Tunnel>) {
  submitting.value = true
  errors.value = {}
  try {
    // Reconcile the runtime state with the saved "enabled" flag so
    // toggling the switch on the edit form actually starts or stops
    // the dataplane — the PUT itself only updates the DB row.
    const wasEnabled = current.value?.enabled === true
    const wantsEnabled = value.enabled === true
    const t = await tunnels.update(id, value)
    current.value = t
    if (wantsEnabled !== wasEnabled) {
      try {
        if (wantsEnabled) await tunnels.start(id)
        else await tunnels.stop(id)
      } catch (lifecycleErr) {
        toast.error(
          wantsEnabled ? 'Saved but could not start' : 'Saved but could not stop',
          (lifecycleErr as Error).message,
        )
        return
      }
    }
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
    await tunnels.remove(id)
    toast.success('Tunnel deleted')
    router.push('/tunnels')
  } catch (e) {
    toast.error('Delete failed', (e as Error).message)
  } finally {
    confirmDelete.value = false
  }
}
</script>

<template>
  <Topbar
    :title="current?.name || 'Tunnel'"
    subtitle="Edit fields and save. Hot-reload applies most changes without dropping traffic."
    @open-menu="drawer.show"
  />

  <TunnelForm
    v-if="current"
    :initial="current"
    :submitting="submitting"
    :errors="errors"
    :on-delete="() => (confirmDelete = true)"
    @submit="onSubmit"
  />

  <AppDialog
    v-model:open="confirmDelete"
    title="Delete tunnel?"
    description="This stops the listener immediately and removes the configuration. Cannot be undone."
  >
    <p class="text-[13px] text-subtle">
      Confirming deletes <span class="font-semibold text-ink">{{ current?.name }}</span> from this server.
      The matching tunnel on the other side stays intact until you delete it there too.
    </p>
    <template #footer>
      <AppButton variant="secondary" @click="confirmDelete = false">Cancel</AppButton>
      <AppButton variant="danger" @click="doDelete">Delete tunnel</AppButton>
    </template>
  </AppDialog>
</template>
