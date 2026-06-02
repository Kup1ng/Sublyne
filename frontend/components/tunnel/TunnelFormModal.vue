<script setup lang="ts">
import { Save, Trash2 } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useToast } from '~/composables/useToast'
import { useTunnels } from '~/composables/useTunnels'
import type { Tunnel } from '~/types/api'
import TunnelForm from '~/components/tunnel/TunnelForm.vue'

const props = defineProps<{ open: boolean; tunnelId?: number | null }>()
const emit = defineEmits<{
  (e: 'update:open', v: boolean): void
  (e: 'saved', t: Tunnel): void
}>()

const tunnels = useTunnels()
const toast = useToast()

const isEdit = computed(() => !!props.tunnelId)
const submitting = ref(false)
const errors = ref<Record<string, string>>({})
const current = ref<Tunnel | null>(null)
const confirmDelete = ref(false)
const formRef = ref<{ submit: () => void } | null>(null)
// Bumped on every open so the form remounts fresh — no stale draft when the
// same modal instance is reused for a different tunnel (or create vs edit).
const formKey = ref(0)

// Load (edit) or reset (create) whenever the modal opens or its target id
// changes. The form is v-if-gated on `current` for edit so it mounts with
// stable initial data — matching the old standalone edit page.
watch(
  () => [props.open, props.tunnelId] as const,
  async ([open, id]) => {
    if (!open) return
    errors.value = {}
    formKey.value += 1
    if (id) {
      current.value = null
      try {
        current.value = await tunnels.get(id)
      } catch (e) {
        toast.error('Could not load tunnel', (e as Error).message)
        close()
      }
    } else {
      current.value = null
    }
  },
  { immediate: true },
)

function close() {
  emit('update:open', false)
}
function requestSubmit() {
  formRef.value?.submit()
}

async function onSubmit(value: Partial<Tunnel>) {
  submitting.value = true
  errors.value = {}
  try {
    if (props.tunnelId) {
      // Edit: reconcile the runtime state with the saved `enabled` flag,
      // then surface the hot-reload envelope (moved verbatim from the old
      // /tunnels/[id] page).
      const wasEnabled = current.value?.enabled === true
      const wantsEnabled = value.enabled === true
      const t = await tunnels.update(props.tunnelId, value)
      if (wantsEnabled !== wasEnabled) {
        try {
          if (wantsEnabled) await tunnels.start(props.tunnelId)
          else await tunnels.stop(props.tunnelId)
        } catch (lifecycleErr) {
          toast.error(
            wantsEnabled ? 'Saved but could not start' : 'Saved but could not stop',
            (lifecycleErr as Error).message,
          )
          emit('saved', t)
          close()
          return
        }
      }
      if (t.dataplane_error) {
        toast.error('Saved, but the live update failed', t.dataplane_error)
      } else if (t.restart_required) {
        toast.info(
          'Saved — restart needed to apply',
          t.restart_required_message || 'Stop and Start this tunnel for the change to take effect.',
        )
      } else {
        toast.success('Saved')
      }
      emit('saved', t)
      close()
    } else {
      // Create: backend forces Stopped; chain a Start if the form asked for
      // it (moved verbatim from the old /tunnels/new page).
      const wantsStart = value.enabled === true
      const t = await tunnels.create(value)
      if (wantsStart) {
        try {
          await tunnels.start(t.id)
          toast.success('Tunnel created and started', t.name)
        } catch (startErr) {
          toast.error('Tunnel saved but could not start', (startErr as Error).message)
        }
      } else {
        toast.success('Tunnel created', t.name)
      }
      emit('saved', t)
      close()
    }
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
  if (!props.tunnelId) return
  const deleted = current.value
  try {
    await tunnels.remove(props.tunnelId)
    toast.success('Tunnel deleted')
    confirmDelete.value = false
    if (deleted) emit('saved', deleted)
    close()
  } catch (e) {
    toast.error('Delete failed', (e as Error).message)
  }
}
</script>

<template>
  <AppDialog
    :open="open"
    size="2xl"
    scrollable
    :title="isEdit ? 'Edit tunnel' : 'New tunnel'"
    :description="
      isEdit
        ? 'Changes hot-reload where possible; some need a Stop and Start.'
        : 'Configure one tunnel. Both servers share the PSK and matching settings.'
    "
    @update:open="(v) => !v && close()"
  >
    <div v-if="isEdit && !current" class="py-12 text-center text-[13px] text-subtle">Loading…</div>
    <TunnelForm
      v-else
      ref="formRef"
      :key="formKey"
      :initial="current ?? undefined"
      :submitting="submitting"
      :errors="errors"
      in-modal
      @submit="onSubmit"
      @cancel="close"
    />
    <template #footer>
      <AppButton
        v-if="isEdit"
        type="button"
        variant="ghost"
        class="mr-auto"
        @click="confirmDelete = true"
      >
        <Trash2 class="size-4" />
        Delete
      </AppButton>
      <AppButton type="button" variant="secondary" @click="close">Cancel</AppButton>
      <AppButton type="button" :loading="submitting" @click="requestSubmit">
        <Save class="size-4" />
        Save tunnel
      </AppButton>
    </template>
  </AppDialog>

  <AppDialog
    v-model:open="confirmDelete"
    title="Delete tunnel?"
    description="This stops the listener immediately and removes the configuration. Cannot be undone."
  >
    <p class="text-[13px] text-subtle">
      Confirming deletes
      <span class="font-semibold text-ink">{{ current?.name }}</span>
      from this server. The matching tunnel on the other side stays intact until you delete it there
      too.
    </p>
    <template #footer>
      <AppButton variant="secondary" @click="confirmDelete = false">Cancel</AppButton>
      <AppButton variant="danger" @click="doDelete">Delete tunnel</AppButton>
    </template>
  </AppDialog>
</template>
