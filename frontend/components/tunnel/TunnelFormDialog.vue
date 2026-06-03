<script setup lang="ts">
import { AlertTriangle, Save, Trash2 } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useToast } from '~/composables/useToast'
import { useTunnels } from '~/composables/useTunnels'
import type { Tunnel } from '~/types/api'

// The create form lived at /tunnels/new and the edit form at
// /tunnels/:id. Both are now this modal, opened over the /tunnels list.
// The standalone pages remain as thin redirects so deep links keep
// working. The actual fields + validation live in <TunnelForm> — this
// wrapper only adds the dialog chrome, the fetch (edit), the submit
// branches (ported verbatim from the old pages), and the discard/delete
// confirmation step.

// HTML id used to associate the modal's pinned Save button with the
// form rendered in the dialog body (the button lives outside the
// <form> element but submits it via the `form` attribute).
const FORM_ID = 'tunnel-form'

const props = defineProps<{ open: boolean; tunnelId?: number | null }>()
const emit = defineEmits<{
  (e: 'update:open', v: boolean): void
  (e: 'saved', tunnel: Tunnel): void
  (e: 'deleted', id: number): void
}>()

const tunnels = useTunnels()
const toast = useToast()

const isEdit = computed(() => props.tunnelId != null)

const current = ref<Tunnel | null>(null)
const loading = ref(false)
const submitting = ref(false)
const deleting = ref(false)
const errors = ref<Record<string, string>>({})
const dirty = ref(false)
// null = form; 'discard'/'delete' = the matching confirmation layer.
const confirm = ref<null | 'discard' | 'delete'>(null)

// On each open: reset transient state, then (edit) fetch the tunnel so
// the modal shows exactly what GET /tunnels/:id returns — identical to
// the old edit page. AppDialog uses v-if, so <TunnelForm> remounts each
// open and re-captures its clean baseline.
watch(
  () => props.open,
  async (isOpen) => {
    if (!isOpen) return
    errors.value = {}
    confirm.value = null
    dirty.value = false
    deleting.value = false
    submitting.value = false
    if (props.tunnelId == null) {
      current.value = null
      loading.value = false
      return
    }
    loading.value = true
    current.value = null
    try {
      current.value = await tunnels.get(props.tunnelId)
    } catch (e) {
      toast.error('Tunnel not found', (e as Error).message)
      loading.value = false
      emit('update:open', false)
      return
    }
    loading.value = false
  },
)

function doClose() {
  emit('update:open', false)
}

// A close request (Escape, backdrop, Cancel, X) routes through here so
// an open confirmation layer cancels first, and unsaved edits prompt a
// discard confirmation instead of closing outright.
function attemptClose() {
  if (confirm.value) {
    confirm.value = null
    return
  }
  if (dirty.value) {
    confirm.value = 'discard'
    return
  }
  doClose()
}

function onDialogOpenChange(v: boolean) {
  if (!v) attemptClose()
}

function requestDelete() {
  confirm.value = 'delete'
}
function cancelConfirm() {
  confirm.value = null
}
function confirmAction() {
  if (confirm.value === 'discard') {
    dirty.value = false
    confirm.value = null
    doClose()
  } else if (confirm.value === 'delete') {
    void runDelete()
  }
}

async function runDelete() {
  if (props.tunnelId == null) return
  deleting.value = true
  try {
    const id = props.tunnelId
    await tunnels.remove(id)
    toast.success('Tunnel deleted')
    emit('deleted', id)
    confirm.value = null
    dirty.value = false
    doClose()
  } catch (e) {
    toast.error('Delete failed', (e as Error).message)
  } finally {
    deleting.value = false
  }
}

function finishSaved(t: Tunnel) {
  emit('saved', t)
  dirty.value = false
  doClose()
}

async function onSubmit(value: Partial<Tunnel>) {
  submitting.value = true
  errors.value = {}
  try {
    if (isEdit.value && props.tunnelId != null) {
      // EDIT — reconcile runtime state with the saved `enabled` flag and
      // surface the hot-reload envelope (ported from /tunnels/[id]).
      const id = props.tunnelId
      const wasEnabled = current.value?.enabled === true
      const wantsEnabled = value.enabled === true
      const t = await tunnels.update(id, value)
      if (wantsEnabled !== wasEnabled) {
        try {
          if (wantsEnabled) await tunnels.start(id)
          else await tunnels.stop(id)
        } catch (lifecycleErr) {
          toast.error(
            wantsEnabled ? 'Saved but could not start' : 'Saved but could not stop',
            (lifecycleErr as Error).message,
          )
          finishSaved(t)
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
      finishSaved(t)
    } else {
      // CREATE — backend forces new tunnels to Stopped; chain a Start if
      // the operator left "Will start" on (ported from /tunnels/new).
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
      finishSaved(t)
    }
  } catch (e) {
    // Validation / save errors keep the modal open and surface inline
    // under each field (TunnelForm reads `errors`), with a toast as a
    // secondary signal — the modal does not close on failure.
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

const confirmCopy = computed(() => {
  if (confirm.value === 'delete') {
    return {
      title: current.value ? `Delete “${current.value.name}”?` : 'Delete tunnel?',
      body:
        'This stops the listener immediately and removes the configuration from this server. ' +
        'The matching tunnel on the other side stays intact until you delete it there too. ' +
        'This can’t be undone.',
      confirmLabel: 'Delete tunnel',
      cancelLabel: 'Keep tunnel',
    }
  }
  return {
    title: 'Discard unsaved changes?',
    body: 'Your edits to this tunnel haven’t been saved yet. If you close now, they’ll be lost.',
    confirmLabel: 'Discard changes',
    cancelLabel: 'Keep editing',
  }
})
</script>

<template>
  <AppDialog
    :open="open"
    size="2xl"
    mobile-sheet
    body-class="bg-bg px-5 py-5 sm:px-6 sm:py-6"
    :title="isEdit ? 'Edit tunnel' : 'New tunnel'"
    :description="
      isEdit
        ? 'Update this port mapping. Hot-reload applies most changes without dropping traffic.'
        : 'Configure one port mapping. It stays stopped unless you switch it on.'
    "
    @update:open="onDialogOpenChange"
  >
    <div v-if="loading" class="grid place-items-center py-20">
      <AppSpinner />
    </div>
    <TunnelForm
      v-else
      :initial="current ?? undefined"
      :submitting="submitting"
      :errors="errors"
      embedded
      :form-id="FORM_ID"
      @submit="onSubmit"
      @update:dirty="(v) => (dirty = v)"
    />

    <template #footer>
      <div class="flex w-full items-center justify-between gap-3">
        <AppButton
          v-if="isEdit"
          type="button"
          variant="ghost"
          :disabled="submitting"
          @click="requestDelete"
        >
          <Trash2 class="size-4" />
          Delete
        </AppButton>
        <span v-else />
        <div class="flex items-center gap-2">
          <AppButton type="button" variant="secondary" :disabled="submitting" @click="attemptClose">
            Cancel
          </AppButton>
          <AppButton type="submit" :form="FORM_ID" :loading="submitting" :disabled="submitting">
            <Save class="size-4" />
            Save tunnel
          </AppButton>
        </div>
      </div>
    </template>
  </AppDialog>

  <!-- Confirmation layer (discard unsaved / delete). A teleported layer
       above the form modal rather than a stacked AppDialog, so it never
       double-binds Escape: Escape/backdrop here route through
       attemptClose, which just cancels the confirmation. The form stays
       mounted underneath, so "Keep editing" preserves every field. -->
  <Teleport to="body">
    <Transition
      enter-active-class="transition duration-150 ease-out"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="transition duration-100 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open && confirm"
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
        @click.self="cancelConfirm"
      >
        <div
          class="w-full max-w-sm rounded-2xl border border-line bg-surface p-6 text-center shadow-[0_24px_64px_-24px_rgba(0,0,0,0.55)] animate-popIn"
          role="alertdialog"
          aria-modal="true"
        >
          <div class="mx-auto grid size-12 place-items-center rounded-2xl bg-danger/12 text-danger">
            <AlertTriangle class="size-6" />
          </div>
          <h3 class="mt-4 text-[16px] font-semibold tracking-[-0.008em] text-ink">
            {{ confirmCopy.title }}
          </h3>
          <p class="mx-auto mt-1.5 max-w-xs text-[13px] leading-relaxed text-subtle">
            {{ confirmCopy.body }}
          </p>
          <div class="mt-5 flex items-center justify-center gap-2">
            <AppButton type="button" variant="secondary" :disabled="deleting" @click="cancelConfirm">
              {{ confirmCopy.cancelLabel }}
            </AppButton>
            <AppButton
              type="button"
              variant="danger"
              :loading="deleting"
              :disabled="deleting"
              @click="confirmAction"
            >
              {{ confirmCopy.confirmLabel }}
            </AppButton>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
