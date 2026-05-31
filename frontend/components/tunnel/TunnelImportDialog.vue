<script setup lang="ts">
import { ref } from 'vue'
import { Upload } from 'lucide-vue-next'
import type { Tunnel } from '~/types/api'
import type { ApiError } from '~/composables/useApi'
import { useTunnels } from '~/composables/useTunnels'
import { useToast } from '~/composables/useToast'

defineProps<{ open: boolean }>()

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void
  (e: 'imported', tunnel: Tunnel): void
}>()

const tunnels = useTunnels()
const toast = useToast()

const text = ref('')
const name = ref('')
const psk = ref('')
const busy = ref(false)
// banner holds file/type/version + resource-missing messages; per-field
// messages render under their input via errors[field].
const banner = ref('')
const errors = ref<Record<string, string>>({})

function reset() {
  text.value = ''
  name.value = ''
  psk.value = ''
  banner.value = ''
  errors.value = {}
}

function setOpen(v: boolean) {
  if (!v) reset()
  emit('update:open', v)
}

async function onFile(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const contents = await file.text()
  // Reset so re-picking the same file fires change again (mirrors settings.vue).
  input.value = ''
  text.value = contents
  banner.value = ''
  errors.value = {}
}

// Map the backend's per-field error keys. file/type/version + resource-missing
// keys surface in the top banner; psk and name (and any other tunnel field)
// render inline under their input.
function applyApiError(err: ApiError) {
  errors.value = {}
  banner.value = ''
  const fields = err.fields ?? {}

  if (fields.file) banner.value = fields.file
  if (fields.wireguard_config_name) {
    banner.value =
      fields.wireguard_config_name +
      ' Create a WireGuard config with that exact name on this panel first, then import again.'
  }
  if (fields.socks5_proxy_name) {
    banner.value =
      fields.socks5_proxy_name +
      ' Create a SOCKS5 proxy with that exact name on this panel first, then import again.'
  }
  if (fields.psk) errors.value.psk = fields.psk
  if (fields.name) errors.value.name = fields.name

  // Any remaining tunnel-field validation errors render inline too.
  for (const [k, v] of Object.entries(fields)) {
    if (
      k !== 'file' &&
      k !== 'psk' &&
      k !== 'name' &&
      k !== 'wireguard_config_name' &&
      k !== 'socks5_proxy_name'
    ) {
      errors.value[k] = v
    }
  }

  // Name clash (409) carries no fields — guide the operator to rename.
  if (err.status === 409) {
    errors.value.name = 'A tunnel with that name already exists — choose a different name.'
    if (!banner.value) banner.value = err.message
  }

  // Nothing field-specific matched: fall back to a banner so the user sees why.
  if (!banner.value && Object.keys(errors.value).length === 0) {
    banner.value = err.message || 'Import failed.'
  }
}

async function onSubmit() {
  if (!text.value.trim()) {
    banner.value = 'Paste the export JSON or choose a file first.'
    return
  }
  busy.value = true
  banner.value = ''
  errors.value = {}
  try {
    const created = await tunnels.importOne(text.value, {
      name: name.value.trim() || undefined,
      psk: psk.value || undefined,
    })
    toast.success('Imported', created.name)
    emit('imported', created)
    setOpen(false)
  } catch (e) {
    const err = e as ApiError
    if (typeof err.status === 'number') {
      applyApiError(err)
    } else {
      // Client-side parse / shape error from importOne (plain Error).
      banner.value = (err as Error).message || 'Import failed.'
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppDialog
    :open="open"
    title="Import tunnel"
    description="Recreate a tunnel from a Sublyne export file. It lands stopped so you can review it first."
    @update:open="setOpen"
  >
    <div class="space-y-5">
      <div
        v-if="banner"
        class="rounded-xl border border-danger/40 bg-danger/10 p-3 text-[12.5px] leading-relaxed text-danger"
      >
        {{ banner }}
      </div>

      <FieldGroup
        label="Export file or JSON"
        help="Paste the exported JSON, or choose a .sublyne-tunnel.json file."
      >
        <AppTextarea
          v-model="text"
          :rows="6"
          monospace
          placeholder='{ "type": "sublyne-tunnel-export", "schema_version": 1, … }'
        />
        <label
          class="mt-2 inline-flex h-9 cursor-pointer items-center gap-2 rounded-xl border border-line bg-surface px-3 text-[12.5px] font-medium text-ink transition hover:bg-elevated"
        >
          <Upload class="size-4" />
          <span>Choose file…</span>
          <input
            type="file"
            accept=".json,.sublyne-tunnel.json,application/json"
            class="hidden"
            @change="onFile"
          />
        </label>
      </FieldGroup>

      <FieldGroup
        label="Name"
        help="Optional. Override the tunnel name — useful if a tunnel with the same name already exists here."
        :error="errors.name || null"
      >
        <AppInput
          v-model="name"
          placeholder="Leave blank to keep the file’s name"
          :invalid="!!errors.name"
        />
      </FieldGroup>

      <FieldGroup
        label="Pre-shared key"
        help="Required if the file doesn’t include one (exported without secrets). Ignored if the file already carries a key."
        :error="errors.psk || null"
      >
        <AppInput
          v-model="psk"
          type="password"
          monospace
          autocomplete="off"
          placeholder="Paste the tunnel’s pre-shared key"
          :invalid="!!errors.psk"
        />
      </FieldGroup>
    </div>

    <template #footer>
      <AppButton variant="secondary" :disabled="busy" @click="setOpen(false)">Cancel</AppButton>
      <AppButton :loading="busy" :disabled="busy" @click="onSubmit">Import tunnel</AppButton>
    </template>
  </AppDialog>
</template>
