<script setup lang="ts">
import { ref } from 'vue'
import { Copy, Download, ShieldAlert } from 'lucide-vue-next'
import type { Tunnel } from '~/types/api'
import type { ApiError } from '~/composables/useApi'
import { useTunnels } from '~/composables/useTunnels'
import { useToast } from '~/composables/useToast'
import { downloadTextFile, copyText } from '~/utils/clientFile'

const props = defineProps<{
  open: boolean
  tunnel: Tunnel
}>()

const emit = defineEmits<{ (e: 'update:open', value: boolean): void }>()

const tunnels = useTunnels()
const toast = useToast()

const includeSecrets = ref(false)
const busy = ref(false)

function setOpen(v: boolean) {
  if (!v) includeSecrets.value = false
  emit('update:open', v)
}

async function onCopy() {
  busy.value = true
  try {
    const { text } = await tunnels.exportOne(props.tunnel.id, { secrets: includeSecrets.value })
    const ok = await copyText(text)
    if (ok) toast.success('Copied', 'Export JSON is on your clipboard.')
    else toast.error('Couldn’t copy', 'Use “Download .json” instead.')
  } catch (e) {
    toast.error('Export failed', (e as ApiError).message)
  } finally {
    busy.value = false
  }
}

async function onDownload() {
  busy.value = true
  try {
    const { filename, text } = await tunnels.exportOne(props.tunnel.id, {
      secrets: includeSecrets.value,
    })
    downloadTextFile(filename, text)
    toast.success('Downloaded', filename)
  } catch (e) {
    toast.error('Export failed', (e as ApiError).message)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppDialog
    :open="open"
    title="Export tunnel"
    description="Save this tunnel so you can recreate it on another Sublyne panel."
    @update:open="setOpen"
  >
    <div class="space-y-4">
      <p class="text-[13px] leading-relaxed text-subtle">
        This file recreates
        <span class="font-semibold text-ink">{{ tunnel.name }}</span>
        on another Sublyne panel. WireGuard configs and SOCKS5 proxies are referenced
        <span class="font-medium text-ink">by name</span> — the other panel must already have a
        WireGuard config / SOCKS5 proxy with the same name, or the import will be rejected. Their
        keys and passwords are never written to this file.
      </p>

      <div class="rounded-xl border border-line/70 bg-elevated/40 p-4">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="text-[13px] font-medium text-ink">Include secrets (pre-shared key)</div>
            <p class="mt-0.5 text-[12px] leading-relaxed text-subtle">
              Off by default. When off, the pre-shared key is stripped and you type it in on the
              other panel at import time.
            </p>
          </div>
          <AppSwitch v-model="includeSecrets" />
        </div>

        <div
          v-if="includeSecrets"
          class="mt-3 flex items-start gap-2 rounded-lg border border-warn/30 bg-warn/12 p-3 text-[12px] leading-relaxed text-subtle"
        >
          <ShieldAlert class="mt-0.5 size-4 shrink-0 text-warn" />
          <span>
            The file will contain this tunnel’s pre-shared key in plain text. Treat it like a
            password — anyone with the file can impersonate the tunnel. Prefer leaving this off and
            typing the key on the other panel.
          </span>
        </div>
      </div>
    </div>

    <template #footer>
      <AppButton variant="secondary" :disabled="busy" @click="setOpen(false)">Close</AppButton>
      <AppButton variant="secondary" :disabled="busy" @click="onCopy">
        <Copy class="size-4" />
        Copy to clipboard
      </AppButton>
      <AppButton :disabled="busy" @click="onDownload">
        <Download class="size-4" />
        Download .json
      </AppButton>
    </template>
  </AppDialog>
</template>
