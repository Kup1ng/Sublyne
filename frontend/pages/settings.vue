<script setup lang="ts">
import { Download, KeyRound, Upload } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useAuth } from '~/composables/useAuth'
import { useBackup } from '~/composables/useBackup'
import { useDrawer } from '~/composables/useDrawer'
import { useSettings } from '~/composables/useSettings'
import { useToast } from '~/composables/useToast'

const settings = useSettings()
const auth = useAuth()
const backup = useBackup()
const toast = useToast()
const drawer = useDrawer()

const current = ref('')
const next = ref('')
const confirm = ref('')
const changing = ref(false)
const restoring = ref(false)

// Backend canonicalises to lowercase ("info" etc.) so the option
// values match the stored shape. We still surface uppercase labels
// because severity reads better in caps.
const levelOptions = [
  { value: 'trace', label: 'TRACE' },
  { value: 'debug', label: 'DEBUG' },
  { value: 'info', label: 'INFO' },
  { value: 'warn', label: 'WARN' },
  { value: 'error', label: 'ERROR' },
]

onMounted(() => settings.refresh())

async function setLevel(v: string) {
  try {
    await settings.setLogLevel(v)
    toast.success('Log level updated', `Now logging at ${v.toUpperCase()}`)
  } catch (e) {
    toast.error('Could not change log level', (e as Error).message)
  }
}

async function changePassword() {
  if (next.value.length < 8) {
    toast.error('Password too short', 'Use at least 8 characters.')
    return
  }
  if (next.value !== confirm.value) {
    toast.error('Passwords do not match')
    return
  }
  changing.value = true
  const res = await auth.changePassword(current.value, next.value)
  changing.value = false
  if (res.ok) {
    toast.success('Password changed', 'Existing sessions remain valid until they expire.')
    current.value = next.value = confirm.value = ''
  } else {
    toast.error('Could not change password', res.error)
  }
}

async function doBackup() {
  try {
    await backup.download()
    toast.success('Backup downloaded')
  } catch (e) {
    toast.error('Backup failed', (e as Error).message)
  }
}

async function onRestoreFile(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (!file) return
  restoring.value = true
  try {
    await backup.restore(file)
    toast.success(
      'Restore complete',
      'Tunnels, WG configs, and audit log replaced. Admin credentials and panel URL preserved.',
    )
  } catch (err) {
    toast.error('Restore failed', (err as Error).message)
  } finally {
    restoring.value = false
    ;(e.target as HTMLInputElement).value = ''
  }
}
</script>

<template>
  <Topbar title="Settings" subtitle="Admin credentials, log level, backup and restore." @open-menu="drawer.show" />

  <div class="space-y-6">
    <AppCard title="Server" description="What this install is and where it lives.">
      <dl class="grid gap-x-6 gap-y-5 md:grid-cols-2">
        <div>
          <dt class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">Role</dt>
          <dd class="mt-2">
            <AppBadge :tone="settings.view.value?.server_role === 'client' ? 'brand' : 'accent'">
              {{ settings.view.value?.server_role ?? '—' }}
            </AppBadge>
          </dd>
        </div>
        <div>
          <dt class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">Version</dt>
          <dd class="mt-2 font-mono text-[13.5px] text-ink">
            {{ settings.view.value?.version ?? '—' }}
          </dd>
        </div>
        <div>
          <dt class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">
            Panel port
          </dt>
          <dd class="mt-2 flex flex-wrap items-center gap-2">
            <span class="font-mono text-[13.5px] text-ink">
              {{ settings.view.value?.panel_port ?? '—' }}
            </span>
            <AppBadge tone="warn" :soft="true">restart required</AppBadge>
          </dd>
        </div>
        <div class="min-w-0">
          <dt class="text-[10.5px] font-medium uppercase tracking-[0.14em] text-faint">Web path</dt>
          <dd class="mt-2 flex flex-wrap items-center gap-2">
            <span class="truncate font-mono text-[13.5px] text-ink">
              /{{ settings.view.value?.web_path ?? '—' }}/
            </span>
            <AppBadge tone="warn" :soft="true">restart required</AppBadge>
          </dd>
        </div>
      </dl>
    </AppCard>

    <AppCard title="Log level" description="Applies immediately to both the control plane and the dataplane.">
      <FieldGroup
        label="Active level"
        help="Default INFO. TRACE/DEBUG are noisy under load; switch back to INFO once you're done."
      >
        <div class="max-w-xs">
          <AppSelect
            :model-value="(settings.view.value?.log_level ?? 'info').toLowerCase()"
            :options="levelOptions"
            @update:model-value="setLevel(String($event))"
          />
        </div>
      </FieldGroup>
    </AppCard>

    <AppCard
      title="Change admin password"
      description="Existing JWT sessions stay valid until their natural 31-day expiry."
    >
      <form @submit.prevent="changePassword" class="grid gap-5 md:grid-cols-3">
        <FieldGroup label="Current password" required>
          <AppInput v-model="current" type="password" autocomplete="current-password" />
        </FieldGroup>
        <FieldGroup label="New password" required>
          <AppInput v-model="next" type="password" autocomplete="new-password" />
        </FieldGroup>
        <FieldGroup label="Confirm new password" required>
          <AppInput v-model="confirm" type="password" autocomplete="new-password" />
        </FieldGroup>
        <div class="md:col-span-3 flex justify-end">
          <AppButton type="submit" :loading="changing">
            <KeyRound class="size-4" />
            Change password
          </AppButton>
        </div>
      </form>
    </AppCard>

    <AppCard
      title="Backup and restore"
      description="Backup downloads the entire SQLite file. Restore replaces every record except the admin row, panel port, and web path."
    >
      <div class="flex flex-wrap items-center gap-3">
        <AppButton variant="secondary" @click="doBackup">
          <Download class="size-4" />
          Download backup
        </AppButton>
        <label
          class="inline-flex h-10 cursor-pointer items-center gap-2 rounded-xl border border-line bg-surface px-4 text-sm font-medium text-ink hover:bg-elevated"
        >
          <Upload class="size-4" />
          {{ restoring ? 'Restoring…' : 'Restore from file' }}
          <input type="file" accept=".db" class="hidden" @change="onRestoreFile" />
        </label>
      </div>
    </AppCard>
  </div>
</template>
