<script setup lang="ts">
import { ref } from 'vue'
import { ApiError } from '~/composables/useApi'
import { useDrawer } from '~/composables/useDrawer'
import { useToast } from '~/composables/useToast'
import { useTunnels } from '~/composables/useTunnels'
import type { Tunnel } from '~/types/api'

const tunnels = useTunnels()
const toast = useToast()
const router = useRouter()
const drawer = useDrawer()

const submitting = ref(false)
const errors = ref<Record<string, string>>({})

async function onSubmit(value: Partial<Tunnel>) {
  submitting.value = true
  errors.value = {}
  try {
    // Backend forces every new tunnel to Stopped per PRD §3.6
    // (create-then-start lifecycle). If the operator left the
    // "Will start" toggle on, chain a Start call after the Create
    // so the saved tunnel ends in the state the form said it would.
    const wantsStart = value.enabled === true
    const t = await tunnels.create(value)
    if (wantsStart) {
      try {
        await tunnels.start(t.id)
        toast.success('Tunnel created and started', t.name)
      } catch (startErr) {
        // Surface the start failure without losing the fact that
        // create itself worked — operator may want to inspect the
        // dataplane log and retry the start manually.
        toast.error(
          'Tunnel saved but could not start',
          (startErr as Error).message,
        )
      }
    } else {
      toast.success('Tunnel created', t.name)
    }
    router.push(`/tunnels/${t.id}`)
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
  <Topbar title="New tunnel" subtitle="Configure one port mapping." @open-menu="drawer.show" />
  <TunnelForm :submitting="submitting" :errors="errors" @submit="onSubmit" />
</template>
