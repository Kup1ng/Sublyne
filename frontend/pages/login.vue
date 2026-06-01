<script setup lang="ts">
import { LockKeyhole } from 'lucide-vue-next'
import { ref } from 'vue'
import { useAuth } from '~/composables/useAuth'

definePageMeta({ layout: 'auth' })

const auth = useAuth()
const router = useRouter()
const route = useRoute()

const username = ref('')
const password = ref('')
const submitting = ref(false)
const error = ref<string | null>(null)

async function submit() {
  error.value = null
  submitting.value = true
  try {
    const res = await auth.login(username.value, password.value)
    if (!res.ok) {
      error.value = res.error ?? 'Sign in failed.'
      return
    }
    const next = (route.query.next as string) || '/dashboard'
    router.push(next)
  } catch (e) {
    // auth.login re-throws non-ApiError failures (a dropped connection,
    // or a non-401 on the post-login /session refresh). Without this
    // catch the spinner would just stop with no message, leaving the
    // operator clicking Sign in with no feedback.
    error.value = (e as Error)?.message || 'Sign in failed — check the connection and try again.'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="w-full max-w-[400px] space-y-7">
    <div class="flex flex-col items-center text-center">
      <BrandMark size="lg" :show-word="false" class="mb-5" />
      <h1 class="text-[32px] font-semibold leading-none tracking-[-0.022em] text-ink">
        <span class="brand-text">Sublyne</span>
      </h1>
      <p class="mt-2.5 text-[14px] text-subtle">A quiet lifeline. Sign in to continue.</p>
    </div>

    <AppCard glow>
      <form @submit.prevent="submit" class="space-y-5">
        <FieldGroup label="Username" required>
          <AppInput
            v-model="username"
            autocomplete="username"
            placeholder="admin"
            autofocus
          />
        </FieldGroup>
        <FieldGroup label="Password" required>
          <AppInput
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="••••••••"
          />
        </FieldGroup>
        <p
          v-if="error"
          class="rounded-xl border border-danger/30 bg-danger/10 px-3.5 py-2.5 text-[12.5px] text-danger"
        >
          {{ error }}
        </p>
        <AppButton type="submit" size="lg" block :loading="submitting">
          <LockKeyhole class="size-4" />
          Sign in
        </AppButton>
      </form>
    </AppCard>

    <p class="text-center text-[12.5px] text-faint">
      Forgot your password? Run
      <code class="rounded bg-muted px-1.5 py-0.5 font-mono text-[11.5px] text-subtle">
        sublyne --reset-admin
      </code>
      on the host.
    </p>
  </div>
</template>
