<script setup lang="ts">
import { Check, AlertTriangle, Info, X } from 'lucide-vue-next'
import { useToast } from '~/composables/useToast'

const { toasts, dismiss } = useToast()
</script>

<template>
  <Teleport to="body">
    <div class="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2">
      <TransitionGroup
        enter-active-class="transition duration-200 ease-out"
        enter-from-class="opacity-0 translate-y-2"
        enter-to-class="opacity-100 translate-y-0"
        leave-active-class="transition duration-150 ease-in"
        leave-from-class="opacity-100"
        leave-to-class="opacity-0"
        move-class="transition"
        tag="div"
        class="flex flex-col gap-2"
      >
        <div
          v-for="t in toasts"
          :key="t.id"
          class="pointer-events-auto flex items-start gap-3 rounded-xl border border-line bg-surface px-3.5 py-3 shadow-soft animate-fadeIn"
        >
          <span
            :class="`mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-lg
              ${t.kind === 'success' ? 'bg-ok/15 text-ok' : ''}
              ${t.kind === 'error' ? 'bg-danger/15 text-danger' : ''}
              ${t.kind === 'info' ? 'bg-brand-soft text-brand' : ''}`"
          >
            <Check v-if="t.kind === 'success'" class="size-4" />
            <AlertTriangle v-else-if="t.kind === 'error'" class="size-4" />
            <Info v-else class="size-4" />
          </span>
          <div class="flex-1">
            <p class="text-[13.5px] font-medium text-ink">{{ t.title }}</p>
            <p v-if="t.body" class="text-[12.5px] text-subtle">{{ t.body }}</p>
          </div>
          <button
            type="button"
            class="inline-flex size-6 items-center justify-center rounded-md text-faint hover:text-ink"
            @click="dismiss(t.id)"
            aria-label="Dismiss"
          >
            <X class="size-3.5" />
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>
