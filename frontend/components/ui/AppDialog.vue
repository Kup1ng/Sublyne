<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { onBeforeUnmount, watch } from 'vue'

const props = defineProps<{ open: boolean; title?: string; description?: string }>()
const emit = defineEmits<{ (e: 'update:open', v: boolean): void }>()

function close() {
  emit('update:open', false)
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') close()
}

watch(
  () => props.open,
  (v) => {
    if (typeof document === 'undefined') return
    if (v) {
      document.addEventListener('keydown', onKey)
      document.body.style.overflow = 'hidden'
    } else {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  },
)
onBeforeUnmount(() => {
  if (typeof document === 'undefined') return
  document.removeEventListener('keydown', onKey)
  document.body.style.overflow = ''
})
</script>

<template>
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
        v-if="open"
        class="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 backdrop-blur-md"
        role="dialog"
        aria-modal="true"
        @click.self="close"
      >
        <div
          class="surface-card relative w-full max-w-md animate-fadeIn shadow-[0_24px_64px_-24px_rgba(0,0,0,0.55)]"
          role="document"
          @click.stop
        >
          <button
            type="button"
            class="absolute right-4 top-4 inline-flex size-8 items-center justify-center rounded-lg text-subtle transition hover:bg-elevated hover:text-ink"
            @click="close"
          >
            <X class="size-4" />
          </button>
          <div v-if="title" class="px-7 pr-14 pt-7">
            <h2 class="text-[17px] font-semibold tracking-[-0.008em] text-ink">{{ title }}</h2>
            <p v-if="description" class="mt-1.5 text-[13px] leading-relaxed text-subtle">
              {{ description }}
            </p>
          </div>
          <div class="px-7 py-6">
            <slot />
          </div>
          <div
            v-if="$slots.footer"
            class="flex items-center justify-end gap-2 border-t border-line/70 px-7 py-4"
          >
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
