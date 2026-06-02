<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { computed, onBeforeUnmount, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    open: boolean
    title?: string
    description?: string
    // Width tier. Default 'md' suits confirmations; 'xl' / '2xl' host the
    // taller tunnel form.
    size?: 'md' | 'lg' | 'xl' | '2xl'
    // When true the card is height-capped to the viewport and its body
    // scrolls internally, with the header + footer pinned — so a long form
    // never pushes the action buttons off-screen.
    scrollable?: boolean
  }>(),
  { size: 'md', scrollable: false },
)
const emit = defineEmits<{ (e: 'update:open', v: boolean): void }>()

const sizeClass = computed(
  () => ({ md: 'max-w-md', lg: 'max-w-lg', xl: 'max-w-xl', '2xl': 'max-w-2xl' })[props.size],
)

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
          :class="[
            'surface-card relative w-full animate-fadeIn shadow-[0_24px_64px_-24px_rgba(0,0,0,0.55)]',
            sizeClass,
            scrollable ? 'flex max-h-[calc(100dvh-2rem)] flex-col' : '',
          ]"
          role="document"
          @click.stop
        >
          <button
            type="button"
            class="absolute right-4 top-4 z-10 inline-flex size-8 items-center justify-center rounded-lg text-subtle transition hover:bg-elevated hover:text-ink"
            @click="close"
          >
            <X class="size-4" />
          </button>
          <div v-if="title" :class="['px-7 pr-14 pt-7', scrollable ? 'shrink-0' : '']">
            <h2 class="text-[17px] font-semibold tracking-[-0.008em] text-ink">{{ title }}</h2>
            <p v-if="description" class="mt-1.5 text-[13px] leading-relaxed text-subtle">
              {{ description }}
            </p>
          </div>
          <div :class="[scrollable ? 'flex-1 overflow-y-auto' : '', 'px-7 py-6']">
            <slot />
          </div>
          <div
            v-if="$slots.footer"
            :class="[
              'flex items-center justify-end gap-2 border-t border-line/70 px-7 py-4',
              scrollable ? 'shrink-0' : '',
            ]"
          >
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
