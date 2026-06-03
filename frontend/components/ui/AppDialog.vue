<script lang="ts">
// Module-scoped counter so every dialog instance gets a stable, unique
// id for aria-labelledby without depending on Vue 3.5's useId().
let dialogUid = 0
</script>

<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

type DialogSize = 'sm' | 'md' | 'lg' | 'xl' | '2xl'

const props = withDefaults(
  defineProps<{
    open: boolean
    title?: string
    description?: string
    // Max width of the centered panel. Small confirm dialogs use the
    // default 'md'; tall forms pass '2xl'.
    size?: DialogSize
    // When true the panel fills the viewport as a sheet on narrow
    // screens (and becomes a centered card from `sm` up). Tall forms
    // turn this on; short confirm dialogs stay centered everywhere.
    mobileSheet?: boolean
    // Overrides the scroll-body padding. Defaults to the confirm-dialog
    // padding; a tall form passes its own (e.g. an app-bg content area).
    bodyClass?: string
  }>(),
  { size: 'md', mobileSheet: false },
)
const emit = defineEmits<{ (e: 'update:open', v: boolean): void }>()

const titleId = `app-dialog-title-${++dialogUid}`

// Panel ref + previously-focused element so we can move focus into the
// dialog on open and restore it to the trigger on close (a11y).
const panel = ref<HTMLElement | null>(null)
let previouslyFocused: HTMLElement | null = null

const maxWidth: Record<DialogSize, string> = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
  '2xl': 'max-w-2xl',
}

const overlayClass = computed(() =>
  [
    'fixed inset-0 z-40 flex items-center justify-center bg-black/70 backdrop-blur-md',
    props.mobileSheet ? 'p-0 sm:p-4' : 'p-4',
  ].join(' '),
)

const panelClass = computed(() => {
  const base =
    'relative flex w-full flex-col border border-line bg-surface outline-none shadow-[0_24px_64px_-24px_rgba(0,0,0,0.55)] animate-popIn'
  // A capped max-height + an overflow-y-auto body keeps the header and
  // footer pinned while only the content scrolls. mobileSheet fills the
  // screen below `sm` and snaps back to a centered card above it.
  const shape = props.mobileSheet
    ? 'h-full max-h-[100dvh] rounded-none sm:h-auto sm:max-h-[calc(100dvh-2rem)] sm:rounded-2xl'
    : 'max-h-[calc(100dvh-2rem)] rounded-2xl'
  return [base, shape, maxWidth[props.size]].join(' ')
})

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
      previouslyFocused = (document.activeElement as HTMLElement | null) ?? null
      document.addEventListener('keydown', onKey)
      document.body.style.overflow = 'hidden'
      nextTick(() => panel.value?.focus())
    } else {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
      previouslyFocused?.focus?.()
      previouslyFocused = null
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
      <div v-if="open" :class="overlayClass" @click.self="close">
        <div
          ref="panel"
          :class="panelClass"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="title ? titleId : undefined"
          tabindex="-1"
          @click.stop
        >
          <div v-if="title" class="shrink-0 px-7 pr-14 pt-7">
            <h2 :id="titleId" class="text-[17px] font-semibold tracking-[-0.008em] text-ink">
              {{ title }}
            </h2>
            <p v-if="description" class="mt-1.5 text-[13px] leading-relaxed text-subtle">
              {{ description }}
            </p>
          </div>

          <div class="min-h-0 flex-1 overflow-y-auto" :class="bodyClass ?? 'px-7 py-6'">
            <slot />
          </div>

          <div
            v-if="$slots.footer"
            class="flex shrink-0 items-center justify-end gap-2 border-t border-line/70 bg-surface px-7 py-4"
          >
            <slot name="footer" />
          </div>

          <button
            type="button"
            class="absolute right-4 top-4 inline-flex size-8 items-center justify-center rounded-lg text-subtle transition hover:bg-elevated hover:text-ink"
            aria-label="Close"
            @click="close"
          >
            <X class="size-4" />
          </button>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
