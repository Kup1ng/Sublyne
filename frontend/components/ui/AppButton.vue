<script setup lang="ts">
import { Loader2 } from 'lucide-vue-next'
import { computed } from 'vue'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'subtle'
type Size = 'sm' | 'md' | 'lg'

const props = withDefaults(
  defineProps<{
    variant?: Variant
    size?: Size
    type?: 'button' | 'submit' | 'reset'
    loading?: boolean
    disabled?: boolean
    block?: boolean
  }>(),
  {
    variant: 'primary',
    size: 'md',
    type: 'button',
    loading: false,
    disabled: false,
    block: false,
  },
)

const cls = computed(() => {
  const base =
    'relative inline-flex items-center justify-center gap-2 font-medium rounded-xl transition active:translate-y-px disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none select-none whitespace-nowrap'
  const sizeMap: Record<Size, string> = {
    sm: 'h-8 px-3 text-[12.5px]',
    md: 'h-10 px-4 text-[13.5px]',
    lg: 'h-12 px-5 text-[14px]',
  }
  const variantMap: Record<Variant, string> = {
    // brand-strong is violet-700/600 (vs --brand which is violet-400 on
    // dark) — keeps white text legible at WCAG AA. The inset highlight
    // is a 1-px glossy top-edge that reads as "raised"; the drop shadow
    // grounds the button in the surface.
    primary:
      'text-white bg-brand-strong hover:bg-brand-strong/90 shadow-[0_1px_0_rgba(255,255,255,0.18)_inset,0_8px_24px_-12px_rgb(var(--brand-strong)/0.65)]',
    secondary:
      'border border-line bg-surface text-ink hover:bg-elevated hover:border-line/80',
    ghost: 'text-ink hover:bg-elevated',
    subtle: 'bg-brand-soft text-brand hover:bg-brand-soft/80',
    danger:
      'text-white bg-danger hover:bg-danger/90 shadow-[0_1px_0_rgba(255,255,255,0.15)_inset,0_8px_24px_-12px_rgb(var(--danger)/0.55)]',
  }
  return [base, sizeMap[props.size], variantMap[props.variant], props.block ? 'w-full' : '']
    .filter(Boolean)
    .join(' ')
})
</script>

<template>
  <button :type="type" :class="cls" :disabled="disabled || loading">
    <Loader2 v-if="loading" class="size-4 animate-spin" />
    <slot />
  </button>
</template>
