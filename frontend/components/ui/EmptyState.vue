<script setup lang="ts">
import { Sparkles } from 'lucide-vue-next'

withDefaults(
  defineProps<{
    title: string
    description?: string
    icon?: unknown
    /** Compact mode reduces the vertical padding by half. */
    compact?: boolean
  }>(),
  { compact: false },
)
</script>

<template>
  <div
    :class="[
      'flex flex-col items-center justify-center rounded-2xl border border-dashed border-line/70 bg-elevated/40 px-6 text-center',
      compact ? 'py-8' : 'py-10',
    ]"
  >
    <div
      class="mb-3.5 flex size-11 items-center justify-center rounded-2xl bg-brand-soft text-brand"
    >
      <component :is="icon || Sparkles" class="size-[18px]" />
    </div>
    <p class="text-[14.5px] font-semibold tracking-[-0.005em] text-ink">{{ title }}</p>
    <p v-if="description" class="mt-1.5 max-w-md text-[12.5px] leading-relaxed text-subtle">
      {{ description }}
    </p>
    <div v-if="$slots.actions" class="mt-4 flex items-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>
