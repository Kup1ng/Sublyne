<script setup lang="ts">
import { HelpCircle } from 'lucide-vue-next'

defineProps<{
  label: string
  help?: string
  hint?: string
  error?: string | null
  required?: boolean
}>()
</script>

<template>
  <div class="space-y-2">
    <div class="flex items-center gap-1.5">
      <AppLabel :required="required">{{ label }}</AppLabel>
      <span v-if="help" class="group relative inline-flex">
        <HelpCircle class="size-3.5 cursor-help text-faint transition hover:text-subtle" />
        <span
          class="pointer-events-none absolute left-5 top-0 z-30 w-72 origin-top-left scale-95 rounded-xl border border-line bg-elevated px-3 py-2.5 text-[12px] leading-relaxed text-subtle opacity-0 shadow-soft transition group-hover:scale-100 group-hover:opacity-100"
        >
          {{ help }}
        </span>
      </span>
    </div>
    <slot />
    <p v-if="hint && !error" class="text-[12px] leading-relaxed text-subtle">{{ hint }}</p>
    <p v-if="error" class="text-[12px] font-medium text-danger">{{ error }}</p>
  </div>
</template>
