<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    modelValue?: string | null
    placeholder?: string
    rows?: number
    monospace?: boolean
    invalid?: boolean
    disabled?: boolean
  }>(),
  { rows: 8, monospace: false, invalid: false, disabled: false },
)
const emit = defineEmits<{ (e: 'update:modelValue', v: string): void }>()

const family = props.monospace
  ? 'font-mono text-[12.5px] leading-relaxed'
  : 'font-sans text-[13.5px]'
const border = props.invalid
  ? 'border-danger/60'
  : 'border-line/80 hover:border-line focus:border-brand/60 focus:bg-surface'
</script>

<template>
  <textarea
    :class="`block w-full rounded-xl border bg-elevated/50 p-3.5 text-ink placeholder:text-faint transition ${border} ${family}`"
    :placeholder="placeholder"
    :rows="rows"
    :disabled="disabled"
    :value="modelValue ?? ''"
    @input="(e) => emit('update:modelValue', (e.target as HTMLTextAreaElement).value)"
  />
</template>
