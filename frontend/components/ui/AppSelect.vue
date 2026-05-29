<script setup lang="ts">
import { ChevronDown } from 'lucide-vue-next'

interface Option {
  value: string | number
  label: string
  // When true the option renders but cannot be chosen (grayed out).
  // Used by the tunnel form to show upload modes that exist but are
  // off-matrix for the selected download transport.
  disabled?: boolean
}

const props = defineProps<{
  modelValue: string | number | null | undefined
  options: Option[]
  disabled?: boolean
  invalid?: boolean
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: string | number): void }>()

function onChange(e: Event) {
  const v = (e.target as HTMLSelectElement).value
  // Preserve numeric inputs as numbers when the original options were numeric
  const numericOpt = props.options.find((o) => String(o.value) === v && typeof o.value === 'number')
  emit('update:modelValue', numericOpt ? (numericOpt.value as number) : v)
}
</script>

<template>
  <div class="relative">
    <select
      :class="`block w-full h-10 appearance-none rounded-xl border bg-elevated/50 pl-3.5 pr-9 text-[13.5px] text-ink transition focus:bg-surface focus:border-brand/60 ${invalid ? 'border-danger/60' : 'border-line/80 hover:border-line'}`"
      :value="modelValue ?? ''"
      :disabled="disabled"
      @change="onChange"
    >
      <option v-for="o in options" :key="o.value" :value="o.value" :disabled="o.disabled">
        {{ o.label }}
      </option>
    </select>
    <ChevronDown
      class="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-subtle"
    />
  </div>
</template>
