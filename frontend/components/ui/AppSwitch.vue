<script setup lang="ts">
// Accept boolean | undefined so callers can bind a Partial<Tunnel>
// field whose boolean fields are typed as optional. Undefined is
// treated as `false` everywhere.
const props = defineProps<{ modelValue?: boolean; disabled?: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()
function toggle() {
  if (!props.disabled) emit('update:modelValue', !props.modelValue)
}
</script>

<template>
  <button
    type="button"
    role="switch"
    :aria-checked="modelValue"
    :class="`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition ${modelValue ? 'bg-brand border-brand' : 'bg-muted border-line'} ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`"
    @click="toggle"
  >
    <span
      :class="`inline-block size-5 -translate-x-px transform rounded-full bg-white shadow-sm transition ${modelValue ? 'translate-x-[22px]' : 'translate-x-px'}`"
    />
  </button>
</template>
