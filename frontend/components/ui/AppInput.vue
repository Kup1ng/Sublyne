<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue?: string | number | null
    type?: string
    placeholder?: string
    disabled?: boolean
    autocomplete?: string
    inputmode?: 'text' | 'numeric' | 'decimal' | 'tel' | 'email' | 'search' | 'url'
    invalid?: boolean
    monospace?: boolean
    autofocus?: boolean
  }>(),
  {
    type: 'text',
    invalid: false,
    monospace: false,
    autofocus: false,
  },
)
const emit = defineEmits<{
  (e: 'update:modelValue', v: string | number | null | undefined): void
  (e: 'enter'): void
}>()

const cls = computed(() => {
  const base =
    'block w-full h-10 rounded-xl border bg-elevated/50 px-3.5 text-[13.5px] text-ink placeholder:text-faint transition'
  const border = props.invalid
    ? 'border-danger/60'
    : 'border-line/80 hover:border-line focus:border-brand/60 focus:bg-surface'
  const family = props.monospace ? 'font-mono tracking-tight' : 'font-sans'
  return [base, border, family].join(' ')
})

function onInput(e: Event) {
  const t = e.target as HTMLInputElement
  // For numeric fields the backend rejects "1080" (string) — coerce
  // to a real number so the bound draft holds the right TS shape and
  // Go's strict-decoder doesn't fail with
  // "cannot unmarshal string into Go struct field …".
  if (props.type === 'number') {
    if (t.value === '') {
      // Cleared field: emit `undefined` (not null) so the form's
      // pickAllowed + JSON.stringify drop the key entirely. Posting JSON
      // `null` into a non-pointer Go int (mtu / port /
      // parallel_connections / min_ready_slots / …) fails the strict
      // decoder with a 400; an omitted field falls back to the backend
      // default instead.
      emit('update:modelValue', undefined)
      return
    }
    const n = Number(t.value)
    if (Number.isNaN(n)) return
    emit('update:modelValue', n)
    return
  }
  emit('update:modelValue', t.value)
}
</script>

<template>
  <input
    :class="cls"
    :type="type"
    :value="modelValue ?? ''"
    :placeholder="placeholder"
    :disabled="disabled"
    :autocomplete="autocomplete"
    :inputmode="inputmode"
    :autofocus="autofocus"
    @input="onInput"
    @keydown.enter="emit('enter')"
  />
</template>
