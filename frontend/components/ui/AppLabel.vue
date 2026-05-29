<script setup lang="ts">
defineProps<{ for?: string; required?: boolean }>()
</script>

<template>
  <label :for="$props.for" class="block text-[12.5px] font-semibold tracking-[-0.005em] text-ink">
    <slot />
    <span v-if="required" class="ml-0.5 text-brand">*</span>
  </label>
</template>
