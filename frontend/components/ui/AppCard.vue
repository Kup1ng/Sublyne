<script setup lang="ts">
defineProps<{
  title?: string
  description?: string
  noPad?: boolean
  glow?: boolean
}>()
</script>

<template>
  <section :class="`surface-card animate-fadeIn ${glow ? 'shadow-glow' : ''}`">
    <header
      v-if="title || $slots.title || $slots.actions"
      class="flex items-start justify-between gap-4 px-6 py-5"
    >
      <div class="min-w-0">
        <h2 class="text-[15.5px] font-semibold tracking-[-0.008em] text-ink">
          <slot name="title">{{ title }}</slot>
        </h2>
        <p v-if="description || $slots.description" class="mt-1 text-[12.5px] leading-relaxed text-subtle">
          <slot name="description">{{ description }}</slot>
        </p>
      </div>
      <div v-if="$slots.actions" class="flex shrink-0 items-center gap-2">
        <slot name="actions" />
      </div>
    </header>
    <div
      :class="
        !noPad
          ? title || $slots.title || $slots.actions
            ? 'px-6 pb-6'
            : 'p-6'
          : ''
      "
    >
      <slot />
    </div>
    <footer v-if="$slots.footer" class="border-t border-line/70 px-6 py-4">
      <slot name="footer" />
    </footer>
  </section>
</template>
