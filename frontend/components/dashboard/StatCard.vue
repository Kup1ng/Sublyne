<script setup lang="ts">
defineProps<{
  label: string
  value: string
  hint?: string
  tone?: 'brand' | 'accent' | 'ok' | 'warn' | 'danger' | 'neutral'
  icon?: unknown
}>()
</script>

<template>
  <div class="surface-card relative overflow-hidden p-5">
    <div
      v-if="tone && tone !== 'neutral'"
      class="pointer-events-none absolute -right-10 -top-10 size-44 rounded-full opacity-35 blur-3xl"
      :class="{
        'bg-brand': tone === 'brand',
        'bg-accent': tone === 'accent',
        'bg-ok': tone === 'ok',
        'bg-warn': tone === 'warn',
        'bg-danger': tone === 'danger',
      }"
    />
    <div class="relative flex items-start justify-between gap-4">
      <div class="min-w-0">
        <p class="text-[11px] font-medium uppercase tracking-[0.14em] text-faint">{{ label }}</p>
        <p
          class="tabular mt-2.5 truncate text-[28px] font-semibold leading-none tracking-[-0.022em] text-ink"
        >
          {{ value }}
        </p>
        <p v-if="hint" class="mt-2 truncate text-[12.5px] text-subtle">{{ hint }}</p>
      </div>
      <div
        v-if="icon"
        :class="[
          'grid size-9 shrink-0 place-items-center rounded-xl border transition',
          tone === 'brand' && 'border-brand/20 bg-brand-soft text-brand',
          tone === 'accent' && 'border-accent/20 bg-accent/10 text-accent',
          tone === 'ok' && 'border-ok/20 bg-ok/10 text-ok',
          tone === 'warn' && 'border-warn/20 bg-warn/10 text-warn',
          tone === 'danger' && 'border-danger/20 bg-danger/10 text-danger',
          (!tone || tone === 'neutral') && 'border-line bg-elevated/40 text-subtle',
        ]"
      >
        <component :is="icon" class="size-4" />
      </div>
    </div>
  </div>
</template>
