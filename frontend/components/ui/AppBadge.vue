<script setup lang="ts">
import { computed } from 'vue'

type Tone = 'neutral' | 'brand' | 'ok' | 'warn' | 'danger' | 'accent'

const props = withDefaults(defineProps<{ tone?: Tone; soft?: boolean; pulse?: boolean }>(), {
  tone: 'neutral',
  soft: true,
  pulse: false,
})

const dotColour: Record<Tone, string> = {
  neutral: 'bg-subtle',
  brand: 'bg-brand',
  ok: 'bg-ok',
  warn: 'bg-warn',
  danger: 'bg-danger',
  accent: 'bg-accent',
}

const cls = computed(() => {
  const t = props.tone
  if (props.soft) {
    const soft: Record<Tone, string> = {
      neutral: 'bg-muted text-subtle border-line/70',
      brand: 'bg-brand-soft text-brand border-brand/15',
      ok: 'bg-ok/12 text-ok border-ok/25',
      warn: 'bg-warn/12 text-warn border-warn/25',
      danger: 'bg-danger/12 text-danger border-danger/25',
      accent: 'bg-accent/12 text-accent border-accent/25',
    }
    return `inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11.5px] font-medium tracking-tight ${soft[t]}`
  }
  return `inline-flex items-center gap-1.5 rounded-full bg-ink px-2 py-0.5 text-[11.5px] font-medium tracking-tight text-bg`
})
</script>

<template>
  <span :class="cls">
    <span
      :class="`inline-block size-1.5 shrink-0 rounded-full ${dotColour[tone]} ${pulse ? 'animate-pulseSoft' : ''}`"
    />
    <slot />
  </span>
</template>
