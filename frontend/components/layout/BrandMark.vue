<script setup lang="ts">
withDefaults(
  defineProps<{
    size?: 'sm' | 'md' | 'lg'
    showWord?: boolean
  }>(),
  { size: 'md', showWord: true },
)

const dims: Record<string, { box: string; text: string; gap: string }> = {
  sm: { box: 'size-7', text: 'text-[14px]', gap: 'gap-2' },
  md: { box: 'size-9', text: 'text-[15.5px]', gap: 'gap-2.5' },
  lg: { box: 'size-14', text: 'text-[18px]', gap: 'gap-3' },
}
</script>

<template>
  <span :class="`inline-flex items-center ${dims[size].gap}`">
    <!--
      Brand mark: a sub-line motif — three horizontal beams of
      decreasing length anchored on the left, suggesting a 'descending
      line' (sub-lyne). The middle beam glows with the brand gradient.
    -->
    <svg
      :class="`${dims[size].box} text-brand`"
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="Sublyne mark"
    >
      <defs>
        <linearGradient id="sublyne-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="rgb(var(--brand-edge))" />
          <stop offset="55%" stop-color="rgb(var(--brand))" />
          <stop offset="100%" stop-color="rgb(var(--accent))" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="28" height="28" rx="9" fill="rgb(var(--brand-soft))" />
      <rect
        x="2.5"
        y="2.5"
        width="27"
        height="27"
        rx="9"
        stroke="currentColor"
        stroke-opacity="0.25"
      />
      <rect x="7" y="9" width="18" height="2.5" rx="1.25" fill="currentColor" opacity="0.45" />
      <rect x="7" y="14.75" width="14" height="2.5" rx="1.25" fill="url(#sublyne-grad)" />
      <rect x="7" y="20.5" width="9" height="2.5" rx="1.25" fill="currentColor" opacity="0.45" />
    </svg>
    <span
      v-if="showWord"
      :class="`${dims[size].text} font-semibold tracking-[-0.012em] text-ink`"
    >
      Sublyne
    </span>
  </span>
</template>
