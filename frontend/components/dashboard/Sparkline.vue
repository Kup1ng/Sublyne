<script setup lang="ts">
// Sparkline — a tiny, dependency-free canvas line graph for the live
// dashboard. Replaces the old vue-chartjs LineChart (which pulled in all
// of Chart.js and did a full re-render per frame). This draws an
// nload-style rolling window directly to a <canvas>: one cheap imperative
// redraw per data frame (coalesced through requestAnimationFrame), no
// reactive churn on the pixels, DPR capped at 2 for crisp-but-cheap
// output. The newest sample is pinned to the right edge and the window
// scrolls left, exactly like nload's terminal graph.

import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    /** One entry per series; `data` is oldest→newest. Up=brand, down=accent. */
    series: Array<{ data: number[]; tone?: 'brand' | 'accent' | 'ok' }>
    /** Max samples drawn (the rolling window width, in samples). */
    window?: number
    /** CSS pixel height of the canvas. */
    height?: number
  }>(),
  { window: 30, height: 132 },
)

const wrap = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
let ro: ResizeObserver | null = null
let raf = 0
let cssW = 0
let cssH = 0

function toneColor(tone?: string): { line: string; fill: string } {
  switch (tone) {
    case 'accent':
      return { line: 'rgb(var(--accent))', fill: 'rgba(var(--accent), 0.14)' }
    case 'ok':
      return { line: 'rgb(var(--ok))', fill: 'rgba(var(--ok), 0.14)' }
    default:
      return { line: 'rgb(var(--brand))', fill: 'rgba(var(--brand), 0.14)' }
  }
}

function resize() {
  const el = wrap.value
  const cv = canvas.value
  if (!el || !cv) return
  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  cssW = el.clientWidth
  cssH = props.height
  cv.width = Math.max(1, Math.round(cssW * dpr))
  cv.height = Math.max(1, Math.round(cssH * dpr))
  const ctx = cv.getContext('2d')
  // Draw in CSS pixels; the transform scales to device pixels.
  if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  draw()
}

function draw() {
  const cv = canvas.value
  if (!cv) return
  const ctx = cv.getContext('2d')
  if (!ctx) return
  const w = cssW
  const h = cssH
  ctx.clearRect(0, 0, w, h)

  const win = Math.max(2, props.window)
  // Shared scale across all series so up/down are visually comparable.
  let max = 1
  for (const s of props.series) {
    const start = Math.max(0, s.data.length - win)
    for (let i = start; i < s.data.length; i++) {
      if (s.data[i] > max) max = s.data[i]
    }
  }
  max *= 1.15 // a little headroom above the peak

  const pad = 2
  const plotH = h - pad * 2
  const stepX = w / (win - 1)

  for (const s of props.series) {
    const data = s.data.length > win ? s.data.slice(-win) : s.data
    const n = data.length
    if (n < 2) continue
    const c = toneColor(s.tone)
    // Right-align the newest sample to the right edge.
    const x0 = w - (n - 1) * stepX
    const yOf = (v: number) => pad + plotH - (v / max) * plotH

    // Filled area under the line.
    ctx.beginPath()
    ctx.moveTo(x0, yOf(data[0]))
    for (let i = 1; i < n; i++) ctx.lineTo(x0 + i * stepX, yOf(data[i]))
    ctx.lineTo(x0 + (n - 1) * stepX, h - pad)
    ctx.lineTo(x0, h - pad)
    ctx.closePath()
    ctx.fillStyle = c.fill
    ctx.fill()

    // The line itself.
    ctx.beginPath()
    ctx.moveTo(x0, yOf(data[0]))
    for (let i = 1; i < n; i++) ctx.lineTo(x0 + i * stepX, yOf(data[i]))
    ctx.strokeStyle = c.line
    ctx.lineWidth = 1.75
    ctx.lineJoin = 'round'
    ctx.stroke()
  }
}

function scheduleDraw() {
  if (raf) return
  raf = requestAnimationFrame(() => {
    raf = 0
    draw()
  })
}

// The parent rebuilds the `series` array each frame (its `data` arrays are
// replaced immutably by useMetrics), so the prop identity changes once per
// frame — watch it and coalesce the redraw into one rAF.
watch(() => props.series, scheduleDraw)

onMounted(() => {
  resize()
  ro = new ResizeObserver(() => resize())
  if (wrap.value) ro.observe(wrap.value)
})

onBeforeUnmount(() => {
  if (raf) cancelAnimationFrame(raf)
  if (ro) ro.disconnect()
  ro = null
})
</script>

<template>
  <div ref="wrap" class="w-full" :style="{ height: height + 'px' }">
    <canvas ref="canvas" class="block h-full w-full" />
  </div>
</template>
