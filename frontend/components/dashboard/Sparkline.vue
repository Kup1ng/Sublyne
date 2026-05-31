<script setup lang="ts">
// Sparkline — a tiny, dependency-free canvas bandwidth graph for the live
// dashboard. No Chart.js: it draws an nload-style 30-second rolling window
// straight to a <canvas>, one cheap imperative redraw per data frame
// (coalesced through requestAnimationFrame), DPR-capped at 2 for
// crisp-but-cheap output, newest sample pinned to the right edge.
//
// Redesign notes (vs the first canvas version):
//   - Colours are resolved from the live theme tokens via
//     getComputedStyle. A canvas 2D context CANNOT resolve `var(--x)`
//     inside a colour string (it silently falls back to opaque black), so
//     the previous `rgb(var(--brand))` strings never rendered the intended
//     violet/cyan — the lines drew black. We read the raw `R G B` triplet
//     and build real rgba() strings instead, and re-resolve on theme flip.
//   - The line is a monotone-cubic spline (shape-preserving: it never
//     overshoots into fake peaks/valleys) over a lightly moving-averaged
//     series, so it reads as a trend instead of a row of spikes — while a
//     genuine multi-second burst still shows clearly.
//   - A soft vertical gradient fills under each line (denser near the top,
//     fading to nothing at the baseline) for visual weight without clutter.
//   - The Y axis auto-scales to a "nice" rounded ceiling computed from the
//     smoothed peak, so a single transient sample can't compress the rest
//     of the window, and the ceiling label (with auto Kbps/Mbps/Gbps unit)
//     plus a "30s" tag make the scale honest at a glance.
//   - A dot + colour-matched value pill rides the end of each line, so the
//     current number sits right on the data, not only in the tile above.

import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { formatBitsPerSecond } from '~/utils/format'

type Tone = 'brand' | 'accent' | 'ok'

const props = withDefaults(
  defineProps<{
    /** One entry per series; `data` is oldest→newest. */
    series: Array<{ data: number[]; tone?: Tone; label?: string }>
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
let mo: MutationObserver | null = null
let raf = 0
let cssW = 0
let cssH = 0

// --- theme token resolution -------------------------------------------

type RGB = [number, number, number]

function readToken(name: string, fallback: RGB): RGB {
  if (typeof window === 'undefined') return fallback
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  if (!raw) return fallback
  const parts = raw.split(/[\s,]+/).map((n) => Number(n))
  if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return fallback
  return [parts[0], parts[1], parts[2]]
}

function toneToken(tone?: Tone): RGB {
  switch (tone) {
    case 'accent':
      return readToken('--accent', [34, 211, 238])
    case 'ok':
      return readToken('--ok', [52, 211, 153])
    default:
      return readToken('--brand', [167, 139, 250])
  }
}

function rgba([r, g, b]: RGB, a: number): string {
  return `rgba(${r}, ${g}, ${b}, ${a})`
}

// --- maths -------------------------------------------------------------

// A light symmetric moving average: tempers single-sample jitter without
// erasing a sustained burst (a burst spanning ≥2 samples survives almost
// intact; a lone 1-frame blip is roughly halved but still visible).
function smooth(arr: number[]): number[] {
  const n = arr.length
  if (n < 3) return arr.slice()
  const out = new Array<number>(n)
  out[0] = arr[0] * 0.75 + arr[1] * 0.25
  out[n - 1] = arr[n - 1] * 0.75 + arr[n - 2] * 0.25
  for (let i = 1; i < n - 1; i++) out[i] = arr[i - 1] * 0.25 + arr[i] * 0.5 + arr[i + 1] * 0.25
  return out
}

// Round a value up to a clean 1 / 2 / 2.5 / 5 × 10ⁿ ceiling so the axis is
// stable frame-to-frame and reads as a sensible number.
function niceCeil(v: number): number {
  if (v <= 0) return 1
  const exp = Math.floor(Math.log10(v))
  const base = Math.pow(10, exp)
  const f = v / base
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10
  return nf * base
}

// Monotone-cubic (Fritsch–Carlson) path through uniformly-spaced points.
function tracePath(ctx: CanvasRenderingContext2D, xs: number[], ys: number[]) {
  const n = xs.length
  if (n === 0) return
  ctx.moveTo(xs[0], ys[0])
  if (n === 1) return
  if (n === 2) {
    ctx.lineTo(xs[1], ys[1])
    return
  }
  const dx = xs[1] - xs[0] // uniform spacing
  const slope: number[] = []
  for (let i = 0; i < n - 1; i++) slope.push((ys[i + 1] - ys[i]) / dx)
  const m = new Array<number>(n)
  m[0] = slope[0]
  m[n - 1] = slope[n - 2]
  for (let i = 1; i < n - 1; i++) {
    m[i] = slope[i - 1] * slope[i] <= 0 ? 0 : (slope[i - 1] + slope[i]) / 2
  }
  for (let i = 0; i < n - 1; i++) {
    if (slope[i] === 0) {
      m[i] = 0
      m[i + 1] = 0
      continue
    }
    const a = m[i] / slope[i]
    const b = m[i + 1] / slope[i]
    const s = a * a + b * b
    if (s > 9) {
      const t = 3 / Math.sqrt(s)
      m[i] = t * a * slope[i]
      m[i + 1] = t * b * slope[i]
    }
  }
  for (let i = 0; i < n - 1; i++) {
    ctx.bezierCurveTo(
      xs[i] + dx / 3,
      ys[i] + (m[i] * dx) / 3,
      xs[i + 1] - dx / 3,
      ys[i + 1] - (m[i + 1] * dx) / 3,
      xs[i + 1],
      ys[i + 1],
    )
  }
}

// --- draw --------------------------------------------------------------

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
  if (w < 2 || h < 2) return

  const line = readToken('--line', [38, 38, 47])
  const faint = readToken('--faint', [102, 102, 115])
  const surface = readToken('--surface', [19, 19, 24])

  const win = Math.max(2, props.window)
  const padTop = 12
  const padBottom = 6
  const plotTop = padTop
  const baseline = h - padBottom
  const plotH = baseline - plotTop
  const stepX = w / (win - 1)

  // Smooth every series first; the scale is computed on the smoothed peak
  // so one transient sample can't blow out the axis for the whole window.
  const prepared = props.series.map((s) => {
    const recent = s.data.length > win ? s.data.slice(-win) : s.data.slice()
    return { tone: s.tone, label: s.label, sm: smooth(recent), raw: recent }
  })

  let peak = 0
  for (const p of prepared) for (const v of p.sm) if (v > peak) peak = v
  // Seat the peak at ~85% of plot height, then snap to a clean ceiling.
  const scaleMax = niceCeil(peak / 0.85)

  // Gridlines: a baseline + a single subtle mid line. Quiet enough not to
  // compete with the data (gridline-subtle).
  ctx.lineWidth = 1
  ctx.strokeStyle = rgba(line, 0.9)
  ctx.beginPath()
  ctx.moveTo(0, baseline + 0.5)
  ctx.lineTo(w, baseline + 0.5)
  ctx.stroke()

  ctx.save()
  ctx.setLineDash([3, 4])
  ctx.strokeStyle = rgba(line, 0.55)
  ctx.beginPath()
  const midY = plotTop + plotH * 0.5
  ctx.moveTo(0, midY + 0.5)
  ctx.lineTo(w, midY + 0.5)
  ctx.stroke()
  ctx.restore()

  // Axis ceiling label (top-left) + rolling-window tag (bottom-right).
  ctx.font = '600 10.5px Inter, ui-sans-serif, system-ui, sans-serif'
  ctx.textBaseline = 'alphabetic'
  ctx.textAlign = 'left'
  ctx.fillStyle = rgba(faint, 1)
  ctx.fillText(formatBitsPerSecond(scaleMax), 1, padTop - 3)
  ctx.textAlign = 'right'
  ctx.fillText(`${props.window}s`, w - 1, baseline - 4)

  const yOf = (v: number) => plotTop + plotH - (Math.max(0, v) / scaleMax) * plotH

  // Draw the larger-magnitude series first so the smaller line+pill end up
  // on top and never hide under the bigger series' gradient fill.
  const order = prepared
    .map((p, i) => ({ p, i, last: p.sm.length ? p.sm[p.sm.length - 1] : 0 }))
    .sort((a, b) => b.last - a.last)

  const endpoints: Array<{ x: number; y: number; color: RGB; value: number }> = []

  for (const { p } of order) {
    const n = p.sm.length
    if (n < 1) continue
    const color = toneToken(p.tone)
    const x0 = w - (n - 1) * stepX
    const xs = p.sm.map((_, i) => x0 + i * stepX)
    const ys = p.sm.map((v) => yOf(v))

    if (n >= 2) {
      // Soft gradient fill under the curve.
      const grad = ctx.createLinearGradient(0, plotTop, 0, baseline)
      grad.addColorStop(0, rgba(color, 0.3))
      grad.addColorStop(0.55, rgba(color, 0.08))
      grad.addColorStop(1, rgba(color, 0))
      ctx.beginPath()
      tracePath(ctx, xs, ys)
      ctx.lineTo(xs[n - 1], baseline)
      ctx.lineTo(xs[0], baseline)
      ctx.closePath()
      ctx.fillStyle = grad
      ctx.fill()

      // The line itself, with a soft glow for the live-monitoring feel.
      ctx.save()
      ctx.beginPath()
      tracePath(ctx, xs, ys)
      ctx.strokeStyle = rgba(color, 1)
      ctx.lineWidth = 2
      ctx.lineJoin = 'round'
      ctx.lineCap = 'round'
      ctx.shadowColor = rgba(color, 0.45)
      ctx.shadowBlur = 7
      ctx.stroke()
      ctx.restore()
    }

    endpoints.push({ x: xs[n - 1], y: ys[n - 1], color, value: p.raw[n - 1] ?? 0 })
  }

  // End-of-line markers + current-value pills. Nudge apart if the two
  // series end too close to stay legible.
  endpoints.sort((a, b) => a.y - b.y)
  for (let i = 1; i < endpoints.length; i++) {
    if (endpoints[i].y - endpoints[i - 1].y < 15) endpoints[i].y = endpoints[i - 1].y + 15
  }
  for (const e of endpoints) {
    const ey = Math.min(baseline - 2, Math.max(plotTop + 8, e.y))

    // Dot on the line end.
    ctx.beginPath()
    ctx.fillStyle = rgba(e.color, 1)
    ctx.arc(Math.min(e.x, w - 1.5), Math.min(baseline - 1.5, Math.max(plotTop + 1.5, e.y)), 2.6, 0, Math.PI * 2)
    ctx.fill()

    // Value pill, right-aligned at the edge.
    const text = formatBitsPerSecond(e.value)
    ctx.font = '600 11px Inter, ui-sans-serif, system-ui, sans-serif'
    const tw = ctx.measureText(text).width
    const padX = 5
    const pillW = tw + padX * 2
    const pillH = 16
    const pillX = w - pillW - 1
    const pillY = ey - pillH / 2
    ctx.fillStyle = rgba(surface, 0.82)
    if (typeof ctx.roundRect === 'function') {
      ctx.beginPath()
      ctx.roundRect(pillX, pillY, pillW, pillH, 5)
      ctx.fill()
    } else {
      ctx.fillRect(pillX, pillY, pillW, pillH)
    }
    ctx.fillStyle = rgba(e.color, 1)
    ctx.textAlign = 'right'
    ctx.textBaseline = 'middle'
    ctx.fillText(text, w - 1 - padX, ey + 0.5)
    ctx.textBaseline = 'alphabetic'
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
watch(() => props.series, scheduleDraw, { deep: false })

const ariaLabel = computed(() => {
  const parts = props.series.map((s) => {
    const v = s.data.length ? s.data[s.data.length - 1] : 0
    return `${s.label ?? s.tone ?? 'series'} ${formatBitsPerSecond(v)}`
  })
  return `Bandwidth, last ${props.window} seconds. ${parts.join(', ')}.`
})

onMounted(() => {
  resize()
  ro = new ResizeObserver(() => resize())
  if (wrap.value) ro.observe(wrap.value)
  // Recolour immediately when the theme (.dark class on <html>) flips,
  // rather than waiting for the next data frame.
  mo = new MutationObserver(() => scheduleDraw())
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
})

onBeforeUnmount(() => {
  if (raf) cancelAnimationFrame(raf)
  if (ro) ro.disconnect()
  if (mo) mo.disconnect()
  ro = null
  mo = null
})
</script>

<template>
  <div
    ref="wrap"
    class="w-full"
    role="img"
    :aria-label="ariaLabel"
    :style="{ height: height + 'px' }"
  >
    <canvas ref="canvas" class="block h-full w-full" />
  </div>
</template>
