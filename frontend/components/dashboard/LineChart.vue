<script setup lang="ts">
import {
  Chart as ChartJS,
  CategoryScale,
  Filler,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
  type ChartOptions,
} from 'chart.js'
import { LineChart as LineIcon } from 'lucide-vue-next'
import { computed } from 'vue'
import { Line } from 'vue-chartjs'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip)

const props = defineProps<{
  labels: string[]
  datasets: Array<{ label: string; data: number[]; tone?: 'brand' | 'accent' | 'ok' }>
  yFormatter?: (n: number) => string
  height?: number
}>()

function color(tone?: string): { line: string; fill: string } {
  switch (tone) {
    case 'accent':
      return { line: 'rgb(var(--accent))', fill: 'rgba(var(--accent), 0.10)' }
    case 'ok':
      return { line: 'rgb(var(--ok))', fill: 'rgba(var(--ok), 0.10)' }
    default:
      return { line: 'rgb(var(--brand))', fill: 'rgba(var(--brand), 0.10)' }
  }
}

// Show the chart only when there are enough points AND at least one
// dataset has a non-zero value. A flat-zero series renders as
// "-1.00 / 0.00 / 1.00 bps" gridlines with no line, which the
// audit flagged as visual noise on an empty dashboard.
const hasData = computed(() => {
  if (props.labels.length < 4) return false
  for (const d of props.datasets) {
    for (const v of d.data) {
      if (Math.abs(v) > 0) return true
    }
  }
  return false
})

const chartData = computed(() => ({
  labels: props.labels,
  datasets: props.datasets.map((d) => {
    const c = color(d.tone)
    return {
      label: d.label,
      data: d.data,
      borderColor: c.line,
      backgroundColor: c.fill,
      borderWidth: 1.75,
      tension: 0, // straight segments — cheaper, no Bezier per point
      pointRadius: 0,
      pointHitRadius: 8,
      fill: true,
    }
  }),
}))

// Cap the tick count so the auto-scaler doesn't render 11 stacked "0.10
// bps" labels on a flat empty series. We keep at most 4 horizontal
// gridlines, which matches the dashboard's visual weight.
const chartOptions = computed<ChartOptions<'line'>>(() => ({
  animation: false as const,
  responsive: true,
  maintainAspectRatio: false,
  devicePixelRatio: typeof window !== 'undefined' ? Math.min(window.devicePixelRatio, 2) : 1,
  scales: {
    x: { display: false, grid: { display: false } },
    y: {
      beginAtZero: true,
      grid: { color: 'rgba(127, 127, 138, 0.10)', drawTicks: false },
      ticks: {
        color: 'rgba(127, 127, 138, 0.75)',
        font: { size: 10 },
        maxTicksLimit: 4,
        padding: 6,
        callback: (v: number | string) =>
          props.yFormatter ? props.yFormatter(Number(v)) : String(v),
      },
      border: { display: false },
    },
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgb(var(--surface))',
      borderColor: 'rgb(var(--line))',
      borderWidth: 1,
      titleColor: 'rgb(var(--ink))',
      bodyColor: 'rgb(var(--subtle))',
      padding: 8,
      callbacks: {
        label: (ctx) =>
          `${ctx.dataset.label ?? ''}  ${props.yFormatter ? props.yFormatter(Number(ctx.parsed.y)) : String(ctx.parsed.y)}`,
      },
    },
  },
}))
</script>

<template>
  <div class="relative w-full" :style="{ height: (height ?? 220) + 'px' }">
    <div
      v-if="!hasData"
      class="flex h-full w-full flex-col items-center justify-center text-center"
    >
      <div class="grid size-11 place-items-center rounded-2xl bg-brand-soft text-brand">
        <LineIcon class="size-[18px]" />
      </div>
      <p class="mt-3.5 text-[13.5px] font-medium text-ink">Waiting for samples</p>
      <p class="mt-1 max-w-xs text-[12.5px] text-subtle">
        The chart starts plotting as soon as a tunnel begins forwarding traffic.
      </p>
    </div>
    <Line v-else :data="chartData" :options="chartOptions" />
  </div>
</template>
