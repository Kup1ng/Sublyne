// Small formatting helpers shared across pages. Default to en-US for
// consistency; the panel is English only.

const numberFmt = new Intl.NumberFormat('en-US')

export function formatNumber(n: number): string {
  return numberFmt.format(n)
}

export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function formatBitsPerSecond(bps: number): string {
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let v = bps
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function formatPercent(p: number, digits = 1): string {
  return `${p.toFixed(digits)}%`
}

export function formatDate(iso: string | number | Date): string {
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatRelative(iso: string | number | Date): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 1000) return 'just now'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}
