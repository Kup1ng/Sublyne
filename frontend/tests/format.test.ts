import { describe, expect, it } from 'vitest'
import {
  formatBitsPerSecond,
  formatBytes,
  formatNumber,
  formatPercent,
  formatRelative,
} from '~/utils/format'

describe('formatBytes', () => {
  it('formats binary multiples', () => {
    expect(formatBytes(0)).toBe('0.00 B')
    expect(formatBytes(1024)).toBe('1.00 KiB')
    expect(formatBytes(1024 * 1024)).toBe('1.00 MiB')
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.00 GiB')
  })
})

describe('formatBitsPerSecond', () => {
  it('formats decimal multiples', () => {
    expect(formatBitsPerSecond(0)).toBe('0.00 bps')
    expect(formatBitsPerSecond(1000)).toBe('1.00 Kbps')
    expect(formatBitsPerSecond(1_000_000)).toBe('1.00 Mbps')
    expect(formatBitsPerSecond(250_000_000)).toBe('250 Mbps')
  })
})

describe('formatNumber', () => {
  it('inserts thousands separators', () => {
    expect(formatNumber(1234567)).toBe('1,234,567')
  })
})

describe('formatPercent', () => {
  it('honours the digits argument', () => {
    expect(formatPercent(12.345, 1)).toBe('12.3%')
    expect(formatPercent(12.345, 2)).toBe('12.35%')
  })
})

describe('formatRelative', () => {
  it('produces human strings', () => {
    const now = Date.now()
    expect(formatRelative(new Date(now))).toMatch(/(just now|\ds ago)/)
    expect(formatRelative(new Date(now - 65 * 1000))).toBe('1m ago')
    expect(formatRelative(new Date(now - 2 * 3600 * 1000))).toBe('2h ago')
  })
})
