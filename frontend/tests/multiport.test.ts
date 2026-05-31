import { describe, expect, it } from 'vitest'
import {
  MAX_PORTS_PER_TUNNEL,
  buildPorts,
  extrasFromPorts,
  parseExtraPorts,
  portFromAddr,
} from '~/utils/multiport'

// These encode the client-side multi-port contract the panel enforces
// before submit. The Go validator (control-plane/internal/tunnels:
// validation.go) is the source of truth and re-checks on save; these keep
// the panel from offering the operator a list the backend would reject.
describe('multiport.parseExtraPorts', () => {
  it('treats blank / whitespace input as a single-port tunnel', () => {
    expect(parseExtraPorts('', 8000)).toEqual({ ok: true, extras: [] })
    expect(parseExtraPorts('   ', 8000)).toEqual({ ok: true, extras: [] })
  })

  it('parses a comma-separated list, tolerating spaces and stray commas', () => {
    expect(parseExtraPorts('8001, 8002 ,8003', 8000)).toEqual({
      ok: true,
      extras: [8001, 8002, 8003],
    })
    expect(parseExtraPorts('8001, , 8002,', 8000)).toEqual({ ok: true, extras: [8001, 8002] })
  })

  it('rejects non-numeric entries', () => {
    const r = parseExtraPorts('8001, abc', 8000)
    expect(r.ok).toBe(false)
  })

  it('rejects out-of-range ports', () => {
    expect(parseExtraPorts('0', 8000).ok).toBe(false)
    expect(parseExtraPorts('65536', 8000).ok).toBe(false)
    expect(parseExtraPorts('65535', 8000)).toEqual({ ok: true, extras: [65535] })
  })

  it('rejects a duplicate extra', () => {
    expect(parseExtraPorts('8001, 8001', 8000).ok).toBe(false)
  })

  it('rejects an extra equal to the main port', () => {
    expect(parseExtraPorts('8000, 8001', 8000).ok).toBe(false)
  })

  it('rejects more than MAX_PORTS_PER_TUNNEL total (main + extras)', () => {
    // main port + 31 extras == 32 (allowed); + 32 extras == 33 (rejected).
    const ok = Array.from({ length: MAX_PORTS_PER_TUNNEL - 1 }, (_, i) => 9000 + i).join(',')
    expect(parseExtraPorts(ok, 8000).ok).toBe(true)
    const tooMany = Array.from({ length: MAX_PORTS_PER_TUNNEL }, (_, i) => 9000 + i).join(',')
    expect(parseExtraPorts(tooMany, 8000).ok).toBe(false)
  })

  it('validates even without a known main port', () => {
    expect(parseExtraPorts('8001, 8002')).toEqual({ ok: true, extras: [8001, 8002] })
  })
})

describe('multiport.buildPorts', () => {
  it('returns undefined for a single-port tunnel (no extras)', () => {
    expect(buildPorts(8000, [])).toBeUndefined()
  })

  it('builds a sorted, unique [main, ...extras] union', () => {
    expect(buildPorts(8000, [8002, 8001])).toEqual([8000, 8001, 8002])
  })

  it('drops a duplicate of the main port from the union', () => {
    // buildPorts is defensive even though parseExtraPorts already rejects
    // an extra equal to the main port.
    expect(buildPorts(8000, [8000, 8001])).toEqual([8000, 8001])
  })

  it('returns undefined when the main port is unknown', () => {
    expect(buildPorts(undefined, [8001])).toBeUndefined()
  })
})

describe('multiport.extrasFromPorts', () => {
  it('is blank for a single-port tunnel', () => {
    expect(extrasFromPorts(undefined, 8000)).toBe('')
    expect(extrasFromPorts([], 8000)).toBe('')
    expect(extrasFromPorts([8000], 8000)).toBe('')
  })

  it('lists the ports minus the main port, sorted', () => {
    expect(extrasFromPorts([8000, 8002, 8001], 8000)).toBe('8001, 8002')
  })
})

describe('multiport.portFromAddr', () => {
  it('extracts the port from host:port', () => {
    expect(portFromAddr('0.0.0.0:443')).toBe(443)
    expect(portFromAddr('192.0.2.10:8000')).toBe(8000)
  })

  it('returns undefined for missing / malformed input', () => {
    expect(portFromAddr(undefined)).toBeUndefined()
    expect(portFromAddr('0.0.0.0')).toBeUndefined()
    expect(portFromAddr('host:notaport')).toBeUndefined()
    expect(portFromAddr('host:99999')).toBeUndefined()
  })
})
