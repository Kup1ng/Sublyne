import { describe, expect, it } from 'vitest'
import { MAX_PORTS_PER_TUNNEL, buildPorts, parsePorts, portsToInput } from '~/utils/multiport'

// The unified ports list the panel enforces before submit. The Go validator
// (control-plane/internal/tunnels/validation.go) is the source of truth and
// re-checks on save; these keep the panel from offering the operator a list
// the backend would reject.
describe('multiport.parsePorts', () => {
  it('treats blank / whitespace input as an empty list with no error', () => {
    expect(parsePorts('')).toEqual({ ports: [], error: null })
    expect(parsePorts('   ')).toEqual({ ports: [], error: null })
  })

  it('parses a comma-separated list, tolerating spaces and stray commas', () => {
    expect(parsePorts('443, 8001 ,8002')).toEqual({ ports: [443, 8001, 8002], error: null })
    expect(parsePorts('443, , 8001,')).toEqual({ ports: [443, 8001], error: null })
  })

  it('reports an error but keeps the valid prefix (for the live count)', () => {
    const r = parsePorts('443, abc')
    expect(r.error).not.toBeNull()
    expect(r.ports).toEqual([443])
  })

  it('rejects out-of-range ports', () => {
    expect(parsePorts('0').error).not.toBeNull()
    expect(parsePorts('65536').error).not.toBeNull()
    expect(parsePorts('65535')).toEqual({ ports: [65535], error: null })
  })

  it('rejects a duplicate port', () => {
    expect(parsePorts('443, 443').error).not.toBeNull()
  })

  it('rejects more than MAX_PORTS_PER_TUNNEL', () => {
    const ok = Array.from({ length: MAX_PORTS_PER_TUNNEL }, (_, i) => 9000 + i).join(',')
    expect(parsePorts(ok).error).toBeNull()
    const tooMany = Array.from({ length: MAX_PORTS_PER_TUNNEL + 1 }, (_, i) => 9000 + i).join(',')
    expect(parsePorts(tooMany).error).not.toBeNull()
  })
})

describe('multiport.buildPorts', () => {
  it('returns undefined for an empty list', () => {
    expect(buildPorts([])).toBeUndefined()
  })

  it('sorts and de-duplicates', () => {
    expect(buildPorts([8002, 443, 8001])).toEqual([443, 8001, 8002])
    expect(buildPorts([443, 443, 8001])).toEqual([443, 8001])
  })
})

describe('multiport.portsToInput', () => {
  it('is blank when there are no ports', () => {
    expect(portsToInput(undefined)).toBe('')
    expect(portsToInput([])).toBe('')
  })

  it('renders a sorted, comma-separated list', () => {
    expect(portsToInput([8002, 443, 8001])).toBe('443, 8001, 8002')
  })
})
