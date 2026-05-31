// multiport — parse + validate the unified application-port list the
// operator types into the tunnel form, as pure data + helpers (no Vue,
// fully testable).
//
// Since v2.7.0 a tunnel's address fields (local_listen_addr / forward_target)
// carry only a HOST; every application port lives in one comma-separated
// list. All ports are first-class peers with a fixed 1:1 same-number mapping
// between Client and Remote (client :8001 <-> remote :8001) and identical
// forwarding quality — there is no "main port" vs "extra ports" distinction.
//
// The Go validator is the source of truth — it re-checks the list on save
// (range 1..65535, no dups, <= 32, no cross-tunnel overlap). These helpers
// let the panel guide the operator BEFORE they submit and produce the exact
// `ports` array the API expects: sorted and de-duplicated.

/** Hard cap on the number of application ports a tunnel may carry. */
export const MAX_PORTS_PER_TUNNEL = 32

/**
 * Parsed result of the ports string. `ports` is the valid list parsed so
 * far (so the form can show a live count even while the operator is mid-edit
 * with a trailing error); `error` is the first problem found, or null.
 */
export interface ParsePortsResult {
  ports: number[]
  error: string | null
}

/**
 * Parse + validate the comma-separated ports string. Empty / whitespace-only
 * input yields an empty list with NO error (the form shows count 0 and
 * blocks submit). Otherwise every entry must be a whole number in 1..65535,
 * none may repeat, and the total must not exceed MAX_PORTS_PER_TUNNEL.
 * Stray / empty tokens ("443, , 8001," / trailing commas) are tolerated.
 */
export function parsePorts(raw: string): ParsePortsResult {
  const ports: number[] = []
  const seen = new Set<number>()
  let error: string | null = null
  for (const part of raw.split(',')) {
    const token = part.trim()
    if (token === '') continue // tolerate "443, , 8001" / trailing commas
    if (!/^\d+$/.test(token)) {
      error = `"${token}" is not a whole number.`
      break
    }
    const port = Number(token)
    if (port < 1 || port > 65535) {
      error = `Port ${port} is out of range (1–65535).`
      break
    }
    if (seen.has(port)) {
      error = `Port ${port} is listed more than once.`
      break
    }
    seen.add(port)
    ports.push(port)
  }
  if (!error && ports.length > MAX_PORTS_PER_TUNNEL) {
    error = `Too many ports — at most ${MAX_PORTS_PER_TUNNEL} per tunnel.`
  }
  return { ports, error }
}

/**
 * Build the API `ports` array: the sorted, de-duplicated list. Returns
 * undefined for an empty list so the caller can keep `ports` out of the
 * request until at least one port is entered (the Go validator requires >= 1).
 */
export function buildPorts(ports: number[]): number[] | undefined {
  if (!ports.length) return undefined
  const all = Array.from(new Set(ports))
  all.sort((a, b) => a - b)
  return all
}

/**
 * Render an existing tunnel's `ports` for the form input: sorted,
 * comma-separated. Blank when the tunnel has no ports yet.
 */
export function portsToInput(ports: number[] | undefined): string {
  if (!ports || !ports.length) return ''
  return [...ports].sort((a, b) => a - b).join(', ')
}
