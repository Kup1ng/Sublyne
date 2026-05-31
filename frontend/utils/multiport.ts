// multiport — parse + validate the "additional ports" the operator types
// into the tunnel form, as pure data + helpers (no Vue, fully testable).
//
// A multi-port tunnel carries several application ports through the one
// secure download-spoof / upload pipeline with a fixed 1:1 same-number
// mapping (client :8001 <-> remote :8001). The operator enters the EXTRA
// ports as a comma-separated string; the main port (taken from
// local_listen_addr / forward_target) is always included automatically.
//
// The Go validator is the source of truth — it hard-rejects an invalid
// `ports` list on save (range 1..65535, no dups, canonical port a member,
// <= 32 total, no cross-tunnel overlap). These helpers let the panel guide
// the operator BEFORE they submit and produce the exact `ports` array the
// API expects:  sorted, unique, [mainPort, ...extras].

/** Hard cap on the total number of application ports a tunnel may carry. */
export const MAX_PORTS_PER_TUNNEL = 32

/** Parsed result of the extras string: either valid ports or an error. */
export type ParseExtrasResult = { ok: true; extras: number[] } | { ok: false; error: string }

/**
 * Parse + validate the comma-separated "additional ports" string against
 * the tunnel's main port. `raw` is the operator's free text; `mainPort` is
 * the port of local_listen_addr (Client) / forward_target (Remote), or
 * undefined when the main address hasn't been filled in yet.
 *
 * Empty / whitespace-only input is a VALID single-port tunnel (ok with an
 * empty extras list). Otherwise every entry must be an integer in
 * 1..65535, none may duplicate another extra or equal the main port, and
 * the total (main + extras) must not exceed MAX_PORTS_PER_TUNNEL.
 */
export function parseExtraPorts(raw: string, mainPort?: number): ParseExtrasResult {
  const trimmed = raw.trim()
  if (trimmed === '') return { ok: true, extras: [] }

  const extras: number[] = []
  const seen = new Set<number>()
  for (const part of trimmed.split(',')) {
    const token = part.trim()
    if (token === '') continue // tolerate "8001, , 8002" / trailing commas
    if (!/^\d+$/.test(token)) {
      return { ok: false, error: `"${token}" is not a whole number.` }
    }
    const port = Number(token)
    if (port < 1 || port > 65535) {
      return { ok: false, error: `Port ${port} is out of range (1–65535).` }
    }
    if (mainPort !== undefined && port === mainPort) {
      return { ok: false, error: `Port ${port} is already the main port.` }
    }
    if (seen.has(port)) {
      return { ok: false, error: `Port ${port} is listed more than once.` }
    }
    seen.add(port)
    extras.push(port)
  }

  const total = (mainPort !== undefined ? 1 : 0) + extras.length
  if (total > MAX_PORTS_PER_TUNNEL) {
    return { ok: false, error: `Too many ports — at most ${MAX_PORTS_PER_TUNNEL} per tunnel.` }
  }

  return { ok: true, extras }
}

/**
 * Build the API `ports` array from a main port and the extras. Returns the
 * sorted, de-duplicated union [mainPort, ...extras] when there is at least
 * one extra, or undefined for a plain single-port tunnel (so the caller
 * omits `ports` from the request — wire-identical to legacy tunnels).
 */
export function buildPorts(mainPort: number | undefined, extras: number[]): number[] | undefined {
  if (!extras.length) return undefined
  if (mainPort === undefined) return undefined
  const all = Array.from(new Set([mainPort, ...extras]))
  all.sort((a, b) => a - b)
  return all
}

/**
 * Derive the "extras" text shown in the form when editing an existing
 * tunnel: the tunnel's `ports` minus the main port, comma-separated. Blank
 * when the tunnel is single-port (no `ports`, or only the main port).
 */
export function extrasFromPorts(ports: number[] | undefined, mainPort?: number): string {
  if (!ports || !ports.length) return ''
  return ports
    .filter((p) => p !== mainPort)
    .sort((a, b) => a - b)
    .join(', ')
}

/** Extract the port from a "host:port" address, or undefined if absent. */
export function portFromAddr(addr?: string): number | undefined {
  if (!addr) return undefined
  const idx = addr.lastIndexOf(':')
  if (idx < 0) return undefined
  const token = addr.slice(idx + 1).trim()
  if (!/^\d+$/.test(token)) return undefined
  const port = Number(token)
  if (port < 1 || port > 65535) return undefined
  return port
}
