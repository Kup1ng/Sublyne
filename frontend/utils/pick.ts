// Tiny "pick allowed keys" helper. The Go control plane uses
// `json.DisallowUnknownFields()` on every input struct, so submitting
// the whole DTO (with id / created_at / updated_at / runtime fields
// from a GET response) fails the request with
//   400 "invalid request body: json: unknown field \"id\"".
//
// Composables run their update payloads through pickAllowed() to keep
// the wire body to the fields the backend's input struct actually
// declares.

export function pickAllowed<T extends object>(
  source: T,
  allowed: readonly (keyof T | string)[],
): Partial<T> {
  const out: Record<string, unknown> = {}
  const set = new Set<string>(allowed.map((k) => String(k)))
  for (const [k, v] of Object.entries(source)) {
    if (set.has(k)) out[k] = v
  }
  return out as Partial<T>
}
