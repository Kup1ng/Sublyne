// tunables — pure helpers for the Performance settings section.
//
// The panel renders each performance tunable as a free-text numeric
// field. An empty field means "use the built-in default" (the panel
// sends null to clear any override); a filled field is parsed to an
// integer and bounds-checked against the tunable's [min, max] before
// save. The Go validator re-checks on PUT and may return per-field
// errors — these helpers only cover the client-side pass so the
// operator gets immediate feedback and we never PUT an obviously
// out-of-range value.
//
// All logic here is hermetic (no network, no DOM) so tunables.test.ts
// can exercise it directly.

import type { Tunable, TunablesUpdate } from '~/types/api'

// The string a tunable's input shows when it has no override. We bind
// inputs to strings (not numbers) so "" cleanly means "cleared".
export type DraftMap = Record<string, string>

// Per-field validation messages, keyed by tunable key. Empty = valid.
export type ErrorMap = Record<string, string>

/**
 * Turns a server value into the string the input field should hold.
 * An unset override (null) renders as an empty field so the placeholder
 * ("default: …") shows through.
 */
export function draftFromValue(value: number | null): string {
  return value === null || value === undefined ? '' : String(value)
}

/**
 * Builds the initial draft map from a list of tunables — one entry per
 * key, holding the current override (or "" when unset).
 */
export function draftsFromTunables(tunables: Tunable[]): DraftMap {
  const out: DraftMap = {}
  for (const t of tunables) {
    out[t.key] = draftFromValue(t.value)
  }
  return out
}

/**
 * Parses a draft string to an integer override, or null when the field
 * is empty (= clear the override / use the default). Returns NaN for a
 * non-integer so validate() can flag it; callers never send NaN.
 */
export function parseDraft(raw: string): number | null {
  const trimmed = raw.trim()
  if (trimmed === '') return null
  // Reject anything that isn't a plain base-10 integer (no "1e3", no
  // "1.5", no "12px") — these are whole-count knobs (bytes, packets,
  // worker threads).
  if (!/^-?\d+$/.test(trimmed)) return Number.NaN
  return Number(trimmed)
}

/**
 * Validates a single draft against a tunable's bounds. Returns an empty
 * string when valid, otherwise a human message suitable for the field.
 * An empty draft is always valid (it clears back to the default).
 */
export function validateDraft(raw: string, t: Tunable): string {
  const trimmed = raw.trim()
  if (trimmed === '') return ''
  const n = parseDraft(trimmed)
  if (n === null || Number.isNaN(n)) return 'Enter a whole number.'
  if (n < t.min || n > t.max) {
    return `Must be between ${t.min} and ${t.max}.`
  }
  return ''
}

/**
 * Validates every draft against its tunable. Returns a map of key →
 * message for the fields that fail; valid fields are omitted, so an
 * empty map means "all good".
 */
export function validateAll(drafts: DraftMap, tunables: Tunable[]): ErrorMap {
  const out: ErrorMap = {}
  for (const t of tunables) {
    const msg = validateDraft(drafts[t.key] ?? '', t)
    if (msg !== '') out[t.key] = msg
  }
  return out
}

/**
 * Diffs the current drafts against the server values and returns only
 * the fields that changed, in the PUT body shape ({name: number|null}).
 * A field that now holds a number it didn't before is set; a field that
 * was an override and is now empty is cleared (null); an unchanged field
 * is omitted entirely so the PUT touches nothing it shouldn't.
 *
 * Assumes the drafts already passed validateAll() — it parses with
 * parseDraft and skips any field that fails to parse, so a NaN never
 * reaches the wire.
 */
export function changedFields(drafts: DraftMap, tunables: Tunable[]): TunablesUpdate {
  const out: TunablesUpdate = {}
  for (const t of tunables) {
    const next = parseDraft(drafts[t.key] ?? '')
    if (Number.isNaN(next)) continue
    if (next !== t.value) out[t.key] = next
  }
  return out
}

/** Whether changedFields would send anything (drives the Save button). */
export function hasChanges(drafts: DraftMap, tunables: Tunable[]): boolean {
  return Object.keys(changedFields(drafts, tunables)).length > 0
}

/**
 * The placeholder for a tunable's empty input — what the dataplane will
 * use if no override is set. per_core_sockets' null default means the
 * dataplane auto-sizes to one worker per CPU core, so we say "auto".
 */
export function placeholderFor(t: Tunable): string {
  if (t.default === null || t.default === undefined) return 'auto'
  return `default: ${t.default}`
}
