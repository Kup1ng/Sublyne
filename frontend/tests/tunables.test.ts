import { describe, expect, it } from 'vitest'
import type { Tunable } from '~/types/api'
import {
  changedFields,
  draftFromValue,
  draftsFromTunables,
  hasChanges,
  parseDraft,
  placeholderFor,
  validateAll,
  validateDraft,
} from '~/utils/tunables'

// A small fixture mirroring the four tunables the Go control plane
// reports on GET /settings/tunables. per_core_sockets carries a null
// default (= "auto") and is the interesting edge case throughout.
function fixture(): Tunable[] {
  return [
    {
      key: 'socket_buf_bytes',
      env: 'SUBLYNE_SOCKET_BUF_BYTES',
      value: null,
      default: 4194304,
      min: 262144,
      max: 16777216,
      unit: 'bytes',
      label: 'Socket buffer size',
      help: 'Per-socket send/recv buffer.',
    },
    {
      key: 'recv_batch',
      value: 32,
      default: 16,
      min: 1,
      max: 64,
      unit: 'packets',
      label: 'Receive batch size',
      help: 'Packets per recvmmsg call.',
    },
    {
      key: 'send_batch',
      value: null,
      default: 16,
      min: 1,
      max: 64,
      unit: 'packets',
      label: 'Send batch size',
      help: 'Packets per sendmmsg call.',
    },
    {
      key: 'per_core_sockets',
      value: null,
      default: null,
      min: 1,
      max: 64,
      unit: 'workers',
      label: 'Worker threads',
      help: 'One per CPU core when unset.',
    },
  ]
}

describe('draftFromValue', () => {
  it('renders null as an empty string', () => {
    expect(draftFromValue(null)).toBe('')
  })

  it('renders a number as its decimal string', () => {
    expect(draftFromValue(16)).toBe('16')
  })
})

describe('draftsFromTunables', () => {
  it('seeds one draft per key with the current override or ""', () => {
    expect(draftsFromTunables(fixture())).toEqual({
      socket_buf_bytes: '',
      recv_batch: '32',
      send_batch: '',
      per_core_sockets: '',
    })
  })
})

describe('parseDraft', () => {
  it('treats an empty / whitespace field as a clear (null)', () => {
    expect(parseDraft('')).toBeNull()
    expect(parseDraft('   ')).toBeNull()
  })

  it('parses a plain integer', () => {
    expect(parseDraft('16')).toBe(16)
    expect(parseDraft(' 32 ')).toBe(32)
  })

  it('returns NaN for non-integer input', () => {
    expect(parseDraft('1.5')).toBeNaN()
    expect(parseDraft('1e3')).toBeNaN()
    expect(parseDraft('12px')).toBeNaN()
    expect(parseDraft('abc')).toBeNaN()
  })
})

describe('validateDraft', () => {
  const [bufT, , , workersT] = fixture()

  it('accepts an empty field (clears to default)', () => {
    expect(validateDraft('', bufT)).toBe('')
    expect(validateDraft('  ', workersT)).toBe('')
  })

  it('accepts a value inside the inclusive bounds', () => {
    expect(validateDraft('262144', bufT)).toBe('')
    expect(validateDraft('16777216', bufT)).toBe('')
    expect(validateDraft('1', workersT)).toBe('')
    expect(validateDraft('64', workersT)).toBe('')
  })

  it('rejects a value outside the bounds with a range message', () => {
    expect(validateDraft('0', workersT)).toBe('Must be between 1 and 64.')
    expect(validateDraft('65', workersT)).toBe('Must be between 1 and 64.')
    expect(validateDraft('100', bufT)).toBe('Must be between 262144 and 16777216.')
  })

  it('rejects a non-integer', () => {
    expect(validateDraft('1.5', workersT)).toBe('Enter a whole number.')
    expect(validateDraft('xyz', workersT)).toBe('Enter a whole number.')
  })
})

describe('validateAll', () => {
  it('returns an empty map when every draft is valid', () => {
    const tunables = fixture()
    const drafts = draftsFromTunables(tunables)
    expect(validateAll(drafts, tunables)).toEqual({})
  })

  it('flags only the offending fields', () => {
    const tunables = fixture()
    const drafts = { ...draftsFromTunables(tunables), recv_batch: '999', per_core_sockets: 'x' }
    expect(validateAll(drafts, tunables)).toEqual({
      recv_batch: 'Must be between 1 and 64.',
      per_core_sockets: 'Enter a whole number.',
    })
  })
})

describe('changedFields', () => {
  it('returns nothing when drafts match the server values', () => {
    const tunables = fixture()
    expect(changedFields(draftsFromTunables(tunables), tunables)).toEqual({})
  })

  it('sets a newly filled override', () => {
    const tunables = fixture()
    const drafts = { ...draftsFromTunables(tunables), send_batch: '8' }
    expect(changedFields(drafts, tunables)).toEqual({ send_batch: 8 })
  })

  it('clears an emptied override with null', () => {
    const tunables = fixture()
    const drafts = { ...draftsFromTunables(tunables), recv_batch: '' }
    expect(changedFields(drafts, tunables)).toEqual({ recv_batch: null })
  })

  it('omits an unchanged override and never emits NaN', () => {
    const tunables = fixture()
    // recv_batch unchanged at 32; per_core_sockets holds garbage that
    // would have failed validateAll — changedFields must skip it.
    const drafts = { ...draftsFromTunables(tunables), per_core_sockets: 'oops' }
    expect(changedFields(drafts, tunables)).toEqual({})
  })

  it('treats setting a value equal to the default as a real change', () => {
    // send_batch is unset (null) on the server; typing its default (16)
    // is still an override the operator chose, so it must be sent.
    const tunables = fixture()
    const drafts = { ...draftsFromTunables(tunables), send_batch: '16' }
    expect(changedFields(drafts, tunables)).toEqual({ send_batch: 16 })
  })
})

describe('hasChanges', () => {
  it('is false for an untouched form and true after an edit', () => {
    const tunables = fixture()
    const drafts = draftsFromTunables(tunables)
    expect(hasChanges(drafts, tunables)).toBe(false)
    expect(hasChanges({ ...drafts, recv_batch: '8' }, tunables)).toBe(true)
  })
})

describe('placeholderFor', () => {
  it('shows the numeric default', () => {
    const [bufT] = fixture()
    expect(placeholderFor(bufT)).toBe('default: 4194304')
  })

  it('shows "auto" for a null default', () => {
    const workersT = fixture()[3]
    expect(placeholderFor(workersT)).toBe('auto')
  })
})
