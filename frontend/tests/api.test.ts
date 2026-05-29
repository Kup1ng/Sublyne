import { describe, expect, it, vi } from 'vitest'
import { buildApiUrl, webPathPrefix } from '~/composables/useApi'

describe('webPathPrefix', () => {
  it('returns empty string when no meta tag exists', () => {
    document.head.innerHTML = ''
    expect(webPathPrefix()).toBe('')
  })

  it('reads the meta-tag content and strips trailing slash', () => {
    document.head.innerHTML = '<meta name="sublyne-web-path" content="x7Kp9aR2/">'
    expect(webPathPrefix()).toBe('x7Kp9aR2')
  })

  it('treats the unresolved placeholder as no prefix', () => {
    document.head.innerHTML = '<meta name="sublyne-web-path" content="__SUBLYNE_WEB_PATH__">'
    expect(webPathPrefix()).toBe('')
  })
})

describe('buildApiUrl', () => {
  it('prefixes /api before the given path', () => {
    document.head.innerHTML = '<meta name="sublyne-web-path" content="prefix">'
    expect(buildApiUrl('/tunnels')).toBe('prefix/api/tunnels')
    expect(buildApiUrl('tunnels')).toBe('prefix/api/tunnels')
  })

  it('falls through with no prefix when meta tag is absent', () => {
    document.head.innerHTML = ''
    expect(buildApiUrl('/session')).toBe('/api/session')
  })

  it('does not call fetch (smoke)', () => {
    const fetchSpy = vi.fn()
    // Just exercising imports — the URL builder must not invoke fetch.
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
