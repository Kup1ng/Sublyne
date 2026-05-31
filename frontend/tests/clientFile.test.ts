import { afterEach, describe, expect, it, vi } from 'vitest'
import { sanitizeTunnelFilename, downloadTextFile, copyText } from '~/utils/clientFile'

// happy-dom does not implement document.execCommand, and vi.spyOn refuses to
// stub a property that doesn't already exist. Define a stub directly so the
// HTTP-only clipboard fallback path is testable, then remove it afterward.
// (navigator.clipboard is also absent here, so copyText always takes the
// execCommand branch — exactly the HTTP-panel case we care about.)
function withExecCommand(result: boolean) {
  const doc = document as unknown as { execCommand?: (cmd: string) => boolean }
  const fn = vi.fn((_cmd: string) => result)
  doc.execCommand = fn
  return fn
}

afterEach(() => {
  delete (document as unknown as { execCommand?: unknown }).execCommand
  vi.restoreAllMocks()
})

describe('clientFile.sanitizeTunnelFilename', () => {
  it('slugifies spaces and parens', () => {
    expect(sanitizeTunnelFilename('My VPN (443)')).toBe('my-vpn-443.sublyne-tunnel.json')
  })

  it('lowercases an already-clean name and keeps hyphens/underscores', () => {
    expect(sanitizeTunnelFilename('Edge_Node-1')).toBe('edge_node-1.sublyne-tunnel.json')
  })

  it('collapses repeated separators', () => {
    expect(sanitizeTunnelFilename('a   b///c')).toBe('a-b-c.sublyne-tunnel.json')
  })

  it('trims leading and trailing junk', () => {
    expect(sanitizeTunnelFilename('  ***hello!!!  ')).toBe('hello.sublyne-tunnel.json')
  })

  it('replaces unicode and symbols with a single hyphen', () => {
    expect(sanitizeTunnelFilename('tunnel→тест✓ok')).toBe('tunnel-ok.sublyne-tunnel.json')
  })

  it('falls back to "tunnel" for an empty name', () => {
    expect(sanitizeTunnelFilename('')).toBe('tunnel.sublyne-tunnel.json')
  })

  it('falls back to "tunnel" when nothing survives sanitization', () => {
    expect(sanitizeTunnelFilename('!!!---@@@')).toBe('tunnel.sublyne-tunnel.json')
  })

  it('tolerates a null-ish name', () => {
    expect(sanitizeTunnelFilename(undefined as unknown as string)).toBe('tunnel.sublyne-tunnel.json')
  })
})

describe('clientFile.downloadTextFile', () => {
  it('creates an object URL, clicks an anchor, and revokes the URL', () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:fake')
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    downloadTextFile('x.sublyne-tunnel.json', '{"ok":true}')

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(revokeSpy).toHaveBeenCalledWith('blob:fake')

    createSpy.mockRestore()
    revokeSpy.mockRestore()
    clickSpy.mockRestore()
  })
})

describe('clientFile.copyText', () => {
  it('uses the execCommand fallback when no secure clipboard is available', async () => {
    const exec = withExecCommand(true)
    const ok = await copyText('hello')
    expect(ok).toBe(true)
    expect(exec).toHaveBeenCalledWith('copy')
  })

  it('returns false when the fallback copy command fails', async () => {
    const exec = withExecCommand(false)
    const ok = await copyText('hello')
    expect(ok).toBe(false)
    expect(exec).toHaveBeenCalledWith('copy')
  })
})
