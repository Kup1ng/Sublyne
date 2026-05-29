import { describe, expect, it } from 'vitest'
import {
  allowedListenModes,
  allowedUploadModes,
  defaultListenMode,
  defaultUploadMode,
  listenModeAllowed,
  mechanismName,
  uploadModeAllowed,
} from '~/utils/uploadMatrix'

// These mirror control-plane/internal/tunnels/validation_test.go's
// TestUploadMatrix_Helpers so the panel and the Go validator can never
// silently drift on what the matrix allows.
describe('uploadMatrix', () => {
  it('udp allows only wireguard upload', () => {
    expect(allowedUploadModes('udp')).toEqual(['wireguard'])
    expect(uploadModeAllowed('udp', 'wireguard')).toBe(true)
    expect(uploadModeAllowed('udp', 'socks5')).toBe(false)
    expect(defaultUploadMode('udp')).toBe('wireguard')
  })

  it('tcp_syn allows only socks5 upload', () => {
    expect(allowedUploadModes('tcp_syn')).toEqual(['socks5'])
    expect(uploadModeAllowed('tcp_syn', 'socks5')).toBe(true)
    expect(uploadModeAllowed('tcp_syn', 'wireguard')).toBe(false)
    expect(defaultUploadMode('tcp_syn')).toBe('socks5')
  })

  it('icmp and icmpv6 allow either upload mode, default wireguard', () => {
    for (const t of ['icmp', 'icmpv6'] as const) {
      expect(allowedUploadModes(t)).toEqual(['wireguard', 'socks5'])
      expect(uploadModeAllowed(t, 'wireguard')).toBe(true)
      expect(uploadModeAllowed(t, 'socks5')).toBe(true)
      expect(defaultUploadMode(t)).toBe('wireguard')
    }
  })

  it('remote listen modes mirror the client matrix', () => {
    expect(allowedListenModes('udp')).toEqual(['udp'])
    expect(allowedListenModes('tcp_syn')).toEqual(['socks5_tcp'])
    expect(allowedListenModes('icmp')).toEqual(['udp', 'socks5_tcp'])
    expect(defaultListenMode('tcp_syn')).toBe('socks5_tcp')
    expect(defaultListenMode('udp')).toBe('udp')
    expect(listenModeAllowed('udp', 'socks5_tcp')).toBe(false)
    expect(listenModeAllowed('tcp_syn', 'socks5_tcp')).toBe(true)
  })

  it('names the six mechanisms for matrix-valid pairs', () => {
    expect(mechanismName('udp', 'wireguard')).toBe('udp-wg')
    expect(mechanismName('tcp_syn', 'socks5')).toBe('tcp-socks5')
    expect(mechanismName('icmp', 'wireguard')).toBe('icmp-wg')
    expect(mechanismName('icmp', 'socks5')).toBe('icmp-socks5')
    expect(mechanismName('icmpv6', 'wireguard')).toBe('icmpv6-wg')
    expect(mechanismName('icmpv6', 'socks5')).toBe('icmpv6-socks5')
  })

  it('returns null mechanism for an off-matrix pair', () => {
    expect(mechanismName('udp', 'socks5')).toBeNull()
    expect(mechanismName('tcp_syn', 'wireguard')).toBeNull()
  })
})
