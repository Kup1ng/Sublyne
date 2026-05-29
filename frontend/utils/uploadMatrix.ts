// uploadMatrix — the v2 "upload path is a function of the download
// transport" rule, as pure data + helpers.
//
// This is the TypeScript mirror of control-plane/internal/tunnels:
// AllowedUploadModes / DefaultUploadMode / AllowedListenModes /
// DefaultListenMode. The Go validator is the source of truth (it hard-
// rejects an off-matrix tunnel on save); these helpers let the panel
// guide the operator BEFORE they submit — restricting the picker,
// auto-correcting a now-invalid selection, and graying out the modes
// that don't apply.
//
//   download  │ client upload mode      │ default   │ remote listen mode        │ default
//   ──────────┼─────────────────────────┼───────────┼───────────────────────────┼───────────
//   udp       │ wireguard               │ wireguard │ udp                       │ udp
//   tcp_syn   │ socks5                  │ socks5    │ socks5_tcp                │ socks5_tcp
//   icmp      │ wireguard, socks5       │ wireguard │ udp, socks5_tcp           │ udp
//   icmpv6    │ wireguard, socks5       │ wireguard │ udp, socks5_tcp           │ udp

import type { DownloadTransport, UploadListenMode, UploadMode } from '~/types/api'

/** Client-side upload modes valid for a download transport. */
export function allowedUploadModes(t: DownloadTransport | undefined): UploadMode[] {
  switch (t) {
    case 'udp':
      return ['wireguard']
    case 'tcp_syn':
      return ['socks5']
    case 'icmp':
    case 'icmpv6':
      return ['wireguard', 'socks5']
    default:
      // Unknown / unset transport — be permissive in the UI; the Go
      // validator still has the final say on save.
      return ['wireguard', 'socks5']
  }
}

/** Sensible default upload mode per download transport. */
export function defaultUploadMode(t: DownloadTransport | undefined): UploadMode {
  return t === 'tcp_syn' ? 'socks5' : 'wireguard'
}

/** Whether an upload mode is valid for a download transport. */
export function uploadModeAllowed(
  t: DownloadTransport | undefined,
  m: UploadMode | undefined,
): boolean {
  return !!m && allowedUploadModes(t).includes(m)
}

/** Remote-side upload-listen modes valid for a download transport. */
export function allowedListenModes(t: DownloadTransport | undefined): UploadListenMode[] {
  switch (t) {
    case 'udp':
      return ['udp']
    case 'tcp_syn':
      return ['socks5_tcp']
    case 'icmp':
    case 'icmpv6':
      return ['udp', 'socks5_tcp']
    default:
      return ['udp', 'socks5_tcp']
  }
}

/** Sensible default Remote-side listen mode per download transport. */
export function defaultListenMode(t: DownloadTransport | undefined): UploadListenMode {
  return t === 'tcp_syn' ? 'socks5_tcp' : 'udp'
}

/** Whether a listen mode is valid for a download transport. */
export function listenModeAllowed(
  t: DownloadTransport | undefined,
  m: UploadListenMode | undefined,
): boolean {
  return !!m && allowedListenModes(t).includes(m)
}

/**
 * The human name of the resolved upload mechanism for a
 * (download, upload mode) pair — the same six names the dataplane logs
 * (udp-wg, tcp-socks5, icmp-wg, icmp-socks5, icmpv6-wg, icmpv6-socks5).
 * Returns null for an off-matrix pair so the caller can show a warning
 * instead of a mechanism name.
 */
export function mechanismName(
  t: DownloadTransport | undefined,
  m: UploadMode | undefined,
): string | null {
  if (!t || !m || !uploadModeAllowed(t, m)) return null
  const sub = m === 'socks5' ? 'socks5' : 'wg'
  return `${t === 'tcp_syn' ? 'tcp' : t}-${sub}`
}

/** One-line explanation of the matrix for inline panel help. */
export const MATRIX_HELP = 'UDP → WireGuard · TCP-SYN → SOCKS5 · ICMP/ICMPv6 → either.'
