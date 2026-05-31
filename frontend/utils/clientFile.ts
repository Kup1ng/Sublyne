// Client-side file helpers for tunnel export/import.
//
// These intentionally have no API dependency: the composable produces the
// bytes, the component decides whether to download or copy them. The panel is
// HTTP-only, so `navigator.clipboard` is frequently unavailable (it is gated
// behind a secure context); copyText falls back to a hidden <textarea> +
// document.execCommand('copy') so copy still works over plain HTTP.

const EXPORT_SUFFIX = '.sublyne-tunnel.json'

// sanitizeTunnelFilename turns a human tunnel name into a safe download
// filename: lowercase, every character outside [a-z0-9-_] becomes '-',
// repeated '-' collapse, leading/trailing '-' are trimmed, and an empty
// result falls back to "tunnel". The .sublyne-tunnel.json suffix is appended.
// Mirrors the Go sanitizeFilename in tunnel_handlers.go so the client-derived
// name matches the server's Content-Disposition.
//
//   "My VPN (443)" -> "my-vpn-443.sublyne-tunnel.json"
export function sanitizeTunnelFilename(name: string): string {
  const slug = (name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
  const base = slug.length > 0 ? slug : 'tunnel'
  return base + EXPORT_SUFFIX
}

// downloadTextFile streams an in-memory string to the browser as a file via a
// temporary object URL and a synthetic <a> click. Mirrors useBackup.ts.
export function downloadTextFile(
  filename: string,
  text: string,
  mime = 'application/json',
): void {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// copyText copies a string to the clipboard. It prefers the async Clipboard
// API when present AND in a secure context; otherwise (the common HTTP-panel
// case) it falls back to a hidden <textarea> + execCommand('copy'). Returns
// whether the copy succeeded so callers can prompt the user to download
// instead.
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Fall through to the execCommand path below.
    }
  }

  if (typeof document === 'undefined') return false

  try {
    const ta = document.createElement('textarea')
    ta.value = text
    // Keep it out of the layout/viewport but still selectable.
    ta.style.position = 'fixed'
    ta.style.top = '-9999px'
    ta.style.left = '-9999px'
    ta.setAttribute('readonly', '')
    document.body.appendChild(ta)
    ta.select()
    ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch {
    return false
  }
}
