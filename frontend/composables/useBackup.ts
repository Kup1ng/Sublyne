import { apiFetch } from '~/composables/useApi'

// Backup downloads the entire SQLite DB; restore takes an uploaded
// .db blob. Both endpoints stream binary, so we bypass the JSON
// helpers in useApi.

export function useBackup() {
  async function download(): Promise<void> {
    // Real path is /api/settings/backup — the handler lives in the
    // logs/settings sub-tree on the Go side.
    const res = await apiFetch('/settings/backup', { method: 'GET' })
    if (!res.ok) throw new Error(`backup download failed: ${res.status}`)
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') ?? ''
    const m = cd.match(/filename="([^"]+)"/)
    const name = m?.[1] ?? `sublyne-${new Date().toISOString().slice(0, 10)}.db`
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  async function restore(file: File): Promise<void> {
    const fd = new FormData()
    fd.append('backup', file, file.name)
    const res = await apiFetch('/settings/restore', { method: 'POST', body: fd })
    if (!res.ok) {
      const body = await res.json().catch(() => ({}) as Record<string, string>)
      const msg = (body && (body.error || body.message)) || `restore failed: ${res.status}`
      throw new Error(msg)
    }
  }

  return { download, restore }
}
