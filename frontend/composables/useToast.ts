// Minimal toast bus. AppToastTray (mounted in app.vue) listens to
// this composable and renders queued toasts in the corner. Components
// just call `useToast().success(...)` or `error(...)`.

export type ToastKind = 'success' | 'error' | 'info'

export interface Toast {
  id: number
  kind: ToastKind
  title: string
  body?: string
  ttl_ms: number
}

let nextId = 1

export function useToast() {
  const toasts = useState<Toast[]>('sublyne-toasts', () => [])

  function push(kind: ToastKind, title: string, body?: string, ttl_ms = 4200) {
    const id = nextId++
    toasts.value = [...toasts.value, { id, kind, title, body, ttl_ms }]
    if (ttl_ms > 0 && typeof window !== 'undefined') {
      setTimeout(() => dismiss(id), ttl_ms)
    }
    return id
  }

  function dismiss(id: number) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  return {
    toasts,
    success: (title: string, body?: string) => push('success', title, body),
    error: (title: string, body?: string) => push('error', title, body, 6500),
    info: (title: string, body?: string) => push('info', title, body),
    dismiss,
  }
}
