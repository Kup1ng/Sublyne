// Frontend mirror of the TCP-forwarding engine tuning presets.
//
// The SINGLE SOURCE OF TRUTH for these numbers is the Go control plane
// (control-plane/internal/tunnels/forward.go); this file mirrors them so
// the panel can pre-fill the Advanced override fields and describe each
// preset. Keep the two in lockstep — the backend re-validates whatever the
// panel sends, so a drift here can only ever surface as a save-time error,
// never as a silent mis-tune.

import type { ForwardEnginePreset, TcpReliabilityEngine } from '~/types/api'

export interface KcpTuning {
  nodelay: number
  interval: number
  resend: number
  nc: number
  snd_wnd: number
  rcv_wnd: number
}

export interface QuicTuning {
  congestion: 'cubic' | 'newreno' | 'bbr'
  initial_rtt_ms: number
  max_idle_ms: number
  keep_alive_ms: number
  stream_recv_window: number
  conn_recv_window: number
}

const MIB = 1024 * 1024

export const KCP_PRESETS: Record<ForwardEnginePreset, KcpTuning> = {
  interactive: { nodelay: 1, interval: 10, resend: 2, nc: 1, snd_wnd: 256, rcv_wnd: 256 },
  balanced: { nodelay: 1, interval: 20, resend: 2, nc: 0, snd_wnd: 1024, rcv_wnd: 1024 },
  lossy: { nodelay: 1, interval: 10, resend: 1, nc: 1, snd_wnd: 512, rcv_wnd: 512 },
}

export const QUIC_PRESETS: Record<ForwardEnginePreset, QuicTuning> = {
  interactive: {
    congestion: 'newreno',
    initial_rtt_ms: 150,
    max_idle_ms: 30000,
    keep_alive_ms: 10000,
    stream_recv_window: 2 * MIB,
    conn_recv_window: 8 * MIB,
  },
  balanced: {
    congestion: 'cubic',
    initial_rtt_ms: 200,
    max_idle_ms: 60000,
    keep_alive_ms: 20000,
    stream_recv_window: 8 * MIB,
    conn_recv_window: 32 * MIB,
  },
  lossy: {
    congestion: 'bbr',
    initial_rtt_ms: 200,
    max_idle_ms: 90000,
    keep_alive_ms: 20000,
    stream_recv_window: 8 * MIB,
    conn_recv_window: 32 * MIB,
  },
}

export const PRESET_OPTIONS: { value: ForwardEnginePreset; label: string }[] = [
  { value: 'interactive', label: 'Low-latency interactive (VLESS-WS, SSH)' },
  { value: 'balanced', label: 'Balanced / bulk (VLESS-TCP, web)' },
  { value: 'lossy', label: 'Lossy link / aggressive recovery' },
]

export const ENGINE_OPTIONS: { value: TcpReliabilityEngine; label: string }[] = [
  { value: 'kcp', label: 'KCP (recommended)' },
  { value: 'quic', label: 'QUIC' },
]

/** Default KCP tuning for a preset (clone so callers can edit freely). */
export function kcpPreset(preset: ForwardEnginePreset): KcpTuning {
  return { ...KCP_PRESETS[preset] }
}

/** Default QUIC tuning for a preset (clone so callers can edit freely). */
export function quicPreset(preset: ForwardEnginePreset): QuicTuning {
  return { ...QUIC_PRESETS[preset] }
}
