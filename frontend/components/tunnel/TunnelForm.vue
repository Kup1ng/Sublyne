<script setup lang="ts">
import { Save, Trash2 } from 'lucide-vue-next'
import { computed, ref, watch, watchEffect } from 'vue'
import type {
  DownloadTransport,
  IcmpEchoMode,
  Tunnel,
  UploadMode,
  UploadListenMode,
} from '~/types/api'
import { useAuth } from '~/composables/useAuth'
import { useWireguard } from '~/composables/useWireguard'
import { useSocks5 } from '~/composables/useSocks5'
import {
  MATRIX_HELP,
  allowedListenModes,
  allowedUploadModes,
  defaultListenMode,
  defaultUploadMode,
  listenModeAllowed,
  mechanismName,
  uploadModeAllowed,
} from '~/utils/uploadMatrix'

const props = defineProps<{
  initial?: Partial<Tunnel>
  submitting?: boolean
  onDelete?: (() => void) | null
  errors?: Record<string, string>
}>()
const emit = defineEmits<{ (e: 'submit', value: Partial<Tunnel>): void }>()

const auth = useAuth()
const wg = useWireguard()
const socks = useSocks5()

const isClient = computed(() => auth.role.value !== 'remote')

const draft = ref<Partial<Tunnel>>({
  enabled: true,
  mtu: 1400,
  max_connections: 50000,
  idle_timeout: 300,
  download_transport: 'udp',
  icmp_echo_mode: 'request',
  upload_mode: 'wireguard',
  ping_smoothing_enabled: false,
  ping_smoothing_target_ms: 60,
  pacing_enabled: false,
  pacing_target_ms: 60,
  upload_listen_mode: 'udp',
  ...props.initial,
})

watchEffect(() => {
  if (props.initial) draft.value = { ...draft.value, ...props.initial }
})

// Backend validation rejects a tunnel that has both wg_config_id and
// socks5_proxy_id set, even when upload_mode is exclusive — switching
// from WireGuard to SOCKS5 must explicitly null the WG side (and
// vice versa). Doing it here means the user just picks the new mode
// and saves without having to remember to clear the old picker.
watch(
  () => draft.value.upload_mode,
  (mode) => {
    if (mode === 'socks5') {
      draft.value.wg_config_id = null
    } else if (mode === 'wireguard') {
      draft.value.socks5_proxy_id = null
    }
  },
)

// v2 upload/download matrix: the upload path follows the download
// transport. When the operator changes the download transport, snap the
// upload mode (client) or listen mode (remote) to the matrix default if
// the current choice is no longer valid, so the form can never sit in an
// off-matrix state the backend would reject on save. Only an INVALID
// selection is auto-corrected; a still-valid one (icmp allows either) is
// left as the operator set it.
watch(
  () => draft.value.download_transport,
  (dt) => {
    if (isClient.value) {
      if (!uploadModeAllowed(dt, draft.value.upload_mode)) {
        draft.value.upload_mode = defaultUploadMode(dt)
      }
    } else if (!listenModeAllowed(dt, draft.value.upload_listen_mode)) {
      draft.value.upload_listen_mode = defaultListenMode(dt)
    }
  },
)

onMounted(async () => {
  if (isClient.value) {
    if (!wg.list.value.length) await wg.refresh().catch(() => undefined)
    if (!socks.list.value.length) await socks.refresh().catch(() => undefined)
  }
})

const transportOptions: { value: DownloadTransport; label: string }[] = [
  { value: 'udp', label: 'UDP' },
  { value: 'tcp_syn', label: 'TCP-SYN' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'icmpv6', label: 'ICMPv6' },
]
const icmpModeOptions: { value: IcmpEchoMode; label: string }[] = [
  { value: 'request', label: 'echo-request (recommended)' },
  { value: 'reply', label: 'echo-reply (legacy)' },
]
// Upload-mode / listen-mode pickers are matrix-aware: every mode is
// shown, but the ones off-matrix for the selected download transport are
// disabled (grayed out) with a "(not for X)" suffix so the operator sees
// why they can't pick it.
const uploadModeLabels: Record<UploadMode, string> = {
  wireguard: 'WireGuard',
  socks5: 'SOCKS5 (multi-link)',
}
const remoteListenLabels: Record<UploadListenMode, string> = {
  udp: 'UDP',
  socks5_tcp: 'SOCKS5-TCP',
}

// Build select options from a label map, graying out (and explaining)
// the modes that are off-matrix for the current download transport.
function modeOptions<T extends string>(labels: Record<T, string>, allowed: T[]) {
  const dt = draft.value.download_transport
  const suffix = dt ? ` (not for ${dt.toUpperCase()})` : ''
  return (Object.keys(labels) as T[]).map((v) => ({
    value: v,
    label: allowed.includes(v) ? labels[v] : `${labels[v]}${suffix}`,
    disabled: !allowed.includes(v),
  }))
}

const uploadModeOptions = computed(() =>
  modeOptions(uploadModeLabels, allowedUploadModes(draft.value.download_transport)),
)
const remoteListenOptions = computed(() =>
  modeOptions(remoteListenLabels, allowedListenModes(draft.value.download_transport)),
)

// The resolved mechanism (one of: udp-wg, tcp-socks5, icmp-wg,
// icmp-socks5, icmpv6-wg, icmpv6-socks5) for the current download/upload
// pair, shown as a confirmation line under the upload-mode picker.
const resolvedMechanism = computed(() =>
  mechanismName(draft.value.download_transport, draft.value.upload_mode),
)
const matrixHelp = MATRIX_HELP

const wgOptions = computed(() => wg.list.value.map((c) => ({ value: c.id, label: c.name })))
const socksOptions = computed(() =>
  socks.list.value.map((p) => ({ value: p.id, label: `${p.name} (${p.host}:${p.port})` })),
)

function err(field: string) {
  return props.errors?.[field] ?? null
}

function submit() {
  emit('submit', draft.value)
}
</script>

<template>
  <form @submit.prevent="submit" class="space-y-6">
    <AppCard title="Identity" description="What to call this tunnel and whether it auto-starts.">
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup
          label="Name"
          help="Free-form name shown in the dashboard. Must be unique on this server."
          :error="err('name')"
          required
        >
          <AppInput v-model="draft.name" :invalid="!!err('name')" placeholder="iran-3xui-443" />
        </FieldGroup>
        <FieldGroup
          label="Enabled"
          help="When disabled, the listener isn't started on service restart."
        >
          <div class="flex h-10 items-center gap-2.5">
            <AppSwitch v-model="draft.enabled" />
            <span class="text-[13px] text-subtle">
              {{ draft.enabled ? 'Will start' : 'Stopped' }}
            </span>
          </div>
        </FieldGroup>
      </div>
    </AppCard>

    <!-- CLIENT-side fields -->
    <AppCard
      v-if="isClient"
      title="Listener"
      description="Where the end-user device connects and how spoofed return packets are accepted."
    >
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup
          label="Local listen address"
          help="UDP listener for the end user, e.g. 0.0.0.0:443."
          :error="err('local_listen_addr')"
          required
        >
          <AppInput
            v-model="draft.local_listen_addr"
            :invalid="!!err('local_listen_addr')"
            placeholder="0.0.0.0:443"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Download receive port"
          help="Local port that receives spoofed download packets. Doesn't need to be unique across tunnels — the spoof source IP/port pair makes the routing deterministic."
          :error="err('download_receive_port')"
          required
        >
          <AppInput
            v-model="draft.download_receive_port"
            type="number"
            :invalid="!!err('download_receive_port')"
            placeholder="55556"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Spoof source IP"
          help="The white IP we expect as the source of every spoofed packet. Anything else is dropped."
          :error="err('download_spoof_source_ip')"
          required
        >
          <AppInput
            v-model="draft.download_spoof_source_ip"
            :invalid="!!err('download_spoof_source_ip')"
            placeholder="203.0.113.42"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Spoof source port"
          help="Expected source port of spoofed packets (often 443 for camouflage)."
          :error="err('download_spoof_source_port')"
        >
          <AppInput
            v-model="draft.download_spoof_source_port"
            type="number"
            placeholder="443"
            monospace
          />
        </FieldGroup>
      </div>
    </AppCard>

    <AppCard
      v-if="isClient"
      title="Upload path"
      description="Choose between a single WireGuard interface and the parallel SOCKS5 multi-link mode."
    >
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup
          label="Upload target"
          help="Remote server's upload_listen_addr (host:port). Must match the Remote-side tunnel."
          :error="err('upload_target_addr')"
          required
        >
          <AppInput
            v-model="draft.upload_target_addr"
            :invalid="!!err('upload_target_addr')"
            placeholder="198.51.100.40:55555"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Upload mode"
          :help="`Follows the download transport. ${matrixHelp}`"
          :error="err('upload_mode')"
        >
          <AppSelect v-model="draft.upload_mode" :options="uploadModeOptions" />
          <p v-if="resolvedMechanism" class="mt-1.5 text-[12px] font-medium text-brand">
            Mechanism: {{ resolvedMechanism }}
          </p>
        </FieldGroup>

        <FieldGroup
          v-if="draft.upload_mode === 'wireguard'"
          label="WireGuard config"
          help="Pick from the configs in the WireGuard page. Multiple tunnels may share one config."
          :error="err('wg_config_id')"
          required
        >
          <AppSelect v-if="wgOptions.length" v-model="draft.wg_config_id" :options="wgOptions" />
          <NuxtLink
            v-else
            to="/wireguard/new"
            class="flex h-10 items-center justify-between rounded-xl border border-dashed border-line/80 bg-elevated/30 px-3 text-[13px] text-subtle transition hover:border-brand/40 hover:text-ink"
          >
            <span>No WireGuard configs yet</span>
            <span class="font-medium text-brand">Create one →</span>
          </NuxtLink>
        </FieldGroup>

        <FieldGroup
          v-else
          label="SOCKS5 proxy"
          help="The proxy is itself a multi-link load balancer. The dataplane opens N parallel TCP connections (set N on the proxy entry)."
          :error="err('socks5_proxy_id')"
          required
        >
          <AppSelect
            v-if="socksOptions.length"
            v-model="draft.socks5_proxy_id"
            :options="socksOptions"
          />
          <NuxtLink
            v-else
            to="/socks5/new"
            class="flex h-10 items-center justify-between rounded-xl border border-dashed border-line/80 bg-elevated/30 px-3 text-[13px] text-subtle transition hover:border-brand/40 hover:text-ink"
          >
            <span>No SOCKS5 proxies yet</span>
            <span class="font-medium text-brand">Add one →</span>
          </NuxtLink>
        </FieldGroup>
      </div>
    </AppCard>

    <!-- REMOTE-side fields -->
    <AppCard
      v-if="!isClient"
      title="Listener"
      description="Where the seller's egress arrives and where to forward it."
    >
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup
          label="Upload listen address"
          help="Address+port the seller's exit hits, e.g. 0.0.0.0:55555."
          :error="err('upload_listen_addr')"
          required
        >
          <AppInput
            v-model="draft.upload_listen_addr"
            :invalid="!!err('upload_listen_addr')"
            placeholder="0.0.0.0:55555"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Listen mode"
          :help="`Must mirror the Client. ${matrixHelp}`"
          :error="err('upload_listen_mode')"
        >
          <AppSelect v-model="draft.upload_listen_mode" :options="remoteListenOptions" />
        </FieldGroup>
        <FieldGroup
          label="Forward target"
          help="The real destination (host:port) — typically your proxy panel."
          :error="err('forward_target')"
          required
        >
          <AppInput
            v-model="draft.forward_target"
            :invalid="!!err('forward_target')"
            placeholder="192.0.2.10:443"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Download send port"
          help="Must equal the Client's download_receive_port."
          :error="err('download_send_port')"
          required
        >
          <AppInput
            v-model="draft.download_send_port"
            type="number"
            :invalid="!!err('download_send_port')"
            placeholder="55556"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Spoof source IP"
          help="The white IP we forge as the source of every download packet."
          required
        >
          <AppInput v-model="draft.download_spoof_source_ip" placeholder="203.0.113.42" monospace />
        </FieldGroup>
        <FieldGroup label="Spoof source port" help="Forged source port. Same as Client.">
          <AppInput
            v-model="draft.download_spoof_source_port"
            type="number"
            placeholder="443"
            monospace
          />
        </FieldGroup>
        <FieldGroup
          label="Client real IP"
          help="Public IP of the Iran-Client server (destination of every spoofed packet)."
          :error="err('client_real_ip')"
          required
        >
          <AppInput
            v-model="draft.client_real_ip"
            :invalid="!!err('client_real_ip')"
            placeholder="198.51.100.30"
            monospace
          />
        </FieldGroup>
      </div>
    </AppCard>

    <AppCard
      title="Spoof envelope"
      description="Picked per tunnel; both sides must agree. Switching is hot-reloaded."
    >
      <div class="grid gap-5 md:grid-cols-3">
        <FieldGroup
          label="Download transport"
          help="UDP is the default. TCP-SYN is the most reliable on aggressive paths. ICMP/ICMPv6 are useful when both UDP and TCP-SYN are filtered upstream."
        >
          <AppSelect v-model="draft.download_transport" :options="transportOptions" />
        </FieldGroup>
        <FieldGroup
          v-if="draft.download_transport === 'icmp' || draft.download_transport === 'icmpv6'"
          label="ICMP echo mode"
          help="echo-request matches what unfiltered hops expect; the dataplane suppresses the kernel's auto-reply for the tunnel's lifetime."
        >
          <AppSelect v-model="draft.icmp_echo_mode" :options="icmpModeOptions" />
        </FieldGroup>
        <FieldGroup label="MTU" help="Default 1400 — leaves headroom for WG + HMAC overhead.">
          <AppInput v-model="draft.mtu" type="number" placeholder="1400" monospace />
        </FieldGroup>
      </div>
    </AppCard>

    <AppCard
      title="Security"
      description="The PSK is shared by both sides; rotation requires both at once."
    >
      <div class="grid gap-5 md:grid-cols-2">
        <FieldGroup
          label="Pre-shared key (PSK)"
          help="Base64 32-byte secret. The panel returns *** on reads — paste the new value here to rotate."
          :error="err('psk')"
          :required="!props.initial?.id"
        >
          <AppInput
            v-model="draft.psk"
            type="password"
            :invalid="!!err('psk')"
            placeholder="••••••••"
            monospace
          />
        </FieldGroup>
      </div>
    </AppCard>

    <AppCard title="Capacity" description="Per-tunnel session cap and idle eviction.">
      <div class="grid gap-5 md:grid-cols-3">
        <FieldGroup
          label="Max connections"
          help="Drop new sessions above this cap with a WARN log."
        >
          <AppInput v-model="draft.max_connections" type="number" monospace />
        </FieldGroup>
        <FieldGroup
          label="Idle timeout (seconds)"
          help="Sessions idle longer than this are evicted."
        >
          <AppInput v-model="draft.idle_timeout" type="number" monospace />
        </FieldGroup>
      </div>
    </AppCard>

    <AppCard
      v-if="isClient"
      title="Optional latency tweaks"
      description="Off by default. ICMP smoothing is cosmetic; pacing is experimental."
    >
      <div class="grid gap-5 md:grid-cols-2">
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <AppLabel>Ping smoothing</AppLabel>
            <AppSwitch v-model="draft.ping_smoothing_enabled" />
          </div>
          <p class="text-[12px] text-subtle">
            Synthesise ICMP echo replies locally to mask the up/down RTT asymmetry. The real request
            still travels — reachability is unaffected.
          </p>
          <AppInput
            v-if="draft.ping_smoothing_enabled"
            v-model="draft.ping_smoothing_target_ms"
            type="number"
            placeholder="60"
            monospace
          />
        </div>
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <AppLabel>Pacing</AppLabel>
            <AppSwitch v-model="draft.pacing_enabled" />
          </div>
          <p class="text-[12px] text-subtle">
            Experimental — buffers download packets so the apparent round-trip looks symmetric.
            Reduces bandwidth and increases CPU.
          </p>
          <AppInput
            v-if="draft.pacing_enabled"
            v-model="draft.pacing_target_ms"
            type="number"
            placeholder="60"
            monospace
          />
        </div>
      </div>
    </AppCard>

    <div
      class="sticky bottom-0 -mx-6 flex items-center justify-between gap-2 border-t border-line/70 bg-bg/90 px-6 py-4 backdrop-blur-md md:-mx-10 md:px-10"
    >
      <AppButton v-if="onDelete" type="button" variant="ghost" @click="onDelete">
        <Trash2 class="size-4" />
        Delete tunnel
      </AppButton>
      <span v-else />
      <div class="flex items-center gap-2">
        <NuxtLink to="/tunnels">
          <AppButton type="button" variant="secondary">Cancel</AppButton>
        </NuxtLink>
        <AppButton type="submit" :loading="submitting">
          <Save class="size-4" />
          Save tunnel
        </AppButton>
      </div>
    </div>
  </form>
</template>
