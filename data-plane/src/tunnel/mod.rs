//! Per-tunnel actors.
//!
//! Each tunnel runs as a self-contained set of tokio tasks owned by a
//! `TunnelHandle`. Stopping a tunnel drops the handle, which fires its
//! shutdown watch channel so every spawned task wakes and exits.
//!
//! The two role-specific implementations live in `client.rs` and
//! `remote.rs`; this module wires both up behind a single
//! `TunnelHandle` shape so `manager.rs` doesn't need to know which
//! side it owns.
//!
//! ## Hot-reload (Phase 9)
//!
//! The fields that can change live without rebinding the listener
//! sockets — PSK, MTU, max_connections, idle_timeout, spoof source IP
//! and port — are stored in a `MutableConfig` shared with the tasks via
//! `Arc<RwLock<MutableConfig>>`. Every read loop and HMAC operation
//! consults this slot fresh on each iteration, so the
//! `TunnelManager::update_tunnel` IPC path just writes the new values
//! once and the running tasks pick them up on the next packet without
//! needing to coordinate with each task individually.
//!
//! `local_listen_addr` / `upload_listen_addr` changes require a full
//! Stop + Start (PRD §3.6) — `TunnelManager::update_tunnel` returns
//! `UpdateError::RestartRequired` in that case so the panel can show
//! "restart this tunnel" instead of silently doing nothing.
//!
//! `download_transport` changes do an *internal* Stop + Start: the
//! manager tears down the handle and spawns a fresh one with the new
//! transport. The operator only sees a brief blip in the tunnel's
//! `running` badge; the DB row stays `enabled = true`.

mod client;
mod remote;

use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::{broadcast, watch};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tracing::{info, warn};

use crate::icmp_sysctl::EchoIgnoreGuard;
use crate::manager::StateBroadcast;
use crate::metrics::TunnelMetrics;
use crate::protocol::TunnelState;
use crate::rst_suppress::RstSuppressGuard;
use crate::spec::{
    ForwardProtocol, IcmpEchoMode, KcpTuning, QuicTuning, Role, Socks5Target, TcpReliabilityEngine,
    Transport, TunnelSpec, UploadListenMode,
};

/// Shared state slot used by the tunnel actor to publish its
/// lifecycle status. Wrapped in `Arc<Mutex<T>>` so the spawn function
/// can hand both ends out without referencing a generic guard type.
pub(crate) type StateSlot = Arc<Mutex<TunnelState>>;
pub(crate) type ReasonSlot = Arc<Mutex<Option<String>>>;

/// Hot-reloadable subset of a tunnel's runtime configuration. Stored in
/// an `Arc<RwLock<MutableConfig>>` and shared with every task spawned by
/// the tunnel actor; reads happen once per packet, so a `std::sync`
/// RwLock is the right primitive (no async await on the hot path).
///
/// `download_transport` is deliberately NOT here — changing the
/// transport rebinds raw sockets, which is handled by an internal
/// Stop+Start in the manager.
#[derive(Debug, Clone)]
pub(crate) struct MutableConfig {
    /// Pre-derived HMAC key (HKDF-expanded PSK + primed `Hmac<Sha256>`
    /// state). Replaced atomically on PSK edit. The hot path clones the
    /// primed state per packet instead of re-keying — see
    /// `data-plane/src/hmac.rs` for the cost analysis.
    pub psk: Arc<crate::hmac::HmacKey>,
    /// Tunnel MTU, used to cap inner UDP payload size.
    pub mtu: u32,
    /// Spoof source IP we accept inbound spoofed packets from (Client
    /// side) / spoof source IP we forge on outbound spoofed packets
    /// (Remote side).
    pub spoof_ip: IpAddr,
    /// Spoof source port (same dual role as `spoof_ip`).
    pub spoof_port: u16,
    /// Phase 13 cosmetic ICMP smoothing. When true, the client's ping
    /// responder synthesizes echo-replies for incoming echo-requests
    /// after `ping_smoothing_target_ms`. PRD §3.3: cosmetic only.
    pub ping_smoothing_enabled: bool,
    pub ping_smoothing_target_ms: u32,
    /// Phase 13 experimental download pacing. When true, the client's
    /// download deliverer briefly defers each payload so the perceived
    /// RTT approximates `pacing_target_ms`. PRD §3.3 marks this as
    /// experimental — it reduces bandwidth and is OFF by default.
    pub pacing_enabled: bool,
    pub pacing_target_ms: u32,
}

pub(crate) type MutableConfigSlot = Arc<RwLock<MutableConfig>>;

/// Snapshot of the spec fields captured at spawn time so the manager
/// can classify an incoming `UpdateTunnel` payload into one of three
/// buckets:
///
/// 1. **Listen-addr changed** — return `RESTART_REQUIRED` to the panel.
///    The operator clicks Stop, then Start, after fixing the value.
/// 2. **Internal-restart field changed** — transport, fwmark, the
///    "other side's" addresses (upload_target_addr / forward_target /
///    download_receive_port / download_send_port / client_real_ip).
///    The manager does an internal Stop + Start with the new spec; the
///    operator sees a brief blip in the badge but doesn't have to
///    intervene.
/// 3. **Hot-reload field changed** — psk / mtu / spoof params /
///    max_connections / idle_timeout. Tasks pick up the new values on
///    the next packet via the shared `MutableConfig`.
#[derive(Debug, Clone, Default)]
pub(crate) struct SpecSnapshot {
    pub local_listen_addr: Option<String>,
    pub upload_listen_addr: Option<String>,
    pub transport: Option<Transport>,
    pub icmp_echo_mode: IcmpEchoMode,
    pub upload_target_addr: Option<String>,
    pub download_receive_port: Option<u16>,
    pub forward_target: Option<String>,
    pub download_send_port: Option<u16>,
    pub client_real_ip: Option<String>,
    pub wireguard_fwmark: u32,
    /// Phase R9a — Client-side SOCKS5 target. Mutually exclusive with
    /// `wireguard_fwmark`; any change to this field (set, clear, host,
    /// port, credentials, parallel_connections) is an internal restart
    /// because we'd otherwise have to keep dragging a partially-built
    /// connection pool through a hot-reload.
    pub socks5_target: Option<Socks5Target>,
    /// Phase R9a — Remote-side upload-listen mode. Switching between
    /// UDP and SOCKS5/TCP rebinds the listener (different socket type
    /// entirely), so a change is operator-visible restart-required.
    pub upload_listen_mode: UploadListenMode,

    /// v4.0.0 TCP forwarding fields. These are consumed ONLY at spawn
    /// time (client::spawn / remote::spawn build the reliability engine,
    /// its listener/dial, the per-port conv map, and the inbox once and
    /// never re-read them), so they are NOT in `MutableConfig` and CANNOT
    /// hot-reload — any change must route through an internal Stop+Start.
    /// Tracking them here is what lets `internal_restart_field_differs`
    /// detect such a change instead of silently classifying it as a
    /// no-op hot-reload (the engine/preset/tuning would otherwise keep
    /// running the old config while the panel reported success).
    pub forward_protocol: ForwardProtocol,
    pub tcp_reliability_engine: TcpReliabilityEngine,
    pub forward_kcp: Option<KcpTuning>,
    pub forward_quic: Option<QuicTuning>,
    /// Tunnel MTU. Hot-reloadable for UDP forwarding (the relay path
    /// reads it fresh per packet via `MutableConfig`), but the reliability
    /// engine bakes `mtu - PORT_TAG_LEN` into its segment size at spawn,
    /// so for a `forward_protocol=tcp` tunnel an MTU change must rebuild
    /// the engine via an internal restart (see
    /// `internal_restart_field_differs`).
    pub mtu: u32,
    /// Multi-port app-port list. A change rebinds per-port sockets, so it
    /// is always an internal restart regardless of `forward_protocol`.
    pub ports: Vec<u16>,
}

impl SpecSnapshot {
    pub fn from_spec(spec: &TunnelSpec) -> Self {
        Self {
            local_listen_addr: spec.local_listen_addr.clone(),
            upload_listen_addr: spec.upload_listen_addr.clone(),
            transport: Some(spec.download_transport),
            icmp_echo_mode: spec.icmp_echo_mode,
            upload_target_addr: spec.upload_target_addr.clone(),
            download_receive_port: spec.download_receive_port,
            forward_target: spec.forward_target.clone(),
            download_send_port: spec.download_send_port,
            client_real_ip: spec.client_real_ip.clone(),
            wireguard_fwmark: spec.wireguard_fwmark,
            socks5_target: spec.socks5_target.clone(),
            upload_listen_mode: spec.upload_listen_mode,
            forward_protocol: spec.forward_protocol,
            tcp_reliability_engine: spec.tcp_reliability_engine,
            forward_kcp: spec.forward_kcp,
            forward_quic: spec.forward_quic.clone(),
            mtu: spec.mtu,
            ports: spec.ports.clone(),
        }
    }

    /// True iff a listen address (or the Remote-side upload-listen
    /// mode) differs. Operator-visible restart — the listener socket
    /// itself has to be torn down and rebound, which we don't do
    /// silently. See also [`Self::socks5_credentials_differ`] for the
    /// other operator-visible-restart case.
    pub fn listen_addr_differs(&self, spec: &TunnelSpec) -> bool {
        self.local_listen_addr != spec.local_listen_addr
            || self.upload_listen_addr != spec.upload_listen_addr
            || self.upload_listen_mode != spec.upload_listen_mode
    }

    /// True iff the SOCKS5 credentials (host / port / auth) changed or
    /// the upload mode itself toggled (None ↔ Some). These changes
    /// require a full handshake replay on every connection, so R9b
    /// classifies them as operator-visible `RESTART_REQUIRED` rather
    /// than silent internal-restart. `parallel_connections` is
    /// deliberately excluded — it's hot-reloadable via
    /// [`Socks5Upload::resize_pool`].
    pub fn socks5_credentials_differ(&self, spec: &TunnelSpec) -> bool {
        match (&self.socks5_target, &spec.socks5_target) {
            (None, None) => false,
            // Toggle in or out of SOCKS5 mode — needs a fresh
            // `build_for_client_spec` call, which is what Stop+Start
            // does.
            (Some(_), None) | (None, Some(_)) => true,
            (Some(a), Some(b)) => {
                a.host != b.host
                    || a.port != b.port
                    || a.username != b.username
                    || a.password != b.password
            }
        }
    }

    /// True iff a non-listen, non-hot-reload field differs. These
    /// trigger an internal Stop + Start by the manager. SOCKS5 changes
    /// are deliberately NOT in here:
    ///
    /// - credentials → [`Self::socks5_credentials_differ`] →
    ///   operator-visible `RESTART_REQUIRED`.
    /// - `parallel_connections` → live pool resize via
    ///   `Socks5Upload::resize_pool` (the manager handles this on the
    ///   hot-reload branch).
    pub fn internal_restart_field_differs(&self, spec: &TunnelSpec) -> bool {
        self.transport != Some(spec.download_transport)
            || self.icmp_echo_mode != spec.icmp_echo_mode
            || self.upload_target_addr != spec.upload_target_addr
            || self.download_receive_port != spec.download_receive_port
            || self.forward_target != spec.forward_target
            || self.download_send_port != spec.download_send_port
            || self.client_real_ip != spec.client_real_ip
            || self.wireguard_fwmark != spec.wireguard_fwmark
            // v4.0.0 TCP-forwarding fields: spawn-time-only, so any change
            // rebuilds the reliability engine via an internal Stop+Start
            // rather than silently no-op'ing as a hot-reload. Toggling
            // forward_protocol (incl. udp<->tcp) also rebinds the
            // listener socket (UDP socket vs TCP listener), which the
            // internal restart handles.
            || self.forward_protocol != spec.forward_protocol
            || self.tcp_reliability_engine != spec.tcp_reliability_engine
            || self.forward_kcp != spec.forward_kcp
            || self.forward_quic != spec.forward_quic
            // Multi-port app-port set: a change rebinds per-port sockets.
            || self.ports != spec.ports
            // MTU is hot-reloadable for UDP forwarding (the relay path
            // re-reads it per packet), but a TCP-forwarding engine bakes
            // mtu - PORT_TAG_LEN into its segment size at spawn and cannot
            // resize live — so a TCP tunnel's MTU change must rebuild the
            // engine. Routing it through the internal restart also re-runs
            // validate(), restoring the QUIC mtu>=1252 floor check.
            || (self.forward_protocol == ForwardProtocol::Tcp && self.mtu != spec.mtu)
    }

    /// True iff `spec` is identical to the snapshot across every field
    /// the snapshot tracks AND every hot-reloadable field. Used by the
    /// manager to make `StartTunnel` for an already-running tunnel an
    /// idempotent no-op when the spec hasn't changed (Go startup Sync /
    /// dataplane-respawn replay), while still erroring on a genuine
    /// spec conflict. Built from the existing differ helpers so the
    /// "what counts as a change" rules stay in one place.
    pub fn matches_spec(&self, spec: &TunnelSpec) -> bool {
        !self.listen_addr_differs(spec)
            && !self.socks5_credentials_differ(spec)
            && !self.internal_restart_field_differs(spec)
            && self.socks5_parallel_connections() == spec_socks5_parallel(spec)
    }

    /// The snapshot's SOCKS5 `parallel_connections`, or `None` when this
    /// tunnel has no SOCKS5 target. Lets `matches_spec` treat a pure
    /// `parallel_connections` edit (otherwise a hot-reload) as a spec
    /// change so an identical-spec start stays a true no-op.
    fn socks5_parallel_connections(&self) -> Option<u32> {
        self.socks5_target.as_ref().map(|t| t.parallel_connections)
    }
}

/// The spec's SOCKS5 `parallel_connections`, or `None` when no SOCKS5
/// target is set. Mirror of [`SpecSnapshot::socks5_parallel_connections`]
/// for the incoming spec side of [`SpecSnapshot::matches_spec`].
fn spec_socks5_parallel(spec: &TunnelSpec) -> Option<u32> {
    spec.socks5_target.as_ref().map(|t| t.parallel_connections)
}

/// Live handle for a running tunnel. Drop this to stop the tunnel —
/// the background tasks observe the watch channel transition to
/// `true` and exit cleanly.
pub struct TunnelHandle {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub(crate) transport: Transport,
    pub(crate) spec_snapshot: SpecSnapshot,
    /// The full spec this tunnel was started with. Kept so the manager
    /// can roll an internal-restart back to the previous known-good spec
    /// if the new spec fails to start, and so an identical-spec
    /// `StartTunnel` replay can be matched without reconstructing it.
    pub(crate) spec: TunnelSpec,
    /// Hot-reloadable knobs shared with every spawned task.
    pub(crate) mutable_config: MutableConfigSlot,
    /// Session table — shared with tasks so live edits land in the same
    /// table all tasks see.
    pub(crate) session_table: Arc<crate::session::SessionTable>,
    /// Per-tunnel metric counters shared with every spawned task. Read
    /// by the IPC stats reporter every 5 s; written by every upload /
    /// download path on the hot loop via `record_*` increments.
    pub metrics: Arc<TunnelMetrics>,
    /// Client-side upload transport (None for Remote tunnels). The
    /// manager clones the `Arc` on `UpdateTunnel` to call
    /// `set_parallel_connections` for live SOCKS5 pool resize
    /// (Phase R9b) without holding the manager's tunnels lock
    /// across the resize await.
    pub(crate) upload_transport: Option<Arc<dyn crate::upload::UploadTransport>>,
    state: StateSlot,
    error_reason: ReasonSlot,
    /// Signals every task to shut down.
    stop_tx: watch::Sender<bool>,
    /// Kept just so the receiver outlives the sender; not used.
    _stop_rx: watch::Receiver<bool>,
    /// Supervisor task. It owns the `JoinSet` of every per-tunnel task
    /// and awaits them: if any task exits early with an error or panics
    /// while the tunnel was NOT deliberately shut down, it flips the
    /// tunnel to `TunnelState::Error` (updating the stored state AND
    /// pushing a `TunnelStateChanged` so the panel agrees). On
    /// deliberate `shutdown()` the stop flag is set first, so the
    /// monitor drains the tasks without raising a spurious error.
    monitor: JoinHandle<()>,
    /// iptables DROP rule (TCP-SYN, Client role only). Dropping this on
    /// shutdown removes the rule. `None` for other transports / roles.
    _rst_suppress: Option<RstSuppressGuard>,
    /// `icmp_echo_ignore_all=1` sysctl flip (ICMP/ICMPv6, Client role,
    /// Request mode only). Reference-counted across overlapping
    /// tunnels. Dropping on shutdown restores the original value.
    _echo_ignore_guard: Option<EchoIgnoreGuard>,
}

impl TunnelHandle {
    /// Current dataplane state. Returned by `ListTunnels`.
    pub fn state(&self) -> (TunnelState, Option<String>) {
        let s = *self.state.lock().expect("state mutex");
        let r = self.error_reason.lock().expect("reason mutex").clone();
        (s, r)
    }

    /// Apply a hot-reload `UpdateTunnel` payload. Caller has already
    /// verified that listen addresses and transport are unchanged.
    /// Returns the field names that were applied so the manager can
    /// log a summary, or an error if the payload was inconsistent with
    /// this tunnel's transport (e.g., a v6 spoof IP on UDP/TCP-SYN/ICMP
    /// which only accept v4 raw sockets, or v4 on ICMPv6).
    pub(crate) fn apply_updates(&self, spec: &TunnelSpec) -> Result<Vec<&'static str>, String> {
        let mut changed = Vec::new();
        let new_psk = Arc::new(crate::hmac::HmacKey::from_psk(&spec.psk));
        let new_spoof_ip: IpAddr = spec.download_spoof_source_ip.parse().map_err(|_| {
            format!(
                "download_spoof_source_ip {:?} is not a valid IP",
                spec.download_spoof_source_ip
            )
        })?;
        // The receive raw socket is bound to a specific address family at
        // spawn time. Refuse a spoof-IP swap that changes family — the
        // operator must change the transport too (which goes through an
        // internal Stop+Start) or pick a same-family IP.
        let family_mismatch = matches!(
            (self.transport, new_spoof_ip),
            (
                Transport::Udp | Transport::TcpSyn | Transport::Icmp,
                IpAddr::V6(_)
            ) | (Transport::Icmpv6, IpAddr::V4(_))
        );
        if family_mismatch {
            return Err(format!(
                "download_spoof_source_ip family does not match transport {:?}",
                self.transport
            ));
        }
        {
            let mut guard = self.mutable_config.write().expect("mutable_config write");
            if guard.psk != new_psk {
                guard.psk = new_psk;
                changed.push("psk");
            }
            if guard.mtu != spec.mtu {
                guard.mtu = spec.mtu;
                changed.push("mtu");
            }
            if guard.spoof_ip != new_spoof_ip {
                guard.spoof_ip = new_spoof_ip;
                changed.push("download_spoof_source_ip");
            }
            if guard.spoof_port != spec.download_spoof_source_port {
                guard.spoof_port = spec.download_spoof_source_port;
                changed.push("download_spoof_source_port");
            }
            if guard.ping_smoothing_enabled != spec.ping_smoothing_enabled {
                guard.ping_smoothing_enabled = spec.ping_smoothing_enabled;
                changed.push("ping_smoothing_enabled");
            }
            if guard.ping_smoothing_target_ms != spec.ping_smoothing_target_ms {
                guard.ping_smoothing_target_ms = spec.ping_smoothing_target_ms;
                changed.push("ping_smoothing_target_ms");
            }
            if guard.pacing_enabled != spec.pacing_enabled {
                guard.pacing_enabled = spec.pacing_enabled;
                changed.push("pacing_enabled");
            }
            if guard.pacing_target_ms != spec.pacing_target_ms {
                guard.pacing_target_ms = spec.pacing_target_ms;
                changed.push("pacing_target_ms");
            }
        }
        let prev_max = self.session_table.max_connections();
        if prev_max != spec.max_connections {
            self.session_table.set_max_connections(spec.max_connections);
            changed.push("max_connections");
        }
        let prev_idle = self.session_table.idle_timeout_sec() as u32;
        if prev_idle != spec.idle_timeout_sec {
            self.session_table.set_idle_timeout(spec.idle_timeout_sec);
            changed.push("idle_timeout_sec");
        }
        Ok(changed)
    }

    /// Trigger shutdown and await every task. Called by the manager
    /// on `StopTunnel`.
    pub async fn shutdown(self) {
        // Set the stop flag FIRST so the monitor treats the tasks'
        // exits as a deliberate teardown and does NOT raise a spurious
        // `Error`. The monitor then drains the `JoinSet` (which it owns)
        // and returns; awaiting it here gives the same "every task has
        // finished" guarantee the old inline drain did.
        let _ = self.stop_tx.send(true);
        let _ = self.monitor.await;
        // `_rst_suppress` drops here, undoing any iptables rule.
    }
}

/// Spawn a tunnel for `spec`. Returns a handle that owns every
/// background task. The handle's `state` starts at `Starting` and
/// transitions to `Running` once the sockets are bound.
///
/// `state_tx` is the manager's broadcast sender. The supervisor task
/// uses it to push a `TunnelState::Error` event if any per-tunnel task
/// dies unexpectedly (a fatal Remote/Client error or a panic) so the
/// failure surfaces on the panel instead of dying silently.
pub async fn spawn_tunnel(
    spec: TunnelSpec,
    state_tx: broadcast::Sender<StateBroadcast>,
) -> Result<TunnelHandle, crate::manager::SpawnError> {
    let resolved = spec
        .validate()
        .map_err(crate::manager::SpawnError::InvalidSpec)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let state: StateSlot = Arc::new(Mutex::new(TunnelState::Starting));
    let error_reason: ReasonSlot = Arc::new(Mutex::new(None));
    let mut tasks = JoinSet::new();

    let psk = Arc::new(crate::hmac::HmacKey::from_psk(&spec.psk));
    let mutable_config: MutableConfigSlot = Arc::new(RwLock::new(MutableConfig {
        psk,
        mtu: spec.mtu,
        spoof_ip: resolved.spoof_ip,
        spoof_port: spec.download_spoof_source_port,
        ping_smoothing_enabled: spec.ping_smoothing_enabled,
        ping_smoothing_target_ms: spec.ping_smoothing_target_ms,
        pacing_enabled: spec.pacing_enabled,
        pacing_target_ms: spec.pacing_target_ms,
    }));
    let session_table = Arc::new(crate::session::SessionTable::new(
        spec.max_connections,
        spec.idle_timeout_sec,
    ));
    let role_label = match spec.role {
        Role::Client => "client",
        Role::Remote => "remote",
    };
    let transport_label = match spec.download_transport {
        Transport::Udp => "udp",
        Transport::TcpSyn => "tcp_syn",
        Transport::Icmp => "icmp",
        Transport::Icmpv6 => "icmpv6",
    };
    let metrics = Arc::new(TunnelMetrics::new(spec.id, role_label, transport_label));

    // Capture the Client-side upload transport so the handle can hand
    // it to the manager's hot-reload path for live SOCKS5 pool resize
    // (Phase R9b). Remote tunnels don't have one.
    let upload_transport: Option<Arc<dyn crate::upload::UploadTransport>> = match spec.role {
        Role::Client => Some(
            client::spawn(
                &spec,
                &resolved,
                state.clone(),
                error_reason.clone(),
                &mut tasks,
                stop_rx.clone(),
                mutable_config.clone(),
                session_table.clone(),
                metrics.clone(),
            )
            .await?,
        ),
        Role::Remote => {
            remote::spawn(
                &spec,
                &resolved,
                state.clone(),
                error_reason.clone(),
                &mut tasks,
                stop_rx.clone(),
                mutable_config.clone(),
                session_table.clone(),
                metrics.clone(),
            )
            .await?;
            None
        }
    };

    // Install TCP-RST suppression for Client + TCP-SYN tunnels. The
    // guard is held on the handle so the rule is torn down on Stop.
    let rst_guard = if matches!(spec.role, Role::Client)
        && matches!(spec.download_transport, Transport::TcpSyn)
    {
        let port = resolved
            .download_receive_port
            .expect("client + tcp-syn has download_receive_port");
        Some(crate::rst_suppress::install(
            port,
            &spec.download_spoof_source_ip,
        ))
    } else {
        None
    };

    // Phase R4: install `icmp_echo_ignore_all=1` for Client + ICMP/ICMPv6
    // + Request mode so the kernel doesn't auto-reply to every incoming
    // spoofed echo-request. Drop on Stop restores the original value.
    // The Remote side doesn't need this — its spoofed packets are
    // outbound and don't trigger local kernel replies.
    let echo_guard = if matches!(spec.role, Role::Client) {
        Some(crate::icmp_sysctl::install(
            spec.download_transport,
            spec.icmp_echo_mode,
        ))
    } else {
        None
    };

    *state.lock().expect("state mutex") = TunnelState::Running;

    // Spawn the supervisor. It takes ownership of the `JoinSet` and
    // watches every per-tunnel task; on an unexpected exit (fatal error
    // via early return, or a panic) while the tunnel was not deliberately
    // shut down, it flips the tunnel to `Error` and pushes the event.
    let monitor = spawn_monitor(
        spec.id,
        tasks,
        state.clone(),
        error_reason.clone(),
        stop_rx.clone(),
        state_tx,
    );

    Ok(TunnelHandle {
        id: spec.id,
        name: spec.name.clone(),
        role: spec.role,
        transport: spec.download_transport,
        spec_snapshot: SpecSnapshot::from_spec(&spec),
        spec,
        mutable_config,
        session_table,
        metrics,
        upload_transport,
        state,
        error_reason,
        stop_tx,
        _stop_rx: stop_rx,
        monitor,
        _rst_suppress: rst_guard,
        _echo_ignore_guard: echo_guard,
    })
}

/// Supervise every per-tunnel task in `tasks`. Returns the supervisor's
/// own `JoinHandle`.
///
/// Behaviour:
/// - On a deliberate teardown (the `stop_rx` watch holds `true`, set by
///   [`TunnelHandle::shutdown`] before it awaits this task), the monitor
///   drains the remaining tasks and returns without touching state.
/// - On an UNEXPECTED exit — a task returns early because it hit a fatal
///   error (Remote tasks, the Client upload loop) or a task PANICS
///   (`JoinError::is_panic`) — while the stop flag is still `false`, the
///   monitor flips the stored state to `Error` with a concise reason
///   and broadcasts a matching `TunnelStateChanged` so `handle.state()`
///   and the panel agree. It then keeps draining the rest so a single
///   crash doesn't leak the other tasks.
fn spawn_monitor(
    id: i64,
    mut tasks: JoinSet<()>,
    state: StateSlot,
    error_reason: ReasonSlot,
    stop_rx: watch::Receiver<bool>,
    state_tx: broadcast::Sender<StateBroadcast>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reported_error = false;
        while let Some(joined) = tasks.join_next().await {
            // A deliberate shutdown sets the stop flag before any task
            // is expected to exit. If it's set, every exit from here on
            // is part of the teardown — drain quietly.
            if *stop_rx.borrow() {
                continue;
            }

            // Determine why this task ended. A panic is always a crash;
            // a clean `Ok(())` return while we did NOT ask to stop means
            // a hot-loop bailed on a fatal error (it logged + returned).
            let reason = match joined {
                Err(e) if e.is_panic() => {
                    Some(format!("a tunnel task panicked: {}", panic_reason(&e)))
                }
                Err(_) => Some("a tunnel task was cancelled unexpectedly".to_string()),
                Ok(()) => Some("a tunnel task exited unexpectedly".to_string()),
            };

            // Only the FIRST crash drives the visible state; later task
            // exits (often cascading from the first) shouldn't overwrite
            // the original reason.
            if !reported_error {
                reported_error = true;
                if let Some(reason) = reason {
                    warn!(tunnel_id = id, %reason, "tunnel: task died unexpectedly — marking Error");
                    *state.lock().expect("state mutex") = TunnelState::Error;
                    *error_reason.lock().expect("reason mutex") = Some(reason.clone());
                    let _ = state_tx.send((id, TunnelState::Error, Some(reason)));
                }
            }
        }
        if !reported_error {
            info!(
                tunnel_id = id,
                "tunnel: all tasks ended (deliberate shutdown)"
            );
        }
    })
}

/// Best-effort human string for a panicked task's payload.
fn panic_reason(err: &JoinError) -> String {
    // `JoinError` doesn't expose the payload directly without consuming
    // it; `try_into_panic` would consume `err`. We only have a shared
    // ref here, so fall back to the Display form, which renders as
    // "task <id> panicked".
    err.to_string()
}

// Shared role-agnostic helpers ----------------------------------------------

/// LOG_SAMPLE_EVERY is the sampling rate for steady-state, per-packet
/// warnings (oversized frames, session-table-full, forward failures,
/// HMAC/replay drops). At even modest packet rates an unsampled per-packet
/// `warn!` floods journald, churns the in-memory log ring, and rotates
/// app.log through its backups in seconds — blinding the operator exactly
/// when the fault is active. The dashboard metric still counts EVERY
/// occurrence; only the log line is sampled.
pub(crate) const LOG_SAMPLE_EVERY: u64 = 1000;

/// sampled bumps `counter` and returns `Some(new_total)` once every
/// LOG_SAMPLE_EVERY calls (including the first), else None — so a caller
/// can write `if let Some(total) = sampled(&COUNTER) { warn!(..., dropped_total = total) }`.
pub(crate) fn sampled(counter: &std::sync::atomic::AtomicU64) -> Option<u64> {
    let prev = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if prev % LOG_SAMPLE_EVERY == 0 {
        Some(prev + 1)
    } else {
        None
    }
}

pub(crate) async fn sleep_or_stopped(
    duration: std::time::Duration,
    stop_rx: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = stop_rx.changed() => true,
    }
}

#[cfg(test)]
mod classification_tests {
    //! These tests cover the manager's hot-reload decision logic
    //! without bringing up real sockets (which would need
    //! CAP_NET_RAW). The full end-to-end Update flow is in the
    //! ignored loopback tests under tests/.

    use super::*;
    use crate::spec::Transport;

    fn baseline_client() -> TunnelSpec {
        TunnelSpec {
            id: 1,
            role: Role::Client,
            name: "c1".into(),
            mtu: 1400,
            psk: "psk".into(),
            max_connections: 1000,
            idle_timeout_sec: 300,
            download_transport: Transport::Udp,
            icmp_echo_mode: crate::spec::IcmpEchoMode::Reply,
            download_spoof_source_ip: "203.0.113.5".into(),
            download_spoof_source_port: 443,
            local_listen_addr: Some("0.0.0.0:44443".into()),
            download_receive_port: Some(8443),
            upload_target_addr: Some("198.51.100.10:55555".into()),
            wireguard_fwmark: 0x1001,
            upload_listen_addr: None,
            forward_target: None,
            download_send_port: None,
            client_real_ip: None,
            ping_smoothing_enabled: false,
            ping_smoothing_target_ms: 60,
            pacing_enabled: false,
            pacing_target_ms: 100,
            socks5_target: None,
            upload_listen_mode: crate::spec::UploadListenMode::Udp,
            ports: Vec::new(),
            forward_protocol: crate::spec::ForwardProtocol::Udp,
            tcp_reliability_engine: crate::spec::TcpReliabilityEngine::Kcp,
            forward_kcp: None,
            forward_quic: None,
        }
    }

    #[test]
    fn listen_addr_change_is_restart_required() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.local_listen_addr = Some("0.0.0.0:44444".into());
        assert!(snap.listen_addr_differs(&next));
        assert!(!snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn transport_change_is_internal_restart() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.download_transport = Transport::TcpSyn;
        assert!(!snap.listen_addr_differs(&next));
        assert!(snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn upload_target_change_is_internal_restart() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.upload_target_addr = Some("198.51.100.20:55555".into());
        assert!(!snap.listen_addr_differs(&next));
        assert!(snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn fwmark_change_is_internal_restart() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.wireguard_fwmark = 0x1002;
        assert!(!snap.listen_addr_differs(&next));
        assert!(snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn psk_only_change_is_hot_reload() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.psk = "different-psk".into();
        assert!(!snap.listen_addr_differs(&next));
        assert!(!snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn mtu_max_idle_spoof_changes_are_hot_reload() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.mtu = 1380;
        next.max_connections = 2000;
        next.idle_timeout_sec = 120;
        next.download_spoof_source_ip = "203.0.113.6".into();
        next.download_spoof_source_port = 8443;
        assert!(!snap.listen_addr_differs(&next));
        assert!(!snap.internal_restart_field_differs(&next));
    }

    #[test]
    fn baseline_no_change_is_classified_as_hot_reload_no_op() {
        let base = baseline_client();
        let snap = SpecSnapshot::from_spec(&base);
        assert!(!snap.listen_addr_differs(&base));
        assert!(!snap.internal_restart_field_differs(&base));
        assert!(!snap.socks5_credentials_differ(&base));
    }

    /// R9b: editing only `parallel_connections` on an active SOCKS5
    /// tunnel must classify as hot-reload so the manager can call
    /// `set_parallel_connections` on the live transport (live pool
    /// resize, no tunnel restart).
    #[test]
    fn socks5_parallel_only_change_is_hot_reload() {
        let mut base = baseline_client();
        base.wireguard_fwmark = 0;
        base.socks5_target = Some(Socks5Target {
            host: "10.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            parallel_connections: 4,
            min_ready_slots: 1,
        });
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        if let Some(t) = next.socks5_target.as_mut() {
            t.parallel_connections = 8;
        }
        assert!(!snap.listen_addr_differs(&next));
        assert!(
            !snap.socks5_credentials_differ(&next),
            "parallel_connections is not a credential field"
        );
        assert!(
            !snap.internal_restart_field_differs(&next),
            "parallel_connections must not trigger internal restart"
        );
    }

    /// R9b: editing host / port / username / password on a SOCKS5
    /// tunnel requires Stop+Start (operator-visible RESTART_REQUIRED).
    #[test]
    fn socks5_credential_change_is_restart_required() {
        let mut base = baseline_client();
        base.wireguard_fwmark = 0;
        base.socks5_target = Some(Socks5Target {
            host: "10.0.0.1".into(),
            port: 1080,
            username: Some("alice".into()),
            password: Some("s3cret".into()),
            parallel_connections: 4,
            min_ready_slots: 1,
        });
        let snap = SpecSnapshot::from_spec(&base);

        // Host change.
        let mut h = base.clone();
        if let Some(t) = h.socks5_target.as_mut() {
            t.host = "10.0.0.2".into();
        }
        assert!(snap.socks5_credentials_differ(&h));

        // Port change.
        let mut p = base.clone();
        if let Some(t) = p.socks5_target.as_mut() {
            t.port = 1081;
        }
        assert!(snap.socks5_credentials_differ(&p));

        // Password rotation.
        let mut pw = base.clone();
        if let Some(t) = pw.socks5_target.as_mut() {
            t.password = Some("new-secret".into());
        }
        assert!(snap.socks5_credentials_differ(&pw));
    }

    /// R9b: toggling between WireGuard and SOCKS5 upload modes
    /// requires Stop+Start (the upload transport itself swaps).
    #[test]
    fn socks5_toggle_is_restart_required() {
        // WireGuard → SOCKS5
        let mut wg = baseline_client();
        wg.wireguard_fwmark = 0x1001;
        wg.socks5_target = None;
        let snap_wg = SpecSnapshot::from_spec(&wg);
        let mut to_socks = wg.clone();
        to_socks.wireguard_fwmark = 0;
        to_socks.socks5_target = Some(Socks5Target {
            host: "10.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            parallel_connections: 4,
            min_ready_slots: 1,
        });
        assert!(snap_wg.socks5_credentials_differ(&to_socks));

        // SOCKS5 → WireGuard
        let mut socks = baseline_client();
        socks.wireguard_fwmark = 0;
        socks.socks5_target = Some(Socks5Target {
            host: "10.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            parallel_connections: 4,
            min_ready_slots: 1,
        });
        let snap_socks = SpecSnapshot::from_spec(&socks);
        let mut to_wg = socks.clone();
        to_wg.wireguard_fwmark = 0x1001;
        to_wg.socks5_target = None;
        assert!(snap_socks.socks5_credentials_differ(&to_wg));
    }

    // --- v4.0.0 TCP forwarding (v4-audit A1/A2 regressions) -------------
    //
    // The reliability engine, its tuning, the multi-port set, and (for TCP
    // tunnels) the MTU are all spawn-time-only. Editing any of them on a
    // running tunnel MUST force an internal Stop+Start, not a silent
    // hot-reload no-op. Before the fix all of these fell through to
    // HotReload and were silently dropped while the panel reported success.

    #[test]
    fn forward_engine_change_is_internal_restart() {
        let mut base = baseline_client();
        base.forward_protocol = ForwardProtocol::Tcp;
        base.tcp_reliability_engine = TcpReliabilityEngine::Kcp;
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.tcp_reliability_engine = TcpReliabilityEngine::Quic;
        assert!(!snap.listen_addr_differs(&next));
        assert!(
            snap.internal_restart_field_differs(&next),
            "KCP->QUIC on a running tunnel must be an internal restart, not a no-op"
        );
    }

    #[test]
    fn forward_protocol_toggle_is_internal_restart() {
        let base = baseline_client(); // forward_protocol = Udp
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.forward_protocol = ForwardProtocol::Tcp;
        assert!(
            snap.internal_restart_field_differs(&next),
            "udp->tcp must rebuild the listener/engine via internal restart"
        );
    }

    #[test]
    fn forward_tuning_override_change_is_internal_restart() {
        let mut base = baseline_client();
        base.forward_protocol = ForwardProtocol::Tcp;
        base.forward_kcp = Some(KcpTuning::default());
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.forward_kcp = Some(KcpTuning {
            snd_wnd: 256,
            ..KcpTuning::default()
        });
        assert!(
            snap.internal_restart_field_differs(&next),
            "an Advanced tuning override change must rebuild the engine"
        );
    }

    #[test]
    fn mtu_change_on_tcp_forward_is_internal_restart() {
        let mut base = baseline_client();
        base.forward_protocol = ForwardProtocol::Tcp;
        base.tcp_reliability_engine = TcpReliabilityEngine::Kcp;
        base.mtu = 1400;
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.mtu = 1300;
        assert!(
            snap.internal_restart_field_differs(&next),
            "lowering MTU on a tcp-forward tunnel must rebuild the engine"
        );
    }

    #[test]
    fn mtu_change_on_udp_forward_stays_hot_reload() {
        let base = baseline_client(); // forward_protocol = Udp
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.mtu = 1300;
        assert!(
            !snap.internal_restart_field_differs(&next),
            "UDP-forward MTU stays hot-reloadable (relay reads it per packet)"
        );
    }

    #[test]
    fn ports_change_is_internal_restart() {
        let mut base = baseline_client();
        base.ports = vec![44443, 44444];
        let snap = SpecSnapshot::from_spec(&base);
        let mut next = base.clone();
        next.ports = vec![44443, 44444, 44445];
        assert!(
            snap.internal_restart_field_differs(&next),
            "adding an app port must rebind sockets via internal restart"
        );
    }
}
