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

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::icmp_sysctl::EchoIgnoreGuard;
use crate::metrics::TunnelMetrics;
use crate::protocol::TunnelState;
use crate::rst_suppress::RstSuppressGuard;
use crate::spec::{IcmpEchoMode, Role, Socks5Target, Transport, TunnelSpec, UploadListenMode};

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
    }
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
    tasks: JoinSet<()>,
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
    pub async fn shutdown(mut self) {
        let _ = self.stop_tx.send(true);
        while self.tasks.join_next().await.is_some() {}
        // `_rst_suppress` drops here, undoing any iptables rule.
    }
}

/// Spawn a tunnel for `spec`. Returns a handle that owns every
/// background task. The handle's `state` starts at `Starting` and
/// transitions to `Running` once the sockets are bound.
pub async fn spawn_tunnel(spec: TunnelSpec) -> Result<TunnelHandle, crate::manager::SpawnError> {
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
    Ok(TunnelHandle {
        id: spec.id,
        name: spec.name.clone(),
        role: spec.role,
        transport: spec.download_transport,
        spec_snapshot: SpecSnapshot::from_spec(&spec),
        mutable_config,
        session_table,
        metrics,
        upload_transport,
        state,
        error_reason,
        stop_tx,
        _stop_rx: stop_rx,
        tasks,
        _rst_suppress: rst_guard,
        _echo_ignore_guard: echo_guard,
    })
}

// Shared role-agnostic helpers ----------------------------------------------

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
}
