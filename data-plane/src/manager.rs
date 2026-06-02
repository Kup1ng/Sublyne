//! Top-level tunnel manager.
//!
//! Holds the dictionary of running `TunnelHandle`s keyed by tunnel id
//! and bridges IPC commands to per-tunnel actor lifecycles. Also
//! owns the global log-level reload handle so `SetLogLevel` works.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};
use tracing_subscriber::reload::Handle;
use tracing_subscriber::EnvFilter;

use crate::metrics::PerTunnelStats;
use crate::protocol::{codes, IpcError, TunnelListEntry, TunnelState, TunnelStateChanged};
use crate::spec::{SpecError, TunnelSpec};
use crate::tunnel::{spawn_tunnel, TunnelHandle};

/// Errors returned by `update_tunnel`. Mapped to `IpcError` codes for
/// the wire reply.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("tunnel id {0} is not running")]
    NotFound(i64),
    #[error("tunnel spec invalid: {0}")]
    InvalidSpec(SpecError),
    #[error("restart required to apply this change")]
    RestartRequired,
    #[error("hot-reload failed: {0}")]
    ApplyFailed(String),
    /// The change requires an internal Stop + Start. The outer flow
    /// performs that itself; this variant is only used internally and
    /// never surfaces to IPC callers.
    #[error("internal restart performed")]
    InternalRestart,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl UpdateError {
    pub fn into_ipc_error(self) -> IpcError {
        match self {
            UpdateError::NotFound(id) => IpcError::new(
                codes::TUNNEL_NOT_FOUND,
                format!("tunnel {id} is not running"),
            ),
            UpdateError::InvalidSpec(e) => IpcError::new(codes::INVALID_TUNNEL_SPEC, e.to_string()),
            UpdateError::RestartRequired => IpcError::new(
                codes::RESTART_REQUIRED,
                "Change to local_listen_addr / upload_listen_addr requires stop then start.",
            ),
            UpdateError::ApplyFailed(m) => IpcError::new(codes::INVALID_TUNNEL_SPEC, m),
            UpdateError::InternalRestart => {
                IpcError::new(codes::INTERNAL, "internal restart leaked to caller")
            }
            UpdateError::Io(e) => IpcError::new(codes::INTERNAL, format!("io: {e}")),
        }
    }
}

/// Errors returned by `start_tunnel`. Mapped to `IpcError` codes for
/// the wire reply.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("tunnel spec invalid: {0}")]
    InvalidSpec(SpecError),
    #[error("tunnel id {0} already running")]
    AlreadyRunning(i64),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl SpawnError {
    pub fn into_ipc_error(self) -> IpcError {
        match self {
            SpawnError::InvalidSpec(e) => IpcError::new(codes::INVALID_TUNNEL_SPEC, e.to_string()),
            SpawnError::AlreadyRunning(id) => IpcError::new(
                codes::INVALID_TUNNEL_SPEC,
                format!("tunnel {id} is already running"),
            ),
            SpawnError::Io(e) => {
                // Heuristic: a permission error on raw socket creation
                // surfaces as CAP_NET_RAW missing.
                if e.kind() == io::ErrorKind::PermissionDenied {
                    IpcError::new(codes::RAW_SOCKET_FORBIDDEN, format!("raw socket: {e}"))
                } else if e.kind() == io::ErrorKind::AddrInUse {
                    IpcError::new(codes::PORT_IN_USE, format!("bind: {e}"))
                } else {
                    IpcError::new(codes::INTERNAL, format!("io: {e}"))
                }
            }
        }
    }
}

/// Internal classification of an `UpdateTunnel` payload. Used by
/// `update_tunnel` to pick between hot-reload, internal restart, and
/// operator-visible restart-required.
#[derive(Debug, Clone, Copy)]
enum Classification {
    RestartRequired,
    InternalRestart,
    HotReload,
}

/// Errors returned by `stop_tunnel`.
#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error("tunnel id {0} not running")]
    NotFound(i64),
}

impl StopError {
    pub fn into_ipc_error(self) -> IpcError {
        match self {
            StopError::NotFound(id) => {
                IpcError::new(codes::TUNNEL_NOT_FOUND, format!("tunnel {id} not running"))
            }
        }
    }
}

/// Broadcast payload carried over the state-change channel. We send the
/// three owned fields as a tuple rather than `TunnelStateChanged` itself
/// so the broadcast value only needs `Clone` on primitives we already
/// have (`i64`/`TunnelState` are `Copy`, the reason is an
/// `Option<String>`); `recv()` reassembles the public
/// `TunnelStateChanged`. This keeps the broadcast independent of any
/// derive on the protocol type.
pub(crate) type StateBroadcast = (i64, TunnelState, Option<String>);

/// Capacity of the broadcast ring buffer. State changes are low-rate
/// (start / stop / error per tunnel), so 256 absorbs a burst of every
/// tunnel changing at once with room to spare before a slow subscriber
/// would lag.
const STATE_BROADCAST_CAP: usize = 256;

/// Top-level orchestrator owned by `main.rs` and shared with the IPC
/// server.
pub struct TunnelManager {
    tunnels: Mutex<HashMap<i64, TunnelHandle>>,
    /// Broadcast sender for tunnel state changes. Every call to
    /// `subscribe_state` (each IPC connection, including reconnects)
    /// gets a fresh live receiver, so a dataplane IPC reconnect no
    /// longer leaves the panel blind to state changes.
    state_tx: broadcast::Sender<StateBroadcast>,
    log_reload: Option<Arc<dyn ReloadFilter>>,
    shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

/// Object-safe wrapper around `Handle<S, F>` so we can store it in
/// the manager without knowing the inner type.
pub trait ReloadFilter: Send + Sync {
    fn reload(&self, filter: EnvFilter) -> Result<(), anyhow::Error>;
}

impl<S> ReloadFilter for Handle<EnvFilter, S>
where
    S: 'static + Send + Sync,
{
    fn reload(&self, filter: EnvFilter) -> Result<(), anyhow::Error> {
        Handle::reload(self, filter).map_err(|e| anyhow::anyhow!("reload log filter: {e}"))
    }
}

impl TunnelManager {
    /// Construct a new manager. `shutdown_tx` is fired exactly once
    /// when `Shutdown` arrives over IPC.
    pub fn new(
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        log_reload: Option<Arc<dyn ReloadFilter>>,
    ) -> Self {
        let (state_tx, _state_rx) = broadcast::channel(STATE_BROADCAST_CAP);
        Self {
            tunnels: Mutex::new(HashMap::new()),
            state_tx,
            log_reload,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }
    }

    /// Subscribe to the state-change stream. Every call returns a fresh
    /// live receiver, so each IPC connection — including the ones that
    /// open after a dataplane IPC reconnect — sees all future state
    /// changes. (Previously the single mpsc receiver was taken by the
    /// first subscriber and every later subscriber got a dead channel,
    /// so the panel stopped seeing state changes after any reconnect.)
    pub fn subscribe_state(&self) -> StateRx {
        StateRx {
            rx: self.state_tx.subscribe(),
        }
    }

    /// Start a tunnel.
    ///
    /// Idempotent for an identical spec: if the id is already running
    /// with a byte-for-byte equal spec, this returns `Ok(())` without
    /// touching the live tunnel. The Go side's startup Sync and a
    /// dataplane-respawn replay both re-issue `StartTunnel` for tunnels
    /// that are already up; treating an identical replay as an error
    /// (mapped to `INVALID_TUNNEL_SPEC`) would make those flows fail
    /// spuriously. A running id with a *different* spec is still an
    /// `AlreadyRunning` error — the caller uses `UpdateTunnel` for
    /// changes.
    pub async fn start_tunnel(&self, spec: TunnelSpec) -> Result<(), SpawnError> {
        let id = spec.id;
        let name = spec.name.clone();
        {
            let guard = self.tunnels.lock().await;
            if let Some(existing) = guard.get(&id) {
                if existing.spec_snapshot.matches_spec(&spec) {
                    info!(
                        tunnel_id = id,
                        %name,
                        "manager: start for already-running tunnel with identical spec — no-op"
                    );
                    return Ok(());
                }
                return Err(SpawnError::AlreadyRunning(id));
            }
        }
        let handle = spawn_tunnel(spec, self.state_tx.clone()).await?;
        let (state, reason) = handle.state();
        self.notify_state(id, state, reason);
        info!(tunnel_id = id, %name, "manager: tunnel started");
        let mut guard = self.tunnels.lock().await;
        guard.insert(id, handle);
        Ok(())
    }

    /// Hot-reload or internally restart a tunnel for an `UpdateTunnel`
    /// IPC command. Returns `UpdateError::RestartRequired` if a
    /// listen-addr field OR a SOCKS5 credential field changed — the
    /// operator must Stop+Start manually for those. For non-listen,
    /// non-hot-reload field changes (transport, fwmark, the "other
    /// side's" addresses) the manager performs an internal Stop+Start
    /// with the new spec and returns Ok. SOCKS5 `parallel_connections`
    /// is hot-reloadable (Phase R9b) via a live pool resize.
    pub async fn update_tunnel(&self, spec: TunnelSpec) -> Result<Vec<&'static str>, UpdateError> {
        let id = spec.id;
        // Validate the incoming spec first; an invalid one short-
        // circuits before we touch any running tunnel state.
        spec.validate().map_err(UpdateError::InvalidSpec)?;

        // Classify the change. We hold the lock only long enough to
        // read the snapshot — apply happens with the handle by-ref.
        let classification = {
            let guard = self.tunnels.lock().await;
            let handle = guard.get(&id).ok_or(UpdateError::NotFound(id))?;
            if handle.spec_snapshot.listen_addr_differs(&spec)
                || handle.spec_snapshot.socks5_credentials_differ(&spec)
            {
                Classification::RestartRequired
            } else if handle.spec_snapshot.internal_restart_field_differs(&spec) {
                Classification::InternalRestart
            } else {
                Classification::HotReload
            }
        };

        match classification {
            Classification::RestartRequired => Err(UpdateError::RestartRequired),
            Classification::InternalRestart => {
                info!(tunnel_id = id, "manager: update needs internal stop+start (transport / target / fwmark changed)");
                // Capture the currently-running spec so we can roll back
                // if the new spec fails to start — a bad edit must never
                // leave a previously-healthy tunnel permanently stopped.
                let prev_spec = {
                    let guard = self.tunnels.lock().await;
                    guard
                        .get(&id)
                        .ok_or(UpdateError::NotFound(id))?
                        .spec
                        .clone()
                };
                // Stop the running tunnel — drop the handle so its
                // raw socket releases and the iptables guard cleans
                // up — then start fresh with the new spec.
                self.stop_tunnel(id).await.map_err(|e| match e {
                    StopError::NotFound(id) => UpdateError::NotFound(id),
                })?;
                match self.start_tunnel(spec).await {
                    Ok(()) => Ok(vec!["restarted"]),
                    Err(start_err) => {
                        // The new spec didn't come up. Restore the
                        // previous, known-good spec so the tunnel keeps
                        // running, then surface the original error to the
                        // caller regardless.
                        let orig = match start_err {
                            SpawnError::InvalidSpec(s) => UpdateError::InvalidSpec(s),
                            SpawnError::AlreadyRunning(id) => UpdateError::NotFound(id),
                            SpawnError::Io(e) => UpdateError::Io(e),
                        };
                        match self.start_tunnel(prev_spec).await {
                            Ok(()) => warn!(
                                tunnel_id = id,
                                "manager: new spec failed to start; rolled back to previous spec"
                            ),
                            Err(rollback_err) => warn!(
                                tunnel_id = id,
                                err = %rollback_err,
                                "manager: new spec failed AND rollback to previous spec failed; \
                                 tunnel left stopped"
                            ),
                        }
                        Err(orig)
                    }
                }
            }
            Classification::HotReload => {
                // Take the lock briefly: apply the sync hot-reload
                // fields against the live handle AND clone out the
                // upload transport Arc + desired pool size so the
                // (potentially-slow) live resize can run after we
                // release the lock. Holding the manager lock across
                // multiple TCP handshakes would block every other
                // tunnel operation; clone-and-release keeps the
                // manager responsive.
                let (changed_sync, resize_target, new_parallel) = {
                    let guard = self.tunnels.lock().await;
                    let handle = guard.get(&id).ok_or(UpdateError::NotFound(id))?;
                    let changed = handle
                        .apply_updates(&spec)
                        .map_err(UpdateError::ApplyFailed)?;
                    // Live SOCKS5 pool resize (Phase R9b) — only when
                    // the spec carries a SOCKS5 target. The transport's
                    // default impl returns Ok(false) when already at N,
                    // so calling unconditionally is safe and avoids a
                    // spec-snapshot-vs-current-state mismatch dance.
                    let target_n = spec.socks5_target.as_ref().map(|t| t.parallel_connections);
                    let transport_arc = if target_n.is_some() {
                        handle.upload_transport.clone()
                    } else {
                        None
                    };
                    (changed, transport_arc, target_n.unwrap_or(0))
                };
                let mut changed = changed_sync;
                if let Some(transport) = resize_target {
                    match transport.set_parallel_connections(new_parallel).await {
                        Ok(true) => changed.push("parallel_connections"),
                        Ok(false) => {}
                        Err(e) => {
                            return Err(UpdateError::ApplyFailed(format!(
                                "live SOCKS5 pool resize: {e}"
                            )));
                        }
                    }
                }
                if !changed.is_empty() {
                    info!(tunnel_id = id, fields = ?changed, "manager: hot-reload applied");
                }
                Ok(changed)
            }
        }
    }

    /// Stop a tunnel by id.
    pub async fn stop_tunnel(&self, id: i64) -> Result<(), StopError> {
        let handle = {
            let mut guard = self.tunnels.lock().await;
            guard.remove(&id).ok_or(StopError::NotFound(id))?
        };
        handle.shutdown().await;
        self.notify_state(id, TunnelState::Stopped, None);
        info!(tunnel_id = id, "manager: tunnel stopped");
        Ok(())
    }

    /// Stop every running tunnel and emit `Stopped` for each.
    pub async fn stop_all(&self) {
        let drained: Vec<(i64, TunnelHandle)> = {
            let mut guard = self.tunnels.lock().await;
            guard.drain().collect()
        };
        for (id, handle) in drained {
            handle.shutdown().await;
            self.notify_state(id, TunnelState::Stopped, None);
        }
    }

    /// Snapshot of per-tunnel metric counters across every running
    /// tunnel. Called by the IPC stats reporter every 5 s. Cheap —
    /// atomics only, the session-count read does not lock the session
    /// table itself (the idle sweeper publishes it).
    pub async fn collect_stats(&self) -> Vec<PerTunnelStats> {
        let guard = self.tunnels.lock().await;
        guard.values().map(|h| h.metrics.snapshot()).collect()
    }

    /// Cheap snapshot of currently-running tunnels.
    pub fn list_tunnels(&self) -> Vec<TunnelListEntry> {
        let guard = match self.tunnels.try_lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        guard
            .iter()
            .map(|(id, h)| {
                let (state, reason) = h.state();
                TunnelListEntry {
                    id: *id,
                    name: h.name.clone(),
                    role: match h.role {
                        crate::spec::Role::Client => "client".into(),
                        crate::spec::Role::Remote => "remote".into(),
                    },
                    state,
                    reason,
                }
            })
            .collect()
    }

    /// Update the global log filter to `level`. Invalid values are
    /// logged and ignored — we don't want a typo from the panel to
    /// crash the dataplane.
    pub fn set_log_level(&self, level: &str) {
        let filter = match EnvFilter::try_new(format!("sublyne_dataplane={level}")) {
            Ok(f) => f,
            Err(e) => {
                warn!(level, err = %e, "manager: invalid log level, ignoring");
                return;
            }
        };
        if let Some(handle) = &self.log_reload {
            if let Err(e) = handle.reload(filter) {
                warn!(err = %e, "manager: failed to reload log filter");
            } else {
                info!(level, "manager: log level updated");
            }
        }
    }

    /// Fire the shutdown channel exactly once, then stop every
    /// running tunnel. Called by IPC `Shutdown`.
    pub async fn shutdown(&self) {
        self.stop_all().await;
        let mut guard = self.shutdown_tx.lock().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }

    fn notify_state(&self, tunnel_id: i64, state: TunnelState, reason: Option<String>) {
        // `broadcast::Sender::send` only errors when there are zero live
        // receivers — i.e. no IPC subscriber is currently attached. That
        // is not fatal: the next subscriber gets the current state via
        // `ListTunnels`, and every later change streams normally.
        let _ = self.state_tx.send((tunnel_id, state, reason));
    }
}

/// Receiver wrapper returned by `TunnelManager::subscribe_state`.
pub struct StateRx {
    rx: broadcast::Receiver<StateBroadcast>,
}

impl StateRx {
    pub async fn recv(&mut self) -> Option<TunnelStateChanged> {
        loop {
            match self.rx.recv().await {
                Ok((tunnel_id, state, reason)) => {
                    return Some(TunnelStateChanged {
                        tunnel_id,
                        state,
                        reason,
                    });
                }
                // A slow subscriber fell behind and the ring buffer
                // dropped `n` events. Don't tear the subscription down —
                // log and keep receiving newer events. The next
                // `ListTunnels` reconciles any missed transition.
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    debug!(
                        skipped = n,
                        "state subscriber lagged; dropping missed events"
                    );
                    continue;
                }
                // The sender was dropped (manager gone) — signal EOF.
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_stop_roundtrip() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let mgr = TunnelManager::new(tx, None);
        let spec = TunnelSpec {
            id: 1,
            role: crate::spec::Role::Client,
            name: "t1".into(),
            mtu: 1400,
            psk: "psk".into(),
            max_connections: 10,
            idle_timeout_sec: 60,
            download_transport: crate::spec::Transport::Udp,
            icmp_echo_mode: crate::spec::IcmpEchoMode::Reply,
            download_spoof_source_ip: "203.0.113.5".into(),
            download_spoof_source_port: 443,
            // local_listen on an ephemeral port the test owner can
            // be sure isn't otherwise in use; we don't actually send
            // traffic to it in this unit test.
            local_listen_addr: Some("127.0.0.1:0".into()),
            download_receive_port: Some(8443),
            upload_target_addr: Some("127.0.0.1:9".into()),
            wireguard_fwmark: 0,
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
            forward_protocol: crate::spec::ForwardProtocol::Udp,
            tcp_reliability_engine: crate::spec::TcpReliabilityEngine::Kcp,
            forward_kcp: None,
            forward_quic: None,
            ports: Vec::new(),
        };
        // This test requires CAP_NET_RAW for the raw socket open;
        // mark it ignored so unprivileged CI still passes. The
        // loopback integration test in tests/ exercises it under sudo.
        let res = mgr.start_tunnel(spec).await;
        if let Err(SpawnError::Io(e)) = &res {
            if e.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping: needs CAP_NET_RAW");
                return;
            }
        }
        res.expect("start");
        let entries = mgr.list_tunnels();
        assert_eq!(entries.len(), 1);
        mgr.stop_tunnel(1).await.expect("stop");
        assert!(mgr.list_tunnels().is_empty());
    }

    /// Two distinct free UDP ports, held simultaneously so they can't
    /// collide, then released for the tunnel under test to bind.
    fn two_free_udp_ports() -> (u16, u16) {
        let s1 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral #1");
        let s2 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral #2");
        let p1 = s1.local_addr().expect("local_addr #1").port();
        let p2 = s2.local_addr().expect("local_addr #2").port();
        // `s1`/`s2` drop here, freeing both ports for the tunnel to bind.
        (p1, p2)
    }

    /// Regression for the multi-port `PORT_IN_USE` start bug: the client
    /// used to bind `local_listen_addr` up front AND then re-bind that same
    /// port inside the per-port loop (the spec guarantees the primary port
    /// is also in `ports`), so the first loop iteration hit
    /// `EADDRINUSE` → `PORT_IN_USE` and the tunnel never started.
    ///
    /// The fix binds each configured port exactly once and never binds
    /// `local` separately. The listener binds happen BEFORE the raw
    /// download socket is opened, so this test catches the regression on
    /// BOTH privileged and unprivileged CI:
    ///
    /// - Fixed code, with CAP_NET_RAW → `Ok(())` (we tear it back down).
    /// - Fixed code, no CAP_NET_RAW → `PermissionDenied` from the raw
    ///   socket (the listeners bound fine — no `PORT_IN_USE`).
    /// - Buggy code, either way → `PORT_IN_USE` from the bind collision,
    ///   which fails the test below.
    #[tokio::test]
    async fn multiport_start_does_not_collide_on_primary_port() {
        let (p_a, p_b) = two_free_udp_ports();
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let mgr = TunnelManager::new(tx, None);
        let spec = TunnelSpec {
            id: 1,
            role: crate::spec::Role::Client,
            name: "mp".into(),
            mtu: 1400,
            psk: "psk".into(),
            max_connections: 10,
            idle_timeout_sec: 60,
            download_transport: crate::spec::Transport::Udp,
            icmp_echo_mode: crate::spec::IcmpEchoMode::Reply,
            download_spoof_source_ip: "203.0.113.5".into(),
            download_spoof_source_port: 443,
            // The primary listen port (p_a) is ALSO the first entry of the
            // unified ports list — exactly the shape the v2.7.0 unified-ports
            // import produces, and the shape that triggered the live bug.
            local_listen_addr: Some(format!("127.0.0.1:{p_a}")),
            download_receive_port: Some(18443),
            upload_target_addr: Some("127.0.0.1:9".into()),
            wireguard_fwmark: 0,
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
            forward_protocol: crate::spec::ForwardProtocol::Udp,
            tcp_reliability_engine: crate::spec::TcpReliabilityEngine::Kcp,
            forward_kcp: None,
            forward_quic: None,
            ports: vec![p_a, p_b],
        };
        match mgr.start_tunnel(spec).await {
            Ok(()) => {
                // Runner has CAP_NET_RAW — the multi-port tunnel came up
                // cleanly. Tear it back down.
                mgr.stop_tunnel(1).await.expect("stop");
            }
            Err(SpawnError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                // No CAP_NET_RAW: the per-port listeners bound fine (no
                // PORT_IN_USE) and only the raw download socket was refused.
                // That is the pass signal on unprivileged CI.
                eprintln!(
                    "multiport_start: no CAP_NET_RAW, listeners bound OK (raw socket refused)"
                );
            }
            Err(e) => panic!(
                "multi-port start must not fail with a bind error; \
                 the primary-port double-bind regressed: {e:?}"
            ),
        }
    }
}
