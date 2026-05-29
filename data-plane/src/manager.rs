//! Top-level tunnel manager.
//!
//! Holds the dictionary of running `TunnelHandle`s keyed by tunnel id
//! and bridges IPC commands to per-tunnel actor lifecycles. Also
//! owns the global log-level reload handle so `SetLogLevel` works.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
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

/// Top-level orchestrator owned by `main.rs` and shared with the IPC
/// server.
pub struct TunnelManager {
    tunnels: Mutex<HashMap<i64, TunnelHandle>>,
    state_tx: mpsc::Sender<TunnelStateChanged>,
    state_rx: Mutex<Option<mpsc::Receiver<TunnelStateChanged>>>,
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
        let (state_tx, state_rx) = mpsc::channel(64);
        Self {
            tunnels: Mutex::new(HashMap::new()),
            state_tx,
            state_rx: Mutex::new(Some(state_rx)),
            log_reload,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }
    }

    /// Take the receiver side of the state-change channel. The IPC
    /// server calls this exactly once per connection; subsequent
    /// connections after an Rx reset get a fresh channel on the next
    /// state push.
    pub fn subscribe_state(&self) -> StateRx {
        let mut guard = self
            .state_rx
            .try_lock()
            .expect("subscribe_state contention");
        if let Some(rx) = guard.take() {
            return StateRx { rx };
        }
        // Already consumed once. Create a placeholder receiver that
        // will yield nothing — Phase 11 will broaden this to a real
        // broadcast channel.
        let (_tx, rx) = mpsc::channel(1);
        StateRx { rx }
    }

    /// Start a tunnel; returns an error if the id is already running.
    pub async fn start_tunnel(&self, spec: TunnelSpec) -> Result<(), SpawnError> {
        let id = spec.id;
        let name = spec.name.clone();
        {
            let guard = self.tunnels.lock().await;
            if guard.contains_key(&id) {
                return Err(SpawnError::AlreadyRunning(id));
            }
        }
        let handle = spawn_tunnel(spec).await?;
        let (state, reason) = handle.state();
        self.notify_state(id, state, reason).await;
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
                // Stop the running tunnel — drop the handle so its
                // raw socket releases and the iptables guard cleans
                // up — then start fresh with the new spec.
                self.stop_tunnel(id).await.map_err(|e| match e {
                    StopError::NotFound(id) => UpdateError::NotFound(id),
                })?;
                self.start_tunnel(spec).await.map_err(|e| match e {
                    SpawnError::InvalidSpec(s) => UpdateError::InvalidSpec(s),
                    SpawnError::AlreadyRunning(id) => UpdateError::NotFound(id),
                    SpawnError::Io(e) => UpdateError::Io(e),
                })?;
                Ok(vec!["restarted"])
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
        self.notify_state(id, TunnelState::Stopped, None).await;
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
            self.notify_state(id, TunnelState::Stopped, None).await;
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

    async fn notify_state(&self, tunnel_id: i64, state: TunnelState, reason: Option<String>) {
        if self
            .state_tx
            .send(TunnelStateChanged {
                tunnel_id,
                state,
                reason,
            })
            .await
            .is_err()
        {
            // The receiver was dropped — IPC subscriber is gone. Not
            // fatal; the next Reply from the manager will still land.
        }
    }
}

/// Receiver wrapper returned by `TunnelManager::subscribe_state`.
pub struct StateRx {
    rx: mpsc::Receiver<TunnelStateChanged>,
}

impl StateRx {
    pub async fn recv(&mut self) -> Option<TunnelStateChanged> {
        self.rx.recv().await
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
}
