//! Typed tunnel specification.
//!
//! The Go control plane sends one of these inside every `StartTunnel`
//! and `UpdateTunnel` command payload. Fields that don't apply to a
//! given role (e.g. `local_listen_addr` on a remote tunnel) may be
//! omitted; the validator below rejects specs that are missing fields
//! they need.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    TcpSyn,
    Icmp,
    Icmpv6,
}

/// Whether the ICMP / ICMPv6 spoof envelope is sent as an echo-REPLY
/// (Phase 8b default — type 0 / 129) or an echo-REQUEST (Phase R4 —
/// type 8 / 128, with the kernel's auto-reply suppressed for the
/// lifetime of the receiver via `icmp_echo_ignore_all=1`).
///
/// The Iranian DPI / inbound firewall drops unsolicited type-0
/// echo-replies more aggressively than incoming echo-requests, which
/// is why R4 exists. See tests/perf/icmp-on-real-path.md for the
/// packet-capture evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IcmpEchoMode {
    #[default]
    Reply,
    Request,
}

/// Remote-side upload-listen mode (Phase R9a). Pairs with the Client
/// side's [`Socks5Target`] selector: a Client tunnel with
/// `socks5_target=Some(...)` MUST point at a Remote tunnel with
/// `upload_listen_mode=Socks5Tcp`. The PRD's "no inter-server control
/// plane" rule means symmetry is the operator's responsibility — the
/// Go control plane validates per side, the Rust dataplane just trusts
/// what it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UploadListenMode {
    /// Bind a UDP socket on `upload_listen_addr` — the historical
    /// behaviour for every tunnel pre-R9.
    #[default]
    Udp,
    /// Accept a TCP connection on `upload_listen_addr` and decode
    /// `[u16 BE length][payload bytes]` frames into UDP payloads
    /// forwarded to `forward_target`. Used when the paired Client
    /// uploads via SOCKS5.
    Socks5Tcp,
}

/// SOCKS5 upload target (Phase R9a). When set on a Client tunnel
/// spec, the dataplane opens TCP connection(s) to `(host, port)` and
/// performs SOCKS5 CONNECT to `upload_target_addr` — replacing the
/// fwmark/SO_MARK UDP egress path entirely. Mutually exclusive with
/// [`TunnelSpec::wireguard_fwmark`]: both being set is a spec error.
///
/// `parallel_connections` is the connection pool size R9b will honour;
/// the R9a dataplane hardcodes the pool to **1** and logs a warning if
/// the operator stored a larger value. Structuring the field on the
/// IPC payload now means R9b is purely a dataplane change with no
/// schema or wire-format churn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Target {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_parallel_connections")]
    pub parallel_connections: u32,
    /// Sublyne hardening: the warm-up gate. `Socks5Upload::connect`
    /// refuses to mark the tunnel up until at least this many slots
    /// complete the SOCKS5 handshake. Defaults to 1 when the field is
    /// absent from the IPC payload (older Go peers).
    #[serde(default = "default_min_ready_slots")]
    pub min_ready_slots: u32,
}

fn default_parallel_connections() -> u32 {
    1
}

fn default_min_ready_slots() -> u32 {
    1
}

/// Tunnel specification carried across IPC. Mirrors the schema in
/// `.claude/skills/rust-go-ipc/SKILL.md` §"Tunnel spec schema".
///
/// `psk_b64` is a base64-encoded blob the dataplane expands via
/// HKDF-SHA256 to a 32-byte key. The Go side either passes the
/// operator's raw PSK string or pre-expands it; we always re-expand so
/// short PSKs still produce a 32-byte HMAC key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub id: i64,
    pub role: Role,
    pub name: String,

    #[serde(default = "default_mtu")]
    pub mtu: u32,

    /// Raw operator-supplied PSK. Either b64 or freeform text; the
    /// dataplane derives a fixed 32-byte key with HKDF before using
    /// it.
    pub psk: String,

    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_sec: u32,

    pub download_transport: Transport,

    /// Wire direction for ICMP / ICMPv6 download spoof packets.
    /// Default = Reply for back-compat with Phase 8b.
    #[serde(default)]
    pub icmp_echo_mode: IcmpEchoMode,

    // Spoof envelope (applies to both roles — the Client uses it to
    // validate the source of incoming spoofed packets; the Remote uses
    // it to set the source of outbound spoofed packets).
    pub download_spoof_source_ip: String,
    pub download_spoof_source_port: u16,

    // Client-only fields. `wireguard_fwmark = 0` disables SO_MARK on
    // the upload socket — handy for loopback tests that don't have a
    // real WG interface available.
    #[serde(default)]
    pub local_listen_addr: Option<String>,
    #[serde(default)]
    pub download_receive_port: Option<u16>,
    #[serde(default)]
    pub upload_target_addr: Option<String>,
    #[serde(default)]
    pub wireguard_fwmark: u32,
    /// SOCKS5 upload target (Phase R9a). When Some, the dataplane
    /// uploads via a SOCKS5 TCP connection instead of the WG-marked
    /// UDP egress path. Mutually exclusive with `wireguard_fwmark` —
    /// validation rejects specs that set both.
    #[serde(default)]
    pub socks5_target: Option<Socks5Target>,

    // Remote-only fields.
    #[serde(default)]
    pub upload_listen_addr: Option<String>,
    #[serde(default)]
    pub forward_target: Option<String>,
    #[serde(default)]
    pub download_send_port: Option<u16>,
    #[serde(default)]
    pub client_real_ip: Option<String>,
    /// Upload-listen mode (Phase R9a) — Remote-only. Defaults to UDP
    /// for back-compat; `Socks5Tcp` switches the listener to TCP and
    /// decodes `[u16][bytes]` frames.
    #[serde(default)]
    pub upload_listen_mode: UploadListenMode,

    // Phase 13: cosmetic latency knobs (client-only, but carried on the
    // shared spec so the deserialiser doesn't need a role-aware variant).
    // Both default to OFF; pacing in particular is documented in the panel
    // as experimental — see PRD §3.3.
    #[serde(default)]
    pub ping_smoothing_enabled: bool,
    #[serde(default = "default_ping_smoothing_target_ms")]
    pub ping_smoothing_target_ms: u32,
    #[serde(default)]
    pub pacing_enabled: bool,
    #[serde(default = "default_pacing_target_ms")]
    pub pacing_target_ms: u32,

    /// Multi-port app ports (shared by both roles, 1:1 same-number).
    /// Empty (the default, and what older Go control planes emit) = a
    /// single-port tunnel, wire-identical to before. A list of length
    /// `>= 2` activates the application-port tag: per-port sockets are
    /// bound on the bind host taken from `local_listen_addr` (Client) /
    /// `forward_target` (Remote), and every forwarded datagram is
    /// prefixed with a 2-byte port tag (see [`crate::multiport`]). A
    /// 1-element list is treated defensively as single-port. The list
    /// INCLUDES the primary port that also appears in
    /// `local_listen_addr` / `forward_target`.
    #[serde(default)]
    pub ports: Vec<u16>,
}

fn default_mtu() -> u32 {
    1400
}
fn default_max_connections() -> u32 {
    50_000
}
fn default_idle_timeout() -> u32 {
    300
}

fn default_ping_smoothing_target_ms() -> u32 {
    60
}

fn default_pacing_target_ms() -> u32 {
    100
}

/// Errors returned by `TunnelSpec::validate`. Each variant maps to one
/// missing or malformed field so the panel can surface the failure
/// next to the offending input.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("psk is empty")]
    EmptyPsk,
    #[error("download_spoof_source_ip is empty")]
    EmptySpoofIp,
    #[error("missing client field: {0}")]
    MissingClientField(&'static str),
    #[error("missing remote field: {0}")]
    MissingRemoteField(&'static str),
    #[error("invalid socket address {field}={value}: {source}")]
    InvalidAddr {
        field: &'static str,
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("download_spoof_source_ip {0} is not a valid IP address")]
    InvalidSpoofIp(String),
    #[error("mtu {0} is below the HMAC envelope overhead")]
    MtuTooSmall(u32),
    /// A client tunnel spec carried both `wireguard_fwmark != 0` and a
    /// `socks5_target` block. The two upload paths are mutually
    /// exclusive — the Go control plane never sets both, but the
    /// dataplane refuses defensively so a malformed spec from an older
    /// control plane can't produce undefined behaviour.
    #[error("client tunnel spec carries both wireguard_fwmark and socks5_target — must pick one upload path")]
    ConflictingUploadPaths,
    /// A SOCKS5 target with credentials must carry BOTH username and
    /// password, or neither. Half-configured pairs reach this when the
    /// API layer didn't normalise (e.g. a stale import).
    #[error("socks5_target carries username without password or vice versa")]
    HalfConfiguredSocks5Auth,
    /// `parallel_connections` outside the supported `[1, 64]` range.
    /// 64 is the same cap the Go validator enforces.
    #[error("socks5_target parallel_connections={0} out of range [1, 64]")]
    Socks5ParallelOutOfRange(u32),
    /// SOCKS5 host string is empty.
    #[error("socks5_target host is empty")]
    EmptySocks5Host,
    /// SOCKS5 port is zero.
    #[error("socks5_target port must be 1..=65535")]
    InvalidSocks5Port,
}

impl TunnelSpec {
    /// Validate that the spec carries the fields its role needs and
    /// that every IP / addr / port parses cleanly. Returns the parsed
    /// addresses so the caller doesn't have to re-parse them.
    pub fn validate(&self) -> Result<ResolvedSpec, SpecError> {
        if self.psk.is_empty() {
            return Err(SpecError::EmptyPsk);
        }
        if self.download_spoof_source_ip.trim().is_empty() {
            return Err(SpecError::EmptySpoofIp);
        }
        let spoof_ip: std::net::IpAddr = self
            .download_spoof_source_ip
            .parse()
            .map_err(|_| SpecError::InvalidSpoofIp(self.download_spoof_source_ip.clone()))?;
        if self.mtu < crate::hmac::OVERHEAD as u32 + 40 {
            return Err(SpecError::MtuTooSmall(self.mtu));
        }

        match self.role {
            Role::Client => {
                let local = parse_addr(
                    "local_listen_addr",
                    self.local_listen_addr
                        .as_deref()
                        .ok_or(SpecError::MissingClientField("local_listen_addr"))?,
                )?;
                let upload_target = parse_addr(
                    "upload_target_addr",
                    self.upload_target_addr
                        .as_deref()
                        .ok_or(SpecError::MissingClientField("upload_target_addr"))?,
                )?;
                let download_port = self
                    .download_receive_port
                    .ok_or(SpecError::MissingClientField("download_receive_port"))?;
                // Validate SOCKS5 fields if the upload mode is SOCKS5.
                // The Go control plane already enforces these on save,
                // but a stale or hand-crafted spec might slip through —
                // refuse loudly so the operator gets a clear error code.
                if let Some(target) = &self.socks5_target {
                    if self.wireguard_fwmark != 0 {
                        return Err(SpecError::ConflictingUploadPaths);
                    }
                    if target.host.trim().is_empty() {
                        return Err(SpecError::EmptySocks5Host);
                    }
                    if target.port == 0 {
                        return Err(SpecError::InvalidSocks5Port);
                    }
                    if target.parallel_connections == 0 || target.parallel_connections > 64 {
                        return Err(SpecError::Socks5ParallelOutOfRange(
                            target.parallel_connections,
                        ));
                    }
                    let has_user = target
                        .username
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|s| !s.is_empty());
                    let has_pass = target
                        .password
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|s| !s.is_empty());
                    if has_user != has_pass {
                        return Err(SpecError::HalfConfiguredSocks5Auth);
                    }
                }
                Ok(ResolvedSpec {
                    spoof_ip,
                    local_listen_addr: Some(local),
                    upload_target_addr: Some(upload_target),
                    download_receive_port: Some(download_port),
                    upload_listen_addr: None,
                    forward_target: None,
                    download_send_port: None,
                    client_real_ip: None,
                    ports: self.ports.clone(),
                })
            }
            Role::Remote => {
                let upload_listen = parse_addr(
                    "upload_listen_addr",
                    self.upload_listen_addr
                        .as_deref()
                        .ok_or(SpecError::MissingRemoteField("upload_listen_addr"))?,
                )?;
                let forward_target = parse_addr(
                    "forward_target",
                    self.forward_target
                        .as_deref()
                        .ok_or(SpecError::MissingRemoteField("forward_target"))?,
                )?;
                let send_port = self
                    .download_send_port
                    .ok_or(SpecError::MissingRemoteField("download_send_port"))?;
                let client_ip = self
                    .client_real_ip
                    .as_deref()
                    .ok_or(SpecError::MissingRemoteField("client_real_ip"))?;
                let client_ip: std::net::IpAddr = client_ip
                    .parse()
                    .map_err(|_| SpecError::InvalidSpoofIp(client_ip.to_string()))?;
                Ok(ResolvedSpec {
                    spoof_ip,
                    local_listen_addr: None,
                    upload_target_addr: None,
                    download_receive_port: None,
                    upload_listen_addr: Some(upload_listen),
                    forward_target: Some(forward_target),
                    download_send_port: Some(send_port),
                    client_real_ip: Some(client_ip),
                    ports: self.ports.clone(),
                })
            }
        }
    }
}

fn parse_addr(field: &'static str, value: &str) -> Result<SocketAddr, SpecError> {
    value.parse().map_err(|source| SpecError::InvalidAddr {
        field,
        value: value.into(),
        source,
    })
}

/// Validated form of `TunnelSpec`. Holds the parsed `SocketAddr` /
/// `IpAddr` values so downstream code never has to re-parse strings.
#[derive(Debug, Clone)]
pub struct ResolvedSpec {
    pub spoof_ip: std::net::IpAddr,
    pub local_listen_addr: Option<SocketAddr>,
    pub upload_target_addr: Option<SocketAddr>,
    pub download_receive_port: Option<u16>,
    pub upload_listen_addr: Option<SocketAddr>,
    pub forward_target: Option<SocketAddr>,
    pub download_send_port: Option<u16>,
    pub client_real_ip: Option<std::net::IpAddr>,
    /// Multi-port app ports (shared by both roles). Empty or single =
    /// single-port legacy path; length >= 2 activates the per-port
    /// sockets + application-port tag (see [`ResolvedSpec::multiport`]).
    pub ports: Vec<u16>,
}

impl ResolvedSpec {
    /// True when this tunnel carries several application ports and must
    /// use the [`crate::multiport`] tag. A 0- or 1-element list is the
    /// single-port legacy path, wire-identical to before.
    pub fn multiport(&self) -> bool {
        self.ports.len() >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_client() -> TunnelSpec {
        TunnelSpec {
            id: 1,
            role: Role::Client,
            name: "c1".into(),
            mtu: 1400,
            psk: "psk".into(),
            max_connections: 10,
            idle_timeout_sec: 60,
            download_transport: Transport::Udp,
            icmp_echo_mode: IcmpEchoMode::Reply,
            download_spoof_source_ip: "203.0.113.5".into(),
            download_spoof_source_port: 443,
            local_listen_addr: Some("127.0.0.1:5001".into()),
            download_receive_port: Some(8443),
            upload_target_addr: Some("127.0.0.1:8001".into()),
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
            upload_listen_mode: UploadListenMode::Udp,
            ports: Vec::new(),
        }
    }

    fn base_remote() -> TunnelSpec {
        TunnelSpec {
            id: 2,
            role: Role::Remote,
            name: "r1".into(),
            mtu: 1400,
            psk: "psk".into(),
            max_connections: 10,
            idle_timeout_sec: 60,
            download_transport: Transport::Udp,
            icmp_echo_mode: IcmpEchoMode::Reply,
            download_spoof_source_ip: "203.0.113.5".into(),
            download_spoof_source_port: 443,
            local_listen_addr: None,
            download_receive_port: None,
            upload_target_addr: None,
            wireguard_fwmark: 0,
            upload_listen_addr: Some("127.0.0.1:8001".into()),
            forward_target: Some("127.0.0.1:9001".into()),
            download_send_port: Some(8443),
            client_real_ip: Some("127.0.0.1".into()),
            ping_smoothing_enabled: false,
            ping_smoothing_target_ms: 60,
            pacing_enabled: false,
            pacing_target_ms: 100,
            socks5_target: None,
            upload_listen_mode: UploadListenMode::Udp,
            ports: Vec::new(),
        }
    }

    #[test]
    fn client_ok() {
        let r = base_client().validate().unwrap();
        assert!(r.local_listen_addr.is_some());
        assert!(r.upload_target_addr.is_some());
        assert_eq!(r.download_receive_port, Some(8443));
    }

    #[test]
    fn remote_ok() {
        let r = base_remote().validate().unwrap();
        assert!(r.upload_listen_addr.is_some());
        assert!(r.forward_target.is_some());
        assert_eq!(r.client_real_ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn empty_psk_rejected() {
        let mut s = base_client();
        s.psk = String::new();
        assert!(matches!(s.validate(), Err(SpecError::EmptyPsk)));
    }

    #[test]
    fn ports_defaults_empty_and_is_single_port() {
        // A spec without `ports` (older Go control planes) must default to
        // an empty list, which the resolver reports as single-port.
        let json = serde_json::json!({
            "id": 1,
            "role": "client",
            "name": "c",
            "psk": "psk",
            "download_transport": "udp",
            "download_spoof_source_ip": "203.0.113.5",
            "download_spoof_source_port": 443,
            "local_listen_addr": "127.0.0.1:5001",
            "download_receive_port": 8443,
            "upload_target_addr": "127.0.0.1:8001",
        });
        let spec: TunnelSpec = serde_json::from_value(json).expect("decode no-ports spec");
        assert!(spec.ports.is_empty());
        let resolved = spec.validate().expect("validate");
        assert!(!resolved.multiport(), "empty ports must be single-port");
        assert!(resolved.ports.is_empty());
    }

    #[test]
    fn ports_multiport_carries_into_resolved() {
        let mut s = base_client();
        s.ports = vec![8000, 8001, 8002];
        let resolved = s.validate().expect("validate");
        assert!(resolved.multiport(), "len>=2 ports must be multiport");
        assert_eq!(resolved.ports, vec![8000, 8001, 8002]);
    }

    #[test]
    fn ports_single_element_is_not_multiport() {
        // The panel never emits a 1-element list, but the dataplane treats
        // it defensively as single-port.
        let mut s = base_remote();
        s.ports = vec![9001];
        let resolved = s.validate().expect("validate");
        assert!(!resolved.multiport(), "1-element ports must be single-port");
    }

    #[test]
    fn client_missing_listen_rejected() {
        let mut s = base_client();
        s.local_listen_addr = None;
        assert!(matches!(
            s.validate(),
            Err(SpecError::MissingClientField("local_listen_addr"))
        ));
    }

    #[test]
    fn malformed_addr_rejected() {
        let mut s = base_client();
        s.local_listen_addr = Some("not-an-addr".into());
        assert!(matches!(s.validate(), Err(SpecError::InvalidAddr { .. })));
    }

    #[test]
    fn malformed_spoof_ip_rejected() {
        let mut s = base_client();
        s.download_spoof_source_ip = "999.999.999.999".into();
        assert!(matches!(s.validate(), Err(SpecError::InvalidSpoofIp(_))));
    }

    fn sample_socks5_target() -> Socks5Target {
        Socks5Target {
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            parallel_connections: 1,
            min_ready_slots: 1,
        }
    }

    #[test]
    fn socks5_target_validates_ok() {
        let mut s = base_client();
        s.wireguard_fwmark = 0;
        s.socks5_target = Some(sample_socks5_target());
        assert!(s.validate().is_ok());
    }

    #[test]
    fn socks5_and_fwmark_both_set_is_rejected() {
        let mut s = base_client();
        s.wireguard_fwmark = 0x1001;
        s.socks5_target = Some(sample_socks5_target());
        assert!(matches!(
            s.validate(),
            Err(SpecError::ConflictingUploadPaths)
        ));
    }

    #[test]
    fn socks5_half_configured_auth_is_rejected() {
        let mut s = base_client();
        s.wireguard_fwmark = 0;
        s.socks5_target = Some(Socks5Target {
            username: Some("alice".into()),
            password: None,
            ..sample_socks5_target()
        });
        assert!(matches!(
            s.validate(),
            Err(SpecError::HalfConfiguredSocks5Auth)
        ));
    }

    #[test]
    fn socks5_parallel_out_of_range_is_rejected() {
        let mut s = base_client();
        s.wireguard_fwmark = 0;
        s.socks5_target = Some(Socks5Target {
            parallel_connections: 200,
            ..sample_socks5_target()
        });
        assert!(matches!(
            s.validate(),
            Err(SpecError::Socks5ParallelOutOfRange(200))
        ));
    }

    #[test]
    fn socks5_empty_host_is_rejected() {
        let mut s = base_client();
        s.wireguard_fwmark = 0;
        s.socks5_target = Some(Socks5Target {
            host: "".into(),
            ..sample_socks5_target()
        });
        assert!(matches!(s.validate(), Err(SpecError::EmptySocks5Host)));
    }

    #[test]
    fn upload_listen_mode_defaults_to_udp() {
        // Deserialise a remote spec without `upload_listen_mode` — the
        // default must be Udp so pre-R9 Go control planes that don't
        // emit the field keep working.
        let json = serde_json::json!({
            "id": 1,
            "role": "remote",
            "name": "r",
            "psk": "psk",
            "download_transport": "udp",
            "download_spoof_source_ip": "203.0.113.5",
            "download_spoof_source_port": 443,
            "upload_listen_addr": "127.0.0.1:0",
            "forward_target": "127.0.0.1:0",
            "download_send_port": 5001,
            "client_real_ip": "127.0.0.1",
        });
        let spec: TunnelSpec = serde_json::from_value(json).expect("decode default-mode spec");
        assert!(matches!(spec.upload_listen_mode, UploadListenMode::Udp));
    }

    #[test]
    fn upload_listen_mode_socks5_tcp_decodes() {
        let json = serde_json::json!({
            "id": 1,
            "role": "remote",
            "name": "r",
            "psk": "psk",
            "download_transport": "udp",
            "download_spoof_source_ip": "203.0.113.5",
            "download_spoof_source_port": 443,
            "upload_listen_addr": "127.0.0.1:0",
            "forward_target": "127.0.0.1:0",
            "download_send_port": 5001,
            "client_real_ip": "127.0.0.1",
            "upload_listen_mode": "socks5_tcp",
        });
        let spec: TunnelSpec = serde_json::from_value(json).expect("decode socks5_tcp spec");
        assert!(matches!(
            spec.upload_listen_mode,
            UploadListenMode::Socks5Tcp
        ));
    }
}
