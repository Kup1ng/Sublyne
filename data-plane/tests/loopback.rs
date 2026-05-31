//! End-to-end loopback tests for the four download spoof transports
//! (UDP, TCP-SYN, ICMP, ICMPv6).
//!
//! Marked `#[ignore]` because they open raw sockets and therefore need
//! `CAP_NET_RAW`. Run manually on a Linux host with:
//!
//! ```text
//! sudo setcap cap_net_raw,cap_net_admin=eip target/debug/deps/loopback-*
//! cargo test --test loopback -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` matters: every test binds raw sockets and a
//! handful of UDP ports. Running them in parallel would let the IPv4
//! raw recv sockets (which see *every* packet on the host of a given
//! protocol) cross-talk, e.g. the UDP test's traffic would also be
//! picked up by an ICMP test running concurrently — the source-IP /
//! source-port filter would drop it, but the noise hurts confidence
//! in failure diagnostics. Serializing keeps the tests deterministic.
//!
//! Each test runs a Client and a Remote tunnel pair on the same
//! `127.0.0.1` (or `::1` for ICMPv6) host. A simulated end-user UDP
//! socket sends a payload into `local_listen_addr`; a simulated
//! forward target echoes incoming UDP back; the test asserts the same
//! payload re-emerges out of the end-user socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sublyne_dataplane::manager::TunnelManager;
use sublyne_dataplane::spec::{Role, Transport, TunnelSpec};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// All addresses required to run an end-to-end loopback for one
/// transport. Each transport gets its own set of ports / addresses so
/// the tests can be run back-to-back without TIME_WAIT and raw-socket
/// cross-talk interfering with the next iteration.
struct LoopbackConfig {
    transport: Transport,
    /// ICMP wire direction (Phase R4). Defaulted to `Reply` for every
    /// non-ICMP test; the per-transport tests pick `Request` for the
    /// new mode. Ignored when `transport` is UDP / TCP-SYN.
    icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode,
    /// Spoof source IP — also used as `client_real_ip`. Either
    /// `127.0.0.1` (IPv4 transports) or `::1` (ICMPv6).
    spoof_ip: &'static str,
    end_user_listen: SocketAddr,
    remote_upload: SocketAddr,
    forward_target_addr: SocketAddr,
    /// `download_receive_port` on the Client / `download_send_port` on
    /// the Remote. For ICMP / ICMPv6 this number doesn't appear on the
    /// wire (the ICMP identifier carries the matching tag instead) but
    /// is still required by the spec for parity with UDP/TCP-SYN.
    download_port: u16,
    /// Client and Remote tunnel ids must be distinct across all
    /// concurrent tunnels owned by one `TunnelManager`; we bump these
    /// per-test so a test that fails to stop_all leaves a clean slate
    /// for the next.
    client_id: i64,
    remote_id: i64,
}

fn client_spec(cfg: &LoopbackConfig, psk: &str) -> TunnelSpec {
    TunnelSpec {
        id: cfg.client_id,
        role: Role::Client,
        name: format!("loop-client-{:?}", cfg.transport).to_lowercase(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: cfg.transport,
        icmp_echo_mode: cfg.icmp_echo_mode,
        download_spoof_source_ip: cfg.spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: Some(cfg.end_user_listen.to_string()),
        download_receive_port: Some(cfg.download_port),
        upload_target_addr: Some(cfg.remote_upload.to_string()),
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
        upload_listen_mode: sublyne_dataplane::spec::UploadListenMode::Udp,
        ports: Vec::new(),
    }
}

fn remote_spec(cfg: &LoopbackConfig, psk: &str) -> TunnelSpec {
    TunnelSpec {
        id: cfg.remote_id,
        role: Role::Remote,
        name: format!("loop-remote-{:?}", cfg.transport).to_lowercase(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: cfg.transport,
        icmp_echo_mode: cfg.icmp_echo_mode,
        download_spoof_source_ip: cfg.spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: None,
        download_receive_port: None,
        upload_target_addr: None,
        wireguard_fwmark: 0,
        upload_listen_addr: Some(cfg.remote_upload.to_string()),
        forward_target: Some(cfg.forward_target_addr.to_string()),
        download_send_port: Some(cfg.download_port),
        client_real_ip: Some(cfg.spoof_ip.into()),
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: None,
        upload_listen_mode: sublyne_dataplane::spec::UploadListenMode::Udp,
        ports: Vec::new(),
    }
}

/// The full test body shared by every transport. Stands up an echo
/// server at `forward_target_addr`, brings up the Client+Remote tunnel
/// pair, exercises:
///
/// * small round-trip (`b"hello loopback world"`)
/// * near-MTU round-trip (1400 B) — the regression for the PR #14
///   silent-truncate bug
/// * oversize drop (1500 B → no reply) — the regression for the
///   PR #15 buffer-truncation bug
/// * wrong-PSK tamper (replaces the Client with a fresh tunnel using
///   a different PSK; the next packet must NOT round-trip)
async fn run_endtoend(cfg: LoopbackConfig) {
    let (mgr_tx, _mgr_rx) = tokio::sync::oneshot::channel();
    let mgr = Arc::new(TunnelManager::new(mgr_tx, None));

    let psk = "loopback-shared-psk";

    // (a) Echo server at forward_target.
    let echo_sock = UdpSocket::bind(cfg.forward_target_addr)
        .await
        .expect("bind echo");
    let echo_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match echo_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let _ = echo_sock.send_to(&buf[..n], from).await;
                }
                Err(_) => return,
            }
        }
    });

    // (b) Bring up Remote first so the upload listener is ready.
    mgr.start_tunnel(remote_spec(&cfg, psk))
        .await
        .expect("start remote");

    // (c) Bring up Client.
    mgr.start_tunnel(client_spec(&cfg, psk))
        .await
        .expect("start client");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // (d) Simulated end-user socket on the SAME address family as the
    // Client's local_listen_addr. local_listen is always IPv4 in our
    // test fixtures (it's the inner UDP listener; transport selection
    // only changes the spoof envelope on the download path).
    let user_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind user");
    let payload = b"hello loopback world";
    user_sock
        .send_to(payload, cfg.end_user_listen)
        .await
        .expect("send");

    let mut buf = vec![0u8; 65536];
    let (n, _from) = timeout(Duration::from_secs(2), user_sock.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "recv timed out for transport {:?}: payload didn't round-trip",
                cfg.transport
            )
        })
        .expect("recv ok");
    assert_eq!(
        &buf[..n],
        payload,
        "round-tripped payload mismatch for transport {:?}",
        cfg.transport
    );
    eprintln!(
        "loopback[{:?}]: sent {} bytes, received {} bytes; match=true",
        cfg.transport,
        payload.len(),
        n
    );

    // (e) Near-MTU round-trip — regression guard for PR #14.
    let big_payload = vec![0xAB_u8; 1400];
    user_sock
        .send_to(&big_payload, cfg.end_user_listen)
        .await
        .expect("send big");
    let (n_big, _) = timeout(Duration::from_secs(2), user_sock.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "near-MTU recv timed out for transport {:?} — silent oversize drop?",
                cfg.transport
            )
        })
        .expect("recv big ok");
    assert_eq!(
        &buf[..n_big],
        &big_payload[..],
        "1400-byte payload mangled for transport {:?}",
        cfg.transport
    );
    eprintln!(
        "loopback[{:?}]: 1400-byte round-trip match=true",
        cfg.transport
    );

    // (f) Oversize drop — regression guard for PR #15. A 1500-byte
    // payload exceeds the mtu=1400 cap; the cap check must WARN-drop
    // it, not silently truncate.
    let oversize_payload = vec![0xCD_u8; 1500];
    user_sock
        .send_to(&oversize_payload, cfg.end_user_listen)
        .await
        .expect("send oversize");
    let oversize_res = timeout(Duration::from_millis(500), user_sock.recv_from(&mut buf)).await;
    assert!(
        oversize_res.is_err(),
        "oversize (1500 > mtu=1400) packet should be WARN-dropped for transport {:?}",
        cfg.transport
    );
    eprintln!(
        "loopback[{:?}]: oversize packet correctly dropped (not truncated)",
        cfg.transport
    );

    // (g) Tamper test: replace Client with a different PSK; next
    // packet must NOT come back.
    mgr.stop_tunnel(cfg.client_id).await.unwrap();
    let mut tampered = client_spec(&cfg, "a-different-psk");
    tampered.name = format!("loop-client-{:?}-tamper", cfg.transport).to_lowercase();
    mgr.start_tunnel(tampered).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    user_sock
        .send_to(b"tampered", cfg.end_user_listen)
        .await
        .unwrap();
    let tamper_res = timeout(Duration::from_millis(500), user_sock.recv_from(&mut buf)).await;
    assert!(
        tamper_res.is_err(),
        "wrong-PSK packet should have been dropped for transport {:?}",
        cfg.transport
    );
    eprintln!(
        "loopback[{:?}]: wrong-PSK packet correctly dropped",
        cfg.transport
    );

    mgr.stop_all().await;
    echo_handle.abort();
}

#[tokio::test]
#[ignore]
async fn loopback_udp_endtoend() {
    run_endtoend(LoopbackConfig {
        transport: Transport::Udp,
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        spoof_ip: "127.0.0.1",
        end_user_listen: "127.0.0.1:25001".parse().unwrap(),
        remote_upload: "127.0.0.1:28001".parse().unwrap(),
        forward_target_addr: "127.0.0.1:29001".parse().unwrap(),
        download_port: 28443,
        client_id: 101,
        remote_id: 102,
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn loopback_tcp_syn_endtoend() {
    run_endtoend(LoopbackConfig {
        transport: Transport::TcpSyn,
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        spoof_ip: "127.0.0.1",
        end_user_listen: "127.0.0.1:25011".parse().unwrap(),
        remote_upload: "127.0.0.1:28011".parse().unwrap(),
        forward_target_addr: "127.0.0.1:29011".parse().unwrap(),
        download_port: 28453,
        client_id: 201,
        remote_id: 202,
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn loopback_icmp_endtoend() {
    run_endtoend(LoopbackConfig {
        transport: Transport::Icmp,
        // Phase 8b-compatible loopback default. Phase R4 adds a separate
        // `loopback_icmp_request_endtoend` test for the new mode.
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        spoof_ip: "127.0.0.1",
        end_user_listen: "127.0.0.1:25021".parse().unwrap(),
        remote_upload: "127.0.0.1:28021".parse().unwrap(),
        forward_target_addr: "127.0.0.1:29021".parse().unwrap(),
        // ICMP has no destination port on the wire; the value is still
        // required by the spec for parity with UDP/TCP-SYN.
        download_port: 28463,
        client_id: 301,
        remote_id: 302,
    })
    .await;
}

/// Regression for the idle-resume bug ("won't reconnect after 5 min
/// idle until I Stop+Start").
///
/// Scenario, in dataplane-time:
/// 1. End-user A sends a packet via the Client tunnel. Iran's session
///    table now holds A.
/// 2. A goes silent.
/// 3. Before A is idle-evicted, end-user B (different source port —
///    the same end-user device after a WireGuard reconnect picks a
///    new ephemeral port) sends a fresh packet. The table now holds
///    A and B.
/// 4. The Remote echoes B's payload back as a spoofed download. The
///    Client must deliver it to B, not A — A's port is long gone on
///    the end-user side and any reply addressed there would vanish.
///
/// With the pre-fix `any_session` implementation (shard-iteration,
/// first-non-empty wins), the reply would land on A's address
/// deterministically, the test would time out on B's socket, and the
/// real-world symptom is the user-visible "won't reconnect" bug. The
/// fix tracks the most-recently-active session and prefers it.
///
/// `idle_timeout_sec` is set to 60 here so both sessions stay live for
/// the duration of the test; the bug is precisely the overlap window.
#[tokio::test]
#[ignore]
async fn loopback_idle_resume_picks_freshest_session() {
    use std::sync::Arc;
    use std::time::Duration;

    use sublyne_dataplane::manager::TunnelManager;
    use sublyne_dataplane::spec::{Role, Transport, TunnelSpec};
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let (mgr_tx, _mgr_rx) = tokio::sync::oneshot::channel();
    let mgr = Arc::new(TunnelManager::new(mgr_tx, None));

    // Distinct ports so this test runs cleanly back-to-back with the
    // four transport-specific loopback tests above.
    let end_user_listen: SocketAddr = "127.0.0.1:25101".parse().unwrap();
    let remote_upload: SocketAddr = "127.0.0.1:28101".parse().unwrap();
    let forward_target_addr: SocketAddr = "127.0.0.1:29101".parse().unwrap();
    let download_port = 28543u16;
    let psk = "idle-resume-shared-psk";

    // Echo at forward_target — same shape as run_endtoend's echo.
    let echo_sock = UdpSocket::bind(forward_target_addr)
        .await
        .expect("bind echo");
    let echo_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match echo_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let _ = echo_sock.send_to(&buf[..n], from).await;
                }
                Err(_) => return,
            }
        }
    });

    // Build Client + Remote specs by hand so we can use distinct
    // tunnel ids without colliding with the four transport tests'
    // 101/201/301/401 series.
    let client_spec = TunnelSpec {
        id: 501,
        role: Role::Client,
        name: "loop-client-idle-resume".into(),
        mtu: 1400,
        psk: psk.into(),
        // Plenty of room for two concurrent sessions; we deliberately
        // keep both alive for the duration of the test.
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        download_spoof_source_ip: "127.0.0.1".into(),
        download_spoof_source_port: 443,
        local_listen_addr: Some(end_user_listen.to_string()),
        download_receive_port: Some(download_port),
        upload_target_addr: Some(remote_upload.to_string()),
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
        upload_listen_mode: sublyne_dataplane::spec::UploadListenMode::Udp,
        ports: Vec::new(),
    };
    let remote_spec = TunnelSpec {
        id: 502,
        role: Role::Remote,
        name: "loop-remote-idle-resume".into(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        download_spoof_source_ip: "127.0.0.1".into(),
        download_spoof_source_port: 443,
        local_listen_addr: None,
        download_receive_port: None,
        upload_target_addr: None,
        wireguard_fwmark: 0,
        upload_listen_addr: Some(remote_upload.to_string()),
        forward_target: Some(forward_target_addr.to_string()),
        download_send_port: Some(download_port),
        client_real_ip: Some("127.0.0.1".into()),
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: None,
        upload_listen_mode: sublyne_dataplane::spec::UploadListenMode::Udp,
        ports: Vec::new(),
    };

    mgr.start_tunnel(remote_spec).await.expect("start remote");
    mgr.start_tunnel(client_spec).await.expect("start client");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // User A — bind a specific ephemeral port so we can compare
    // against B's port unambiguously.
    let user_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind A");
    user_a
        .send_to(b"hello-from-A", end_user_listen)
        .await
        .expect("A send");
    // Drain A's echo so the table sees A as active, but A's
    // last_seen is now ~immediately.
    let mut buf = vec![0u8; 4096];
    let (n_a, _) = timeout(Duration::from_secs(2), user_a.recv_from(&mut buf))
        .await
        .expect("A round-trip timed out")
        .expect("A recv ok");
    assert_eq!(
        &buf[..n_a],
        b"hello-from-A",
        "baseline A → A reply did not round-trip"
    );

    // Now user B reconnects — distinct ephemeral port. Both A and B
    // are now live (A's last_seen is ~50 ms old, well under the 60 s
    // idle timeout). With the pre-fix selection rule, A would still
    // win every spoofed-reply delivery and B would never see its echo.
    let user_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind B");
    let b_local = user_b.local_addr().expect("B local_addr");
    let a_local = user_a.local_addr().expect("A local_addr");
    assert_ne!(
        a_local.port(),
        b_local.port(),
        "A and B must pick different ephemeral ports for this test to mean anything"
    );
    user_b
        .send_to(b"hello-from-B", end_user_listen)
        .await
        .expect("B send");

    // B's echo must come back to B, not A. Time-bound both reads to
    // make the failure mode crisp.
    let mut b_buf = vec![0u8; 4096];
    let (n_b, _) = timeout(Duration::from_secs(2), user_b.recv_from(&mut b_buf))
        .await
        .expect("B round-trip timed out — idle-resume bug regression: spoofed reply was delivered to the stale session A instead of the fresh B")
        .expect("B recv ok");
    assert_eq!(
        &b_buf[..n_b],
        b"hello-from-B",
        "B's round-tripped payload was corrupted"
    );

    // A must NOT have received B's echo while waiting. (If the bug
    // were present, A would have grabbed B's reply.)
    let leaked = timeout(Duration::from_millis(200), user_a.recv_from(&mut buf)).await;
    assert!(
        leaked.is_err(),
        "spoofed reply intended for B leaked to A — `any_session` returned the stale session"
    );

    mgr.stop_all().await;
    echo_handle.abort();
}

#[tokio::test]
#[ignore]
async fn loopback_icmpv6_endtoend() {
    run_endtoend(LoopbackConfig {
        transport: Transport::Icmpv6,
        icmp_echo_mode: sublyne_dataplane::spec::IcmpEchoMode::Reply,
        spoof_ip: "::1",
        // The end-user UDP listener and the forward-target echo
        // server are unaffected by the download transport — they
        // remain IPv4 here. Only the spoof envelope flips to IPv6.
        end_user_listen: "127.0.0.1:25031".parse().unwrap(),
        remote_upload: "127.0.0.1:28031".parse().unwrap(),
        forward_target_addr: "127.0.0.1:29031".parse().unwrap(),
        download_port: 28473,
        client_id: 401,
        remote_id: 402,
    })
    .await;
}
