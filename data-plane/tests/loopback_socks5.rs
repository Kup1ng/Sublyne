//! End-to-end loopback test for the SOCKS5 upload path.
//!
//! Stands up the four pieces in a single process:
//!
//! 1. **microsocks** as a real RFC 1928 SOCKS5 server on `127.0.0.1`.
//! 2. **UDP echo server** standing in for `forward_target`.
//! 3. **Remote tunnel** with `upload_listen_mode = Socks5Tcp`, reading
//!    `[u16][bytes]` frames off a TCP listener and forwarding payloads
//!    to the echo server (UDP). Download via plain UDP spoof to the
//!    Client.
//! 4. **Client tunnel** with `socks5_target` pointing at microsocks,
//!    `upload_target_addr` pointing at the Remote's TCP listen addr
//!    (which microsocks dials on its behalf).
//!
//! End-user UDP packet → Client local_listen → SOCKS5 framing →
//! microsocks → Remote TCP listen → Remote upload to echo → echo
//! reply → Remote spoofs UDP back to Client → Client delivers UDP to
//! end-user socket. Bytes round-trip.
//!
//! Two test variants:
//!
//! - `socks5_upload_round_trip_through_microsocks` — the R9a baseline,
//!   `parallel_connections=1`.
//! - `socks5_pool_of_4_round_trip_through_microsocks` — the R9b
//!   variant, `parallel_connections=4`. Asserts that microsocks
//!   actually saw 4 distinct inbound TCP connections (which means 4
//!   independent Starlink links on the real proxy).
//!
//! Marked `#[ignore]` because:
//!  - The download path opens raw sockets (`CAP_NET_RAW` required).
//!  - microsocks must be installed (`apt-get install microsocks`).
//!
//! Run on a Linux host with:
//! ```text
//! sudo setcap cap_net_raw,cap_net_admin=eip target/debug/deps/loopback_socks5-*
//! cargo test --test loopback_socks5 -- --ignored --nocapture --test-threads=1
//! ```

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sublyne_dataplane::manager::TunnelManager;
use sublyne_dataplane::spec::{
    IcmpEchoMode, Role, Socks5Target, Transport, TunnelSpec, UploadListenMode,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Spawn microsocks on a random free port and return both the bound
/// port and the child handle. The child is killed when the test
/// returns; microsocks itself shuts down cleanly on SIGTERM.
async fn spawn_microsocks() -> (u16, tokio::process::Child) {
    // microsocks doesn't take a "bind to ephemeral port" flag, so
    // first grab a free port via a tokio listener, drop it, then
    // launch microsocks against the just-freed port. There's a brief
    // race window but in practice it's never hit on loopback.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let child = tokio::process::Command::new("microsocks")
        .args(["-i", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn microsocks (apt-get install microsocks)");
    // microsocks binds the listener synchronously inside its main();
    // give it a heartbeat to be ready.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (port, child)
}

/// End-to-end: send a UDP payload through the SOCKS5 client tunnel
/// and verify the bytes echo back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn socks5_upload_round_trip_through_microsocks() {
    let (proxy_port, mut microsocks_child) = spawn_microsocks().await;

    let (mgr_tx, _mgr_rx) = tokio::sync::oneshot::channel();
    let mgr = Arc::new(TunnelManager::new(mgr_tx, None));
    let psk = "loopback-socks5-psk";

    // Echo server stands in for forward_target.
    let echo_addr: SocketAddr = "127.0.0.1:14501".parse().unwrap();
    let echo_sock = UdpSocket::bind(echo_addr).await.expect("bind echo");
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

    // Remote tunnel: TCP listener (upload_listen_mode=socks5_tcp) on
    // 127.0.0.1:14502; spoofs UDP downloads back to 127.0.0.1:14503.
    let remote_upload_listen: SocketAddr = "127.0.0.1:14502".parse().unwrap();
    let download_port: u16 = 14503;
    let spoof_ip = "127.0.0.1";
    let remote_spec = TunnelSpec {
        id: 901,
        role: Role::Remote,
        name: "loop-socks5-remote".into(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: IcmpEchoMode::Reply,
        download_spoof_source_ip: spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: None,
        download_receive_port: None,
        upload_target_addr: None,
        wireguard_fwmark: 0,
        upload_listen_addr: Some(remote_upload_listen.to_string()),
        forward_target: Some(echo_addr.to_string()),
        download_send_port: Some(download_port),
        client_real_ip: Some(spoof_ip.into()),
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: None,
        upload_listen_mode: UploadListenMode::Socks5Tcp,
        ports: Vec::new(),
        forward_protocol: sublyne_dataplane::spec::ForwardProtocol::Udp,
        tcp_reliability_engine: sublyne_dataplane::spec::TcpReliabilityEngine::Kcp,
        forward_kcp: None,
        forward_quic: None,
    };

    // Client tunnel: end-user UDP listener on 127.0.0.1:14504, uploads
    // through microsocks (127.0.0.1:proxy_port) to the Remote's TCP
    // listen at 14502.
    let end_user_listen: SocketAddr = "127.0.0.1:14504".parse().unwrap();
    let client_spec = TunnelSpec {
        id: 902,
        role: Role::Client,
        name: "loop-socks5-client".into(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 10,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: IcmpEchoMode::Reply,
        download_spoof_source_ip: spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: Some(end_user_listen.to_string()),
        download_receive_port: Some(download_port),
        upload_target_addr: Some(remote_upload_listen.to_string()),
        wireguard_fwmark: 0,
        upload_listen_addr: None,
        forward_target: None,
        download_send_port: None,
        client_real_ip: None,
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: Some(Socks5Target {
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: None,
            password: None,
            parallel_connections: 1,
            min_ready_slots: 1,
        }),
        upload_listen_mode: UploadListenMode::Udp,
        ports: Vec::new(),
        forward_protocol: sublyne_dataplane::spec::ForwardProtocol::Udp,
        tcp_reliability_engine: sublyne_dataplane::spec::TcpReliabilityEngine::Kcp,
        forward_kcp: None,
        forward_quic: None,
    };

    // Bring up Remote first so the TCP listener is ready before the
    // Client tries to CONNECT through microsocks.
    mgr.start_tunnel(remote_spec)
        .await
        .expect("start remote socks5_tcp");
    mgr.start_tunnel(client_spec)
        .await
        .expect("start client socks5");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // End-user UDP socket.
    let user_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind user");
    let payload = b"hello via microsocks";
    user_sock
        .send_to(payload, end_user_listen)
        .await
        .expect("send");

    let mut buf = vec![0u8; 65536];
    let (n, _from) = timeout(Duration::from_secs(3), user_sock.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("recv timed out: SOCKS5 path didn't round-trip"))
        .expect("recv");
    assert_eq!(&buf[..n], payload, "SOCKS5 round-tripped payload mismatch");
    eprintln!(
        "loopback[socks5]: sent {} bytes, received {} bytes; match=true",
        payload.len(),
        n
    );

    // Send a few more so the user can later confirm multiple frames
    // share one TCP connection on the proxy (the test doesn't directly
    // verify that — it's a "tcpdump on the proxy" sort of check — but
    // the framing test in src/upload/socks5.rs's unit suite already
    // pins it).
    for i in 0..5 {
        let pl = format!("frame-{i}");
        user_sock
            .send_to(pl.as_bytes(), end_user_listen)
            .await
            .expect("send frame");
        let (n, _) = timeout(Duration::from_secs(2), user_sock.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("frame-{i} round-trip timeout"))
            .expect("recv frame");
        assert_eq!(&buf[..n], pl.as_bytes(), "frame-{i} mismatch");
    }
    eprintln!("loopback[socks5]: 5 extra frames round-trip cleanly");

    drop(echo_handle);
    let _ = microsocks_child.kill().await;
}

/// R9b variant: end-to-end with `parallel_connections=4`. Sends a
/// burst of distinct end-user source ports to spread the flows across
/// the SOCKS5 pool, then asserts:
///
/// 1. The forward_target (UDP echo server) received the expected
///    number of upload payloads, proving the SOCKS5 path actually
///    moved bytes from Client → microsocks → Remote → forward_target.
/// 2. `ss -tn` shows microsocks holding 4 ESTABLISHED inbound TCP
///    connections from the dataplane, proving the pool genuinely
///    opened N parallel links.
/// 3. At least one round-trip succeeds end-to-end (the spoof return
///    path works through the parallel-pool variant).
///
/// We do NOT check per-flow round-trip because the Client side
/// delivers spoofed downloads via `session_table.any_session()` —
/// it has no way to recover the original UDP source from the spoof
/// envelope, so multi-flow replies all land on whichever session is
/// "current". This is by design (PRD: one tunnel = one end user).
/// The full round-trip is covered by the single-flow R9a test
/// above; this test exercises pool *distribution* and the *upload*
/// half of the multi-link parallelism.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn socks5_pool_of_4_round_trip_through_microsocks() {
    let (proxy_port, mut microsocks_child) = spawn_microsocks().await;

    let (mgr_tx, _mgr_rx) = tokio::sync::oneshot::channel();
    let mgr = Arc::new(TunnelManager::new(mgr_tx, None));
    let psk = "loopback-socks5-pool-psk";

    // Count incoming UDP datagrams at the forward target so we can
    // assert the SOCKS5 upload path actually moved bytes through.
    let echo_addr: SocketAddr = "127.0.0.1:14601".parse().unwrap();
    let echo_sock = UdpSocket::bind(echo_addr).await.expect("bind echo");
    let echo_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let echo_count_for_task = echo_count.clone();
    let echo_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match echo_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    echo_count_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = echo_sock.send_to(&buf[..n], from).await;
                }
                Err(_) => return,
            }
        }
    });

    let remote_upload_listen: SocketAddr = "127.0.0.1:14602".parse().unwrap();
    let download_port: u16 = 14603;
    let spoof_ip = "127.0.0.1";
    let remote_spec = TunnelSpec {
        id: 911,
        role: Role::Remote,
        name: "loop-socks5-remote-pool".into(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 64,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: IcmpEchoMode::Reply,
        download_spoof_source_ip: spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: None,
        download_receive_port: None,
        upload_target_addr: None,
        wireguard_fwmark: 0,
        upload_listen_addr: Some(remote_upload_listen.to_string()),
        forward_target: Some(echo_addr.to_string()),
        download_send_port: Some(download_port),
        client_real_ip: Some(spoof_ip.into()),
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: None,
        upload_listen_mode: UploadListenMode::Socks5Tcp,
        ports: Vec::new(),
        forward_protocol: sublyne_dataplane::spec::ForwardProtocol::Udp,
        tcp_reliability_engine: sublyne_dataplane::spec::TcpReliabilityEngine::Kcp,
        forward_kcp: None,
        forward_quic: None,
    };

    let end_user_listen: SocketAddr = "127.0.0.1:14604".parse().unwrap();
    let client_spec = TunnelSpec {
        id: 912,
        role: Role::Client,
        name: "loop-socks5-client-pool".into(),
        mtu: 1400,
        psk: psk.into(),
        max_connections: 64,
        idle_timeout_sec: 60,
        download_transport: Transport::Udp,
        icmp_echo_mode: IcmpEchoMode::Reply,
        download_spoof_source_ip: spoof_ip.into(),
        download_spoof_source_port: 443,
        local_listen_addr: Some(end_user_listen.to_string()),
        download_receive_port: Some(download_port),
        upload_target_addr: Some(remote_upload_listen.to_string()),
        wireguard_fwmark: 0,
        upload_listen_addr: None,
        forward_target: None,
        download_send_port: None,
        client_real_ip: None,
        ping_smoothing_enabled: false,
        ping_smoothing_target_ms: 60,
        pacing_enabled: false,
        pacing_target_ms: 100,
        socks5_target: Some(Socks5Target {
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: None,
            password: None,
            parallel_connections: 4,
            min_ready_slots: 1,
        }),
        upload_listen_mode: UploadListenMode::Udp,
        ports: Vec::new(),
        forward_protocol: sublyne_dataplane::spec::ForwardProtocol::Udp,
        tcp_reliability_engine: sublyne_dataplane::spec::TcpReliabilityEngine::Kcp,
        forward_kcp: None,
        forward_quic: None,
    };

    mgr.start_tunnel(remote_spec)
        .await
        .expect("start remote socks5_tcp pool");
    mgr.start_tunnel(client_spec)
        .await
        .expect("start client socks5 pool");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Spin up 16 distinct end-user source sockets so each flow has
    // its own session key. The Client's sticky-hash routes the
    // sessions across the 4 pool slots; over 16 flows the spread
    // should cover every slot.
    let mut user_socks: Vec<UdpSocket> = Vec::new();
    for _ in 0..16 {
        user_socks.push(UdpSocket::bind("127.0.0.1:0").await.expect("bind user"));
    }
    let payload = b"r9b pool payload";
    for sock in &user_socks {
        sock.send_to(payload, end_user_listen).await.expect("send");
    }
    // Give the SOCKS5 path time to ferry every upload to the echo
    // server. 16 frames × ~5 ms loopback is generous.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let upload_count = echo_count.load(std::sync::atomic::Ordering::SeqCst);
    eprintln!("loopback[socks5/4]: echo server received {upload_count} upload datagrams (sent 16)");
    assert!(
        upload_count >= 16,
        "expected ≥ 16 upload datagrams at forward_target, got {upload_count} — pool not moving bytes?"
    );

    // Confirm at least one round-trip works on the parallel-pool
    // variant. The reply goes to whichever session is "current" —
    // typically the most recent sender — so we await on the LAST
    // socket. The earlier flows' reply payloads are dropped by
    // design (PRD: one tunnel = one end user).
    let last_sock = user_socks.last().expect("at least one user sock");
    let mut buf = vec![0u8; 65536];
    let (n, _from) = timeout(Duration::from_secs(3), last_sock.recv_from(&mut buf))
        .await
        .expect("at least one reply must round-trip back through the pool")
        .expect("recv");
    assert_eq!(&buf[..n], payload, "round-trip payload mismatch");
    eprintln!("loopback[socks5/4]: at least one round-trip succeeded ({n} bytes)");

    // Count distinct established inbound TCP connections to microsocks
    // by parsing `ss -tn`. The dataplane is the only client on this
    // loopback proxy in the test, so the count equals the pool size
    // when the pool is healthy.
    let ss_out = tokio::process::Command::new("ss")
        .args(["-tn", "state", "established"])
        .output()
        .await
        .expect("run ss");
    let table = String::from_utf8_lossy(&ss_out.stdout);
    let needle = format!("127.0.0.1:{proxy_port}");
    let count = table.lines().filter(|l| l.contains(&needle)).count();
    eprintln!(
        "loopback[socks5/4]: ss reports {count} ESTABLISHED conns to 127.0.0.1:{proxy_port}\n{}",
        table
    );
    assert!(
        count >= 4,
        "expected at least 4 ESTABLISHED TCP conns to microsocks, got {count}"
    );

    drop(user_socks);
    drop(echo_handle);
    let _ = microsocks_child.kill().await;
}
