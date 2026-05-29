//! Cosmetic ICMP echo-reply synthesis for Client tunnels.
//!
//! PRD §3.3 lists ping smoothing as an opt-in, *cosmetic* feature: when
//! `ping_smoothing_enabled` is true on a Client tunnel, the dataplane
//! synthesizes ICMP echo-replies for incoming echo-requests after a
//! configured delay (`ping_smoothing_target_ms`, default 60 ms). The
//! intent is to hide the asymmetric upload/download RTT from external
//! monitoring tools that ping the Client's public IP.
//!
//! ## Why this is a separate module from `transport::icmp`
//!
//! `transport::icmp` parses ICMP type 0 (echo-reply) packets — that's
//! the spoof transport. Here we parse type 8 (echo-request), so the
//! parsers live in their own module to avoid coupling.
//!
//! ## Kernel competition (and how to suppress it)
//!
//! Linux's kernel responds to incoming echo-requests by default. Our
//! synthesized reply usually arrives later than the kernel's (we
//! deliberately introduce delay), so `ping(8)` picks up the kernel's
//! reply first and reports its faster RTT. To make smoothing visible
//! to monitoring tools the operator must drop kernel echo-replies
//! with iptables — see the install-time log message emitted by
//! [`spawn`].
//!
//! Two reasons we don't install that iptables rule from here:
//!
//! 1. The rule needs to be scoped to a destination IP. The typical
//!    `local_listen_addr` is `0.0.0.0:443` (wildcard), so the
//!    appropriate scope would be every public IP on the box — far too
//!    invasive a side effect for a per-tunnel toggle.
//! 2. Operators sometimes want both replies visible during testing
//!    (e.g. tcpdump can see the smoothed packet next to the kernel's
//!    instant one). Forcing the suppression would mask that workflow.
//!
//! The synthesized reply is still observable in `tcpdump` regardless of
//! the kernel competition, which is what the Phase 13 live test
//! verifies.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use super::tunnel::MutableConfigSlot;
use crate::transport::icmp::{IPV4_HDR_LEN, IP_PROTO_ICMP};

/// ICMP echo-request type per RFC 792. ICMP code is always 0 for echo.
const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_TYPE_ECHO_REPLY: u8 = 0;
/// Minimum bytes we need to look at to extract id/seq from an ICMP
/// header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8.
const ICMP_HDR_LEN: usize = 8;

/// Open the raw IPv4 ICMP socket the responder reads from. Returns the
/// fd ready to wrap in `AsyncFd`. Same kernel delivery rules as the
/// existing ICMP recv socket: every ICMP packet the kernel sees ends up
/// here via `raw_local_deliver`, ahead of the kernel's own protocol
/// stack.
pub fn open_recv_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "ping-smooth/recv");
    Ok(sock)
}

/// Open the raw IPv4 ICMP send socket with `IP_HDRINCL` so we can forge
/// the source IP (= the request's destination IP). One socket per
/// responder is enough — `sendto` is non-blocking and the responder
/// only issues a couple of bytes per packet.
pub fn open_send_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    sock.set_header_included_v4(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "ping-smooth/send");
    Ok(sock)
}

/// Spawn the ICMP echo responder task on the supplied JoinSet. The task
/// reads echo-requests, schedules synthesized echo-replies after the
/// per-tunnel `ping_smoothing_target_ms`, and stops cleanly when
/// `stop_rx` flips.
///
/// `listen_ip` is the dotted-quad IP the tunnel binds (`0.0.0.0` for a
/// wildcard listen). Echo-requests destined to a different specific
/// address are ignored — the responder only smooths pings to *this*
/// tunnel's listen address. For a wildcard listen the responder
/// accepts every request (matching what the operator's monitoring
/// tools would actually probe).
///
/// Errors during socket setup are logged and the responder simply
/// doesn't start; the tunnel itself stays up.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    tasks: &mut JoinSet<()>,
    tunnel_id: i64,
    listen_ip: Option<Ipv4Addr>,
    mutable_config: MutableConfigSlot,
    stop_rx: watch::Receiver<bool>,
) {
    let recv_sock = match open_recv_socket() {
        Ok(s) => s,
        Err(e) => {
            warn!(tunnel_id, err = %e,
                "ping-smooth: could not open raw ICMP recv socket (need CAP_NET_RAW); smoothing disabled for this tunnel");
            return;
        }
    };
    let send_sock = match open_send_socket() {
        Ok(s) => s,
        Err(e) => {
            warn!(tunnel_id, err = %e,
                "ping-smooth: could not open raw ICMP send socket; smoothing disabled for this tunnel");
            return;
        }
    };

    info!(
        tunnel_id,
        listen_ip = ?listen_ip,
        "ping-smooth: responder armed. NOTE: the Linux kernel also replies to echo-requests by default; add 'iptables -A INPUT -p icmp --icmp-type echo-request -j DROP' (carefully scoped) if you need pings to show the smoothed RTT instead of the real one."
    );

    let recv_fd: OwnedFd = recv_sock.into();
    let recv = match AsyncFd::new(recv_fd) {
        Ok(f) => Arc::new(f),
        Err(e) => {
            warn!(tunnel_id, err = %e,
                "ping-smooth: AsyncFd setup failed; smoothing disabled for this tunnel");
            return;
        }
    };
    let send_fd: OwnedFd = send_sock.into();
    let send = Arc::new(send_fd);

    tasks.spawn(responder_loop(
        recv,
        send,
        tunnel_id,
        listen_ip,
        mutable_config,
        stop_rx,
    ));
}

async fn responder_loop(
    recv: Arc<AsyncFd<OwnedFd>>,
    send: Arc<OwnedFd>,
    tunnel_id: i64,
    listen_ip: Option<Ipv4Addr>,
    mutable_config: MutableConfigSlot,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!(tunnel_id, "ping-smooth: responder stopping");
                return;
            }
            guard_res = recv.readable() => {
                let mut guard = match guard_res {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(tunnel_id, err = %e, "ping-smooth: readable awaiter failed");
                        return;
                    }
                };
                let n_res = guard.try_io(|fd| {
                    // SAFETY: the AsyncFd guarantees fd is open and
                    // exclusively borrowed across this call.
                    let rc = unsafe {
                        libc::recvfrom(
                            fd.get_ref().as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            libc::MSG_DONTWAIT,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    };
                    if rc < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(rc as usize)
                    }
                });
                let n = match n_res {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        warn!(tunnel_id, err = %e, "ping-smooth: recvfrom");
                        continue;
                    }
                    Err(_would_block) => continue,
                };
                if n < IPV4_HDR_LEN + ICMP_HDR_LEN { continue; }
                handle_echo_request(
                    &buf[..n],
                    tunnel_id,
                    listen_ip,
                    &mutable_config,
                    &send,
                ).await;
            }
        }
    }
}

/// Process one IPv4 packet from the raw socket. Returns immediately if
/// it isn't an echo-request, doesn't match our listen IP, or smoothing
/// is currently disabled (the operator can flip the toggle at runtime
/// via UpdateTunnel; we honour the freshest value per packet).
async fn handle_echo_request(
    pkt: &[u8],
    tunnel_id: i64,
    listen_ip: Option<Ipv4Addr>,
    mutable_config: &MutableConfigSlot,
    send: &Arc<OwnedFd>,
) {
    // IPv4 header parsing — version + IHL + protocol must match. The
    // helper module's parser is type=0 only; inline the bits we need
    // here so we can accept type=8.
    let version = pkt[0] >> 4;
    let ihl = (pkt[0] & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return;
    }
    let ip_hdr_len = ihl * 4;
    if pkt.len() < ip_hdr_len + ICMP_HDR_LEN {
        return;
    }
    if pkt[9] != IP_PROTO_ICMP {
        return;
    }

    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    let icmp = &pkt[ip_hdr_len..];
    if icmp[0] != ICMP_TYPE_ECHO_REQUEST || icmp[1] != 0 {
        return;
    }

    // If the operator pinned the tunnel to a specific listen IP, only
    // smooth pings destined to that IP. Wildcard listen accepts all
    // (matching what the monitoring tools would naturally probe).
    if let Some(ip) = listen_ip {
        if ip != dst_ip {
            return;
        }
    }

    // Read the operator-set delay fresh on every packet so a runtime
    // flip via UpdateTunnel applies immediately.
    let (enabled, target_ms) = {
        let cfg = mutable_config.read().expect("mutable_config read");
        (cfg.ping_smoothing_enabled, cfg.ping_smoothing_target_ms)
    };
    if !enabled {
        return;
    }

    // Copy the echo-request body. The synthesized reply has the same
    // identifier, sequence, and payload — exactly what RFC 792 says an
    // echo-reply should carry.
    let id_seq_body: Vec<u8> = icmp[4..].to_vec();

    let mut reply = Vec::with_capacity(IPV4_HDR_LEN + ICMP_HDR_LEN + id_seq_body.len());
    build_echo_reply(dst_ip, src_ip, &id_seq_body, &mut reply);

    let send_clone = send.clone();
    tokio::spawn(async move {
        if target_ms > 0 {
            sleep(Duration::from_millis(target_ms as u64)).await;
        }
        // Use libc::sendto directly (matching the pattern in
        // tunnel/remote.rs). The send socket is non-blocking; if the
        // kernel buffer is full we get EAGAIN and drop the reply (the
        // operator's monitoring sees the kernel's reply anyway).
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(src_ip.octets()),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: send_clone is a valid open raw socket fd for the
        // duration of this call; sa and reply live for the call. The
        // raw send socket has IP_HDRINCL set so the IPv4 header bytes
        // we built are honoured.
        let rc = unsafe {
            libc::sendto(
                send_clone.as_raw_fd(),
                reply.as_ptr() as *const libc::c_void,
                reply.len(),
                0,
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                debug!(tunnel_id, err = %e, "ping-smooth: send would block; dropping reply");
            } else {
                warn!(tunnel_id, err = %e, "ping-smooth: sendto");
            }
        } else {
            debug!(
                tunnel_id,
                dst = %src_ip,
                ms = target_ms,
                "ping-smooth: synthesized echo-reply"
            );
        }
    });
}

/// Build the IPv4 echo-reply we send back. `id_seq_body` is the bytes
/// from the request's ICMP header offset 4 onward (identifier +
/// sequence + payload), which we mirror verbatim in the reply.
fn build_echo_reply(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, id_seq_body: &[u8], out: &mut Vec<u8>) {
    let total_len = IPV4_HDR_LEN + ICMP_HDR_LEN + id_seq_body.len();
    out.clear();
    out.reserve(total_len);

    // IPv4 header (20 bytes), DF cleared.
    out.push(0x45);
    out.push(0x00);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // identification
    out.extend_from_slice(&0u16.to_be_bytes()); // flags=0, frag offset=0
    out.push(64); // TTL
    out.push(IP_PROTO_ICMP);
    out.extend_from_slice(&0u16.to_be_bytes()); // IP checksum placeholder
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());

    let ip_check = crate::transport::internet_checksum(&out[..IPV4_HDR_LEN]);
    out[10] = (ip_check >> 8) as u8;
    out[11] = ip_check as u8;

    // ICMP header (type=0, code=0, checksum=0 placeholder).
    out.push(ICMP_TYPE_ECHO_REPLY);
    out.push(0); // code
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder

    // identifier + sequence + payload (mirrored from the request).
    out.extend_from_slice(id_seq_body);

    let icmp_check = crate::transport::internet_checksum(&out[IPV4_HDR_LEN..]);
    out[IPV4_HDR_LEN + 2] = (icmp_check >> 8) as u8;
    out[IPV4_HDR_LEN + 3] = icmp_check as u8;
}

/// `parse_listen_ip` is a small shim used by the client tunnel actor
/// to pull the host-IP out of a `host:port` listen string. Wildcard
/// listens (`0.0.0.0`) come back as `None` so the responder accepts
/// every echo-request.
pub fn parse_listen_ip(listen: &str) -> Option<Ipv4Addr> {
    let addr: std::net::SocketAddr = listen.parse().ok()?;
    match addr.ip() {
        IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED => None,
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_ip_handles_wildcard() {
        assert_eq!(parse_listen_ip("0.0.0.0:443"), None);
    }

    #[test]
    fn parse_listen_ip_handles_specific_v4() {
        assert_eq!(
            parse_listen_ip("198.51.100.10:443"),
            Some("198.51.100.10".parse().unwrap())
        );
    }

    #[test]
    fn parse_listen_ip_handles_v6() {
        // v6 listens fall through to None — IPv6 ping smoothing isn't
        // wired in this phase, and 0.0.0.0:0 semantics already covers
        // the "accept every request" case the responder needs.
        assert_eq!(parse_listen_ip("[::]:443"), None);
    }

    #[test]
    fn build_echo_reply_has_type_zero() {
        let mut out = Vec::new();
        // id (2) + seq (2) + 4-byte payload.
        let body = [0, 1, 0, 2, b'x', b'y', b'z', b'q'];
        build_echo_reply(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            &body,
            &mut out,
        );
        assert_eq!(out[IPV4_HDR_LEN], ICMP_TYPE_ECHO_REPLY);
        assert_eq!(out[IPV4_HDR_LEN + 1], 0);
    }

    #[test]
    fn build_echo_reply_mirrors_id_seq_and_payload() {
        let mut out = Vec::new();
        let body = [0xDE, 0xAD, 0x12, 0x34, 0xAA, 0xBB, 0xCC];
        build_echo_reply(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            &body,
            &mut out,
        );
        let icmp = &out[IPV4_HDR_LEN..];
        assert_eq!(&icmp[4..], &body[..]);
    }
}
