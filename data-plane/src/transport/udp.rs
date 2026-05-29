//! Raw IPv4 UDP send + receive for the download spoof transport.
//!
//! We use AF_INET / SOCK_RAW / IPPROTO_UDP sockets with IP_HDRINCL on
//! the send side so we can forge the IPv4 source IP. The kernel's
//! own UDP layer still sees these packets, so we have to filter by
//! destination port in user space — see `parse_inbound` for the
//! filter.
//!
//! Phase 8a is IPv4 only. Phase 10 will lift the IPv6 path; the
//! current module deliberately panics in places where v6 would belong
//! so the missing path is loud, not silent.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use socket2::{Domain, Protocol, Socket, Type};

use super::{internet_checksum, internet_checksum_pieces, ParsedInbound};

/// Fixed IPv4 header size (no options) used by every packet we build.
pub const IPV4_HDR_LEN: usize = 20;
/// Fixed UDP header size.
pub const UDP_HDR_LEN: usize = 8;
/// Total fixed header overhead for an IPv4+UDP spoof packet.
pub const TOTAL_HDR_LEN: usize = IPV4_HDR_LEN + UDP_HDR_LEN;

/// Recv buffer size used for the regular kernel UDP sockets (upload
/// listeners on both sides, and the forward_target reply socket on
/// the Remote). It MUST be strictly greater than any payload size the
/// dataplane is willing to forward, otherwise `recv_from` silently
/// truncates oversized datagrams to `buf.len()` and returns the
/// truncated length — which our cap check then accepts as in-bounds,
/// corrupting the WireGuard AEAD tag at the tail of every >MTU user
/// packet (real symptom: small Telegram messages survived, full-page
/// Google responses + speed-test bursts were silently corrupted and
/// the downstream WG server dropped them, capping throughput around
/// 4 Mbit/s). A 65 536-byte buffer comfortably exceeds the 65 507-byte
/// IPv4 UDP payload ceiling so any legitimate datagram fits whole.
pub const MAX_UDP_DATAGRAM: usize = 65536;

/// Build a single IPv4 UDP packet ready for the kernel to transmit
/// when written to an `IP_HDRINCL` raw socket.
///
/// `ttl=64` matches the Linux default. The IP flags field is left
/// zero (DF NOT set, More-Fragments NOT set, frag offset 0). Setting
/// DF on a spoofed packet is a black-hole footgun: every router on
/// the path with MTU < wire_size silently drops the packet and the
/// ICMP "fragmentation needed" reply goes back to the *spoofed*
/// source IP — which doesn't reach us, so we never learn. The
/// observable effect is that small payloads survive (Telegram works)
/// but anything that crosses a single low-MTU hop disappears (Google
/// search hangs, speed test collapses to a few Mbit/s). Allowing
/// fragmentation costs a fraction of a percent in throughput and
/// removes the entire failure mode; the receive side uses
/// `IPPROTO_UDP` raw sockets, which see fully reassembled datagrams.
pub fn build_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    let total_len = TOTAL_HDR_LEN + payload.len();
    out.clear();
    out.reserve(total_len);

    // IPv4 header (20 bytes).
    out.push(0x45); // version=4, IHL=5 (20 bytes).
    out.push(0x00); // DSCP + ECN.
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // identification.
                                                // Flags+frag offset: all zero. We deliberately do NOT set the
                                                // DF bit — see the build_packet doc comment for why letting the
                                                // path fragment is safer for a spoofed-source-IP transport.
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(64); // TTL.
    out.push(17); // protocol = UDP.
    out.extend_from_slice(&0u16.to_be_bytes()); // header checksum placeholder.
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());

    // Compute and patch the IPv4 header checksum.
    let ip_checksum = internet_checksum(&out[..IPV4_HDR_LEN]);
    out[10] = (ip_checksum >> 8) as u8;
    out[11] = ip_checksum as u8;

    // UDP header (8 bytes).
    let udp_len = (UDP_HDR_LEN + payload.len()) as u16;
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    let udp_checksum_off = out.len();
    out.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum placeholder.

    // Payload.
    out.extend_from_slice(payload);

    // UDP checksum is computed over a pseudo-header (src, dst, proto,
    // udp length) + UDP header + payload. Use the streaming pieces
    // helper so we don't allocate a per-packet Vec the size of the
    // payload purely to concatenate the pseudo-header in front.
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    let proto_word: [u8; 2] = [0, 17];
    let udp_len_bytes = udp_len.to_be_bytes();
    let udp_checksum = match internet_checksum_pieces(&[
        &src_octets,
        &dst_octets,
        &proto_word,
        &udp_len_bytes,
        &out[IPV4_HDR_LEN..], // udp header + payload, with zero checksum
    ]) {
        // RFC 768: if the computed checksum is zero, transmit all
        // ones (0xFFFF) so the receiver can distinguish "no checksum"
        // (zero) from "checksum equal to zero".
        0 => 0xFFFF,
        v => v,
    };
    out[udp_checksum_off] = (udp_checksum >> 8) as u8;
    out[udp_checksum_off + 1] = udp_checksum as u8;
}

/// Parse an IPv4 UDP packet as delivered to a raw socket bound to
/// IPPROTO_UDP. Validates the IP version, length, protocol, and UDP
/// header length consistency. Does **not** verify checksums — the
/// kernel did that on the way in.
///
/// Returns `None` if the packet is not a well-formed IPv4 UDP frame
/// or if the IP header has options we don't expect.
pub fn parse_inbound(packet: &[u8]) -> Option<ParsedInbound<'_>> {
    if packet.len() < TOTAL_HDR_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let ip_hdr_len = ihl * 4;
    if packet.len() < ip_hdr_len + UDP_HDR_LEN {
        return None;
    }
    let protocol = packet[9];
    if protocol != 17 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    // The kernel sometimes hands raw sockets a buffer larger than the
    // actual packet (e.g. ETH_DATA_LEN). Trust the header value when
    // it is the smaller of the two but treat a larger header value as
    // truncation.
    if total_len > packet.len() {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[ip_hdr_len..total_len];
    if udp.len() < UDP_HDR_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < UDP_HDR_LEN || udp_len > udp.len() {
        return None;
    }
    let payload = &udp[UDP_HDR_LEN..udp_len];
    Some(ParsedInbound {
        src_ip: IpAddr::V4(src_ip),
        src_id: src_port,
        dst_ip: IpAddr::V4(dst_ip),
        dst_id: dst_port,
        payload,
    })
}

/// Create the AF_INET raw socket the Remote uses to *send* spoofed
/// UDP packets. The kernel expects us to provide the entire IPv4
/// header (set via `IP_HDRINCL`). The send buffer is enlarged via
/// `perf::tune_socket` so a burst of spoofed downloads doesn't block
/// on a full kernel send queue.
pub fn open_raw_udp_send_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    sock.set_header_included_v4(true)?;
    sock.set_nonblocking(true)?;
    // SO_REUSEPORT is harmless when only one socket is open and
    // positions us for any future per-core fan-out.
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-udp/send");
    // The kernel delivers a copy of every UDP packet on the host to
    // this raw send socket. We never read it; without a drop-all BPF
    // filter the recv queue grows to multi-MiB and silently drops the
    // tail. The filter costs one BPF instruction per inbound packet.
    if let Err(e) = super::attach_drop_all_filter(&sock) {
        tracing::warn!(err = %e,
            "raw-udp/send: attach drop-all BPF filter failed; recv queue may accumulate");
    }
    Ok(sock)
}

/// Create the AF_INET raw socket the Client uses to *receive*
/// spoofed UDP packets. The kernel includes the IPv4 header in
/// delivered datagrams (an IPv4-raw-socket quirk), so the caller
/// parses through `parse_inbound`. The receive buffer is enlarged via
/// `perf::tune_socket` (uses `SO_RCVBUFFORCE` to bypass `rmem_max`).
pub fn open_raw_udp_recv_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-udp/recv");
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_matches() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let payload = b"hello there";
        let mut buf = Vec::new();
        build_packet(src_ip, 443, dst_ip, 8443, payload, &mut buf);

        let parsed = parse_inbound(&buf).expect("must parse");
        assert_eq!(parsed.src_ip, IpAddr::V4(src_ip));
        assert_eq!(parsed.src_id, 443);
        assert_eq!(parsed.dst_ip, IpAddr::V4(dst_ip));
        assert_eq!(parsed.dst_id, 8443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn rejects_non_ipv4_packet() {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60; // version=6.
        assert!(parse_inbound(&buf).is_none());
    }

    #[test]
    fn rejects_non_udp_protocol() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 1, dst_ip, 2, b"x", &mut buf);
        buf[9] = 6; // protocol=TCP.
                    // The IP-header checksum is now incorrect, but parse_inbound
                    // doesn't verify it (kernel did). It should still reject on
                    // the protocol field.
        assert!(parse_inbound(&buf).is_none());
    }

    #[test]
    fn rejects_truncated_packet() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 1, dst_ip, 2, b"data", &mut buf);
        buf.truncate(buf.len() - 1);
        assert!(parse_inbound(&buf).is_none());
    }

    // Regression for the PMTU-black-hole bug shipped to Iran:
    // every spoofed download packet was built with DF=1 (0x4000) in
    // the IP flags field, which silently dropped any packet larger
    // than the smallest-MTU link on the Estonia→Iran path. Because
    // the source IP is spoofed, the ICMP "fragmentation needed"
    // reply went to a host that doesn't process it, so the dataplane
    // never learned and never shrank. Symptom: Telegram (tiny
    // messages) worked but Google search (full-page TCP segments
    // tunneled through WireGuard) hung; speed tests collapsed to
    // ~4 Mbit/s. The fix sets flags=0 so transit routers may
    // fragment when needed; the receiver uses IPPROTO_UDP raw
    // sockets, which see fully reassembled datagrams.
    #[test]
    fn ip_flags_do_not_set_df_bit() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 443, dst_ip, 5002, b"hello", &mut buf);
        let flags_and_offset = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(
            flags_and_offset & 0x4000,
            0,
            "DF bit must not be set on spoofed packets (regression: black-holed large packets in Iran↔foreign deploy)"
        );
        assert_eq!(
            flags_and_offset & 0x2000,
            0,
            "MF bit must not be set by the builder"
        );
        assert_eq!(
            flags_and_offset & 0x1FFF,
            0,
            "fragment offset must be zero (we build whole datagrams)"
        );
    }

    #[test]
    fn checksums_are_present_and_nonzero() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 53, dst_ip, 60000, b"payload", &mut buf);
        let ip_check = u16::from_be_bytes([buf[10], buf[11]]);
        let udp_check = u16::from_be_bytes([buf[IPV4_HDR_LEN + 6], buf[IPV4_HDR_LEN + 7]]);
        assert_ne!(ip_check, 0);
        assert_ne!(udp_check, 0);
    }
}
