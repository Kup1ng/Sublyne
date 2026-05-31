//! Raw IPv6 ICMPv6 spoof envelope (Phase 8b + Phase R4).
//!
//! Mirrors `transport/icmp.rs` for IPv6: ICMPv6 type 129 (echo-reply,
//! Phase 8b default) or type 128 (echo-request, Phase R4) from a
//! spoofed white IPv6 address to the Client's IPv6 address.
//!
//! Two quirks vs. IPv4 are worth flagging:
//!
//! 1. **Send side uses `IPV6_HDRINCL`** so we can forge the source
//!    address. Without it, the kernel chooses the source from the
//!    box's own IPv6 addresses and the spoof is impossible.
//! 2. **Receive side INCLUDES the IPv6 header on Linux.** Empirically
//!    verified on kernel 6.8 — `recvfrom` returns the full IPv6 packet
//!    bytes, not just the ICMPv6 message.
//!
//! Wire layout (the bytes we hand to `sendto`):
//!
//! ```text
//! +---------------+--------------+--------------------+
//! | IPv6 header   | ICMPv6 hdr   | sealed body        |
//! | (40 B)        | (8 B)        | (HMAC + seq + ts + |
//! |               |              |  forwarded UDP)    |
//! +---------------+--------------+--------------------+
//! ```

use std::io;
use std::net::{IpAddr, Ipv6Addr};

use socket2::{Domain, Protocol, Socket, Type};

use super::{internet_checksum_pieces, ParsedInbound};
use crate::spec::IcmpEchoMode;

pub const IPV6_HDR_LEN: usize = 40;
pub const ICMPV6_HDR_LEN: usize = 8;
pub const TOTAL_HDR_LEN: usize = IPV6_HDR_LEN + ICMPV6_HDR_LEN;

/// Next-header value for ICMPv6 (RFC 4443).
pub const IP_PROTO_ICMPV6: u8 = 58;

/// ICMPv6 type for "echo reply" (RFC 4443 §4.2). Phase 8b default.
pub const ICMPV6_TYPE_ECHO_REPLY: u8 = 129;
/// ICMPv6 type for "echo request" (RFC 4443 §4.1). Phase R4.
pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
const ICMPV6_CODE: u8 = 0;

/// Resolve the ICMPv6 type byte for the chosen echo mode.
pub fn type_byte(mode: IcmpEchoMode) -> u8 {
    match mode {
        IcmpEchoMode::Reply => ICMPV6_TYPE_ECHO_REPLY,
        IcmpEchoMode::Request => ICMPV6_TYPE_ECHO_REQUEST,
    }
}

/// Build a single IPv6 ICMPv6 packet carrying `payload`.
///
/// `identifier` is stamped into the ICMPv6 `identifier` field (same role
/// as in the IPv4 ICMP transport). `dst_port` is unused; kept in the
/// signature so all four builders match shape-wise.
#[allow(clippy::too_many_arguments)]
pub fn build_packet(
    src_ip: Ipv6Addr,
    identifier: u16,
    dst_ip: Ipv6Addr,
    _dst_port: u16,
    icmp_seq: u16,
    mode: IcmpEchoMode,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    let icmpv6_len = ICMPV6_HDR_LEN + payload.len();
    out.clear();
    out.reserve(IPV6_HDR_LEN + icmpv6_len);

    // IPv6 header (40 bytes).
    out.push(0x60);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&(icmpv6_len as u16).to_be_bytes());
    out.push(IP_PROTO_ICMPV6);
    out.push(64);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());

    // ICMPv6 header (8 bytes).
    out.push(type_byte(mode)); // 40  type
    out.push(ICMPV6_CODE); //       41  code
    out.extend_from_slice(&0u16.to_be_bytes()); // 42..44 checksum placeholder
    out.extend_from_slice(&identifier.to_be_bytes()); // 44..46 identifier
    out.extend_from_slice(&icmp_seq.to_be_bytes()); // 46..48 sequence

    // Payload.
    out.extend_from_slice(payload);

    // ICMPv6 checksum (RFC 4443) — covers an IPv6 pseudo-header plus
    // the entire ICMPv6 message. Unlike ICMPv4, the pseudo-header is
    // mandatory.
    // Stream the IPv6 pseudo-header + the ICMPv6 message through the
    // no-alloc checksum helper rather than copying the whole message into a
    // freshly-allocated scratch Vec on every packet. Matches the UDP/TCP
    // builders (the IPv4 ICMP builder needs no pseudo-header at all).
    let checksum = match internet_checksum_pieces(&[
        &src_ip.octets(),
        &dst_ip.octets(),
        &(icmpv6_len as u32).to_be_bytes(),
        &[0u8, 0, 0, IP_PROTO_ICMPV6],
        &out[IPV6_HDR_LEN..],
    ]) {
        0 => 0xFFFF,
        v => v,
    };
    out[IPV6_HDR_LEN + 2] = (checksum >> 8) as u8;
    out[IPV6_HDR_LEN + 3] = checksum as u8;
}

/// Parse a packet delivered to an AF_INET6 SOCK_RAW IPPROTO_ICMPV6
/// socket. `mode` selects whether the parser accepts type 129 (Reply)
/// or type 128 (Request) packets.
pub fn parse_inbound(packet: &[u8], mode: IcmpEchoMode) -> Option<ParsedInbound<'_>> {
    if packet.len() < IPV6_HDR_LEN + ICMPV6_HDR_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 6 {
        return None;
    }
    let next_header = packet[6];
    if next_header != IP_PROTO_ICMPV6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if IPV6_HDR_LEN + payload_len > packet.len() {
        return None;
    }
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let icmpv6 = &packet[IPV6_HDR_LEN..IPV6_HDR_LEN + payload_len];
    if icmpv6.len() < ICMPV6_HDR_LEN {
        return None;
    }
    if icmpv6[0] != type_byte(mode) || icmpv6[1] != ICMPV6_CODE {
        return None;
    }
    let identifier = u16::from_be_bytes([icmpv6[4], icmpv6[5]]);
    let payload = &icmpv6[ICMPV6_HDR_LEN..];
    Some(ParsedInbound {
        src_ip: IpAddr::V6(src_ip),
        src_id: identifier,
        dst_ip: IpAddr::V6(dst_ip),
        dst_id: identifier,
        payload,
    })
}

/// Open the AF_INET6 raw socket the Remote uses to *send* spoofed
/// ICMPv6 messages. `IPV6_HDRINCL` is set so we can write the IPv6
/// header (and therefore the source address) ourselves.
pub fn open_raw_icmpv6_send_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    sock.set_header_included_v6(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-icmpv6/send");
    // See open_raw_icmp_send_socket: the kernel copies every matching ICMPv6
    // packet onto this never-read send fd, pinning the forced 4 MiB recv
    // buffer and dropping unrelated inbound ICMPv6. Attach the same drop-all
    // BPF filter the UDP/TCP send sockets use.
    if let Err(e) = super::attach_drop_all_filter(&sock) {
        tracing::warn!(err = %e,
            "raw-icmpv6/send: attach drop-all BPF filter failed; recv queue may accumulate");
    }
    Ok(sock)
}

/// Open the AF_INET6 raw socket the Client uses to *receive* spoofed
/// ICMPv6 messages. The kernel includes the IPv6 header in the received
/// buffer on Linux 6.8.
pub fn open_raw_icmpv6_recv_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-icmpv6/recv");
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_reply_matches() {
        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let payload = b"sealed body";
        let mut buf = Vec::new();
        build_packet(
            src_ip,
            443,
            dst_ip,
            0,
            5,
            IcmpEchoMode::Reply,
            payload,
            &mut buf,
        );

        let parsed = parse_inbound(&buf, IcmpEchoMode::Reply).expect("must parse");
        assert_eq!(parsed.src_ip, IpAddr::V6(src_ip));
        assert_eq!(parsed.src_id, 443);
        assert_eq!(parsed.dst_ip, IpAddr::V6(dst_ip));
        assert_eq!(parsed.dst_id, 443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn build_then_parse_request_matches() {
        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let payload = b"sealed body";
        let mut buf = Vec::new();
        build_packet(
            src_ip,
            0xfedc,
            dst_ip,
            0,
            5,
            IcmpEchoMode::Request,
            payload,
            &mut buf,
        );

        let parsed = parse_inbound(&buf, IcmpEchoMode::Request).expect("must parse");
        assert_eq!(parsed.src_id, 0xfedc);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reply_packet_has_type_129() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        assert_eq!(buf[IPV6_HDR_LEN], ICMPV6_TYPE_ECHO_REPLY);
        assert_eq!(buf[IPV6_HDR_LEN + 1], ICMPV6_CODE);
    }

    #[test]
    fn request_packet_has_type_128() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Request,
            b"x",
            &mut buf,
        );
        assert_eq!(buf[IPV6_HDR_LEN], ICMPV6_TYPE_ECHO_REQUEST);
        assert_eq!(buf[IPV6_HDR_LEN + 1], ICMPV6_CODE);
    }

    #[test]
    fn reply_parser_rejects_request_wire() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Request,
            b"x",
            &mut buf,
        );
        assert!(parse_inbound(&buf, IcmpEchoMode::Reply).is_none());
    }

    #[test]
    fn request_parser_rejects_reply_wire() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        assert!(parse_inbound(&buf, IcmpEchoMode::Request).is_none());
    }

    #[test]
    fn next_header_is_icmpv6() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        assert_eq!(buf[6], IP_PROTO_ICMPV6);
    }

    #[test]
    fn rejects_truncated_message() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"data",
            &mut buf,
        );
        buf.truncate(IPV6_HDR_LEN + 4);
        assert!(parse_inbound(&buf, IcmpEchoMode::Reply).is_none());
    }

    #[test]
    fn rejects_wrong_next_header() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            1,
            "2001:db8::2".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"data",
            &mut buf,
        );
        buf[6] = 17;
        assert!(parse_inbound(&buf, IcmpEchoMode::Reply).is_none());
    }

    #[test]
    fn checksum_is_present_and_nonzero() {
        let mut buf = Vec::new();
        build_packet(
            "2001:db8::1".parse().unwrap(),
            53,
            "2001:db8::2".parse().unwrap(),
            0,
            42,
            IcmpEchoMode::Reply,
            b"payload",
            &mut buf,
        );
        let icmpv6_check = u16::from_be_bytes([buf[IPV6_HDR_LEN + 2], buf[IPV6_HDR_LEN + 3]]);
        assert_ne!(icmpv6_check, 0);
    }

    #[test]
    fn type_byte_mapping() {
        assert_eq!(type_byte(IcmpEchoMode::Reply), 129);
        assert_eq!(type_byte(IcmpEchoMode::Request), 128);
    }
}
