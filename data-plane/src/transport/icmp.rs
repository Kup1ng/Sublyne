//! Raw IPv4 ICMP spoof envelope (Phase 8b + Phase R4).
//!
//! We carry the download payload inside an ICMP message addressed from
//! the spoofed "white" IP to the Client. Two wire shapes are supported
//! via the per-tunnel `icmp_echo_mode`:
//!
//! - **Reply** (Phase 8b default, `type = 0`, code = 0). DPI sees a normal
//!   echo-reply coming back from a trusted host; the kernel sees an
//!   unsolicited echo-reply (we never sent the matching request) and
//!   silently ignores it; our raw socket bound to `IPPROTO_ICMP` receives
//!   a copy and lifts the payload out for HMAC verification. Works on
//!   loopback and on links that don't filter unsolicited replies.
//!
//! - **Request** (Phase R4, `type = 8`, code = 0). Iranian inbound
//!   filters drop unsolicited echo-replies more aggressively than
//!   echo-requests, so this mode is required to make ICMP work on the
//!   real Iran ↔ foreign path (see tests/perf/icmp-on-real-path.md for
//!   the packet-capture evidence). The kernel on the receiving box would
//!   normally auto-reply to every incoming echo-request; the tunnel
//!   actor suppresses that with `net.ipv4.icmp_echo_ignore_all=1` for
//!   the lifetime of the receiver via `crate::icmp_sysctl::EchoIgnore`.
//!
//! Wire layout (identical for both modes — only the type byte differs):
//!
//! ```text
//! +---------------+-----------+--------------------+
//! | IPv4 header   | ICMP hdr  | sealed body        |
//! | (20 B)        | (8 B)     | (HMAC + seq + ts + |
//! |               |           |  forwarded UDP)    |
//! +---------------+-----------+--------------------+
//! ```
//!
//! ICMP has no "port" concept on the wire. We borrow the 16-bit
//! `identifier` field of the ICMP header for two purposes:
//!
//! - **Pre-R4**: a static value (`download_spoof_source_port`) so the
//!   Client filter could check `parsed.src_id == spoof_source_port`
//!   uniformly with UDP and TCP-SYN.
//! - **R4 onwards**: a *random per-tunnel-start* value, chosen at spawn
//!   time and shared between Remote and Client (the Client logs both
//!   the configured spoof port and the runtime-chosen identifier so a
//!   ping collision is debuggable). The Client filter no longer rejects
//!   on identifier mismatch for ICMP — HMAC verification is the
//!   authentication. The identifier still rides the wire because Iranian
//!   DPI middleboxes sometimes inspect it and a non-zero random value
//!   looks more plausible than a fixed `443` repeated for hours.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use socket2::{Domain, Protocol, Socket, Type};

use super::{internet_checksum, ParsedInbound};
use crate::spec::IcmpEchoMode;

pub const IPV4_HDR_LEN: usize = 20;
pub const ICMP_HDR_LEN: usize = 8;
pub const TOTAL_HDR_LEN: usize = IPV4_HDR_LEN + ICMP_HDR_LEN;

/// IANA protocol number for ICMP (v4).
pub const IP_PROTO_ICMP: u8 = 1;

/// ICMP type for "echo reply" (RFC 792). Phase 8b default.
pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
/// ICMP type for "echo request" (RFC 792). Phase R4 introduces this for
/// the `IcmpEchoMode::Request` mode that matches `spoof-tunnel`.
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_CODE: u8 = 0;

/// Resolve the ICMP type byte for the chosen echo mode.
pub fn type_byte(mode: IcmpEchoMode) -> u8 {
    match mode {
        IcmpEchoMode::Reply => ICMP_TYPE_ECHO_REPLY,
        IcmpEchoMode::Request => ICMP_TYPE_ECHO_REQUEST,
    }
}

/// Build a single IPv4 ICMP packet carrying `payload`.
///
/// `identifier` is stamped into the ICMP `identifier` field. Phase R4
/// chooses this randomly per tunnel start (see `crate::icmp_id`); pre-R4
/// callers passed `download_spoof_source_port` here. `dst_port` is
/// currently unused (ICMP has no destination port concept); we still
/// take it in the signature so all four transports share an identical
/// builder shape.
///
/// `icmp_seq` is the per-packet ICMP sequence counter — separate from
/// the HMAC envelope's `seq` (which lives inside the sealed payload).
#[allow(clippy::too_many_arguments)]
pub fn build_packet(
    src_ip: Ipv4Addr,
    identifier: u16,
    dst_ip: Ipv4Addr,
    _dst_port: u16,
    icmp_seq: u16,
    mode: IcmpEchoMode,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    let total_len = TOTAL_HDR_LEN + payload.len();
    out.clear();
    out.reserve(total_len);

    // IPv4 header (20 bytes).
    out.push(0x45); // version=4, IHL=5.
    out.push(0x00); // DSCP + ECN.
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // identification.
    out.extend_from_slice(&0u16.to_be_bytes()); // flags=0 (no DF), frag offset=0.
    out.push(64); // TTL.
    out.push(IP_PROTO_ICMP); // protocol=ICMP.
    out.extend_from_slice(&0u16.to_be_bytes()); // IPv4 checksum placeholder.
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());

    let ip_checksum = internet_checksum(&out[..IPV4_HDR_LEN]);
    out[10] = (ip_checksum >> 8) as u8;
    out[11] = ip_checksum as u8;

    // ICMP header (8 bytes).
    out.push(type_byte(mode)); // 20  type
    out.push(ICMP_CODE); //         21  code
    out.extend_from_slice(&0u16.to_be_bytes()); // 22..24 checksum placeholder
    out.extend_from_slice(&identifier.to_be_bytes()); // 24..26 identifier
    out.extend_from_slice(&icmp_seq.to_be_bytes()); // 26..28 sequence

    // Payload.
    out.extend_from_slice(payload);

    // ICMP checksum is one's-complement over the entire ICMP message
    // (header + payload). No pseudo-header for ICMPv4.
    let icmp_checksum = internet_checksum(&out[IPV4_HDR_LEN..]);
    out[IPV4_HDR_LEN + 2] = (icmp_checksum >> 8) as u8;
    out[IPV4_HDR_LEN + 3] = icmp_checksum as u8;
}

/// Parse an IPv4 ICMP packet as delivered to a raw socket bound to
/// `IPPROTO_ICMP`. Returns `None` if the packet is not an echo message
/// of the kind we expect (`mode == Reply` accepts type 0; `mode ==
/// Request` accepts type 8). Mixing modes between Client and Remote
/// produces a silent drop here — there's no way to make e.g. a type 8
/// receiver consume a type 0 packet because the Iranian filter wouldn't
/// have let it through anyway.
pub fn parse_inbound(packet: &[u8], mode: IcmpEchoMode) -> Option<ParsedInbound<'_>> {
    if packet.len() < TOTAL_HDR_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let ip_hdr_len = ihl * 4;
    if packet.len() < ip_hdr_len + ICMP_HDR_LEN {
        return None;
    }
    let protocol = packet[9];
    if protocol != IP_PROTO_ICMP {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() || total_len < ip_hdr_len + ICMP_HDR_LEN {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let icmp = &packet[ip_hdr_len..total_len];
    if icmp[0] != type_byte(mode) || icmp[1] != ICMP_CODE {
        return None;
    }
    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let payload = &icmp[ICMP_HDR_LEN..];
    Some(ParsedInbound {
        src_ip: IpAddr::V4(src_ip),
        // For ICMP we don't carry a port pair on the wire. We stamp the
        // per-tunnel identifier into the ICMP id on send and surface it
        // as BOTH `src_id` and `dst_id`. Phase R4: the identifier is
        // random per tunnel start; the client filter skips the
        // `src_id == spoof_port` check for ICMP transports since the
        // HMAC envelope authenticates the packet.
        src_id: identifier,
        dst_ip: IpAddr::V4(dst_ip),
        dst_id: identifier,
        payload,
    })
}

/// Open the AF_INET raw socket the Remote uses to *send* spoofed
/// ICMP messages. `IP_HDRINCL` lets us forge the source IP.
pub fn open_raw_icmp_send_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| crate::perf::socket_err(e, "raw-icmp/send"))?;
    sock.set_header_included_v4(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-icmp/send");
    // The kernel delivers a copy of every ICMP packet on the host to this
    // raw send socket (`raw_local_deliver`); we never read it, so without a
    // drop-all BPF filter the recv queue grows to the forced 4 MiB SO_RCVBUF
    // and the kernel then silently drops new inbound ICMP. Same one-BPF-
    // instruction guard the UDP/TCP send sockets already carry.
    if let Err(e) = super::attach_drop_all_filter(&sock) {
        tracing::warn!(err = %e,
            "raw-icmp/send: attach drop-all BPF filter failed; recv queue may accumulate");
    }
    Ok(sock)
}

/// Open the AF_INET raw socket the Client uses to *receive* spoofed
/// ICMP messages. In Reply mode, unsolicited replies are normally
/// dropped silently by the kernel; in Request mode, the kernel would
/// auto-reply to every echo-request unless `icmp_echo_ignore_all=1`
/// (the `crate::icmp_sysctl::EchoIgnore` guard handles that). The raw
/// socket receives a copy in parallel via `raw_local_deliver`.
pub fn open_raw_icmp_recv_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| crate::perf::socket_err(e, "raw-icmp/recv"))?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-icmp/recv");
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_reply_matches() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let payload = b"forwarded udp body";
        let mut buf = Vec::new();
        build_packet(
            src_ip,
            443,
            dst_ip,
            0,
            7,
            IcmpEchoMode::Reply,
            payload,
            &mut buf,
        );

        let parsed = parse_inbound(&buf, IcmpEchoMode::Reply).expect("must parse");
        assert_eq!(parsed.src_ip, IpAddr::V4(src_ip));
        assert_eq!(parsed.src_id, 443);
        assert_eq!(parsed.dst_ip, IpAddr::V4(dst_ip));
        assert_eq!(parsed.dst_id, 443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn build_then_parse_request_matches() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let payload = b"forwarded udp body";
        let mut buf = Vec::new();
        build_packet(
            src_ip,
            0x9abc,
            dst_ip,
            0,
            7,
            IcmpEchoMode::Request,
            payload,
            &mut buf,
        );

        let parsed = parse_inbound(&buf, IcmpEchoMode::Request).expect("must parse");
        assert_eq!(parsed.src_ip, IpAddr::V4(src_ip));
        assert_eq!(parsed.src_id, 0x9abc);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reply_packet_has_type_0() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            443,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        assert_eq!(buf[IPV4_HDR_LEN], ICMP_TYPE_ECHO_REPLY);
        assert_eq!(buf[IPV4_HDR_LEN + 1], ICMP_CODE);
    }

    #[test]
    fn request_packet_has_type_8() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            443,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Request,
            b"x",
            &mut buf,
        );
        assert_eq!(buf[IPV4_HDR_LEN], ICMP_TYPE_ECHO_REQUEST);
        assert_eq!(buf[IPV4_HDR_LEN + 1], ICMP_CODE);
    }

    #[test]
    fn reply_parser_rejects_request_wire() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            443,
            "5.6.7.8".parse().unwrap(),
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
            "1.2.3.4".parse().unwrap(),
            443,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        assert!(parse_inbound(&buf, IcmpEchoMode::Request).is_none());
    }

    #[test]
    fn ip_flags_do_not_set_df_bit() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            443,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"hi",
            &mut buf,
        );
        let flags = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(flags & 0x4000, 0, "DF must not be set");
        assert_eq!(flags & 0x2000, 0, "MF must not be set");
        assert_eq!(flags & 0x1FFF, 0, "frag offset must be zero");
    }

    #[test]
    fn rejects_non_icmp_protocol() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            1,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"x",
            &mut buf,
        );
        buf[9] = 17; // UDP
        assert!(parse_inbound(&buf, IcmpEchoMode::Reply).is_none());
    }

    #[test]
    fn rejects_truncated_packet() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            1,
            "5.6.7.8".parse().unwrap(),
            0,
            1,
            IcmpEchoMode::Reply,
            b"abcd",
            &mut buf,
        );
        buf.truncate(buf.len() - 2);
        assert!(parse_inbound(&buf, IcmpEchoMode::Reply).is_none());
    }

    #[test]
    fn checksum_is_present_and_nonzero() {
        let mut buf = Vec::new();
        build_packet(
            "1.2.3.4".parse().unwrap(),
            53,
            "5.6.7.8".parse().unwrap(),
            0,
            42,
            IcmpEchoMode::Reply,
            b"payload",
            &mut buf,
        );
        let icmp_check = u16::from_be_bytes([buf[IPV4_HDR_LEN + 2], buf[IPV4_HDR_LEN + 3]]);
        assert_ne!(icmp_check, 0);
    }

    #[test]
    fn type_byte_mapping() {
        assert_eq!(type_byte(IcmpEchoMode::Reply), 0);
        assert_eq!(type_byte(IcmpEchoMode::Request), 8);
    }
}
