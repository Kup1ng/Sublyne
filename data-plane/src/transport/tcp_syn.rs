//! Raw IPv4 TCP-SYN spoof envelope.
//!
//! We carry the download payload inside what looks to DPI like a normal
//! TCP SYN packet. There is no real TCP state machine — no SYN-ACK, no
//! handshake, no retransmit. The receiver pulls the payload straight out
//! of the bytes following the (minimal-size) TCP header. From the
//! firewall's point of view this is "an incoming SYN from a whitelisted
//! IP", which is allowed; the kernel of the receiver sees the same SYN
//! and (absent the host firewall fix-up described in
//! `.claude/skills/raw-sockets-and-spoofing/SKILL.md`) would generate
//! an RST. The RST going *out* to the spoofed source IP is harmless
//! when the destination is a "white" IP we don't control, but in
//! production the install path adds an iptables OUTPUT rule that DROPs
//! the RST so we don't leak our presence.
//!
//! Wire layout:
//!
//! ```text
//! +---------------+---------------+--------------------+
//! | IPv4 header   | TCP header    | sealed body        |
//! | (20 B)        | (20 B, SYN)   | (HMAC + seq + ts + |
//! |               |               |  forwarded UDP)    |
//! +---------------+---------------+--------------------+
//! ```
//!
//! Phase 8b ships IPv4 only. IPv6 TCP-SYN is feasible but the PRD only
//! requires ICMPv6 for the IPv6 path, so we don't open that yet.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use socket2::{Domain, Protocol, Socket, Type};

use super::{internet_checksum, internet_checksum_pieces, ParsedInbound};

pub const IPV4_HDR_LEN: usize = 20;
pub const TCP_HDR_LEN: usize = 20;
pub const TOTAL_HDR_LEN: usize = IPV4_HDR_LEN + TCP_HDR_LEN;

/// IANA protocol number for TCP.
pub const IP_PROTO_TCP: u8 = 6;

/// TCP flag bits we care about. We always emit SYN and only SYN.
const TCP_FLAG_SYN: u8 = 0x02;

/// Build a single IPv4 TCP-SYN packet carrying `payload` after the TCP
/// header. Designed to be written to a raw socket opened with
/// `IP_HDRINCL`.
///
/// The TCP `sequence_number` field is *not* our HMAC sequence — DPI
/// heuristics flag SYN-with-seq=0 as suspicious. The sequence is
/// derived from the per-packet HMAC seq purely so it varies across
/// packets (`hmac_seq` is monotonically incrementing on the sender
/// side); the HMAC envelope's own seq lives inside the payload.
///
/// DF is not set — see `transport/udp.rs::build_packet` for the
/// production-incident write-up that motivated keeping DF=0 on every
/// spoof transport.
pub fn build_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    hmac_seq: u64,
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
    out.push(IP_PROTO_TCP); // protocol=TCP.
    out.extend_from_slice(&0u16.to_be_bytes()); // IPv4 checksum placeholder.
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());

    // Patch IPv4 header checksum.
    let ip_checksum = internet_checksum(&out[..IPV4_HDR_LEN]);
    out[10] = (ip_checksum >> 8) as u8;
    out[11] = ip_checksum as u8;

    // TCP header (20 bytes).
    out.extend_from_slice(&src_port.to_be_bytes()); // 20..22 sport
    out.extend_from_slice(&dst_port.to_be_bytes()); // 22..24 dport
                                                    // Sequence number — derive from hmac_seq so it varies and
                                                    // never hits 0 (DPI heuristic).
    let tcp_seq = derive_tcp_seq(hmac_seq);
    out.extend_from_slice(&tcp_seq.to_be_bytes()); // 24..28
    out.extend_from_slice(&0u32.to_be_bytes()); // 28..32 ack=0 (SYN has no ack to send)
                                                // Data offset (4 bits) | reserved (3 bits) | NS (1 bit)
                                                // data_offset = TCP_HDR_LEN / 4 = 5 → upper nibble 0x50.
    out.push(0x50); // 32 data offset + reserved
    out.push(TCP_FLAG_SYN); // 33 flags
                            // Window size — anything plausible for a real SYN. 65 535 is the
                            // standard max-no-scaling value and matches what Linux's own
                            // SYN packets often advertise.
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // 34..36 window
    out.extend_from_slice(&0u16.to_be_bytes()); // 36..38 checksum placeholder
    out.extend_from_slice(&0u16.to_be_bytes()); // 38..40 urgent pointer

    // Payload.
    out.extend_from_slice(payload);

    // TCP checksum: pseudo-header + TCP header + payload. Use the
    // streaming pieces helper to avoid a per-packet Vec the size of the
    // payload.
    let tcp_segment_len = (TCP_HDR_LEN + payload.len()) as u16;
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    let proto_word: [u8; 2] = [0, IP_PROTO_TCP];
    let seg_len_bytes = tcp_segment_len.to_be_bytes();
    let tcp_checksum = match internet_checksum_pieces(&[
        &src_octets,
        &dst_octets,
        &proto_word,
        &seg_len_bytes,
        &out[IPV4_HDR_LEN..], // TCP header + payload
    ]) {
        0 => 0xFFFF,
        v => v,
    };
    let cksum_off = IPV4_HDR_LEN + 16;
    out[cksum_off] = (tcp_checksum >> 8) as u8;
    out[cksum_off + 1] = tcp_checksum as u8;
}

/// Map the dataplane's monotonic HMAC sequence to a 32-bit TCP seq
/// that is (a) deterministic for a given hmac_seq, (b) never zero, and
/// (c) spread enough that a passive observer can't trivially correlate
/// it with the HMAC seq. We just take the low 32 bits XOR a fixed
/// 32-bit constant — DPI doesn't crypto-analyse SYN seq numbers, and a
/// truly random per-packet seq is fine; this stays deterministic for
/// the build/parse test below.
fn derive_tcp_seq(hmac_seq: u64) -> u32 {
    let v = hmac_seq as u32 ^ 0x5A5A_5A5Au32;
    if v == 0 {
        1
    } else {
        v
    }
}

/// Parse an IPv4 TCP packet as delivered to a raw socket bound to
/// `IPPROTO_TCP`. Returns `None` for anything that is not a SYN-flagged
/// IPv4 TCP frame addressed in a way we know about.
///
/// Like the UDP parser, we trust the kernel to have validated the
/// header checksums on the way in and don't re-check them here.
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
    if packet.len() < ip_hdr_len + TCP_HDR_LEN {
        return None;
    }
    let protocol = packet[9];
    if protocol != IP_PROTO_TCP {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() || total_len < ip_hdr_len + TCP_HDR_LEN {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ip_hdr_len..total_len];
    if tcp.len() < TCP_HDR_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let data_offset_words = (tcp[12] >> 4) as usize;
    let data_offset = data_offset_words * 4;
    if data_offset < TCP_HDR_LEN || data_offset > tcp.len() {
        return None;
    }
    // Accept only SYN-flagged packets — drop anything else (RSTs etc.).
    let flags = tcp[13];
    if flags & TCP_FLAG_SYN == 0 {
        return None;
    }
    let payload = &tcp[data_offset..];
    Some(ParsedInbound {
        src_ip: IpAddr::V4(src_ip),
        src_id: src_port,
        dst_ip: IpAddr::V4(dst_ip),
        dst_id: dst_port,
        payload,
    })
}

/// Open the AF_INET raw socket used by the Remote to *send* spoofed
/// TCP-SYN packets. `IP_HDRINCL` lets us forge the source IP. Buffer
/// sizes are tuned via `perf::tune_socket` so a burst of spoofed SYNs
/// doesn't stall on a full kernel send queue.
pub fn open_raw_tcp_send_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .map_err(|e| crate::perf::socket_err(e, "raw-tcp/send"))?;
    sock.set_header_included_v4(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-tcp/send");
    // See raw-udp/send: drop-all BPF on the send-only raw socket so
    // the kernel doesn't accrue copies of every host TCP packet in a
    // recv queue we never drain.
    if let Err(e) = super::attach_drop_all_filter(&sock) {
        tracing::warn!(err = %e,
            "raw-tcp/send: attach drop-all BPF filter failed; recv queue may accumulate");
    }
    Ok(sock)
}

/// Open the AF_INET raw socket the Client uses to *receive* spoofed
/// TCP-SYN packets. The kernel sees the same SYN and would normally
/// reply with RST; the install path adds an iptables OUTPUT DROP for
/// outgoing RSTs to the spoof source IP so that side channel doesn't
/// fire.
pub fn open_raw_tcp_recv_socket() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .map_err(|e| crate::perf::socket_err(e, "raw-tcp/recv"))?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_reuse_port(true);
    crate::perf::tune_socket(&sock, "raw-tcp/recv");
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_matches() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let payload = b"sealed envelope bytes";
        let mut buf = Vec::new();
        build_packet(src_ip, 443, dst_ip, 8443, 1, payload, &mut buf);

        let parsed = parse_inbound(&buf).expect("must parse");
        assert_eq!(parsed.src_ip, IpAddr::V4(src_ip));
        assert_eq!(parsed.src_id, 443);
        assert_eq!(parsed.dst_ip, IpAddr::V4(dst_ip));
        assert_eq!(parsed.dst_id, 8443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn syn_flag_is_set() {
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 443, dst_ip, 5002, 1, b"x", &mut buf);
        let tcp_flags = buf[IPV4_HDR_LEN + 13];
        assert_eq!(tcp_flags & TCP_FLAG_SYN, TCP_FLAG_SYN);
        // No other flags set.
        assert_eq!(tcp_flags & !TCP_FLAG_SYN, 0);
    }

    #[test]
    fn ip_flags_do_not_set_df_bit() {
        // Same regression guard as udp.rs: spoofed packets MUST NOT set
        // the DF bit, or oversized packets get black-holed end-to-end
        // because ICMP "frag needed" returns to the spoofed source.
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 443, dst_ip, 5002, 1, b"hello", &mut buf);
        let flags_and_offset = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(flags_and_offset & 0x4000, 0, "DF must not be set");
        assert_eq!(flags_and_offset & 0x2000, 0, "MF must not be set");
        assert_eq!(flags_and_offset & 0x1FFF, 0, "fragment offset must be zero");
    }

    #[test]
    fn rejects_non_tcp_protocol() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 1, dst_ip, 2, 1, b"x", &mut buf);
        buf[9] = 17; // protocol=UDP — wrong family.
        assert!(parse_inbound(&buf).is_none());
    }

    #[test]
    fn rejects_packet_without_syn() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 1, dst_ip, 2, 1, b"x", &mut buf);
        // Clear all flags — parser must reject anything without SYN.
        buf[IPV4_HDR_LEN + 13] = 0x00;
        assert!(parse_inbound(&buf).is_none());
    }

    #[test]
    fn rejects_truncated_packet() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 1, dst_ip, 2, 1, b"data", &mut buf);
        // Lop off the payload so the IP total-length field disagrees
        // with the actual buffer length.
        buf.truncate(buf.len() - 2);
        assert!(parse_inbound(&buf).is_none());
    }

    #[test]
    fn checksums_are_present_and_nonzero() {
        let src_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let dst_ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let mut buf = Vec::new();
        build_packet(src_ip, 53, dst_ip, 60000, 42, b"payload", &mut buf);
        let ip_check = u16::from_be_bytes([buf[10], buf[11]]);
        let tcp_check = u16::from_be_bytes([buf[IPV4_HDR_LEN + 16], buf[IPV4_HDR_LEN + 17]]);
        assert_ne!(ip_check, 0);
        assert_ne!(tcp_check, 0);
    }

    #[test]
    fn tcp_seq_is_never_zero() {
        // The derivation maps hmac_seq=0x5A5A5A5A → 0 by XOR; we
        // explicitly bump that to 1 so the wire never carries seq=0
        // (DPI heuristic).
        assert_eq!(derive_tcp_seq(0x5A5A_5A5Au64), 1);
        assert_ne!(derive_tcp_seq(1), 0);
        assert_ne!(derive_tcp_seq(u64::MAX), 0);
    }
}
