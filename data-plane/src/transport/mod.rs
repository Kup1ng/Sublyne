//! Shared transport-layer helpers and the four download-spoof
//! envelopes (UDP, TCP-SYN, ICMP, ICMPv6).
//!
//! Each `transport/<name>.rs` module owns the wire format for one
//! envelope and exposes a `build_packet` (for the Remote send side) and
//! a `parse_inbound` (for the Client receive side), plus helpers to
//! open the corresponding raw socket. The tunnel actors in
//! `tunnel/client.rs` and `tunnel/remote.rs` dispatch on the
//! per-tunnel `download_transport` enum and call into the chosen
//! module — every transport carries the same HMAC envelope, the same
//! drop rules, and the same MTU semantics from Phase 8a.
//!
//! `ParsedInbound` is the common return shape. The `src_id` / `dst_id`
//! fields hold a UDP/TCP port for UDP and TCP-SYN; they hold the
//! ICMP `identifier` field for ICMP / ICMPv6 (set to
//! `download_spoof_source_port` per
//! `.claude/skills/raw-sockets-and-spoofing/SKILL.md`). This lets the
//! client-side filter check `src_id == spoof_source_port` uniformly
//! across all four transports.

pub mod icmp;
pub mod icmpv6;
pub mod tcp_syn;
pub mod udp;

use std::io;
use std::net::IpAddr;

/// Parsed view of an inbound spoof packet, normalized across all four
/// transports.
///
/// - For **UDP**, `src_id`/`dst_id` are the UDP source / destination
///   ports.
/// - For **TCP-SYN**, `src_id`/`dst_id` are the TCP source / destination
///   ports.
/// - For **ICMP** and **ICMPv6**, `src_id` and `dst_id` are both set to
///   the ICMP `identifier` field — there is no port concept on the
///   wire. The Remote stamps `download_spoof_source_port` into the
///   identifier on send; the Client filters on `src_id ==
///   download_spoof_source_port`. `dst_id` is identical to `src_id`
///   for ICMP transports so the Client's "destination port" filter is
///   a no-op (the tunnel actor explicitly skips the dst-port check for
///   ICMP, see `tunnel/client.rs`).
#[derive(Debug, Clone, Copy)]
pub struct ParsedInbound<'a> {
    pub src_ip: IpAddr,
    pub src_id: u16,
    pub dst_ip: IpAddr,
    pub dst_id: u16,
    pub payload: &'a [u8],
}

/// Internet checksum (one's-complement 16-bit sum). Used by IPv4,
/// UDP, TCP, ICMP, and ICMPv6 header checksums alike.
///
/// The implementation reads big-endian 16-bit words off `data`; the
/// trailing odd byte (if any) is treated as the high byte of a final
/// word with a zero low byte.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Attach a single-instruction match-nothing classic BPF program to a
/// raw socket so the kernel never enqueues a copy of any matching
/// packet for delivery. Used on the Remote-side raw SEND sockets:
/// `IPPROTO_{UDP,TCP,ICMP,ICMPV6}` raw sockets receive a copy of every
/// matching packet on the host (Linux `net/ipv4/raw.c::raw_local_deliver`),
/// and we never read those sockets — so the recv queue grows until it
/// hits `SO_RCVBUF` and the kernel silently drops new arrivals. The
/// resident bytes also pin multi-MiB of memory per send fd (seen in
/// `ss -anpem` as `Recv-Q 8390272` on the dataplane fd).
///
/// The filter is `BPF_RET | BPF_K, k=0` — a single instruction that
/// returns "accept 0 bytes of this packet", which the kernel's BPF
/// receive path interprets as "drop". Attached once at socket creation
/// time; no per-packet work, no draining goroutine, no memory accrual.
///
/// Soft-fails: a kernel without classic BPF socket filter support (or
/// a missing CAP_NET_RAW) would error out here, but the underlying
/// send socket still works without the filter — we just regress to
/// pre-fix behaviour. So errors are returned for the caller to log
/// and continue rather than crashing tunnel start.
#[cfg(target_os = "linux")]
pub fn attach_drop_all_filter(sock: &socket2::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let mut filter = [libc::sock_filter {
        // BPF_RET | BPF_K — return immediate value (k field) for every
        // packet. With k=0 the kernel accepts 0 bytes → packet dropped.
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let fprog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: setsockopt reads `optlen` bytes from `optval`. We pass a
    // properly-sized `sock_fprog` whose `filter` pointer references the
    // still-live `filter` array on this stack frame. The fd is valid
    // for the lifetime of `sock`.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const libc::sock_fprog as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn attach_drop_all_filter(_sock: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

/// Streaming Internet checksum over multiple non-contiguous byte
/// slices. Equivalent to calling `internet_checksum` on the
/// concatenation of `parts`, but **without allocating** a contiguous
/// buffer first. Used by the pseudo-header transports (UDP, TCP,
/// ICMPv6) to compute their L4 checksums per packet without a per-call
/// `Vec::with_capacity(mtu)` allocation.
///
/// The algorithm carries a single byte across part boundaries: if a
/// part has odd length the trailing byte is paired with the first byte
/// of the next part (or padded with zero at end-of-input).
pub fn internet_checksum_pieces(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for part in parts {
        let mut i = 0;
        if let Some(low) = carry.take() {
            if !part.is_empty() {
                sum += u16::from_be_bytes([low, part[0]]) as u32;
                i = 1;
            } else {
                // Empty part — re-carry and continue.
                carry = Some(low);
                continue;
            }
        }
        while i + 1 < part.len() {
            sum += u16::from_be_bytes([part[i], part[i + 1]]) as u32;
            i += 2;
        }
        if i < part.len() {
            carry = Some(part[i]);
        }
    }
    if let Some(low) = carry {
        sum += (low as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // From RFC 1071 — checksum of [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]
        // is 0x220D.
        let v = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        assert_eq!(internet_checksum(&v), 0x220D);
    }

    #[test]
    fn checksum_odd_length() {
        // An odd-length buffer should pad the last byte with zero.
        let v = [0x12, 0x34, 0x56];
        // 0x1234 + 0x5600 = 0x6834 -> ~ = 0x97CB.
        assert_eq!(internet_checksum(&v), 0x97CB);
    }

    #[test]
    fn checksum_pieces_matches_contiguous() {
        // The streaming-pieces helper must agree with the contiguous
        // checksum for every plausible split, including odd-length
        // pieces (which carry across the boundary).
        let full = [
            0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7, 0x10, 0x11, 0x12,
        ];
        let reference = internet_checksum(&full);
        // Single piece
        assert_eq!(internet_checksum_pieces(&[&full]), reference);
        // Even-aligned split
        assert_eq!(
            internet_checksum_pieces(&[&full[..4], &full[4..]]),
            reference
        );
        // Odd-aligned split — first piece has odd length, second piece
        // starts with the carry byte's pair.
        assert_eq!(
            internet_checksum_pieces(&[&full[..3], &full[3..]]),
            reference
        );
        // Three pieces, both internal splits odd.
        assert_eq!(
            internet_checksum_pieces(&[&full[..3], &full[3..7], &full[7..]]),
            reference
        );
        // Empty pieces interleaved — must not perturb the carry.
        assert_eq!(
            internet_checksum_pieces(&[&full[..3], &[], &full[3..]]),
            reference
        );
    }
}
