//! KCP tuning application + MTU clamp math for the forwarding engine.

use kcp::Kcp;
use std::io::Write;
use tracing::warn;

use crate::spec::KcpTuning;

/// KCP segment header length (conv + cmd + frg + wnd + ts + sn + una +
/// len = 24 bytes). The conv id is the first 4 bytes, little-endian.
pub const KCP_OVERHEAD: usize = 24;

/// Reusable scratch size for draining `Kcp::recv`. Stream-mode recv
/// returns up to this many bytes per call.
pub const RECV_BUF: usize = 64 * 1024;

/// TCP read chunk handed to `Kcp::send` per syscall.
pub const TCP_READ_CHUNK: usize = 16 * 1024;

/// Per-conv TCP-write queue depth (KCP-decoded chunks awaiting the write
/// pump). Bounded so a slow TCP consumer flow-controls back through KCP's
/// receive window rather than growing memory.
pub const WRITE_QUEUE: usize = 256;

/// Safe upper bound on the KCP segment size. Chosen to dodge PMTU
/// blackholes on the Iran path (the DF bit is already cleared on every
/// spoofed egress packet, but a conservative segment keeps us well under
/// any middlebox MTU). Matches the production-proven reference value.
pub const KCP_MTU_CEIL: usize = 1280;

/// Worst-case per-packet overhead reserved below the tunnel MTU before
/// the KCP segment: IPv6 header (40) + worst L4 (TCP-SYN carrier, 20) +
/// HMAC seal envelope (33) + the 2-byte multiport application-port tag
/// (subtracted unconditionally so single- and multi-port tunnels use an
/// identical engine MTU). 40+20+33+2 = 95.
pub const FORWARD_OVERHEAD_RESERVE: usize = 95;

/// Compute the KCP segment MTU for a tunnel: the tunnel MTU minus the
/// worst-case wire overhead, clamped to the safe ceiling, honouring an
/// explicit operator override (`tuning.mtu > 0`) as the ceiling. Never
/// returns less than `KCP_OVERHEAD + 1`.
pub fn kcp_mtu(tunnel_mtu: u32, tuning: &KcpTuning) -> usize {
    let derived = (tunnel_mtu as usize).saturating_sub(FORWARD_OVERHEAD_RESERVE);
    let ceil = if tuning.mtu > 0 {
        tuning.mtu as usize
    } else {
        KCP_MTU_CEIL
    };
    derived.min(ceil).max(KCP_OVERHEAD + 1)
}

/// Apply the resolved KCP tuning to a fresh `Kcp`. Stream mode is always
/// on (we bridge a byte stream, not messages). The `kcp` crate's
/// `set_nodelay` takes `(nodelay: bool, interval, resend, nc: bool)`.
pub fn apply_tuning<W: Write>(kcp: &mut Kcp<W>, t: &KcpTuning, mtu: usize, tunnel_id: i64) {
    kcp.set_nodelay(
        t.nodelay != 0,
        t.interval.max(1) as i32,
        t.resend as i32,
        t.nc != 0,
    );
    let snd = t.snd_wnd.min(u32::from(u16::MAX)) as u16;
    let rcv = t.rcv_wnd.min(u32::from(u16::MAX)) as u16;
    kcp.set_wndsize(snd, rcv);
    if let Err(e) = kcp.set_mtu(mtu) {
        warn!(tunnel_id, mtu, err = %e, "kcp: set_mtu failed; using crate default");
    }
}

/// Peek the conv id (first 4 bytes, little-endian) of a KCP segment.
/// Returns `None` when the buffer is too short to be a KCP segment.
pub fn peek_conv(seg: &[u8]) -> Option<u32> {
    if seg.len() < KCP_OVERHEAD {
        return None;
    }
    Some(u32::from_le_bytes([seg[0], seg[1], seg[2], seg[3]]))
}
