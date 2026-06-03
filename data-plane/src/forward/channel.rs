//! The opaque-datagram boundary between a reliability engine (KCP or
//! QUIC) and Sublyne's asymmetric spoof/upload channel.
//!
//! A `forward_protocol=tcp` tunnel terminates the user's TCP stream and
//! carries it as a sequence of **opaque datagrams** over the existing
//! best-effort channel: on the Client those datagrams leave via the
//! upload transport (WireGuard / SOCKS5) and arrive via the download
//! verify workers; on the Remote they arrive via the upload listener and
//! leave sealed+spoofed through the seal pipeline. The engine never
//! touches sockets, HMAC, or spoofing — it only needs a two-way
//! "deliver-or-drop datagram" pipe, which is exactly what this module
//! abstracts.
//!
//! The inbound half is a plain bounded `mpsc` the rest of the dataplane
//! feeds; the outbound half is the [`DatagramSink`] trait, implemented by
//! the Client (→ upload transport) and the Remote (→ seal enqueue).

use std::io;

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Inbound queue depth. Matches the download verify pipeline's
/// `DOWNLOAD_CHANNEL_CAP` so a burst that the verify side accepted isn't
/// re-dropped at the engine boundary. On overflow the producer drops the
/// datagram (best-effort — the inner KCP/QUIC layer retransmits).
pub const INBOX_CAP: usize = 4096;

/// Egress staging depth between the engine's KCP output sink and the
/// async task that pushes datagrams into the channel. Bounded so a stalled
/// channel can't grow memory without bound; on overflow the segment is
/// dropped and the engine retransmits.
pub const EGRESS_CAP: usize = 2048;

/// Outbound half of the channel: the engine pushes one opaque datagram
/// (each `<= max_payload()` bytes) toward the peer.
///
/// `send` mirrors [`crate::upload::UploadTransport::send`]'s tri-state
/// contract: `Ok(true)` = handed to the wire (or queued for it),
/// `Ok(false)` = deliberately dropped before the wire (the channel is
/// best-effort and the engine will retransmit), `Err` = a hard transport
/// error the caller logs.
#[async_trait]
pub trait DatagramSink: Send + Sync {
    /// Push one opaque datagram into the asymmetric channel.
    async fn send(&self, datagram: &[u8]) -> io::Result<bool>;

    /// The largest datagram the channel can carry without the seal /
    /// upload path dropping it for being oversized. The engine clamps its
    /// own MTU to this. Equals the tunnel MTU minus the 2-byte multiport
    /// tag reserve (subtracted unconditionally so single- and multi-port
    /// tunnels use the identical engine MTU).
    fn max_payload(&self) -> usize;
}

/// Sender half of the inbound datagram queue. Cloned into whichever part
/// of the dataplane delivers datagrams to this engine (the Client's
/// download verify workers, the Remote's upload listener).
pub type InboundTx = mpsc::Sender<Vec<u8>>;

/// Receiver half of the inbound datagram queue, owned by the engine.
pub type InboundRx = mpsc::Receiver<Vec<u8>>;

/// Create the bounded inbound datagram queue for one engine instance.
pub fn inbound_channel() -> (InboundTx, InboundRx) {
    mpsc::channel(INBOX_CAP)
}
