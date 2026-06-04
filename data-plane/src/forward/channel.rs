//! The opaque-datagram boundary between the KCP engine and Sublyne's
//! asymmetric spoof/upload channel.
//!
//! A `forward_protocol=tcp` tunnel terminates the user's TCP stream and
//! carries it as a sequence of **opaque datagrams** over the existing
//! best-effort channel: on the Client those datagrams leave via the
//! upload transport (WireGuard / SOCKS5) and arrive via the download
//! verify workers; on the Remote they arrive via the upload listener and
//! leave sealed+spoofed through the seal pipeline. The engine never
//! touches sockets, HMAC, or spoofing — it only needs a one-way
//! "send-or-backpressure datagram" sink plus a per-conv inbound queue,
//! which is exactly what this module abstracts.
//!
//! The outbound half is the [`DatagramSink`] trait, implemented by the
//! Client (→ upload transport) and the Remote (→ seal enqueue). Unlike
//! the rolled-back v4, the engine forwards each KCP segment **inline**
//! from the owning conv task with real backpressure (`send().await`) —
//! there is no central egress task, no extra channel hop, and no
//! best-effort drop of KCP output (which would trigger retransmit
//! storms).

use std::io;

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Per-conv inbound queue depth (KCP segments awaiting `Kcp::input`).
/// Bounded so a stalled conv can't grow memory without bound; on
/// overflow the producer (the verify worker / upload listener) drops the
/// segment and KCP retransmits. 256 segments ≈ a full window's worth of
/// burst headroom per conv.
pub const INBOUND_CONV_CAP: usize = 256;

/// Outbound half of the channel: the engine pushes one opaque datagram
/// (each `<= max_payload()` bytes) toward the peer, awaiting on a full
/// downstream so KCP output is never dropped.
///
/// `send` mirrors [`crate::upload::UploadTransport::send`]'s tri-state
/// contract: `Ok(true)` = handed to the wire (or queued for it),
/// `Ok(false)` = deliberately dropped before the wire (the downstream
/// was saturated and signalled best-effort drop), `Err` = a hard
/// transport error the caller logs.
#[async_trait]
pub trait DatagramSink: Send + Sync {
    /// Push one opaque datagram into the asymmetric channel, applying
    /// backpressure (await) rather than dropping when the downstream is
    /// momentarily full.
    async fn send(&self, datagram: &[u8]) -> io::Result<bool>;
}

/// Sender half of one conv's inbound segment queue. Held in the engine's
/// conv map; the verify worker (Client) / upload listener (Remote) clones
/// nothing — it `try_send`s into it by conv id.
pub type InboundTx = mpsc::Sender<Vec<u8>>;

/// Receiver half of one conv's inbound segment queue, owned by the conv
/// task.
pub type InboundRx = mpsc::Receiver<Vec<u8>>;

/// Create the bounded inbound segment queue for one conv.
pub fn inbound_channel() -> (InboundTx, InboundRx) {
    mpsc::channel(INBOUND_CONV_CAP)
}
