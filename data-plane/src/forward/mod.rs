//! Reliability engines for `forward_protocol=tcp` (v4.0.0).
//!
//! A TCP-forwarding tunnel terminates the user's TCP connection on the
//! Client and re-originates it to `forward_target` on the Remote, carrying
//! the byte stream reliably over Sublyne's best-effort spoof/upload
//! datagram channel. The engine sits entirely at the forward-payload
//! layer: it consumes/produces opaque datagrams via [`channel::DatagramSink`]
//! + an inbound queue, and never touches the seal/HMAC/anti-replay/spoof
//! machinery (which keeps treating those datagrams as opaque ≤MTU payloads).
//!
//! [`kcp`] is the KCP engine; the QUIC engine lands alongside it. Both
//! implement the same boundary so the Client/Remote integration is
//! engine-agnostic.

pub mod channel;
pub mod kcp;

pub use channel::{inbound_channel, DatagramSink, InboundRx, InboundTx};
pub use kcp::{EngineConfig, EngineRole, EngineStats, KcpEngine};
