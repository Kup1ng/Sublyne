//! Reliability engine for `forward_protocol=tcp` (v4.0.0).
//!
//! A TCP-forwarding tunnel terminates the user's TCP connection on the
//! Client and re-originates it to `forward_target` on the Remote, carrying
//! the byte stream reliably over Sublyne's best-effort spoof/upload
//! datagram channel using **KCP**. The engine sits entirely at the
//! forward-payload layer: it consumes and produces opaque datagrams via
//! the [`channel::DatagramSink`] trait and per-conv inbound queues, and
//! never touches the seal / HMAC / anti-replay / spoof machinery (which
//! keeps treating those datagrams as opaque ≤MTU payloads). Multi-port
//! tunnels run one [`engine::Engine`] per application port inside an
//! [`engine::EngineSet`], routed by the existing 2-byte port tag.
//!
//! Per-conversation = per-user-TCP-connection (no smux): one [`conv`]
//! task owns its `Kcp`, stages output into a reused buffer, and forwards
//! it inline with backpressure. See `conv.rs` for why this is both
//! simpler and faster than the rolled-back v4 harness.

pub mod channel;
pub mod conv;
pub mod engine;
pub mod tuning;

pub use channel::{inbound_channel, DatagramSink, InboundRx, InboundTx, INBOUND_CONV_CAP};
pub use engine::{Engine, EngineConfig, EngineRole, EngineSet};
pub use tuning::kcp_mtu;
