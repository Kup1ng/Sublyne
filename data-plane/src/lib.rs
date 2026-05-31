// Library surface for sublyne-dataplane.
//
// The production binary lives in `main.rs`; everything that is
// interesting to test sits in modules exposed here. The integration
// tests under `tests/` link against this library, so anything they
// touch must be `pub`.

pub mod batch;
pub mod hmac;
pub mod icmp_id;
pub mod icmp_sysctl;
pub mod ipc;
pub mod manager;
pub mod memory;
pub mod metrics;
pub mod multiport;
pub mod perf;
pub mod ping_smoothing;
pub mod protocol;
pub mod rst_suppress;
pub mod session;
pub mod spec;
pub mod time_util;
pub mod transport;
pub mod tunnel;
pub mod upload;
