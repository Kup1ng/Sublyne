//! Kernel echo-suppression for the Phase R4 ICMP / ICMPv6 `Request`
//! mode.
//!
//! When the data plane crafts a spoofed **ICMP echo-REQUEST** as the
//! download envelope (type 8 on IPv4, type 128 on IPv6), the receiving
//! Iran box's kernel sees a perfectly valid incoming ping and, by
//! default, **auto-replies to it** from the same IP it received the
//! request on. The reply doesn't break our raw-socket receive (the raw
//! socket gets its copy before the kernel emits the reply) but it does
//! two undesirable things:
//!
//! 1. **Leaks our real IP.** The kernel-generated reply goes out from
//!    the Iran box's real IP back to the spoofed white IP — for
//!    operators trying to keep the host's existence quiet behind a
//!    whitelisted source, that's an immediate giveaway.
//! 2. **Wastes bandwidth on the slowest link** in the path. At 200
//!    Mbit/s × 1400 B that's ~17 800 pps of auto-replies pointed at the
//!    white IP. Even if it doesn't break our throughput, it's noise.
//!
//! `spoof-tunnel` solves this with
//! `sysctl net.ipv4.icmp_echo_ignore_all=1` (see its
//! `relay/local.go:suppressICMPEchoReply()`). We do the same, with a
//! lifecycle guard that **restores the original value** when the tunnel
//! stops. Reference counting handles overlapping Request-mode tunnels:
//! the sysctl flips to 1 on the first guard, stays at 1 while any guard
//! is alive, and reverts when the last guard drops.
//!
//! ## Safety notes
//!
//! - Setting `icmp_echo_ignore_all=1` makes the box stop replying to
//!   **all** pings (real or otherwise). That's a behavior change the
//!   operator must opt into via the panel — we log a clear INFO line on
//!   install and a WARN line on cleanup-failure.
//! - The sysctl is **not** namespaced; it affects the entire net
//!   namespace the dataplane runs in. On Ubuntu 22/24 that's the host
//!   namespace, which is what we want.
//! - The path is `/proc/sys/net/ipv4/icmp_echo_ignore_all` for ICMP and
//!   `/proc/sys/net/ipv6/icmp/echo_ignore_all` for ICMPv6. Writes need
//!   `CAP_NET_ADMIN` (which the service already has).
//! - If the write fails (e.g. read-only `/proc`, sandboxed container)
//!   we log a WARN and leave the guard "uninstalled" so its `Drop` is a
//!   no-op. The tunnel continues to run — the only consequence is that
//!   the box may keep replying to pings.

use std::fs;
use std::io;
use std::sync::Mutex;

use tracing::{info, warn};

use crate::spec::Transport;

/// Reference-counted sysctl state, per knob.
///
/// `count > 0` means at least one guard is alive; the sysctl is being
/// held at 1. `original` is the value read the first time we flipped
/// the knob (typically `0`). On the last guard drop we restore that
/// value.
#[derive(Debug, Default)]
struct KnobState {
    count: usize,
    original: Option<String>,
}

static V4_KNOB: Mutex<KnobState> = Mutex::new(KnobState {
    count: 0,
    original: None,
});

static V6_KNOB: Mutex<KnobState> = Mutex::new(KnobState {
    count: 0,
    original: None,
});

const V4_PATH: &str = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
const V6_PATH: &str = "/proc/sys/net/ipv6/icmp/echo_ignore_all";

/// Per-tunnel guard. Installs `icmp_echo_ignore_all=1` on construction
/// when the transport is ICMP / ICMPv6 and the mode is `Request`;
/// restores the original value when the last guard drops.
///
/// `installed = false` means the constructor decided no kernel write
/// was needed (mode = Reply, or transport doesn't use ICMP, or the
/// caller is running on a non-Linux host). `Drop` is a no-op in that
/// case.
#[derive(Debug)]
pub struct EchoIgnoreGuard {
    kind: GuardKind,
    installed: bool,
}

#[derive(Debug, Clone, Copy)]
enum GuardKind {
    V4,
    V6,
    None,
}

impl Drop for EchoIgnoreGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        let (knob, path, label) = match self.kind {
            GuardKind::V4 => (&V4_KNOB, V4_PATH, "ipv4"),
            GuardKind::V6 => (&V6_KNOB, V6_PATH, "ipv6"),
            GuardKind::None => return,
        };
        let mut state = match knob.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.count = state.count.saturating_sub(1);
        if state.count == 0 {
            // Last guard — restore the original.
            if let Some(orig) = state.original.take() {
                if let Err(e) = fs::write(path, orig.as_bytes()) {
                    warn!(
                        path,
                        family = label,
                        err = %e,
                        "icmp-sysctl: failed to restore echo_ignore_all; please run \
                         'sysctl -w net.{}={}' manually if local pings still don't reply",
                        match self.kind { GuardKind::V4 => "ipv4.icmp_echo_ignore_all", _ => "ipv6.icmp.echo_ignore_all" },
                        orig.trim(),
                    );
                } else {
                    info!(
                        path,
                        family = label,
                        restored = %orig.trim(),
                        "icmp-sysctl: restored echo_ignore_all to its original value"
                    );
                }
            }
        }
    }
}

/// Install the guard for the given transport + mode, if needed.
///
/// Returns a `EchoIgnoreGuard` either way — the caller stores it on the
/// tunnel handle so it drops on shutdown. The guard is installed (i.e.
/// will restore on drop) only when:
///
/// - `transport` is ICMP or ICMPv6, AND
/// - `mode` is Request, AND
/// - the relevant `/proc/sys/.../echo_ignore_all` is writable.
///
/// All other cases produce a guard with `installed = false` whose
/// `Drop` does nothing.
pub fn install(transport: Transport, mode: crate::spec::IcmpEchoMode) -> EchoIgnoreGuard {
    if !matches!(mode, crate::spec::IcmpEchoMode::Request) {
        return EchoIgnoreGuard {
            kind: GuardKind::None,
            installed: false,
        };
    }
    let kind = match transport {
        Transport::Icmp => GuardKind::V4,
        Transport::Icmpv6 => GuardKind::V6,
        _ => {
            return EchoIgnoreGuard {
                kind: GuardKind::None,
                installed: false,
            }
        }
    };
    let (knob, path, label) = match kind {
        GuardKind::V4 => (&V4_KNOB, V4_PATH, "ipv4"),
        GuardKind::V6 => (&V6_KNOB, V6_PATH, "ipv6"),
        GuardKind::None => unreachable!(),
    };
    let mut state = match knob.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if state.count == 0 {
        // First holder — capture the original and flip.
        match read_current(path) {
            Ok(orig) => {
                if let Err(e) = fs::write(path, b"1\n") {
                    warn!(
                        path,
                        family = label,
                        err = %e,
                        "icmp-sysctl: could not write echo_ignore_all=1; \
                         box will reply to incoming pings while the tunnel runs"
                    );
                    return EchoIgnoreGuard {
                        kind,
                        installed: false,
                    };
                }
                // Defensive: if the knob is ALREADY "1" before we touch it,
                // it is almost certainly an orphan from a previous unclean
                // dataplane exit (SIGKILL / OOM / panic-abort) where the Drop
                // guard never ran — NOT a value the operator chose. Trusting
                // it as the restore target would make every future clean Stop
                // restore "1", permanently suppressing ping replies on the
                // host. Restore the kernel default "0" (replies on) instead,
                // which is the safe failure direction, and warn loudly.
                let restore_target = if orig.trim() == "1" {
                    warn!(
                        path,
                        family = label,
                        "icmp-sysctl: echo_ignore_all was already 1 before this tunnel started \
                         (likely orphaned by a prior unclean exit); on stop it will be restored \
                         to 0 (replies on), not 1"
                    );
                    "0\n".to_string()
                } else {
                    orig.clone()
                };
                info!(
                    path,
                    family = label,
                    previous = %orig.trim(),
                    "icmp-sysctl: echo_ignore_all=1 — kernel will NOT reply to incoming pings while this tunnel runs"
                );
                state.original = Some(restore_target);
                state.count = 1;
                EchoIgnoreGuard {
                    kind,
                    installed: true,
                }
            }
            Err(e) => {
                warn!(
                    path,
                    family = label,
                    err = %e,
                    "icmp-sysctl: could not read current echo_ignore_all; leaving alone"
                );
                EchoIgnoreGuard {
                    kind,
                    installed: false,
                }
            }
        }
    } else {
        // Subsequent holder — just bump the refcount.
        state.count += 1;
        EchoIgnoreGuard {
            kind,
            installed: true,
        }
    }
}

fn read_current(path: &str) -> io::Result<String> {
    fs::read_to_string(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::IcmpEchoMode;

    #[test]
    fn reply_mode_is_no_op() {
        // Reply mode should never touch the sysctl, regardless of
        // transport. We just construct + drop a guard and verify the
        // guard is `installed = false`.
        let g = install(Transport::Icmp, IcmpEchoMode::Reply);
        assert!(!g.installed);
        drop(g);
    }

    #[test]
    fn udp_transport_is_no_op() {
        let g = install(Transport::Udp, IcmpEchoMode::Request);
        assert!(!g.installed);
    }

    #[test]
    fn tcp_syn_transport_is_no_op() {
        let g = install(Transport::TcpSyn, IcmpEchoMode::Request);
        assert!(!g.installed);
    }
}
