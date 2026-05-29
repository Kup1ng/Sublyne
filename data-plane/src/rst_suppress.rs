//! TCP-RST suppression for the TCP-SYN download spoof transport.
//!
//! When a Remote sends a spoofed TCP-SYN to a Client's
//! `download_receive_port`, the Client kernel sees an unsolicited SYN to
//! a port nothing is listening on (the data plane reads via raw socket,
//! not via a TCP listener). The kernel's default response is to send a
//! TCP RST back to the spoofed source — the "white IP" — which (a) is
//! useless noise on the wire and (b) is a DPI heuristic that can mark
//! the path as suspicious.
//!
//! ## Why we drop the RST on OUTPUT, not the SYN on INPUT
//!
//! The obvious-looking approach — `iptables -A INPUT -p tcp --dport
//! <port> -j DROP` — does NOT work, because `ip_local_deliver_finish`
//! (the kernel function that calls into `raw_local_deliver`) only runs
//! if the filter INPUT chain accepts the packet. An INPUT DROP rule
//! prevents BOTH the raw socket delivery and the TCP stack from
//! processing the SYN. We confirmed this empirically when an early
//! version of this module killed the TCP-SYN loopback round-trip test.
//!
//! The actually-correct mechanism: let the kernel see the SYN (raw
//! socket gets its copy via `raw_local_deliver`, then the TCP stack
//! runs and generates a RST), and drop the kernel's RST on the way
//! out. That's done with a surgical OUTPUT rule:
//!
//! ```text
//! iptables -A FORWARD-TCP-SYN-SUPP -p tcp \
//!          --tcp-flags RST RST --sport <download_port> -d <spoof_ip> \
//!          -j DROP
//! iptables -I OUTPUT -p tcp -j FORWARD-TCP-SYN-SUPP
//! ```
//!
//! Scope guarantees (do not regress):
//!
//! 1. The rule is bounded by `--tcp-flags RST RST`,
//!    `--sport <download_port>`, AND `-d <spoof_ip>`. Three orthogonal
//!    matches; it cannot affect any non-RST packet, any RST not from
//!    our download port, or any RST to anywhere other than the spoof
//!    source IP. In particular it cannot block SSH (a different
//!    sport), HTTP responses to operators (different flags), or any
//!    other legitimate traffic.
//! 2. We use our own chain (`FORWARD-TCP-SYN-SUPP`) so an operator can
//!    flush our rules without disturbing anything else: `iptables -F
//!    FORWARD-TCP-SYN-SUPP`.
//! 3. The rule is added at tunnel start and removed at tunnel stop. The
//!    `RstSuppressGuard` returned by `install` implements `Drop` so the
//!    cleanup runs even on panic.
//! 4. iptables failures are non-fatal: we log a WARN and continue. The
//!    tunnel still works — the only side effect is the kernel still
//!    sends RST. This avoids the dataplane refusing to start on a host
//!    without `iptables` installed (rare, but possible).

use std::io;
use std::process::Command;

use tracing::{info, warn};

/// Our private chain. Idempotently created. Holds one DROP rule per
/// running TCP-SYN tunnel, so flushing this chain wipes our footprint
/// without affecting the operator's other rules.
const CHAIN: &str = "FORWARD-TCP-SYN-SUPP";

/// Guard returned by [`install`]. Dropping the guard tears down the
/// rule. Cloning is intentionally unsupported — a tunnel that wants to
/// keep the rule alive should keep the guard alive.
#[derive(Debug)]
pub struct RstSuppressGuard {
    port: u16,
    spoof_ip: String,
    /// Set to `false` if `install` couldn't add the rule (e.g. iptables
    /// missing). Drop is a no-op in that case so we don't `-D` a rule
    /// we never `-A`'d.
    installed: bool,
}

impl Drop for RstSuppressGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        if let Err(e) = remove_drop_for_tunnel(self.port, &self.spoof_ip) {
            warn!(
                port = self.port,
                spoof_ip = %self.spoof_ip,
                err = %e,
                "rst-suppress: cleanup failed; flush manually with 'iptables -F FORWARD-TCP-SYN-SUPP' if you see RSTs"
            );
        } else {
            info!(
                port = self.port,
                spoof_ip = %self.spoof_ip,
                "rst-suppress: removed iptables rule"
            );
        }
    }
}

/// Install the chain (if not already installed) and add an OUTPUT RST
/// DROP rule matching the given (download port, spoof source IP) pair.
/// Returns a guard; when the guard is dropped the rule is removed.
///
/// If iptables isn't available or any individual command fails we log a
/// WARN, return a guard with `installed = false`, and the caller
/// proceeds. The tunnel still functions; the kernel will just send the
/// extra RST that this code was meant to prevent.
pub fn install(port: u16, spoof_ip: &str) -> RstSuppressGuard {
    if let Err(e) = ensure_chain_installed() {
        warn!(
            port,
            spoof_ip = %spoof_ip,
            err = %e,
            "rst-suppress: could not create chain; kernel may emit TCP RST on download_receive_port"
        );
        return RstSuppressGuard {
            port,
            spoof_ip: spoof_ip.to_string(),
            installed: false,
        };
    }
    if let Err(e) = install_drop_for_tunnel(port, spoof_ip) {
        warn!(
            port,
            spoof_ip = %spoof_ip,
            err = %e,
            "rst-suppress: could not add DROP rule; kernel may emit TCP RST on download_receive_port"
        );
        return RstSuppressGuard {
            port,
            spoof_ip: spoof_ip.to_string(),
            installed: false,
        };
    }
    info!(
        port,
        spoof_ip = %spoof_ip,
        "rst-suppress: installed iptables OUTPUT DROP for tcp RST from spoof source"
    );
    RstSuppressGuard {
        port,
        spoof_ip: spoof_ip.to_string(),
        installed: true,
    }
}

/// `iptables -N FORWARD-TCP-SYN-SUPP` (idempotent) plus a single
/// jump from OUTPUT into the chain. We tolerate "chain already exists"
/// errors so multiple tunnels share the chain without fighting.
fn ensure_chain_installed() -> io::Result<()> {
    // Create the chain. If it already exists iptables returns non-zero
    // with stderr "Chain already exists." — treat that as success.
    let create = run_iptables(["-N", CHAIN]);
    if let Err(e) = &create {
        if !e.to_string().to_lowercase().contains("already exists") {
            return create;
        }
    }
    // Make sure OUTPUT jumps into our chain. `-C` checks first; if the
    // rule isn't there, `-I` inserts it at the top of OUTPUT so the
    // DROPs are evaluated before any general ACCEPT.
    if run_iptables(["-C", "OUTPUT", "-p", "tcp", "-j", CHAIN]).is_err() {
        run_iptables(["-I", "OUTPUT", "-p", "tcp", "-j", CHAIN])?;
    }
    Ok(())
}

fn install_drop_for_tunnel(port: u16, spoof_ip: &str) -> io::Result<()> {
    let port_s = port.to_string();
    // `--tcp-flags RST RST`: examine the RST flag, require it set.
    // `--sport <download_port>`: only RSTs originating from our raw-
    //   socket port (the kernel generates these in response to the
    //   spoofed SYN that landed there).
    // `-d <spoof_ip>`: only RSTs heading toward the white IP. The
    //   spoofed SYN's source was that white IP, so the kernel's RST
    //   destination is that same address.
    let args_check: [&str; 13] = [
        "-C",
        CHAIN,
        "-p",
        "tcp",
        "--tcp-flags",
        "RST",
        "RST",
        "--sport",
        &port_s,
        "-d",
        spoof_ip,
        "-j",
        "DROP",
    ];
    if run_iptables(args_check).is_ok() {
        return Ok(()); // Already there.
    }
    let mut args_append: Vec<&str> = args_check.to_vec();
    args_append[0] = "-A";
    run_iptables(args_append)?;
    Ok(())
}

fn remove_drop_for_tunnel(port: u16, spoof_ip: &str) -> io::Result<()> {
    let port_s = port.to_string();
    run_iptables([
        "-D",
        CHAIN,
        "-p",
        "tcp",
        "--tcp-flags",
        "RST",
        "RST",
        "--sport",
        &port_s,
        "-d",
        spoof_ip,
        "-j",
        "DROP",
    ])
}

fn run_iptables<I, S>(args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new("iptables").args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "iptables exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_drop_with_not_installed_does_nothing() {
        // No call to iptables; Drop must not panic.
        let g = RstSuppressGuard {
            port: 8443,
            spoof_ip: "203.0.113.5".into(),
            installed: false,
        };
        drop(g);
    }
}
