//! WireGuard-marked UDP upload transport (Phase R9a refactor).
//!
//! This module wraps the **existing** WG-marked UDP egress path in the
//! [`UploadTransport`] trait. The runtime behaviour is byte-for-byte
//! unchanged from pre-R9: bind one tokio `UdpSocket`, set `SO_MARK` to
//! the per-tunnel fwmark, run `perf::tune_socket` for the enlarged
//! `SO_SNDBUF`. The R2 perf work all happens before the trait dispatch
//! is even called, so wrapping in a trait costs only ~3 ns of vtable
//! overhead per packet — see the rationale in [`super`].

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tracing::info;

use super::{SessionKey, UploadTransport};

/// UDP-over-WireGuard upload transport. Owns one tokio `UdpSocket`
/// whose `SO_MARK` is the per-tunnel fwmark, and a fixed destination
/// `upload_target` `SocketAddr`. Cloning the inner `Arc<UdpSocket>` so
/// the existing recv loop in `client.rs::spawn_upload_task` can still
/// `recv_from` on the listener while we own the egress is no longer
/// necessary — the upload task moves the listener and the egress into
/// closures separately, and this transport just holds the egress.
pub struct WireguardUpload {
    /// Destination for every UDP send. Constant for the lifetime of
    /// the tunnel; a hot-reload of `upload_target_addr` is classified
    /// as an "internal restart" by the manager, which tears down the
    /// whole tunnel and rebuilds it — so this value never changes
    /// while the transport is alive.
    upload_target: SocketAddr,
    egress: Arc<UdpSocket>,
}

impl WireguardUpload {
    /// Bind a new egress UDP socket, set `SO_MARK = fwmark`, apply the
    /// `perf::tune_socket` knobs (enlarged buffers etc.), and wrap it
    /// as a tokio `UdpSocket`.
    pub fn bind(tunnel_id: i64, upload_target: SocketAddr, fwmark: u32) -> io::Result<Self> {
        // Bind on the same address family as the upload target — a v6
        // upload target needs a v6 socket. This mirrors the
        // pre-R9 path exactly (see `client.rs::spawn` before the
        // R9a refactor).
        let bind = if upload_target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let egress_std = std::net::UdpSocket::bind(bind)?;
        egress_std.set_nonblocking(true)?;
        set_so_mark_fd(&egress_std, fwmark)?;
        crate::perf::tune_socket(&egress_std, "client/egress");
        let egress = Arc::new(UdpSocket::from_std(egress_std)?);
        info!(
            tunnel_id,
            target = %upload_target,
            fwmark = format!("0x{:x}", fwmark),
            "client: WG-mode upload transport bound (R9a)"
        );
        Ok(Self {
            upload_target,
            egress,
        })
    }
}

#[async_trait]
impl UploadTransport for WireguardUpload {
    async fn send(&self, _session: SessionKey, payload: &[u8]) -> io::Result<()> {
        // One syscall per packet — same as the pre-R9 path; the R2
        // batching for upload was deliberately scoped to the listener
        // side. Egress is `recv_from → send_to` single-thread today;
        // batching could land in a follow-up but isn't a part of R9.
        //
        // `_session` is ignored: the WG path has exactly one egress
        // socket, so there's no per-flow routing to do. SOCKS5 honours
        // it for sticky pool routing.
        self.egress
            .send_to(payload, self.upload_target)
            .await
            .map(|_| ())
    }
}

/// Apply `SO_MARK` to a raw fd. Lifted verbatim from `client.rs` so
/// the trait wrapper can stay self-contained.
#[cfg(target_os = "linux")]
fn set_so_mark_fd(sock: &std::net::UdpSocket, mark: u32) -> io::Result<()> {
    if mark == 0 {
        return Ok(());
    }
    // SAFETY: `sock.as_raw_fd()` is a valid open file descriptor for
    // the lifetime of `sock`; SO_MARK reads a 4-byte int from our buffer.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_so_mark_fd(_sock: &std::net::UdpSocket, _mark: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_send_byte_for_byte() {
        // End-to-end smoke test: bind a WireguardUpload pointing at a
        // dummy UDP listener and verify the bytes arrive unchanged.
        // SO_MARK is zero so the test doesn't need CAP_NET_ADMIN.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().expect("local_addr");
        let upload = WireguardUpload::bind(1, server_addr, 0).expect("bind upload");

        let payload = b"hello loopback wireguard";
        let key = SessionKey {
            client_addr: "127.0.0.1:33333".parse().expect("test addr"),
            local_port: 0,
        };
        upload.send(key, payload).await.expect("send");
        let mut buf = vec![0u8; 1500];
        let (n, _from) = server.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], payload);
    }
}
