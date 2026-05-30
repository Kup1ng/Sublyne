//! Batched send/recv syscalls (`recvmmsg` / `sendmmsg`) for the
//! dataplane hot path.
//!
//! Linux's `recvmmsg(2)` and `sendmmsg(2)` accept an array of message
//! descriptors and process the whole batch in one user→kernel
//! transition. At 17 800 packets/sec (200 Mbit/s × 1400 B) the
//! one-syscall-per-packet pattern in v0.1.x was the chief CPU cost on
//! the spoof recv/send loops; batching at 16 amortises that to
//! ~1100 syscalls/sec.
//!
//! ## Memory layout
//!
//! Each batch owns:
//!
//! * `slots: Vec<Slot>` — one buffer + sockaddr storage per message.
//! * `iovecs: Vec<libc::iovec>` — one entry per slot.
//! * `mmsghdrs: Vec<libc::mmsghdr>` — one entry per slot.
//!
//! `iovec.iov_base` and `mmsghdr.msg_iov` / `msg_name` hold raw
//! pointers into the slot storage. Moving the batch struct moves the
//! `Vec` headers, which can leave those raw pointers dangling. Each
//! call therefore **re-stitches** the pointers from scratch before
//! invoking the syscall — the cost is `O(batch_size)` simple writes
//! (~1 µs at batch 16), vastly less than the syscall itself.
//!
//! ## Buffer sizing
//!
//! Recv slots use [`crate::transport::udp::MAX_UDP_DATAGRAM`] (64 KiB)
//! to avoid the `MSG_TRUNC`-without-error trap documented in
//! `.claude/skills/raw-sockets-and-spoofing/SKILL.md` §"Recv buffer
//! size". Send slots size to the caller-provided MTU plus headroom for
//! the spoof + HMAC envelope.

use std::io;
use std::mem;
use std::net::SocketAddr;

use crate::transport::udp::MAX_UDP_DATAGRAM;

// ---- recv ----------------------------------------------------------------

/// One slot in a [`RecvBatch`]. Holds an owned buffer, the address
/// `recvmmsg` filled in on the last call, and the actual byte count.
pub struct RecvSlot {
    pub buf: Vec<u8>,
    pub len: usize,
    addr: libc::sockaddr_storage,
    addr_len: libc::socklen_t,
}

impl RecvSlot {
    fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            len: 0,
            // SAFETY: `sockaddr_storage` is `Copy` and zeroed-init is
            // a valid representation (address family AF_UNSPEC).
            addr: unsafe { mem::zeroed() },
            addr_len: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        }
    }

    /// Bytes received this call. Slice into `self.buf[..self.len]`
    /// for the actual payload.
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Parse the recorded source address into a `SocketAddr`. Returns
    /// `None` for unexpected families or short lengths (raw sockets
    /// occasionally deliver minimal sockaddrs).
    pub fn src(&self) -> Option<SocketAddr> {
        sockaddr_to_socketaddr(&self.addr, self.addr_len)
    }
}

/// Reusable receive batch. Allocate once at task start and drive
/// [`recvmmsg`] against it on every readability wake-up.
///
/// Storage layout: only the per-slot `Vec<u8>` buffers and the
/// `sockaddr_storage` are kept in the struct. The `iovec` and
/// `mmsghdr` arrays — which hold raw pointers and would otherwise
/// poison `Send` for the whole struct — are allocated fresh inside
/// [`recvmmsg`] each call. The per-call alloc cost is one
/// `Vec<iovec>` + one `Vec<mmsghdr>` of `batch_size` elements; at the
/// default 16-element batch on the modern Linux allocator this is
/// ~200 ns total, vs the ~1–10 µs `recvmmsg` syscall itself.
pub struct RecvBatch {
    pub slots: Vec<RecvSlot>,
}

impl RecvBatch {
    /// Build a batch of `batch_size` slots, each backed by a buffer of
    /// `buf_size` bytes. The batch size is clamped to `1..=256` because
    /// the kernel rejects `vlen == 0` and refuses very large
    /// `mmsghdr` arrays (a 256-element batch is already absurdly
    /// generous for our 1500-byte UDP workload).
    pub fn new(batch_size: usize, buf_size: usize) -> Self {
        let n = batch_size.clamp(1, 256);
        Self {
            slots: (0..n).map(|_| RecvSlot::new(buf_size)).collect(),
        }
    }

    /// A batch sized for the spoof / kernel UDP recv hot path: full
    /// 64 KiB buffer per slot to absorb any legitimate UDP datagram.
    pub fn for_udp(batch_size: usize) -> Self {
        Self::new(batch_size, MAX_UDP_DATAGRAM)
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}

/// Run `recvmmsg` on `fd`. Returns the number of slots filled, which is
/// guaranteed to be `<= batch.capacity()`. Slots past the returned
/// count retain whatever data the previous call left in them.
///
/// On `EAGAIN` / `EWOULDBLOCK` the underlying syscall returns -1 and
/// `errno` is set accordingly — callers should treat that the same way
/// they would a `recvfrom` with `MSG_DONTWAIT`.
///
/// # Safety
///
/// The `fd` must be a valid socket file descriptor that the caller
/// owns for the duration of this call. The function does not take
/// ownership of `fd`.
pub fn recvmmsg(fd: i32, batch: &mut RecvBatch) -> io::Result<usize> {
    let n = batch.slots.len();
    // Build iovec + mmsghdr arrays as locals. Holding them in the
    // RecvBatch struct would poison `Send`/`Sync` (raw pointers); the
    // per-call alloc cost is negligible compared to the syscall itself.
    //
    // We assign through zero-initialised `msghdr` rather than using a
    // struct literal because musl's `libc::msghdr` has private
    // `__pad1`/`__pad2` fields that the literal form can't construct.
    let mut iovecs: Vec<libc::iovec> = (0..n).map(|_| unsafe { mem::zeroed() }).collect();
    let mut mmsghdrs: Vec<libc::mmsghdr> = (0..n).map(|_| unsafe { mem::zeroed() }).collect();
    for i in 0..n {
        let slot = &mut batch.slots[i];
        slot.addr_len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        iovecs[i] = libc::iovec {
            iov_base: slot.buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: slot.buf.len(),
        };
        let hdr = &mut mmsghdrs[i].msg_hdr;
        hdr.msg_name = &mut slot.addr as *mut _ as *mut libc::c_void;
        hdr.msg_namelen = slot.addr_len;
        hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        hdr.msg_iovlen = 1;
        hdr.msg_control = std::ptr::null_mut();
        hdr.msg_controllen = 0;
        hdr.msg_flags = 0;
        // mmsghdrs[i].msg_len was zeroed by the initial mem::zeroed().
    }
    let rc = unsafe {
        libc::recvmmsg(
            fd,
            mmsghdrs.as_mut_ptr(),
            n as libc::c_uint,
            // MSG_DONTWAIT is `c_int` (signed) on glibc but `c_uint`
            // on musl. `as _` lets the compiler pick the right one.
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = rc as usize;
    for (i, mhdr) in mmsghdrs.iter().enumerate().take(received) {
        batch.slots[i].len = mhdr.msg_len as usize;
        batch.slots[i].addr_len = mhdr.msg_hdr.msg_namelen;
    }
    Ok(received)
}

// ---- send ----------------------------------------------------------------

/// One slot in a [`SendBatch`]. The caller fills `buf[..len]` with the
/// bytes to send and sets `dest` to the destination address.
pub struct SendSlot {
    pub buf: Vec<u8>,
    pub len: usize,
    addr: libc::sockaddr_storage,
    addr_len: libc::socklen_t,
    /// When `false`, the slot is skipped (msg_iovlen=0). Lets the
    /// caller stage a partially-full batch without re-allocating.
    pub active: bool,
}

impl SendSlot {
    fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            len: 0,
            addr: unsafe { mem::zeroed() },
            addr_len: 0,
            active: false,
        }
    }

    /// Set the destination address for this slot. Required before
    /// every send unless the underlying socket is `connect()`ed.
    pub fn set_dest(&mut self, dest: SocketAddr) {
        let (sa, len) = socketaddr_to_sockaddr(dest);
        self.addr = sa;
        self.addr_len = len;
    }

    /// Clear the destination so `sendmmsg` will use the socket's
    /// connected peer (when the socket has `connect()`ed; otherwise
    /// the kernel returns `EDESTADDRREQ`).
    pub fn clear_dest(&mut self) {
        self.addr_len = 0;
    }
}

/// Reusable send batch. Allocate once and reuse across send loops.
/// Same `Send`-friendly layout as [`RecvBatch`] — iovec/mmsghdr arrays
/// are built locally on each [`sendmmsg`] call.
pub struct SendBatch {
    pub slots: Vec<SendSlot>,
}

impl SendBatch {
    pub fn new(batch_size: usize, buf_size: usize) -> Self {
        let n = batch_size.clamp(1, 256);
        Self {
            slots: (0..n).map(|_| SendSlot::new(buf_size)).collect(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Reset `active` on every slot. Call before staging a fresh
    /// batch so the previous round's leftover slots aren't re-sent.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.active = false;
            slot.len = 0;
        }
    }

    /// Compact the un-sent tail `[accepted..count]` to the front of the
    /// batch, preserving its relative order, and return the new pending
    /// count (`count - accepted`).
    ///
    /// Used by a single send worker to requeue the part of a partial
    /// `sendmmsg` the kernel did not accept. Because the tail keeps its
    /// order and is moved to slots `0..(count-accepted)`, the next
    /// `sendmmsg` re-emits exactly those packets FIRST — wire FIFO is
    /// preserved across the partial send. Slots beyond the new pending
    /// prefix are marked inactive so a later stage can refill them.
    ///
    /// The move is a `Vec::swap` of whole [`SendSlot`] values, so each
    /// slot's owned buffer and sockaddr travel with it — no per-packet
    /// heap allocation, no re-copy of payload bytes.
    ///
    /// `accepted` and `count` are clamped to the batch length; if
    /// `accepted >= count` nothing is pending and the batch is reset.
    pub fn shift_unsent_to_front(&mut self, accepted: usize, count: usize) -> usize {
        let cap = self.slots.len();
        let count = count.min(cap);
        let accepted = accepted.min(count);
        let pending = count - accepted;
        if pending == 0 {
            self.reset();
            return 0;
        }
        if accepted > 0 {
            // Move slots[accepted..count] down to slots[0..pending],
            // keeping their order. `swap` exchanges whole slot values
            // (buf + sockaddr + flags) so private fields move too.
            for i in 0..pending {
                self.slots.swap(i, accepted + i);
            }
        }
        // Anything past the requeued prefix is stale — deactivate it so
        // a future `reset`-free stage can't accidentally resend it.
        for slot in self.slots.iter_mut().skip(pending) {
            slot.active = false;
            slot.len = 0;
        }
        pending
    }
}

/// Send up to `count` active prefix slots from `batch`. Returns the
/// number of messages the kernel accepted (which may be less than
/// `count` under back-pressure — re-queue the un-sent tail and retry).
///
/// `count` MUST be `<= batch.capacity()`. Slots `0..count` must all
/// have `active = true` and valid `dest` + `len`. The implementation
/// only sends contiguous active prefix; it does not skip inactive
/// slots in the middle of the range.
///
/// # Safety
///
/// `fd` must be a valid socket file descriptor owned by the caller
/// for the duration of the call.
pub fn sendmmsg(fd: i32, batch: &mut SendBatch, count: usize) -> io::Result<usize> {
    let n = count.min(batch.slots.len());
    if n == 0 {
        return Ok(0);
    }
    // Build iovec + mmsghdr arrays as locals (see RecvBatch doc for
    // why we don't keep them in the struct). Field-assignment style
    // for the same musl-private-padding reason as recvmmsg above.
    let mut iovecs: Vec<libc::iovec> = (0..n).map(|_| unsafe { mem::zeroed() }).collect();
    let mut mmsghdrs: Vec<libc::mmsghdr> = (0..n).map(|_| unsafe { mem::zeroed() }).collect();
    for i in 0..n {
        let slot = &mut batch.slots[i];
        iovecs[i] = libc::iovec {
            iov_base: slot.buf.as_ptr() as *mut libc::c_void,
            iov_len: slot.len,
        };
        let msg_name = if slot.addr_len == 0 {
            std::ptr::null_mut()
        } else {
            &mut slot.addr as *mut _ as *mut libc::c_void
        };
        let hdr = &mut mmsghdrs[i].msg_hdr;
        hdr.msg_name = msg_name;
        hdr.msg_namelen = slot.addr_len;
        hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        hdr.msg_iovlen = 1;
        hdr.msg_control = std::ptr::null_mut();
        hdr.msg_controllen = 0;
        hdr.msg_flags = 0;
    }
    let rc = unsafe {
        libc::sendmmsg(
            fd,
            mmsghdrs.as_mut_ptr(),
            n as libc::c_uint,
            // glibc takes `c_int`, musl takes `c_uint` — let the
            // compiler pick.
            libc::MSG_DONTWAIT as _,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

// ---- sockaddr conversion -------------------------------------------------

fn socketaddr_to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const libc::sockaddr_in as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const libc::sockaddr_in6 as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn sockaddr_to_socketaddr(
    addr: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    let len = len as usize;
    let family = addr.ss_family as libc::c_int;
    if family == libc::AF_INET && len >= mem::size_of::<libc::sockaddr_in>() {
        let sin: libc::sockaddr_in = unsafe {
            let mut sin: libc::sockaddr_in = mem::zeroed();
            std::ptr::copy_nonoverlapping(
                addr as *const libc::sockaddr_storage as *const u8,
                &mut sin as *mut libc::sockaddr_in as *mut u8,
                mem::size_of::<libc::sockaddr_in>(),
            );
            sin
        };
        let ip = std::net::Ipv4Addr::from(u32::from_be(u32::from_ne_bytes(
            sin.sin_addr.s_addr.to_ne_bytes(),
        )));
        let port = u16::from_be(sin.sin_port);
        Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
    } else if family == libc::AF_INET6 && len >= mem::size_of::<libc::sockaddr_in6>() {
        let sin6: libc::sockaddr_in6 = unsafe {
            let mut sin6: libc::sockaddr_in6 = mem::zeroed();
            std::ptr::copy_nonoverlapping(
                addr as *const libc::sockaddr_storage as *const u8,
                &mut sin6 as *mut libc::sockaddr_in6 as *mut u8,
                mem::size_of::<libc::sockaddr_in6>(),
            );
            sin6
        };
        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            ip,
            port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    #[test]
    fn sockaddr_v4_roundtrip() {
        let original: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (sa, len) = socketaddr_to_sockaddr(original);
        let parsed = sockaddr_to_socketaddr(&sa, len).expect("v4 parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn sockaddr_v6_roundtrip() {
        let original: SocketAddr = "[::1]:54321".parse().unwrap();
        let (sa, len) = socketaddr_to_sockaddr(original);
        let parsed = sockaddr_to_socketaddr(&sa, len).expect("v6 parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn recv_batch_capacity_clamps() {
        assert_eq!(RecvBatch::new(0, 1500).capacity(), 1);
        assert_eq!(RecvBatch::new(16, 1500).capacity(), 16);
        assert_eq!(RecvBatch::new(1024, 1500).capacity(), 256);
    }

    #[test]
    fn send_batch_reset_clears_active() {
        let mut b = SendBatch::new(4, 64);
        for slot in &mut b.slots {
            slot.active = true;
            slot.len = 32;
        }
        b.reset();
        for slot in &b.slots {
            assert!(!slot.active);
            assert_eq!(slot.len, 0);
        }
    }

    #[test]
    fn shift_unsent_to_front_requeues_tail_in_order() {
        let mut b = SendBatch::new(8, 64);
        // Stage 6 packets with distinguishable payloads.
        for i in 0..6 {
            b.slots[i].buf[0] = i as u8;
            b.slots[i].len = 1;
            b.slots[i].active = true;
        }
        // Kernel accepted the first 4 of 6 — requeue [4..6].
        let pending = b.shift_unsent_to_front(4, 6);
        assert_eq!(pending, 2);
        // The two un-sent packets moved to the front, in order.
        assert_eq!(b.slots[0].buf[0], 4);
        assert_eq!(b.slots[1].buf[0], 5);
        assert!(b.slots[0].active && b.slots[1].active);
        assert_eq!(b.slots[0].len, 1);
        assert_eq!(b.slots[1].len, 1);
        // Everything past the requeued prefix is deactivated.
        for slot in &b.slots[2..] {
            assert!(!slot.active);
            assert_eq!(slot.len, 0);
        }
    }

    #[test]
    fn shift_unsent_to_front_full_accept_resets() {
        let mut b = SendBatch::new(4, 64);
        for slot in &mut b.slots {
            slot.active = true;
            slot.len = 8;
        }
        // accepted == count: nothing pending, whole batch reset.
        let pending = b.shift_unsent_to_front(4, 4);
        assert_eq!(pending, 0);
        for slot in &b.slots {
            assert!(!slot.active);
            assert_eq!(slot.len, 0);
        }
    }

    /// End-to-end loopback: bind two UDP sockets, send 8 messages via
    /// sendmmsg, receive them via recvmmsg, verify every byte and the
    /// source address match.
    #[test]
    fn sendmmsg_recvmmsg_loopback_roundtrip() {
        let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv.local_addr().expect("recv addr");
        recv.set_nonblocking(true).expect("nonblocking");
        let send = UdpSocket::bind("127.0.0.1:0").expect("bind send");
        let send_addr = send.local_addr().expect("send addr");
        send.set_nonblocking(true).expect("nonblocking");

        let mut batch = SendBatch::new(8, 128);
        for (i, slot) in batch.slots.iter_mut().enumerate() {
            let payload = format!("hello-{i}");
            slot.buf[..payload.len()].copy_from_slice(payload.as_bytes());
            slot.len = payload.len();
            slot.set_dest(recv_addr);
            slot.active = true;
        }
        let sent = sendmmsg(send.as_raw_fd(), &mut batch, 8).expect("sendmmsg");
        assert_eq!(sent, 8, "all eight messages must send on loopback");

        // Give the kernel a tick so loopback delivery lands.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut rb = RecvBatch::new(8, 256);
        let received = recvmmsg(recv.as_raw_fd(), &mut rb).expect("recvmmsg");
        assert_eq!(received, 8, "must receive every sent message");
        // The OS doesn't guarantee ordering across distinct sends, but
        // on loopback we get them in order; assert the set of payloads
        // matches and every src is `send_addr`.
        let mut seen: Vec<String> = (0..received)
            .map(|i| {
                let slot = &rb.slots[i];
                assert_eq!(slot.src(), Some(send_addr));
                String::from_utf8(slot.data().to_vec()).unwrap()
            })
            .collect();
        seen.sort();
        let mut expected: Vec<String> = (0..8).map(|i| format!("hello-{i}")).collect();
        expected.sort();
        assert_eq!(seen, expected);
    }
}
