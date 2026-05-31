//! Application-port tag for multi-port tunnels.
//!
//! A single tunnel can carry several application ports through the one
//! secure download-spoof / upload pipeline, with a fixed 1:1 same-number
//! mapping (client `:8000` <-> remote `:8000`, etc.). To demultiplex the
//! ports over the shared pipeline, every forwarded UDP datagram on a
//! MULTI-PORT tunnel is prefixed with a 2-byte big-endian application-port
//! tag:
//!
//! ```text
//! PORT-TAGGED PAYLOAD = [u16 BE app_port] || [original UDP datagram body]
//! ```
//!
//! This tagged blob is what travels as the "payload" in BOTH directions:
//!
//! - DOWNLOAD (Remote->Client): the tag is INSIDE the HMAC-sealed envelope
//!   payload, so it is authenticated and tamper-proof for free — the seal
//!   already hashes `SHA256(payload)`. The tag lives ABOVE the
//!   [`crate::hmac`] layer: the Remote prepends it before `seal_with` and
//!   the Client strips it after `open_with`. `OVERHEAD`, `SeqWindow`,
//!   `session_id`, and `PROTO_VERSION` are all UNCHANGED.
//! - UPLOAD (Client->Remote): the tag is the first 2 bytes of the datagram
//!   the Client hands to the upload substrate. WireGuard encrypts it; the
//!   SOCKS5 framing carries it inside the existing `[u16 len][payload]`
//!   frame (so `len = 2 + body.len()`). The upload substrates ship opaque
//!   bytes and need no change.
//!
//! SINGLE-PORT tunnels carry NO tag — they are byte-for-byte identical to
//! the pre-multi-port wire format. Multi-port-ness is derived from shared
//! static config (the port list both sides hold), so `PROTO_VERSION` stays
//! at 2 and the change is backward compatible for single-port tunnels.
//!
//! ## Why a full 2-byte port, not a 1-byte index
//!
//! The tag is self-describing and validated: the receiver maps it directly
//! to a socket and DROPS+warns if the port is not in the tunnel's
//! configured set, so config drift can never silently misroute traffic to
//! the wrong service. There is no index-ordering coupling between the two
//! sides. At a 1400 B MTU the 2 bytes cost ~0.14 % — negligible — and the
//! download tag is HMAC-authenticated.

/// Length of the application-port tag in bytes (a big-endian `u16`).
pub const PORT_TAG_LEN: usize = 2;

/// Prepend the 2-byte big-endian `port` tag to `body`, writing the result
/// into `out`. `out` is cleared first and reserved to the exact size, so a
/// caller can reuse a single scratch `Vec` across packets without
/// reallocating once it has grown.
pub fn encode_tag(port: u16, body: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(PORT_TAG_LEN + body.len());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(body);
}

/// Split a port-tagged buffer into its `(app_port, body)` parts. Returns
/// `None` when the buffer is too short to contain the 2-byte tag, in which
/// case the caller drops the datagram.
pub fn decode_tag(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() < PORT_TAG_LEN {
        return None;
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    Some((port, &buf[PORT_TAG_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_port_and_body() {
        let mut out = Vec::new();
        encode_tag(8000, b"hello world", &mut out);
        let (port, body) = decode_tag(&out).expect("decode");
        assert_eq!(port, 8000);
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn roundtrip_empty_body() {
        let mut out = Vec::new();
        encode_tag(443, b"", &mut out);
        assert_eq!(out.len(), PORT_TAG_LEN);
        let (port, body) = decode_tag(&out).expect("decode");
        assert_eq!(port, 443);
        assert!(body.is_empty());
    }

    #[test]
    fn big_endian_byte_order_is_pinned() {
        // 0x1F40 == 8000 -> bytes [0x1F, 0x40] (big-endian). This pins the
        // wire contract so the two sides never disagree on byte order.
        let mut out = Vec::new();
        encode_tag(0x1F40, b"x", &mut out);
        assert_eq!(&out[..PORT_TAG_LEN], &[0x1F, 0x40]);
        assert_eq!(out[PORT_TAG_LEN], b'x');
    }

    #[test]
    fn too_short_returns_none() {
        assert!(decode_tag(&[]).is_none());
        assert!(decode_tag(&[0x1F]).is_none());
        // Exactly the tag length with no body is still valid (empty body).
        assert!(decode_tag(&[0x1F, 0x40]).is_some());
    }

    #[test]
    fn encode_reuses_and_clears_scratch() {
        let mut out = Vec::new();
        encode_tag(1, b"first-packet", &mut out);
        // Reusing the same buffer must not leak bytes from the prior call.
        encode_tag(2, b"x", &mut out);
        let (port, body) = decode_tag(&out).expect("decode");
        assert_eq!(port, 2);
        assert_eq!(body, b"x");
        assert_eq!(out.len(), PORT_TAG_LEN + 1);
    }

    #[test]
    fn covers_full_u16_range() {
        for port in [0u16, 1, 1080, 8000, 51820, 65535] {
            let mut out = Vec::new();
            encode_tag(port, b"payload", &mut out);
            let (got, body) = decode_tag(&out).expect("decode");
            assert_eq!(got, port);
            assert_eq!(body, b"payload");
        }
    }

    #[test]
    fn tag_then_seal_roundtrip_recovers_port_and_body() {
        // End-to-end: the Remote prepends the port tag, seals the tagged
        // payload with the HMAC envelope; the Client opens the envelope
        // and strips the tag, recovering the original (port, body). This
        // pins that the tag rides INSIDE — and is authenticated by — the
        // seal, exactly as the wire design requires.
        use crate::hmac::{self, SeqWindow};

        let key = hmac::derive_key("a-shared-secret");
        let session_id = 0xDEAD_BEEF_CAFE_BABEu64;
        let seq = 42u64;
        let port = 8001u16;
        let app_body = b"application datagram bytes";

        let mut tagged = Vec::new();
        encode_tag(port, app_body, &mut tagged);

        let mut sealed = Vec::new();
        hmac::seal(&key, session_id, seq, &tagged, &mut sealed);

        let mut window = SeqWindow::new();
        let opened = hmac::open(&key, &sealed, &mut window).expect("open");
        let (got_port, got_body) = decode_tag(opened).expect("decode tag");
        assert_eq!(got_port, port);
        assert_eq!(got_body, app_body);
    }
}
