-- 0009_upload_matrix: enforce the v2 upload × download mechanism matrix.
-- Created in the v2.0.0 (upload×download matrix) release.
--
-- v2 makes the upload path a function of the download transport instead
-- of a free, orthogonal choice:
--
--   download  | client upload_mode  | remote upload_listen_mode
--   ----------+---------------------+--------------------------
--   udp       | wireguard           | udp
--   tcp_syn   | socks5              | socks5_tcp
--   icmp      | wireguard | socks5  | udp | socks5_tcp
--   icmpv6    | wireguard | socks5  | udp | socks5_tcp
--
-- The matrix is a CONSTRAINT BETWEEN existing columns
-- (download_transport, upload_mode, upload_listen_mode), so this
-- migration adds NO new columns. Enforcement of new authoring lives in
-- the Go validator (control-plane/internal/tunnels/validation.go) and
-- the panel; the dataplane warns-but-runs on an off-matrix legacy row so
-- a deploy never dead-tunnels a working pair.
--
-- The ONLY data change here is the single provably-safe normalization:
-- a Remote row whose download_transport is 'udp' can physically only
-- pair with a UDP upload listener, so any such row is pinned to
-- upload_listen_mode='udp'. This is a no-op for every row that already
-- holds the correct value (migration 0007 defaulted them all to 'udp').
--
-- We deliberately do NOT rewrite the Client's upload_mode or a Remote's
-- non-udp listen mode:
--   * flipping a Client 'socks5'->'wireguard' would silently strip a
--     working proxy link;
--   * flipping 'wireguard'->'socks5' has no proxy to point at;
--   * a Remote 'tcp_syn' that is currently on 'udp' (the pre-v2 "one
--     size fits all" combo) can't be safely auto-migrated to
--     'socks5_tcp' because its paired Client may still be on WireGuard.
-- Those ambiguous rows keep running after the upgrade and are surfaced
-- to the operator by the panel + validator on the next edit, where the
-- fix is a single dropdown change with the proxy picker in reach.

UPDATE tunnels
   SET upload_listen_mode = 'udp'
 WHERE role = 'remote'
   AND download_transport = 'udp'
   AND upload_listen_mode <> 'udp';
