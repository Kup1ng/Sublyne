-- 0011_unified_ports.sql
-- v2.7.0 unified application-port list.
--
-- Before v2.7.0 a tunnel's primary ("main") application port lived inside
-- the host:port of local_listen_addr (Client) / forward_target (Remote),
-- while any EXTRA ports lived in the `ports` CSV (added in 0010). The main
-- port was therefore stored twice for multi-port tunnels and only inside
-- the address string for single-port tunnels — two places to think about.
--
-- v2.7.0 unifies this: EVERY application port lives in the `ports` CSV, and
-- local_listen_addr / forward_target carry a bare HOST (no port). This
-- migration folds the address-embedded port into `ports` and strips the
-- port off the address column, so every existing tunnel keeps working with
-- zero operator action.
--
-- The dataplane WIRE FORMAT is unchanged. The Go control plane rebuilds
-- host:port for the IPC payload from (host, ports[0]) and still gates the
-- 2-byte app-port tag on len(ports) >= 2, so a single-port tunnel stays
-- byte-identical on the network. This is a UX/schema refactor, not a
-- protocol change.
--
-- Address parsing mirrors Go's net.SplitHostPort: the value is either a
-- bracketed IPv6 literal ("[2001:db8::1]:443" / "[::]:443") split at the
-- "]:" delimiter, or a single-colon host:port ("0.0.0.0:443",
-- "host:443") split at the (only) ":". A bare unbracketed IPv6 is not a
-- valid host:port and never occurs in a pre-v2.7.0 row, so it is not
-- handled here.
--
-- For multi-port rows (ports already non-empty) the list is the full
-- authoritative set INCLUDING the canonical port (the pre-v2.7.0 validator
-- guaranteed this), so we keep `ports` as-is and only strip the address.
-- For single-port rows (ports = '') we seed the list with the one port
-- parsed out of the address.

-- Client rows: the application port lives in local_listen_addr.
UPDATE tunnels
   SET ports = CASE
                 WHEN ports <> '' THEN ports
                 WHEN local_listen_addr LIKE '%]:%'
                   THEN substr(local_listen_addr, instr(local_listen_addr, ']:') + 2)
                 ELSE substr(local_listen_addr, instr(local_listen_addr, ':') + 1)
               END,
       local_listen_addr = CASE
                 WHEN local_listen_addr LIKE '%]:%'
                   THEN substr(local_listen_addr, 2, instr(local_listen_addr, ']:') - 2)
                 ELSE substr(local_listen_addr, 1, instr(local_listen_addr, ':') - 1)
               END
 WHERE role = 'client'
   AND local_listen_addr IS NOT NULL
   AND local_listen_addr LIKE '%:%';

-- Remote rows: the application port lives in forward_target.
UPDATE tunnels
   SET ports = CASE
                 WHEN ports <> '' THEN ports
                 WHEN forward_target LIKE '%]:%'
                   THEN substr(forward_target, instr(forward_target, ']:') + 2)
                 ELSE substr(forward_target, instr(forward_target, ':') + 1)
               END,
       forward_target = CASE
                 WHEN forward_target LIKE '%]:%'
                   THEN substr(forward_target, 2, instr(forward_target, ']:') - 2)
                 ELSE substr(forward_target, 1, instr(forward_target, ':') - 1)
               END
 WHERE role = 'remote'
   AND forward_target IS NOT NULL
   AND forward_target LIKE '%:%';
