package dataplane

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// appAddr rebuilds the host:port string the dataplane needs from the
// host-only address column and the unified application-port list.
//
// Since v2.7.0 local_listen_addr (Client) / forward_target (Remote) carry
// only a host; every application port lives in tunnels.Ports. The Rust
// dataplane still parses these into a numeric SocketAddr, so we join the
// host with ports[0]. In multi-port mode (the IPC `ports` array, gated on
// len >= 2 by buildSpec) the dataplane uses only the host from this string
// and binds every listed port, so which port we pick here is cosmetic; in
// single-port mode it is THE port, and the result is byte-identical to the
// pre-v2.7.0 wire.
//
// It tolerates a legacy address that still carries a port (a pre-0011 or
// hand-edited row) by taking just the host, so correctness never hinges on
// the data migration's string parsing.
func appAddr(stored string, ports []int) (string, error) {
	host := strings.TrimSpace(stored)
	legacyPort := 0
	hadLegacyPort := false
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, perr := strconv.Atoi(p); perr == nil {
			legacyPort, hadLegacyPort = n, true
		}
	}
	if host == "" {
		return "", errors.New("empty listen/forward host")
	}
	var port int
	switch {
	case len(ports) > 0:
		port = ports[0]
	case hadLegacyPort:
		port = legacyPort
	default:
		return "", errors.New("no application port configured")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
