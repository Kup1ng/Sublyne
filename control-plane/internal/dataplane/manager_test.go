package dataplane

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
)

func TestBuildSpec_Client(t *testing.T) {
	tun := tunnels.Tunnel{
		ID:                      42,
		Name:                    "c1",
		Role:                    tunnels.RoleClient,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{Valid: true, String: "0.0.0.0:5001"},
		DownloadReceivePort:     sql.NullInt64{Valid: true, Int64: 8443},
		UploadTargetAddr:        sql.NullString{Valid: true, String: "198.51.100.10:55555"},
		WGConfigID:              sql.NullInt64{Valid: true, Int64: 1},
	}
	spec, err := buildSpec(tun, nil)
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	if spec.ID != 42 || spec.Role != "client" || spec.Name != "c1" {
		t.Errorf("scalar fields wrong: %+v", spec)
	}
	if spec.LocalListenAddr != "0.0.0.0:5001" {
		t.Errorf("local_listen_addr: %q", spec.LocalListenAddr)
	}
	if spec.UploadTargetAddr != "198.51.100.10:55555" {
		t.Errorf("upload_target_addr: %q", spec.UploadTargetAddr)
	}
	if spec.DownloadReceivePort != 8443 {
		t.Errorf("download_receive_port: %d", spec.DownloadReceivePort)
	}
	// 0x1000 | (42 & 0xfff) = 0x102a = 4138.
	if spec.WireguardFwmark != 0x102a {
		t.Errorf("fwmark: 0x%x (want 0x102a)", spec.WireguardFwmark)
	}
}

func TestBuildSpec_Remote(t *testing.T) {
	tun := tunnels.Tunnel{
		ID:                      9,
		Name:                    "r1",
		Role:                    tunnels.RoleRemote,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		UploadListenAddr:        sql.NullString{Valid: true, String: "0.0.0.0:8001"},
		ForwardTarget:           sql.NullString{Valid: true, String: "127.0.0.1:5201"},
		DownloadSendPort:        sql.NullInt64{Valid: true, Int64: 5001},
		ClientRealIP:            sql.NullString{Valid: true, String: "198.51.100.20"},
	}
	spec, err := buildSpec(tun, nil)
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	if spec.Role != "remote" || spec.UploadListenAddr != "0.0.0.0:8001" {
		t.Errorf("wrong: %+v", spec)
	}
	if spec.ForwardTarget != "127.0.0.1:5201" {
		t.Errorf("forward_target: %q", spec.ForwardTarget)
	}
	if spec.DownloadSendPort != 5001 {
		t.Errorf("download_send_port: %d", spec.DownloadSendPort)
	}
	if spec.ClientRealIP != "198.51.100.20" {
		t.Errorf("client_real_ip: %q", spec.ClientRealIP)
	}
}

func TestBuildSpec_ClientSocks5UploadCarriesProxy(t *testing.T) {
	// Phase R9a: a Client tunnel with UploadMode='socks5' must carry a
	// Socks5Target on the wire and NOT a WireguardFwmark (mutually
	// exclusive). Validation in tunnels/validation.go already enforces
	// the SOCKS5 FK is set, but buildSpec needs the resolved proxy row.
	tun := tunnels.Tunnel{
		ID:                      7,
		Name:                    "via-starlink",
		Role:                    tunnels.RoleClient,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{Valid: true, String: "0.0.0.0:5001"},
		DownloadReceivePort:     sql.NullInt64{Valid: true, Int64: 8443},
		UploadTargetAddr:        sql.NullString{Valid: true, String: "198.51.100.10:55555"},
		UploadMode:              tunnels.UploadModeSocks5,
		Socks5ProxyID:           sql.NullInt64{Valid: true, Int64: 1},
	}
	proxy := &socks5.Proxy{
		ID:                  1,
		Name:                "starlink-lb",
		Host:                "127.0.0.1",
		Port:                1080,
		Username:            sql.NullString{Valid: true, String: "alice"},
		Password:            sql.NullString{Valid: true, String: "s3cret"},
		ParallelConnections: 4,
	}
	spec, err := buildSpec(tun, proxy)
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	if spec.WireguardFwmark != 0 {
		t.Errorf("socks5 spec must not carry an fwmark, got 0x%x", spec.WireguardFwmark)
	}
	if spec.Socks5Target == nil {
		t.Fatal("expected Socks5Target to be set for socks5 upload mode")
	}
	if spec.Socks5Target.Host != "127.0.0.1" || spec.Socks5Target.Port != 1080 {
		t.Errorf("socks5 host:port = %s:%d, want 127.0.0.1:1080",
			spec.Socks5Target.Host, spec.Socks5Target.Port)
	}
	if spec.Socks5Target.Username != "alice" || spec.Socks5Target.Password != "s3cret" {
		t.Errorf("socks5 credentials lost in spec: %+v", spec.Socks5Target)
	}
	if spec.Socks5Target.ParallelConnections != 4 {
		t.Errorf("parallel_connections = %d, want 4 (R9b honours this on the dataplane)",
			spec.Socks5Target.ParallelConnections)
	}
}

func TestBuildSpec_ClientSocks5RequiresProxy(t *testing.T) {
	// A SOCKS5-mode tunnel without a resolved proxy is a developer
	// error — the handler layer is supposed to resolve before calling.
	tun := tunnels.Tunnel{
		ID:                      8,
		Name:                    "no-proxy",
		Role:                    tunnels.RoleClient,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{Valid: true, String: "0.0.0.0:5001"},
		DownloadReceivePort:     sql.NullInt64{Valid: true, Int64: 8443},
		UploadTargetAddr:        sql.NullString{Valid: true, String: "198.51.100.10:55555"},
		UploadMode:              tunnels.UploadModeSocks5,
	}
	if _, err := buildSpec(tun, nil); err == nil {
		t.Fatal("expected error when socks5 mode lacks resolved proxy")
	}
}

func TestBuildSpec_RemoteSocks5TcpListenMode(t *testing.T) {
	tun := tunnels.Tunnel{
		ID:                      11,
		Name:                    "remote-tcp",
		Role:                    tunnels.RoleRemote,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		UploadListenAddr:        sql.NullString{Valid: true, String: "0.0.0.0:8001"},
		ForwardTarget:           sql.NullString{Valid: true, String: "127.0.0.1:5201"},
		DownloadSendPort:        sql.NullInt64{Valid: true, Int64: 5001},
		ClientRealIP:            sql.NullString{Valid: true, String: "198.51.100.20"},
		UploadListenMode:        tunnels.UploadListenModeSocks5TCP,
	}
	spec, err := buildSpec(tun, nil)
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	if spec.UploadListenMode != "socks5_tcp" {
		t.Errorf("UploadListenMode = %q, want socks5_tcp", spec.UploadListenMode)
	}
}

func TestBuildSpec_MultiPortCarriesPorts(t *testing.T) {
	// v2.5.0: a tunnel with >= 2 ports must carry the list on the wire as
	// []uint16; a 0- or 1-element list must leave spec.Ports empty so the
	// dataplane takes the byte-for-byte-identical single-port path.
	base := tunnels.Tunnel{
		ID:                      42,
		Name:                    "mp",
		Role:                    tunnels.RoleClient,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{Valid: true, String: "0.0.0.0:8000"},
		DownloadReceivePort:     sql.NullInt64{Valid: true, Int64: 8443},
		UploadTargetAddr:        sql.NullString{Valid: true, String: "198.51.100.10:55555"},
		WGConfigID:              sql.NullInt64{Valid: true, Int64: 1},
	}

	multi := base
	multi.Ports = []int{8000, 8001, 8002}
	spec, err := buildSpec(multi, nil)
	if err != nil {
		t.Fatalf("buildSpec multi: %v", err)
	}
	if len(spec.Ports) != 3 || spec.Ports[0] != 8000 || spec.Ports[2] != 8002 {
		t.Errorf("spec.Ports = %v, want [8000 8001 8002]", spec.Ports)
	}

	// Single-port: empty list => no Ports on the wire.
	single := base
	single.Ports = nil
	spec, err = buildSpec(single, nil)
	if err != nil {
		t.Fatalf("buildSpec single: %v", err)
	}
	if len(spec.Ports) != 0 {
		t.Errorf("single-port spec must not carry Ports, got %v", spec.Ports)
	}

	// Defensive: a 1-element list is also single-port.
	one := base
	one.Ports = []int{8000}
	spec, err = buildSpec(one, nil)
	if err != nil {
		t.Fatalf("buildSpec one: %v", err)
	}
	if len(spec.Ports) != 0 {
		t.Errorf("1-element list must be treated as single-port, got %v", spec.Ports)
	}
}

func TestBuildSpec_ClientMissingListen(t *testing.T) {
	tun := tunnels.Tunnel{
		ID:                42,
		Name:              "c1",
		Role:              tunnels.RoleClient,
		DownloadTransport: tunnels.TransportUDP,
	}
	_, err := buildSpec(tun, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestManager_TransportUnsupported(t *testing.T) {
	// Manager with no supervisor (nil) — we only want to test the
	// transport check, which runs before any IPC. Phase 8b accepts
	// UDP / TCP-SYN / ICMP / ICMPv6; only a stranger value should be
	// rejected as unsupported.
	mgr := NewManager(nil, nil)
	tun := tunnels.Tunnel{ID: 1, DownloadTransport: tunnels.Transport("ftp")}
	err := mgr.Start(context.TODO(), tun, nil)
	if _, ok := err.(*TransportUnsupportedError); !ok {
		t.Fatalf("expected TransportUnsupportedError, got %T: %v", err, err)
	}
}

func TestManager_AllPhase8bTransportsAccepted(t *testing.T) {
	// Sanity check: the transport guard in Start() lets every Phase 8b
	// transport through to the IPC layer. With a nil supervisor the
	// call short-circuits at the "not ready" check just AFTER the
	// transport switch, so a non-TransportUnsupportedError here means
	// the transport itself was accepted.
	mgr := NewManager(nil, nil)
	for _, transport := range []tunnels.Transport{
		tunnels.TransportUDP,
		tunnels.TransportTCPSYN,
		tunnels.TransportICMP,
		tunnels.TransportICMPv6,
	} {
		tun := tunnels.Tunnel{ID: 1, DownloadTransport: transport}
		err := mgr.Start(context.TODO(), tun, nil)
		if _, ok := err.(*TransportUnsupportedError); ok {
			t.Errorf("transport %q wrongly flagged as unsupported: %v", transport, err)
		}
	}
}

func TestManager_UpdateNilManagerErrors(t *testing.T) {
	// A nil manager (dev build without -tags=embed) should refuse
	// Update cleanly — the HTTP handler explicitly checks deps.Dataplane
	// before calling, but defend in depth.
	var mgr *Manager
	tun := tunnels.Tunnel{ID: 1, DownloadTransport: tunnels.TransportUDP}
	if _, err := mgr.Update(context.TODO(), tun, nil); err == nil {
		t.Fatal("expected error for nil manager")
	}
}

func TestManager_UpdateTransportUnsupported(t *testing.T) {
	mgr := NewManager(nil, nil)
	tun := tunnels.Tunnel{ID: 1, DownloadTransport: tunnels.Transport("ftp")}
	if _, err := mgr.Update(context.TODO(), tun, nil); err == nil {
		t.Fatal("expected error")
	} else if _, ok := err.(*TransportUnsupportedError); !ok {
		t.Fatalf("expected TransportUnsupportedError, got %T: %v", err, err)
	}
}

func TestManager_UpdateNoSupervisorClient(t *testing.T) {
	mgr := NewManager(nil, nil)
	tun := tunnels.Tunnel{
		ID:                      1,
		Name:                    "c1",
		Role:                    tunnels.RoleClient,
		PSK:                     "psk",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{Valid: true, String: "0.0.0.0:5001"},
		DownloadReceivePort:     sql.NullInt64{Valid: true, Int64: 8443},
		UploadTargetAddr:        sql.NullString{Valid: true, String: "198.51.100.10:55555"},
	}
	if _, err := mgr.Update(context.TODO(), tun, nil); err == nil {
		t.Fatal("expected 'not ready' error when supervisor client is nil")
	}
}

func TestManager_StateDefaults(t *testing.T) {
	mgr := NewManager(nil, nil)
	st := mgr.State(99)
	if st.State != "stopped" {
		t.Errorf("expected stopped, got %q", st.State)
	}
}

func TestManager_IPCErrorRoundtrip(t *testing.T) {
	// Verify the manager preserves typed IPC errors so the API layer
	// can branch on Code.
	mgr := NewManager(nil, nil)
	mgr.recordState(1, "error", "PORT_IN_USE: 5001 already bound")
	st := mgr.State(1)
	if st.State != "error" {
		t.Errorf("state: %q", st.State)
	}
	if st.Reason != "PORT_IN_USE: 5001 already bound" {
		t.Errorf("reason: %q", st.Reason)
	}
	// Untyped IPC error from the wire decodes via json:
	raw := []byte(`{"code":"PORT_IN_USE","message":"bad"}`)
	var e ipc.IPCError
	if err := jsonUnmarshalTest(raw, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Code != ipc.CodePortInUse {
		t.Errorf("code: %q", e.Code)
	}
}

// jsonUnmarshalTest is a tiny helper that keeps the test from
// depending on encoding/json directly.
func jsonUnmarshalTest(b []byte, v any) error {
	return jsonUnmarshalTestImpl(b, v)
}
