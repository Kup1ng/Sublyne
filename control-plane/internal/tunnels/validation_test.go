package tunnels

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestValidate_RequiredClientFields(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()

	bare := Tunnel{Role: RoleClient}
	err := Validate(ctx, repo, RoleClient, &bare, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	for _, key := range []string{
		"name", "psk", "download_transport", "download_spoof_source_ip",
		"download_spoof_source_port", "mtu", "max_connections", "idle_timeout",
		"local_listen_addr", "download_receive_port", "upload_target_addr",
		"wg_config_id",
	} {
		if _, ok := ve.Fields[key]; !ok {
			t.Errorf("expected validation error on field %q, fields=%v", key, ve.Fields)
		}
	}
}

func TestValidate_RequiredRemoteFields(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	bare := Tunnel{Role: RoleRemote}
	err := Validate(ctx, repo, RoleRemote, &bare, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	for _, key := range []string{
		"name", "psk", "download_transport",
		"upload_listen_addr", "forward_target", "download_send_port", "client_real_ip",
	} {
		if _, ok := ve.Fields[key]; !ok {
			t.Errorf("expected validation error on field %q, fields=%v", key, ve.Fields)
		}
	}
	// And the client-only field set should NOT appear in a remote-role
	// validation pass — those fields are simply unused.
	for _, key := range []string{"local_listen_addr", "download_receive_port", "upload_target_addr", "wireguard_config", "wg_config_id"} {
		if _, ok := ve.Fields[key]; ok {
			t.Errorf("client-only field %q surfaced in remote validation", key)
		}
	}
}

func TestValidate_RoleMustMatchServer(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleRemote("mismatch")
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if msg, ok := ve.Fields["role"]; !ok || !strings.Contains(msg, "client") {
		t.Errorf("role mismatch error missing or wrong: %v", ve.Fields)
	}
}

func TestValidate_HappyClient(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("good")
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("validate happy: %v", err)
	}
}

func TestValidate_HappyRemote(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleRemote("good")
	if err := Validate(ctx, repo, RoleRemote, &t1, 0); err != nil {
		t.Fatalf("validate happy remote: %v", err)
	}
}

// Phase R4: icmp_echo_mode must validate to either "reply" or "request",
// and must default to "reply" when the field is empty.
func TestValidate_IcmpEchoMode_DefaultsToReply(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("default-mode")
	t1.IcmpEchoMode = "" // simulate caller that didn't populate the field
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if t1.IcmpEchoMode != IcmpEchoModeReply {
		t.Errorf("Validate did not default icmp_echo_mode to reply; got %q", t1.IcmpEchoMode)
	}
}

func TestValidate_IcmpEchoMode_AcceptsRequest(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("req-mode")
	t1.DownloadTransport = TransportICMP
	t1.IcmpEchoMode = IcmpEchoModeRequest
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidate_IcmpEchoMode_RejectsUnknown(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("bad-mode")
	t1.IcmpEchoMode = "garbage"
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["icmp_echo_mode"]; !ok {
		t.Errorf("missing icmp_echo_mode error: %v", ve.Fields)
	}
}

func TestValidate_PortConflict_LocalListenVsExistingLocalListen(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	a := sampleClient("a")
	if _, err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create a: %v", err)
	}

	b := sampleClient("b")
	b.LocalListenAddr = sql.NullString{String: "0.0.0.0:44443", Valid: true} // collides
	b.DownloadReceivePort = sql.NullInt64{Int64: 8444, Valid: true}          // different
	err := Validate(ctx, repo, RoleClient, &b, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	msg, ok := ve.Fields["local_listen_addr"]
	if !ok {
		t.Fatalf("missing local_listen_addr error: %v", ve.Fields)
	}
	if !strings.Contains(msg, "44443") || !strings.Contains(msg, "\"a\"") {
		t.Errorf("unexpected conflict message: %q", msg)
	}
}

func TestValidate_PortConflict_DownloadReceiveVsExistingDownloadReceive(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	a := sampleClient("a")
	if _, err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create a: %v", err)
	}
	b := sampleClient("b")
	b.LocalListenAddr = sql.NullString{String: "0.0.0.0:44444", Valid: true} // different
	// b.DownloadReceivePort defaults to 8443 — collides with a.DownloadReceivePort.
	err := Validate(ctx, repo, RoleClient, &b, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["download_receive_port"]; !ok {
		t.Fatalf("expected download_receive_port conflict, fields=%v", ve.Fields)
	}
}

func TestValidate_PortConflict_AllowsSelfWhenUpdating(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	a, err := repo.Create(ctx, sampleClient("a"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	a.MTU = 1380
	// Re-validating the SAME row must not flag itself.
	if err := Validate(ctx, repo, RoleClient, &a, a.ID); err != nil {
		t.Fatalf("update validation tripped on self: %v", err)
	}
}

func TestValidate_RejectsBadIP(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("badip")
	t1.DownloadSpoofSourceIP = "not-an-ip"
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["download_spoof_source_ip"]; !ok {
		t.Errorf("expected ip error: %v", ve.Fields)
	}
}

func TestValidate_RejectsBadHostPort(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("badhp")
	t1.LocalListenAddr = sql.NullString{String: "garbage", Valid: true}
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["local_listen_addr"]; !ok {
		t.Errorf("expected local_listen_addr error: %v", ve.Fields)
	}
}

func TestValidate_TransportEnumGuard(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("bt")
	t1.DownloadTransport = Transport("ftp")
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["download_transport"]; !ok {
		t.Errorf("expected transport error: %v", ve.Fields)
	}
}

func TestValidate_IPv6LocalListenIsAcceptedAndScannedForConflicts(t *testing.T) {
	// PRD §8.3: IPv4 and IPv6 are first-class. The validator must
	// accept `[::]:port` for local_listen_addr and still flag a
	// later tunnel that reuses the same port.
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	a := sampleClient("a")
	a.LocalListenAddr = sql.NullString{String: "[::]:44443", Valid: true}
	a.DownloadReceivePort = sql.NullInt64{Int64: 8443, Valid: true}
	if _, err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create v6 listener: %v", err)
	}

	b := sampleClient("b")
	b.LocalListenAddr = sql.NullString{String: "0.0.0.0:44443", Valid: true}
	b.DownloadReceivePort = sql.NullInt64{Int64: 8444, Valid: true}
	err := Validate(ctx, repo, RoleClient, &b, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if msg, ok := ve.Fields["local_listen_addr"]; !ok || !strings.Contains(msg, "44443") {
		t.Fatalf("v6 listener should conflict with v4 on the same port, fields=%v", ve.Fields)
	}

	// And reversed direction: existing v4, new v6 must also be rejected.
	c := sampleClient("c")
	c.LocalListenAddr = sql.NullString{String: "[::]:44443", Valid: true}
	c.DownloadReceivePort = sql.NullInt64{Int64: 8445, Valid: true}
	if err := Validate(ctx, repo, RoleClient, &c, 0); err == nil {
		t.Fatalf("c should fail the conflict scan, got nil error")
	}
}

// --- v2 upload × download matrix --------------------------------------

func TestUploadMatrix_Helpers(t *testing.T) {
	if got := DefaultUploadMode(TransportTCPSYN); got != UploadModeSocks5 {
		t.Errorf("DefaultUploadMode(tcp_syn) = %q, want socks5", got)
	}
	if got := DefaultUploadMode(TransportUDP); got != UploadModeWireguard {
		t.Errorf("DefaultUploadMode(udp) = %q, want wireguard", got)
	}
	if !UploadModeAllowed(TransportICMP, UploadModeSocks5) ||
		!UploadModeAllowed(TransportICMP, UploadModeWireguard) {
		t.Errorf("icmp should allow both upload modes")
	}
	if UploadModeAllowed(TransportUDP, UploadModeSocks5) {
		t.Errorf("udp must not allow socks5 upload")
	}
	if UploadModeAllowed(TransportTCPSYN, UploadModeWireguard) {
		t.Errorf("tcp_syn must not allow wireguard upload")
	}
	if got := DefaultListenMode(TransportTCPSYN); got != UploadListenModeSocks5TCP {
		t.Errorf("DefaultListenMode(tcp_syn) = %q, want socks5_tcp", got)
	}
	if !ListenModeAllowed(TransportICMPv6, UploadListenModeUDP) ||
		!ListenModeAllowed(TransportICMPv6, UploadListenModeSocks5TCP) {
		t.Errorf("icmpv6 should allow both listen modes")
	}
	if ListenModeAllowed(TransportUDP, UploadListenModeSocks5TCP) {
		t.Errorf("udp must not allow socks5_tcp listen")
	}
}

func TestValidate_Matrix_ClientTCPSYNRejectsWireguard(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("tcpsyn-wg")
	c.DownloadTransport = TransportTCPSYN
	c.UploadMode = UploadModeWireguard // off-matrix; tcp_syn needs socks5
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["upload_mode"]; !ok {
		t.Errorf("expected upload_mode matrix error, fields=%v", ve.Fields)
	}
}

func TestValidate_Matrix_ClientUDPRejectsSOCKS5(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("udp-socks5")
	c.DownloadTransport = TransportUDP
	c.UploadMode = UploadModeSocks5 // off-matrix; udp needs wireguard
	c.WireguardConfig = sql.NullString{}
	c.Socks5ProxyID = sql.NullInt64{Int64: 1, Valid: true}
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["upload_mode"]; !ok {
		t.Errorf("expected upload_mode matrix error, fields=%v", ve.Fields)
	}
}

func TestValidate_Matrix_ClientTCPSYNWithSOCKS5OK(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("tcpsyn-socks5")
	c.DownloadTransport = TransportTCPSYN
	c.UploadMode = UploadModeSocks5
	c.WireguardConfig = sql.NullString{} // clear legacy WG text
	c.Socks5ProxyID = sql.NullInt64{Int64: 1, Valid: true}
	if err := Validate(ctx, repo, RoleClient, &c, 0); err != nil {
		t.Fatalf("tcp_syn + socks5 must be matrix-valid: %v", err)
	}
}

func TestValidate_Matrix_ClientICMPAllowsEither(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()

	// icmp + wireguard (sampleClient ships a legacy WG text → satisfies
	// the wg requirement).
	wgc := sampleClient("icmp-wg")
	wgc.DownloadTransport = TransportICMP
	wgc.UploadMode = UploadModeWireguard
	if err := Validate(ctx, repo, RoleClient, &wgc, 0); err != nil {
		t.Fatalf("icmp + wireguard must be matrix-valid: %v", err)
	}

	// icmp + socks5.
	sc := sampleClient("icmp-socks5")
	sc.DownloadTransport = TransportICMP
	sc.UploadMode = UploadModeSocks5
	sc.WireguardConfig = sql.NullString{}
	sc.Socks5ProxyID = sql.NullInt64{Int64: 1, Valid: true}
	if err := Validate(ctx, repo, RoleClient, &sc, 0); err != nil {
		t.Fatalf("icmp + socks5 must be matrix-valid: %v", err)
	}
}

func TestValidate_Matrix_RemoteTCPSYNRequiresSocks5TCP(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	r := sampleRemote("r-tcpsyn-udp")
	r.DownloadTransport = TransportTCPSYN
	r.UploadListenMode = UploadListenModeUDP // off-matrix
	err := Validate(ctx, repo, RoleRemote, &r, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["upload_listen_mode"]; !ok {
		t.Errorf("expected upload_listen_mode matrix error, fields=%v", ve.Fields)
	}
}

func TestValidate_Matrix_RemoteUDPRejectsSocks5TCP(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	r := sampleRemote("r-udp-socks5tcp")
	r.DownloadTransport = TransportUDP
	r.UploadListenMode = UploadListenModeSocks5TCP // off-matrix
	err := Validate(ctx, repo, RoleRemote, &r, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["upload_listen_mode"]; !ok {
		t.Errorf("expected upload_listen_mode matrix error, fields=%v", ve.Fields)
	}
}

func TestValidate_Matrix_RemoteTCPSYNWithSocks5TCPOK(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	r := sampleRemote("r-tcpsyn-ok")
	r.DownloadTransport = TransportTCPSYN
	r.UploadListenMode = UploadListenModeSocks5TCP
	if err := Validate(ctx, repo, RoleRemote, &r, 0); err != nil {
		t.Fatalf("tcp_syn + socks5_tcp must be matrix-valid: %v", err)
	}
}

// --- v2.5.0 multi-port -----------------------------------------------

func TestValidate_MultiPort_HappyClient(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-ok")
	// Canonical Client port is local_listen_addr's 44443; the list MUST
	// include it (full authoritative set).
	c.Ports = []int{44443, 8001, 8002}
	if err := Validate(ctx, repo, RoleClient, &c, 0); err != nil {
		t.Fatalf("valid multi-port list should pass: %v", err)
	}
}

func TestValidate_MultiPort_SinglePortEmptyListStillValid(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-empty")
	c.Ports = nil // legacy single-port marker
	if err := Validate(ctx, repo, RoleClient, &c, 0); err != nil {
		t.Fatalf("empty Ports must validate exactly like single-port: %v", err)
	}
}

func TestValidate_MultiPort_RejectsDuplicate(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-dup")
	c.Ports = []int{44443, 8001, 8001}
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["ports"]; !ok {
		t.Errorf("expected ports error for duplicate, fields=%v", ve.Fields)
	}
}

func TestValidate_MultiPort_RejectsOutOfRange(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-range")
	c.Ports = []int{44443, 70000}
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["ports"]; !ok {
		t.Errorf("expected ports error for out-of-range, fields=%v", ve.Fields)
	}
}

func TestValidate_MultiPort_RejectsTooMany(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-toomany")
	ports := make([]int, 0, MaxPortsPerTunnel+1)
	ports = append(ports, 44443) // canonical
	for p := 9000; len(ports) <= MaxPortsPerTunnel; p++ {
		ports = append(ports, p)
	}
	c.Ports = ports
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["ports"]; !ok {
		t.Errorf("expected ports error for >%d ports, fields=%v", MaxPortsPerTunnel, ve.Fields)
	}
}

func TestValidate_MultiPort_RejectsCanonicalNotInList(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	c := sampleClient("mp-canon")
	// Canonical port 44443 deliberately omitted.
	c.Ports = []int{8001, 8002}
	err := Validate(ctx, repo, RoleClient, &c, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["ports"]; !ok {
		t.Errorf("expected ports error when canonical port missing, fields=%v", ve.Fields)
	}
}

func TestValidate_MultiPort_HappyRemote(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	r := sampleRemote("mp-remote-ok")
	// Canonical Remote port is forward_target's 5201.
	r.Ports = []int{5201, 5202, 5203}
	if err := Validate(ctx, repo, RoleRemote, &r, 0); err != nil {
		t.Fatalf("valid remote multi-port list should pass: %v", err)
	}
}

func TestValidate_MultiPort_CrossTunnelOverlapOnListMember(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()

	// First tunnel claims app ports {44443, 8001, 8002}.
	a := sampleClient("mp-a")
	a.Ports = []int{44443, 8001, 8002}
	if _, err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create a: %v", err)
	}

	// Second tunnel uses a different local_listen / receive port so the
	// ONLY collision is on the shared app-port list member 8002.
	b := sampleClient("mp-b")
	b.LocalListenAddr = sql.NullString{String: "0.0.0.0:44455", Valid: true}
	b.DownloadReceivePort = sql.NullInt64{Int64: 8455, Valid: true}
	b.Ports = []int{44455, 8002, 8003}
	err := Validate(ctx, repo, RoleClient, &b, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	msg, ok := ve.Fields["ports"]
	if !ok {
		t.Fatalf("expected ports overlap error, fields=%v", ve.Fields)
	}
	if !strings.Contains(msg, "8002") || !strings.Contains(msg, "mp-a") {
		t.Errorf("overlap message should name the port and owner; got %q", msg)
	}
}

func TestValidate_LocalListenSameAsDownloadReceiveIsRejected(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("samesame")
	// Both pointing at the same UDP port — meaningless on a real
	// kernel and we should refuse before the data plane gets confused.
	t1.LocalListenAddr = sql.NullString{String: "0.0.0.0:9000", Valid: true}
	t1.DownloadReceivePort = sql.NullInt64{Int64: 9000, Valid: true}
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["download_receive_port"]; !ok {
		t.Errorf("expected self-conflict error, fields=%v", ve.Fields)
	}
}
