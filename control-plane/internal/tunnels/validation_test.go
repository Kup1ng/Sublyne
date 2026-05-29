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
