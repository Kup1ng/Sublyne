package tunnels

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
)

// newTestDB returns an in-memory SQLite database with every Phase 6
// migration applied. The package's tests target the repo layer
// directly (no HTTP), so we don't depend on the api package fixtures.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(on)")
	q.Add("_pragma", "journal_mode(MEMORY)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared&" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db
}

// sampleClient builds a minimal valid client-role tunnel. Tests modify
// the returned struct in place before handing it to the repo.
func sampleClient(name string) Tunnel {
	return Tunnel{
		Name:                    name,
		Role:                    RoleClient,
		Enabled:                 false,
		PSK:                     "shared-psk-32-chars-long-aaaaaaaa",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{String: "0.0.0.0:44443", Valid: true},
		DownloadReceivePort:     sql.NullInt64{Int64: 8443, Valid: true},
		UploadTargetAddr:        sql.NullString{String: "198.51.100.10:55555", Valid: true},
		WireguardConfig:         sql.NullString{String: "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0", Valid: true},
		PingSmoothingTargetMS:   60,
		PacingTargetMS:          100,
		IcmpEchoMode:            IcmpEchoModeReply,
	}
}

func sampleRemote(name string) Tunnel {
	return Tunnel{
		Name:                    name,
		Role:                    RoleRemote,
		Enabled:                 false,
		PSK:                     "shared-psk-32-chars-long-bbbbbbbb",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		UploadListenAddr:        sql.NullString{String: "0.0.0.0:55555", Valid: true},
		ForwardTarget:           sql.NullString{String: "127.0.0.1:5201", Valid: true},
		DownloadSendPort:        sql.NullInt64{Int64: 8443, Valid: true},
		ClientRealIP:            sql.NullString{String: "198.51.100.20", Valid: true},
		IcmpEchoMode:            IcmpEchoModeReply,
	}
}

func TestRepoCreateRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()

	got, err := repo.Create(ctx, sampleClient("alpha"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == 0 {
		t.Fatal("create did not set id")
	}
	if got.Name != "alpha" {
		t.Errorf("name = %q, want alpha", got.Name)
	}
	if got.Role != RoleClient {
		t.Errorf("role = %q, want client", got.Role)
	}
	if !got.LocalListenAddr.Valid || got.LocalListenAddr.String != "0.0.0.0:44443" {
		t.Errorf("local_listen_addr round-trip = %+v", got.LocalListenAddr)
	}
	if got.MTU != 1400 || got.IdleTimeout != 300 || got.MaxConnections != 50000 {
		t.Errorf("shared defaults dropped: %+v", got)
	}
	if got.Enabled {
		t.Error("create should land disabled")
	}
}

func TestRepoUniqueName(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if _, err := repo.Create(ctx, sampleClient("dup")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := repo.Create(ctx, sampleClient("dup"))
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("second create error = %v, want ErrNameTaken", err)
	}
}

func TestRepoSetEnabled(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1, err := repo.Create(ctx, sampleClient("toggle"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := repo.SetEnabled(ctx, t1.ID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !updated.Enabled {
		t.Error("after enable, enabled should be true")
	}
	updated, err = repo.SetEnabled(ctx, t1.ID, false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if updated.Enabled {
		t.Error("after disable, enabled should be false")
	}
}

func TestRepoDeleteRefusesWhileEnabled(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1, err := repo.Create(ctx, sampleClient("running"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := repo.SetEnabled(ctx, t1.ID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := repo.Delete(ctx, t1.ID); !errors.Is(err, ErrEnabled) {
		t.Fatalf("delete-while-enabled err = %v, want ErrEnabled", err)
	}
	if _, err := repo.Get(ctx, t1.ID); err != nil {
		t.Fatalf("tunnel should still exist: %v", err)
	}
	if _, err := repo.SetEnabled(ctx, t1.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := repo.Delete(ctx, t1.ID); err != nil {
		t.Fatalf("delete after stop: %v", err)
	}
	if _, err := repo.Get(ctx, t1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete get = %v, want ErrNotFound", err)
	}
}

func TestRepoUpdateKeepsPSK(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleClient("psk-keep"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	changed := original
	changed.PSK = "this-should-be-ignored"
	changed.MTU = 1380
	updated, err := repo.Update(ctx, changed, true)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.PSK != original.PSK {
		t.Errorf("PSK changed despite keepPSK=true: got %q, want %q", updated.PSK, original.PSK)
	}
	if updated.MTU != 1380 {
		t.Errorf("MTU update lost: got %d", updated.MTU)
	}
}

func TestRepoUpdateReplacesPSK(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleClient("psk-replace"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	changed := original
	changed.PSK = "new-psk-with-enough-bytes-bbbbbbbb"
	updated, err := repo.Update(ctx, changed, false)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.PSK != "new-psk-with-enough-bytes-bbbbbbbb" {
		t.Errorf("PSK did not update: got %q", updated.PSK)
	}
}

func TestRepoListOrdersByID(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	for _, n := range []string{"alpha", "beta", "gamma"} {
		if _, err := repo.Create(ctx, sampleClient(n)); err != nil {
			t.Fatalf("create %s: %v", n, err)
		}
	}
	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len(list) = %d, want 3", len(rows))
	}
	if rows[0].Name != "alpha" || rows[1].Name != "beta" || rows[2].Name != "gamma" {
		t.Errorf("list order: %+v", names(rows))
	}
}

func TestPortsCSVRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		csv  string
	}{
		{"empty", nil, ""},
		{"single", []int{8000}, "8000"},
		{"multi", []int{8000, 8001, 8002}, "8000,8001,8002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PortsToCSV(tc.in); got != tc.csv {
				t.Fatalf("PortsToCSV(%v) = %q, want %q", tc.in, got, tc.csv)
			}
			got, err := ParsePortsCSV(tc.csv)
			if err != nil {
				t.Fatalf("ParsePortsCSV(%q): %v", tc.csv, err)
			}
			if PortsToCSV(got) != tc.csv {
				t.Fatalf("round-trip drifted: %q -> %v -> %q", tc.csv, got, PortsToCSV(got))
			}
		})
	}
}

func TestParsePortsCSV_TolerantOfSpacesAndEmpties(t *testing.T) {
	got, err := ParsePortsCSV(" 8000 , ,8001, ")
	if err != nil {
		t.Fatalf("ParsePortsCSV: %v", err)
	}
	if len(got) != 2 || got[0] != 8000 || got[1] != 8001 {
		t.Fatalf("got %v, want [8000 8001]", got)
	}
}

func TestParsePortsCSV_RejectsNonNumeric(t *testing.T) {
	if _, err := ParsePortsCSV("8000,notaport"); err == nil {
		t.Fatal("expected error for non-numeric entry")
	}
}

func TestRepoMultiPortRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()

	c := sampleClient("mp")
	c.Ports = []int{44443, 8001, 8002}
	created, err := repo.Create(ctx, c)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if PortsToCSV(created.Ports) != "44443,8001,8002" {
		t.Fatalf("create round-trip lost ports: %v", created.Ports)
	}

	// Clearing the list (back to single-port) must persist as empty.
	created.Ports = nil
	updated, err := repo.Update(ctx, created, true)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.Ports) != 0 {
		t.Fatalf("update should have cleared ports, got %v", updated.Ports)
	}
}

func names(rows []Tunnel) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}
