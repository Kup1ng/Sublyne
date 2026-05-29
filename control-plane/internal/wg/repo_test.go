package wg

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
)

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

// sampleConfig returns a freshly-parsed ParsedConfig + Config pair
// that the repo tests can hand to Create. It uses the parser so we
// don't have to keep the wire-format details in sync with the test
// fixtures by hand.
func sampleConfig(t *testing.T, name string) Config {
	t.Helper()
	text := prdExampleConfig(t)
	parsed, err := ParseConfig(text)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	c := Config{
		Name:             name,
		RawText:          text,
		InterfaceAddress: parsed.AddressesAsString(),
		Endpoint:         parsed.FirstEndpoint(),
		PublicKeySelf:    parsed.PublicKeySelf(),
		PeerCount:        len(parsed.Peers),
	}
	if parsed.Interface.MTU > 0 {
		c.MTU = sql.NullInt64{Int64: int64(parsed.Interface.MTU), Valid: true}
	}
	if parsed.Interface.ListenPort > 0 {
		c.ListenPort = sql.NullInt64{Int64: int64(parsed.Interface.ListenPort), Valid: true}
	}
	return c
}

func TestRepoCreateRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	got, err := repo.Create(ctx, sampleConfig(t, "starlink-1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == 0 || got.Name != "starlink-1" {
		t.Errorf("create returned wrong row: %+v", got)
	}
	if !got.MTU.Valid || got.MTU.Int64 != 1280 {
		t.Errorf("MTU not round-tripped: %+v", got.MTU)
	}
	if got.PeerCount != 1 {
		t.Errorf("PeerCount = %d, want 1", got.PeerCount)
	}
}

func TestRepoCreate_UniqueName(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if _, err := repo.Create(ctx, sampleConfig(t, "dup")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := repo.Create(ctx, sampleConfig(t, "dup"))
	if !errors.Is(err, ErrConfigNameTaken) {
		t.Errorf("second create err = %v, want ErrConfigNameTaken", err)
	}
}

func TestRepoDelete_RefusesWhileReferenced(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	// Seed a config and a tunnel that references it.
	c, err := repo.Create(ctx, sampleConfig(t, "linked"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tunnels (
  name, role, enabled, psk, download_spoof_source_ip, download_spoof_source_port,
  download_transport, mtu, max_connections, idle_timeout,
  local_listen_addr, download_receive_port, upload_target_addr, wg_config_id
) VALUES (?, 'client', 0, 'shared-psk-xx-xx', '203.0.113.5', 443, 'udp',
  1400, 50000, 300, '0.0.0.0:44443', 8443, '198.51.100.10:55555', ?)`,
		"linked-tun", c.ID); err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}
	if err := repo.Delete(ctx, c.ID); !errors.Is(err, ErrConfigReferenced) {
		t.Fatalf("Delete err = %v, want ErrConfigReferenced", err)
	}
	// Confirm the names list reports the dependent tunnel.
	names, err := repo.ReferencingTunnels(ctx, c.ID)
	if err != nil {
		t.Fatalf("ReferencingTunnels: %v", err)
	}
	if len(names) != 1 || names[0] != "linked-tun" {
		t.Errorf("ReferencingTunnels = %v, want [linked-tun]", names)
	}
	// Detach the link and the delete should succeed.
	if _, err := db.ExecContext(ctx, `UPDATE tunnels SET wg_config_id = NULL WHERE name = ?`, "linked-tun"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := repo.Delete(ctx, c.ID); err != nil {
		t.Fatalf("delete after detach: %v", err)
	}
	if _, err := repo.Get(ctx, c.ID); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("after delete Get err = %v, want ErrConfigNotFound", err)
	}
}

func TestRepoUpdate_KeepRawPreservesSecret(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleConfig(t, "rename-only"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Caller submits a "rename only" update: same id, new name, no
	// raw_text. The repo should preserve every byte of the original
	// row except `name` and the updated_at timestamp.
	renamed := Config{ID: original.ID, Name: "renamed"}
	got, err := repo.Update(ctx, renamed, true)
	if err != nil {
		t.Fatalf("update keep raw: %v", err)
	}
	if got.RawText != original.RawText {
		t.Error("RawText was clobbered despite keepRaw=true")
	}
	if got.Name != "renamed" {
		t.Errorf("Name = %q, want renamed", got.Name)
	}
}

func TestRepoUpdate_ReplaceRawWritesNewSummary(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleConfig(t, "replace"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Build a fresh config with a different endpoint and re-use the
	// existing row id.
	fresh := sampleConfig(t, "replace")
	fresh.ID = original.ID
	fresh.Endpoint = "1.2.3.4:51820"
	fresh.RawText = original.RawText + "\n# tweaked\n"
	got, err := repo.Update(ctx, fresh, false)
	if err != nil {
		t.Fatalf("update replace: %v", err)
	}
	if got.Endpoint != "1.2.3.4:51820" {
		t.Errorf("Endpoint = %q, want 1.2.3.4:51820", got.Endpoint)
	}
	if got.RawText == original.RawText {
		t.Error("RawText should have been replaced")
	}
}

func TestRepoList_OrdersByID(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := repo.Create(ctx, sampleConfig(t, n)); err != nil {
			t.Fatalf("create %s: %v", n, err)
		}
	}
	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 || rows[0].Name != "a" || rows[2].Name != "c" {
		t.Errorf("list order: %+v", rows)
	}
}
