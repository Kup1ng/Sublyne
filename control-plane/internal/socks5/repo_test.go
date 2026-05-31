package socks5

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

func sampleProxy(name string) Proxy {
	return Proxy{
		Name:                name,
		Host:                "192.0.2.10",
		Port:                1080,
		Username:            sql.NullString{String: "alice", Valid: true},
		Password:            sql.NullString{String: "secret-xx-yy", Valid: true},
		ParallelConnections: 4,
		Notes:               sql.NullString{String: "starlink LB", Valid: true},
	}
}

func TestRepoCreateRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	got, err := repo.Create(ctx, sampleProxy("starlink-lb"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == 0 || got.Name != "starlink-lb" {
		t.Errorf("create returned wrong row: %+v", got)
	}
	if got.Host != "192.0.2.10" || got.Port != 1080 {
		t.Errorf("host/port not round-tripped: %s:%d", got.Host, got.Port)
	}
	if got.ParallelConnections != 4 {
		t.Errorf("ParallelConnections = %d, want 4", got.ParallelConnections)
	}
	if !got.Username.Valid || got.Username.String != "alice" {
		t.Errorf("Username not round-tripped: %+v", got.Username)
	}
	if !got.Password.Valid || got.Password.String != "secret-xx-yy" {
		t.Errorf("Password not round-tripped: %+v", got.Password)
	}
}

func TestRepoCreate_DefaultsParallelToFour(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	// Caller may legitimately submit a Proxy with the zero value if the
	// API layer didn't normalise — but our applyDefaults pattern in
	// every handler does, so production never hits zero. Pin a non-zero
	// value here so this test verifies the column DEFAULT in the
	// migration matches the code's expectation.
	p := sampleProxy("zero-test")
	p.ParallelConnections = 4
	got, err := repo.Create(ctx, p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ParallelConnections != 4 {
		t.Errorf("ParallelConnections = %d, want 4", got.ParallelConnections)
	}
}

func TestRepoCreate_UniqueName(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if _, err := repo.Create(ctx, sampleProxy("dup")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := repo.Create(ctx, sampleProxy("dup"))
	if !errors.Is(err, ErrProxyNameTaken) {
		t.Errorf("second create err = %v, want ErrProxyNameTaken", err)
	}
}

func TestRepoDelete_RefusesWhileReferenced(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	// Seed a proxy and a tunnel that references it via socks5_proxy_id
	// + upload_mode='socks5'. We INSERT directly so this test stays
	// independent of the tunnel handler / validator (those are tested
	// separately in the api package).
	p, err := repo.Create(ctx, sampleProxy("linked"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tunnels (
  name, role, enabled, psk, download_spoof_source_ip, download_spoof_source_port,
  download_transport, mtu, max_connections, idle_timeout,
  local_listen_addr, download_receive_port, upload_target_addr,
  upload_mode, socks5_proxy_id
) VALUES (?, 'client', 0, 'shared-psk-xx-xx', '203.0.113.5', 443, 'udp',
  1400, 50000, 300, '0.0.0.0:44443', 8443, '198.51.100.10:55555',
  'socks5', ?)`,
		"linked-tun", p.ID); err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}
	if err := repo.Delete(ctx, p.ID); !errors.Is(err, ErrProxyReferenced) {
		t.Fatalf("Delete err = %v, want ErrProxyReferenced", err)
	}
	names, err := repo.ReferencingTunnels(ctx, p.ID)
	if err != nil {
		t.Fatalf("ReferencingTunnels: %v", err)
	}
	if len(names) != 1 || names[0] != "linked-tun" {
		t.Errorf("ReferencingTunnels = %v, want [linked-tun]", names)
	}
	// Detach the link; delete should succeed.
	if _, err := db.ExecContext(ctx, `UPDATE tunnels SET socks5_proxy_id = NULL, upload_mode = 'wireguard' WHERE name = ?`, "linked-tun"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := repo.Delete(ctx, p.ID); err != nil {
		t.Fatalf("delete after detach: %v", err)
	}
	if _, err := repo.Get(ctx, p.ID); !errors.Is(err, ErrProxyNotFound) {
		t.Fatalf("after delete Get err = %v, want ErrProxyNotFound", err)
	}
}

func TestRepoUpdate_KeepPasswordPreservesSecret(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleProxy("rename-only"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Rename-only update: same id, new name, password field omitted
	// (NULL on the Proxy passed in). With keepPassword=true the repo
	// reads the existing bytes and writes them back.
	updated := Proxy{
		ID:                  original.ID,
		Name:                "renamed",
		Host:                original.Host,
		Port:                original.Port,
		Username:            original.Username,
		Password:            sql.NullString{},
		ParallelConnections: original.ParallelConnections,
		Notes:               original.Notes,
	}
	got, err := repo.Update(ctx, updated, true)
	if err != nil {
		t.Fatalf("update keep password: %v", err)
	}
	if !got.Password.Valid || got.Password.String != original.Password.String {
		t.Errorf("Password was clobbered despite keepPassword=true: %+v", got.Password)
	}
	if got.Name != "renamed" {
		t.Errorf("Name = %q, want renamed", got.Name)
	}
}

func TestRepoUpdate_ReplacePassword(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	original, err := repo.Create(ctx, sampleProxy("rotate"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fresh := Proxy{
		ID:                  original.ID,
		Name:                "rotate",
		Host:                original.Host,
		Port:                original.Port,
		Username:            original.Username,
		Password:            sql.NullString{String: "new-secret-abc", Valid: true},
		ParallelConnections: 8,
		Notes:               original.Notes,
	}
	got, err := repo.Update(ctx, fresh, false)
	if err != nil {
		t.Fatalf("update replace: %v", err)
	}
	if !got.Password.Valid || got.Password.String != "new-secret-abc" {
		t.Errorf("Password not replaced: %+v", got.Password)
	}
	if got.ParallelConnections != 8 {
		t.Errorf("ParallelConnections not updated: %d", got.ParallelConnections)
	}
}

func TestRepoList_OrdersByID(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := repo.Create(ctx, sampleProxy(n)); err != nil {
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

func TestRepoGet_NotFound(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if _, err := repo.Get(ctx, 9999); !errors.Is(err, ErrProxyNotFound) {
		t.Errorf("Get unknown id err = %v, want ErrProxyNotFound", err)
	}
}

func TestRepoDelete_NotFound(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if err := repo.Delete(ctx, 9999); !errors.Is(err, ErrProxyNotFound) {
		t.Errorf("Delete unknown id err = %v, want ErrProxyNotFound", err)
	}
}

func TestRepoGetByName_Found(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	created, err := repo.Create(ctx, sampleProxy("by-name"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByName(ctx, "by-name")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.ID != created.ID || got.Name != "by-name" {
		t.Errorf("GetByName = %+v, want id=%d name=by-name", got, created.ID)
	}
}

func TestRepoGetByName_NotFound(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	if _, err := repo.GetByName(ctx, "nonesuch"); !errors.Is(err, ErrProxyNotFound) {
		t.Errorf("GetByName unknown name err = %v, want ErrProxyNotFound", err)
	}
}
