package api

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"net/url"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
	"github.com/Kup1ng/Sublyne/control-plane/internal/metrics"
	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// testWebPath is the obfuscated prefix every handler test mounts the
// router under. Using a stable value keeps the test URLs readable.
const testWebPath = "testpanel"

// newTestDB returns an in-memory SQLite database with migrations applied.
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
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := migrations.Apply(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db
}

// testFixture wires a DB and AuthDeps for handler tests. Tests can
// mutate clockNow to advance time deterministically (e.g. to check
// lockout expiry).
type testFixture struct {
	db          *sql.DB
	deps        AuthDeps
	tunnelDeps  TunnelDeps
	tunnelRepo  *tunnels.Repo
	tunnelCache *tunnels.Cache
	wgDeps      WGDeps
	wgRepo      *wg.Repo
	socks5Deps  SOCKS5Deps
	socks5Repo  *socks5.Repo
	metricsDeps MetricsDeps
	recorder    *metrics.Recorder
	statsBus    *Broadcast
	logsDeps    LogsDeps
	auditDeps   AuditDeps
	logBus      *logging.LogBus
	levelCtrl   *logging.LevelControl
	auditRec    *audit.Recorder
	mu          sync.Mutex
	now         time.Time
	password    string
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	db := newTestDB(t)

	hash, err := auth.HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.NewAdminStore(db).Upsert(context.Background(), "admin", hash); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	f := &testFixture{db: db, now: time.Now(), password: "correct horse"}
	clock := func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}

	signing := auth.NewSigningKeyStore(db)
	issuer := auth.NewIssuer(signing, clock)
	cfg := auth.DefaultLimiterConfig()
	cfg.PruneInterval = time.Hour
	lim := auth.NewLimiter(db, cfg, clock, slog.Default())

	auditRec := audit.NewRecorder(db)
	f.deps = AuthDeps{
		DB:       db,
		Admins:   auth.NewAdminStore(db),
		Issuer:   issuer,
		Limiter:  lim,
		Role:     "client",
		CookieFn: DefaultCookie,
		Audit:    auditRec,
	}
	f.tunnelRepo = tunnels.NewRepo(db)
	f.tunnelCache = tunnels.NewCache(f.tunnelRepo)
	f.wgRepo = wg.NewRepo(db)
	f.socks5Repo = socks5.NewRepo(db)
	f.tunnelDeps = TunnelDeps{
		Repo:        f.tunnelRepo,
		ServerRole:  tunnels.RoleClient,
		WGRepo:      f.wgRepo,
		SOCKS5Repo:  f.socks5Repo,
		Audit:       auditRec,
		TunnelCache: f.tunnelCache,
		// No Manager — Phase 7 handler tests verify the API contract
		// without trying to bring up real kernel interfaces. The VM
		// acceptance test covers the live path.
	}
	f.wgDeps = WGDeps{
		Repo:       f.wgRepo,
		TunnelRepo: f.tunnelRepo,
		Audit:      auditRec,
	}
	f.socks5Deps = SOCKS5Deps{
		Repo:  f.socks5Repo,
		Audit: auditRec,
	}
	f.recorder = metrics.NewRecorder(nil)
	f.statsBus = NewBroadcast()
	f.metricsDeps = MetricsDeps{
		Recorder:       f.recorder,
		TunnelRepo:     f.tunnelRepo,
		TunnelCache:    f.tunnelCache,
		WGRepo:         f.wgRepo,
		StatsBroadcast: f.statsBus,
	}
	// Wire the render-once renderer the same way main.go does so the
	// WS handler tests see the same fan-out shape (one render per
	// Publish, bytes fanned to every subscriber).
	f.statsBus.SetRenderer(func(report ipc.StatsReport) ([]byte, error) {
		return RenderSnapshotFrame(f.metricsDeps, report, time.Now())
	}, nil)
	f.logBus = logging.NewLogBus(0)
	f.levelCtrl = logging.NewLevelControl(slog.LevelInfo)
	f.auditRec = auditRec
	f.logsDeps = LogsDeps{
		Bus:   f.logBus,
		Level: f.levelCtrl,
		DB:    db,
		Audit: f.auditRec,
	}
	f.auditDeps = AuditDeps{Recorder: f.auditRec}
	return f
}

// routerDeps returns RouterDeps assembled around the fixture's
// AuthDeps with a stable WebPath and a small in-memory SPA dist so
// tests can exercise both the API and the asset-serving paths.
func (f *testFixture) routerDeps() RouterDeps {
	return RouterDeps{
		Auth:      f.deps,
		Tunnels:   f.tunnelDeps,
		WG:        f.wgDeps,
		SOCKS5:    f.socks5Deps,
		Metrics:   f.metricsDeps,
		Logs:      f.logsDeps,
		Audit:     f.auditDeps,
		WebPath:   testWebPath,
		AssetFS:   testAssetFS(),
		PanelPort: 18080,
		LogLevel:  "info",
		Version:   "test",
	}
}

// withRole rebuilds the fixture's TunnelDeps with the supplied role
// so tests can assert remote-side validation against a client-server
// fixture by flipping the role for the call site.
func (f *testFixture) withRole(role tunnels.Role) *testFixture {
	f.deps.Role = string(role)
	f.tunnelDeps.ServerRole = role
	return f
}

func testAssetFS() fs.FS {
	return fstest.MapFS{
		"index.html": {Data: []byte(
			"<!DOCTYPE html><html><head></head><body><div id=\"__nuxt\">spa</div></body></html>",
		)},
		"_nuxt/entry.js": {Data: []byte(
			"console.log('sublyne panel');",
		)},
	}
}

func (f *testFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
