package api

import (
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Kup1ng/Sublyne/control-plane/internal/webassets"
)

// RouterDeps holds the pieces NewRouter needs to assemble the HTTP
// tree. Tests construct a RouterDeps with fakes; main wires real
// implementations from config + the auth package + the webassets
// package.
type RouterDeps struct {
	// Auth bundles the credential, JWT, and rate-limit stores used by
	// the login / session / password endpoints.
	Auth AuthDeps

	// Tunnels bundles the persistence + server role used by every
	// /api/tunnels handler. Phase 6 introduces this; Phase 8+ will
	// extend it with the IPC client so start/stop call into the real
	// data plane instead of merely flipping the enabled flag.
	Tunnels TunnelDeps

	// WG bundles the WireGuard config repo + kernel manager. Phase 7
	// mounts /api/wg-configs only when WG.Repo is non-nil so unit
	// tests that don't care about WG can leave the field zero.
	WG WGDeps

	// SOCKS5 bundles the SOCKS5 proxy repo (Phase R8). Mount is only
	// enabled when SOCKS5.Repo is non-nil; tests that don't care about
	// the SOCKS5 upload path can leave the field zero. R10 hid the
	// routes on Remote-role panels (mirroring R6's WG hide): SOCKS5
	// upload is a Client-only concept, so a Remote operator has no use
	// for the proxy list and direct REST hits return 404.
	SOCKS5 SOCKS5Deps

	// Metrics bundles the Phase 11 live-monitoring pieces. Mount is
	// only enabled when Metrics.Recorder is non-nil.
	Metrics MetricsDeps

	// Logs bundles the Phase 12 in-memory log bus, the runtime log-
	// level control, the crash-report directory, and the optional
	// rotating-file sink. Mount is enabled when Logs.Bus is non-nil.
	Logs LogsDeps

	// Audit bundles the Phase 12 audit_log recorder. Mount is enabled
	// when Audit.Recorder is non-nil.
	Audit AuditDeps

	// BackupRestore bundles the Phase 13 backup + restore endpoints.
	// Mount is enabled when BackupRestore.DB is non-nil.
	BackupRestore BackupRestoreDeps

	// WebPath is the obfuscated prefix under which every panel and
	// API route is mounted (e.g. "x7Kp9aR2", no slashes). setup.sh
	// generates a 16-char URL-safe string at install time.
	WebPath string

	// AssetFS is the SPA dist served under the prefix. In production
	// it is the embedded `frontend_dist`; in dev it is an os.DirFS
	// of the `pnpm build` output. May be nil — the SPA handler then
	// responds 503 with a clear message.
	AssetFS fs.FS

	// PanelPort is reported via /api/settings so the operator can
	// confirm what setup.sh chose without SSHing in. Required.
	PanelPort int

	// LogLevel mirrors the config field; surfaced via /api/settings.
	LogLevel string

	// Version is the build version baked in at compile time. Returned
	// by /api/settings and (later) used by the Update menu in setup.sh.
	Version string
}

// NewRouter assembles the chi router that the HTTP server mounts.
//
// Routing layout for Phase 6:
//
//	/                                  → 404 (no body — panel is hidden)
//	/<webpath>/                        → SPA index.html
//	/<webpath>/_nuxt/...               → SPA assets (placeholder substituted)
//	/<webpath>/<anything-else>         → SPA fallback to index.html (Vue Router)
//	/<webpath>/healthz                 → 200 "ok"
//	/<webpath>/api/healthz             → 200 "ok"
//	/<webpath>/api/login               → POST, public
//	/<webpath>/api/logout              → POST, public
//	/<webpath>/api/session             → GET, RequireAuth
//	/<webpath>/api/password            → POST, RequireAuth
//	/<webpath>/api/settings            → GET, RequireAuth
//	/<webpath>/api/tunnels             → GET/POST, RequireAuth
//	/<webpath>/api/tunnels/{id}        → GET/PUT/DELETE, RequireAuth
//	/<webpath>/api/tunnels/{id}/start  → POST, RequireAuth
//	/<webpath>/api/tunnels/{id}/stop   → POST, RequireAuth
//	/<webpath>/api/tunnels/{id}/export → GET, RequireAuth
//	/<webpath>/api/tunnels/import      → POST, RequireAuth
//
// The whole panel sits behind chi.Mount, so URL.Path inside handlers
// is the *stripped* sub-path (e.g. `/api/login`, `/dashboard`).
func NewRouter(deps RouterDeps) http.Handler {
	if deps.WebPath == "" {
		panic("api: NewRouter requires a non-empty WebPath")
	}

	root := chi.NewRouter()
	root.Use(middleware.RealIP)
	// CrashRecoverer is our own recover middleware — it writes a
	// crash-<unix>.log file to /var/lib/sublyne/logs/ before falling
	// through to chi.Recoverer's existing 500 response. Order: ours
	// first so the file write happens before chi's response commit.
	root.Use(CrashRecoverer)
	root.Use(middleware.Recoverer)

	// Anything outside the obfuscated prefix is a 404 with no body.
	// PRD §4.1: the panel must never advertise itself.
	root.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	panel := chi.NewRouter()
	panel.Use(middleware.NoCache)

	// /healthz is reachable both at the panel root (kept for systemd
	// readiness probes that don't care about the API tree) and under
	// /api/ (per the Phase 5 acceptance test).
	panel.Get("/healthz", handleHealthz)

	settingsView := SettingsView{
		ServerRole: deps.Auth.Role,
		PanelPort:  deps.PanelPort,
		WebPath:    deps.WebPath,
		LogLevel:   deps.LogLevel,
		Version:    deps.Version,
	}

	panel.Route("/api", func(api chi.Router) {
		api.Get("/healthz", handleHealthz)
		api.Post("/login", LoginHandler(deps.Auth))
		api.Post("/logout", LogoutHandler(deps.Auth))

		api.Group(func(protected chi.Router) {
			protected.Use(RequireAuth(deps.Auth.Issuer, deps.Auth.Admins))
			protected.Get("/session", SessionHandler(deps.Auth.Role))
			protected.Post("/password", PasswordChangeHandler(deps.Auth))
			protected.Get("/settings", SettingsHandler(settingsView))
			if deps.Tunnels.Repo != nil {
				protected.Route("/tunnels", func(sub chi.Router) {
					MountTunnelRoutes(sub, deps.Tunnels)
				})
			}
			// R6: WireGuard upload is a Client-role concept. On a
			// Remote-role server the panel hides every WG entry; we also
			// refuse the routes here so an operator with the raw URL
			// gets an honest 404 instead of an empty list or a 500.
			switch {
			case deps.Auth.Role == "remote":
				protected.HandleFunc("/wg-configs", http.NotFound)
				protected.HandleFunc("/wg-configs/*", http.NotFound)
			case deps.WG.Repo != nil:
				protected.Route("/wg-configs", func(sub chi.Router) {
					MountWGRoutes(sub, deps.WG)
				})
			}
			// R10: SOCKS5 upload is a Client-only concept — the Client
			// is what dials the proxy when it sends upload, while the
			// Remote just receives plain UDP on `upload_listen_addr`.
			// R8 originally exposed the page on both roles "for parity";
			// the user-visible reality is that a Remote operator has no
			// use for the proxy list, so we mirror R6's WG-hide here:
			// the panel filters the sidebar entry and bounces direct
			// URLs, and the backend honestly 404s the REST routes for
			// the curious operator with the URL memorised.
			switch {
			case deps.Auth.Role == "remote":
				protected.HandleFunc("/socks5-proxies", http.NotFound)
				protected.HandleFunc("/socks5-proxies/*", http.NotFound)
			case deps.SOCKS5.Repo != nil:
				protected.Route("/socks5-proxies", func(sub chi.Router) {
					MountSOCKS5Routes(sub, deps.SOCKS5)
				})
			}
			if deps.Metrics.Recorder != nil {
				MountMetricsRoutes(protected, deps.Metrics)
				protected.Get("/ws", MetricsWebSocketHandler(deps.Metrics, deps.Logs))
			}
			if deps.Logs.Bus != nil || deps.Audit.Recorder != nil {
				MountLogsRoutes(protected, deps.Logs, deps.Audit)
			}
			if deps.BackupRestore.DB != nil {
				MountBackupRoutes(protected, deps.BackupRestore)
			}
		})
	})

	// SPA catch-all: any GET that didn't match an API or healthz route
	// is served from the embedded dist (falling back to index.html for
	// unknown paths so Vue Router can resolve them client-side).
	panel.Method(http.MethodGet, "/*", webassets.SPAHandler(deps.AssetFS, deps.WebPath))

	prefix := "/" + deps.WebPath
	root.Mount(prefix, http.StripPrefix(prefix, panel))

	return root
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
