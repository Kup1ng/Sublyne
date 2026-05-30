// Command sublyne is the Sublyne control plane.
//
// The binary boots, loads /etc/sublyne/config.toml, opens the
// SQLite database at db_path, applies any not-yet-applied migrations,
// consumes /etc/sublyne/bootstrap-admin.toml (if present) to seed
// the admin row, and serves the admin HTTP panel on panel_port.
//
// Phase 5 mounts the entire panel and API under the obfuscated
// /<web_path>/ prefix and serves the embedded Nuxt 3 SPA from inside
// the same binary. Later phases wire in tunnel CRUD, the WireGuard
// manager, metrics, and the IPC supervisor for the Rust data plane.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/api"
	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
	"github.com/Kup1ng/Sublyne/control-plane/internal/config"
	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplane"
	"github.com/Kup1ng/Sublyne/control-plane/internal/dataplaneasset"
	"github.com/Kup1ng/Sublyne/control-plane/internal/db"
	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
	"github.com/Kup1ng/Sublyne/control-plane/internal/metrics"
	"github.com/Kup1ng/Sublyne/control-plane/internal/migrations"
	"github.com/Kup1ng/Sublyne/control-plane/internal/socks5"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/webassets"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// version is injected at build time via -ldflags="-X main.version=...".
// In dev builds it stays as the placeholder below.
var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sublyne", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/sublyne/config.toml", "path to config.toml")
	showVersion := fs.Bool("version", false, "print version and exit")
	tearDown := fs.Bool("tear-down", false, "remove every sub-wg-* interface and project-owned ip rule / route entry, then exit 0. Used by setup.sh's Uninstall flow so a stale tunnel from a previous install does not leak.")
	resetAdmin := fs.Bool("reset-admin", false, "interactively reset the admin username/password directly in the DB (re-hashes via Argon2id, clears active lockouts) and exit. Use this when the panel login is broken or the credentials have been lost. Requires the same DB the running service uses; stop the service first to avoid SQLite WAL contention.")
	showAdminUsername := fs.Bool("show-admin-username", false, "print the configured admin username (no password, no hash) to stdout and exit. Used by setup.sh's Status menu so operators can see who their panel login is without exposing any secret material.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Printf("sublyne %s\n", version)
		return 0
	}
	if *tearDown {
		return runTearDown()
	}
	if *resetAdmin {
		return runResetAdmin(*configPath, os.Stdin, os.Stdout, os.Stderr)
	}
	if *showAdminUsername {
		return runShowAdminUsername(*configPath, os.Stdout, os.Stderr)
	}

	// Bootstrap a stdout-only logger so config errors are not silent.
	// We can't open the file sink yet — we don't know its path until
	// config has been loaded.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}

	// Reconfigure logging now that we know both the requested level
	// AND the on-disk log path. PROJECT_REQUIREMENTS §8.1 mandates a
	// dual sink: stdout (which systemd drains into journald) AND a
	// rotating file at log_path so the panel's Logs page and shell
	// `tail` both have a stable file. Phase 12 adds an in-memory log
	// bus to the same fanout so the panel can subscribe over WebSocket.
	// SUBLYNE_LOG_FORMAT=json (typically set via a systemd drop-in)
	// flips both the Rust dataplane formatter and this slog logger to
	// emit one JSON object per line. Operators get
	// `journalctl -u sublyne` lines they can pipe into jq / a log
	// shipper without parsing key=value pairs.
	logFormat := logging.ParseFormat(os.Getenv("SUBLYNE_LOG_FORMAT"))
	logSetup, err := logging.SetupDefaultLogger(
		os.Stdout,
		parseLogLevel(cfg.LogLevel),
		logging.DefaultFileSinkConfig(cfg.LogPath),
		logFormat,
	)
	if err != nil {
		slog.Error("setup logger", "err", err)
		return 1
	}
	if logSetup.Closer != nil {
		defer func() { _ = logSetup.Closer.Close() }()
	}
	// Crash files share the directory with app.log so operators only
	// have one place to look. SetCrashDir is sync.Once-gated.
	logging.SetCrashDir(filepath.Dir(cfg.LogPath))

	// Defer a top-level panic catcher so any panic that escapes a
	// handler — or, more importantly, the supervisor goroutine —
	// produces a crash-<ts>.log under /var/lib/sublyne/logs/ before
	// the process exits. The systemd unit's Restart=on-failure brings
	// us back up; this catcher just guarantees the report exists.
	defer func() {
		if rec := recover(); rec != nil {
			body := logging.FormatPanic(rec, "main")
			if name, werr := logging.WriteCrashReport(logging.CrashDir(), body); werr != nil {
				slog.Error("crash: failed to write crash log", "err", werr)
			} else {
				slog.Error("crash: panic recovered; crash log written",
					"file", name, "panic", fmt.Sprint(rec))
			}
			// Re-raise so systemd records a non-zero exit and restarts.
			panic(rec)
		}
	}()

	slog.Info("starting sublyne",
		"version", version,
		"role", cfg.Role,
		"panel_port", cfg.PanelPort,
		"db_path", cfg.DBPath,
		"web_path", cfg.WebPath,
		"assets_embedded", webassets.Embedded,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	database, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		slog.Error("open database", "path", cfg.DBPath, "err", err)
		return 1
	}
	defer func() { _ = database.Close() }()

	if err := migrations.Apply(ctx, database); err != nil {
		slog.Error("apply migrations", "err", err)
		return 1
	}

	// If the operator previously toggled the runtime log level from
	// the panel, apply that here so the choice survives the restart.
	// Otherwise the config-file default (already in effect) sticks.
	if persisted := api.ReadRuntimeLogLevel(ctx, database); persisted != "" {
		runtime := logging.ParseLevel(persisted)
		if logSetup.Level != nil {
			logSetup.Level.Set(runtime)
		}
		slog.Info("log level restored from settings", "level", persisted)
	}

	// Phase 3 first job per the roadmap: on service start, if
	// /etc/sublyne/bootstrap-admin.toml exists, hash the password
	// with Argon2id, insert/update the admin row, then delete the
	// file. After this the admin only ever exists as an Argon2id
	// hash in the DB.
	bootstrapPath := bootstrapAdminPath(*configPath)
	if _, err := auth.ConsumeBootstrap(ctx, database, bootstrapPath, slog.Default()); err != nil {
		slog.Error("consume bootstrap-admin.toml", "path", bootstrapPath, "err", err)
		return 1
	}

	admins := auth.NewAdminStore(database)
	signingKeys := auth.NewSigningKeyStore(database)
	issuer := auth.NewIssuer(signingKeys, nil)
	limiter := auth.NewLimiter(database, auth.DefaultLimiterConfig(), nil, slog.Default())
	limiter.StartPruner(ctx)
	defer limiter.Stop()

	auditRecorder := audit.NewRecorder(database, audit.WithLogger(slog.Default()))
	auditRecorder.StartPruner(ctx)
	defer auditRecorder.Close()

	authDeps := api.AuthDeps{
		DB:       database,
		Admins:   admins,
		Issuer:   issuer,
		Limiter:  limiter,
		Role:     cfg.Role,
		CookieFn: api.DefaultCookie,
		Logger:   slog.Default(),
		Audit:    auditRecorder,
	}

	// Pull the SPA dist out of the binary (embed build) or off disk
	// (dev build). A nil FS still lets the API run; the SPA handler
	// then responds 503 with a clear message instead of crashing.
	assetFS, err := webassets.FrontendFS()
	if err != nil {
		slog.Warn("frontend dist unavailable; panel UI will reply 503", "err", err)
	}

	tunnelRepo := tunnels.NewRepo(database)
	// Cache for the metrics hot path: dashboards and the polling
	// fallback hit `tunnels.List` on every refresh, which is N×
	// duplicate SQLite queries pre-R3. The cache invalidation is
	// driven by the tunnel CRUD handlers so the cached snapshot is
	// always at most one mutation behind reality.
	tunnelCache := tunnels.NewCache(tunnelRepo)
	wgRepo := wg.NewRepo(database)
	socks5Repo := socks5.NewRepo(database)

	// Phase 7: stand up the WireGuard kernel manager. On Linux this
	// dials wgctrl + netlink; on other platforms it returns a stub
	// that lets the panel still mount its WG-aware routes but rejects
	// real bring-up with ErrManagerUnsupported. We fall back to nil if
	// the constructor itself fails so the rest of the panel keeps
	// working even on a host without CAP_NET_ADMIN.
	wgManager, wgErr := wg.NewManager(slog.Default())
	if wgErr != nil {
		slog.Warn("wg: manager unavailable; WireGuard bring-up disabled this session", "err", wgErr)
	}

	// Phase 11: metrics ring buffer + WebSocket broadcast bus. Created
	// up-front (before the dataplane supervisor) so the IPC subscriber
	// has a sink ready when Ready fires. The bus's snapshot renderer is
	// wired LATER (after metricsDeps is constructed, before the IPC
	// subscriber goroutine starts) so the closure captures the deps.
	metricsRecorder := metrics.NewRecorder(nil)
	statsBroadcast := api.NewBroadcast()

	// Phase 8a: extract and spawn the Rust dataplane child process.
	// The supervisor runs in the background and exposes a typed
	// IPC client we hand to the tunnel manager. On dev builds the
	// embedded binary is empty, so we skip the supervisor and the
	// dataplane manager runs in "not configured" mode — the panel
	// still renders, every Start tunnel returns a clear error
	// instead of crashing.
	var (
		dpManager  *dataplane.Manager
		supervisor *ipc.Supervisor
	)
	if dataplaneasset.Embedded && len(dataplaneasset.Bytes()) > 0 {
		supCfg := ipc.DefaultSupervisorConfig()
		// The Unix socket lives in /run/sublyne (tmpfs, fine for
		// non-executable bytes). The dataplane *binary* must live on
		// a regular filesystem — systemd mounts /run with `noexec`
		// on every recent Ubuntu, so exec()ing a binary written
		// there fails with EACCES regardless of file mode. The unit
		// already has /var/lib/sublyne in ReadWritePaths.
		supCfg.SocketPath = "/run/sublyne/dataplane.sock"
		supCfg.BinaryPath = "/var/lib/sublyne/dataplane"
		supCfg.Logger = slog.Default()
		supervisor = ipc.NewSupervisor(supCfg)
		go func() {
			if err := supervisor.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("dataplane supervisor exited", "err", err)
			}
		}()
		dpManager = dataplane.NewManager(supervisor, slog.Default())
		go dpManager.ListenStateChanges(ctx)
		// Replay every enabled tunnel into the dataplane so the
		// service restart is transparent to in-flight users.
		go func() {
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := supervisor.WaitReady(waitCtx); err != nil {
				slog.Warn("dataplane: not ready in time; skipping startup sync", "err", err)
				return
			}
			all, err := tunnelRepo.List(ctx)
			if err != nil {
				slog.Warn("dataplane: list tunnels for sync failed", "err", err)
				return
			}
			// Reboot recovery: a host reboot drops every kernel
			// WireGuard link, ip rule, and route. The dataplane Sync
			// below only replays the StartTunnel IPC — it never
			// recreates the kernel WG egress. So before we tell the
			// dataplane to start forwarding, bring each enabled
			// wireguard-mode Client tunnel's interface back up. Up is
			// idempotent, so on a plain process restart (interfaces
			// still present) this is a cheap no-op. Failures are logged
			// per-tunnel and never block the Sync that follows.
			api.ReconcileClientWireGuard(ctx, wgRepo, wgManager, all, slog.Default())
			dpManager.Sync(ctx, all, socks5Repo)
		}()
	} else {
		slog.Warn("dataplane: binary not embedded in this build; tunnel start will return an error (rebuild with -tags=embed)")
	}

	tunnelDeps := api.TunnelDeps{
		Repo:        tunnelRepo,
		ServerRole:  tunnels.Role(cfg.Role),
		WGRepo:      wgRepo,
		WGManager:   wgManager,
		SOCKS5Repo:  socks5Repo,
		Dataplane:   dpManager,
		Logger:      slog.Default(),
		Audit:       auditRecorder,
		TunnelCache: tunnelCache,
	}
	wgDeps := api.WGDeps{
		Repo:       wgRepo,
		Manager:    wgManager,
		TunnelRepo: tunnelRepo,
		Logger:     slog.Default(),
		Audit:      auditRecorder,
	}
	socks5Deps := api.SOCKS5Deps{
		Repo:   socks5Repo,
		Logger: slog.Default(),
		Audit:  auditRecorder,
	}

	metricsDeps := api.MetricsDeps{
		Recorder:       metricsRecorder,
		Dataplane:      dpManager,
		TunnelRepo:     tunnelRepo,
		TunnelCache:    tunnelCache,
		WGRepo:         wgRepo,
		WGManager:      wgManager,
		StatsBroadcast: statsBroadcast,
		Logger:         slog.Default(),
	}
	// Wire the WS broadcast renderer now that the deps are constructed.
	// Render-once-per-push: every IPC StatsReport produces ONE rendered
	// snapshot frame, fanned out to all connected dashboards.
	// Pre-R3 the bus carried raw reports and each WS handler re-built +
	// re-marshalled the same snapshot per client per push (~14k CPU
	// cycles × N tabs × 12 pushes/min × 60 min = wasted CPU). Now the
	// render happens once in the IPC subscriber goroutine below.
	statsBroadcast.SetRenderer(func(report ipc.StatsReport) ([]byte, error) {
		return api.RenderSnapshotFrame(metricsDeps, report, time.Now())
	}, slog.Default())

	// Phase 11: subscribe to dataplane StatsReport events. The goroutine
	// below polls the supervisor for a live client every time it
	// disconnects (e.g. dataplane respawn) and re-attaches. Started AFTER
	// statsBroadcast.SetRenderer so the very first published report
	// already has bytes to fan out.
	if supervisor != nil {
		go func() {
			for {
				if err := ctx.Err(); err != nil {
					return
				}
				client := supervisor.Client()
				if client == nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(500 * time.Millisecond):
					}
					continue
				}
				stats := client.SubscribeStats(8)
			drain:
				for {
					select {
					case <-ctx.Done():
						return
					case report, ok := <-stats:
						if !ok {
							break drain
						}
						metricsRecorder.Append(report)
						statsBroadcast.Publish(report)
					}
				}
			}
		}()
	}

	logsDeps := api.LogsDeps{
		Bus:      logSetup.Bus,
		Level:    logSetup.Level,
		DB:       database,
		Audit:    auditRecorder,
		FileSink: logSetup.FileSink,
		Logger:   slog.Default(),
	}
	auditDeps := api.AuditDeps{Recorder: auditRecorder, Logger: slog.Default()}

	// Phase 13: backup + restore. Same DB, dataplane manager, and WG
	// manager the tunnel handlers use — restore needs to stop running
	// tunnels, swap tables, and start them again from the restored DB.
	backupDeps := api.BackupRestoreDeps{
		DB:          database,
		DBPath:      cfg.DBPath,
		TunnelRepo:  tunnelRepo,
		WGRepo:      wgRepo,
		WGManager:   wgManager,
		SOCKS5Repo:  socks5Repo,
		Dataplane:   dpManager,
		Logger:      slog.Default(),
		Audit:       auditRecorder,
		TunnelCache: tunnelCache,
	}

	// Propagate every operator-driven log-level change to the Rust
	// dataplane via the IPC supervisor. The callback fires after the
	// Go side has already swapped its own level, so a "set to DEBUG"
	// from the panel takes effect in both processes within one IPC
	// round-trip.
	if logSetup.Level != nil {
		logSetup.Level.OnChange(func(l slog.Level) {
			if dpManager == nil {
				return
			}
			lvlStr := logging.LevelString(l)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := dpManager.SetLogLevel(ctx, lvlStr); err != nil {
				slog.Warn("dataplane: log-level push failed", "level", lvlStr, "err", err)
			}
		})
	}

	routerDeps := api.RouterDeps{
		Auth:          authDeps,
		Tunnels:       tunnelDeps,
		WG:            wgDeps,
		SOCKS5:        socks5Deps,
		Metrics:       metricsDeps,
		Logs:          logsDeps,
		Audit:         auditDeps,
		BackupRestore: backupDeps,
		WebPath:       cfg.WebPath,
		AssetFS:       assetFS,
		PanelPort:     cfg.PanelPort,
		LogLevel:      cfg.LogLevel,
		Version:       version,
	}

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.PanelPort),
		Handler:           api.NewRouter(routerDeps),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", srv.Addr, "web_path", cfg.WebPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		slog.Error("http server crashed", "err", err)
		return 1
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "err", err)
		return 1
	}
	return 0
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "trace", "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// runTearDown removes every sub-wg-* interface, every project-owned
// ip rule / route entry, and the dataplane's iptables RST-suppression
// chain, then exits 0. The Uninstall path in setup.sh shells out to
// this so a stale interface or rule from a previous install doesn't
// leak into the next one. On non-Linux builds the stub manager's
// TearDownAll is a no-op (the binary couldn't have created state to
// clean up there).
//
// Two layers of cleanup:
//
//  1. WireGuard interfaces + ip rules + routes — handled by the wg
//     manager's TearDownAll. Best-effort: errors are logged, not
//     fatal, so a half-broken host can still complete uninstall.
//  2. iptables RST-suppression chain — installed at tunnel start by
//     the Rust dataplane (see data-plane/src/rst_suppress.rs) and
//     normally removed on tunnel stop via RAII. If the dataplane
//     crashed or was killed abruptly the rules can survive; this
//     pass tears them down by name. The chain constant lives in
//     two places (one Rust, one Go) deliberately — Phase 14 doesn't
//     have a stable IPC for "please clean up your iptables" from a
//     stopped child process, so the chain name is the contract.
func runTearDown() int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	mgr, err := wg.NewManager(slog.Default())
	if err != nil {
		// We can't talk to wgctrl/netlink — usually CAP_NET_ADMIN is
		// missing. Log and continue so we still attempt the iptables
		// cleanup below; there's nothing to remove that the wg
		// manager could have created in this state, but old
		// dataplane runs may still have left iptables rules behind.
		slog.Warn("tear-down: wg manager unavailable; skipping WG sweep", "err", err)
	} else if err := mgr.TearDownAll(context.Background()); err != nil {
		slog.Warn("tear-down: WG cleanup encountered errors (continuing)", "err", err)
	}
	if err := tearDownRstSuppressChain(); err != nil {
		slog.Warn("tear-down: iptables RST-suppression cleanup encountered errors (continuing)", "err", err)
	}
	return 0
}

// rstSuppressChainName must stay in lockstep with the CHAIN constant
// in data-plane/src/rst_suppress.rs. The two sides have no IPC for
// "clean up your iptables" from a stopped child, so this string is
// the contract.
const rstSuppressChainName = "FORWARD-TCP-SYN-SUPP"

// tearDownRstSuppressChain best-effort-removes the per-tunnel DROP
// rules the Rust dataplane installs to suppress kernel-generated TCP
// RSTs on the spoofed download path. The dataplane normally cleans
// these up itself via the RstSuppressGuard's Drop impl; this pass is
// the fallback for unclean shutdowns and for `sublyne --tear-down`
// run by an Uninstall after the service is already stopped.
//
// The sequence:
//
//  1. Remove the OUTPUT → CHAIN jump (idempotent: `-C` first, `-D`
//     only if present).
//  2. Flush every DROP rule out of the chain.
//  3. Delete the chain itself.
//
// All three iptables calls are best-effort: a missing chain, missing
// jump, or missing iptables binary itself returns nil. The goal is
// "leave nothing behind on a successful uninstall", not "fail loudly
// if iptables happens to be in an unexpected state". `nft` is not
// shelled out to: the dataplane only ever installs iptables-legacy
// rules and Ubuntu's `iptables` binary maps to nft-iptables by
// default on 22.04+, so a single `iptables` command path covers
// every supported host.
func tearDownRstSuppressChain() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		// iptables not installed — nothing to remove.
		return nil
	}
	// Step 1: drop the OUTPUT jump if it's there. `-C` is the check
	// form; it returns non-zero when the rule is absent, which we
	// treat as "already clean".
	checkJump := exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "-j", rstSuppressChainName)
	if err := checkJump.Run(); err == nil {
		delJump := exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-j", rstSuppressChainName)
		if out, err := delJump.CombinedOutput(); err != nil {
			slog.Warn("tear-down: iptables -D OUTPUT jump failed", "err", err, "output", string(out))
		}
	}
	// Step 2: flush our chain. If the chain doesn't exist, the
	// command exits non-zero and we silently move on.
	flush := exec.Command("iptables", "-F", rstSuppressChainName)
	_ = flush.Run()
	// Step 3: remove the chain itself. Same tolerance for "doesn't
	// exist".
	del := exec.Command("iptables", "-X", rstSuppressChainName)
	_ = del.Run()
	slog.Info("tear-down: iptables RST-suppression chain swept", "chain", rstSuppressChainName)
	return nil
}

// runResetAdmin re-hashes a fresh username/password into the admin
// row and clears every active brute-force lockout for the current IP.
//
// Why this command exists: setup.sh option 3 (Reinstall) is still
// stubbed until Phase 14, so a botched bootstrap or a forgotten
// password used to lock the operator out of their own panel with no
// recourse short of `rm -rf /var/lib/sublyne`. `sublyne --reset-admin`
// is the supported back door — root-only by virtue of needing read+
// write access to /var/lib/sublyne/sublyne.db.
//
// The function reads the same config file the running service uses
// so it operates on the right DB. The operator MUST stop the service
// first (the SQLite WAL lets two readers coexist but a writer + the
// running service racing on the admin row leads to surprises).
func runResetAdmin(configPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: load config %q: %v\n", configPath, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: open db %q: %v\n", cfg.DBPath, err)
		return 1
	}
	defer func() { _ = database.Close() }()

	if err := migrations.Apply(ctx, database); err != nil {
		fmt.Fprintf(stderr, "reset-admin: apply migrations: %v\n", err)
		return 1
	}

	reader := bufio.NewReader(stdin)
	fmt.Fprintln(stdout, "Reset the admin account in", cfg.DBPath)
	fmt.Fprint(stdout, "  New username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: read username: %v\n", err)
		return 1
	}
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Fprintln(stderr, "reset-admin: username must not be empty")
		return 1
	}
	fmt.Fprint(stdout, "  New password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: read password: %v\n", err)
		return 1
	}
	password = strings.TrimRight(password, "\r\n")
	if len(password) < 8 {
		fmt.Fprintln(stderr, "reset-admin: password must be at least 8 characters")
		return 1
	}
	fmt.Fprint(stdout, "  Confirm password: ")
	confirm, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: read confirmation: %v\n", err)
		return 1
	}
	confirm = strings.TrimRight(confirm, "\r\n")
	if confirm != password {
		fmt.Fprintln(stderr, "reset-admin: passwords do not match")
		return 1
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(stderr, "reset-admin: hash password: %v\n", err)
		return 1
	}
	if err := auth.NewAdminStore(database).Upsert(ctx, username, hash); err != nil {
		fmt.Fprintf(stderr, "reset-admin: write admin row: %v\n", err)
		return 1
	}
	// Drop every login_attempts row so a fresh login doesn't trip
	// over an old IP lockout. The pruner would catch up eventually,
	// but the operator running --reset-admin is by definition trying
	// to log in *now*.
	if _, err := database.ExecContext(ctx, `DELETE FROM login_attempts`); err != nil {
		fmt.Fprintf(stderr, "reset-admin: clear login_attempts: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "OK: admin %q reset. Restart the service: systemctl restart sublyne\n", username)
	return 0
}

// runShowAdminUsername prints the configured admin username and exits.
// Used by setup.sh's Status menu so operators can see their panel
// login at a glance. By design it prints only the username — never
// the password hash, never the JWT signing key, never any other
// row from the DB. If the admin row hasn't been created yet (the
// service hasn't consumed bootstrap-admin.toml), this returns a
// non-zero exit so callers can render "(unknown)" rather than a
// stale value.
func runShowAdminUsername(configPath string, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "show-admin-username: load config %q: %v\n", configPath, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	database, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "show-admin-username: open db %q: %v\n", cfg.DBPath, err)
		return 1
	}
	defer func() { _ = database.Close() }()

	a, err := auth.NewAdminStore(database).Get(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "show-admin-username: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, a.Username)
	return 0
}

// bootstrapAdminPath returns the on-disk location of the plaintext
// install credentials. The default lives next to config.toml inside
// /etc/sublyne; tests pass a dev config path and the bootstrap file
// is colocated.
func bootstrapAdminPath(configPath string) string {
	dir := configDir(configPath)
	if dir == "" {
		return auth.DefaultBootstrapPath
	}
	return dir + string(os.PathSeparator) + "bootstrap-admin.toml"
}

func configDir(configPath string) string {
	for i := len(configPath) - 1; i >= 0; i-- {
		if configPath[i] == '/' || configPath[i] == os.PathSeparator {
			return configPath[:i]
		}
	}
	return ""
}
