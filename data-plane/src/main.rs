//! Entry point for the Rust data plane.
//!
//! The binary is launched by the Go control plane's supervisor; it
//! takes one CLI flag pointing at the Unix domain socket it should
//! listen on for IPC. Once the socket is bound it emits a `Ready`
//! event over IPC and waits for commands.

use std::backtrace::Backtrace;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use sublyne_dataplane::ipc::IpcServer;
use sublyne_dataplane::manager::{ReloadFilter, TunnelManager};

const DEFAULT_SOCKET_PATH: &str = "/run/sublyne/dataplane.sock";
const DEFAULT_CRASH_DIR: &str = "/var/lib/sublyne/logs";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Install the crash hook BEFORE any other initialization so a
    // panic inside the runtime setup itself still produces a crash
    // report. PROJECT_REQUIREMENTS §8.2: on panic/fatal write a full
    // stack trace to BOTH journald AND
    // /var/lib/sublyne/logs/crash-<timestamp>.log. The Cargo.toml
    // pins `panic = "abort"` in release; the hook still fires before
    // abort so the file lands on disk.
    install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("sublyne-dataplane {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let socket_path =
        parse_socket_flag(&args).unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));

    // tracing-subscriber with a reload handle so the IPC SetLogLevel
    // command can swap the filter live.
    //
    // ANSI colour is force-disabled because the dataplane's stdout is
    // always captured by a pipe from the Go supervisor — never a TTY —
    // so colour escapes are pure noise that pollutes journalctl, the
    // rotating file at /var/lib/sublyne/logs/app.log, and the panel's
    // Logs page. tracing-subscriber's fmt layer defaults to ANSI=on
    // regardless of whether stdout is a pipe, so the call has to be
    // explicit (see .claude/skills/log-hygiene/SKILL.md).
    //
    // SUBLYNE_LOG_FORMAT=json (default `text`) switches the formatter
    // to .json() so the Go supervisor can parse each line into
    // structured slog attrs (target, tunnel_id, transport, etc.).
    let log_format = parse_log_format(std::env::var("SUBLYNE_LOG_FORMAT").ok().as_deref());
    let initial_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sublyne_dataplane=info"));
    let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(initial_filter);
    let registry = tracing_subscriber::registry().with(filter_layer);
    match log_format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_ansi(false)
                    .json(),
            )
            .init(),
        LogFormat::Text => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_ansi(false),
            )
            .init(),
    }

    // Log the resolved per-socket buffer target once. This both proves
    // the env var made it through systemd's environment and lets
    // operators see at a glance whether their tuning is in effect.
    sublyne_dataplane::perf::log_startup_settings();

    // PRD §7 memory soft cap: poll /proc every 5 s and flip the global
    // pressure flag with hysteresis. SessionTable consults it on every
    // new-session insert. The sampler must be on the tokio runtime;
    // it's spawn-and-forget for the lifetime of the process.
    sublyne_dataplane::memory::spawn_sampler();

    let reload_arc: Arc<dyn ReloadFilter> = Arc::new(reload_handle);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let manager = Arc::new(TunnelManager::new(shutdown_tx, Some(reload_arc)));

    let server = IpcServer::new(socket_path.clone(), manager.clone());
    let serve_task = tokio::spawn(async move {
        if let Err(e) = server.serve().await {
            tracing::error!(err = %e, "ipc server exited with error");
        }
    });

    // Wait for either an IPC `Shutdown` or a process signal.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).context("install sigterm")?;
        let mut sigint = signal(SignalKind::interrupt()).context("install sigint")?;
        tokio::select! {
            _ = shutdown_rx => {
                tracing::info!("shutdown via IPC Shutdown");
            }
            _ = sigterm.recv() => {
                tracing::info!("shutdown via SIGTERM");
                manager.stop_all().await;
            }
            _ = sigint.recv() => {
                tracing::info!("shutdown via SIGINT");
                manager.stop_all().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = shutdown_rx.await;
    }

    // Allow the ipc serve task to wind down on its own — closing
    // the listener happens automatically when its socket is unlinked.
    serve_task.abort();
    let _ = serve_task.await;

    // Best-effort cleanup of the socket file.
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// install_panic_hook installs a `std::panic::set_hook` that mirrors
/// the Go side's crash recoverer: every panic produces a
/// `crash-<unix>.log` file alongside the application log (default
/// `/var/lib/sublyne/logs/`, overridable via `SUBLYNE_CRASH_DIR` for
/// tests) and also emits a `tracing::error!` so journald sees the
/// same content.
///
/// The hook deliberately defers to the *previous* hook after writing
/// the file. That preserves Cargo's default panic-handler behavior
/// (stderr trace, abort under `panic="abort"`) so the operator's
/// existing debugging muscle memory still works.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let dir = env::var("SUBLYNE_CRASH_DIR").unwrap_or_else(|_| DEFAULT_CRASH_DIR.into());
        let body = format_panic_body(info);
        // Best-effort: a failure to write must not stop the standard
        // panic flow.
        if let Err(e) = write_crash_file(Path::new(&dir), &body) {
            eprintln!("sublyne-dataplane: failed to write crash file: {e}");
        }
        // Emit through tracing so journald captures the same bytes.
        // Using direct stderr is the only thing we can rely on here —
        // the tracing subscriber may be mid-shutdown.
        eprintln!("sublyne-dataplane: PANIC — crash log written under {dir}");
        eprintln!("{body}");
        prev(info);
    }));
}

fn format_panic_body(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info
        .payload()
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(non-string payload)".into());
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "(unknown location)".into());
    let backtrace = Backtrace::force_capture();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "sublyne-dataplane: panic\ntime_unix: {now}\nlocation: {location}\npanic: {payload}\n\n{backtrace}\n",
    )
}

fn write_crash_file(dir: &Path, body: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("crash-{now}.log"));
    fs::write(&path, body)?;
    // 0o640 — group-readable for the operator. We do a chmod after
    // write because OpenOptions cannot set the precise mode on every
    // platform.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o640);
        let _ = fs::set_permissions(&path, perm);
    }
    Ok(())
}

/// LogFormat is the value of the SUBLYNE_LOG_FORMAT env var, after
/// parsing. `Text` is the default; `Json` is opt-in for operators who
/// want trivially-parseable structured logs on the Go supervisor side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

/// parse_log_format converts the raw env-var value into a LogFormat.
/// Anything other than a case-insensitive `json` falls through to
/// `Text` — an unrecognised value should NOT silently turn on JSON,
/// because text is the operator-friendly default.
fn parse_log_format(raw: Option<&str>) -> LogFormat {
    match raw {
        Some(v) if v.trim().eq_ignore_ascii_case("json") => LogFormat::Json,
        _ => LogFormat::Text,
    }
}

fn parse_socket_flag(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter().skip(1);
    while let Some(a) = iter.next() {
        if a == "--ipc-socket" {
            return iter.next().map(PathBuf::from);
        }
        if let Some(rest) = a.strip_prefix("--ipc-socket=") {
            return Some(PathBuf::from(rest));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::panic;
    use std::sync::Mutex;

    // Serialise tests that mutate the global panic hook. Cargo runs
    // tests in parallel by default and set_hook isn't thread-safe with
    // concurrent panics.
    static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_socket_flag_split() {
        let args = vec!["bin".into(), "--ipc-socket".into(), "/tmp/x".into()];
        assert_eq!(parse_socket_flag(&args), Some(PathBuf::from("/tmp/x")));
    }
    #[test]
    fn parse_socket_flag_inline() {
        let args = vec!["bin".into(), "--ipc-socket=/tmp/y".into()];
        assert_eq!(parse_socket_flag(&args), Some(PathBuf::from("/tmp/y")));
    }
    #[test]
    fn parse_socket_flag_missing() {
        let args = vec!["bin".into()];
        assert_eq!(parse_socket_flag(&args), None);
    }

    #[test]
    fn parse_log_format_defaults_to_text() {
        assert_eq!(parse_log_format(None), LogFormat::Text);
        assert_eq!(parse_log_format(Some("")), LogFormat::Text);
        assert_eq!(parse_log_format(Some("text")), LogFormat::Text);
        assert_eq!(parse_log_format(Some("garbage")), LogFormat::Text);
    }

    #[test]
    fn parse_log_format_recognises_json_case_insensitive() {
        assert_eq!(parse_log_format(Some("json")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("JSON")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("Json")), LogFormat::Json);
        // Tolerate whitespace from systemd Environment= entries.
        assert_eq!(parse_log_format(Some("  json  ")), LogFormat::Json);
    }

    /// install_panic_hook + a deliberate panic must produce a crash-*.log
    /// file under SUBLYNE_CRASH_DIR. We catch the unwind so the test
    /// harness keeps running.
    #[test]
    fn panic_hook_writes_crash_file() {
        let _guard = PANIC_HOOK_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: env mutation during a single-threaded test path.
        unsafe {
            env::set_var("SUBLYNE_CRASH_DIR", dir.path());
        }

        // Save and restore the original hook around the test so other
        // tests running afterwards still get vanilla panic behaviour.
        let prev = panic::take_hook();
        install_panic_hook();

        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            panic!("simulated dataplane crash");
        }));

        panic::set_hook(prev);

        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("crash-"))
            .collect();
        assert!(
            !entries.is_empty(),
            "expected at least one crash-*.log file"
        );
        let body = fs::read_to_string(entries[0].path()).expect("read body");
        assert!(
            body.contains("simulated dataplane crash"),
            "crash file missing panic payload: {body}"
        );
    }
}
