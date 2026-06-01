//! Integration test: the dataplane half of the runtime log-level toggle.
//!
//! The panel's "set log level to DEBUG" reaches the dataplane as a
//! `SetLogLevel` IPC command, which `ipc::dispatch` turns into
//! `TunnelManager::set_log_level`, which reloads the live `EnvFilter`
//! through the reload handle `main.rs` installs on the subscriber. This
//! test wires that exact path against a capturing subscriber and proves a
//! `debug!` that is filtered out at the default INFO level starts being
//! emitted after `set_log_level("debug")`.
//!
//! It doubles as a guard that `debug!` is COMPILED INTO the build: a
//! `tracing` release feature such as `release_max_level_info` would strip
//! the macro and the post-reload assertion below would fail.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing::debug;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

use sublyne_dataplane::manager::{ReloadFilter, TunnelManager};

/// A `MakeWriter` that appends every formatted line into a shared buffer so
/// the test can inspect exactly what the subscriber emitted.
#[derive(Clone)]
struct BufMaker(Arc<Mutex<Vec<u8>>>);
struct BufSink(Arc<Mutex<Vec<u8>>>);

impl Write for BufSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buf lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufMaker {
    type Writer = BufSink;
    fn make_writer(&'a self) -> Self::Writer {
        BufSink(self.0.clone())
    }
}

#[test]
fn set_log_level_enables_debug_at_runtime() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    // Same layer composition as main.rs: a reloadable EnvFilter Layer over
    // the registry, with the fmt layer below it.
    let (filter_layer, reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::new("sublyne_dataplane=info"));
    let subscriber = tracing_subscriber::registry().with(filter_layer).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(BufMaker(buf.clone())),
    );

    // Hand the reload handle to the manager exactly as main.rs does.
    let reload_arc: Arc<dyn ReloadFilter> = Arc::new(reload_handle);
    tracing::subscriber::with_default(subscriber, || {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let mgr = TunnelManager::new(tx, Some(reload_arc));
        // Default INFO filter: this debug! must be dropped.
        debug!(target: "sublyne_dataplane::logtest", "before-debug-line");
        // Operator flips the panel to DEBUG → SetLogLevel IPC →
        // manager.set_log_level → live EnvFilter reload.
        mgr.set_log_level("debug");
        // The same debug! must now be emitted.
        debug!(target: "sublyne_dataplane::logtest", "after-debug-line");
    });

    let out = String::from_utf8(buf.lock().expect("buf lock").clone()).expect("utf8");
    assert!(
        !out.contains("before-debug-line"),
        "debug! must be filtered out at the default INFO level; got: {out}"
    );
    assert!(
        out.contains("after-debug-line"),
        "debug! must be emitted after set_log_level(\"debug\") reloads the filter \
         (and therefore must be compiled into the build); got: {out}"
    );
}
