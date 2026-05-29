//! IPC smoke test that doesn't require raw sockets.
//!
//! Spawns the built `sublyne-dataplane` binary against a temp Unix
//! socket, sends a `Ping`, and asserts the reply correlates by `id`.
//! This is what CI exercises — the full loopback test requires
//! CAP_NET_RAW and lives behind `#[ignore]` in `loopback.rs`.

use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::sleep;

const BIN: &str = env!("CARGO_BIN_EXE_sublyne-dataplane");

#[tokio::test]
async fn ipc_ping_reply_roundtrip() {
    // On non-unix CI runners this whole test is irrelevant; skip.
    if cfg!(not(unix)) {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let sock_path = dir.path().join("dataplane.sock");

    // Spawn the binary as a child process.
    let mut child = Command::new(BIN)
        .arg(format!("--ipc-socket={}", sock_path.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dataplane");

    // Wait up to ~5 s for the socket to appear.
    let mut tries = 0;
    while !sock_path.exists() && tries < 50 {
        sleep(Duration::from_millis(100)).await;
        tries += 1;
    }
    if !sock_path.exists() {
        let _ = child.kill();
        panic!("dataplane never created socket at {}", sock_path.display());
    }

    let mut stream = UnixStream::connect(&sock_path)
        .await
        .expect("connect to dataplane");

    // Read the first frame: should be a Ready event.
    let mut got_len = [0u8; 4];
    stream.read_exact(&mut got_len).await.expect("read len");
    let n = u32::from_be_bytes(got_len) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.expect("read body");
    let v: serde_json::Value = serde_json::from_slice(&buf).expect("parse Ready");
    assert_eq!(v["type"], "Ready");
    assert!(v["payload"]["version"].is_string());

    // Send a Ping command.
    let ping = serde_json::json!({
        "type": "Ping",
        "id": "test-ping-1",
        "payload": {}
    });
    let body = serde_json::to_vec(&ping).unwrap();
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();

    // Read the reply (may be preceded by other events; loop until we
    // see a Reply matching our id).
    let reply: serde_json::Value = loop {
        stream.read_exact(&mut got_len).await.expect("reply len");
        let n = u32::from_be_bytes(got_len) as usize;
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await.expect("reply body");
        let v: serde_json::Value = serde_json::from_slice(&buf).expect("parse reply");
        if v["type"] == "Reply" && v["id"] == "test-ping-1" {
            break v;
        }
    };
    assert_eq!(reply["payload"]["ok"], true);

    // Send Shutdown to give the child a clean exit.
    let shut = serde_json::json!({
        "type": "Shutdown",
        "id": "shut-1",
        "payload": {}
    });
    let body = serde_json::to_vec(&shut).unwrap();
    let len = (body.len() as u32).to_be_bytes();
    let _ = stream.write_all(&len).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;
    drop(stream);

    // Reap the child.
    let _ = child.wait();
}
