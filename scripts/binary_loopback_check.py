"""Drive a built sublyne-dataplane binary through real IPC.

Spawns the binary, starts a remote+client tunnel pair on 127.0.0.1,
sends a UDP packet into local_listen_addr, asserts the same payload
comes back out via the spoofed download path.

Intended as a stage-1 sanity check; the regular Rust integration test
exercises the same code paths through the library API.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

DP = "/root/work/Sublyne/data-plane/target/x86_64-unknown-linux-musl/release/sublyne-dataplane"
SOCK = "/tmp/dp-check.sock"
if os.path.exists(SOCK):
    os.remove(SOCK)
proc = subprocess.Popen(
    [DP, "--ipc-socket", SOCK], stdout=subprocess.PIPE, stderr=subprocess.PIPE
)

# Wait for socket
for _ in range(50):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)
assert os.path.exists(SOCK), "dataplane never bound socket"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)


def read_frame():
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    n = struct.unpack(">I", hdr)[0]
    body = b""
    while len(body) < n:
        body += s.recv(n - len(body))
    return json.loads(body)


def write_frame(env):
    body = json.dumps(env).encode()
    s.sendall(struct.pack(">I", len(body)) + body)


def send_cmd(ty, payload):
    cid = str(uuid.uuid4())
    write_frame({"type": ty, "id": cid, "payload": payload})
    while True:
        env = read_frame()
        if env.get("type") == "Reply" and env.get("id") == cid:
            return env


ready = read_frame()
print(f"got: {ready['type']} version={ready['payload'].get('version')}")

echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
echo.bind(("127.0.0.1", 39001))


def echo_loop():
    while True:
        try:
            data, addr = echo.recvfrom(4096)
            echo.sendto(data, addr)
        except Exception:
            return


threading.Thread(target=echo_loop, daemon=True).start()

PSK = "stage1-binary-loopback-shared-psk"
r = send_cmd(
    "StartTunnel",
    {
        "id": 2,
        "role": "remote",
        "name": "bin-r",
        "mtu": 1400,
        "psk": PSK,
        "max_connections": 32,
        "idle_timeout_sec": 60,
        "download_transport": "udp",
        "download_spoof_source_ip": "127.0.0.1",
        "download_spoof_source_port": 443,
        "upload_listen_addr": "127.0.0.1:38001",
        "forward_target": "127.0.0.1:39001",
        "download_send_port": 38443,
        "client_real_ip": "127.0.0.1",
    },
)
print(f"remote start: {r['payload']}")
assert r["payload"]["ok"], r["payload"]

c = send_cmd(
    "StartTunnel",
    {
        "id": 1,
        "role": "client",
        "name": "bin-c",
        "mtu": 1400,
        "psk": PSK,
        "max_connections": 32,
        "idle_timeout_sec": 60,
        "download_transport": "udp",
        "download_spoof_source_ip": "127.0.0.1",
        "download_spoof_source_port": 443,
        "local_listen_addr": "127.0.0.1:35001",
        "download_receive_port": 38443,
        "upload_target_addr": "127.0.0.1:38001",
        "wireguard_fwmark": 0,
    },
)
print(f"client start: {c['payload']}")
assert c["payload"]["ok"], c["payload"]

time.sleep(0.2)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", 0))
u.settimeout(2.0)
payload = b"BINARY LOOPBACK PROOF-OF-LIFE 42 bytes for sure"
u.sendto(payload, ("127.0.0.1", 35001))
print(f"sent {len(payload)} bytes -> 127.0.0.1:35001")
try:
    got, src = u.recvfrom(4096)
    print(f"received {len(got)} bytes from {src}")
    print(f"payload match: {got == payload}")
    assert got == payload
    print(
        "PASS - end-user -> client -> remote -> forward_target -> remote -> spoofed UDP -> client -> end-user"
    )
except socket.timeout:
    print("FAIL - no reply within 2s")
    sys.exit(2)

write_frame({"type": "Shutdown", "id": "shut", "payload": {}})
time.sleep(0.2)
s.close()
proc.wait(timeout=5)
print("clean exit")
