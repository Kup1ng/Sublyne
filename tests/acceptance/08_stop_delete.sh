#!/usr/bin/env bash
# PRD §11 acceptance #8: Stop / Delete frees the listener
# immediately. After a tunnel is disabled the OS must no longer
# show our process bound to its `local_listen_addr` port within 2 s.
#
# This requires:
#   - At least one tunnel exists in the DB, and the test can read its
#     local_listen_addr via /api/tunnels.
#   - The test admin can authenticate.
#
# Required env:
#   ADMIN_USER, ADMIN_PASS, TUNNEL_ID (numeric; the script targets
#   this specific row so it doesn't accidentally stop a tunnel the
#   operator was using).
#
# Optional env:
#   PANEL_HOST  default 127.0.0.1
#   PANEL_PORT  default from /etc/sublyne/config.toml
#   WEB_PATH    default from /etc/sublyne/config.toml
#
# Exit codes:
#   0  port was released within 2 s
#   1  preflight failed
#   2  start / stop API call failed
#   3  port still bound 2 s after stop

set -euo pipefail

PANEL_HOST="${PANEL_HOST:-127.0.0.1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
TUNNEL_ID="${TUNNEL_ID:-}"

if [[ -z "${ADMIN_PASS}" || -z "${TUNNEL_ID}" ]]; then
  echo "FAIL: ADMIN_PASS and TUNNEL_ID env vars are required." >&2
  exit 1
fi
if [[ -z "${PANEL_PORT:-}" || -z "${WEB_PATH:-}" ]]; then
  if [[ ! -f /etc/sublyne/config.toml ]]; then
    echo "FAIL: /etc/sublyne/config.toml missing; set PANEL_PORT/WEB_PATH explicitly." >&2
    exit 1
  fi
  PANEL_PORT="${PANEL_PORT:-$(awk -F'[ =]+' '/^panel_port/ {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)}"
  WEB_PATH="${WEB_PATH:-$(awk -F'[ =]+'  '/^web_path/   {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)}"
fi

BASE="http://${PANEL_HOST}:${PANEL_PORT}/${WEB_PATH}/api"

# 1) Authenticate.
token=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${BASE}/login" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
if [[ -z "${token}" ]]; then
  echo "FAIL: login did not return a token." >&2
  exit 1
fi
auth=(-H "Authorization: Bearer ${token}")

# 2) Read the target tunnel's local_listen_addr.
tunnel=$(curl -s "${auth[@]}" "${BASE}/tunnels/${TUNNEL_ID}")
addr=$(echo "${tunnel}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("local_listen_addr") or d.get("upload_listen_addr") or "")')
if [[ -z "${addr}" ]]; then
  echo "FAIL: could not read local_listen_addr (Client) or upload_listen_addr (Remote) for tunnel ${TUNNEL_ID}" >&2
  echo "${tunnel}" >&2
  exit 1
fi
# Parse host:port — we only care about the port for the ss check.
port="${addr##*:}"
if [[ -z "${port}" || "${port}" == "${addr}" ]]; then
  echo "FAIL: cannot parse port from ${addr}" >&2
  exit 1
fi

# 3) Start the tunnel.
echo "==> Starting tunnel ${TUNNEL_ID} (listen port ${port})"
rc=$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" -X POST "${BASE}/tunnels/${TUNNEL_ID}/start")
if [[ "${rc}" != "200" ]]; then
  echo "FAIL: /start returned HTTP ${rc}" >&2
  exit 2
fi
sleep 1

# Confirm the listener is up.
if ! ss -lunp 2>/dev/null | awk '{print $5}' | grep -q ":${port}\$"; then
  echo "FAIL: tunnel started but no UDP listener on :${port}" >&2
  ss -lunp >&2
  exit 2
fi
echo "    listener up on :${port}"

# 4) Stop the tunnel.
echo "==> Stopping tunnel ${TUNNEL_ID}"
rc=$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" -X POST "${BASE}/tunnels/${TUNNEL_ID}/stop")
if [[ "${rc}" != "200" ]]; then
  echo "FAIL: /stop returned HTTP ${rc}" >&2
  exit 2
fi

# 5) Poll for up to 2 s — the listener must vanish.
echo "==> Waiting up to 2 s for :${port} to disappear"
start=$(date +%s%N)
while : ; do
  if ! ss -lunp 2>/dev/null | awk '{print $5}' | grep -q ":${port}\$"; then
    elapsed_ns=$(( $(date +%s%N) - start ))
    elapsed_ms=$(( elapsed_ns / 1000000 ))
    echo "PASS: listener freed within ${elapsed_ms} ms"
    exit 0
  fi
  elapsed_ns=$(( $(date +%s%N) - start ))
  if (( elapsed_ns > 2000000000 )); then
    echo "FAIL: listener still bound on :${port} after 2 s" >&2
    ss -lunp >&2
    exit 3
  fi
  sleep 0.1
done
