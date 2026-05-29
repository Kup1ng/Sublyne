#!/usr/bin/env bash
# PRD §11 acceptance #1: fresh install reaches a working panel
# within 30 seconds.
#
# Assumes:
#   - Running on a clean Ubuntu 22.04 or 24.04 amd64 host.
#   - /tmp/sublyne-linux-amd64 already exists (the operator placed
#     the artifact there, exactly the workflow PRD §9.1 describes).
#   - scripts/setup.sh exists at the path passed via --setup-sh
#     (default ./scripts/setup.sh).
#
# Designed to run idempotently: it Uninstalls (with data deletion)
# at the end so a subsequent CI run starts from the same blank slate.
#
# Exit codes:
#   0  install completed AND panel served HTTP 200 on /healthz
#      within 30 s of `setup.sh` returning.
#   1  preflight failed (wrong OS, missing binary, missing setup.sh)
#   2  setup.sh exited non-zero
#   3  service active but panel did not respond inside 30 s

set -euo pipefail

SETUP_SH="${SETUP_SH:-./scripts/setup.sh}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-acceptance-test-$$}"
ROLE="${ROLE:-client}"
DEADLINE_SECS="${DEADLINE_SECS:-30}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-sh)      SETUP_SH="$2"; shift 2;;
    --setup-sh=*)    SETUP_SH="${1#*=}"; shift;;
    --deadline)      DEADLINE_SECS="$2"; shift 2;;
    --deadline=*)    DEADLINE_SECS="${1#*=}"; shift;;
    -h|--help)
      sed -n '1,/^set/p' "$0" | sed 's/^# \?//' | sed '/^set/d'
      exit 0;;
    *)
      echo "unknown flag: $1" >&2; exit 64;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "FAIL: must run as root (setup.sh writes /etc/sublyne, /usr/local/bin, etc.)" >&2
  exit 1
fi

if [[ ! -f /tmp/sublyne-linux-amd64 ]]; then
  echo "FAIL: /tmp/sublyne-linux-amd64 missing — drop the release artifact there first." >&2
  exit 1
fi

if [[ ! -f "${SETUP_SH}" ]]; then
  echo "FAIL: setup.sh not found at ${SETUP_SH}" >&2
  exit 1
fi

# Pipe the menu selections into setup.sh:
#   1   → Fresh install
#   ${ROLE}
#   ${ADMIN_USER}
#   ${ADMIN_PASS}
#   ${ADMIN_PASS}   (confirm)
#   6   → Exit (after the install runs)
#
# The fresh install always prints the panel URL, port, and creds.
# We capture the port from /etc/sublyne/config.toml afterwards so
# this script doesn't depend on stdout-scraping the installer.
echo "==> Running setup.sh Fresh install"
set +e
printf '1\n%s\n%s\n%s\n%s\n6\n' "${ROLE}" "${ADMIN_USER}" "${ADMIN_PASS}" "${ADMIN_PASS}" \
  | bash "${SETUP_SH}" > /tmp/setup-install.log 2>&1
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
  echo "FAIL: setup.sh exited with code $rc. Log:" >&2
  tail -50 /tmp/setup-install.log >&2 || true
  exit 2
fi

if [[ ! -f /etc/sublyne/config.toml ]]; then
  echo "FAIL: /etc/sublyne/config.toml not written" >&2
  exit 2
fi

# Extract panel_port and web_path. Both are quoted TOML strings; the
# port may be a bare integer. Tolerate both.
PORT=$(awk -F'[ =]+' '/^panel_port/ {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)
WEB=$(awk -F'[ =]+'  '/^web_path/   {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)
if [[ -z "${PORT}" || -z "${WEB}" ]]; then
  echo "FAIL: could not parse panel_port or web_path from /etc/sublyne/config.toml" >&2
  cat /etc/sublyne/config.toml >&2
  exit 2
fi

# Poll /healthz with a hard deadline.
URL="http://127.0.0.1:${PORT}/${WEB}/healthz"
echo "==> Polling ${URL} for up to ${DEADLINE_SECS}s"
start=$(date +%s)
while : ; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${URL}" || echo 000)
  if [[ "${code}" == "200" ]]; then
    elapsed=$(( $(date +%s) - start ))
    echo "PASS: panel served 200 on /healthz after ${elapsed}s"
    exit 0
  fi
  now=$(date +%s)
  if (( now - start >= DEADLINE_SECS )); then
    echo "FAIL: panel did not return 200 within ${DEADLINE_SECS}s (last code: ${code})" >&2
    systemctl status sublyne --no-pager -l | head -30 >&2 || true
    journalctl -u sublyne --no-pager --since "2 minutes ago" | tail -20 >&2 || true
    exit 3
  fi
  sleep 1
done
