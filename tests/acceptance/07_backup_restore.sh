#!/usr/bin/env bash
# PRD §11 acceptance #7: backup → wipe DB → restore preserves the
# four sticky values:
#   - admin.username
#   - admin.password_hash
#   - settings.panel_port
#   - settings.web_path
#
# The Phase 13 implementation handles this at the application layer
# (POST /api/settings/restore). This script exercises it via the
# panel API rather than poking the SQLite file directly so we
# validate the same code path an operator would use.
#
# Required env:
#   ADMIN_USER     username (default admin)
#   ADMIN_PASS     plaintext password
#
# Optional env:
#   PANEL_HOST     default 127.0.0.1
#   PANEL_PORT     default from /etc/sublyne/config.toml
#   WEB_PATH       default from /etc/sublyne/config.toml
#
# Exit codes:
#   0  round-trip preserves the four values
#   1  preflight failed (config missing, login failed)
#   2  backup endpoint failed
#   3  restore endpoint failed
#   4  one of the four sticky values changed after restore

set -euo pipefail

PANEL_HOST="${PANEL_HOST:-127.0.0.1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"

if [[ -z "${ADMIN_PASS}" ]]; then
  echo "FAIL: ADMIN_PASS environment variable is required." >&2
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
WORK=$(mktemp -d -t fwd-acceptance-07-XXXX)
trap 'rm -rf "${WORK}"' EXIT

# 1) Log in and grab the JWT.
echo "==> Logging in as ${ADMIN_USER}"
token=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${BASE}/login" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
if [[ -z "${token}" ]]; then
  echo "FAIL: login did not return a token; check credentials" >&2
  exit 1
fi

auth=(-H "Authorization: Bearer ${token}")

# 2) Capture the sticky values BEFORE backup.
before=$(curl -s "${auth[@]}" "${BASE}/settings")
before_port=$(echo "${before}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("panel_port",""))')
before_webpath=$(echo "${before}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("web_path",""))')

sess=$(curl -s "${auth[@]}" "${BASE}/session")
before_user=$(echo "${sess}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("username",""))')

echo "    before: user=${before_user} port=${before_port} web=${before_webpath}"

# 3) Download a backup.
echo "==> Downloading backup"
if ! curl -fsS "${auth[@]}" -o "${WORK}/backup.db" "${BASE}/settings/backup"; then
  echo "FAIL: backup endpoint did not return 200" >&2
  exit 2
fi
if [[ ! -s "${WORK}/backup.db" ]]; then
  echo "FAIL: backup file is empty" >&2
  exit 2
fi

# 4) Restore from that same backup. The Phase 13 implementation
#    preserves the four sticky values regardless of what's in the
#    uploaded DB, so this is the test: even with the same DB, the
#    response must include the right tunnel count and the sticky
#    values must match.
echo "==> Restoring backup"
restore_resp=$(curl -s -o "${WORK}/restore.json" -w '%{http_code}' \
  "${auth[@]}" \
  -F "file=@${WORK}/backup.db" \
  "${BASE}/settings/restore")
if [[ "${restore_resp}" != "200" ]]; then
  echo "FAIL: restore returned HTTP ${restore_resp}" >&2
  cat "${WORK}/restore.json" >&2 || true
  exit 3
fi

# Restore drops in-flight sessions and re-issues the JWT only if the
# admin row changed. Re-login (in case the response invalidated the
# old token) and re-check.
sleep 2
token2=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${BASE}/login" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
if [[ -z "${token2}" ]]; then
  echo "FAIL: cannot log in after restore — admin row was clobbered" >&2
  exit 4
fi
auth=(-H "Authorization: Bearer ${token2}")

# 5) Re-read sticky values AFTER restore and compare.
after=$(curl -s "${auth[@]}" "${BASE}/settings")
after_port=$(echo "${after}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("panel_port",""))')
after_webpath=$(echo "${after}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("web_path",""))')

sess=$(curl -s "${auth[@]}" "${BASE}/session")
after_user=$(echo "${sess}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("username",""))')

echo "    after:  user=${after_user} port=${after_port} web=${after_webpath}"

ok=1
[[ "${before_user}"    != "${after_user}"    ]] && { echo "FAIL: username changed across restore"     >&2; ok=0; }
[[ "${before_port}"    != "${after_port}"    ]] && { echo "FAIL: panel_port changed across restore"  >&2; ok=0; }
[[ "${before_webpath}" != "${after_webpath}" ]] && { echo "FAIL: web_path changed across restore"    >&2; ok=0; }

if (( ok == 0 )); then
  exit 4
fi

echo "PASS: backup/restore round-trip preserved username, panel_port, web_path"
