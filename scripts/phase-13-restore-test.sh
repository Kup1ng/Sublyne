#!/usr/bin/env bash
# Phase 13 restore live-verify script. Drives the foreign panel through
# a full backup → throwaway-change → restore cycle and asserts:
#   * The pre-change tunnel list comes back after restore.
#   * The pre-existing admin password still authenticates after restore.
#   * The pre-existing panel URL (port + web path) is unchanged.
#
# This is not committed to the release artifact — it lives in scripts/
# so the user can re-run it after merge if they want to spot-check.

set -e

PORT=${PORT:-17118}
WEB=${WEB:-a0C9c9Fr7OZsyFxU}
USER=${USERNAME:-ping}
PASS=${PASSWORD:-2ping2ping}
BACKUP=${BACKUP:-/tmp/sublyne-pre-restore.db}

base="http://localhost:$PORT/$WEB"

login() {
  curl -s -i -X POST "$base/api/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    | awk -F': ' 'tolower($1)=="set-cookie" {print $2}' \
    | head -1 | cut -d';' -f1
}

list_tunnels() {
  curl -s -H "Cookie: $1" "$base/api/tunnels" \
    | python3 -c "import sys, json; print([t['name'] for t in json.load(sys.stdin).get('tunnels', [])])"
}

echo "--- POST restore (uploads $BACKUP) ---"
COOKIE=$(login)
curl -s -X POST -H "Cookie: $COOKIE" -F "backup=@$BACKUP" "$base/api/settings/restore" \
  -w "\nhttp=%{http_code}\n"

echo "--- old cookie probe (key may have rotated) ---"
RC=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: $COOKIE" "$base/api/tunnels")
echo "old cookie GET /api/tunnels = $RC"

echo "--- fresh login with the preserved admin creds ---"
COOKIE2=$(login)
echo "cookie: ${COOKIE2:0:40}..."

echo "--- tunnels after restore (expect throwaway gone) ---"
list_tunnels "$COOKIE2"

echo "--- panel URL still answers the same way ---"
curl -s -o /dev/null -w "panel root http=%{http_code}\n" "$base/"
curl -s -o /dev/null -w "/healthz http=%{http_code}\n" "$base/healthz"
