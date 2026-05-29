#!/usr/bin/env bash
# Operator acceptance check: after `setup.sh` finishes a Fresh install
# (or an Update / Reinstall), this script asserts that the running
# service is actually serving traffic AND that the embedded Rust data
# plane successfully forked, executed, and reached Ready over IPC.
#
# Why this exists: a Go control plane that has no usable data plane
# still serves the panel and `/healthz` — it just silently fails to
# move any packets. Phase 8a originally shipped that hole; one
# regression caused a fork/exec EACCES on `/run/sublyne/dataplane`
# because systemd mounts /run with `noexec`. This check would have
# caught it.
#
# Exit codes:
#   0  service active AND dataplane Ready observed within `--since`
#   1  service is not active
#   2  service is active but no Ready event in the journal window
#   3  service is active but the journal contains permission errors
#      that indicate the dataplane never started cleanly
#
# Usage:
#   sudo ./scripts/check_systemd_install.sh              # default: last 5 minutes
#   sudo ./scripts/check_systemd_install.sh --since 30s  # arbitrary journalctl --since value
#
# Designed to be re-run safely (e.g., from CI on a real test VM, or
# from the operator's shell after `systemctl restart sublyne`).

set -euo pipefail

SINCE="5m"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)
      SINCE="$2"; shift 2;;
    --since=*)
      SINCE="${1#*=}"; shift;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0;;
    *)
      echo "unknown flag: $1" >&2
      exit 64;;
  esac
done

# (1) Service must be active. Without this every later check is noise.
if ! systemctl is-active --quiet sublyne; then
  echo "FAIL: sublyne.service is not active." >&2
  systemctl status sublyne --no-pager -l | sed 's/^/    /' >&2 || true
  exit 1
fi
echo "OK: sublyne.service is active."

# (2) Sweep the journal for any sign the dataplane silently failed.
#     The exact lines this string-matches are the supervisor's own
#     error messages from control-plane/internal/ipc/supervisor.go.
JOURNAL=$(journalctl -u sublyne --since "${SINCE} ago" --no-pager 2>/dev/null || true)

if grep -q 'restart budget exhausted' <<<"${JOURNAL}"; then
  echo "FAIL: dataplane supervisor exhausted its restart budget. Recent errors:" >&2
  grep -E 'dataplane attempt failed|restart budget' <<<"${JOURNAL}" | tail -5 | sed 's/^/    /' >&2
  exit 3
fi
if grep -q 'permission denied' <<<"${JOURNAL}"; then
  echo "FAIL: 'permission denied' in the dataplane journal. Recent matches:" >&2
  grep 'permission denied' <<<"${JOURNAL}" | tail -5 | sed 's/^/    /' >&2
  exit 3
fi

# (3) Positive signal: the supervisor's "dataplane up" line (from
#     supervisor.go's startOnce after Ready arrives) must appear at
#     least once in the journal window.
if ! grep -q 'ipc: dataplane up' <<<"${JOURNAL}"; then
  echo "FAIL: no 'ipc: dataplane up' line in the last ${SINCE} of journal." >&2
  echo "       The control plane is running but the Rust dataplane never reached Ready." >&2
  echo "       Last 10 sublyne.service lines:" >&2
  tail -10 <<<"${JOURNAL}" | sed 's/^/    /' >&2
  exit 2
fi
READY_LINE=$(grep 'ipc: dataplane up' <<<"${JOURNAL}" | tail -1)
echo "OK: dataplane reached Ready -> ${READY_LINE}"

# (4) Extra sanity: the extracted binary must live on an exec-able
#     filesystem. Find it via the supervisor's known production path
#     and confirm the mount it's on doesn't carry `noexec`. This
#     turns a silent runtime failure into a loud operator-visible
#     diagnostic.
BIN=/var/lib/sublyne/dataplane
if [[ -f "${BIN}" ]]; then
  MOUNT_OPTS=$(findmnt -n -o OPTIONS --target "${BIN}" 2>/dev/null || true)
  if [[ "${MOUNT_OPTS}" == *noexec* ]]; then
    echo "FAIL: ${BIN} is on a mount with noexec (${MOUNT_OPTS}); fork/exec will fail." >&2
    exit 3
  fi
  echo "OK: ${BIN} is on an exec-able mount (${MOUNT_OPTS})."
fi

echo "PASS: sublyne.service is healthy and the dataplane is running."
