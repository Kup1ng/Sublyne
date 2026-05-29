#!/usr/bin/env bash
# CI sandbox test for scripts/setup.sh.
#
# Why this exists: the production setup.sh runs as root, manipulates
# /etc, /var, /usr/local, and systemd, which we cannot do inside the
# GitHub Actions worker without rooting it. This harness flips the
# SUBLYNE_TEST_* environment variables that setup.sh honors to redirect
# every install path under a sandbox tree and no-op the calls that
# need privilege (systemctl, useradd, chown, sysctl --system, healthz
# probe).
#
# The harness exercises every menu option that Phase 14 wires up:
#
#   1) Fresh install  — verifies binary, config.toml, bootstrap-admin
#                       file, systemd unit, sysctl conf are written.
#   2) Update         — verifies the binary is replaced atomically and
#                       the service is restarted (logged via
#                       maybe_systemctl).
#   3) Reinstall      — verifies the systemd unit is re-written and
#                       the service is daemon-reloaded + restarted.
#   4) Uninstall      — verifies binary, unit, sysctl conf are removed
#                       and (with data-wipe) /etc/sublyne, /var/lib/
#                       sublyne, and /run/sublyne are gone too.
#   5) Status         — verifies role / version / panel URL render
#                       against the installed config.
#
# Each test is independent: a fresh sandbox per case. Failing the
# overall run is an explicit `exit 1` from inside a function so the
# operator sees which case broke.
#
# Usage:
#     ./scripts/test-setup-menus.sh                # all cases
#     ./scripts/test-setup-menus.sh fresh_install  # one case

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SETUP_SH="$SCRIPT_DIR/setup.sh"

if [ ! -x "$SETUP_SH" ]; then
  chmod +x "$SETUP_SH"
fi

# Tests fan out into per-case sandboxes under a single root so an
# `ls` reveals which cases ran.
SANDBOX_ROOT="${SANDBOX_ROOT:-$(mktemp -d -t sublyne-setup-test.XXXXXX)}"
trap 'cleanup_sandboxes' EXIT
cleanup_sandboxes() {
  # KEEP_SANDBOX=1 ./test-setup-menus.sh   # for post-mortem debugging
  if [ -n "${KEEP_SANDBOX:-}" ]; then
    echo
    echo "Preserved sandbox tree at: $SANDBOX_ROOT"
    return
  fi
  rm -rf "$SANDBOX_ROOT"
}

# ----- Fake sublyne binary ------------------------------------------------
#
# The harness needs a `sublyne-linux-amd64` artifact for the Fresh
# install / Update / Reinstall paths to copy into place. A tiny shell
# script is enough: setup.sh only invokes --version (for sanity check
# and Status), --tear-down (for Uninstall), and --show-admin-username
# (for Status). Each is faked here. The script is portable shell so it
# runs on the CI runner without needing a cross-compile.

make_fake_binary() {
  local out="$1" version="$2"
  cat > "$out" <<EOF
#!/usr/bin/env bash
# Fake sublyne binary for setup.sh menu tests.
case "\${1:-}" in
  --version)
    echo "sublyne ${version}"
    exit 0
    ;;
  --tear-down)
    echo "fake-sublyne: tear-down (no-op)"
    exit 0
    ;;
  --config)
    # Match setup.sh's calling form: --config <path> --show-admin-username
    shift 2
    case "\${1:-}" in
      --show-admin-username)
        echo "operator-1"
        exit 0
        ;;
      *)
        echo "fake-sublyne: unsupported flag \${1:-}"
        exit 2
        ;;
    esac
    ;;
  *)
    echo "fake-sublyne: unsupported invocation \$*"
    exit 2
    ;;
esac
EOF
  chmod +x "$out"
}

# ----- Sandbox setup ------------------------------------------------------
#
# Every case runs in its own subdirectory so leftover state from one
# test doesn't bleed into the next. The env vars below are read by
# setup.sh at the top of the script — they MUST be exported BEFORE we
# invoke it.

setup_sandbox() {
  local case_name="$1" version="${2:-0.0.0-test}"
  local root="$SANDBOX_ROOT/$case_name"
  mkdir -p "$root/tmp" "$root/usr/local/bin"
  # Pre-stage the "downloaded" artifact at /tmp/sublyne-linux-amd64
  # inside the sandbox.
  make_fake_binary "$root/tmp/sublyne-linux-amd64" "$version"
  printf '%s\n' "$root"
}

run_setup() {
  # Pipe the menu choice + any prompt answers into setup.sh's stdin.
  # The harness uses heredoc so quoting is sane and the input order
  # exactly matches setup.sh's read calls.
  local root="$1" input_stream="$2"
  SUBLYNE_TEST_ROOT="$root" \
  SUBLYNE_TEST_SKIP_OS_CHECK=1 \
  SUBLYNE_TEST_SKIP_ROOT_CHECK=1 \
  SUBLYNE_TEST_SKIP_SYSTEMCTL=1 \
  SUBLYNE_TEST_SKIP_USERADD=1 \
  SUBLYNE_TEST_SKIP_SYSCTL=1 \
  SUBLYNE_TEST_SKIP_HEALTHCHECK=1 \
  SUBLYNE_TEST_SKIP_CHOWN=1 \
    bash "$SETUP_SH" <<< "$input_stream"
}

# ----- Assertions ---------------------------------------------------------

assert_file() {
  if [ ! -f "$1" ]; then
    echo "FAIL: expected file $1 to exist" >&2
    exit 1
  fi
}

assert_no_file() {
  if [ -e "$1" ]; then
    echo "FAIL: expected $1 to be absent" >&2
    exit 1
  fi
}

assert_dir() {
  if [ ! -d "$1" ]; then
    echo "FAIL: expected dir $1 to exist" >&2
    exit 1
  fi
}

assert_no_dir() {
  if [ -e "$1" ]; then
    echo "FAIL: expected dir $1 to be absent" >&2
    exit 1
  fi
}

assert_contains() {
  local file="$1" needle="$2"
  if ! grep -q -F -- "$needle" "$file"; then
    echo "FAIL: expected '$needle' in $file" >&2
    echo "--- file contents ---" >&2
    cat "$file" >&2
    echo "----------------------" >&2
    exit 1
  fi
}

assert_output_contains() {
  local output="$1" needle="$2"
  if ! printf '%s\n' "$output" | grep -q -F -- "$needle"; then
    echo "FAIL: expected output to contain '$needle'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$output" >&2
    echo "------------------------" >&2
    exit 1
  fi
}

# ----- Cases --------------------------------------------------------------

case_fresh_install() {
  echo "==> case_fresh_install"
  local root
  root="$(setup_sandbox fresh_install 0.0.1-test)"

  local out
  # Menu input order:
  #   "1\n"  → option 1 (Fresh install)
  #   "client\n"     → Role prompt
  #   "admin\n"      → Admin username prompt (default)
  #   "p@ss-1234\n"  → password
  #   "p@ss-1234\n"  → password confirm
  out="$(run_setup "$root" "$(printf '1\nclient\nadmin\np@ss-1234\np@ss-1234\n')")"

  assert_file "$root/usr/local/bin/sublyne"
  assert_file "$root/etc/sublyne/config.toml"
  assert_file "$root/etc/sublyne/bootstrap-admin.toml"
  assert_file "$root/etc/systemd/system/sublyne.service"
  assert_file "$root/etc/sysctl.d/99-sublyne.conf"
  assert_dir  "$root/var/lib/sublyne/logs"
  assert_dir  "$root/run/sublyne"

  assert_contains "$root/etc/sublyne/config.toml" 'role        = "client"'
  assert_contains "$root/etc/sublyne/bootstrap-admin.toml" 'username = "admin"'
  assert_contains "$root/etc/sublyne/bootstrap-admin.toml" 'password = "p@ss-1234"'
  assert_contains "$root/etc/systemd/system/sublyne.service" 'ExecStart=/usr/local/bin/sublyne'
  assert_contains "$root/etc/systemd/system/sublyne.service" 'AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN'
  assert_contains "$root/etc/sysctl.d/99-sublyne.conf" 'net.core.rmem_max'

  assert_output_contains "$out" 'Installation complete.'
  assert_output_contains "$out" 'Admin user:  admin'
  echo "    PASS"
}

case_update() {
  echo "==> case_update"
  local root
  root="$(setup_sandbox update 0.0.1-test)"

  # First, get a fresh install in place so Update has something to
  # replace.
  run_setup "$root" "$(printf '1\nclient\nadmin\nold-pass\nold-pass\n')" >/dev/null

  # Read what version is currently installed.
  local installed_before
  installed_before="$("$root/usr/local/bin/sublyne" --version | head -n1)"
  assert_output_contains "$installed_before" 'sublyne 0.0.1-test'

  # Stage a "new" artifact with a different version string at the same
  # path setup.sh expects.
  make_fake_binary "$root/tmp/sublyne-linux-amd64" 0.0.2-test

  # Run option 2 (Update). No prompts.
  local out
  out="$(run_setup "$root" "$(printf '2\n')")"

  # Verify the binary now reports the new version.
  local installed_after
  installed_after="$("$root/usr/local/bin/sublyne" --version | head -n1)"
  assert_output_contains "$installed_after" 'sublyne 0.0.2-test'

  # Sandbox config + data should still be in place.
  assert_file "$root/etc/sublyne/config.toml"
  assert_file "$root/etc/sublyne/bootstrap-admin.toml"

  # systemctl restart should have been invoked via the harness no-op.
  assert_output_contains "$out" '[skip-systemctl] systemctl restart sublyne.service'
  assert_output_contains "$out" 'Update complete.'
  echo "    PASS"
}

case_update_rejects_corrupt_binary() {
  echo "==> case_update_rejects_corrupt_binary"
  local root
  root="$(setup_sandbox update_corrupt 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Replace the staged artifact with one that does NOT respond to
  # --version cleanly. setup.sh's sanity check should refuse to swap.
  cat > "$root/tmp/sublyne-linux-amd64" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
  chmod +x "$root/tmp/sublyne-linux-amd64"

  local original_size
  original_size="$(stat -c %s "$root/usr/local/bin/sublyne")"

  local out exit_code=0
  out="$(run_setup "$root" "$(printf '2\n')" 2>&1)" || exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    echo "FAIL: Update should have failed on a corrupt binary" >&2
    echo "$out" >&2
    exit 1
  fi

  assert_output_contains "$out" 'failed to run --version'

  # The installed binary must NOT have been touched.
  local current_size
  current_size="$(stat -c %s "$root/usr/local/bin/sublyne")"
  if [ "$current_size" != "$original_size" ]; then
    echo "FAIL: installed binary was replaced even though sanity-check failed" >&2
    exit 1
  fi
  echo "    PASS"
}

case_reinstall() {
  echo "==> case_reinstall"
  local root
  root="$(setup_sandbox reinstall 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Wipe the systemd unit so we can confirm reinstall recreates it
  # (and not just leaves the existing one in place).
  rm -f "$root/etc/systemd/system/sublyne.service"
  assert_no_file "$root/etc/systemd/system/sublyne.service"

  make_fake_binary "$root/tmp/sublyne-linux-amd64" 0.0.3-test

  local out
  out="$(run_setup "$root" "$(printf '3\n')")"

  assert_file "$root/etc/systemd/system/sublyne.service"
  assert_contains "$root/etc/systemd/system/sublyne.service" 'ExecStart=/usr/local/bin/sublyne'

  local installed_after
  installed_after="$("$root/usr/local/bin/sublyne" --version | head -n1)"
  assert_output_contains "$installed_after" 'sublyne 0.0.3-test'

  # Config + data preserved.
  assert_file "$root/etc/sublyne/config.toml"
  assert_dir  "$root/var/lib/sublyne/logs"

  assert_output_contains "$out" '[skip-systemctl] systemctl daemon-reload'
  assert_output_contains "$out" '[skip-systemctl] systemctl restart sublyne.service'
  assert_output_contains "$out" 'Reinstall complete.'
  echo "    PASS"
}

case_uninstall_keep_data() {
  echo "==> case_uninstall_keep_data"
  local root
  root="$(setup_sandbox uninstall_keep 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Menu input order:
  #   "4\n" → option 4 (Uninstall)
  #   "y\n" → confirm "Uninstall sublyne?"
  #   "n\n" → DON'T delete data
  local out
  out="$(run_setup "$root" "$(printf '4\ny\nn\n')")"

  assert_no_file "$root/usr/local/bin/sublyne"
  assert_no_file "$root/etc/systemd/system/sublyne.service"
  assert_no_file "$root/etc/sysctl.d/99-sublyne.conf"

  # With "n" to the data prompt, /etc/sublyne and /var/lib/sublyne must
  # survive.
  assert_dir "$root/etc/sublyne"
  assert_file "$root/etc/sublyne/config.toml"
  assert_dir "$root/var/lib/sublyne"

  assert_output_contains "$out" 'Data preserved at:'
  assert_output_contains "$out" 'Uninstall complete.'
  echo "    PASS"
}

case_uninstall_wipe_data() {
  echo "==> case_uninstall_wipe_data"
  local root
  root="$(setup_sandbox uninstall_wipe 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Menu input order:
  #   "4\n" → option 4 (Uninstall)
  #   "y\n" → confirm "Uninstall sublyne?"
  #   "y\n" → confirm data wipe
  local out
  out="$(run_setup "$root" "$(printf '4\ny\ny\n')")"

  assert_no_file "$root/usr/local/bin/sublyne"
  assert_no_file "$root/etc/systemd/system/sublyne.service"
  assert_no_dir  "$root/etc/sublyne"
  assert_no_dir  "$root/var/lib/sublyne"
  assert_no_dir  "$root/run/sublyne"

  assert_output_contains "$out" 'Removing'
  assert_output_contains "$out" 'Uninstall complete.'
  echo "    PASS"
}

case_uninstall_abort() {
  echo "==> case_uninstall_abort"
  local root
  root="$(setup_sandbox uninstall_abort 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Menu input order:
  #   "4\n" → option 4 (Uninstall)
  #   "n\n" → abort confirmation
  local out
  out="$(run_setup "$root" "$(printf '4\nn\n')")"

  # Everything must still exist; the abort short-circuited.
  assert_file "$root/usr/local/bin/sublyne"
  assert_file "$root/etc/systemd/system/sublyne.service"
  assert_dir "$root/etc/sublyne"

  assert_output_contains "$out" 'Aborted.'
  echo "    PASS"
}

case_status() {
  echo "==> case_status"
  local root
  root="$(setup_sandbox status 0.0.1-test)"
  run_setup "$root" "$(printf '1\nclient\nadmin\npass-1234\npass-1234\n')" >/dev/null

  # Menu input order:
  #   "5\n" → option 5 (Status)
  local out
  out="$(run_setup "$root" "$(printf '5\n')")"

  assert_output_contains "$out" 'Version:'
  assert_output_contains "$out" 'sublyne 0.0.1-test'
  assert_output_contains "$out" 'Role:          client'
  assert_output_contains "$out" 'Admin user:    operator-1'
  assert_output_contains "$out" 'Panel URL:     http'
  echo "    PASS"
}

case_status_no_install() {
  echo "==> case_status_no_install"
  local root
  root="$(setup_sandbox status_no_install 0.0.1-test)"

  local out
  out="$(run_setup "$root" "$(printf '5\n')")"

  assert_output_contains "$out" 'Not installed'
  echo "    PASS"
}

case_menu_invalid_choice() {
  echo "==> case_menu_invalid_choice"
  local root
  root="$(setup_sandbox menu_invalid 0.0.1-test)"

  local out exit_code=0
  out="$(run_setup "$root" "$(printf '9\n')" 2>&1)" || exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    echo "FAIL: invalid menu choice should exit non-zero" >&2
    echo "$out" >&2
    exit 1
  fi
  assert_output_contains "$out" 'Invalid choice'
  echo "    PASS"
}

# ----- Runner -------------------------------------------------------------

CASES=(
  case_fresh_install
  case_update
  case_update_rejects_corrupt_binary
  case_reinstall
  case_uninstall_keep_data
  case_uninstall_wipe_data
  case_uninstall_abort
  case_status
  case_status_no_install
  case_menu_invalid_choice
)

run_one() {
  local arg="$1"
  for c in "${CASES[@]}"; do
    if [ "${c#case_}" = "$arg" ] || [ "$c" = "$arg" ]; then
      "$c"
      return
    fi
  done
  echo "Unknown case: $arg" >&2
  echo "Available:" >&2
  for c in "${CASES[@]}"; do
    echo "  ${c#case_}" >&2
  done
  exit 64
}

main() {
  echo "Sandbox root: $SANDBOX_ROOT"
  if [ $# -gt 0 ]; then
    for arg in "$@"; do
      run_one "$arg"
    done
  else
    for c in "${CASES[@]}"; do
      "$c"
    done
  fi
  echo
  echo "All setup.sh menu cases passed."
}

main "$@"
