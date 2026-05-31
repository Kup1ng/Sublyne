#!/usr/bin/env bash
# Sublyne installer (PRD §9).
#
# Run as root on Ubuntu 22.04 or 24.04 amd64. The operator workflow:
#
#     # First time, or after downloading a new release:
#     curl -L -o /tmp/sublyne-linux-amd64 \
#         https://github.com/Kup1ng/Sublyne/releases/latest/download/sublyne-linux-amd64
#     curl -L -o /root/setup.sh \
#         https://github.com/Kup1ng/Sublyne/releases/latest/download/setup.sh
#     chmod +x /root/setup.sh
#     sudo /root/setup.sh
#
# Menu (PRD §9.2):
#   1) Fresh install
#   2) Update             — replaces /usr/local/bin/sublyne with
#                           /tmp/sublyne-linux-amd64, restarts the
#                           service, keeps all data + credentials.
#   3) Reinstall          — replaces binary + recreates the systemd
#                           unit, keeps all data + credentials.
#   4) Uninstall          — stops + disables the service, removes the
#                           binary and unit, runs `sublyne --tear-down`
#                           to remove WG interfaces / ip rules / nft
#                           rules, then asks whether to delete data.
#   5) Show status / credentials / panel URL
#   6) Exit
#
# Phase 14 wires up options 2-5; option 1 has been in place since
# Phase 2.

set -euo pipefail

# ----- Test seams ---------------------------------------------------------
#
# Production operators never set the SUBLYNE_TEST_* variables below.
# scripts/test-setup-menus.sh sets them so a CI runner without root,
# without systemd, and without an actual `sublyne` binary can still
# exercise every menu path against a sandbox directory tree.
#
#   SUBLYNE_TEST_ROOT             prefixed onto every install path
#                                 (binary, /etc/sublyne, /var/lib/sublyne,
#                                 /run/sublyne, systemd unit, sysctl conf).
#                                 Empty in production = absolute paths.
#   SUBLYNE_TEST_SKIP_OS_CHECK    skip the Ubuntu 22/24 + amd64 gate.
#   SUBLYNE_TEST_SKIP_ROOT_CHECK  skip the "must be root" gate.
#   SUBLYNE_TEST_SKIP_SYSTEMCTL   no-op every systemctl call (CI doesn't
#                                 have a running systemd; the test
#                                 verifies file-system state instead).
#   SUBLYNE_TEST_SKIP_USERADD     no-op useradd / groupadd / userdel /
#                                 groupdel; CI runs as an unprivileged
#                                 user that can't manage system accounts.
#   SUBLYNE_TEST_SKIP_SYSCTL      no-op `sysctl --system` reload; CI's
#                                 kernel parameters are not ours to touch.
#   SUBLYNE_TEST_SKIP_HEALTHCHECK skip the post-restart healthz wait
#                                 (the fake binary in CI doesn't serve
#                                 HTTP).
#   SUBLYNE_TEST_SKIP_CHOWN       no-op `chown` calls so the sandbox
#                                 owner stays as the invoking test user.

SUBLYNE_TEST_ROOT="${SUBLYNE_TEST_ROOT:-}"
SUBLYNE_TEST_SKIP_OS_CHECK="${SUBLYNE_TEST_SKIP_OS_CHECK:-}"
SUBLYNE_TEST_SKIP_ROOT_CHECK="${SUBLYNE_TEST_SKIP_ROOT_CHECK:-}"
SUBLYNE_TEST_SKIP_SYSTEMCTL="${SUBLYNE_TEST_SKIP_SYSTEMCTL:-}"
SUBLYNE_TEST_SKIP_USERADD="${SUBLYNE_TEST_SKIP_USERADD:-}"
SUBLYNE_TEST_SKIP_SYSCTL="${SUBLYNE_TEST_SKIP_SYSCTL:-}"
SUBLYNE_TEST_SKIP_HEALTHCHECK="${SUBLYNE_TEST_SKIP_HEALTHCHECK:-}"
SUBLYNE_TEST_SKIP_CHOWN="${SUBLYNE_TEST_SKIP_CHOWN:-}"

# ----- Paths --------------------------------------------------------------

BINARY_SRC="${SUBLYNE_TEST_ROOT}/tmp/sublyne-linux-amd64"
BINARY_DEST="${SUBLYNE_TEST_ROOT}/usr/local/bin/sublyne"
ETC_DIR="${SUBLYNE_TEST_ROOT}/etc/sublyne"
CONFIG_PATH="${ETC_DIR}/config.toml"
BOOTSTRAP_PATH="${ETC_DIR}/bootstrap-admin.toml"
DATA_DIR="${SUBLYNE_TEST_ROOT}/var/lib/sublyne"
LOGS_DIR="${DATA_DIR}/logs"
RUNTIME_DIR="${SUBLYNE_TEST_ROOT}/run/sublyne"
SERVICE_FILE="${SUBLYNE_TEST_ROOT}/etc/systemd/system/sublyne.service"
SYSCTL_FILE="${SUBLYNE_TEST_ROOT}/etc/sysctl.d/99-sublyne.conf"

SERVICE_USER="sublyne"
SERVICE_GROUP="sublyne"

# Per-socket buffer target. Matches sublyne-dataplane's
# SUBLYNE_SOCKET_BUF_BYTES default (4 MiB). The kernel limits below
# must be at least this big or setsockopt(SO_RCVBUF) gets silently
# clamped — see data-plane/src/perf.rs for the rationale.
SOCKET_BUF_BYTES=4194304
SYSCTL_RMEM_MAX=16777216
SYSCTL_WMEM_MAX=16777216
SYSCTL_RMEM_DEFAULT=4194304
SYSCTL_WMEM_DEFAULT=4194304
SYSCTL_NETDEV_MAX_BACKLOG=4000

# ----- Preconditions ------------------------------------------------------

require_root() {
  if [ -n "$SUBLYNE_TEST_SKIP_ROOT_CHECK" ]; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: setup.sh must be run as root (try: sudo $0)" >&2
    exit 1
  fi
}

require_supported_os() {
  if [ -n "$SUBLYNE_TEST_SKIP_OS_CHECK" ]; then
    return 0
  fi
  if [ ! -r /etc/os-release ]; then
    echo "Error: cannot read /etc/os-release; refusing to run on unknown OS." >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ]; then
    echo "Error: this installer only supports Ubuntu (detected: ${PRETTY_NAME:-unknown})." >&2
    exit 1
  fi
  case "${VERSION_ID:-}" in
    22.04|24.04) ;;
    *)
      echo "Error: this installer supports only Ubuntu 22.04 and 24.04 (detected: ${VERSION_ID:-unknown})." >&2
      exit 1
      ;;
  esac
  local arch
  arch="$(uname -m)"
  if [ "$arch" != "x86_64" ]; then
    echo "Error: this installer supports only x86_64 (amd64) hosts (detected: ${arch})." >&2
    exit 1
  fi
}

# ----- Generators ---------------------------------------------------------

random_port() {
  # 5-digit panel port in 10000..65535, sourced from /dev/urandom for
  # uniformity across the range (awk srand() is seeded from time and
  # gives noticeably uneven results).
  local n
  while :; do
    n=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
    n=$((10000 + n % 55536))
    if [ "$n" -ge 10000 ] && [ "$n" -le 65535 ]; then
      printf '%d' "$n"
      return
    fi
  done
}

random_webpath() {
  # 16-char URL-safe slug. tr filters /dev/urandom down to [A-Za-z0-9];
  # head -c 16 takes the first 16 surviving chars and then closes the
  # pipe. That close gives tr a SIGPIPE, which under `set -o pipefail`
  # would otherwise propagate up as a 141 exit. We run the pipeline in
  # a subshell with pipefail off to isolate the expected SIGPIPE.
  (
    set +o pipefail
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
  )
}

# ----- Prompts ------------------------------------------------------------

prompt() {
  local var_name="$1" prompt_text="$2" default="${3:-}" val=""
  if [ -n "$default" ]; then
    read -r -p "${prompt_text} [${default}]: " val
    val="${val:-$default}"
  else
    while [ -z "$val" ]; do
      read -r -p "${prompt_text}: " val
    done
  fi
  printf -v "$var_name" '%s' "$val"
}

prompt_password() {
  local var_name="$1" prompt_text="$2"
  local val1="" val2=""
  while :; do
    read -r -s -p "${prompt_text}: " val1
    echo
    if [ -z "$val1" ]; then
      echo "Password must not be empty." >&2
      continue
    fi
    read -r -s -p "${prompt_text} (confirm): " val2
    echo
    if [ "$val1" = "$val2" ]; then
      printf -v "$var_name" '%s' "$val1"
      return
    fi
    echo "Passwords did not match. Try again." >&2
  done
}

prompt_yes_no() {
  # Returns 0 (true) on y/yes (case-insensitive), 1 (false) otherwise.
  # Default is "no" — destructive prompts must require an explicit
  # affirmation, so users who hit Enter by accident don't wipe data.
  local prompt_text="$1" reply=""
  read -r -p "${prompt_text} [y/N]: " reply
  case "${reply,,}" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

# ----- Sandboxed system calls --------------------------------------------

maybe_systemctl() {
  # Wraps systemctl so the test harness can no-op every call. In
  # production this is the real systemctl with all its exit semantics
  # preserved.
  if [ -n "$SUBLYNE_TEST_SKIP_SYSTEMCTL" ]; then
    echo "[skip-systemctl] systemctl $*"
    return 0
  fi
  systemctl "$@"
}

maybe_useradd() {
  if [ -n "$SUBLYNE_TEST_SKIP_USERADD" ]; then
    echo "[skip-useradd] useradd $*"
    return 0
  fi
  useradd "$@"
}

maybe_groupadd() {
  if [ -n "$SUBLYNE_TEST_SKIP_USERADD" ]; then
    echo "[skip-groupadd] groupadd $*"
    return 0
  fi
  groupadd "$@"
}

maybe_userdel() {
  if [ -n "$SUBLYNE_TEST_SKIP_USERADD" ]; then
    echo "[skip-userdel] userdel $*"
    return 0
  fi
  userdel "$@"
}

maybe_groupdel() {
  if [ -n "$SUBLYNE_TEST_SKIP_USERADD" ]; then
    echo "[skip-groupdel] groupdel $*"
    return 0
  fi
  groupdel "$@"
}

maybe_chown() {
  if [ -n "$SUBLYNE_TEST_SKIP_CHOWN" ]; then
    return 0
  fi
  chown "$@"
}

maybe_install() {
  # `install -o user -g group` requires CAP_CHOWN. In test mode we drop
  # the ownership *and* the mode flags so the call still copies the
  # file or makes the directory without tripping a permission check
  # on Git Bash / MSYS hosts where chmod over Windows ACLs is iffy.
  # Tests verify file presence and content, not file modes.
  if [ -n "$SUBLYNE_TEST_SKIP_CHOWN" ]; then
    local is_dir=0
    local args=()
    local skip=0
    for a in "$@"; do
      if [ "$skip" -eq 1 ]; then skip=0; continue; fi
      case "$a" in
        -o|-g|-m) skip=1 ;;
        -d) is_dir=1 ;;
        *) args+=("$a") ;;
      esac
    done
    if [ "$is_dir" -eq 1 ]; then
      mkdir -p "${args[@]}"
      return $?
    fi
    # File install: just cp the source(s) to the dest. install's
    # multi-source semantics are "last arg is dest", which mirrors
    # what cp wants.
    cp "${args[@]}"
    return $?
  fi
  install "$@"
}

# ----- Helpers ------------------------------------------------------------

ensure_service_user() {
  if [ -n "$SUBLYNE_TEST_SKIP_USERADD" ]; then
    return 0
  fi
  if ! getent group "$SERVICE_GROUP" >/dev/null; then
    maybe_groupadd --system "$SERVICE_GROUP"
  fi
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    maybe_useradd --system \
                  --gid "$SERVICE_GROUP" \
                  --no-create-home \
                  --home-dir "$DATA_DIR" \
                  --shell /usr/sbin/nologin \
                  "$SERVICE_USER"
  fi
}

detect_public_ip() {
  # Best-effort: outbound default route's source address. Falls back
  # to a placeholder so the printed URL still makes sense if the box
  # has no internet at install time.
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null \
         | awk '/src/ { for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit } }')"
  if [ -z "$ip" ]; then
    ip="<server-ip>"
  fi
  printf '%s' "$ip"
}

read_config_value() {
  # Minimal TOML reader for the bootstrap config file we wrote
  # ourselves at install time. Handles both `key = "string"` and
  # `key = number` lines. Returns the raw value with surrounding
  # quotes stripped and trailing # comments removed.
  #
  # We don't reach for `jq`/`tomlq` because Ubuntu 22.04 ships neither
  # by default; the format we wrote is simple enough that awk is
  # entirely sufficient and stays dep-free.
  local key="$1"
  if [ ! -f "$CONFIG_PATH" ]; then
    return 0
  fi
  awk -v key="$key" '
    $0 ~ "^[[:space:]]*"key"[[:space:]]*=" {
      sub(/^[^=]+=[[:space:]]*/, "", $0)
      sub(/[[:space:]]+#.*$/, "", $0)
      gsub(/^[ \t]+|[ \t]+$/, "", $0)
      gsub(/^"|"$/, "", $0)
      print
      exit
    }
  ' "$CONFIG_PATH"
}

write_config() {
  local role="$1" panel_port="$2" web_path="$3"
  cat > "$CONFIG_PATH" <<EOF
# Sublyne control-plane config.
# Generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).

role        = "${role}"
panel_port  = ${panel_port}
web_path    = "${web_path}"
db_path     = "${DATA_DIR}/sublyne.db"
log_path    = "${LOGS_DIR}/app.log"
log_level   = "info"
EOF
  maybe_chown "${SERVICE_USER}:${SERVICE_GROUP}" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
}

write_bootstrap_admin() {
  # Plaintext credentials, mode 0600 owned by the service user.
  # On first start the running binary hashes the password with
  # Argon2id, inserts the admin row, and removes the file.
  local username="$1" password="$2"
  umask 0177
  cat > "$BOOTSTRAP_PATH" <<EOF
# Bootstrap admin credentials.
# The control plane hashes this password, writes the admin row to
# sublyne.db, and removes this file on its first successful start.
# Until then, guard it carefully.

username = "${username}"
password = "${password}"
EOF
  umask 0022
  maybe_chown "${SERVICE_USER}:${SERVICE_GROUP}" "$BOOTSTRAP_PATH"
  chmod 0600 "$BOOTSTRAP_PATH"
}

write_systemd_unit() {
  # Note: we set SUBLYNE_SOCKET_BUF_BYTES in the unit as documentation
  # (the dataplane defaults to 4 MiB anyway when the var is unset).
  # Operators tuning for higher-bandwidth links can edit this line and
  # `systemctl daemon-reload && systemctl restart sublyne`.
  local service_dir
  service_dir="$(dirname "$SERVICE_FILE")"
  mkdir -p "$service_dir"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sublyne control plane
# Both Wants= and After= are required to actually wait for the network:
# After= only orders us *if* the target is pulled in, and Wants= is what
# pulls it in. Without Wants= the ordering is a no-op on boots where
# nothing else requests network-online.target, and sublyne can start
# before the network is fully up.
Wants=network-online.target
After=network-online.target

[Service]
User=sublyne
Group=sublyne
Environment=SUBLYNE_SOCKET_BUF_BYTES=${SOCKET_BUF_BYTES}
ExecStart=/usr/local/bin/sublyne --config /etc/sublyne/config.toml
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
RuntimeDirectory=sublyne
RuntimeDirectoryMode=0750
# /etc/sublyne holds config.toml (which we never write at runtime) and,
# until the service consumes it, bootstrap-admin.toml (which the
# service deletes on first start). Allowing writes under /etc/sublyne
# is what makes that delete succeed under ProtectSystem=strict.
ReadWritePaths=/var/lib/sublyne /run/sublyne /etc/sublyne
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$SERVICE_FILE"
}

# Persist the sysctl values needed to actually sustain ≥ 200 Mbit/s per
# tunnel. The Ubuntu defaults of 208 KiB on rmem_max/wmem_max silently
# clamp our SO_RCVBUF setsockopt and cap throughput at the kernel UDP
# queue. The dataplane separately uses SO_RCVBUFFORCE / SO_SNDBUFFORCE
# (which bypass these limits because we have CAP_NET_ADMIN) — this file
# raises the system-wide ceiling too, for other tooling and for the
# fallback path on quirky kernels.
write_sysctl_conf() {
  local sysctl_dir
  sysctl_dir="$(dirname "$SYSCTL_FILE")"
  mkdir -p "$sysctl_dir"
  cat > "$SYSCTL_FILE" <<EOF
# Installed by /root/setup.sh for Sublyne.
# These values let the sublyne dataplane sustain hundreds of Mbit/s
# through a per-tunnel UDP socket without dropping packets at the
# kernel receive queue. Safe to leave in place; they only matter when
# applications request large SO_RCVBUF / SO_SNDBUF (the kernel still
# allocates buffers on demand, not up front).
net.core.rmem_max = ${SYSCTL_RMEM_MAX}
net.core.wmem_max = ${SYSCTL_WMEM_MAX}
net.core.rmem_default = ${SYSCTL_RMEM_DEFAULT}
net.core.wmem_default = ${SYSCTL_WMEM_DEFAULT}
net.core.netdev_max_backlog = ${SYSCTL_NETDEV_MAX_BACKLOG}
# Loose reverse-path filtering (mode 2), NOT strict (1) and NOT off (0).
# Sublyne's data path is asymmetric: the spoofed download packets arrive
# on one interface with a source IP that the host has no route back out
# of, while the WireGuard / SOCKS5 upload leaves on another path. With
# strict RPF (rp_filter=1) the kernel silently DROPS those inbound
# spoofed download packets, killing the download direction entirely.
# Loose mode (2) still drops obviously-bogus packets (no route to the
# source at all) but permits the asymmetric routing we depend on.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# BBR congestion control + fq qdisc for the SOCKS5/TCP upload substrate.
# That hop is a real TCP byte stream over a high-RTT (trans-continental,
# Starlink) path; the kernel default CUBIC collapses its window hard on the
# loss such links exhibit, while BBR sustains throughput, and fq paces the
# stream. Both are in-tree on Ubuntu 22.04/24.04. tcp_congestion_control
# takes effect on new connections immediately (so the tunnel's SOCKS5
# connections pick it up); default_qdisc applies to interfaces brought up
# afterwards (a reboot, or already-fq on most clouds). If tcp_bbr is
# somehow unavailable the kernel keeps the previous value — a harmless
# no-op. This only affects local TCP; the UDP/WireGuard lane is unchanged.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  chmod 0644 "$SYSCTL_FILE"
  if [ -n "$SUBLYNE_TEST_SKIP_SYSCTL" ]; then
    return 0
  fi
  # Make sure the BBR module is present so the tcp_congestion_control line
  # applies (modern kernels auto-load it on set, but be explicit + tolerant).
  modprobe tcp_bbr 2>/dev/null || true
  # Apply immediately so the first dataplane start sees the new values.
  # --pattern restricts to our file so we don't replay every other
  # sysctl rule on the box (some of which may not be safe to re-apply).
  if ! sysctl --system >/dev/null 2>&1; then
    # Fall back to applying just our file if sysctl --system isn't
    # available (rare; sysctl from procps does support it on 22.04 and
    # 24.04).
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
  fi
}

wait_for_healthz() {
  # The panel + API both live under the obfuscated /<web_path>/ prefix;
  # /healthz at the bare root would 404. The healthz endpoint is
  # mounted at /<web_path>/api/healthz (and also at
  # /<web_path>/healthz for backwards-compat), so the install script
  # probes the API form.
  if [ -n "$SUBLYNE_TEST_SKIP_HEALTHCHECK" ]; then
    return 0
  fi
  local panel_port="$1" web_path="$2" tries=0 max_tries=60
  while [ "$tries" -lt "$max_tries" ]; do
    # -f so a non-2xx still counts as "not ready" and we keep looping;
    # drop -S and silence stderr so the transient "connection refused"
    # curl prints on the first iteration(s) doesn't leak to the
    # operator's terminal. systemd Type=simple returns at fork/exec,
    # before the Go process calls listen(), so the early polls
    # legitimately race the bind — that noise is expected, not an error.
    if curl -fs -o /dev/null --max-time 2 "http://127.0.0.1:${panel_port}/${web_path}/api/healthz" 2>/dev/null; then
      return 0
    fi
    # Fast-fail a crash-loop: if the unit has already gone to "failed"
    # (not "activating"/"active"), it will never bind no matter how long
    # we wait, so stop early and fall through to the loud diagnostics
    # below instead of burning the full ~60 s budget. Stay conservative —
    # never break on the first couple of iterations, since a
    # legitimately-starting service reports "activating" for a moment.
    # Guarded behind SUBLYNE_TEST_SKIP_SYSTEMCTL (via maybe_systemctl)
    # so CI's fake — which never starts a real unit — stays green.
    if [ "$tries" -gt 2 ] && [ -z "$SUBLYNE_TEST_SKIP_SYSTEMCTL" ] \
       && command -v systemctl >/dev/null 2>&1; then
      if [ "$(maybe_systemctl is-active sublyne.service 2>/dev/null)" = "failed" ]; then
        echo "       (sublyne.service entered 'failed' state while waiting; stopping early)" >&2
        break
      fi
    fi
    sleep 1
    tries=$((tries + 1))
  done
  # Tell the operator what's wrong rather than just "timed out". When
  # we drop out of the wait loop something is genuinely broken; the
  # extra context helps the operator decide whether to retry, rollback,
  # or open a bug.
  echo "       (waited ${max_tries}s; the service never bound on 127.0.0.1:${panel_port})" >&2
  if [ -z "$SUBLYNE_TEST_SKIP_SYSTEMCTL" ] && command -v systemctl >/dev/null 2>&1; then
    echo "       --- systemctl status sublyne --no-pager (last 20 lines) ---" >&2
    systemctl --no-pager -l status sublyne 2>&1 | tail -20 >&2 || true
    echo "       --- journalctl -u sublyne --no-pager -n 30 ---" >&2
    journalctl -u sublyne --no-pager -n 30 2>&1 | tail -30 >&2 || true
  fi
  return 1
}

binary_version() {
  # `sublyne --version` prints "sublyne <version>\n" — see
  # control-plane/cmd/sublyne/main.go. Use `2>&1` so a non-zero exit
  # on a corrupted binary surfaces its complaint instead of being
  # swallowed.
  local bin="$1"
  if [ ! -x "$bin" ]; then
    echo "(missing)"
    return 1
  fi
  "$bin" --version 2>&1 | head -n1
}

sanity_check_new_binary() {
  # The Update / Reinstall paths swap a binary into place before
  # restarting the service. A wrong-arch or corrupted download is the
  # single most-recoverable failure mode here: we'd rather refuse the
  # swap and leave the old binary running than restart into a
  # crash-loop.
  local bin="$1"
  if [ ! -f "$bin" ]; then
    echo "Error: binary not found at ${bin}." >&2
    echo "       Place the sublyne-linux-amd64 release artifact there and re-run." >&2
    return 1
  fi
  chmod +x "$bin" 2>/dev/null || true
  local out
  if ! out="$("$bin" --version 2>&1)"; then
    echo "Error: ${bin} failed to run --version. Possible causes:" >&2
    echo "        - wrong architecture (only linux-amd64 is supported)" >&2
    echo "        - corrupted download (re-download from the GitHub release)" >&2
    echo "        - downloaded the HTML 404 page instead of the artifact" >&2
    echo "       Output was: ${out}" >&2
    return 1
  fi
  printf '%s\n' "$out" | head -n1
}

# ----- Menu actions -------------------------------------------------------

fresh_install() {
  if [ ! -f "$BINARY_SRC" ]; then
    echo "Error: binary not found at ${BINARY_SRC}." >&2
    echo "       Place the sublyne-linux-amd64 release artifact there and re-run." >&2
    exit 1
  fi

  echo
  echo "=== Fresh install ==="
  echo

  local role username password panel_port web_path
  while :; do
    prompt role "Role (client or remote)" "client"
    case "$role" in
      client|remote) break ;;
      *) echo "Role must be \"client\" or \"remote\"." >&2 ;;
    esac
  done
  prompt username "Admin username" "admin"
  prompt_password password "Admin password"

  panel_port="$(random_port)"
  web_path="$(random_webpath)"

  echo
  echo "Generated panel port: ${panel_port}"
  echo "Generated web path:   ${web_path}"
  echo

  echo "==> Creating system user 'sublyne'"
  ensure_service_user

  echo "==> Creating directories"
  maybe_install -d -m 0755 -o root -g root "$(dirname "$BINARY_DEST")"
  maybe_install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$ETC_DIR"
  maybe_install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
  maybe_install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOGS_DIR"
  maybe_install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$RUNTIME_DIR"

  echo "==> Installing binary at ${BINARY_DEST}"
  maybe_install -m 0755 -o root -g root "$BINARY_SRC" "$BINARY_DEST"

  echo "==> Writing ${CONFIG_PATH}"
  write_config "$role" "$panel_port" "$web_path"

  echo "==> Writing ${BOOTSTRAP_PATH}"
  write_bootstrap_admin "$username" "$password"

  echo "==> Writing ${SYSCTL_FILE} (kernel socket buffer limits)"
  write_sysctl_conf

  echo "==> Installing systemd unit"
  write_systemd_unit
  maybe_systemctl daemon-reload
  maybe_systemctl enable sublyne.service >/dev/null
  maybe_systemctl restart sublyne.service

  echo "==> Waiting for healthz"
  if ! wait_for_healthz "$panel_port" "$web_path"; then
    echo "Error: service did not become healthy within 60 s." >&2
    echo "       Inspect 'journalctl -u sublyne -n 100' for details." >&2
    exit 1
  fi

  local ip
  ip="$(detect_public_ip)"

  cat <<EOF

================================================================
 Installation complete.
================================================================

  Panel URL:   http://${ip}:${panel_port}/${web_path}/
  Role:        ${role}
  Admin user:  ${username}
  Admin pass:  ${password}

Write this password down NOW. It will not be shown again.
================================================================

EOF
}

update_install() {
  echo
  echo "=== Update ==="
  echo

  if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: no existing install detected (${CONFIG_PATH} missing)." >&2
    echo "       Run option 1 (Fresh install) first." >&2
    exit 1
  fi

  local new_version
  if ! new_version="$(sanity_check_new_binary "$BINARY_SRC")"; then
    exit 1
  fi
  echo "==> New binary reports: ${new_version}"

  local old_version="(unknown)"
  if [ -x "$BINARY_DEST" ]; then
    if out="$("$BINARY_DEST" --version 2>/dev/null | head -n1)"; then
      old_version="$out"
    fi
  fi
  echo "==> Current install:    ${old_version}"

  # Atomic swap on the same filesystem (/usr/local/bin should always
  # be on the root filesystem). We write side-by-side and rename so
  # the running service — which already has the old inode open for
  # ExecStart — keeps running until systemctl restart re-execs from
  # the new path. mv on the same fs is rename(2) on Linux, i.e. atomic.
  echo "==> Replacing binary at ${BINARY_DEST}"
  maybe_install -m 0755 -o root -g root "$BINARY_SRC" "${BINARY_DEST}.new"
  mv -f "${BINARY_DEST}.new" "$BINARY_DEST"

  # Re-apply the network sysctl tunings so an Update can't accidentally
  # leave a box on kernel defaults (rmem_max ≈ 212 KB) — the dataplane
  # asks for 4 MiB SO_RCVBUFFORCE; without the raised ceiling the kernel
  # silently clamps to 212 KB and drops at high packet rates, dragging
  # download throughput from ~200 Mbit/s back to tens of Mbit/s.
  echo "==> Refreshing sysctl tunables at ${SYSCTL_FILE}"
  write_sysctl_conf

  echo "==> Restarting sublyne.service"
  maybe_systemctl restart sublyne.service

  local panel_port web_path
  panel_port="$(read_config_value panel_port)"
  web_path="$(read_config_value web_path)"
  if [ -n "$panel_port" ] && [ -n "$web_path" ]; then
    echo "==> Waiting for healthz"
    if ! wait_for_healthz "$panel_port" "$web_path"; then
      echo "Error: service did not become healthy within 60 s after update." >&2
      echo "       Inspect 'journalctl -u sublyne -n 100' for details." >&2
      echo "       The new binary is in place; you can roll back by copying" >&2
      echo "       the previous release artifact to ${BINARY_SRC} and re-running" >&2
      echo "       option 2 (Update)." >&2
      exit 1
    fi
  else
    # Couldn't parse panel_port / web_path back out of the config, so we
    # can't probe healthz. Warn loudly rather than skip silently — a
    # config parse failure must not masquerade as a successful update.
    echo "Warning: could not read panel_port/web_path from ${CONFIG_PATH};" >&2
    echo "         skipping the post-update health check. Verify manually" >&2
    echo "         with 'systemctl status sublyne' and the panel URL." >&2
  fi

  cat <<EOF

================================================================
 Update complete.
================================================================

  Previous:    ${old_version}
  Now running: ${new_version}

  Data, credentials, panel port, and web path are unchanged.
================================================================

EOF
}

reinstall() {
  echo
  echo "=== Reinstall ==="
  echo "  Replaces the binary AND recreates the systemd unit + sysctl"
  echo "  tunables from the install-time template. All data (tunnels,"
  echo "  WG configs, admin credentials) is preserved."
  echo

  if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: no existing install detected (${CONFIG_PATH} missing)." >&2
    echo "       Run option 1 (Fresh install) first, or option 4 (Uninstall)" >&2
    echo "       to clean up any partial install state." >&2
    exit 1
  fi

  local new_version
  if ! new_version="$(sanity_check_new_binary "$BINARY_SRC")"; then
    exit 1
  fi
  echo "==> New binary reports: ${new_version}"

  echo "==> Stopping service"
  maybe_systemctl stop sublyne.service 2>/dev/null || true

  echo "==> Replacing binary at ${BINARY_DEST}"
  maybe_install -m 0755 -o root -g root "$BINARY_SRC" "${BINARY_DEST}.new"
  mv -f "${BINARY_DEST}.new" "$BINARY_DEST"

  # The systemd unit format itself may have evolved between releases
  # (e.g. new env vars, different ReadWritePaths). Re-emit from the
  # install-time template so older boxes pick up new settings.
  echo "==> Rewriting systemd unit at ${SERVICE_FILE}"
  write_systemd_unit

  # The sysctl file is part of the deployment template too; re-apply
  # so kernel buffer limits track the current binary's expectations.
  echo "==> Rewriting sysctl tunables at ${SYSCTL_FILE}"
  write_sysctl_conf

  # If the original install predated the system user (older installs
  # before Phase 2 hardening), make sure the account + group exist
  # before we restart the service.
  ensure_service_user

  echo "==> daemon-reload"
  maybe_systemctl daemon-reload

  echo "==> Re-enabling sublyne.service"
  maybe_systemctl enable sublyne.service >/dev/null

  echo "==> Starting service"
  maybe_systemctl restart sublyne.service

  local panel_port web_path
  panel_port="$(read_config_value panel_port)"
  web_path="$(read_config_value web_path)"
  if [ -n "$panel_port" ] && [ -n "$web_path" ]; then
    echo "==> Waiting for healthz"
    if ! wait_for_healthz "$panel_port" "$web_path"; then
      echo "Error: service did not become healthy within 60 s after reinstall." >&2
      echo "       Inspect 'journalctl -u sublyne -n 100' for details." >&2
      exit 1
    fi
  else
    # Couldn't parse panel_port / web_path back out of the config, so we
    # can't probe healthz. Warn loudly rather than skip silently — a
    # config parse failure must not masquerade as a successful reinstall.
    echo "Warning: could not read panel_port/web_path from ${CONFIG_PATH};" >&2
    echo "         skipping the post-reinstall health check. Verify manually" >&2
    echo "         with 'systemctl status sublyne' and the panel URL." >&2
  fi

  local ip
  ip="$(detect_public_ip)"

  cat <<EOF

================================================================
 Reinstall complete.
================================================================

  Running:   ${new_version}
  Role:      $(read_config_value role)
  Panel URL: http://${ip}:${panel_port:-?}/${web_path:-?}/

  Data and credentials are preserved at:
    ${ETC_DIR}
    ${DATA_DIR}
================================================================

EOF
}

uninstall() {
  echo
  echo "=== Uninstall ==="
  echo
  echo "  This stops the service, removes the binary, removes the systemd"
  echo "  unit, and tears down WireGuard interfaces / ip rules / nft rules"
  echo "  installed by the dataplane."
  echo

  if ! prompt_yes_no "Uninstall sublyne?"; then
    echo "Aborted."
    return 0
  fi

  echo "==> Stopping service"
  maybe_systemctl stop sublyne.service 2>/dev/null || true
  echo "==> Disabling service"
  maybe_systemctl disable sublyne.service 2>/dev/null || true

  # Best-effort: clean up WG interfaces / ip rules / iptables RST-
  # suppression rules installed by the dataplane. We run --tear-down
  # AFTER stopping the service so the running binary isn't recreating
  # state on the way out. If the binary is missing or lacks the flag
  # (very old install), the failure is non-fatal.
  if [ -x "$BINARY_DEST" ]; then
    echo "==> Removing sub-wg-* interfaces and policy routes"
    "$BINARY_DEST" --tear-down 2>/dev/null || true
  fi

  echo "==> Removing binary at ${BINARY_DEST}"
  rm -f "$BINARY_DEST"

  echo "==> Removing systemd unit at ${SERVICE_FILE}"
  rm -f "$SERVICE_FILE"
  maybe_systemctl daemon-reload 2>/dev/null || true

  echo "==> Removing sysctl tunables at ${SYSCTL_FILE}"
  rm -f "$SYSCTL_FILE"
  # Re-apply the remaining sysctl files so the host's own defaults take
  # effect again without waiting for a reboot. This matters because our
  # file set net.ipv4.conf.{all,default}.rp_filter = 2 (loose), which is
  # behaviour-changing: leaving it at our value after uninstall would
  # silently alter reverse-path filtering on a box that no longer runs
  # sublyne. `sysctl --system` replays whatever the distro ships in
  # /etc/sysctl.d, /usr/lib/sysctl.d, etc., restoring rp_filter (and the
  # socket-buffer ceilings) to the host's configured defaults. Note this
  # cannot revert a value that no file specifies; for those the next
  # reboot resets them. Best-effort: never fail uninstall over a reload.
  if [ -z "$SUBLYNE_TEST_SKIP_SYSCTL" ]; then
    sysctl --system >/dev/null 2>&1 || true
  fi

  if prompt_yes_no "Delete all data including tunnels and credentials?"; then
    echo "==> Removing ${ETC_DIR}"
    rm -rf "$ETC_DIR"
    echo "==> Removing ${DATA_DIR}"
    rm -rf "$DATA_DIR"
    echo "==> Removing ${RUNTIME_DIR}"
    rm -rf "$RUNTIME_DIR"
    # User/group removal is best-effort: a leftover process owned
    # by the user (shouldn't happen after stop) keeps userdel from
    # succeeding. We log but don't fail; the next install just
    # re-creates it.
    echo "==> Removing ${SERVICE_USER} user and group"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
      maybe_userdel "$SERVICE_USER" 2>/dev/null || true
    fi
    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
      maybe_groupdel "$SERVICE_GROUP" 2>/dev/null || true
    fi
  else
    echo "==> Data preserved at:"
    echo "      ${ETC_DIR}"
    echo "      ${DATA_DIR}"
    echo "    A future Fresh install will reuse it if you leave it in place."
  fi

  cat <<EOF

================================================================
 Uninstall complete.
================================================================

EOF
}

status() {
  echo
  echo "=== Status ==="
  echo

  if [ ! -f "$CONFIG_PATH" ]; then
    echo "  Not installed: ${CONFIG_PATH} does not exist."
    echo "  Run option 1 (Fresh install) to set up sublyne."
    echo
    return 0
  fi

  local role panel_port web_path version_str systemd_state admin_user
  role="$(read_config_value role)"
  panel_port="$(read_config_value panel_port)"
  web_path="$(read_config_value web_path)"

  if [ -x "$BINARY_DEST" ]; then
    version_str="$("$BINARY_DEST" --version 2>/dev/null | head -n1 || echo "(unknown)")"
  else
    version_str="(binary missing at ${BINARY_DEST})"
  fi

  if [ -n "$SUBLYNE_TEST_SKIP_SYSTEMCTL" ]; then
    systemd_state="(test-mode)"
  else
    systemd_state="$(systemctl is-active sublyne.service 2>/dev/null || echo 'inactive')"
  fi

  # Admin username comes from the running service's DB via a dedicated
  # read-only flag. We invoke it WITHOUT root so the SQLite WAL doesn't
  # race the running service; the binary itself drops privileges via
  # its own logic. If the call fails — usually because the service
  # hasn't consumed bootstrap-admin.toml yet — fall through to
  # "(see bootstrap-admin.toml)".
  admin_user="(unknown)"
  if [ -x "$BINARY_DEST" ] && [ -f "$CONFIG_PATH" ]; then
    if out="$("$BINARY_DEST" --config "$CONFIG_PATH" --show-admin-username 2>/dev/null)"; then
      if [ -n "$out" ]; then
        admin_user="$out"
      fi
    fi
  fi
  if [ "$admin_user" = "(unknown)" ] && [ -f "$BOOTSTRAP_PATH" ]; then
    # Bootstrap file still exists → service hasn't consumed it.
    local bs_user
    bs_user="$(awk '/^[[:space:]]*username[[:space:]]*=/ { sub(/^[^=]+=[[:space:]]*/, "", $0); gsub(/^"|"$/, "", $0); print; exit }' "$BOOTSTRAP_PATH" 2>/dev/null || true)"
    if [ -n "$bs_user" ]; then
      admin_user="${bs_user} (bootstrap pending)"
    fi
  fi

  local ip
  ip="$(detect_public_ip)"

  cat <<EOF
  Version:       ${version_str}
  Role:          ${role:-(unknown)}
  Admin user:    ${admin_user}
  Panel URL:     http://${ip}:${panel_port:-?}/${web_path:-?}/
  Systemd:       ${systemd_state}

  Binary:        ${BINARY_DEST}
  Config:        ${CONFIG_PATH}
  Data:          ${DATA_DIR}
  Logs:          ${LOGS_DIR}/app.log

  To rotate the admin password, run:
    sudo systemctl stop sublyne
    sudo ${BINARY_DEST} --config ${CONFIG_PATH} --reset-admin
    sudo systemctl start sublyne

EOF
}

# ----- Menu ---------------------------------------------------------------

show_menu() {
  cat <<'EOF'

  Sublyne installer

  1) Fresh install
  2) Update
  3) Reinstall
  4) Uninstall
  5) Show status / credentials / panel URL
  6) Exit

EOF
  local choice=""
  read -r -p "Choose [1-6]: " choice
  case "$choice" in
    1) fresh_install ;;
    2) update_install ;;
    3) reinstall ;;
    4) uninstall ;;
    5) status ;;
    6) exit 0 ;;
    *) echo "Invalid choice: ${choice}" >&2; exit 1 ;;
  esac
}

# ----- Entry point --------------------------------------------------------

main() {
  require_root
  require_supported_os
  show_menu
}

main "$@"
