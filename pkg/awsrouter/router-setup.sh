#!/bin/bash
# router-setup.sh — the Tailscale subnet router's setup logic: chrony,
# audit rules, persistent journald, sshd hardening, the tailnet repo and
# join unit, optional SSH user-certificate login (ssh.go), and optional
# opkssh OIDC sign-in (opkssh.go).
#
# GENERIC and VERSION-PINNED. Every router — any environment, any
# tailnet, with or without the optional features — downloads this SAME
# file for a given truvity/tailscale release: it is published verbatim
# as that release's GitHub Release asset `router-setup-vX.Y.Z.sh`
# (.goreleaser.yaml) and embedded byte-for-byte into the Go module
# (pkg/awsrouter/bootstrap.go's `go:embed`), so the sha256 a consumer's
# own build computes from the embedded copy is exactly the sha256 of
# the asset a router downloads — both are the same git blob at the tag.
# The small cloud-init bootstrap (tailscale_userdata.yaml.gotmpl) pins
# that digest and refuses to run a download that doesn't match
# (docs/safety.md, "The bootstrap split").
#
# Per-router values (region, routes, the SSM auth-key path, ASG/hook
# names) and feature flags (SSH_USER_CA, OPKSSH) come from
# $ROUTER_SETUP_ROOT/etc/tailscale-router/router.env, written by
# cloud-init — never from arguments or from Go templating in this file.
# A few small, literal, per-router files sit alongside it (the CA public
# keys, each user's authorized_principals, opkssh's providers/auth_id
# lines) — see the write_files list this script's caller renders.
#
# ROUTER_SETUP_ROOT prefixes every absolute path this script writes or
# reads. Empty (production default) means "/". pkg/awsrouter's tests set
# it to a throwaway directory so the exact same code path that runs on a
# real router can run, for real, in a test — see router_setup_test.go.
# The handful of operations that need a real AL2023 host (package
# installs, service management, SELinux module compilation, network
# fetches) are isolated in the functions below so a test can override
# them; nothing else is different between a test run and a real one.
#
# This file is sourced, never executed directly, when
# ROUTER_SETUP_SOURCE_ONLY=1 (set by tests) — main() then runs only when
# a caller invokes it explicitly. Mirrors opkssh's own install-linux.sh
# SHUNIT_RUNNING convention.
set -uo pipefail

ROOT="${ROUTER_SETUP_ROOT:-}"
CONF_DIR="$ROOT/etc/tailscale-router"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') router-setup: $*"; }

# own is a best-effort chown: it always succeeds (as root, on a real
# router, it is not — this is defense in depth, not a fallback anyone
# should rely on) so a test running unprivileged can still exercise
# every other line of this script against a throwaway ROOT.
own() { chown "$1" "$2" 2>/dev/null || true; }

# ── The handful of operations a test cannot run for real ─────────────
# Defined as functions (not called directly), so a test can override
# any of them by defining a same-named function AFTER sourcing this
# file and BEFORE calling main — bash always uses the most recently
# defined function body.
pkg_remove() { dnf remove -y "$@" || true; }
svc_enable_now() { systemctl enable --now "$@"; }
svc_restart() { systemctl restart "$@"; }
svc_reload_or_restart() { systemctl reload "$1" 2>/dev/null || systemctl restart "$1"; }
fw() { firewall-cmd "$@"; }
time_step() {
  for i in 1 2 3; do
    chronyc makestep && return 0
    log "chronyc makestep attempt $i failed, retrying..."
    sleep 2
  done
  return 0
}
sysctl_apply() { sysctl --system; }
selinux_status() { command -v getenforce >/dev/null 2>&1 && getenforce || echo Disabled; }
selinux_load_module() {
  # $1 = path to the .te file already downloaded and checksum-verified.
  local te="$1" d
  d="$(dirname "$te")"
  restorecon /usr/local/bin/opkssh || true
  checkmodule -M -m -o "$d/opkssh.mod" "$te" &&
    semodule_package -o "$d/opkssh.pp" -m "$d/opkssh.mod" &&
    semodule -i "$d/opkssh.pp"
}
ensure_user_group() {
  local user="$1" group="$2"
  getent group "$group" >/dev/null || groupadd --system "$group"
  id -u "$user" >/dev/null 2>&1 || useradd -r -M -s /sbin/nologin -g "$group" "$user"
}
sshd_check() { sshd -t; }
# fetch_verify downloads $1 (a URL) to $2 (a destination path) and
# checks it against $3 (a lowercase sha256 hex digest). Fail closed: any
# failure — download or checksum — is a non-zero return, never a
# half-written or unverified file left where the caller would use it.
fetch_verify() {
  local url="$1" dest="$2" want="$3"
  curl -fsSL -o "$dest" "$url" || return 1
  printf '%s  %s\n' "$want" "$dest" | sha256sum -c - >/dev/null 2>&1
}

# ── Static configuration (identical on every router) ──────────────────

write_static_files() {
  mkdir -p "$ROOT/etc/chrony.d"
  cat >"$ROOT/etc/chrony.d/99-hardening.conf" <<'EOF'
# Amazon Time Sync Service (link-local, no network dependency)
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 6
# Amazon NTP pool as fallback
pool time.aws iburst
EOF

  mkdir -p "$ROOT/etc/sysctl.d"
  cat >"$ROOT/etc/sysctl.d/99-tailscale.conf" <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF

  mkdir -p "$ROOT/etc/audit/rules.d"
  cat >"$ROOT/etc/audit/rules.d/99-iso27001.rules" <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /var/log/secure -p wa -k logins
EOF

  mkdir -p "$ROOT/etc/systemd/journald.conf.d"
  cat >"$ROOT/etc/systemd/journald.conf.d/99-persistent.conf" <<'EOF'
[Journal]
Storage=persistent
EOF

  mkdir -p "$ROOT/etc/ssh/sshd_config.d"
  cat >"$ROOT/etc/ssh/sshd_config.d/99-hardening.conf" <<'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

  mkdir -p "$ROOT/etc/yum.repos.d"
  cat >"$ROOT/etc/yum.repos.d/tailscale.repo" <<'EOF'
[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/amazon-linux/2023/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=1
gpgkey=https://pkgs.tailscale.com/stable/amazon-linux/2023/repo.gpg
EOF

  mkdir -p "$ROOT/usr/local/sbin"
  cat >"$ROOT/usr/local/sbin/nightly-update-reboot.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
exec >> /var/log/nightly-update-reboot.log 2>&1
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') Starting nightly update cycle"

DELAY=$((RANDOM % 7200))
echo "Sleeping ${DELAY}s before update"
sleep "$DELAY"

dnf upgrade -y

set +e
needs-restarting -r > /dev/null 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "No reboot required"
elif [ "$rc" -eq 1 ]; then
  echo "Reboot required — rebooting now"
  reboot
else
  echo "needs-restarting failed with exit code $rc — aborting"
  exit 1
fi
EOF
  chmod 0755 "$ROOT/usr/local/sbin/nightly-update-reboot.sh"

  mkdir -p "$ROOT/etc/cron.d"
  cat >"$ROOT/etc/cron.d/nightly-update-reboot" <<'EOF'
0 0 * * * root /usr/local/sbin/nightly-update-reboot.sh
EOF

  mkdir -p "$ROOT/etc/systemd/system/cloud-final.service.d"
  cat >"$ROOT/etc/systemd/system/cloud-final.service.d/99-tailscale-join.conf" <<'EOF'
[Service]
ExecStartPost=-/usr/local/sbin/tailscale-join.sh
ExecStopPost=-/usr/local/sbin/tailscale-join.sh
EOF

  mkdir -p "$ROOT/etc/systemd/system"
  cat >"$ROOT/etc/systemd/system/tailscale-join.service" <<'EOF'
[Unit]
Description=Tailscale subnet-router join (idempotent, survives first-boot reboot)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tailscale-join.sh
StandardOutput=journal+console
TimeoutStartSec=900
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

# ── Per-router configuration (values come from router.env) ───────────

write_join_script() {
  mkdir -p "$ROOT/usr/local/sbin"
  # $REGION/$ASG_NAME/$LIFECYCLE_HOOK_NAME/$SSM_AUTH_KEY_PATH/
  # $ADVERTISE_ROUTES are substituted NOW, from router.env; every other
  # $-prefixed name here is backslash-escaped so it reaches the written
  # file literally and is evaluated at JOIN time instead.
  cat >"$ROOT/usr/local/sbin/tailscale-join.sh" <<EOF
#!/bin/bash
# Runs on EVERY boot (cloud-final drop-in + bootcmd + runcmd all arm it).
# Two-phase because of warm pools: the JOIN happens once (marker-gated),
# but a lifecycle action fires BOTH at warm-pool entry and again when the
# stopped instance starts into service — completion must run every boot.
set -uo pipefail
MARKER=/var/lib/tailscale-join.done
# Log file AND stdout: both callers send stdout to the serial console,
# so \`aws ec2 get-console-output\` shows a join failing without a shell.
exec > >(tee -a /var/log/tailscale-join.log) 2>&1
echo "\$(date -u '+%Y-%m-%dT%H:%M:%SZ') tailscale-join boot pass (marker: \$([ -f \$MARKER ] && echo present || echo absent))"

complete_hook() {
  TOKEN=\$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
  INSTANCE_ID=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
  aws ec2 modify-instance-attribute --instance-id "\$INSTANCE_ID" --no-source-dest-check --region $REGION || true
  # No-op (swallowed error) when no lifecycle action is pending.
  aws autoscaling complete-lifecycle-action \\
    --lifecycle-hook-name $LIFECYCLE_HOOK_NAME \\
    --auto-scaling-group-name $ASG_NAME \\
    --instance-id "\$INSTANCE_ID" \\
    --lifecycle-action-result CONTINUE \\
    --region $REGION || true
}

if [ -f "\$MARKER" ]; then
  # Already joined (e.g. during warm-pool entry) — tailscaled reconnects
  # from persisted state; just complete any pending lifecycle action.
  systemctl is-active -q tailscaled || systemctl enable --now tailscaled || true
  complete_hook
  echo "\$(date -u '+%Y-%m-%dT%H:%M:%SZ') hook pass done (already joined)"
  exit 0
fi

for attempt in \$(seq 1 20); do
  if ! command -v tailscale >/dev/null 2>&1; then
    dnf install -y tailscale && systemctl enable --now tailscaled
  fi
  if command -v tailscale >/dev/null 2>&1; then
    systemctl is-active -q tailscaled || systemctl enable --now tailscaled
    AUTH_KEY=\$(aws ssm get-parameter --name $SSM_AUTH_KEY_PATH --with-decryption --query Parameter.Value --output text --region $REGION) || AUTH_KEY=""
    if [ -n "\$AUTH_KEY" ] && tailscale up --authkey "\$AUTH_KEY" --advertise-routes=$ADVERTISE_ROUTES --accept-dns=false; then
      complete_hook
      touch "\$MARKER"
      echo "\$(date -u '+%Y-%m-%dT%H:%M:%SZ') joined + hook completed"
      exit 0
    fi
  fi
  echo "attempt \$attempt failed; retrying in 15s"
  sleep 15
done
echo "tailscale join failed after 20 attempts"
exit 1
EOF
  chmod 0755 "$ROOT/usr/local/sbin/tailscale-join.sh"
}

# ── SSH user certificates (ssh.go) — additive, never touched by opkssh ─

setup_ssh_user_ca() {
  mkdir -p "$ROOT/etc/ssh/sshd_config.d"
  cat >"$ROOT/etc/ssh/sshd_config.d/10-user-ca.conf" <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub
AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u
LogLevel VERBOSE
EOF
  chmod 0600 "$ROOT/etc/ssh/sshd_config.d/10-user-ca.conf"

  install -m 0644 "$CONF_DIR/trusted-user-ca-keys.pub" "$ROOT/etc/ssh/trusted-user-ca-keys.pub"

  mkdir -p "$ROOT/etc/ssh/authorized_principals"
  if [ -d "$CONF_DIR/authorized_principals" ]; then
    local f
    for f in "$CONF_DIR"/authorized_principals/*; do
      [ -e "$f" ] || continue
      install -m 0644 "$f" "$ROOT/etc/ssh/authorized_principals/$(basename "$f")"
    done
  fi
}

# ── opkssh (opkssh.go) — additive OIDC sign-in via AuthorizedKeysCommand
#
# This OWNS the install steps rather than running opkssh's upstream
# scripts/install-linux.sh: that script's determine_linux_type() only
# recognizes /etc/redhat-release, /etc/debian_version, /etc/arch-release
# or an ID_LIKE=*suse os-release — AL2023 has none of these (ID=amzn,
# ID_LIKE=fedora, no /etc/redhat-release), so it fails "Unsupported OS
# type" on every AL2023 host, on every version through opkssh's own main
# branch as of this fix (checked; no upstream release recognizes AL2023
# — see CHANGELOG.md and docs/safety.md). The steps below are exactly
# what that script does for a redhat-family host — AL2023 is one —
# skipping only its OS-detection branch and its HOME_POLICY-true path,
# which this router never uses.
setup_opkssh() {
  local d c
  d="$ROOT/tmp/opkssh-install"
  c="$ROOT/etc/ssh/sshd_config.d/60-opk-ssh.conf"
  mkdir -p "$d"

  fail() {
    log "opkssh $1 fail"
    rm -f "$c"
  }

  pkg_remove ec2-instance-connect

  if ! fetch_verify "$OPKSSH_ARTIFACT_URL" "$d/opkssh" "$OPKSSH_ARTIFACT_SHA256"; then
    fail "checksum"
    return 0
  fi

  if ! fetch_verify "$OPKSSH_SELINUX_URL" "$d/opkssh.te" "$OPKSSH_SELINUX_SHA256"; then
    fail "checksum"
    return 0
  fi

  ensure_user_group opksshuser opksshuser

  mkdir -p "$ROOT/usr/local/bin"
  install -m 0755 "$d/opkssh" "$ROOT/usr/local/bin/opkssh"
  own root:opksshuser "$ROOT/usr/local/bin/opkssh"

  if [ "$(selinux_status)" != "Disabled" ]; then
    if ! selinux_load_module "$d/opkssh.te"; then
      fail "selinux"
      return 0
    fi
  fi

  mkdir -p "$ROOT/etc/opk"
  own root:opksshuser "$ROOT/etc/opk"
  chmod 0750 "$ROOT/etc/opk"

  : >"$ROOT/etc/opk/providers"
  : >"$ROOT/etc/opk/auth_id"
  [ -f "$CONF_DIR/opkssh-providers" ] && cat "$CONF_DIR/opkssh-providers" >>"$ROOT/etc/opk/providers"
  [ -f "$CONF_DIR/opkssh-auth_id" ] && cat "$CONF_DIR/opkssh-auth_id" >>"$ROOT/etc/opk/auth_id"
  own root:opksshuser "$ROOT/etc/opk/providers"
  own root:opksshuser "$ROOT/etc/opk/auth_id"
  chmod 0640 "$ROOT/etc/opk/providers" "$ROOT/etc/opk/auth_id"

  # --no-home-policy, structurally: this script never writes
  # /etc/sudoers.d/opkssh at all — there is no flag to get this wrong,
  # unlike install-linux.sh's own --no-home-policy which still has to
  # assert the file it might otherwise create was not created.
  cat >"$c" <<'EOF'
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
EOF

  mkdir -p "$ROOT/var/log"
  : >>"$ROOT/var/log/opkssh.log"
  own root:opksshuser "$ROOT/var/log/opkssh.log"
  chmod 0660 "$ROOT/var/log/opkssh.log"
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') installed opkssh $("$ROOT/usr/local/bin/opkssh" --version 2>&1)" >>"$ROOT/var/log/opkssh.log"

  if sshd_check; then
    svc_reload_or_restart sshd
    log "opkssh installed"
  else
    log "sshd -t failed"
    rm -f "$c"
  fi
}

# ── main ───────────────────────────────────────────────────────────────

main() {
  # shellcheck disable=SC1091
  source "$CONF_DIR/router.env"

  write_static_files
  write_join_script

  if [ "${SSH_USER_CA:-false}" = "true" ]; then
    setup_ssh_user_ca
  fi

  sed -i -E 's/^(server|pool|peer) /# &/' "$ROOT/etc/chrony.conf" 2>/dev/null || true
  svc_enable_now chronyd
  svc_restart chronyd
  time_step || true

  sysctl_apply

  svc_enable_now auditd

  mkdir -p "$ROOT/var/log/journal"
  svc_restart systemd-journald

  sed -i 's/apply_updates = no/apply_updates = yes/' "$ROOT/etc/dnf/automatic.conf" 2>/dev/null || true
  svc_enable_now dnf-automatic-install.timer

  svc_enable_now firewalld
  fw --permanent --zone=public --add-interface="$PRIMARY_INTERFACE"
  fw --permanent --zone=public --add-port="$WIREGUARD_PORT"/udp
  fw --permanent --zone=public --add-masquerade
  fw --permanent --zone=trusted --add-interface=tailscale0
  if [ "${SSH_USER_CA:-false}" = "true" ]; then
    fw --permanent --zone=public --remove-service=ssh
  fi
  fw --reload

  if [ "${SSH_USER_CA:-false}" = "true" ]; then
    sshd_check
  fi

  if [ "${OPKSSH:-false}" = "true" ]; then
    setup_opkssh
  fi

  log "done"
}

if [ "${ROUTER_SETUP_SOURCE_ONLY:-}" != "1" ]; then
  main "$@"
fi
