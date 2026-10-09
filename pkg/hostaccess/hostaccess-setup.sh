#!/bin/bash
# hostaccess-setup.sh — opkssh OIDC sign-in and SSH host certificates for
# an EC2 host that is NOT a tailnet router (pkg/hostaccess).
#
# GENERIC and VERSION-PINNED, like pkg/awsrouter's router-setup.sh: one
# file per truvity/tailscale release, published verbatim as the release
# asset `hostaccess-setup-vX.Y.Z.sh` and embedded byte-for-byte into the
# Go module (setup.go's `go:embed`), so a consumer's build computes the
# digest of the exact bytes a host downloads. A consumer may instead write
# the same bytes into its user data (hostaccess.DeliveryInline).
#
# Per-host values and feature flags come from
# $HOSTACCESS_ROOT/etc/hostaccess/hostaccess.env, written by the
# consumer's cloud-init, with the small literal files beside it
# (opkssh-providers, opkssh-auth_id, hostcert-ca.pem). Nothing is taken
# from arguments, and nothing is templated into this file.
#
# setup_opkssh and its helpers are the SAME text as router-setup.sh's
# (pkg/hostaccess/drift_test.go fails when either side changes alone), so
# the two paths install the same pinned binary the same way: checksum
# verified and fail closed, no home policy, the 10-ssh-login.conf
# lockdown. setup_hostcert differs in one place: where the host
# certificate's principal comes from (HOST_CERT_PRINCIPAL_SOURCE):
#
#   tailscale      `tailscale status` (what a router does); the first
#                  certificate is signed by whoever runs
#                  openbao-hostcert-boot.sh after the join.
#   imds-hostname  the EC2 private DNS name, from IMDSv2 `local-hostname`
#                  (ip-10-68-x-y.<region>.compute.internal); signed once
#                  here, again at every boot (openbao-hostcert-boot.service)
#                  and every 12 hours (openbao-hostcert.timer, jittered).
#
# Every failure is fail-safe for the host: sshd keeps its plain host key
# and the script carries on. ROOT-prefixed paths and overridable host
# operations let hostaccess's tests run this file for real.
set -uo pipefail

ROOT="${HOSTACCESS_ROOT:-}"
CONF_DIR="$ROOT/etc/hostaccess"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') hostaccess-setup: $*"; }

# own is a best-effort chown: it always succeeds (as root it works; this
# is defense in depth) so a test running unprivileged can run every
# other line.
own() { chown "$1" "$2" 2>/dev/null || true; }

# ── Host operations a test cannot run for real ───────────────────────
pkg_remove() { dnf remove -y "$@" || true; }
svc_enable_now() { systemctl enable --now "$@"; }
svc_enable() { systemctl enable "$@"; }
svc_reload_or_restart() { systemctl reload "$1" 2>/dev/null || systemctl restart "$1"; }

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

# extract_binary pulls $3 (a member name) out of $1 (a .tar.gz already
# fetch_verify'd) into $2 (a directory). Its own function, like
# fetch_verify, so a test can stub it: the fixture bytes fetch_verify's
# own test stub writes are not a real archive.
extract_binary() {
  tar -xzf "$1" -C "$2" "$3"
}

# ── SSH login lockdown (shared with router-setup.sh) ────────────────

setup_ssh_login() {
  mkdir -p "$ROOT/etc/ssh/sshd_config.d"
  cat >"$ROOT/etc/ssh/sshd_config.d/10-ssh-login.conf" <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
LogLevel VERBOSE
EOF
  chmod 0600 "$ROOT/etc/ssh/sshd_config.d/10-ssh-login.conf"
}

# ── opkssh (shared with router-setup.sh) ────────────────────────────

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

# ── SSH host certificates (principal source differs from router-setup.sh) ─

setup_hostcert() {
  local d c archive ca_cert_line
  d="$ROOT/tmp/hostcert-install"
  c="$ROOT/etc/ssh/sshd_config.d/70-hostcert.conf"
  mkdir -p "$d"

  fail() {
    log "hostcert $1 fail"
    rm -f "$c"
  }

  # Only one architecture is ever downloaded: this package's own AMI is
  # always arm64 (pkg/awsrouter's LookupAmi) — HOST_CERT_ARTIFACT_SHA256 is
  # already the resolved digest for it, computed Go-side
  # (pkg/hostaccess's Render), not a map read here.
  archive="openbao-hostcert_${HOST_CERT_ARTIFACT_VERSION}_linux_arm64.tar.gz"
  if ! fetch_verify \
    "https://github.com/truvity/openbao/releases/download/v${HOST_CERT_ARTIFACT_VERSION}/${archive}" \
    "$d/$archive" "$HOST_CERT_ARTIFACT_SHA256"; then
    fail "checksum"
    return 0
  fi

  mkdir -p "$ROOT/usr/local/bin"
  if ! extract_binary "$d/$archive" "$ROOT/usr/local/bin" openbao-hostcert; then
    fail "extract"
    return 0
  fi
  chmod 0755 "$ROOT/usr/local/bin/openbao-hostcert"

  mkdir -p "$ROOT/etc/openbao-hostcert"
  chmod 0700 "$ROOT/etc/openbao-hostcert"

  # The OpenBAO server's CA bundle, when HostCert.CABundle staged one —
  # copied to its final location, never referenced in place, the same
  # convention ssh.go's trusted-user-ca-keys.pub follows.
  ca_cert_line=""
  if [ -f "$CONF_DIR/hostcert-ca.pem" ]; then
    install -m 0644 "$CONF_DIR/hostcert-ca.pem" "$ROOT/etc/openbao-hostcert/ca.pem"
    ca_cert_line="OPENBAO_HOSTCERT_CA_CERT=/etc/openbao-hostcert/ca.pem"
  fi

  # Renamed from this script's own HOST_CERT_* names (hostaccess.env) to the
  # OPENBAO_HOSTCERT_* names the binary itself reads
  # (cmd/openbao-hostcert/main.go) — two different files because
  # hostaccess.env is cloud-init's, written once at boot, and this one is
  # what the SYSTEMD SERVICE reads every run, on its own schedule, long
  # after cloud-init is done. OPENBAO_HOSTCERT_PRINCIPALS is
  # deliberately absent: openbao-hostcert-run.sh (below) supplies
  # --principal itself, fresh, every run.
  cat >"$ROOT/etc/openbao-hostcert/hostcert.env" <<EOF
OPENBAO_HOSTCERT_ADDRESS=$HOST_CERT_ADDRESS
OPENBAO_HOSTCERT_NAMESPACE=$HOST_CERT_NAMESPACE
OPENBAO_HOSTCERT_AUTH_MOUNT=$HOST_CERT_AUTH_MOUNT
OPENBAO_HOSTCERT_AUTH_ROLE=$HOST_CERT_AUTH_ROLE
OPENBAO_HOSTCERT_SERVER_ID_HEADER=$HOST_CERT_SERVER_ID_HEADER
OPENBAO_HOSTCERT_SSH_MOUNT=$HOST_CERT_SSH_MOUNT
OPENBAO_HOSTCERT_SSH_ROLE=$HOST_CERT_SSH_ROLE
OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS=$HOST_CERT_PRINCIPAL_PATTERNS
OPENBAO_HOSTCERT_PUBLIC_KEY=/etc/ssh/ssh_host_ed25519_key.pub
OPENBAO_HOSTCERT_CERT_PATH=/etc/ssh/ssh_host_ed25519_key-cert.pub
OPENBAO_HOSTCERT_RELOAD_CMD=systemctl reload sshd
$ca_cert_line
EOF
  chmod 0600 "$ROOT/etc/openbao-hostcert/hostcert.env"

  # The wrapper every run actually execs: it derives THIS host's principal
  # fresh, every time, never a value baked in at cloud-init time (which
  # cannot know the hostname a not-yet-launched instance will get).
  mkdir -p "$ROOT/usr/local/sbin"
  case "$HOST_CERT_PRINCIPAL_SOURCE" in
    tailscale)
      # --peers=false keeps "DNSName" to exactly one match (this
      # host's own), so the grep needs no JSON parser.
      cat >"$ROOT/usr/local/sbin/openbao-hostcert-run.sh" <<'EOF'
#!/bin/bash
set -uo pipefail
PRINCIPAL=$(tailscale status --peers=false --json 2>/dev/null \
  | grep -o '"DNSName": *"[^"]*"' | head -1 | sed -E 's/.*"DNSName": *"([^"]*)".*/\1/; s/\.$//')
if [ -z "$PRINCIPAL" ]; then
  echo "openbao-hostcert-run: tailscale status gave no DNSName (not joined yet?)" >&2
  exit 1
fi
exec /usr/local/bin/openbao-hostcert --principal "$PRINCIPAL"
EOF
      ;;
    imds-hostname)
      # IMDSv2 only (a PUT for the token, then the token on the GET): the
      # EC2 private DNS name, e.g. ip-10-68-1-2.eu-west-3.compute.internal.
      # The value is checked against a plain DNS-name shape before it is
      # passed on, and openbao-hostcert checks it against
      # --principal-pattern again.
      cat >"$ROOT/usr/local/sbin/openbao-hostcert-run.sh" <<'EOF'
#!/bin/bash
set -uo pipefail
IMDS=http://169.254.169.254
TOKEN=$(curl -fsS --max-time 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' "$IMDS/latest/api/token" 2>/dev/null)
PRINCIPAL=""
if [ -n "$TOKEN" ]; then
  PRINCIPAL=$(curl -fsS --max-time 5 -H "X-aws-ec2-metadata-token: $TOKEN" "$IMDS/latest/meta-data/local-hostname" 2>/dev/null)
fi
case "$PRINCIPAL" in
  "" | *[!A-Za-z0-9.-]* | *..* | .* | *.)
    echo "openbao-hostcert-run: IMDS gave no usable local-hostname" >&2
    exit 1
    ;;
esac
exec /usr/local/bin/openbao-hostcert --principal "$PRINCIPAL"
EOF
      ;;
    *)
      fail "principal-source"
      return 0
      ;;
  esac
  chmod 0755 "$ROOT/usr/local/sbin/openbao-hostcert-run.sh"

  # The first certificate, signed at boot rather than on the timer's
  # first tick (OnBootSec=5min plus up to 10 minutes of jitter, during
  # which a client that trusts hosts by @cert-authority alone refuses
  # this one). imds-hostname: main() runs it right here, and
  # openbao-hostcert-boot.service runs it at every later boot.
  # tailscale: the caller runs it right after `tailscale up`. It runs
  # the wrapper directly, not `systemctl start openbao-hostcert.service`
  # (a tailscale-ordered unit would wait on the join that calls this).
  # Bounded (ATTEMPTS tries of TIMEOUT seconds,
  # BACKOFF seconds more before each retry) and fail-safe: a failure is
  # logged, sshd keeps its plain host key, the timer retries, and this
  # script still exits 0, so it never fails or holds up the join.
  cat >"$ROOT/usr/local/sbin/openbao-hostcert-boot.sh" <<'EOF'
#!/bin/bash
set -uo pipefail
ENV_FILE=/etc/openbao-hostcert/hostcert.env
DROP_IN=/etc/ssh/sshd_config.d/70-hostcert.conf
RUN=/usr/local/sbin/openbao-hostcert-run.sh
ATTEMPTS=3
TIMEOUT=45
BACKOFF=5
log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') openbao-hostcert-boot: $*"; }
# No drop-in: setup_hostcert rolled back (sshd -t failed), and sshd
# would not serve a certificate anyway.
if [ ! -f "$DROP_IN" ] || [ ! -r "$ENV_FILE" ]; then
  log "skipped: the host certificate is not configured"
  exit 0
fi
# The service's EnvironmentFile, read as systemd reads it: one
# KEY=value per line, the value verbatim (the reload command has
# spaces), never evaluated by a shell.
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    OPENBAO_HOSTCERT_*=*) export "${line%%=*}=${line#*=}" ;;
  esac
done <"$ENV_FILE"
for attempt in $(seq 1 "$ATTEMPTS"); do
  if timeout "$TIMEOUT" "$RUN"; then
    log "host certificate signed at boot (attempt $attempt/$ATTEMPTS)"
    exit 0
  fi
  log "attempt $attempt/$ATTEMPTS failed"
  if [ "$attempt" -lt "$ATTEMPTS" ]; then
    sleep $((attempt * BACKOFF))
  fi
done
log "host certificate NOT signed at boot; sshd serves the plain host key until openbao-hostcert.timer renews it"
exit 0
EOF
  chmod 0755 "$ROOT/usr/local/sbin/openbao-hostcert-boot.sh"

  # The systemd unit content lives here, not a second checksummed
  # download: two small, static files, reviewed the same way every
  # other line in this script is, at this script's own release cadence
  # — see pkg/hostaccess's own doc comment for why.
  mkdir -p "$ROOT/etc/systemd/system"
  unit_after="network-online.target"
  if [ "$HOST_CERT_PRINCIPAL_SOURCE" = "tailscale" ]; then
    unit_after="network-online.target tailscale-join.service"
  fi
  cat >"$ROOT/etc/systemd/system/openbao-hostcert.service" <<EOF
[Unit]
Description=Renew this host's SSH host certificate from OpenBAO
After=$unit_after
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/openbao-hostcert/hostcert.env
ExecStart=/usr/local/sbin/openbao-hostcert-run.sh
User=root
Group=root
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/ssh
PrivateTmp=yes
EOF

  cat >"$ROOT/etc/systemd/system/openbao-hostcert.timer" <<'EOF'
[Unit]
Description=Periodic SSH host-certificate renewal (openbao-hostcert)

[Timer]
OnBootSec=5min
OnUnitActiveSec=12h
RandomizedDelaySec=10min
Persistent=true
Unit=openbao-hostcert.service

[Install]
WantedBy=timers.target
EOF

  cat >"$c" <<'EOF'
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
EOF

  # Signed again at every boot, not only at the first: a stopped and
  # restarted host must not wait on the timer with an expired certificate.
  if [ "$HOST_CERT_PRINCIPAL_SOURCE" = "imds-hostname" ]; then
    cat >"$ROOT/etc/systemd/system/openbao-hostcert-boot.service" <<'EOF'
[Unit]
Description=Sign this host's SSH host certificate at boot (openbao-hostcert)
After=network-online.target sshd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/openbao-hostcert-boot.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
  fi

  if sshd_check; then
    svc_enable_now openbao-hostcert.timer
    if [ "$HOST_CERT_PRINCIPAL_SOURCE" = "imds-hostname" ]; then
      svc_enable openbao-hostcert-boot.service
      sign_host_cert
    fi
    log "hostcert installed"
  else
    log "sshd -t failed"
    rm -f "$c"
  fi
}

# sign_host_cert runs the bounded, fail-safe boot signer, when installed.
sign_host_cert() {
  [ -x "$ROOT/usr/local/sbin/openbao-hostcert-boot.sh" ] || return 0
  "$ROOT/usr/local/sbin/openbao-hostcert-boot.sh" || true
}

# ── main ───────────────────────────────────────────────────────────────

main() {
  # shellcheck disable=SC1091
  source "$CONF_DIR/hostaccess.env"

  if [ "${OPKSSH:-false}" = "true" ]; then
    setup_ssh_login
    sshd_check
    setup_opkssh
  fi

  if [ "${HOST_CERT:-false}" = "true" ]; then
    setup_hostcert
  fi

  log "done"
}

if [ "${HOSTACCESS_SOURCE_ONLY:-}" != "1" ]; then
  main "$@"
fi
