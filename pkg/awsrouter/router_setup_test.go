package awsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file runs router-setup.sh for real, with real bash — not a
// golden-string match — against a throwaway ROUTER_SETUP_ROOT. The
// operations that need a real AL2023 host (package installs, service
// management, SELinux module compilation, network fetches) are
// shell functions the script calls by name (pkg_remove, svc_*, fw,
// sysctl_apply, time_step, selinux_status, selinux_load_module,
// ensure_user_group, sshd_check, fetch_verify); a test overrides any of
// them, after sourcing the script and before calling main, the same way
// opkssh's own install-linux.sh lets SHUNIT_RUNNING source it without
// running main. Every other line — the actual file-writing logic that
// determines the router's effective configuration — runs unmodified.

// routerSetupHarness writes router-setup.sh to a temp file (so bash can
// source it by path), runs it under a throwaway ROOT with the given
// router.env body and staged files, and returns that ROOT plus the
// combined stdout+stderr. overrideFuncs is bash source appended AFTER
// sourcing the script and BEFORE calling main — typically function
// redefinitions and/or a `log_calls=1`-style setup.
func routerSetupHarness(t *testing.T, env string, staged map[string]string, overrideFuncs string) (root string, output string) {
	t.Helper()

	root = t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "router-setup.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(routerSetupScript), 0o755))

	confDir := filepath.Join(root, "etc", "tailscale-router")
	require.NoError(t, os.MkdirAll(confDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "router.env"), []byte(env), 0o600))

	for path, content := range staged {
		full := filepath.Join(confDir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}

	harness := "set -uo pipefail\n" +
		"ROUTER_SETUP_SOURCE_ONLY=1\n" +
		"source " + shellQuote(scriptPath) + "\n" +
		overrideFuncs + "\n" +
		"main\n"

	cmd := exec.Command("bash", "-c", harness)
	cmd.Env = append(os.Environ(), "ROUTER_SETUP_ROOT="+root)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "router-setup.sh harness failed:\n%s", string(out))

	return root, string(out)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// baseEnv is router.env for a router with neither optional feature —
// the shape every non-pilot router renders.
const baseEnv = `REGION="eu-west-1"
ADVERTISE_ROUTES="10.0.0.0/16"
SSM_AUTH_KEY_PATH="/tailscale/acme/auth-key"
WIREGUARD_PORT="41641"
PRIMARY_INTERFACE="ens5"
ASG_NAME="example-tailscale-acme"
LIFECYCLE_HOOK_NAME="example-tailscale-acme-launch"
SSH_USER_CA="false"
OPKSSH="false"
HOST_CERT="false"
`

// noopSystemFuncs stubs every operation that needs a real AL2023 host
// with a no-op (or a fixed, safe answer), so main() can run to
// completion against a throwaway root without dnf/systemd/SELinux/a
// network. Individual tests override one or more of these further to
// exercise a specific branch (a checksum failure, SELinux enforcing,
// sshd -t failing, ...).
const noopSystemFuncs = `
pkg_remove() { echo "pkg_remove $*" >> "$ROOT/calls.log"; }
svc_enable_now() { echo "svc_enable_now $*" >> "$ROOT/calls.log"; }
svc_restart() { echo "svc_restart $*" >> "$ROOT/calls.log"; }
svc_reload_or_restart() { echo "svc_reload_or_restart $*" >> "$ROOT/calls.log"; }
fw() { echo "fw $*" >> "$ROOT/calls.log"; }
time_step() { return 0; }
sysctl_apply() { echo "sysctl_apply" >> "$ROOT/calls.log"; }
selinux_status() { echo Disabled; }
selinux_load_module() { echo "selinux_load_module $*" >> "$ROOT/calls.log"; return 0; }
ensure_user_group() { echo "ensure_user_group $*" >> "$ROOT/calls.log"; }
sshd_check() { echo "sshd_check" >> "$ROOT/calls.log"; return 0; }
fetch_verify() {
  # $1=url $2=dest $3=sha256 — simulate a successful, verified download
  # by writing deterministic fixture bytes naming the URL, so a test can
  # confirm the RIGHT url/dest pair reached this function without a
  # network.
  echo "fetch_verify $*" >> "$ROOT/calls.log"
  printf 'fixture-content-for:%s\n' "$1" > "$2"
  return 0
}
extract_binary() {
  # $1=archive $2=destdir $3=member — fetch_verify's own fixture is not
  # a real tar.gz, so this simulates a successful extraction the same
  # deterministic way: fixture bytes naming the archive, at the member
  # name the caller asked for.
  echo "extract_binary $*" >> "$ROOT/calls.log"
  printf 'fixture-binary-for:%s\n' "$1" > "$2/$3"
  return 0
}
# An 8 GiB root volume after the image's own ~1.6 GiB: room for swap.
free_mib() { echo 6300; }
swap_active() { return 1; }
swap_alloc() { echo "swap_alloc $*" >> "$ROOT/calls.log"; : > "$1"; }
swap_on() { echo "swap_on $*" >> "$ROOT/calls.log"; }
`

func mustRead(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err, "expected file missing: %s", path)

	return string(b)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "expected %s to not exist", path)
}

// ── Equivalence: a router with neither feature ────────────────────────
//
// This is the property Part 2 of the fix must hold: a plain router's
// EFFECTIVE configuration — the files sshd and systemd actually read —
// is the same set of files with the same content the single-file
// template used to write directly. Compare this list against
// testdata/userdata-default.yaml (pre-split) by hand at review time;
// this test pins it going forward.
func TestRouterSetupDefaultEffectiveConfig(t *testing.T) {
	root, _ := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs)

	for path, sentinel := range map[string]string{
		"etc/chrony.d/99-hardening.conf":                 "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 6",
		"etc/sysctl.d/99-tailscale.conf":                 "net.ipv4.ip_forward=1",
		"etc/audit/rules.d/99-iso27001.rules":            "-w /etc/passwd -p wa -k identity",
		"etc/systemd/journald.conf.d/99-persistent.conf": "Storage=persistent",
		"etc/systemd/journald.conf.d/99-size-cap.conf":   "SystemMaxUse=200M",
		"etc/fstab": "/swapfile none swap sw 0 0",
		"etc/ssh/sshd_config.d/99-hardening.conf":                         "PermitRootLogin no",
		"etc/yum.repos.d/tailscale.repo":                                  "baseurl=https://pkgs.tailscale.com/stable/amazon-linux/2023/$basearch",
		"etc/systemd/system/cloud-final.service.d/99-tailscale-join.conf": "ExecStartPost=-/usr/local/sbin/tailscale-join.sh",
		"etc/systemd/system/tailscale-join.service":                       "StandardOutput=journal+console",
		"etc/cron.d/nightly-update-reboot":                                "/usr/local/sbin/nightly-update-reboot.sh",
	} {
		assert.Contains(t, mustRead(t, filepath.Join(root, path)), sentinel, "file %s", path)
	}

	join := mustRead(t, filepath.Join(root, "usr/local/sbin/tailscale-join.sh"))
	assert.Contains(t, join, "exec > >(tee -a /var/log/tailscale-join.log) 2>&1", "the join log reaches the serial console")
	assert.Contains(t, join, "--region eu-west-1")
	assert.Contains(t, join, "--advertise-routes=10.0.0.0/16")
	assert.Contains(t, join, "--lifecycle-hook-name example-tailscale-acme-launch")
	assert.Contains(t, join, "--auto-scaling-group-name example-tailscale-acme")
	assert.Contains(t, join, "--name /tailscale/acme/auth-key")
	assert.Contains(t, join, "LOCK=/run/tailscale-join.lock")
	assert.Contains(t, join, "flock -n 9", "the join is single-flight")

	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-ssh-login.conf"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub"))
	mustNotExist(t, filepath.Join(root, "etc/opk/providers"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	mustNotExist(t, filepath.Join(root, "usr/local/bin/openbao-hostcert"))
	mustNotExist(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf"))
	mustNotExist(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.timer"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "swap_alloc "+filepath.Join(root, "swapfile")+" 1024")
	assert.Contains(t, calls, "swap_on "+filepath.Join(root, "swapfile"))
	assert.Contains(t, calls, "fw --permanent --zone=public --add-interface=ens5")
	assert.Contains(t, calls, "fw --permanent --zone=public --add-port=41641/udp")
	assert.NotContains(t, calls, "remove-service=ssh")
	assert.NotContains(t, calls, "sshd_check")
	assert.NotContains(t, calls, "pkg_remove ec2-instance-connect")
	assert.NotContains(t, calls, "ensure_user_group")
	assert.NotContains(t, calls, "extract_binary")
}

// ── SSH user certificates ──────────────────────────────────────────────

func TestRouterSetupSSHUserCA(t *testing.T) {
	env := strings.Replace(baseEnv, `SSH_USER_CA="false"`, `SSH_USER_CA="true"`, 1)
	staged := map[string]string{
		"trusted-user-ca-keys.pub":       "ssh-ed25519 AAAAexample current\nssh-ed25519 AAAAexample next\n",
		"authorized_principals/ec2-user": "ec2-user\n",
		"authorized_principals/operator": "breakglass\noncall\n",
	}

	root, _ := routerSetupHarness(t, env, staged, noopSystemFuncs)

	assert.Equal(t, staged["trusted-user-ca-keys.pub"], mustRead(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub")))
	assert.Equal(t, staged["authorized_principals/ec2-user"], mustRead(t, filepath.Join(root, "etc/ssh/authorized_principals/ec2-user")))
	assert.Equal(t, staged["authorized_principals/operator"], mustRead(t, filepath.Join(root, "etc/ssh/authorized_principals/operator")))

	assert.Equal(t,
		"TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub\n"+
			"AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u\n",
		mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf")),
		"the certificate drop-in carries the CA trust and nothing else")

	info, err := os.Stat(filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	assertSSHLoginLockdown(t, root)

	// The 99-hardening.conf drop-in is untouched.
	assert.Contains(t, mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/99-hardening.conf")), "PermitRootLogin no")
}

// ── The SSH login lockdown, shared by both login paths ─────────────────

// sshLoginLockdown is 10-ssh-login.conf, byte for byte.
const sshLoginLockdown = `PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
LogLevel VERBOSE
`

// assertSSHLoginLockdown checks what every router with a login path
// gets, whichever path it is: the lockdown drop-in (0600), sshd off the
// public zone exactly once, and sshd -t before anything reloads it.
func assertSSHLoginLockdown(t *testing.T, root string) {
	t.Helper()

	path := filepath.Join(root, "etc/ssh/sshd_config.d/10-ssh-login.conf")
	assert.Equal(t, sshLoginLockdown, mustRead(t, path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Equal(t, 1, strings.Count(calls, "fw --permanent --zone=public --remove-service=ssh"))
	assert.Contains(t, calls, "sshd_check")
}

// Dropping certificate login from a router that keeps opkssh must leave
// it exactly as locked down as before: the lockdown belongs to neither
// path. Every combination of the two login inputs renders the same
// 10-ssh-login.conf; only certificate login adds its trust files.
func TestRouterSetupSSHLoginLockdownIndependentOfUserCA(t *testing.T) {
	cases := map[string]struct {
		userCA, opkssh bool
	}{
		"certificates only": {userCA: true},
		"opkssh only":       {opkssh: true},
		"both":              {userCA: true, opkssh: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := baseEnv
			staged := map[string]string{}

			if tc.opkssh {
				env = opksshEnv()
				staged["opkssh-providers"] = "https://access.example.com opkssh 24h\n"
				staged["opkssh-auth_id"] = "ec2-user oidc:groups:ssh-admins https://access.example.com\n"
			}

			if tc.userCA {
				env = strings.Replace(env, `SSH_USER_CA="false"`, `SSH_USER_CA="true"`, 1)
				staged["trusted-user-ca-keys.pub"] = "ssh-ed25519 AAAAexample current\n"
				staged["authorized_principals/ec2-user"] = "ec2-user\n"
			}

			root, _ := routerSetupHarness(t, env, staged, noopSystemFuncs)

			assertSSHLoginLockdown(t, root)

			if tc.userCA {
				assert.FileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
				assert.FileExists(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub"))
				assert.FileExists(t, filepath.Join(root, "etc/ssh/authorized_principals/ec2-user"))
			} else {
				mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
				mustNotExist(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub"))
				mustNotExist(t, filepath.Join(root, "etc/ssh/authorized_principals"))
			}
		})
	}
}

// ── opkssh: the fixed AL2023 install path ─────────────────────────────

func opksshEnv() string {
	env := strings.Replace(baseEnv, `OPKSSH="false"`, `OPKSSH="true"`, 1)
	env += `OPKSSH_ARTIFACT_VERSION="0.16.0"
OPKSSH_ARTIFACT_URL="https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64"
OPKSSH_ARTIFACT_SHA256="9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44"
OPKSSH_SELINUX_URL="https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/opkssh.te"
OPKSSH_SELINUX_SHA256="f68bac733ecd604172eb5b4fe6e472eba195bcffa8444e44723e6fb9546926c4"
`

	return env
}

func TestRouterSetupOPKSSHInstall(t *testing.T) {
	staged := map[string]string{
		"opkssh-providers": "https://access.example.com opkssh 24h\n",
		"opkssh-auth_id":   "ec2-user oidc:groups:ssh-admins https://access.example.com\n",
	}

	root, _ := routerSetupHarness(t, opksshEnv(), staged, noopSystemFuncs)

	// The binary is installed (fetch_verify's fixture content, since no
	// real network runs in this test) with the right ownership/mode.
	bin := filepath.Join(root, "usr/local/bin/opkssh")
	assert.Contains(t, mustRead(t, bin), "fixture-content-for:https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64")

	info, err := os.Stat(bin)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	assert.Equal(t, staged["opkssh-providers"], mustRead(t, filepath.Join(root, "etc/opk/providers")))
	assert.Equal(t, staged["opkssh-auth_id"], mustRead(t, filepath.Join(root, "etc/opk/auth_id")))

	for _, p := range []string{"etc/opk/providers", "etc/opk/auth_id"} {
		info, err := os.Stat(filepath.Join(root, p))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	}

	sshd := mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	assert.Contains(t, sshd, "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t")
	assert.Contains(t, sshd, "AuthorizedKeysCommandUser opksshuser")

	// No sudoers file — structurally: setup_opkssh never writes one.
	mustNotExist(t, filepath.Join(root, "etc/sudoers.d/opkssh"))
	// The certificate path's own files are never named by opkssh.
	mustNotExist(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/authorized_principals"))

	// opkssh alone is an SSH host too: the same lockdown certificate
	// login gets, with no certificate trust anywhere.
	assertSSHLoginLockdown(t, root)

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	dnfIdx := strings.Index(calls, "pkg_remove ec2-instance-connect")
	userIdx := strings.Index(calls, "ensure_user_group opksshuser opksshuser")
	require.GreaterOrEqual(t, dnfIdx, 0)
	require.GreaterOrEqual(t, userIdx, 0)
	assert.Less(t, dnfIdx, userIdx, "ec2-instance-connect must be removed before opkssh is installed")
	assert.Contains(t, calls, "sshd_check")
	assert.Contains(t, calls, "svc_reload_or_restart sshd")
	assert.NotContains(t, calls, "selinux_load_module", "SELinux Disabled must skip the module install")

	log := mustRead(t, filepath.Join(root, "var/log/opkssh.log"))
	assert.Contains(t, log, "installed opkssh")
}

// A checksum mismatch (the artifact or the SELinux module) fails
// closed: the sshd drop-in is never created, so AuthorizedKeysCommand
// never points at an unverified binary, and nothing here touches sshd.
func TestRouterSetupOPKSSHChecksumMismatchFailsClosed(t *testing.T) {
	staged := map[string]string{
		"opkssh-providers": "https://access.example.com opkssh 24h\n",
		"opkssh-auth_id":   "ec2-user oidc:groups:ssh-admins https://access.example.com\n",
	}

	badFetch := noopSystemFuncs + `
fetch_verify() { echo "fetch_verify $*" >> "$ROOT/calls.log"; return 1; }
`

	root, out := routerSetupHarness(t, opksshEnv(), staged, badFetch)

	assert.Contains(t, out, "opkssh checksum fail")
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	mustNotExist(t, filepath.Join(root, "usr/local/bin/opkssh"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Equal(t, 1, strings.Count(calls, "sshd_check"),
		"only the lockdown's own sshd -t runs: a failed download must never reach setup_opkssh's gate")
	assert.NotContains(t, calls, "svc_reload_or_restart", "a failed download must never reload sshd")
}

// sshd -t failing after an otherwise-successful install removes only
// the opkssh drop-in — the lock-out-safe guard from the original
// (pre-fix) design, unchanged by owning the install steps.
func TestRouterSetupOPKSSHBadSSHDConfigRemovesDropIn(t *testing.T) {
	staged := map[string]string{
		"opkssh-providers": "https://access.example.com opkssh 24h\n",
		"opkssh-auth_id":   "ec2-user oidc:groups:ssh-admins https://access.example.com\n",
	}

	failingSSHD := noopSystemFuncs + `
sshd_check() { echo "sshd_check" >> "$ROOT/calls.log"; return 1; }
`

	root, out := routerSetupHarness(t, opksshEnv(), staged, failingSSHD)

	assert.Contains(t, out, "sshd -t failed")
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	// The binary and /etc/opk/* are left in place — only the sshd
	// wiring is rolled back, matching the original design's own
	// contract ("removes only the opkssh drop-in").
	assert.FileExists(t, filepath.Join(root, "usr/local/bin/opkssh"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.NotContains(t, calls, "svc_reload_or_restart", "a failing sshd -t must never be followed by a reload")
}

// SELinux enforcing: the module is compiled and loaded before the sshd
// drop-in is written; a module load failure also fails closed.
func TestRouterSetupOPKSSHSELinuxEnforcing(t *testing.T) {
	staged := map[string]string{
		"opkssh-providers": "https://access.example.com opkssh 24h\n",
		"opkssh-auth_id":   "ec2-user oidc:groups:ssh-admins https://access.example.com\n",
	}

	enforcing := noopSystemFuncs + `
selinux_status() { echo Enforcing; }
`

	root, _ := routerSetupHarness(t, opksshEnv(), staged, enforcing)

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "selinux_load_module")
	assert.FileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))

	failing := noopSystemFuncs + `
selinux_status() { echo Enforcing; }
selinux_load_module() { echo "selinux_load_module $*" >> "$ROOT/calls.log"; return 1; }
`
	root2, out := routerSetupHarness(t, opksshEnv(), staged, failing)
	assert.Contains(t, out, "opkssh selinux fail")
	mustNotExist(t, filepath.Join(root2, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
}

// ── SSH host-certificate renewal (hostcert.go) ──────────────────────────

func hostCertEnv() string {
	env := strings.Replace(baseEnv, `HOST_CERT="false"`, `HOST_CERT="true"`, 1)
	env += `HOST_CERT_ARTIFACT_VERSION="0.13.0"
HOST_CERT_ARTIFACT_SHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HOST_CERT_ADDRESS="https://openbao.example.internal"
HOST_CERT_NAMESPACE="example"
HOST_CERT_AUTH_MOUNT="aws"
HOST_CERT_AUTH_ROLE="router-host"
HOST_CERT_SERVER_ID_HEADER="example-openbao-aws-host"
HOST_CERT_SSH_MOUNT="ssh-host"
HOST_CERT_SSH_ROLE="router"
HOST_CERT_PRINCIPAL_PATTERNS="ip-10-0-*.tailnet.example.ts.net"
`

	return env
}

func TestRouterSetupHostCertInstall(t *testing.T) {
	staged := map[string]string{
		"hostcert-ca.pem": "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n",
	}

	root, _ := routerSetupHarness(t, hostCertEnv(), staged, noopSystemFuncs)

	bin := filepath.Join(root, "usr/local/bin/openbao-hostcert")
	assert.Contains(t, mustRead(t, bin), "fixture-binary-for:")
	info, err := os.Stat(bin)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	assert.Equal(t, staged["hostcert-ca.pem"], mustRead(t, filepath.Join(root, "etc/openbao-hostcert/ca.pem")))

	env := mustRead(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))
	for _, want := range []string{
		"OPENBAO_HOSTCERT_ADDRESS=https://openbao.example.internal",
		"OPENBAO_HOSTCERT_NAMESPACE=example",
		"OPENBAO_HOSTCERT_AUTH_MOUNT=aws",
		"OPENBAO_HOSTCERT_AUTH_ROLE=router-host",
		"OPENBAO_HOSTCERT_SERVER_ID_HEADER=example-openbao-aws-host",
		"OPENBAO_HOSTCERT_SSH_MOUNT=ssh-host",
		"OPENBAO_HOSTCERT_SSH_ROLE=router",
		"OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS=ip-10-0-*.tailnet.example.ts.net",
		"OPENBAO_HOSTCERT_PUBLIC_KEY=/etc/ssh/ssh_host_ed25519_key.pub",
		"OPENBAO_HOSTCERT_CERT_PATH=/etc/ssh/ssh_host_ed25519_key-cert.pub",
		"OPENBAO_HOSTCERT_RELOAD_CMD=systemctl reload sshd",
		"OPENBAO_HOSTCERT_CA_CERT=/etc/openbao-hostcert/ca.pem",
	} {
		assert.Contains(t, env, want)
	}
	assert.NotContains(t, env, "OPENBAO_HOSTCERT_PRINCIPALS=", "the wrapper supplies --principal itself, fresh, every run")

	info, err = os.Stat(filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	wrapper := mustRead(t, filepath.Join(root, "usr/local/sbin/openbao-hostcert-run.sh"))
	assert.Contains(t, wrapper, `tailscale status --peers=false --json`)
	assert.Contains(t, wrapper, `exec /usr/local/bin/openbao-hostcert --principal "$PRINCIPAL"`)
	info, err = os.Stat(filepath.Join(root, "usr/local/sbin/openbao-hostcert-run.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	assert.Contains(t, mustRead(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.service")), "EnvironmentFile=/etc/openbao-hostcert/hostcert.env")
	assert.Contains(t, mustRead(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.timer")), "OnUnitActiveSec=12h")

	assert.Equal(t, "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n", mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf")))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "sshd_check")
	assert.Contains(t, calls, "svc_enable_now openbao-hostcert.timer")

	// A host certificate opens no login: no lockdown, no firewall change.
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-ssh-login.conf"))
	assert.NotContains(t, calls, "remove-service=ssh")
}

func TestRouterSetupHostCertNoCABundleSkipsCACert(t *testing.T) {
	root, _ := routerSetupHarness(t, hostCertEnv(), nil, noopSystemFuncs)

	mustNotExist(t, filepath.Join(root, "etc/openbao-hostcert/ca.pem"))
	env := mustRead(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))
	assert.NotContains(t, env, "OPENBAO_HOSTCERT_CA_CERT")
}

// A checksum mismatch fails closed: nothing is installed, and the sshd
// drop-in is never created.
func TestRouterSetupHostCertChecksumMismatchFailsClosed(t *testing.T) {
	badFetch := noopSystemFuncs + `
fetch_verify() { echo "fetch_verify $*" >> "$ROOT/calls.log"; return 1; }
`

	root, out := routerSetupHarness(t, hostCertEnv(), nil, badFetch)

	assert.Contains(t, out, "hostcert checksum fail")
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf"))
	mustNotExist(t, filepath.Join(root, "usr/local/bin/openbao-hostcert"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.NotContains(t, calls, "extract_binary")
	assert.NotContains(t, calls, "sshd_check", "a failed download must never reach the sshd -t gate")
}

// sshd -t failing after an otherwise-successful install removes only
// the hostcert drop-in — the binary, units and env file are left in
// place, the same rollback contract setup_opkssh's own failure takes.
func TestRouterSetupHostCertBadSSHDConfigRemovesDropIn(t *testing.T) {
	failingSSHD := noopSystemFuncs + `
sshd_check() { echo "sshd_check" >> "$ROOT/calls.log"; return 1; }
`

	root, out := routerSetupHarness(t, hostCertEnv(), nil, failingSSHD)

	assert.Contains(t, out, "sshd -t failed")
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf"))
	assert.FileExists(t, filepath.Join(root, "usr/local/bin/openbao-hostcert"))
	assert.FileExists(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.NotContains(t, calls, "svc_enable_now openbao-hostcert.timer", "a failing sshd -t must never be followed by enabling the timer")
}

// Independent of certificate login and opkssh: all three install
// cleanly together, each exactly as it does alone.
func TestRouterSetupHostCertWithSSHUserCAAndOPKSSH(t *testing.T) {
	env := strings.Replace(hostCertEnv(), `SSH_USER_CA="false"`, `SSH_USER_CA="true"`, 1)
	env = strings.Replace(env, `OPKSSH="false"`, `OPKSSH="true"`, 1)
	env += `OPKSSH_ARTIFACT_VERSION="0.16.0"
OPKSSH_ARTIFACT_URL="https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64"
OPKSSH_ARTIFACT_SHA256="9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44"
OPKSSH_SELINUX_URL="https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/opkssh.te"
OPKSSH_SELINUX_SHA256="f68bac733ecd604172eb5b4fe6e472eba195bcffa8444e44723e6fb9546926c4"
`

	staged := map[string]string{
		"trusted-user-ca-keys.pub":       "ssh-ed25519 AAAAexample current\n",
		"authorized_principals/ec2-user": "ec2-user\n",
		"opkssh-providers":               "https://access.example.com opkssh 24h\n",
		"opkssh-auth_id":                 "ec2-user oidc:groups:ssh-admins https://access.example.com\n",
	}

	root, _ := routerSetupHarness(t, env, staged, noopSystemFuncs)

	assertSSHLoginLockdown(t, root)
	assert.FileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	assert.FileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	assert.FileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf"))
	assert.FileExists(t, filepath.Join(root, "usr/local/bin/openbao-hostcert"))
}

// ── The first host certificate, signed at boot ─────────────────────────
//
// openbao-hostcert-boot.sh is the one-shot the join runs right after
// `tailscale up`, so a router is InService already presenting a
// CA-signed host key. These run the script router-setup.sh writes, for
// real, with its absolute paths pointed at the harness's own root and
// the signing wrapper replaced by a stub.

// hostCertBoot installs HostCert through the harness, then writes the
// boot script with its paths pointed into that root and RUN pointed at
// a stub whose body is runBody. BACKOFF is 0 so a retry costs no time;
// extra replacements (e.g. a shorter TIMEOUT) apply last. Returns the
// script's path and the scratch directory the stub can write into.
func hostCertBoot(t *testing.T, runBody string, extra ...string) (script, tmp, root string) {
	t.Helper()

	root, _ = routerSetupHarness(t, hostCertEnv(), nil, noopSystemFuncs)
	tmp = t.TempDir()

	run := filepath.Join(tmp, "run.sh")
	require.NoError(t, os.WriteFile(run, []byte("#!/bin/bash\n"+runBody+"\n"), 0o755))

	boot := mustRead(t, filepath.Join(root, "usr/local/sbin/openbao-hostcert-boot.sh"))

	replacements := []string{
		"ENV_FILE=/etc/openbao-hostcert/hostcert.env", "ENV_FILE=" + shellQuote(filepath.Join(root, "etc/openbao-hostcert/hostcert.env")),
		"DROP_IN=/etc/ssh/sshd_config.d/70-hostcert.conf", "DROP_IN=" + shellQuote(filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf")),
		"RUN=/usr/local/sbin/openbao-hostcert-run.sh", "RUN=" + shellQuote(run),
		"BACKOFF=5", "BACKOFF=0",
	}
	replacements = append(replacements, extra...)

	for i := 0; i < len(replacements); i += 2 {
		require.Contains(t, boot, replacements[i], "the boot script lost the line a test points elsewhere")
		boot = strings.ReplaceAll(boot, replacements[i], replacements[i+1])
	}

	script = filepath.Join(tmp, "openbao-hostcert-boot.sh")
	require.NoError(t, os.WriteFile(script, []byte(boot), 0o755))

	return script, tmp, root
}

func TestRouterSetupHostCertInstallsBootSigner(t *testing.T) {
	root, _ := routerSetupHarness(t, hostCertEnv(), nil, noopSystemFuncs)

	path := filepath.Join(root, "usr/local/sbin/openbao-hostcert-boot.sh")
	boot := mustRead(t, path)
	assert.Contains(t, boot, `timeout "$TIMEOUT" "$RUN"`, "every attempt is bounded")
	assert.Contains(t, boot, "RUN=/usr/local/sbin/openbao-hostcert-run.sh", "the same wrapper the timer's service runs")
	assert.NotContains(t, boot, "systemctl start openbao-hostcert", "the service is ordered after the join, which calls this")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	// The timer stays: the boot signing is the first certificate, the
	// timer renews it.
	assert.Contains(t, mustRead(t, filepath.Join(root, "calls.log")), "svc_enable_now openbao-hostcert.timer")
}

func TestHostCertBootSignsOnce(t *testing.T) {
	script, tmp, _ := hostCertBoot(t, `echo run >> "$(dirname "$0")/runs"
env | grep '^OPENBAO_HOSTCERT_' | sort > "$(dirname "$0")/env"
exit 0`)

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "host certificate signed at boot (attempt 1/3)")
	assert.Equal(t, "run\n", mustRead(t, filepath.Join(tmp, "runs")))

	// The service's EnvironmentFile reaches the wrapper exactly as
	// systemd would pass it: values verbatim, spaces included.
	env := mustRead(t, filepath.Join(tmp, "env"))
	assert.Contains(t, env, "OPENBAO_HOSTCERT_ADDRESS=https://openbao.example.internal\n")
	assert.Contains(t, env, "OPENBAO_HOSTCERT_RELOAD_CMD=systemctl reload sshd\n")
	assert.Contains(t, env, "OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS=ip-10-0-*.tailnet.example.ts.net\n")
}

func TestHostCertBootRetriesThenSigns(t *testing.T) {
	script, tmp, _ := hostCertBoot(t, `echo run >> "$(dirname "$0")/runs"
[ "$(wc -l < "$(dirname "$0")/runs")" -ge 3 ]`)

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "attempt 1/3 failed")
	assert.Contains(t, string(out), "attempt 2/3 failed")
	assert.Contains(t, string(out), "host certificate signed at boot (attempt 3/3)")
	assert.Equal(t, "run\nrun\nrun\n", mustRead(t, filepath.Join(tmp, "runs")))
}

// OpenBAO unreachable, a refused login or sign: every attempt fails, and
// the script still exits 0, so the join carries on to the lifecycle
// action with sshd serving the plain host key.
func TestHostCertBootFailureIsNotFatal(t *testing.T) {
	script, tmp, _ := hostCertBoot(t, `echo run >> "$(dirname "$0")/runs"
echo "error: openbao unreachable" >&2
exit 1`)

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, "a failed signing must never fail its caller:\n%s", string(out))
	assert.Contains(t, string(out), "attempt 3/3 failed")
	assert.Contains(t, string(out), "host certificate NOT signed at boot")
	assert.Equal(t, "run\nrun\nrun\n", mustRead(t, filepath.Join(tmp, "runs")))
}

// A hung OpenBAO call is cut off by the per-attempt timeout: the whole
// script ends in about ATTEMPTS x TIMEOUT, never waits on the hang.
func TestHostCertBootIsBounded(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("timeout not installed")
	}

	script, _, _ := hostCertBoot(t, `exec sleep 60`, "TIMEOUT=45", "TIMEOUT=1")

	start := time.Now()
	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Contains(t, string(out), "host certificate NOT signed at boot")
}

// No sshd drop-in (setup_hostcert rolled back on a failing sshd -t):
// nothing to sign for, and nothing runs.
func TestHostCertBootSkipsWithoutDropIn(t *testing.T) {
	script, tmp, root := hostCertBoot(t, `echo run >> "$(dirname "$0")/runs"`)
	require.NoError(t, os.Remove(filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf")))

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "skipped: the host certificate is not configured")
	mustNotExist(t, filepath.Join(tmp, "runs"))
}

// ── The join signs before it completes the lifecycle action ────────────

// runJoin runs the join script router-setup.sh writes, for real, with
// its absolute paths pointed into a temp dir and tailscale, aws, curl
// and systemctl stubbed on PATH (each appends its argv to calls). The
// boot signer is a stub with body signBody, or absent when signBody is
// empty — a router without HOST_CERT. Returns the output and the calls.
func runJoin(t *testing.T, marker bool, signBody string) (output, calls string) {
	t.Helper()

	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}

	root, _ := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs)
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))

	log := filepath.Join(tmp, "calls")
	stub := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name),
			[]byte("#!/bin/bash\necho \""+name+" $*\" >> "+shellQuote(log)+"\n"+body+"\n"), 0o755))
	}
	stub("tailscale", "exit 0")
	stub("systemctl", "exit 0")
	stub("curl", "echo stub")
	stub("aws", `[ "$1" = ssm ] && echo tskey-stub; exit 0`)

	signer := filepath.Join(tmp, "openbao-hostcert-boot.sh")
	if signBody != "" {
		require.NoError(t, os.WriteFile(signer,
			[]byte("#!/bin/bash\necho \"sign\" >> "+shellQuote(log)+"\n"+signBody+"\n"), 0o755))
	}

	markerPath := filepath.Join(tmp, "marker")
	if marker {
		require.NoError(t, os.WriteFile(markerPath, nil, 0o644))
	}

	join := mustRead(t, filepath.Join(root, "usr/local/sbin/tailscale-join.sh"))
	for _, r := range [][2]string{
		{"LOCK=/run/tailscale-join.lock", "LOCK=" + shellQuote(filepath.Join(tmp, "join.lock"))},
		{"MARKER=/var/lib/tailscale-join.done", "MARKER=" + shellQuote(markerPath)},
		{"/var/log/tailscale-join.log", filepath.Join(tmp, "join.log")},
		{"/usr/local/sbin/openbao-hostcert-boot.sh", signer},
	} {
		require.Contains(t, join, r[0])
		join = strings.ReplaceAll(join, r[0], r[1])
	}

	script := filepath.Join(tmp, "tailscale-join.sh")
	require.NoError(t, os.WriteFile(script, []byte(join), 0o755))

	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	return string(out), mustRead(t, log)
}

// assertOrder checks each of want appears in calls, in that order.
func assertOrder(t *testing.T, calls string, want ...string) {
	t.Helper()

	at := -1
	for _, w := range want {
		i := strings.Index(calls, w)
		require.GreaterOrEqual(t, i, 0, "%q never happened:\n%s", w, calls)
		assert.Greater(t, i, at, "%q happened out of order:\n%s", w, calls)
		at = i
	}
}

func TestJoinScriptSignsHostCertBeforeCompletingHook(t *testing.T) {
	t.Run("first join", func(t *testing.T) {
		out, calls := runJoin(t, false, "exit 0")
		assert.Contains(t, out, "joined + hook completed")
		assertOrder(t, calls, "tailscale up", "sign", "aws autoscaling complete-lifecycle-action")
	})

	// A warm-pool instance joined at warm-pool entry; starting into
	// service re-signs, so it is never InService on an expired
	// certificate from a long stop.
	t.Run("already joined", func(t *testing.T) {
		out, calls := runJoin(t, true, "exit 0")
		assert.Contains(t, out, "hook pass done (already joined)")
		assert.NotContains(t, calls, "tailscale up")
		assertOrder(t, calls, "sign", "aws autoscaling complete-lifecycle-action")
	})
}

// The signer exiting non-zero (it never should) still never stops the
// join: the lifecycle action completes and the marker is written.
func TestJoinScriptContinuesWhenSigningFails(t *testing.T) {
	out, calls := runJoin(t, false, "exit 1")
	assert.Contains(t, out, "joined + hook completed")
	assertOrder(t, calls, "tailscale up", "sign", "aws autoscaling complete-lifecycle-action")
}

// No HOST_CERT: no signer on disk, and the join is what it always was.
func TestJoinScriptWithoutHostCert(t *testing.T) {
	out, calls := runJoin(t, false, "")
	assert.Contains(t, out, "joined + hook completed")
	assert.NotContains(t, calls, "sign")
	assertOrder(t, calls, "tailscale up", "aws autoscaling complete-lifecycle-action")
}

// ── Swap: only when the disk has room, never a failed setup ────────────

// A root filesystem without room for the swap file plus the space kept
// free after it skips the swap file with a log line, and the rest of
// the setup still runs: the ENOSPC a 2 GiB root volume gave cloud-init's
// own swap module must not recur as a failure here.
func TestRouterSetupSwapSkippedWhenDiskIsFull(t *testing.T) {
	root, out := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs+`
free_mib() { echo 418; }
`)

	assert.Contains(t, out, "swap: skipped, 418 MiB free on /, need 2048 MiB")
	assert.Contains(t, out, "router-setup: done")
	mustNotExist(t, filepath.Join(root, "swapfile"))
	mustNotExist(t, filepath.Join(root, "etc/fstab"))
	assert.NotContains(t, mustRead(t, filepath.Join(root, "calls.log")), "swap_alloc")
}

// An unreadable free-space figure is a skip too, never an arithmetic
// error that aborts the setup.
func TestRouterSetupSwapSkippedWhenFreeSpaceUnknown(t *testing.T) {
	root, out := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs+`
free_mib() { echo ""; }
`)

	assert.Contains(t, out, "swap: skipped, unknown MiB free on /")
	assert.Contains(t, out, "router-setup: done")
	mustNotExist(t, filepath.Join(root, "swapfile"))
}

// A swap file that cannot be activated is removed and logged; it never
// reaches fstab (a stale fstab entry would fail every later boot's
// swapon) and never fails the setup.
func TestRouterSetupSwapActivationFailureIsNotFatal(t *testing.T) {
	root, out := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs+`
swap_on() { return 1; }
`)

	assert.Contains(t, out, "swap: creating /swapfile failed, continuing without swap")
	assert.Contains(t, out, "router-setup: done")
	mustNotExist(t, filepath.Join(root, "swapfile"))
	mustNotExist(t, filepath.Join(root, "etc/fstab"))
}

// An already active swap file is left alone, and the fstab line is
// never written twice.
func TestRouterSetupSwapAlreadyActive(t *testing.T) {
	root, out := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs+`
swap_active() { return 0; }
`)

	assert.Contains(t, out, "swap: /swapfile already active")
	assert.NotContains(t, mustRead(t, filepath.Join(root, "calls.log")), "swap_alloc")
}

// ── The join is single-flight ──────────────────────────────────────────

// Runs the join script router-setup.sh writes, for real, while another
// process holds its lock: the second pass must leave without doing
// anything (no "boot pass", so no dnf, no tailscale up, no lifecycle
// call). The script's absolute paths are pointed into a temp dir.
func TestJoinScriptSecondPassLeavesTheJoinToTheFirst(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}

	root, _ := routerSetupHarness(t, baseEnv, nil, noopSystemFuncs)
	tmp := t.TempDir()
	lock := filepath.Join(tmp, "join.lock")

	join := mustRead(t, filepath.Join(root, "usr/local/sbin/tailscale-join.sh"))
	join = strings.ReplaceAll(join, "LOCK=/run/tailscale-join.lock", "LOCK="+shellQuote(lock))
	join = strings.ReplaceAll(join, "MARKER=/var/lib/tailscale-join.done", "MARKER="+shellQuote(filepath.Join(tmp, "marker")))
	join = strings.ReplaceAll(join, "/var/log/tailscale-join.log", filepath.Join(tmp, "join.log"))

	script := filepath.Join(tmp, "tailscale-join.sh")
	require.NoError(t, os.WriteFile(script, []byte(join), 0o755))

	f, err := os.Create(lock)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "another pass holds the lock; leaving the join to it")
	assert.NotContains(t, string(out), "boot pass")
}

// ── router-setup.sh's own checksum, as pinned by the bootstrap ─────────

func TestRouterSetupSHA256MatchesEmbeddedContent(t *testing.T) {
	sum := sha256.Sum256([]byte(routerSetupScript))
	want := hex.EncodeToString(sum[:])
	assert.Equal(t, want, RouterSetupSHA256())

	// A single byte of drift must change the digest — the whole point
	// of pinning it.
	tampered := routerSetupScript + " "
	tsum := sha256.Sum256([]byte(tampered))
	assert.NotEqual(t, want, hex.EncodeToString(tsum[:]))
}

func TestRouterSetupURL(t *testing.T) {
	assert.Equal(t, "https://github.com/truvity/tailscale/releases/download/v1.11.0/router-setup-v1.11.0.sh", RouterSetupURL("1.11.0"))
	assert.Equal(t, "router-setup-v1.11.0.sh", RouterSetupAssetName("1.11.0"))
}

func TestValidateRouterSetupVersion(t *testing.T) {
	cases := map[string]struct {
		version string
		wantErr string
	}{
		"valid":       {version: "1.11.0"},
		"empty":       {version: "", wantErr: "is required"},
		"leading v":   {version: "v1.11.0", wantErr: "is not"},
		"two parts":   {version: "1.11", wantErr: "is not"},
		"pre-release": {version: "1.11.0-rc1", wantErr: "is not"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := exampleConfig()
			c.RouterSetupVersion = tc.version

			err := c.validateRouterSetupVersion()
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
