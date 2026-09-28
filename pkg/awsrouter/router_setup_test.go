package awsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
		"etc/chrony.d/99-hardening.conf":                                  "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 6",
		"etc/sysctl.d/99-tailscale.conf":                                  "net.ipv4.ip_forward=1",
		"etc/audit/rules.d/99-iso27001.rules":                             "-w /etc/passwd -p wa -k identity",
		"etc/systemd/journald.conf.d/99-persistent.conf":                  "Storage=persistent",
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

	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/trusted-user-ca-keys.pub"))
	mustNotExist(t, filepath.Join(root, "etc/opk/providers"))
	mustNotExist(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "fw --permanent --zone=public --add-interface=ens5")
	assert.Contains(t, calls, "fw --permanent --zone=public --add-port=41641/udp")
	assert.NotContains(t, calls, "remove-service=ssh")
	assert.NotContains(t, calls, "pkg_remove ec2-instance-connect")
	assert.NotContains(t, calls, "ensure_user_group")
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

	sshd := mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	for _, line := range []string{
		"TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub",
		"AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u",
		"AuthorizedKeysFile none",
		"LogLevel VERBOSE",
	} {
		assert.Contains(t, sshd, line)
	}

	info, err := os.Stat(filepath.Join(root, "etc/ssh/sshd_config.d/10-user-ca.conf"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	calls := mustRead(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "fw --permanent --zone=public --remove-service=ssh")
	assert.Contains(t, calls, "sshd_check")

	// The 99-hardening.conf drop-in is untouched.
	assert.Contains(t, mustRead(t, filepath.Join(root, "etc/ssh/sshd_config.d/99-hardening.conf")), "PermitRootLogin no")
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
	assert.NotContains(t, calls, "sshd_check", "a failed download must never reach the sshd -t gate")
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
