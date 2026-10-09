package hostaccess

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func testConfig() Config {
	return Config{
		OPKSSH: NewOPKSSH(OPKSSHPreset{
			Issuer: "https://issuer.example.com/realms/ops", ClientID: "opkssh", User: "ec2-user", Group: "ops",
		}),
		HostCert: NewHostCert(HostCertPreset{
			Address: "https://openbao.example.internal", Namespace: "admin", AuthMount: "aws", AuthRole: "host",
			ServerIDHeader: "openbao.example.internal", SSHMount: "ssh-host", SSHRole: "host",
			PrincipalPatterns: []string{"ip-10-68-*.eu-west-3.compute.internal"},
		}),
	}
}

// ── pins ──────────────────────────────────────────────────────────────

func TestDigestsArePinned(t *testing.T) {
	o := NewOPKSSH(OPKSSHPreset{Issuer: "https://i.example.com", ClientID: "c", User: "u", Group: "g"})
	assert.Equal(t, "0.16.0", PinnedOPKSSHVersion)
	assert.Equal(t, "9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44", o.ArtifactSHA256)
	assert.Equal(t, "f68bac733ecd604172eb5b4fe6e472eba195bcffa8444e44723e6fb9546926c4", o.SELinuxModuleSHA256)
	assert.Contains(t, o.ArtifactURL, "/v"+PinnedOPKSSHVersion+"/")
	assert.Contains(t, o.SELinuxModuleURL, "/v"+PinnedOPKSSHVersion+"/")
	assert.Equal(t, "24h", o.Providers[0].Expiration)

	h := NewHostCert(HostCertPreset{})
	assert.Equal(t, "0.13.0", PinnedHostCertVersion)
	assert.Equal(t, "66659c1b0352c880e1b4e78456d702df1c6a68e7e4e853cd429ebb58788fae41", h.ArtifactSHA256["arm64"])
	assert.Equal(t, "97cdac0f14b6472fddb066db5460582bca53dbda80e82f8fee739588747457c3", h.ArtifactSHA256["amd64"])

	// A caller's map is a copy: mutating it never moves the pin.
	h.ArtifactSHA256["arm64"] = "x"
	assert.NotEqual(t, "x", NewHostCert(HostCertPreset{}).ArtifactSHA256["arm64"])
}

func TestValidateRefusesUnpinnedArtifacts(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"opkssh digest empty":    func(c *Config) { c.OPKSSH.ArtifactSHA256 = "" },
		"opkssh digest upper":    func(c *Config) { c.OPKSSH.SELinuxModuleSHA256 = strings.ToUpper(c.OPKSSH.SELinuxModuleSHA256) },
		"hostcert digest empty":  func(c *Config) { c.HostCert.ArtifactSHA256 = nil },
		"hostcert digest short":  func(c *Config) { c.HostCert.ArtifactSHA256["arm64"] = "abc" },
		"opkssh http url":        func(c *Config) { c.OPKSSH.ArtifactURL = "http://example.com/opkssh" },
		"url with shell syntax":  func(c *Config) { c.OPKSSH.ArtifactURL = "https://example.com/$(id)" },
		"url with quote":         func(c *Config) { c.OPKSSH.SELinuxModuleURL = `https://example.com/"x` },
		"address trailing slash": func(c *Config) { c.HostCert.Address = "https://openbao.example.internal/" },
		"root login":             func(c *Config) { c.OPKSSH.AuthorizedIdentities[0].User = "root" },
		"issuer not a provider":  func(c *Config) { c.OPKSSH.AuthorizedIdentities[0].Issuer = "https://other.example.com" },
		"bad expiration":         func(c *Config) { c.OPKSSH.Providers[0].Expiration = "forever" },
		"shell in client id":     func(c *Config) { c.OPKSSH.Providers[0].ClientID = "a;b" },
		"shell in role":          func(c *Config) { c.HostCert.AuthRole = `a"b` },
		"nothing enabled":        func(c *Config) { c.OPKSSH.Enabled, c.HostCert.Enabled = false, false },
		"bad principal source":   func(c *Config) { c.PrincipalSource = "dns" },
	} {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			mutate(&c)
			assert.Error(t, c.Validate())
		})
	}

	require.NoError(t, testConfig().Validate())
}

// ── no wildcard principals ────────────────────────────────────────────

func TestPrincipalPatternsNeverMatchAnything(t *testing.T) {
	for _, bad := range []string{
		"", "*", "**", "*.*", "ip-*", "*.internal", "ip-10-*.*.internal", "ip-10-68-1-2.eu-west-3.compute.*",
		"ip-10-68-1-2.eu-west-3.*.internal", "ip-10-68-1-2.eu-west-3.compute.?", "a..b", "ip-10-[0-9].a.b", "a b.c.d",
	} {
		c := testConfig()
		c.HostCert.PrincipalPatterns = []string{"ip-10-68-*.eu-west-3.compute.internal", bad}
		assert.Error(t, c.Validate(), "pattern %q", bad)
	}

	c := testConfig()
	c.HostCert.PrincipalPatterns = nil
	assert.Error(t, c.Validate())

	// What an estate actually writes is accepted, and renders unchanged.
	for _, ok := range []string{"ip-10-68-*.eu-west-3.compute.internal", "ip-10-65-*.example.ts.net", "ip-10-68-1-2.ec2.internal"} {
		c := testConfig()
		c.HostCert.PrincipalPatterns = []string{ok}
		require.NoError(t, c.Validate(), ok)
	}
}

func TestRenderedFilesHoldNoWildcardOnlyPattern(t *testing.T) {
	b, err := Render(testConfig(), Options{Version: "1.25.0"})
	require.NoError(t, err)

	env := findFile(t, b, ConfDir+"/hostaccess.env").Content
	assert.Contains(t, env, `HOST_CERT_PRINCIPAL_PATTERNS="ip-10-68-*.eu-west-3.compute.internal"`)
	assert.NotRegexp(t, regexp.MustCompile(`PRINCIPAL_PATTERNS="(\*|[^"]*,\*[,"])`), env)
}

// ── Render ────────────────────────────────────────────────────────────

func findFile(t *testing.T, b *Bundle, path string) File {
	t.Helper()

	for _, f := range b.Files {
		if f.Path == path {
			return f
		}
	}

	require.Failf(t, "file missing", "%s", path)

	return File{}
}

func TestRenderDownload(t *testing.T) {
	b, err := Render(testConfig(), Options{Version: "1.25.0"})
	require.NoError(t, err)

	assert.Equal(t, []string{"checkpolicy"}, b.Packages)
	assert.Equal(t, SetupSHA256(), b.ScriptSHA256)

	env := findFile(t, b, ConfDir+"/hostaccess.env")
	assert.Equal(t, "0600", env.Mode)
	assert.Contains(t, env.Content, `HOST_CERT_PRINCIPAL_SOURCE="imds-hostname"`)
	assert.Contains(t, env.Content, `OPKSSH_ARTIFACT_SHA256="9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44"`)
	assert.Contains(t, env.Content, `HOST_CERT_ARTIFACT_SHA256="66659c1b0352c880e1b4e78456d702df1c6a68e7e4e853cd429ebb58788fae41"`)

	assert.Equal(t, "https://issuer.example.com/realms/ops opkssh 24h\n", findFile(t, b, ConfDir+"/opkssh-providers").Content)
	assert.Equal(t, "ec2-user oidc:groups:ops https://issuer.example.com/realms/ops\n", findFile(t, b, ConfDir+"/opkssh-auth_id").Content)

	for _, f := range b.Files {
		assert.NotEqual(t, SetupPath, f.Path, "download delivery does not inline the script")
	}

	require.Len(t, b.Commands, 1)
	assert.Contains(t, b.Commands[0], "https://github.com/truvity/tailscale/releases/download/v1.25.0/hostaccess-setup-v1.25.0.sh")
	assert.Contains(t, b.Commands[0], SetupSHA256()+"  "+SetupPath)
	assert.Contains(t, b.Commands[0], "sha256sum -c - && chmod 0755")
}

func TestRenderInline(t *testing.T) {
	b, err := Render(testConfig(), Options{Delivery: DeliveryInline})
	require.NoError(t, err)

	s := findFile(t, b, SetupPath)
	assert.Equal(t, "0755", s.Mode)
	assert.Equal(t, SetupScript(), s.Content)
}

func TestRenderRefusesDownloadWithoutVersion(t *testing.T) {
	_, err := Render(testConfig(), Options{})
	assert.Error(t, err)
	_, err = Render(testConfig(), Options{Version: "v1.25.0"})
	assert.Error(t, err)
}

func TestRenderHostCertOnlyHasNoOpkssh(t *testing.T) {
	c := testConfig()
	c.OPKSSH = nil
	b, err := Render(c, Options{Version: "1.25.0"})
	require.NoError(t, err)

	assert.Empty(t, b.Packages)
	assert.Contains(t, findFile(t, b, ConfDir+"/hostaccess.env").Content, `OPKSSH="false"`)
	assert.Len(t, b.Files, 1)
}

// The byte budget: the numbers the docs quote, and the limit they are held to.
func TestBundleSizes(t *testing.T) {
	const ec2Limit = 16384

	dl, err := Render(testConfig(), Options{Version: "1.25.0"})
	require.NoError(t, err)

	n, err := dl.Size(EncodingPlain)
	require.NoError(t, err)
	t.Logf("download delivery: %d bytes; script %d bytes", n, dl.ScriptBytes)
	assert.Less(t, n, 2500, "download delivery must stay small")

	inline, err := Render(testConfig(), Options{Delivery: DeliveryInline})
	require.NoError(t, err)

	plain, err := inline.Size(EncodingPlain)
	require.NoError(t, err)
	gz, err := inline.Size(EncodingGzipBase64)
	require.NoError(t, err)
	t.Logf("inline delivery: %d bytes plain, %d bytes gz+b64", plain, gz)
	assert.Less(t, gz, 10000, "gz+b64 inline leaves room under EC2's %d", ec2Limit)
	assert.Less(t, gz, plain)
}

// The cloud-config fragment parses back to the files that went in, in both encodings.
func TestWriteFilesYAMLRoundTrips(t *testing.T) {
	b, err := Render(testConfig(), Options{Delivery: DeliveryInline})
	require.NoError(t, err)

	for _, enc := range []Encoding{EncodingPlain, EncodingGzipBase64} {
		y, err := b.WriteFilesYAML(enc, 2)
		require.NoError(t, err)

		var doc struct {
			WriteFiles []cloudFile `yaml:"write_files"`
		}

		require.NoError(t, yaml.Unmarshal([]byte("write_files:\n"+y), &doc))
		require.Len(t, doc.WriteFiles, len(b.Files))

		for i, f := range doc.WriteFiles {
			content := f.Content

			if f.Encoding == "gz+b64" {
				raw, err := base64.StdEncoding.DecodeString(content)
				require.NoError(t, err)
				zr, err := gzip.NewReader(bytes.NewReader(raw))
				require.NoError(t, err)
				plain, err := io.ReadAll(zr)
				require.NoError(t, err)
				content = string(plain)
			}

			assert.Equal(t, b.Files[i].Path, f.Path)
			assert.Equal(t, b.Files[i].Mode, f.Permissions)
			assert.Equal(t, b.Files[i].Content, content, f.Path)
		}
	}
}

func TestSetupScriptEmbeddedMatchesDisk(t *testing.T) {
	disk, err := os.ReadFile("hostaccess-setup.sh")
	require.NoError(t, err)
	assert.Equal(t, string(disk), SetupScript())
	assert.Equal(t, "hostaccess-setup-v1.2.3.sh", SetupAssetName("1.2.3"))
	assert.Equal(t, "https://github.com/truvity/tailscale/releases/download/v1.2.3/hostaccess-setup-v1.2.3.sh", SetupURL("1.2.3"))
}

// ── drift against router-setup.sh ─────────────────────────────────────

func shellFunc(t *testing.T, src, name string) string {
	t.Helper()

	if one := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\(\) \{.*\}$`).FindString(src); one != "" {
		return one
	}

	m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{.*?^\}\n`).FindString(src)
	require.NotEmpty(t, m, "function %s", name)

	return m
}

func heredoc(t *testing.T, src, marker string) string {
	t.Helper()

	i := strings.Index(src, marker)
	require.GreaterOrEqual(t, i, 0, marker)
	rest := src[i+len(marker):]
	j := strings.Index(rest, "\nEOF\n")
	require.GreaterOrEqual(t, j, 0)

	return rest[:j]
}

// The opkssh install is shared text: a fix on one side must reach the other.
func TestSharedWithRouterSetup(t *testing.T) {
	router, err := os.ReadFile(filepath.Join("..", "awsrouter", "router-setup.sh"))
	require.NoError(t, err)

	for _, fn := range []string{
		"setup_opkssh", "setup_ssh_login", "fetch_verify", "extract_binary",
		"selinux_load_module", "ensure_user_group", "sshd_check", "selinux_status", "own",
	} {
		assert.Equal(t, shellFunc(t, string(router), fn), shellFunc(t, setupScript, fn), "%s drifted from router-setup.sh", fn)
	}

	for _, marker := range []string{
		`cat >"$ROOT/usr/local/sbin/openbao-hostcert-boot.sh" <<'EOF'`,
		`cat >"$ROOT/etc/systemd/system/openbao-hostcert.timer" <<'EOF'`,
	} {
		assert.Equal(t, heredoc(t, string(router), marker), heredoc(t, setupScript, marker), marker)
	}
}

// ── running the script for real ───────────────────────────────────────

const stubs = `
pkg_remove() { echo "pkg_remove $*" >> "$ROOT/calls.log"; }
svc_enable_now() { echo "svc_enable_now $*" >> "$ROOT/calls.log"; }
svc_enable() { echo "svc_enable $*" >> "$ROOT/calls.log"; }
svc_reload_or_restart() { echo "svc_reload_or_restart $*" >> "$ROOT/calls.log"; }
selinux_status() { echo Disabled; }
selinux_load_module() { echo "selinux_load_module $*" >> "$ROOT/calls.log"; }
ensure_user_group() { echo "ensure_user_group $*" >> "$ROOT/calls.log"; }
sshd_check() { echo "sshd_check" >> "$ROOT/calls.log"; return 0; }
sign_host_cert() { echo "sign_host_cert" >> "$ROOT/calls.log"; }
fetch_verify() { echo "fetch_verify $*" >> "$ROOT/calls.log"; printf 'fixture:%s\n' "$1" > "$2"; }
extract_binary() { echo "extract_binary $*" >> "$ROOT/calls.log"; printf 'bin:%s\n' "$1" > "$2/$3"; }
`

func runSetup(t *testing.T, c Config, overrides string) (root, out string) {
	t.Helper()

	b, err := Render(c, Options{Version: "1.25.0"})
	require.NoError(t, err)

	root = t.TempDir()
	for _, f := range b.Files {
		p := filepath.Join(root, f.Path)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(f.Content), 0o600))
	}

	script := filepath.Join(t.TempDir(), "hostaccess-setup.sh")
	require.NoError(t, os.WriteFile(script, []byte(setupScript), 0o755))

	cmd := exec.Command("bash", "-c", "set -uo pipefail\nHOSTACCESS_SOURCE_ONLY=1\nsource '"+script+"'\n"+stubs+overrides+"\nmain\n")
	cmd.Env = append(os.Environ(), "HOSTACCESS_ROOT="+root)
	o, err := cmd.CombinedOutput()
	require.NoError(t, err, string(o))

	return root, string(o)
}

func read(t *testing.T, p string) string {
	t.Helper()

	b, err := os.ReadFile(p)
	require.NoError(t, err, p)

	return string(b)
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()

	i, err := os.Stat(p)
	require.NoError(t, err, p)

	return i.Mode().Perm()
}

func TestSetupInstallsOpksshAndHostCert(t *testing.T) {
	root, out := runSetup(t, testConfig(), "")
	assert.Contains(t, out, "hostaccess-setup: opkssh installed")
	assert.Contains(t, out, "hostaccess-setup: hostcert installed")

	calls := read(t, filepath.Join(root, "calls.log"))
	assert.Contains(t, calls, "pkg_remove ec2-instance-connect")
	assert.Contains(t, calls, "fetch_verify https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64 ")
	assert.Contains(t, calls, "9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44")
	assert.Contains(t, calls, "https://github.com/truvity/openbao/releases/download/v0.13.0/openbao-hostcert_0.13.0_linux_arm64.tar.gz")
	assert.Contains(t, calls, "66659c1b0352c880e1b4e78456d702df1c6a68e7e4e853cd429ebb58788fae41")
	assert.Contains(t, calls, "svc_enable_now openbao-hostcert.timer")
	assert.Contains(t, calls, "svc_enable openbao-hostcert-boot.service")
	assert.Contains(t, calls, "sign_host_cert", "imds-hostname signs once at setup")

	// Posture: no home policy, lockdown, opkssh policy files owned by opksshuser mode 0640.
	assert.NoFileExists(t, filepath.Join(root, "etc/sudoers.d/opkssh"))
	assert.Equal(t, "PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile none\nLogLevel VERBOSE\n",
		read(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-ssh-login.conf")))
	assert.Contains(t, read(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf")), "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t")
	assert.Equal(t, os.FileMode(0o640), mode(t, filepath.Join(root, "etc/opk/auth_id")))
	assert.Equal(t, "ec2-user oidc:groups:ops https://issuer.example.com/realms/ops\n", read(t, filepath.Join(root, "etc/opk/auth_id")))
	assert.Equal(t, os.FileMode(0o600), mode(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env")))
	hostcertEnv := read(t, filepath.Join(root, "etc/openbao-hostcert/hostcert.env"))
	assert.Contains(t, hostcertEnv, "OPENBAO_HOSTCERT_PRINCIPAL_PATTERNS=ip-10-68-*.eu-west-3.compute.internal\n")
	assert.Equal(t, "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n", read(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf")))

	timer := read(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.timer"))
	assert.Contains(t, timer, "OnUnitActiveSec=12h")
	assert.Contains(t, timer, "RandomizedDelaySec=10min")

	svc := read(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.service"))
	assert.Contains(t, svc, "After=network-online.target\n")
	assert.NotContains(t, svc, "tailscale")
	assert.Contains(t, read(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert-boot.service")), "ExecStart=/usr/local/sbin/openbao-hostcert-boot.sh")
}

func TestSetupTailscaleSourceDoesNotSignAtSetup(t *testing.T) {
	c := testConfig()
	c.PrincipalSource = PrincipalTailscale
	root, _ := runSetup(t, c, "")

	calls := read(t, filepath.Join(root, "calls.log"))
	assert.NotContains(t, calls, "sign_host_cert")
	assert.NotContains(t, calls, "openbao-hostcert-boot.service")
	assert.Contains(t, read(t, filepath.Join(root, "usr/local/sbin/openbao-hostcert-run.sh")), "tailscale status --peers=false --json")
	assert.Contains(t, read(t, filepath.Join(root, "etc/systemd/system/openbao-hostcert.service")), "After=network-online.target tailscale-join.service")
}

func TestSetupOpksshFailsClosedOnChecksum(t *testing.T) {
	root, out := runSetup(t, testConfig(), `fetch_verify() { return 1; }`)
	assert.Contains(t, out, "opkssh checksum fail")
	assert.Contains(t, out, "hostcert checksum fail")
	assert.NoFileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-opk-ssh.conf"))
	assert.NoFileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/70-hostcert.conf"))
	assert.NoFileExists(t, filepath.Join(root, "usr/local/bin/opkssh"))
}

func TestSetupHostCertOnlyLeavesSSHAlone(t *testing.T) {
	c := testConfig()
	c.OPKSSH = nil
	root, _ := runSetup(t, c, "")

	assert.NoFileExists(t, filepath.Join(root, "etc/ssh/sshd_config.d/10-ssh-login.conf"))
	assert.NotContains(t, read(t, filepath.Join(root, "calls.log")), "pkg_remove")
}

// The imds-hostname principal: IMDSv2 token PUT, then local-hostname with the token.
func runWrapper(t *testing.T, curlBody string) (out string, err error) {
	t.Helper()

	root, _ := runSetup(t, testConfig(), "")
	dir := t.TempDir()

	wrapper := read(t, filepath.Join(root, "usr/local/sbin/openbao-hostcert-run.sh"))
	wrapper = strings.ReplaceAll(wrapper, "/usr/local/bin/openbao-hostcert", filepath.Join(dir, "openbao-hostcert"))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "openbao-hostcert"), []byte("#!/bin/bash\necho \"principal=$2\"\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/bash\n"+curlBody+"\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), []byte(wrapper), 0o755))

	cmd := exec.Command("bash", filepath.Join(dir, "run.sh"))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	o, err := cmd.CombinedOutput()

	return string(o), err
}

const imdsCurl = `case "$*" in
  *"-X PUT"*"/latest/api/token"*) echo TOK ;;
  *"X-aws-ec2-metadata-token: TOK"*"/latest/meta-data/local-hostname"*) echo "$HOSTNAME_FIXTURE" ;;
  *) exit 22 ;;
esac`

func TestIMDSHostnamePrincipal(t *testing.T) {
	t.Setenv("HOSTNAME_FIXTURE", "ip-10-68-1-2.eu-west-3.compute.internal")

	out, err := runWrapper(t, imdsCurl)
	require.NoError(t, err, out)
	assert.Equal(t, "principal=ip-10-68-1-2.eu-west-3.compute.internal\n", out)
}

func TestIMDSHostnameRefusesUnusableAnswers(t *testing.T) {
	for _, h := range []string{"", "a b.internal", "x;id.internal", ".internal", "a..b", "host.", "$(id)"} {
		t.Setenv("HOSTNAME_FIXTURE", h)

		out, err := runWrapper(t, imdsCurl)
		require.Error(t, err, "hostname %q", h)
		assert.NotContains(t, out, "principal=", "hostname %q", h)
	}

	_, err := runWrapper(t, `exit 7`)
	assert.Error(t, err, "IMDS unreachable")
}
