package awsrouter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

func exampleConfig() TailscaleInstanceConfig {
	return TailscaleInstanceConfig{
		Environment:        "example",
		Region:             "eu-west-1",
		VPCCIDRs:           []string{"10.0.0.0/16", "10.1.0.0/16"},
		Tailnet:            "acme",
		SSMAuthKeyPath:     "/tailscale/acme/auth-key",
		RouterSetupVersion: "1.11.0",
	}
}

// caKey is a deterministic ed25519 public key in authorized_keys form,
// so the golden render is stable.
func caKey(t *testing.T, seed byte, comment string) string {
	t.Helper()

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))

	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err)

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line += " " + comment
	}

	return line
}

func sshCAConfig(t *testing.T) TailscaleInstanceConfig {
	t.Helper()

	c := exampleConfig()
	c.TrustedUserCAKeys = []string{caKey(t, 1, "example-ca-current"), caKey(t, 2, "example-ca-next")}
	c.AuthorizedPrincipals = map[string][]string{
		"ec2-user": {"ec2-user"},
		"operator": {"oncall", "breakglass"},
	}

	return c
}

// assertGolden compares a render with testdata/<name>; UPDATE_GOLDEN=1
// rewrites it (review the diff).
func assertGolden(t *testing.T, name, got string) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))

		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "golden missing: UPDATE_GOLDEN=1 go test ./pkg/awsrouter/")
	assert.Equal(t, string(want), got)
}

// writeFiles parses the cloud-config and returns write_files by path.
func writeFiles(t *testing.T, userData string) (map[string]string, []string) {
	t.Helper()

	var doc struct {
		WriteFiles []struct {
			Path    string `yaml:"path"`
			Content string `yaml:"content"`
		} `yaml:"write_files"`
		RunCmd []any `yaml:"runcmd"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(userData), &doc), "user data must stay valid YAML")

	files := map[string]string{}
	for _, f := range doc.WriteFiles {
		files[f.Path] = f.Content
	}

	var cmds []string

	for _, c := range doc.RunCmd {
		if s, ok := c.(string); ok {
			cmds = append(cmds, s)
		}
	}

	return files, cmds
}

// The default render is pinned byte-for-byte: any change to it is a new
// launch template version, and the ASG's instance refresh replaces every
// router. Change testdata/userdata-default.yaml only on purpose.
func TestUserDataDefaultUnchanged(t *testing.T) {
	c := exampleConfig()
	require.NoError(t, c.validateSSHUserCA())
	assertGolden(t, "userdata-default.yaml", buildTailscaleUserData(c))
}

// The bootstrap's own runcmd is the one critical path this file still
// renders directly: a broken download or checksum must never run
// router-setup.sh, and a broken router-setup.sh must never block the
// tailnet join it itself arms. The join's own log reaching the serial
// console is router-setup.sh's job — see router_setup_test.go.
func TestUserDataBootstrapFailsClosed(t *testing.T) {
	_, cmds := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	joined := strings.Join(cmds, "\n")
	assert.Contains(t, joined, "sha256sum -c -", "the download is checksum-verified before use")
	assert.Contains(t, joined, `echo "router-setup checksum fail"`)
	assert.Contains(t, joined, `/usr/local/sbin/router-setup.sh || echo "router-setup fail"`,
		"a failing router-setup.sh must not stop the join from being armed")
	assert.Contains(t, cmds, "systemctl enable --now --no-block tailscale-join.service")
}

// The bootstrap pins router-setup.sh's own digest — computed from the
// exact bytes embedded in this build, so it is always self-consistent —
// and fetches it from a URL keyed by RouterSetupVersion.
func TestUserDataBootstrapPinsRouterSetupScript(t *testing.T) {
	c := exampleConfig()
	files, cmds := writeFiles(t, buildTailscaleUserData(c))

	assert.Contains(t, strings.Join(cmds, "\n"), RouterSetupSHA256())
	assert.Contains(t, strings.Join(cmds, "\n"), RouterSetupURL(c.RouterSetupVersion))
	assert.Contains(t, cmds, `curl -fsSL -o /usr/local/sbin/router-setup.sh "`+RouterSetupURL(c.RouterSetupVersion)+`"`)

	env := files["/etc/tailscale-router/router.env"]
	assert.Contains(t, env, `REGION="eu-west-1"`)
	assert.Contains(t, env, `SSH_USER_CA="false"`)
	assert.Contains(t, env, `OPKSSH="false"`)
}

func TestUserDataDefaultHasNoCertificateLogin(t *testing.T) {
	files, cmds := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.NotContains(t, files, "/etc/tailscale-router/trusted-user-ca-keys.pub")

	for path := range files {
		assert.NotContains(t, path, "authorized_principals")
	}

	assert.Contains(t, files["/etc/tailscale-router/router.env"], `SSH_USER_CA="false"`)
	assert.NotContains(t, strings.Join(cmds, "\n"), "remove-service=ssh")
}

func TestUserDataSSHUserCAGolden(t *testing.T) {
	c := sshCAConfig(t)
	require.NoError(t, c.validateSSHUserCA())
	assertGolden(t, "userdata-ssh-user-ca.yaml", buildTailscaleUserData(c))
}

// The bootstrap stages the raw CA material unchanged; router-setup.sh
// (router_setup_test.go) is what turns it into sshd's final
// configuration, so this only checks what the bootstrap itself renders.
func TestUserDataSSHUserCAStagesFiles(t *testing.T) {
	c := sshCAConfig(t)
	files, _ := writeFiles(t, buildTailscaleUserData(c))

	assert.Equal(t, c.TrustedUserCAKeys[0]+"\n"+c.TrustedUserCAKeys[1]+"\n", files["/etc/tailscale-router/trusted-user-ca-keys.pub"],
		"both keys, in the caller's order (current, then next during a rotation)")
	assert.Equal(t, "ec2-user\n", files["/etc/tailscale-router/authorized_principals/ec2-user"])
	assert.Equal(t, "breakglass\noncall\n", files["/etc/tailscale-router/authorized_principals/operator"], "principals sorted")
	assert.NotContains(t, files, "/etc/tailscale-router/authorized_principals/root")

	assert.Contains(t, files["/etc/tailscale-router/router.env"], `SSH_USER_CA="true"`)
}

// Map iteration and the caller's principal order never reach the
// launch template.
func TestUserDataSSHUserCADeterministic(t *testing.T) {
	a := sshCAConfig(t)
	b := sshCAConfig(t)
	b.AuthorizedPrincipals = map[string][]string{
		"operator": {"breakglass", "oncall"},
		"ec2-user": {"ec2-user"},
	}

	first := buildTailscaleUserData(a)
	for range 20 {
		assert.Equal(t, first, buildTailscaleUserData(b))
	}
}

func TestValidateSSHUserCA(t *testing.T) {
	key := caKey(t, 1, "")

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"x"}}
	require.NoError(t, cert.SignCert(rand.Reader, signer))
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	ok := map[string][]string{"ec2-user": {"ec2-user"}}

	cases := map[string]struct {
		keys       []string
		principals map[string][]string
		wantErr    string
	}{
		"both empty is off":          {},
		"one key":                    {keys: []string{key}, principals: ok},
		"surrounding space trimmed":  {keys: []string{"  " + key + "\n"}, principals: ok},
		"keys without principals":    {keys: []string{key}, wantErr: "needs AuthorizedPrincipals"},
		"principals without keys":    {principals: ok, wantErr: "needs TrustedUserCAKeys"},
		"not a key":                  {keys: []string{"ssh-ed25519 notbase64"}, principals: ok, wantErr: "not one plain OpenSSH public key"},
		"two keys on one entry":      {keys: []string{key + "\n" + caKey(t, 2, "")}, principals: ok, wantErr: "not one plain"},
		"key options":                {keys: []string{`cert-authority ` + key}, principals: ok, wantErr: "not one plain"},
		"a certificate is not a CA":  {keys: []string{certLine}, principals: ok, wantErr: "is a certificate"},
		"repeated key":               {keys: []string{key, key + " other-comment"}, principals: ok, wantErr: "repeats"},
		"root":                       {keys: []string{key}, principals: map[string][]string{"root": {"root"}}, wantErr: "root"},
		"user is a path":             {keys: []string{key}, principals: map[string][]string{"../x": {"x"}}, wantErr: "not a login name"},
		"empty principal list":       {keys: []string{key}, principals: map[string][]string{"ec2-user": {}}, wantErr: "is empty"},
		"principal with space":       {keys: []string{key}, principals: map[string][]string{"ec2-user": {"a b"}}, wantErr: "not a plain name"},
		"principal is a comment":     {keys: []string{key}, principals: map[string][]string{"ec2-user": {"#x"}}, wantErr: "not a plain name"},
		"principal with options":     {keys: []string{key}, principals: map[string][]string{"ec2-user": {`from="10.0.0.1"`}}, wantErr: "not a plain name"},
		"repeated principal":         {keys: []string{key}, principals: map[string][]string{"ec2-user": {"a", "a"}}, wantErr: "repeats a principal"},
		"email-shaped principal":     {keys: []string{key}, principals: map[string][]string{"ec2-user": {"someone@example.com"}}},
		"two users, sorted and kept": {keys: []string{key}, principals: map[string][]string{"b": {"b"}, "a": {"a"}}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := exampleConfig()
			c.TrustedUserCAKeys = tc.keys
			c.AuthorizedPrincipals = tc.principals

			err := c.validateSSHUserCA()
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// EC2 refuses user data over 16 KiB (before base64). Since the bootstrap
// split (moving chrony/audit/journald/sshd hardening/the join
// script/systemd units/the opkssh install steps into router-setup.sh,
// a download this file only pins by URL and sha256), what is left in
// user data is small even with every feature enabled together —
// generous headroom, not the tight margin the pre-split design needed.
func TestUserDataFitsEC2Limit(t *testing.T) {
	const ec2UserDataLimit = 16 * 1024
	// 12 KiB, not 8: HostCert's own CA bundle (a full PEM certificate,
	// staged verbatim) is the one input here whose size is not this
	// package's to bound — an estate supplies whatever chain its
	// OpenBAO server needs. Still a third under EC2's real limit.
	const generousLimit = 12 * 1024

	c := sshCAConfig(t)
	c.OPKSSH = opksshConfig(t).OPKSSH
	c.HostCert = hostCertConfig(t).HostCert
	require.NoError(t, c.validateSSHUserCA())
	require.NoError(t, c.validateOPKSSH())
	require.NoError(t, c.validateHostCert())

	for name, cfg := range map[string]TailscaleInstanceConfig{
		"default":                         exampleConfig(),
		"ssh-user-ca":                     sshCAConfig(t),
		"opkssh":                          opksshConfig(t),
		"hostcert":                        hostCertConfig(t),
		"ssh-user-ca + opkssh + hostcert": c,
	} {
		size := len(buildTailscaleUserData(cfg))
		msg := "%s user data is %d bytes; want under %d (EC2's own hard limit is %d)"
		assert.Less(t, size, generousLimit, msg, name, size, generousLimit, ec2UserDataLimit)
	}
}
