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
		Environment:    "example",
		Region:         "eu-west-1",
		VPCCIDRs:       []string{"10.0.0.0/16", "10.1.0.0/16"},
		Tailnet:        "acme",
		SSMAuthKeyPath: "/tailscale/acme/auth-key",
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
// router. Change testdata/userdata-default.yaml only on purpose (the SSH
// inputs left it untouched; the join log on the serial console did not).
func TestUserDataDefaultUnchanged(t *testing.T) {
	c := exampleConfig()
	require.NoError(t, c.validateSSHUserCA())
	assertGolden(t, "userdata-default.yaml", buildTailscaleUserData(c))
}

// The join is the one critical path; its log must reach the serial
// console, the only diagnosis there is without a shell on the router.
func TestUserDataJoinLogsToConsole(t *testing.T) {
	files, _ := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.Contains(t, files["/usr/local/sbin/tailscale-join.sh"], "exec > >(tee -a /var/log/tailscale-join.log) 2>&1")
	assert.Contains(t, files["/etc/systemd/system/tailscale-join.service"], "StandardOutput=journal+console")
}

func TestUserDataDefaultHasNoCertificateLogin(t *testing.T) {
	files, cmds := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.NotContains(t, files, "/etc/ssh/sshd_config.d/10-user-ca.conf")
	assert.NotContains(t, files, "/etc/ssh/trusted-user-ca-keys.pub")

	for path := range files {
		assert.NotContains(t, path, "authorized_principals")
	}

	assert.NotContains(t, cmds, "firewall-cmd --permanent --zone=public --remove-service=ssh")
}

func TestUserDataSSHUserCAGolden(t *testing.T) {
	c := sshCAConfig(t)
	require.NoError(t, c.validateSSHUserCA())
	assertGolden(t, "userdata-ssh-user-ca.yaml", buildTailscaleUserData(c))
}

func TestUserDataSSHUserCAFiles(t *testing.T) {
	c := sshCAConfig(t)
	files, cmds := writeFiles(t, buildTailscaleUserData(c))

	assert.Equal(t, c.TrustedUserCAKeys[0]+"\n"+c.TrustedUserCAKeys[1]+"\n", files["/etc/ssh/trusted-user-ca-keys.pub"],
		"both keys, in the caller's order (current, then next during a rotation)")
	assert.Equal(t, "ec2-user\n", files["/etc/ssh/authorized_principals/ec2-user"])
	assert.Equal(t, "breakglass\noncall\n", files["/etc/ssh/authorized_principals/operator"], "principals sorted")
	assert.NotContains(t, files, "/etc/ssh/authorized_principals/root")

	sshd := files["/etc/ssh/sshd_config.d/10-user-ca.conf"]
	for _, line := range []string{
		"TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub",
		"AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u",
		"AuthorizedKeysFile none",
		"PubkeyAuthentication yes",
		"PasswordAuthentication no",
		"LogLevel VERBOSE",
	} {
		assert.Contains(t, strings.Split(sshd, "\n"), line)
	}

	// The existing hardening drop-in is untouched and still refuses root.
	assert.Contains(t, files["/etc/ssh/sshd_config.d/99-hardening.conf"], "PermitRootLogin no\n")

	assert.Contains(t, cmds, "firewall-cmd --permanent --zone=public --remove-service=ssh")
	assert.Contains(t, cmds, "sshd -t")
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

// EC2 refuses user data over 16 KB (before base64). The SSH variant,
// with two CA keys (a rotation) and two users, must fit with room left.
func TestUserDataFitsEC2Limit(t *testing.T) {
	const ec2UserDataLimit = 16 * 1024

	for name, c := range map[string]TailscaleInstanceConfig{
		"default":     exampleConfig(),
		"ssh-user-ca": sshCAConfig(t),
	} {
		size := len(buildTailscaleUserData(c))
		assert.Less(t, size, ec2UserDataLimit-1024, "%s user data is %d bytes; keep 1 KiB of headroom under EC2's 16 KiB", name, size)
	}
}
