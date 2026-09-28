package awsrouter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostCertConfig(t *testing.T) TailscaleInstanceConfig {
	t.Helper()

	c := exampleConfig()
	c.HostCert = &HostCertConfig{
		Enabled:         true,
		ArtifactVersion: "0.13.0",
		ArtifactSHA256:  map[string]string{"arm64": strings.Repeat("a", 64)},
		Address:         "https://openbao.example.internal",
		CABundle:        testCABundlePEM,
		Namespace:       "example",
		AuthMount:       "aws",
		AuthRole:        "router-host",
		ServerIDHeader:  "example-openbao-aws-host",
		SSHMount:        "ssh-host",
		SSHRole:         "router",
		PrincipalPatterns: []string{
			"ip-10-0-*.tailnet.example.ts.net",
			"ip-10-1-*.tailnet.example.ts.net",
		},
	}

	return c
}

// testCABundlePEM is a syntactically valid, self-signed PEM certificate
// — its content is never trusted for anything, only parsed.
const testCABundlePEM = `-----BEGIN CERTIFICATE-----
MIIBWzCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQKEwpFeGFtcGxl
IENBMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowFTETMBEGA1UEChMK
RXhhbXBsZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL6fdpIQMq0bdKis
TFXqqnU49pjkir8d+1xH5sVrqlFYiylvmEchrvWy3iN2/GaLmZxcKqXgep53fwG/
IADH1JSjQjBAMA4GA1UdDwEB/wQEAwIChDAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBT6otk0hCrB+07wNy597W6qWfFmyTAKBggqhkjOPQQDAgNIADBFAiEAt/1c
QoOIFM2vdApUw6yOcYxkK8v4E3UZhSv+IFuWUn4CIHhK3QCy/atdEF5cEprFyFE0
9nqDCf7K1cVNkX6NjJ07
-----END CERTIFICATE-----
`

func TestUserDataDefaultHasNoHostCert(t *testing.T) {
	files, _ := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.NotContains(t, files, "/etc/tailscale-router/hostcert-ca.pem")
	assert.Contains(t, files["/etc/tailscale-router/router.env"], `HOST_CERT="false"`)

	for path := range files {
		assert.NotContains(t, strings.ToLower(path), "hostcert")
	}
}

func TestUserDataHostCertGolden(t *testing.T) {
	c := hostCertConfig(t)
	require.NoError(t, c.validateHostCert())
	assertGolden(t, "userdata-hostcert.yaml", buildTailscaleUserData(c))
}

// The bootstrap stages the exact host-cert config values (as
// /etc/tailscale-router/router.env plus the CA bundle file);
// router-setup.sh's setup_hostcert (router_setup_test.go) is what
// installs the binary, the systemd units, the wrapper and the sshd
// drop-in from them.
func TestUserDataHostCertStagesConfig(t *testing.T) {
	c := hostCertConfig(t)
	files, _ := writeFiles(t, buildTailscaleUserData(c))

	env := files["/etc/tailscale-router/router.env"]
	for _, want := range []string{
		`HOST_CERT="true"`,
		`HOST_CERT_ARTIFACT_VERSION="0.13.0"`,
		`HOST_CERT_ARTIFACT_SHA256="` + strings.Repeat("a", 64) + `"`,
		`HOST_CERT_ADDRESS="https://openbao.example.internal"`,
		`HOST_CERT_NAMESPACE="example"`,
		`HOST_CERT_AUTH_MOUNT="aws"`,
		`HOST_CERT_AUTH_ROLE="router-host"`,
		`HOST_CERT_SERVER_ID_HEADER="example-openbao-aws-host"`,
		`HOST_CERT_SSH_MOUNT="ssh-host"`,
		`HOST_CERT_SSH_ROLE="router"`,
		`HOST_CERT_PRINCIPAL_PATTERNS="ip-10-0-*.tailnet.example.ts.net,ip-10-1-*.tailnet.example.ts.net"`,
	} {
		assert.Contains(t, env, want)
	}

	assert.Equal(t, testCABundlePEM, files["/etc/tailscale-router/hostcert-ca.pem"])
}

// No CA bundle: the mount config renders, but the file never appears —
// router-setup.sh checks for its presence, not a flag.
func TestUserDataHostCertNoCABundle(t *testing.T) {
	c := hostCertConfig(t)
	c.HostCert.CABundle = ""
	require.NoError(t, c.validateHostCert())

	files, _ := writeFiles(t, buildTailscaleUserData(c))

	assert.NotContains(t, files, "/etc/tailscale-router/hostcert-ca.pem")
	assert.Contains(t, files["/etc/tailscale-router/router.env"], `HOST_CERT="true"`)
}

// The host-certificate path is independent of certificate login and
// opkssh: all three can be set, and each renders exactly as it does
// alone.
func TestUserDataHostCertWithOPKSSHAndSSHUserCA(t *testing.T) {
	c := sshCAConfig(t)
	c.OPKSSH = opksshConfig(t).OPKSSH
	c.HostCert = hostCertConfig(t).HostCert
	require.NoError(t, c.validateSSHUserCA())
	require.NoError(t, c.validateOPKSSH())
	require.NoError(t, c.validateHostCert())

	files, _ := writeFiles(t, buildTailscaleUserData(c))

	assert.Contains(t, files, "/etc/tailscale-router/trusted-user-ca-keys.pub")
	assert.Contains(t, files, "/etc/tailscale-router/opkssh-providers")
	assert.Contains(t, files, "/etc/tailscale-router/hostcert-ca.pem")

	env := files["/etc/tailscale-router/router.env"]
	assert.Contains(t, env, `SSH_USER_CA="true"`)
	assert.Contains(t, env, `OPKSSH="true"`)
	assert.Contains(t, env, `HOST_CERT="true"`)
}

func TestValidateHostCert(t *testing.T) {
	valid := func() *HostCertConfig {
		return &HostCertConfig{
			Enabled:           true,
			ArtifactVersion:   "0.13.0",
			ArtifactSHA256:    map[string]string{"arm64": strings.Repeat("a", 64)},
			Address:           "https://openbao.example.internal",
			Namespace:         "example",
			AuthMount:         "aws",
			AuthRole:          "router-host",
			ServerIDHeader:    "example-openbao-aws-host",
			SSHMount:          "ssh-host",
			SSHRole:           "router",
			PrincipalPatterns: []string{"ip-10-0-*.tailnet.example.ts.net"},
		}
	}

	cases := map[string]struct {
		mutate  func(*HostCertConfig)
		wantErr string
	}{
		"nil is off":                   {mutate: nil},
		"disabled with garbage is off": {mutate: func(h *HostCertConfig) { h.Enabled = false; h.Address = "not a url" }},
		"valid":                        {mutate: func(*HostCertConfig) {}},
		"missing version":              {mutate: func(h *HostCertConfig) { h.ArtifactVersion = "" }, wantErr: "ArtifactVersion is required"},
		"malformed version":            {mutate: func(h *HostCertConfig) { h.ArtifactVersion = "v0.13.0" }, wantErr: `is not "X.Y.Z"`},
		"missing arch checksum": {
			mutate:  func(h *HostCertConfig) { h.ArtifactSHA256 = map[string]string{"amd64": strings.Repeat("a", 64)} },
			wantErr: `no entry for "arm64"`,
		},
		"short checksum": {mutate: func(h *HostCertConfig) { h.ArtifactSHA256["arm64"] = "abc123" }, wantErr: "not a 64-character"},
		"uppercase checksum": {
			mutate:  func(h *HostCertConfig) { h.ArtifactSHA256["arm64"] = strings.ToUpper(strings.Repeat("a", 64)) },
			wantErr: "not a 64-character",
		},
		"http address":                 {mutate: func(h *HostCertConfig) { h.Address = "http://openbao.example.internal" }, wantErr: "not an https URL"},
		"address trailing slash":       {mutate: func(h *HostCertConfig) { h.Address = "https://openbao.example.internal/" }, wantErr: "trailing slash"},
		"not a url at all":             {mutate: func(h *HostCertConfig) { h.Address = "not a url" }, wantErr: "not an https URL"},
		"malformed CA bundle":          {mutate: func(h *HostCertConfig) { h.CABundle = "not a pem" }, wantErr: "not a PEM certificate bundle"},
		"valid CA bundle":              {mutate: func(h *HostCertConfig) { h.CABundle = testCABundlePEM }},
		"missing auth mount":           {mutate: func(h *HostCertConfig) { h.AuthMount = "" }, wantErr: "AuthMount is required"},
		"auth mount with space":        {mutate: func(h *HostCertConfig) { h.AuthMount = "a b" }, wantErr: "AuthMount \"a b\" is not a plain token"},
		"missing auth role":            {mutate: func(h *HostCertConfig) { h.AuthRole = "" }, wantErr: "AuthRole is required"},
		"missing server id header":     {mutate: func(h *HostCertConfig) { h.ServerIDHeader = "" }, wantErr: "ServerIDHeader is required"},
		"missing ssh mount":            {mutate: func(h *HostCertConfig) { h.SSHMount = "" }, wantErr: "SSHMount is required"},
		"missing ssh role":             {mutate: func(h *HostCertConfig) { h.SSHRole = "" }, wantErr: "SSHRole is required"},
		"empty namespace is root":      {mutate: func(h *HostCertConfig) { h.Namespace = "" }},
		"namespace with space":         {mutate: func(h *HostCertConfig) { h.Namespace = "a b" }, wantErr: "Namespace \"a b\" is not a plain token"},
		"no principal patterns":        {mutate: func(h *HostCertConfig) { h.PrincipalPatterns = nil }, wantErr: "PrincipalPatterns is empty"},
		"empty principal pattern":      {mutate: func(h *HostCertConfig) { h.PrincipalPatterns = []string{""} }, wantErr: "PrincipalPatterns[0] is empty"},
		"bare star principal pattern":  {mutate: func(h *HostCertConfig) { h.PrincipalPatterns = []string{"*"} }, wantErr: "bare \"*\""},
		"principal pattern with space": {mutate: func(h *HostCertConfig) { h.PrincipalPatterns = []string{"a b"} }, wantErr: "not a plain glob token"},
		"principal pattern with glob":  {mutate: func(h *HostCertConfig) { h.PrincipalPatterns = []string{"ip-10-*-0-1.example.ts.net"} }},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := exampleConfig()

			if tc.mutate != nil {
				h := valid()
				tc.mutate(h)
				c.HostCert = h
			}

			err := c.validateHostCert()
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
