package awsrouter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// opksshConfig returns exampleConfig with a realistic (fictitious) opkssh
// input: one provider, one authorized identity. The checksums are real
// v0.16.0 sha256 digests (from the release's checksums.txt and the
// tagged repo), so this doubles as a record of what was verified for the
// PR — but pkg/awsrouter itself is version-agnostic: nothing here is
// hardcoded outside this test.
func opksshConfig(t *testing.T) TailscaleInstanceConfig {
	t.Helper()

	c := exampleConfig()
	c.OPKSSH = &OPKSSHConfig{
		Enabled:             true,
		ArtifactVersion:     "0.16.0",
		ArtifactURL:         "https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64",
		ArtifactSHA256:      "9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44",
		SELinuxModuleURL:    "https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/opkssh.te",
		SELinuxModuleSHA256: "f68bac733ecd604172eb5b4fe6e472eba195bcffa8444e44723e6fb9546926c4",
		Providers: []OPKSSHProvider{
			{Issuer: "https://access.example.com", ClientID: "opkssh", Expiration: "24h"},
		},
		AuthorizedIdentities: []OPKSSHAuthID{
			{User: "ec2-user", Group: "ssh-admins", Issuer: "https://access.example.com"},
		},
	}

	return c
}

func TestUserDataDefaultHasNoOPKSSH(t *testing.T) {
	files, _ := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.NotContains(t, files, "/etc/tailscale-router/opkssh-providers")
	assert.NotContains(t, files, "/etc/tailscale-router/opkssh-auth_id")
	assert.Contains(t, files["/etc/tailscale-router/router.env"], `OPKSSH="false"`)

	for path := range files {
		assert.NotContains(t, path, "opkssh")
	}
}

func TestUserDataOPKSSHGolden(t *testing.T) {
	c := opksshConfig(t)
	require.NoError(t, c.validateOPKSSH())
	assertGolden(t, "userdata-opkssh.yaml", buildTailscaleUserData(c))
}

func TestUserDataOPKSSHPackages(t *testing.T) {
	rendered := buildTailscaleUserData(opksshConfig(t))
	assert.Contains(t, rendered, "\n  - checkpolicy\n", "router-setup.sh's opkssh install needs checkmodule/semodule_package")
	// router-setup.sh downloads with curl, already present on AL2023 —
	// install-linux.sh's own wget requirement no longer applies.
	assert.NotContains(t, rendered, "wget")

	// Off by default: the package doesn't appear without OPKSSH.
	def := buildTailscaleUserData(exampleConfig())
	assert.NotContains(t, def, "checkpolicy")
}

// The bootstrap stages the exact opkssh config values (as
// /etc/tailscale-router/router.env and two small literal files);
// router-setup.sh's setup_opkssh (router_setup_test.go) is what
// actually installs opkssh and writes its final /etc/opk/* files and
// sshd drop-in, replacing opkssh's own upstream install-linux.sh (which
// does not recognize Amazon Linux 2023 — see CHANGELOG.md) with steps
// this package owns.
func TestUserDataOPKSSHStagesConfig(t *testing.T) {
	c := opksshConfig(t)
	files, _ := writeFiles(t, buildTailscaleUserData(c))

	env := files["/etc/tailscale-router/router.env"]
	for _, want := range []string{
		`OPKSSH="true"`,
		`OPKSSH_ARTIFACT_VERSION="0.16.0"`,
		`OPKSSH_ARTIFACT_URL="` + c.OPKSSH.ArtifactURL + `"`,
		`OPKSSH_ARTIFACT_SHA256="` + c.OPKSSH.ArtifactSHA256 + `"`,
		`OPKSSH_SELINUX_URL="` + c.OPKSSH.SELinuxModuleURL + `"`,
		`OPKSSH_SELINUX_SHA256="` + c.OPKSSH.SELinuxModuleSHA256 + `"`,
	} {
		assert.Contains(t, env, want)
	}

	assert.Equal(t, "https://access.example.com opkssh 24h\n", files["/etc/tailscale-router/opkssh-providers"])
	assert.Equal(t, "ec2-user oidc:groups:ssh-admins https://access.example.com\n", files["/etc/tailscale-router/opkssh-auth_id"])

	for path := range files {
		assert.NotContains(t, path, "trusted-user-ca-keys")
	}
}

// opkssh is independent of the certificate path: both can be set, and
// each renders exactly as it does alone.
// opkssh is independent of the certificate path: both stage cleanly
// together, and router-setup.sh runs both setup_ssh_user_ca and
// setup_opkssh independently of each other (router_setup_test.go).
func TestUserDataOPKSSHWithSSHUserCA(t *testing.T) {
	c := sshCAConfig(t)
	c.OPKSSH = opksshConfig(t).OPKSSH
	require.NoError(t, c.validateSSHUserCA())
	require.NoError(t, c.validateOPKSSH())

	files, _ := writeFiles(t, buildTailscaleUserData(c))

	assert.Contains(t, files, "/etc/tailscale-router/trusted-user-ca-keys.pub")
	assert.Contains(t, files, "/etc/tailscale-router/opkssh-providers")
	env := files["/etc/tailscale-router/router.env"]
	assert.Contains(t, env, `SSH_USER_CA="true"`)
	assert.Contains(t, env, `OPKSSH="true"`)
}

// Stacking opkssh on a certificate-login rotation no longer meaningfully
// threatens the EC2 limit post-bootstrap-split (see TestUserDataFitsEC2Limit's
// "ssh-user-ca + opkssh" case, checked against an 8 KiB generous limit,
// not the pre-split 200-byte margin this used to need) — the size test
// in userdata_test.go now covers this combination directly.
func TestValidateOPKSSH(t *testing.T) {
	valid := func() *OPKSSHConfig {
		return &OPKSSHConfig{
			Enabled:             true,
			ArtifactVersion:     "0.16.0",
			ArtifactURL:         "https://example.com/opkssh-linux-arm64",
			ArtifactSHA256:      strings.Repeat("a", 64),
			SELinuxModuleURL:    "https://example.com/opkssh.te",
			SELinuxModuleSHA256: strings.Repeat("b", 64),
			Providers: []OPKSSHProvider{
				{Issuer: "https://access.example.com", ClientID: "opkssh", Expiration: "24h"},
			},
			AuthorizedIdentities: []OPKSSHAuthID{
				{User: "ec2-user", Group: "ssh-admins", Issuer: "https://access.example.com"},
			},
		}
	}

	cases := map[string]struct {
		mutate  func(*OPKSSHConfig)
		wantErr string
	}{
		"nil is off": {mutate: nil},
		"disabled with garbage is off": {mutate: func(o *OPKSSHConfig) {
			o.Enabled = false
			o.ArtifactSHA256 = "not-a-checksum"
		}},
		"valid": {mutate: func(*OPKSSHConfig) {}},
		"missing version": {mutate: func(o *OPKSSHConfig) {
			o.ArtifactVersion = ""
		}, wantErr: "ArtifactVersion is required"},
		"short checksum": {mutate: func(o *OPKSSHConfig) {
			o.ArtifactSHA256 = "abc123"
		}, wantErr: "ArtifactSHA256 is not a 64-character"},
		"uppercase checksum": {mutate: func(o *OPKSSHConfig) {
			o.ArtifactSHA256 = strings.ToUpper(o.ArtifactSHA256)
		}, wantErr: "ArtifactSHA256 is not a 64-character"},
		"non-hex checksum": {mutate: func(o *OPKSSHConfig) {
			o.SELinuxModuleSHA256 = strings.Repeat("g", 64)
		}, wantErr: "SELinuxModuleSHA256 is not a 64-character"},
		"http artifact url": {mutate: func(o *OPKSSHConfig) {
			o.ArtifactURL = "http://example.com/opkssh-linux-arm64"
		}, wantErr: "ArtifactURL"},
		"empty selinux module url": {mutate: func(o *OPKSSHConfig) {
			o.SELinuxModuleURL = ""
		}, wantErr: "SELinuxModuleURL"},
		"no providers": {mutate: func(o *OPKSSHConfig) {
			o.Providers = nil
		}, wantErr: "Providers is empty"},
		"provider http issuer": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].Issuer = "http://access.example.com"
		}, wantErr: "Providers[0].Issuer"},
		"provider issuer not a url": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].Issuer = "access.example.com"
		}, wantErr: "Providers[0].Issuer"},
		"provider empty client id": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].ClientID = ""
		}, wantErr: "ClientID"},
		"provider client id with space": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].ClientID = "opkssh client"
		}, wantErr: "ClientID"},
		"provider client id with shell metacharacters": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].ClientID = "$(rm -rf /)"
		}, wantErr: "ClientID"},
		"provider bad expiration": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].Expiration = "1day"
		}, wantErr: "Expiration"},
		"provider expiration case sensitive": {mutate: func(o *OPKSSHConfig) {
			o.Providers[0].Expiration = "24H"
		}, wantErr: "Expiration"},
		"no authorized identities": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities = nil
		}, wantErr: "AuthorizedIdentities is empty"},
		"authid user is a path": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].User = "../x"
		}, wantErr: "not a login name"},
		"authid root": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].User = "root"
		}, wantErr: "names root"},
		"authid empty group": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = ""
		}, wantErr: "not a plain group name"},
		"authid group with space": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = "ssh admins"
		}, wantErr: "not a plain group name"},
		"authid group with semicolon": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = "ssh-admins; rm -rf /"
		}, wantErr: "not a plain group name"},
		"authid group with backtick": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = "`id`"
		}, wantErr: "not a plain group name"},
		"authid group with dollar-paren": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = "$(whoami)"
		}, wantErr: "not a plain group name"},
		"authid group with quote": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Group = `ssh"admins`
		}, wantErr: "not a plain group name"},
		"authid issuer not a configured provider": {mutate: func(o *OPKSSHConfig) {
			o.AuthorizedIdentities[0].Issuer = "https://other.example.com"
		}, wantErr: "is not one of OPKSSH.Providers"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := exampleConfig()

			if tc.mutate != nil {
				o := valid()
				tc.mutate(o)
				c.OPKSSH = o
			}

			err := c.validateOPKSSH()
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
