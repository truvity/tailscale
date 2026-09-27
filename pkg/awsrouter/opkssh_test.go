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
		InstallScriptURL:    "https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/scripts/install-linux.sh",
		InstallScriptSHA256: "493cc42f55b2da31491c3947fd75dc2589d691d1a79fa284fc8e9fef3815ca54",
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
	files, cmds := writeFiles(t, buildTailscaleUserData(exampleConfig()))

	assert.NotContains(t, files, "/usr/local/sbin/opkssh-install.sh")
	assert.NotContains(t, files, "/etc/opk/providers")
	assert.NotContains(t, files, "/etc/opk/auth_id")
	assert.NotContains(t, cmds, "/usr/local/sbin/opkssh-install.sh")

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
	assert.Contains(t, rendered, "\n  - wget\n", "install-linux.sh requires wget")
	assert.Contains(t, rendered, "\n  - checkpolicy\n", "checkmodule/semodule_package build the SELinux module")

	// Off by default: neither package appears without OPKSSH.
	def := buildTailscaleUserData(exampleConfig())
	assert.NotContains(t, def, "wget")
	assert.NotContains(t, def, "checkpolicy")
}

func TestUserDataOPKSSHInstallScript(t *testing.T) {
	c := opksshConfig(t)
	files, cmds := writeFiles(t, buildTailscaleUserData(c))

	assert.Contains(t, cmds, "/usr/local/sbin/opkssh-install.sh", "runcmd invokes the script written by write_files")

	script := files["/usr/local/sbin/opkssh-install.sh"]
	require.NotEmpty(t, script)

	// Fail-closed: the artifacts are verified against the exact
	// configured sha256 before install-linux.sh ever runs, and a verify
	// failure aborts (exit 0, not a hard failure that would leave the
	// router mid-install).
	for _, want := range []string{
		c.OPKSSH.ArtifactURL,
		c.OPKSSH.ArtifactSHA256,
		c.OPKSSH.SELinuxModuleURL,
		c.OPKSSH.SELinuxModuleSHA256,
		c.OPKSSH.InstallScriptURL,
		c.OPKSSH.InstallScriptSHA256,
		"sha256sum -c",
		`c=/etc/ssh/sshd_config.d/60-opk-ssh.conf`,
		`fail(){ echo "opkssh $1 fail"; rm -f "$c"; exit 0; }`,
		`|| fail "checksum"`,
		`|| fail "install"`,
	} {
		assert.Contains(t, script, want)
	}

	// EC2 Instance Connect ships its own AuthorizedKeysCommand on some
	// AL2023 AMIs, which would silently win over opkssh's AND change
	// which sshd drop-in filename install-linux.sh picks — so it is
	// removed BEFORE install-linux.sh ever runs, not after.
	dnfIndex := strings.Index(script, "dnf remove -y ec2-instance-connect || true")
	installIndex := strings.Index(script, `bash "$d/s"`)
	require.GreaterOrEqual(t, dnfIndex, 0)
	require.GreaterOrEqual(t, installIndex, 0)
	assert.Less(t, dnfIndex, installIndex, "ec2-instance-connect must be removed before install-linux.sh runs")

	// --no-home-policy: the only policy surface is /etc/opk/auth_id.
	// Without it, install-linux.sh lets a login user grant themselves
	// extra identities via ~user/.opk/auth_id and installs a passwordless
	// sudoers rule for opkssh to read it. The script also asserts that
	// rule was not created, rather than trusting the flag silently.
	assert.Contains(t, script, "--no-home-policy")
	assert.Contains(t, script, `[ -e /etc/sudoers.d/opkssh ] && fail "sudoers"`)

	// install-linux.sh runs with the verified local files and
	// --no-sshd-restart, so nothing reloads sshd before our own sshd -t
	// gate below.
	assert.Contains(t, script, `--install-from="$d/b" --install-te-from="$d/t"`)
	assert.Contains(t, script, `--install-version="0.16.0" --no-sshd-restart`)

	// The providers/auth_id content and the ownership/mode opkssh's own
	// docs require.
	assert.Contains(t, script, "https://access.example.com opkssh 24h")
	assert.Contains(t, script, "ec2-user oidc:groups:ssh-admins https://access.example.com")
	assert.Contains(t, script, "chown root:opksshuser /etc/opk/providers /etc/opk/auth_id")
	assert.Contains(t, script, "chmod 640 /etc/opk/providers /etc/opk/auth_id")

	// The lock-out-safe guard: sshd -t before any reload, and a
	// rollback (removing only the opkssh drop-in) on failure — the
	// certificate path's own files are never named here.
	sshdTIndex := strings.Index(script, "sshd -t && {")
	require.GreaterOrEqual(t, sshdTIndex, 0, "sshd -t must gate the reload")
	assert.Contains(t, script, "systemctl reload sshd")
	assert.Contains(t, script, `rm -f "$c"`)
	assert.NotContains(t, script, "trusted-user-ca-keys")
	assert.NotContains(t, script, "10-user-ca.conf")
	for path := range files {
		assert.NotContains(t, path, "trusted-user-ca-keys")
	}
}

// opkssh is independent of the certificate path: both can be set, and
// each renders exactly as it does alone.
func TestUserDataOPKSSHWithSSHUserCA(t *testing.T) {
	c := sshCAConfig(t)
	c.OPKSSH = opksshConfig(t).OPKSSH
	require.NoError(t, c.validateSSHUserCA())
	require.NoError(t, c.validateOPKSSH())

	files, cmds := writeFiles(t, buildTailscaleUserData(c))

	assert.Contains(t, files, "/etc/ssh/sshd_config.d/10-user-ca.conf")
	assert.Contains(t, files, "/usr/local/sbin/opkssh-install.sh")
	assert.Contains(t, cmds, "sshd -t")
	assert.Contains(t, cmds, "/usr/local/sbin/opkssh-install.sh")
}

// opkssh alone fits userdata_test.go's shared 1 KiB headroom (see
// TestUserDataFitsEC2Limit). Stacked on an existing certificate login —
// the realistic shape for the pilot router, which already has one — the
// margin is much tighter: opkssh's own pinned artifacts (three URLs and
// three sha256 digests it must carry to fail closed) leave little room.
// This test enforces the true EC2 limit for that combination, with a
// smaller, explicit margin — not the 1 KiB convention the other cases
// use.
//
// **Operational consequence, not just a test detail**: enabling opkssh
// alongside a certificate-login rotation (two CA keys, more than one
// principal user) can exceed the hard limit outright, which Pulumi/AWS
// would refuse at apply time. Keep `Providers`/`AuthorizedIdentities`
// minimal, and do not roll an opkssh change during an active CA
// rotation without re-running this test against the real inputs.
func TestUserDataOPKSSHWithCertificateLoginFitsEC2Limit(t *testing.T) {
	const ec2UserDataLimit = 16 * 1024
	const margin = 200 // smaller than the 1 KiB convention — see comment above

	// The realistic pilot shape: opkssh added to a router that already
	// has certificate login for exactly one user, one CA key (no
	// rotation in progress).
	c := exampleConfig()
	c.TrustedUserCAKeys = []string{caKey(t, 1, "example-ca-current")}
	c.AuthorizedPrincipals = map[string][]string{"ec2-user": {"ec2-user"}}
	c.OPKSSH = opksshConfig(t).OPKSSH

	require.NoError(t, c.validateSSHUserCA())
	require.NoError(t, c.validateOPKSSH())

	size := len(buildTailscaleUserData(c))
	assert.Less(t, size, ec2UserDataLimit-margin,
		"opkssh + one-key certificate login user data is %d bytes; keep at least %d bytes under EC2's 16 KiB limit", size, margin)
}

func TestValidateOPKSSH(t *testing.T) {
	valid := func() *OPKSSHConfig {
		return &OPKSSHConfig{
			Enabled:             true,
			ArtifactVersion:     "0.16.0",
			ArtifactURL:         "https://example.com/opkssh-linux-arm64",
			ArtifactSHA256:      strings.Repeat("a", 64),
			SELinuxModuleURL:    "https://example.com/opkssh.te",
			SELinuxModuleSHA256: strings.Repeat("b", 64),
			InstallScriptURL:    "https://example.com/install-linux.sh",
			InstallScriptSHA256: strings.Repeat("c", 64),
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
		"empty install script url": {mutate: func(o *OPKSSHConfig) {
			o.InstallScriptURL = ""
		}, wantErr: "InstallScriptURL"},
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
