package awsrouter

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/truvity/tailscale/pkg/hostaccess"
)

// opkssh (OpenPubkey SSH): OIDC sign-in to the accounts sshd already
// exposes over the tailnet, additive to (never instead of) the OpenSSH
// user-certificate login in ssh.go. AuthorizedKeysCommand and
// TrustedUserCAKeys are independent sshd mechanisms — sshd tries each
// configured one in turn for pubkey auth — so enabling opkssh never
// disables or reorders certificate login; ssh.go's files
// (`10-user-ca.conf`, `trusted-user-ca-keys.pub`,
// `authorized_principals/*`) are never touched by this file. Neither
// path needs the other: opkssh alone gets the same SSH lockdown
// (`10-ssh-login.conf`, sshd off the public firewalld zone) certificate
// login gets, so a router can drop its certificate trust and keep
// opkssh without loosening anything.
//
// With OPKSSH set, router-setup.sh's setup_opkssh (see that file):
//
//   - removes ec2-instance-connect first (some AL2023 AMIs ship it
//     pre-enabled with its own AuthorizedKeysCommand, which would
//     silently win over opkssh's, and would also collide with the sshd
//     drop-in name below);
//   - downloads the pinned opkssh binary and its SELinux
//     type-enforcement module, verifying each against its sha256 before
//     using it — a mismatch aborts the install, fail closed, rather
//     than running an unverified binary as root;
//   - creates the opksshuser system account, installs the binary and
//     (when SELinux is enforcing) the SELinux module, and writes the
//     sshd AuthorizedKeysCommand drop-in — OWN steps, not opkssh's
//     upstream scripts/install-linux.sh: that script's
//     determine_linux_type() does not recognize Amazon Linux 2023 (no
//     /etc/redhat-release, ID_LIKE=fedora not *suse) on any release
//     through its own main branch as of this fix, so it always fails
//     "Unsupported OS type" here — see CHANGELOG.md. There is no
//     --no-home-policy flag to get right or assert after the fact:
//     this script never writes /etc/sudoers.d/opkssh at all, so the
//     only policy surface is the single roster-rendered
//     /etc/opk/auth_id;
//   - writes /etc/opk/providers and /etc/opk/auth_id with the ownership
//     (root:opksshuser) and mode (0640) opkssh's own docs require;
//   - runs `sshd -t` before ever reloading sshd; on failure (or on any
//     earlier fail-closed abort) it removes only the opkssh drop-in and
//     leaves the previously running sshd, and the certificate path,
//     untouched.
//
// nil OPKSSH, or OPKSSH.Enabled false (the default): none of the above
// runs, and the user data renders exactly as it did before this input
// existed.
// The types are defined in pkg/hostaccess, which installs the same
// opkssh on hosts that are not routers; these are aliases, so existing
// callers compile unchanged.
type (
	// OPKSSHConfig configures optional OIDC sign-in via opkssh. A caller
	// can populate every other field ahead of a rollout and flip Enabled
	// later without touching anything else.
	OPKSSHConfig = hostaccess.OPKSSHConfig
	// OPKSSHProvider is one /etc/opk/providers line.
	OPKSSHProvider = hostaccess.OPKSSHProvider
	// OPKSSHAuthID is one /etc/opk/auth_id line.
	OPKSSHAuthID = hostaccess.OPKSSHAuthID
)

// opksshExpirationPolicies are the only values opkssh's
// /etc/opk/providers parser accepts for a provider's expiration column
// (opkssh README, "Server Configuration" § "/etc/opk/providers").
var opksshExpirationPolicies = map[string]bool{
	"12h":            true,
	"24h":            true,
	"48h":            true,
	"1week":          true,
	"oidc":           true,
	"oidc-refreshed": true,
}

// opksshTokenPattern is deliberately conservative: opkssh's config files
// are space-delimited, so a client id or group containing whitespace
// would silently split into extra columns, and either could otherwise
// carry a shell metacharacter into the rendered install script or into
// providers/auth_id. Refuse anything else rather than trying to quote or
// escape it.
var opksshTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// sha256HexPattern matches a lowercase, 64-character sha256 digest.
var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateOPKSSH reports the first error in the opkssh inputs. nil, or
// Enabled false (the default), is always valid: opkssh is off.
func (c TailscaleInstanceConfig) validateOPKSSH() error {
	o := c.OPKSSH
	if o == nil || !o.Enabled {
		return nil
	}

	if o.ArtifactVersion == "" {
		return errors.New("awsrouter: OPKSSH.ArtifactVersion is required")
	}

	for _, sum := range []struct{ name, value string }{
		{"ArtifactSHA256", o.ArtifactSHA256},
		{"SELinuxModuleSHA256", o.SELinuxModuleSHA256},
	} {
		if !sha256HexPattern.MatchString(sum.value) {
			return fmt.Errorf("awsrouter: OPKSSH.%s is not a 64-character lowercase-hex sha256 digest", sum.name)
		}
	}

	for _, u := range []struct{ name, value string }{
		{"ArtifactURL", o.ArtifactURL},
		{"SELinuxModuleURL", o.SELinuxModuleURL},
	} {
		if err := validateOPKSSHHTTPSURL(u.value); err != nil {
			return fmt.Errorf("awsrouter: OPKSSH.%s: %w", u.name, err)
		}
	}

	if len(o.Providers) == 0 {
		return errors.New("awsrouter: OPKSSH.Providers is empty — opkssh would trust no OpenID Provider")
	}

	issuers := map[string]bool{}

	for i, p := range o.Providers {
		if err := validateOPKSSHHTTPSURL(p.Issuer); err != nil {
			return fmt.Errorf("awsrouter: OPKSSH.Providers[%d].Issuer: %w", i, err)
		}

		if p.ClientID == "" || !opksshTokenPattern.MatchString(p.ClientID) {
			return fmt.Errorf("awsrouter: OPKSSH.Providers[%d].ClientID %q is not a plain client id", i, p.ClientID)
		}

		if !opksshExpirationPolicies[p.Expiration] {
			return fmt.Errorf("awsrouter: OPKSSH.Providers[%d].Expiration %q is not one of opkssh's expiration policies", i, p.Expiration)
		}

		issuers[p.Issuer] = true
	}

	if len(o.AuthorizedIdentities) == 0 {
		return errors.New("awsrouter: OPKSSH.AuthorizedIdentities is empty — opkssh would admit nobody")
	}

	for i, a := range o.AuthorizedIdentities {
		if !loginUserPattern.MatchString(a.User) {
			return fmt.Errorf("awsrouter: OPKSSH.AuthorizedIdentities[%d] user %q is not a login name", i, a.User)
		}

		if a.User == "root" {
			return errors.New("awsrouter: OPKSSH.AuthorizedIdentities names root, which sshd refuses (PermitRootLogin no)")
		}

		if a.Group == "" || !opksshTokenPattern.MatchString(a.Group) {
			return fmt.Errorf("awsrouter: OPKSSH.AuthorizedIdentities[%d] group %q is not a plain group name", i, a.Group)
		}

		if !issuers[a.Issuer] {
			return fmt.Errorf("awsrouter: OPKSSH.AuthorizedIdentities[%d] issuer %q is not one of OPKSSH.Providers", i, a.Issuer)
		}
	}

	return nil
}

// validateOPKSSHHTTPSURL requires an absolute https URL: opkssh's
// providers file trusts an issuer by exact string match, so anything
// looser (http, a bare host, a relative reference) is a configuration
// mistake worth refusing here rather than at the first failed sign-in.
func validateOPKSSHHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", raw)
	}

	return nil
}

// opksshParams returns the template's view of the OPKSSH input, or nil
// when it is off. Providers and AuthorizedIdentities are ordered slices,
// not maps, so — unlike sshUserCAParams — there is no map-iteration order
// to normalize: the caller's own order is the rendered order. Call
// validateOPKSSH first.
func (c TailscaleInstanceConfig) opksshParams() *OPKSSHConfig {
	if c.OPKSSH == nil || !c.OPKSSH.Enabled {
		return nil
	}

	return c.OPKSSH
}
