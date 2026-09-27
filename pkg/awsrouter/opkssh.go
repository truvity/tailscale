package awsrouter

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

// opkssh (OpenPubkey SSH): OIDC sign-in to the accounts sshd already
// exposes over the tailnet, additive to (never instead of) the OpenSSH
// user-certificate login in ssh.go. AuthorizedKeysCommand and
// TrustedUserCAKeys are independent sshd mechanisms — sshd tries each
// configured one in turn for pubkey auth — so enabling opkssh never
// disables or reorders certificate login; ssh.go's files
// (`10-user-ca.conf`, `trusted-user-ca-keys.pub`,
// `authorized_principals/*`) are never touched by this file.
//
// With OPKSSH set, cloud-init:
//
//   - removes ec2-instance-connect first (some AL2023 AMIs ship it
//     pre-enabled with its own AuthorizedKeysCommand, which would
//     silently win over opkssh's, and would also change which sshd
//     drop-in filename install-linux.sh picks next);
//   - downloads the pinned opkssh binary, its scripts/install-linux.sh
//     and its SELinux type-enforcement module, verifying each against
//     its sha256 before using it — a mismatch aborts the install, fail
//     closed, rather than running an unverified binary as root;
//   - runs install-linux.sh (which creates the opksshuser system
//     account, installs the SELinux module AL2023's enforcing policy
//     needs, and wires sshd's AuthorizedKeysCommand) with
//     --no-home-policy and --no-sshd-restart. --no-home-policy matters:
//     without it, install-linux.sh lets a login user grant their own
//     account extra identities via ~user/.opk/auth_id and installs a
//     passwordless sudoers rule so opkssh can read it — a second policy
//     surface a shell user could self-serve from, bypassing the single
//     roster-rendered /etc/opk/auth_id this router is meant to enforce.
//     The install script also asserts /etc/sudoers.d/opkssh does not
//     exist afterward and aborts if it does, rather than trusting the
//     flag silently. --no-sshd-restart means nothing reloads sshd until
//     our own `sshd -t` gate passes;
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
type (
	// OPKSSHConfig configures optional OIDC sign-in via opkssh. A caller
	// can populate every other field ahead of a rollout and flip Enabled
	// later without touching anything else.
	OPKSSHConfig struct {
		Enabled bool

		// ArtifactVersion is the opkssh release these artifacts come
		// from, e.g. "0.16.0" — passed to install-linux.sh's own
		// --install-version flag and recorded in the install log.
		ArtifactVersion string
		// ArtifactURL/ArtifactSHA256 are the opkssh binary for this
		// fleet's AMI architecture. This package is AL2023 ARM64 only
		// (see router.go's LookupAmi), so there is one binary, not one
		// per architecture; a sha256 mismatch aborts the install.
		ArtifactURL    string
		ArtifactSHA256 string
		// SELinuxModuleURL/SHA256 are opkssh.te at the same tag. AL2023
		// runs SELinux enforcing and this module ships neither in the
		// binary nor in the rpm.
		SELinuxModuleURL    string
		SELinuxModuleSHA256 string
		// InstallScriptURL/SHA256 are scripts/install-linux.sh at the
		// same tag.
		InstallScriptURL    string
		InstallScriptSHA256 string

		// Providers are the OpenID Providers /etc/opk/providers admits,
		// rendered one per line in this order.
		Providers []OPKSSHProvider
		// AuthorizedIdentities are the /etc/opk/auth_id entries,
		// rendered one per line in this order. Each admits User to sign
		// in as the identity oidc:groups:Group, trusted only when
		// Issuer signed the ID token.
		AuthorizedIdentities []OPKSSHAuthID
	}

	// OPKSSHProvider is one /etc/opk/providers line: an OpenID Provider
	// this router's opkssh trusts, its client id (the audience claim
	// opkssh requires), and how long the ssh key opkssh mints stays
	// valid.
	OPKSSHProvider struct {
		Issuer     string // https issuer URI, exact string match
		ClientID   string
		Expiration string // one of opksshExpirationPolicies
	}

	// OPKSSHAuthID is one /etc/opk/auth_id line.
	OPKSSHAuthID struct {
		User   string // local login user (an existing account)
		Group  string // bare group name; rendered as oidc:groups:<Group>
		Issuer string // must be one of OPKSSHConfig.Providers' Issuer
	}
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
		{"InstallScriptSHA256", o.InstallScriptSHA256},
	} {
		if !sha256HexPattern.MatchString(sum.value) {
			return fmt.Errorf("awsrouter: OPKSSH.%s is not a 64-character lowercase-hex sha256 digest", sum.name)
		}
	}

	for _, u := range []struct{ name, value string }{
		{"ArtifactURL", o.ArtifactURL},
		{"SELinuxModuleURL", o.SELinuxModuleURL},
		{"InstallScriptURL", o.InstallScriptURL},
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
