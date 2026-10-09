// Package hostaccess installs opkssh OIDC sign-in and OpenBAO-signed SSH host
// certificates on an EC2 host that is not a tailnet router.
//
// pkg/awsrouter does the same for routers, from router-setup.sh. This package
// is the part a second kind of host needs: the same pinned artifacts and
// digests, the same install steps and security posture, with the host
// certificate's principal read from where that host can read it (EC2 instance
// metadata) rather than from tailscale. The types and pins live here and
// pkg/awsrouter aliases them, so there is one definition of each.
//
// Render turns a Config into a Bundle: the small files a consumer writes
// (path, mode, content) and the command that runs the version-pinned
// hostaccess-setup.sh. The script itself is delivered either inline (written
// with the other files) or by download with a sha256 check; Bundle reports
// the byte cost of both, so a consumer can budget its 16 KiB of EC2 user data.
package hostaccess

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The artifact pins an estate takes unless it says otherwise. A pin moves only
// with a release of this module that carries the new digests.
const (
	// PinnedOPKSSHVersion is the opkssh release NewOPKSSH pins.
	PinnedOPKSSHVersion = "0.16.0"
	// PinnedHostCertVersion is the openbao-hostcert release NewHostCert pins.
	PinnedHostCertVersion = "0.13.0"

	defaultOPKSSHExpiration = "24h"

	// HostCertArch is the one GOARCH the setup script downloads: Amazon Linux
	// 2023 arm64.
	HostCertArch = "arm64"
)

// pinnedHostCertSHA256 is the PinnedHostCertVersion archive checksum per
// GOARCH, from that release's checksums.txt.
var pinnedHostCertSHA256 = map[string]string{
	"arm64": "66659c1b0352c880e1b4e78456d702df1c6a68e7e4e853cd429ebb58788fae41",
	"amd64": "97cdac0f14b6472fddb066db5460582bca53dbda80e82f8fee739588747457c3",
}

// PrincipalSource says where a host learns the one principal its host
// certificate is requested for.
type PrincipalSource string

const (
	// PrincipalTailscale is the host's tailnet name from `tailscale status`
	// (what a router uses). The first certificate is signed by whoever runs
	// openbao-hostcert-boot.sh after the host has joined the tailnet.
	PrincipalTailscale PrincipalSource = "tailscale"
	// PrincipalIMDSHostname is the EC2 private DNS name from IMDSv2
	// `local-hostname`, e.g. ip-10-68-1-2.eu-west-3.compute.internal. It is
	// the default for this package.
	PrincipalIMDSHostname PrincipalSource = "imds-hostname"
)

type (
	// OPKSSHConfig configures optional OIDC sign-in via opkssh.
	OPKSSHConfig struct {
		Enabled bool

		// ArtifactVersion is the opkssh release, e.g. "0.16.0".
		ArtifactVersion string
		// ArtifactURL/ArtifactSHA256 are the opkssh arm64 binary; a sha256
		// mismatch aborts the install.
		ArtifactURL    string
		ArtifactSHA256 string
		// SELinuxModuleURL/SHA256 are opkssh.te at the same tag.
		SELinuxModuleURL    string
		SELinuxModuleSHA256 string

		// Providers are the OpenID Providers /etc/opk/providers admits, one
		// per line in this order.
		Providers []OPKSSHProvider
		// AuthorizedIdentities are the /etc/opk/auth_id entries, one per line
		// in this order.
		AuthorizedIdentities []OPKSSHAuthID
	}

	// OPKSSHProvider is one /etc/opk/providers line.
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

	// HostCertConfig configures optional SSH host-certificate renewal.
	HostCertConfig struct {
		Enabled bool

		// ArtifactVersion is the truvity/openbao release, "X.Y.Z".
		ArtifactVersion string
		// ArtifactSHA256 is the openbao-hostcert archive's sha256 per GOARCH.
		// Only HostCertArch is read.
		ArtifactSHA256 map[string]string

		// Address is OpenBAO's https URL, no trailing slash.
		Address string
		// CABundle is a PEM bundle to trust beyond the OS roots; empty: OS only.
		CABundle string
		// Namespace is the OpenBAO namespace; empty: root.
		Namespace string
		// AuthMount and AuthRole are the AWS IAM auth mount and role.
		AuthMount string
		AuthRole  string
		// ServerIDHeader is the mount's iam_server_id_header_value.
		ServerIDHeader string
		// SSHMount and SSHRole are the SSH host-CA mount and role.
		SSHMount string
		SSHRole  string
		// PrincipalPatterns are path.Match globs openbao-hostcert refuses to
		// request a principal outside of. Required; see Config.Validate for
		// what is refused.
		PrincipalPatterns []string
	}

	// OPKSSHPreset is what an estate decides about opkssh sign-in: whom to
	// trust and whom to admit. Everything else is the pinned release.
	OPKSSHPreset struct {
		// Issuer and ClientID are the one OpenID Provider the host trusts.
		Issuer   string
		ClientID string
		// Expiration is how long the minted ssh key stays valid; empty is "24h".
		Expiration string
		// User is the local login the identity is admitted as; Group is the
		// bare group name (rendered as oidc:groups:<Group>).
		User  string
		Group string
	}

	// HostCertPreset is what an estate decides about host-certificate
	// renewal: where the CA is and which names the host may ask for.
	HostCertPreset struct {
		Address           string
		CABundle          string
		Namespace         string
		AuthMount         string
		AuthRole          string
		ServerIDHeader    string
		SSHMount          string
		SSHRole           string
		PrincipalPatterns []string
	}
)

// NewOPKSSH is an enabled OPKSSHConfig for one provider and one admitted
// identity, with the opkssh binary and its SELinux module pinned to
// PinnedOPKSSHVersion and their digests.
func NewOPKSSH(p OPKSSHPreset) *OPKSSHConfig {
	expiration := p.Expiration
	if expiration == "" {
		expiration = defaultOPKSSHExpiration
	}

	return &OPKSSHConfig{
		Enabled: true,

		ArtifactVersion:     PinnedOPKSSHVersion,
		ArtifactURL:         "https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64",
		ArtifactSHA256:      "9dd10c2b6ce99cde18e52c054877ca014134b291fd82afe71741c68db4f83d44",
		SELinuxModuleURL:    "https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/opkssh.te",
		SELinuxModuleSHA256: "f68bac733ecd604172eb5b4fe6e472eba195bcffa8444e44723e6fb9546926c4",

		Providers:            []OPKSSHProvider{{Issuer: p.Issuer, ClientID: p.ClientID, Expiration: expiration}},
		AuthorizedIdentities: []OPKSSHAuthID{{User: p.User, Group: p.Group, Issuer: p.Issuer}},
	}
}

// NewHostCert is an enabled HostCertConfig, with the openbao-hostcert archive
// pinned to PinnedHostCertVersion and its per-architecture digests.
func NewHostCert(p HostCertPreset) *HostCertConfig {
	digests := make(map[string]string, len(pinnedHostCertSHA256))
	for arch, sum := range pinnedHostCertSHA256 {
		digests[arch] = sum
	}

	return &HostCertConfig{
		Enabled:         true,
		ArtifactVersion: PinnedHostCertVersion,
		ArtifactSHA256:  digests,

		Address:        p.Address,
		CABundle:       p.CABundle,
		Namespace:      p.Namespace,
		AuthMount:      p.AuthMount,
		AuthRole:       p.AuthRole,
		ServerIDHeader: p.ServerIDHeader,
		SSHMount:       p.SSHMount,
		SSHRole:        p.SSHRole,

		PrincipalPatterns: p.PrincipalPatterns,
	}
}

// Config is what Render turns into files. At least one of OPKSSH and HostCert
// must be enabled.
type Config struct {
	OPKSSH   *OPKSSHConfig
	HostCert *HostCertConfig
	// PrincipalSource is where the host certificate's principal comes from;
	// empty is PrincipalIMDSHostname.
	PrincipalSource PrincipalSource
}

func (c Config) principalSource() PrincipalSource {
	if c.PrincipalSource == "" {
		return PrincipalIMDSHostname
	}

	return c.PrincipalSource
}

func (c Config) opksshOn() bool   { return c.OPKSSH != nil && c.OPKSSH.Enabled }
func (c Config) hostCertOn() bool { return c.HostCert != nil && c.HostCert.Enabled }

var (
	opksshExpirationPolicies = map[string]bool{
		"12h": true, "24h": true, "48h": true, "1week": true, "oidc": true, "oidc-refreshed": true,
	}
	// tokenPattern is conservative on purpose: these values reach a sourced
	// shell env file and space-delimited opkssh files.
	tokenPattern        = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	loginUserPattern    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sha256HexPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	principalGlobPatten = regexp.MustCompile(`^[A-Za-z0-9._:*?-]+$`)
	// urlPattern admits no shell metacharacter, quote or space: URLs land in
	// double quotes in a sourced env file.
	urlPattern = regexp.MustCompile(`^https://[A-Za-z0-9._~:/?#@!&'*+,;=%-]+$`)
)

// Validate reports the first error in the config. Refused, among the rest:
// a missing or malformed digest; a URL with shell metacharacters; empty
// Providers or AuthorizedIdentities; root as a login; and principal patterns
// that are empty, a bare "*", or that put a wildcard in the last two DNS
// labels or have no domain at all, because a pattern that matches any name
// defeats the pin.
func (c Config) Validate() error {
	if !c.opksshOn() && !c.hostCertOn() {
		return errors.New("hostaccess: neither OPKSSH nor HostCert is enabled")
	}

	switch c.principalSource() {
	case PrincipalTailscale, PrincipalIMDSHostname:
	default:
		return fmt.Errorf("hostaccess: PrincipalSource %q is not %q or %q", c.PrincipalSource, PrincipalTailscale, PrincipalIMDSHostname)
	}

	if c.opksshOn() {
		if err := validateOPKSSH(c.OPKSSH); err != nil {
			return err
		}
	}

	if c.hostCertOn() {
		if err := validateHostCert(c.HostCert); err != nil {
			return err
		}
	}

	return nil
}

func validateOPKSSH(o *OPKSSHConfig) error {
	if o.ArtifactVersion == "" || !tokenPattern.MatchString(o.ArtifactVersion) {
		return errors.New("hostaccess: OPKSSH.ArtifactVersion is required and must be a plain token")
	}

	for _, s := range []struct{ name, value string }{
		{"ArtifactSHA256", o.ArtifactSHA256}, {"SELinuxModuleSHA256", o.SELinuxModuleSHA256},
	} {
		if !sha256HexPattern.MatchString(s.value) {
			return fmt.Errorf("hostaccess: OPKSSH.%s is not a 64-character lowercase-hex sha256 digest", s.name)
		}
	}

	for _, u := range []struct{ name, value string }{
		{"ArtifactURL", o.ArtifactURL}, {"SELinuxModuleURL", o.SELinuxModuleURL},
	} {
		if err := validateURL(u.value, false); err != nil {
			return fmt.Errorf("hostaccess: OPKSSH.%s: %w", u.name, err)
		}
	}

	if len(o.Providers) == 0 {
		return errors.New("hostaccess: OPKSSH.Providers is empty — opkssh would trust no OpenID Provider")
	}

	issuers := map[string]bool{}

	for i, p := range o.Providers {
		if err := validateURL(p.Issuer, false); err != nil {
			return fmt.Errorf("hostaccess: OPKSSH.Providers[%d].Issuer: %w", i, err)
		}

		if !tokenPattern.MatchString(p.ClientID) {
			return fmt.Errorf("hostaccess: OPKSSH.Providers[%d].ClientID %q is not a plain client id", i, p.ClientID)
		}

		if !opksshExpirationPolicies[p.Expiration] {
			return fmt.Errorf("hostaccess: OPKSSH.Providers[%d].Expiration %q is not one of opkssh's expiration policies", i, p.Expiration)
		}

		issuers[p.Issuer] = true
	}

	if len(o.AuthorizedIdentities) == 0 {
		return errors.New("hostaccess: OPKSSH.AuthorizedIdentities is empty — opkssh would admit nobody")
	}

	for i, a := range o.AuthorizedIdentities {
		if !loginUserPattern.MatchString(a.User) {
			return fmt.Errorf("hostaccess: OPKSSH.AuthorizedIdentities[%d] user %q is not a login name", i, a.User)
		}

		if a.User == "root" {
			return errors.New("hostaccess: OPKSSH.AuthorizedIdentities names root, which sshd refuses (PermitRootLogin no)")
		}

		if !tokenPattern.MatchString(a.Group) {
			return fmt.Errorf("hostaccess: OPKSSH.AuthorizedIdentities[%d] group %q is not a plain group name", i, a.Group)
		}

		if !issuers[a.Issuer] {
			return fmt.Errorf("hostaccess: OPKSSH.AuthorizedIdentities[%d] issuer %q is not one of OPKSSH.Providers", i, a.Issuer)
		}
	}

	return nil
}

func validateHostCert(h *HostCertConfig) error {
	if !versionPattern.MatchString(h.ArtifactVersion) {
		return fmt.Errorf("hostaccess: HostCert.ArtifactVersion %q is not \"X.Y.Z\"", h.ArtifactVersion)
	}

	if !sha256HexPattern.MatchString(h.ArtifactSHA256[HostCertArch]) {
		return fmt.Errorf("hostaccess: HostCert.ArtifactSHA256[%q] is not a 64-character lowercase-hex sha256 digest", HostCertArch)
	}

	if err := validateURL(h.Address, true); err != nil {
		return fmt.Errorf("hostaccess: HostCert.Address: %w", err)
	}

	if h.CABundle != "" {
		block, _ := pem.Decode([]byte(h.CABundle))
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("hostaccess: HostCert.CABundle is not a PEM certificate bundle")
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("hostaccess: HostCert.CABundle: %w", err)
		}
	}

	for _, f := range []struct{ name, value string }{
		{"AuthMount", h.AuthMount}, {"AuthRole", h.AuthRole}, {"ServerIDHeader", h.ServerIDHeader},
		{"SSHMount", h.SSHMount}, {"SSHRole", h.SSHRole},
	} {
		if !tokenPattern.MatchString(f.value) {
			return fmt.Errorf("hostaccess: HostCert.%s %q is required and must be a plain token", f.name, f.value)
		}
	}

	if h.Namespace != "" && !tokenPattern.MatchString(h.Namespace) {
		return fmt.Errorf("hostaccess: HostCert.Namespace %q is not a plain token", h.Namespace)
	}

	if len(h.PrincipalPatterns) == 0 {
		return errors.New("hostaccess: HostCert.PrincipalPatterns is empty — openbao-hostcert would refuse to request any principal")
	}

	for i, p := range h.PrincipalPatterns {
		if err := validatePrincipalPattern(p); err != nil {
			return fmt.Errorf("hostaccess: HostCert.PrincipalPatterns[%d]: %w", i, err)
		}
	}

	return nil
}

// validatePrincipalPattern refuses a pattern that could match a name outside
// one domain: it must be a plain glob token with at least two dot-separated
// labels, whose last two labels are literal.
func validatePrincipalPattern(p string) error {
	if p == "" || p == "*" {
		return fmt.Errorf("%q matches anything — name the domain it should stay under", p)
	}

	if !principalGlobPatten.MatchString(p) {
		return fmt.Errorf("%q is not a plain glob token", p)
	}

	labels := strings.Split(p, ".")
	if len(labels) < 3 {
		return fmt.Errorf("%q has no domain: give at least host.domain.tld with a literal domain", p)
	}

	for _, l := range labels[len(labels)-2:] {
		if l == "" || strings.ContainsAny(l, "*?") {
			return fmt.Errorf("%q has a wildcard (or an empty label) in its last two labels", p)
		}
	}

	return nil
}

func validateURL(raw string, noTrailingSlash bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || !urlPattern.MatchString(raw) {
		return fmt.Errorf("%q is not a plain https URL", raw)
	}

	if noTrailingSlash && strings.HasSuffix(raw, "/") {
		return fmt.Errorf("%q has a trailing slash", raw)
	}

	return nil
}
