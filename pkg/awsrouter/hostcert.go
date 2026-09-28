package awsrouter

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// hostCertPrincipalPatterns is HostCert.PrincipalPatterns, comma-joined
// (openbao-hostcert's own --principal-pattern env var shape). Empty when
// HostCert is off.
func (c TailscaleInstanceConfig) hostCertPrincipalPatterns() string {
	if c.HostCert == nil || !c.HostCert.Enabled {
		return ""
	}

	return strings.Join(c.HostCert.PrincipalPatterns, ",")
}

// hostCertCABundleLines splits HostCert.CABundle into lines for the
// template's range-based rendering (the same shape
// SSHUserCA.TrustedUserCAKeys already takes). nil when CABundle is
// empty or HostCert is off.
func (c TailscaleInstanceConfig) hostCertCABundleLines() []string {
	if c.HostCert == nil || !c.HostCert.Enabled || c.HostCert.CABundle == "" {
		return nil
	}

	return strings.Split(strings.TrimRight(c.HostCert.CABundle, "\n"), "\n")
}

// Host-certificate renewal: the router signs its own SSH host key with
// a short-lived certificate from an OpenBAO AWS IAM auth login,
// additive to (never instead of) the plain host key sshd already
// serves — see truvity/openbao's `cmd/openbao-hostcert`, the one
// intended consumer of this config, for the renewal's own design and
// what its own tests prove.
//
// With HostCert set, router-setup.sh's setup_hostcert (see that file):
//
//   - downloads the pinned `openbao-hostcert` archive for this
//     package's own architecture (arm64: router.go's LookupAmi never
//     resolves anything else) and refuses to install it on a checksum
//     mismatch — fail closed, the same as opkssh's artifact and
//     SELinux-module downloads;
//   - installs the binary, the systemd service and timer (their
//     content lives in router-setup.sh itself, not a second checksummed
//     download — two small, static unit files change less often than
//     this script's own release cadence and are reviewed the same way
//     every other line here is), and writes the env file the service's
//     EnvironmentFile reads (mode 0600: it carries the CA bundle path
//     and the mount/role names, nothing secret by itself, but treated
//     as such);
//   - writes a tiny wrapper the service actually execs, which derives
//     this router's OWN principal from `tailscale status --peers=false
//     --json` at EVERY run (never a value baked in at cloud-init time,
//     which cannot know what tailnet hostname a not-yet-launched
//     instance will get) and passes it as `--principal`, with no new
//     package: AL2023 already has grep/sed, and `tailscale` is this
//     package's own reason to exist;
//   - adds `HostCertificate` to sshd's config and enables the timer.
//
// nil HostCert, or HostCert.Enabled false (the default): none of the
// above runs, and the user data renders exactly as it did before this
// input existed.
type (
	// HostCertConfig configures optional SSH host-certificate renewal.
	// A caller can populate every other field ahead of a rollout and
	// flip Enabled later without touching anything else — the same
	// convention OPKSSHConfig takes.
	HostCertConfig struct {
		Enabled bool

		// ArtifactVersion is the truvity/openbao release these artifacts
		// come from, e.g. "0.13.0" (no leading "v") — the same shape
		// RouterSetupVersion takes, because it composes into the same
		// kind of GitHub Release download URL.
		ArtifactVersion string
		// ArtifactSHA256 is the openbao-hostcert archive's sha256, per
		// GOARCH ("arm64", "amd64", ...) as goreleaser names its
		// archives (openbao-hostcert_<version>_linux_<arch>.tar.gz).
		// This package deploys arm64 only (router.go's LookupAmi), so
		// only that key is ever read, but the map is keyed by arch
		// rather than being one flat field so a future architecture
		// does not need a new field name here.
		ArtifactSHA256 map[string]string

		// Address is OpenBAO's URL as the router reaches it
		// (https://openbao.example.internal). No trailing slash.
		Address string
		// CABundle is a PEM bundle to trust beyond AL2023's OS roots,
		// written to its own file and passed as openbao-hostcert's
		// --ca-cert. Empty: the OS trust store alone.
		CABundle string
		// Namespace is the OpenBAO namespace both the AWS IAM login and
		// the certificate sign call are made in. Empty: root.
		Namespace string
		// AuthMount and AuthRole are the AWS IAM auth mount's path and
		// the role this router's own instance role ARN is bound to,
		// server-side (openbao-config's business, not this package's —
		// HostCertConfig only has to match it).
		AuthMount string
		AuthRole  string
		// ServerIDHeader is the value the mount's client configuration
		// pins as iam_server_id_header_value — must match exactly, or
		// AWS auth refuses the login.
		ServerIDHeader string
		// SSHMount and SSHRole are the SSH host-CA mount and role this
		// router's certificate is signed with.
		SSHMount string
		SSHRole  string
		// PrincipalPatterns are path.Match globs openbao-hostcert
		// refuses to request a principal outside of (its own
		// --principal-pattern, defense in depth: OpenBAO's SSH secrets
		// engine cannot restrict a host role's domain by CIDR or glob,
		// only by exact match or DNS suffix — see that tool's own docs).
		// Required, and neither empty nor a bare "*": either would
		// defeat the whole point of pinning a pattern here at all.
		PrincipalPatterns []string
	}
)

// hostCertArch is the one GOARCH this package ever deploys — AL2023
// ARM64, router.go's LookupAmi filter ("al2023-ami-*-arm64") admits
// nothing else. A future architecture needs a new entry here AND a new
// LookupAmi filter, never one without the other.
const hostCertArch = "arm64"

// principalPatternPattern is opksshTokenPattern's same conservative
// token shape, WITH path.Match's own glob metacharacters ("*", "?")
// added — permissive enough for a real hostname glob
// (`ip-10-65-*.tailnet.example.ts.net`), strict enough to keep a shell
// metacharacter or a character class (path.Match's "[...]", which this
// package's own use never needs) out of the rendered env file.
var principalPatternPattern = regexp.MustCompile(`^[A-Za-z0-9._:*?-]+$`)

// validateHostCert reports the first error in the host-certificate
// inputs. nil, or Enabled false (the default), is always valid:
// host-certificate renewal is off.
func (c TailscaleInstanceConfig) validateHostCert() error {
	h := c.HostCert
	if h == nil || !h.Enabled {
		return nil
	}

	if h.ArtifactVersion == "" {
		return errors.New("awsrouter: HostCert.ArtifactVersion is required")
	}

	if !routerSetupVersionPattern.MatchString(h.ArtifactVersion) {
		return fmt.Errorf("awsrouter: HostCert.ArtifactVersion %q is not \"X.Y.Z\"", h.ArtifactVersion)
	}

	sum, ok := h.ArtifactSHA256[hostCertArch]
	if !ok {
		return fmt.Errorf("awsrouter: HostCert.ArtifactSHA256 has no entry for %q, this package's only architecture", hostCertArch)
	}

	if !sha256HexPattern.MatchString(sum) {
		return fmt.Errorf("awsrouter: HostCert.ArtifactSHA256[%q] is not a 64-character lowercase-hex sha256 digest", hostCertArch)
	}

	if err := validateHTTPSURL(h.Address); err != nil {
		return fmt.Errorf("awsrouter: HostCert.Address: %w", err)
	}

	if h.CABundle != "" {
		block, _ := pem.Decode([]byte(h.CABundle))
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("awsrouter: HostCert.CABundle is not a PEM certificate bundle")
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("awsrouter: HostCert.CABundle: %w", err)
		}
	}

	for _, f := range []struct{ name, value string }{
		{"AuthMount", h.AuthMount},
		{"AuthRole", h.AuthRole},
		{"ServerIDHeader", h.ServerIDHeader},
		{"SSHMount", h.SSHMount},
		{"SSHRole", h.SSHRole},
	} {
		if f.value == "" {
			return fmt.Errorf("awsrouter: HostCert.%s is required", f.name)
		}

		if !opksshTokenPattern.MatchString(f.value) {
			return fmt.Errorf("awsrouter: HostCert.%s %q is not a plain token", f.name, f.value)
		}
	}

	if h.Namespace != "" && !opksshTokenPattern.MatchString(h.Namespace) {
		return fmt.Errorf("awsrouter: HostCert.Namespace %q is not a plain token", h.Namespace)
	}

	if len(h.PrincipalPatterns) == 0 {
		return errors.New("awsrouter: HostCert.PrincipalPatterns is empty — openbao-hostcert would refuse to request any principal at all")
	}

	for i, p := range h.PrincipalPatterns {
		switch {
		case p == "":
			return fmt.Errorf("awsrouter: HostCert.PrincipalPatterns[%d] is empty", i)
		case p == "*":
			return fmt.Errorf("awsrouter: HostCert.PrincipalPatterns[%d] is a bare \"*\", which matches anything — name the domain it should stay under", i)
		case !principalPatternPattern.MatchString(p):
			return fmt.Errorf("awsrouter: HostCert.PrincipalPatterns[%d] %q is not a plain glob token", i, p)
		}
	}

	return nil
}

// validateHTTPSURL requires an absolute https URL with no trailing
// slash — composed directly into openbao-hostcert's --address, which
// refuses exactly that shape itself (see its own checkInputs-equivalent).
func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", raw)
	}

	if strings.HasSuffix(raw, "/") {
		return fmt.Errorf("%q has a trailing slash", raw)
	}

	return nil
}

// hostCertParams returns the template's view of the HostCert input, or
// nil when it is off. Call validateHostCert first.
func (c TailscaleInstanceConfig) hostCertParams() *HostCertConfig {
	if c.HostCert == nil || !c.HostCert.Enabled {
		return nil
	}

	return c.HostCert
}

// hostCertArtifactSHA256 is HostCert.ArtifactSHA256[hostCertArch] —
// validateHostCert has already confirmed it exists and is well-formed.
func (c TailscaleInstanceConfig) hostCertArtifactSHA256() string {
	if c.HostCert == nil {
		return ""
	}

	return c.HostCert.ArtifactSHA256[hostCertArch]
}
