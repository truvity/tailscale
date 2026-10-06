package awsrouter

// The artifact pins an estate's fleets take unless it says otherwise: the
// opkssh release whose Amazon Linux 2023 install this package owns
// (opkssh_test.go carries the same digests), and the openbao-hostcert
// release a router downloads by URL and checksum. A pin moves only with a
// release of this module that carries the new digests, so an estate never
// has to retype a digest.
const (
	// PinnedOPKSSHVersion is the opkssh release NewOPKSSH pins.
	PinnedOPKSSHVersion = "0.16.0"
	// PinnedHostCertVersion is the openbao-hostcert release NewHostCert pins.
	PinnedHostCertVersion = "0.13.0"

	defaultOPKSSHExpiration = "24h"
)

// pinnedHostCertSHA256 is the PinnedHostCertVersion archive checksum per
// GOARCH, from that release's checksums.txt. This package's own AMI is
// arm64, so only that entry is ever read; amd64 is carried for the same
// forward-compatibility reason HostCertConfig.ArtifactSHA256 is a map.
var pinnedHostCertSHA256 = map[string]string{
	"arm64": "66659c1b0352c880e1b4e78456d702df1c6a68e7e4e853cd429ebb58788fae41",
	"amd64": "97cdac0f14b6472fddb066db5460582bca53dbda80e82f8fee739588747457c3",
}

type (
	// OPKSSHPreset is what an estate decides about opkssh sign-in: whom to
	// trust and whom to admit. Everything else is the pinned release.
	OPKSSHPreset struct {
		// Issuer and ClientID are the one OpenID Provider the router trusts.
		Issuer   string
		ClientID string
		// Expiration is how long the ssh key opkssh mints stays valid; empty
		// is "24h".
		Expiration string
		// User is the local login the identity is admitted as; Group is the
		// bare group name (rendered as oidc:groups:<Group>).
		User  string
		Group string
	}

	// HostCertPreset is what an estate decides about host-certificate
	// renewal: where the CA is and which names the router may ask for.
	HostCertPreset struct {
		Address        string
		CABundle       string
		Namespace      string
		AuthMount      string
		AuthRole       string
		ServerIDHeader string
		SSHMount       string
		SSHRole        string
		// PrincipalPatterns is the client-side security boundary: the SSH
		// secrets engine cannot restrict a role's domain by CIDR, only by
		// exact match or DNS suffix, so what stops a compromised router
		// from asking to be signed for a name that merely looks like
		// another environment's is this list.
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

// NewHostCert is an enabled HostCertConfig, with the openbao-hostcert
// archive pinned to PinnedHostCertVersion and its per-architecture digests.
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
