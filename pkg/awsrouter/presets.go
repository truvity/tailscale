package awsrouter

import "github.com/truvity/tailscale/pkg/hostaccess"

// The artifact pins, presets and their constructors are defined in
// pkg/hostaccess, which installs the same opkssh and openbao-hostcert on
// hosts that are not routers; these are aliases and thin wrappers, so there
// is one set of pinned digests and existing callers compile unchanged. A pin
// moves only with a release of this module that carries the new digests, so
// an estate never has to retype a digest.
const (
	// PinnedOPKSSHVersion is the opkssh release NewOPKSSH pins.
	PinnedOPKSSHVersion = hostaccess.PinnedOPKSSHVersion
	// PinnedHostCertVersion is the openbao-hostcert release NewHostCert pins.
	PinnedHostCertVersion = hostaccess.PinnedHostCertVersion
)

type (
	// OPKSSHPreset is what an estate decides about opkssh sign-in: whom to
	// trust and whom to admit. Everything else is the pinned release.
	OPKSSHPreset = hostaccess.OPKSSHPreset

	// HostCertPreset is what an estate decides about host-certificate
	// renewal: where the CA is and which names the router may ask for.
	// PrincipalPatterns is the client-side security boundary: the SSH
	// secrets engine cannot restrict a role's domain by CIDR, only by exact
	// match or DNS suffix, so what stops a compromised router from asking
	// to be signed for a name that merely looks like another environment's
	// is this list.
	HostCertPreset = hostaccess.HostCertPreset
)

// NewOPKSSH is an enabled OPKSSHConfig for one provider and one admitted
// identity, with the opkssh binary and its SELinux module pinned to
// PinnedOPKSSHVersion and their digests.
func NewOPKSSH(p OPKSSHPreset) *OPKSSHConfig { return hostaccess.NewOPKSSH(p) }

// NewHostCert is an enabled HostCertConfig, with the openbao-hostcert
// archive pinned to PinnedHostCertVersion and its per-architecture digests.
func NewHostCert(p HostCertPreset) *HostCertConfig { return hostaccess.NewHostCert(p) }
