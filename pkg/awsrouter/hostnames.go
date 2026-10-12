package awsrouter

import "github.com/truvity/tailscale/pkg/awsrouterspec"

// InstanceRoleName is one router fleet's IAM role name (and the stem of
// every other AWS name the fleet owns): "{environment}-tailscale-{tailnet}".
// The rule lives in pkg/awsrouterspec, which links no SDK; a caller that
// only needs the name should import that package directly.
func InstanceRoleName(environment, tailnet string) string {
	return awsrouterspec.InstanceRoleName(environment, tailnet)
}

// HostnamePatterns turns an IPv4 VPC CIDR and a tailnet's MagicDNS suffix
// into the OpenSSH known_hosts glob pattern(s) matching exactly the
// AWS-assigned tailnet hostnames of a router in that VPC. See
// awsrouterspec.HostnamePatterns for the full contract.
func HostnamePatterns(cidr, magicDNSSuffix string) ([]string, error) {
	return awsrouterspec.HostnamePatterns(cidr, magicDNSSuffix)
}
