package awsrouter

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// InstanceRoleName is one router fleet's IAM role name (and the stem of
// every other AWS name the fleet owns): "{environment}-tailscale-{tailnet}".
// A caller that must name the role before the fleet exists (an OpenBAO
// auth role bound to it, say) calls this instead of restating the rule.
func InstanceRoleName(environment, tailnet string) string {
	return environment + "-tailscale-" + tailnet
}

const (
	// maxHostnamePatterns caps how many glob patterns HostnamePatterns will
	// emit for one CIDR, so a CIDR far narrower than a /16 VPC fails loudly
	// instead of silently emitting dozens of patterns nobody reviews.
	// Splitting one octet emits at most 128 patterns (a /9's single-bit
	// split); 64 refuses that and anything wider while still covering a
	// /20 (sixteen patterns).
	maxHostnamePatterns = 64
)

// HostnamePatterns turns an IPv4 VPC CIDR and a tailnet's MagicDNS suffix
// into the OpenSSH known_hosts glob pattern(s) matching exactly the
// AWS-assigned tailnet hostnames a router of that tailnet in that VPC could
// ever have (`ip-<a>-<b>-<c>-<d>.<suffix>`): never a hostname outside it,
// and never a tailnet-wide wildcard. The `@cert-authority` known_hosts
// lines and a router's own HostCertConfig.PrincipalPatterns should render
// from this, so they cannot drift.
//
// This is the client-side half of the host-certificate boundary: every
// environment's routers on one tailnet share the SAME suffix, and an SSH
// CA has no CIDR- or glob-aware host-name restriction of its own. A client
// that trusts `*.<suffix>` for one environment's CA would also accept a
// certificate that CA signed for a name that looks like another
// environment's; scoping the trust pattern to the signing environment's
// own VPC CIDR stops that, as long as peered VPC CIDRs do not overlap.
//
// An octet-aligned prefix length (/8, /16, /24) gives exactly one pattern.
// A prefix that splits an octet (/20, say) enumerates every value that
// octet may take within the CIDR (16 patterns for /20) and refuses past
// maxHostnamePatterns rather than emitting an unreviewable pile of them.
// /32 (a single address, not a range of router hosts) is refused outright,
// and so is a suffix that is not one label under ts.net.
func HostnamePatterns(cidr, magicDNSSuffix string) ([]string, error) {
	if !strings.HasSuffix(magicDNSSuffix, ".ts.net") || strings.Count(magicDNSSuffix, ".") != 2 {
		return nil, fmt.Errorf("awsrouter: hostname pattern: %q is not a tailnet MagicDNS suffix (one label under ts.net)", magicDNSSuffix)
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("awsrouter: hostname pattern: %q: %w", cidr, err)
	}

	ip4 := ipnet.IP.To4()

	ones, bits := ipnet.Mask.Size()
	if ip4 == nil || bits != 32 {
		return nil, fmt.Errorf("awsrouter: hostname pattern: %q is not an IPv4 CIDR", cidr)
	}

	if ones == 32 {
		return nil, fmt.Errorf("awsrouter: hostname pattern: %q is a single address, not a range of router hosts", cidr)
	}

	fullOctets := ones / 8
	remainder := ones % 8

	fixed := make([]string, fullOctets)
	for i := range fixed {
		fixed[i] = strconv.Itoa(int(ip4[i]))
	}

	if remainder == 0 {
		return []string{hostPattern(fixed, true, magicDNSSuffix)}, nil
	}

	base := int(ip4[fullOctets])
	count := 1 << (8 - remainder)

	if count > maxHostnamePatterns {
		return nil, fmt.Errorf(
			"awsrouter: hostname pattern: %q needs %d patterns, more than this helper emits (%d) -- "+
				"widen the CIDR to an octet boundary or extend this helper", cidr, count, maxHostnamePatterns)
	}

	moreOctets := fullOctets+1 < 4

	patterns := make([]string, 0, count)

	for i := range count {
		octets := append(append([]string{}, fixed...), strconv.Itoa(base+i))
		patterns = append(patterns, hostPattern(octets, moreOctets, magicDNSSuffix))
	}

	return patterns, nil
}

// hostPattern renders one glob: "ip-<octets, dash-joined>[-*]." +
// the tailnet's MagicDNS suffix -- the trailing "-*" only when octets does not
// already name all four (wildcardRemainder false: the CIDR's prefix
// reached the last octet, so every remaining bit is already enumerated
// across the caller's patterns, not left as a wildcard).
func hostPattern(octets []string, wildcardRemainder bool, magicDNSSuffix string) string {
	suffix := ""
	if wildcardRemainder {
		suffix = "-*"
	}

	return "ip-" + strings.Join(octets, "-") + suffix + "." + magicDNSSuffix
}
