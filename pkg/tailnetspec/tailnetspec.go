// Package tailnetspec holds the pure address and DNS rules of a tailnet:
// pinned service addresses and the MagicDNS suffix shape. No Tailscale API
// call, no Pulumi resource, no SDK import of any kind: an estate's config
// layer that only computes an address or validates a suffix links this
// package and not the Pulumi and Tailscale SDKs that pkg/tailnet imports to
// manage the tailnet. pkg/tailnet re-exports everything here, so existing
// callers keep compiling.
//
// TestNoNonStdlibImports fails the moment this package imports anything
// outside the standard library.
package tailnetspec

import (
	"fmt"
	"net"
	"regexp"
)

// ServiceIP returns base+offset inside a service CIDR — the pinned-IP
// conventions a tailnet leans on (a DNS gateway at .0.53, the cluster
// resolver at .0.10) without anyone hand-writing addresses.
func ServiceIP(serviceCIDR string, offset uint32) (string, error) {
	ip, ipNet, err := net.ParseCIDR(serviceCIDR)
	if err != nil {
		return "", fmt.Errorf("parse service cidr %q: %w", serviceCIDR, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("service cidr %q is not IPv4", serviceCIDR)
	}

	val := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]) + offset

	result := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	if !ipNet.Contains(result) {
		return "", fmt.Errorf("ip %s (offset %d) is outside service cidr %s", result, offset, serviceCIDR)
	}

	return result.String(), nil
}

// magicDNSSuffixPattern is one DNS label under ts.net: Tailscale's own
// `tail<hex>` default, or a customized tailnet DNS name.
var magicDNSSuffixPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.ts\.net$`)

// ValidMagicDNSSuffix reports whether s is a tailnet's MagicDNS suffix: a
// single DNS label under ts.net (`tail1234.ts.net`, `my-net.ts.net`).
func ValidMagicDNSSuffix(s string) bool {
	return magicDNSSuffixPattern.MatchString(s)
}
