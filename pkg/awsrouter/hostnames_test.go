package awsrouter

import (
	"reflect"
	"strings"
	"testing"
)

func TestHostnamePatterns(t *testing.T) {
	const sfx = "tailexample.ts.net"

	for name, tc := range map[string]struct {
		cidr string
		want []string
	}{
		"a /16": {"10.65.0.0/16", []string{"ip-10-65-*." + sfx}},
		"a /24": {"10.65.7.0/24", []string{"ip-10-65-7-*." + sfx}},
		"a /8":  {"10.0.0.0/8", []string{"ip-10-*." + sfx}},
		"a /30, no trailing glob": {"10.65.7.4/30", []string{
			"ip-10-65-7-4." + sfx, "ip-10-65-7-5." + sfx, "ip-10-65-7-6." + sfx, "ip-10-65-7-7." + sfx,
		}},
	} {
		got, err := HostnamePatterns(tc.cidr, sfx)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, %v; want %v", name, got, err, tc.want)
		}
	}

	got, err := HostnamePatterns("10.65.0.0/20", sfx)
	if err != nil || len(got) != 16 || got[0] != "ip-10-65-0-*."+sfx || got[15] != "ip-10-65-15-*."+sfx {
		t.Errorf("/20: got %v, %v", got, err)
	}
}

func TestHostnamePatternsRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ cidr, sfx, want string }{
		"not a CIDR":     {"not-a-cidr", "t.ts.net", "not-a-cidr"},
		"IPv6":           {"2001:db8::/32", "t.ts.net", "not an IPv4"},
		"single address": {"10.65.0.1/32", "t.ts.net", "single address"},
		"too narrow":     {"10.0.0.0/9", "t.ts.net", "more than this helper emits"},
		"bad suffix":     {"10.65.0.0/16", "example.com", "not a tailnet MagicDNS suffix"},
	} {
		_, err := HostnamePatterns(tc.cidr, tc.sfx)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}

func TestInstanceRoleName(t *testing.T) {
	if got := InstanceRoleName("devel", "acme"); got != "devel-tailscale-acme" {
		t.Errorf("got %q", got)
	}

	if got := (TailscaleInstanceConfig{Environment: "devel", Tailnet: "acme"}).baseName(); got != InstanceRoleName("devel", "acme") {
		t.Errorf("baseName %q diverges from InstanceRoleName", got)
	}
}
