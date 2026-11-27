package acl

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtraMemberCIDRGrantsRenderNarrowRules(t *testing.T) {
	p := examplePolicy()
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{
		{DstCIDR: "10.1.0.2/32", Ports: []string{"53"}},
	}

	_, doc := build(t, p)

	var found *rule

	for i, r := range doc.ACLs {
		if len(r.Src) == 1 && r.Src[0] == "autogroup:member" && len(r.Dst) == 1 && r.Dst[0] == "10.1.0.2/32:53" {
			found = &doc.ACLs[i]
		}
	}

	require.NotNil(t, found, "no rule matched autogroup:member -> 10.1.0.2/32:53 in %+v", doc.ACLs)
	assert.Equal(t, accept, found.Action)
}

func TestExtraMemberCIDRGrantsJoinPortsAndRanges(t *testing.T) {
	p := examplePolicy()
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{
		{DstCIDR: "10.1.32.0/20", Ports: []string{"443", "8000-8100"}},
	}

	_, doc := build(t, p)

	last := doc.ACLs[len(doc.ACLs)-1]
	assert.Equal(t, []string{"autogroup:member"}, last.Src)
	assert.Equal(t, []string{"10.1.32.0/20:443,8000-8100"}, last.Dst)
}

func TestExtraMemberCIDRGrantsComeLastInDeclarationOrder(t *testing.T) {
	p := examplePolicy()
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "b", Ports: []string{"80"}}}
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{
		{DstCIDR: "10.1.0.2/32", Ports: []string{"53"}},
		{DstCIDR: "2001:db8::/64", Ports: []string{"443"}},
	}

	_, doc := build(t, p)

	n := len(doc.ACLs)
	require.GreaterOrEqual(t, n, 3)
	assert.Equal(t, []string{"tag:b:80"}, doc.ACLs[n-3].Dst, "member grants render before member CIDR grants")
	assert.Equal(t, []string{"10.1.0.2/32:53"}, doc.ACLs[n-2].Dst)
	assert.Equal(t, []string{"2001:db8::/64:443"}, doc.ACLs[n-1].Dst)
}

func TestExtraMemberCIDRGrantsAddNoTagOwnerOrApproval(t *testing.T) {
	base := examplePolicy()
	_, before := build(t, base)

	p := examplePolicy()
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{{DstCIDR: "10.1.0.2/32", Ports: []string{"53"}}}
	_, after := build(t, p)

	assert.Equal(t, before.TagOwners, after.TagOwners)
	assert.Equal(t, before.AutoApprovers, after.AutoApprovers)
	assert.Len(t, after.ACLs, len(before.ACLs)+1)
}

func TestExtraMemberCIDRGrantsEmptyRendersEveryExistingPolicyUnchanged(t *testing.T) {
	// The golden the unmodified suite pins, with the other three grants as
	// it renders them, and an empty (not just nil) list of the new one.
	p := examplePolicy()
	p.ExtraGrants = []Grant{{SrcTag: "a", DstTag: "b", Ports: []string{"9092"}}}
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "a", DstCIDR: "10.1.0.20/32", Ports: []string{"443", "8443"}}}
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "b", Ports: []string{"80"}}}
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{}

	want, err := os.ReadFile("testdata/example-policy.json")
	require.NoError(t, err)

	got, err := Build(p)
	require.NoError(t, err)
	assert.Equal(t, string(want), got)
}

func TestExtraMemberCIDRGrantsValidateRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		g    MemberCIDRGrant
		want string
	}{
		{"no dstCidr", MemberCIDRGrant{Ports: []string{"53"}}, "needs dstCidr"},
		{"not a CIDR", MemberCIDRGrant{DstCIDR: "10.1.0.2", Ports: []string{"53"}}, "is not a CIDR"},
		{"host bits set", MemberCIDRGrant{DstCIDR: "10.1.0.2/16", Ports: []string{"53"}}, "is not canonical"},
		{"IPv4-mapped", MemberCIDRGrant{DstCIDR: "::ffff:10.1.0.2/128", Ports: []string{"53"}}, "IPv4-mapped"},
		{"IPv4 default route", MemberCIDRGrant{DstCIDR: "0.0.0.0/0", Ports: []string{"443"}}, "is a default route"},
		{"IPv6 default route", MemberCIDRGrant{DstCIDR: "::/0", Ports: []string{"443"}}, "is a default route"},
		{"no ports", MemberCIDRGrant{DstCIDR: "10.1.0.2/32"}, "has no ports"},
		{"every port", MemberCIDRGrant{DstCIDR: "10.1.0.2/32", Ports: []string{"53", "*"}}, `lists "*"`},
		{"repeated port", MemberCIDRGrant{DstCIDR: "10.1.0.2/32", Ports: []string{"53", "53"}}, "listed twice"},
		{"bad port", MemberCIDRGrant{DstCIDR: "10.1.0.2/32", Ports: []string{"70000"}}, "outside"},
		{"reversed range", MemberCIDRGrant{DstCIDR: "10.1.0.2/32", Ports: []string{"90-80"}}, "reversed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := examplePolicy()
			p.ExtraMemberCIDRGrants = []MemberCIDRGrant{tc.g}

			err := p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)

			_, err = Build(p)
			require.Error(t, err, "Build validates too")
		})
	}
}

func TestExtraMemberCIDRGrantsAreHeldToTheCeiling(t *testing.T) {
	// Inside the ceiling: rendered.
	p := withCeiling(ceilingPolicy(), fullCeiling())
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{{DstCIDR: "10.0.0.2/32", Ports: []string{"53"}}}
	_, err := Build(p)
	require.NoError(t, err)

	// Outside it: refused, by destination.
	p.ExtraMemberCIDRGrants = []MemberCIDRGrant{{DstCIDR: "10.99.0.2/32", Ports: []string{"53"}}}
	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.99.0.2/32:53")
}
