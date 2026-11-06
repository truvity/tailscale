package acl

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ceilingPolicy renders four rules: the VPC tier, the in-cluster tier, the
// network router's reachability and the cluster router's reachability.
func ceilingPolicy() Policy {
	return Policy{
		Networks: []Network{{Name: "a", VPCCIDR: "10.0.0.0/16", RouterTag: "a-router"}},
		Clusters: []Cluster{{
			Name: "a", Network: "a", ServiceCIDR: "172.16.0.0/16", Member: true,
			VPCGroups: []string{"eng@example.com"}, InClusterGroups: []string{"ops@example.com"},
		}},
	}
}

// fullCeiling admits exactly what ceilingPolicy renders.
func fullCeiling() *Ceiling {
	return &Ceiling{Destinations: []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"*"}},
		{CIDR: "172.16.0.0/16", Ports: []string{"*"}},
		{Tag: "a-router", Ports: []string{"*"}},
		{Tag: "k8s-a-router", Ports: []string{"*"}},
	}}
}

// withCeiling returns p bounded by c.
func withCeiling(p Policy, c *Ceiling) Policy {
	p.Ceiling = c

	return p
}

// grantless is ceilingPolicy without groups: it renders no rule at all.
func grantless() Policy {
	p := ceilingPolicy()
	p.Clusters[0].VPCGroups = nil
	p.Clusters[0].InClusterGroups = nil

	return p
}

func TestBuildWithoutCeilingIsByteIdentical(t *testing.T) {
	p := examplePolicy()
	p.ExtraGrants = []Grant{{SrcTag: "a", DstTag: "b", Ports: []string{"9092"}}}
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "a", DstCIDR: "10.1.0.20/32", Ports: []string{"443", "8443"}}}
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "b", Ports: []string{"80"}}}

	want, err := os.ReadFile("testdata/example-policy.json")
	require.NoError(t, err)

	got, err := Build(p)
	require.NoError(t, err)
	assert.Equal(t, string(want), got, "no Ceiling: the output is the one v1.30.1 rendered")

	// A ceiling that admits everything the policy renders changes nothing: the check never alters output.
	p.Ceiling = &Ceiling{Destinations: []Destination{
		{CIDR: "0.0.0.0/0", Ports: []string{"*"}},
		{Tag: "devel-router", Ports: []string{"*"}}, {Tag: "prod-router", Ports: []string{"*"}},
		{Tag: "k8s-devel-router", Ports: []string{"*"}}, {Tag: "k8s-prod-router", Ports: []string{"*"}},
		{Tag: "b", Ports: []string{"*"}},
	}}

	got, err = Build(p)
	require.NoError(t, err)
	assert.Equal(t, string(want), got)
}

func TestNilCeilingChecksNothing(t *testing.T) {
	p := examplePolicy()
	require.NoError(t, p.CheckCeiling())
}

func TestPolicyCeilingAdmitsWhatTheModelRenders(t *testing.T) {
	p := withCeiling(ceilingPolicy(), fullCeiling())

	require.NoError(t, p.CheckCeiling())

	_, err := Build(p)
	require.NoError(t, err)
}

func TestCeilingRefusesDestinationOutsideCIDRInBuild(t *testing.T) {
	p := withCeiling(ceilingPolicy(), fullCeiling())
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "10.1.0.5/32", Ports: []string{"443"}}}

	open := ceilingPolicy()
	open.ExtraCIDRGrants = p.ExtraCIDRGrants

	_, err := Build(open)
	require.NoError(t, err, "without a ceiling the same grant renders")

	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acl: rule 4 destination 10.1.0.5/32:443 is outside the tailnet ceiling")
	assert.Contains(t, err.Error(), "nearest entry")
	assert.Equal(t, err.Error(), p.CheckCeiling().Error(), "CheckCeiling reports what Build refuses")
}

func TestCeilingRefusesPortsOutsideTheEntryInBuild(t *testing.T) {
	narrow := &Ceiling{Destinations: []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"443"}},
		{Tag: "a-router", Ports: []string{"*"}},
		{Tag: "k8s-a-router", Ports: []string{"*"}},
	}}

	// The VPC tier renders 10.0.0.0/16:*, which the entry's 443 does not cover.
	_, err := Build(withCeiling(ceilingPolicy(), narrow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule 0 destination 10.0.0.0/16:* is outside the tailnet ceiling")

	// A grant limited to 443 passes.
	p := withCeiling(grantless(), narrow)
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "10.0.0.5/32", Ports: []string{"443"}}}
	_, err = Build(p)
	require.NoError(t, err)
}

func TestCeilingRefusesWidenedPrefixInBuild(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "10.0.1.0/24", Ports: []string{"*"}}}}

	p := withCeiling(grantless(), c)
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "10.0.0.0/16", Ports: []string{"*"}}}
	_, err := Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.0/16:*")

	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "10.0.1.0/25", Ports: []string{"*"}}}
	_, err = Build(p)
	require.NoError(t, err)
}

func TestCeilingRefusesTagNotListedInBuild(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{Tag: "devel-router", Ports: []string{"*"}}}}

	// A derived router-tag rule.
	_, err := Build(withCeiling(ceilingPolicy(), c))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag:a-router:*")

	// Both escape hatches that name a tag.
	p := withCeiling(grantless(), c)
	p.ExtraGrants = []Grant{{SrcTag: "x", DstTag: "other-router", Ports: []string{"22"}}}
	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag:other-router:22")

	p = withCeiling(grantless(), c)
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "other-router", Ports: []string{"80"}}}
	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag:other-router:80")

	p = withCeiling(grantless(), c)
	p.ExtraGrants = []Grant{{SrcTag: "x", DstTag: "devel-router", Ports: []string{"22"}}}
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "devel-router", Ports: []string{"80"}}}
	_, err = Build(p)
	require.NoError(t, err)
}

func TestCeilingFailsClosedOnUnknownShapesInBuild(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "0.0.0.0/0", Ports: []string{"*"}}}}

	for _, dst := range []string{"10.1.2.3/16", "10.0.0.1", "autogroup:internet", "garbage", "host.example.com"} {
		p := grantless()
		p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: dst, Ports: []string{"443"}}}

		_, err := Build(p)
		require.NoError(t, err, "%q: without a ceiling DstCIDR is not parsed", dst)

		p.Ceiling = c
		_, err = Build(p)
		require.Error(t, err, "%q must be refused under a ceiling", dst)
	}
}

func TestCeilingEmptyAdmitsNothingInBuild(t *testing.T) {
	_, err := Build(withCeiling(ceilingPolicy(), &Ceiling{}))
	require.Error(t, err)

	// A policy that grants nothing renders no rule, so there is nothing to refuse.
	_, err = Build(withCeiling(grantless(), &Ceiling{}))
	require.NoError(t, err)
}

func TestCeilingParsesIPv6InBuild(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "2001:db8::/32", Ports: []string{"443"}}}}

	p := withCeiling(grantless(), c)
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "2001:db8::5/128", Ports: []string{"443"}}}
	_, err := Build(p)
	require.NoError(t, err)

	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "2001:db9::5/128", Ports: []string{"443"}}}
	_, err = Build(p)
	require.Error(t, err)
}

func TestCeilingReportsEveryViolationInRuleOrder(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"*"}},
		{Tag: "a-router", Ports: []string{"*"}},
		{Tag: "k8s-a-router", Ports: []string{"*"}},
	}}

	p := withCeiling(ceilingPolicy(), c)
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "dev", DstCIDR: "10.9.0.1/32", Ports: []string{"22"}}}

	_, err := Build(p)
	require.Error(t, err)

	lines := strings.Split(err.Error(), "\n")
	require.Len(t, lines, 2, err.Error())
	assert.Contains(t, lines[0], "rule 1 destination 172.16.0.0/16:*")
	assert.Contains(t, lines[1], "rule 4 destination 10.9.0.1/32:22")

	_, again := Build(p)
	assert.Equal(t, err.Error(), again.Error(), "identical on repeated runs")
}

func TestCeilingViolationsDoNotDependOnDeclarationOrder(t *testing.T) {
	two := func() Policy {
		p := ceilingPolicy()
		p.Networks = append(p.Networks, Network{Name: "b", VPCCIDR: "10.8.0.0/16", RouterTag: "b-router"})
		p.Clusters = append(p.Clusters, Cluster{
			Name: "b", Network: "b", ServiceCIDR: "172.24.0.0/16", Member: true,
			VPCGroups: []string{"eng@example.com"}, InClusterGroups: []string{"ops@example.com"},
		})

		return withCeiling(p, fullCeiling())
	}

	_, want := Build(two())
	require.Error(t, want)
	assert.Equal(t, 4, strings.Count(want.Error(), "\n")+1, "network b renders four rules, all outside")

	p := two()
	p.Networks[0], p.Networks[1] = p.Networks[1], p.Networks[0]
	p.Clusters[0], p.Clusters[1] = p.Clusters[1], p.Clusters[0]

	_, got := Build(p)
	require.Error(t, got)
	assert.Equal(t, want.Error(), got.Error())
}

func TestBuildRefusesAMalformedCeiling(t *testing.T) {
	p := withCeiling(ceilingPolicy(), &Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/16"}}})

	require.ErrorContains(t, p.Validate(), "no ports")

	_, err := Build(p)
	require.ErrorContains(t, err, "no ports")
}
