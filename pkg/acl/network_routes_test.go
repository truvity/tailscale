package acl

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routesNetworkPolicy is ceilingPolicy with the network's address space split
// in three: the VPC CIDR and two extra routes.
func routesNetworkPolicy() Policy {
	p := ceilingPolicy()
	p.Networks[0].ExtraCIDRs = []string{"192.0.2.0/24", "198.51.100.0/24"}

	return p
}

func TestNetworkRoutesUnsetRenderEveryExistingPolicyUnchanged(t *testing.T) {
	// The golden file is the one the unmodified suite pins; an empty (not
	// just nil) Routes renders the same bytes.
	p := examplePolicy()
	p.ExtraGrants = []Grant{{SrcTag: "a", DstTag: "b", Ports: []string{"9092"}}}
	p.ExtraCIDRGrants = []CIDRGrant{{SrcTag: "a", DstCIDR: "10.1.0.20/32", Ports: []string{"443", "8443"}}}
	p.ExtraMemberGrants = []MemberGrant{{DstTag: "b", Ports: []string{"80"}}}

	want, err := os.ReadFile("testdata/example-policy.json")
	require.NoError(t, err)

	for i := range p.Networks {
		p.Networks[i].Routes = []string{}
	}

	got, err := Build(p)
	require.NoError(t, err)
	assert.Equal(t, string(want), got)

	// With extra CIDRs too: nil and empty Routes are the same policy.
	base, err := Build(routesNetworkPolicy())
	require.NoError(t, err)

	p = routesNetworkPolicy()
	p.Networks[0].Routes = []string{}
	again, err := Build(p)
	require.NoError(t, err)
	assert.Equal(t, base, again)
}

func TestNetworkRoutesNarrowTheTierAndTheApprovals(t *testing.T) {
	wide := routesNetworkPolicy()
	_, wideDoc := build(t, wide)

	narrow := routesNetworkPolicy()
	narrow.Networks[0].Routes = []string{"10.0.8.0/24", "192.0.2.0/24"}
	_, doc := build(t, narrow)

	// The VPC tier reaches the two listed prefixes and nothing else.
	require.NotEmpty(t, doc.ACLs)
	assert.Equal(t, []string{"10.0.8.0/24:*", "192.0.2.0/24:*"}, doc.ACLs[0].Dst)
	assert.Equal(t, []string{"10.0.0.0/16:*", "192.0.2.0/24:*", "198.51.100.0/24:*"}, wideDoc.ACLs[0].Dst)

	// Only the listed prefixes are auto-approved, for the network's router
	// and for the cluster's, and the service CIDR is untouched.
	assert.Equal(t, map[string][]string{
		"10.0.8.0/24":   {"tag:a-router", "tag:k8s-a-router"},
		"192.0.2.0/24":  {"tag:a-router", "tag:k8s-a-router"},
		"172.16.0.0/16": {"tag:k8s-a-router"},
	}, doc.AutoApprovers.Routes)

	// Everything else is the wide policy's: tiers, router tags, owners.
	assert.Equal(t, wideDoc.ACLs[1:], doc.ACLs[1:])
	assert.Equal(t, wideDoc.TagOwners, doc.TagOwners)
}

func TestNetworkRoutesAreHeldBelowTheNetworksOwnSpace(t *testing.T) {
	for name, routes := range map[string][]string{
		"not a cidr":                {"banana"},
		"host bits set":             {"10.0.8.1/24"},
		"outside every prefix":      {"10.1.0.0/24"},
		"wider than the VPC CIDR":   {"10.0.0.0/8"},
		"straddles the VPC CIDR":    {"10.0.0.0/15"},
		"the default route":         {"0.0.0.0/0"},
		"repeats an entry":          {"10.0.8.0/24", "10.0.8.0/24"},
		"overlaps an entry":         {"10.0.8.0/24", "10.0.8.128/25"},
		"one good, one outside":     {"10.0.8.0/24", "203.0.113.0/24"},
		"v6 inside a v4 only space": {"2001:db8::/32"},
	} {
		t.Run(name, func(t *testing.T) {
			p := routesNetworkPolicy()
			p.Networks[0].Routes = routes

			require.Error(t, p.Validate())

			_, err := Build(p)
			require.Error(t, err)
		})
	}

	// Equal to the whole network is a narrowing of nothing, and allowed.
	p := routesNetworkPolicy()
	p.Networks[0].Routes = []string{"10.0.0.0/16", "192.0.2.0/24", "198.51.100.0/24"}
	require.NoError(t, p.Validate())
}

func TestNetworkRoutesNeedAWellFormedVPCCIDR(t *testing.T) {
	p := routesNetworkPolicy()
	p.Networks[0].VPCCIDR = "banana"
	p.Networks[0].Routes = []string{"10.0.8.0/24"}
	assert.ErrorContains(t, p.Validate(), "not a CIDR")
}

func TestNetworkRoutesStayInsideACeilingThatListsThem(t *testing.T) {
	// The destination ceiling and the route ceiling see the narrowed tier:
	// a ceiling holding only the narrow prefixes admits it, and refuses the
	// same policy without Routes.
	narrow := routesNetworkPolicy()
	narrow.Networks[0].Routes = []string{"10.0.8.0/24"}
	narrow.Ceiling = &Ceiling{
		Destinations: append(anyDestination()[1:], Destination{CIDR: "10.0.8.0/24", Ports: []string{"*"}}, Destination{CIDR: "172.16.0.0/16", Ports: []string{"*"}}),
		Routes:       []string{"10.0.8.0/24", "172.16.0.0/16"},
	}
	_, err := Build(narrow)
	require.NoError(t, err)

	wide := routesNetworkPolicy()
	wide.Ceiling = narrow.Ceiling
	_, err = Build(wide)
	require.Error(t, err)
	assert.ErrorContains(t, err, "is outside the tailnet ceiling")
	assert.ErrorContains(t, err, "autoApprovers.routes")
}

func TestCheckAdvertisedRefusesADifferenceInEitherDirection(t *testing.T) {
	p := routesNetworkPolicy()
	p.Networks[0].Routes = []string{"10.0.8.0/24", "192.0.2.0/24"}

	// The same list, in any order, agrees.
	require.NoError(t, p.CheckAdvertised("a", []string{"10.0.8.0/24", "192.0.2.0/24"}))
	require.NoError(t, p.CheckAdvertised("a", []string{"192.0.2.0/24", "10.0.8.0/24"}))

	// An exposed prefix must sit inside ONE advertised route, so the same
	// space cut finer is reported rather than summed up.
	errFiner := p.CheckAdvertised("a", []string{"10.0.8.0/25", "10.0.8.128/25", "192.0.2.0/24"})
	require.ErrorContains(t, errFiner, "exposes 10.0.8.0/24, which its routers do not advertise")

	// Advertised wider than the policy exposes: the fleet still carries the
	// whole network.
	err := p.CheckAdvertised("a", []string{"10.0.0.0/16", "192.0.2.0/24", "198.51.100.0/24"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "advertises 10.0.0.0/16, which the policy neither grants nor auto-approves")
	assert.ErrorContains(t, err, "advertises 198.51.100.0/24")
	assert.NotContains(t, err.Error(), "exposes")

	// Advertised narrower than the policy grants: a granted prefix never routed.
	err = p.CheckAdvertised("a", []string{"10.0.8.0/24"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "exposes 192.0.2.0/24, which its routers do not advertise")
	assert.NotContains(t, err.Error(), "advertises")

	// A route in neither space, and one that is not a CIDR.
	require.Error(t, p.CheckAdvertised("a", []string{"10.0.8.0/24", "192.0.2.0/24", "203.0.113.0/24"}))
	require.Error(t, p.CheckAdvertised("a", []string{"banana"}))

	// An unknown network, and a policy that is itself invalid.
	require.ErrorContains(t, p.CheckAdvertised("nowhere", nil), "unknown network")

	p.Networks[0].Routes = []string{"203.0.113.0/24"}
	require.ErrorContains(t, p.CheckAdvertised("a", []string{"203.0.113.0/24"}), "outside the network's own address space")
}

func TestCheckAdvertisedWithoutRoutesComparesTheWholeNetwork(t *testing.T) {
	p := routesNetworkPolicy()
	require.NoError(t, p.CheckAdvertised("a", []string{"10.0.0.0/16", "192.0.2.0/24", "198.51.100.0/24"}))
	require.Error(t, p.CheckAdvertised("a", []string{"10.0.0.0/16"}))
}
