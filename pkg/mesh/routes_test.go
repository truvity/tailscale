package mesh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/tailscale/pkg/acl"
)

// narrowedInputs is exampleInputs with the dev network's address space given
// an extra route and its Routes cut down to part of it.
func narrowedInputs() Inputs {
	in := exampleInputs()

	for i := range in.Networks {
		if in.Networks[i].Name == "dev" {
			in.Networks[i].ExtraCIDRs = []string{"10.99.0.0/24"}
			in.Networks[i].Routes = []string{"10.65.8.0/24", "10.99.0.0/24"}
		}
	}

	return in
}

func TestRoutesOfANetworkOutsideTheTailnetChangeNothing(t *testing.T) {
	// Routes on a network the tailnet does not join render nothing, so the
	// policy is the one a program that never set them renders.
	other := exampleInputs()
	other.Tailnet.Networks = []string{"hub", "lab"}

	for i := range other.Networks {
		if other.Networks[i].Name == "dev" {
			other.Networks[i].Routes = []string{"10.65.8.0/24"}
		}
	}

	require.NoError(t, other.Validate())

	plain := exampleInputs()
	plain.Tailnet.Networks = []string{"hub", "lab"}

	want, err := plain.PolicyModel()
	require.NoError(t, err)

	got, err := other.PolicyModel()
	require.NoError(t, err)

	wantDoc, err := acl.Build(want)
	require.NoError(t, err)
	gotDoc, err := acl.Build(got)
	require.NoError(t, err)
	assert.Equal(t, wantDoc, gotDoc)
}

func TestRoutesNarrowThePolicyOfOneTailnetOnly(t *testing.T) {
	narrow := narrowedInputs()
	require.NoError(t, narrow.Validate())

	p, err := narrow.PolicyModel()
	require.NoError(t, err)

	doc, err := acl.Build(p)
	require.NoError(t, err)
	assert.Contains(t, doc, `"10.65.8.0/24:*"`)
	assert.Contains(t, doc, `"10.99.0.0/24:*"`)
	assert.NotContains(t, doc, `"10.65.0.0/16:*"`, "the dev network's tier no longer reaches its whole VPC CIDR")

	// A second tailnet on the same network, with the same Network value but
	// no Routes, keeps everything.
	wide := narrowedInputs()
	for i := range wide.Networks {
		wide.Networks[i].Routes = nil
	}

	pw, err := wide.PolicyModel()
	require.NoError(t, err)

	docWide, err := acl.Build(pw)
	require.NoError(t, err)
	assert.Contains(t, docWide, `"10.65.0.0/16:*"`)
}

func TestValidateRefusesRoutesThatWidenTheNetwork(t *testing.T) {
	in := narrowedInputs()

	for i := range in.Networks {
		if in.Networks[i].Name == "dev" {
			in.Networks[i].Routes = []string{"10.0.0.0/8"}
		}
	}

	err := in.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "outside the network's own address space")
}

func TestValidateIgnoresRoutesOfANetworkOutsideTheTailnet(t *testing.T) {
	in := narrowedInputs()
	in.Tailnet.Networks = []string{"hub", "lab"}

	for i := range in.Networks {
		if in.Networks[i].Name == "dev" {
			in.Networks[i].Routes = []string{"10.0.0.0/8"}
		}
	}

	require.NoError(t, in.Validate())
}

func TestCheckAdvertisedRefusesAFleetThatDisagreesWithThePolicy(t *testing.T) {
	in := narrowedInputs()

	require.NoError(t, in.CheckAdvertised("dev", []string{"10.65.8.0/24", "10.99.0.0/24"}))

	// The fleet still advertises the whole VPC CIDR.
	err := in.CheckAdvertised("dev", []string{"10.65.0.0/16", "10.99.0.0/24"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "tailnet acme")
	assert.ErrorContains(t, err, "advertises 10.65.0.0/16")

	// The fleet advertises less than the policy grants.
	require.ErrorContains(t, in.CheckAdvertised("dev", []string{"10.65.8.0/24"}), "exposes 10.99.0.0/24")

	// A network the tailnet does not list.
	in.Tailnet.Networks = []string{"hub"}
	require.ErrorContains(t, in.CheckAdvertised("dev", nil), "unknown network")
}

func TestRoutesStayInsideACeiling(t *testing.T) {
	in := narrowedInputs()
	in.Tailnet.Networks = []string{"dev"}
	in.Policy.Ceiling = &acl.Ceiling{
		Destinations: []acl.Destination{
			{CIDR: "10.65.8.0/24", Ports: []string{"*"}},
			{CIDR: "10.99.0.0/24", Ports: []string{"*"}},
			{CIDR: "172.21.0.0/16", Ports: []string{"*"}},
			{Tag: "dev-router", Ports: []string{"*"}},
			{Tag: "k8s-dev-router", Ports: []string{"*"}},
		},
		Routes: []string{"10.65.8.0/24", "10.99.0.0/24", "172.21.0.0/16"},
	}

	require.NoError(t, in.Validate())

	// Without Routes the same ceiling refuses the whole VPC CIDR.
	for i := range in.Networks {
		in.Networks[i].Routes = nil
	}

	err := in.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "10.65.0.0/16:*")
}
