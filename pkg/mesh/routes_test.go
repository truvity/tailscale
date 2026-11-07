package mesh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/tailscale/pkg/acl"
)

// narrowedInputs is exampleInputs with the dev network's address space given
// an extra route and the tailnet's routes for it cut down to part of it.
func narrowedInputs() Inputs {
	in := exampleInputs()

	for i := range in.Networks {
		if in.Networks[i].Name == "dev" {
			in.Networks[i].ExtraCIDRs = []string{"10.99.0.0/24"}
		}
	}

	in.Tailnet.Routes = map[string][]string{"dev": {"10.65.8.0/24", "10.99.0.0/24"}}

	return in
}

func TestEmptyRoutesChangeNothingAndAStrayNameIsRefused(t *testing.T) {
	// Routes for a network the tailnet does not join are refused (a name
	// that matches nothing would silently narrow nothing), but an empty
	// entry is the same as none: the policy is the one a program that never
	// set them renders.
	plain := exampleInputs()

	want, err := plain.PolicyModel()
	require.NoError(t, err)

	wantDoc, err := acl.Build(want)
	require.NoError(t, err)

	for _, routes := range []map[string][]string{nil, {}, {"dev": nil}, {"dev": {}}, {"lab": {}, "elsewhere": nil}} {
		in := exampleInputs()
		in.Tailnet.Routes = routes
		require.NoError(t, in.Validate())

		got, err := in.PolicyModel()
		require.NoError(t, err)

		gotDoc, err := acl.Build(got)
		require.NoError(t, err)
		assert.Equal(t, wantDoc, gotDoc)
	}

	other := exampleInputs()
	other.Tailnet.Networks = []string{"hub", "lab"}
	other.Tailnet.Routes = map[string][]string{"dev": {"10.65.8.0/24"}}
	require.ErrorContains(t, other.Validate(), `network "dev", which the tailnet does not join`)
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
	wide.Tailnet.Routes = nil

	pw, err := wide.PolicyModel()
	require.NoError(t, err)

	docWide, err := acl.Build(pw)
	require.NoError(t, err)
	assert.Contains(t, docWide, `"10.65.0.0/16:*"`)
}

func TestValidateRefusesRoutesThatWidenTheNetwork(t *testing.T) {
	in := narrowedInputs()
	in.Tailnet.Routes = map[string][]string{"dev": {"10.0.0.0/8"}}

	err := in.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "outside the network's own address space")
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
	in.Tailnet.Routes = nil

	err := in.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "10.65.0.0/16:*")
}

func TestRoutesForANetworkThePolicySkipsAreRefused(t *testing.T) {
	// PolicyModel skips a network that is not declared, has no router, or is
	// not joined, so a list for it would read as narrowed and narrow nothing.
	// Each case asserts the message that names the network and the reason.
	for _, tc := range []struct {
		name   string
		mutate func(in *Inputs)
		want   string
	}{
		{
			name: "joined network without a router",
			mutate: func(in *Inputs) {
				in.Tailnet.Networks = append(in.Tailnet.Networks, "bare")
				in.Tailnet.Routes = map[string][]string{"bare": {"10.70.0.0/24"}}
			},
			want: `routes name network "bare", which has no router, so the list would narrow nothing`,
		},
		{
			name: "declared network without a router that is not joined",
			mutate: func(in *Inputs) {
				in.Tailnet.Routes = map[string][]string{"bare": {"10.70.0.0/24"}}
			},
			want: `routes name network "bare", which has no router, so the list would narrow nothing`,
		},
		{
			name: "joined network missing from the inputs",
			mutate: func(in *Inputs) {
				in.Tailnet.Networks = append(in.Tailnet.Networks, "ghost")
				in.Tailnet.Routes = map[string][]string{"ghost": {"10.71.0.0/24"}}
			},
			want: `routes name network "ghost", which is not declared in the inputs, so the list would narrow nothing`,
		},
		{
			name: "network missing from the inputs and not joined",
			mutate: func(in *Inputs) {
				in.Tailnet.Routes = map[string][]string{"ghost": {"10.71.0.0/24"}}
			},
			want: `routes name network "ghost", which is not declared in the inputs, so the list would narrow nothing`,
		},
		{
			name: "declared router network that is not joined",
			mutate: func(in *Inputs) {
				in.Tailnet.Networks = []string{"hub", "lab"}
				in.Tailnet.Routes = map[string][]string{"dev": {"10.65.8.0/24"}}
			},
			want: `routes name network "dev", which the tailnet does not join`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := exampleInputs()
			tc.mutate(&in)

			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "tailnet acme: "+tc.want)
		})
	}
}
