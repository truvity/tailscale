package awsrouter

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unset case is pinned by the unmodified goldens (userdata-default.yaml
// and the resource-set goldens); these tests cover what Routes changes.

func TestRoutesUnsetAdvertiseTheVPCCIDRAndTheExtras(t *testing.T) {
	a := exampleFleet()
	assert.Equal(t, []string{"10.0.0.0/16"}, a.AdvertisedRoutes())

	a.ExtraCIDRs = []string{"10.9.0.0/24"}
	assert.Equal(t, []string{"10.0.0.0/16", "10.9.0.0/24"}, a.AdvertisedRoutes())

	a.Routes = []string{}
	assert.Equal(t, []string{"10.0.0.0/16", "10.9.0.0/24"}, a.AdvertisedRoutes(), "an empty list is unset")
}

func TestRoutesNarrowTheAdvertisedRoutes(t *testing.T) {
	a := exampleFleet()
	a.ExtraCIDRs = []string{"10.9.0.0/24"}
	a.Routes = []string{"10.0.8.0/24", "10.9.0.0/24"}

	assert.Equal(t, []string{"10.0.8.0/24", "10.9.0.0/24"}, a.AdvertisedRoutes())
	assert.Equal(t, []string{"10.0.8.0/24", "10.9.0.0/24"}, a.InstanceConfig(pulumi.ID("vpc").ToIDOutput(), nil).VPCCIDRs)

	// The router's user data carries the narrowed list and nothing of the rest.
	c := exampleConfig()
	c.VPCCIDRs = a.AdvertisedRoutes()
	data := buildTailscaleUserData(c)
	assert.Contains(t, data, `ADVERTISE_ROUTES="10.0.8.0/24,10.9.0.0/24"`)
	assert.NotContains(t, data, "10.0.0.0/16")

	// The caller's slice is not shared with the config.
	got := a.AdvertisedRoutes()
	got[0] = "changed"
	assert.Equal(t, "10.0.8.0/24", a.Routes[0])

	_, err := runFleet(t, a)
	require.NoError(t, err)
}

func TestRoutesAreHeldBelowTheFleetsOwnSpace(t *testing.T) {
	for name, routes := range map[string][]string{
		"not a cidr":             {"banana"},
		"host bits set":          {"10.0.8.1/24"},
		"outside the VPC CIDR":   {"10.1.0.0/24"},
		"wider than the VPC":     {"10.0.0.0/8"},
		"the default route":      {"0.0.0.0/0"},
		"repeats a route":        {"10.0.8.0/24", "10.0.8.0/24"},
		"overlaps a route":       {"10.0.8.0/24", "10.0.8.128/25"},
		"one good, one outside":  {"10.0.8.0/24", "203.0.113.0/24"},
		"outside the extras too": {"10.9.1.0/24"},
	} {
		t.Run(name, func(t *testing.T) {
			a := exampleFleet()
			a.ExtraCIDRs = []string{"10.9.0.0/24"}
			a.Routes = routes
			require.Error(t, a.ValidateRoutes())

			_, err := runFleet(t, a)
			require.Error(t, err, "DeployFleet refuses the fleet before anything is created")
		})
	}

	// Equal to the whole space is allowed, and so is a route inside an extra.
	a := exampleFleet()
	a.ExtraCIDRs = []string{"10.9.0.0/24"}
	a.Routes = []string{"10.0.0.0/16", "10.9.0.128/25"}
	require.NoError(t, a.ValidateRoutes())
}
