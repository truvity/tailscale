package acl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// anyDestination admits every rule destination the model can render, so a
// test of Routes isolates the route check.
func anyDestination() []Destination {
	return []Destination{
		{CIDR: "0.0.0.0/0", Ports: []string{"*"}},
		{Tag: "a-router", Ports: []string{"*"}},
		{Tag: "k8s-a-router", Ports: []string{"*"}},
	}
}

func routesPolicy(routes ...string) Policy {
	p := ceilingPolicy()
	p.Ceiling = &Ceiling{Destinations: anyDestination(), Routes: routes}

	return p
}

func TestCeilingRoutesRefuseUnlistedRoute(t *testing.T) {
	// The model approves 10.0.0.0/16 and 172.16.0.0/16 for the routers.
	_, err := Build(routesPolicy("10.0.0.0/16", "172.16.0.0/16"))
	require.NoError(t, err)

	// A service CIDR outside Routes.
	_, err = Build(routesPolicy("10.0.0.0/16"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "172.16.0.0/16")
	assert.Contains(t, err.Error(), "autoApprovers.routes")

	// A network's extra CIDR outside Routes.
	p := routesPolicy("10.0.0.0/16", "172.16.0.0/16")
	p.Networks[0].ExtraCIDRs = []string{"192.0.2.0/24"}
	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "192.0.2.0/24")

	// Inside a wider listed prefix is fine.
	_, err = Build(routesPolicy("10.0.0.0/8", "172.16.0.0/12"))
	require.NoError(t, err)

	// The default route is refused unless it is listed.
	p = routesPolicy("10.0.0.0/8", "172.16.0.0/12")
	p.Networks[0].ExtraCIDRs = []string{"0.0.0.0/0"}
	_, err = Build(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.0.0.0/0")

	p = routesPolicy("0.0.0.0/0")
	p.Networks[0].ExtraCIDRs = []string{"0.0.0.0/0"}
	_, err = Build(p)
	require.NoError(t, err)
}

func TestCeilingWithoutRoutesLeavesRoutesUnchecked(t *testing.T) {
	p := routesPolicy()
	p.Networks[0].ExtraCIDRs = []string{"192.0.2.0/24", "0.0.0.0/0"}

	_, err := Build(p)
	require.NoError(t, err)
}

func TestCeilingRoutesDoNotChangeTheOutput(t *testing.T) {
	want, err := Build(ceilingPolicy())
	require.NoError(t, err)

	got, err := Build(routesPolicy("10.0.0.0/8", "172.16.0.0/12"))
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCeilingReportsRuleViolationsBeforeRouteViolationsInOrder(t *testing.T) {
	p := routesPolicy("10.0.0.0/16")
	p.Ceiling.Destinations = []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"*"}},
		{Tag: "a-router", Ports: []string{"*"}},
		{Tag: "k8s-a-router", Ports: []string{"*"}},
	}
	p.Networks[0].ExtraCIDRs = []string{"198.51.100.0/24", "192.0.2.0/24"}

	_, err := Build(p)
	require.Error(t, err)

	want := err.Error()
	assert.Regexp(t, `(?s)rule 0 destination 198\.51\.100\.0/24:\*.*rule 0 destination 192\.0\.2\.0/24:\*.*rule 1 destination 172\.16\.0\.0/16:\*.*autoApprovers\.routes 172\.16\.0\.0/16.*autoApprovers\.routes 192\.0\.2\.0/24.*autoApprovers\.routes 198\.51\.100\.0/24`, want)

	_, again := Build(p)
	assert.Equal(t, want, again.Error())
}

func TestCeilingCheckRoute(t *testing.T) {
	c := &Ceiling{Routes: []string{"10.0.0.0/16", "2001:db8::/32"}}

	require.NoError(t, c.CheckRoute("10.0.0.0/16"))
	require.NoError(t, c.CheckRoute("10.0.5.0/24"))
	require.NoError(t, c.CheckRoute("2001:db8:1::/48"))
	require.Error(t, c.CheckRoute("10.1.0.0/16"))
	require.Error(t, c.CheckRoute("10.0.0.0/8"), "a wider prefix is not inside")
	require.Error(t, c.CheckRoute("0.0.0.0/0"))
	require.Error(t, c.CheckRoute("10.0.0.1/16"), "non-canonical")
	require.Error(t, c.CheckRoute("10.0.0.1"), "bare address")
	require.Error(t, c.CheckRoute("not-a-route"))

	// Empty Routes means routes are not bounded.
	require.NoError(t, (&Ceiling{}).CheckRoute("0.0.0.0/0"))

	var nilCeiling *Ceiling
	require.Error(t, nilCeiling.CheckRoute("10.0.0.0/16"), "a nil receiver fails closed")
}

func TestCeilingValidateRoutesRefusals(t *testing.T) {
	require.NoError(t, (&Ceiling{Routes: []string{"10.0.0.0/16", "2001:db8::/32"}}).Validate())

	for name, routes := range map[string][]string{
		"non-canonical": {"10.0.0.1/16"},
		"unparsable":    {"nope"},
		"bare address":  {"10.0.0.1"},
		"empty entry":   {""},
		"duplicate":     {"10.0.0.0/16", "10.0.0.0/16"},
		"mapped ipv6":   {"::ffff:10.0.0.0/104"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, (&Ceiling{Routes: routes}).Validate())
		})
	}
}

func TestCeilingWithinBoundsRoutes(t *testing.T) {
	registered := &Ceiling{Routes: []string{"10.0.0.0/16", "192.0.2.0/24"}}

	require.NoError(t, (&Ceiling{Routes: []string{"10.0.0.0/16", "192.0.2.0/24"}}).Within(registered))
	require.NoError(t, (&Ceiling{Routes: []string{"10.0.5.0/24"}}).Within(registered))

	// An extra route, a widened prefix, and no Routes at all (unbounded) are wider.
	require.Error(t, (&Ceiling{Routes: []string{"10.1.0.0/16"}}).Within(registered))
	require.Error(t, (&Ceiling{Routes: []string{"10.0.0.0/8"}}).Within(registered))
	require.Error(t, (&Ceiling{}).Within(registered))

	// A registered ceiling without Routes bounds none, so any Routes are within it.
	require.NoError(t, (&Ceiling{Routes: []string{"10.1.0.0/16"}}).Within(&Ceiling{}))
	require.NoError(t, (&Ceiling{}).Within(&Ceiling{}))
}
