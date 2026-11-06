package acl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleCeiling admits one /16 on every port, one /24 on 443 only, and a
// router tag on two ports. Every value is documentation-range or example data.
func exampleCeiling() *Ceiling {
	return &Ceiling{Destinations: []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"*"}},
		{CIDR: "192.0.2.0/24", Ports: []string{"443"}},
		{Tag: "devel-router", Ports: []string{"22", "8000-8100"}},
	}}
}

func TestCeilingValidateAcceptsAWellFormedCeiling(t *testing.T) {
	require.NoError(t, exampleCeiling().Validate())
	// A nil ceiling is "no ceiling"; an empty one admits nothing. Neither is malformed.
	require.NoError(t, (*Ceiling)(nil).Validate())
	require.NoError(t, (&Ceiling{}).Validate())
}

func TestCeilingValidateRefusals(t *testing.T) {
	cases := map[string]Destination{
		"both cidr and tag":    {CIDR: "10.0.0.0/16", Tag: "x", Ports: []string{"*"}},
		"neither cidr nor tag": {Ports: []string{"*"}},
		"empty ports":          {CIDR: "10.0.0.0/16"},
		"port zero":            {CIDR: "10.0.0.0/16", Ports: []string{"0"}},
		"reversed range":       {CIDR: "10.0.0.0/16", Ports: []string{"80-70"}},
		"port above 65535":     {CIDR: "10.0.0.0/16", Ports: []string{"70000"}},
		"range above 65535":    {CIDR: "10.0.0.0/16", Ports: []string{"80-70000"}},
		"port not a number":    {CIDR: "10.0.0.0/16", Ports: []string{"http"}},
		"signed port":          {CIDR: "10.0.0.0/16", Ports: []string{"+80"}},
		"empty port entry":     {CIDR: "10.0.0.0/16", Ports: []string{""}},
		"duplicate port":       {CIDR: "10.0.0.0/16", Ports: []string{"80", "80"}},
		"non-canonical cidr":   {CIDR: "10.1.2.3/16", Ports: []string{"*"}},
		"unparsable cidr":      {CIDR: "not-a-cidr", Ports: []string{"*"}},
		"bare address":         {CIDR: "10.0.0.1", Ports: []string{"*"}},
		"tag with prefix":      {Tag: "tag:x", Ports: []string{"*"}},
		"tag with colon":       {Tag: "x:y", Ports: []string{"*"}},
		"tag with space":       {Tag: "x y", Ports: []string{"*"}},
	}

	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, (&Ceiling{Destinations: []Destination{d}}).Validate())
		})
	}

	t.Run("duplicate cidr", func(t *testing.T) {
		c := &Ceiling{Destinations: []Destination{
			{CIDR: "10.0.0.0/16", Ports: []string{"80"}},
			{CIDR: "10.0.0.0/16", Ports: []string{"443"}},
		}}
		require.Error(t, c.Validate())
	})

	t.Run("duplicate tag", func(t *testing.T) {
		c := &Ceiling{Destinations: []Destination{
			{Tag: "x", Ports: []string{"80"}},
			{Tag: "x", Ports: []string{"443"}},
		}}
		require.Error(t, c.Validate())
	})
}

func TestCeilingRefusesDestinationOutsideCIDR(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/16", Ports: []string{"*"}}}}

	require.NoError(t, c.CheckDst("10.0.0.0/16:*"))
	require.NoError(t, c.CheckDst("10.0.0.5/32:443"))

	err := c.CheckDst("10.1.0.5/32:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.1.0.5/32:443")
	assert.Contains(t, err.Error(), "ceiling")
}

func TestCeilingRefusesPortsOutsideTheEntry(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/16", Ports: []string{"443"}}}}

	require.NoError(t, c.CheckDst("10.0.0.0/16:443"))
	require.Error(t, c.CheckDst("10.0.0.0/16:*"))
	require.Error(t, c.CheckDst("10.0.0.0/16:443,8443"))
	require.Error(t, c.CheckDst("10.0.0.0/16:400-500"))
}

func TestCeilingAdmitsPortListsAndRanges(t *testing.T) {
	c := exampleCeiling()

	require.NoError(t, c.CheckDst("tag:devel-router:22"))
	require.NoError(t, c.CheckDst("tag:devel-router:22,8050"))
	require.NoError(t, c.CheckDst("tag:devel-router:8000-8100"))
	require.NoError(t, c.CheckDst("tag:devel-router:8010-8020,8030"))
	require.Error(t, c.CheckDst("tag:devel-router:8000-8101"))
	require.Error(t, c.CheckDst("tag:devel-router:*"))
	// Two entries' ports are not pooled across prefixes that do not both contain the destination.
	require.Error(t, c.CheckDst("192.0.2.0/24:80"))
}

func TestCeilingRefusesWidenedPrefix(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "10.0.1.0/24", Ports: []string{"*"}}}}

	require.Error(t, c.CheckDst("10.0.0.0/16:*"))
	require.NoError(t, c.CheckDst("10.0.1.0/25:*"))
	require.NoError(t, c.CheckDst("10.0.1.0/24:*"))
	// A /16 is not the union of its /24s: a prefix is admitted by one entry that contains it.
	require.Error(t, c.CheckDst("10.0.0.0/23:*"))
}

func TestCeilingUnionsThePortsOfEntriesThatContainTheDestination(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{
		{CIDR: "10.0.0.0/16", Ports: []string{"80"}},
		{CIDR: "10.0.1.0/24", Ports: []string{"443"}},
	}}

	require.NoError(t, c.CheckDst("10.0.1.5/32:80,443"))
	require.Error(t, c.CheckDst("10.0.2.5/32:80,443"))
}

func TestCeilingRefusesTagNotListed(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{Tag: "devel-router", Ports: []string{"*"}}}}

	require.NoError(t, c.CheckDst("tag:devel-router:*"))
	require.NoError(t, c.CheckDst("tag:devel-router:22"))
	require.Error(t, c.CheckDst("tag:other-router:*"))
	require.Error(t, c.CheckDst("tag:devel-router-2:22"))
	// A prefix entry never admits a tag, nor the reverse.
	require.Error(t, (&Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/16", Ports: []string{"*"}}}}).CheckDst("tag:devel-router:*"))
}

func TestCeilingFailsClosedOnUnknownShapes(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{
		{CIDR: "0.0.0.0/0", Ports: []string{"*"}},
		{Tag: "x", Ports: []string{"*"}},
	}}

	for _, dst := range []string{
		"autogroup:internet:*",
		"autogroup:self:*",
		"group:eng@example.com:*",
		"*:*",
		"*",
		"10.0.0.1:443",
		"10.0.0.1/32",
		"10.1.2.3/16:*",
		"not-a-cidr/33:*",
		"host.example.com:443",
		"tag:x",
		"tag:x:",
		"tag:x:0",
		"tag:x:99999",
		"10.0.0.0/16:80,,443",
		"",
	} {
		require.Error(t, c.CheckDst(dst), "%q must be refused", dst)
	}
}

func TestCeilingEmptyAdmitsNothing(t *testing.T) {
	c := &Ceiling{}

	require.Error(t, c.CheckDst("10.0.0.0/16:*"))
	require.Error(t, c.CheckDst("tag:x:22"))
}

func TestNilCeilingFailsClosed(t *testing.T) {
	var c *Ceiling

	require.Error(t, c.CheckDst("10.0.0.0/16:*"))
	require.Error(t, c.Within(exampleCeiling()))
	require.Error(t, exampleCeiling().Within(nil))
}

func TestCeilingParsesIPv6(t *testing.T) {
	c := &Ceiling{Destinations: []Destination{{CIDR: "2001:db8::/32", Ports: []string{"443"}}}}

	require.NoError(t, c.Validate())
	require.NoError(t, c.CheckDst("2001:db8:1::/48:443"))
	require.NoError(t, c.CheckDst("2001:db8::5/128:443"))
	require.Error(t, c.CheckDst("2001:db9::/32:443"))
	require.Error(t, c.CheckDst("2001:db8::/32:80"))
	// An IPv4 destination is not inside an IPv6 entry, and the reverse.
	require.Error(t, c.CheckDst("10.0.0.0/8:443"))
	require.Error(t, (&Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/8", Ports: []string{"*"}}}}).CheckDst("2001:db8::/32:443"))
}

func TestCeilingRefusalNamesTheNearestEntry(t *testing.T) {
	c := exampleCeiling()

	err := c.CheckDst("192.0.2.0/24:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nearest entry 192.0.2.0/24")

	err = c.CheckDst("198.51.100.0/24:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no entry")
}

func TestCeilingWithinRefusesWidening(t *testing.T) {
	registered := exampleCeiling()

	// Equal, and narrower in each dimension, are within.
	require.NoError(t, exampleCeiling().Within(registered))
	require.NoError(t, (&Ceiling{Destinations: []Destination{
		{CIDR: "10.0.5.0/24", Ports: []string{"443", "8443"}},
		{Tag: "devel-router", Ports: []string{"22"}},
	}}).Within(registered))
	require.NoError(t, (&Ceiling{}).Within(registered))

	// One extra CIDR.
	wider := exampleCeiling()
	wider.Destinations = append(wider.Destinations, Destination{CIDR: "198.51.100.0/24", Ports: []string{"443"}})
	require.Error(t, wider.Within(registered))

	// One widened prefix.
	wider = exampleCeiling()
	wider.Destinations[1].CIDR = "192.0.0.0/16"
	require.Error(t, wider.Within(registered))

	// One extra port.
	wider = exampleCeiling()
	wider.Destinations[1].Ports = []string{"443", "80"}
	require.Error(t, wider.Within(registered))

	// One extra tag.
	wider = exampleCeiling()
	wider.Destinations = append(wider.Destinations, Destination{Tag: "other-router", Ports: []string{"22"}})
	require.Error(t, wider.Within(registered))

	// A tag on a port the registered tag does not carry.
	wider = exampleCeiling()
	wider.Destinations[2].Ports = []string{"22", "9000"}
	require.Error(t, wider.Within(registered))
}

func TestCeilingWithinRefusesAMalformedCeiling(t *testing.T) {
	bad := &Ceiling{Destinations: []Destination{{CIDR: "10.0.0.0/16"}}}

	require.Error(t, bad.Within(exampleCeiling()))
	require.Error(t, (&Ceiling{}).Within(bad))
}
