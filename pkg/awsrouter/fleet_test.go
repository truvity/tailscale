package awsrouter

import (
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func exampleFleet() FleetArgs {
	return FleetArgs{
		Environment:             "example",
		Region:                  "eu-west-1",
		VPCCIDR:                 "10.0.0.0/16",
		Min:                     1,
		Desired:                 1,
		Max:                     2,
		Tailnet:                 "acme",
		SSMAuthKeyPath:          "/tailscale/acme/auth-key",
		PermissionsBoundaryName: "example-boundary",
		RouterSetupVersion:      "1.11.0",
	}
}

// fleetMocks answers the two network lookups with one VPC and two subnets
// and records every filter set it was asked for; a route table lookup
// answers routeTables[subnet], or "rtb-public".
type fleetMocks struct {
	providerGuardMocks
	mu2         sync.Mutex
	filters     map[string][]resource.PropertyValue
	routeTables map[string]string
}

func (m *fleetMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if f := args.Args["filters"]; f.IsArray() {
		m.mu2.Lock()
		if m.filters == nil {
			m.filters = map[string][]resource.PropertyValue{}
		}
		m.filters[args.Token] = f.ArrayValue()
		m.mu2.Unlock()
	}

	switch args.Token {
	case "aws:ec2/getVpc:getVpc":
		return resource.NewPropertyMapFromMap(map[string]interface{}{"id": "vpc-0123456789abcdef0"}), nil
	case "aws:ec2/getSubnets:getSubnets":
		return resource.NewPropertyMapFromMap(map[string]interface{}{
			"ids": []interface{}{"subnet-a", "subnet-b"},
		}), nil
	case "aws:ec2/getRouteTable:getRouteTable":
		rt := "rtb-public"
		if v, ok := m.routeTables[args.Args["subnetId"].StringValue()]; ok {
			rt = v
		}

		return resource.NewPropertyMapFromMap(map[string]interface{}{"id": rt, "routeTableId": rt}), nil
	}

	return m.providerGuardMocks.Call(args)
}

func runFleet(t *testing.T, a FleetArgs) (*fleetMocks, error) {
	t.Helper()

	return runFleetWith(t, a, nil)
}

func runFleetWith(t *testing.T, a FleetArgs, routeTables map[string]string) (*fleetMocks, error) {
	t.Helper()

	m := &fleetMocks{providerGuardMocks: providerGuardMocks{res: map[string]resource.PropertyMap{}}, routeTables: routeTables}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{Region: pulumi.String("eu-west-1")})
		if err != nil {
			return err
		}

		return DeployFleet(ctx, slog.Default(), provider, a)
	}, pulumi.WithMocks("p", "s", m))

	return m, err
}

func filterPairs(t *testing.T, filters []resource.PropertyValue) map[string]string {
	t.Helper()

	out := map[string]string{}

	for _, f := range filters {
		obj := f.ObjectValue()
		out[obj["name"].StringValue()] = obj["values"].ArrayValue()[0].StringValue()
	}

	return out
}

func TestDeployFleetFindsTheNetworkByTagAndCreatesTheFleet(t *testing.T) {
	m, err := runFleet(t, exampleFleet())
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"tag:Environment": "example", "tag:ManagedBy": "pulumi"},
		filterPairs(t, m.filters["aws:ec2/getVpc:getVpc"]))
	assert.Equal(t, map[string]string{"vpc-id": "vpc-0123456789abcdef0", "tag:Type": "public", "tag:ManagedBy": "pulumi"},
		filterPairs(t, m.filters["aws:ec2/getSubnets:getSubnets"]))

	_, ok := m.res["aws:ec2/launchTemplate:LaunchTemplate/tailscale-lt"]
	assert.True(t, ok, "the fleet's launch template is registered")
	asg := m.res["aws:autoscaling/group:Group/tailscale-asg"]
	assert.Equal(t, "subnet-a", asg["vpcZoneIdentifiers"].ArrayValue()[0].StringValue())
}

func TestDeployFleetHonoursOtherTagConventions(t *testing.T) {
	a := exampleFleet()
	a.Network = NetworkTags{EnvironmentKey: "Env", ManagedByKey: "Owner", ManagedByValue: "iac", SubnetTypeKey: "Tier", PublicValue: "edge"}

	m, err := runFleet(t, a)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"tag:Env": "example", "tag:Owner": "iac"},
		filterPairs(t, m.filters["aws:ec2/getVpc:getVpc"]))
	assert.Equal(t, map[string]string{"vpc-id": "vpc-0123456789abcdef0", "tag:Tier": "edge", "tag:Owner": "iac"},
		filterPairs(t, m.filters["aws:ec2/getSubnets:getSubnets"]))
}

func TestInstanceConfigCarriesNoSSHUserCA(t *testing.T) {
	a := exampleFleet()
	a.OPKSSH = NewOPKSSH(OPKSSHPreset{Issuer: "https://issuer.example.test", ClientID: "ssh", User: "ec2-user", Group: "example.ssh.admin"})

	c := a.InstanceConfig(pulumi.ID("vpc").ToIDOutput(), nil)

	assert.Empty(t, c.TrustedUserCAKeys)
	assert.Empty(t, c.AuthorizedPrincipals)
	assert.Equal(t, []string{"10.0.0.0/16"}, c.VPCCIDRs)
	assert.Equal(t, "example-boundary", c.PermissionsBoundaryName)
	assert.NoError(t, c.validateOPKSSH())
}

func TestNewOPKSSHPinsTheVerifiedRelease(t *testing.T) {
	o := NewOPKSSH(OPKSSHPreset{Issuer: "https://issuer.example.test", ClientID: "ssh", User: "ec2-user", Group: "g"})

	assert.True(t, o.Enabled)
	assert.Equal(t, PinnedOPKSSHVersion, o.ArtifactVersion)
	assert.Contains(t, o.ArtifactURL, "/v"+PinnedOPKSSHVersion+"/")
	assert.Contains(t, o.SELinuxModuleURL, "/v"+PinnedOPKSSHVersion+"/")
	assert.Equal(t, []OPKSSHProvider{{Issuer: "https://issuer.example.test", ClientID: "ssh", Expiration: "24h"}}, o.Providers)
	assert.Equal(t, []OPKSSHAuthID{{User: "ec2-user", Group: "g", Issuer: "https://issuer.example.test"}}, o.AuthorizedIdentities)

	cfg := exampleConfig()
	cfg.OPKSSH = o
	assert.NoError(t, cfg.validateOPKSSH())
}

func TestNewHostCertPinsTheArtifactAndKeepsTheEstatesNames(t *testing.T) {
	h := NewHostCert(HostCertPreset{
		Address: "https://bao.example.test", Namespace: "example", AuthMount: "aws", AuthRole: "router",
		ServerIDHeader: "bao.example.test", SSHMount: "ssh", SSHRole: "router-host",
		PrincipalPatterns: []string{"*.example.ts.net"},
	})

	assert.True(t, h.Enabled)
	assert.Equal(t, PinnedHostCertVersion, h.ArtifactVersion)
	assert.Contains(t, h.ArtifactSHA256, "arm64")
	assert.Equal(t, []string{"*.example.ts.net"}, h.PrincipalPatterns)

	// A caller changing its copy must not change the pin.
	h.ArtifactSHA256["arm64"] = "changed"
	assert.NotEqual(t, "changed", NewHostCert(HostCertPreset{}).ArtifactSHA256["arm64"])
}

func TestTwoTailnetsFleetsFitInOneStack(t *testing.T) {
	m := &fleetMocks{providerGuardMocks: providerGuardMocks{res: map[string]resource.PropertyMap{}}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{Region: pulumi.String("eu-west-1")})
		if err != nil {
			return err
		}

		if err := DeployFleet(ctx, slog.Default(), provider, exampleFleet()); err != nil {
			return err
		}

		other := exampleFleet()
		other.Tailnet = "other"
		other.SSMAuthKeyPath = "/tailscale/other/auth-key"
		other.ResourcePrefix = "other-"

		return DeployFleet(ctx, slog.Default(), provider, other)
	}, pulumi.WithMocks("p", "s", m))
	require.NoError(t, err)

	// The unprefixed fleet keeps the names it always had; the other one
	// carries its prefix on every resource, and names its AWS objects
	// after its own tailnet.
	for _, name := range []string{"tailscale-sg", "tailscale-sg-ingress-wireguard", "tailscale-sg-egress-all",
		"tailscale-role", "tailscale-instance-profile", "tailscale-lt", "tailscale-asg",
		"tailscale-lifecycle-hook"} {
		found := 0

		for key := range m.res {
			if strings.HasSuffix(key, "/"+name) || strings.HasSuffix(key, "/other-"+name) {
				found++
			}
		}

		assert.Equal(t, 2, found, "%s: one per fleet", name)
	}

	// The fleet's two CloudWatch alarms are gone: monitoring is the estate's own.
	for key := range m.res {
		assert.NotContains(t, key, "cloudwatch", "no alarm is created")
	}

	assert.Equal(t, "example-tailscale-other", m.res["aws:ec2/securityGroup:SecurityGroup/other-tailscale-sg"]["name"].StringValue())
	assert.Equal(t, "example-tailscale-acme", m.res["aws:ec2/securityGroup:SecurityGroup/tailscale-sg"]["name"].StringValue())
}

func TestExtraCIDRsFollowTheVPCCIDRInTheAdvertisedRoutes(t *testing.T) {
	a := exampleFleet()
	assert.Equal(t, []string{"10.0.0.0/16"}, a.InstanceConfig(pulumi.ID("vpc").ToIDOutput(), nil).VPCCIDRs, "no extras: unchanged")

	a.ExtraCIDRs = []string{"10.9.0.0/24", "10.10.0.0/24"}
	assert.Equal(t, []string{"10.0.0.0/16", "10.9.0.0/24", "10.10.0.0/24"}, a.InstanceConfig(pulumi.ID("vpc").ToIDOutput(), nil).VPCCIDRs)

	_, err := runFleet(t, a)
	require.NoError(t, err)
}

func TestExtraCIDRsAreValidated(t *testing.T) {
	for name, extras := range map[string][]string{
		"not a cidr":            {"banana"},
		"repeats the VPC CIDR":  {"10.0.0.0/16"},
		"inside the VPC CIDR":   {"10.0.5.0/24"},
		"contains the VPC CIDR": {"10.0.0.0/8"},
		"repeats an extra":      {"10.9.0.0/24", "10.9.0.0/24"},
		"overlaps an extra":     {"10.9.0.0/24", "10.9.0.128/25"},
	} {
		t.Run(name, func(t *testing.T) {
			a := exampleFleet()
			a.ExtraCIDRs = extras
			require.Error(t, a.ValidateRoutes())

			_, err := runFleet(t, a)
			require.Error(t, err)
		})
	}
}

// ownSubnets are a fleet's subnets of its own in two zones, listed out of
// zone order.
func ownSubnets() []FleetSubnet {
	return []FleetSubnet{
		{AvailabilityZone: "eu-west-1b", CIDR: "10.0.3.16/28"},
		{AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.0/28"},
	}
}

func TestDeployFleetWithoutSubnetsCreatesNoSubnet(t *testing.T) {
	m, err := runFleet(t, exampleFleet())
	require.NoError(t, err)

	for key := range m.res {
		assert.NotContains(t, key, "aws:ec2/subnet:Subnet", "no subnet is created")
		assert.NotContains(t, key, "aws:ec2/routeTableAssociation:RouteTableAssociation", "no association is created")
	}

	_, looked := m.calls["aws:ec2/getRouteTable:getRouteTable"]
	assert.False(t, looked, "no route table is looked up")

	// A change of subnets refreshes the routers whichever subnets they are:
	// moving out of the fleet's own subnets again replaces them too.
	triggers := m.res["aws:autoscaling/group:Group/tailscale-asg"]["instanceRefresh"].ObjectValue()["triggers"].ArrayValue()
	require.Len(t, triggers, 1)
	assert.Equal(t, "vpc_zone_identifier", triggers[0].StringValue())
}

func TestDeployFleetRunsTheRoutersInSubnetsOfTheirOwn(t *testing.T) {
	a := exampleFleet()
	a.Subnets = ownSubnets()

	m, err := runFleet(t, a)
	require.NoError(t, err)

	for zone, cidr := range map[string]string{"eu-west-1a": "10.0.3.0/28", "eu-west-1b": "10.0.3.16/28"} {
		sn, ok := m.res["aws:ec2/subnet:Subnet/tailscale-subnet-"+zone]
		require.True(t, ok, "the %s subnet is registered", zone)
		assert.Equal(t, "vpc-0123456789abcdef0", sn["vpcId"].StringValue())
		assert.Equal(t, cidr, sn["cidrBlock"].StringValue())
		assert.Equal(t, zone, sn["availabilityZone"].StringValue())
		assert.False(t, sn["mapPublicIpOnLaunch"].BoolValue(), "the launch template gives the public address")
		assert.False(t, sn.HasValue("ipv6CidrBlock"), "no IPv6 block")

		tags := sn["tags"].ObjectValue()
		assert.Equal(t, "example-tailscale-acme-"+zone, tags["Name"].StringValue())
		assert.Equal(t, "example", tags["Environment"].StringValue())
		assert.Equal(t, "pulumi", tags["ManagedBy"].StringValue())
		assert.Equal(t, RouterSubnetType, tags["Type"].StringValue(), "not the public type: a public-subnet lookup does not find it")
		assert.Equal(t, "acme", tags["Tailnet"].StringValue())

		rta, ok := m.res["aws:ec2/routeTableAssociation:RouteTableAssociation/tailscale-subnet-route-"+zone]
		require.True(t, ok, "the %s subnet is associated", zone)
		assert.Equal(t, "rtb-public", rta["routeTableId"].StringValue(), "the public subnets' route table")
		assert.Equal(t, "tailscale-subnet-"+zone+"-id", rta["subnetId"].StringValue())
	}

	// The group runs in the fleet's subnets alone, in zone order, and a
	// change of them refreshes the routers.
	asg := m.res["aws:autoscaling/group:Group/tailscale-asg"]
	var got []string
	for _, v := range asg["vpcZoneIdentifiers"].ArrayValue() {
		got = append(got, v.StringValue())
	}

	assert.Equal(t, []string{"tailscale-subnet-eu-west-1a-id", "tailscale-subnet-eu-west-1b-id"}, got)

	triggers := asg["instanceRefresh"].ObjectValue()["triggers"].ArrayValue()
	require.Len(t, triggers, 1)
	assert.Equal(t, "vpc_zone_identifier", triggers[0].StringValue())
}

func TestFleetSubnetsCarryTheResourcePrefix(t *testing.T) {
	a := exampleFleet()
	a.Tailnet = "other"
	a.ResourcePrefix = "other-"
	a.Subnets = ownSubnets()

	m, err := runFleet(t, a)
	require.NoError(t, err)

	_, ok := m.res["aws:ec2/subnet:Subnet/other-tailscale-subnet-eu-west-1a"]
	assert.True(t, ok)
	_, ok = m.res["aws:ec2/routeTableAssociation:RouteTableAssociation/other-tailscale-subnet-route-eu-west-1b"]
	assert.True(t, ok)
	assert.Equal(t, "example-tailscale-other-eu-west-1a",
		m.res["aws:ec2/subnet:Subnet/other-tailscale-subnet-eu-west-1a"]["tags"].ObjectValue()["Name"].StringValue())
}

func TestFleetSubnetsRefuseTwoPublicRouteTables(t *testing.T) {
	a := exampleFleet()
	a.Subnets = ownSubnets()

	_, err := runFleetWith(t, a, map[string]string{"subnet-b": "rtb-other"})
	require.ErrorContains(t, err, "more than one route table")
}

func TestFleetSubnetsAreValidated(t *testing.T) {
	for name, subnets := range map[string][]FleetSubnet{
		"not a cidr":          {{AvailabilityZone: "eu-west-1a", CIDR: "banana"}},
		"no zone":             {{CIDR: "10.0.3.0/28"}},
		"a zone twice":        {{AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.0/28"}, {AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.16/28"}},
		"outside the VPC":     {{AvailabilityZone: "eu-west-1a", CIDR: "10.1.3.0/28"}},
		"larger than the VPC": {{AvailabilityZone: "eu-west-1a", CIDR: "10.0.0.0/8"}},
		"smaller than a /28":  {{AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.0/29"}},
		"host bits set":       {{AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.5/28"}},
		"IPv6":                {{AvailabilityZone: "eu-west-1a", CIDR: "2001:db8::/64"}},
		"overlapping":         {{AvailabilityZone: "eu-west-1a", CIDR: "10.0.3.0/27"}, {AvailabilityZone: "eu-west-1b", CIDR: "10.0.3.16/28"}},
	} {
		t.Run(name, func(t *testing.T) {
			a := exampleFleet()
			a.Subnets = subnets
			require.Error(t, a.ValidateSubnets())

			_, err := runFleet(t, a)
			require.Error(t, err)
		})
	}

	a := exampleFleet()
	a.Subnets = ownSubnets()
	require.NoError(t, a.ValidateSubnets())
}
