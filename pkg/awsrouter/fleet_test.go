package awsrouter

import (
	"log/slog"
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
// and records every filter set it was asked for.
type fleetMocks struct {
	providerGuardMocks
	mu2     sync.Mutex
	filters map[string][]resource.PropertyValue
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
	}

	return m.providerGuardMocks.Call(args)
}

func runFleet(t *testing.T, a FleetArgs) (*fleetMocks, error) {
	t.Helper()

	m := &fleetMocks{providerGuardMocks: providerGuardMocks{res: map[string]resource.PropertyMap{}}}
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
