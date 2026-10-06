package mesh

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/tailscale/pkg/acl"
)

// Neutral fixtures: two networks, one with a hub role, three clusters.
func exampleInputs() Inputs {
	return Inputs{
		Tailnet: Tailnet{Name: "acme", Domain: "acme.example", Primary: true, Networks: []string{"hub", "dev", "lab"}},
		Networks: []Network{
			{Name: "hub", Router: true, Tag: "hub-router", VPCCIDR: "10.64.0.0/16", DNSIP: "10.64.0.2", PrivateDomain: "hub.example.internal"},
			{Name: "dev", Router: true, Tag: "dev-router", VPCCIDR: "10.65.0.0/16", DNSIP: "10.65.0.2", PrivateDomain: "dev.example.internal"},
			{Name: "lab", Router: true, Tag: "lab-router", VPCCIDR: "10.66.0.0/16", DNSIP: "10.66.0.2", PrivateDomain: "lab.example.internal"},
			{Name: "bare", Router: false},
		},
		Clusters: []Cluster{
			{Name: "hub", Network: "hub", Router: true, ServiceCIDR: "172.20.0.0/16", EKS: true,
				VPCGroups: []string{"ops@acme.example", "ops@partner.example"}, InClusterGroups: []string{"ops@acme.example"}},
			{Name: "dev", Network: "dev", Router: true, ServiceCIDR: "172.21.0.0/16", EKS: true,
				EndpointZone: "ABCDEF.gr7.eu-example-1.eks.example.test", VPCGroups: []string{"dev@acme.example"}},
			{Name: "lab", Network: "lab", Router: true, ServiceCIDR: "10.160.0.0/12", DNSDomain: "cluster.lab"},
			{Name: "norole", Network: "dev", Router: false, ServiceCIDR: "10.170.0.0/12", DNSDomain: "cluster.norole"},
		},
		Hub:               "hub",
		BaseDomain:        "example.internal",
		ExtraSplitDNS:     []ExtraSplitDNS{{Domain: "ephemeral.example.internal", Network: "dev"}},
		ClusterLocalOwner: "dev",
		Policy:            acl.Policy{ManagerTag: "manager"},
		AuthKeyPath:       "/ts/acme/auth-key",
		K8sKeyPath:        func(c string) string { return "/ts/acme/k8s-" + c },
		K8sKeyInSSM:       func(c Cluster) bool { return c.Name == "hub" },
		Now:               func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) },
	}
}

func TestValidate(t *testing.T) {
	in := exampleInputs()
	require.NoError(t, in.Validate())

	// The hub joins the primary tailnet alone.
	in.Tailnet.Primary = false
	require.ErrorContains(t, in.Validate(), "primary-tailnet-only")
	in.Tailnet.Networks = []string{"dev"}
	require.NoError(t, in.Validate())

	in.Tailnet.Networks = []string{"nowhere"}
	require.ErrorContains(t, in.Validate(), "not declared")

	in.Tailnet.Networks = []string{"bare"}
	require.ErrorContains(t, in.Validate(), "has no router")
}

func TestFilterGroupsKeepsOnlyTheTailnetsOwnDomain(t *testing.T) {
	tn := Tailnet{Domain: "acme.example"}

	assert.Equal(t, []string{"a@acme.example"}, tn.FilterGroups([]string{"a@acme.example", "b@partner.example", "c@evilacme.example"}))
	assert.False(t, tn.ResolvesGroup("a@sub.acme.example"))
	assert.Empty(t, tn.FilterGroups(nil))
}

func TestPolicyModelListsMemberNetworksAndEveryCluster(t *testing.T) {
	in := exampleInputs()
	in.Tailnet.Networks = []string{"dev"} // lab and hub are not members

	p, err := in.PolicyModel()
	require.NoError(t, err)

	assert.Equal(t, "manager", p.ManagerTag)
	assert.Equal(t, []acl.Network{{Name: "dev", VPCCIDR: "10.65.0.0/16", RouterTag: "dev-router"}}, p.Networks)

	got := map[string]acl.Cluster{}
	for _, c := range p.Clusters {
		got[c.Name] = c
	}

	require.Len(t, got, 4)
	assert.True(t, got["dev"].Member)
	assert.False(t, got["hub"].Member, "the cluster's network is not a member")
	assert.False(t, got["norole"].Member, "no router role")
	// Non-member clusters keep their (filtered) groups: they still reach the network.
	assert.Equal(t, []string{"ops@acme.example"}, got["hub"].VPCGroups)
	assert.Equal(t, []string{"dev@acme.example"}, got["dev"].VPCGroups)

	doc, err := acl.Build(p)
	require.NoError(t, err)
	assert.Contains(t, doc, "tag:dev-router")
	assert.NotContains(t, doc, "tag:lab-router")
}

func TestPolicyModelKeepsTheCallersOwnExtras(t *testing.T) {
	in := exampleInputs()
	in.Policy.ExtraTagOwners = map[string][]string{"extra": {"autogroup:admin"}}
	in.Policy.ExtraMemberGrants = []acl.MemberGrant{{DstTag: "extra", Ports: []string{"80"}}}

	p, err := in.PolicyModel()
	require.NoError(t, err)
	assert.Equal(t, in.Policy.ExtraTagOwners, p.ExtraTagOwners)
	assert.Equal(t, in.Policy.ExtraMemberGrants, p.ExtraMemberGrants)
}

func TestSplitDNSEntries(t *testing.T) {
	in := exampleInputs()

	got, err := in.SplitDNSEntries()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"example.internal":           "10.64.0.2", // the base domain, through the hub
		"hub.example.internal":       "10.64.0.2",
		"dev.example.internal":       "10.65.0.2",
		"lab.example.internal":       "10.66.0.2",
		"ephemeral.example.internal": "10.65.0.2",
	}, got)

	// A tailnet the hub does not join gets no base-domain entry; "lab" is
	// not a member either, so it adds nothing.
	in.Tailnet.Networks = []string{"dev"}
	got, err = in.SplitDNSEntries()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"dev.example.internal":       "10.65.0.2",
		"ephemeral.example.internal": "10.65.0.2",
	}, got)

	// The extra domain follows its network's membership.
	in.Tailnet.Networks = []string{"lab"}
	got, err = in.SplitDNSEntries()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"lab.example.internal": "10.66.0.2"}, got)
}

func TestSplitDNSEntriesRefusesAHubWithoutARouter(t *testing.T) {
	in := exampleInputs()
	in.Networks[0].Router = false

	_, err := in.SplitDNSEntries()
	require.ErrorContains(t, err, "must have a router")
}

func TestK8sSplitDNS(t *testing.T) {
	in := exampleInputs()
	byName := map[string]Cluster{}

	for _, c := range in.Clusters {
		byName[c.Name] = c
	}

	// The cluster.local owner: its own resolver, plus the endpoint zone
	// (lowercased) through the network's VPC resolver.
	got, err := in.K8sSplitDNS(byName["dev"])
	require.NoError(t, err)
	assert.Equal(t, []SplitDNSEntry{
		{Resource: "k8s-dns-dev-local", Domain: "cluster.local", Nameserver: "172.21.0.10"},
		{Resource: "k8s-dns-dev-endpoint", Domain: "abcdef.gr7.eu-example-1.eks.example.test", Nameserver: "10.65.0.2"},
	}, got)

	// A managed cluster that does not own cluster.local and has no
	// endpoint yet advertises nothing.
	got, err = in.K8sSplitDNS(byName["hub"])
	require.NoError(t, err)
	assert.Empty(t, got)

	// A self-hosted cluster keeps its own domain at the .10.
	got, err = in.K8sSplitDNS(byName["lab"])
	require.NoError(t, err)
	assert.Equal(t, []SplitDNSEntry{{Resource: "k8s-dns-lab", Domain: "cluster.lab", Nameserver: "10.160.0.10"}}, got)

	// No service CIDR, or a self-hosted cluster with no domain: skipped.
	assert.Empty(t, mustEntries(t, in, Cluster{Name: "x", EKS: true}))
	assert.Empty(t, mustEntries(t, in, Cluster{Name: "x", ServiceCIDR: "10.0.0.0/16"}))

	// An endpoint on an undeclared network is refused.
	_, err = in.K8sSplitDNS(Cluster{Name: "y", EKS: true, ServiceCIDR: "10.0.0.0/16", Network: "nowhere", EndpointZone: "z.example.test"})
	require.ErrorContains(t, err, "does not exist")
}

func mustEntries(t *testing.T, in Inputs, c Cluster) []SplitDNSEntry {
	t.Helper()

	got, err := in.K8sSplitDNS(c)
	require.NoError(t, err)

	return got
}

func TestClusterInTailnet(t *testing.T) {
	in := exampleInputs()
	in.Tailnet.Networks = []string{"dev"}

	assert.True(t, in.ClusterInTailnet("dev"))
	assert.False(t, in.ClusterInTailnet("hub"), "not a member network")
	assert.False(t, in.ClusterInTailnet("norole"), "no router role")
	assert.False(t, in.ClusterInTailnet("missing"))
}

func TestDeployRegistersTheNamedResources(t *testing.T) {
	in := exampleInputs()
	in.FlowLogs = FlowLogConfig{Enabled: true, Bucket: "example-logs", RoleArn: "arn:aws:iam::example:role/flow"}
	in.Region = "eu-example-1"

	var sunk []string

	in.K8sKeySink = func(_ *pulumi.Context, c Cluster, _ pulumi.StringOutput) error {
		sunk = append(sunk, c.Name)

		return nil
	}
	in.OAuth = func(*pulumi.Context) (string, string, error) { return "client-id", "client-secret", nil }

	m := runDeploy(t, in)

	assert.Equal(t, []string{"tailscale"}, m.names("pulumi:providers:tailscale"))
	assert.Equal(t, []string{"acl"}, m.names("tailscale:index/acl:Acl"))

	// Keys are named by month: replace-on-rename is the rotation.
	assert.Equal(t, []string{
		"auth-key-dev-2026-10", "auth-key-hub-2026-10", "auth-key-lab-2026-10",
		"k8s-auth-key-dev-2026-10", "k8s-auth-key-hub-2026-10", "k8s-auth-key-lab-2026-10",
	}, m.names("tailscale:index/tailnetKey:TailnetKey"))

	assert.Equal(t,
		[]string{"k8s-tailscale-auth-key-hub", "tailscale-auth-key-dev", "tailscale-auth-key-hub", "tailscale-auth-key-lab"},
		m.names("aws:ssm/parameter:Parameter"))
	assert.Equal(t, "/ts/acme/auth-key", m.input("aws:ssm/parameter:Parameter", "tailscale-auth-key-dev", "name"))
	assert.Equal(t, "/ts/acme/k8s-hub", m.input("aws:ssm/parameter:Parameter", "k8s-tailscale-auth-key-hub", "name"))
	assert.Equal(t, []string{"dev", "hub", "lab"}, sunk, "every member cluster's key reaches the sink; the role-less one has none")

	assert.Equal(t, []string{
		"dns-dev.example.internal", "dns-ephemeral.example.internal", "dns-example.internal", "dns-hub.example.internal",
		"dns-lab.example.internal", "k8s-dns-dev-endpoint", "k8s-dns-dev-local", "k8s-dns-lab",
	}, m.names("tailscale:index/dnsSplitNameservers:DnsSplitNameservers"))

	assert.Equal(t, []string{"flow-logs"}, m.names("tailscale:index/logstreamConfiguration:LogstreamConfiguration"))
}

func TestDeployWithoutFlowLogsOrOnACompanyTailnet(t *testing.T) {
	in := exampleInputs()
	in.OAuth = func(*pulumi.Context) (string, string, error) { return "id", "secret", nil }

	m := runDeploy(t, in)
	assert.Empty(t, m.names("tailscale:index/logstreamConfiguration:LogstreamConfiguration"), "disabled")

	in = exampleInputs()
	in.Tailnet.Primary = false
	in.Tailnet.Networks = []string{"dev"}
	in.FlowLogs = FlowLogConfig{Enabled: true, Bucket: "b", RoleArn: "r"}
	in.OAuth = func(*pulumi.Context) (string, string, error) { return "id", "secret", nil }

	m = runDeploy(t, in)
	assert.Empty(t, m.names("tailscale:index/logstreamConfiguration:LogstreamConfiguration"), "a company tailnet decides for itself")
	assert.Equal(t, []string{"auth-key-dev-2026-10", "k8s-auth-key-dev-2026-10"}, m.names("tailscale:index/tailnetKey:TailnetKey"))
}

func runDeploy(t *testing.T, in Inputs) *mocks {
	t.Helper()

	m := &mocks{}
	in.Logger = slog.New(slog.DiscardHandler)
	in.AWSProvider = func(ctx *pulumi.Context, network string) (*aws.Provider, error) {
		return aws.NewProvider(ctx, "aws-"+network, &aws.ProviderArgs{Region: pulumi.String("eu-example-1")})
	}

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error { return Deploy(ctx, in) },
		pulumi.WithMocks("example", "tailscale", m)))

	return m
}

type (
	recorded struct {
		typ, name string
		inputs    resource.PropertyMap
	}

	mocks struct {
		mu        sync.Mutex
		resources []recorded
	}
)

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.resources = append(m.resources, recorded{args.TypeToken, args.Name, args.Inputs})

	state := args.Inputs.Copy()
	if args.TypeToken == "tailscale:index/tailnetKey:TailnetKey" {
		state["key"] = resource.NewStringProperty("tskey-" + args.Name)
	}

	return fmt.Sprintf("%s-id", args.Name), state, nil
}

func (m *mocks) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func (m *mocks) names(typ string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string

	for _, r := range m.resources {
		if r.typ == typ {
			out = append(out, r.name)
		}
	}

	slices.Sort(out)

	return out
}

func (m *mocks) input(typ, name, key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.resources {
		if r.typ == typ && r.name == name {
			return r.inputs[resource.PropertyKey(key)].StringValue()
		}
	}

	return ""
}
