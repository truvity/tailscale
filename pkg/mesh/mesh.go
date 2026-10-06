// Package mesh is the stack of one tailnet: its ACL policy, its router auth
// keys, its split DNS, and (on the account's primary tailnet, plan
// permitting) its flow logs, from one plain Inputs value.
//
// Where pkg/acl derives a policy document from a model and pkg/tailnet wraps
// the individual provider resources, this package is what stands between an
// estate's facts and those: the rules for which networks and clusters belong
// to a tailnet, which groups a tailnet can resolve, which names its split DNS
// serves and where every key goes.
//
// Mechanism only. Nothing here names a tailnet, a domain, a tag or a path:
// Inputs carries them all, and every place a secret lands (SSM in a network's
// account, a cluster's secret store) is the caller's, through the sinks and
// providers in Inputs. An estate adopting this over a stack it already has
// keeps every resource name: the names below are the contract.
package mesh

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssm"
	"github.com/pulumi/pulumi-tailscale/sdk/go/tailscale"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/tailscale/pkg/acl"
	"github.com/truvity/tailscale/pkg/tailnet"
)

const (
	// ClusterLocalDomain is the in-cluster DNS suffix every Kubernetes
	// cluster uses. The tailnet routes it to exactly one of them.
	ClusterLocalDomain = "cluster.local"

	// coreDNSOffset is the Kubernetes convention for the cluster DNS
	// ClusterIP: the 10th address of the service CIDR.
	coreDNSOffset = 10
)

type (
	// Tailnet is one tailnet's identity and membership.
	Tailnet struct {
		// Name keys the tailnet's resources and secrets.
		Name string
		// Domain is the directory domain whose groups the tailnet can
		// resolve: only its own domain's groups exist in the tailnet, so a
		// rule naming any other would reference a group it never learns.
		Domain string
		// Primary marks the account's primary tailnet: the only one that
		// carries flow logs, and the only one the hub network may join.
		Primary bool
		// Networks are the physical networks (Network.Name) whose routers
		// join this tailnet.
		Networks []string
	}

	// Network is one physical network.
	Network struct {
		Name string
		// Router is true when the network has a subnet router.
		Router bool
		// Tag is the router's tag, without the "tag:" prefix.
		Tag string
		// VPCCIDR is the network's address space.
		VPCCIDR string
		// DNSIP is the network's VPC resolver.
		DNSIP string
		// PrivateDomain is the domain the network's own resolver answers;
		// each member network's split DNS entry maps it to DNSIP.
		PrivateDomain string
	}

	// Cluster is one Kubernetes cluster.
	Cluster struct {
		Name    string
		Network string
		// Router is true when the cluster carries the role that runs a
		// tailnet router; only those clusters belong to a tailnet's
		// rendered world.
		Router      bool
		ServiceCIDR string
		// EKS selects the managed-cluster DNS shape (see K8sSplitDNS).
		EKS bool
		// DNSDomain is a self-hosted cluster's own DNS domain.
		DNSDomain string
		// EndpointZone is an EKS cluster's private endpoint zone, once the
		// cluster exists; empty before.
		EndpointZone string
		// VPCGroups and InClusterGroups are the directory groups with
		// network-tier and Service-CIDR-tier access to this cluster,
		// unfiltered: Policy keeps the ones the tailnet resolves.
		VPCGroups       []string
		InClusterGroups []string
	}

	// ExtraSplitDNS is one more split DNS domain, served by a member
	// network's resolver.
	ExtraSplitDNS struct {
		Domain  string
		Network string
	}

	// Inputs is everything Deploy needs, already resolved.
	Inputs struct {
		Tailnet  Tailnet
		Networks []Network
		Clusters []Cluster

		// Hub is the network that hosts the base domain's resolver and
		// that only the primary tailnet may join. Empty: none.
		Hub string
		// BaseDomain is resolved through the hub's resolver, for tailnets
		// the hub joins.
		BaseDomain string
		// ExtraSplitDNS are further domains, each served by a network.
		ExtraSplitDNS []ExtraSplitDNS
		// ClusterLocalOwner is the one cluster whose own resolver answers
		// ClusterLocalDomain. The tailnet holds one nameserver per domain,
		// so only one cluster can claim it. Empty: none.
		ClusterLocalOwner string

		// Policy carries the estate's own part of the ACL: the manager tag,
		// the extra tag owners and the extra grants. Networks and Clusters
		// are filled in from the fields above.
		Policy acl.Policy

		// AuthKeyPath is where each member network's router auth key lands,
		// in that network's account. K8sKeyPath is the same for a cluster's
		// router key, written when K8sKeyInSSM says so.
		AuthKeyPath string
		K8sKeyPath  func(cluster string) string
		K8sKeyInSSM func(Cluster) bool
		// K8sKeySink is told every cluster router key (for the stores that
		// are not SSM). Optional.
		K8sKeySink func(ctx *pulumi.Context, c Cluster, key pulumi.StringOutput) error

		// OAuth returns the tailnet's OAuth client credentials. They
		// configure a provider, so they are plain values, read before the
		// program registers anything that depends on them.
		OAuth func(ctx *pulumi.Context) (clientID, clientSecret string, err error)
		// AWSProvider returns the provider for the account a network (by
		// Network.Name) lives in.
		AWSProvider func(ctx *pulumi.Context, network string) (*aws.Provider, error)

		// FlowLogs is the flow-log configuration (primary tailnet only),
		// and Region the S3 bucket's region.
		FlowLogs FlowLogConfig
		Region   string

		// Now names the rotation month of the keys; default time.Now.
		Now func() time.Time

		Logger *slog.Logger
	}
)

// Validate cross-checks the tailnet's membership against the networks, and
// enforces the placement rule: the hub is primary-tailnet-only. Refusal by
// absence of a path, not by an ACL rule.
func (in Inputs) Validate() error {
	nets := in.networkByName()

	for _, name := range in.Tailnet.Networks {
		n, ok := nets[name]
		if !ok {
			return fmt.Errorf("tailnet %s: network %q is not declared", in.Tailnet.Name, name)
		}

		if !n.Router {
			return fmt.Errorf("tailnet %s: network %q has no router", in.Tailnet.Name, name)
		}
	}

	if in.Hub != "" && !in.Tailnet.Primary && in.hasNetwork(in.Hub) {
		return fmt.Errorf("tailnet %s: the hub network %q is primary-tailnet-only", in.Tailnet.Name, in.Hub)
	}

	return nil
}

// Deploy registers the tailnet's stack: provider, ACL, auth keys, k8s router
// keys, split DNS, k8s split DNS and, on the primary tailnet, flow logs.
func Deploy(ctx *pulumi.Context, in Inputs) error {
	logger := in.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	if err := in.Validate(); err != nil {
		return err
	}

	provider, err := in.provider(ctx, logger)
	if err != nil {
		return fmt.Errorf("setup tailscale provider: %w", err)
	}

	policy, err := in.PolicyModel()
	if err != nil {
		return fmt.Errorf("build acl policy: %w", err)
	}

	doc, err := acl.Build(policy)
	if err != nil {
		return fmt.Errorf("build acl policy: %w", err)
	}

	// Sole-owner semantics are the library's NewACL contract.
	policyRes, err := tailnet.NewACL(ctx, "acl", doc, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("deploy acl: %w", err)
	}

	logger.InfoContext(ctx.Context(), "tailscale acl policy deployed", slog.String("tailnet", in.Tailnet.Name))

	if err := in.deployAuthKeys(ctx, logger, provider, policyRes); err != nil {
		return fmt.Errorf("deploy auth keys: %w", err)
	}

	if err := in.deployK8sRouterKeys(ctx, logger, provider, policyRes); err != nil {
		return fmt.Errorf("deploy k8s router keys: %w", err)
	}

	if err := in.deploySplitDNS(ctx, logger, provider); err != nil {
		return fmt.Errorf("deploy split dns: %w", err)
	}

	if err := in.deployK8sSplitDNS(ctx, logger, provider); err != nil {
		return fmt.Errorf("deploy k8s router split dns: %w", err)
	}

	// Flow logs are a plan feature of the primary account only; a company
	// tailnet decides (and pays for) its own.
	if in.Tailnet.Primary {
		if err := in.deployFlowLogs(ctx, logger, provider); err != nil {
			return fmt.Errorf("deploy flow logs: %w", err)
		}
	}

	routers := 0

	for _, n := range in.Networks {
		if n.Router && in.hasNetwork(n.Name) {
			routers++
		}
	}

	logger.InfoContext(ctx.Context(), "tailnet deployed",
		slog.String("tailnet", in.Tailnet.Name),
		slog.String("domain", in.Tailnet.Domain),
		slog.Int("router_environments", routers),
		slog.Bool("flow_logs", in.Tailnet.Primary && in.FlowLogs.Enabled),
	)

	return nil
}

// provider creates the tailnet's Tailscale provider from its OAuth client.
func (in Inputs) provider(ctx *pulumi.Context, logger *slog.Logger) (*tailscale.Provider, error) {
	clientID, clientSecret, err := in.OAuth(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := tailscale.NewProvider(ctx, "tailscale", &tailscale.ProviderArgs{
		OauthClientId:     pulumi.String(clientID),
		OauthClientSecret: pulumi.ToSecret(pulumi.String(clientSecret)).(pulumi.StringOutput),
	})
	if err != nil {
		return nil, fmt.Errorf("create tailscale provider: %w", err)
	}

	logger.InfoContext(ctx.Context(), "tailscale provider created from the resolved oauth credentials",
		slog.String("tailnet", in.Tailnet.Name),
	)

	return provider, nil
}

// deployAuthKeys creates a tailnet's per-network router keys (member networks
// only) and writes each to its network's account as an SSM SecureString.
// Keys are created after the ACL (the tags must exist first). A key expires
// after tailnet.DefaultKeyExpiry: the stack must apply at least once per
// window or new enrollments stall, the price of bounding a leaked key's
// blast radius.
func (in Inputs) deployAuthKeys(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider, policy *tailscale.Acl) error {
	for _, n := range in.sortedNetworks() {
		if !n.Router || !in.hasNetwork(n.Name) {
			continue
		}

		tag := "tag:" + n.Tag

		key, err := tailnet.NewRouterKey(ctx, "auth-key-"+n.Name+"-"+in.rotation(),
			tailnet.RouterKeyArgs{Tag: tag},
			pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{policy}))
		if err != nil {
			return fmt.Errorf("create auth key for %s: %w", n.Name, err)
		}

		awsProvider, err := in.AWSProvider(ctx, n.Name)
		if err != nil {
			return fmt.Errorf("get AWS provider for %s: %w", n.Name, err)
		}

		if _, err := ssm.NewParameter(ctx, "tailscale-auth-key-"+n.Name, &ssm.ParameterArgs{
			Name:      pulumi.String(in.AuthKeyPath),
			Type:      pulumi.String("SecureString"),
			Value:     key.Key,
			Overwrite: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider)); err != nil {
			return fmt.Errorf("create ssm parameter for %s: %w", n.Name, err)
		}

		logger.InfoContext(ctx.Context(), "auth key created and written to ssm",
			slog.String("tailnet", in.Tailnet.Name),
			slog.String("environment", n.Name),
			slog.String("tag", tag),
			slog.String("path", in.AuthKeyPath),
		)
	}

	return nil
}

// deployK8sRouterKeys creates a tailnet's per-cluster router keys (member
// clusters only) and hands each to where its cluster reads it: SSM in the
// cluster's network account when K8sKeyInSSM says so, and the K8sKeySink for
// every other store.
func (in Inputs) deployK8sRouterKeys(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider, policy *tailscale.Acl) error {
	for _, c := range in.sortedClusters() {
		if !in.clusterInTailnet(c) {
			continue
		}

		tag := "tag:" + routerTag(c)

		key, err := tailnet.NewRouterKey(ctx, "k8s-auth-key-"+c.Name+"-"+in.rotation(),
			tailnet.RouterKeyArgs{Tag: tag},
			pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{policy}))
		if err != nil {
			return fmt.Errorf("create k8s auth key for %s: %w", c.Name, err)
		}

		if in.K8sKeyInSSM != nil && in.K8sKeyInSSM(*c) {
			awsProvider, err := in.AWSProvider(ctx, c.Network)
			if err != nil {
				return fmt.Errorf("get AWS provider for k8s router %s: %w", c.Name, err)
			}

			if _, err := ssm.NewParameter(ctx, "k8s-tailscale-auth-key-"+c.Name, &ssm.ParameterArgs{
				Name:      pulumi.String(in.K8sKeyPath(c.Name)),
				Type:      pulumi.String("SecureString"),
				Value:     key.Key,
				Overwrite: pulumi.Bool(true),
			}, pulumi.Provider(awsProvider)); err != nil {
				return fmt.Errorf("create ssm parameter for k8s router %s: %w", c.Name, err)
			}
		}

		if in.K8sKeySink != nil {
			if err := in.K8sKeySink(ctx, *c, key.Key); err != nil {
				return err
			}
		}

		logger.InfoContext(ctx.Context(), "k8s router auth key created",
			slog.String("tailnet", in.Tailnet.Name),
			slog.String("cluster", c.Name),
			slog.String("tag", tag),
		)
	}

	return nil
}

func routerTag(c *Cluster) string { return "k8s-" + c.Name + "-router" }

func (in Inputs) rotation() string {
	now := in.Now
	if now == nil {
		now = time.Now
	}

	return tailnet.RotationSuffix(now())
}

func (in Inputs) networkByName() map[string]Network {
	out := make(map[string]Network, len(in.Networks))
	for _, n := range in.Networks {
		out[n.Name] = n
	}

	return out
}

func (in Inputs) hasNetwork(name string) bool {
	for _, n := range in.Tailnet.Networks {
		if n == name {
			return true
		}
	}

	return false
}

func (in Inputs) sortedNetworks() []Network {
	out := append([]Network(nil), in.Networks...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

func (in Inputs) sortedClusters() []*Cluster {
	out := make([]*Cluster, len(in.Clusters))
	for i := range in.Clusters {
		out[i] = &in.Clusters[i]
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// clusterInTailnet reports whether a cluster belongs to the tailnet's
// rendered world: it must carry the router role AND live on one of the
// tailnet's member networks.
func (in Inputs) clusterInTailnet(c *Cluster) bool {
	return c.Router && in.hasNetwork(c.Network)
}

// ClusterInTailnet is clusterInTailnet for callers that derive their own
// extras (for instance a grant that must exist only where a given cluster's
// network is a member).
func (in Inputs) ClusterInTailnet(name string) bool {
	for i := range in.Clusters {
		if in.Clusters[i].Name == name {
			return in.clusterInTailnet(&in.Clusters[i])
		}
	}

	return false
}

// HasNetwork reports membership in a physical network: the coarse grant.
// Absent a network, no routers, no rules, no reachability.
func (t Tailnet) HasNetwork(name string) bool {
	for _, n := range t.Networks {
		if n == name {
			return true
		}
	}

	return false
}

// ResolvesGroup reports whether this tailnet's directory sync can resolve the
// given group email: only its own domain's groups exist in the tailnet.
func (t Tailnet) ResolvesGroup(group string) bool {
	return strings.HasSuffix(group, "@"+t.Domain)
}

// FilterGroups keeps the groups this tailnet resolves. A partner-directory
// group belongs on the partner tailnet's own rendered policy, never on this
// one: this tailnet's sync would simply never learn it.
func (t Tailnet) FilterGroups(groups []string) []string {
	out := make([]string, 0, len(groups))

	for _, g := range groups {
		if t.ResolvesGroup(g) {
			out = append(out, g)
		}
	}

	return out
}
