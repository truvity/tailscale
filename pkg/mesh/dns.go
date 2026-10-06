package mesh

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/pulumi/pulumi-tailscale/sdk/go/tailscale"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/tailscale/pkg/tailnet"
)

// SplitDNSEntry is one tailnet split-DNS mapping.
type SplitDNSEntry struct {
	// Resource is the Pulumi name of the mapping.
	Resource   string
	Domain     string
	Nameserver string
}

// SplitDNSEntries derives a tailnet's split DNS domains and resolver IPs.
// Per network: each member network's own domain resolves through its own VPC
// resolver, reached through the local router. The base domain resolves
// through the hub's resolver, for tailnets the hub joins only: a resolver you
// cannot route to is worse than public DNS. Extra domains resolve through
// their network's resolver when that network is a router-bearing member.
func (in Inputs) SplitDNSEntries() (map[string]string, error) {
	entries := make(map[string]string)
	nets := in.networkByName()

	if in.Hub != "" && in.hasNetwork(in.Hub) {
		hub, ok := nets[in.Hub]
		if !ok {
			return nil, fmt.Errorf("hub physical network %q not found", in.Hub)
		}

		if !hub.Router {
			return nil, fmt.Errorf("hub physical network %q must have a router for split DNS", in.Hub)
		}

		entries[in.BaseDomain] = hub.DNSIP
	}

	for _, n := range in.sortedNetworks() {
		if !n.Router || !in.hasNetwork(n.Name) {
			continue
		}

		entries[n.PrivateDomain] = n.DNSIP
	}

	for _, e := range in.ExtraSplitDNS {
		if n, ok := nets[e.Network]; ok && n.Router && in.hasNetwork(e.Network) {
			entries[e.Domain] = n.DNSIP
		}
	}

	return entries, nil
}

func (in Inputs) deploySplitDNS(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider) error {
	entries, err := in.SplitDNSEntries()
	if err != nil {
		return fmt.Errorf("build split dns entries: %w", err)
	}

	domains := make([]string, 0, len(entries))
	for d := range entries {
		domains = append(domains, d)
	}

	sort.Strings(domains)

	for _, domain := range domains {
		if err := tailnet.NewSplitDNS(ctx, fmt.Sprintf("dns-%s", domain), domain, entries[domain], pulumi.Provider(provider)); err != nil {
			return err
		}
	}

	logger.InfoContext(ctx.Context(), "tailscale split dns deployed",
		slog.String("tailnet", in.Tailnet.Name),
		slog.Int("entries", len(entries)),
	)

	return nil
}

// K8sSplitDNS decides the tailnet DNS mappings for one cluster.
//
// A managed (EKS) cluster gets up to two entries and neither goes through a
// gateway of its own:
//
//   - cluster.local -> the cluster's own resolver at the service CIDR's .10,
//     on the ClusterLocalOwner alone. cluster.local is the same name on every
//     cluster, so the tailnet can point it at exactly one.
//   - the private-endpoint zone -> the network's VPC resolver, so kubectl over
//     the tailnet keeps working (public DNS will not resolve a private
//     endpoint). Lowercased: DNS is case-insensitive and both Tailscale and
//     CoreDNS reject an uppercase hex label.
//
// A self-hosted cluster keeps its own DNS domain, served by its in-cluster
// resolver at the service CIDR's .10.
func (in Inputs) K8sSplitDNS(c Cluster) ([]SplitDNSEntry, error) {
	if c.ServiceCIDR == "" {
		return nil, nil
	}

	if c.EKS {
		var entries []SplitDNSEntry

		if c.Name == in.ClusterLocalOwner {
			resolverIP, err := tailnet.ServiceIP(c.ServiceCIDR, coreDNSOffset)
			if err != nil {
				return nil, err
			}

			entries = append(entries, SplitDNSEntry{
				Resource:   "k8s-dns-" + c.Name + "-local",
				Domain:     ClusterLocalDomain,
				Nameserver: resolverIP,
			})
		}

		if c.EndpointZone != "" {
			n, ok := in.networkByName()[c.Network]
			if !ok {
				return nil, fmt.Errorf("cluster %q names physical network %q, which does not exist", c.Name, c.Network)
			}

			entries = append(entries, SplitDNSEntry{
				Resource:   "k8s-dns-" + c.Name + "-endpoint",
				Domain:     strings.ToLower(c.EndpointZone),
				Nameserver: n.DNSIP,
			})
		}

		return entries, nil
	}

	if c.DNSDomain == "" {
		return nil, nil
	}

	resolverIP, err := tailnet.ServiceIP(c.ServiceCIDR, coreDNSOffset)
	if err != nil {
		return nil, err
	}

	return []SplitDNSEntry{{Resource: "k8s-dns-" + c.Name, Domain: c.DNSDomain, Nameserver: resolverIP}}, nil
}

func (in Inputs) deployK8sSplitDNS(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider) error {
	count := 0

	for _, c := range in.sortedClusters() {
		if !in.clusterInTailnet(c) {
			continue
		}

		entries, err := in.K8sSplitDNS(c)
		if err != nil {
			return fmt.Errorf("derive split dns for %s: %w", c.Name, err)
		}

		for _, e := range entries {
			if _, err := tailscale.NewDnsSplitNameservers(ctx, e.Resource, &tailscale.DnsSplitNameserversArgs{
				Domain:      pulumi.String(e.Domain),
				Nameservers: pulumi.ToStringArray([]string{e.Nameserver}),
			}, pulumi.Provider(provider)); err != nil {
				return fmt.Errorf("create k8s split dns %s: %w", e.Resource, err)
			}

			count++
		}
	}

	if count > 0 {
		logger.InfoContext(ctx.Context(), "k8s router split dns deployed", slog.Int("entries", count))
	}

	return nil
}
