package mesh

import (
	"github.com/truvity/tailscale/pkg/acl"
)

// PolicyModel is the DERIVATION half of the ACL split: the networks and
// clusters of the tailnet's rendered world and the groups it resolves, folded
// into pkg/acl's neutral model on top of the caller's own Policy (manager
// tag, extra owners, extra grants). The ASSEMBLY, which rules a policy
// contains and in what order, is pkg/acl's.
//
// Only member networks with a router are listed. Every cluster is listed,
// members and not: a non-member cluster gets no rules, tags or approvals of
// its own, but its groups still count toward its network's reachability,
// because those people reach the shared network through the network's router
// wherever the cluster's own router lives. Groups are filtered to the
// tailnet's directory domain.
func (in Inputs) PolicyModel() (acl.Policy, error) {
	p := in.Policy

	p.Networks = append([]acl.Network(nil), in.Policy.Networks...)
	p.Clusters = append([]acl.Cluster(nil), in.Policy.Clusters...)

	for _, n := range in.sortedNetworks() {
		if !n.Router || !in.hasNetwork(n.Name) {
			continue
		}

		p.Networks = append(p.Networks, acl.Network{Name: n.Name, VPCCIDR: n.VPCCIDR, RouterTag: n.Tag, ExtraCIDRs: n.ExtraCIDRs})
	}

	for _, c := range in.sortedClusters() {
		p.Clusters = append(p.Clusters, acl.Cluster{
			Name:            c.Name,
			Network:         c.Network,
			ServiceCIDR:     c.ServiceCIDR,
			Member:          in.clusterInTailnet(c),
			VPCGroups:       in.Tailnet.FilterGroups(c.VPCGroups),
			InClusterGroups: in.Tailnet.FilterGroups(c.InClusterGroups),
		})
	}

	return p, nil
}
