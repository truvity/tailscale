// Package acl builds a tailnet's complete ACL policy document from a
// neutral model — pure data in, deterministic JSON out, no Tailscale
// SDK, no cloud, no config-file opinions.
//
// The model it encodes (proven in a multi-company production estate):
//
//   - One MANAGER TAG (default "infra-manager") owns every router tag.
//     The tailnet's OAuth credential is scoped to the manager tag alone,
//     which is what lets it mint auth keys for any child router tag —
//     Tailscale requires tag ownership hierarchy for subset-tag keys.
//   - Two access tiers per cluster: the VPC tier (any role on the scope
//     reaches the network's VPC CIDR) and the in-cluster tier (operator
//     rungs reach the Kubernetes Service CIDR). Sources are groups the
//     tailnet's own directory sync provides ("group:<email>") — the
//     policy declares no group membership itself.
//   - Per-environment isolation: Tailscale is default-deny, and every
//     route auto-approval binds a CIDR to ITS OWN environment's tags
//     only — the EC2 router's tag and the environment's own Kubernetes
//     router tag, never another environment's.
//   - Kubernetes routers join with EPHEMERAL keys, so every CIDR they
//     advertise must be auto-approved for their tag — including the VPC
//     CIDR they advertise alongside the Service CIDR. Without that
//     entry, every pod re-registration strands the route in "pending
//     approval" (observed across four clusters at once).
//
// No `ssh` and no `groups` sections, deliberately: SSH access to
// routers belongs to the cloud's own channel (SSM and the like), and
// group membership comes exclusively from the tailnet's directory sync.
package acl

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	accept = "accept"
	// DefaultManagerTag owns every router tag; the tailnet's OAuth
	// credential is scoped to it.
	DefaultManagerTag = "infra-manager"
)

type (
	// Network is one physical network whose subnet router joins the
	// tailnet.
	Network struct {
		// Name identifies the network; Cluster.Network references it.
		Name string `json:"name" yaml:"name"`
		// VPCCIDR is the network's address space, the VPC-tier target.
		VPCCIDR string `json:"vpcCidr" yaml:"vpcCidr"`
		// RouterTag is the network router's tag, without the "tag:"
		// prefix.
		RouterTag string `json:"routerTag" yaml:"routerTag"`
	}

	// Cluster is one Kubernetes cluster.
	Cluster struct {
		// Name of the cluster; also names its router tag
		// (k8s-<name>-router unless RouterTag overrides).
		Name string `json:"name" yaml:"name"`
		// Network is the Network.Name this cluster lives on.
		Network string `json:"network" yaml:"network"`
		// ServiceCIDR is the in-cluster tier's target; empty = no
		// in-cluster tier for this cluster.
		ServiceCIDR string `json:"serviceCidr,omitempty" yaml:"serviceCidr,omitempty"`
		// RouterTag overrides the k8s-<name>-router convention (no
		// "tag:" prefix).
		RouterTag string `json:"routerTag,omitempty" yaml:"routerTag,omitempty"`
		// Member: the cluster's own router joins THIS tailnet. Non-member
		// clusters get no rules, tags or approvals of their own — but
		// their VPCGroups still count toward the network router's
		// reachability, because those people reach the shared network
		// through the EC2 router regardless of where the cluster's own
		// router lives.
		Member bool `json:"member" yaml:"member"`
		// VPCGroups are directory group emails with VPC-tier access.
		VPCGroups []string `json:"vpcGroups,omitempty" yaml:"vpcGroups,omitempty"`
		// InClusterGroups are directory group emails with Service-CIDR
		// access.
		InClusterGroups []string `json:"inClusterGroups,omitempty" yaml:"inClusterGroups,omitempty"`
	}

	// Policy is the whole tailnet's input model. Plain data,
	// yaml/json-taggable.
	Policy struct {
		// ManagerTag owns every router tag. Default: DefaultManagerTag.
		ManagerTag string `json:"managerTag,omitempty" yaml:"managerTag,omitempty"`
		// ExtraTagOwners are additional tagOwners entries rendered
		// verbatim (tag names without the "tag:" prefix).
		ExtraTagOwners map[string][]string `json:"extraTagOwners,omitempty" yaml:"extraTagOwners,omitempty"`
		// Networks with tailnet routers.
		Networks []Network `json:"networks" yaml:"networks"`
		// Clusters, members and non-members alike (see Cluster.Member).
		Clusters []Cluster `json:"clusters" yaml:"clusters"`
	}

	policyDoc struct {
		TagOwners     map[string][]string `json:"tagOwners"`
		ACLs          []rule              `json:"acls"`
		AutoApprovers autoApprovers       `json:"autoApprovers"`
	}

	rule struct {
		Action string   `json:"action"`
		Src    []string `json:"src"`
		Dst    []string `json:"dst"`
	}

	autoApprovers struct {
		Routes map[string][]string `json:"routes"`
	}
)

// routerTag returns the cluster's tag without the "tag:" prefix.
func (c *Cluster) routerTag() string {
	if c.RouterTag != "" {
		return c.RouterTag
	}

	return "k8s-" + c.Name + "-router"
}

// Validate reports the first model error.
func (p *Policy) Validate() error {
	nets := map[string]bool{}
	for _, n := range p.Networks {
		if n.Name == "" || n.VPCCIDR == "" || n.RouterTag == "" {
			return fmt.Errorf("acl: network %+v needs name, vpcCidr and routerTag", n)
		}

		if nets[n.Name] {
			return fmt.Errorf("acl: duplicate network %q", n.Name)
		}

		nets[n.Name] = true
	}

	seen := map[string]bool{}

	for _, c := range p.Clusters {
		if c.Name == "" {
			return fmt.Errorf("acl: cluster with empty name")
		}

		if seen[c.Name] {
			return fmt.Errorf("acl: duplicate cluster %q", c.Name)
		}

		seen[c.Name] = true

		if c.Member && c.Network != "" && !nets[c.Network] {
			return fmt.Errorf("acl: cluster %q references unknown network %q", c.Name, c.Network)
		}
	}

	return nil
}

// Build renders the policy document as deterministic, indented JSON —
// the string Tailscale's ACL resource takes verbatim.
func Build(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	manager := p.ManagerTag
	if manager == "" {
		manager = DefaultManagerTag
	}

	networks := append([]Network(nil), p.Networks...)
	sort.Slice(networks, func(i, j int) bool { return networks[i].Name < networks[j].Name })

	clusters := append([]Cluster(nil), p.Clusters...)
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })

	netByName := map[string]*Network{}
	for i := range networks {
		netByName[networks[i].Name] = &networks[i]
	}

	doc := policyDoc{
		TagOwners:     tagOwners(manager, p.ExtraTagOwners, networks, clusters),
		ACLs:          rules(networks, clusters, netByName),
		AutoApprovers: approvers(networks, clusters, netByName),
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal acl policy: %w", err)
	}

	return string(data), nil
}

func tagOwners(manager string, extra map[string][]string, networks []Network, clusters []Cluster) map[string][]string {
	owners := map[string][]string{
		"tag:" + manager: {"autogroup:admin"},
	}

	for tag, o := range extra {
		owners["tag:"+tag] = append([]string(nil), o...)
	}

	// Every router tag is owned by the manager tag: that hierarchy is
	// what lets the manager-scoped OAuth credential mint keys carrying
	// individual router tags.
	for _, n := range networks {
		owners["tag:"+n.RouterTag] = []string{"tag:" + manager}
	}

	for i := range clusters {
		if !clusters[i].Member {
			continue
		}

		owners["tag:"+clusters[i].routerTag()] = []string{"tag:" + manager}
	}

	return owners
}

func groupSrc(groups []string) []string {
	src := make([]string, len(groups))
	for i, g := range groups {
		src[i] = "group:" + g
	}

	return src
}

func rules(networks []Network, clusters []Cluster, netByName map[string]*Network) []rule {
	var out []rule

	// Per-cluster tiers, clusters in name order.
	for i := range clusters {
		c := &clusters[i]
		if !c.Member {
			continue
		}

		if len(c.VPCGroups) > 0 {
			if net, ok := netByName[c.Network]; ok {
				out = append(out, rule{Action: accept, Src: groupSrc(c.VPCGroups), Dst: []string{net.VPCCIDR + ":*"}})
			}
		}

		if len(c.InClusterGroups) > 0 && c.ServiceCIDR != "" {
			out = append(out, rule{Action: accept, Src: groupSrc(c.InClusterGroups), Dst: []string{c.ServiceCIDR + ":*"}})
		}
	}

	// Network router reachability + return traffic, networks in name
	// order. Sources are every group with VPC access to ANY cluster on
	// the network — members and non-members alike, deduplicated and
	// sorted: those people reach the shared network through this router
	// regardless of where a given cluster's own router lives.
	for i := range networks {
		n := &networks[i]
		tag := "tag:" + n.RouterTag

		seen := map[string]bool{}

		var groups []string

		for j := range clusters {
			if clusters[j].Network != n.Name {
				continue
			}

			for _, g := range clusters[j].VPCGroups {
				key := "group:" + g
				if !seen[key] {
					seen[key] = true

					groups = append(groups, key)
				}
			}
		}

		sort.Strings(groups)

		if len(groups) > 0 {
			out = append(out, rule{Action: accept, Src: groups, Dst: []string{tag + ":*"}})
		}

		out = append(out, rule{Action: accept, Src: []string{tag}, Dst: []string{"autogroup:member:*"}})
	}

	// Kubernetes router reachability + return traffic, clusters in name
	// order.
	for i := range clusters {
		c := &clusters[i]
		if !c.Member {
			continue
		}

		tag := "tag:" + c.routerTag()

		if len(c.VPCGroups) > 0 {
			out = append(out, rule{Action: accept, Src: groupSrc(c.VPCGroups), Dst: []string{tag + ":*"}})
		}

		out = append(out, rule{Action: accept, Src: []string{tag}, Dst: []string{"autogroup:member:*"}})
	}

	return out
}

func approvers(networks []Network, clusters []Cluster, netByName map[string]*Network) autoApprovers {
	routes := map[string][]string{}

	for i := range networks {
		routes[networks[i].VPCCIDR] = []string{"tag:" + networks[i].RouterTag}
	}

	// Kubernetes routers advertise BOTH their Service CIDR and their
	// network's VPC CIDR, with ephemeral keys — both must be approved
	// for the router's tag or every re-registration strands a route.
	for i := range clusters {
		c := &clusters[i]
		if !c.Member {
			continue
		}

		tag := "tag:" + c.routerTag()

		if c.ServiceCIDR != "" {
			routes[c.ServiceCIDR] = append(routes[c.ServiceCIDR], tag)
		}

		if net, ok := netByName[c.Network]; ok {
			routes[net.VPCCIDR] = append(routes[net.VPCCIDR], tag)
		}
	}

	return autoApprovers{Routes: routes}
}
