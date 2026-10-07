// Package acl builds a tailnet's complete ACL policy document from a
// neutral model — pure data in, deterministic JSON out, no Tailscale
// SDK, no cloud, no config-file opinions.
//
// The model it encodes:
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
//   - Policy.ExtraGrants is the one escape hatch: a single tag-to-tag
//     accept rule on a spelled-out port list, for access that is neither
//     a VPC/Service-CIDR tier nor a router's own reachability — an
//     application box outside every cluster that one cluster's egress
//     identity needs to reach on one port, say. It stays this narrow on
//     purpose: see Grant's own doc comment.
//   - Policy.ExtraCIDRGrants is the same escape hatch for the one shape
//     Grant's own doc comment names and refuses to grow into: a
//     destination that is an address rather than a tag — a tagged
//     device reaching one address behind a subnet router (a private
//     gateway's pinned ClusterIP, say) that carries no tag of its own
//     for a Grant to name. See CIDRGrant's own doc comment.
//   - Policy.ExtraMemberGrants is Grant's other sibling, for the shape
//     neither Grant nor CIDRGrant can name: a source that is every
//     tailnet member (autogroup:member) rather than a tag — a box any
//     signed-in user may reach on one port, not gated by a directory
//     group. See MemberGrant's own doc comment.
//
// No `ssh` and no `groups` sections, deliberately. The `ssh` section
// configures Tailscale SSH (tailscaled answering SSH itself); a router
// that runs OpenSSH — pkg/awsrouter's optional certificate login — needs
// only an ordinary rule to its tag on port 22, which the network router
// rule above already carries for every VPC-tier group, and its
// certificates decide who logs in. Group membership comes exclusively
// from the tailnet's directory sync.
package acl

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
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
		// ExtraCIDRs are further routes the network's router advertises
		// (a peered VPC, say). They are auto-approved for the same router
		// tag and join VPCCIDR as destinations of the VPC tier. Empty, the
		// default, renders exactly as before.
		ExtraCIDRs []string `json:"extraCidrs,omitempty" yaml:"extraCidrs,omitempty"`
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

	// Grant is one explicit, narrow accept rule between two tags — the
	// escape hatch for access that does not fit the network/cluster
	// model above: a single application on one side, a specific port
	// list on the other, neither a VPC CIDR nor a Service CIDR. Ports is
	// required and deliberately not "*": a Grant that admits a whole tag
	// rather than a small, spelled-out port list is exactly the blast
	// radius this type exists to avoid, so Validate refuses an empty
	// list rather than defaulting it to everything.
	//
	// This is deliberately the ONLY shape ExtraGrants accepts — one tag
	// to one tag, ports only, no groups, no autogroups, no CIDRs. A need
	// that does not fit even this (a source that is a group, a
	// destination that is a CIDR) is a sign the model itself needs a new
	// concept, not that this escape hatch should grow another field.
	Grant struct {
		// SrcTag and DstTag are tag names without the "tag:" prefix.
		SrcTag string `json:"srcTag" yaml:"srcTag"`
		DstTag string `json:"dstTag" yaml:"dstTag"`
		// Ports the rule admits on DstTag, e.g. []string{"9092"}. Every
		// entry is rendered into one comma-joined dst ("tag:x:9092,9093"),
		// the ACL policy's own way of listing several ports on one line.
		Ports []string `json:"ports" yaml:"ports"`
	}

	// CIDRGrant is one explicit, narrow accept rule from a tag to a
	// destination address — Grant's sibling for the one shape Grant's
	// own doc comment names and refuses to grow into.
	//
	// A tagged device reaching one address behind a subnet router (a
	// private gateway's pinned ClusterIP, say, rather than the whole VPC
	// CIDR the router already advertises) is neither a VPC/Service-CIDR
	// tier — those are GROUP-sourced, reached by a person's role, not a
	// TAG the way a device like this carries one — nor a router's own
	// reachability rule, which admits the router itself and not
	// something behind it. It is a second escape hatch rather than a
	// field grown onto Grant, on purpose: Grant is deliberately tag only
	// on both sides (its own doc comment says so), and a type whose
	// destination is sometimes a tag and sometimes an address is a type
	// whose every caller has to check which one it got.
	//
	// This is deliberately the ONLY shape ExtraCIDRGrants accepts — one
	// tag to one address, ports only, no groups, no autogroups, no tag
	// destination (that is Grant's shape, not this one).
	CIDRGrant struct {
		// SrcTag is a tag name without the "tag:" prefix.
		SrcTag string `json:"srcTag" yaml:"srcTag"`
		// DstCIDR is the destination address, in the exact form the
		// rendered rule should carry it — a single host as a /32 (or
		// /128), or a narrower CIDR, e.g. "100.20.0.20/32". Never a bare
		// address without a prefix length: Tailscale's ACL syntax reads
		// one unqualified, so the shape that means "this one address"
		// is spelled out rather than implied.
		DstCIDR string `json:"dstCidr" yaml:"dstCidr"`
		// Ports the rule admits on DstCIDR, e.g. []string{"443"}. Every
		// entry is rendered into one comma-joined dst
		// ("100.20.0.20/32:443,8443"), the same list-of-ports spelling
		// Grant uses for a tag destination. Required, for the identical
		// reason Grant refuses an empty list: a rule with no port list
		// admits the whole address rather than the one service it
		// exists to reach.
		Ports []string `json:"ports" yaml:"ports"`
	}

	// MemberGrant is Grant's other sibling: one explicit, narrow accept
	// rule from EVERY tailnet member — Tailscale's own autogroup:member,
	// not a tag and not a directory group — to one tag, on a
	// spelled-out port list.
	//
	// Neither Grant nor CIDRGrant can name this source: both are
	// deliberately tag-only on the source side (their own doc comments
	// say so). A box any signed-in tailnet member may reach on one
	// port — regardless of which directory group they are in, unlike
	// the VPC/Service-CIDR tiers, which are always group-sourced — is
	// neither of those shapes, so it is a third escape hatch rather
	// than a field grown onto either existing one.
	//
	// This is deliberately the ONLY shape ExtraMemberGrants accepts —
	// autogroup:member to one tag, ports only, no groups, no CIDRs, no
	// other autogroup. A need that does not fit even this is a sign the
	// model itself needs a new concept, the same rule Grant's own doc
	// comment states for itself.
	MemberGrant struct {
		// DstTag is a tag name without the "tag:" prefix.
		DstTag string `json:"dstTag" yaml:"dstTag"`
		// Ports the rule admits on DstTag, e.g. []string{"80"}. Every
		// entry is rendered into one comma-joined dst
		// ("tag:x:80,8080"), the same list-of-ports spelling Grant and
		// CIDRGrant use. Required, for the identical reason both of
		// those refuse an empty list: a rule with no port list admits
		// the whole tag rather than the one service it exists to reach.
		Ports []string `json:"ports" yaml:"ports"`
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
		// ExtraGrants are one-off tag-to-tag accept rules the
		// network/cluster model above cannot express — see Grant's own
		// doc comment for why this stays narrow. Rendered after every
		// rule the model derives, in the order given.
		ExtraGrants []Grant `json:"extraGrants,omitempty" yaml:"extraGrants,omitempty"`
		// ExtraCIDRGrants are one-off tag-to-address accept rules —
		// Grant's sibling for a destination that is an address rather
		// than a tag. See CIDRGrant's own doc comment. Rendered after
		// ExtraGrants, in the order given.
		ExtraCIDRGrants []CIDRGrant `json:"extraCidrGrants,omitempty" yaml:"extraCidrGrants,omitempty"`
		// ExtraMemberGrants are one-off autogroup:member-to-tag accept
		// rules — Grant's other sibling, for a source that is every
		// tailnet member rather than a tag. See MemberGrant's own doc
		// comment. Rendered after ExtraCIDRGrants, in the order given.
		ExtraMemberGrants []MemberGrant `json:"extraMemberGrants,omitempty" yaml:"extraMemberGrants,omitempty"`
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

// vpcDst is the VPC tier's destinations: the VPC CIDR, then any extra routes.
func (n *Network) vpcDst() []string {
	dst := []string{n.VPCCIDR + ":*"}
	for _, c := range n.ExtraCIDRs {
		dst = append(dst, c+":*")
	}

	return dst
}

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

		for _, c := range n.ExtraCIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return fmt.Errorf("acl: network %q extra cidr %q is not a CIDR: %w", n.Name, c, err)
			}
		}
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

	for _, g := range p.ExtraGrants {
		if g.SrcTag == "" || g.DstTag == "" {
			return fmt.Errorf("acl: extra grant %+v needs srcTag and dstTag", g)
		}

		if len(g.Ports) == 0 {
			return fmt.Errorf("acl: extra grant %s -> %s has no ports: "+
				"a Grant admitting a whole tag with no port list is exactly "+
				"the blast radius this type exists to avoid, so it is "+
				"refused rather than defaulted to everything", g.SrcTag, g.DstTag)
		}
	}

	for _, g := range p.ExtraCIDRGrants {
		if g.SrcTag == "" || g.DstCIDR == "" {
			return fmt.Errorf("acl: extra cidr grant %+v needs srcTag and dstCidr", g)
		}

		if len(g.Ports) == 0 {
			return fmt.Errorf("acl: extra cidr grant %s -> %s has no ports: "+
				"a CIDRGrant admitting a whole address with no port list is "+
				"exactly the blast radius this type exists to avoid, so it is "+
				"refused rather than defaulted to everything", g.SrcTag, g.DstCIDR)
		}
	}

	for _, g := range p.ExtraMemberGrants {
		if g.DstTag == "" {
			return fmt.Errorf("acl: extra member grant %+v needs dstTag", g)
		}

		if len(g.Ports) == 0 {
			return fmt.Errorf("acl: extra member grant autogroup:member -> %s has no ports: "+
				"a MemberGrant admitting a whole tag with no port list is "+
				"exactly the blast radius this type exists to avoid, so it is "+
				"refused rather than defaulted to everything", g.DstTag)
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

	acls := rules(networks, clusters, netByName)
	acls = append(acls, grantRules(p.ExtraGrants)...)
	acls = append(acls, cidrGrantRules(p.ExtraCIDRGrants)...)
	acls = append(acls, memberGrantRules(p.ExtraMemberGrants)...)

	doc := policyDoc{
		TagOwners:     tagOwners(manager, p.ExtraTagOwners, networks, clusters),
		ACLs:          acls,
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
				out = append(out, rule{Action: accept, Src: groupSrc(c.VPCGroups), Dst: net.vpcDst()})
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

// grantRules renders each ExtraGrant as one rule: a single tag source, a
// single tag destination restricted to that Grant's own port list. Order
// is preserved (not sorted) so a caller's own ordering — the only thing
// about ExtraGrants this package does not otherwise normalize — is
// exactly what ends up in the rendered policy; determinism instead comes
// from the caller building the slice in a stable order, the same
// responsibility Policy.Networks and Policy.Clusters already have before
// Build sorts them.
func grantRules(grants []Grant) []rule {
	out := make([]rule, 0, len(grants))

	for _, g := range grants {
		out = append(out, rule{
			Action: accept,
			Src:    []string{"tag:" + g.SrcTag},
			Dst:    []string{"tag:" + g.DstTag + ":" + strings.Join(g.Ports, ",")},
		})
	}

	return out
}

// cidrGrantRules renders each ExtraCIDRGrant as one rule, the same way
// grantRules renders a Grant — order preserved, not sorted, for the same
// reason grantRules is not: determinism comes from the caller building
// the slice in a stable order.
func cidrGrantRules(grants []CIDRGrant) []rule {
	out := make([]rule, 0, len(grants))

	for _, g := range grants {
		out = append(out, rule{
			Action: accept,
			Src:    []string{"tag:" + g.SrcTag},
			Dst:    []string{g.DstCIDR + ":" + strings.Join(g.Ports, ",")},
		})
	}

	return out
}

// memberGrantRules renders each ExtraMemberGrant as one rule, the same
// way grantRules and cidrGrantRules render their own grants — order
// preserved, not sorted, for the same reason neither of those is:
// determinism comes from the caller building the slice in a stable
// order. The source is the literal Tailscale keyword, never prefixed
// the way a tag is.
func memberGrantRules(grants []MemberGrant) []rule {
	out := make([]rule, 0, len(grants))

	for _, g := range grants {
		out = append(out, rule{
			Action: accept,
			Src:    []string{"autogroup:member"},
			Dst:    []string{"tag:" + g.DstTag + ":" + strings.Join(g.Ports, ",")},
		})
	}

	return out
}

func approvers(networks []Network, clusters []Cluster, netByName map[string]*Network) autoApprovers {
	routes := map[string][]string{}

	for i := range networks {
		routes[networks[i].VPCCIDR] = []string{"tag:" + networks[i].RouterTag}

		for _, c := range networks[i].ExtraCIDRs {
			routes[c] = append(routes[c], "tag:"+networks[i].RouterTag)
		}
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

			for _, x := range net.ExtraCIDRs {
				routes[x] = append(routes[x], tag)
			}
		}
	}

	return autoApprovers{Routes: routes}
}
