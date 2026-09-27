package acl

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func examplePolicy() Policy {
	return Policy{
		ExtraTagOwners: map[string][]string{"k8s-operator": {"autogroup:admin"}},
		Networks: []Network{
			{Name: "prod", VPCCIDR: "10.2.0.0/16", RouterTag: "prod-router"},
			{Name: "devel", VPCCIDR: "10.1.0.0/16", RouterTag: "devel-router"},
		},
		Clusters: []Cluster{
			{
				Name: "prod", Network: "prod", ServiceCIDR: "172.2.0.0/16", Member: true,
				VPCGroups:       []string{"eng@example.com"},
				InClusterGroups: []string{"ops@example.com"},
			},
			{
				Name: "devel", Network: "devel", ServiceCIDR: "172.1.0.0/16", Member: true,
				VPCGroups:       []string{"eng@example.com", "qa@example.com"},
				InClusterGroups: []string{"eng@example.com"},
			},
			// A cluster on a member network whose OWN router joins a
			// different tailnet: no rules/tags/approvals of its own, but
			// its people still reach the shared network router.
			{
				Name: "partner", Network: "devel", Member: false,
				VPCGroups: []string{"partner@example.com"},
			},
		},
	}
}

func build(t *testing.T, p Policy) (string, policyDoc) {
	t.Helper()

	s, err := Build(p)
	require.NoError(t, err)

	var doc policyDoc
	require.NoError(t, json.Unmarshal([]byte(s), &doc))

	return s, doc
}

func TestBuildIsDeterministic(t *testing.T) {
	a, _ := build(t, examplePolicy())

	p := examplePolicy()
	// Same content, different declaration order.
	p.Networks[0], p.Networks[1] = p.Networks[1], p.Networks[0]
	p.Clusters[0], p.Clusters[1] = p.Clusters[1], p.Clusters[0]
	b, _ := build(t, p)

	assert.Equal(t, a, b)
}

func TestTagOwnershipHierarchy(t *testing.T) {
	_, doc := build(t, examplePolicy())

	assert.Equal(t, []string{"autogroup:admin"}, doc.TagOwners["tag:infra-manager"])
	assert.Equal(t, []string{"autogroup:admin"}, doc.TagOwners["tag:k8s-operator"])
	// Every router tag is owned by the manager tag — the hierarchy the
	// manager-scoped OAuth credential depends on to mint child-tag keys.
	for _, tag := range []string{"tag:devel-router", "tag:prod-router", "tag:k8s-devel-router", "tag:k8s-prod-router"} {
		assert.Equal(t, []string{"tag:infra-manager"}, doc.TagOwners[tag], tag)
	}
	// Non-members get no tag.
	assert.NotContains(t, doc.TagOwners, "tag:k8s-partner-router")
}

func TestPerEnvironmentIsolation(t *testing.T) {
	_, doc := build(t, examplePolicy())

	// No CIDR is ever auto-approved for another environment's tag.
	assert.ElementsMatch(t, []string{"tag:devel-router", "tag:k8s-devel-router"}, doc.AutoApprovers.Routes["10.1.0.0/16"])
	assert.ElementsMatch(t, []string{"tag:prod-router", "tag:k8s-prod-router"}, doc.AutoApprovers.Routes["10.2.0.0/16"])
	assert.Equal(t, []string{"tag:k8s-devel-router"}, doc.AutoApprovers.Routes["172.1.0.0/16"])
	assert.Equal(t, []string{"tag:k8s-prod-router"}, doc.AutoApprovers.Routes["172.2.0.0/16"])

	// qa has VPC access on devel only: no rule carries qa toward prod's
	// CIDRs, and prod's service CIDR is reachable only by ops.
	for _, r := range doc.ACLs {
		for _, src := range r.Src {
			if src == "group:qa@example.com" {
				for _, dst := range r.Dst {
					assert.False(t, strings.HasPrefix(dst, "10.2.") || strings.HasPrefix(dst, "172.2."),
						"qa reached a prod destination: %v", r)
				}
			}
		}

		for _, dst := range r.Dst {
			if dst == "172.2.0.0/16:*" {
				assert.Equal(t, []string{"group:ops@example.com"}, r.Src)
			}
		}
	}
}

func TestNonMemberClusterFeedsTheNetworkRuleOnly(t *testing.T) {
	_, doc := build(t, examplePolicy())

	var develRouterRule *rule

	for i, r := range doc.ACLs {
		if len(r.Dst) == 1 && r.Dst[0] == "tag:devel-router:*" {
			develRouterRule = &doc.ACLs[i]
		}

		// The non-member cluster contributes NO per-cluster rule.
		for _, dst := range r.Dst {
			assert.NotContains(t, dst, "k8s-partner")
		}
	}

	require.NotNil(t, develRouterRule)
	// Deduplicated, sorted union of every group on the network — the
	// non-member's people included.
	assert.Equal(t, []string{"group:eng@example.com", "group:partner@example.com", "group:qa@example.com"}, develRouterRule.Src)
}

func TestRouterReturnTraffic(t *testing.T) {
	_, doc := build(t, examplePolicy())

	returns := 0

	for _, r := range doc.ACLs {
		if len(r.Dst) == 1 && r.Dst[0] == "autogroup:member:*" {
			returns++
		}
	}

	// One per network router + one per member k8s router.
	assert.Equal(t, 4, returns)
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Policy)
		want string
	}{
		{"network missing fields", func(p *Policy) { p.Networks[0].VPCCIDR = "" }, "needs name, vpcCidr and routerTag"},
		{"duplicate network", func(p *Policy) { p.Networks[1].Name = p.Networks[0].Name }, "duplicate network"},
		{"nameless cluster", func(p *Policy) { p.Clusters[0].Name = "" }, "empty name"},
		{"duplicate cluster", func(p *Policy) { p.Clusters[1].Name = p.Clusters[0].Name }, "duplicate cluster"},
		{"member on unknown network", func(p *Policy) { p.Clusters[0].Network = "nope" }, "unknown network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := examplePolicy()
			tc.mut(&p)
			err := p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestExtraGrantsRenderNarrowRules(t *testing.T) {
	p := examplePolicy()
	p.ExtraGrants = []Grant{
		{SrcTag: "k8s-devel-router", DstTag: "statusbox", Ports: []string{"9092"}},
	}

	_, doc := build(t, p)

	var found *rule

	for i, r := range doc.ACLs {
		if len(r.Src) == 1 && r.Src[0] == "tag:k8s-devel-router" && len(r.Dst) == 1 && r.Dst[0] == "tag:statusbox:9092" {
			found = &doc.ACLs[i]
		}
	}

	require.NotNil(t, found, "no rule matched tag:k8s-devel-router -> tag:statusbox:9092 in %+v", doc.ACLs)
	assert.Equal(t, accept, found.Action)

	// ExtraGrants introduces no tagOwners entry of its own — Grant is
	// purely a rule, and ownership of the destination tag is still
	// ExtraTagOwners's job (or Validate would have to know a great deal
	// more about what a caller intends the destination tag to mean).
	assert.NotContains(t, doc.TagOwners, "tag:statusbox")
}

func TestExtraGrantsJoinMultiplePorts(t *testing.T) {
	p := examplePolicy()
	p.ExtraGrants = []Grant{
		{SrcTag: "k8s-devel-router", DstTag: "statusbox", Ports: []string{"9092", "9093"}},
	}

	_, doc := build(t, p)

	var dsts []string
	for _, r := range doc.ACLs {
		if len(r.Src) == 1 && r.Src[0] == "tag:k8s-devel-router" {
			dsts = append(dsts, r.Dst...)
		}
	}

	assert.Contains(t, dsts, "tag:statusbox:9092,9093")
}

func TestExtraGrantsPreserveDeclarationOrder(t *testing.T) {
	p := examplePolicy()
	p.ExtraGrants = []Grant{
		{SrcTag: "a", DstTag: "b", Ports: []string{"1"}},
		{SrcTag: "c", DstTag: "d", Ports: []string{"2"}},
	}

	_, doc := build(t, p)

	n := len(doc.ACLs)
	require.GreaterOrEqual(t, n, 2)
	assert.Equal(t, []string{"tag:a"}, doc.ACLs[n-2].Src)
	assert.Equal(t, []string{"tag:c"}, doc.ACLs[n-1].Src)
}

func TestExtraGrantsValidateRefusesAnEmptyPortList(t *testing.T) {
	p := examplePolicy()
	p.ExtraGrants = []Grant{{SrcTag: "a", DstTag: "b"}}

	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ports")
}

func TestExtraGrantsValidateRefusesAMissingTag(t *testing.T) {
	for _, tc := range []struct {
		name string
		g    Grant
	}{
		{"no srcTag", Grant{DstTag: "b", Ports: []string{"1"}}},
		{"no dstTag", Grant{SrcTag: "a", Ports: []string{"1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := examplePolicy()
			p.ExtraGrants = []Grant{tc.g}
			err := p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "needs srcTag and dstTag")
		})
	}
}

func TestManagerTagDefaultAndOverride(t *testing.T) {
	_, doc := build(t, examplePolicy())
	assert.Contains(t, doc.TagOwners, "tag:infra-manager")

	p := examplePolicy()
	p.ManagerTag = "fleet-manager"
	_, doc = build(t, p)
	assert.Contains(t, doc.TagOwners, "tag:fleet-manager")
	assert.Equal(t, []string{"tag:fleet-manager"}, doc.TagOwners["tag:devel-router"])
}
