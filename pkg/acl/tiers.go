package acl

import "sort"

type (
	// Tier says which of a cluster's two access tiers a level reaches: the
	// VPC tier (the network's VPC CIDR) and the in-cluster tier (the
	// Kubernetes Service CIDR). The caller owns the table that maps its own
	// level names to tiers; this package never learns them.
	Tier struct {
		VPC       bool
		InCluster bool
	}

	// Holder is one role on a scope: the access level it holds there and the
	// directory groups that carry the role.
	Holder struct {
		Level  string
		Groups []string
	}
)

// TierGroups derives, for one scope, the directory groups that reach each
// tier. A holder whose level is missing from levels reaches neither tier. A
// group reaches a tier when ANY role that carries it does, and each result is
// sorted and free of duplicates; a tier nobody reaches is nil.
func TierGroups(levels map[string]Tier, holders []Holder) (vpc, inCluster []string) {
	vpcSet := map[string]bool{}
	inClusterSet := map[string]bool{}

	for _, h := range holders {
		t, ok := levels[h.Level]
		if !ok {
			continue
		}

		for _, g := range h.Groups {
			if t.VPC {
				vpcSet[g] = true
			}

			if t.InCluster {
				inClusterSet[g] = true
			}
		}
	}

	return sortedKeys(vpcSet), sortedKeys(inClusterSet)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}

	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
