package acl

import (
	"reflect"
	"testing"
)

func TestTierGroups(t *testing.T) {
	levels := map[string]Tier{
		"op":   {VPC: true, InCluster: true},
		"view": {VPC: true},
	}

	vpc, in := TierGroups(levels, []Holder{
		{Level: "op", Groups: []string{"b@x", "a@x"}},
		{Level: "view", Groups: []string{"c@x", "a@x"}},
		{Level: "unknown", Groups: []string{"z@x"}},
	})

	if want := []string{"a@x", "b@x", "c@x"}; !reflect.DeepEqual(vpc, want) {
		t.Errorf("vpc = %v, want %v", vpc, want)
	}

	if want := []string{"a@x", "b@x"}; !reflect.DeepEqual(in, want) {
		t.Errorf("inCluster = %v, want %v", in, want)
	}

	vpc, in = TierGroups(levels, nil)
	if vpc != nil || in != nil {
		t.Errorf("empty input must give nil tiers, got %v %v", vpc, in)
	}
}
