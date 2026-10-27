package awsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The resource-set goldens (testdata/resources-*.golden.json) are what a
// fleet asks the AWS provider for, under Pulumi mocks: every resource's
// type, logical name, parent, provider and inputs. testdata/handbuilt/
// holds the same record taken from the hand-built fleet of v1.26.2, before
// it moved onto github.com/truvity/asg; it is never regenerated, and
// TestStepBChangesTheHandBuiltResourceSetAsDocumented compares the fleet
// with it: the proof that a stack's next preview replaces nothing and
// changes only what the changelog says.
//
// This repository is public: the mocked account id is built at run time
// and written to the goldens as a placeholder, and the user-data, which
// the user-data goldens already pin byte for byte, is recorded as its
// sha256.

// rsAccount is the mocked account id: twelve digits, as an ARN needs,
// never a literal in a tracked file.
var rsAccount = strings.Repeat("7", 12)

const rsAccountPlaceholder = "@ACCOUNT@"

type resourceSetMocks struct {
	mu  sync.Mutex
	all []map[string]any
}

func (m *resourceSetMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	in := args.Inputs.Mappable()

	if args.TypeToken == "aws:ec2/launchTemplate:LaunchTemplate" {
		if ud, ok := in["userData"].(string); ok {
			sum := sha256.Sum256([]byte(ud))
			in["userData"] = "sha256:" + hex.EncodeToString(sum[:])
		}
	}

	// The provider's Auto Scaling group `tag` block is a set: the order in
	// which a program lists the tags is not part of the resource, and the
	// provider never diffs on it.
	if args.TypeToken == "aws:autoscaling/group:Group" {
		if tags, ok := in["tags"].([]any); ok {
			sort.Slice(tags, func(i, j int) bool {
				return tags[i].(map[string]any)["key"].(string) < tags[j].(map[string]any)["key"].(string)
			})
		}
	}

	parent := ""
	if args.RegisterRPC != nil {
		parent = rsURNName(args.RegisterRPC.GetParent())
	}

	// A provider reference is "<urn>::<id>".
	provider := ""
	if i := strings.LastIndex(args.Provider, "::"); i >= 0 {
		provider = rsURNName(args.Provider[:i])
	}

	m.all = append(m.all, map[string]any{
		"type":     args.TypeToken,
		"name":     args.Name,
		"parent":   parent,
		"provider": provider,
		"inputs":   in,
	})

	out := args.Inputs.Copy()
	if args.TypeToken == "aws:ec2/launchTemplate:LaunchTemplate" {
		out["latestVersion"] = resource.NewNumberProperty(7)
	}

	return args.Name + "-id", out, nil
}

func (m *resourceSetMocks) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.NewPropertyMapFromMap(map[string]any{
		"id":             "ami-0123456789abcdef0",
		"rootDeviceName": "/dev/xvda",
		"accountId":      rsAccount,
		"region":         "eu-west-1",
		"name":           "eu-west-1",
	}), nil
}

// rsURNName is the type and name end of a URN: what tells two parents apart
// without the project and stack the mocks invent.
func rsURNName(urn string) string {
	parts := strings.Split(urn, "::")
	if len(parts) < 2 {
		return urn
	}

	return strings.Join(parts[len(parts)-2:], "::")
}

// dump is the resource set, sorted, as indented JSON with the account id
// replaced by its placeholder.
func (m *resourceSetMocks) dump(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()

	sort.Slice(m.all, func(i, j int) bool {
		return m.all[i]["type"].(string)+"/"+m.all[i]["name"].(string) < m.all[j]["type"].(string)+"/"+m.all[j]["name"].(string)
	})

	b, err := json.MarshalIndent(m.all, "", "  ")
	require.NoError(t, err)

	return strings.ReplaceAll(string(b), rsAccount, rsAccountPlaceholder) + "\n"
}

// recordResourceSet runs CreateTailscaleInstance under the recording mocks.
func recordResourceSet(t *testing.T, c TailscaleInstanceConfig) *resourceSetMocks {
	t.Helper()

	m := &resourceSetMocks{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{Region: pulumi.String("eu-west-1")})
		if err != nil {
			return err
		}

		_, err = CreateTailscaleInstance(ctx, slog.Default(), provider, c)

		return err
	}, pulumi.WithMocks("p", "s", m))
	require.NoError(t, err)

	return m
}

// resourceSetCases are the shapes the estates deploy: the primary
// tailnet's fleet (no prefix, one router, warm pool, boundary, opkssh and
// host certificates), a second tailnet's fleet in the same stack (prefix,
// two routers, so the refresh keeps half healthy) and the zero config.
func resourceSetCases(t *testing.T) map[string]TailscaleInstanceConfig {
	t.Helper()

	withNetwork := func(c TailscaleInstanceConfig) TailscaleInstanceConfig {
		c.VPCID = pulumi.ID("vpc-0123456789abcdef0").ToIDOutput()
		c.RouterSubnets = []pulumi.IDOutput{
			pulumi.ID("subnet-0123456789abcdef0").ToIDOutput(),
			pulumi.ID("subnet-0123456789abcdef1").ToIDOutput(),
		}

		return c
	}

	primary := hostCertConfig(t)
	primary.OPKSSH = opksshConfig(t).OPKSSH
	primary.Min, primary.Desired, primary.Max = 1, 1, 2
	primary.WarmPool = true
	primary.PermissionsBoundaryName = "example-boundary"

	second := exampleConfig()
	second.Tailnet = "other"
	second.SSMAuthKeyPath = "/tailscale/other/auth-key"
	second.ResourcePrefix = "other-"
	second.Min, second.Desired, second.Max = 1, 2, 3
	second.WarmPool = true
	second.PermissionsBoundaryName = "example-boundary"

	return map[string]TailscaleInstanceConfig{
		"primary": withNetwork(primary),
		"second":  withNetwork(second),
		"default": withNetwork(exampleConfig()),
	}
}

// resourceSetGolden reads testdata/resources-<name>.golden.json;
// UPDATE_GOLDEN=1 rewrites it from got (review the diff: a change here is
// a change to every router stack's next preview).
func resourceSetGolden(t *testing.T, name, got string) string {
	t.Helper()

	path := filepath.Join("testdata", "resources-"+name+".golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "golden missing: UPDATE_GOLDEN=1 go test ./pkg/awsrouter/")

	return string(want)
}

// TestResourceSetIsPinned pins what each fleet shape asks the provider
// for. Any change to these goldens is a change to a live router stack.
func TestResourceSetIsPinned(t *testing.T) {
	for name, c := range resourceSetCases(t) {
		t.Run(name, func(t *testing.T) {
			got := recordResourceSet(t, c).dump(t)
			require.Equal(t, resourceSetGolden(t, name, got), got)
		})
	}
}

// stepAGroupDelta is everything the move onto github.com/truvity/asg and
// the router changes after it add to the hand-built Auto Scaling group.
// healthCheckType EC2 and healthCheckGracePeriod 300 are the values every
// live group already has (AWS's and the provider's defaults), so they plan
// no change; waitForCapacityTimeout "0" (asg v0.4.2) exists only in the
// provider, so it is an in-place update of the state that calls no AWS API
// and starts no refresh.
var stepAGroupDelta = map[string]any{
	"healthCheckGracePeriod": float64(300),
	"healthCheckType":        "EC2",
	"waitForCapacityTimeout": "0",
}

// stepBRefresh is the group's instance refresh now: launch the replacement
// before ending a router, never fewer than all of them in service, and no
// trigger named (the hand-built group named launch_template, which Auto
// Scaling does anyway).
var stepBRefresh = map[string]any{
	"strategy": "Rolling",
	"preferences": map[string]any{
		"minHealthyPercentage": float64(100),
		"maxHealthyPercentage": float64(200),
		"instanceWarmup":       "300",
	},
}

// The two CloudWatch alarms of the hand-built fleet, deleted by step B.
var stepBDeleted = map[string]bool{
	"aws:cloudwatch/metricAlarm:MetricAlarm": true,
}

// TestStepBChangesTheHandBuiltResourceSetAsDocumented: against the record of
// the hand-built fleet, a fleet now has
//   - no CloudWatch alarm (they are deleted);
//   - on its Auto Scaling group, stepAGroupDelta's inputs and stepBRefresh
//     in place of the old refresh, and nothing else;
//   - a launch template whose user data differs (the join script is new)
//     and nothing else;
//   - a role without the inline policy that let it change its own
//     source/destination check (ec2:ModifyInstanceAttribute, and
//     ec2:DescribeInstances, which nothing used);
//   - every other resource unchanged: same type, logical name, parent,
//     provider and inputs.
func TestStepBChangesTheHandBuiltResourceSetAsDocumented(t *testing.T) {
	for name, c := range resourceSetCases(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "handbuilt", "resources-"+name+".json"))
			require.NoError(t, err)

			var all, old, now []map[string]any
			require.NoError(t, json.Unmarshal(raw, &all))
			require.NoError(t, json.Unmarshal([]byte(recordResourceSet(t, c).dump(t)), &now))

			deleted := 0

			for _, r := range all {
				if stepBDeleted[r["type"].(string)] {
					deleted++

					continue
				}

				old = append(old, r)
			}

			require.Equal(t, 2, deleted, "the hand-built fleet had two alarms")
			require.Len(t, now, len(old), "the resource count changed")

			for i := range old {
				for _, k := range []string{"type", "name", "parent", "provider"} {
					require.Equal(t, old[i][k], now[i][k], "resource %d: %s", i, k)
				}

				typ := old[i]["type"].(string)
				oldIn := old[i]["inputs"].(map[string]any)
				nowIn := now[i]["inputs"].(map[string]any)

				switch typ {
				case "aws:autoscaling/group:Group":
					for k, v := range stepAGroupDelta {
						require.NotContains(t, oldIn, k, "the hand-built group already set %s", k)
						require.Equal(t, v, nowIn[k], k)
						delete(nowIn, k)
					}

					require.Equal(t, stepBRefresh, nowIn["instanceRefresh"], "instanceRefresh")
					require.NotEqual(t, oldIn["instanceRefresh"], nowIn["instanceRefresh"])
					delete(oldIn, "instanceRefresh")
					delete(nowIn, "instanceRefresh")
				case "aws:iam/role:Role":
					// The role may no longer change its own source/destination
					// check: the inline policy that allowed it is gone, and
					// the other three are as they were.
					var kept []any

					for _, p := range oldIn["inlinePolicies"].([]any) {
						if p.(map[string]any)["name"] != "ec2-source-dest-check" {
							kept = append(kept, p)
						}
					}

					require.Len(t, kept, 3, "the hand-built role had four inline policies")
					oldIn["inlinePolicies"] = kept
				case "aws:ec2/launchTemplate:LaunchTemplate":
					require.NotEqual(t, oldIn["userData"], nowIn["userData"], "the join script changed the user data")
					delete(oldIn, "userData")
					delete(nowIn, "userData")
				}

				require.Equal(t, oldIn, nowIn, "%s %s: inputs", typ, old[i]["name"])
			}
		})
	}
}

// A refresh that launches the replacement before it ends a router needs room
// for one extra instance, so the group's maximum is at least Desired+1.
func TestMaxLeavesRoomForARefresh(t *testing.T) {
	for _, tc := range []struct{ min, desired, max, want int }{
		{0, 0, 0, 2}, // the zero config: one router, room for a second
		{1, 1, 1, 2}, // a maximum equal to the desired size is raised
		{1, 3, 3, 4},
		{1, 3, 0, 4},
		{1, 1, 2, 2}, // already room: kept
		{1, 2, 6, 6}, // more room than needed: kept
	} {
		got := TailscaleInstanceConfig{Min: tc.min, Desired: tc.desired, Max: tc.max}.sizes()
		assert.Equal(t, tc.want, got.max, "min %d desired %d max %d", tc.min, tc.desired, tc.max)
	}
}

// No fleet's role may allow an EC2 action: the source/destination check
// stays at EC2's default, and the join does not touch it.
func TestRoleAllowsNoEC2Action(t *testing.T) {
	for name, c := range resourceSetCases(t) {
		t.Run(name, func(t *testing.T) {
			got := recordResourceSet(t, c).dump(t)
			assert.NotContains(t, got, "ec2:")
			assert.NotContains(t, got, "ModifyInstanceAttribute")
		})
	}

	assert.NotContains(t, routerSetupScript, "modify-instance-attribute")
	assert.NotContains(t, routerSetupScript, "source-dest")
}
