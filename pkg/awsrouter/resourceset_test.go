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
	"github.com/stretchr/testify/require"
)

// The resource-set goldens (testdata/resources-*.golden.json) are what a
// fleet asks the AWS provider for, under Pulumi mocks: every resource's
// type, logical name, parent, provider and inputs. They were recorded
// from the hand-built fleet (v1.26.2) before it moved onto
// github.com/truvity/asg, so a test that compares the fleet with them is
// the proof that a stack's next preview replaces nothing.
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

func (m *resourceSetMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
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
