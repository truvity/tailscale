package awsrouter

import (
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerGuardMocks fails any invoke (a Lookup*/Get* data-source call)
// made without an explicit provider reference. The SDK's ordinary mocks
// accept an unscoped invoke — it silently falls back to the ambient
// default provider — so a call site missing pulumi.Provider(...) passes
// every unit test and only fails at `pulumi preview`, on any estate
// that disables default providers. This guard turns that gap into a
// unit-test failure: see the "must pass its own provider" test below,
// and CHANGELOG.md.
type providerGuardMocks struct {
	mu    sync.Mutex
	res   map[string]resource.PropertyMap
	calls map[string]resource.PropertyMap // invoke token -> its arguments
}

func (m *providerGuardMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[args.TypeToken+"/"+args.Name] = args.Inputs

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *providerGuardMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Provider == "" {
		return nil, fmt.Errorf("invoke %q carries no explicit provider reference — pass pulumi.Provider(...) naming this package's provider", args.Token)
	}

	m.mu.Lock()
	if m.calls == nil {
		m.calls = map[string]resource.PropertyMap{}
	}
	m.calls[args.Token] = args.Args
	m.mu.Unlock()

	// Enough keys to satisfy every invoke this package makes today
	// (aws.GetCallerIdentity, ec2.LookupAmi); unused keys are ignored by
	// the caller's result struct.
	return resource.NewPropertyMapFromMap(map[string]interface{}{
		"id":             "ami-0123456789abcdef0",
		"rootDeviceName": "/dev/xvda",
		"accountId":      "example-account",
		"arn":            "arn:aws:iam::example-account:root",
		"userId":         "AIDACKCEVSQ6C2EXAMPLE",
	}), nil
}

// awsRouterTestConfig is exampleConfig with the VPC fields
// CreateTailscaleInstance needs (blank in exampleConfig because the
// user-data tests never touch resources).
func awsRouterTestConfig() TailscaleInstanceConfig {
	c := exampleConfig()
	c.VPCID = pulumi.ID("vpc-0123456789abcdef0").ToIDOutput()
	c.RouterSubnets = []pulumi.IDOutput{pulumi.ID("subnet-0123456789abcdef0").ToIDOutput()}

	return c
}

// TestCreateTailscaleInstanceInvokesAreScoped runs the package's full
// resource graph — including both invokes it makes (the caller-identity
// lookup in createTailscaleInstanceProfile and the AMI lookup in
// createTailscaleLaunchTemplate) — under providerGuardMocks. It must
// succeed: every invoke in this package passes the same explicit AWS
// provider its resources use.
func TestCreateTailscaleInstanceInvokesAreScoped(t *testing.T) {
	m := &providerGuardMocks{res: map[string]resource.PropertyMap{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{
			Region: pulumi.String("eu-west-1"),
		})
		if err != nil {
			return err
		}

		_, err = CreateTailscaleInstance(ctx, slog.Default(), provider, awsRouterTestConfig())

		return err
	}, pulumi.WithMocks("p", "s", m))

	require.NoError(t, err, "every invoke in pkg/awsrouter must pass pulumi.Provider(...) — an unscoped one only fails at preview time")
}

// runRouter runs CreateTailscaleInstance under providerGuardMocks and
// returns the recorded resource inputs.
func runRouter(t *testing.T, c TailscaleInstanceConfig) (map[string]resource.PropertyMap, error) {
	t.Helper()

	m := &providerGuardMocks{res: map[string]resource.PropertyMap{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{
			Region: pulumi.String("eu-west-1"),
		})
		if err != nil {
			return err
		}

		_, err = CreateTailscaleInstance(ctx, slog.Default(), provider, c)

		return err
	}, pulumi.WithMocks("p", "s", m))

	return m.res, err
}

// The launch template names the root volume explicitly, on the image's
// own root device: without it the volume is the image's default, 2 GiB
// on a minimal AL2023 image, which the swap file and the journal filled.
func TestLaunchTemplateRootVolume(t *testing.T) {
	cases := map[string]struct {
		volume   RootVolumeConfig
		wantSize float64
		wantType string
	}{
		"default":  {wantSize: 8, wantType: "gp3"},
		"override": {volume: RootVolumeConfig{SizeGiB: 16, Type: "gp2"}, wantSize: 16, wantType: "gp2"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := awsRouterTestConfig()
			c.RootVolume = tc.volume

			res, err := runRouter(t, c)
			require.NoError(t, err)

			lt, ok := res["aws:ec2/launchTemplate:LaunchTemplate/tailscale-lt"]
			require.True(t, ok, "launch template not recorded")

			mappings := lt["blockDeviceMappings"].ArrayValue()
			require.Len(t, mappings, 1)

			bdm := mappings[0].ObjectValue()
			assert.Equal(t, "/dev/xvda", bdm["deviceName"].StringValue(), "the image's own root device name")

			ebs := bdm["ebs"].ObjectValue()
			assert.InDelta(t, tc.wantSize, ebs["volumeSize"].NumberValue(), 0)
			assert.Equal(t, tc.wantType, ebs["volumeType"].StringValue())
			assert.Equal(t, "true", ebs["encrypted"].StringValue())
			assert.Equal(t, "true", ebs["deleteOnTermination"].StringValue())
		})
	}
}

func TestRootBlockDeviceNeedsADeviceName(t *testing.T) {
	_, err := rootBlockDevice("", RootVolumeConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root device name")
}

func TestValidateRootVolume(t *testing.T) {
	cases := map[string]struct {
		volume  RootVolumeConfig
		wantErr string
	}{
		"zero value":  {},
		"minimum":     {volume: RootVolumeConfig{SizeGiB: 8}},
		"larger gp2":  {volume: RootVolumeConfig{SizeGiB: 20, Type: "gp2"}},
		"below image": {volume: RootVolumeConfig{SizeGiB: 2}, wantErr: "below the minimum 8 GiB"},
		"negative":    {volume: RootVolumeConfig{SizeGiB: -1}, wantErr: "below the minimum"},
		"io2 refused": {volume: RootVolumeConfig{Type: "io2"}, wantErr: "is not gp3 or gp2"},
		"magnetic":    {volume: RootVolumeConfig{Type: "standard"}, wantErr: "is not gp3 or gp2"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.volume.validate()
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)

			c := awsRouterTestConfig()
			c.RootVolume = tc.volume
			_, runErr := runRouter(t, c)
			require.Error(t, runErr, "CreateTailscaleInstance must refuse it too")
		})
	}
}

// amiLookupArgs runs CreateTailscaleInstance and returns the arguments
// of its one AMI lookup.
func amiLookupArgs(t *testing.T, c TailscaleInstanceConfig) resource.PropertyMap {
	t.Helper()

	m := &providerGuardMocks{res: map[string]resource.PropertyMap{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		provider, err := aws.NewProvider(ctx, "aws", &aws.ProviderArgs{
			Region: pulumi.String("eu-west-1"),
		})
		if err != nil {
			return err
		}

		_, err = CreateTailscaleInstance(ctx, slog.Default(), provider, c)

		return err
	}, pulumi.WithMocks("p", "s", m))
	require.NoError(t, err)

	args, ok := m.calls["aws:ec2/getAmi:getAmi"]
	require.True(t, ok, "no AMI lookup recorded")

	return args
}

// amiFilters flattens the lookup's filters to name -> values.
func amiFilters(t *testing.T, args resource.PropertyMap) map[string][]string {
	t.Helper()

	out := map[string][]string{}

	for _, f := range args["filters"].ArrayValue() {
		obj := f.ObjectValue()

		var values []string
		for _, v := range obj["values"].ArrayValue() {
			values = append(values, v.StringValue())
		}

		out[obj["name"].StringValue()] = values
	}

	return out
}

// ec2NameMatches is EC2's name-filter wildcard semantics ("*" any run,
// "?" one character) for the names Amazon publishes, which carry no
// "/", "[" or "\\" — exactly path.Match's for them.
func ec2NameMatches(t *testing.T, pattern, name string) bool {
	t.Helper()

	ok, err := path.Match(pattern, name)
	require.NoError(t, err)

	return ok
}

// The lookup can only return a standard AL2023 arm64 image on one
// kernel line. Before v1.18.0 its "al2023-ami-*-arm64" matched the
// minimal and ECS images and every kernel line too, and "most recent"
// picked among them — routers rolled onto a 2 GiB minimal image.
func TestAMILookupIsTheStandardFamilyOnly(t *testing.T) {
	// Real Amazon image names, as describe-images lists them.
	standard618 := []string{
		"al2023-ami-2023.12.20260928.0-kernel-6.18-arm64",
		"al2023-ami-2023.12.20260918.0-kernel-6.18-arm64",
	}
	never := []string{
		"al2023-ami-minimal-2023.12.20260928.0-kernel-6.18-arm64",
		"al2023-ami-minimal-2023.12.20260928.0-kernel-6.12-arm64",
		"al2023-ami-minimal-2023.12.20260918.0-kernel-6.1-arm64",
		"al2023-ami-ecs-hvm-2023.0.20260922-kernel-6.1-arm64",
		"al2023-ami-2023.12.20260928.0-kernel-6.12-arm64",
		"al2023-ami-2023.12.20260928.0-kernel-6.1-arm64",
		"al2023-ami-2023.12.20260928.0-kernel-6.18-x86_64",
		"al2023-ami-minimal-2023.12.20260928.0-kernel-6.18-x86_64",
	}

	args := amiLookupArgs(t, awsRouterTestConfig())

	assert.Equal(t, []resource.PropertyValue{resource.NewStringProperty("amazon")}, args["owners"].ArrayValue())
	assert.True(t, args["mostRecent"].BoolValue())

	filters := amiFilters(t, args)
	assert.Equal(t, []string{"arm64"}, filters["architecture"])
	assert.Equal(t, []string{"available"}, filters["state"])
	require.Len(t, filters["name"], 1)

	pattern := filters["name"][0]
	assert.Equal(t, "al2023-ami-2023.*-kernel-6.18-arm64", pattern)

	for _, name := range standard618 {
		assert.True(t, ec2NameMatches(t, pattern, name), "must match %s", name)
	}

	for _, name := range never {
		assert.False(t, ec2NameMatches(t, pattern, name), "must never match %s", name)
	}

	assert.False(t, strings.Contains(pattern, "minimal"))
	assert.True(t, strings.HasPrefix(pattern, "al2023-ami-2023."),
		"the standard images' own prefix is what shuts out al2023-ami-minimal-*")
}

func TestAMILookupKernelOverride(t *testing.T) {
	c := awsRouterTestConfig()
	c.Image = ImageConfig{Kernel: "6.12"}

	pattern := amiFilters(t, amiLookupArgs(t, c))["name"][0]
	assert.Equal(t, "al2023-ami-2023.*-kernel-6.12-arm64", pattern)
	assert.True(t, ec2NameMatches(t, pattern, "al2023-ami-2023.12.20260928.0-kernel-6.12-arm64"))
	assert.False(t, ec2NameMatches(t, pattern, "al2023-ami-minimal-2023.12.20260928.0-kernel-6.12-arm64"))
	assert.False(t, ec2NameMatches(t, pattern, "al2023-ami-2023.12.20260928.0-kernel-6.18-arm64"))
}

func TestValidateImage(t *testing.T) {
	cases := map[string]struct {
		image   ImageConfig
		wantErr bool
	}{
		"zero value":      {},
		"6.1":             {image: ImageConfig{Kernel: "6.1"}},
		"6.12":            {image: ImageConfig{Kernel: "6.12"}},
		"wildcard":        {image: ImageConfig{Kernel: "*"}, wantErr: true},
		"widened":         {image: ImageConfig{Kernel: "6.*"}, wantErr: true},
		"single char":     {image: ImageConfig{Kernel: "6.?"}, wantErr: true},
		"minimal smuggle": {image: ImageConfig{Kernel: "6.18-arm64,al2023-ami-minimal"}, wantErr: true},
		"major only":      {image: ImageConfig{Kernel: "6"}, wantErr: true},
		"default word":    {image: ImageConfig{Kernel: "default"}, wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.image.validate()
			if !tc.wantErr {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), "is not a <major>.<minor> kernel line")

			c := awsRouterTestConfig()
			c.Image = tc.image
			_, runErr := runRouter(t, c)
			require.Error(t, runErr, "CreateTailscaleInstance must refuse it too")
		})
	}
}
