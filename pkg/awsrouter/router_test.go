package awsrouter

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
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
	mu  sync.Mutex
	res map[string]resource.PropertyMap
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

	// Enough keys to satisfy every invoke this package makes today
	// (aws.GetCallerIdentity, ec2.LookupAmi); unused keys are ignored by
	// the caller's result struct.
	return resource.NewPropertyMapFromMap(map[string]interface{}{
		"id":        "ami-0123456789abcdef0",
		"accountId": "example-account",
		"arn":       "arn:aws:iam::example-account:root",
		"userId":    "AIDACKCEVSQ6C2EXAMPLE",
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
