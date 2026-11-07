package mesh

import (
	"encoding/json"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFlowLogConfig(t *testing.T, cfg map[string]string) (FlowLogConfig, error) {
	t.Helper()

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	t.Setenv("PULUMI_CONFIG", string(raw))

	var got FlowLogConfig

	err = pulumi.RunErr(func(ctx *pulumi.Context) error {
		var err error

		got, err = LoadFlowLogConfig(ctx)

		return err
	}, pulumi.WithMocks("example", "tailnet-stack", &mocks{}))

	return got, err
}

func TestLoadFlowLogConfigUnsetIsTheZeroValue(t *testing.T) {
	got, err := loadFlowLogConfig(t, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, FlowLogConfig{}, got)
}

func TestLoadFlowLogConfigReadsAllThree(t *testing.T) {
	got, err := loadFlowLogConfig(t, map[string]string{
		"tailscale-stack:enableFlowLogs": "true",
		"tailscale-stack:flowLogBucket":  "b",
		"tailscale-stack:flowLogRoleArn": "arn:aws:iam::example:role/r",
	})
	require.NoError(t, err)
	assert.Equal(t, FlowLogConfig{Enabled: true, Bucket: "b", RoleArn: "arn:aws:iam::example:role/r"}, got)
}

func TestLoadFlowLogConfigRefusesEnabledWithoutBucketOrRoleNamingTheStack(t *testing.T) {
	_, err := loadFlowLogConfig(t, map[string]string{"tailscale-stack:enableFlowLogs": "true", "tailscale-stack:flowLogRoleArn": "r"})
	require.ErrorContains(t, err, "stack tailnet-stack: flowLogBucket is required")

	_, err = loadFlowLogConfig(t, map[string]string{"tailscale-stack:enableFlowLogs": "true", "tailscale-stack:flowLogBucket": "b"})
	require.ErrorContains(t, err, "stack tailnet-stack: flowLogRoleArn is required")
}
