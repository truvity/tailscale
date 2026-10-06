package mesh

import (
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-tailscale/sdk/go/tailscale"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	pulumiconfig "github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"

	"github.com/truvity/tailscale/pkg/tailnet"
)

// FlowLogConfigNamespace is the Pulumi config namespace LoadFlowLogConfig
// reads: enableFlowLogs, flowLogBucket and flowLogRoleArn.
const FlowLogConfigNamespace = "tailscale-stack"

// FlowLogConfig holds a stack's configuration for Tailscale flow logs.
type FlowLogConfig struct {
	// Enabled turns on the log stream (requires a Premium plan).
	Enabled bool
	// Bucket is the S3 bucket flow logs land in, when enabled.
	Bucket string
	// RoleArn is the IAM role the stream authenticates to S3 as (rolearn
	// type), created in the account's own IAM stack.
	RoleArn string
}

// LoadFlowLogConfig reads the flow-log configuration from the stack's Pulumi
// config, refusing an enabled stream with no bucket or role.
func LoadFlowLogConfig(ctx *pulumi.Context) (FlowLogConfig, error) {
	cfg := pulumiconfig.New(ctx, FlowLogConfigNamespace)

	c := FlowLogConfig{
		Enabled: cfg.GetBool("enableFlowLogs"),
		Bucket:  cfg.Get("flowLogBucket"),
		RoleArn: cfg.Get("flowLogRoleArn"),
	}

	if c.Enabled {
		if c.Bucket == "" {
			return FlowLogConfig{}, fmt.Errorf("flowLogBucket is required when enableFlowLogs is true")
		}

		if c.RoleArn == "" {
			return FlowLogConfig{}, fmt.Errorf("flowLogRoleArn is required when enableFlowLogs is true")
		}
	}

	return c, nil
}

func (in Inputs) deployFlowLogs(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider) error {
	if !in.FlowLogs.Enabled {
		logger.InfoContext(ctx.Context(), "flow logs disabled (starter plan), skipping")

		return nil
	}

	if err := tailnet.NewS3FlowLogs(ctx, "flow-logs", tailnet.S3FlowLogs{
		Bucket:  in.FlowLogs.Bucket,
		Region:  in.Region,
		RoleARN: in.FlowLogs.RoleArn,
	}, pulumi.Provider(provider)); err != nil {
		return err
	}

	logger.InfoContext(ctx.Context(), "tailscale flow logs configured", slog.String("bucket", in.FlowLogs.Bucket))

	return nil
}
