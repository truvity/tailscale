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
	// Enabled turns on the log stream (requires a plan that offers it, on
	// the account of the tailnet this configuration belongs to).
	Enabled bool
	// Bucket is the S3 bucket flow logs land in, when enabled.
	Bucket string
	// RoleArn is the IAM role the stream authenticates to S3 as (rolearn
	// type), created in the account's own IAM stack.
	RoleArn string
}

// LoadFlowLogConfig reads the flow-log configuration from the stack's Pulumi
// config, refusing an enabled stream with no bucket or role (the error names
// the stack; Inputs.Validate refuses the same, and a bucket without a role or
// the reverse, naming the tailnet). All keys unset yields the zero value.
func LoadFlowLogConfig(ctx *pulumi.Context) (FlowLogConfig, error) {
	cfg := pulumiconfig.New(ctx, FlowLogConfigNamespace)

	c := FlowLogConfig{
		Enabled: cfg.GetBool("enableFlowLogs"),
		Bucket:  cfg.Get("flowLogBucket"),
		RoleArn: cfg.Get("flowLogRoleArn"),
	}

	if c.Enabled {
		if c.Bucket == "" {
			return FlowLogConfig{}, fmt.Errorf("stack %s: flowLogBucket is required when enableFlowLogs is true", ctx.Stack())
		}

		if c.RoleArn == "" {
			return FlowLogConfig{}, fmt.Errorf("stack %s: flowLogRoleArn is required when enableFlowLogs is true", ctx.Stack())
		}
	}

	return c, nil
}

// checkFlowLogs refuses a flow-log configuration that would otherwise be
// skipped or fail late: a bucket without a role (or the reverse) is refused
// whether or not Enabled is set, since a half-set pair reads as configured
// and deploys nothing; an enabled stream also needs both and a region. The
// zero value passes. Every refusal names the tailnet.
func (in Inputs) checkFlowLogs() error {
	f := in.FlowLogs

	switch {
	case f.Bucket != "" && f.RoleArn == "":
		return fmt.Errorf("tailnet %s: flow logs name bucket %q but no role ARN", in.Tailnet.Name, f.Bucket)
	case f.Bucket == "" && f.RoleArn != "":
		return fmt.Errorf("tailnet %s: flow logs name a role ARN but no bucket", in.Tailnet.Name)
	case f.Enabled && f.Bucket == "":
		return fmt.Errorf("tailnet %s: flow logs are enabled but name no bucket and no role ARN", in.Tailnet.Name)
	case f.Enabled && in.Region == "":
		return fmt.Errorf("tailnet %s: flow logs are enabled but the bucket's region is empty", in.Tailnet.Name)
	}

	return nil
}

func (in Inputs) deployFlowLogs(ctx *pulumi.Context, logger *slog.Logger, provider *tailscale.Provider) error {
	if !in.FlowLogs.Enabled {
		logger.InfoContext(ctx.Context(), "flow logs not enabled, skipping", slog.String("tailnet", in.Tailnet.Name))

		return nil
	}

	if err := tailnet.NewS3FlowLogs(ctx, "flow-logs", tailnet.S3FlowLogs{
		Bucket:  in.FlowLogs.Bucket,
		Region:  in.Region,
		RoleARN: in.FlowLogs.RoleArn,
	}, pulumi.Provider(provider)); err != nil {
		return err
	}

	logger.InfoContext(ctx.Context(), "tailscale flow logs configured", slog.String("tailnet", in.Tailnet.Name), slog.String("bucket", in.FlowLogs.Bucket))

	return nil
}
