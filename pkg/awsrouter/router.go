// Package awsrouter provisions the EC2 half of a tailnet: an
// auto-scaling subnet router fleet — security group, IAM instance
// profile (SSM-managed, no SSH), launch template with cloud-init
// user data, and the ASG with an optional warm pool — reading its
// tagged auth key from an SSM parameter the tailnet stack wrote
// (pkg/tailnet NewRouterKey → the caller's SSM write).
//
// This is the ONE deliberately cloud-specific package in the module:
// everything else is provider-agnostic, an EC2 router is AWS by
// definition. Resource names derive from "{environment}-tailscale-
// {tailnet}", keyed by tailnet because two companies' fleets can share
// one VPC and AWS names are account-namespaced.
package awsrouter

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"text/template"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/autoscaling"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Standard AWS tag keys stamped on every resource the fleet owns.
const (
	TagName        = "Name"
	TagEnvironment = "Environment"
	TagManagedBy   = "ManagedBy"
	// TagValuePulumi marks resources this package manages.
	TagValuePulumi = "pulumi"

	// IAM policy document constants (trust and inline policies below).
	iamVersion    = "2012-10-17"
	iamKeyVersion = "Version"
	iamStatement  = "Statement"
	iamEffect     = "Effect"
	iamAllow      = "Allow"
	iamAction     = "Action"
	iamResource   = "Resource"
	iamService    = "Service"
)

//go:embed tailscale_userdata.yaml.gotmpl
var userDataTemplateContent string

const (
	// wireGuardPort is the UDP port used by Tailscale WireGuard.
	wireGuardPort = 41641

	// primaryInterface is the primary network interface on AL2023 EC2 instances.
	primaryInterface = "ens5"
)

type (
	// TailscaleInstanceConfig holds configuration for the Tailscale subnet router instance.
	TailscaleInstanceConfig struct {
		Environment   string
		Region        string
		VPCID         pulumi.IDOutput
		RouterSubnets []pulumi.IDOutput // Router (public) subnet IDs
		VPCCIDRs      []string          // All VPC CIDRs to advertise via --advertise-routes
		Min           int               // ASG MinSize (default 1 if 0)
		Desired       int               // ASG DesiredCapacity (default 1 if 0)
		Max           int               // ASG MaxSize (default desired+1 if 0)
		WarmPool      bool              // Enable warm pool (size = desired)

		// Tailnet is the company tailnet slug this router joins
		// (ADR-029). Required: every fleet is company-keyed, so two
		// companies' routers can share a VPC without colliding.
		Tailnet string
		// SSMAuthKeyPath is the auth-key parameter this fleet reads at
		// boot, written by the tailnet's tailscale-{company} stack.
		SSMAuthKeyPath string
		// PermissionsBoundaryName is the account-local IAM policy name
		// attached as the router role's permissions boundary — an
		// ESTATE convention, so it is an input. Empty: no boundary.
		PermissionsBoundaryName string
	}

	// TailscaleInstanceResult holds references to all created Tailscale instance resources.
	TailscaleInstanceResult struct {
		SecurityGroupID   pulumi.IDOutput
		InstanceProfileID pulumi.IDOutput
		LaunchTemplateID  pulumi.IDOutput
		ASGID             pulumi.IDOutput
	}

	// userDataParams holds template parameters for the Tailscale instance user-data script.
	userDataParams struct {
		Region            string // AWS region for SSM and EC2 API calls
		AdvertiseRoutes   string // Comma-separated VPC CIDRs for --advertise-routes
		SSMAuthKeyPath    string // SSM parameter path for the auth key
		WireGuardPort     int    // UDP port for Tailscale WireGuard
		PrimaryInterface  string // Primary network interface (ens5 on AL2023)
		ASGName           string // ASG name for lifecycle hook signal
		LifecycleHookName string // Lifecycle hook name for readiness signal
	}
)

// boundaryPtr renders the optional permissions boundary: nil when the
// estate configures none.
func boundaryPtr(arn string) pulumi.StringPtrInput {
	if arn == "" {
		return nil
	}

	return pulumi.StringPtr(arn)
}

// baseName is the AWS-visible name stem. These live in one shared AWS
// account namespace — two companies' fleets in the same VPC cannot both
// own the security group "devel-tailscale" — so every fleet is keyed.
func (c TailscaleInstanceConfig) baseName() string {
	return fmt.Sprintf("%s-tailscale-%s", c.Environment, c.Tailnet)
}

// CreateTailscaleInstance creates all resources for the Tailscale subnet router:
// security group, IAM role + instance profile, launch template, and ASG.
func CreateTailscaleInstance(
	c *pulumi.Context,
	logger *slog.Logger,
	awsProvider *aws.Provider,
	config TailscaleInstanceConfig,
) (*TailscaleInstanceResult, error) {
	ctx := c.Context()

	logger.InfoContext(ctx, "creating Tailscale subnet router instance",
		slog.String("environment", config.Environment),
		slog.String("region", config.Region),
		slog.Int("vpc_cidrs", len(config.VPCCIDRs)),
	)

	// ── Security Group ──────────────────────────────────────────────────
	sg, err := createTailscaleSG(c, awsProvider, config)
	if err != nil {
		return nil, err
	}

	// ── IAM Role + Instance Profile ─────────────────────────────────────
	instanceProfile, err := createTailscaleInstanceProfile(c, awsProvider, config)
	if err != nil {
		return nil, err
	}

	// ── Launch Template ─────────────────────────────────────────────────
	lt, err := createTailscaleLaunchTemplate(c, awsProvider, config, sg, instanceProfile)
	if err != nil {
		return nil, err
	}

	// ── Auto Scaling Group ──────────────────────────────────────────────
	asg, err := createTailscaleASG(c, awsProvider, config, lt)
	if err != nil {
		return nil, err
	}

	logger.InfoContext(ctx, "Tailscale subnet router instance created successfully",
		slog.String("environment", config.Environment),
	)

	return &TailscaleInstanceResult{
		SecurityGroupID:   sg.ID(),
		InstanceProfileID: instanceProfile.ID(),
		LaunchTemplateID:  lt.ID(),
		ASGID:             asg.ID(),
	}, nil
}

// ── Security Group ──────────────────────────────────────────────────────────

func createTailscaleSG(
	c *pulumi.Context,
	awsProvider *aws.Provider,
	config TailscaleInstanceConfig,
) (*ec2.SecurityGroup, error) {
	env := config.Environment

	sg, err := ec2.NewSecurityGroup(c, "tailscale-sg", &ec2.SecurityGroupArgs{
		Name:        pulumi.String(config.baseName()),
		Description: pulumi.String("Tailscale subnet router - WireGuard UDP ingress, SSM access"),
		VpcId:       config.VPCID.ToStringOutput(),
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName()),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale security group: %w", err)
	}

	// UDP 41641 from 0.0.0.0/0 — Tailscale WireGuard
	// TODO: Add IPv6 ingress rule (::/0 UDP 41641) when IPv6 transport is needed.
	_, err = ec2.NewSecurityGroupRule(c, "tailscale-sg-ingress-wireguard", &ec2.SecurityGroupRuleArgs{
		Type:            pulumi.String("ingress"),
		FromPort:        pulumi.Int(wireGuardPort),
		ToPort:          pulumi.Int(wireGuardPort),
		Protocol:        pulumi.String("udp"),
		CidrBlocks:      pulumi.StringArray{pulumi.String("0.0.0.0/0")},
		SecurityGroupId: sg.ID(),
		Description:     pulumi.String("Tailscale WireGuard"),
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale WireGuard ingress rule: %w", err)
	}

	// All outbound
	_, err = ec2.NewSecurityGroupRule(c, "tailscale-sg-egress-all", &ec2.SecurityGroupRuleArgs{
		Type:            pulumi.String("egress"),
		FromPort:        pulumi.Int(0),
		ToPort:          pulumi.Int(0),
		Protocol:        pulumi.String("-1"),
		CidrBlocks:      pulumi.StringArray{pulumi.String("0.0.0.0/0")},
		SecurityGroupId: sg.ID(),
		Description:     pulumi.String("All outbound"),
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale egress rule: %w", err)
	}

	return sg, nil
}

// ── IAM Role + Instance Profile ─────────────────────────────────────────────

func createTailscaleInstanceProfile(
	c *pulumi.Context,
	awsProvider *aws.Provider,
	config TailscaleInstanceConfig,
) (*iam.InstanceProfile, error) {
	env := config.Environment

	callerIdentity, err := aws.GetCallerIdentity(c, nil, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}

	// Permissions boundary: the estate's convention, by NAME — composed
	// against the fleet's own account.
	pbARN := ""
	if config.PermissionsBoundaryName != "" {
		pbARN = fmt.Sprintf("arn:aws:iam::%s:policy/%s", callerIdentity.AccountId, config.PermissionsBoundaryName)
	}

	// EC2 assume-role trust policy
	assumeRolePolicy, err := json.Marshal(map[string]any{
		iamKeyVersion: iamVersion,
		iamStatement: []map[string]any{{
			iamEffect:   iamAllow,
			"Principal": map[string]any{iamService: "ec2.amazonaws.com"},
			iamAction:   "sts:AssumeRole",
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal assume role policy: %w", err)
	}

	// SSM parameter read policy (for /tailscale/auth-key)
	ssmPolicy, err := json.Marshal(map[string]any{
		iamKeyVersion: iamVersion,
		iamStatement: []map[string]any{{
			iamEffect: iamAllow,
			iamAction: []string{
				"ssm:GetParameter",
				"ssm:GetParameters",
			},
			iamResource: fmt.Sprintf(
				"arn:aws:ssm:%s:%s:parameter%s",
				config.Region, callerIdentity.AccountId, config.SSMAuthKeyPath,
			),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal SSM policy: %w", err)
	}

	// KMS decrypt policy (for aws/ssm key — needed for SecureString)
	// Use key/* with ResourceAliases condition because IAM kms:Decrypt requires the actual key ARN, not an alias ARN.
	kmsPolicy, err := json.Marshal(map[string]any{
		iamKeyVersion: iamVersion,
		iamStatement: []map[string]any{{
			iamEffect:   iamAllow,
			iamAction:   []string{"kms:Decrypt"},
			iamResource: fmt.Sprintf("arn:aws:kms:%s:%s:key/*", config.Region, callerIdentity.AccountId),
			"Condition": map[string]any{
				"ForAnyValue:StringEquals": map[string]any{
					"kms:ResourceAliases": "alias/aws/ssm",
				},
			},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal KMS policy: %w", err)
	}

	// EC2 policy — disable source/dest check on self (required for subnet router).
	// Resource: "*" is intentional: ModifyInstanceAttribute runs in user-data before
	// ASG tags propagate, so tag-based conditions would cause AccessDenied.
	// DescribeInstances doesn't support resource-level restrictions.
	// The permissions boundary (when configured) limits blast radius at account level.
	ec2Policy, err := json.Marshal(map[string]any{
		iamKeyVersion: iamVersion,
		iamStatement: []map[string]any{{
			iamEffect: iamAllow,
			iamAction: []string{
				"ec2:ModifyInstanceAttribute",
				"ec2:DescribeInstances",
			},
			iamResource: "*",
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal EC2 policy: %w", err)
	}

	// ASG lifecycle hook policy — signal readiness after tailscale up
	asgPolicy, err := json.Marshal(map[string]any{
		iamKeyVersion: iamVersion,
		iamStatement: []map[string]any{{
			iamEffect: iamAllow,
			iamAction: []string{
				"autoscaling:CompleteLifecycleAction",
			},
			iamResource: fmt.Sprintf(
				"arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/%s",
				config.Region, callerIdentity.AccountId, config.baseName(),
			),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ASG policy: %w", err)
	}

	role, err := iam.NewRole(c, "tailscale-role", &iam.RoleArgs{
		Name:                pulumi.String(config.baseName()),
		AssumeRolePolicy:    pulumi.String(string(assumeRolePolicy)),
		PermissionsBoundary: boundaryPtr(pbARN),
		InlinePolicies: iam.RoleInlinePolicyArray{
			iam.RoleInlinePolicyArgs{
				Name:   pulumi.String("ssm-auth-key"),
				Policy: pulumi.String(string(ssmPolicy)),
			},
			iam.RoleInlinePolicyArgs{
				Name:   pulumi.String("kms-decrypt-ssm"),
				Policy: pulumi.String(string(kmsPolicy)),
			},
			iam.RoleInlinePolicyArgs{
				Name:   pulumi.String("ec2-source-dest-check"),
				Policy: pulumi.String(string(ec2Policy)),
			},
			iam.RoleInlinePolicyArgs{
				Name:   pulumi.String("asg-lifecycle-hook"),
				Policy: pulumi.String(string(asgPolicy)),
			},
		},
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName()),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale IAM role: %w", err)
	}

	// Attach AmazonSSMManagedInstanceCore managed policy (SSM Session Manager)
	_, err = iam.NewRolePolicyAttachment(c, "tailscale-role/ssm-core", &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("attach SSM managed policy: %w", err)
	}

	instanceProfile, err := iam.NewInstanceProfile(c, "tailscale-instance-profile", &iam.InstanceProfileArgs{
		Name: pulumi.String(config.baseName()),
		Role: role.Name,
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName()),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale instance profile: %w", err)
	}

	return instanceProfile, nil
}

// ── Launch Template ─────────────────────────────────────────────────────────

func createTailscaleLaunchTemplate(
	c *pulumi.Context,
	awsProvider *aws.Provider,
	config TailscaleInstanceConfig,
	sg *ec2.SecurityGroup,
	instanceProfile *iam.InstanceProfile,
) (*ec2.LaunchTemplate, error) {
	env := config.Environment

	// Look up latest Amazon Linux 2023 ARM64 AMI.
	// Using al2023-ami-* (not al2023-ami-minimal-*) because user-data needs AWS CLI
	// for ssm:GetParameter and ec2:ModifyInstanceAttribute.
	ami, err := ec2.LookupAmi(c, &ec2.LookupAmiArgs{
		Owners:     []string{"amazon"},
		MostRecent: pulumi.BoolRef(true),
		Filters: []ec2.GetAmiFilter{
			{Name: "name", Values: []string{"al2023-ami-*-arm64"}},
			{Name: "state", Values: []string{"available"}},
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("lookup AL2023 ARM64 AMI: %w", err)
	}

	// Build user-data script with dynamic VPC CIDRs and region
	userData := buildTailscaleUserData(config)
	userDataB64 := base64.StdEncoding.EncodeToString([]byte(userData))

	lt, err := ec2.NewLaunchTemplate(c, "tailscale-lt", &ec2.LaunchTemplateArgs{
		Name:                 pulumi.String(config.baseName()),
		UpdateDefaultVersion: pulumi.Bool(true),
		ImageId:              pulumi.String(ami.Id),
		// t4g.micro (1GB): t4g.nano's 512MB OOM-killed cloud-init during
		// first-boot dnf runs on current AL2023 (see tailscale_userdata
		// swap/no-upgrade notes) — 1GB + swap gives dnf real headroom.
		InstanceType: pulumi.String("t4g.micro"),
		UserData:     pulumi.String(userDataB64),
		IamInstanceProfile: ec2.LaunchTemplateIamInstanceProfileArgs{
			Arn: instanceProfile.Arn,
		},
		// Network interface — source/dest check is disabled via user-data after instance launch
		NetworkInterfaces: ec2.LaunchTemplateNetworkInterfaceArray{
			ec2.LaunchTemplateNetworkInterfaceArgs{
				AssociatePublicIpAddress: pulumi.String("true"),
				DeviceIndex:              pulumi.Int(0),
				SecurityGroups: pulumi.StringArray{
					sg.ID().ToStringOutput(),
				},
			},
		},
		MetadataOptions: ec2.LaunchTemplateMetadataOptionsArgs{
			HttpTokens:              pulumi.String("required"), // IMDSv2
			HttpEndpoint:            pulumi.String("enabled"),
			HttpPutResponseHopLimit: pulumi.Int(2),
		},
		TagSpecifications: ec2.LaunchTemplateTagSpecificationArray{
			ec2.LaunchTemplateTagSpecificationArgs{
				ResourceType: pulumi.String("instance"),
				Tags: pulumi.StringMap{
					TagName:        pulumi.String(config.baseName()),
					TagEnvironment: pulumi.String(env),
					TagManagedBy:   pulumi.String(TagValuePulumi),
				},
			},
		},
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName()),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale launch template: %w", err)
	}

	return lt, nil
}

func buildTailscaleUserData(config TailscaleInstanceConfig) string {
	routes := strings.Join(config.VPCCIDRs, ",")

	tmpl := template.Must(template.New("userdata").Parse(userDataTemplateContent))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, userDataParams{
		Region:            config.Region,
		AdvertiseRoutes:   routes,
		SSMAuthKeyPath:    config.SSMAuthKeyPath,
		WireGuardPort:     wireGuardPort,
		PrimaryInterface:  primaryInterface,
		ASGName:           config.baseName(),
		LifecycleHookName: config.baseName() + "-launch",
	}); err != nil {
		// Template is embedded and tested — panic is appropriate for a compile-time error.
		panic(fmt.Sprintf("render tailscale user-data template: %v", err))
	}

	return buf.String()
}

// ── Auto Scaling Group ──────────────────────────────────────────────────────

func createTailscaleASG(
	c *pulumi.Context,
	awsProvider *aws.Provider,
	config TailscaleInstanceConfig,
	lt *ec2.LaunchTemplate,
) (*autoscaling.Group, error) {
	env := config.Environment

	// Apply defaults for ASG sizing
	minSize := config.Min
	if minSize < 1 {
		minSize = 1
	}

	desired := config.Desired
	if desired < 1 {
		desired = 1
	}

	maxSize := config.Max
	if maxSize < desired {
		maxSize = desired + 1
	}

	// MinHealthyPercentage: 0 for single instance, 50 for 2+
	minHealthy := 0
	if desired > 1 {
		minHealthy = 50
	}

	// Convert subnet IDs to StringArray for VpcZoneIdentifiers
	subnetIDs := make(pulumi.StringArray, len(config.RouterSubnets))
	for i, id := range config.RouterSubnets {
		subnetIDs[i] = id.ToStringOutput()
	}

	asgArgs := &autoscaling.GroupArgs{
		Name:               pulumi.String(config.baseName()),
		MinSize:            pulumi.Int(minSize),
		MaxSize:            pulumi.Int(maxSize),
		DesiredCapacity:    pulumi.Int(desired),
		VpcZoneIdentifiers: subnetIDs,
		LaunchTemplate: autoscaling.GroupLaunchTemplateArgs{
			Id:      lt.ID(),
			Version: lt.LatestVersion.ApplyT(func(v int) string { return fmt.Sprintf("%d", v) }).(pulumi.StringOutput),
		},
		InstanceRefresh: autoscaling.GroupInstanceRefreshArgs{
			Strategy: pulumi.String("Rolling"),
			Preferences: autoscaling.GroupInstanceRefreshPreferencesArgs{
				MinHealthyPercentage: pulumi.Int(minHealthy),
				InstanceWarmup:       pulumi.String("300"), // 5 min — Tailscale needs time to connect and advertise routes
			},
			Triggers: pulumi.StringArray{
				pulumi.String("launch_template"),
			},
		},
		Tags: autoscaling.GroupTagArray{
			autoscaling.GroupTagArgs{
				Key:               pulumi.String(TagName),
				Value:             pulumi.String(config.baseName()),
				PropagateAtLaunch: pulumi.Bool(true),
			},
			autoscaling.GroupTagArgs{
				Key:               pulumi.String(TagEnvironment),
				Value:             pulumi.String(env),
				PropagateAtLaunch: pulumi.Bool(true),
			},
			autoscaling.GroupTagArgs{
				Key:               pulumi.String(TagManagedBy),
				Value:             pulumi.String(TagValuePulumi),
				PropagateAtLaunch: pulumi.Bool(true),
			},
		},
	}

	if config.WarmPool {
		asgArgs.WarmPool = autoscaling.GroupWarmPoolArgs{
			PoolState:                pulumi.String("Stopped"),
			MinSize:                  pulumi.Int(desired),
			MaxGroupPreparedCapacity: pulumi.Int(maxSize), // Cap at ASG max — no over-provisioning
		}
	}

	asg, err := autoscaling.NewGroup(c, "tailscale-asg", asgArgs, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale ASG: %w", err)
	}

	// Lifecycle hook — instance must signal readiness after tailscale up or get terminated.
	hookName := config.baseName() + "-launch"

	_, err = autoscaling.NewLifecycleHook(c, "tailscale-lifecycle-hook", &autoscaling.LifecycleHookArgs{
		Name:                 pulumi.String(hookName),
		AutoscalingGroupName: asg.Name,
		LifecycleTransition:  pulumi.String("autoscaling:EC2_INSTANCE_LAUNCHING"),
		// 15 minutes: first boot may reboot mid-cloud-init (AL2023 SELinux
		// kernel-cmdline apply) before the tailscale-join unit completes.
		HeartbeatTimeout: pulumi.Int(900),
		DefaultResult:    pulumi.String("ABANDON"),
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale ASG lifecycle hook: %w", err)
	}

	// CloudWatch alarms — Vanta compliance (Server CPU monitored) + instance health.
	// Temporary: will be replaced by VictoriaMetrics alerting (Phase 21+, INF-184).
	// TODO(INF-184): Add AlarmActions — SNS topics exist in root account (guardduty stack)
	// but cross-account alarm→SNS requires additional IAM setup. Defer to obs stack migration.
	_, err = cloudwatch.NewMetricAlarm(c, "tailscale-cpu-alarm", &cloudwatch.MetricAlarmArgs{
		Name:               pulumi.String(config.baseName() + "-cpu-high"),
		ComparisonOperator: pulumi.String("GreaterThanThreshold"),
		EvaluationPeriods:  pulumi.Int(3),
		MetricName:         pulumi.String("CPUUtilization"),
		Namespace:          pulumi.String("AWS/EC2"),
		Period:             pulumi.Int(300),
		Statistic:          pulumi.String("Average"),
		Threshold:          pulumi.Float64(90),
		AlarmDescription:   pulumi.String("Tailscale router CPU > 90% for 15 minutes"),
		Dimensions: pulumi.StringMap{
			"AutoScalingGroupName": asg.Name,
		},
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName() + "-cpu-high"),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale CPU alarm: %w", err)
	}

	_, err = cloudwatch.NewMetricAlarm(c, "tailscale-status-alarm", &cloudwatch.MetricAlarmArgs{
		Name:               pulumi.String(config.baseName() + "-status-check"),
		ComparisonOperator: pulumi.String("GreaterThanThreshold"),
		EvaluationPeriods:  pulumi.Int(2),
		MetricName:         pulumi.String("StatusCheckFailed"),
		Namespace:          pulumi.String("AWS/EC2"),
		Period:             pulumi.Int(60),
		Statistic:          pulumi.String("Maximum"),
		Threshold:          pulumi.Float64(0),
		AlarmDescription:   pulumi.String("Tailscale router instance status check failed"),
		Dimensions: pulumi.StringMap{
			"AutoScalingGroupName": asg.Name,
		},
		Tags: pulumi.StringMap{
			TagName:        pulumi.String(config.baseName() + "-status-check"),
			TagEnvironment: pulumi.String(env),
			TagManagedBy:   pulumi.String(TagValuePulumi),
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale status check alarm: %w", err)
	}

	return asg, nil
}
