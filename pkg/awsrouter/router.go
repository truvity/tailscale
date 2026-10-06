// Package awsrouter provisions the EC2 half of a tailnet: an
// auto-scaling subnet router fleet — security group, IAM instance
// profile (least privilege, no SSH key), launch template with cloud-init
// user data, and the ASG with an optional warm pool — reading its
// tagged auth key from an SSM parameter the caller wrote
// (pkg/tailnet NewRouterKey → the caller's SSM write).
//
// SSH is off by default: no key pair, no port in the security group.
// Two independent login paths turn it on, either alone or both:
// TrustedUserCAKeys and AuthorizedPrincipals admit OpenSSH user
// certificates from those CAs only (ssh.go), and OPKSSH admits OIDC
// sign-in via opkssh (opkssh.go). Either one gets the same lockdown —
// no static keys, no passwords, SSH over the tailnet interface only —
// so dropping one path never loosens the other. There is no other shell
// (no SSM Session Manager): break-glass is replacing the instance, and
// diagnosis is the serial console (`aws ec2 get-console-output`),
// where cloud-init and the join script log.
//
// This is the ONE deliberately cloud-specific package in the module:
// everything else is provider-agnostic, an EC2 router is AWS by
// definition. Resource names derive from "{environment}-tailscale-
// {tailnet}", keyed by tailnet because two tailnets' fleets can share
// one VPC and AWS names are account-namespaced.
package awsrouter

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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

	// DefaultRootVolumeSizeGiB is RootVolumeConfig.SizeGiB's default,
	// the standard AL2023 image's own size. Before v1.18.0 the image
	// lookup could resolve to an AL2023 "minimal" image, whose own root
	// volume is 2 GiB — too small for the packages, a swap file and the
	// journal; the explicit size keeps the disk independent of the image.
	DefaultRootVolumeSizeGiB = 8
	// MinRootVolumeSizeGiB is the smallest RootVolumeConfig.SizeGiB
	// accepted: the standard AL2023 image's snapshot is 8 GiB, and EC2
	// refuses a root volume smaller than its image's snapshot.
	MinRootVolumeSizeGiB = 8
	// DefaultRootVolumeType is RootVolumeConfig.Type's default.
	DefaultRootVolumeType = "gp3"

	// DefaultImageKernel is ImageConfig.Kernel's default: the kernel
	// line Amazon's own "kernel-default" AL2023 arm64 image carried when
	// this default was set. Amazon publishes every kernel line at the
	// same instant, so an unpinned lookup would pick among them at random.
	DefaultImageKernel = "6.18"
)

// imageKernelPattern is the shape ImageConfig.Kernel accepts: a
// "<major>.<minor>" kernel line, digits and one dot, so the name filter
// it lands in carries no wildcard of the caller's.
var imageKernelPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}$`)

// rootVolumeTypes are the EBS volume types RootVolumeConfig.Type
// accepts: the general-purpose SSD types. A router needs no
// provisioned IOPS.
var rootVolumeTypes = map[string]bool{"gp3": true, "gp2": true}

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

		// Tailnet is the slug of the tailnet this router joins.
		// Required: every fleet is keyed by its tailnet, so routers of
		// two tailnets can share a VPC without colliding.
		Tailnet string
		// ResourcePrefix is prepended to the Pulumi resource name of
		// every resource of the fleet ("tailscale-sg" becomes
		// ResourcePrefix+"tailscale-sg"), so the fleets of several
		// tailnets fit in one Pulumi stack. Empty (the default): the
		// names are exactly as before this input existed. It names
		// nothing in the cloud (the AWS names follow from Environment and
		// Tailnet), so a stack that changes it for an existing fleet
		// renames that fleet's resources in its state
		// (`pulumi state rename`) or gives them aliases, and replaces
		// nothing.
		ResourcePrefix string
		// SSMAuthKeyPath is the auth-key parameter this fleet reads at
		// boot, written by the caller that mints the tailnet's router
		// key (pkg/tailnet NewRouterKey).
		SSMAuthKeyPath string
		// PermissionsBoundaryName is the account-local IAM policy name
		// attached as the router role's permissions boundary — an
		// ESTATE convention, so it is an input. Empty: no boundary.
		PermissionsBoundaryName string

		// TrustedUserCAKeys are the OpenSSH user CA public keys sshd
		// trusts, one authorized_keys-format line each ("ssh-ed25519
		// AAAA..."). Two during a CA rotation, otherwise one. Empty (the
		// default): no certificate login — no CA trusted, no principals
		// file — and the user data renders exactly as it did before
		// these inputs existed; OPKSSH, if set, still gets the full SSH
		// lockdown on its own. Requires AuthorizedPrincipals.
		TrustedUserCAKeys []string
		// AuthorizedPrincipals maps a local login user to the
		// certificate principals that may log in as it, written to
		// /etc/ssh/authorized_principals/<user>. A certificate whose
		// principals name none of them is refused, even when a trusted
		// CA signed it; a user absent from the map accepts no
		// certificate at all. root is refused (PermitRootLogin no).
		// Requires TrustedUserCAKeys.
		AuthorizedPrincipals map[string][]string

		// OPKSSH configures optional OIDC sign-in via opkssh
		// (AuthorizedKeysCommand), with or without the certificate login
		// above — see opkssh.go. nil, or OPKSSH.Enabled false (the
		// default): the user data renders exactly as it did before this
		// input existed.
		OPKSSH *OPKSSHConfig

		// HostCert configures optional SSH host-certificate renewal via
		// truvity/openbao's cmd/openbao-hostcert — see hostcert.go. nil,
		// or HostCert.Enabled false (the default): the user data renders
		// exactly as it did before this input existed.
		HostCert *HostCertConfig

		// RouterSetupVersion is the truvity/tailscale release this
		// router's bootstrap downloads router-setup.sh from — normally
		// the exact version the caller's own go.mod pins (bootstrap.go).
		// Required: "X.Y.Z", no leading "v". The bootstrap fetches
		// https://github.com/truvity/tailscale/releases/download/vX.Y.Z/router-setup-vX.Y.Z.sh
		// and refuses to run it unless it matches
		// RouterSetupSHA256() — the sha256 of the copy embedded in
		// THIS build, which is byte-for-byte what that release
		// published (see bootstrap.go and docs/safety.md).
		RouterSetupVersion string

		// RootVolume sizes the router's root EBS volume. The zero value
		// is DefaultRootVolumeSizeGiB GiB of DefaultRootVolumeType. The
		// volume is always encrypted (with the account's default EBS
		// key) and deleted with the instance.
		RootVolume RootVolumeConfig

		// Image selects the router's Amazon Linux 2023 image. The zero
		// value is the newest standard (never minimal) arm64 image on
		// the DefaultImageKernel kernel line.
		Image ImageConfig
	}

	// ImageConfig selects the router's image within one family: Amazon's
	// standard Amazon Linux 2023 arm64 images (owner "amazon", name
	// "al2023-ami-2023.<release>-kernel-<Kernel>-arm64"). The minimal
	// images ("al2023-ami-minimal-…") lack the AWS CLI the join needs and
	// are never a match; neither are the ECS-optimized ones.
	ImageConfig struct {
		// Kernel is the AL2023 kernel line, "<major>.<minor>" (e.g.
		// "6.12"). Empty means DefaultImageKernel. A kernel line Amazon
		// does not publish fails the lookup at preview.
		Kernel string
	}

	// RootVolumeConfig is the router's root EBS volume, on the image's
	// own root device name. Before this input existed the volume was
	// the image's default size, 2 GiB on a minimal image.
	RootVolumeConfig struct {
		// SizeGiB is the volume size. 0 means DefaultRootVolumeSizeGiB;
		// anything else must be at least MinRootVolumeSizeGiB.
		SizeGiB int
		// Type is the EBS volume type, "gp3" or "gp2". Empty means
		// DefaultRootVolumeType.
		Type string
	}

	// TailscaleInstanceResult holds references to all created Tailscale instance resources.
	TailscaleInstanceResult struct {
		SecurityGroupID   pulumi.IDOutput
		InstanceProfileID pulumi.IDOutput
		LaunchTemplateID  pulumi.IDOutput
		ASGID             pulumi.IDOutput
	}

	// userDataParams holds template parameters for the Tailscale instance
	// bootstrap user-data (tailscale_userdata.yaml.gotmpl). The bulk of
	// what this used to render directly now lives in the version-pinned,
	// checksum-verified router-setup.sh it downloads — see bootstrap.go.
	userDataParams struct {
		Region            string           // AWS region for SSM and EC2 API calls
		AdvertiseRoutes   string           // Comma-separated VPC CIDRs for --advertise-routes
		SSMAuthKeyPath    string           // SSM parameter path for the auth key
		WireGuardPort     int              // UDP port for Tailscale WireGuard
		PrimaryInterface  string           // Primary network interface (ens5 on AL2023)
		ASGName           string           // ASG name for lifecycle hook signal
		LifecycleHookName string           // Lifecycle hook name for readiness signal
		SSHUserCA         *sshUserCAParams // nil: no certificate login (default)
		OPKSSH            *OPKSSHConfig    // nil: no opkssh sign-in (default)
		HostCert          *HostCertConfig  // nil: no host-certificate renewal (default)
		HostCertSHA256    string           // HostCert.ArtifactSHA256[hostCertArch]; empty when HostCert is nil
		// HostCertPrincipalPatterns is HostCert.PrincipalPatterns,
		// comma-joined (openbao-hostcert's own --principal-pattern env
		// var shape) — precomputed here rather than in the template,
		// which registers no join function.
		HostCertPrincipalPatterns string
		// HostCertCABundleLines is HostCert.CABundle split into lines,
		// so the template can render it the same range-based way
		// SSHUserCA.TrustedUserCAKeys is rendered. nil when CABundle is
		// empty.
		HostCertCABundleLines []string
		SetupScriptURL        string // where the bootstrap downloads router-setup.sh from
		SetupScriptSHA256     string // pinned digest; a mismatch is refused, fail closed
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

// sizeGiB is SizeGiB with its default applied.
func (v RootVolumeConfig) sizeGiB() int {
	if v.SizeGiB == 0 {
		return DefaultRootVolumeSizeGiB
	}

	return v.SizeGiB
}

// volumeType is Type with its default applied.
func (v RootVolumeConfig) volumeType() string {
	if v.Type == "" {
		return DefaultRootVolumeType
	}

	return v.Type
}

// validate refuses a root volume EC2 would refuse at launch (smaller
// than the image) or that this package does not mean to offer.
func (v RootVolumeConfig) validate() error {
	if v.SizeGiB != 0 && v.SizeGiB < MinRootVolumeSizeGiB {
		return fmt.Errorf("awsrouter: RootVolume.SizeGiB %d is below the minimum %d GiB", v.SizeGiB, MinRootVolumeSizeGiB)
	}

	if !rootVolumeTypes[v.volumeType()] {
		return fmt.Errorf("awsrouter: RootVolume.Type %q is not gp3 or gp2", v.Type)
	}

	return nil
}

// rootBlockDevice is the launch template's one block device mapping:
// the image's own root device, resized, encrypted and deleted with the
// instance. EC2 names the root device per image (/dev/xvda on AL2023),
// so the name comes from the image lookup, never a constant.
func rootBlockDevice(deviceName string, v RootVolumeConfig) (ec2.LaunchTemplateBlockDeviceMappingArray, error) {
	if deviceName == "" {
		return nil, errors.New("awsrouter: the AL2023 image lookup returned no root device name")
	}

	return ec2.LaunchTemplateBlockDeviceMappingArray{
		ec2.LaunchTemplateBlockDeviceMappingArgs{
			DeviceName: pulumi.String(deviceName),
			Ebs: ec2.LaunchTemplateBlockDeviceMappingEbsArgs{
				VolumeSize:          pulumi.Int(v.sizeGiB()),
				VolumeType:          pulumi.String(v.volumeType()),
				Encrypted:           pulumi.String("true"),
				DeleteOnTermination: pulumi.String("true"),
			},
		},
	}, nil
}

// kernel is Kernel with its default applied.
func (i ImageConfig) kernel() string {
	if i.Kernel == "" {
		return DefaultImageKernel
	}

	return i.Kernel
}

// nameFilter is the EC2 image name filter: the standard AL2023 family
// only. "al2023-ami-2023." is the standard images' own prefix — the
// minimal ("al2023-ami-minimal-…") and ECS ("al2023-ami-ecs-…") images
// never start with it — and the kernel suffix pins one kernel line.
func (i ImageConfig) nameFilter() string {
	return fmt.Sprintf("al2023-ami-2023.*-kernel-%s-arm64", i.kernel())
}

// validate refuses a kernel line that is not "<major>.<minor>": the
// value lands inside an EC2 name filter, where a "*" would widen the
// family again.
func (i ImageConfig) validate() error {
	if i.Kernel != "" && !imageKernelPattern.MatchString(i.Kernel) {
		return fmt.Errorf("awsrouter: Image.Kernel %q is not a <major>.<minor> kernel line", i.Kernel)
	}

	return nil
}

// baseName is the AWS-visible name stem. These live in one shared AWS
// account namespace — two tailnets' fleets in the same VPC cannot both
// own the security group "<environment>-tailscale" — so every fleet is
// keyed.
// resourceName is the Pulumi resource name of one of the fleet's
// resources: ResourcePrefix, then the resource's own name.
func (c TailscaleInstanceConfig) resourceName(name string) string {
	return c.ResourcePrefix + name
}

func (c TailscaleInstanceConfig) baseName() string {
	return InstanceRoleName(c.Environment, c.Tailnet)
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

	if err := config.validateSSHUserCA(); err != nil {
		return nil, err
	}

	if err := config.validateOPKSSH(); err != nil {
		return nil, err
	}

	if err := config.validateHostCert(); err != nil {
		return nil, err
	}

	if err := config.validateRouterSetupVersion(); err != nil {
		return nil, err
	}

	if err := config.RootVolume.validate(); err != nil {
		return nil, err
	}

	if err := config.Image.validate(); err != nil {
		return nil, err
	}

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

	sg, err := ec2.NewSecurityGroup(c, config.resourceName("tailscale-sg"), &ec2.SecurityGroupArgs{
		Name: pulumi.String(config.baseName()),
		// Historical wording ("SSM access"): a description change forces
		// AWS to replace the security group, so it stays as is.
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
	_, err = ec2.NewSecurityGroupRule(c, config.resourceName("tailscale-sg-ingress-wireguard"), &ec2.SecurityGroupRuleArgs{
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
	_, err = ec2.NewSecurityGroupRule(c, config.resourceName("tailscale-sg-egress-all"), &ec2.SecurityGroupRuleArgs{
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

	role, err := iam.NewRole(c, config.resourceName("tailscale-role"), &iam.RoleArgs{
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

	// No AmazonSSMManagedInstanceCore: it grants ssm:GetParameter(s) on
	// every parameter in the account (which, with kms-decrypt-ssm above,
	// reads every default-key SecureString) and routers run no Session
	// Manager shell. Break-glass is replacing the instance; diagnosis is
	// the serial console output (docs/safety.md, "Routers: access,
	// diagnosis and break-glass").

	instanceProfile, err := iam.NewInstanceProfile(c, config.resourceName("tailscale-instance-profile"), &iam.InstanceProfileArgs{
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

	// Look up the newest standard Amazon Linux 2023 ARM64 AMI on one
	// kernel line (see ImageConfig): never a minimal image, which lacks
	// the AWS CLI the join needs.
	ami, err := ec2.LookupAmi(c, &ec2.LookupAmiArgs{
		Owners:     []string{"amazon"},
		MostRecent: pulumi.BoolRef(true),
		Filters: []ec2.GetAmiFilter{
			{Name: "name", Values: []string{config.Image.nameFilter()}},
			{Name: "architecture", Values: []string{hostCertArch}},
			{Name: "state", Values: []string{"available"}},
		},
	}, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("lookup AL2023 ARM64 AMI: %w", err)
	}

	// Build user-data script with dynamic VPC CIDRs and region
	userData := buildTailscaleUserData(config)
	userDataB64 := base64.StdEncoding.EncodeToString([]byte(userData))

	blockDevices, err := rootBlockDevice(ami.RootDeviceName, config.RootVolume)
	if err != nil {
		return nil, err
	}

	lt, err := ec2.NewLaunchTemplate(c, config.resourceName("tailscale-lt"), &ec2.LaunchTemplateArgs{
		Name:                 pulumi.String(config.baseName()),
		UpdateDefaultVersion: pulumi.Bool(true),
		ImageId:              pulumi.String(ami.Id),
		// t4g.micro (1GB): t4g.nano's 512MB OOM-killed cloud-init during
		// first-boot dnf runs on current AL2023 (see tailscale_userdata
		// swap/no-upgrade notes) — 1GB + swap gives dnf real headroom.
		InstanceType: pulumi.String("t4g.micro"),
		UserData:     pulumi.String(userDataB64),
		// The root volume: sized here, not by the image (see
		// RootVolumeConfig).
		BlockDeviceMappings: blockDevices,
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
		Region:                    config.Region,
		AdvertiseRoutes:           routes,
		SSMAuthKeyPath:            config.SSMAuthKeyPath,
		WireGuardPort:             wireGuardPort,
		PrimaryInterface:          primaryInterface,
		ASGName:                   config.baseName(),
		LifecycleHookName:         config.baseName() + "-launch",
		SSHUserCA:                 config.sshUserCAParams(),
		OPKSSH:                    config.opksshParams(),
		HostCert:                  config.hostCertParams(),
		HostCertSHA256:            config.hostCertArtifactSHA256(),
		HostCertPrincipalPatterns: config.hostCertPrincipalPatterns(),
		HostCertCABundleLines:     config.hostCertCABundleLines(),
		SetupScriptURL:            RouterSetupURL(config.RouterSetupVersion),
		SetupScriptSHA256:         RouterSetupSHA256(),
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

	asg, err := autoscaling.NewGroup(c, config.resourceName("tailscale-asg"), asgArgs, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale ASG: %w", err)
	}

	// Lifecycle hook — instance must signal readiness after tailscale up or get terminated.
	hookName := config.baseName() + "-launch"

	_, err = autoscaling.NewLifecycleHook(c, config.resourceName("tailscale-lifecycle-hook"), &autoscaling.LifecycleHookArgs{
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

	// CloudWatch alarms: sustained high CPU and a failed instance status
	// check, so the router's CPU and health are monitored where AWS
	// records them. They carry no AlarmActions: where an alarm notifies
	// is the caller's decision, and an SNS topic in another account needs
	// cross-account IAM this module does not own. A caller routes them
	// from CloudWatch (or replaces them with its own alerting).
	_, err = cloudwatch.NewMetricAlarm(c, config.resourceName("tailscale-cpu-alarm"), &cloudwatch.MetricAlarmArgs{
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

	_, err = cloudwatch.NewMetricAlarm(c, config.resourceName("tailscale-status-alarm"), &cloudwatch.MetricAlarmArgs{
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
