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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"text/template"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/asg"
	"github.com/truvity/asg/bootstrap"
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

// rootVolume is the launch template's one block device mapping: the
// image's own root device, resized, encrypted and deleted with the
// instance (the library encrypts and deletes every volume). EC2 names the
// root device per image (/dev/xvda on AL2023), so the name comes from the
// image lookup, never a constant.
func rootVolume(deviceName string, v RootVolumeConfig) (*asg.RootVolumeArgs, error) {
	if deviceName == "" {
		return nil, errors.New("awsrouter: the AL2023 image lookup returned no root device name")
	}

	return &asg.RootVolumeArgs{DeviceName: deviceName, SizeGiB: v.sizeGiB(), Type: v.volumeType()}, nil
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
//
// The security group, the role and its profile, the launch template, the
// group and its launch hook are one github.com/truvity/asg box (fleetBox).
// Every resource keeps the logical name and the physical name it had before
// the library, so moving a stack onto this version replaces nothing. The
// two CloudWatch alarms the fleet used to have are gone: monitoring is the
// estate's own.
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

	callerIdentity, err := aws.GetCallerIdentity(c, nil, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}

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

	args, err := fleetBox(config, awsProvider, callerIdentity.AccountId, ami)
	if err != nil {
		return nil, err
	}

	box, err := asg.New(c, config.resourceName("tailscale"), args, pulumi.Provider(awsProvider))
	if err != nil {
		return nil, fmt.Errorf("create Tailscale router box: %w", err)
	}

	logger.InfoContext(ctx, "Tailscale subnet router instance created successfully",
		slog.String("environment", config.Environment),
	)

	return &TailscaleInstanceResult{
		SecurityGroupID:   box.SecurityGroup.ID(),
		InstanceProfileID: box.InstanceProfile.ID(),
		LaunchTemplateID:  box.LaunchTemplate.ID(),
		ASGID:             box.Group.ID(),
	}, nil
}

// fleetBox is the router fleet as a github.com/truvity/asg box. The Compat
// block keeps every resource where the hand-built fleet put it: no
// component (Flat), the old logical names, the instance-only launch tags
// and the compact trust policy. Everything else the library already
// declares the same way.
func fleetBox(config TailscaleInstanceConfig, awsProvider *aws.Provider, accountID string, ami *ec2.LookupAmiResult) (*asg.Args, error) {
	root, err := rootVolume(ami.RootDeviceName, config.RootVolume)
	if err != nil {
		return nil, err
	}

	userData, err := bootstrap.Verbatim(buildTailscaleUserData(config), 0)
	if err != nil {
		return nil, fmt.Errorf("tailscale user-data: %w", err)
	}

	policies, err := rolePolicies(config, accountID)
	if err != nil {
		return nil, err
	}

	// Permissions boundary: the estate's convention, by NAME — composed
	// against the fleet's own account.
	pbARN := ""
	if config.PermissionsBoundaryName != "" {
		pbARN = fmt.Sprintf("arn:aws:iam::%s:policy/%s", accountID, config.PermissionsBoundaryName)
	}

	sizes := config.sizes()
	publicIP := true

	subnetIDs := make([]pulumi.StringInput, len(config.RouterSubnets))
	for i, id := range config.RouterSubnets {
		subnetIDs[i] = id.ToStringOutput()
	}

	var warmPool *asg.WarmPoolArgs
	if config.WarmPool {
		// Capped at the group's maximum: no over-provisioning.
		maxPrepared := sizes.max
		warmPool = &asg.WarmPoolArgs{State: "Stopped", MinSize: sizes.desired, MaxGroupPreparedCapacity: &maxPrepared}
	}

	prefixed := config.resourceName

	return &asg.Args{
		Names: asg.Names{
			Base: config.baseName(),
			// The fixed name the security group has always had (the
			// library's default is a generated one).
			SecurityGroup: config.baseName(),
		},
		Tags:     map[string]string{TagEnvironment: config.Environment},
		Provider: awsProvider,
		UserData: userData,
		Image:    asg.ImageArgs{ID: pulumi.String(ami.Id)},
		Instance: asg.InstanceArgs{
			// t4g.micro (1GB): t4g.nano's 512MB OOM-killed cloud-init during
			// first-boot dnf runs on current AL2023 (see tailscale_userdata
			// swap/no-upgrade notes) — 1GB + swap gives dnf real headroom.
			Type: "t4g.micro",
			// IMDSv2 (the library always requires it) with the hop limit
			// the launch template has always had.
			HopLimit: 2,
			// The root volume: sized here, not by the image (see
			// RootVolumeConfig).
			RootVolume: root,
			// The source/destination check stays on, EC2's default: the router
			// masquerades what it forwards into the VPC (firewalld, set up by
			// router-setup.sh), so the VPC sees the router's own address, and
			// the role may not change the check.
			PublicIP: &publicIP,
		},
		Group: asg.GroupArgs{
			Min:       sizes.min,
			Max:       sizes.max,
			Desired:   sizes.desired,
			SubnetIDs: subnetIDs,
		},
		// The instance must signal readiness after tailscale up or get
		// terminated. 15 minutes: first boot may reboot mid-cloud-init
		// (AL2023 SELinux kernel-cmdline apply) before the tailscale-join
		// unit completes. A separate resource, as it always was.
		Hook:     &asg.HookArgs{Mode: asg.HookSeparate, HeartbeatTimeoutSeconds: 900, DefaultResult: "ABANDON"},
		WarmPool: warmPool,
		// A refresh launches the replacement router first and ends the old
		// one only after the replacement is InService, which it is only once
		// it has joined the tailnet and completed the launch hook: a VPC is
		// never without a router while the fleet restarts. No trigger is
		// named; Auto Scaling refreshes on every launch template version
		// anyway.
		Refresh: &asg.RefreshArgs{
			MinHealthyPercentage: refreshMinHealthyPercentage,
			MaxHealthyPercentage: refreshMaxHealthyPercentage,
			// 5 min — Tailscale needs time to connect and advertise routes.
			WarmupSeconds: 300,
		},
		IAM: asg.IAMArgs{
			PermissionsBoundary: pbARN,
			PolicyName:          policies[0].Name,
			Policy:              policies[0].Policy,
			ExtraInlinePolicies: policies[1:],
		},
		Security: asg.SecurityArgs{
			VPCID: config.VPCID.ToStringOutput(),
			// Historical wording ("SSM access"): a description change forces
			// AWS to replace the security group, so it stays as is.
			Description: "Tailscale subnet router - WireGuard UDP ingress, SSM access",
			Style:       asg.RulesLegacy,
			// UDP 41641 from 0.0.0.0/0 — Tailscale WireGuard.
			// TODO: Add IPv6 ingress rule (::/0 UDP 41641) when IPv6 transport is needed.
			Ingress: []asg.Rule{{
				Description: "Tailscale WireGuard",
				Protocol:    "udp",
				FromPort:    wireGuardPort,
				ToPort:      wireGuardPort,
				CIDRs:       []string{"0.0.0.0/0"},
				World:       true,
			}},
			Egress: []asg.Rule{{Description: "All outbound", Protocol: "-1", CIDRs: []string{"0.0.0.0/0"}}},
		},
		Compat: asg.Compat{
			Flat: true,
			Names: asg.Logical{
				Role:            prefixed("tailscale-role"),
				InstanceProfile: prefixed("tailscale-instance-profile"),
				SecurityGroup:   prefixed("tailscale-sg"),
				LaunchTemplate:  prefixed("tailscale-lt"),
				Group:           prefixed("tailscale-asg"),
				Hook:            prefixed("tailscale-lifecycle-hook"),
				Ingress:         func(int, int) string { return prefixed("tailscale-sg-ingress-wireguard") },
				Egress:          func(int, int) string { return prefixed("tailscale-sg-egress-all") },
			},
			LaunchTemplateTagTypes: []string{"instance"},
			AssumeRolePolicy:       assumeRolePolicy,
		},
	}, nil
}

// The rolling instance refresh keeps every router in service until its
// replacement is InService: it may launch up to twice the desired capacity
// before it ends an old router, and never drops below the desired capacity.
const (
	refreshMinHealthyPercentage = 100
	refreshMaxHealthyPercentage = 200
)

// fleetSizes is the group's sizing after this package's defaults.
type fleetSizes struct {
	min, desired, max int
}

// sizes applies the defaults. Max is at least Desired+1: a refresh that
// launches the replacement before it ends the old router needs room for one
// extra instance, and a group at its maximum could not start one. (The warm
// pool is sized from the maximum, so a Max equal to Desired also gains one
// stopped instance.)
func (c TailscaleInstanceConfig) sizes() fleetSizes {
	s := fleetSizes{min: max(c.Min, 1), desired: max(c.Desired, 1), max: c.Max}
	if s.max < s.desired+1 {
		s.max = s.desired + 1
	}

	return s
}

// assumeRolePolicy is the role's trust policy, compact, exactly as the
// role has carried it since before the library.
const assumeRolePolicy = `{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}],"Version":"2012-10-17"}`

// rolePolicies are the role's three inline policies, in their order. The
// first is the library's main policy; the documents are the same bytes the
// role has always carried.
func rolePolicies(config TailscaleInstanceConfig, accountID string) ([]asg.InlinePolicy, error) {
	doc := func(statement map[string]any) (string, error) {
		statement[iamEffect] = iamAllow

		b, err := json.Marshal(map[string]any{
			iamKeyVersion: iamVersion,
			iamStatement:  []map[string]any{statement},
		})

		return string(b), err
	}

	// SSM parameter read policy (for the auth key).
	ssmPolicy, err := doc(map[string]any{
		iamAction: []string{
			"ssm:GetParameter",
			"ssm:GetParameters",
		},
		iamResource: fmt.Sprintf(
			"arn:aws:ssm:%s:%s:parameter%s",
			config.Region, accountID, config.SSMAuthKeyPath,
		),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal SSM policy: %w", err)
	}

	// KMS decrypt policy (for aws/ssm key — needed for SecureString)
	// Use key/* with ResourceAliases condition because IAM kms:Decrypt requires the actual key ARN, not an alias ARN.
	kmsPolicy, err := doc(map[string]any{
		iamAction:   []string{"kms:Decrypt"},
		iamResource: fmt.Sprintf("arn:aws:kms:%s:%s:key/*", config.Region, accountID),
		"Condition": map[string]any{
			"ForAnyValue:StringEquals": map[string]any{
				"kms:ResourceAliases": "alias/aws/ssm",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal KMS policy: %w", err)
	}

	// ASG lifecycle hook policy — signal readiness after tailscale up
	asgPolicy, err := doc(map[string]any{
		iamAction: []string{
			"autoscaling:CompleteLifecycleAction",
		},
		iamResource: fmt.Sprintf(
			"arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/%s",
			config.Region, accountID, config.baseName(),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ASG policy: %w", err)
	}

	fixed := func(name, policy string) asg.InlinePolicy {
		return asg.InlinePolicy{Name: name, Policy: func(asg.PolicyContext) (string, error) { return policy, nil }}
	}

	// No AmazonSSMManagedInstanceCore: it grants ssm:GetParameter(s) on
	// every parameter in the account (which, with kms-decrypt-ssm above,
	// reads every default-key SecureString) and routers run no Session
	// Manager shell. Break-glass is replacing the instance; diagnosis is
	// the serial console output (docs/safety.md, "Routers: access,
	// diagnosis and break-glass").
	return []asg.InlinePolicy{
		fixed("ssm-auth-key", ssmPolicy),
		fixed("kms-decrypt-ssm", kmsPolicy),
		fixed("asg-lifecycle-hook", asgPolicy),
	}, nil
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
