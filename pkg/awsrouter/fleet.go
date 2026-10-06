package awsrouter

import (
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// NetworkTags says how the VPC and its public subnets are found: by the
	// tags their network stack put on them. A zero field is the default.
	NetworkTags struct {
		// EnvironmentKey names the tag whose value is the environment
		// (default "Environment").
		EnvironmentKey string
		// ManagedByKey and ManagedByValue select what the network stack
		// created (default "ManagedBy" = "pulumi").
		ManagedByKey   string
		ManagedByValue string
		// SubnetTypeKey and PublicValue select the public subnets
		// (default "Type" = "public").
		SubnetTypeKey string
		PublicValue   string
	}

	// FleetArgs is one router fleet in one environment, with the network
	// looked up rather than passed: a router stack runs after the network
	// stack and finds what it built by tag.
	FleetArgs struct {
		Environment string
		Region      string
		// VPCCIDR is the one CIDR the fleet advertises.
		VPCCIDR string
		Min     int
		Desired int
		Max     int
		// WarmPool enables a warm pool of the desired size.
		WarmPool bool

		// Tailnet and SSMAuthKeyPath select the tailnet the fleet joins and
		// the parameter it reads its auth key from at boot.
		Tailnet        string
		SSMAuthKeyPath string
		// ResourcePrefix is prepended to the fleet's Pulumi resource names,
		// so several tailnets' fleets fit in one stack (see
		// TailscaleInstanceConfig); empty keeps the names.
		ResourcePrefix string
		// PermissionsBoundaryName is the account-local IAM policy attached as
		// the router role's boundary; empty is none.
		PermissionsBoundaryName string
		// OPKSSH and HostCert are the optional sign-in and host-certificate
		// inputs (see NewOPKSSH and NewHostCert); nil is off.
		OPKSSH   *OPKSSHConfig
		HostCert *HostCertConfig
		// RouterSetupVersion is the release the bootstrap downloads
		// router-setup.sh from (see TailscaleInstanceConfig).
		RouterSetupVersion string

		Network NetworkTags
	}
)

func (t NetworkTags) withDefaults() NetworkTags {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}

	def(&t.EnvironmentKey, "Environment")
	def(&t.ManagedByKey, "ManagedBy")
	def(&t.ManagedByValue, "pulumi")
	def(&t.SubnetTypeKey, "Type")
	def(&t.PublicValue, "public")

	return t
}

// InstanceConfig is the TailscaleInstanceConfig for the fleet, once the
// network is known.
//
// No SSH user CA, deliberately: TrustedUserCAKeys and AuthorizedPrincipals
// stay empty, so sshd trusts no certificate authority and has no principals
// file. People sign in through opkssh alone; trusting a CA anyway would be a
// second root path.
func (a FleetArgs) InstanceConfig(vpcID pulumi.IDOutput, subnets []pulumi.IDOutput) TailscaleInstanceConfig {
	return TailscaleInstanceConfig{
		Environment:             a.Environment,
		Region:                  a.Region,
		VPCID:                   vpcID,
		RouterSubnets:           subnets,
		VPCCIDRs:                []string{a.VPCCIDR},
		Min:                     a.Min,
		Desired:                 a.Desired,
		Max:                     a.Max,
		WarmPool:                a.WarmPool,
		Tailnet:                 a.Tailnet,
		ResourcePrefix:          a.ResourcePrefix,
		SSMAuthKeyPath:          a.SSMAuthKeyPath,
		PermissionsBoundaryName: a.PermissionsBoundaryName,
		OPKSSH:                  a.OPKSSH,
		HostCert:                a.HostCert,
		RouterSetupVersion:      a.RouterSetupVersion,
	}
}

// DeployFleet looks up the environment's VPC and public subnets by tag and
// creates the router fleet in them.
func DeployFleet(ctx *pulumi.Context, logger *slog.Logger, provider *aws.Provider, args FleetArgs) error {
	goCtx := ctx.Context()
	tags := args.Network.withDefaults()

	logger.InfoContext(goCtx, "deploying Tailscale router",
		slog.String("environment", args.Environment),
		slog.String("tailnet", args.Tailnet),
		slog.String("cidr", args.VPCCIDR),
		slog.Int("desired", args.Desired),
		slog.Bool("opkssh", args.OPKSSH != nil),
		slog.Bool("host_cert", args.HostCert != nil),
	)

	vpc, err := ec2.LookupVpc(ctx, &ec2.LookupVpcArgs{
		Filters: []ec2.GetVpcFilter{
			{Name: "tag:" + tags.EnvironmentKey, Values: []string{args.Environment}},
			{Name: "tag:" + tags.ManagedByKey, Values: []string{tags.ManagedByValue}},
		},
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("lookup VPC for %s: %w", args.Environment, err)
	}

	public, err := ec2.GetSubnets(ctx, &ec2.GetSubnetsArgs{
		Filters: []ec2.GetSubnetsFilter{
			{Name: "vpc-id", Values: []string{vpc.Id}},
			{Name: "tag:" + tags.SubnetTypeKey, Values: []string{tags.PublicValue}},
			{Name: "tag:" + tags.ManagedByKey, Values: []string{tags.ManagedByValue}},
		},
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("lookup public subnets for %s: %w", args.Environment, err)
	}

	if len(public.Ids) == 0 {
		return fmt.Errorf("no public subnets found for %s", args.Environment)
	}

	subnets := make([]pulumi.IDOutput, len(public.Ids))
	for i, id := range public.Ids {
		subnets[i] = pulumi.ID(id).ToIDOutput()
	}

	if _, err := CreateTailscaleInstance(ctx, logger, provider, args.InstanceConfig(pulumi.ID(vpc.Id).ToIDOutput(), subnets)); err != nil {
		return fmt.Errorf("create tailscale instance: %w", err)
	}

	logger.InfoContext(goCtx, "Tailscale router deployed successfully", slog.String("environment", args.Environment))

	return nil
}
