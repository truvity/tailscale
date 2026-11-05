package awsrouter

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

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
		// VPCCIDR is the VPC's own CIDR, the first route the fleet advertises.
		VPCCIDR string
		// ExtraCIDRs are further routes the fleet advertises after VPCCIDR,
		// for example a peered VPC reachable from this one. Each must be a
		// CIDR that neither repeats nor overlaps VPCCIDR or another extra;
		// DeployFleet refuses the fleet otherwise. Empty, the default,
		// advertises VPCCIDR alone.
		ExtraCIDRs []string
		Min        int
		Desired    int
		Max        int
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

		// Subnets, when set, are subnets of the fleet's own, one per zone:
		// DeployFleet creates them in the VPC, gives them the route table of
		// the VPC's public subnets and runs the routers in them alone. A
		// router masquerades what it forwards into the VPC to its own
		// address, so the fleet's traffic then comes from these CIDRs only,
		// and a network policy can tell one tailnet's routers from another's
		// and from anything else in the public subnets. Changing them (or
		// setting them on a fleet that ran in the public subnets) replaces
		// the routers with an instance refresh, launch-first. Empty, the
		// default: the routers run in the VPC's public subnets, as before.
		// See ValidateSubnets for the rules.
		Subnets []FleetSubnet

		Network NetworkTags
	}

	// FleetSubnet is one zone's subnet of a fleet that runs in subnets of
	// its own (FleetArgs.Subnets).
	FleetSubnet struct {
		// AvailabilityZone is the zone's name, e.g. "eu-west-1a".
		AvailabilityZone string
		// CIDR is the subnet's IPv4 block, inside the VPC's CIDR and in
		// none of its other subnets: AWS refuses an overlap at apply time.
		// The smallest subnet AWS allows, a /28, holds 11 routers (AWS
		// keeps 5 addresses of every subnet): room for the desired
		// capacity, the warm pool and a refresh's extra router.
		CIDR string
	}
)

// RouterSubnetType is the value of the subnet type tag
// (NetworkTags.SubnetTypeKey) on the subnets DeployFleet creates for a fleet
// (FleetArgs.Subnets). It is not the public value on purpose: a lookup of
// the VPC's public subnets, this package's own or a load balancer
// controller's, does not find them.
const RouterSubnetType = "tailscale-router"

// subnetPrefixMin and subnetPrefixMax bound a fleet subnet's prefix length:
// AWS allows /16 to /28.
const (
	subnetPrefixMin = 16
	subnetPrefixMax = 28
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

// ValidateRoutes refuses ExtraCIDRs that are not CIDRs, or that repeat or
// overlap VPCCIDR or each other: two overlapping routes from one router are
// at best redundant and at worst a misconfigured peering.
func (a FleetArgs) ValidateRoutes() error {
	routes := append([]string{a.VPCCIDR}, a.ExtraCIDRs...)
	prefixes := make([]netip.Prefix, len(routes))

	for i, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("awsrouter: route %q is not a CIDR: %w", r, err)
		}

		for j := range i {
			if prefixes[j].Overlaps(p) {
				return fmt.Errorf("awsrouter: route %q overlaps %q", r, routes[j])
			}
		}

		prefixes[i] = p
	}

	return nil
}

// ValidateSubnets refuses Subnets that are not IPv4 CIDRs of /16 to /28
// inside VPCCIDR, that overlap each other, or that name a zone twice or no
// zone at all. Empty Subnets are valid: the fleet runs in the public
// subnets.
func (a FleetArgs) ValidateSubnets() error {
	if len(a.Subnets) == 0 {
		return nil
	}

	vpc, err := netip.ParsePrefix(a.VPCCIDR)
	if err != nil {
		return fmt.Errorf("awsrouter: VPC CIDR %q is not a CIDR: %w", a.VPCCIDR, err)
	}

	zones := map[string]bool{}
	prefixes := make([]netip.Prefix, len(a.Subnets))

	for i, sn := range a.Subnets {
		if sn.AvailabilityZone == "" {
			return fmt.Errorf("awsrouter: subnet %q names no availability zone", sn.CIDR)
		}

		if zones[sn.AvailabilityZone] {
			return fmt.Errorf("awsrouter: availability zone %q has two subnets", sn.AvailabilityZone)
		}

		zones[sn.AvailabilityZone] = true

		p, err := netip.ParsePrefix(sn.CIDR)
		if err != nil {
			return fmt.Errorf("awsrouter: subnet %q is not a CIDR: %w", sn.CIDR, err)
		}

		if !p.Addr().Is4() || p.Masked() != p {
			return fmt.Errorf("awsrouter: subnet %q is not an IPv4 network address", sn.CIDR)
		}

		if p.Bits() < subnetPrefixMin || p.Bits() > subnetPrefixMax {
			return fmt.Errorf("awsrouter: subnet %q: prefix length /%d is outside /%d to /%d", sn.CIDR, p.Bits(), subnetPrefixMin, subnetPrefixMax)
		}

		if p.Bits() < vpc.Bits() || !vpc.Contains(p.Addr()) {
			return fmt.Errorf("awsrouter: subnet %q is not inside the VPC CIDR %q", sn.CIDR, a.VPCCIDR)
		}

		for j := range i {
			if prefixes[j].Overlaps(p) {
				return fmt.Errorf("awsrouter: subnet %q overlaps %q", sn.CIDR, a.Subnets[j].CIDR)
			}
		}

		prefixes[i] = p
	}

	return nil
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
		VPCCIDRs:                append([]string{a.VPCCIDR}, a.ExtraCIDRs...),
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
// creates the router fleet in them, or, with FleetArgs.Subnets, in subnets
// of its own that it creates beside them.
func DeployFleet(ctx *pulumi.Context, logger *slog.Logger, provider *aws.Provider, args FleetArgs) error {
	goCtx := ctx.Context()
	tags := args.Network.withDefaults()

	if err := args.ValidateRoutes(); err != nil {
		return err
	}

	if err := args.ValidateSubnets(); err != nil {
		return err
	}

	logger.InfoContext(goCtx, "deploying Tailscale router",
		slog.String("environment", args.Environment),
		slog.String("tailnet", args.Tailnet),
		slog.String("cidr", args.VPCCIDR),
		slog.Any("extra_cidrs", args.ExtraCIDRs),
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

	if len(args.Subnets) > 0 {
		if subnets, err = createFleetSubnets(ctx, provider, args, tags, vpc.Id, public.Ids); err != nil {
			return err
		}
	}

	if _, err := CreateTailscaleInstance(ctx, logger, provider, args.InstanceConfig(pulumi.ID(vpc.Id).ToIDOutput(), subnets)); err != nil {
		return fmt.Errorf("create tailscale instance: %w", err)
	}

	logger.InfoContext(goCtx, "Tailscale router deployed successfully", slog.String("environment", args.Environment))

	return nil
}

// createFleetSubnets creates the fleet's own subnets (FleetArgs.Subnets),
// in zone order, each associated with the route table of the VPC's public
// subnets, and returns their IDs. The public subnets must share one route
// table, explicitly associated: the fleet's subnets get exactly the routes
// the routers had there (the internet gateway the routers reach the
// tailnet's coordination and relay servers through, and whatever else the
// network routes publicly). The subnets assign no public address of their
// own: the launch template gives each router one. They have no IPv6 block.
// Their network ACL is the VPC's default one, as for any subnet without an
// explicit association.
func createFleetSubnets(ctx *pulumi.Context, provider *aws.Provider, args FleetArgs, tags NetworkTags, vpcID string, publicIDs []string) ([]pulumi.IDOutput, error) {
	routeTable := ""

	for _, id := range slices.Sorted(slices.Values(publicIDs)) {
		subnetID := id

		rt, err := ec2.LookupRouteTable(ctx, &ec2.LookupRouteTableArgs{VpcId: &vpcID, SubnetId: &subnetID}, pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("lookup the route table of public subnet %s: %w", id, err)
		}

		if routeTable != "" && rt.RouteTableId != routeTable {
			return nil, fmt.Errorf("the public subnets of %s have more than one route table (%s, %s): a fleet's own subnets need the one they share",
				args.Environment, routeTable, rt.RouteTableId)
		}

		routeTable = rt.RouteTableId
	}

	cfg := args.InstanceConfig(pulumi.ID(vpcID).ToIDOutput(), nil)

	ordered := slices.SortedFunc(slices.Values(args.Subnets), func(a, b FleetSubnet) int {
		return strings.Compare(a.AvailabilityZone, b.AvailabilityZone)
	})

	ids := make([]pulumi.IDOutput, 0, len(ordered))

	for _, sn := range ordered {
		subnet, err := ec2.NewSubnet(ctx, cfg.resourceName("tailscale-subnet-"+sn.AvailabilityZone), &ec2.SubnetArgs{
			VpcId:               pulumi.String(vpcID),
			CidrBlock:           pulumi.String(sn.CIDR),
			AvailabilityZone:    pulumi.String(sn.AvailabilityZone),
			MapPublicIpOnLaunch: pulumi.Bool(false),
			Tags: pulumi.StringMap{
				TagName:             pulumi.String(cfg.baseName() + "-" + sn.AvailabilityZone),
				tags.EnvironmentKey: pulumi.String(args.Environment),
				tags.ManagedByKey:   pulumi.String(tags.ManagedByValue),
				tags.SubnetTypeKey:  pulumi.String(RouterSubnetType),
				TagTailnet:          pulumi.String(args.Tailnet),
			},
		}, pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("create router subnet %s (%s): %w", sn.CIDR, sn.AvailabilityZone, err)
		}

		if _, err := ec2.NewRouteTableAssociation(ctx, cfg.resourceName("tailscale-subnet-route-"+sn.AvailabilityZone), &ec2.RouteTableAssociationArgs{
			SubnetId:     subnet.ID(),
			RouteTableId: pulumi.String(routeTable),
		}, pulumi.Provider(provider)); err != nil {
			return nil, fmt.Errorf("associate router subnet %s with %s: %w", sn.CIDR, routeTable, err)
		}

		ids = append(ids, subnet.ID())
	}

	return ids, nil
}
