// Package tailnet wraps the Tailscale provider resources a Kubernetes
// estate's tailnet needs, with the conventions that make them safe to
// operate — thin by design: every resource is top-level and fully named
// by the caller (adopting an existing estate means zero URN churn), the
// provider comes in via pulumi.Provider, and secrets (auth keys) go out
// as Outputs for the caller to store.
//
// The conventions, each with its reason:
//
//   - The ACL resource OVERWRITES existing content: the stack is the
//     policy's sole owner, and every new tailnet starts from a
//     non-default document (the tagOwners bootstrap that lets its OAuth
//     client hold the manager tag), so a refuse-if-modified posture
//     would fail the very first apply.
//   - Router keys are reusable + ephemeral + preauthorized + tagged,
//     with a bounded expiry (default 90 days) — a leaked key's blast
//     radius is limited, at the cost that the stack must apply at least
//     once per expiry to mint fresh keys.
//   - Rotation is a NAME, not a clock inside resources:
//     RotationSuffix(t) renders YYYY-MM, the caller appends it to the
//     key's resource name, and Pulumi's replace-on-rename does the
//     rotation — same month, same name, no change.
//   - Keys are created AFTER the ACL (pass it via pulumi.DependsOn):
//     a key carrying a tag the policy does not yet own is refused.
package tailnet

import (
	"fmt"
	"net"
	"time"

	"github.com/pulumi/pulumi-tailscale/sdk/go/tailscale"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DefaultKeyExpiry bounds a router key's life. The stack must apply at
// least once inside the window or new enrollments stall until it does.
const DefaultKeyExpiry = 90 * 24 * time.Hour

// NewACL declares the tailnet's policy document (the JSON string
// pkg/acl builds, or any document the caller renders).
func NewACL(ctx *pulumi.Context, name, doc string, opts ...pulumi.ResourceOption) (*tailscale.Acl, error) {
	res, err := tailscale.NewAcl(ctx, name, &tailscale.AclArgs{
		Acl: pulumi.String(doc),
		// Sole-owner semantics — see the package comment.
		OverwriteExistingContent: pulumi.Bool(true),
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("tailnet acl %q: %w", name, err)
	}

	return res, nil
}

// RotationSuffix renders t as YYYY-MM: append it to a key's resource
// name and monthly rotation falls out of Pulumi's replace-on-rename.
func RotationSuffix(t time.Time) string {
	return fmt.Sprintf("%d-%02d", t.UTC().Year(), t.UTC().Month())
}

type (
	// RouterKeyArgs configures one subnet router's auth key.
	RouterKeyArgs struct {
		// Tag the key carries (with the "tag:" prefix). The tailnet
		// policy must own it — pass the ACL via pulumi.DependsOn.
		Tag string
		// Expiry bounds the key's life. Default: DefaultKeyExpiry.
		Expiry time.Duration
	}
)

// NewRouterKey mints a reusable, ephemeral, preauthorized, tagged auth
// key. The key VALUE is `key.Key` — a secret Output the caller stores
// wherever the estate keeps secrets.
func NewRouterKey(ctx *pulumi.Context, name string, args RouterKeyArgs, opts ...pulumi.ResourceOption) (*tailscale.TailnetKey, error) {
	if args.Tag == "" {
		return nil, fmt.Errorf("tailnet key %q: tag is required", name)
	}

	expiry := args.Expiry
	if expiry == 0 {
		expiry = DefaultKeyExpiry
	}

	key, err := tailscale.NewTailnetKey(ctx, name, &tailscale.TailnetKeyArgs{
		Reusable:      pulumi.Bool(true),
		Ephemeral:     pulumi.Bool(true),
		Preauthorized: pulumi.Bool(true),
		Tags:          pulumi.ToStringArray([]string{args.Tag}),
		Expiry:        pulumi.Int(int(expiry / time.Second)),
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("tailnet key %q: %w", name, err)
	}

	return key, nil
}

// NewSplitDNS points one domain at one resolver for every tailnet
// client (Tailscale split DNS).
func NewSplitDNS(ctx *pulumi.Context, name, domain, nameserver string, opts ...pulumi.ResourceOption) error {
	_, err := tailscale.NewDnsSplitNameservers(ctx, name, &tailscale.DnsSplitNameserversArgs{
		Domain:      pulumi.String(domain),
		Nameservers: pulumi.ToStringArray([]string{nameserver}),
	}, opts...)
	if err != nil {
		return fmt.Errorf("split dns %q (%s): %w", name, domain, err)
	}

	return nil
}

type (
	// S3FlowLogs configures network flow-log streaming to S3
	// (Tailscale Premium).
	S3FlowLogs struct {
		Bucket  string `json:"bucket" yaml:"bucket"`
		Region  string `json:"region" yaml:"region"`
		RoleARN string `json:"roleArn" yaml:"roleArn"`
	}
)

// NewS3FlowLogs streams the tailnet's network flow logs to an S3 bucket
// via an assumed role.
func NewS3FlowLogs(ctx *pulumi.Context, name string, cfg S3FlowLogs, opts ...pulumi.ResourceOption) error {
	if cfg.Bucket == "" || cfg.Region == "" || cfg.RoleARN == "" {
		return fmt.Errorf("flow logs %q: bucket, region and roleArn are all required", name)
	}

	_, err := tailscale.NewLogstreamConfiguration(ctx, name, &tailscale.LogstreamConfigurationArgs{
		LogType:              pulumi.String("network"),
		DestinationType:      pulumi.String("s3"),
		S3Bucket:             pulumi.String(cfg.Bucket),
		S3Region:             pulumi.String(cfg.Region),
		S3AuthenticationType: pulumi.String("rolearn"),
		S3RoleArn:            pulumi.StringPtr(cfg.RoleARN),
	}, opts...)
	if err != nil {
		return fmt.Errorf("flow logs %q: %w", name, err)
	}

	return nil
}

// ServiceIP returns base+offset inside a service CIDR — the pinned-IP
// conventions a tailnet leans on (a DNS gateway at .0.53, the cluster
// resolver at .0.10) without anyone hand-writing addresses.
func ServiceIP(serviceCIDR string, offset uint32) (string, error) {
	ip, ipNet, err := net.ParseCIDR(serviceCIDR)
	if err != nil {
		return "", fmt.Errorf("parse service cidr %q: %w", serviceCIDR, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("service cidr %q is not IPv4", serviceCIDR)
	}

	val := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]) + offset

	result := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	if !ipNet.Contains(result) {
		return "", fmt.Errorf("ip %s (offset %d) is outside service cidr %s", result, offset, serviceCIDR)
	}

	return result.String(), nil
}
