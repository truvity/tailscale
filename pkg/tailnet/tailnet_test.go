package tailnet

import (
	"sync"
	"testing"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mocks struct {
	mu  sync.Mutex
	res map[string]resource.PropertyMap
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[args.TypeToken+"/"+args.Name] = args.Inputs

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *mocks) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func run(t *testing.T, f func(ctx *pulumi.Context) error) *mocks {
	t.Helper()
	m := &mocks{res: map[string]resource.PropertyMap{}}
	require.NoError(t, pulumi.RunErr(f, pulumi.WithMocks("p", "s", m)))

	return m
}

func TestRotationSuffix(t *testing.T) {
	assert.Equal(t, "2026-08", RotationSuffix(time.Date(2026, 8, 23, 23, 59, 0, 0, time.UTC)))
	// Renders in UTC regardless of the input's zone.
	assert.Equal(t, "2026-09", RotationSuffix(time.Date(2026, 8, 31, 23, 0, 0, 0, time.FixedZone("x", -7200))))
}

func TestRouterKeyShape(t *testing.T) {
	m := run(t, func(ctx *pulumi.Context) error {
		_, err := NewRouterKey(ctx, "auth-key-devel-2026-08", RouterKeyArgs{Tag: "tag:devel-router"})
		return err
	})

	in := m.res["tailscale:index/tailnetKey:TailnetKey/auth-key-devel-2026-08"]
	require.NotNil(t, in)
	assert.True(t, in["reusable"].BoolValue())
	assert.True(t, in["ephemeral"].BoolValue())
	assert.True(t, in["preauthorized"].BoolValue())
	assert.Equal(t, float64(90*24*3600), in["expiry"].NumberValue())
	assert.Equal(t, "tag:devel-router", in["tags"].ArrayValue()[0].StringValue())
}

func TestRouterKeyRequiresTag(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := NewRouterKey(ctx, "x", RouterKeyArgs{})
		return err
	}, pulumi.WithMocks("p", "s", &mocks{res: map[string]resource.PropertyMap{}}))
	require.ErrorContains(t, err, "tag is required")
}

func TestACLOverwrites(t *testing.T) {
	m := run(t, func(ctx *pulumi.Context) error {
		_, err := NewACL(ctx, "acl", `{"acls":[]}`)
		return err
	})

	in := m.res["tailscale:index/acl:Acl/acl"]
	require.NotNil(t, in)
	assert.True(t, in["overwriteExistingContent"].BoolValue())
}

func TestSplitDNS(t *testing.T) {
	m := run(t, func(ctx *pulumi.Context) error {
		return NewSplitDNS(ctx, "dns-cluster.example", "cluster.example", "172.20.0.53")
	})

	in := m.res["tailscale:index/dnsSplitNameservers:DnsSplitNameservers/dns-cluster.example"]
	require.NotNil(t, in)
	assert.Equal(t, "cluster.example", in["domain"].StringValue())
	assert.Equal(t, "172.20.0.53", in["nameservers"].ArrayValue()[0].StringValue())
}

func TestS3FlowLogsValidates(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return NewS3FlowLogs(ctx, "flow-logs", S3FlowLogs{Bucket: "b"})
	}, pulumi.WithMocks("p", "s", &mocks{res: map[string]resource.PropertyMap{}}))
	require.ErrorContains(t, err, "all required")
}

func TestServiceIP(t *testing.T) {
	ip, err := ServiceIP("172.20.0.0/16", 53)
	require.NoError(t, err)
	assert.Equal(t, "172.20.0.53", ip)

	ip, err = ServiceIP("172.20.0.0/16", 10)
	require.NoError(t, err)
	assert.Equal(t, "172.20.0.10", ip)

	_, err = ServiceIP("172.20.0.0/30", 53)
	require.Error(t, err)

	_, err = ServiceIP("fd00::/64", 53)
	require.Error(t, err)
}
