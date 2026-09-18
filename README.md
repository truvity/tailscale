# tailscale

Tailscale for Kubernetes estates, as reusable mechanism: the subnet routers
and the DNS gateway that put a cluster on a tailnet, and the tailnet's policy,
keys and split DNS as code.

| Artifact | What | Status |
|---|---|---|
| `charts/tailscaled` | Subnet router: userspace `tailscaled` as a plain Deployment, advertising the CIDRs you name | shipped |
| `charts/tsdns` | Split-DNS gateway: CoreDNS on a pinned ClusterIP serving a tailnet-only suffix, plus forwarded zones | shipped |
| `pkg/acl` | Pure tailnet policy builder: tag ownership, two access tiers, per-environment route auto-approval, from a neutral model; deterministic JSON out | shipped |
| `pkg/tailnet` | Pulumi Go: the policy resource (sole owner), router auth keys (ephemeral, tagged, rotated by name), split DNS, S3 flow logs, a pinned service-IP helper | shipped |
| `pkg/awsrouter` | Pulumi Go: an EC2 auto-scaling subnet router fleet (security group, least-privilege role, launch template, ASG with optional warm pool), optional SSH user-certificate login; the one cloud-specific package | shipped |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag; the
Go module is `github.com/truvity/tailscale`.

## Who it is for

A platform team that runs Kubernetes and a Tailscale tailnet, and wants the
cluster's Services and its network reachable, and nameable, from the tailnet,
with who-reaches-what stated as data. It assumes a tailnet whose groups come
from its own directory sync, an OAuth client for the Tailscale Pulumi
provider, somewhere the estate keeps secrets, and, for `pkg/awsrouter`, an AWS
VPC with public subnets. The charts need nothing beyond Kubernetes: no
operator, no CRDs, no `NET_ADMIN`.

It deliberately does not install the Tailscale Kubernetes operator, the
OAuth client, a secret store, the VPC, or any NetworkPolicy. Keys leave the
Go packages as Pulumi Outputs and the caller stores them.

## The model

A **router** is a tailnet node that advertises routes: the EC2 fleet
(`pkg/awsrouter`) carries a network's VPC CIDR, and a cluster's own router
(`charts/tailscaled`) carries its Service CIDR. Each router has a **tag**, and
the **policy** (`pkg/acl`) says which directory groups reach which CIDRs,
which tag owns which, and which tag may advertise which route without a
person approving it. **Keys** (`pkg/tailnet`) are minted per tag after the
policy exists. The **DNS gateway** (`charts/tsdns`) makes the Services
nameable under a suffix that exists only on the tailnet.

```
tailnet client ──(split DNS: cluster.<name> → tsdns ClusterIP)──▶ tsdns ──▶ cluster resolver
       │
       ├──(route: Service CIDR)──▶ tailscaled (in the cluster) ──▶ Services
       └──(route: VPC CIDR)──────▶ EC2 router fleet ─────────────▶ nodes, VPC endpoints
```

`foo.bar.svc.cluster.<name>` resolves over the tailnet to a Service address
the cluster's router carries you to. The suffix is deliberately not the
cluster domain: those names resolve only over the tailnet, and two clusters
never collide.

## Install and a worked example

The tailnet side, in a Pulumi Go program (`go get github.com/truvity/tailscale@<tag>`):

```go
package main

import (
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/tailscale/pkg/acl"
	"github.com/truvity/tailscale/pkg/tailnet"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// The whole tailnet policy, from a model: one network with an EC2
		// router, one cluster with its own router.
		doc, err := acl.Build(acl.Policy{
			Networks: []acl.Network{
				{Name: "example", VPCCIDR: "10.0.0.0/16", RouterTag: "example-router"},
			},
			Clusters: []acl.Cluster{{
				Name:            "example", // router tag: k8s-example-router
				Network:         "example",
				ServiceCIDR:     "172.20.0.0/16",
				Member:          true,
				VPCGroups:       []string{"engineering@example.com"},
				InClusterGroups: []string{"operators@example.com"},
			}},
		})
		if err != nil {
			return err
		}

		policy, err := tailnet.NewACL(ctx, "tailnet-policy", doc)
		if err != nil {
			return err
		}

		// Rotation is the name: next month's apply mints a new key.
		key, err := tailnet.NewRouterKey(ctx,
			"k8s-example-router-"+tailnet.RotationSuffix(time.Now()),
			tailnet.RouterKeyArgs{Tag: "tag:k8s-example-router"},
			pulumi.DependsOn([]pulumi.Resource{policy}))
		if err != nil {
			return err
		}

		// A secret Output: store it wherever the estate keeps secrets, as
		// the Secret the tailscaled chart reads.
		ctx.Export("k8sRouterAuthKey", key.Key)

		// tsdns's pinned address: .0.53 of the Service CIDR.
		dnsIP, err := tailnet.ServiceIP("172.20.0.0/16", 53)
		if err != nil {
			return err
		}

		return tailnet.NewSplitDNS(ctx, "split-dns-example", "cluster.example", dnsIP)
	})
}
```

The cluster side, once the key is in a Secret named `tailscaled-auth-key`
(key `auth-key`) in the router's namespace:

```sh
helm install tailscaled oci://ghcr.io/truvity/charts/tailscaled --version <tag> \
  --namespace tailscale-router --values tailscaled-values.yaml
helm install tsdns oci://ghcr.io/truvity/charts/tsdns --version <tag> \
  --namespace tailscale-dns-system --values tsdns-values.yaml
```

```yaml
# tailscaled-values.yaml
# Both CIDRs: the policy above auto-approves them for tag:k8s-example-router.
advertiseRoutes: "172.20.0.0/16,10.0.0.0/16"
hostname: k8s-example-router
```

```yaml
# tsdns-values.yaml
suffix: cluster.example
clusterIP: 172.20.0.53     # the split-DNS entry above names it
resolverIP: 172.20.0.10    # the cluster's own resolver
```

A client in `operators@example.com` now resolves
`foo.bar.svc.cluster.example` and reaches the Service. The EC2 router fleet
for the VPC CIDR is the same pattern with `pkg/awsrouter`;
[docs/reference.md](docs/reference.md#pkgawsrouter) has the worked example.

## Documentation

- [docs/adoption.md](docs/adoption.md) — prerequisites, install order,
  adopting a tailnet and routers that already exist, the zero-diff gate, and
  what each upgrade changes
- [docs/safety.md](docs/safety.md) — every refusal and the failure it
  prevents, the defaults that replaced ones that failed, router break-glass
  and diagnosis
- [docs/reference.md](docs/reference.md) — every chart value, every Go input
  and output
- [docs/doctrine.md](docs/doctrine.md) — what this repository owns and what
  the consuming estate owns, and why the pieces are shaped as they are
- [CHANGELOG.md](CHANGELOG.md) — what changed for a consumer, per version

## The rule that makes this repository public

**Mechanism only.** Nothing here names a tailnet, a cluster, an account, a
CIDR or a secret path. Every such thing is an input with a neutral default,
and the consuming estate supplies it from its own (private) repository.
`hack/leak-canary.sh` enforces this in CI, and public history cannot be
unpublished, so the rule is mechanical, not remembered.

The same rule shapes the Go packages: credentials come in as a provider,
keys go out as Pulumi Outputs and the **caller** stores them. Everything is
cloud-agnostic except `pkg/awsrouter`, which is AWS by definition.

This repository follows the shared
[component contract](https://github.com/truvity/ci-workflows/blob/master/docs/component-contract.md).

## Status

Used in production by its maintainers. Releases are listed on the
[releases page](https://github.com/truvity/tailscale/releases).

## Development

```sh
devbox shell        # or direnv
just check          # build + lint + golden renders and Go tests + leak canary + govulncheck
just golden         # regenerate tests/golden after a template change — review the diff
UPDATE_GOLDEN=1 go test ./pkg/awsrouter/   # regenerate the router user-data goldens
```

`just --list` shows the rest (`fmt`, `tidy`, `package`, and each part of
`check` on its own). Every `tests/cases/<chart>/<case>/values.yaml` is
rendered and compared byte-for-byte with `tests/golden/<chart>/<case>.yaml`;
the router's cloud-init user data is pinned the same way under
`pkg/awsrouter/testdata/`.

`tests/invalid/<chart>/` holds one fixture per refusal. Each must fail to
render; `just lint` proves it. A rule without a fixture is a rule that will
quietly stop working.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub Release
and pushes both charts at that version — a chart's own `version` field is a
placeholder that never moves — and the same tag is the Go module's version.

Auto-release is present but not armed (`vars.AUTO_RELEASE` is unset), so
every release today is a manual tag. When armed it cuts **patches only**:
at once for a merged `security`-labelled pull request, weekly for
dependency bumps. Minors and majors are always manual, tagged when the
change merges and after its CHANGELOG heading.

## Licence

MIT — see [LICENSE](LICENSE).
