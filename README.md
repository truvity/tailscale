# tailscale

Tailscale for Kubernetes estates, as reusable mechanism:

| Artifact | What | Status |
| --- | --- | --- |
| `charts/tailscaled` | Subnet router — userspace `tailscaled` as a plain Deployment, advertising the CIDRs you name | shipped |
| `charts/tsdns` | Split-DNS gateway — CoreDNS on a pinned ClusterIP serving `cluster.<name>` plus forwarded zones | shipped |
| `pkg/acl` | Pure tailnet policy builder — tag ownership hierarchy, two access tiers, per-environment auto-approver isolation — from a neutral model; deterministic JSON out | shipped |
| `pkg/tailnet` | Pulumi Go: the ACL resource (sole-owner semantics), router auth keys (ephemeral+tagged, rotation-by-name), split DNS, S3 flow logs, pinned service-IP helper | shipped |
| `pkg/awsrouter` | Pulumi Go: an EC2 auto-scaling subnet router fleet — SG, SSM-only IAM profile (optional permissions boundary), launch template + user data, ASG with warm pool (the one cloud-specific package) | shipped |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag; the
Go module is `github.com/truvity/tailscale`.

## The rule that makes this repository public

**Mechanism only.** Nothing here names a tailnet, a cluster, a CIDR or a
secret path — every such thing is an input with a neutral default, and
the consuming estate supplies it from its own (private) repository.
`hack/leak-canary.sh` enforces this in CI; public history cannot be
unpublished, so the rule is mechanical, not remembered.

The same rule shapes the planned Go packages: credentials come in as a
provider, keys go out as Pulumi `Output`s and the **caller** stores them.
Everything is cloud-agnostic except `pkg/awsrouter`, which is AWS by
definition.

## How the two charts fit together

```
tailnet client ──(split DNS: cluster.<name> → tsdns ClusterIP)──▶ tsdns ──▶ cluster resolver
       │
       └──(routes: service CIDR, node CIDR)──▶ tailscaled subnet router ──▶ Services / nodes
```

`tailscaled` makes the cluster's CIDRs reachable; `tsdns` makes them
*nameable* — `foo.bar.svc.cluster.<name>` resolves over the tailnet to a
Service the router carries you to. The suffix is deliberately not the
cluster domain: those names resolve only over the tailnet, and two
clusters never collide.

## charts/tailscaled

```sh
helm install tailscaled oci://ghcr.io/truvity/charts/tailscaled --version <tag> \
  --namespace tailscale-router --create-namespace \
  --set advertiseRoutes="172.20.0.0/16,10.0.0.0/16" --set hostname=k8s-mycluster-router
```

| Value | Default | Notes |
| --- | --- | --- |
| `advertiseRoutes` | `""` | comma-separated CIDRs; auto-approve them in the tailnet policy for the router's tag |
| `hostname` | `""` | the router's tailnet name |
| `secretName` / `secretKey` | `tailscaled-auth-key` / `auth-key` | a reusable, pre-authorized, tagged auth key; the Secret is yours to create |
| `extraArgs` | `""` | appended to `TS_EXTRA_ARGS` |
| `replicaCount` | `2` | each replica is its own ephemeral tailnet node (no state write-back, no RBAC) |
| scheduling (`nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName`) | empty | the estate's |

Userspace networking (`TS_USERSPACE=true`): no `NET_ADMIN`, no tun device,
works on any CNI. Traffic for advertised routes is proxied by the process.

## charts/tsdns

```sh
helm install tsdns oci://ghcr.io/truvity/charts/tsdns --version <tag> \
  --namespace tailscale-dns-system --create-namespace \
  --set suffix=cluster.mycluster --set clusterIP=172.20.0.53 --set resolverIP=172.20.0.10
```

| Value | Default | Notes |
| --- | --- | --- |
| `suffix` | required | the tailnet-only name space, e.g. `cluster.mycluster` |
| `clusterIP` | required | pinned, inside the Service CIDR — the split-DNS entry names it |
| `resolverIP` | required | the in-cluster resolver the suffix is forwarded to |
| `clusterDomain` | `cluster.local` | rewrite target |
| `forwardZones` | `[]` | `[{zone, resolver}]` — zones the gateway can resolve but tailnet clients cannot (a private cloud API endpoint zone) |
| `image.repository` / `image.tag` | `registry.k8s.io/coredns/coredns` / pinned | point `repository` at a pull-through cache if the gateway must not depend on the internet |

Then add a Tailscale split-DNS nameserver for `<suffix>` → `<clusterIP>`,
restricted to the cluster's router tag (`pkg/tailnet`'s NewSplitDNS +
NewRouterKey are the Pulumi half of that wiring).

## Development

```sh
devbox shell        # or direnv
just check          # lint + golden renders + leak canary + go build/vuln
just golden         # regenerate tests/golden after a template change — review the diff
```

Every `tests/cases/<chart>/<case>/values.yaml` is rendered and compared
byte-for-byte with `tests/golden/<chart>/<case>.yaml`.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub
Release and pushes both charts at that version — a chart's own `version`
field is a placeholder that never moves.

## Licence

MIT — see [LICENSE](LICENSE).
