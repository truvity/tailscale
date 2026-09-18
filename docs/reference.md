# Reference

Every value of both charts and every input and output of the Go packages.
For the charts, `charts/<chart>/values.yaml` carries the same keys with their
defaults, and `values.schema.json` is the authority on types: an unknown key
fails the render. For the Go packages, the package documentation
(`go doc github.com/truvity/tailscale/pkg/<name>`) is the authority.

## tailscaled

A subnet router: one Deployment and, optionally, its ServiceAccount, both
named from the values below and placed in the release namespace. Userspace
networking (`TS_USERSPACE=true`): no `NET_ADMIN`, no tun device, works on any
CNI; traffic for the advertised routes is proxied by the process. Each
replica is its own ephemeral tailnet node: state lives in an `emptyDir`
(`TS_STATE_DIR=/tmp/tailscale-state`) and nothing is written back to a
Secret (`TS_KUBE_SECRET` is empty), so the pod needs no RBAC. `tailscale up`
always carries `--accept-dns=false`.

| Value | Default | Notes |
|---|---|---|
| `advertiseRoutes` | `""` | comma-separated CIDRs, `--advertise-routes`; auto-approve each for the router's tag in the tailnet policy |
| `hostname` | `""` | the router's tailnet name, `--hostname` |
| `extraArgs` | `""` | appended to `TS_EXTRA_ARGS` after the flags above |
| `secretName` | `tailscaled-auth-key` | the Secret holding the auth key, mounted read-only at `/secrets`; yours to create |
| `secretKey` | `auth-key` | the key inside it; passed as `TS_AUTH_KEY=file:/secrets/<secretKey>` |
| `replicaCount` | `2` | integer, `0` or more |
| `image.repository` | `tailscale/tailscale` | |
| `image.tag` | `stable` | a moving tag; pin a version to make the render say what runs |
| `image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `serviceAccount.create` | `true` | `false`: the pod uses an existing ServiceAccount of the same name |
| `serviceAccount.name` | `tailscaled` | non-empty |
| `serviceAccount.annotations` | `{}` | string values |
| `podAnnotations`, `podLabels` | `{}` | string values; `app.kubernetes.io/name: tailscaled` is always set and is the selector |
| `priorityClassName` | `""` | |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |
| `topologySpreadConstraints` | `[]` | |
| `resources` | requests `cpu: 10m`, `memory: 128Mi`; limit `memory: 512Mi` | no CPU limit on purpose; see [safety.md](safety.md#tailscaled-512mi-and-no-cpu-limit) |
| `global` | — | accepted and ignored, for umbrella charts |

The pod runs as UID/GID 65532, non-root, with the `RuntimeDefault` seccomp
profile, every capability dropped and no privilege escalation.

## tsdns

A split-DNS gateway: a ConfigMap with the Corefile, a Deployment of CoreDNS
and a ClusterIP Service, all named `tsdns`, in the release namespace. A
Corefile change rolls the pods (`checksum/corefile` annotation).

| Value | Default | Notes |
|---|---|---|
| `suffix` | *required* | the tailnet-only name space, e.g. `cluster.example`; `*.svc.<suffix>` is rewritten to `*.svc.<clusterDomain>` and forwarded to `resolverIP` |
| `clusterIP` | *required* | the Service's address, pinned inside the Service CIDR; the tailnet's split-DNS entry names it |
| `resolverIP` | *required* | the in-cluster resolver the suffix (and, with `catchAll`, everything else) is forwarded to |
| `clusterDomain` | `cluster.local` | the rewrite target |
| `forwardZones` | `[]` | `[{zone, resolver}]`, both required: zones the gateway can resolve but tailnet clients cannot, such as a cloud provider's private endpoint zone |
| `catchAll` | `false` | `true` adds a `.` block forwarding every other name to `resolverIP`, so a pod can use tsdns as its only nameserver; off, names outside the declared zones are refused |
| `debugLog` | `false` | per-query logging in every block, tagged `suffix-block`, `forwardzone-block` or `catchall-block`, with the rcode and the response flags; a log line per query |
| `replicas` | `2` | integer, `0` or more |
| `image.repository` | `registry.k8s.io/coredns/coredns` | point it at a pull-through cache if the gateway must not depend on the internet |
| `image.tag` | the pinned CoreDNS release (`values.yaml`) | |
| `image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `podAnnotations`, `podLabels` | `{}` | string values |
| `priorityClassName` | `""` | |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |
| `topologySpreadConstraints` | one, across `kubernetes.io/hostname`, `ScheduleAnyway` | replaced, not merged, when set |
| `resources` | requests `cpu: 20m`, `memory: 32Mi`; limit `memory: 128Mi` | |
| `global` | — | accepted and ignored |

Every block answers `errors` and caches for 30 seconds. The suffix block also
serves `health` on `:8080` (liveness), `ready` on `:8181` (readiness) and
`prometheus` on `:9153` (container port `metrics`). The container keeps only
`NET_BIND_SERVICE` and runs with a read-only root filesystem.

## pkg/acl

`acl.Build(acl.Policy) (string, error)` renders the whole tailnet policy
document — `tagOwners`, `acls`, `autoApprovers` — as indented JSON, the
string `tailnet.NewACL` takes. Input order never changes the output.
`Policy.Validate()` is called first; [safety.md](safety.md#pkgacl) lists what
it refuses.

### `Policy`

| Field | Default | Notes |
|---|---|---|
| `ManagerTag` | `infra-manager` (`acl.DefaultManagerTag`) | owned by `autogroup:admin`; owns every router tag. Scope the tailnet's OAuth client to this tag alone |
| `ExtraTagOwners` | none | `map[tag][]owner`, rendered verbatim; tags without the `tag:` prefix |
| `Networks` | none | one per network with an EC2 (or other) router |
| `Clusters` | none | members and non-members alike |

### `Network`

| Field | Notes |
|---|---|
| `Name` | required, unique; `Cluster.Network` refers to it |
| `VPCCIDR` | required; the VPC tier's destination, auto-approved for `RouterTag` |
| `RouterTag` | required; without the `tag:` prefix |

### `Cluster`

| Field | Notes |
|---|---|
| `Name` | required, unique |
| `Network` | the `Network.Name` the cluster lives on; must exist for a member |
| `ServiceCIDR` | the in-cluster tier's destination; empty means no in-cluster tier |
| `RouterTag` | overrides `k8s-<Name>-router` (without `tag:`) |
| `Member` | `true`: the cluster's own router joins this tailnet and gets its tag, rules and approvals. `false`: nothing of its own, but its `VPCGroups` still reach the network router |
| `VPCGroups` | directory group emails that reach the network's VPC CIDR and the routers on it |
| `InClusterGroups` | directory group emails that reach the Service CIDR |

### What it renders

For the model in the [README](../README.md#install-and-a-worked-example):

- `tagOwners`: the manager tag owned by `autogroup:admin`, every network
  router tag and every member cluster's router tag owned by the manager tag,
  plus `ExtraTagOwners`.
- `acls`, in this order: per member cluster, `VPCGroups` → `<VPCCIDR>:*` and
  `InClusterGroups` → `<ServiceCIDR>:*`; per network, every `VPCGroups` of any
  cluster on it (members and non-members, deduplicated) → `tag:<router>:*`,
  and the router tag → `autogroup:member:*` for return traffic; per member
  cluster, `VPCGroups` → its router tag, and its router tag →
  `autogroup:member:*`.
- `autoApprovers.routes`: each `VPCCIDR` for its network's router tag and for
  every member cluster's router on that network; each `ServiceCIDR` for its
  cluster's router tag.

No `ssh` section (that configures Tailscale SSH, which nothing here uses) and
no `groups` section (membership comes from directory sync).

## pkg/tailnet

Thin wrappers over the Tailscale Pulumi provider. Every resource is
top-level and named by the caller, and the provider comes in through
`pulumi.Provider(...)` in `opts`.

| Function | Creates | Notes |
|---|---|---|
| `NewACL(ctx, name, doc, opts...)` | `tailscale.Acl` | `OverwriteExistingContent: true`: the stack is the policy's sole owner |
| `NewRouterKey(ctx, name, RouterKeyArgs, opts...)` | `tailscale.TailnetKey` | reusable, ephemeral, preauthorized, carrying one tag. The key is `key.Key`, a secret Output the caller stores. Pass the ACL in `pulumi.DependsOn` |
| `NewSplitDNS(ctx, name, domain, nameserver, opts...)` | `tailscale.DnsSplitNameservers` | one domain to one nameserver, for every tailnet client |
| `NewS3FlowLogs(ctx, name, S3FlowLogs, opts...)` | `tailscale.LogstreamConfiguration` | network flow logs to S3 through an assumed role (a Tailscale plan feature) |
| `RotationSuffix(t)` | — | `YYYY-MM` in UTC; append it to a key's resource name and a new month's apply replaces the key |
| `ServiceIP(cidr, offset)` | — | the IPv4 address `offset` past the CIDR's base, refused if outside it: `ServiceIP("172.20.0.0/16", 53)` is `172.20.0.53` |

| Type | Field | Default | Notes |
|---|---|---|---|
| `RouterKeyArgs` | `Tag` | *required* | with the `tag:` prefix; the policy must own it |
| | `Expiry` | 90 days (`tailnet.DefaultKeyExpiry`) | the stack must apply at least once inside it |
| `S3FlowLogs` | `Bucket`, `Region`, `RoleARN` | *required*, all three | |

## pkg/awsrouter

`awsrouter.CreateTailscaleInstance(ctx, logger, awsProvider, config)`
creates one router fleet. Its AWS names are `<Environment>-tailscale-<Tailnet>`;
its Pulumi resource names are fixed (`tailscale-sg`, `tailscale-role`,
`tailscale-asg`, …), so a stack holds one fleet.

```go
func routerFleet(
	ctx *pulumi.Context,
	provider *aws.Provider,
	policy pulumi.Resource, // the tailnet.NewACL resource
	vpcID pulumi.IDOutput,
	publicSubnets []pulumi.IDOutput,
) error {
	key, err := tailnet.NewRouterKey(ctx,
		"example-router-"+tailnet.RotationSuffix(time.Now()),
		tailnet.RouterKeyArgs{Tag: "tag:example-router"},
		pulumi.DependsOn([]pulumi.Resource{policy}))
	if err != nil {
		return err
	}

	// The caller stores the key; the fleet reads it at boot. SecureString
	// under the default aws/ssm key: the router role may decrypt nothing else.
	const keyPath = "/example/tailscale/auth-key"
	if _, err := ssm.NewParameter(ctx, "example-router-auth-key", &ssm.ParameterArgs{
		Name:  pulumi.String(keyPath),
		Type:  pulumi.String("SecureString"),
		Value: key.Key,
	}, pulumi.Provider(provider)); err != nil {
		return err
	}

	_, err = awsrouter.CreateTailscaleInstance(ctx, slog.Default(), provider, awsrouter.TailscaleInstanceConfig{
		Environment:    "example",
		Region:         "eu-example-1",
		VPCID:          vpcID,
		RouterSubnets:  publicSubnets,
		VPCCIDRs:       []string{"10.0.0.0/16"},
		Desired:        2,
		WarmPool:       true,
		Tailnet:        "example",
		SSMAuthKeyPath: keyPath,

		// Optional: OpenSSH user-certificate login, over the tailnet only.
		TrustedUserCAKeys: []string{
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... example-user-ca", // your CA's public key
		},
		AuthorizedPrincipals: map[string][]string{
			"ec2-user": {"example-operator"},
		},
	})

	return err
}
```

(Imports: `log/slog`, `time`, `github.com/pulumi/pulumi-aws/sdk/v7/go/aws`,
`.../aws/ssm`, `github.com/pulumi/pulumi/sdk/v3/go/pulumi`, and this module's
`pkg/awsrouter` and `pkg/tailnet`.)

### `TailscaleInstanceConfig`

| Field | Default | Notes |
|---|---|---|
| `Environment` | *required* | first part of every AWS name; the `Environment` tag |
| `Tailnet` | *required* | the tailnet's slug, last part of every AWS name, so two tailnets' fleets can share a VPC and an account |
| `Region` | *required* | composes the IAM ARNs and the user data's `--region`; must be the provider's region |
| `VPCID` | *required* | the security group's VPC |
| `RouterSubnets` | *required* | the ASG's subnets; public, because each router gets a public address for direct WireGuard |
| `VPCCIDRs` | *required* | advertised with `--advertise-routes`, comma-joined |
| `SSMAuthKeyPath` | *required* | the SSM parameter holding the auth key, read at boot; a SecureString under the default `aws/ssm` key |
| `Min` | `1` | below 1 becomes 1 |
| `Desired` | `1` | below 1 becomes 1 |
| `Max` | `Desired + 1` | used when it is at least `Desired` |
| `WarmPool` | `false` | a warm pool of stopped, already-joined instances, `Desired` of them, capped at `Max` |
| `PermissionsBoundaryName` | `""` (none) | the name of an IAM policy in the fleet's own account, attached as the role's permissions boundary |
| `TrustedUserCAKeys` | empty (off) | OpenSSH user-CA public keys, one `authorized_keys`-format line each, written to `/etc/ssh/trusted-user-ca-keys.pub`. Requires `AuthorizedPrincipals` |
| `AuthorizedPrincipals` | empty (off) | login user → the certificate principals that may log in as it, written to `/etc/ssh/authorized_principals/<user>`. Requires `TrustedUserCAKeys` |

The result, `*TailscaleInstanceResult`, carries `SecurityGroupID`,
`InstanceProfileID`, `LaunchTemplateID` and `ASGID`.

### What it creates

| Resource | Shape |
|---|---|
| security group | ingress UDP 41641 (WireGuard) from anywhere, egress everything; **no TCP port** |
| IAM role and instance profile | trusted by EC2; four inline policies and nothing else: `ssm:GetParameter(s)` on the one `SSMAuthKeyPath` parameter; `kms:Decrypt` on keys aliased `alias/aws/ssm`; `ec2:ModifyInstanceAttribute` and `ec2:DescribeInstances` (to turn off the source/destination check on itself); `autoscaling:CompleteLifecycleAction` on its own ASG. No managed policy |
| launch template | the newest Amazon Linux 2023 arm64 image (see below), `t4g.micro`, a public address, IMDSv2 required with hop limit 2, the cloud-init user data; each change is a new default version |
| auto-scaling group | the sizes above; a rolling instance refresh on every launch-template change, keeping 0% healthy for one instance and 50% for more, with a 300-second warm-up; optional warm pool (`Stopped`) |
| lifecycle hook | `<name>-launch` on launch: a router is in service only after it has joined; no signal in 900 seconds abandons it |
| CloudWatch alarms | CPU above 90% for 15 minutes, and a failed status check; no actions attached |

### The image lookup

The launch template's image is resolved on every preview and update: owner
`amazon`, name `al2023-ami-*-arm64`, state `available`, most recent. The
family is fixed in code, not an input. When Amazon publishes a newer image
that matches, the next update writes a new launch-template version, and the
instance refresh replaces every router, one after another. Running routers
between updates patch themselves (below). See
[safety.md](safety.md#the-image-follows-the-newest-match) for what the name
pattern also matches.

### The user data

cloud-init, pinned by `pkg/awsrouter/testdata/userdata-default.yaml`:

- installs chrony (pinned to the Amazon Time Sync Service), audit (with watch
  rules on the identity and login files), dnf-automatic (applying updates),
  firewalld and a few diagnostic tools; a 1 GiB swap file; persistent
  journald;
- a nightly job applies updates and reboots when `needs-restarting -r` says so,
  after a random delay of up to two hours so a fleet does not reboot at once;
- firewalld: the primary interface in `public` with the WireGuard port and
  masquerading, `tailscale0` in `trusted`;
- `tailscale-join.sh`, run by a systemd unit and a cloud-final drop-in on every
  boot: installs Tailscale from its signed repository, reads the key from
  `SSMAuthKeyPath`, runs `tailscale up --advertise-routes=… --accept-dns=false`,
  turns off the source/destination check and completes the lifecycle action —
  retrying 20 times, 15 seconds apart. Its output goes to
  `/var/log/tailscale-join.log` and to the serial console.

With the SSH inputs set it also writes the CA keys, one principals file per
user and `/etc/ssh/sshd_config.d/10-user-ca.conf` (`PubkeyAuthentication yes`,
`PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
`AuthorizedKeysFile none`, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`,
`LogLevel VERBOSE`), removes `ssh` from the `public` zone so SSH arrives over
`tailscale0` only, and runs `sshd -t`. `PermitRootLogin no` is set in every
case. With neither input, the SSH inputs add nothing: the default user data
is byte-for-byte what it was before they existed.

EC2 refuses user data over 16 KiB; a test keeps the SSH variant, with two CA
keys and two users, 1 KiB under it.
