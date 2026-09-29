# Reference

Every value of the chart and every input and output of the Go packages.
For the chart, `charts/tailscaled/values.yaml` carries the same keys with
their defaults, and `values.schema.json` is the authority on types: an
unknown key fails the render. For the Go packages, the package documentation
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
		// The truvity/tailscale release this router's bootstrap
		// downloads router-setup.sh from — normally the version this
		// go.mod pins.
		RouterSetupVersion: "1.11.0",

		// Optional: OpenSSH user-certificate login, over the tailnet only.
		TrustedUserCAKeys: []string{
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... example-user-ca", // your CA's public key
		},
		AuthorizedPrincipals: map[string][]string{
			"ec2-user": {"example-operator"},
		},

		// Optional: OIDC sign-in via opkssh, with or without the
		// certificate login above.
		OPKSSH: &awsrouter.OPKSSHConfig{
			Enabled:             true,
			ArtifactVersion:     "0.16.0",
			ArtifactURL:         "https://github.com/openpubkey/opkssh/releases/download/v0.16.0/opkssh-linux-arm64",
			ArtifactSHA256:      "...", // the release's sha256 for that binary
			SELinuxModuleURL:    "https://raw.githubusercontent.com/openpubkey/opkssh/v0.16.0/opkssh.te",
			SELinuxModuleSHA256: "...",
			Providers: []awsrouter.OPKSSHProvider{
				{Issuer: "https://access.example.com", ClientID: "opkssh", Expiration: "24h"},
			},
			AuthorizedIdentities: []awsrouter.OPKSSHAuthID{
				{User: "ec2-user", Group: "ssh-admins", Issuer: "https://access.example.com"},
			},
		},

		// Optional: SSH host-certificate renewal via truvity/openbao's
		// cmd/openbao-hostcert.
		HostCert: &awsrouter.HostCertConfig{
			Enabled:         true,
			ArtifactVersion: "0.13.0",
			ArtifactSHA256:  map[string]string{"arm64": "..."}, // that release's sha256 for openbao-hostcert_0.13.0_linux_arm64.tar.gz
			Address:         "https://openbao.example.internal",
			Namespace:       "example",
			AuthMount:       "aws",
			AuthRole:        "router-host",
			ServerIDHeader:  "example-openbao-aws-host",
			SSHMount:        "ssh-host",
			SSHRole:         "router",
			PrincipalPatterns: []string{
				"ip-10-0-*.tailnet.example.ts.net", // this fleet's own VPC CIDR, never the whole tailnet
			},
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
| `TrustedUserCAKeys` | empty (off) | OpenSSH user-CA public keys, one `authorized_keys`-format line each, written to `/etc/ssh/trusted-user-ca-keys.pub`. Requires `AuthorizedPrincipals`. Empty with `OPKSSH` set: no CA trusted, the same SSH lockdown |
| `AuthorizedPrincipals` | empty (off) | login user → the certificate principals that may log in as it, written to `/etc/ssh/authorized_principals/<user>`. Requires `TrustedUserCAKeys` |
| `OPKSSH` | `nil` (off) | optional OIDC sign-in via [opkssh](https://github.com/openpubkey/opkssh), with or without `TrustedUserCAKeys`/`AuthorizedPrincipals` — see `OPKSSHConfig` below |
| `HostCert` | `nil` (off) | optional SSH host-certificate renewal via [truvity/openbao](https://github.com/truvity/openbao)'s `cmd/openbao-hostcert`, additive to everything above — see `HostCertConfig` below |
| `RouterSetupVersion` | *required* | `"X.Y.Z"` (no leading `v`) — the truvity/tailscale release the bootstrap downloads `router-setup.sh` from; normally the version this `go.mod` pins |
| `RootVolume` | 8 GiB `gp3` | `RootVolumeConfig{SizeGiB, Type}`: the root EBS volume, on the image's own root device name, always encrypted (the account's default EBS key) and deleted with the instance. `SizeGiB` 0 is 8, otherwise at least 8 (the standard AL2023 image's own snapshot size); `Type` empty is `gp3`, otherwise `gp3` or `gp2` |

### `OPKSSHConfig`

`nil`, or `Enabled: false`, is the default: opkssh is off and the user data
is byte-for-byte what it would be without this input. Set `Enabled: true`
once every other field is populated, so a caller can stage the rollout
ahead of flipping the one field that turns it on.

| Field | Notes |
|---|---|
| `Enabled` | off by default |
| `ArtifactVersion` | the opkssh release, e.g. `"0.16.0"` — recorded in `/var/log/opkssh.log`'s install line |
| `ArtifactURL`, `ArtifactSHA256` | the opkssh binary for this fleet's AMI architecture (AL2023 ARM64 — this package is ARM64-only, see "The image lookup" below); a sha256 mismatch aborts the install |
| `SELinuxModuleURL`, `SELinuxModuleSHA256` | `opkssh.te` at the same tag — AL2023 runs SELinux enforcing and this module ships in neither the binary nor the rpm |
| `Providers` | `[]OPKSSHProvider{Issuer, ClientID, Expiration}` — one `/etc/opk/providers` line each, in order. `Issuer` must be an absolute `https://` URL; `ClientID` and `Expiration` must be plain tokens (no whitespace or shell metacharacters); `Expiration` must be one of opkssh's own policies (`12h`, `24h`, `48h`, `1week`, `oidc`, `oidc-refreshed`) |
| `AuthorizedIdentities` | `[]OPKSSHAuthID{User, Group, Issuer}` — one `/etc/opk/auth_id` line each, in order, admitting `User` to sign in as `oidc:groups:Group` when `Issuer` signed the ID token. `User` must be a plain login name and not `root`; `Group` must be a plain token (no whitespace or shell metacharacters — refused outright, never escaped); `Issuer` must be one of `Providers`' issuers |

### `HostCertConfig`

`nil`, or `Enabled: false`, is the default: host-certificate renewal is off
and the user data is byte-for-byte what it would be without this input. Set
`Enabled: true` once every other field is populated, the same staged-rollout
convention `OPKSSHConfig` takes.

| Field | Notes |
|---|---|
| `Enabled` | off by default |
| `ArtifactVersion` | the truvity/openbao release, e.g. `"0.13.0"` (no leading `v`) — the same shape `RouterSetupVersion` takes |
| `ArtifactSHA256` | `map[string]string`, keyed by `GOARCH` (`"arm64"`, ...) — the `openbao-hostcert_<version>_linux_<arch>.tar.gz` archive's sha256. This package deploys `arm64` only (see "The image lookup" above), so only that key is ever read; a missing or malformed entry for it is refused |
| `Address` | the OpenBAO server's URL — an absolute `https://` URL with no trailing slash |
| `CABundle` | a PEM certificate bundle to trust beyond AL2023's OS roots; empty is the OS trust store alone. When set, must parse as a real PEM certificate |
| `Namespace` | the OpenBAO namespace the AWS IAM login and the sign call are both made in; empty is root |
| `AuthMount`, `AuthRole` | the AWS IAM auth mount's path and the role this router's instance role ARN is bound to (server-side, not this package's business — these only have to match it) |
| `ServerIDHeader` | the mount's pinned `iam_server_id_header_value`, exactly |
| `SSHMount`, `SSHRole` | the SSH host-CA mount and role the certificate is signed with |
| `PrincipalPatterns` | `[]string`, `path.Match` globs — `openbao-hostcert`'s own `--principal-pattern`, refusing to even request a principal outside them (defense in depth: OpenBAO's SSH secrets engine cannot restrict a host role's domain by CIDR or glob — see [safety.md](safety.md#host-certificate-renewal-the-principal-pattern-is-the-real-boundary)). Required; a pattern may not be empty or a bare `"*"` |

Every field is a plain token (no whitespace or shell metacharacters — refused
outright, never escaped), the same discipline `OPKSSHConfig`'s tokens take.

The result, `*TailscaleInstanceResult`, carries `SecurityGroupID`,
`InstanceProfileID`, `LaunchTemplateID` and `ASGID`.

### What it creates

| Resource | Shape |
|---|---|
| security group | ingress UDP 41641 (WireGuard) from anywhere, egress everything; **no TCP port** |
| IAM role and instance profile | trusted by EC2; four inline policies and nothing else: `ssm:GetParameter(s)` on the one `SSMAuthKeyPath` parameter; `kms:Decrypt` on keys aliased `alias/aws/ssm`; `ec2:ModifyInstanceAttribute` and `ec2:DescribeInstances` (to turn off the source/destination check on itself); `autoscaling:CompleteLifecycleAction` on its own ASG. No managed policy |
| launch template | the newest Amazon Linux 2023 arm64 image (see below), `t4g.micro`, the `RootVolume` root EBS volume (8 GiB `gp3`, encrypted, by default), a public address, IMDSv2 required with hop limit 2, the cloud-init user data; each change is a new default version |
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

### The user data: a small bootstrap, plus a downloaded script

The cloud-init user data (`pkg/awsrouter/testdata/userdata-default.yaml`) is
deliberately small. It:

- installs the packages `router-setup.sh` needs (chrony, audit,
  dnf-automatic, dnf-utils, firewalld, a few diagnostic tools, and
  `checkpolicy` when `OPKSSH` is set). It sets up no swap file: that is
  `router-setup.sh`'s, below;
- writes this router's own small values and feature flags to
  `/etc/tailscale-router/router.env`, plus — only when set —
  `TrustedUserCAKeys`/`AuthorizedPrincipals`, `OPKSSH`'s providers/auth_id
  lines, or `HostCert`'s CA bundle, as small literal files alongside it;
- downloads `router-setup.sh` from a URL keyed by `RouterSetupVersion`,
  checks it against a pinned sha256, and runs it — fail closed: a
  download failure or a checksum mismatch is logged and skipped, never a
  half-verified script run as root (and never blocks the tailnet join,
  armed independently right after).

**`router-setup.sh`** (`pkg/awsrouter/router-setup.sh`) does everything the
single template used to render directly, reading `router.env` and the small
staged files instead of Go template variables — it is the SAME file for
every router of a given truvity/tailscale release, with or without the
optional features:

- a 1 GiB swap file at `/swapfile` (dnf headroom), only when the root
  filesystem has room for it and 1 GiB more; otherwise it logs
  `swap: skipped, N MiB free on /, need 2048 MiB …` and carries on. A swap
  file that fails to activate is removed and logged, never a failed setup;
- chrony (pinned to the Amazon Time Sync Service), audit (with watch rules on
  the identity and login files), persistent journald capped at 200 MB
  (`/etc/systemd/journald.conf.d/99-size-cap.conf`, `SystemMaxUse=200M`), and
  `/etc/ssh/sshd_config.d/99-hardening.conf` (`PermitRootLogin no`, always);
- a nightly job that applies updates and reboots when `needs-restarting -r`
  says so, after a random delay of up to two hours so a fleet does not
  reboot at once;
- firewalld: the primary interface in `public` with the WireGuard port and
  masquerading, `tailscale0` in `trusted`;
- `tailscale-join.sh`, run by a systemd unit and a cloud-final drop-in on
  every boot, single-flight (`flock` on `/run/tailscale-join.lock`: when both
  start at once, the second logs `another pass holds the lock` and leaves
  the join to the first): installs Tailscale from its signed repository, reads the key
  from `SSMAuthKeyPath`, runs
  `tailscale up --advertise-routes=… --accept-dns=false`, turns off the
  source/destination check and completes the lifecycle action — retrying 20
  times, 15 seconds apart. Its output goes to `/var/log/tailscale-join.log`
  and to the serial console;
- when `SSH_USER_CA=true` or `OPKSSH=true` — either login path, or both:
  the SSH login lockdown, `/etc/ssh/sshd_config.d/10-ssh-login.conf`
  (`PubkeyAuthentication yes`, `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `AuthorizedKeysFile none`,
  `LogLevel VERBOSE`), then removes `ssh` from the `public` zone so SSH
  arrives over `tailscale0` only, and runs `sshd -t`. The lockdown belongs
  to neither path, so dropping certificate login from an opkssh router
  loosens nothing;
- when `SSH_USER_CA=true`: the CA keys, one principals file per user and
  `/etc/ssh/sshd_config.d/10-user-ca.conf` (`TrustedUserCAKeys`,
  `AuthorizedPrincipalsFile`, nothing else);
- when `OPKSSH=true`: opkssh, installed by OWN steps rather than opkssh's
  upstream `scripts/install-linux.sh` — that script's OS detection does not
  recognize Amazon Linux 2023 on any release through its own `main` branch,
  so it always fails there (see CHANGELOG.md's v1.11.0 entry). First it
  removes `ec2-instance-connect` (some AL2023 AMIs ship it pre-enabled with
  its own `AuthorizedKeysCommand`, which would otherwise silently win over
  opkssh's), then downloads the pinned opkssh binary and `opkssh.te`,
  verifying each against its configured sha256 before using it — a mismatch
  aborts, fail closed, and never touches sshd. It creates the `opksshuser`
  system account, installs the binary, compiles and loads the SELinux module
  when SELinux is enforcing, writes `/etc/opk/providers` and
  `/etc/opk/auth_id` (`root:opksshuser`, mode `0640`), and writes the
  `AuthorizedKeysCommand` sshd drop-in — but never a sudoers file; there is
  no `--no-home-policy` flag to get right, because these steps never create
  one. Only then does it run `sshd -t`: on success it reloads sshd, on
  failure — or any earlier fail-closed abort — it removes only the opkssh
  drop-in and leaves the previously running sshd, and the certificate-login
  files above (never touched by this step), exactly as they were.
  `AuthorizedKeysCommand` and `TrustedUserCAKeys` are independent sshd
  mechanisms, so opkssh works the same whether certificate login is also
  set or not;
- when `HOST_CERT=true`: downloads the pinned `openbao-hostcert` archive for
  this package's own architecture (`arm64` — see "The image lookup" above)
  and verifies it against its configured sha256 — a mismatch aborts, fail
  closed, the same as opkssh's downloads. It installs the binary at
  `/usr/local/bin/openbao-hostcert`, the systemd service and timer (their
  content lives in `router-setup.sh` itself, not a second checksummed
  download), and `/etc/openbao-hostcert/hostcert.env` (mode `0600`) with
  the mount/role/address configuration renamed from `HOST_CERT_*` to the
  `OPENBAO_HOSTCERT_*` names the binary reads — everything except the
  principal, which is never baked in at cloud-init time (an
  as-yet-unlaunched instance's eventual tailnet hostname is not knowable
  then). A small wrapper,
  `/usr/local/sbin/openbao-hostcert-run.sh`, derives it instead, fresh on
  every run, from `tailscale status --peers=false --json`
  (`--peers=false` keeps `"DNSName"` to exactly one match, so a plain
  `grep`/`sed` needs no JSON parser and no new package — AL2023 already
  has both, and `tailscale` is this package's own reason to exist), and
  execs the binary with `--principal`. Then it adds
  `/etc/ssh/sshd_config.d/70-hostcert.conf` (`HostCertificate
  /etc/ssh/ssh_host_ed25519_key-cert.pub`), runs `sshd -t`, and on success
  enables the timer — on failure, removes only this drop-in, the same
  rollback contract opkssh's own failure takes. The timer fires ~5 minutes
  after boot, then every 12 hours with up to 10 minutes of jitter; see
  [safety.md](safety.md#host-certificate-renewal-the-principal-pattern-is-the-real-boundary)
  for why `PrincipalPatterns` — not this package, not the OpenBAO role —
  is what actually stops a certificate from being trusted for the wrong
  host.

With neither `TrustedUserCAKeys`/`AuthorizedPrincipals`, `OPKSSH`, nor
`HostCert` set, the router's effective configuration — every file sshd and
systemd actually read, and their content and mode — is unchanged from
before this split; `pkg/awsrouter/router_setup_test.go` runs
`router-setup.sh` for real (real bash, a throwaway root, no golden-string
matching) and checks exactly this.

EC2 refuses user data over 16 KiB. Before the bootstrap split, a real router
with both certificate login and opkssh configured rendered 16,120 of those
16,384 bytes; `pkg/awsrouter/userdata_test.go`'s `TestUserDataFitsEC2Limit`
checks every combination of features — `HostCert`'s own CA bundle included,
a full PEM certificate whose size is the caller's to supply, not this
package's to bound — against a 12 KiB generous limit, since almost
everything that used to count against the 16 KiB limit is now inside the
downloaded, version-pinned `router-setup.sh` instead.
