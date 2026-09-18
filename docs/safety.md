# Safety — what can break, and what the components do about it

A subnet router fails quietly: a route stuck waiting for approval, a name
that answers NXDOMAIN, a router that never joined. None of it shows in the
object that caused it. So the charts refuse at render time, the Go packages
refuse before they create anything, and the router keeps a log a person can
read without a shell.

## Refused at render time

Every chart refusal has a fixture under `tests/invalid/<chart>/`; `just lint`
renders each one and fails if any of them renders.

### tailscaled

| Refusal | Fixture | What it prevents |
|---|---|---|
| any unknown top-level key | `unknown-key.yaml` | a typo (`advertiseRoute`) read as "use the default", which advertises nothing |
| an unknown key under `image` | `image-unknown-key.yaml` | `image.version` silently ignored while the default tag runs |
| `advertiseRoutes` that is not comma-separated CIDRs | `advertise-routes-not-cidrs.yaml` | an argument `tailscaled` rejects at start-up, so the pod crash-loops after the render looked fine |
| an empty `secretName` | `secret-name-empty.yaml` | a pod with no auth key to join with |
| an empty `serviceAccount.name` | `service-account-name-empty.yaml` | a ServiceAccount the API server refuses after the rest has applied |
| a negative `replicaCount` | `replicas-negative.yaml` | a Deployment the API server refuses |

### tsdns

| Refusal | Fixture | What it prevents |
|---|---|---|
| no `suffix` | `no-suffix.yaml` | a gateway with no zone to answer for |
| no `clusterIP` | `no-cluster-ip.yaml` | an allocated address that the split-DNS entry, written elsewhere, does not name |
| no `resolverIP` | `no-resolver-ip.yaml` | a suffix block with nowhere to forward to |
| a `forwardZones` entry without a `resolver` | `forward-zone-no-resolver.yaml` | a server block CoreDNS will not load |
| an unknown key in a `forwardZones` entry | `forward-zone-unknown-key.yaml` | `port: 53` silently ignored |
| any unknown top-level key | `unknown-key.yaml` | `catchall: true` read as `catchAll: false` |

The three required values are refused twice, by the schema and by `required`
in the templates, so a render that skips schema validation still fails.

## Refused before anything is created

### pkg/awsrouter

`CreateTailscaleInstance` validates the SSH inputs first and returns an error
without creating a resource:

| Refusal | What it prevents |
|---|---|
| `TrustedUserCAKeys` without `AuthorizedPrincipals` | a CA that opens no user, which looks like working SSH and is not |
| `AuthorizedPrincipals` without `TrustedUserCAKeys` | principals nothing can sign for |
| an entry that is not exactly one plain OpenSSH public key (two keys in one entry, key options, trailing text) | a CA file sshd reads differently from what the caller meant |
| a certificate given as a CA key | trusting one user's certificate as an authority |
| the same key twice (by fingerprint, whatever the comment) | a rotation that looks like two CAs and is one |
| a user that is not a plain login name | a principals file written outside `/etc/ssh/authorized_principals/` |
| `root` | a user sshd refuses anyway (`PermitRootLogin no`) |
| a user with an empty principal list | an entry that admits nobody; omit the user instead |
| a principal with spaces, options or a leading `#`, or repeated | an `authorized_principals` line sshd reads as options or as a comment |

### pkg/acl

`Build` validates first: a network without a name, VPC CIDR or router tag;
two networks or two clusters with one name; a cluster without a name; a
member cluster naming a network that does not exist.

### pkg/tailnet

`NewRouterKey` refuses a key without a tag: ownership, access and route
approval in the policy are all by tag, so an untagged router fits none of it.
`NewS3FlowLogs` refuses a missing bucket, region or role. `ServiceIP` refuses
a CIDR that is not IPv4, and an offset outside it.

## Defaults chosen because the other one failed

### tailscaled: 512Mi, and no CPU limit

Userspace networking buffers every proxied connection in the Go heap, so
memory follows concurrent connections, not anything static. A router in a
consuming estate idled at about 44Mi and was still OOM-killed sixteen times
in four hours at a 128Mi limit, whenever the backends behind it churned and
clients re-dialled each one. The limit is 512Mi and the request 128Mi. There
is no CPU limit: throttling a router adds latency to every packet instead of
shedding one pod.

### tailscaled: ephemeral replicas

Each replica joins as a new node and writes no state back to a Secret, so the
pod needs no RBAC and two replicas never fight over one identity. The cost is
that every restart is a new node, which is why the policy must auto-approve
every route the router advertises (below).

### tsdns: a pinned address and a suffix that is not the cluster domain

The split-DNS entry is written in the tailnet, out of band, so the Service
address must not be whatever the allocator hands out. The suffix is not the
cluster domain, so the names resolve only over the tailnet and two clusters'
names never collide.

### tsdns: refuse by default, `catchAll` on request

Off, the gateway answers its declared zones and refuses everything else. A pod
that needs the tailnet suffix cannot get it by adding tsdns as a *second*
nameserver: a stub resolver takes the first server's NXDOMAIN as final, and
musl asks every server at once and takes the fastest answer. So `catchAll`
lets a pod use tsdns as its *only* nameserver (`dnsPolicy: None`). The pod
then depends on tsdns for all resolution, which is why it is a choice and
not the default.

### tsdns: `debugLog` to tell one NXDOMAIN from another

A gateway returning NXDOMAIN for a name in its own suffix looks the same from
outside whether the rewrite did not fire or the upstream had no answer, and
`errors` logs neither: NXDOMAIN is an answer, not an error. `debugLog` tags
every query with the server block that answered. It costs a line per query:
turn it on to diagnose, and off again.

### pkg/acl: every advertised route auto-approved for its router's tag

Kubernetes routers join with ephemeral keys, so each re-registration is a new
node whose routes need approval. A Kubernetes router advertises its network's
VPC CIDR alongside its Service CIDR; without an approval for both, every pod
restart leaves a route pending approval, which a consuming estate saw on four
clusters at once. `Build` approves both for the cluster's router tag, and each
CIDR only for its own environment's tags.

### pkg/tailnet: the stack owns the policy outright

`NewACL` overwrites whatever policy is there. A new tailnet already holds a
non-default policy (the bootstrap that lets the OAuth client hold the manager
tag), so refusing to overwrite would fail the very first apply. The
consequence: an edit in the admin console is undone at the next apply.

### pkg/tailnet: keys after the policy, bounded, rotated by name

A key carrying a tag the policy does not yet own is refused, so keys depend on
the ACL. Keys expire after 90 days: the stack must apply at least once inside
that window or new routers cannot join. Rotation is a resource name
(`RotationSuffix`), never a timer inside a resource, so the same month is the
same key and no preview churns.

### pkg/awsrouter: no Session Manager, no managed policy

Up to 1.7.0 the router role also carried `AmazonSSMManagedInstanceCore`. That
policy grants `ssm:GetParameter` on every parameter in the account, and with
the role's `kms:Decrypt` on the `aws/ssm` key it let any router read every
default-key SecureString in its account, which made the policy scoped to the
one auth-key parameter meaningless. It bought nothing: the image does not
guarantee an SSM agent, so Session Manager never reached a router. 1.7.1
removed it. The security group's description still says "SSM access": AWS
replaces a security group whose description changes, so it stays.

### pkg/awsrouter: `t4g.micro`, no first-boot upgrade, a join that survives a reboot

A 512 MB instance was OOM-killed by the first-boot package pass, which took
cloud-init and everything after it down. So the instance is `t4g.micro` with
a swap file, and there is no `package_upgrade` at first boot: dnf-automatic
and the nightly job patch once swap exists. Recent Amazon Linux images reboot
in the middle of the first boot, which kills cloud-init's run-once phases; the
join therefore lives in an idempotent systemd unit that runs on every boot,
and the lifecycle hook allows 15 minutes for it.

## Routers: access, diagnosis and break-glass

A router has **no interactive access** other than SSH with a certificate
signed by a CA in `TrustedUserCAKeys`, and none at all when that input is
empty: no key pair, no TCP port in the security group, no Session Manager.
With the SSH inputs set, SSH arrives over `tailscale0` only, so the tailnet
policy must let the certificate holders reach the router's tag on port 22
(`pkg/acl` grants `tag:<router>:*` to every VPC-tier group; the certificate
decides who logs in). A certificate is refused when it has expired, when
another CA signed it, or when none of its principals is listed for the login
user. Each login logs the certificate's key id and serial.

**Diagnose a router that did not join** from the serial console, no shell
needed. cloud-init and the join script both write there, one line per attempt:

```sh
aws ec2 get-console-output --latest --output text --instance-id i-0123456789abcdef0
```

A router that never joins does not complete its lifecycle action, so the ASG
abandons it after 15 minutes and launches another. Read the console output
before then, or from the next attempt, which fails the same way.

**Repair by replacing it**, never by logging in and fixing it. The ASG launches
a fresh router (from the warm pool when there is one), and the lifecycle hook
keeps it out of service until it has joined:

```sh
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id i-0123456789abcdef0 --no-should-decrement-desired-capacity
```

or roll the whole fleet with
`aws autoscaling start-instance-refresh --auto-scaling-group-name <environment>-tailscale-<tailnet>`.

## Traps worth knowing

### The image follows the newest match

The launch template's image is looked up on every preview and update (owner
`amazon`, name `al2023-ami-*-arm64`, most recent), so routers follow one image
family chosen in code. A newer image means a new launch-template version, and
the instance refresh then replaces every router, one after another, at the
next update. An update that was meant to change nothing can therefore roll
the fleet; read the preview for the launch template's image. A change of
family is a code change, and it replaces every router the same way.

**Known issue:** the name pattern matches more than the standard image. It
also matches Amazon's `minimal` images and every kernel line
(`…-kernel-6.1-arm64`, `…-kernel-6.12-arm64`, and newer), and "most recent"
picks whichever was published last, which can be a minimal image. The code's
own comment excludes minimal images because the join needs the AWS CLI. Until
the pattern is narrowed, check which image a preview resolves to before
applying it.

### Rotating the router SSH CA

The user data carries the CA public keys, so a change to `TrustedUserCAKeys`
is a new launch-template version, and the instance refresh replaces every
router.

- **With one key in the list**, rotation is a short cut-over: publish the new
  CA public key as the only entry, let the refresh roll the routers, and
  re-issue certificates from the new CA. From the moment a router is replaced
  until a person's certificate is re-issued, that person's old certificate is
  refused there.
- **To rotate without the gap**, list both keys: add the new one next to the
  old, roll, move signing to the new CA, wait out the longest certificate
  lifetime, remove the old key, and roll again.

### The user data has a size limit

EC2 refuses user data over 16 KiB, and the SSH inputs are written into it. A
test keeps two CA keys and two users 1 KiB under the limit; a long principal
map can still cross it, and then AWS refuses the launch template.

### tailscaled's image tag moves

`image.tag` defaults to `stable`, so the same render can run a newer
`tailscaled` after a pod restart, and the zero-diff gate cannot see it. Pin a
version where the render must say what runs.

### A name resolves only where its address is reachable

tsdns listens on an address in the Service CIDR, and the policy lets only
`InClusterGroups` reach the Service CIDR. A person with the VPC tier alone
gets no answer from tsdns, which would not help anyway: every name it answers
for is a Service address they cannot reach.
