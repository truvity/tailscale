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

`validateOPKSSH` does the same for the opkssh input, `OPKSSH`, whenever
`Enabled` is `true`:

| Refusal | What it prevents |
|---|---|
| a missing `ArtifactVersion` | an install log line with no version to record |
| a checksum that is not 64 lowercase hex characters | a typo'd or truncated sha256 that would never match anything, silently forcing every install to fail closed at runtime instead of at plan time |
| a URL that is not an absolute `https://` URL (`ArtifactURL`, `SELinuxModuleURL`, or a `Providers[].Issuer`) | fetching a pinned artifact — or trusting an issuer — over anything looser than https |
| an empty `Providers` | opkssh installed to trust no OpenID Provider |
| a `Providers[].ClientID` that is empty or not a plain token | a value opkssh's space-delimited `/etc/opk/providers` would read as extra columns, or a shell metacharacter reaching `router-setup.sh` |
| a `Providers[].Expiration` that is not one of opkssh's own policies (`12h`, `24h`, `48h`, `1week`, `oidc`, `oidc-refreshed`) | a value opkssh's parser does not recognize |
| an empty `AuthorizedIdentities` | opkssh installed to admit nobody |
| an `AuthorizedIdentities[].User` that is not a plain login name, or `root` | the same class of mistake `AuthorizedPrincipals` refuses, for opkssh's principals |
| an `AuthorizedIdentities[].Group` that is empty or not a plain token (whitespace, `;`, `` ` ``, `$()`, quotes, …) | the group name is refused outright, never escaped — see "refuse what we name, escape what we are handed" |
| an `AuthorizedIdentities[].Issuer` that is not one of `Providers`' issuers | a typo'd issuer that opkssh would otherwise trust nothing from, silently |

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
and the nightly job patch once swap exists. The swap file is
`router-setup.sh`'s, created only when the root filesystem has room for it;
before v1.17.0 it was cloud-init's `swap:` module, which on a 2 GiB root
volume failed with ENOSPC and left the router with no swap at all. The root
volume is sized by the launch template (`RootVolume`, 8 GiB by default), not
by the image, and the persistent journal is capped at 200 MB. Recent Amazon Linux images reboot
in the middle of the first boot, which kills cloud-init's run-once phases; the
join therefore lives in an idempotent systemd unit that runs on every boot,
and the lifecycle hook allows 15 minutes for it.

## Routers: access, diagnosis and break-glass

A router has **no interactive access** other than SSH with a certificate
signed by a CA in `TrustedUserCAKeys`, or an identity in `OPKSSH`'s
`AuthorizedIdentities` (opkssh), and none at all when both inputs are empty:
no key pair, no TCP port in the security group, no Session Manager. With
either SSH input set, SSH arrives over `tailscale0` only (before v1.16.0,
only certificate login took `ssh` off the `public` zone; an opkssh-only
router kept it there, closed only by the security group), so the tailnet
policy must let the holders reach the router's tag on port 22 (`pkg/acl`
grants `tag:<router>:*` to every VPC-tier group; the certificate or the ID
token decides who logs in). A certificate is refused when it has expired,
when another CA signed it, or when none of its principals is listed for the
login user; an opkssh sign-in is refused when no `/etc/opk/auth_id` line
matches the login user, group and issuer. `TrustedUserCAKeys` (certificate
login) and `AuthorizedKeysCommand` (opkssh) are independent sshd
mechanisms — sshd tries each configured one in turn for pubkey auth — so
both can be set on the same router at once, and a router can carry either,
both, or neither. The lockdown — `AuthorizedKeysFile none`, no password or
keyboard-interactive login, `LogLevel VERBOSE`, `ssh` off the `public`
zone — is one drop-in (`10-ssh-login.conf`) that either input turns on,
so removing certificate trust from an opkssh router (to retire a CA, or
because nothing signs for it any more) drops only the CA and principals
files. Each login logs the certificate's key id and serial, or (for
opkssh) the identity opkssh extracts from the verified ID token.

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

## Host-certificate renewal: the principal pattern is the real boundary

`HostCertConfig` lets a router sign its own SSH host key with a
short-lived certificate from an OpenBAO AWS IAM auth login
(`truvity/openbao`'s `cmd/openbao-hostcert`), so a client trusts one
`@cert-authority <domains> <key>` line instead of pinning every router's
own host key. What it does NOT do, on its own, is stop that certificate
from being trusted for the WRONG host.

**OpenBAO's SSH secrets engine has no CIDR- or glob-aware way to
restrict a host role's domain** — checked against OpenBAO's own source
(`internal/builtin/logical/ssh/path_issue_sign.go`'s
`validateValidPrincipalForHosts`): a host role's `allowedDomains`
matches a requested principal by exact string equality or by DNS
suffix, never a wildcard or a pattern. If two environments' routers
share one tailnet domain suffix — likely, since a tailnet is usually
one domain for every environment on it — OpenBAO itself cannot stop a
login authenticated as environment A's router from requesting (and
getting signed) a certificate whose principal merely *looks like*
environment B's hostname. The AWS IAM auth role bound to that login
already scopes WHO may authenticate (one instance role's ARN); it does
not scope WHAT hostname a successful login may then ask to be
certified for.

**`PrincipalPatterns` is where this actually gets stopped, and it is
enforced on the ASKING side, not the signing side.**
`cmd/openbao-hostcert`'s `--principal-pattern` refuses to even send a
sign request for a principal outside the configured glob(s) — this
package's own `HostCertConfig.PrincipalPatterns` populates it. That is
defense in depth on a router that is behaving correctly; it is not what
stops a COMPROMISED router (one that could rewrite its own principal
argument) from asking anyway. The boundary that survives that case is
the CLIENT's own trust: an OpenSSH `known_hosts` `@cert-authority` line
DOES support glob patterns, unlike OpenBAO's role, so scoping each
environment's client trust to that environment's own VPC CIDR (never
the whole tailnet domain) means a client refuses a wrong-environment
certificate even if OpenBAO signed it. Never write a client trust line
as `@cert-authority *.<tailnet-domain> <one environment's CA key>` —
scope it to that environment's own address range instead. (The
consuming estate's own docs are where that pattern is actually
rendered and published; this package only carries the value through.)

**Fail-safe either way.** A missed renewal, a refused login, a refused
sign or a `--principal-pattern` refusal all leave whatever certificate
(or none) was already on disk untouched — sshd keeps serving the plain
host key, never a lockout. The first certificate is signed at boot
(`openbao-hostcert-boot.sh`, run by the join right after `tailscale up`),
under the same contract: bounded to 3 attempts of 45 seconds, and a
failure is logged and exits 0, so it never fails the join, the lifecycle
action or routing — the timer retries. `router-setup.sh`'s own install of the
binary, units and sshd drop-in follows the identical fail-closed
contract opkssh's install already does: a checksum mismatch or a
failing `sshd -t` rolls back only the host-certificate drop-in, never
the router's other SSH paths.

## Traps worth knowing

### The image follows the newest match

The launch template's image is looked up on every preview and update (owner
`amazon`, architecture `arm64`, name `al2023-ami-2023.*-kernel-<Kernel>-arm64`,
most recent), so routers follow one image family and one kernel line. A newer
image in that family means a new launch-template version, and the instance
refresh then replaces every router, one after another, at the next update. An
update that was meant to change nothing can therefore roll the fleet; read the
preview for the launch template's image. A change of kernel line
(`Image.Kernel`) or of family is a deliberate change, and it replaces every
router the same way.

Before v1.18.0 the name pattern was `al2023-ami-*-arm64`. It also matched
Amazon's `minimal` images (no AWS CLI, which the join needs; a 2 GiB root
volume), the ECS-optimized images and every kernel line, and "most recent"
picked whichever was published last: routers rolled onto a minimal image.
Amazon publishes every kernel line of a release at the same instant, so even
among standard images the pick was arbitrary. The pattern now starts with the
standard images' own prefix, `al2023-ami-2023.`, which no minimal or ECS image
carries, and ends with one kernel line (`DefaultImageKernel`, 6.18, unless
`Image.Kernel` says otherwise). A kernel line Amazon stops publishing fails
the lookup at preview, never silently falls back to another family. The root
volume stays explicit (`RootVolume`, 8 GiB by default, since v1.17.0).

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

### The user data has a size limit — and the bootstrap split exists because of it

EC2 refuses user data over 16 KiB. Before v1.11.0, a real router with both
certificate login and opkssh configured rendered 16,120 of those 16,384
bytes — 264 bytes of headroom from a hard failure at the next byte added by
either feature. `pkg/awsrouter/userdata_test.go`'s `TestUserDataFitsEC2Limit`
now checks every combination against an 8 KiB generous limit: the bootstrap
(`tailscale_userdata.yaml.gotmpl`) renders only this router's own small
values and feature flags plus a fetch-and-verify `runcmd`; everything that
used to be written directly — chrony, audit, journald, sshd hardening, the
join script and systemd units, and the certificate-login and opkssh
blocks — now lives in `router-setup.sh`, downloaded once by URL and
checksum-verified, not re-rendered per router. There is still no way to
raise EC2's limit; the bootstrap split means almost nothing that varies by
router counts against it any more.

### The bootstrap split: a download must never partially apply

`router-setup.sh` (`pkg/awsrouter/bootstrap.go`'s `go:embed`, published as
this release's `router-setup-vX.Y.Z.sh` GitHub Release asset — both are the
same git blob at the tag, so a consumer's own build always computes the
right digest without anyone hand-maintaining a checksum) is fetched over
plain `curl` and checked against that digest before it ever runs
(`sha256sum -c`). A download failure or a mismatch is logged
(`router-setup checksum fail`) and the bootstrap's own `runcmd` continues to
arm the tailnet join regardless — a broken bootstrap must never block the
one thing that keeps this router reachable at all. Router egress to
github.com was already required (opkssh's own artifacts come from there);
this download reuses it, from the same host.

Inside `router-setup.sh` itself, the handful of operations that need a real
AL2023 host (package removal, service management, SELinux module
compilation, network fetches) are named functions
(`pkg_remove`, `svc_*`, `fw`, `sysctl_apply`, `time_step`, `selinux_status`,
`selinux_load_module`, `ensure_user_group`, `sshd_check`, `fetch_verify`) —
not because production needs the indirection, but because
`pkg/awsrouter/router_setup_test.go` overrides them after sourcing the
script (the same `SHUNIT_RUNNING`-style convention opkssh's own
`install-linux.sh` uses for its own tests) and runs every other line — the
actual file-writing logic that determines the router's effective
configuration — for real, against a throwaway `ROUTER_SETUP_ROOT`.

### pkg/awsrouter: opkssh's home policy — structurally disabled, not merely flagged

opkssh's own upstream `install-linux.sh` defaults to **home policy**
(`HOME_POLICY=true`): it lets `~<user>/.opk/auth_id` grant that account
extra identities on top of `/etc/opk/auth_id`, and to make that work it
installs `/etc/sudoers.d/opkssh` with a passwordless rule
(`opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *`). On a
router that is the wrong shape: the only policy this estate renders is
`/etc/opk/auth_id`, from `OPKSSH.AuthorizedIdentities` — a second,
self-service policy file would let anyone who reaches a shell as a login
user (an already-authorized opkssh or certificate identity) grant that
*same account* extra identities, bypassing the roster-rendered groups
entirely and outliving whatever revoked the identity that let them in.

That script's own answer is a `--no-home-policy` flag plus an assertion
that `/etc/sudoers.d/opkssh` was not created — but `router-setup.sh` does
not run that script at all (its OS detection does not recognize Amazon
Linux 2023; see CHANGELOG.md's v1.11.0 entry), so this estate's own
`setup_opkssh` simply never writes a sudoers file: there is no flag to get
right and nothing to assert afterward. `pkg_remove ec2-instance-connect`
still runs *before* the opkssh install, not after: some AL2023 AMIs ship
that package pre-enabled with its own `AuthorizedKeysCommand`, which would
otherwise either silently win over opkssh's or collide with the fixed
`60-opk-ssh.conf` drop-in name `setup_opkssh` writes — removing it first
keeps "remove that one file" a complete rollback.

### tailscaled's image tag moves

`image.tag` defaults to `stable`, so the same render can run a newer
`tailscaled` after a pod restart, and the zero-diff gate cannot see it. Pin a
version where the render must say what runs.
