# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts and the Go module are released
together at every version.

## v1.10.0

- **New: `pkg/awsrouter`'s `OPKSSHConfig`** — optional OIDC sign-in via
  [opkssh](https://github.com/openpubkey/opkssh), additive to the
  certificate login `TrustedUserCAKeys`/`AuthorizedPrincipals` already
  provide (v1.7.0): `AuthorizedKeysCommand` and `TrustedUserCAKeys` are
  independent sshd mechanisms, so a router can carry either, both, or
  neither, and this input never touches the certificate-login files. When
  set, cloud-init removes `ec2-instance-connect` first (some AL2023 AMIs
  ship it pre-enabled with its own `AuthorizedKeysCommand`, which would
  silently override opkssh's, and would also make install-linux.sh's own
  sshd drop-in filename unpredictable), downloads the pinned opkssh
  binary, `opkssh.te` and `install-linux.sh`, verifying each against its
  sha256 first — a mismatch aborts the install, fail closed — then runs
  `install-linux.sh --no-home-policy` (creating the `opksshuser` account,
  loading the SELinux module AL2023's enforcing policy needs, wiring
  `AuthorizedKeysCommand`, and — because of the flag — never installing
  the passwordless `sudoers.d` rule or the `~user/.opk/auth_id`
  self-service policy install-linux.sh defaults to, which would let a
  login user grant themselves extra identities outside the
  roster-rendered `/etc/opk/auth_id`; the script asserts the sudoers file
  was not created rather than trusting the flag silently), writes
  `/etc/opk/providers` and `/etc/opk/auth_id`, and only then runs
  `sshd -t`: on failure, or any earlier fail-closed abort, it removes
  just the opkssh drop-in and leaves the previously running sshd
  untouched. `nil`, or `OPKSSHConfig.Enabled` false (the default), and the
  user data is byte-for-byte what it was before this input existed, so
  upgrading replaces no router. Stacked on an existing certificate login,
  opkssh's pinned artifacts leave a much tighter margin against EC2's
  16 KiB user-data limit than before — see
  [safety.md](docs/safety.md#pkgawsrouter-opksshs-tight-margin-against-the-16-kib-limit).

## v1.9.0

- **New: `pkg/acl`'s `Policy.ExtraCIDRGrants` / `CIDRGrant`** — `Grant`'s
  sibling escape hatch for the one shape its own doc comment names and
  refuses to grow into: a destination that is an address rather than a
  tag. A tagged device reaching one address behind a subnet router (a
  private gateway's pinned ClusterIP, rather than the whole VPC CIDR the
  router already advertises) carries no tag of its own for a `Grant` to
  name, and is neither a VPC/Service-CIDR tier (those are GROUP-sourced)
  nor a router's own reachability rule. `CIDRGrant` is the same shape as
  `Grant` otherwise — one tag, one address, a required, spelled-out port
  list — and `Validate` refuses an empty port list the same way. Optional;
  a `Policy` with no `ExtraCIDRGrants` renders byte-identical ACLs to
  before this version.

## v1.8.0

- **New: `pkg/acl`'s `Policy.ExtraGrants` / `Grant`** — one narrow,
  explicit tag-to-tag accept rule (a single source tag, a single
  destination tag, a required, spelled-out port list) for access that
  fits neither the VPC/Service-CIDR tiers nor a router's own
  reachability rule: an application box outside every cluster that one
  cluster's egress identity needs to reach on one port, for instance.
  `Validate` refuses a Grant with an empty port list rather than
  defaulting it to the whole tag. Optional; a `Policy` with no
  `ExtraGrants` renders byte-identical ACLs to before this version.

## v1.7.1

- **`pkg/awsrouter`: routers no longer carry `AmazonSSMManagedInstanceCore`.**
  The managed policy granted `ssm:GetParameter` on every parameter, and
  Session Manager was never a way into a router. A router is replaced to
  pick up the new role policy.
- **`pkg/awsrouter`: the join log reaches the serial console**, so a
  router that failed to join the tailnet can be diagnosed with
  `get-console-output`.

## v1.7.0

- **`pkg/awsrouter`: optional SSH user-certificate login.**
  `TrustedUserCAKeys` and `AuthorizedPrincipals` let a router fleet admit
  OpenSSH user certificates from the CAs the caller names, for the
  principals it names per login user; SSH then arrives over the tailnet
  interface only. With neither input the user data renders byte-for-byte
  as in 1.6.1, so upgrading replaces no router.
- **`pkg/acl`**: the documentation now says the `ssh` section is Tailscale
  SSH; routers that run OpenSSH need port 22 in an ACL.
- gRPC updated for GO-2026-6443 and GO-2026-6348 (transitive).

## v1.6.1

- **`tailscaled`: the default memory limit is 512Mi.** 128Mi OOM-killed a
  userspace router under load.

## v1.6.0

- **`tsdns`: opt-in per-query logging** (`debugLog`), tagged with the
  server block that answered. Off by default; the Corefile with it off is
  byte-identical to 1.5.0.
- The CoreDNS image moves to v1.14.7.

## v1.5.0

- **`tsdns`: opt-in catch-all forward** (`catchAll`), so a pod can use
  tsdns as its only nameserver.

## v1.4.0

- **`pkg/awsrouter`**: the EC2 subnet-router fleet.

## v1.3.0

- **`pkg/tailnet`**: the tailnet's policy, keys, split DNS and flow logs
  as a Pulumi component.

## v1.2.0

- **`pkg/acl`**: a pure builder for the tailnet policy.

## v1.1.0

- **`values.schema.json`** for both charts: an unknown key fails the
  render.

## v1.0.0

- First release: the `tailscaled` and `tsdns` charts and the Go module
  skeleton.
