# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. The chart and the Go module are released
together at every version.

## v1.14.0

- **BREAKING: the `tsdns` chart and its CoreDNS image are removed.**
  Split-DNS mechanism now lives entirely in `pkg/tailnet.NewSplitDNS`,
  which is unchanged: point it at a resolver of your own instead of at a
  `tsdns` ClusterIP (see the [README](README.md#the-model)). tsdns's only
  consumer stopped using it on 2026-09-05, and its last change was
  2026-09-04. **v1.13.0 is the last version that shipped the `tsdns`
  chart and image**; that version, and every earlier one, remains
  published at `oci://ghcr.io/truvity/charts/tsdns` and is unaffected by
  this removal. `docs/reference.md`, `docs/doctrine.md` and
  `docs/safety.md` drop their `tsdns` sections; see
  [docs/adoption.md](docs/adoption.md#upgrading) for what an upgrade
  changes.

## v1.13.0

- **`pkg/awsrouter`: optional SSH host-certificate renewal**, via
  `truvity/openbao`'s `cmd/openbao-hostcert` — a router signs its own
  SSH host key with a short-lived certificate from an OpenBAO AWS IAM
  auth login, so a client trusts one `@cert-authority` line instead of
  pinning every router's own host key. `TailscaleInstanceConfig.HostCert`
  (`*HostCertConfig`, nil or `Enabled: false` off by default, the same
  staged-rollout convention `OPKSSHConfig` takes) names the release
  (`ArtifactVersion`, a per-`GOARCH` `ArtifactSHA256` — this package
  deploys `arm64` only), the OpenBAO connection (`Address`, `CABundle`,
  `Namespace`, `AuthMount`, `AuthRole`, `ServerIDHeader`, `SSHMount`,
  `SSHRole`) and `PrincipalPatterns` — `path.Match` globs
  `openbao-hostcert`'s own `--principal-pattern` refuses to request a
  principal outside of. `router-setup.sh` downloads the pinned archive
  by checksum (fail closed on mismatch, same contract opkssh's own
  downloads take), installs the binary plus a systemd service and timer
  whose unit content ships in this script itself (not a second
  checksummed download), and a small wrapper that derives the router's
  own tailnet hostname fresh on every run from `tailscale status
  --peers=false --json` — no new package, `grep`/`sed` are already on
  AL2023. See `docs/safety.md`'s "Host-certificate renewal: the
  principal pattern is the real boundary" for why OpenBAO's own SSH
  secrets engine cannot restrict a host role's domain by CIDR or glob
  (checked against its source), and why the client's own
  `@cert-authority` pattern — never the whole tailnet domain for one
  environment's CA — is what actually closes that gap.
  `TestUserDataDefaultUnchanged` proves `HostCert` nil renders
  byte-for-byte what a router without this input renders.

## v1.11.0

- **Fix: opkssh now installs on Amazon Linux 2023.** v1.10.0's `OPKSSH`
  input ran opkssh's own upstream `scripts/install-linux.sh`, whose
  `determine_linux_type()` recognizes only `/etc/redhat-release`,
  `/etc/debian_version`, `/etc/arch-release`, or an `/etc/os-release`
  with `ID_LIKE=*suse`. AL2023 has none of these (`ID=amzn`,
  `ID_LIKE=fedora`, no `/etc/redhat-release`) — checked against every
  opkssh release through its own `main` branch as of this fix, none
  recognize AL2023 — so the install always failed "Unsupported OS
  type", silently (the error was swallowed into a shell variable), and
  the router's own fail-closed design then removed the opkssh drop-in
  and left the router without opkssh, correctly but without opkssh.
  `pkg/awsrouter` now OWNS the install steps for AL2023 instead of
  depending on that script: creating the `opksshuser` account,
  installing the checksum-verified binary, compiling and loading the
  SELinux module when enforcing, and writing the sshd
  `AuthorizedKeysCommand` drop-in — the same steps that script performs
  for a redhat-family host, which AL2023 is. `OPKSSHConfig` drops
  `InstallScriptURL`/`InstallScriptSHA256` (no longer downloaded); every
  other field is unchanged. There is now no `--no-home-policy` flag to
  get right or assert after the fact — the owned steps never write
  `/etc/sudoers.d/opkssh` at all.

- **Bootstrap split: user data is now a small download, not the whole
  router.** Everything the single cloud-init template used to render
  directly — chrony, audit rules, persistent journald, sshd hardening,
  the tailnet repo and join unit, and the certificate-login and opkssh
  blocks above — now lives in `router-setup.sh`: one generic,
  version-pinned script every router downloads and checksum-verifies
  (fail closed on either a download failure or a mismatch) before
  running. It is published as this release's `router-setup-v1.11.0.sh`
  GitHub Release asset and embedded in the Go module
  (`pkg/awsrouter/bootstrap.go`), so the sha256 a consumer's own build
  computes from the embedded copy is always the sha256 of the asset a
  router downloads — the same git blob, at the same tag. A new required
  field, `TailscaleInstanceConfig.RouterSetupVersion` ("X.Y.Z", no
  leading "v" — normally the version the caller's own `go.mod` pins),
  builds that download URL.

  This exists because EC2 caps user data at 16 KiB and a real router,
  with certificate login and opkssh both configured, was rendering
  16,120 of those 16,384 bytes — 264 bytes of headroom from a hard
  failure at the next added byte. The same router's user data is now a
  few KiB with every feature enabled (`pkg/awsrouter/userdata_test.go`'s
  `TestUserDataFitsEC2Limit` now checks an 8 KiB generous limit, not the
  pre-split 200-byte margin `TestUserDataOPKSSHWithCertificateLoginFitsEC2Limit`
  used to need).

  Behavior for a router with neither optional feature is unchanged —
  `pkg/awsrouter/router_setup_test.go` runs `router-setup.sh` for real,
  with real bash, against a throwaway root and proves the effective
  configuration (every file sshd and systemd actually read, and their
  content/mode) matches what the pre-split template rendered directly.
  Router egress to github.com, already needed for opkssh's own
  artifacts, now also carries this download — see docs/safety.md.

## v1.10.1

- **Guard: every invoke in `pkg/awsrouter` now proves it carries an
  explicit provider.** `ec2.LookupAmi` and `aws.GetCallerIdentity` already
  passed `pulumi.Provider(awsProvider)` — the same provider the package's
  resources use — so no behavior changes here. But an invoke missing that
  option passes every unit test under the SDK's default mocks (it silently
  falls back to the ambient default provider) and only fails at `pulumi
  preview`, on an estate that disables default providers. A new mocks-level
  test (`pkg/awsrouter/router_test.go`) fails any invoke whose mock request
  carries no provider reference, so a future regression is a unit-test
  failure instead of a broken preview.

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
