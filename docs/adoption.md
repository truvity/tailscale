# Adoption

## Prerequisites

- For the charts: Kubernetes (any CNI: the router runs in userspace) and Helm
  with OCI support. Nothing cluster-wide: no CRDs, no operator, no RBAC.
- A Tailscale tailnet whose groups come from its directory sync; the policy
  names groups (`group:<email>`) and declares no membership.
- For the Go packages: a Pulumi Go program and the Tailscale Pulumi provider,
  configured with an OAuth client that holds the manager tag (`pkg/acl`'s
  `ManagerTag`) and may write the policy, auth keys and DNS settings.
- Somewhere the estate keeps secrets: the router keys leave `pkg/tailnet` as
  secret Outputs, and the caller writes them where the routers read them.
- For `pkg/awsrouter`: the AWS Pulumi provider for the fleet's account and
  region, a VPC with public subnets, and the auth key in an SSM SecureString
  parameter under the default `aws/ssm` key.

## Install order

1. **The policy.** `acl.Build` and `tailnet.NewACL`. Every router tag must be
   owned before a key can carry it.
2. **The keys.** One `tailnet.NewRouterKey` per router tag, each with the ACL in
   `pulumi.DependsOn`.
3. **Store the keys.** For `charts/tailscaled`, a Secret in the router's
   namespace (`secretName`, `secretKey`); for `pkg/awsrouter`, the SSM
   parameter at `SSMAuthKeyPath`.
4. **The routers.** `charts/tailscaled` in each cluster, `pkg/awsrouter` for
   each network. Their routes are approved on arrival because step 1
   auto-approved them for the routers' tags.
5. **The names.** `charts/tsdns` with a pinned `clusterIP`, then
   `tailnet.NewSplitDNS` for the suffix to that address.
6. Optionally, `tailnet.NewS3FlowLogs`.

Pin both charts and the Go module at **the same version**: one tag releases
them all.

## The zero-diff gate

Adopt a release only when your render (or preview) is byte-identical to what
runs, or differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md).

- **Charts**: render with your values at the pinned version and at the new one
  (`helm template`) and compare. A diff the CHANGELOG does not explain is a
  reason to stop.
- **Go packages**: `pulumi preview` after bumping the module must show no
  change, or only the announced one. `pkg/awsrouter` resolves its image at
  every preview, so a newer Amazon Linux image shows up as a launch-template
  change whatever the release; preview once before the bump and once after,
  and adopt the release on the difference between the two
  ([safety.md](safety.md#the-image-follows-the-newest-match)).

Tightening a default is a separate change, adopted on its own evidence.

## Adopting what already exists

Moving hand-written objects or an existing Pulumi program onto these
components is one change whose render or preview diff is empty.

**The charts.** tailscaled's Deployment is `tailscaled` and its ServiceAccount
is `serviceAccount.name`; tsdns's ConfigMap, Deployment and Service are all
`tsdns`. Both select on `app.kubernetes.io/name`. A Deployment whose selector
differs cannot be updated in place (a selector is immutable), so an existing
router or gateway with other names or labels is replaced, not adopted: for
tailscaled that is a new ephemeral node and a brief loss of its routes; for
tsdns, keep the `clusterIP` the split-DNS entry names.

**The policy.** `NewACL` overwrites the live policy on its first apply.
Render `acl.Build` and compare it with the live policy as JSON (not text)
before the first apply; model the difference into `Policy` or
`ExtraTagOwners` until the two agree.

**Tailnet resources.** Every `pkg/tailnet` resource is top-level and named by
the caller, so give each the name it already has in the stack and the preview
shows no replacement. Key names carry the rotation suffix; adopting a key
under a different name mints a new one, which is harmless.

**An EC2 fleet.** `pkg/awsrouter`'s Pulumi resource names are fixed
(`tailscale-sg`, `tailscale-role`, `tailscale-instance-profile`,
`tailscale-lt`, `tailscale-asg`, …) and its AWS names are
`<Environment>-tailscale-<Tailnet>`. Import existing resources under those
names, or let the fleet be replaced: routers are cattle, and the lifecycle
hook keeps a new one out of service until it has joined. An imported security
group must keep the description the module writes, or AWS replaces it.

## Upgrading

No release so far has been marked **Breaking**. What each one changes in a
render or a preview:

| Version | What you will see |
|---|---|
| v1.7.1 | `pkg/awsrouter`: the preview deletes the role's attachment of `AmazonSSMManagedInstanceCore`, and the user data changes (the join log goes to the serial console), so the launch template gets a new version and the instance refresh replaces every router once. No input changed. Anything outside this module that relied on the router role holding that managed policy — Session Manager, Systems Manager inventory or patching — loses it; routers were never reachable through Session Manager, and access is now SSH with a certificate or nothing ([safety.md](safety.md#routers-access-diagnosis-and-break-glass)) |
| v1.7.0 | `pkg/awsrouter`: optional `TrustedUserCAKeys` and `AuthorizedPrincipals`. Unset, the user data is byte-for-byte as in 1.6.1 and no router is replaced. Setting them is a new launch-template version and a refresh |
| v1.6.1 | `tailscaled`: the default memory request goes 64Mi → 128Mi and the limit 128Mi → 512Mi, so pods roll. No diff if you set `resources` |
| v1.6.0 | `tsdns`: `debugLog`, off, with an identical Corefile; the default CoreDNS image moves to v1.14.7, so pods roll unless you set `image.tag` |
| v1.5.0 | `tsdns`: `catchAll`, off, with an identical render |
| v1.4.0, v1.3.0, v1.2.0 | new packages: `pkg/awsrouter`, `pkg/tailnet`, `pkg/acl` |
| v1.1.0 | `values.schema.json` for both charts: a values file with an unknown or misspelt key stops rendering. Fix the file; nothing else changes |
