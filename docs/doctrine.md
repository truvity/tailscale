# Doctrine — the design rules

## Five pieces, along the lines that divide them

**`charts/tailscaled` makes a cluster reachable.** A plain Deployment in
userspace mode, not the Tailscale operator: it needs no CRDs, no RBAC, no
`NET_ADMIN` and no particular CNI, so it installs the same way everywhere
and removing it leaves nothing behind.

**`charts/tsdns` makes it nameable.** A small CoreDNS whose only job is a
tailnet-only suffix, a few forwarded zones and, on request, everything else.
It is separate from the cluster's own resolver because a managed resolver
often cannot be extended, and because what the tailnet may resolve should
not depend on what the cluster resolves.

**`pkg/acl` is the policy as a model.** Pure data in, deterministic JSON
out: no SDK, no cloud, no files. The same model always renders the same
document, so a policy change is reviewed as a diff of the model, and the
rules (tag ownership, the two tiers, per-environment approval) are code
rather than a document someone edits by hand.

**`pkg/tailnet` is the tailnet's resources.** Thin wrappers that add only the
conventions that make them safe: sole ownership of the policy, keys that are
tagged, ephemeral and bounded, rotation by name.

**`pkg/awsrouter` is the one cloud-specific piece.** An EC2 router is AWS by
definition, so it lives in its own package and nothing else imports a cloud.

## Routers are cattle

A router holds no state worth keeping: it joins with a key, advertises
routes the policy has already approved, and can be replaced at any moment by
one that does the same. Everything follows from that:

- **No interactive access by default**, and at most SSH with a certificate
  from a CA the caller names, over the tailnet. No Session Manager, no key
  pair, no open TCP port.
- **Break-glass is replacement**, never logging in to fix a router. The fleet
  replaces an instance, and the lifecycle hook keeps the new one out of
  service until it has joined.
- **Diagnosis needs no shell.** The join logs to the serial console.
- **Change arrives as a new instance.** A change to the user data or the
  image is a new launch-template version, rolled through the fleet by the
  instance refresh; nothing is changed on a running router except by its own
  nightly updates.

## The policy follows the key, not the other way round

Tailscale grants by tag. So ownership is a hierarchy (one manager tag owns
every router tag, and the tailnet's OAuth client holds only the manager
tag), keys are always tagged, and every route a router advertises is
approved for that router's tag in advance. A router therefore never waits
for a person, and an environment's routes are approved only for its own
tags.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| the charts' objects and their defaults | the CIDRs, the hostnames, the suffix, the pinned addresses, the resolver |
| the shape of the policy: tag ownership, tiers, auto-approval | the networks, the clusters, the groups and who is in them |
| that keys are tagged, ephemeral, bounded and rotated by name | the OAuth client, and where the keys are stored |
| the router fleet's security group, role, launch template and user data | the account, the VPC, the subnets, the permissions boundary, the SSH CA and its principals |
| that a refusal happens before anything is created | the values and inputs themselves |

## Rules a change must keep

- **Mechanism only.** A default that names a tailnet, a cluster, an account
  or an address is a leak; a default that picks one is a decision the estate
  did not make.
- **Keys go out, never in.** A package returns a secret as an Output; it never
  stores one, and a chart takes a Secret's *name*.
- **A new capability renders nothing until asked for.** An existing values
  file or program renders, or previews, byte-for-byte the same after an
  upgrade unless the release says otherwise; the router's default user data
  is pinned by a golden file for exactly this reason (see
  [adoption.md](adoption.md)).
- **Every refusal has a fixture or a test.** A chart rule comes with its file
  in `tests/invalid/<chart>/`; a Go refusal comes with its test case.
