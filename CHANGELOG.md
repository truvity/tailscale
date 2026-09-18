# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts and the Go module are released
together at every version.

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
