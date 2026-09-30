# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/tailscale/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## What is in scope

This repository publishes:

- The Go packages `pkg/acl`, `pkg/tailnet` and `pkg/awsrouter`.
- The chart `tailscaled`.
- The documentation, where it tells an adopter to do something unsafe.

Reports that matter most:

- `pkg/acl` producing a policy that grants more reach than its model states: a wrong tag owner, a missing tier boundary, a route auto-approved in the wrong environment.
- Auth keys that are not ephemeral, tagged and rotated as documented, or that reach a log, an error or an output in the clear.
- `pkg/awsrouter` creating a security group, role or launch template wider than documented, or weakening the SSH-certificate or OIDC sign-in it offers.
- A chart default that adds a capability, a privilege or a network path the documentation says it does not.

A finding that depends on how a particular deployment uses this repository
belongs with that deployment's owner.
