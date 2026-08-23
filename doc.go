// Package tailscale is the module root of github.com/truvity/tailscale.
//
// The module ships Tailscale mechanism for Kubernetes estates: the
// tailscaled (subnet router) and tsdns (split-DNS gateway) Helm charts
// under charts/, and Pulumi Go packages — pkg/acl, a pure
// tailnet policy builder (shipped); pkg/tailnet, the policy resource, router keys, split DNS
// and flow logs (shipped — per-cluster router wiring folded in rather
// than a separate k8srouter package); pkg/awsrouter, an EC2
// auto-scaling subnet router fleet (shipped). Credentials come in
// as providers, keys go out as Outputs; the caller stores them.
package tailscale
