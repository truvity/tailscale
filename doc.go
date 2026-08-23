// Package tailscale is the module root of github.com/truvity/tailscale.
//
// The module ships Tailscale mechanism for Kubernetes estates: the
// tailscaled (subnet router) and tsdns (split-DNS gateway) Helm charts
// under charts/, and Pulumi Go packages — pkg/acl, a pure
// tailnet policy builder (shipped); (planned) pkg/tailnet, the policy, keys and split-DNS
// resources; pkg/k8srouter, per-cluster router keys and DNS entries;
// pkg/awsrouter, an EC2 auto-scaling subnet router. Credentials come in
// as providers, keys go out as Outputs; the caller stores them.
package tailscale
