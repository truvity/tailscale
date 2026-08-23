# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

# Lint every chart and the Go module.
# tsdns lints with its minimal test case: the schema REQUIRES
# suffix/clusterIP/resolverIP (the chart is meaningless without them),
# and lint validates the merged values. The negative renders prove the
# schema rejects an unknown key.
lint:
    helm lint charts/tailscaled
    helm lint charts/tsdns -f tests/cases/tsdns/minimal/values.yaml
    ! helm template tailscaled charts/tailscaled --set bogusKey=1 >/dev/null 2>&1
    ! helm template tsdns charts/tsdns --set suffix=s --set clusterIP=1.2.3.4 --set resolverIP=1.2.3.5 --set bogusKey=1 >/dev/null 2>&1
    ! helm template tsdns charts/tsdns >/dev/null 2>&1
    golangci-lint config verify
    golangci-lint run ./...

# Golden renders: render every test case and compare with tests/golden.
test:
    hack/golden.sh
    go test ./...

# Regenerate the golden renders — review the diff before committing.
golden:
    hack/golden.sh update

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Compile check (library — nothing to run).
build:
    go build ./...

# Format Go files.
fmt:
    golangci-lint fmt ./...

# Reachable Go advisories (security.yaml, daily).
vuln:
    govulncheck ./...

# Run go mod tidy.
tidy:
    go mod tidy

# Package every chart locally (the release workflow stamps the version from the tag).
package:
    helm package charts/tailscaled --destination dist/
    helm package charts/tsdns --destination dist/

# Everything CI runs on a pull request.
check: build lint test leak-canary vuln
