# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

charts := "tailscaled tsdns"

# Lint every chart and the Go module.
# tsdns lints with its minimal test case: the schema REQUIRES
# suffix/clusterIP/resolverIP (the chart is meaningless without them),
# and lint validates the merged values. Every negative fixture under
# tests/invalid/<chart>/ must fail to render — one that renders is a hole
# in the validation nobody would otherwise notice.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    helm lint charts/tailscaled
    helm lint charts/tsdns -f tests/cases/tsdns/minimal/values.yaml
    # Not `! helm template ...`: bash's `set -e` ignores a command negated
    # with `!`, so such a probe could never fail the recipe.
    if helm template tailscaled charts/tailscaled --set bogusKey=1 >/dev/null 2>&1; then
      echo "tailscaled: an unknown key rendered" >&2
      exit 1
    fi
    if helm template tsdns charts/tsdns >/dev/null 2>&1; then
      echo "tsdns: rendered without its required values" >&2
      exit 1
    fi
    for chart in {{ charts }}; do
      for values in tests/invalid/"$chart"/*.yaml; do
        if helm template invalid "charts/$chart" -f "$values" >/dev/null 2>&1; then
          echo "RENDERED BUT SHOULD HAVE FAILED: $values" >&2
          exit 1
        fi
      done
      echo "$chart: schema and $(ls tests/invalid/"$chart"/*.yaml | wc -l | tr -d ' ') negative fixtures OK"
    done
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
