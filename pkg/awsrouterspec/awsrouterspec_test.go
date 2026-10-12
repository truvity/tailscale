package awsrouterspec_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/tailscale/pkg/awsrouterspec"
)

// TestNoNonStdlibImports guards this package's reason to exist: a caller
// must be able to import awsrouterspec alone, with no Pulumi or AWS SDK
// riding along.
func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/tailscale/pkg/awsrouterspec"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg {
			continue
		}

		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "pkg/awsrouterspec must depend on the standard library only, found %q", line)
	}
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "env1-tailscale-acme", awsrouterspec.InstanceRoleName("env1", "acme"))

	got, err := awsrouterspec.HostnamePatterns("10.65.0.0/16", "tail1.ts.net")
	require.NoError(t, err)
	assert.Equal(t, []string{"ip-10-65-*.tail1.ts.net"}, got)
}
