package tailnetspec_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/tailscale/pkg/tailnetspec"
)

// TestNoNonStdlibImports guards this package's reason to exist: a caller
// must be able to import tailnetspec alone, with no Pulumi or Tailscale SDK
// riding along. `go list -deps` lists every package this one imports,
// transitively; an import path whose first segment contains a "." is a
// module outside the standard library.
func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/tailscale/pkg/tailnetspec"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg {
			continue
		}

		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "pkg/tailnetspec must depend on the standard library only, found %q", line)
	}
}

func TestServiceIP(t *testing.T) {
	ip, err := tailnetspec.ServiceIP("172.20.0.0/16", 53)
	require.NoError(t, err)
	assert.Equal(t, "172.20.0.53", ip)

	ip, err = tailnetspec.ServiceIP("172.20.0.0/16", 10)
	require.NoError(t, err)
	assert.Equal(t, "172.20.0.10", ip)

	_, err = tailnetspec.ServiceIP("172.20.0.0/30", 53)
	require.Error(t, err)

	_, err = tailnetspec.ServiceIP("fd00::/64", 53)
	require.Error(t, err)
}

func TestValidMagicDNSSuffix(t *testing.T) {
	for s, want := range map[string]bool{
		"tail03ed59.ts.net": true,
		"my-net.ts.net":     true,
		"ts.net":            false,
		"a.b.ts.net":        false,
		"-x.ts.net":         false,
		"example.com":       false,
		"":                  false,
	} {
		assert.Equal(t, want, tailnetspec.ValidMagicDNSSuffix(s), "%q", s)
	}
}
