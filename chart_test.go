package tailscale

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v3"
)

// TestTailscaledDefaultImageTagIsVPrefixed guards against the
// ImagePullBackOff regression where charts/tailscaled/values.yaml pinned
// image.tag to a bare-numeric version (e.g. "1.102.4"). Docker Hub's
// tailscale/tailscale tags are v-prefixed (v1.102.4); a bare-numeric tag
// 404s and every pod fails to pull.
func TestTailscaledDefaultImageTagIsVPrefixed(t *testing.T) {
	raw, err := os.ReadFile("charts/tailscaled/values.yaml")
	require.NoError(t, err)

	var values struct {
		Image struct {
			Tag string `yaml:"tag"`
		} `yaml:"image"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &values))

	require.Regexp(t, regexp.MustCompile(`^v\d`), values.Image.Tag,
		"charts/tailscaled/values.yaml image.tag must be v-prefixed (Docker Hub tailscale/tailscale tags are v-prefixed; a bare-numeric tag 404s)")
}
