package awsrouter

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// router-setup.sh does everything the cloud-init user data used to do
// directly (chrony, audit, journald, sshd hardening, the tailnet join,
// the optional SSH user-certificate and opkssh sign-in) — see its own
// header comment. It is embedded here so this package can compute its
// sha256 from the exact bytes any consumer's build resolves at this
// module version, which is also the exact content goreleaser publishes
// as that version's `router-setup-vX.Y.Z.sh` GitHub Release asset: both
// come from the same git blob at the tag, so the two are always equal
// by construction — nobody hand-maintains a checksum for this file.
//
//go:embed router-setup.sh
var routerSetupScript string

// routerSetupVersionPattern is "X.Y.Z", no leading "v" — the same shape
// as a git tag with the "v" stripped.
var routerSetupVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// RouterSetupScript returns router-setup.sh's contents, exactly as
// embedded in this build. Exported for callers that publish it as a
// release asset (a goreleaser `extra_files` entry references the file
// on disk directly, so production releases don't need this — it exists
// for tooling and tests that want the content without reading the repo
// file directly).
func RouterSetupScript() string { return routerSetupScript }

// RouterSetupSHA256 returns the lowercase-hex sha256 of router-setup.sh
// as embedded in this build.
func RouterSetupSHA256() string {
	sum := sha256.Sum256([]byte(routerSetupScript))

	return hex.EncodeToString(sum[:])
}

// RouterSetupAssetName is the GitHub Release asset name for
// router-setup.sh at the given "X.Y.Z" version (no leading "v").
func RouterSetupAssetName(version string) string {
	return fmt.Sprintf("router-setup-v%s.sh", version)
}

// RouterSetupURL is the GitHub Release download URL for router-setup.sh
// at the given "X.Y.Z" version (no leading "v").
func RouterSetupURL(version string) string {
	return fmt.Sprintf("https://github.com/truvity/tailscale/releases/download/v%s/%s", version, RouterSetupAssetName(version))
}

// validateRouterSetupVersion requires TailscaleInstanceConfig's
// RouterSetupVersion to be a plain "X.Y.Z" — it is composed directly
// into a GitHub Release download URL, so anything looser is refused
// here rather than producing a bootstrap that fetches the wrong (or no)
// release.
func (c TailscaleInstanceConfig) validateRouterSetupVersion() error {
	if c.RouterSetupVersion == "" {
		return errors.New("awsrouter: RouterSetupVersion is required")
	}

	if !routerSetupVersionPattern.MatchString(c.RouterSetupVersion) {
		return fmt.Errorf("awsrouter: RouterSetupVersion %q is not \"X.Y.Z\"", c.RouterSetupVersion)
	}

	return nil
}
