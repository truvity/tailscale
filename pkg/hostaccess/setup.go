package hostaccess

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// hostaccess-setup.sh is embedded so a consumer's build computes the sha256
// of the exact bytes goreleaser publishes as that release's
// `hostaccess-setup-vX.Y.Z.sh` asset: both are the same git blob at the tag.
//
//go:embed hostaccess-setup.sh
var setupScript string

// SetupScript returns hostaccess-setup.sh exactly as embedded in this build.
func SetupScript() string { return setupScript }

// SetupSHA256 is the lowercase-hex sha256 of SetupScript.
func SetupSHA256() string {
	sum := sha256.Sum256([]byte(setupScript))

	return hex.EncodeToString(sum[:])
}

// SetupAssetName is the GitHub Release asset name of the script at an "X.Y.Z"
// release of truvity/tailscale.
func SetupAssetName(version string) string { return fmt.Sprintf("hostaccess-setup-v%s.sh", version) }

// SetupURL is the download URL of that asset.
func SetupURL(version string) string {
	return fmt.Sprintf("https://github.com/truvity/tailscale/releases/download/v%s/%s", version, SetupAssetName(version))
}

const (
	// ConfDir is where the consumer's per-host files go.
	ConfDir = "/etc/hostaccess"
	// SetupPath is where the script is installed and run from.
	SetupPath = "/usr/local/sbin/hostaccess-setup.sh"
	// BootSignerPath is the script that signs the host certificate once, now.
	// A consumer on PrincipalTailscale runs it after the tailnet join; with
	// PrincipalIMDSHostname the setup script and a boot-time unit already do.
	BootSignerPath = "/usr/local/sbin/openbao-hostcert-boot.sh"
)

// Delivery is how the setup script reaches the host.
type Delivery int

const (
	// DeliveryDownload (the default) fetches the script from the release
	// asset and refuses to run it unless its sha256 matches the one Render
	// computed from the embedded copy. It costs a few hundred bytes of user
	// data. The host needs egress to github.com, as opkssh's artifacts do.
	DeliveryDownload Delivery = iota
	// DeliveryInline writes the script with the other files. No download, but
	// the script is about 16 KB: use EncodingGzipBase64, or expect to exceed
	// EC2's 16 KiB user-data limit.
	DeliveryInline
)

// Options are what Render needs beyond the Config.
type Options struct {
	Delivery Delivery
	// Version is the "X.Y.Z" truvity/tailscale release the script is
	// downloaded from, which must be the version of this module the consumer
	// builds against (the digest is of the embedded copy). Required for
	// DeliveryDownload.
	Version string
}

// File is one file to write: an absolute path, an octal mode and the content.
type File struct {
	Path    string
	Mode    string
	Content string
}

// Bundle is what a consumer applies to a host.
type Bundle struct {
	// Packages to install before Commands run.
	Packages []string
	// Files to write before Commands run. In DeliveryInline the setup script
	// is one of them.
	Files []File
	// Commands run in order, as root, after Files are written and Packages
	// are installed. Each is a shell script; each fails safe (a failure is
	// logged and the host keeps its plain host key).
	Commands []string
	// ScriptSHA256 and ScriptBytes describe hostaccess-setup.sh.
	ScriptSHA256 string
	ScriptBytes  int
}

// Encoding is how file content is carried in cloud-config.
type Encoding int

const (
	// EncodingPlain is YAML block text.
	EncodingPlain Encoding = iota
	// EncodingGzipBase64 is cloud-init's `gz+b64`: about 0.45x the plain size
	// for the setup script.
	EncodingGzipBase64
)

// Render validates c and returns the files and commands that apply it.
func Render(c Config, o Options) (*Bundle, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	if o.Delivery == DeliveryDownload && !versionPattern.MatchString(o.Version) {
		return nil, errors.New("hostaccess: Options.Version must be \"X.Y.Z\" for DeliveryDownload")
	}

	b := &Bundle{ScriptSHA256: SetupSHA256(), ScriptBytes: len(setupScript)}

	var env strings.Builder

	fmt.Fprintf(&env, "OPKSSH=\"%t\"\n", c.opksshOn())

	if c.opksshOn() {
		b.Packages = append(b.Packages, "checkpolicy")

		op := c.OPKSSH
		envLines(&env, [][2]string{
			{"OPKSSH_ARTIFACT_VERSION", op.ArtifactVersion},
			{"OPKSSH_ARTIFACT_URL", op.ArtifactURL},
			{"OPKSSH_ARTIFACT_SHA256", op.ArtifactSHA256},
			{"OPKSSH_SELINUX_URL", op.SELinuxModuleURL},
			{"OPKSSH_SELINUX_SHA256", op.SELinuxModuleSHA256},
		})

		var providers, authIDs strings.Builder
		for _, p := range op.Providers {
			fmt.Fprintf(&providers, "%s %s %s\n", p.Issuer, p.ClientID, p.Expiration)
		}

		for _, a := range op.AuthorizedIdentities {
			fmt.Fprintf(&authIDs, "%s oidc:groups:%s %s\n", a.User, a.Group, a.Issuer)
		}

		b.Files = append(b.Files,
			File{ConfDir + "/opkssh-providers", "0600", providers.String()},
			File{ConfDir + "/opkssh-auth_id", "0600", authIDs.String()},
		)
	}

	fmt.Fprintf(&env, "HOST_CERT=\"%t\"\n", c.hostCertOn())

	if c.hostCertOn() {
		h := c.HostCert
		envLines(&env, [][2]string{
			{"HOST_CERT_PRINCIPAL_SOURCE", string(c.principalSource())},
			{"HOST_CERT_ARTIFACT_VERSION", h.ArtifactVersion},
			{"HOST_CERT_ARTIFACT_SHA256", h.ArtifactSHA256[HostCertArch]},
			{"HOST_CERT_ADDRESS", h.Address},
			{"HOST_CERT_NAMESPACE", h.Namespace},
			{"HOST_CERT_AUTH_MOUNT", h.AuthMount},
			{"HOST_CERT_AUTH_ROLE", h.AuthRole},
			{"HOST_CERT_SERVER_ID_HEADER", h.ServerIDHeader},
			{"HOST_CERT_SSH_MOUNT", h.SSHMount},
			{"HOST_CERT_SSH_ROLE", h.SSHRole},
			{"HOST_CERT_PRINCIPAL_PATTERNS", strings.Join(h.PrincipalPatterns, ",")},
		})

		if h.CABundle != "" {
			b.Files = append(b.Files, File{ConfDir + "/hostcert-ca.pem", "0644", strings.TrimRight(h.CABundle, "\n") + "\n"})
		}
	}

	b.Files = append([]File{{ConfDir + "/hostaccess.env", "0600", env.String()}}, b.Files...)

	switch o.Delivery {
	case DeliveryInline:
		b.Files = append(b.Files, File{SetupPath, "0755", setupScript})
		b.Commands = []string{SetupPath + ` || echo "hostaccess-setup fail"`}
	default:
		// Fail closed: a download failure or a digest mismatch runs nothing.
		b.Commands = []string{fmt.Sprintf(
			`curl -fsSL -o %[1]s "%[2]s" && echo "%[3]s  %[1]s" | sha256sum -c - && chmod 0755 %[1]s && %[1]s || echo "hostaccess-setup fail"`,
			SetupPath, SetupURL(o.Version), b.ScriptSHA256)}
	}

	return b, nil
}

// envLines writes KEY="value" lines; Validate has already refused any value
// with a quote, a dollar sign or a backtick.
func envLines(w *strings.Builder, kv [][2]string) {
	for _, e := range kv {
		fmt.Fprintf(w, "%s=\"%s\"\n", e[0], e[1])
	}
}

type cloudFile struct {
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"`
	Encoding    string `yaml:"encoding,omitempty"`
	Content     string `yaml:"content"`
}

// WriteFilesYAML is the `write_files:` list items for cloud-config (the
// "- path: ..." entries, without the `write_files:` key), each line indented
// by `indent` spaces, ready to paste under a write_files key.
func (b *Bundle) WriteFilesYAML(enc Encoding, indent int) (string, error) {
	items := make([]cloudFile, 0, len(b.Files))

	for _, f := range b.Files {
		cf := cloudFile{Path: f.Path, Permissions: f.Mode, Content: f.Content}

		if enc == EncodingGzipBase64 && len(f.Content) > 512 {
			var buf bytes.Buffer

			zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			if err != nil {
				return "", err
			}

			if _, err := zw.Write([]byte(f.Content)); err != nil {
				return "", err
			}

			if err := zw.Close(); err != nil {
				return "", err
			}

			cf.Encoding, cf.Content = "gz+b64", base64.StdEncoding.EncodeToString(buf.Bytes())
		}

		items = append(items, cf)
	}

	out, err := yaml.Marshal(items)
	if err != nil {
		return "", err
	}

	pad := strings.Repeat(" ", indent)

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// Size is the bytes this bundle adds to user data: its write_files entries
// (in the given encoding) and its commands, as cloud-config renders them.
// EC2 refuses user data over 16384 bytes in all.
func (b *Bundle) Size(enc Encoding) (int, error) {
	y, err := b.WriteFilesYAML(enc, 2)
	if err != nil {
		return 0, err
	}

	n := len(y)
	for _, c := range b.Commands {
		n += len("  - |\n    ") + len(c) + 1
	}

	return n, nil
}
