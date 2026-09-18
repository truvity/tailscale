package awsrouter

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH user certificates (TrustedUserCAKeys + AuthorizedPrincipals).
//
// With both inputs set, cloud-init writes
//
//   - /etc/ssh/trusted-user-ca-keys.pub — the CA public keys, one per line;
//   - /etc/ssh/authorized_principals/<user> — the principals each user
//     admits, one per line;
//   - /etc/ssh/sshd_config.d/10-user-ca.conf — TrustedUserCAKeys,
//     AuthorizedPrincipalsFile, AuthorizedKeysFile none (no static keys),
//     PubkeyAuthentication yes, PasswordAuthentication no and
//     LogLevel VERBOSE (sshd logs each certificate's key id and serial).
//
// and takes sshd off the primary interface's firewalld zone: the
// security group opens no TCP port, so SSH arrives over the tailnet
// interface (the trusted zone) or not at all.
//
// sshd keeps the FIRST value it reads for a keyword and reads the
// sshd_config.d drop-ins in lexical order, so the drop-in sorts before
// the distribution's and cloud-init's own (50-*): what it says is what
// sshd does.

var (
	// loginUserPattern is a conservative POSIX login name: it becomes a
	// file name under /etc/ssh/authorized_principals.
	loginUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// principalPattern keeps an authorized_principals line unambiguous:
	// sshd reads a line as optional key options followed by the
	// principal, and "#" starts a comment.
	principalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)
)

type (
	// sshUserCAParams is the template's view of the two inputs, sorted.
	sshUserCAParams struct {
		TrustedUserCAKeys []string
		Principals        []principalsFile
	}

	// principalsFile is one /etc/ssh/authorized_principals/<User>.
	principalsFile struct {
		User       string
		Principals []string
	}
)

// validateSSHUserCA reports the first error in the SSH certificate inputs.
// Both empty is valid: certificate login is off.
func (c TailscaleInstanceConfig) validateSSHUserCA() error {
	if len(c.TrustedUserCAKeys) == 0 && len(c.AuthorizedPrincipals) == 0 {
		return nil
	}

	if len(c.TrustedUserCAKeys) == 0 {
		return errors.New("awsrouter: AuthorizedPrincipals needs TrustedUserCAKeys")
	}

	if len(c.AuthorizedPrincipals) == 0 {
		return errors.New("awsrouter: TrustedUserCAKeys needs AuthorizedPrincipals — without them no certificate opens any user")
	}

	seen := map[string]bool{}

	for i, raw := range c.TrustedUserCAKeys {
		line := strings.TrimSpace(raw)

		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
			return fmt.Errorf("awsrouter: TrustedUserCAKeys[%d] is not one plain OpenSSH public key", i)
		}

		if _, isCert := key.(*ssh.Certificate); isCert {
			return fmt.Errorf("awsrouter: TrustedUserCAKeys[%d] is a certificate, not a CA public key", i)
		}

		fp := ssh.FingerprintSHA256(key)
		if seen[fp] {
			return fmt.Errorf("awsrouter: TrustedUserCAKeys[%d] repeats %s", i, fp)
		}

		seen[fp] = true
	}

	for user, principals := range c.AuthorizedPrincipals {
		if !loginUserPattern.MatchString(user) {
			return fmt.Errorf("awsrouter: AuthorizedPrincipals user %q is not a login name", user)
		}

		if user == "root" {
			return errors.New("awsrouter: AuthorizedPrincipals names root, which sshd refuses (PermitRootLogin no)")
		}

		if len(principals) == 0 {
			return fmt.Errorf("awsrouter: AuthorizedPrincipals[%q] is empty — omit the user instead", user)
		}

		for _, p := range principals {
			if !principalPattern.MatchString(p) {
				return fmt.Errorf("awsrouter: AuthorizedPrincipals[%q] principal %q is not a plain name", user, p)
			}
		}

		sorted := slices.Sorted(slices.Values(principals))
		if len(slices.Compact(sorted)) != len(principals) {
			return fmt.Errorf("awsrouter: AuthorizedPrincipals[%q] repeats a principal", user)
		}
	}

	return nil
}

// sshUserCAParams renders the inputs for the template, sorted so the
// user data (and with it the launch template) never changes with map
// order or with the order a caller listed principals in. nil when
// certificate login is off. Call validateSSHUserCA first.
func (c TailscaleInstanceConfig) sshUserCAParams() *sshUserCAParams {
	if len(c.TrustedUserCAKeys) == 0 {
		return nil
	}

	params := &sshUserCAParams{}

	for _, raw := range c.TrustedUserCAKeys {
		params.TrustedUserCAKeys = append(params.TrustedUserCAKeys, strings.TrimSpace(raw))
	}

	users := make([]string, 0, len(c.AuthorizedPrincipals))
	for user := range c.AuthorizedPrincipals {
		users = append(users, user)
	}

	sort.Strings(users)

	for _, user := range users {
		params.Principals = append(params.Principals, principalsFile{
			User:       user,
			Principals: slices.Sorted(slices.Values(c.AuthorizedPrincipals[user])),
		})
	}

	return params
}
