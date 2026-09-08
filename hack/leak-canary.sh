#!/usr/bin/env bash
# This repository is public and its history cannot be unpublished — a
# rewrite changes the SHAs but not what was already fetched. So the rule
# ("mechanism only; particulars are caller inputs") is enforced
# mechanically rather than remembered.
#
# Every chart value that names a cluster, an account, a hostname or a
# secret path is an INPUT with a neutral default. The consuming estate
# supplies the particulars from its own (private) repository.
#
# Copied from truvity/ci-workflows, which is public for the same reason.
# Add a pattern here the first time something new turns out to be a
# particular. Never add an exception without one.
set -uo pipefail

# The 12-digit patterns are anchored on word boundaries. Without them,
# `[0-9]{12}` also matches a 12-digit run that happens to fall inside a
# longer hex string -- and a nixpkgs commit SHA is exactly that. The
# devbox bump to 17de0b976395537756f30a3e78f2f06e5cec89ed contains
# `976395537756`, which failed this canary simultaneously in every repo
# that carries it, for a value that is neither a particular nor secret.
# `\b` keeps every real shape (bare, in an ARN, as an ECR host: each is
# bounded by a non-word character) and drops the hex-embedded ones.
patterns=(
  '\b[0-9]{12}\b'                          # AWS account id
  # No bare 'arn:aws' pattern here, unlike sibling repos: pkg/awsrouter
  # necessarily COMPOSES ARNs from caller inputs (format strings with %s).
  # A concrete leaked ARN still trips the 12-digit account-id pattern.
  '\b[0-9]{12}\.dkr\.ecr\.'              # ECR registry host
  # No '\.svc\.cluster\.local' pattern here, unlike the sibling repos: tsdns
  # is a DNS rewrite to exactly that domain, so the default render
  # necessarily contains it. It is the mechanism, not a particular.
  '/secrets/[a-z0-9-]+/'               # SSM parameter paths (/secrets/<system>/<name>; a bare
                                       # /secrets/<key> mount path is the chart's own mechanism)
  'truvity-[a-z0-9-]*-(ci-cache|artifacts|state)'   # S3 buckets
  '\.truvity\.(xyz|com|co)'            # internal hostnames
  'glpat-|ghp_|github_pat_'            # tokens, in case of an accident
)

fail=0
for p in "${patterns[@]}"; do
  # Exclude this script: it necessarily contains the patterns it bans.
  # go.sum/go.mod carry pseudo-version timestamps (v0.0.0-20200514113438-…)
  # whose digit runs false-positive the AWS-account-id pattern; their
  # content is public dependency data by definition.
  if hits=$(grep -rInE "$p" . \
              --exclude-dir=.git \
              --exclude-dir=.devbox \
              --exclude="go.sum" \
              --exclude="go.mod" \
              --exclude="leak-canary.sh" 2>/dev/null); then
    echo "LEAK: pattern /$p/ matched — particulars belong in caller inputs:"
    echo "$hits" | head -5 | sed 's/^/    /'
    fail=1
  fi
done

if [ "$fail" = 0 ]; then
  echo "leak canary clean — ${#patterns[@]} patterns checked, no particulars found"
fi
exit $fail
