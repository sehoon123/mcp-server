#!/usr/bin/env bash
# Local version parity is a build invariant, not permission to publish a release.
set -euo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT

./gradlew verifyReleaseVersion
version=$(grep '^version=' gradle.properties | cut -d= -f2-)
mismatch=0.0.0
[[ "$version" != "$mismatch" ]] || mismatch=0.0.1
if ./gradlew verifyReleaseVersion -Pversion="$mismatch" >"$log" 2>&1; then
  echo 'Version guard accepted mismatched Gradle/BApp versions' >&2
  exit 1
fi
grep -F "BApp ScreenVersion must match Gradle version $mismatch" "$log" >/dev/null
echo 'Release version parity checks passed'
