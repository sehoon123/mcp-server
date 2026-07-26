#!/usr/bin/env bash
set -euo pipefail

server_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
proxy_dir=${1:-"$server_dir/../mcp-proxy"}
expected_source_url=https://github.com/sehoon123/mcp-proxy
expected_remote_ref=refs/heads/main
destination="$server_dir/libs/mcp-proxy-all.jar"
metadata="$server_dir/libs/mcp-proxy-source.txt"
lock_dir="$server_dir/libs/.proxy-update.lock"
stage=
committed=false
replacement_started=false

if [[ ! -x "$proxy_dir/gradlew" || ! -d "$proxy_dir/.git" ]]; then
  echo "Usage: $0 [path-to-mcp-proxy-checkout]" >&2
  exit 2
fi
if ! mkdir -- "$lock_dir" 2>/dev/null; then
  echo "Another proxy update is already in progress: $lock_dir" >&2
  exit 1
fi
cleanup() {
  if [[ "$committed" != true && "$replacement_started" == true && -n "$stage" ]]; then
    rm -f -- "$destination" "$metadata"
    [[ -f "$stage/old.jar" ]] && mv -- "$stage/old.jar" "$destination"
    [[ -f "$stage/old-source.txt" ]] && mv -- "$stage/old-source.txt" "$metadata"
  fi
  [[ -n "$stage" ]] && rm -rf -- "$stage"
  rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT

configured_source_url=$(git -C "$proxy_dir" remote get-url origin)
source_url=${configured_source_url%.git}
if [[ "$source_url" != "$expected_source_url" ]]; then
  echo "Refusing unexpected proxy origin: $configured_source_url" >&2
  exit 1
fi

if [[ -n $(git -C "$proxy_dir" status --porcelain --untracked-files=all) ]]; then
  echo "Refusing to build a dirty proxy checkout" >&2
  exit 1
fi

commit=$(git -C "$proxy_dir" rev-parse --verify HEAD^{commit})
if [[ ! "$commit" =~ ^[a-f0-9]{40}$ ]]; then
  echo "Proxy HEAD is not a full commit SHA" >&2
  exit 1
fi
branch=$(git -C "$proxy_dir" branch --show-current)
branch=${branch:-detached}
if [[ "$branch" != main && "$branch" != detached ]]; then
  echo "Proxy checkout must be on main or detached at the trusted main commit" >&2
  exit 1
fi
remote_commit=$(git ls-remote --exit-code "$expected_source_url" "$expected_remote_ref" | awk 'NR == 1 { print $1 }')
if [[ ! "$remote_commit" =~ ^[a-f0-9]{40}$ || "$commit" != "$remote_commit" ]]; then
  echo "Proxy HEAD is not the current immutable $expected_remote_ref at $expected_source_url" >&2
  exit 1
fi

"$proxy_dir/gradlew" -p "$proxy_dir" clean test shadowJar writeRuntimeComponents --no-parallel --no-build-cache

if [[ -n $(git -C "$proxy_dir" status --porcelain --untracked-files=all) ]]; then
  echo "Proxy build modified or created an unexpected source-tree file" >&2
  exit 1
fi
if [[ $(git -C "$proxy_dir" rev-parse --verify HEAD^{commit}) != "$commit" ]]; then
  echo "Proxy HEAD changed while the build was running" >&2
  exit 1
fi
remote_commit_after=$(git ls-remote --exit-code "$expected_source_url" "$expected_remote_ref" | awk 'NR == 1 { print $1 }')
if [[ "$remote_commit_after" != "$commit" ]]; then
  echo "Trusted proxy ref moved while the build was running; discarding the result" >&2
  exit 1
fi

artifact="$proxy_dir/build/libs/mcp-proxy-all.jar"
components="$proxy_dir/build/reports/runtime-components.txt"
[[ -s "$artifact" ]] || { echo "Missing built proxy artifact" >&2; exit 1; }
[[ -s "$components" ]] || { echo "Missing proxy runtime component report" >&2; exit 1; }

if grep -Ev '^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^[:space:]]+ [a-f0-9]{64}$' "$components" | grep -q .; then
  echo "Invalid proxy runtime component report" >&2
  exit 1
fi
if [[ $(LC_ALL=C sort -u "$components" | wc -l | tr -d ' ') != $(wc -l < "$components" | tr -d ' ') ]]; then
  echo "Duplicate proxy runtime component entry" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  checksum=$(sha256sum "$artifact" | cut -d' ' -f1)
else
  checksum=$(shasum -a 256 "$artifact" | cut -d' ' -f1)
fi
manifest=$(unzip -p "$artifact" META-INF/MANIFEST.MF | tr -d '\r')
manifest_value() {
  local key=$1
  awk -F': ' -v key="$key" '$1 == key { print $2; exit }' <<< "$manifest"
}
version=$(manifest_value Implementation-Version)
[[ -n "$version" && "$version" != *$'\n'* ]] || { echo "Missing proxy implementation version" >&2; exit 1; }
[[ $(manifest_value Implementation-Title) == "Independent MCP Bridge stdio proxy" ]] || { echo "Unexpected proxy title" >&2; exit 1; }
[[ $(manifest_value Implementation-Vendor) == "sehoon123" ]] || { echo "Unexpected proxy vendor" >&2; exit 1; }
[[ $(manifest_value Implementation-Source) == "$expected_source_url" ]] || { echo "Unexpected proxy source identity" >&2; exit 1; }
[[ $(manifest_value Fork-Status) == "Unofficial independent fork; not supported by PortSwigger" ]] || { echo "Missing independent fork status" >&2; exit 1; }
for entry in \
  META-INF/legal/GPL-3.0.txt \
  META-INF/legal/NOTICE.md \
  META-INF/legal/FORK_NOTICE.md \
  META-INF/legal/THIRD_PARTY_NOTICES.md \
  META-INF/legal/CORRESPONDING_SOURCE.md \
  META-INF/legal/licenses/Apache-2.0.txt \
  META-INF/legal/licenses/MIT-SLF4J.txt \
  META-INF/independent-mcp-bridge/runtime-components.txt; do
  unzip -p "$artifact" "$entry" >/dev/null || { echo "Missing proxy JAR entry: $entry" >&2; exit 1; }
done
if ! cmp -s "$components" <(unzip -p "$artifact" META-INF/independent-mcp-bridge/runtime-components.txt); then
  echo "Embedded proxy runtime report does not match the generated report" >&2
  exit 1
fi

stage=$(mktemp -d "$server_dir/libs/.proxy-update.XXXXXX")
cp -- "$artifact" "$stage/new.jar"
cat > "$stage/new-source.txt" <<EOF
Source: $source_url
Commit: $commit
Branch: $branch
Version: $version
Build: ./gradlew clean test shadowJar writeRuntimeComponents --no-build-cache
Artifact: build/libs/mcp-proxy-all.jar
SHA-256: $checksum
EOF
while IFS= read -r component; do
  printf 'Runtime component: %s\n' "$component" >> "$stage/new-source.txt"
done < "$components"

replacement_started=true
[[ -f "$destination" ]] && mv -- "$destination" "$stage/old.jar"
[[ -f "$metadata" ]] && mv -- "$metadata" "$stage/old-source.txt"
mv -- "$stage/new.jar" "$destination"
mv -- "$stage/new-source.txt" "$metadata"
committed=true

printf 'Updated %s from %s\nSHA-256: %s\n' "$destination" "$commit" "$checksum"
