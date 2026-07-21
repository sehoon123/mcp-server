#!/usr/bin/env bash
set -euo pipefail

server_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
proxy_dir=${1:-"$server_dir/../mcp-proxy"}

if [[ ! -x "$proxy_dir/gradlew" || ! -d "$proxy_dir/.git" ]]; then
  echo "Usage: $0 [path-to-mcp-proxy-checkout]" >&2
  exit 2
fi

"$proxy_dir/gradlew" -p "$proxy_dir" clean test shadowJar --no-parallel

artifact="$proxy_dir/build/libs/mcp-proxy-all.jar"
destination="$server_dir/libs/mcp-proxy-all.jar"
cp -- "$artifact" "$destination"

if command -v sha256sum >/dev/null 2>&1; then
  checksum=$(sha256sum "$destination" | cut -d' ' -f1)
else
  checksum=$(shasum -a 256 "$destination" | cut -d' ' -f1)
fi

source_url=$(git -C "$proxy_dir" remote get-url origin)
commit=$(git -C "$proxy_dir" rev-parse HEAD)
branch=$(git -C "$proxy_dir" branch --show-current)
version=$(unzip -p "$destination" META-INF/MANIFEST.MF | tr -d '\r' | awk -F': ' '$1 == "Implementation-Version" { print $2; exit }')

cat > "$server_dir/libs/mcp-proxy-source.txt" <<EOF
Source: $source_url
Commit: $commit
Branch: $branch
Version: $version
Build: ./gradlew clean test shadowJar
Artifact: build/libs/mcp-proxy-all.jar
SHA-256: $checksum
EOF

printf 'Updated %s\nSHA-256: %s\n' "$destination" "$checksum"
