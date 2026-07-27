#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "history diagnostics require a clean Git worktree" >&2
  exit 1
fi

SOURCE_COMMIT=$(git rev-parse --verify HEAD)
if [[ ! "$SOURCE_COMMIT" =~ ^[a-f0-9]{40}$ ]]; then
  echo "could not resolve a full lowercase source commit" >&2
  exit 1
fi

JDK_IMAGE=${HISTORY_PROBE_JDK_IMAGE:-eclipse-temurin:21-jdk}
GRADLE_VOLUME=${HISTORY_PROBE_GRADLE_VOLUME:-mcp-server-history-probe}
DOCKER_MEMORY=${HISTORY_PROBE_DOCKER_MEMORY:-4g}

if ! docker image inspect "$JDK_IMAGE" >/dev/null 2>&1; then
  docker pull "$JDK_IMAGE" >/dev/null
fi
RESOLVED_IMAGE=$(docker image inspect "$JDK_IMAGE" --format '{{range .RepoDigests}}{{println .}}{{end}}' | awk 'NF { print; exit }')
if [[ -z "$RESOLVED_IMAGE" ]]; then
  RESOLVED_IMAGE=$(docker image inspect "$JDK_IMAGE" --format '{{.Id}}')
fi
IMAGE_ID=$(docker image inspect "$RESOLVED_IMAGE" --format '{{.Id}}')

PROBE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mcp-history-diagnostics.XXXXXX")
trap 'rm -rf "$PROBE_ROOT"' EXIT
SOURCE_DIR="$PROBE_ROOT/source"
OUTPUT_DIR="$PROBE_ROOT/output"
INIT_SCRIPT="$PROBE_ROOT/readonly-build.gradle"
mkdir -p "$SOURCE_DIR" "$OUTPUT_DIR"
git archive --format=tar "$SOURCE_COMMIT" | tar -xf - -C "$SOURCE_DIR"
cat > "$INIT_SCRIPT" <<'EOF'
gradle.beforeProject { project ->
    project.layout.buildDirectory.set(project.file(System.getenv('PROBE_BUILD_DIR')))
}
EOF

RUN_ID="${SOURCE_COMMIT:0:12}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
docker run --rm \
  --memory="$DOCKER_MEMORY" \
  -e SOURCE_COMMIT="$SOURCE_COMMIT" \
  -e PROBE_SOURCE_ARCHIVE=true \
  -e PROBE_RUN_ID="$RUN_ID" \
  -e PROBE_CONTAINER_IMAGE="$RESOLVED_IMAGE" \
  -e PROBE_CONTAINER_IMAGE_ID="$IMAGE_ID" \
  -e PROBE_CONTAINER_MEMORY="$DOCKER_MEMORY" \
  -e PROBE_BUILD_DIR=/probe-output/build \
  -v "$SOURCE_DIR":/source:ro \
  -v "$OUTPUT_DIR":/probe-output \
  -v "$INIT_SCRIPT":/probe/readonly-build.gradle:ro \
  -v "$GRADLE_VOLUME":/root/.gradle \
  --tmpfs /workspace:rw,exec,size=1g \
  -w /workspace \
  "$RESOLVED_IMAGE" \
  sh -euc 'cp -a /source/. /workspace/ &&
    ./gradlew --no-daemon --no-build-cache \
      --project-cache-dir /probe-output/project-cache \
      -Dkotlin.project.persistent.dir=/probe-output/kotlin \
      --init-script /probe/readonly-build.gradle \
      historyPerformanceProbe'

ARCHIVED_OUTPUT="$OUTPUT_DIR/build/reports/performance/history-synthetic.jsonl"
if [[ ! -s "$ARCHIVED_OUTPUT" ]]; then
  echo "diagnostic did not create $ARCHIVED_OUTPUT" >&2
  exit 1
fi
if [[ "$(wc -l < "$ARCHIVED_OUTPUT" | tr -d ' ')" != "12" ]]; then
  echo "diagnostic output must contain exactly 12 JSON Lines records" >&2
  exit 1
fi
grep -Fq "\"sourceCommit\":\"$SOURCE_COMMIT\"" "$ARCHIVED_OUTPUT"
grep -Fq '"sourceArchive":true' "$ARCHIVED_OUTPUT"
grep -Fq "\"containerImageId\":\"$IMAGE_ID\"" "$ARCHIVED_OUTPUT"

if [[ "$(git rev-parse --verify HEAD)" != "$SOURCE_COMMIT" ]] ||
   [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "source checkout changed while the archived diagnostic was running" >&2
  exit 1
fi

OUTPUT="$ROOT_DIR/build/reports/performance/history-synthetic.jsonl"
mkdir -p "$(dirname "$OUTPUT")"
cp "$ARCHIVED_OUTPUT" "$OUTPUT"

if command -v sha256sum >/dev/null 2>&1; then
  OUTPUT_SHA256=$(sha256sum "$OUTPUT" | awk '{print $1}')
else
  OUTPUT_SHA256=$(shasum -a 256 "$OUTPUT" | awk '{print $1}')
fi

printf 'source_commit=%s\ncontainer_image=%s\ncontainer_image_id=%s\nrun_id=%s\noutput=%s\nsha256=%s\n' \
  "$SOURCE_COMMIT" "$RESOLVED_IMAGE" "$IMAGE_ID" "$RUN_ID" "$OUTPUT" "$OUTPUT_SHA256"
