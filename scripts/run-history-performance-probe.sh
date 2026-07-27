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

JDK_IMAGE=${HISTORY_PROBE_JDK_IMAGE:-eclipse-temurin@sha256:da9d3a4f7650db39b918fc5a2c3da76556fb8cc8e5f3767cdea0bb409286951a}
DOCKER_MEMORY=${HISTORY_PROBE_DOCKER_MEMORY:-4g}
if [[ ! "$JDK_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]]; then
  echo "HISTORY_PROBE_JDK_IMAGE must be pinned by sha256 digest" >&2
  exit 1
fi

if ! docker image inspect "$JDK_IMAGE" >/dev/null 2>&1; then
  docker pull "$JDK_IMAGE" >/dev/null
fi
RESOLVED_IMAGE=$(docker image inspect "$JDK_IMAGE" --format '{{range .RepoDigests}}{{println .}}{{end}}' | awk 'NF { print; exit }')
if [[ -z "$RESOLVED_IMAGE" ]]; then
  RESOLVED_IMAGE=$(docker image inspect "$JDK_IMAGE" --format '{{.Id}}')
fi
IMAGE_ID=$(docker image inspect "$RESOLVED_IMAGE" --format '{{.Id}}')

PROBE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mcp-history-diagnostics.XXXXXX")
GRADLE_VOLUME="mcp-history-probe-${SOURCE_COMMIT:0:12}-$$-$RANDOM"
cleanup() {
  if [[ -n "${RESOLVED_IMAGE:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    docker run --rm --pull=never --network=none --cap-drop=ALL \
      --security-opt=no-new-privileges -v "$OUTPUT_DIR":/cleanup "$RESOLVED_IMAGE" \
      sh -euc 'rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?*' >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$GRADLE_VOLUME" >/dev/null 2>&1 || true
  rm -rf "$PROBE_ROOT"
}
trap cleanup EXIT INT TERM HUP
docker volume create "$GRADLE_VOLUME" >/dev/null
SOURCE_DIR="$PROBE_ROOT/source"
OUTPUT_DIR="$PROBE_ROOT/output"
INIT_SCRIPT="$PROBE_ROOT/readonly-build.gradle"
mkdir -p "$SOURCE_DIR" "$OUTPUT_DIR"
git archive --format=tar "$SOURCE_COMMIT" | tar -xf - -C "$SOURCE_DIR"
cat > "$INIT_SCRIPT" <<'EOF'
gradle.beforeProject { project ->
    project.layout.buildDirectory.set(project.file(System.getenv('PROBE_BUILD_DIR')))
    project.tasks.register('resolveHistoryProbeRuntimeClasspath') {
        doLast {
            project.configurations.getByName('testRuntimeClasspath').files.each { file ->
                if (!file.exists()) throw new GradleException("Missing test runtime artifact")
            }
        }
    }
}
EOF

RUN_ID="${SOURCE_COMMIT:0:12}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
DOCKER_ARGS=(
  --rm
  --pull=never
  --memory="$DOCKER_MEMORY"
  --pids-limit=512
  --cap-drop=ALL
  --security-opt=no-new-privileges
  -e SOURCE_COMMIT="$SOURCE_COMMIT"
  -e PROBE_SOURCE_ARCHIVE=true
  -e PROBE_RUN_ID="$RUN_ID"
  -e PROBE_CONTAINER_IMAGE="$RESOLVED_IMAGE"
  -e PROBE_CONTAINER_IMAGE_ID="$IMAGE_ID"
  -e PROBE_CONTAINER_MEMORY="$DOCKER_MEMORY"
  -e PROBE_BUILD_DIR=/probe-output/build
  -v "$SOURCE_DIR":/source:ro
  -v "$OUTPUT_DIR":/probe-output
  -v "$INIT_SCRIPT":/probe/readonly-build.gradle:ro
  -v "$GRADLE_VOLUME":/root/.gradle
  --tmpfs /workspace:rw,exec,size=1g
  -w /workspace
)
GRADLE_ARGS=(
  --no-daemon
  --no-build-cache
  --no-configuration-cache
  --project-cache-dir /probe-output/project-cache
  -Dkotlin.project.persistent.dir=/probe-output/kotlin
  --init-script /probe/readonly-build.gradle
)

# Dependency resolution and compilation happen before measurement in a disposable cache.
docker run "${DOCKER_ARGS[@]}" "$RESOLVED_IMAGE" \
  sh -euc 'cp -a /source/. /workspace/ && ./gradlew "$@" testClasses resolveHistoryProbeRuntimeClasspath' \
  sh "${GRADLE_ARGS[@]}"

# The measured JavaExec phase is offline and has no network interface.
docker run "${DOCKER_ARGS[@]}" --network=none "$RESOLVED_IMAGE" \
  sh -euc 'cp -a /source/. /workspace/ && ./gradlew "$@" --offline historyPerformanceProbe' sh "${GRADLE_ARGS[@]}"

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
