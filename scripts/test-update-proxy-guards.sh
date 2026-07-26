#!/usr/bin/env bash
set -euo pipefail

server_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
update_script="$server_dir/scripts/update-proxy.sh"
tmp=$(mktemp -d)
proxy="$tmp/proxy"
lock_dir="$server_dir/libs/.proxy-update.lock"
test_lock=false
cleanup() {
  [[ "$test_lock" == true ]] && rmdir -- "$lock_dir" 2>/dev/null || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
mkdir "$proxy"

git -C "$proxy" init -q
git -C "$proxy" config user.email test@example.invalid
git -C "$proxy" config user.name Test
cat > "$proxy/gradlew" <<'SH'
#!/usr/bin/env bash
touch "$(dirname -- "$0")/BUILD_RAN"
exit 99
SH
chmod +x "$proxy/gradlew"
git -C "$proxy" add gradlew
git -C "$proxy" commit -qm init
git -C "$proxy" remote add origin https://example.invalid/untrusted.git

if "$update_script" "$proxy" >"$tmp/out" 2>"$tmp/err"; then
  echo "Unexpected proxy origin was accepted" >&2
  exit 1
fi
grep -F 'Refusing unexpected proxy origin' "$tmp/err" >/dev/null
[[ ! -e "$proxy/BUILD_RAN" ]]

mkdir "$lock_dir"
test_lock=true
if "$update_script" "$proxy" >"$tmp/out" 2>"$tmp/err"; then
  echo "Concurrent proxy update was accepted" >&2
  exit 1
fi
grep -F 'Another proxy update is already in progress' "$tmp/err" >/dev/null
rmdir "$lock_dir"
test_lock=false
[[ ! -e "$proxy/BUILD_RAN" ]]

git -C "$proxy" remote set-url origin https://github.com/sehoon123/mcp-proxy.git
touch "$proxy/untracked"
if "$update_script" "$proxy" >"$tmp/out" 2>"$tmp/err"; then
  echo "Dirty proxy checkout was accepted" >&2
  exit 1
fi
grep -F 'Refusing to build a dirty proxy checkout' "$tmp/err" >/dev/null
[[ ! -e "$proxy/BUILD_RAN" ]]

rm "$proxy/untracked"
git -C "$proxy" branch -M topic
if "$update_script" "$proxy" >"$tmp/out" 2>"$tmp/err"; then
  echo "Unexpected proxy branch was accepted" >&2
  exit 1
fi
grep -F 'Proxy checkout must be on main or detached' "$tmp/err" >/dev/null
[[ ! -e "$proxy/BUILD_RAN" ]]
git -C "$proxy" branch -M main

mkdir "$tmp/bin"
real_git=$(command -v git)
cat > "$tmp/bin/git" <<'SH'
#!/usr/bin/env bash
if [[ ${1:-} == ls-remote ]]; then
  printf '%040d\trefs/heads/main\n' 0
  exit 0
fi
exec "$REAL_GIT" "$@"
SH
chmod +x "$tmp/bin/git"
if PATH="$tmp/bin:$PATH" REAL_GIT="$real_git" "$update_script" "$proxy" >"$tmp/out" 2>"$tmp/err"; then
  echo "Proxy commit absent from the trusted remote was accepted" >&2
  exit 1
fi
grep -F 'Proxy HEAD is not the current immutable refs/heads/main' "$tmp/err" >/dev/null
[[ ! -e "$proxy/BUILD_RAN" ]]

printf 'Proxy source guards passed\n'
