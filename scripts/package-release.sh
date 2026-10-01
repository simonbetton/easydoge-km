#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Release packages must be built from exactly what is committed. Tracked
# changes, staged changes, and untracked files all count as dirty; ignored
# build outputs do not.
require_clean_checkout() {
  local when="$1"
  if ! command -v git >/dev/null 2>&1 ||
    [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]]; then
    echo "Release packaging must run inside a git checkout so the packaged sources can be tied to a commit." >&2
    exit 1
  fi

  local status
  status="$(git status --porcelain --untracked-files=normal)"
  if [[ -n "$status" ]]; then
    {
      echo "Release packaging requires a clean checkout ($when). Commit, stash, or remove these paths first:"
      echo "$status"
    } >&2
    exit 1
  fi
}

require_clean_checkout "before verification"
./scripts/verify.sh
require_clean_checkout "after verification"

cargo package -p easydoge-km

if [[ "${PACKAGE_DEPENDENT_CRATES:-0}" == "1" ]]; then
  cargo package -p easydoge-km-ffi
  cargo package -p easydoge-km-cli
else
  echo "Skipping dependent crate package checks because easydoge-km 0.1.0 is not guaranteed to exist in the registry yet."
  echo "After publishing easydoge-km, rerun with PACKAGE_DEPENDENT_CRATES=1."
fi

echo "Release package checks completed. Build native artifacts separately with scripts/build-apple-xcframework.sh and scripts/build-android-native-libs.sh."
