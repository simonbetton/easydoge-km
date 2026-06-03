#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

./scripts/verify.sh
cargo package -p easydoge-km --allow-dirty

if [[ "${PACKAGE_DEPENDENT_CRATES:-0}" == "1" ]]; then
  cargo package -p easydoge-km-ffi --allow-dirty
  cargo package -p easydoge-km-cli --allow-dirty
else
  echo "Skipping dependent crate package checks because easydoge-km 0.1.0 is not guaranteed to exist in the registry yet."
  echo "After publishing easydoge-km, rerun with PACKAGE_DEPENDENT_CRATES=1."
fi

echo "Release package checks completed. Build native artifacts separately with scripts/build-apple-xcframework.sh and scripts/build-android-native-libs.sh."
