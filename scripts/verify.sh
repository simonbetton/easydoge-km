#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/check-open-source-ready.sh
for script in scripts/*.sh; do
  bash -n "$script"
done
cargo fmt --all --check
cargo test --workspace --locked
bash scripts/cross-check.sh
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo doc --workspace --no-deps --locked
./scripts/generate-bindings.sh --check
(cd bindings/swift && swift test)
npx -y -p typescript@7.0.2 tsc -p bindings/expo/tsconfig.json --noEmit

bash scripts/check-native-build-pins.sh

if [[ -x bindings/kotlin/gradlew ]]; then
  (cd bindings/kotlin && ./gradlew test)
else
  echo "Skipping Android Gradle tests: bindings/kotlin/gradlew is not present."
fi
