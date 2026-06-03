#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/check-open-source-ready.sh
bash -n scripts/*.sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo doc --workspace --no-deps --locked
./scripts/generate-bindings.sh
(cd bindings/swift && swift test)
npx -y -p typescript@5.9.3 tsc -p bindings/expo/tsconfig.json --noEmit

if [[ -x bindings/kotlin/gradlew ]]; then
  (cd bindings/kotlin && ./gradlew test)
else
  echo "Skipping Android Gradle tests: bindings/kotlin/gradlew is not present."
fi
