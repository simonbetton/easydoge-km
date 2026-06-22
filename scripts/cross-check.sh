#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p target/cross-check

cargo run -p easydoge-km --example cross_check_vectors -- \
  test-vectors/cross-check.json target/cross-check/rust.json

pnpm install --frozen-lockfile --dir tools/bitcoinjs-cross-check

pnpm --dir tools/bitcoinjs-cross-check run cross-check -- \
  ../../test-vectors/cross-check.json ../../target/cross-check/bitcoinjs.json

node tools/bitcoinjs-cross-check/compare.mjs \
  target/cross-check/rust.json target/cross-check/bitcoinjs.json
