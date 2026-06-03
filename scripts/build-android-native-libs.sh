#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "cargo-ndk is required. Install with: cargo install cargo-ndk" >&2
  exit 1
fi

ANDROID_API="${ANDROID_API:-24}"
OUT_DIR="$ROOT/bindings/kotlin/easydoge-km/src/main/jniLibs"

cargo ndk \
  --target armeabi-v7a \
  --target arm64-v8a \
  --target x86 \
  --target x86_64 \
  --platform "$ANDROID_API" \
  --output-dir "$OUT_DIR" \
  build -p easydoge-km-ffi --release

echo "Android native libraries written to $OUT_DIR"
