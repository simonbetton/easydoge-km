#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Apple XCFramework builds require macOS and Xcode." >&2
  exit 1
fi

command -v xcodebuild >/dev/null 2>&1 || {
  echo "xcodebuild is required." >&2
  exit 1
}

TARGETS=(
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"
  "x86_64-apple-ios"
)

for target in "${TARGETS[@]}"; do
  rustup target add "$target"
  cargo build -p easydoge-km-ffi --release --target "$target"
done

DIST_DIR="$ROOT/dist/apple"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

SIMULATOR_DIR="$DIST_DIR/simulator"
mkdir -p "$SIMULATOR_DIR"
lipo -create \
  "$ROOT/target/aarch64-apple-ios-sim/release/libeasydoge_km_ffi.a" \
  "$ROOT/target/x86_64-apple-ios/release/libeasydoge_km_ffi.a" \
  -output "$SIMULATOR_DIR/libeasydoge_km_ffi.a"

xcodebuild -create-xcframework \
  -library "$ROOT/target/aarch64-apple-ios/release/libeasydoge_km_ffi.a" \
  -headers "$ROOT/bindings/swift/Sources/easydoge_km_ffiFFI" \
  -library "$SIMULATOR_DIR/libeasydoge_km_ffi.a" \
  -headers "$ROOT/bindings/swift/Sources/easydoge_km_ffiFFI" \
  -output "$DIST_DIR/easydoge_km_ffi.xcframework"

echo "Apple XCFramework written to $DIST_DIR/easydoge_km_ffi.xcframework"
