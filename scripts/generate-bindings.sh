#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build -p easydoge-km-ffi

UNI_FFI_VERSION="0.32.0"
UNI_FFI_MANIFEST="${UNI_FFI_MANIFEST:-}"
if [[ -z "$UNI_FFI_MANIFEST" ]]; then
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  for candidate in "$CARGO_HOME"/registry/src/*/uniffi-"$UNI_FFI_VERSION"/Cargo.toml; do
    if [[ -f "$candidate" ]]; then
      UNI_FFI_MANIFEST="$candidate"
      break
    fi
  done
fi

if [[ ! -f "$UNI_FFI_MANIFEST" ]]; then
  echo "UniFFI $UNI_FFI_VERSION source not found in cargo registry. Run: cargo fetch" >&2
  exit 1
fi

FFI_LIBRARY_PATH="${FFI_LIBRARY_PATH:-}"
if [[ -z "$FFI_LIBRARY_PATH" ]]; then
  case "$(uname -s)" in
    Darwin) library_pattern="target/debug/libeasydoge_km_ffi.dylib" ;;
    Linux) library_pattern="target/debug/libeasydoge_km_ffi.so" ;;
    MINGW*|MSYS*|CYGWIN*) library_pattern="target/debug/easydoge_km_ffi.dll" ;;
    *) library_pattern="target/debug/libeasydoge_km_ffi.*" ;;
  esac
  matches=( $library_pattern )
  FFI_LIBRARY_PATH="${matches[0]:-}"
fi

if [[ ! -f "$FFI_LIBRARY_PATH" ]]; then
  echo "Compiled FFI library not found. Expected: $FFI_LIBRARY_PATH" >&2
  exit 1
fi

mkdir -p bindings/generated/swift bindings/generated/kotlin
cargo run --manifest-path "$UNI_FFI_MANIFEST" --features cli --bin uniffi-bindgen -- \
  generate "$FFI_LIBRARY_PATH" \
  --language swift \
  --out-dir bindings/generated/swift \
  --crate easydoge_km_ffi

cargo run --manifest-path "$UNI_FFI_MANIFEST" --features cli --bin uniffi-bindgen -- \
  generate "$FFI_LIBRARY_PATH" \
  --language kotlin \
  --out-dir bindings/generated/kotlin \
  --crate easydoge_km_ffi \
  --no-format

mkdir -p \
  bindings/swift/Sources/easydoge_km_ffi \
  bindings/swift/Sources/easydoge_km_ffiFFI \
  bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi

cp bindings/generated/swift/easydoge_km_ffi.swift \
  bindings/swift/Sources/easydoge_km_ffi/easydoge_km_ffi.swift
cp bindings/generated/swift/easydoge_km_ffiFFI.h \
  bindings/swift/Sources/easydoge_km_ffiFFI/easydoge_km_ffiFFI.h
cp bindings/generated/swift/easydoge_km_ffiFFI.modulemap \
  bindings/swift/Sources/easydoge_km_ffiFFI/module.modulemap
cp bindings/generated/kotlin/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt \
  bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt

perl -pi -e 's/[ \t]+$//' \
  bindings/swift/Sources/easydoge_km_ffi/easydoge_km_ffi.swift \
  bindings/swift/Sources/easydoge_km_ffiFFI/easydoge_km_ffiFFI.h \
  bindings/swift/Sources/easydoge_km_ffiFFI/module.modulemap \
  bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt
