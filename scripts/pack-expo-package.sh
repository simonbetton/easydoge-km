#!/usr/bin/env bash
# Packs @easydoge/km-expo into dist/expo/ and verifies the tarball contents.
#
# `npm pack` runs the package's `prepack` script, which is
# scripts/prepare-expo-package.sh; see that script for the inputs it needs.
#
# stdout: the absolute path of the verified tarball (one line).
# stderr: progress, the file count, the size, and the SHA-256 digest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPO_DIR="$ROOT/bindings/expo"
OUT_DIR="$ROOT/dist/expo"
MAX_TARBALL_BYTES="${EXPO_PACKAGE_MAX_BYTES:-62914560}"

log() { echo "pack-expo-package: $*" >&2; }
fail() {
  log "ERROR: $*"
  exit 1
}

command -v npm >/dev/null 2>&1 || fail "npm is required."

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.tgz "$OUT_DIR/pack.json" "$OUT_DIR/files.txt"

log "running npm pack (prepack assembles the package)"
(cd "$EXPO_DIR" && npm pack --json --pack-destination "$OUT_DIR" >"$OUT_DIR/pack.json")

tarballs=("$OUT_DIR"/*.tgz)
[[ "${#tarballs[@]}" == "1" && -f "${tarballs[0]}" ]] ||
  fail "expected exactly one tarball in dist/expo, found: ${tarballs[*]}"
TARBALL="${tarballs[0]}"

# A tarball that fails verification must not be left behind for a consumer.
reject() {
  rm -f "$TARBALL"
  fail "$*"
}

tar -tzf "$TARBALL" | LC_ALL=C sort >"$OUT_DIR/files.txt"

# --- Every required file is present -------------------------------------------

required=(
  package/package.json
  package/README.md
  package/LICENSE
  package/expo-module.config.json
  package/vendor-manifest.json
  package/build/index.js
  package/build/index.d.ts
  package/ios/EasyDogeKMExpo.podspec
  package/ios/EasyDogeKM.podspec
  package/ios/EasyDogeKMFFI.podspec
  package/ios/EasyDogeKMModule.swift
  package/ios/vendor/easydoge_km_ffi/easydoge_km_ffi.swift
  package/ios/vendor/easydoge_km_ffi.xcframework/Info.plist
  package/android/build.gradle
  package/android/proguard-rules.pro
  package/android/src/main/AndroidManifest.xml
  package/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt
  package/android/vendor/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt
)
for slice in ios-arm64 ios-arm64_x86_64-simulator; do
  required+=(
    "package/ios/vendor/easydoge_km_ffi.xcframework/$slice/libeasydoge_km_ffi.a"
    "package/ios/vendor/easydoge_km_ffi.xcframework/$slice/Headers/easydoge_km_ffiFFI.h"
    "package/ios/vendor/easydoge_km_ffi.xcframework/$slice/Headers/module.modulemap"
  )
done
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
  required+=("package/android/vendor/jniLibs/$abi/libeasydoge_km_ffi.so")
done
# Every handwritten facade source must ship, whatever files exist today.
while IFS= read -r file; do
  required+=("package/ios/vendor/EasyDogeKM/${file#./}")
done < <(cd "$ROOT/bindings/swift/Sources/EasyDogeKM" && find . -type f -name '*.swift' | LC_ALL=C sort)
while IFS= read -r file; do
  required+=("package/android/vendor/java/io/easydoge/km/${file#./}")
done < <(cd "$ROOT/bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km" && find . -type f -name '*.kt' | LC_ALL=C sort)

missing=0
for entry in "${required[@]}"; do
  if ! grep -Fxq "$entry" "$OUT_DIR/files.txt"; then
    log "tarball is missing: $entry"
    missing=1
  fi
done
[[ "$missing" == "0" ]] || reject "tarball is incomplete."

# --- Nothing outside the allowlist ships --------------------------------------

allowed='^package/(package\.json|README\.md|LICENSE|expo-module\.config\.json|vendor-manifest\.json)$'
allowed+='|^package/build/[A-Za-z0-9_./-]+\.(js|d\.ts)$'
allowed+='|^package/ios/(EasyDogeKMExpo|EasyDogeKM|EasyDogeKMFFI)\.podspec$'
allowed+='|^package/ios/[A-Za-z0-9_+]+\.swift$'
allowed+='|^package/ios/vendor/(EasyDogeKM|easydoge_km_ffi)/[A-Za-z0-9_+/]+\.swift$'
allowed+='|^package/ios/vendor/easydoge_km_ffi\.xcframework/Info\.plist$'
allowed+='|^package/ios/vendor/easydoge_km_ffi\.xcframework/ios-arm64(_x86_64-simulator)?/libeasydoge_km_ffi\.a$'
allowed+='|^package/ios/vendor/easydoge_km_ffi\.xcframework/ios-arm64(_x86_64-simulator)?/Headers/(easydoge_km_ffiFFI\.h|module\.modulemap)$'
allowed+='|^package/android/(build\.gradle|proguard-rules\.pro|src/main/AndroidManifest\.xml)$'
allowed+='|^package/android/src/main/java/io/easydoge/km/expo/[A-Za-z0-9_/]+\.kt$'
allowed+='|^package/android/vendor/java/(io/easydoge/km|uniffi/easydoge_km_ffi)/[A-Za-z0-9_/]+\.kt$'
allowed+='|^package/android/vendor/jniLibs/(armeabi-v7a|arm64-v8a|x86|x86_64)/libeasydoge_km_ffi\.so$'

unexpected="$(grep -Ev "$allowed" "$OUT_DIR/files.txt" || true)"
if [[ -n "$unexpected" ]]; then
  log "tarball contains files outside the allowlist:"
  while IFS= read -r entry; do log "  $entry"; done <<<"$unexpected"
  reject "refusing to accept the tarball. Fix \"files\" in bindings/expo/package.json or extend the allowlist in this script deliberately."
fi

# --- Size budget ----------------------------------------------------------------

tarball_bytes="$(wc -c <"$TARBALL" | tr -d ' ')"
entry_count="$(wc -l <"$OUT_DIR/files.txt" | tr -d ' ')"
if command -v shasum >/dev/null 2>&1; then
  digest="$(shasum -a 256 "$TARBALL" | cut -d ' ' -f 1)"
else
  digest="$(sha256sum "$TARBALL" | cut -d ' ' -f 1)"
fi

log "tarball: ${TARBALL#"$ROOT"/}"
log "files:   $entry_count"
log "size:    $tarball_bytes bytes (budget $MAX_TARBALL_BYTES)"
log "sha256:  $digest"

[[ "$tarball_bytes" -le "$MAX_TARBALL_BYTES" ]] ||
  reject "tarball is $tarball_bytes bytes, over the $MAX_TARBALL_BYTES byte budget (EXPO_PACKAGE_MAX_BYTES overrides it)."

echo "$TARBALL"
