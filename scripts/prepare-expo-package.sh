#!/usr/bin/env bash
# Assembles the @easydoge/km-expo npm package under bindings/expo from the
# workspace sources and prebuilt native artifacts. Wired to `prepack` in
# bindings/expo/package.json and safe to run by hand.
#
# Everything this script writes is a build output and is git-ignored:
#   bindings/expo/build/                 compiled JavaScript and declarations
#   bindings/expo/ios/vendor/            Swift facade, UniFFI Swift, XCFramework
#   bindings/expo/android/vendor/        Kotlin facade, UniFFI Kotlin, jniLibs
#   bindings/expo/LICENSE                copy of LICENSE-MIT
#   bindings/expo/vendor-manifest.json   what was copied, with SHA-256 digests
#
# Progress goes to stderr so `npm pack --json` keeps a clean stdout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPO_DIR="$ROOT/bindings/expo"
SWIFT_SOURCES="$ROOT/bindings/swift/Sources"
KOTLIN_MAIN="$ROOT/bindings/kotlin/easydoge-km/src/main"
XCFRAMEWORK="$ROOT/dist/apple/easydoge_km_ffi.xcframework"
JNILIBS_DIR="$KOTLIN_MAIN/jniLibs"
IOS_VENDOR="$EXPO_DIR/ios/vendor"
ANDROID_VENDOR="$EXPO_DIR/android/vendor"
TYPESCRIPT_VERSION="7.0.2"

APPLE_SLICES=(ios-arm64 ios-arm64_x86_64-simulator)
ANDROID_ABIS=(armeabi-v7a arm64-v8a x86 x86_64)

log() { echo "prepare-expo-package: $*" >&2; }
fail() {
  log "ERROR: $*"
  exit 1
}

command -v node >/dev/null 2>&1 || fail "node is required."
command -v npx >/dev/null 2>&1 || fail "npx is required."

if [[ "${EXPO_PACKAGE_BUILD_NATIVE:-0}" == "1" ]]; then
  log "building native artifacts (EXPO_PACKAGE_BUILD_NATIVE=1)"
  ./scripts/build-apple-xcframework.sh >&2
  ./scripts/build-android-native-libs.sh >&2
fi

# --- 1. Required inputs -----------------------------------------------------

native_artifacts=()
for slice in "${APPLE_SLICES[@]}"; do
  native_artifacts+=("$XCFRAMEWORK/$slice/libeasydoge_km_ffi.a")
done
for abi in "${ANDROID_ABIS[@]}"; do
  native_artifacts+=("$JNILIBS_DIR/$abi/libeasydoge_km_ffi.so")
done

required_inputs=("${native_artifacts[@]}" "$XCFRAMEWORK/Info.plist")
for slice in "${APPLE_SLICES[@]}"; do
  required_inputs+=("$XCFRAMEWORK/$slice/Headers/easydoge_km_ffiFFI.h")
  required_inputs+=("$XCFRAMEWORK/$slice/Headers/module.modulemap")
done
required_inputs+=(
  "$SWIFT_SOURCES/EasyDogeKM/EasyDogeKM.swift"
  "$SWIFT_SOURCES/easydoge_km_ffi/easydoge_km_ffi.swift"
  "$SWIFT_SOURCES/easydoge_km_ffiFFI/easydoge_km_ffiFFI.h"
  "$SWIFT_SOURCES/easydoge_km_ffiFFI/module.modulemap"
  "$KOTLIN_MAIN/java/io/easydoge/km/EasyDogeKM.kt"
  "$KOTLIN_MAIN/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt"
  "$ROOT/bindings/kotlin/easydoge-km/build.gradle.kts"
  "$ROOT/LICENSE-MIT"
  "$EXPO_DIR/README.md"
  "$EXPO_DIR/android/build.gradle"
  "$EXPO_DIR/android/proguard-rules.pro"
  "$EXPO_DIR/ios/EasyDogeKMFFI.podspec"
  "$EXPO_DIR/ios/EasyDogeKM.podspec"
  "$EXPO_DIR/ios/EasyDogeKMExpo.podspec"
)

missing=0
for path in "${required_inputs[@]}"; do
  if [[ ! -f "$path" ]]; then
    log "missing required input: ${path#"$ROOT"/}"
    missing=1
  fi
done
if [[ "$missing" == "1" ]]; then
  log "Native artifacts come from:"
  log "  ./scripts/build-apple-xcframework.sh     (macOS + Xcode; writes dist/apple/)"
  log "  ./scripts/build-android-native-libs.sh   (Android NDK + cargo-ndk; writes bindings/kotlin/easydoge-km/src/main/jniLibs/)"
  log "or rerun this script with EXPO_PACKAGE_BUILD_NATIVE=1."
  fail "refusing to assemble an incomplete package."
fi

# --- 2. Native artifacts must match the committed bindings -------------------

for slice in "${APPLE_SLICES[@]}"; do
  for header in easydoge_km_ffiFFI.h module.modulemap; do
    cmp -s "$XCFRAMEWORK/$slice/Headers/$header" "$SWIFT_SOURCES/easydoge_km_ffiFFI/$header" ||
      fail "stale XCFramework: $slice/Headers/$header differs from bindings/swift/Sources/easydoge_km_ffiFFI/$header. Rerun ./scripts/build-apple-xcframework.sh."
  done
done

if [[ "${EXPO_PACKAGE_ALLOW_STALE_NATIVE:-0}" != "1" ]]; then
  rust_inputs=(
    "$ROOT/Cargo.toml"
    "$ROOT/Cargo.lock"
    "$ROOT/crates/easydoge-km/Cargo.toml"
    "$ROOT/crates/easydoge-km/src"
    "$ROOT/crates/easydoge-km-ffi/Cargo.toml"
    "$ROOT/crates/easydoge-km-ffi/src"
  )
  for artifact in "${native_artifacts[@]}"; do
    newer="$(find "${rust_inputs[@]}" -type f -newer "$artifact" -print -quit)"
    if [[ -n "$newer" ]]; then
      fail "stale native artifact: ${artifact#"$ROOT"/} is older than ${newer#"$ROOT"/}. Rebuild the native artifacts (or set EXPO_PACKAGE_ALLOW_STALE_NATIVE=1 if you are certain the binary matches the sources)."
    fi
  done
fi

if command -v lipo >/dev/null 2>&1; then
  device_archs="$(lipo -archs "$XCFRAMEWORK/ios-arm64/libeasydoge_km_ffi.a")"
  [[ "$device_archs" == "arm64" ]] ||
    fail "ios-arm64 slice has architectures '$device_archs', expected 'arm64'."
  simulator_archs="$(lipo -archs "$XCFRAMEWORK/ios-arm64_x86_64-simulator/libeasydoge_km_ffi.a")"
  [[ "$simulator_archs" == *arm64* && "$simulator_archs" == *x86_64* ]] ||
    fail "simulator slice has architectures '$simulator_archs', expected arm64 and x86_64."
fi

for abi in "${ANDROID_ABIS[@]}"; do
  magic="$(head -c 4 "$JNILIBS_DIR/$abi/libeasydoge_km_ffi.so" | od -An -c | tr -d ' \n')"
  [[ "$magic" == "177ELF" ]] ||
    fail "$abi/libeasydoge_km_ffi.so is not an ELF shared library."
done

# The vendored Kotlin facade compiles inside the Expo module's Gradle project,
# so every runtime dependency the facade declares must be declared there too
# (the JNA line carries an extra "@aar" suffix, which still matches).
FACADE_GRADLE="$ROOT/bindings/kotlin/easydoge-km/build.gradle.kts"
EXPO_GRADLE="$EXPO_DIR/android/build.gradle"
facade_dependencies="$(sed -E -n 's/^[[:space:]]*(implementation|api)\("([^"]+)"\).*/\2/p' "$FACADE_GRADLE")"
[[ -n "$facade_dependencies" ]] ||
  fail "found no implementation(\"...\") dependency in bindings/kotlin/easydoge-km/build.gradle.kts; the parity check needs updating."
while IFS= read -r coordinate; do
  grep -Fq "$coordinate" "$EXPO_GRADLE" ||
    fail "dependency drift: the Kotlin facade declares '$coordinate' but bindings/expo/android/build.gradle does not."
done <<<"$facade_dependencies"

# --- 3. JavaScript build -----------------------------------------------------

log "compiling TypeScript into bindings/expo/build"
rm -rf "$EXPO_DIR/build"
npx -y -p "typescript@$TYPESCRIPT_VERSION" tsc -p "$EXPO_DIR/tsconfig.json" >&2
[[ -f "$EXPO_DIR/build/index.js" && -f "$EXPO_DIR/build/index.d.ts" ]] ||
  fail "TypeScript build did not produce build/index.js and build/index.d.ts."

# --- 4. Vendor native sources and binaries -----------------------------------

log "vendoring Swift sources and the XCFramework into bindings/expo/ios/vendor"
rm -rf "$IOS_VENDOR"
mkdir -p "$IOS_VENDOR/EasyDogeKM" "$IOS_VENDOR/easydoge_km_ffi"
cp -R "$SWIFT_SOURCES/EasyDogeKM/." "$IOS_VENDOR/EasyDogeKM/"
cp "$SWIFT_SOURCES/easydoge_km_ffi/easydoge_km_ffi.swift" "$IOS_VENDOR/easydoge_km_ffi/"
cp -R "$XCFRAMEWORK" "$IOS_VENDOR/easydoge_km_ffi.xcframework"

log "vendoring Kotlin sources and jniLibs into bindings/expo/android/vendor"
rm -rf "$ANDROID_VENDOR"
mkdir -p "$ANDROID_VENDOR/java/io/easydoge/km" "$ANDROID_VENDOR/java/uniffi/easydoge_km_ffi"
cp -R "$KOTLIN_MAIN/java/io/easydoge/km/." "$ANDROID_VENDOR/java/io/easydoge/km/"
cp "$KOTLIN_MAIN/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt" "$ANDROID_VENDOR/java/uniffi/easydoge_km_ffi/"
for abi in "${ANDROID_ABIS[@]}"; do
  mkdir -p "$ANDROID_VENDOR/jniLibs/$abi"
  cp "$JNILIBS_DIR/$abi/libeasydoge_km_ffi.so" "$ANDROID_VENDOR/jniLibs/$abi/"
done

cp "$ROOT/LICENSE-MIT" "$EXPO_DIR/LICENSE"
find "$IOS_VENDOR" "$ANDROID_VENDOR" -name .DS_Store -delete

# --- 5. Manifest ---------------------------------------------------------------

source_commit="unknown"
source_tree_dirty="unknown"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_commit="$(git -C "$ROOT" rev-parse HEAD)"
  if [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]]; then
    source_tree_dirty="false"
  else
    source_tree_dirty="true"
  fi
fi

SOURCE_COMMIT="$source_commit" SOURCE_TREE_DIRTY="$source_tree_dirty" node - "$EXPO_DIR" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const expoDir = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(path.join(expoDir, "package.json"), "utf8"));

function walk(relative) {
  const absolute = path.join(expoDir, relative);
  if (!fs.existsSync(absolute)) return [];
  const stat = fs.statSync(absolute);
  if (stat.isFile()) return [relative];
  return fs
    .readdirSync(absolute)
    .sort()
    .flatMap((entry) => walk(path.posix.join(relative, entry)));
}

const files = ["build", "ios/vendor", "android/vendor", "LICENSE"]
  .flatMap(walk)
  .map((relative) => {
    const bytes = fs.readFileSync(path.join(expoDir, relative));
    return {
      path: relative,
      bytes: bytes.length,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  });

const manifest = {
  package: pkg.name,
  version: pkg.version,
  sourceCommit: process.env.SOURCE_COMMIT,
  sourceTreeDirty:
    process.env.SOURCE_TREE_DIRTY === "unknown" ? null : process.env.SOURCE_TREE_DIRTY === "true",
  appleSlices: ["ios-arm64", "ios-arm64_x86_64-simulator"],
  androidAbis: ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"],
  copiedFrom: {
    "build": "bindings/expo/src (compiled by tsc)",
    "ios/vendor/EasyDogeKM": "bindings/swift/Sources/EasyDogeKM",
    "ios/vendor/easydoge_km_ffi": "bindings/swift/Sources/easydoge_km_ffi",
    "ios/vendor/easydoge_km_ffi.xcframework": "dist/apple/easydoge_km_ffi.xcframework",
    "android/vendor/java/io/easydoge/km": "bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km",
    "android/vendor/java/uniffi/easydoge_km_ffi": "bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi",
    "android/vendor/jniLibs": "bindings/kotlin/easydoge-km/src/main/jniLibs",
    "LICENSE": "LICENSE-MIT",
  },
  files,
};

fs.writeFileSync(
  path.join(expoDir, "vendor-manifest.json"),
  JSON.stringify(manifest, null, 2) + "\n",
);
NODE

log "wrote bindings/expo/vendor-manifest.json"
log "package assembled from commit $source_commit (tracked changes present: $source_tree_dirty)"
