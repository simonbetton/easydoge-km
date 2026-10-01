#!/usr/bin/env bash
# Compiles the Expo native modules inside a real host app.
#
# Packs @easydoge/km-expo with scripts/pack-expo-package.sh, installs the
# tarball into a throwaway copy of tools/expo-fixture (a minimal Expo app
# pinned to one Expo SDK), generates the native projects with `expo prebuild`,
# and builds them: Metro bundles, an iOS simulator build, an unsigned iOS
# device build, and an Android debug APK. Nothing is installed or launched on
# a simulator, emulator, or device.
#
# Usage: scripts/verify-expo-native.sh [ios] [android]      (default: both)
#
# Environment:
#   EXPO_NATIVE_REUSE_ARTIFACTS=1  Pack with the XCFramework and jniLibs that
#                                  already exist instead of rebuilding them.
#   ANDROID_HOME, JAVA_HOME        Android SDK and JDK 17 for the Android build.
#   ANDROID_NDK_HOME               NDK that cargo-ndk uses for the Rust libraries.
#
# The host app is assembled in dist/expo-fixture (git-ignored, several GB) and
# every build log is kept in dist/expo-fixture/logs.
#
# Not part of scripts/verify.sh: it needs Xcode, CocoaPods, the Android SDK and
# NDK, cargo-ndk, and network access, and takes several minutes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FIXTURE_DIR="$ROOT/tools/expo-fixture"
WORK_DIR="$ROOT/dist/expo-fixture"
LOG_DIR="$WORK_DIR/logs"
APP_NAME="EasyDogeKMFixture"
PACKAGE_NAME="@easydoge/km-expo"
GRADLE_PROJECT=":easydoge-km-expo"
FIXTURE_FILES="package.json package-lock.json app.json index.js App.js"
IOS_PODS="EasyDogeKMFFI EasyDogeKM EasyDogeKMExpo"
ANDROID_ABIS="armeabi-v7a arm64-v8a x86 x86_64"
ANDROID_RUST_TARGETS="armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android"

log() { echo "verify-expo-native: $*" >&2; }
fail() {
  log "ERROR: $*"
  exit 1
}
need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required${2:+ ($2)}."
}

# Runs a command with its output in a log file. On failure, prints the error
# lines and the end of the log, then exits.
run_logged() {
  local name="$1"
  shift
  local log_file="$LOG_DIR/$name.log"
  local started="$SECONDS"
  log "$name: started (log: ${log_file#"$ROOT"/})"
  if ! "$@" >"$log_file" 2>&1; then
    grep -E '^e: |error:|\*\* BUILD FAILED|FAILED$|What went wrong' "$log_file" | head -n 40 >&2 || true
    tail -n 25 "$log_file" >&2
    fail "$name failed after $((SECONDS - started))s."
  fi
  log "$name: ok ($((SECONDS - started))s)"
}

# Counts matching lines without tripping `pipefail` on an early-closing reader.
count_matches() {
  local pattern="$1"
  grep -c -- "$pattern" || true
}

# --- Arguments and preflight ------------------------------------------------------

build_ios=0
build_android=0
if [[ "$#" -eq 0 ]]; then
  build_ios=1
  build_android=1
fi
for arg in "$@"; do
  case "$arg" in
    ios) build_ios=1 ;;
    android) build_android=1 ;;
    *) fail "unknown platform '$arg' (expected: ios, android)." ;;
  esac
done

need node
need npm
need npx
[[ -x scripts/pack-expo-package.sh && -x scripts/prepare-expo-package.sh ]] ||
  fail "scripts/pack-expo-package.sh and scripts/prepare-expo-package.sh are required."
for file in $FIXTURE_FILES; do
  [[ -f "$FIXTURE_DIR/$file" ]] || fail "missing fixture file: tools/expo-fixture/$file"
done
if [[ "$build_ios" == "1" ]]; then
  [[ "$(uname -s)" == "Darwin" ]] || fail "the iOS build requires macOS and Xcode."
  need xcodebuild
  need pod "CocoaPods"
fi
if [[ "$build_android" == "1" ]]; then
  [[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME:-}" ]] ||
    fail "ANDROID_HOME must point at an Android SDK for the Android build."
  need java "JDK 17"
fi

# --- 1. Pack the module ---------------------------------------------------------------

if [[ "${EXPO_NATIVE_REUSE_ARTIFACTS:-0}" == "1" ]]; then
  log "reusing the existing native artifacts (EXPO_NATIVE_REUSE_ARTIFACTS=1)"
else
  need cargo
  need rustup
  need cargo-ndk "cargo install cargo-ndk"
  log "building the Rust libraries for every Apple slice and Android ABI"
  # shellcheck disable=SC2086
  rustup target add $ANDROID_RUST_TARGETS >&2
  export EXPO_PACKAGE_BUILD_NATIVE=1
fi

log "packing $PACKAGE_NAME"
TARBALL="$(./scripts/pack-expo-package.sh)"
[[ -n "$TARBALL" && -f "$TARBALL" ]] || fail "scripts/pack-expo-package.sh did not print a tarball path."

# --- 2. Assemble the host app ---------------------------------------------------------

log "assembling the host app in ${WORK_DIR#"$ROOT"/}"
rm -rf "$WORK_DIR"
mkdir -p "$LOG_DIR"
for file in $FIXTURE_FILES; do
  cp "$FIXTURE_DIR/$file" "$WORK_DIR/"
done
cd "$WORK_DIR"
# Non-interactive Expo CLI, and no usage telemetry from this check.
export CI="${CI:-1}"
export EXPO_NO_TELEMETRY=1

run_logged npm-ci npm ci --no-audit --no-fund
run_logged npm-install-tarball npm install --no-audit --no-fund "$TARBALL"
[[ -f "node_modules/$PACKAGE_NAME/expo-module.config.json" ]] ||
  fail "$PACKAGE_NAME was not installed into the host app."

if [[ "$build_ios" == "1" && "$build_android" == "1" ]]; then
  prebuild_platform="all"
elif [[ "$build_ios" == "1" ]]; then
  prebuild_platform="ios"
else
  prebuild_platform="android"
fi
run_logged prebuild npx expo prebuild --no-install --platform "$prebuild_platform"

# --- 3. JavaScript: Metro must resolve the package entry point ------------------------

bundle_js() {
  local platform="$1"
  run_logged "metro-$platform" npx expo export --platform "$platform" --output-dir "$WORK_DIR/export-$platform"
  [[ -n "$(find "$WORK_DIR/export-$platform" -type f -name 'index-*' | head -n 1)" ]] ||
    fail "Metro produced no $platform bundle."
}

# --- 4. iOS ---------------------------------------------------------------------------

ios_pod_install() {
  (cd "$WORK_DIR/ios" && LANG=en_US.UTF-8 pod install)
}

ios_xcodebuild() {
  local sdk="$1"
  local destination="$2"
  (
    cd "$WORK_DIR/ios" &&
      xcodebuild \
        -workspace "$APP_NAME.xcworkspace" \
        -scheme "$APP_NAME" \
        -configuration Debug \
        -sdk "$sdk" \
        -destination "$destination" \
        -derivedDataPath build \
        CODE_SIGNING_ALLOWED=NO \
        build
  )
}

assert_ios_products() {
  local products="$WORK_DIR/ios/build/Build/Products/$1"
  local archive="$products/EasyDogeKMExpo/libEasyDogeKMExpo.a"
  local app="$products/$APP_NAME.app"
  local binary
  local linked=0

  [[ -f "$archive" ]] || fail "$1: libEasyDogeKMExpo.a was not built."
  [[ "$(nm "$archive" 2>/dev/null | count_matches 'EasyDogeKMModule')" -gt 0 ]] ||
    fail "$1: libEasyDogeKMExpo.a does not contain EasyDogeKMModule."
  for binary in "$app/$APP_NAME.debug.dylib" "$app/$APP_NAME"; do
    if [[ -f "$binary" && "$(nm "$binary" 2>/dev/null | count_matches 'ffi_easydoge_km_ffi_')" -gt 0 ]]; then
      linked=1
    fi
  done
  [[ "$linked" == "1" ]] || fail "$1: the app binary does not contain the Rust FFI symbols."
  log "$1: EasyDogeKMModule compiled and the Rust library is linked into $APP_NAME.app"
}

if [[ "$build_ios" == "1" ]]; then
  bundle_js ios
  run_logged pod-install ios_pod_install

  for pod in $IOS_PODS; do
    [[ "$(count_matches "^  - $pod (" <ios/Podfile.lock)" -gt 0 ]] ||
      fail "autolinking did not install the $pod pod (check the app's iOS deployment target)."
  done
  provider="$(find ios/Pods -name ExpoModulesProvider.swift | head -n 1)"
  [[ -n "$provider" && "$(count_matches 'EasyDogeKMModule.self' <"$provider")" -gt 0 ]] ||
    fail "autolinking did not register EasyDogeKMModule in ExpoModulesProvider.swift."

  run_logged xcodebuild-simulator ios_xcodebuild iphonesimulator "generic/platform=iOS Simulator"
  assert_ios_products Debug-iphonesimulator
  run_logged xcodebuild-device ios_xcodebuild iphoneos "generic/platform=iOS"
  assert_ios_products Debug-iphoneos
fi

# --- 5. Android -----------------------------------------------------------------------

android_assemble() {
  (cd "$WORK_DIR/android" && ./gradlew :app:assembleDebug --console=plain)
}

if [[ "$build_android" == "1" ]]; then
  bundle_js android
  run_logged gradle-assemble-debug android_assemble

  [[ "$(count_matches "^> Task $GRADLE_PROJECT:compileDebugKotlin\$" <"$LOG_DIR/gradle-assemble-debug.log")" -gt 0 ]] ||
    fail "Gradle did not run $GRADLE_PROJECT:compileDebugKotlin."
  [[ -f "node_modules/$PACKAGE_NAME/android/build/tmp/kotlin-classes/debug/io/easydoge/km/expo/EasyDogeKMModule.class" ]] ||
    fail "EasyDogeKMModule.class was not produced."

  apk="$WORK_DIR/android/app/build/outputs/apk/debug/app-debug.apk"
  [[ -f "$apk" ]] || fail "app-debug.apk was not produced."
  unzip -l "$apk" >"$LOG_DIR/apk-listing.txt"
  for abi in $ANDROID_ABIS; do
    for library in libeasydoge_km_ffi.so libjnidispatch.so; do
      [[ "$(count_matches "lib/$abi/$library\$" <"$LOG_DIR/apk-listing.txt")" -gt 0 ]] ||
        fail "app-debug.apk does not contain lib/$abi/$library."
    done
  done
  log "android: EasyDogeKMModule compiled and the Rust library is packaged for: $ANDROID_ABIS"
fi

log "OK"
