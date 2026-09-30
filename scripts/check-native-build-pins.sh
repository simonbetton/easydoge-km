#!/usr/bin/env bash
# Checks that the native build inputs this repository controls stay pinned:
#   1. gradle-wrapper.properties pins the Gradle distribution by SHA-256;
#   2. bindings/kotlin/gradlew verifies that checksum and fails closed
#      (exercised offline against a tiny fake distribution; no network, and
#      the real Gradle cache is never touched);
#   3. first-party Gradle build files declare no dynamic dependency versions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LAUNCHER="bindings/kotlin/gradlew"
PROPS="bindings/kotlin/gradle/wrapper/gradle-wrapper.properties"

fail() {
  echo "check-native-build-pins: $*" >&2
  exit 1
}

# 1. The Gradle distribution is pinned by URL and SHA-256.
grep -Fq 'distributionUrl=https\://services.gradle.org/distributions/' "$PROPS" \
  || fail "$PROPS must download Gradle from https://services.gradle.org/distributions/"
grep -Eq '^distributionSha256Sum=[0-9a-f]{64}$' "$PROPS" \
  || fail "$PROPS must pin distributionSha256Sum (64 lowercase hex characters)"
[[ ! -e bindings/kotlin/gradle/wrapper/gradle-wrapper.jar ]] \
  || fail "gradle-wrapper.jar must not be committed; $LAUNCHER is a jar-free verifying launcher"

# 2. The launcher fails closed.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_tool=(sha256sum)
else
  sha256_tool=(shasum -a 256)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/project/gradle/wrapper" "$WORK/dist/gradle-0.0.0/bin"
cp "$LAUNCHER" "$WORK/project/gradlew"
printf '%s\n' '#!/usr/bin/env bash' 'echo "fake gradle ran: $*"' > "$WORK/dist/gradle-0.0.0/bin/gradle"
chmod +x "$WORK/project/gradlew" "$WORK/dist/gradle-0.0.0/bin/gradle"
(cd "$WORK/dist" && zip -qr "$WORK/gradle-0.0.0-bin.zip" gradle-0.0.0)

good_sha="$("${sha256_tool[@]}" < "$WORK/gradle-0.0.0-bin.zip")"
good_sha="${good_sha%% *}"
bad_sha="0000000000000000000000000000000000000000000000000000000000000000"
cache="$WORK/home/wrapper/dists/gradle-0.0.0-bin"

write_props() {
  {
    echo "distributionUrl=file\\://$WORK/gradle-0.0.0-bin.zip"
    if [[ -n "$1" ]]; then
      echo "distributionSha256Sum=$1"
    fi
  } > "$WORK/project/gradle/wrapper/gradle-wrapper.properties"
}

run_launcher() {
  status=0
  output="$(GRADLE_USER_HOME="$WORK/home" "$WORK/project/gradlew" --version 2>&1)" || status=$?
}

# A tree left behind by the pre-checksum launcher must never be executed.
mkdir -p "$cache/gradle-0.0.0/bin"
printf '%s\n' '#!/usr/bin/env bash' 'echo "unverified legacy tree ran"' > "$cache/gradle-0.0.0/bin/gradle"
chmod +x "$cache/gradle-0.0.0/bin/gradle"

write_props ""
run_launcher
[[ $status -ne 0 && "$output" == *"distributionSha256Sum is missing"* && "$output" != *" ran"* ]] \
  || fail "launcher must refuse to run without distributionSha256Sum (exit $status): $output"
[[ ! -e "$cache/gradle-0.0.0-bin.zip" ]] \
  || fail "launcher downloaded a distribution that has no pinned checksum"
echo "ok - refuses to run without distributionSha256Sum"

write_props "$bad_sha"
run_launcher
[[ $status -ne 0 && "$output" == *"SHA-256 mismatch"* && "$output" == *"expected: $bad_sha"* \
  && "$output" == *"actual:   $good_sha"* && "$output" != *" ran"* ]] \
  || fail "launcher must reject a distribution whose SHA-256 differs (exit $status): $output"
[[ ! -e "$cache/gradle-0.0.0-bin.zip" && ! -e "$cache/sha256-$bad_sha" ]] \
  || fail "a mismatching archive must be deleted and never extracted"
echo "ok - rejects a mismatching distribution before extracting it"

write_props "$good_sha"
run_launcher
[[ $status -eq 0 && "$output" == "fake gradle ran: --version" ]] \
  || fail "launcher must run a distribution whose SHA-256 matches (exit $status): $output"
echo "ok - runs a distribution whose SHA-256 matches"

rm -f "$WORK/gradle-0.0.0-bin.zip" "$cache/gradle-0.0.0-bin.zip"
run_launcher
[[ $status -eq 0 && "$output" == "fake gradle ran: --version" ]] \
  || fail "launcher must reuse an already verified distribution (exit $status): $output"
echo "ok - reuses the verified distribution without downloading again"

write_props "$bad_sha"
run_launcher
[[ $status -ne 0 && "$output" != *" ran"* ]] \
  || fail "a changed distributionSha256Sum must not be served from the cache (exit $status): $output"
echo "ok - re-verifies when distributionSha256Sum changes"

# 3. No dynamic dependency versions in first-party Gradle build files.
dynamic_versions="$(
  grep -rnE "\+['\"]|latest\.(release|integration)|SNAPSHOT['\"]" \
    --include='*.gradle' --include='*.gradle.kts' \
    --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.kotlin --exclude-dir=node_modules \
    bindings/kotlin bindings/expo/android || true
)"
[[ -z "$dynamic_versions" ]] \
  || fail "dynamic dependency versions are not allowed:"$'\n'"$dynamic_versions"
echo "ok - no dynamic dependency versions in first-party Gradle build files"

echo "Native build inputs are pinned."
