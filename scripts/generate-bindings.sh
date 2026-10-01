#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  echo "usage: scripts/generate-bindings.sh [--check | --print-committed-paths]" >&2
  exit 2
}

# Single source of truth for the generated UniFFI sources that are committed.
# Each entry is "<uniffi-bindgen output>:<committed path>", relative to the
# repository root. The copy step, the whitespace normalization, the --check
# identity gate, and --print-committed-paths all read this list.
BINDING_FILES=(
  "bindings/generated/swift/easydoge_km_ffi.swift:bindings/swift/Sources/easydoge_km_ffi/easydoge_km_ffi.swift"
  "bindings/generated/swift/easydoge_km_ffiFFI.h:bindings/swift/Sources/easydoge_km_ffiFFI/easydoge_km_ffiFFI.h"
  "bindings/generated/swift/easydoge_km_ffiFFI.modulemap:bindings/swift/Sources/easydoge_km_ffiFFI/module.modulemap"
  "bindings/generated/kotlin/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt:bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi/easydoge_km_ffi.kt"
)

COMMITTED_BINDING_PATHS=()
for entry in "${BINDING_FILES[@]}"; do
  COMMITTED_BINDING_PATHS+=("${entry#*:}")
done

if [[ $# -gt 1 ]]; then
  usage
fi

MODE="generate"
case "${1:-}" in
  "") ;;
  --check) MODE="check" ;;
  --print-committed-paths)
    printf '%s\n' "${COMMITTED_BINDING_PATHS[@]}"
    exit 0
    ;;
  *) usage ;;
esac

# Prints the version of every `uniffi` package recorded in the given Cargo
# lockfile, one per line. The binding generator must be the exact UniFFI
# release the FFI crate was compiled against, so the lockfile (not a constant
# in this script) is the authority.
locked_uniffi_versions() {
  awk '
    $0 == "name = \"uniffi\"" { want = 1; next }
    want && /^version = "/ { gsub(/^version = "|"$/, ""); print }
    { want = 0 }
  ' "$1"
}

# Fails when the regenerated committed bindings differ from the git index.
# Comparing against the index (not HEAD) lets a contributor who changed the
# FFI surface stage the regenerated files and continue; in CI the index equals
# HEAD, so stale committed bindings fail the build.
check_committed_bindings() {
  if ! command -v git >/dev/null 2>&1 ||
    [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]]; then
    echo "Skipping generated-binding identity check: not inside a git work tree."
    return 0
  fi

  local path drift=0
  for path in "${COMMITTED_BINDING_PATHS[@]}"; do
    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
      echo "Generated binding is not tracked by git: $path" >&2
      drift=1
    elif ! git diff --quiet -- "$path"; then
      echo "Generated binding differs from the git index: $path" >&2
      drift=1
    fi
  done

  if [[ "$drift" -ne 0 ]]; then
    {
      echo "Regenerated UniFFI bindings differ from the staged/committed sources."
      echo "Review the change with: git diff -- <path>"
      echo "Then stage the regenerated files and re-run:"
      echo "  git add -- \$(./scripts/generate-bindings.sh --print-committed-paths)"
    } >&2
    return 1
  fi

  echo "Generated UniFFI bindings match the git index."
}

cargo build -p easydoge-km-ffi

UNI_FFI_MANIFEST="${UNI_FFI_MANIFEST:-}"
if [[ -n "$UNI_FFI_MANIFEST" ]]; then
  if [[ ! -f "$UNI_FFI_MANIFEST" ]]; then
    echo "UNI_FFI_MANIFEST does not point to a file: $UNI_FFI_MANIFEST" >&2
    exit 1
  fi
else
  if [[ ! -f Cargo.lock ]]; then
    echo "Cargo.lock not found; cannot determine the locked UniFFI version." >&2
    exit 1
  fi
  UNI_FFI_VERSION="$(locked_uniffi_versions Cargo.lock)"
  version_pattern='^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$'
  if [[ -z "$UNI_FFI_VERSION" ]]; then
    echo "Cargo.lock has no uniffi package; cannot determine the UniFFI version." >&2
    exit 1
  elif [[ "$UNI_FFI_VERSION" == *$'\n'* ]]; then
    {
      echo "Cargo.lock pins more than one uniffi version:"
      echo "$UNI_FFI_VERSION"
      echo "Set UNI_FFI_MANIFEST to the Cargo.toml of the uniffi release that crates/easydoge-km-ffi depends on."
    } >&2
    exit 1
  elif [[ ! "$UNI_FFI_VERSION" =~ $version_pattern ]]; then
    echo "Unexpected uniffi version in Cargo.lock: $UNI_FFI_VERSION" >&2
    exit 1
  fi

  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  for candidate in "$CARGO_HOME"/registry/src/*/uniffi-"$UNI_FFI_VERSION"/Cargo.toml; do
    if [[ -f "$candidate" ]]; then
      UNI_FFI_MANIFEST="$candidate"
      break
    fi
  done

  if [[ ! -f "$UNI_FFI_MANIFEST" ]]; then
    echo "UniFFI $UNI_FFI_VERSION source not found in cargo registry. Run: cargo fetch --locked" >&2
    exit 1
  fi
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
  --crate easydoge_km_ffi \
  --no-format

cargo run --manifest-path "$UNI_FFI_MANIFEST" --features cli --bin uniffi-bindgen -- \
  generate "$FFI_LIBRARY_PATH" \
  --language kotlin \
  --out-dir bindings/generated/kotlin \
  --crate easydoge_km_ffi \
  --no-format

for entry in "${BINDING_FILES[@]}"; do
  generated="${entry%%:*}"
  committed="${entry#*:}"
  mkdir -p "$(dirname "$committed")"
  cp "$generated" "$committed"
done

perl -pi -e 's/[ \t]+$//' "${COMMITTED_BINDING_PATHS[@]}"

if [[ "$MODE" == "check" ]]; then
  check_committed_bindings
fi
