#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_files=(
  ".editorconfig"
  ".gitattributes"
  ".github/CODEOWNERS"
  ".github/dependabot.yml"
  ".github/workflows/ci.yml"
  "CHANGELOG.md"
  "CODE_OF_CONDUCT.md"
  "CONTRIBUTING.md"
  "LICENSE-MIT"
  "README.md"
  "SECURITY.md"
  "docs/API.md"
  "docs/RELEASE.md"
  "docs/SECURITY_MODEL.md"
  "rust-toolchain.toml"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing required open-source file: $file" >&2
    exit 1
  fi
done

required_patterns=(
  "Cargo.toml:license ="
  "Cargo.toml:repository ="
  "bindings/expo/package.json:\"license\""
  "bindings/expo/package.json:\"repository\""
  ".gitignore:/target/"
  ".gitignore:**/build/"
  ".gitignore:**/.gradle/"
)

for pattern in "${required_patterns[@]}"; do
  file="${pattern%%:*}"
  text="${pattern#*:}"
  if ! grep -Fq "$text" "$file"; then
    echo "Required pattern not found in $file: $text" >&2
    exit 1
  fi
done

unfinished_pattern="TO""DO|FIX""ME|to""do!|un""implemented!"

if rg -n "$unfinished_pattern" \
  --glob '!target/**' \
  --glob '!bindings/generated/**' \
  --glob '!bindings/kotlin/**/build/**' \
  --glob '!bindings/kotlin/.gradle/**' \
  --glob '!bindings/expo/build/**' \
  --glob '!scripts/check-open-source-ready.sh' \
  .; then
  echo "Open-source readiness check found unfinished markers." >&2
  exit 1
fi
