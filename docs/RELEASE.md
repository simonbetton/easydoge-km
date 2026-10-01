# Release Guide

This guide describes the intended release process and the current helper scripts. As checked on 2026-09-22, the GitHub repository has no tags or releases. Package version `0.1.0` and the changelog's implementation date do not establish a published release.

## Prerequisites

- Rust 1.91 or newer (workspace MSRV); `rust-toolchain.toml` tracks stable.
- Swift 6 or newer.
- JDK 17.
- Node.js 20 or newer and pnpm.
- Bash and ripgrep for verification.
- Android SDK platform 36 for Android package verification, with `ANDROID_HOME` or `bindings/kotlin/local.properties` configured.
- Android NDK, the corresponding Rust targets, and `cargo-ndk` for Android native release artifacts.
- Xcode for Apple native release artifacts.

## Local Verification

Run:

```sh
./scripts/verify.sh
```

Run the full suite on macOS. It checks required repository files/metadata, Rust formatting and tests, bitcoinjs cross-checks, Clippy, Rust builds/docs, generated UniFFI bindings, Swift tests, Expo TypeScript, and Kotlin JVM tests when the Gradle wrapper is executable. It syntax-checks every script under `scripts/`, regenerates the committed binding sources, and fails if they differ from the git index (what is staged; in a clean checkout, the commit itself).

It does not compile or run Expo native modules, exercise device storage/authentication, or build mobile release artifacts. `./scripts/verify-expo-native.sh` compiles the Expo native modules in a host app built from the packed tarball; run it before publishing the Expo package. A passing suite is not a security audit or proof of reproducible release binaries.

## Dependency Advisories

`./scripts/verify.sh` does not query advisory databases, so a passing suite says nothing about known-vulnerable dependencies. Before a release, and whenever `tools/bitcoinjs-cross-check/pnpm-lock.yaml` changes, audit the bitcoinjs cross-check harness (network access required):

```sh
pnpm --dir tools/bitcoinjs-cross-check audit
```

The expected output is `No known vulnerabilities found`. The harness is private verification tooling and nothing from it ships in a release artifact, so an advisory there does not change SDK behavior; resolve it anyway, or record why it does not apply, so the independent cross-check stays trustworthy.

When the patched version of a transitive dependency is inside the ranges its parents declare, refresh only that package and re-run the cross-check. Use pnpm 10, the major that CI activates:

```sh
corepack pnpm@10 --dir tools/bitcoinjs-cross-check update <package> --lockfile-only
bash scripts/cross-check.sh
```

Review the lockfile diff; it should touch only that package. Do not add a `pnpm.overrides` block to the harness `package.json`: pnpm 11 no longer reads that field and then rejects the lockfile under `--frozen-lockfile`. If an override is ever unavoidable, put it in `tools/bitcoinjs-cross-check/pnpm-workspace.yaml`.

Dependabot version updates watch the harness's direct dependencies only. Advisories in transitive dependencies surface through this audit, or through Dependabot alerts and security updates when those are enabled in the repository settings.

## Pinned Build Inputs

`bindings/kotlin/gradlew` is a repository-specific launcher, not the stock Gradle wrapper, and no `gradle-wrapper.jar` is committed. It downloads the distribution named by `distributionUrl` in `bindings/kotlin/gradle/wrapper/gradle-wrapper.properties`, compares its SHA-256 with `distributionSha256Sum` before extracting anything, and refuses to run when the checksum is missing or different. It needs `curl`, `unzip`, and `sha256sum` or `shasum`. Verified distributions are extracted under `<Gradle user home>/wrapper/dists/<distribution>/sha256-<checksum>/`; a tree extracted by an older launcher is never reused and can be deleted once no checkout uses it.

`scripts/check-native-build-pins.sh`, which `verify.sh` runs, tests the launcher offline against a fake distribution (it needs `zip`) and rejects dynamic dependency versions such as `+` in the Kotlin and Expo Android build files. The Expo Android module gets the host build's `:expo-modules-core` project through `expo-module-gradle-plugin`, so the app's package lockfile decides its version.

To change the Gradle version:

1. Pick a final Gradle release supported by the Android Gradle plugin version in `bindings/kotlin/build.gradle.kts`.
2. Fetch the published checksum with `curl -fsSL https://services.gradle.org/distributions/gradle-<version>-bin.zip.sha256` and confirm the same value is listed for that version on <https://gradle.org/release-checksums/>.
3. Update `distributionUrl` and `distributionSha256Sum` together in one commit. Do not run `gradle wrapper` and do not merge a Dependabot `gradle-wrapper` pull request: both replace the launcher with the stock script, which needs the uncommitted jar. Dependabot is configured to ignore that dependency.
4. Run `./scripts/verify.sh`.

Only the Gradle distribution is pinned by checksum. Gradle plugins and Maven libraries are pinned by exact version without checksum verification, `rust-toolchain.toml` tracks the stable channel, and CI actions are referenced by tag.

## Versioning

Update all package versions together:

- Rust crates under `crates/*/Cargo.toml`
- Internal `easydoge-km` dependency versions in the CLI and FFI manifests, plus the resolved `Cargo.lock`
- Expo package under `bindings/expo/package.json` (the podspecs in `bindings/expo/ios/` and `bindings/expo/android/build.gradle` read their version from it)
- Android Gradle package metadata, once publishing is enabled
- `CHANGELOG.md`

During `0.x`, minor versions may include breaking changes. Starting at `1.0.0`, use semantic versioning strictly.

## Binding Generation

Regenerate Swift and Kotlin UniFFI sources with:

```sh
./scripts/generate-bindings.sh
```

Generated scratch output goes under `bindings/generated/`. The committed package surfaces live under:

- `bindings/swift/Sources/easydoge_km_ffi`
- `bindings/swift/Sources/easydoge_km_ffiFFI`
- `bindings/kotlin/easydoge-km/src/main/java/uniffi/easydoge_km_ffi`

The generator takes the UniFFI version from `Cargo.lock`, so a UniFFI upgrade needs no script edit. `./scripts/generate-bindings.sh --check` (run by `verify.sh`) regenerates and then fails if a committed generated file is untracked or differs from the git index; `--print-committed-paths` lists those files. A dependency update that changes UniFFI's output, including a Dependabot pull request, fails this check until the regenerated bindings are committed on that branch. Outside a git work tree the check is skipped with a notice.

## Native Artifacts

For source releases, consumers can build native libraries locally. Binary releases should publish:

- Apple XCFramework for Swift and Expo iOS.
- Android `jniLibs` for all supported ABIs.
- Rust crate packages.
- CLI binaries for supported host platforms.

The release scripts are intentionally separate from `verify.sh` because they require platform toolchains and target SDKs.

Build helpers:

```sh
./scripts/generate-bindings.sh
./scripts/build-apple-xcframework.sh
./scripts/build-android-native-libs.sh
```

The Apple helper rebuilds `dist/apple/` and creates `dist/apple/easydoge_km_ffi.xcframework` for arm64 iOS devices and arm64/x86_64 simulators. The Android helper writes `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` libraries under `bindings/kotlin/easydoge-km/src/main/jniLibs`, targeting API 24 by default (`ANDROID_API` overrides it). Neither helper publishes a package or creates CLI binaries/checksums.

Before distributing mobile packages, complete and verify their native integration. The Swift manifest uses a workspace `target/debug` linker path rather than an XCFramework binary target; that is an integration gap the artifact scripts do not handle. The Expo package is assembled from the artifacts above by `scripts/pack-expo-package.sh`, described below. See [bindings/README.md](../bindings/README.md).

## Expo Package

`@easydoge/km-expo` is assembled at pack time; nothing it vendors is committed.

```sh
./scripts/build-apple-xcframework.sh
./scripts/build-android-native-libs.sh
./scripts/pack-expo-package.sh
```

`pack-expo-package.sh` runs `npm pack` in `bindings/expo`. The package's `prepack` script, `scripts/prepare-expo-package.sh`, compiles the TypeScript, copies the Swift and Kotlin wrappers, the generated UniFFI sources, the XCFramework, and the Android `jniLibs` into git-ignored directories inside the package, and writes `vendor-manifest.json` with the source commit and SHA-256 digests. It refuses to run when a native artifact is missing, is older than the Rust sources, or was built from different UniFFI headers. The pack script then checks the tarball against a required list, an allowlist, and a size budget, and prints the tarball path under `dist/expo/`. Set `EXPO_PACKAGE_BUILD_NATIVE=1` to run both native build helpers first.

A verified tarball is not proof that the module builds inside an app. `./scripts/verify-expo-native.sh` packs the tarball, installs it into the fixture app under `tools/expo-fixture` (Expo SDK 57), and builds that app for the iOS simulator, an unsigned iOS device target, and an Android debug APK; the `Expo Native` CI workflow runs the same script. That check does not launch the app: exercise the module in an Expo development build on each platform before publishing.

## Publishing Order

1. Choose a version, update manifests/internal dependencies and release notes, review the security limitations, and check the [dependency advisories](#dependency-advisories).
2. Commit the release changes, then run `./scripts/package-release.sh` from that checkout. It refuses to start unless `git status --porcelain` is empty (no staged, unstaged, or untracked files), runs the full verification suite including the generated-binding identity check, confirms verification left the checkout clean, and runs `cargo package -p easydoge-km` without `--allow-dirty`; it does not publish.
3. Complete the mobile integration described above, build target artifacts, and test the consuming iOS, Android, and Expo apps, including storage/authentication and recovery behavior.
4. Build the native artifacts and run `./scripts/pack-expo-package.sh`. It builds the Expo JavaScript and declarations, vendors the native sources and binaries, and verifies the tarball. Publish the tarball it prints (`npm publish <tarball>`), not the working directory.
5. Create a signed git tag for the verified release commit. The Expo podspecs name the bare version as their source tag (for example `0.1.0`); keep the tag and the package version consistent.
6. Publish `easydoge-km` and wait for that version to be available in the registry.
7. Run `PACKAGE_DEPENDENT_CRATES=1 ./scripts/package-release.sh` to package-check the FFI and CLI crates against the published core, then publish those crates.
8. Publish the validated mobile packages and attach native artifacts, CLI binaries, checksums, and migration notes to the GitHub release. Publishing is manual; the current CI workflow only verifies the workspace.
