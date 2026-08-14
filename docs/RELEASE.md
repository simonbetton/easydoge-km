# Release Guide

This guide describes how to cut an open-source release from the repository.

## Prerequisites

- Rust 1.91 or newer (workspace MSRV); `rust-toolchain.toml` tracks stable.
- Swift 6 or newer.
- JDK 17.
- Node.js 20 or newer.
- Android SDK for Android package verification.
- `cargo-ndk` for Android native release artifacts.
- Xcode for Apple native release artifacts.

## Local Verification

Run:

```sh
./scripts/verify.sh
```

This checks open-source readiness, Rust formatting, Rust tests, Clippy, Rust docs, generated UniFFI bindings, Swift tests, Expo TypeScript, and Android/Kotlin tests.

## Versioning

Update all package versions together:

- Rust crates under `crates/*/Cargo.toml`
- Expo package under `bindings/expo/package.json`
- Expo iOS podspec under `bindings/expo/ios/EasyDogeKMExpo.podspec`
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

## Native Artifacts

For source releases, consumers can build native libraries locally. Binary releases should publish:

- Apple XCFramework for Swift and Expo iOS.
- Android `jniLibs` for all supported ABIs.
- Rust crate packages.
- CLI binaries for supported host platforms.

The release scripts are intentionally separate from `verify.sh` because they require platform toolchains and target SDKs.

## Publishing Order

1. Run `./scripts/verify.sh`.
2. Run `./scripts/package-release.sh` to package-check the core crate.
3. Regenerate bindings and confirm no unexpected diff.
4. Build native artifacts for target platforms.
5. Create a signed git tag.
6. Publish `easydoge-km`.
7. Run `PACKAGE_DEPENDENT_CRATES=1 ./scripts/package-release.sh`.
8. Publish `easydoge-km-ffi` and `easydoge-km-cli`.
9. Publish Expo package.
10. Attach native artifacts and checksums to the GitHub release.
11. Update release notes with security-relevant changes and migration notes.
