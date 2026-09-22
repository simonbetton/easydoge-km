# EasyDoge KM

Dogecoin key-management SDK for self-custodial products.

EasyDoge KM provides one canonical Rust implementation, native Swift and Kotlin bindings, an Expo React Native bridge, and an engineer CLI/TUI. Shared fixtures exercise the Rust core, UniFFI, Swift, and Kotlin wrappers. Expo native integration and device storage behavior are not covered by the workspace verification suite; see the [security model](docs/SECURITY_MODEL.md) for current limitations.

## Workspace

- `crates/easydoge-km`: Rust core SDK.
- `crates/easydoge-km-cli`: Scriptable CLI and Ratatui TUI.
- `crates/easydoge-km-ffi`: UniFFI wrapper used by mobile bindings.
- `bindings/`: Swift, Kotlin, generated UniFFI, and Expo package surfaces.
- `docs/`: API, CLI/TUI, security model, release, and architecture documentation.
- `scripts/`: Verification, binding generation, and release artifact helpers.
- `test-vectors/`: Shared parity fixtures and inputs for independent Rust/bitcoinjs cross-checks.
- `tools/bitcoinjs-cross-check`: Independent bitcoinjs-based cross-check runner.

## Features

- BIP39 mnemonic generation, validation, and seed hex derivation.
- Dogecoin BIP44 account xpriv/xpub derivation with Dogecoin-native extended-key prefixes.
- Non-hardened xpub derivation for watch-only account/address workflows.
- xpriv path derivation, xpriv-to-xpub conversion, WIF export/import, and address validation.
- P2PKH message signing/verification and transaction signing envelopes.
- Deterministic P2SH multisig descriptors plus sign/combine/finalize CLI flows.
- Generated Swift/Kotlin UniFFI bindings and a handwritten Expo bridge over the Rust implementation. The [API table](docs/API.md#key-and-seed-apis) lists coverage and exceptions.
- Ratatui CLI/TUI for engineers who want terminal access to the Rust implementation.

## Requirements

- Rust 1.91 or newer (workspace MSRV); `rust-toolchain.toml` tracks stable
- Swift 6 or newer for Swift package verification
- JDK 17 for Android/Kotlin verification
- Node.js 20 or newer and pnpm for Expo TypeScript and cross-check verification
- Bash and ripgrep for the verification scripts
- Android SDK with platform 36 and an SDK path configured through `ANDROID_HOME` or `bindings/kotlin/local.properties` for Gradle checks
- Xcode for Apple release artifacts
- Android NDK and `cargo-ndk` for Android native release artifacts

The full verification workflow runs on macOS in CI. Swift storage uses Apple's Security and LocalAuthentication frameworks, so the full suite requires an Apple development environment.

## Quick Start

Run the full verification suite:

```sh
./scripts/verify.sh
```

Install the CLI from the workspace root:

```sh
cargo install --path crates/easydoge-km-cli --force
```

Generate a mnemonic without revealing the phrase:

```sh
easydoge-km mnemonic generate
```

Launch the TUI:

```sh
easydoge-km tui
```

Derive an account key set from a known test mnemonic:

```sh
easydoge-km xpriv from-mnemonic \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

## API Surfaces

- Rust backend services use the `easydoge-km` crate directly.
- iOS apps can integrate the Swift sources under `bindings/swift` with a matching native library.
- Android apps can integrate the Kotlin library under `bindings/kotlin` with native libraries for their target ABIs.
- Expo apps can integrate the native module sources under `bindings/expo` in custom dev-client or EAS builds; Expo Go is unsupported.
- Engineers can use the CLI binary and Ratatui TUI from `crates/easydoge-km-cli`.

See [docs/API.md](docs/API.md) for the parity table and examples, and [docs/CLI.md](docs/CLI.md) for CLI/TUI usage.

The mobile packages currently rely on workspace paths and separately built native libraries. See [bindings/README.md](bindings/README.md) for integration requirements; they are not standalone binary distributions.

## Security Boundary

The SDK derives keys from a seed phrase and optional passphrase. It cannot recover the original BIP39 seed phrase or BIP39 seed from an xpriv; BIP32 derivation is intentionally one-way. APIs that start from an xpriv only derive child keys, xpubs, WIFs, addresses, and signatures.

The Rust core does not provide custodial storage. Platform packages include storage adapters, but applications remain responsible for authentication policy, backup UX, recovery flows, and device compromise assumptions.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [SECURITY.md](SECURITY.md).

## Verification

`./scripts/verify.sh` runs:

- Open-source readiness checks
- Shell syntax checks
- `cargo fmt --all --check`
- Rust workspace tests
- BitcoinJS cross-checks for Dogecoin BIP39/BIP32/BIP44, address, WIF, message signing, transaction signing, and multisig behavior
- Clippy with warnings denied
- Rust workspace build
- Rust docs build
- UniFFI Swift and Kotlin binding generation
- Swift package tests
- Expo TypeScript checks
- Android/Kotlin Gradle tests

The shell syntax command currently checks `scripts/build-android-native-libs.sh`, the first file expanded by `scripts/*.sh`; it does not loop over every script. Gradle tests run when the wrapper is executable. The suite regenerates committed binding sources, so inspect the diff afterward. Expo is typechecked against a local module declaration; its native modules are not compiled or run by this suite. Storage authentication, persistence, and mobile release artifacts need separate device/build verification.

## Releasing

Release steps are documented in [docs/RELEASE.md](docs/RELEASE.md). Native artifact helpers live in:

- `scripts/build-apple-xcframework.sh`
- `scripts/build-android-native-libs.sh`
- `scripts/package-release.sh`

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), follow TDD for behavior changes, and keep all public surfaces in parity.

## License

MIT license ([LICENSE-MIT](LICENSE-MIT)).
