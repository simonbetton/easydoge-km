# EasyDoge KM

Production-ready Dogecoin key-management SDK for self-custodial products.

EasyDoge KM provides one canonical Rust implementation, native Swift and Kotlin bindings, an Expo React Native bridge, and an engineer CLI/TUI. The project is built around deterministic parity vectors so backend, iOS, Android, Expo, CLI, and TUI surfaces stay aligned.

## Workspace

- `crates/easydoge-km`: Rust core SDK.
- `crates/easydoge-km-cli`: Scriptable CLI and Ratatui TUI.
- `crates/easydoge-km-ffi`: UniFFI wrapper used by mobile bindings.
- `bindings/`: Swift, Kotlin, generated UniFFI, and Expo package surfaces.
- `docs/`: API, security model, release, and architecture documentation.
- `scripts/`: Verification, binding generation, and release artifact helpers.
- `test-vectors/`: Shared parity vectors consumed by every public surface.

## Features

- BIP39 mnemonic generation, validation, and seed hex derivation.
- Dogecoin BIP44 account xpriv/xpub derivation with Dogecoin-native extended-key prefixes.
- Non-hardened xpub derivation for watch-only account/address workflows.
- xpriv path derivation, xpriv-to-xpub conversion, WIF export/import, and address validation.
- P2PKH message signing/verification and transaction signing envelopes.
- Deterministic P2SH multisig descriptors plus sign/combine/finalize CLI flows.
- Rust, Swift, Kotlin, and Expo APIs generated from the same Rust implementation for 1:1 feature parity.
- Ratatui CLI/TUI for engineers who want terminal access to the Rust implementation.

## Requirements

- Rust stable from `rust-toolchain.toml`
- Swift 6 or newer for Swift package verification
- JDK 17 for Android/Kotlin verification
- Node.js 20 or newer for Expo TypeScript verification
- Xcode for Apple release artifacts
- Android SDK and `cargo-ndk` for Android native release artifacts

## Quick Start

Run the full verification suite:

```sh
./scripts/verify.sh
```

Generate a mnemonic without revealing the phrase:

```sh
cargo run -p easydoge-km-cli -- mnemonic generate
```

Launch the TUI:

```sh
cargo run -p easydoge-km-cli -- tui
```

Derive an account key set from a known test mnemonic:

```sh
cargo run -p easydoge-km-cli -- xpriv from-mnemonic \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

## API Surfaces

- Rust backend services use the `easydoge-km` crate directly.
- iOS apps use the Swift package under `bindings/swift`.
- Android apps use the Kotlin package under `bindings/kotlin`.
- Expo apps use the Expo Modules API package under `bindings/expo` in custom dev-client or EAS builds.
- Engineers can use the CLI binary and Ratatui TUI from `crates/easydoge-km-cli`.

See [docs/API.md](docs/API.md) for the parity table and examples.

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
- Clippy with warnings denied
- Rust workspace build
- Rust docs build
- UniFFI Swift and Kotlin binding generation
- Swift package tests
- Expo TypeScript checks
- Android/Kotlin Gradle tests

## Releasing

Release steps are documented in [docs/RELEASE.md](docs/RELEASE.md). Native artifact helpers live in:

- `scripts/build-apple-xcframework.sh`
- `scripts/build-android-native-libs.sh`
- `scripts/package-release.sh`

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), follow TDD for behavior changes, and keep all public surfaces in parity.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
