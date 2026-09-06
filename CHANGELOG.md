# Changelog

All notable changes to EasyDoge KM will be documented here.

The project uses semantic versioning for public APIs once it reaches `1.0.0`. During `0.x`, minor versions may include breaking changes.

## [Unreleased]

### Added

- Added a Ratatui paste inspector for Dogecoin addresses, seed phrases, extended keys, and WIFs.

### Changed

- Refreshed Rust workspace dependencies within existing Cargo semver ranges.
- Upgraded UniFFI to 0.32.0 (crate, binding generator, and generated Swift/Kotlin sources). Workspace MSRV is now Rust 1.91 because UniFFI 0.32 pulls `cargo-platform` 0.3.3. Rebuild native libraries together with these bindings or UniFFI checksum checks will fail.
- Upgraded `base64` from 0.22 to 0.23 for message signature encoding.
- Upgraded the Expo TypeScript typecheck to 7.0.2 and pinned `rootDir` to `src` so emit still lands at `build/index.js`.

### Security

- Transaction signing and the Compose-and-Sign Transaction Builder now reject an unsupported sighash type (anything other than the six consensus-defined values) and reject `SIGHASH_SINGLE` for inputs without a matching output. Previously any `u32` was accepted, producing unspendable or, for the SIGHASH_SINGLE bug case, dangerously reusable signatures.
- Signing envelopes are now validated end to end: input descriptors must be unique and in range, P2SH redeem scripts must hash to their script pubkey, signing only covers inputs the key controls, combine/finalize verify every signature, and finalize requires every input to be described. Envelopes with forged or foreign signatures are rejected instead of producing invalid transactions.

## 0.1.0 - 2026-06-04

- Added Rust core Dogecoin key-management SDK.
- Added BIP39 mnemonic generation, validation, and seed derivation.
- Added Dogecoin BIP44 account xpriv/xpub derivation and watch-only address derivation.
- Added xpriv path derivation, xpub path derivation, xpriv-to-xpub conversion, WIF export/import, and address validation.
- Added message signing and verification.
- Added transaction signing envelopes and P2PKH signing.
- Added deterministic P2SH multisig descriptor, sign, combine, and finalize flows.
- Added UniFFI-backed Swift and Kotlin bindings.
- Added Expo Modules API bridge for React Native and Expo apps.
- Completed Swift, Kotlin, and Expo parity surfaces for signing, envelopes, metadata inspection, WIF import/export, and multisig.
- Added scriptable CLI and Ratatui TUI.
- Added parity vectors and full workspace verification.
