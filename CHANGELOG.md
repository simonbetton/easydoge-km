# Changelog

All notable changes to EasyDoge KM will be documented here.

The project uses semantic versioning for public APIs once it reaches `1.0.0`. During `0.x`, minor versions may include breaking changes.

## [Unreleased]

### Added

- Added a Ratatui paste inspector for Dogecoin addresses, seed phrases, extended keys, and WIFs.

### Changed

- Refreshed Rust workspace dependencies within existing Cargo semver ranges and aligned the UniFFI binding-generator pin to 0.31.2.

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
