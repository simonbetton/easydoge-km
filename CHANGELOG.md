# Changelog

All notable changes to EasyDoge KM will be documented here.

The project uses semantic versioning for public APIs once it reaches `1.0.0`. During `0.x`, minor versions may include breaking changes.

## [Unreleased]

### Added

- Added a Ratatui paste inspector for Dogecoin addresses, seed phrases, extended keys, and WIFs.

### Changed

- Redesigned the Ratatui TUI as a live address explorer. The fixed question/answer panels are replaced by a responsive layout (side by side from 80 columns, stacked below that) with a source panel, a receive/change address table that re-derives as you move, and a selected-address panel showing the derivation path and public key. New keys: `t` cycles networks, `:` jumps to an index, `x` returns to the sample mnemonic, `?` opens a key reference, and `Ctrl+C` quits from any mode. The paste inspector and passphrase prompt are masked popups. The `i`/`o`/`d` derivation keys and the `v` sample-validation key were removed because addresses now derive automatically, and `Esc` hides revealed secrets instead of quitting.
- The TUI classifies testnet-style extended keys (`tprv`/`tpub`) as testnet instead of mainnet, and only offers regtest as the alternative network for them.
- Refreshed Rust workspace dependencies within existing Cargo semver ranges.
- Upgraded UniFFI to 0.32.0 (crate, binding generator, and generated Swift/Kotlin sources). Workspace MSRV is now Rust 1.91 because UniFFI 0.32 pulls `cargo-platform` 0.3.3. Rebuild native libraries together with these bindings or UniFFI checksum checks will fail.
- Upgraded `base64` from 0.22 to 0.23 for message signature encoding.
- Upgraded the Expo TypeScript typecheck to 7.0.2 and pinned `rootDir` to `src` so emit still lands at `build/index.js`.
- **Breaking (Kotlin)**: `AndroidKeystoreWalletSecretStore` no longer has a no-argument constructor. Use `AndroidKeystoreWalletSecretStore.persistent(context)` in apps or `.inMemory()` in tests. The Expo Android module now uses the persistent variant.

### Fixed

- **Breaking (Expo)**: koinu amounts in the Expo API are now decimal strings (`Koinu`) instead of numbers, and every other integer field is validated on the native side. Previously values above 2^53 lost precision, negative or fractional values could wrap on Android or crash on iOS.
- Android stored-wallet records (ciphertext and IV) are now persisted to app-private no-backup storage. Previously they lived only in process memory, so a `StoredWalletHandle` became unusable after the process was killed while the Keystore key lingered.

### Security

- Transaction signing and the Compose-and-Sign Transaction Builder now reject an unsupported sighash type (anything other than the six consensus-defined values) and reject `SIGHASH_SINGLE` for inputs without a matching output. Previously any `u32` was accepted, producing unspendable or, for the SIGHASH_SINGLE bug case, dangerously reusable signatures.
- BIP39 passphrases are now NFKD-normalized before PBKDF2, matching the BIP39 specification and the bitcoinjs cross-check. Wallets previously derived through EasyDoge KM with a passphrase containing non-NFKD characters (precomposed accented letters, fullwidth or compatibility characters, ideographic spaces) will derive different keys after this release; those derivations were not reproducible by other BIP39 wallets. Sweep funds using a pre-release build before upgrading. ASCII and empty passphrases are unaffected.
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
