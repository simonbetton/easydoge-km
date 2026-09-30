# Changelog

All notable changes to EasyDoge KM will be documented here.

The project uses semantic versioning for public APIs once it reaches `1.0.0`. During `0.x`, minor versions may include breaking changes.

## [Unreleased]

### Added

- Added a Ratatui paste inspector for Dogecoin addresses, seed phrases, extended keys, and WIFs.

### Changed

- Corrected documentation to distinguish implemented APIs from runtime test coverage, document current storage and passphrase limitations, and clarify native integration and release requirements.
- Redesigned the Ratatui TUI as a live address explorer. The fixed question/answer panels are replaced by a responsive layout (side by side from 80 columns, stacked below that) with a source panel, a receive/change address table that re-derives as you move, and a selected-address panel showing the derivation path and public key. New keys: `t` cycles networks, `:` jumps to an index, `x` returns to the sample mnemonic, `?` opens a key reference, and `Ctrl+C` quits from any mode. The paste inspector and passphrase prompt are masked popups. The `i`/`o`/`d` derivation keys and the `v` sample-validation key were removed because addresses now derive automatically, and `Esc` hides revealed secrets instead of quitting.
- The TUI classifies testnet-style extended keys (`tprv`/`tpub`) as testnet instead of mainnet, and only offers regtest as the alternative network for them.
- Refreshed Rust workspace dependencies within existing Cargo semver ranges.
- Upgraded UniFFI to 0.32.0 (crate, binding generator, and generated Swift/Kotlin sources). Workspace MSRV is now Rust 1.91 because UniFFI 0.32 pulls `cargo-platform` 0.3.3. Rebuild native libraries together with these bindings or UniFFI checksum checks will fail.
- Upgraded `base64` from 0.22 to 0.23 for message signature encoding.
- Upgraded the Expo TypeScript typecheck to 7.0.2 and pinned `rootDir` to `src` so emit still lands at `build/index.js`.
- **Breaking (Kotlin)**: `AndroidKeystoreWalletSecretStore` no longer has a no-argument constructor. Use `AndroidKeystoreWalletSecretStore.persistent(context)` in apps or `.inMemory()` in tests. The Expo Android module now uses the persistent variant.
- Refreshed the bitcoinjs cross-check harness lockfile so its transitive `valibot` dependency resolves to a release patched for GHSA-5qjj-4xww-7phc (moderate; verification tooling only, no shipped artifact was affected), and added the harness to the Dependabot configuration.
- `scripts/verify.sh` now fails when the regenerated UniFFI Swift/Kotlin sources differ from the git index and syntax-checks every script under `scripts/` instead of only the first. `scripts/generate-bindings.sh` reads the UniFFI version from `Cargo.lock` and gained `--check` and `--print-committed-paths`. A UniFFI upgrade must commit the regenerated bindings.
- `scripts/package-release.sh` refuses to run from a checkout with uncommitted or untracked files and no longer passes `--allow-dirty` to `cargo package`.

### Fixed

- **Breaking (Expo)**: koinu amounts in the Expo API are now decimal strings (`Koinu`) instead of numbers, and every other integer field is validated on the native side. Previously values above 2^53 lost precision, negative or fractional values could wrap on Android or crash on iOS.
- Android stored-wallet records (ciphertext and IV) are now persisted to app-private no-backup storage. Previously they lived only in process memory, so a `StoredWalletHandle` became unusable after the process was killed while the Keystore key lingered.
- The Compose-and-Sign Transaction Builder now rejects a request that lists the same UTXO outpoint (`txid:vout`) more than once, comparing txid hex case-insensitively, with `duplicate UTXO outpoint <txid>:<vout>`. Previously a repeated UTXO could be counted twice in the input total and emitted as two identical inputs, which Dogecoin consensus rejects, or be reported as a skipped input.
- The Compose-and-Sign Transaction Builder now reads the P2SH multisig threshold and public keys from the redeem script when estimating fees and when writing signing envelopes. Previously it sized inputs from the caller-supplied `multisig_threshold` without checking it, so a wrong value underfunded the fee and the mismatch only surfaced when a cosigner signed. `multisig_threshold` and `multisig_public_keys_hex` on a UTXO are now optional; when supplied they must match the redeem script. Requests are now rejected at compose time, instead of failing later at signing, when a P2SH multisig redeem script is not a standard `m`-of-`n` `OP_CHECKMULTISIG` script with compressed keys or when a P2PKH UTXO's script pubkey is not a pay-to-pubkey-hash script.

### Security

- Transaction signing and the Compose-and-Sign Transaction Builder now reject an unsupported sighash type (anything other than the six consensus-defined values) and reject `SIGHASH_SINGLE` for inputs without a matching output. Previously any `u32` was accepted, producing unspendable or, for the SIGHASH_SINGLE bug case, dangerously reusable signatures.
- BIP39 passphrases are now NFKD-normalized before PBKDF2, matching the BIP39 specification and the bitcoinjs cross-check. Wallets previously derived through EasyDoge KM with a passphrase containing non-NFKD characters (precomposed accented letters, fullwidth or compatibility characters, ideographic spaces) will derive different keys after this release; those derivations were not reproducible by other BIP39 wallets. Sweep funds using a pre-release build before upgrading. ASCII and empty passphrases are unaffected.
- Signing envelopes now require unique, in-range input descriptors and P2SH redeem scripts that hash to their script pubkey. Signing only covers inputs the key controls. Signing and combining verify signatures for described inputs; partial envelopes can carry unverified signatures for other in-range inputs. Finalization requires every input to be described and verifies every signature.
- The Kotlin Gradle launcher (`bindings/kotlin/gradlew`) now verifies the downloaded Gradle distribution against a pinned `distributionSha256Sum` before extracting it, and refuses to run when the checksum is missing or does not match. Verified distributions are extracted under a checksum-named directory, so the first Gradle run after this change re-extracts Gradle (without downloading again when the archive is already cached). The Expo Android module now depends on the host build's `:expo-modules-core` project instead of the dynamic Maven version `expo.modules:expo-modules-core:+`. `./scripts/verify.sh` runs `scripts/check-native-build-pins.sh` to keep both pinned.
- `create_multisig_descriptor` now rejects cosigners that derive the same public key, including the same xpub supplied twice or under a legacy prefix. Previously a repeated key produced a P2SH address whose threshold could be met by fewer independent signers than advertised.
- P2SH multisig descriptors are limited to 15 cosigners. **Do not fund a 16-cosigner P2SH address created by an earlier build: it is unspendable.** A 16-key redeem script is 547 bytes, above the 520-byte limit for a pushed script element, so no transaction from any wallet can reveal it. Signing envelopes now reject redeem scripts above 520 bytes instead of producing a transaction that can never be valid.
- Signing envelopes now require `multisig_public_keys_hex`, when supplied, to list exactly the redeem script's public keys; previously a same-length list of keys that merely appeared in the script was accepted. Finalization no longer counts the same signature twice when its public key hex differs only in letter case.

## Initial 0.1.0 implementation - 2026-06-04

This records the initial implementation at package version `0.1.0`, not a published GitHub release.

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
