# Security Model

EasyDoge KM is a deterministic key-management SDK for self-custodial Dogecoin products. It does not custody funds, connect to the Dogecoin network, broadcast transactions, or persist wallet secrets in the Rust core.

## Assets

Sensitive assets include:

- BIP39 seed phrases.
- BIP39 seeds.
- Extended private keys.
- WIF private keys.
- Unsigned transaction metadata that may reveal wallet structure.
- Signatures before a transaction is finalized.

Non-secret assets include:

- Extended public keys.
- Derived public keys.
- Addresses.
- Network and derivation-path metadata.

Extended public keys are not spending secrets, but they reveal wallet structure and should still be treated as sensitive user metadata.

## Implemented Checks and Boundaries

- The Rust core is the canonical implementation.
- Generated Swift/Kotlin bindings call the Rust FFI implementation; Expo adds handwritten converters and platform storage. The [API guide](API.md) lists coverage and wire-format differences.
- Successful CLI output redacts mnemonics, seeds, xprivs, WIFs, and message signatures unless `--reveal` is used. Redaction does not protect request files or arbitrary application logging.
- CLI secret inputs (seed phrase, BIP39 passphrase, xpriv, WIF) can be read from a file or from standard input with `--phrase-file`, `--passphrase-file`, `--xpriv-file`, and `--wif-file`, which keeps them out of command-line arguments, shell history, and process listings. The literal `--phrase`, `--passphrase`, `--xpriv`, and `--wif` flags remain for public test vectors; values passed that way are still exposed through shell history and process listings, and the CLI prints a warning on standard error when they are used. Protecting secret files, and the shell commands that create them, is the operator's responsibility.
- Xpub derivation rejects hardened child paths.
- Dogecoin-native extended-key prefixes are emitted by default.
- BIP39 seed phrases and BIP39 seeds cannot be recovered from xprivs.
- Signing rejects undefined sighash types and the SIGHASH_SINGLE output-index bug.
- BIP39 seed phrases and passphrases are NFKD-normalized before seed derivation.
- Signing-envelope descriptors must have unique, in-range input indices; P2SH scripts must match their redeem-script hashes. Signing and combining verify signatures for described inputs. Partial envelopes can carry unverified signatures for other in-range inputs. Finalization requires all inputs to be described and verifies all signatures.
- The Compose-and-Sign Transaction Builder checks the script shape of every UTXO it selects. P2PKH UTXOs need a canonical pay-to-pubkey-hash script pubkey. P2SH multisig fee sizing and signing-envelope metadata are read from the redeem script; caller-declared threshold and public keys are optional and rejected when they disagree with it.
- Multisig descriptors require distinct cosigner public keys and at most 15 cosigners, so the threshold counts independent signers and the redeem script stays within the 520-byte P2SH push limit. Signing envelopes reject redeem scripts above that limit and public-key metadata that is not exactly the redeem script's key list. Redeem scripts created elsewhere with a repeated key can still be spent; finalization counts one signature per distinct public key.
- The Compose-and-Sign Transaction Builder rejects a request that lists the same UTXO outpoint (`txid:vout`) more than once, so a repeated entry cannot inflate the reported input total or yield a transaction with a repeated input. It does not check that an outpoint exists or is unspent.
- Previous-output values and scripts are supplied by the caller, not authenticated against chain state. Internal envelope validation is not consensus or UTXO verification.

Secret values cross APIs as ordinary strings and byte arrays, and CLI display redaction does not imply automatic memory erasure. Debug formatting of every secret-bearing record (`GeneratedMnemonic`, `Xpriv`, `AccountKeySet`, `UtxoSigner`, `ChangeDestination`, `SpendableUtxo`, `ComposeTransactionRequest`) prints `[redacted]` in place of seed phrases, extended private keys, and WIFs. This covers Rust `Debug`, Kotlin `toString()` and string templates, and Swift `String(describing:)`, string interpolation, `print`, and `String(reflecting:)`; the Kotlin and Swift text is produced by the Rust library. Redaction stops there. Serialization (serde/JSON), direct field access, Swift `dump()` and `Mirror`, debugger variable views, Kotlin reflection and serializers, and the plain JavaScript objects returned by the Expo bridge all carry the real values, and secrets passed or returned as bare strings (phrase and WIF arguments, exported WIFs, seed hex) are never wrapped. Do not log secret-bearing records or requests.

## Storage Boundaries

The Rust core does not provide durable secret storage. Platform packages provide storage adapters:

- Swift stores mnemonic text in Keychain using `WhenUnlockedThisDeviceOnly`. Biometric protection requests the current biometric set; device-credential protection uses `userPresence`. The adapter reports `os-backed`, not a Secure Enclave guarantee.
- Kotlin encrypts mnemonic text with AES-GCM and a key in Android Keystore. Apps use `AndroidKeystoreWalletSecretStore.persistent(context)`, which writes the ciphertext and IV to app-private, no-backup storage (`Context.noBackupFilesDir`) so Stored Wallet Handles survive process death. Keystore keys never leave the device, so records are intentionally excluded from Auto Backup. `inMemory()` is for tests and demos and does not survive process death.
- Android requests StrongBox on API 28+ and falls back to standard Keystore. `hardware-backed` reports successful StrongBox key creation; `os-backed` is the fallback label, not proof that a device has no other hardware-backed Keystore.
- Both Android prompt modes currently request the same authentication policy. The adapter does not launch or connect a `BiometricPrompt` flow to its cipher operations. Authenticated storage/export must be verified and integrated on device; selecting a protection enum alone does not provide that UI.
- Expo calls these adapters directly in its native modules. The Android module uses the persistent store. The native modules accept only the exact strings `no-prompt`, `device-credential`, and `biometric` for `protection`; anything else rejects the call instead of falling back to `no-prompt`. `network` and `language` strings are validated the same way.

The adapters store the mnemonic only, not its optional BIP39 passphrase. Applications must retain the handle and arrange recovery of both mnemonic and passphrase. Passing a different protection mode to export does not rewrite the access controls selected at storage time.

Applications remain responsible for backup UX, user authentication policy, device compromise assumptions, and recovery flows.

## Verification Limits

The workspace suite runs Rust tests, independent bitcoinjs vectors, Swift wrapper tests, Kotlin JVM wrapper tests, and numeric and enum codec tests. Expo receives a TypeScript check against a local declaration. The suite does not compile the Expo native modules, test device Keychain/Keystore authentication or process-death recovery, or build mobile release artifacts. Passing it is not evidence of an independent security audit or production readiness.

## Operational Requirements

- Never log seed phrases, xprivs, WIFs, or raw private keys.
- Pass CLI secrets through the `-file` flags or standard input, never as literal flag values.
- Never accept xpub-derived hardened paths.
- Keep release artifacts reproducible from source and CI.
- Run `./scripts/verify.sh` before release.
- Use disposable test vectors in issues, tests, and documentation.

## Known Non-Goals

- Recovering seed phrases from xprivs.
- Hardware wallet transport.
- Dogecoin network indexing or broadcasting.
- Custodial key storage.
- Consensus validation.
