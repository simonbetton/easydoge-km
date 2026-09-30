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
- WIF keys keep their compression flag end to end: addresses, message signatures, and P2PKH ownership checks use the public key form the WIF commits to. Message verification rejects signature headers outside 27–34. Envelope signatures must use a compressed public key or, for P2PKH inputs only, an uncompressed one; hybrid encodings are rejected, and uncompressed keys cannot sign P2SH multisig inputs.
- The Compose-and-Sign Transaction Builder checks the script shape of every UTXO it selects. P2PKH UTXOs need a canonical pay-to-pubkey-hash script pubkey. P2SH multisig fee sizing and signing-envelope metadata are read from the redeem script; caller-declared threshold and public keys are optional and rejected when they disagree with it.
- Multisig descriptors require distinct cosigner public keys and at most 15 cosigners, so the threshold counts independent signers and the redeem script stays within the 520-byte P2SH push limit. Signing envelopes reject redeem scripts above that limit and public-key metadata that is not exactly the redeem script's key list. Redeem scripts created elsewhere with a repeated key can still be spent; finalization counts one signature per distinct public key.
- The Compose-and-Sign Transaction Builder rejects a request that lists the same UTXO outpoint (`txid:vout`) more than once, so a repeated entry cannot inflate the reported input total or yield a transaction with a repeated input. It does not check that an outpoint exists or is unspent.
- Public request boundaries enforce resource limits before any parsing, hashing, key derivation, or signature verification: transaction size, script size, the number of UTXOs, outputs, signers, signatures, and combined envelopes, and the length of Base58Check text. The [API guide](API.md#limits) lists each limit. The limits bound per-call work; they are not rate limiting, and a Signing Envelope at the limits can still take seconds to verify.
- Previous-output values and scripts are supplied by the caller, not authenticated against chain state. Internal envelope validation is not consensus or UTXO verification.

Secret values cross APIs as ordinary strings and byte arrays. The Rust core wipes the secret memory it owns on a best-effort basis ([ADR 0008](adr/0008-secret-memory-hygiene.md)): normalized seed phrases and passphrases, BIP39 seeds, decoded extended-key and WIF payloads, private keys, and chain codes are zeroized or erased when the call that needed them returns, and `Xpriv`, `GeneratedMnemonic`, and `UtxoSigner` records (and therefore `AccountKeySet`, `ChangeDestination`, `SpendableUtxo`, and `ComposeTransactionRequest`) zeroize their secret fields when dropped. The UniFFI layer wipes the Rust copies of `phrase`, `passphrase`, and `wif` arguments and of record arguments, and the TUI wipes its Key Source and input buffers when they are cleared or the session ends. This reduces how many copies exist and how long they live; it is not a guarantee. The SDK cannot wipe Swift, Kotlin, or JavaScript strings, UniFFI's serialized argument and return buffers, values it returns to the caller (seed hex, WIF, xpriv text, mnemonic text), copies made by serialization, cloning, moves, or reallocation, or state inside its cryptographic dependencies. One-shot CLI commands do not wipe their arguments, and CLI display redaction is unrelated to memory erasure.

Debug formatting of every secret-bearing record (`GeneratedMnemonic`, `Xpriv`, `AccountKeySet`, `UtxoSigner`, `ChangeDestination`, `SpendableUtxo`, `ComposeTransactionRequest`) prints `[redacted]` in place of seed phrases, extended private keys, and WIFs. This covers Rust `Debug`, Kotlin `toString()` and string templates, and Swift `String(describing:)`, string interpolation, `print`, and `String(reflecting:)`; the Kotlin and Swift text is produced by the Rust library. Redaction stops there. Serialization (serde/JSON), direct field access, Swift `dump()` and `Mirror`, debugger variable views, Kotlin reflection and serializers, and the plain JavaScript objects returned by the Expo bridge all carry the real values, and secrets passed or returned as bare strings (phrase and WIF arguments, exported WIFs, seed hex) are never wrapped. Do not log secret-bearing records or requests.

## Storage Boundaries

The Rust core does not provide durable secret storage. Platform packages provide storage adapters:

- Swift stores mnemonic text in Keychain using `WhenUnlockedThisDeviceOnly`. Biometric protection requests the current biometric set; device-credential protection uses `userPresence`. The adapter reports `os-backed`, not a Secure Enclave guarantee.
- Kotlin encrypts mnemonic text with AES-GCM and a key in Android Keystore. Apps use `AndroidKeystoreWalletSecretStore.persistent(context)`, which writes the ciphertext and IV to app-private, no-backup storage (`Context.noBackupFilesDir`) so Stored Wallet Handles survive process death. Keystore keys never leave the device, so records are intentionally excluded from Auto Backup. `inMemory()` is for tests and demos and does not survive process death.
- Android requests StrongBox on API 28+ and falls back to standard Keystore. `hardware-backed` reports successful StrongBox key creation; `os-backed` is the fallback label, not proof that a device has no other hardware-backed Keystore.
- Android protection modes use distinct Keystore key policies. `biometric` and `device-credential` keys require authentication for every use. `biometric` accepts strong (Class 3) biometrics only, and its key is permanently invalidated when biometric enrollment changes. `device-credential` accepts a strong biometric or the device PIN, pattern, or password and requires Android 11 (API 30) or newer; on older versions the store rejects the mode instead of weakening it. `no-prompt` keys need no authentication.
- Prompted Android modes need a `WalletAuthenticator`. The Kotlin library ships `BiometricPromptWalletAuthenticator`, which binds the AES-GCM cipher to an AndroidX `BiometricPrompt` through a `CryptoObject`; the Expo Android module passes one that uses the current activity. Without an authenticator the store rejects prompted modes before it creates a key. A Keystore AES key that requires authentication needs it for encryption as well as decryption, so Android prompts when a protected wallet is stored and again on every export; iOS prompts only on export.
- Android persists the mode chosen at storage time with the record. The record only selects which prompt to show; the Keystore key enforces the policy. On export the stored mode governs: asking for `no-prompt` still authenticates with the stored mode, and asking for a prompted mode that differs from the stored one is rejected. iOS leaves the decision to the Keychain access control and does not reject a mismatched request.
- The Android authentication flow is unit-tested on the JVM against a software key vault and a fake authenticator. Keystore policy enforcement and the `BiometricPrompt` UI are not exercised by the workspace suite; verify them on devices before relying on them.
- Expo calls these adapters directly in its native modules. The Android module uses the persistent store. The native modules accept only the exact strings `no-prompt`, `device-credential`, and `biometric` for `protection`; anything else rejects the call instead of falling back to `no-prompt`. `network` and `language` strings are validated the same way.

The adapters store the mnemonic only, not its optional BIP39 passphrase. Applications must retain the handle and arrange recovery of both mnemonic and passphrase. Passing a different protection mode to export never rewrites the access controls selected at storage time: Android rejects a mismatched prompted mode, and iOS applies the stored access control whatever the request says.

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
