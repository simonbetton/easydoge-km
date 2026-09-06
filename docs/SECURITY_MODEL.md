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

## Core Guarantees

- The Rust core is the canonical implementation.
- Generated bindings expose the same public behavior across Swift, Kotlin, and Expo.
- CLI output redacts secret material by default.
- Xpub derivation rejects hardened child paths.
- Dogecoin-native extended-key prefixes are emitted by default.
- BIP39 seed phrases and BIP39 seeds cannot be recovered from xprivs.
- Signing rejects undefined sighash types and the SIGHASH_SINGLE output-index bug.
- Signing envelopes are authenticated: input descriptors must match the unsigned transaction and each other, and every signature is verified before it is combined or finalized.

## Storage Boundaries

The Rust core does not provide durable secret storage. Platform packages provide storage adapters:

- Swift uses Keychain-backed storage.
- Kotlin uses Android Keystore-backed encryption.
- Expo uses native module surfaces and should use the platform storage adapters in custom dev-client or EAS builds.

Applications remain responsible for backup UX, user authentication policy, device compromise assumptions, and recovery flows.

## Operational Requirements

- Never log seed phrases, xprivs, WIFs, or raw private keys.
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
