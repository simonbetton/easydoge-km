# ADR 0004: BitcoinJS Cross-Check Harness

## Status

Accepted

## Context

Rust core, UniFFI, Swift, and Kotlin tests read shared parity vectors; CLI/TUI tests reuse selected fixture values. Those runtime tests ultimately exercise the same Rust implementation. Expo is typechecked but has no native runtime parity suite. Key-derivation regressions can still pass if the canonical implementation and fixtures drift together.

Dogecoin BIP39/BIP32/BIP44 behavior also depends on network constants that are easy to accidentally default to Bitcoin values, especially extended-key version bytes.

## Decision

Add a cross-check harness that feeds input-only cases into two independent engines:

- the Rust SDK through `crates/easydoge-km/examples/cross_check_vectors.rs`
- a pnpm-managed bitcoinjs ecosystem runner under `tools/bitcoinjs-cross-check`

The harness compares canonical JSON outputs for BIP39 seed derivation, Dogecoin BIP44 account and child keys, P2PKH addresses, WIF export/import, hardened xpub derivation rejection, Dogecoin message signing, legacy P2PKH transaction signing, and P2SH multisig descriptors. The Node runner defines Dogecoin `pubKeyHash`, `scriptHash`, `wif`, `bip32.public`, and `bip32.private` parameters explicitly.

`test-vectors/cross-check.json` describes inputs only. Expected outputs are not committed; both engines compute them fresh during verification.

## Consequences

Verification now depends on pnpm and a committed `pnpm-lock.yaml` for the bitcoinjs runner. This adds a second toolchain to the core key-derivation checks, but it makes accidental Rust-only drift much easier to catch.

Dogecoin message signing requires a small independent message-hash implementation in the Node runner because bitcoinjs does not provide it out of the box. Transaction signing and multisig use bitcoinjs primitives with Dogecoin network parameters supplied explicitly.
