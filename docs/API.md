# API Guide

EasyDoge KM has one source of truth: the Rust core crate. Rust backend services call `easydoge-km` directly. Swift, Kotlin, and Expo call the Rust-backed UniFFI surface. The CLI and TUI call the Rust core directly.

## Supported Networks

- `mainnet`
- `testnet`
- `regtest`

Dogecoin-native xpriv/xpub version bytes are emitted by default. Legacy Bitcoin-style extended keys can be imported only when the caller supplies the Dogecoin network explicitly.

## Key and Seed APIs

| Capability | Rust | Swift | Kotlin | Expo | CLI |
| --- | --- | --- | --- | --- | --- |
| Generate BIP39 mnemonic | yes | yes | yes | yes | yes |
| Validate BIP39 mnemonic | yes | yes | yes | yes | yes |
| Derive BIP39 seed hex | yes | yes | yes | yes | yes |
| Derive account xpriv/xpub | yes | yes | yes | yes | yes |
| Inspect xpriv/xpub metadata | yes | yes | yes | yes | yes |
| Derive child xpriv | yes | yes | yes | yes | yes |
| Derive child xpub | yes | yes | yes | yes | yes |
| Convert xpriv to xpub | yes | yes | yes | yes | yes |
| Derive address from xpriv | yes | yes | yes | yes | yes |
| Derive address from xpub | yes | yes | yes | yes | yes |
| Export WIF from xpriv | yes | yes | yes | yes | yes |
| Import WIF and derive address | yes | yes | yes | yes | yes |
| Validate address | yes | yes | yes | yes | yes |
| Sign and verify messages | yes | yes | yes | yes | yes |
| Sign P2PKH transactions | yes | yes | yes | yes | yes |
| Signing envelopes | yes | yes | yes | yes | yes |
| Multisig descriptors | yes | yes | yes | yes | yes |

Swift and Kotlin expose typed UniFFI records directly through their native packages. Expo exposes the same data in camelCase JavaScript objects; signing envelope input kinds are `"p2pkh"` and `"p2sh-multisig"`.

## Derivation Paths

Account derivation follows Dogecoin BIP44:

```text
m/44'/3'/account'
```

Receive and change derivation from an account key uses relative non-hardened paths:

```text
m/0/0
m/0/1
m/1/0
```

Public derivation rejects hardened path components because hardened public derivation is not possible.

## Cross-Check Vectors

`test-vectors/parity.json` remains the public parity fixture consumed by Rust, Swift, Kotlin, Expo, and CLI tests.

`test-vectors/cross-check.json` is an input-only fixture for independent implementation checks. The Rust example emitter and the bitcoinjs runner both read the same mnemonic, network, account, child-path, signing, transaction, and multisig cases, compute Dogecoin outputs independently, and compare canonical JSON output. The harness covers:

- BIP39 seed derivation
- Dogecoin BIP44 account xpriv/xpub derivation
- Non-hardened child xpriv/xpub derivation
- P2PKH address derivation from private and public child keys
- WIF export/import round trips
- Hardened xpub derivation rejection
- Dogecoin message signing and verification
- Legacy P2PKH transaction signing
- P2SH multisig redeem scripts and addresses

Run it directly with:

```sh
bash scripts/cross-check.sh
```

## Non-Reversible Seed Boundary

The SDK can derive xprivs and xpubs from a BIP39 mnemonic and optional passphrase. It cannot recover the original BIP39 mnemonic or BIP39 seed from an xpriv. This is a cryptographic boundary, not a missing feature.

APIs that start from an xpriv can derive child private keys, xpubs, WIFs, addresses, and signatures.

## CLI Examples

Generate a mnemonic without printing the phrase:

```sh
cargo run -p easydoge-km-cli -- mnemonic generate
```

Reveal a generated mnemonic explicitly:

```sh
cargo run -p easydoge-km-cli -- mnemonic generate --reveal
```

Derive an account key set:

```sh
cargo run -p easydoge-km-cli -- xpriv from-mnemonic \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

Launch the TUI:

```sh
cargo run -p easydoge-km-cli -- tui
```

See [CLI.md](CLI.md) for TUI behavior (sample vs generated mnemonic, keybindings, and derivation source).
