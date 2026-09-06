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
| Inspect address network/kind | yes | no | no | no | TUI |
| Sign and verify messages | yes | yes | yes | yes | yes |
| Sign P2PKH transactions | yes | yes | yes | yes | yes |
| Signing envelopes | yes | yes | yes | yes | yes |
| Multisig descriptors | yes | yes | yes | yes | yes |
| Compose-and-sign transaction builder | yes | yes | yes | yes | yes |

Swift and Kotlin expose typed UniFFI records directly through their native packages. Expo exposes the same data in camelCase JavaScript objects; signing envelope input kinds are `"p2pkh"` and `"p2sh-multisig"`.

## Compose-and-Sign Transaction Builder

`compose_and_sign_transaction` builds and funds Dogecoin legacy transactions entirely inside the Rust core, then signs every selected input for which valid signer material is supplied. Callers provide known UTXOs; the SDK does not fetch UTXOs, fetch live fees, broadcast transactions, or validate chain state.

The request includes:

- `utxos`: display/RPC `txid` hex, `vout`, `previous_output_value_koinu`, `script_pubkey_hex`, spend kind, signer metadata, and P2SH multisig descriptor metadata when needed.
- `outputs`: address outputs, zero-value OP_RETURN data outputs, or `ExpertRawScript` outputs.
- `fee_policy`: `fee_rate_koinu_per_kb` and `dust_threshold_koinu`.
- `coin_selection`: `MinInputs`, `SmallestFirst`, `LargestFirst`, or `ManualSelectedInputs`.
- `change`: an address or xpriv derivation source for non-dust change.
- `options`: version, lock time, sequence, and sighash type. Size estimates use serialized bytes, not vbytes or weight. Only the consensus-defined sighash types are accepted: `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE) and their `0x80` ANYONECANPAY variants; an unsupported sighash type is rejected with an error. `SIGHASH_SINGLE` is rejected for any input index that has no output at the same index.

The result is audit-oriented: selected and skipped inputs, input total, spend output total, change amount/address/script, fee, estimated serialized size, actual serialized size when signed, whether dust change was folded into the fee, unsigned tx hex, signed tx hex when complete, and a signing envelope when more signatures are required.

Signer ownership is checked before signing. P2PKH signers must match the previous output script pubkey. P2SH multisig UTXOs must have a script pubkey matching the redeem script, and signatures only count when the public key is part of the expected multisig set.

CLI example:

```sh
easydoge-km --json tx compose --request-file compose-request.json
```

Example `compose-request.json`:

```json
{
  "network": "mainnet",
  "utxos": [
    {
      "txid": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "vout": 0,
      "previous_output_value_koinu": 100000000,
      "script_pubkey_hex": "76a9146dcc18cfcc4715927568546321b78541c8a83e7388ac",
      "kind": "p2pkh",
      "redeem_script_hex": null,
      "multisig_threshold": null,
      "multisig_public_keys_hex": [],
      "signers": [
        {
          "kind": "wif",
          "wif": "<redacted-wif>",
          "xpriv": null,
          "derivation_path": null
        }
      ],
      "manually_selected": false
    }
  ],
  "outputs": [
    {
      "kind": "address",
      "value_koinu": 50000000,
      "address": "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM",
      "op_return_data_hex": null,
      "script_hex": null
    },
    {
      "kind": "op-return",
      "value_koinu": 0,
      "address": null,
      "op_return_data_hex": "65617379646f6765",
      "script_hex": null
    }
  ],
  "fee_policy": {
    "fee_rate_koinu_per_kb": 1000,
    "dust_threshold_koinu": 1
  },
  "coin_selection": "min-inputs",
  "change": {
    "address": "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM",
    "xpriv": null,
    "derivation_path": null
  },
  "options": {
    "version": 1,
    "lock_time": 0,
    "sequence": 4294967295,
    "sighash_type": 1
  }
}
```

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
easydoge-km mnemonic generate
```

Reveal a generated mnemonic explicitly:

```sh
easydoge-km mnemonic generate --reveal
```

Derive an account key set:

```sh
easydoge-km xpriv from-mnemonic \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

Launch the TUI:

```sh
easydoge-km tui
```

See [CLI.md](CLI.md) for TUI behavior (sample vs generated mnemonic, keybindings, and derivation source).
