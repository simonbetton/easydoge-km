# API Guide

EasyDoge KM has one source of truth: the Rust core crate. Rust backend services call `easydoge-km` directly. Swift, Kotlin, and Expo call the Rust-backed UniFFI surface. The CLI and TUI call the Rust core directly.

## Supported Networks

- `mainnet`
- `testnet`
- `regtest`

Extended keys are emitted using the selected Dogecoin network's version bytes: `dgpv`/`dgub` on mainnet and `tprv`/`tpub` on testnet and regtest. The normal `Xpriv`/`Xpub` APIs also accept legacy Bitcoin-style prefixes and interpret them using the record's `network` field; there is no separate compatibility-import API. The CLI defaults to mainnet, so specify `--network` when importing keys for another network. The TUI uses prefix-based classification described in [CLI.md](CLI.md#networks).

## Key and Seed APIs

| Capability | Rust | Swift | Kotlin | Expo | CLI |
| --- | --- | --- | --- | --- | --- |
| Generate BIP39 mnemonic | yes | yes | yes | yes | yes |
| Validate BIP39 mnemonic | yes | yes | yes | yes | yes |
| Derive BIP39 seed hex | yes | yes | yes | yes | yes |
| Derive account xpriv/xpub | yes | yes | yes | yes | yes |
| Inspect xpriv/xpub metadata | yes | yes | yes | yes | yes |
| Derive child xpriv | yes | yes | yes | yes | yes |
| Derive child xpub | yes | yes | yes | yes | no |
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

Swift and Kotlin expose typed UniFFI records directly through their native packages. Expo maps records to camelCase JavaScript objects. Koinu amounts (`valueKoinu`, `previousOutputValueKoinu`, `feeRateKoinuPerKb`, `dustThresholdKoinu`, and the compose result totals) are canonical decimal strings because JavaScript numbers cannot represent every `u64`; use `koinuFromBigInt` / `koinuToBigInt` from the package for arithmetic. Other numeric inputs must be non-negative safe integers within the native range; the wire codecs reject out-of-range or non-integer values with `Invalid <field>: …`. Signing envelope input kinds are `"p2pkh"` and `"p2sh-multisig"`.

The non-negative rule applies to Expo inputs, including transaction `version` (0 through 2147483647); Rust/UniFFI use a signed `i32` for that field. These conversion rules are unit-tested in the native wrapper packages, but the Expo bridge itself is not exercised by workspace tests. TypeScript unions do not provide runtime validation: unrecognized native `network`, `language`, and `protection` strings currently fall back to mainnet, English, and no prompt respectively. Validate values from untyped sources before calling the bridge.

There is also a known Android output mismatch: `inspectXpriv`/`inspectXpub` convert unsigned `childNumber` to a signed Kotlin `Int`. Hardened indices can therefore appear negative in Expo (for example, 2147483648 becomes -2147483648). The Swift bridge preserves the unsigned value. The table indicates which operations are exposed, not complete wire-level parity.

## Seed and Storage Limitations

Mnemonic text and passphrases are NFKD-normalized before PBKDF2, as BIP39 requires, so canonically equivalent Unicode input derives the same wallet across every surface and matches other BIP39 implementations. Wallets derived before this normalization from a passphrase containing non-NFKD characters will not match; recover those with a pre-change build. ASCII and empty passphrases are unaffected.

Swift and Kotlin additionally expose `WalletSecretStore`; Expo exposes `storeMnemonic`, `exportMnemonic`, and `protectionLevel`. These store mnemonic text, not the optional BIP39 passphrase. Kotlin apps persist the encrypted record with `AndroidKeystoreWalletSecretStore.persistent(context)` in app-private no-backup storage, so handles survive process death. `inMemory()` is for tests and demos and does not. See [SECURITY_MODEL.md](SECURITY_MODEL.md#storage-boundaries) for authentication limits.

## Compose-and-Sign Transaction Builder

`compose_and_sign_transaction` builds and funds Dogecoin legacy transactions entirely inside the Rust core, then signs every selected input for which valid signer material is supplied. Callers provide known UTXOs; the SDK does not fetch UTXOs, fetch live fees, broadcast transactions, or validate chain state.

The request includes:

- `utxos`: display/RPC `txid` hex, `vout`, `previous_output_value_koinu`, `script_pubkey_hex`, spend kind, signer metadata, and P2SH multisig descriptor metadata when needed.
- `outputs`: address outputs, zero-value OP_RETURN data outputs, or `ExpertRawScript` outputs.
- `fee_policy`: `fee_rate_koinu_per_kb` and `dust_threshold_koinu`.
- `coin_selection`: `MinInputs`, `SmallestFirst`, `LargestFirst`, or `ManualSelectedInputs`.
- `change`: an address or xpriv derivation source for non-dust change.
- `options`: version, lock time, sequence, and sighash type. Size estimates use serialized bytes, not vbytes or weight. The SDK accepts six sighash values: `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE) and their `0x80` ANYONECANPAY variants; other values are rejected. `SIGHASH_SINGLE` is rejected for any input index that has no output at the same index.

The result reports selected and skipped inputs, input total, spend output total, change amount/address/script, fee, estimated serialized size, actual serialized size when signed, whether dust change was folded into the fee, unsigned tx hex, signed tx hex when complete, and a signing envelope when P2PKH or multisig signatures are missing. These totals use caller-provided UTXO values; they are not an independent audit of chain data.

Signer ownership is checked before signing. P2PKH signers must match the previous output script pubkey. P2SH multisig UTXOs must have a script pubkey matching the redeem script, and signatures only count when the public key is part of the expected multisig set.

CLI example:

```sh
easydoge-km --json tx compose --request-file compose-request.json
```

Example `compose-request.json` (Rust/CLI snake_case fields and numeric koinu, not the Expo wire format). The WIF placeholder must be replaced with a disposable test key matching the input script before this can sign; the txid is synthetic and the fee/dust values are examples, not network policy:

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

## Signing Envelopes

A Signing Envelope describes the inputs a signer knows about; each input
index may appear once and must exist in the unsigned transaction. P2PKH
inputs carry a pay-to-pubkey-hash script pubkey; P2SH multisig inputs carry a
redeem script whose hash matches the script pubkey. `sign_signing_envelope`
signs only inputs the supplied WIF controls and errors when it controls
none. Signing and combining verify signatures for described inputs (DER
encoding, sighash flag, key ownership, and ECDSA validity against the legacy
sighash). A partial envelope may carry signatures for other in-range inputs
without verifying them because their scripts are unavailable. Finalization
requires every transaction input to be described and verifies every signature.
Combining requires identical version, network, unsigned transaction hex, and
input descriptors; it merges signatures, not differing descriptor sets.

The validator checks internal consistency, not whether previous-output scripts
or amounts match the blockchain. Callers must authenticate that UTXO data.
The single-input `sign_p2pkh_transaction` API fills only the selected input's
scriptSig; other inputs may still need signatures.

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

`test-vectors/parity.json` is read by Rust core, UniFFI, Swift, and Kotlin tests. CLI/TUI tests reuse selected fixture values in source. Expo has a TypeScript check, not a runtime parity test suite.

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

The current cross-check fixture uses ASCII/empty passphrases. Passing it does not establish Unicode passphrase normalization, complete API coverage, or native Expo/storage behavior.

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
