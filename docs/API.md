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

The non-negative rule applies to Expo inputs, including transaction `version` (0 through 2147483647); Rust/UniFFI use a signed `i32` for that field. These conversion rules are unit-tested in the native wrapper packages, but the Expo bridge itself is not exercised by workspace tests. The native modules validate `network`, `language`, and `protection` strings at runtime: only the exact lowercase names in the TypeScript unions are accepted. An unrecognized string (including a different letter case), or a missing `network` inside an `Xpriv`, `Xpub`, signing envelope, or compose request, rejects the promise with `Invalid <field>: expected one of …` instead of falling back to a default; non-string values are rejected as well. The message lists the allowed names and never repeats the rejected value. `language` may be omitted only where the TypeScript signature marks it optional (`generateMnemonic` options, `validateMnemonic`, `mnemonicToSeedHex`); omission selects English.

`inspectXpriv`/`inspectXpub` return `childNumber` as the unsigned BIP32 index on both platforms, so a hardened child is 2147483648 or greater (account `0'` is 2147483648). The table indicates which operations are exposed, not complete wire-level parity.

## Secret Redaction in Debug Output

Seven records can carry a seed phrase, extended private key, or WIF: `GeneratedMnemonic`, `Xpriv`, `AccountKeySet`, `UtxoSigner`, `ChangeDestination`, `SpendableUtxo`, and `ComposeTransactionRequest`. Their debug representations print `[redacted]` in place of the secret:

| Surface | Redacted | Not redacted |
| --- | --- | --- |
| Rust | `{:?}` and `{:#?}` | serde serialization, field access |
| Swift | `String(describing:)`, `"\(value)"`, `print`, `String(reflecting:)`, `debugPrint` | `dump`, `Mirror`, field access, debugger variable views |
| Kotlin | `toString()`, string templates, `println` | field access, `componentN()`, reflection, serializers |
| Expo | nothing: records are plain JavaScript objects | `console.log`, `JSON.stringify` |

Swift and Kotlin obtain the text from the Rust library, so it uses Rust formatting on every platform, for example `Xpriv { network: Mainnet, encoded: "[redacted]" }`, and requires the native library to be loaded. Secrets passed or returned as bare strings (phrase and WIF arguments, `wif_from_xpriv`, `mnemonic_to_seed_hex`) are ordinary strings. Redaction is a safety net, not permission to log these values; see [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Secret Memory Hygiene

The Rust core wipes the secret memory it owns on a best-effort basis; [ADR 0008](adr/0008-secret-memory-hygiene.md) records the ownership model.

- Wiped by the SDK: internal working copies (normalized seed phrases and passphrases, BIP39 seeds, decoded extended-key and WIF payloads, private keys, chain codes), and the secret fields of `Xpriv`, `GeneratedMnemonic`, and `UtxoSigner` when those records are dropped. Records that contain them (`AccountKeySet`, `ChangeDestination`, `SpendableUtxo`, `ComposeTransactionRequest`) are covered through their fields. The UniFFI layer wipes the Rust copies of `phrase`, `passphrase`, and `wif` arguments and of record arguments once the call returns.
- Not wiped by the SDK: Swift, Kotlin, and JavaScript strings and objects; UniFFI's serialized argument and return buffers; values returned to the caller (seed hex, WIF, xpriv and mnemonic text); copies made by `Clone`, serde, moves, or reallocation; one-shot CLI arguments.

Rust callers:

- `Xpriv`, `GeneratedMnemonic`, and `UtxoSigner` implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`. Call `.zeroize()` to wipe one before it is dropped.
- Because these records implement `Drop`, a field cannot be moved out of them, they cannot be destructured by value, and they cannot be the base of struct-update syntax. Take the field, clone it, or borrow it. Moving the whole record is unaffected.
- Functions that return a bare secret string (`wif_from_xpriv`, `mnemonic_to_seed_hex`) hand ownership to the caller. Wrap the result in `zeroize::Zeroizing` if it should be wiped when dropped.

```rust
let mut account = easydoge_km::account_xpriv_from_mnemonic(phrase, None, language, network, 0)?;
// A returned secret string belongs to the caller; wrap it to wipe it on drop.
let wif = zeroize::Zeroizing::new(easydoge_km::wif_from_xpriv(&account.xpriv)?);
// `let encoded = account.xpriv.encoded;` no longer compiles; take the field instead.
let encoded = zeroize::Zeroizing::new(std::mem::take(&mut account.xpriv.encoded));
```

Swift, Kotlin, and Expo callers: the API is unchanged. Strings in those runtimes are immutable and managed by the runtime, so the SDK cannot wipe them; keep secrets in as few variables as possible and let them go out of scope promptly.

## Seed and Storage Limitations

Mnemonic text and passphrases are NFKD-normalized before PBKDF2, as BIP39 requires, so canonically equivalent Unicode input derives the same wallet across every surface and matches other BIP39 implementations. Wallets derived before this normalization from a passphrase containing non-NFKD characters will not match; recover those with a pre-change build. ASCII and empty passphrases are unaffected.

Swift and Kotlin additionally expose `WalletSecretStore`; Expo exposes `storeMnemonic`, `exportMnemonic`, and `protectionLevel`. These store mnemonic text, not the optional BIP39 passphrase. Kotlin apps persist the encrypted record with `AndroidKeystoreWalletSecretStore.persistent(context)` in app-private no-backup storage, so handles survive process death. `inMemory()` is for tests and demos and does not. On Android the `device-credential` and `biometric` modes need a `WalletAuthenticator`: pass `BiometricPromptWalletAuthenticator { activity }` to `AndroidKeystoreWalletSecretStore.persistent(context, authenticator)` (the Expo Android module does this with the current activity). Android prompts both when a protected wallet is stored and when it is exported, `device-credential` requires Android 11 (API 30) or newer, and `exportMnemonic` rejects a prompted mode that differs from the one used at storage time. See [SECURITY_MODEL.md](SECURITY_MODEL.md#storage-boundaries) for authentication limits.

## WIF Keys and Public Key Compression

A WIF records which public key form its address uses. A compressed WIF (payload ends in `0x01`) owns the address of the 33-byte public key. An uncompressed WIF (no suffix; Dogecoin mainnet strings start with `6`, typical of older paper wallets) owns the address of the 65-byte public key. The two addresses differ, and an output locked to one cannot be spent with the other form.

- `address_from_wif` reports the WIF's own form: `compressed`, `public_key_hex` (66 hex characters starting `02`/`03`, or 130 starting `04`), and the matching `address`.
- `wif_from_xpriv` always exports compressed WIFs because BIP32-derived keys are compressed.
- `sign_message` signs for the address of the WIF's own form. The signature header byte is 31–34 for compressed keys and 27–30 for uncompressed keys. `verify_message` accepts headers 27–34 only, reads the key form from the header, and compares against the address of that form; any other header fails with `invalid recovery header`.
- P2PKH signing (`sign_p2pkh_transaction`, Signing Envelopes, and the Compose-and-Sign Transaction Builder) treats a WIF as controlling only the script pubkey that commits to the hash of its own public key form, and reveals that form in the scriptSig.
- P2SH multisig uses compressed keys only. Signing a multisig input with an uncompressed WIF fails with `uncompressed WIF keys cannot sign P2SH multisig inputs`.

## Compose-and-Sign Transaction Builder

`compose_and_sign_transaction` builds and funds Dogecoin legacy transactions entirely inside the Rust core, then signs every selected input for which valid signer material is supplied. Callers provide known UTXOs; the SDK does not fetch UTXOs, fetch live fees, broadcast transactions, or validate chain state.

The request includes:

- `utxos`: display/RPC `txid` hex, `vout`, `previous_output_value_koinu`, `script_pubkey_hex`, spend kind, and signer metadata. P2SH multisig UTXOs also require `redeem_script_hex`; `multisig_threshold` and `multisig_public_keys_hex` are optional.
- `outputs`: address outputs, zero-value OP_RETURN data outputs, or `ExpertRawScript` outputs.
- `fee_policy`: `fee_rate_koinu_per_kb` and `dust_threshold_koinu`.
- `coin_selection`: the Coin Selection strategy. Every strategy puts the candidate UTXOs in a fixed order (ties broken by `txid` text, then `vout`), adds them one at a time, and stops at the first selection that funds the transaction:
  - `MinInputs`: highest value net of the fee for spending that input first (`previous_output_value_koinu` minus the input's estimated size at `fee_rate_koinu_per_kb`). This funds the transaction with the fewest inputs the supplied UTXOs allow.
  - `LargestFirst`: highest `previous_output_value_koinu` first, ignoring what each input costs to spend.
  - `SmallestFirst`: lowest `previous_output_value_koinu` first.
  - `ManualSelectedInputs`: only UTXOs with `manually_selected: true` are candidates, lowest `previous_output_value_koinu` first; selection still stops as soon as the transaction is funded, so not every manually selected UTXO is necessarily spent.
- `change`: an address or xpriv derivation source for the change output. It is required when the amount left after the spend outputs and the fee is non-zero and at least `dust_threshold_koinu`.
- `options`: version, lock time, sequence, and sighash type. Size estimates use serialized bytes, not vbytes or weight. The SDK accepts six sighash values: `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE) and their `0x80` ANYONECANPAY variants; other values are rejected. `SIGHASH_SINGLE` is rejected for any input index that has no output at the same index.

Each UTXO outpoint (`txid:vout`) may be listed once per request. A request that repeats an outpoint is rejected with `duplicate UTXO outpoint <txid>:<vout>` before Coin Selection runs, even when the repeated entry would not have been selected or is not manually selected. Txid hex is compared case-insensitively.

The result reports selected and skipped inputs, input total, spend output total, change amount/address/script, fee, estimated serialized size, actual serialized size when signed, whether dust change was folded into the fee, unsigned tx hex, signed tx hex when complete, and a signing envelope when P2PKH or multisig signatures are missing. These totals use caller-provided UTXO values; they are not an independent audit of chain data.

A selection funds the transaction when its input total covers the spend outputs plus the fee for the transaction without a change output. What is left over becomes a change output only if, after also paying the fee for that extra output, the change is non-zero and at least `dust_threshold_koinu`. Otherwise no change output is created, the whole leftover is added to the fee, and `dust_change_folded_into_fee` is `true` when that leftover is non-zero. The builder never adds another input just to afford a change output, so the fee can exceed the rate-based fee by at most the fee for one change output plus the dust threshold.

Each UTXO the builder selects is validated before it contributes to the size estimate, and signer ownership is checked before signing. P2PKH UTXOs must carry a canonical 25-byte pay-to-pubkey-hash script pubkey, and P2PKH signers must match it in their own public key form (the WIF's form for WIF signers, compressed for xpriv derivations). P2SH multisig UTXOs must carry a redeem script of the form `m <33-byte public keys> n OP_CHECKMULTISIG` that hashes to the script pubkey. The threshold used for fee sizing, and the threshold and public keys written to a returned signing envelope (in redeem-script order), are read from that redeem script. `multisig_threshold` and `multisig_public_keys_hex` are optional cross-checks: when supplied they must agree with the redeem script, otherwise composing fails with `multisig threshold metadata does not match redeem script` or `multisig public key metadata does not match redeem script`. Signatures only count when the public key is part of the redeem script.

For each P2PKH input the size estimate assumes a 33-byte compressed public key, or a 65-byte key when that UTXO carries an uncompressed WIF signer. A P2PKH UTXO supplied without signers is sized as compressed; if an uncompressed key later signs the returned envelope, the final transaction is 32 bytes larger per such input than `estimated_size_bytes` and pays a correspondingly lower fee rate.

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

Signature records carry the signing public key in `public_key_hex`: a 33-byte
compressed key for any input, or a 65-byte uncompressed key (prefix `04`) for
P2PKH inputs only. Hybrid encodings (prefix `06`/`07`) and other lengths are
rejected with `unsupported public key encoding`.

For P2SH multisig inputs the redeem script must be at most 520 bytes, the
largest element a scriptSig may push; a larger script can never be spent and
is rejected with `redeem script exceeds 520 bytes and cannot be spent`. When
`multisig_public_keys_hex` is supplied it must list exactly the redeem
script's public keys: the same keys, each the same number of times, in any
order and either hex case. Finalization counts one signature per distinct
public key towards the threshold.

The validator checks internal consistency, not whether previous-output scripts
or amounts match the blockchain. Callers must authenticate that UTXO data.
The single-input `sign_p2pkh_transaction` API fills only the selected input's
scriptSig; other inputs may still need signatures.

## Multisig Descriptors

`create_multisig_descriptor` derives one child public key per cosigner xpub at
the shared non-hardened `child_path` and returns the threshold, the public keys
in redeem-script order (lexicographically sorted when `sorted` is true), the
redeem script, and its P2SH address. It rejects a request when:

- A cosigner appears more than once. Distinctness is checked on the derived
  public keys, so the same xpub supplied twice, or once with a Dogecoin prefix
  and once with a legacy Bitcoin prefix, is a duplicate. A repeated key lets
  one cosigner provide more than one of the required signatures, so the
  threshold would overstate the number of independent signers.
- There are more than 15 cosigners. A P2SH spend reveals the redeem script as
  one pushed element, which consensus limits to 520 bytes. With compressed
  keys 15 cosigners need 513 bytes and 16 would need 547, so a 16-cosigner
  address could receive funds that can never be spent.
- The threshold is zero or exceeds the cosigner count, or an xpub belongs to a
  different network.

Signing, combining, and finalizing still accept a redeem script created
elsewhere that repeats a public key, so funds already held by such a script
stay spendable when enough distinct cosigners sign. If the distinct keys
cannot reach the threshold (for example a 2-of-2 over one key), the SDK cannot
finalize that input.

## Limits

The Rust core bounds the size of everything it accepts at a public boundary,
so Swift, Kotlin, Expo, the CLI, and direct Rust callers inherit the same
limits. Each limit is checked before any parsing, hashing, key derivation, or
signature verification, and input over a limit fails with an error that ends
in `which exceeds the limit of <limit>`. Rust callers can read the numbers
from `easydoge_km::limits`; they are not exported through UniFFI.

| Limit | Value | Applies to | Basis |
| --- | --- | --- | --- |
| `MAX_TRANSACTION_BYTES` | 99,999 bytes | The unsigned transaction of a Signing Envelope or of `sign_p2pkh_transaction` (checked from the hex length before decoding), and the builder's estimated size of the funded transaction | Dogecoin Core 1.14 relays only transactions smaller than 100,000 bytes |
| `MAX_SCRIPT_BYTES` | 10,000 bytes | `script_pubkey_hex` and `redeem_script_hex` on UTXOs and envelope inputs; `script_hex` on `ExpertRawScript` outputs | Consensus maximum script size |
| `MAX_REQUEST_UTXOS` | 10,000 | `utxos` in a compose request | SDK policy |
| `MAX_REQUEST_OUTPUTS` | 3,200 | `outputs` in a compose request | SDK policy |
| `MAX_SIGNERS_PER_UTXO` | 16 | `signers` on one UTXO | SDK policy |
| `MAX_ENVELOPE_SIGNATURES_PER_INPUT` | 16 × transaction inputs | `signatures` in a Signing Envelope, counted across the whole envelope | SDK policy |
| `MAX_ENVELOPES_PER_COMBINE` | 64 | Envelopes passed to one `combine_signing_envelopes` call | SDK policy |
| `MAX_BASE58CHECK_CHARS` | 112 characters | Every address, WIF, and extended key | Longest extended-key encoding |

Consequences for callers:

- A wallet with more than 10,000 candidate UTXOs must pre-filter before calling the builder, for example by passing its largest UTXOs. A standard transaction spends fewer than 700 P2PKH inputs, so the extra candidates could not all be used anyway.
- The builder refuses to fund a payment whose estimated size exceeds 99,999 bytes instead of returning a transaction that nodes will not relay. The estimate assumes maximum-size signatures, so it is slightly conservative. This applies to every Coin Selection strategy, including `ManualSelectedInputs`: split a large consolidation into transactions of at most about 670 P2PKH inputs each.
- To merge more than 64 envelopes, combine them in batches and then combine the results.
- `validate_address` reports over-long text as not an address; it does not return an error.

Derivation paths need no SDK limit: BIP32 stores the depth in one byte, and deriving past depth 255 fails with `cannot derive child of depth 256 or higher`. Message signing and mnemonic handling do work proportional to the input length and are not limited. P2SH multisig descriptors have their own structural limits, enforced where a descriptor is built or parsed. The CLI additionally refuses request and envelope files larger than 16 MiB; see [CLI.md](CLI.md#compose-and-sign-a-transaction).

The limits bound the work one call can be made to do. They are not rate limiting, a Signing Envelope at the limits can still take seconds to verify, and they do not make a transaction valid or standard in every other respect.

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

`test-vectors/cross-check.json` is an input-only fixture for independent implementation checks. The Rust example emitter and the bitcoinjs runner both read the same mnemonic, network, account, child-path, signing, transaction, multisig, and raw-key WIF cases, compute Dogecoin outputs independently, and compare canonical JSON output. The harness covers:

- BIP39 seed derivation
- Dogecoin BIP44 account xpriv/xpub derivation
- Non-hardened child xpriv/xpub derivation
- P2PKH address derivation from private and public child keys
- WIF export/import round trips
- Hardened xpub derivation rejection
- Dogecoin message signing and verification
- Legacy P2PKH transaction signing
- P2SH multisig redeem scripts and addresses
- Compressed and uncompressed WIF import, message signing, and P2PKH signing from raw private keys

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

Derive an account key set. Secrets are read from a file or standard input so they stay out of shell history and process listings; the values below are the public test vector (see [CLI.md](CLI.md#supplying-secrets) for real secrets):

```sh
printf '%s' "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" > phrase.txt
printf '%s' "TREZOR" | easydoge-km xpriv from-mnemonic \
  --phrase-file phrase.txt \
  --passphrase-file - \
  --network mainnet \
  --account 0 \
  --reveal
rm phrase.txt
```

Launch the TUI:

```sh
easydoge-km tui
```

See [CLI.md](CLI.md) for TUI behavior (sample vs generated mnemonic, keybindings, and derivation source).
