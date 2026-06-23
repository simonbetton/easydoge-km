# CLI and TUI Guide

The `easydoge-km` binary in `crates/easydoge-km-cli` is an engineer-facing surface for exploring the Rust SDK from the terminal. It is not a production wallet and does not enforce a setup wizard or custodial storage.

Install from the workspace root:

```sh
cargo install --path crates/easydoge-km-cli --force
```

Then run commands directly:

```sh
easydoge-km <command>
```

Global flags:

- `--json` — print structured JSON output
- `--reveal` — show secrets (mnemonics, seeds, WIFs) that are redacted by default

Use `<command> --help` for subcommand flags. Derivation path conventions match [API.md](API.md).

## Scriptable CLI

Subcommands are independent. Nothing tracks session state between invocations, so there is no required order beyond what your workflow needs.

Typical flow:

1. `mnemonic generate` — create a BIP39 phrase
2. `xpriv from-mnemonic` — derive the account xpriv/xpub at `m/44'/3'/account'`
3. `address derive --xpub … --path m/0/0` — derive a watch-only receive address from the account xpub

`address derive` accepts `--xpub` or `--xpriv` plus a relative path (for example `m/0/0` for incoming, `m/1/0` for outgoing/change). It does not take a mnemonic directly.

Subcommands cover mnemonic handling, account and path derivation, WIF import/export, address validation, message signing, P2PKH transaction signing, compose-and-sign transaction building, multisig envelopes, and more. See `easydoge-km --help`.

### Compose and sign a transaction

`tx compose` reads a JSON request file and prints only the audited result. The request may contain WIFs or xprivs, so do not log request files or shell history that includes them.

```sh
easydoge-km --json tx compose --request-file compose-request.json
```

The request uses the same shape as the Rust `ComposeTransactionRequest`: UTXOs use display/RPC txid hex, values are integer koinu, fee policy is `fee_rate_koinu_per_kb` plus `dust_threshold_koinu`, and transaction sizes are serialized bytes. Outputs can be Dogecoin address outputs, zero-value OP_RETURN data outputs, or `ExpertRawScript` outputs.

The result includes selected inputs, skipped inputs, totals, fee, change details, estimated size, actual signed size when complete, unsigned tx hex, signed tx hex when all signatures are present, or a signing envelope when more multisig signatures are needed.

### Parity test vector

Examples and the TUI sample mode use the shared vector in [test-vectors/parity.json](../test-vectors/parity.json):

- Phrase: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- Passphrase: `TREZOR`
- Account path: `m/44'/3'/0'`
- First receive address (`m/44'/3'/0'/0/0`): `DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM`

Example:

```sh
easydoge-km xpriv from-mnemonic \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

## Ratatui TUI

Launch:

```sh
easydoge-km tui
```

Press `q` or `Esc` to quit.

### Paste inspector

Press `/` to enter paste mode. You can paste or type:

- Dogecoin addresses
- BIP39 seed phrases
- Extended private keys
- Extended public keys
- WIF private keys

The TUI does not echo unclassified input because it may contain secret material. Press `Enter` to inspect, `Backspace` to edit, or `Esc` to cancel.

Seed phrases move through a second passphrase prompt before deriving keys. Leave the passphrase empty and press `Enter` for a normal no-passphrase BIP39 seed, or type/paste the optional BIP39 passphrase first.

Inspector results are redacted by default:

- Seed phrases, xprivs, and WIFs are never shown unless reveal is enabled where the TUI supports revealing that value.
- Xpubs, public keys, addresses, networks, depths, child numbers, and address payload hashes are shown because they are public metadata.
- Address inspection reports every matching Dogecoin network and address kind (`p2pkh` or `p2sh`). Testnet and regtest may both match the same P2SH prefix.

When pasted material can derive addresses, the TUI derives both incoming and outgoing/change addresses immediately for the current account and index. Changing account or index refreshes inspected derivations where applicable.

### Mnemonic source

Address creation does not require generating a mnemonic first. The TUI picks its seed material as follows:

| Mode | When | Phrase | Passphrase |
| --- | --- | --- | --- |
| Sample | Before `g`, or after clearing generated secret | Parity test phrase (above) | `TREZOR` |
| Generated | After `g` | New 24-word English mnemonic | none (empty) |

The status panel shows **Source: sample mnemonic** or **Source: generated mnemonic**. Generated phrases stay redacted until you toggle reveal with `r`.

Pressing `g` generates a new mnemonic and clears any addresses derived from the previous source.

### What addresses derive from

The TUI does not derive addresses from the BIP32 master key directly. For the active mnemonic source it:

1. Builds a BIP39 seed and BIP32 master key
2. Derives the account extended key at `m/44'/3'/{account}'` (Dogecoin BIP44, coin type `3'`)
3. Derives P2PKH addresses from the account **xpub** using relative paths `m/0/{index}` (incoming) and `m/1/{index}` (outgoing/change)

Default account and index are `0`. Change them with the keys below before creating addresses.

Addresses from sample mode are deterministic and publicly known test material. Do not send real funds to them expecting privacy or exclusive control.

### Keybindings

| Key | Action |
| --- | --- |
| `/` | Paste or type material to inspect |
| `g` | Generate a new mnemonic |
| `v` | Validate the parity sample phrase |
| `r` | Toggle reveal for secret material |
| `i` | Create incoming address (`…/0/{index}`) |
| `o` | Create outgoing/change address (`…/1/{index}`) |
| `d` | Create both incoming and outgoing addresses |
| `a` / `z` | Account + / − (clears displayed addresses) |
| `n` / `p` | Address index + / − (clears displayed addresses) |
| `q`, `Esc` | Quit |
