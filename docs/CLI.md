# CLI and TUI Guide

The `easydoge-km` binary in `crates/easydoge-km-cli` is an engineer-facing surface for exploring the Rust SDK from the terminal. It is not a production wallet and does not enforce a setup wizard or custodial storage.

Run from the workspace root:

```sh
cargo run -p easydoge-km-cli -- <command>
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

Subcommands cover mnemonic handling, account and path derivation, WIF import/export, address validation, message signing, P2PKH transaction signing, multisig envelopes, and more. See `cargo run -p easydoge-km-cli -- --help`.

### Parity test vector

Examples and the TUI sample mode use the shared vector in [test-vectors/parity.json](../test-vectors/parity.json):

- Phrase: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- Passphrase: `TREZOR`
- Account path: `m/44'/3'/0'`
- First receive address (`m/44'/3'/0'/0/0`): `DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM`

Example:

```sh
cargo run -p easydoge-km-cli -- xpriv from-mnemonic \
  --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --passphrase TREZOR \
  --network mainnet \
  --account 0 \
  --reveal
```

## Ratatui TUI

Launch:

```sh
cargo run -p easydoge-km-cli -- tui
```

Press `q` or `Esc` to quit.

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
| `g` | Generate a new mnemonic |
| `v` | Validate the parity sample phrase |
| `r` | Toggle reveal for the generated mnemonic |
| `i` | Create incoming address (`…/0/{index}`) |
| `o` | Create outgoing/change address (`…/1/{index}`) |
| `d` | Create both incoming and outgoing addresses |
| `a` / `z` | Account + / − (clears displayed addresses) |
| `n` / `p` | Address index + / − (clears displayed addresses) |
| `q`, `Esc` | Quit |
