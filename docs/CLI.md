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

The TUI is an address explorer for whatever key material you give it. It opens on the public parity-vector sample mnemonic so there is something to explore straight away, and it derives addresses live: pick an account and index and the receive and change addresses are already on screen, together with the full derivation path and public key of the highlighted one.

Press `?` at any time for the key reference. `q` or `Ctrl+C` quits.

### Layout

- **Title bar**: the active network and whether secrets are currently revealed.
- **Source**: what addresses derive from (the sample mnemonic, a generated mnemonic, or pasted material), its public metadata, and the account xpub in use.
- **Addresses**: receive addresses (`…/0/index`) for the current account, with change addresses (`…/1/index`) beside them on terminals at least 120 columns wide. The cursor row is highlighted.
- **Selected**: the derivation path, address, and public key of the cursor row for the active branch.
- **Status row** and **hint row**: what the last key did, and which keys apply right now.

Source and Addresses sit side by side from 80 columns up and stack on narrower terminals, which drop the Selected panel and the explanatory notes. Terminals smaller than 40×10 show a resize prompt instead.

### Paste inspector

Press `/` to open the inspector, or paste straight into the terminal from the explorer. You can paste or type:

- Dogecoin addresses
- BIP39 seed phrases
- Extended private keys
- Extended public keys
- WIF private keys

The inspector never echoes what you typed because it may be secret; it shows a masked field with the character and word count instead. Press `Enter` to inspect, `Backspace` to edit, `Ctrl+U` to clear, or `Esc` to cancel. Classification errors appear inside the popup and leave the input editable.

Seed phrases go through a second prompt for the optional BIP39 passphrase. Leave it empty and press `Enter` for a normal no-passphrase seed. Cancelling either prompt leaves the previous source untouched.

Results are redacted by default:

- Seed phrases and passphrases stay hidden until you press `r`, which renders the phrase as a numbered word grid. `Esc` hides them again.
- Pasted xprivs and WIFs are never shown. Their public side is: the xpub, public key, address, network, depth, child number, and parent fingerprint.
- Xpubs, addresses, public keys, and payload hashes are public metadata and always shown.
- Address inspection reports every matching Dogecoin network and address kind (`p2pkh` or `p2sh`). Testnet and regtest share the same P2SH prefix.

### What addresses derive from

Every address is a P2PKH address derived from an account-level xpub with the relative paths `m/0/index` (receive) and `m/1/index` (change). Where that xpub comes from depends on the source:

| Source | Account xpub | Displayed paths | Account number |
| --- | --- | --- | --- |
| Sample, generated, or pasted seed phrase | `m/44'/3'/account'` on the selected network | absolute, e.g. `m/44'/3'/0'/0/5` | `a` / `z` change it |
| Master xpriv (depth 0) | `m/44'/3'/account'` | absolute | `a` / `z` change it |
| Account-level xpriv or xpub (depth 3) | the pasted key itself | relative, e.g. `m/0/5` | fixed by the key |
| Extended keys at other depths, addresses, WIFs | none | — | — |

Sources that cannot derive addresses say why in the Addresses panel. Moving the index, changing the account, or switching network re-derives immediately; the BIP39 seed stretch runs once per account rather than once per address.

### Mnemonic source

| Source | When | Phrase | Passphrase |
| --- | --- | --- | --- |
| Sample | On launch, and after `x` | Parity test phrase (above) | `TREZOR` |
| Generated | After `g` | New 24-word English mnemonic | none |
| Pasted | After inspecting a seed phrase | Your phrase | Whatever you entered |

A generated phrase exists only for the current session. Reveal it with `r` and back it up before relying on it. `x` discards pasted or generated material and returns to the sample mnemonic.

Addresses from the sample mnemonic are deterministic, publicly known test material. Never send real funds to them.

### Networks

`t` cycles mainnet, testnet, and regtest for seed-phrase sources. Pasted extended keys are pinned to the networks their version bytes allow: Dogecoin-native mainnet keys (`dgpv`/`dgub`) stay on mainnet, while testnet-style keys (`tprv`/`tpub`) can switch between testnet and regtest, which share key prefixes but not address prefixes. Bitcoin-style legacy keys (`xprv`/`xpub`) can be interpreted on any network. Addresses and WIFs report their networks and cannot be switched.

### Keybindings

| Key | Action |
| --- | --- |
| `/` | Paste or type material to inspect (pasting from the explorer works too) |
| `g` | Generate a new 24-word mnemonic |
| `r` | Reveal or hide secret material |
| `x` | Clear pasted or generated material and return to the sample mnemonic |
| `t` | Cycle network where the source allows it |
| `↑` / `↓`, `j` / `k`, `n` / `p` | Move the address index |
| `PgUp` / `PgDn` | Move the index by a page |
| `Home` | Back to index 0 |
| `:` | Jump to an index |
| `Tab`, `←` / `→` | Switch between receive and change |
| `a` / `z` | Account + / − |
| `?` | Toggle the key reference |
| `Esc` | Close a popup, or hide revealed secrets |
| `q`, `Ctrl+C` | Quit (`Ctrl+C` works inside popups too) |
