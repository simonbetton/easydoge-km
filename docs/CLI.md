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

- `--json` — select JSON for commands with a text-output alternative; many commands always return JSON
- `--reveal` — show mnemonics, seeds, xprivs, WIFs, and message signatures that are redacted by default (transaction hex is returned without this flag)

Use `<command> --help` for subcommand flags. Derivation path conventions match [API.md](API.md).

## Scriptable CLI

Subcommands are independent. Nothing tracks session state between invocations, so there is no required order beyond what your workflow needs.

Typical flow:

1. `mnemonic generate` — create a BIP39 phrase
2. `xpriv from-mnemonic` — derive the account xpriv/xpub at `m/44'/3'/account'`
3. `address derive --xpub … --path m/0/0` — derive a watch-only receive address from the account xpub

`address derive` accepts exactly one key source — `--xpub`, `--xpriv-file`, or the literal `--xpriv` — plus a relative path (for example `m/0/0` for incoming, `m/1/0` for outgoing/change). It does not take a mnemonic directly.

Subcommands cover mnemonic handling, account and path derivation, WIF import/export, address validation, message signing, P2PKH transaction signing, compose-and-sign transaction building, multisig envelopes, and more. See `easydoge-km --help`.

### Supplying secrets

Do not type seed phrases, BIP39 passphrases, extended private keys, or WIFs as flag values. Literal arguments are saved in shell history and are visible to other local users through process listings. Every secret-bearing flag has a `-file` companion that takes a path instead:

| Secret | File or standard input | Literal flag (discouraged) |
| --- | --- | --- |
| Seed phrase | `--phrase-file <PATH>` | `--phrase` |
| BIP39 passphrase | `--passphrase-file <PATH>` | `--passphrase` |
| Extended private key | `--xpriv-file <PATH>` | `--xpriv` |
| WIF private key | `--wif-file <PATH>` | `--wif` |

- The path `-` reads standard input. Only one secret per invocation can come from standard input; put any other in a file.
- Exactly one trailing line ending (`\n` or `\r\n`) is removed. Nothing else is trimmed, so a passphrase keeps its leading and trailing spaces, and a file that ends in two newlines keeps one of them.
- The content must be UTF-8, at most 64 KiB, and not empty. To use no passphrase, omit both passphrase flags.
- A literal flag and its `-file` companion cannot be combined. `address derive` takes exactly one of `--xpub`, `--xpriv-file`, or `--xpriv`.
- Errors name the flag and the path, never the contents.
- The literal flags remain for public test vectors and print a warning on standard error each time they are used.

Keep secret files readable only by you (`chmod 600`) and delete them when you are done. Piping from `printf` or `echo` with the secret typed inline still records it in shell history. Read it without echo instead:

```sh
read -rs SEED_PHRASE
printf '%s' "$SEED_PHRASE" | easydoge-km mnemonic validate --phrase-file -
unset SEED_PHRASE
```

Typing directly into `--phrase-file -` at a terminal also works (finish with Ctrl-D), but the terminal echoes what you type.

### Compose and sign a transaction

`tx compose` reads a JSON request file and prints only the audited result. The request may contain WIFs or xprivs, so do not log request files or shell history that includes them.

```sh
easydoge-km --json tx compose --request-file compose-request.json
```

The request uses the same shape as the Rust `ComposeTransactionRequest`: UTXOs use display/RPC txid hex, values are integer koinu, fee policy is `fee_rate_koinu_per_kb` plus `dust_threshold_koinu`, and transaction sizes are serialized bytes. Outputs can be Dogecoin address outputs, zero-value OP_RETURN data outputs, or `ExpertRawScript` outputs.

The result includes selected inputs, skipped inputs, totals, fee, change details, estimated size, actual signed size when complete, unsigned tx hex, signed tx hex when all signatures are present, or a signing envelope when P2PKH or multisig signatures are missing. The reported totals depend on the UTXO values supplied in the request.

Request files and Signing Envelope files larger than 16 MiB are rejected without being parsed. The core limits in [API.md](API.md#limits) apply to their contents.

### Parity test vector

Examples and the TUI sample mode use the shared vector in [test-vectors/parity.json](../test-vectors/parity.json):

- Phrase: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- Passphrase: `TREZOR`
- Account path: `m/44'/3'/0'`
- First receive address (`m/44'/3'/0'/0/0`): `DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM`

Example. The phrase and passphrase are public test values, so writing them inline here is harmless; never do this with a real secret (see [Supplying secrets](#supplying-secrets)):

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

## Ratatui TUI

Launch:

```sh
easydoge-km tui
```

The TUI is an address explorer for whatever key material you give it. It opens on the public parity-vector sample mnemonic so there is something to explore straight away, and it derives addresses live: pick an account and index and the receive and change addresses are already on screen, together with the full derivation path and public key of the highlighted one.

From the explorer, press `?` for the key reference or `q` to quit. In help, `q` closes help; in text-entry popups it is input. `Ctrl+C` quits from every mode.

### Layout

- **Title bar**: the active network and whether secrets are currently revealed.
- **Source**: what addresses derive from (the sample mnemonic, a generated mnemonic, or pasted material), its public metadata, and the account xpub in use.
- **Addresses**: the active branch's addresses (`…/0/index` for receive, `…/1/index` for change). When the table has enough space for both 34-character address columns and the index, it shows receive and change side by side. The cursor row is highlighted.
- **Selected**: the derivation path, address, and public key of the cursor row for the active branch.
- **Status row** and **hint row**: what the last key did, and which keys apply right now.

Source and Addresses sit side by side from 80 columns up and stack on narrower terminals, which drop the Selected panel. Source panels shorter than 12 inner rows omit explanatory notes. Terminals below 40 columns or 10 rows show a resize prompt instead.

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
- Xpubs, addresses, public keys, and payload hashes are not masked, though terminal size may clip the displayed metadata.
- Address inspection reports every matching Dogecoin network and address kind (`p2pkh` or `p2sh`). Testnet and regtest share the same P2SH prefix.

### What addresses derive from

Every address is a P2PKH address derived from an account-level xpub with the relative paths `m/0/index` (receive) and `m/1/index` (change). Where that xpub comes from depends on the source:

| Source | Account xpub | Displayed paths | Account number |
| --- | --- | --- | --- |
| Sample, generated, or pasted seed phrase | `m/44'/3'/account'` on the selected network | absolute, e.g. `m/44'/3'/0'/0/5` | `a` / `z` change it |
| Master xpriv (depth 0) | `m/44'/3'/account'` | absolute | `a` / `z` change it |
| Account-level xpriv or xpub (depth 3) | the pasted key itself | relative, e.g. `m/0/5` | fixed by the key |
| Extended keys at other depths, addresses, WIFs | none | — | — |

Sources that cannot derive addresses say why in the Addresses panel. Moving within the cached 64-index window uses existing rows; moving beyond it derives a new window. Changing the source, account, or network rebuilds the account context. For mnemonic sources, the BIP39 seed stretch runs during that rebuild, not for each address.

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
| `?` | Open the key reference from the explorer, or close it from help |
| `Esc` | Close a popup, or hide revealed secrets |
| `q`, `Ctrl+C` | `q` quits from the explorer; `Ctrl+C` quits from every mode |
