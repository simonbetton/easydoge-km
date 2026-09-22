# ADR 0007: TUI Address Explorer With Live Derivation

## Status

Accepted

## Context

The Ratatui surface grew out of a question-and-answer demo: a fixed ASCII header, a panel of keybindings, and a panel of `label: value` lines. Addresses were derived one at a time on request, every derivation re-ran the BIP39 seed stretch, and the whole TUI lived in `main.rs` beside the CLI. That layout hid what engineers actually want from the tool (a run of addresses, the path and public key of one address, extended-key metadata), could not adapt to terminal size, and had no help, no scrolling, and no way to change network.

## Decision

Rebuild the TUI as an address explorer in its own `tui` module, split into pure state (`app`), classification and derivation (`material`), rendering (`ui`), and styling (`theme`). The app keeps one Key Source (sample, generated, or Pasted Material) and caches the account xpub for the current account and network; a window of 64 indices is derived from that xpub and shown as a table with a cursor. Moving the cursor, changing the account, switching network, or adopting a new source re-derives immediately.

The layout is responsive: two columns from 80 columns wide, stacked below that, and a resize prompt under 40×10. Input that may contain secrets is collected in masked popups, and secrets stay redacted until the user reveals them. Extended keys are classified on the network their version bytes imply (`dg…` mainnet, `tp…` testnet or regtest) before the core's legacy-prefix fallback is used.

## Consequences

Address exploration no longer needs explicit "create address" keys, and the seed stretch runs once per account instead of once per address. State transitions and rendering are exercised against a headless backend, so the redaction rules and the responsive layout are enforced by tests rather than by review. The scriptable CLI subcommands are unchanged; only the interactive surface moved.
