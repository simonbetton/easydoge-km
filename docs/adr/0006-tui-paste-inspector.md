# ADR 0006: TUI Paste Inspector With Shared Address Inspection

## Status

Accepted

## Context

The Ratatui surface started as a deterministic mnemonic demo. Users also need an engineer-facing way to paste wallet material and inspect what it represents without immediately exposing secrets.

Address validation previously returned only a boolean for a caller-supplied network, which forced every UI to duplicate prefix checks when explaining which Dogecoin network and script family an address belongs to.

## Decision

Extend the TUI with a paste inspector for addresses, seed phrases, extended private keys, extended public keys, and WIFs. Keep classification and redacted presentation in the CLI/TUI layer, but expose a small Rust-core `inspect_address` helper that returns matching networks, address kind, and payload hash material for Base58Check Dogecoin addresses.

Seed phrases require an optional passphrase step before derivation. Derivable material shows incoming and outgoing/change addresses for the current account and address index. Secret material stays redacted unless the user explicitly enables reveal.

## Consequences

The address network/kind rules now have one Rust implementation that can be reused by other surfaces later. The TUI still avoids a broad universal inspector API, so extended-key and mnemonic classification remains a UI concern until other bindings need the same workflow.
