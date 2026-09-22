# ADR 0002: Dogecoin-Native Extended Keys

## Status

Accepted

## Context

Many HD-wallet tools use Bitcoin-style `xpub`/`xprv` prefixes, while Dogecoin Core defines Dogecoin-specific extended key version bytes.

## Decision

Export extended keys using the selected Dogecoin network's version bytes. Accept Bitcoin-style legacy prefixes through the normal `Xpriv`/`Xpub` operations, using the network carried in the key record; there is no separate compatibility-import API.

## Consequences

Default exports use `dgpv`/`dgub` on mainnet and `tprv`/`tpub` on testnet and regtest. Legacy prefixes do not establish the caller's intended Dogecoin network. Callers must choose the correct network; the CLI defaults to mainnet, while the TUI first classifies extended keys by their prefix.
