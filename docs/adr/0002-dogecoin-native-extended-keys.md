# ADR 0002: Dogecoin-Native Extended Keys

## Status

Accepted

## Context

Many HD-wallet tools use Bitcoin-style `xpub`/`xprv` prefixes, while Dogecoin Core defines Dogecoin-specific extended key version bytes.

## Decision

Export Dogecoin-native extended key serialization by default. Permit Bitcoin-style legacy imports only through explicit compatibility APIs that require the caller to supply the Dogecoin network.

## Consequences

Default exports match Dogecoin Core network constants. Compatibility imports remain possible without silently interpreting Bitcoin network prefixes as Dogecoin authority.

