# ADR 0005: Offline Compose-and-Sign Transaction Builder

## Status

Accepted

## Context

The SDK previously signed caller-supplied unsigned transaction hex. Wallet callers still had to compose transactions, select UTXOs, estimate fees, add change, and serialize unsigned transactions outside the library before using the signing APIs.

That split made it easy for different platform callers to disagree on txid byte order, dust policy, fee sizing, OP_RETURN construction, and multisig completion rules.

## Decision

Implement an offline Compose-and-Sign Transaction Builder in the Rust core and expose it through the existing UniFFI, Expo, and CLI surfaces.

The builder accepts caller-provided UTXO data, output requests, fee policy, coin-selection strategy, change destination, transaction options, and signer metadata. It composes and funds a legacy Dogecoin transaction, validates signer ownership, signs selected inputs, and returns either signed transaction hex or a signing envelope when more multisig signatures are needed.

The SDK still does not fetch UTXOs, fetch live fee rates, broadcast transactions, or validate chain state.

## Consequences

Transaction construction rules now have one implementation shared by Rust, Swift, Kotlin, Expo, and CLI callers.

Callers must provide complete and accurate previous-output metadata, including display/RPC txid hex, previous output value, script pubkey, and P2SH multisig descriptor metadata when applicable.

Fee and dust behavior is explicit through request policy rather than hidden network defaults.

Requests may contain signer secrets, so result DTOs and CLI output must never echo WIFs or xprivs.
