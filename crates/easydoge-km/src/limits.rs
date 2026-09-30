//! Resource limits enforced at the SDK's public request boundaries.
//!
//! Every limit is an inclusive maximum: a value equal to the constant is
//! accepted and the first value above it is rejected. The checks run before
//! any parsing, hashing, key derivation, or signature verification, so an
//! oversized Compose-and-Sign request or Signing Envelope costs a length
//! comparison and nothing else. Limits marked "SDK policy" are choices made by
//! this SDK; the others restate Dogecoin Core 1.14 or encoding rules.

use std::fmt;

use crate::{Error, Result};

/// Largest serialized transaction, in bytes, that the SDK builds or signs.
///
/// Dogecoin Core 1.14 relays and mines only transactions smaller than 100,000
/// bytes: `IsStandardTx` rejects a weight greater than or equal to
/// `MAX_STANDARD_TX_WEIGHT` (400,000) with reason `tx-size`, and a legacy
/// transaction weighs four units per byte. The limit also bounds signing work,
/// because every legacy signature hash covers the whole transaction.
pub const MAX_TRANSACTION_BYTES: usize = 99_999;

/// Largest script, in bytes, accepted as a Script Pubkey, a Redeem Script, or
/// an `ExpertRawScript` output. Equals consensus `MAX_SCRIPT_SIZE`: a longer
/// script fails evaluation, so an output locked by one is unspendable.
pub const MAX_SCRIPT_BYTES: usize = 10_000;

/// Most candidate UTXOs in one Compose-and-Sign request. SDK policy: a
/// transaction within [`MAX_TRANSACTION_BYTES`] spends fewer than 700 P2PKH
/// inputs, so 10,000 candidates leave Coin Selection ample choice while
/// keeping sorting and skipped-input reporting cheap. A wallet holding more
/// UTXOs must pre-filter, for example by passing its largest ones.
pub const MAX_REQUEST_UTXOS: usize = 10_000;

/// Most outputs in one Compose-and-Sign request. SDK policy: a transaction
/// within [`MAX_TRANSACTION_BYTES`] holds roughly 3,100 address outputs at
/// most (32 bytes per P2SH output, 34 per P2PKH output), so this never rejects
/// a payment that could have been relayed.
pub const MAX_REQUEST_OUTPUTS: usize = 3_200;

/// Most signers listed on one UTXO. SDK policy: the largest cosigner set a
/// multisig script can name with a single small-integer opcode (`OP_16`).
pub const MAX_SIGNERS_PER_UTXO: usize = 16;

/// A Signing Envelope may carry at most this many signatures per transaction
/// input, counted across the whole envelope (limit = transaction inputs × 16).
/// SDK policy, same reasoning as [`MAX_SIGNERS_PER_UTXO`]. Every signature
/// costs one signature hash and one ECDSA verification.
pub const MAX_ENVELOPE_SIGNATURES_PER_INPUT: usize = 16;

/// Most Signing Envelopes accepted by one `combine_signing_envelopes` call.
/// SDK policy: four times the largest cosigner set. Combine in batches to
/// merge more.
pub const MAX_ENVELOPES_PER_COMBINE: usize = 64;

/// Longest Base58Check text the SDK decodes. An extended key (78-byte payload
/// plus 4-byte checksum) never encodes to more than 112 characters; addresses
/// and WIFs are shorter. Base58 decoding is quadratic in the text length.
pub const MAX_BASE58CHECK_CHARS: usize = 112;

/// Rejects a collection that holds more than `max` items.
pub(crate) fn check_count(
    owner: fmt::Arguments<'_>,
    count: usize,
    items: &str,
    max: usize,
) -> Result<()> {
    if count > max {
        return Err(Error::InvalidTransaction(format!(
            "{owner} has {count} {items}, which exceeds the limit of {max}"
        )));
    }
    Ok(())
}

/// Rejects hex text that would decode to more than `max_bytes` bytes. Only the
/// text length is inspected, so this runs before any decoding or allocation.
pub(crate) fn check_hex_len(
    field: fmt::Arguments<'_>,
    hex_value: &str,
    max_bytes: usize,
) -> Result<()> {
    let max_chars = max_bytes * 2;
    if hex_value.len() > max_chars {
        return Err(Error::InvalidTransaction(format!(
            "{field} has {} hex characters, which exceeds the limit of {max_chars} ({max_bytes} bytes)",
            hex_value.len()
        )));
    }
    Ok(())
}
