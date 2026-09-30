use bitcoin::hashes::{hash160, Hash};
use sha2::{Digest, Sha256};

use crate::{limits, Error, Network, Result};

pub(crate) fn hash160_bytes(bytes: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(bytes).to_byte_array()
}

pub(crate) fn base58check_encode(prefix: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(payload.len() + 1);
    data.push(prefix);
    data.extend_from_slice(payload);
    bs58::encode(data).with_check().into_string()
}

pub(crate) fn base58check_decode(value: &str) -> Result<Vec<u8>> {
    // Base58 decoding is quadratic in the input length, so refuse anything
    // longer than the longest value the SDK accepts before decoding.
    if value.len() > limits::MAX_BASE58CHECK_CHARS {
        return Err(Error::InvalidKey(format!(
            "base58check value has {} characters, which exceeds the limit of {}",
            value.len(),
            limits::MAX_BASE58CHECK_CHARS
        )));
    }
    bs58::decode(value)
        .with_check(None)
        .into_vec()
        .map_err(|err| Error::InvalidKey(err.to_string()))
}

/// Encodes the P2PKH address for a serialized public key. The caller chooses
/// the serialization (33-byte compressed or 65-byte uncompressed); the two
/// forms of one key hash to different addresses.
pub(crate) fn p2pkh_address(network: Network, public_key_bytes: &[u8]) -> String {
    base58check_encode(network.prefixes().p2pkh, &hash160_bytes(public_key_bytes))
}

pub(crate) fn p2sh_address(network: Network, redeem_script: &[u8]) -> String {
    base58check_encode(network.prefixes().p2sh, &hash160_bytes(redeem_script))
}

pub(crate) fn wif(network: Network, private_key: &[u8; 32], compressed: bool) -> String {
    let mut payload = Vec::with_capacity(if compressed { 33 } else { 32 });
    payload.extend_from_slice(private_key);
    if compressed {
        payload.push(0x01);
    }
    base58check_encode(network.prefixes().wif, &payload)
}

pub(crate) fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}
