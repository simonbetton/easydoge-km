use bitcoin::blockdata::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::encoding::p2sh_address;
use crate::keys::{decode_xpub, derive_path_from_xpub, Xpub};
use crate::{Error, Network, Result};

/// Largest script a P2SH spend can reveal. The spending scriptSig pushes the
/// whole redeem script as one stack element, and consensus rejects any pushed
/// element above 520 bytes (`MAX_SCRIPT_ELEMENT_SIZE` in Dogecoin Core), so
/// funds sent to a larger redeem script can never be spent.
pub(crate) const MAX_P2SH_REDEEM_SCRIPT_BYTES: usize = 520;

/// Most cosigners a P2SH multisig redeem script can carry. With compressed
/// keys the script is `1 + 34 * n + 2` bytes: 15 keys fit (513 bytes), 16 do
/// not (547 bytes).
pub(crate) const MAX_P2SH_MULTISIG_COSIGNERS: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigDescriptor {
    pub network: Network,
    pub threshold: u8,
    pub cosigner_count: u8,
    pub child_path: String,
    pub sorted: bool,
    pub public_keys_hex: Vec<String>,
    pub redeem_script_hex: String,
    pub p2sh_address: String,
}

/// Creates a P2SH multisig descriptor from one child public key per cosigner
/// xpub, derived at the shared non-hardened `child_path`.
///
/// Every cosigner must derive a distinct public key, and at most 15 cosigners
/// are supported: a redeem script for 16 compressed keys is 547 bytes, above
/// the 520-byte limit for a pushed script element, so its P2SH address could
/// receive funds that can never be spent.
pub fn create_multisig_descriptor(
    network: Network,
    threshold: u8,
    cosigner_xpubs: &[Xpub],
    child_path: &str,
    sorted: bool,
) -> Result<MultisigDescriptor> {
    if cosigner_xpubs.is_empty() {
        return Err(Error::InvalidKey(
            "at least one cosigner xpub is required".to_owned(),
        ));
    }
    if threshold == 0 || usize::from(threshold) > cosigner_xpubs.len() {
        return Err(Error::InvalidKey(
            "threshold must be between 1 and cosigner count".to_owned(),
        ));
    }
    if cosigner_xpubs.len() > MAX_P2SH_MULTISIG_COSIGNERS {
        return Err(Error::Unsupported(
            "P2SH multisig supports at most 15 cosigners".to_owned(),
        ));
    }

    let mut public_keys: Vec<PublicKey> = cosigner_xpubs
        .iter()
        .map(|xpub| {
            if xpub.network != network {
                return Err(Error::InvalidNetwork(
                    "cosigner xpub network mismatch".to_owned(),
                ));
            }
            let child = derive_path_from_xpub(xpub, child_path)?;
            Ok(decode_xpub(network, &child.encoded)?.public_key)
        })
        .collect::<Result<Vec<_>>>()?;

    if sorted {
        public_keys.sort_by_key(|key| key.serialize());
    }

    let redeem_script = build_multisig_redeem_script(threshold, &public_keys)?;
    let redeem_script_bytes = redeem_script.as_bytes().to_vec();
    Ok(MultisigDescriptor {
        network,
        threshold,
        cosigner_count: cosigner_xpubs
            .len()
            .try_into()
            .map_err(|_| Error::Unsupported("too many cosigners".to_owned()))?,
        child_path: child_path.to_owned(),
        sorted,
        public_keys_hex: public_keys
            .iter()
            .map(|key| hex::encode(key.serialize()))
            .collect(),
        redeem_script_hex: hex::encode(&redeem_script_bytes),
        p2sh_address: p2sh_address(network, &redeem_script_bytes),
    })
}

pub(crate) fn build_multisig_redeem_script(
    threshold: u8,
    public_keys: &[PublicKey],
) -> Result<bitcoin::ScriptBuf> {
    if public_keys.len() > MAX_P2SH_MULTISIG_COSIGNERS {
        return Err(Error::Unsupported(
            "P2SH multisig supports at most 15 cosigners".to_owned(),
        ));
    }
    if threshold == 0 || usize::from(threshold) > public_keys.len() {
        return Err(Error::InvalidKey("invalid multisig threshold".to_owned()));
    }
    // A repeated key would let one cosigner satisfy more than one of the
    // threshold signatures, so an "m-of-n" script would need fewer than m
    // distinct signers.
    let has_repeated_key = public_keys
        .iter()
        .enumerate()
        .any(|(index, key)| public_keys[..index].contains(key));
    if has_repeated_key {
        return Err(Error::InvalidKey(
            "duplicate cosigner public key in multisig descriptor".to_owned(),
        ));
    }

    let mut builder = Builder::new().push_opcode(pushnum_opcode(threshold)?);
    for key in public_keys {
        builder = builder.push_key(&bitcoin::PublicKey::new(*key));
    }
    let redeem_script = builder
        .push_opcode(pushnum_opcode(public_keys.len() as u8)?)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    if redeem_script.len() > MAX_P2SH_REDEEM_SCRIPT_BYTES {
        return Err(Error::Unsupported(
            "multisig redeem script exceeds 520 bytes and cannot be spent".to_owned(),
        ));
    }
    Ok(redeem_script)
}

fn pushnum_opcode(value: u8) -> Result<bitcoin::blockdata::opcodes::Opcode> {
    if value == 0 || value > 16 {
        return Err(Error::InvalidKey(
            "pushnum must be between 1 and 16".to_owned(),
        ));
    }
    Ok(bitcoin::blockdata::opcodes::Opcode::from(
        OP_PUSHNUM_1.to_u8() + value - 1,
    ))
}
