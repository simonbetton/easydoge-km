use base64::Engine;
use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};

use crate::encoding::{double_sha256, p2pkh_address};
use crate::keys::secret_key_from_wif;
use crate::{Error, Network, Result};

const DOGECOIN_MESSAGE_MAGIC: &str = "Dogecoin Signed Message:\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSignature {
    pub network: Network,
    pub address: String,
    pub signature_base64: String,
}

pub fn sign_message(network: Network, wif: &str, message: &str) -> Result<MessageSignature> {
    let secret_key = secret_key_from_wif(wif, network)?;
    let secp = Secp256k1::new();
    let digest = message_digest(message)?;
    let msg = Message::from_digest(digest);
    let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = p2pkh_address(network, &public_key.serialize());
    let (recovery_id, sig_bytes) = signature.serialize_compact();
    let header = 27 + 4 + recovery_id.to_i32() as u8;
    let mut compact = Vec::with_capacity(65);
    compact.push(header);
    compact.extend_from_slice(&sig_bytes);
    Ok(MessageSignature {
        network,
        address,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(compact),
    })
}

pub fn verify_message(
    network: Network,
    address: &str,
    signature_base64: &str,
    message: &str,
) -> Result<bool> {
    let compact = base64::engine::general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    if compact.len() != 65 {
        return Err(Error::Crypto(
            "message signature must be 65 bytes".to_owned(),
        ));
    }
    let recovery_value = compact[0]
        .checked_sub(27)
        .ok_or_else(|| Error::Crypto("invalid recovery header".to_owned()))?
        & 0x03;
    let recovery_id = RecoveryId::from_i32(i32::from(recovery_value))
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let signature = RecoverableSignature::from_compact(&compact[1..65], recovery_id)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let msg = Message::from_digest(message_digest(message)?);
    let secp = Secp256k1::new();
    let public_key = secp
        .recover_ecdsa(&msg, &signature)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    Ok(p2pkh_address(network, &public_key.serialize()) == address)
}

fn message_digest(message: &str) -> Result<[u8; 32]> {
    let mut data = Vec::new();
    write_var_string(&mut data, DOGECOIN_MESSAGE_MAGIC)?;
    write_var_string(&mut data, message)?;
    Ok(double_sha256(&data))
}

fn write_var_string(target: &mut Vec<u8>, value: &str) -> Result<()> {
    let len = VarInt(value.len() as u64);
    len.consensus_encode(target)
        .map_err(|err| Error::Serialization(err.to_string()))?;
    target.extend_from_slice(value.as_bytes());
    Ok(())
}
