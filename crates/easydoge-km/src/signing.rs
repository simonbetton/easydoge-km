use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

use crate::keys::secret_key_from_wif;
use crate::{Error, Network, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningEnvelope {
    pub version: u8,
    pub network: Network,
    pub unsigned_tx_hex: String,
    pub inputs: Vec<SigningEnvelopeInput>,
    pub signatures: Vec<SigningEnvelopeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningEnvelopeInput {
    pub input_index: usize,
    pub kind: SigningInputKind,
    pub script_pubkey_hex: String,
    pub redeem_script_hex: Option<String>,
    pub sighash_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningInputKind {
    P2pkh,
    P2shMultisig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningEnvelopeSignature {
    pub input_index: usize,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub network: Network,
    pub signed_tx_hex: String,
}

pub fn sign_p2pkh_transaction(
    network: Network,
    unsigned_tx_hex: &str,
    input_index: usize,
    script_pubkey_hex: &str,
    wif: &str,
    sighash_type: u32,
) -> Result<SignedTransaction> {
    let mut envelope = SigningEnvelope {
        version: 1,
        network,
        unsigned_tx_hex: unsigned_tx_hex.to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index,
            kind: SigningInputKind::P2pkh,
            script_pubkey_hex: script_pubkey_hex.to_owned(),
            redeem_script_hex: None,
            sighash_type,
        }],
        signatures: vec![],
    };
    envelope = sign_signing_envelope(&envelope, wif)?;
    finalize_signing_envelope(&envelope)
}

pub fn sign_signing_envelope(envelope: &SigningEnvelope, wif: &str) -> Result<SigningEnvelope> {
    let secret_key = secret_key_from_wif(wif, envelope.network)?;
    let secp = Secp256k1::new();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let mut signatures = envelope.signatures.clone();

    for input in &envelope.inputs {
        let script_hex = input
            .redeem_script_hex
            .as_deref()
            .unwrap_or(input.script_pubkey_hex.as_str());
        let script = parse_script(script_hex)?;
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(input.input_index, script.as_script(), input.sighash_type)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &secret_key);
        let mut der = signature.serialize_der().to_vec();
        der.push(input.sighash_type as u8);
        signatures.push(SigningEnvelopeSignature {
            input_index: input.input_index,
            public_key_hex: hex::encode(public_key.serialize()),
            signature_hex: hex::encode(der),
        });
    }

    let mut next = envelope.clone();
    next.signatures = signatures;
    Ok(next)
}

pub fn combine_signing_envelopes(envelopes: &[SigningEnvelope]) -> Result<SigningEnvelope> {
    let first = envelopes
        .first()
        .ok_or_else(|| Error::InvalidTransaction("at least one envelope is required".to_owned()))?;
    let mut combined = first.clone();
    for envelope in envelopes.iter().skip(1) {
        if envelope.version != first.version
            || envelope.network != first.network
            || envelope.unsigned_tx_hex != first.unsigned_tx_hex
            || envelope.inputs != first.inputs
        {
            return Err(Error::InvalidTransaction(
                "cannot combine envelopes with different transaction metadata".to_owned(),
            ));
        }
        for signature in &envelope.signatures {
            if !combined.signatures.iter().any(|existing| {
                existing.input_index == signature.input_index
                    && existing.public_key_hex == signature.public_key_hex
                    && existing.signature_hex == signature.signature_hex
            }) {
                combined.signatures.push(signature.clone());
            }
        }
    }
    Ok(combined)
}

pub fn finalize_signing_envelope(envelope: &SigningEnvelope) -> Result<SignedTransaction> {
    let mut tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    for input in &envelope.inputs {
        let mut matching: Vec<&SigningEnvelopeSignature> = envelope
            .signatures
            .iter()
            .filter(|signature| signature.input_index == input.input_index)
            .collect();
        matching.sort_by_key(|signature| signature.public_key_hex.as_str());
        if matching.is_empty() {
            return Err(Error::InvalidTransaction(format!(
                "input {} has no signatures",
                input.input_index
            )));
        }
        let script_sig = match input.kind {
            SigningInputKind::P2pkh => {
                let signature = matching[0];
                Builder::new()
                    .push_slice(push_bytes(hex::decode(&signature.signature_hex).map_err(
                        |err| Error::Serialization(format!("invalid signature hex: {err}")),
                    )?)?)
                    .push_slice(push_bytes(
                        hex::decode(&signature.public_key_hex).map_err(|err| {
                            Error::Serialization(format!("invalid public key hex: {err}"))
                        })?,
                    )?)
                    .into_script()
            }
            SigningInputKind::P2shMultisig => {
                let redeem_script = input.redeem_script_hex.as_ref().ok_or_else(|| {
                    Error::InvalidTransaction(
                        "P2SH multisig input requires redeem script".to_owned(),
                    )
                })?;
                let mut builder = Builder::new().push_int(0);
                for signature in matching {
                    builder = builder.push_slice(push_bytes(
                        hex::decode(&signature.signature_hex).map_err(|err| {
                            Error::Serialization(format!("invalid signature hex: {err}"))
                        })?,
                    )?);
                }
                builder
                    .push_slice(push_bytes(hex::decode(redeem_script).map_err(|err| {
                        Error::Serialization(format!("invalid redeem script hex: {err}"))
                    })?)?)
                    .into_script()
            }
        };
        let txin = tx.input.get_mut(input.input_index).ok_or_else(|| {
            Error::InvalidTransaction(format!("input index {} out of range", input.input_index))
        })?;
        txin.script_sig = script_sig;
    }
    Ok(SignedTransaction {
        network: envelope.network,
        signed_tx_hex: hex::encode(serialize(&tx)),
    })
}

fn parse_transaction(hex_value: &str) -> Result<Transaction> {
    let bytes = hex::decode(hex_value)
        .map_err(|err| Error::InvalidTransaction(format!("invalid tx hex: {err}")))?;
    deserialize(&bytes).map_err(|err| Error::InvalidTransaction(err.to_string()))
}

fn parse_script(hex_value: &str) -> Result<bitcoin::ScriptBuf> {
    let bytes = hex::decode(hex_value)
        .map_err(|err| Error::Serialization(format!("invalid script hex: {err}")))?;
    Ok(bitcoin::ScriptBuf::from_bytes(bytes))
}

fn push_bytes(bytes: Vec<u8>) -> Result<PushBytesBuf> {
    PushBytesBuf::try_from(bytes).map_err(|err| Error::Serialization(err.to_string()))
}
