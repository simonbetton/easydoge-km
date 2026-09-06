use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

use crate::encoding::hash160_bytes;
use crate::keys::secret_key_from_wif;
use crate::{Error, Network, Result};

const SIGHASH_ALL: u32 = 0x01;
const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Accepts only the six consensus-defined sighash values and returns the
/// single byte appended to a DER signature.
pub(crate) fn validate_sighash_type(sighash_type: u32) -> Result<u8> {
    let base = sighash_type & !SIGHASH_ANYONECANPAY;
    let recognised =
        sighash_type <= 0xff && matches!(base, SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE);
    if !recognised {
        return Err(Error::InvalidTransaction(format!(
            "unsupported sighash type {sighash_type:#x}; expected 0x01, 0x02, 0x03, 0x81, 0x82, or 0x83"
        )));
    }
    Ok(sighash_type as u8)
}

/// Validates the sighash type for one input, including the SIGHASH_SINGLE
/// rule that the input index must have a matching output.
pub(crate) fn validated_sighash_flag(
    sighash_type: u32,
    input_index: usize,
    output_count: usize,
) -> Result<u8> {
    let flag = validate_sighash_type(sighash_type)?;
    if (sighash_type & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE && input_index >= output_count {
        return Err(Error::InvalidTransaction(format!(
            "SIGHASH_SINGLE for input {input_index} requires an output at index {input_index}, but the transaction has {output_count} outputs"
        )));
    }
    Ok(flag)
}

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
    #[serde(default)]
    pub previous_output_value_koinu: Option<u64>,
    #[serde(default)]
    pub multisig_threshold: Option<u8>,
    #[serde(default)]
    pub multisig_public_keys_hex: Vec<String>,
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
            previous_output_value_koinu: None,
            multisig_threshold: None,
            multisig_public_keys_hex: vec![],
        }],
        signatures: vec![],
    };
    envelope = sign_signing_envelope(&envelope, wif)?;
    apply_signatures(&envelope, DescriptorCoverage::Partial)
}

pub fn sign_signing_envelope(envelope: &SigningEnvelope, wif: &str) -> Result<SigningEnvelope> {
    let tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let validated = validate_envelope(envelope, &tx, DescriptorCoverage::Partial)?;
    let secret_key = secret_key_from_wif(wif, envelope.network)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize());
    let cache = SighashCache::new(&tx);
    let mut signatures = envelope.signatures.clone();
    let mut controls_any_input = false;

    for input in &validated {
        if !input.controls(&public_key) {
            continue;
        }
        controls_any_input = true;
        let index = input.index();
        let already_signed = signatures.iter().any(|signature| {
            signature.input_index == index
                && signature
                    .public_key_hex
                    .eq_ignore_ascii_case(&public_key_hex)
        });
        if already_signed {
            continue;
        }
        let sighash = cache
            .legacy_signature_hash(
                index,
                input.signing_script.as_script(),
                input.descriptor.sighash_type,
            )
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        let mut der = secp
            .sign_ecdsa(&message, &secret_key)
            .serialize_der()
            .to_vec();
        der.push(input.sighash_flag);
        signatures.push(SigningEnvelopeSignature {
            input_index: index,
            public_key_hex: public_key_hex.clone(),
            signature_hex: hex::encode(der),
        });
    }

    if !controls_any_input {
        return Err(Error::InvalidKey(
            "WIF does not control any input in the signing envelope".to_owned(),
        ));
    }
    let mut next = envelope.clone();
    next.signatures = signatures;
    Ok(next)
}

pub fn combine_signing_envelopes(envelopes: &[SigningEnvelope]) -> Result<SigningEnvelope> {
    let first = envelopes
        .first()
        .ok_or_else(|| Error::InvalidTransaction("at least one envelope is required".to_owned()))?;
    let tx = parse_transaction(&first.unsigned_tx_hex)?;
    validate_envelope(first, &tx, DescriptorCoverage::Partial)?;
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
        validate_envelope(envelope, &tx, DescriptorCoverage::Partial)?;
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
    apply_signatures(envelope, DescriptorCoverage::Complete)
}

fn apply_signatures(
    envelope: &SigningEnvelope,
    coverage: DescriptorCoverage,
) -> Result<SignedTransaction> {
    let mut tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let validated = validate_envelope(envelope, &tx, coverage)?;
    let mut script_sigs = Vec::with_capacity(validated.len());
    for input in &validated {
        let index = input.index();
        let mut matching: Vec<&SigningEnvelopeSignature> = envelope
            .signatures
            .iter()
            .filter(|signature| signature.input_index == index)
            .collect();
        matching.sort_by_key(|signature| signature.public_key_hex.as_str());
        if matching.is_empty() {
            return Err(Error::InvalidTransaction(format!(
                "input {index} has no signatures"
            )));
        }
        let script_sig = match input.descriptor.kind {
            SigningInputKind::P2pkh => {
                // Every signature was verified against the owning key in validate_envelope.
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
                let metadata = input
                    .multisig
                    .as_ref()
                    .expect("validated P2SH input carries multisig metadata");
                let redeem_script = input
                    .descriptor
                    .redeem_script_hex
                    .as_deref()
                    .expect("validated P2SH input carries a redeem script");
                let mut matching = matching
                    .into_iter()
                    .filter(|signature| {
                        metadata.public_keys_hex.iter().any(|public_key| {
                            public_key.eq_ignore_ascii_case(&signature.public_key_hex)
                        })
                    })
                    .collect::<Vec<_>>();
                matching.sort_by_key(|signature| {
                    metadata
                        .public_keys_hex
                        .iter()
                        .position(|public_key| {
                            public_key.eq_ignore_ascii_case(&signature.public_key_hex)
                        })
                        .unwrap_or(usize::MAX)
                });
                matching.dedup_by(|left, right| left.public_key_hex == right.public_key_hex);
                if matching.len() < usize::from(metadata.threshold) {
                    return Err(Error::InvalidTransaction(format!(
                        "input {} has {} valid multisig signatures, threshold is {}",
                        index,
                        matching.len(),
                        metadata.threshold
                    )));
                }
                let mut builder = Builder::new().push_int(0);
                for signature in matching.into_iter().take(usize::from(metadata.threshold)) {
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
        script_sigs.push((index, script_sig));
    }
    for (index, script_sig) in script_sigs {
        tx.input[index].script_sig = script_sig;
    }
    Ok(SignedTransaction {
        network: envelope.network,
        signed_tx_hex: hex::encode(serialize(&tx)),
    })
}

/// Whether an envelope must describe every transaction input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DescriptorCoverage {
    /// Signing and combining: a co-signer may only know about some inputs.
    Partial,
    /// Finalizing: every input needs a scriptSig.
    Complete,
}

/// One envelope input after structural validation.
struct ValidatedInput<'a> {
    descriptor: &'a SigningEnvelopeInput,
    /// Script committed to by the legacy sighash: the script pubkey for
    /// P2PKH, the redeem script for P2SH multisig.
    signing_script: bitcoin::ScriptBuf,
    /// 20-byte pubkey hash for P2PKH inputs.
    pubkey_hash: Option<[u8; 20]>,
    sighash_flag: u8,
    multisig: Option<MultisigMetadata>,
}

impl ValidatedInput<'_> {
    fn index(&self) -> usize {
        self.descriptor.input_index
    }

    fn controls(&self, public_key: &PublicKey) -> bool {
        match (&self.pubkey_hash, &self.multisig) {
            (Some(hash), _) => hash160_bytes(&public_key.serialize()) == *hash,
            (None, Some(metadata)) => {
                let hex = hex::encode(public_key.serialize());
                metadata
                    .public_keys_hex
                    .iter()
                    .any(|key| key.eq_ignore_ascii_case(&hex))
            }
            (None, None) => false,
        }
    }
}

/// Validates envelope structure, script consistency, and every present
/// signature. Returns inputs sorted by transaction input index.
fn validate_envelope<'a>(
    envelope: &'a SigningEnvelope,
    tx: &Transaction,
    coverage: DescriptorCoverage,
) -> Result<Vec<ValidatedInput<'a>>> {
    if envelope.version != 1 {
        return Err(Error::InvalidTransaction(format!(
            "unsupported signing envelope version {}",
            envelope.version
        )));
    }
    let mut descriptors: Vec<&SigningEnvelopeInput> = envelope.inputs.iter().collect();
    descriptors.sort_by_key(|input| input.input_index);
    if let Some(pair) = descriptors
        .windows(2)
        .find(|pair| pair[0].input_index == pair[1].input_index)
    {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope describes input {} more than once",
            pair[0].input_index
        )));
    }
    if let Some(out_of_range) = descriptors
        .iter()
        .find(|input| input.input_index >= tx.input.len())
    {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope input index {} out of range (transaction has {} inputs)",
            out_of_range.input_index,
            tx.input.len()
        )));
    }
    if coverage == DescriptorCoverage::Complete && descriptors.len() != tx.input.len() {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope must describe every transaction input (transaction has {} inputs, envelope describes {})",
            tx.input.len(),
            descriptors.len()
        )));
    }

    let mut validated = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let index = descriptor.input_index;
        let script_pubkey = parse_script(&descriptor.script_pubkey_hex)?;
        let sighash_flag = validated_sighash_flag(descriptor.sighash_type, index, tx.output.len())?;
        let input = match descriptor.kind {
            SigningInputKind::P2pkh => {
                if descriptor.redeem_script_hex.is_some() {
                    return Err(Error::InvalidTransaction(format!(
                        "P2PKH input {index} must not include a redeem script"
                    )));
                }
                let bytes = script_pubkey.as_bytes();
                let is_p2pkh = bytes.len() == 25
                    && bytes[0..3] == [0x76, 0xa9, 0x14]
                    && bytes[23..25] == [0x88, 0xac];
                if !is_p2pkh {
                    return Err(Error::InvalidTransaction(format!(
                        "P2PKH input {index} script pubkey is not a pay-to-pubkey-hash script"
                    )));
                }
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&bytes[3..23]);
                ValidatedInput {
                    descriptor,
                    signing_script: script_pubkey,
                    pubkey_hash: Some(hash),
                    sighash_flag,
                    multisig: None,
                }
            }
            SigningInputKind::P2shMultisig => {
                let redeem_script_hex =
                    descriptor.redeem_script_hex.as_deref().ok_or_else(|| {
                        Error::InvalidTransaction(format!(
                            "P2SH multisig input {index} requires redeem script"
                        ))
                    })?;
                let redeem_script = parse_script(redeem_script_hex)?;
                let mut expected = Vec::with_capacity(23);
                expected.extend_from_slice(&[0xa9, 0x14]);
                expected.extend_from_slice(&hash160_bytes(redeem_script.as_bytes()));
                expected.push(0x87);
                if script_pubkey.as_bytes() != expected.as_slice() {
                    return Err(Error::InvalidTransaction(format!(
                        "P2SH input {index} script pubkey does not match redeem script"
                    )));
                }
                let metadata = multisig_metadata(descriptor, redeem_script_hex)?;
                ValidatedInput {
                    descriptor,
                    signing_script: redeem_script,
                    pubkey_hash: None,
                    sighash_flag,
                    multisig: Some(metadata),
                }
            }
        };
        validated.push(input);
    }

    let secp = Secp256k1::verification_only();
    let cache = SighashCache::new(tx);
    for signature in &envelope.signatures {
        let index = signature.input_index;
        let input = match validated.iter().find(|input| input.index() == index) {
            Some(input) => input,
            None if index >= tx.input.len() => {
                return Err(Error::InvalidTransaction(format!(
                    "signature references input {index} which is out of range (transaction has {} inputs)",
                    tx.input.len()
                )));
            }
            // Only reachable under Partial coverage, because Complete coverage
            // describes every in-range input. A co-signer, or the transaction
            // builder (which signs one input at a time while carrying the
            // signatures already collected for other inputs), may hold
            // signatures for inputs this envelope does not describe. They cannot
            // be verified here because the signing script is unknown; they are
            // verified at finalization, which requires every input described.
            None => continue,
        };
        let public_key_bytes = hex::decode(&signature.public_key_hex)
            .map_err(|err| Error::Serialization(format!("invalid public key hex: {err}")))?;
        let public_key = PublicKey::from_slice(&public_key_bytes).map_err(|_| {
            Error::InvalidTransaction(format!(
                "signature for input {index} has an invalid public key"
            ))
        })?;
        if public_key_bytes.len() != 33 || !input.controls(&public_key) {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} was made by a key that does not control the input"
            )));
        }
        let signature_bytes = hex::decode(&signature.signature_hex)
            .map_err(|err| Error::Serialization(format!("invalid signature hex: {err}")))?;
        let (der, flag) = match signature_bytes.split_last() {
            Some((flag, der)) if !der.is_empty() => (der, *flag),
            _ => {
                return Err(Error::InvalidTransaction(format!(
                    "signature for input {index} is empty"
                )))
            }
        };
        if flag != input.sighash_flag {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} uses sighash type {flag:#x} but the input requires {:#x}",
                input.sighash_flag
            )));
        }
        let parsed = Signature::from_der(der).map_err(|_| {
            Error::InvalidTransaction(format!("signature for input {index} is not valid DER"))
        })?;
        let sighash = cache
            .legacy_signature_hash(
                index,
                input.signing_script.as_script(),
                input.descriptor.sighash_type,
            )
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        if secp.verify_ecdsa(&message, &parsed, &public_key).is_err() {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} does not verify against the transaction"
            )));
        }
    }
    Ok(validated)
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

struct MultisigMetadata {
    threshold: u8,
    public_keys_hex: Vec<String>,
}

fn multisig_metadata(
    input: &SigningEnvelopeInput,
    redeem_script_hex: &str,
) -> Result<MultisigMetadata> {
    let parsed = parse_multisig_redeem_script(redeem_script_hex)?;
    if let Some(threshold) = input.multisig_threshold {
        if threshold != parsed.threshold {
            return Err(Error::InvalidTransaction(
                "multisig threshold metadata does not match redeem script".to_owned(),
            ));
        }
    }
    if !input.multisig_public_keys_hex.is_empty()
        && (input.multisig_public_keys_hex.len() != parsed.public_keys_hex.len()
            || !input.multisig_public_keys_hex.iter().all(|key| {
                parsed
                    .public_keys_hex
                    .iter()
                    .any(|parsed_key| parsed_key.eq_ignore_ascii_case(key))
            }))
    {
        return Err(Error::InvalidTransaction(
            "multisig public key metadata does not match redeem script".to_owned(),
        ));
    }
    Ok(MultisigMetadata {
        threshold: input.multisig_threshold.unwrap_or(parsed.threshold),
        public_keys_hex: parsed.public_keys_hex,
    })
}

fn parse_multisig_redeem_script(redeem_script_hex: &str) -> Result<MultisigMetadata> {
    let bytes = hex::decode(redeem_script_hex)
        .map_err(|err| Error::Serialization(format!("invalid redeem script hex: {err}")))?;
    if bytes.len() < 3 {
        return Err(Error::InvalidTransaction(
            "invalid multisig redeem script".to_owned(),
        ));
    }
    let threshold = decode_pushnum(bytes[0])
        .ok_or_else(|| Error::InvalidTransaction("invalid multisig threshold opcode".to_owned()))?;
    let mut index = 1;
    let mut public_keys_hex = Vec::new();
    while index < bytes.len() {
        if (0x51..=0x60).contains(&bytes[index]) {
            break;
        }
        let push_len = usize::from(bytes[index]);
        index += 1;
        if push_len != 33 || index + push_len > bytes.len() {
            return Err(Error::InvalidTransaction(
                "invalid multisig public key push".to_owned(),
            ));
        }
        public_keys_hex.push(hex::encode(&bytes[index..index + push_len]));
        index += push_len;
    }
    if index + 2 != bytes.len() {
        return Err(Error::InvalidTransaction(
            "invalid multisig redeem script length".to_owned(),
        ));
    }
    let cosigner_count = decode_pushnum(bytes[index]).ok_or_else(|| {
        Error::InvalidTransaction("invalid multisig cosigner count opcode".to_owned())
    })?;
    if usize::from(cosigner_count) != public_keys_hex.len() {
        return Err(Error::InvalidTransaction(
            "multisig public key count does not match redeem script".to_owned(),
        ));
    }
    if bytes[index + 1] != 0xae {
        return Err(Error::InvalidTransaction(
            "multisig redeem script must end with OP_CHECKMULTISIG".to_owned(),
        ));
    }
    if threshold == 0 || threshold > cosigner_count {
        return Err(Error::InvalidTransaction(
            "invalid multisig threshold".to_owned(),
        ));
    }
    Ok(MultisigMetadata {
        threshold,
        public_keys_hex,
    })
}

fn decode_pushnum(opcode: u8) -> Option<u8> {
    if (0x51..=0x60).contains(&opcode) {
        Some(opcode - 0x50)
    } else {
        None
    }
}
