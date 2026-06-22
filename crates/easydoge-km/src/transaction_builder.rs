use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::serialize;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fmt;
use std::str::FromStr;

use crate::encoding::{base58check_decode, hash160_bytes, wif};
use crate::keys::{decode_xpriv, derive_path_from_xpriv, secret_key_from_wif, Xpriv};
use crate::signing::{
    finalize_signing_envelope, sign_signing_envelope, SigningEnvelope, SigningEnvelopeInput,
    SigningEnvelopeSignature, SigningInputKind,
};
use crate::{Error, Network, Result};

const DEFAULT_SEQUENCE: u32 = 0xffff_ffff;
const DEFAULT_SIGHASH_ALL: u32 = 1;
const OP_RETURN_STANDARD_DATA_LIMIT_BYTES: usize = 80;
const MAX_SIGNATURE_PUSH_BYTES: usize = 73;
const COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeTransactionRequest {
    pub network: Network,
    pub utxos: Vec<SpendableUtxo>,
    pub outputs: Vec<TransactionOutput>,
    pub fee_policy: FeePolicy,
    pub coin_selection: CoinSelectionStrategy,
    pub change: Option<ChangeDestination>,
    pub options: TransactionOptions,
}

impl fmt::Debug for ComposeTransactionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComposeTransactionRequest")
            .field("network", &self.network)
            .field("utxos", &self.utxos)
            .field("outputs", &self.outputs)
            .field("fee_policy", &self.fee_policy)
            .field("coin_selection", &self.coin_selection)
            .field("change", &self.change)
            .field("options", &self.options)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendableUtxo {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub script_pubkey_hex: String,
    pub kind: SigningInputKind,
    pub redeem_script_hex: Option<String>,
    pub multisig_threshold: Option<u8>,
    #[serde(default)]
    pub multisig_public_keys_hex: Vec<String>,
    #[serde(default)]
    pub signers: Vec<UtxoSigner>,
    #[serde(default)]
    pub manually_selected: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoSigner {
    pub kind: UtxoSignerKind,
    pub wif: Option<String>,
    pub xpriv: Option<Xpriv>,
    pub derivation_path: Option<String>,
}

impl fmt::Debug for UtxoSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UtxoSigner")
            .field("kind", &self.kind)
            .field("wif", &self.wif.as_ref().map(|_| "[redacted]"))
            .field("xpriv", &self.xpriv.as_ref().map(|_| "[redacted]"))
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UtxoSignerKind {
    Wif,
    XprivDerivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub kind: TransactionOutputKind,
    pub value_koinu: u64,
    pub address: Option<String>,
    pub op_return_data_hex: Option<String>,
    pub script_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionOutputKind {
    Address,
    OpReturn,
    ExpertRawScript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    pub fee_rate_koinu_per_kb: u64,
    pub dust_threshold_koinu: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoinSelectionStrategy {
    MinInputs,
    SmallestFirst,
    LargestFirst,
    ManualSelectedInputs,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeDestination {
    pub address: Option<String>,
    pub xpriv: Option<Xpriv>,
    pub derivation_path: Option<String>,
}

impl fmt::Debug for ChangeDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeDestination")
            .field("address", &self.address)
            .field("xpriv", &self.xpriv.as_ref().map(|_| "[redacted]"))
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOptions {
    pub version: i32,
    pub lock_time: u32,
    pub sequence: u32,
    pub sighash_type: u32,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            version: 1,
            lock_time: 0,
            sequence: DEFAULT_SEQUENCE,
            sighash_type: DEFAULT_SIGHASH_ALL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeTransactionResult {
    pub network: Network,
    pub selected_inputs: Vec<AuditedInput>,
    pub skipped_inputs: Vec<SkippedInput>,
    pub input_total_koinu: u64,
    pub spend_output_total_koinu: u64,
    pub change_amount_koinu: u64,
    pub change_address: Option<String>,
    pub change_script_pubkey_hex: Option<String>,
    pub fee_koinu: u64,
    pub estimated_size_bytes: u64,
    pub actual_size_bytes: Option<u64>,
    pub dust_change_folded_into_fee: bool,
    pub unsigned_tx_hex: String,
    pub signed_tx_hex: Option<String>,
    pub signing_envelope: Option<SigningEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditedInput {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub script_pubkey_hex: String,
    pub kind: SigningInputKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedInput {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub reason: String,
}

struct PreparedOutput {
    txout: TxOut,
    spend_value_koinu: u64,
    script_pubkey_hex: String,
}

struct FundingResult {
    selected_indices: Vec<usize>,
    skipped_inputs: Vec<SkippedInput>,
    fee_koinu: u64,
    estimated_size_bytes: u64,
    change_amount_koinu: u64,
    change_script: Option<ScriptBuf>,
    dust_change_folded_into_fee: bool,
}

struct ResolvedSigner {
    public_key_hex: String,
    public_key: PublicKey,
    wif: String,
}

pub fn compose_and_sign_transaction(
    request: &ComposeTransactionRequest,
) -> Result<ComposeTransactionResult> {
    validate_request(request)?;
    let prepared_outputs = prepare_outputs(request)?;
    let spend_output_total_koinu = prepared_outputs
        .iter()
        .map(|output| output.spend_value_koinu)
        .try_fold(0u64, checked_add)?;
    let funding = fund_transaction(request, &prepared_outputs)?;

    let mut outputs = prepared_outputs
        .into_iter()
        .map(|output| output.txout)
        .collect::<Vec<_>>();
    let (change_address, change_script_pubkey_hex) = match &funding.change_script {
        Some(script) => {
            outputs.push(TxOut {
                value: Amount::from_sat(funding.change_amount_koinu),
                script_pubkey: script.clone(),
            });
            (
                change_address(request)?,
                Some(hex::encode(script.as_bytes())),
            )
        }
        None => (None, None),
    };

    let selected_utxos = funding
        .selected_indices
        .iter()
        .map(|index| request.utxos[*index].clone())
        .collect::<Vec<_>>();
    let tx = build_unsigned_transaction(request, &selected_utxos, outputs)?;
    let unsigned_tx_hex = hex::encode(serialize(&tx));
    let mut envelope = SigningEnvelope {
        version: 1,
        network: request.network,
        unsigned_tx_hex: unsigned_tx_hex.clone(),
        inputs: selected_utxos
            .iter()
            .enumerate()
            .map(|(input_index, utxo)| SigningEnvelopeInput {
                input_index,
                kind: utxo.kind.clone(),
                script_pubkey_hex: utxo.script_pubkey_hex.clone(),
                redeem_script_hex: utxo.redeem_script_hex.clone(),
                sighash_type: request.options.sighash_type,
                previous_output_value_koinu: Some(utxo.previous_output_value_koinu),
                multisig_threshold: utxo.multisig_threshold,
                multisig_public_keys_hex: utxo.multisig_public_keys_hex.clone(),
            })
            .collect(),
        signatures: vec![],
    };

    for (input_index, utxo) in selected_utxos.iter().enumerate() {
        let signers = resolve_valid_signers(request.network, utxo)?;
        for signer in signers {
            let single_input_envelope = SigningEnvelope {
                version: envelope.version,
                network: envelope.network,
                unsigned_tx_hex: envelope.unsigned_tx_hex.clone(),
                inputs: vec![envelope.inputs[input_index].clone()],
                signatures: envelope.signatures.clone(),
            };
            let signed_partial = sign_signing_envelope(&single_input_envelope, &signer.wif)?;
            envelope.signatures = signed_partial.signatures;
        }
    }
    envelope.signatures = dedupe_signatures(envelope.signatures);

    let signed = if envelope_is_complete(&envelope)? {
        Some(finalize_signing_envelope(&envelope)?)
    } else {
        None
    };
    let actual_size_bytes = signed
        .as_ref()
        .map(|signed| signed.signed_tx_hex.len() as u64 / 2);

    Ok(ComposeTransactionResult {
        network: request.network,
        selected_inputs: selected_utxos.iter().map(AuditedInput::from).collect(),
        skipped_inputs: funding.skipped_inputs,
        input_total_koinu: selected_utxos
            .iter()
            .map(|utxo| utxo.previous_output_value_koinu)
            .try_fold(0u64, checked_add)?,
        spend_output_total_koinu,
        change_amount_koinu: funding.change_amount_koinu,
        change_address,
        change_script_pubkey_hex,
        fee_koinu: funding.fee_koinu,
        estimated_size_bytes: funding.estimated_size_bytes,
        actual_size_bytes,
        dust_change_folded_into_fee: funding.dust_change_folded_into_fee,
        unsigned_tx_hex,
        signed_tx_hex: signed.map(|signed| signed.signed_tx_hex),
        signing_envelope: if envelope_is_complete(&envelope)? {
            None
        } else {
            Some(envelope)
        },
    })
}

fn validate_request(request: &ComposeTransactionRequest) -> Result<()> {
    if request.utxos.is_empty() {
        return Err(Error::InvalidTransaction(
            "at least one UTXO is required".to_owned(),
        ));
    }
    if request.outputs.is_empty() {
        return Err(Error::InvalidTransaction(
            "at least one output is required".to_owned(),
        ));
    }
    if request.fee_policy.fee_rate_koinu_per_kb == 0 {
        return Err(Error::InvalidTransaction(
            "fee rate must be greater than zero".to_owned(),
        ));
    }
    if request.options.version <= 0 {
        return Err(Error::InvalidTransaction(
            "transaction version must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn prepare_outputs(request: &ComposeTransactionRequest) -> Result<Vec<PreparedOutput>> {
    request
        .outputs
        .iter()
        .map(|output| {
            let script = match output.kind {
                TransactionOutputKind::Address => {
                    if output.value_koinu < request.fee_policy.dust_threshold_koinu {
                        return Err(Error::InvalidTransaction(
                            "address output is below dust threshold".to_owned(),
                        ));
                    }
                    let address = output.address.as_deref().ok_or_else(|| {
                        Error::InvalidAddress("address output requires address".to_owned())
                    })?;
                    script_pubkey_from_address(request.network, address)?
                }
                TransactionOutputKind::OpReturn => {
                    if output.value_koinu != 0 {
                        return Err(Error::InvalidTransaction(
                            "OP_RETURN outputs must have zero value".to_owned(),
                        ));
                    }
                    let data_hex = output.op_return_data_hex.as_deref().ok_or_else(|| {
                        Error::InvalidTransaction("OP_RETURN output requires data hex".to_owned())
                    })?;
                    op_return_script(data_hex)?
                }
                TransactionOutputKind::ExpertRawScript => {
                    if output.value_koinu < request.fee_policy.dust_threshold_koinu {
                        return Err(Error::InvalidTransaction(
                            "ExpertRawScript output is below dust threshold".to_owned(),
                        ));
                    }
                    let script_hex = output.script_hex.as_deref().ok_or_else(|| {
                        Error::InvalidTransaction(
                            "ExpertRawScript output requires script hex".to_owned(),
                        )
                    })?;
                    parse_script(script_hex)?
                }
            };
            Ok(PreparedOutput {
                txout: TxOut {
                    value: Amount::from_sat(output.value_koinu),
                    script_pubkey: script.clone(),
                },
                spend_value_koinu: output.value_koinu,
                script_pubkey_hex: hex::encode(script.as_bytes()),
            })
        })
        .collect()
}

fn fund_transaction(
    request: &ComposeTransactionRequest,
    outputs: &[PreparedOutput],
) -> Result<FundingResult> {
    let spend_total = outputs
        .iter()
        .map(|output| output.spend_value_koinu)
        .try_fold(0u64, checked_add)?;
    let mut selected_indices = Vec::new();
    let mut skipped_inputs = Vec::new();
    let ordered = ordered_utxo_indices(request);

    for index in ordered {
        let utxo = &request.utxos[index];
        if request.coin_selection == CoinSelectionStrategy::ManualSelectedInputs
            && !utxo.manually_selected
        {
            skipped_inputs.push(skipped(utxo, "not manually selected"));
            continue;
        }
        validate_utxo(request.network, utxo)?;
        selected_indices.push(index);
        if let Some(funding) =
            funding_for_selection(request, outputs, &selected_indices, spend_total)?
        {
            skipped_inputs.extend(
                request
                    .utxos
                    .iter()
                    .enumerate()
                    .filter(|(candidate, _)| !selected_indices.contains(candidate))
                    .filter(|(_, candidate)| {
                        request.coin_selection != CoinSelectionStrategy::ManualSelectedInputs
                            || candidate.manually_selected
                    })
                    .map(|(_, candidate)| skipped(candidate, "not selected by strategy")),
            );
            return Ok(FundingResult {
                selected_indices,
                skipped_inputs,
                ..funding
            });
        }
    }

    Err(Error::InvalidTransaction(
        "insufficient funds for outputs and fee".to_owned(),
    ))
}

fn funding_for_selection(
    request: &ComposeTransactionRequest,
    outputs: &[PreparedOutput],
    selected_indices: &[usize],
    spend_total: u64,
) -> Result<Option<FundingResult>> {
    let input_total = selected_indices
        .iter()
        .map(|index| request.utxos[*index].previous_output_value_koinu)
        .try_fold(0u64, checked_add)?;
    let output_scripts = outputs
        .iter()
        .map(|output| output.script_pubkey_hex.as_str())
        .collect::<Vec<_>>();
    let no_change_size = estimate_size_bytes(request, selected_indices, &output_scripts, None)?;
    let no_change_fee = fee_for_size(no_change_size, request.fee_policy.fee_rate_koinu_per_kb)?;
    if input_total < checked_add(spend_total, no_change_fee)? {
        return Ok(None);
    }
    let remainder_without_change = input_total - spend_total - no_change_fee;
    if remainder_without_change < request.fee_policy.dust_threshold_koinu {
        return Ok(Some(FundingResult {
            selected_indices: selected_indices.to_vec(),
            skipped_inputs: vec![],
            fee_koinu: input_total - spend_total,
            estimated_size_bytes: no_change_size,
            change_amount_koinu: 0,
            change_script: None,
            dust_change_folded_into_fee: remainder_without_change > 0,
        }));
    }

    let change_script = change_script(request)?;
    let with_change_size = estimate_size_bytes(
        request,
        selected_indices,
        &output_scripts,
        Some(&change_script),
    )?;
    let with_change_fee = fee_for_size(with_change_size, request.fee_policy.fee_rate_koinu_per_kb)?;
    if input_total < checked_add(spend_total, with_change_fee)? {
        return Ok(None);
    }
    let change_amount = input_total - spend_total - with_change_fee;
    if change_amount < request.fee_policy.dust_threshold_koinu {
        return Ok(Some(FundingResult {
            selected_indices: selected_indices.to_vec(),
            skipped_inputs: vec![],
            fee_koinu: input_total - spend_total,
            estimated_size_bytes: no_change_size,
            change_amount_koinu: 0,
            change_script: None,
            dust_change_folded_into_fee: change_amount > 0,
        }));
    }
    Ok(Some(FundingResult {
        selected_indices: selected_indices.to_vec(),
        skipped_inputs: vec![],
        fee_koinu: with_change_fee,
        estimated_size_bytes: with_change_size,
        change_amount_koinu: change_amount,
        change_script: Some(change_script),
        dust_change_folded_into_fee: false,
    }))
}

fn ordered_utxo_indices(request: &ComposeTransactionRequest) -> Vec<usize> {
    let mut indices = (0..request.utxos.len()).collect::<Vec<_>>();
    match request.coin_selection {
        CoinSelectionStrategy::MinInputs | CoinSelectionStrategy::LargestFirst => {
            indices.sort_by_key(|index| {
                let utxo = &request.utxos[*index];
                (
                    Reverse(utxo.previous_output_value_koinu),
                    utxo.txid.clone(),
                    utxo.vout,
                )
            });
        }
        CoinSelectionStrategy::SmallestFirst | CoinSelectionStrategy::ManualSelectedInputs => {
            indices.sort_by_key(|index| {
                let utxo = &request.utxos[*index];
                (
                    utxo.previous_output_value_koinu,
                    utxo.txid.clone(),
                    utxo.vout,
                )
            });
        }
    }
    indices
}

fn validate_utxo(network: Network, utxo: &SpendableUtxo) -> Result<()> {
    parse_txid(&utxo.txid)?;
    parse_script(&utxo.script_pubkey_hex)?;
    match utxo.kind {
        SigningInputKind::P2pkh => {
            if utxo.redeem_script_hex.is_some() {
                return Err(Error::InvalidTransaction(
                    "P2PKH UTXO must not include redeem script".to_owned(),
                ));
            }
        }
        SigningInputKind::P2shMultisig => {
            let redeem_script_hex = utxo.redeem_script_hex.as_deref().ok_or_else(|| {
                Error::InvalidTransaction("P2SH multisig UTXO requires redeem script".to_owned())
            })?;
            let redeem_script = parse_script(redeem_script_hex)?;
            let expected = p2sh_script_pubkey(redeem_script.as_bytes());
            if hex::encode(expected.as_bytes()) != utxo.script_pubkey_hex.to_ascii_lowercase() {
                return Err(Error::InvalidTransaction(
                    "P2SH script pubkey does not match redeem script".to_owned(),
                ));
            }
            if let Some(threshold) = utxo.multisig_threshold {
                if threshold == 0 {
                    return Err(Error::InvalidTransaction(
                        "multisig threshold must be greater than zero".to_owned(),
                    ));
                }
            }
            if !utxo.multisig_public_keys_hex.is_empty()
                && usize::from(utxo.multisig_threshold.unwrap_or(0))
                    > utxo.multisig_public_keys_hex.len()
            {
                return Err(Error::InvalidTransaction(
                    "multisig threshold exceeds public key count".to_owned(),
                ));
            }
        }
    }
    for signer in &utxo.signers {
        let resolved = resolve_signer(network, signer)?;
        validate_signer_ownership(utxo, &resolved)?;
    }
    Ok(())
}

fn build_unsigned_transaction(
    request: &ComposeTransactionRequest,
    selected_utxos: &[SpendableUtxo],
    outputs: Vec<TxOut>,
) -> Result<Transaction> {
    let input = selected_utxos
        .iter()
        .map(|utxo| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: parse_txid(&utxo.txid)?,
                    vout: utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(request.options.sequence),
                witness: Witness::default(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Transaction {
        version: Version(request.options.version),
        lock_time: LockTime::from_consensus(request.options.lock_time),
        input,
        output: outputs,
    })
}

fn resolve_valid_signers(network: Network, utxo: &SpendableUtxo) -> Result<Vec<ResolvedSigner>> {
    utxo.signers
        .iter()
        .map(|signer| {
            let resolved = resolve_signer(network, signer)?;
            validate_signer_ownership(utxo, &resolved)?;
            Ok(resolved)
        })
        .collect()
}

fn resolve_signer(network: Network, signer: &UtxoSigner) -> Result<ResolvedSigner> {
    let wif_value = match signer.kind {
        UtxoSignerKind::Wif => signer.wif.clone().ok_or_else(|| {
            Error::InvalidKey("WIF signer requires redacted WIF field".to_owned())
        })?,
        UtxoSignerKind::XprivDerivation => {
            let xpriv = signer.xpriv.as_ref().ok_or_else(|| {
                Error::InvalidKey("xpriv derivation signer requires xpriv".to_owned())
            })?;
            if xpriv.network != network {
                return Err(Error::InvalidNetwork(
                    "signer xpriv network mismatch".to_owned(),
                ));
            }
            let path = signer.derivation_path.as_deref().ok_or_else(|| {
                Error::InvalidDerivationPath(
                    "xpriv derivation signer requires derivation path".to_owned(),
                )
            })?;
            let child = derive_path_from_xpriv(xpriv, path)?;
            let child_key = decode_xpriv(network, &child.encoded)?;
            wif(network, &child_key.private_key.secret_bytes(), true)
        }
    };
    let secret_key = secret_key_from_wif(&wif_value, network)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(ResolvedSigner {
        public_key_hex: hex::encode(public_key.serialize()),
        public_key,
        wif: wif_value,
    })
}

fn validate_signer_ownership(utxo: &SpendableUtxo, signer: &ResolvedSigner) -> Result<()> {
    match utxo.kind {
        SigningInputKind::P2pkh => {
            let expected = p2pkh_script_pubkey(&hash160_bytes(&signer.public_key.serialize()));
            if hex::encode(expected.as_bytes()) != utxo.script_pubkey_hex.to_ascii_lowercase() {
                return Err(Error::InvalidKey(format!(
                    "signer public key does not match P2PKH UTXO {}:{}",
                    utxo.txid, utxo.vout
                )));
            }
        }
        SigningInputKind::P2shMultisig => {
            if !utxo.multisig_public_keys_hex.is_empty()
                && !utxo
                    .multisig_public_keys_hex
                    .iter()
                    .any(|key| key.eq_ignore_ascii_case(&signer.public_key_hex))
            {
                return Err(Error::InvalidKey(format!(
                    "signer public key is not in multisig descriptor for UTXO {}:{}",
                    utxo.txid, utxo.vout
                )));
            }
            let redeem_script =
                parse_script(utxo.redeem_script_hex.as_deref().ok_or_else(|| {
                    Error::InvalidTransaction(
                        "P2SH multisig UTXO requires redeem script".to_owned(),
                    )
                })?)?;
            if !redeem_script
                .as_bytes()
                .windows(COMPRESSED_PUBLIC_KEY_BYTES)
                .any(|window| window == signer.public_key.serialize())
            {
                return Err(Error::InvalidKey(format!(
                    "signer public key is not in redeem script for UTXO {}:{}",
                    utxo.txid, utxo.vout
                )));
            }
        }
    }
    Ok(())
}

fn envelope_is_complete(envelope: &SigningEnvelope) -> Result<bool> {
    envelope.inputs.iter().try_fold(true, |complete, input| {
        let matching = envelope
            .signatures
            .iter()
            .filter(|signature| signature.input_index == input.input_index)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Ok(false);
        }
        match input.kind {
            SigningInputKind::P2pkh => Ok(complete),
            SigningInputKind::P2shMultisig => {
                let threshold = input.multisig_threshold.ok_or_else(|| {
                    Error::InvalidTransaction(
                        "P2SH multisig completion requires threshold metadata".to_owned(),
                    )
                })?;
                let expected = &input.multisig_public_keys_hex;
                if expected.is_empty() {
                    return Err(Error::InvalidTransaction(
                        "P2SH multisig completion requires expected public keys".to_owned(),
                    ));
                }
                let valid_count = matching
                    .iter()
                    .filter(|signature| {
                        expected
                            .iter()
                            .any(|key| key.eq_ignore_ascii_case(signature.public_key_hex.as_str()))
                    })
                    .count();
                Ok(complete && valid_count >= usize::from(threshold))
            }
        }
    })
}

fn estimate_size_bytes(
    request: &ComposeTransactionRequest,
    selected_indices: &[usize],
    output_script_hexes: &[&str],
    change_script: Option<&ScriptBuf>,
) -> Result<u64> {
    let input_count = selected_indices.len();
    let output_count = output_script_hexes.len() + usize::from(change_script.is_some());
    let mut size = 4 + varint_len(input_count) + varint_len(output_count) + 4;
    for index in selected_indices {
        size += estimated_input_size(&request.utxos[*index])?;
    }
    for script_hex in output_script_hexes {
        let script_len = hex::decode(script_hex)
            .map_err(|err| Error::Serialization(format!("invalid script hex: {err}")))?
            .len();
        size += 8 + varint_len(script_len) + script_len;
    }
    if let Some(script) = change_script {
        size += 8 + varint_len(script.len()) + script.len();
    }
    Ok(size as u64)
}

fn estimated_input_size(utxo: &SpendableUtxo) -> Result<usize> {
    let script_sig_len = match utxo.kind {
        SigningInputKind::P2pkh => 1 + MAX_SIGNATURE_PUSH_BYTES + 1 + COMPRESSED_PUBLIC_KEY_BYTES,
        SigningInputKind::P2shMultisig => {
            let threshold = utxo.multisig_threshold.ok_or_else(|| {
                Error::InvalidTransaction(
                    "P2SH multisig input size requires threshold metadata".to_owned(),
                )
            })? as usize;
            let redeem_script_len =
                parse_script(utxo.redeem_script_hex.as_deref().ok_or_else(|| {
                    Error::InvalidTransaction(
                        "P2SH multisig UTXO requires redeem script".to_owned(),
                    )
                })?)?
                .len();
            1 + threshold * (1 + MAX_SIGNATURE_PUSH_BYTES)
                + script_push_prefix_len(redeem_script_len)
                + redeem_script_len
        }
    };
    Ok(32 + 4 + varint_len(script_sig_len) + script_sig_len + 4)
}

fn fee_for_size(size_bytes: u64, fee_rate_koinu_per_kb: u64) -> Result<u64> {
    let product = size_bytes
        .checked_mul(fee_rate_koinu_per_kb)
        .ok_or_else(|| Error::InvalidTransaction("fee calculation overflow".to_owned()))?;
    Ok(product.div_ceil(1000))
}

fn change_script(request: &ComposeTransactionRequest) -> Result<ScriptBuf> {
    let change = request.change.as_ref().ok_or_else(|| {
        Error::InvalidTransaction(
            "change destination is required when change is not dust".to_owned(),
        )
    })?;
    if let Some(address) = change.address.as_deref() {
        return script_pubkey_from_address(request.network, address);
    }
    let xpriv = change.xpriv.as_ref().ok_or_else(|| {
        Error::InvalidTransaction("change requires address or derivation xpriv".to_owned())
    })?;
    if xpriv.network != request.network {
        return Err(Error::InvalidNetwork(
            "change xpriv network mismatch".to_owned(),
        ));
    }
    let path = change.derivation_path.as_deref().ok_or_else(|| {
        Error::InvalidDerivationPath("change derivation requires path".to_owned())
    })?;
    let child = derive_path_from_xpriv(xpriv, path)?;
    let child_key = decode_xpriv(request.network, &child.encoded)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &child_key.private_key);
    Ok(p2pkh_script_pubkey(&hash160_bytes(&public_key.serialize())))
}

fn change_address(request: &ComposeTransactionRequest) -> Result<Option<String>> {
    let Some(change) = request.change.as_ref() else {
        return Ok(None);
    };
    if let Some(address) = change.address.clone() {
        return Ok(Some(address));
    }
    let xpriv = change.xpriv.as_ref().ok_or_else(|| {
        Error::InvalidTransaction("change requires address or derivation xpriv".to_owned())
    })?;
    let path = change.derivation_path.as_deref().ok_or_else(|| {
        Error::InvalidDerivationPath("change derivation requires path".to_owned())
    })?;
    Ok(Some(
        crate::keys::derive_address_from_xpriv(xpriv, path)?.address,
    ))
}

fn script_pubkey_from_address(network: Network, address: &str) -> Result<ScriptBuf> {
    let data = base58check_decode(address).map_err(|err| Error::InvalidAddress(err.to_string()))?;
    if data.len() != 21 {
        return Err(Error::InvalidAddress(
            "address payload must be 20 bytes plus prefix".to_owned(),
        ));
    }
    let prefixes = network.prefixes();
    let payload: [u8; 20] = data[1..21].try_into().expect("slice length checked");
    if data[0] == prefixes.p2pkh {
        Ok(p2pkh_script_pubkey(&payload))
    } else if data[0] == prefixes.p2sh {
        Ok(p2sh_script_pubkey_from_hash(&payload))
    } else {
        Err(Error::InvalidAddress(
            "address prefix does not match network".to_owned(),
        ))
    }
}

fn op_return_script(data_hex: &str) -> Result<ScriptBuf> {
    let data = hex::decode(data_hex)
        .map_err(|err| Error::Serialization(format!("invalid OP_RETURN data hex: {err}")))?;
    if data.len() > OP_RETURN_STANDARD_DATA_LIMIT_BYTES {
        return Err(Error::InvalidTransaction(format!(
            "OP_RETURN data exceeds {OP_RETURN_STANDARD_DATA_LIMIT_BYTES} bytes"
        )));
    }
    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_bytes(data)?)
        .into_script())
}

fn parse_script(script_hex: &str) -> Result<ScriptBuf> {
    let bytes = hex::decode(script_hex)
        .map_err(|err| Error::Serialization(format!("invalid script hex: {err}")))?;
    Ok(ScriptBuf::from_bytes(bytes))
}

fn parse_txid(txid: &str) -> Result<Txid> {
    Txid::from_str(txid)
        .map_err(|err| Error::InvalidTransaction(format!("invalid display txid hex: {err}")))
}

fn p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(25);
    bytes.extend_from_slice(&[0x76, 0xa9, 0x14]);
    bytes.extend_from_slice(pubkey_hash);
    bytes.extend_from_slice(&[0x88, 0xac]);
    ScriptBuf::from_bytes(bytes)
}

fn p2sh_script_pubkey(redeem_script: &[u8]) -> ScriptBuf {
    p2sh_script_pubkey_from_hash(&hash160_bytes(redeem_script))
}

fn p2sh_script_pubkey_from_hash(script_hash: &[u8; 20]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(23);
    bytes.extend_from_slice(&[0xa9, 0x14]);
    bytes.extend_from_slice(script_hash);
    bytes.push(0x87);
    ScriptBuf::from_bytes(bytes)
}

fn push_bytes(bytes: Vec<u8>) -> Result<PushBytesBuf> {
    PushBytesBuf::try_from(bytes).map_err(|err| Error::Serialization(err.to_string()))
}

fn varint_len(value: usize) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn script_push_prefix_len(value: usize) -> usize {
    match value {
        0..=0x4b => 1,
        0x4c..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

fn checked_add(lhs: u64, rhs: u64) -> Result<u64> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::InvalidTransaction("amount overflow".to_owned()))
}

fn skipped(utxo: &SpendableUtxo, reason: &str) -> SkippedInput {
    SkippedInput {
        txid: utxo.txid.clone(),
        vout: utxo.vout,
        previous_output_value_koinu: utxo.previous_output_value_koinu,
        reason: reason.to_owned(),
    }
}

fn dedupe_signatures(signatures: Vec<SigningEnvelopeSignature>) -> Vec<SigningEnvelopeSignature> {
    signatures.into_iter().fold(Vec::new(), |mut unique, sig| {
        if !unique.iter().any(|existing: &SigningEnvelopeSignature| {
            existing.input_index == sig.input_index
                && existing.public_key_hex == sig.public_key_hex
                && existing.signature_hex == sig.signature_hex
        }) {
            unique.push(sig);
        }
        unique
    })
}

impl From<&SpendableUtxo> for AuditedInput {
    fn from(value: &SpendableUtxo) -> Self {
        Self {
            txid: value.txid.clone(),
            vout: value.vout,
            previous_output_value_koinu: value.previous_output_value_koinu,
            script_pubkey_hex: value.script_pubkey_hex.clone(),
            kind: value.kind.clone(),
        }
    }
}
