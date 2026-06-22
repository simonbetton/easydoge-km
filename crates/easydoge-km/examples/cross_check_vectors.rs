use bitcoin::hashes::{hash160, Hash};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, derive_address_from_xpriv,
    derive_address_from_xpub, derive_path_from_xpriv, derive_path_from_xpub, mnemonic_to_seed_hex,
    sign_message, sign_p2pkh_transaction, validate_mnemonic, verify_message, wif_from_xpriv,
    xpub_from_xpriv, Language, Network, Xpub,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct CrossCheckInput {
    version: u32,
    mnemonics: Vec<MnemonicCase>,
    bip44_cases: Vec<Bip44Case>,
    message_cases: Vec<MessageCase>,
    transaction_cases: Vec<TransactionCase>,
    multisig_cases: Vec<MultisigCase>,
}

#[derive(Debug, Deserialize)]
struct MnemonicCase {
    id: String,
    language: String,
    phrase: String,
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct Bip44Case {
    id: String,
    mnemonic_id: String,
    network: String,
    account: u32,
    child_paths: Vec<String>,
    hardened_public_path: String,
}

#[derive(Debug, Deserialize)]
struct MessageCase {
    id: String,
    bip44_case_id: String,
    signer_path: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TransactionCase {
    id: String,
    bip44_case_id: String,
    signer_path: String,
    unsigned_tx_hex: String,
    input_index: usize,
    sighash_type: u32,
}

#[derive(Debug, Deserialize)]
struct MultisigCase {
    id: String,
    network: String,
    threshold: u8,
    cosigner_bip44_case_ids: Vec<String>,
    child_path: String,
    sorted: bool,
}

fn main() -> easydoge_km::Result<()> {
    let mut args = env::args().skip(1);
    let input_path = args.next().ok_or_else(|| {
        easydoge_km::Error::InvalidKey("missing input cross-check JSON path".to_owned())
    })?;
    let output_path = args.next().ok_or_else(|| {
        easydoge_km::Error::InvalidKey("missing output cross-check JSON path".to_owned())
    })?;

    let input = read_input(&input_path)?;
    let mnemonic_cases = input
        .mnemonics
        .iter()
        .map(|case| Ok((case.id.clone(), emit_mnemonic(case)?)))
        .collect::<easydoge_km::Result<BTreeMap<_, _>>>()?;

    let mnemonic_by_id = input
        .mnemonics
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let bip44_by_id = input
        .bip44_cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();

    let bip44_cases = input
        .bip44_cases
        .iter()
        .map(|case| emit_bip44(case, &mnemonic_by_id))
        .collect::<easydoge_km::Result<Vec<_>>>()?;
    let message_cases = input
        .message_cases
        .iter()
        .map(|case| emit_message(case, &mnemonic_by_id, &bip44_by_id))
        .collect::<easydoge_km::Result<Vec<_>>>()?;
    let transaction_cases = input
        .transaction_cases
        .iter()
        .map(|case| emit_transaction(case, &mnemonic_by_id, &bip44_by_id))
        .collect::<easydoge_km::Result<Vec<_>>>()?;
    let multisig_cases = input
        .multisig_cases
        .iter()
        .map(|case| emit_multisig(case, &mnemonic_by_id, &bip44_by_id))
        .collect::<easydoge_km::Result<Vec<_>>>()?;

    let output = json!({
        "version": input.version,
        "mnemonics": mnemonic_cases,
        "bip44_cases": bip44_cases,
        "message_cases": message_cases,
        "transaction_cases": transaction_cases,
        "multisig_cases": multisig_cases,
    });

    if let Some(parent) = Path::new(&output_path).parent() {
        fs::create_dir_all(parent)
            .map_err(|err| easydoge_km::Error::InvalidKey(err.to_string()))?;
    }
    fs::write(
        &output_path,
        serde_json::to_string_pretty(&output).map_err(json_error)?,
    )
    .map_err(|err| easydoge_km::Error::InvalidKey(err.to_string()))?;
    Ok(())
}

fn read_input(path: &str) -> easydoge_km::Result<CrossCheckInput> {
    let contents =
        fs::read_to_string(path).map_err(|err| easydoge_km::Error::InvalidKey(err.to_string()))?;
    serde_json::from_str(&contents).map_err(json_error)
}

fn emit_mnemonic(case: &MnemonicCase) -> easydoge_km::Result<serde_json::Value> {
    let language = Language::from_str(&case.language)?;
    Ok(json!({
        "id": case.id,
        "language": case.language,
        "valid": validate_mnemonic(&case.phrase, language)?,
        "seed_hex": mnemonic_to_seed_hex(&case.phrase, Some(&case.passphrase), language)?,
    }))
}

fn emit_bip44(
    case: &Bip44Case,
    mnemonic_by_id: &BTreeMap<&str, &MnemonicCase>,
) -> easydoge_km::Result<serde_json::Value> {
    let mnemonic = mnemonic_by_id
        .get(case.mnemonic_id.as_str())
        .ok_or_else(|| {
            easydoge_km::Error::InvalidKey(format!("unknown mnemonic case {}", case.mnemonic_id))
        })?;
    let language = Language::from_str(&mnemonic.language)?;
    let network = Network::from_str(&case.network)?;
    let account = account_xpriv_from_mnemonic(
        &mnemonic.phrase,
        Some(&mnemonic.passphrase),
        language,
        network,
        case.account,
    )?;

    let children = case
        .child_paths
        .iter()
        .map(|path| {
            let child_xpriv = derive_path_from_xpriv(&account.xpriv, path)?;
            let child_xpub_from_xpriv = xpub_from_xpriv(&child_xpriv)?;
            let child_xpub = derive_path_from_xpub(&account.xpub, path)?;
            let address_from_private = derive_address_from_xpriv(&account.xpriv, path)?;
            let address_from_public = derive_address_from_xpub(&account.xpub, path)?;
            let wif = wif_from_xpriv(&child_xpriv)?;
            let wif_import = address_from_wif(network, &wif)?;

            Ok(json!({
                "path": path,
                "xpriv": child_xpriv.encoded,
                "xpub": child_xpub.encoded,
                "xpub_from_xpriv": child_xpub_from_xpriv.encoded,
                "public_key_hex_from_xpriv": address_from_private.public_key_hex,
                "public_key_hex_from_xpub": address_from_public.public_key_hex,
                "address_from_xpriv": address_from_private.address,
                "address_from_xpub": address_from_public.address,
                "wif": wif,
                "wif_import": {
                    "public_key_hex": wif_import.public_key_hex,
                    "address": wif_import.address,
                    "compressed": wif_import.compressed,
                },
            }))
        })
        .collect::<easydoge_km::Result<Vec<_>>>()?;

    let hardened_public_derivation =
        match derive_path_from_xpub(&account.xpub, &case.hardened_public_path) {
            Ok(_) => json!({
                "path": case.hardened_public_path,
                "rejected": false,
                "error_kind": null,
            }),
            Err(easydoge_km::Error::HardenedPublicDerivation(_)) => json!({
                "path": case.hardened_public_path,
                "rejected": true,
                "error_kind": "hardened-public-derivation",
            }),
            Err(err) => json!({
                "path": case.hardened_public_path,
                "rejected": true,
                "error_kind": err.to_string(),
            }),
        };

    Ok(json!({
        "id": case.id,
        "mnemonic_id": case.mnemonic_id,
        "network": case.network,
        "account": case.account,
        "account_path": account.account_path,
        "account_xpriv": account.xpriv.encoded,
        "account_xpub": account.xpub.encoded,
        "children": children,
        "hardened_public_derivation": hardened_public_derivation,
    }))
}

fn emit_message(
    case: &MessageCase,
    mnemonic_by_id: &BTreeMap<&str, &MnemonicCase>,
    bip44_by_id: &BTreeMap<&str, &Bip44Case>,
) -> easydoge_km::Result<serde_json::Value> {
    let (network, account) = account_for_case(&case.bip44_case_id, mnemonic_by_id, bip44_by_id)?;
    let signer_xpriv = derive_path_from_xpriv(&account.xpriv, &case.signer_path)?;
    let signer_wif = wif_from_xpriv(&signer_xpriv)?;
    let signature = sign_message(network, &signer_wif, &case.message)?;
    let verified = verify_message(
        network,
        &signature.address,
        &signature.signature_base64,
        &case.message,
    )?;

    Ok(json!({
        "id": case.id,
        "bip44_case_id": case.bip44_case_id,
        "signer_path": case.signer_path,
        "message": case.message,
        "network": network.to_string(),
        "address": signature.address,
        "signature_base64": signature.signature_base64,
        "verified": verified,
    }))
}

fn emit_transaction(
    case: &TransactionCase,
    mnemonic_by_id: &BTreeMap<&str, &MnemonicCase>,
    bip44_by_id: &BTreeMap<&str, &Bip44Case>,
) -> easydoge_km::Result<serde_json::Value> {
    let (network, account) = account_for_case(&case.bip44_case_id, mnemonic_by_id, bip44_by_id)?;
    let signer_xpriv = derive_path_from_xpriv(&account.xpriv, &case.signer_path)?;
    let signer_wif = wif_from_xpriv(&signer_xpriv)?;
    let signer_address = derive_address_from_xpriv(&account.xpriv, &case.signer_path)?;
    let script_pubkey_hex = p2pkh_script_pubkey_hex(&signer_address.public_key_hex)?;
    let signed = sign_p2pkh_transaction(
        network,
        &case.unsigned_tx_hex,
        case.input_index,
        &script_pubkey_hex,
        &signer_wif,
        case.sighash_type,
    )?;

    Ok(json!({
        "id": case.id,
        "bip44_case_id": case.bip44_case_id,
        "signer_path": case.signer_path,
        "network": network.to_string(),
        "unsigned_tx_hex": case.unsigned_tx_hex,
        "input_index": case.input_index,
        "sighash_type": case.sighash_type,
        "script_pubkey_hex": script_pubkey_hex,
        "public_key_hex": signer_address.public_key_hex,
        "address": signer_address.address,
        "signed_tx_hex": signed.signed_tx_hex,
    }))
}

fn emit_multisig(
    case: &MultisigCase,
    mnemonic_by_id: &BTreeMap<&str, &MnemonicCase>,
    bip44_by_id: &BTreeMap<&str, &Bip44Case>,
) -> easydoge_km::Result<serde_json::Value> {
    let network = Network::from_str(&case.network)?;
    let cosigner_xpubs = case
        .cosigner_bip44_case_ids
        .iter()
        .map(|case_id| {
            let (cosigner_network, account) =
                account_for_case(case_id, mnemonic_by_id, bip44_by_id)?;
            if cosigner_network != network {
                return Err(easydoge_km::Error::InvalidNetwork(
                    "cosigner xpub network mismatch".to_owned(),
                ));
            }
            Ok(Xpub {
                network,
                encoded: account.xpub.encoded,
            })
        })
        .collect::<easydoge_km::Result<Vec<_>>>()?;

    let descriptor = easydoge_km::create_multisig_descriptor(
        network,
        case.threshold,
        &cosigner_xpubs,
        &case.child_path,
        case.sorted,
    )?;

    Ok(json!({
        "id": case.id,
        "network": case.network,
        "threshold": descriptor.threshold,
        "cosigner_count": descriptor.cosigner_count,
        "cosigner_bip44_case_ids": case.cosigner_bip44_case_ids,
        "child_path": descriptor.child_path,
        "sorted": descriptor.sorted,
        "public_keys_hex": descriptor.public_keys_hex,
        "redeem_script_hex": descriptor.redeem_script_hex,
        "p2sh_address": descriptor.p2sh_address,
    }))
}

fn account_for_case(
    case_id: &str,
    mnemonic_by_id: &BTreeMap<&str, &MnemonicCase>,
    bip44_by_id: &BTreeMap<&str, &Bip44Case>,
) -> easydoge_km::Result<(Network, easydoge_km::AccountKeySet)> {
    let case = bip44_by_id
        .get(case_id)
        .ok_or_else(|| easydoge_km::Error::InvalidKey(format!("unknown BIP44 case {case_id}")))?;
    let mnemonic = mnemonic_by_id
        .get(case.mnemonic_id.as_str())
        .ok_or_else(|| {
            easydoge_km::Error::InvalidKey(format!("unknown mnemonic case {}", case.mnemonic_id))
        })?;
    let language = Language::from_str(&mnemonic.language)?;
    let network = Network::from_str(&case.network)?;
    let account = account_xpriv_from_mnemonic(
        &mnemonic.phrase,
        Some(&mnemonic.passphrase),
        language,
        network,
        case.account,
    )?;
    Ok((network, account))
}

fn p2pkh_script_pubkey_hex(public_key_hex: &str) -> easydoge_km::Result<String> {
    let public_key = hex::decode(public_key_hex)
        .map_err(|err| easydoge_km::Error::Serialization(err.to_string()))?;
    let hash = hash160::Hash::hash(&public_key).to_byte_array();
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash);
    script.extend_from_slice(&[0x88, 0xac]);
    Ok(hex::encode(script))
}

fn json_error(err: serde_json::Error) -> easydoge_km::Error {
    easydoge_km::Error::Serialization(err.to_string())
}
