use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{hash160, Hash};
use easydoge_km::{
    account_xpriv_from_mnemonic, compose_and_sign_transaction, create_multisig_descriptor,
    derive_address_from_xpriv, derive_address_from_xpub, finalize_signing_envelope,
    inspect_address, inspect_xpriv, mnemonic_to_seed_hex, sign_message, sign_p2pkh_transaction,
    validate_mnemonic, verify_message, wif_from_xpriv, AddressKind, ChangeDestination,
    CoinSelectionStrategy, ComposeTransactionRequest, FeePolicy, Language, Network,
    SigningEnvelope, SigningEnvelopeInput, SigningEnvelopeSignature, SigningInputKind,
    SpendableUtxo, TransactionOptions, TransactionOutput, TransactionOutputKind, UtxoSigner,
    UtxoSignerKind,
};
use serde_json::Value;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../test-vectors/parity.json")).expect("parity vectors")
}

#[test]
fn network_constants_match_dogecoin_core() {
    let vectors = vectors();
    assert_eq!(
        Network::Mainnet.prefixes().p2pkh,
        vectors["networks"]["mainnet"]["p2pkh"].as_u64().unwrap() as u8
    );
    assert_eq!(hex::encode(Network::Mainnet.prefixes().xpub), "02facafd");
    assert_eq!(Network::Testnet.prefixes().p2sh, 196);
    assert_eq!(Network::Regtest.prefixes().wif, 239);
}

#[test]
fn mnemonic_derives_account_extended_keys_and_watch_only_address() {
    let vectors = vectors();
    assert!(validate_mnemonic(PHRASE, Language::English).unwrap());
    let seed = mnemonic_to_seed_hex(PHRASE, Some("TREZOR"), Language::English).unwrap();
    assert_eq!(seed.len(), 128);

    let account = account_xpriv_from_mnemonic(
        PHRASE,
        Some("TREZOR"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    assert_eq!(
        account.account_path,
        vectors["mnemonic"]["bip44_account_path"].as_str().unwrap()
    );
    assert_eq!(
        account.xpriv.encoded,
        vectors["mnemonic"]["account"]["xpriv"].as_str().unwrap()
    );
    assert_eq!(
        account.xpub.encoded,
        vectors["mnemonic"]["account"]["xpub"].as_str().unwrap()
    );

    let receive_path = vectors["mnemonic"]["receive"]["relative_path"]
        .as_str()
        .unwrap();
    let receive_from_private = derive_address_from_xpriv(&account.xpriv, receive_path).unwrap();
    let receive_from_public = derive_address_from_xpub(&account.xpub, receive_path).unwrap();
    assert_eq!(receive_from_private.address, receive_from_public.address);
    assert_eq!(
        receive_from_public.public_key_hex,
        vectors["mnemonic"]["receive"]["public_key_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        receive_from_public.address,
        vectors["mnemonic"]["receive"]["address"].as_str().unwrap()
    );
}

#[test]
fn xpub_rejects_hardened_watch_only_derivation() {
    let account =
        account_xpriv_from_mnemonic(PHRASE, None, Language::English, Network::Mainnet, 0).unwrap();
    let error = derive_address_from_xpub(&account.xpub, "m/0'/0").unwrap_err();
    assert!(error.to_string().contains("hardened public derivation"));
}

#[test]
fn xpriv_inspection_does_not_expose_private_key_material() {
    let account =
        account_xpriv_from_mnemonic(PHRASE, None, Language::English, Network::Mainnet, 0).unwrap();
    let info = inspect_xpriv(&account.xpriv).unwrap();
    assert!(info.private_key_redacted);
    let public_key_hex = info.public_key_hex.unwrap();
    assert!(public_key_hex.starts_with("02") || public_key_hex.starts_with("03"));
}

#[test]
fn address_inspection_reports_matching_networks_and_kinds() {
    let vectors = vectors();
    let receive = vectors["mnemonic"]["receive"]["address"].as_str().unwrap();
    let receive_info = inspect_address(receive).unwrap();
    assert_eq!(receive_info.len(), 1);
    assert_eq!(receive_info[0].network, Network::Mainnet);
    assert_eq!(receive_info[0].kind, AddressKind::P2pkh);
    assert_eq!(receive_info[0].payload_hex.len(), 40);

    let p2sh = vectors["multisig"]["p2sh_address"].as_str().unwrap();
    let p2sh_info = inspect_address(p2sh).unwrap();
    assert_eq!(p2sh_info.len(), 1);
    assert_eq!(p2sh_info[0].network, Network::Mainnet);
    assert_eq!(p2sh_info[0].kind, AddressKind::P2sh);

    assert!(inspect_address("not an address").unwrap().is_empty());
}

#[test]
fn fixture_account_inspection_wif_message_and_transaction_are_deterministic() {
    let vectors = vectors();
    let xpriv = easydoge_km::Xpriv {
        network: Network::Mainnet,
        encoded: vectors["mnemonic"]["account"]["xpriv"]
            .as_str()
            .unwrap()
            .to_owned(),
    };

    let info = inspect_xpriv(&xpriv).unwrap();
    assert_eq!(
        info.depth,
        vectors["mnemonic"]["account"]["depth"].as_u64().unwrap() as u8
    );
    assert_eq!(
        info.child_number,
        vectors["mnemonic"]["account"]["child_number"]
            .as_u64()
            .unwrap() as u32
    );
    assert_eq!(
        info.parent_fingerprint_hex,
        vectors["mnemonic"]["account"]["parent_fingerprint_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        info.public_key_hex.unwrap(),
        vectors["mnemonic"]["account"]["public_key_hex"]
            .as_str()
            .unwrap()
    );
    assert!(info.private_key_redacted);

    let wif = wif_from_xpriv(&xpriv).unwrap();
    assert_eq!(wif, vectors["mnemonic"]["account"]["wif"].as_str().unwrap());

    let signature = sign_message(
        Network::Mainnet,
        &wif,
        vectors["message"]["text"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        signature.address,
        vectors["mnemonic"]["account"]["address"].as_str().unwrap()
    );
    assert_eq!(
        signature.signature_base64,
        vectors["message"]["signature_base64"].as_str().unwrap()
    );
    assert!(verify_message(
        Network::Mainnet,
        &signature.address,
        &signature.signature_base64,
        vectors["message"]["text"].as_str().unwrap()
    )
    .unwrap());

    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        vectors["transaction"]["unsigned_tx_hex"].as_str().unwrap(),
        vectors["transaction"]["input_index"].as_u64().unwrap() as usize,
        vectors["transaction"]["script_pubkey_hex"]
            .as_str()
            .unwrap(),
        &wif,
        vectors["transaction"]["sighash_type"].as_u64().unwrap() as u32,
    )
    .unwrap();
    assert_eq!(
        signed.signed_tx_hex,
        vectors["transaction"]["signed_tx_hex"].as_str().unwrap()
    );
}

#[test]
fn multisig_descriptor_is_deterministic_and_dogecoin_p2sh() {
    let vectors = vectors();
    let cosigner_xpubs = vectors["multisig"]["cosigner_xpubs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|encoded| easydoge_km::Xpub {
            network: Network::Mainnet,
            encoded: encoded.as_str().unwrap().to_owned(),
        })
        .collect::<Vec<_>>();
    let descriptor = create_multisig_descriptor(
        Network::Mainnet,
        vectors["multisig"]["threshold"].as_u64().unwrap() as u8,
        &cosigner_xpubs,
        vectors["multisig"]["child_path"].as_str().unwrap(),
        vectors["multisig"]["sorted"].as_bool().unwrap(),
    )
    .unwrap();
    assert_eq!(
        descriptor.threshold,
        vectors["multisig"]["threshold"].as_u64().unwrap() as u8
    );
    assert_eq!(
        serde_json::to_value(&descriptor.public_keys_hex).unwrap(),
        vectors["multisig"]["public_keys_hex"]
    );
    assert_eq!(
        descriptor.redeem_script_hex,
        vectors["multisig"]["redeem_script_hex"].as_str().unwrap()
    );
    assert_eq!(
        descriptor.p2sh_address,
        vectors["multisig"]["p2sh_address"].as_str().unwrap()
    );
}

#[test]
fn compose_builder_uses_display_txid_hex_and_serializes_reversed_outpoint_bytes() {
    let request = compose_request_base(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        100_000_000,
    );
    let result = compose_and_sign_transaction(&request).unwrap();
    assert!(result.signed_tx_hex.is_some());
    assert_eq!(
        &result.unsigned_tx_hex[10..74],
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
    );
}

#[test]
fn compose_builder_signs_p2pkh_with_change_and_audited_result() {
    let request = compose_request_base(
        "1111111111111111111111111111111111111111111111111111111111111111",
        150_000_000,
    );
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.selected_inputs.len(), 1);
    assert_eq!(result.input_total_koinu, 150_000_000);
    assert_eq!(result.spend_output_total_koinu, 50_000_000);
    assert!(result.change_amount_koinu > 0);
    assert!(result.fee_koinu > 0);
    assert!(result.actual_size_bytes.is_some());
    assert!(result.signed_tx_hex.is_some());
    assert!(result.signing_envelope.is_none());
}

#[test]
fn compose_builder_supports_op_return_and_expert_raw_script_outputs() {
    let mut request = compose_request_base(
        "2222222222222222222222222222222222222222222222222222222222222222",
        200_000_000,
    );
    request.outputs.push(TransactionOutput {
        kind: TransactionOutputKind::OpReturn,
        value_koinu: 0,
        address: None,
        op_return_data_hex: Some("65617379646f6765".to_owned()),
        script_hex: None,
    });
    request.outputs.push(TransactionOutput {
        kind: TransactionOutputKind::ExpertRawScript,
        value_koinu: 1_000,
        address: None,
        op_return_data_hex: None,
        script_hex: Some("51".to_owned()),
    });
    let result = compose_and_sign_transaction(&request).unwrap();
    assert!(result.unsigned_tx_hex.contains("6a0865617379646f6765"));
    assert!(result.signed_tx_hex.is_some());
}

#[test]
fn compose_builder_rejects_signer_that_does_not_match_p2pkh_utxo() {
    let mut request = compose_request_base(
        "3333333333333333333333333333333333333333333333333333333333333333",
        100_000_000,
    );
    request.utxos[0].script_pubkey_hex =
        "76a914000000000000000000000000000000000000000088ac".to_owned();
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(error.to_string().contains("does not match P2PKH UTXO"));
}

#[test]
fn p2sh_multisig_finalize_requires_threshold_signatures() {
    let vectors = vectors();
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: vectors["transaction"]["unsigned_tx_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index: 0,
            kind: SigningInputKind::P2shMultisig,
            script_pubkey_hex: "a914000000000000000000000000000000000000000087".to_owned(),
            redeem_script_hex: Some(
                vectors["multisig"]["redeem_script_hex"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
            sighash_type: 1,
            previous_output_value_koinu: Some(100_000_000),
            multisig_threshold: Some(2),
            multisig_public_keys_hex: vectors["multisig"]["public_keys_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect(),
        }],
        signatures: vec![SigningEnvelopeSignature {
            input_index: 0,
            public_key_hex: vectors["multisig"]["public_keys_hex"][0]
                .as_str()
                .unwrap()
                .to_owned(),
            signature_hex: "01".to_owned(),
        }],
    };
    let error = finalize_signing_envelope(&envelope).unwrap_err();
    assert!(error.to_string().contains("threshold is 2"));
}

#[test]
fn p2sh_multisig_finalize_uses_redeem_script_public_key_order() {
    let vectors = vectors();
    let public_keys = vectors["multisig"]["public_keys_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut reversed_public_keys = public_keys.clone();
    reversed_public_keys.reverse();
    let redeem_script_hex = vectors["multisig"]["redeem_script_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: vectors["transaction"]["unsigned_tx_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index: 0,
            kind: SigningInputKind::P2shMultisig,
            script_pubkey_hex: "a914000000000000000000000000000000000000000087".to_owned(),
            redeem_script_hex: Some(redeem_script_hex.clone()),
            sighash_type: 1,
            previous_output_value_koinu: Some(100_000_000),
            multisig_threshold: Some(2),
            multisig_public_keys_hex: reversed_public_keys,
        }],
        signatures: vec![
            SigningEnvelopeSignature {
                input_index: 0,
                public_key_hex: public_keys[1].clone(),
                signature_hex: "bb".to_owned(),
            },
            SigningEnvelopeSignature {
                input_index: 0,
                public_key_hex: public_keys[0].clone(),
                signature_hex: "aa".to_owned(),
            },
        ],
    };

    let signed = finalize_signing_envelope(&envelope).unwrap();

    assert!(signed
        .signed_tx_hex
        .contains(&format!("4d0001aa01bb47{redeem_script_hex}")));
}

#[test]
fn compose_builder_counts_pushdata_prefix_for_large_p2sh_redeem_script() {
    let mut request = compose_request_base(
        "4444444444444444444444444444444444444444444444444444444444444444",
        9_343,
    );
    let public_keys = [
        "020000000000000000000000000000000000000000000000000000000000000001",
        "030000000000000000000000000000000000000000000000000000000000000002",
        "020000000000000000000000000000000000000000000000000000000000000003",
    ];
    let redeem_script_hex = format!(
        "52{}53ae",
        public_keys
            .iter()
            .map(|public_key| format!("21{public_key}"))
            .collect::<String>()
    );
    let redeem_script = hex::decode(&redeem_script_hex).unwrap();
    let script_hash = hash160::Hash::hash(&redeem_script);
    request.utxos[0] = SpendableUtxo {
        txid: "4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
        vout: 0,
        previous_output_value_koinu: 9_343,
        script_pubkey_hex: format!("a914{}87", hex::encode(script_hash)),
        kind: SigningInputKind::P2shMultisig,
        redeem_script_hex: Some(redeem_script_hex),
        multisig_threshold: Some(2),
        multisig_public_keys_hex: public_keys.iter().map(|key| (*key).to_owned()).collect(),
        signers: vec![],
        manually_selected: false,
    };
    request.change = None;
    request.outputs[0].value_koinu = 9_000;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(result.estimated_size_bytes, 343);
    assert_eq!(result.fee_koinu, 343);
    assert!(result.signed_tx_hex.is_none());
    assert!(result.signing_envelope.is_some());
}

fn compose_request_base(txid: &str, previous_output_value_koinu: u64) -> ComposeTransactionRequest {
    let vectors = vectors();
    ComposeTransactionRequest {
        network: Network::Mainnet,
        utxos: vec![SpendableUtxo {
            txid: txid.to_owned(),
            vout: 0,
            previous_output_value_koinu,
            script_pubkey_hex: vectors["transaction"]["script_pubkey_hex"]
                .as_str()
                .unwrap()
                .to_owned(),
            kind: SigningInputKind::P2pkh,
            redeem_script_hex: None,
            multisig_threshold: None,
            multisig_public_keys_hex: vec![],
            signers: vec![UtxoSigner {
                kind: UtxoSignerKind::Wif,
                wif: Some(
                    vectors["mnemonic"]["account"]["wif"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
                xpriv: None,
                derivation_path: None,
            }],
            manually_selected: false,
        }],
        outputs: vec![TransactionOutput {
            kind: TransactionOutputKind::Address,
            value_koinu: 50_000_000,
            address: Some(
                vectors["mnemonic"]["receive"]["address"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
            op_return_data_hex: None,
            script_hex: None,
        }],
        fee_policy: FeePolicy {
            fee_rate_koinu_per_kb: 1_000,
            dust_threshold_koinu: 1,
        },
        coin_selection: CoinSelectionStrategy::MinInputs,
        change: Some(ChangeDestination {
            address: Some(
                vectors["mnemonic"]["receive"]["address"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
            xpriv: None,
            derivation_path: None,
        }),
        options: TransactionOptions::default(),
    }
}

fn parity_unsigned_tx_hex() -> String {
    vectors()["transaction"]["unsigned_tx_hex"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn parity_script_pubkey_hex() -> String {
    vectors()["transaction"]["script_pubkey_hex"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn parity_wif() -> String {
    vectors()["mnemonic"]["account"]["wif"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The parity transaction with its single input duplicated (vout 1), giving
/// two inputs and one output.
fn two_input_unsigned_tx_hex() -> String {
    let mut tx: bitcoin::Transaction =
        deserialize(&hex::decode(parity_unsigned_tx_hex()).unwrap()).unwrap();
    let mut second = tx.input[0].clone();
    second.previous_output.vout = 1;
    tx.input.push(second);
    hex::encode(serialize(&tx))
}

#[test]
fn sign_p2pkh_rejects_sighash_types_outside_consensus_set() {
    for sighash_type in [0x00u32, 0x04, 0x41, 0x80, 0x101, 0xff01] {
        let error = sign_p2pkh_transaction(
            Network::Mainnet,
            &parity_unsigned_tx_hex(),
            0,
            &parity_script_pubkey_hex(),
            &parity_wif(),
            sighash_type,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported sighash type"),
            "{sighash_type:#x}: {error}"
        );
    }
}

#[test]
fn sign_p2pkh_accepts_anyone_can_pay_and_appends_flag_byte() {
    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        &parity_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x81,
    )
    .unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    let script_sig = tx.input[0].script_sig.as_bytes();
    let signature_push_len = usize::from(script_sig[0]);
    assert_eq!(script_sig[signature_push_len], 0x81);
}

#[test]
fn sign_p2pkh_rejects_sighash_single_without_matching_output() {
    let unsigned = two_input_unsigned_tx_hex();
    let error = sign_p2pkh_transaction(
        Network::Mainnet,
        &unsigned,
        1,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x03,
    )
    .unwrap_err();
    assert!(error.to_string().contains("SIGHASH_SINGLE"), "{error}");

    // Input 0 does have a matching output, so SINGLE is allowed there.
    sign_p2pkh_transaction(
        Network::Mainnet,
        &unsigned,
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x03,
    )
    .unwrap();
}

#[test]
fn compose_builder_rejects_unsupported_sighash_type() {
    let mut request = compose_request_base(
        "5555555555555555555555555555555555555555555555555555555555555555",
        100_000_000,
    );
    request.options.sighash_type = 0x80;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error.to_string().contains("unsupported sighash type"),
        "{error}"
    );
}

#[test]
fn finalize_rejects_envelope_input_with_unsupported_sighash_type() {
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: parity_unsigned_tx_hex(),
        inputs: vec![SigningEnvelopeInput {
            input_index: 0,
            kind: SigningInputKind::P2pkh,
            script_pubkey_hex: parity_script_pubkey_hex(),
            redeem_script_hex: None,
            sighash_type: 1,
            previous_output_value_koinu: None,
            multisig_threshold: None,
            multisig_public_keys_hex: vec![],
        }],
        signatures: vec![],
    };
    let mut signed = easydoge_km::sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    signed.inputs[0].sighash_type = 0x104;
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(
        error.to_string().contains("unsupported sighash type"),
        "{error}"
    );
}
