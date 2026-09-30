use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{hash160, Hash};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, combine_signing_envelopes,
    compose_and_sign_transaction, create_multisig_descriptor, derive_address_from_xpriv,
    derive_address_from_xpub, derive_path_from_xpriv, finalize_signing_envelope, generate_mnemonic,
    inspect_address, inspect_xpriv, mnemonic_to_seed_hex, sign_message, sign_p2pkh_transaction,
    sign_signing_envelope, validate_mnemonic, verify_message, wif_from_xpriv, AddressKind,
    ChangeDestination, CoinSelectionStrategy, ComposeTransactionRequest, FeePolicy,
    GeneratedMnemonic, Language, MnemonicOptions, MultisigDescriptor, Network, SigningEnvelope,
    SigningEnvelopeInput, SigningEnvelopeSignature, SigningInputKind, SpendableUtxo,
    TransactionOptions, TransactionOutput, TransactionOutputKind, UtxoSigner, UtxoSignerKind,
};
use serde_json::Value;
use std::collections::HashMap;

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
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let partial = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    assert_eq!(partial.signatures.len(), 1);
    let error = finalize_signing_envelope(&partial).unwrap_err();
    assert!(error.to_string().contains("threshold is 2"), "{error}");
}

#[test]
fn p2sh_multisig_finalize_uses_redeem_script_public_key_order() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    // Sign with the second cosigner first so envelope order differs from redeem-script order.
    let second_first = sign_signing_envelope(&fixture.envelope, &fixture.wifs[1]).unwrap();
    let both = sign_signing_envelope(&second_first, &fixture.wifs[0]).unwrap();
    assert_eq!(both.signatures.len(), 2);
    let signed = finalize_signing_envelope(&both).unwrap();

    let sig_for = |key: &str| {
        both.signatures
            .iter()
            .find(|signature| signature.public_key_hex == key)
            .unwrap()
            .signature_hex
            .clone()
    };
    let first = sig_for(&fixture.descriptor.public_keys_hex[0]);
    let second = sig_for(&fixture.descriptor.public_keys_hex[1]);
    let first_at = signed.signed_tx_hex.find(&first).unwrap();
    let second_at = signed.signed_tx_hex.find(&second).unwrap();
    assert!(
        first_at < second_at,
        "signatures must follow redeem script key order"
    );
    assert!(signed
        .signed_tx_hex
        .contains(&fixture.descriptor.redeem_script_hex));
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

struct TwoOfTwoFixture {
    descriptor: MultisigDescriptor,
    /// WIFs ordered to match `descriptor.public_keys_hex`.
    wifs: Vec<String>,
    envelope: SigningEnvelope,
}

fn two_of_two_fixture(unsigned_tx_hex: &str, input_index: usize) -> TwoOfTwoFixture {
    let accounts = [0u32, 1].map(|account| {
        account_xpriv_from_mnemonic(
            PHRASE,
            Some("TREZOR"),
            Language::English,
            Network::Mainnet,
            account,
        )
        .unwrap()
    });
    let xpubs = accounts
        .iter()
        .map(|account| account.xpub.clone())
        .collect::<Vec<_>>();
    let descriptor =
        create_multisig_descriptor(Network::Mainnet, 2, &xpubs, "m/0/7", true).unwrap();
    let mut wif_by_public_key = accounts
        .iter()
        .map(|account| {
            let child = derive_address_from_xpriv(&account.xpriv, "m/0/7").unwrap();
            let child_xpriv = derive_path_from_xpriv(&account.xpriv, "m/0/7").unwrap();
            (child.public_key_hex, wif_from_xpriv(&child_xpriv).unwrap())
        })
        .collect::<HashMap<_, _>>();
    let wifs = descriptor
        .public_keys_hex
        .iter()
        .map(|key| wif_by_public_key.remove(key).unwrap())
        .collect::<Vec<_>>();
    let redeem_script = hex::decode(&descriptor.redeem_script_hex).unwrap();
    let script_pubkey_hex = format!(
        "a914{}87",
        hex::encode(hash160::Hash::hash(&redeem_script).to_byte_array())
    );
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: unsigned_tx_hex.to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index,
            kind: SigningInputKind::P2shMultisig,
            script_pubkey_hex,
            redeem_script_hex: Some(descriptor.redeem_script_hex.clone()),
            sighash_type: 1,
            previous_output_value_koinu: Some(100_000_000),
            multisig_threshold: Some(2),
            multisig_public_keys_hex: descriptor.public_keys_hex.clone(),
        }],
        signatures: vec![],
    };
    TwoOfTwoFixture {
        descriptor,
        wifs,
        envelope,
    }
}

fn p2pkh_envelope() -> SigningEnvelope {
    SigningEnvelope {
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
    }
}

/// A WIF that controls nothing in the parity fixtures (account 1, m/0/0).
fn foreign_wif() -> String {
    let account = account_xpriv_from_mnemonic(
        PHRASE,
        Some("TREZOR"),
        Language::English,
        Network::Mainnet,
        1,
    )
    .unwrap();
    wif_from_xpriv(&derive_path_from_xpriv(&account.xpriv, "m/0/0").unwrap()).unwrap()
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

#[test]
fn seed_derivation_normalizes_passphrase_to_nfkd() {
    let precomposed = mnemonic_to_seed_hex(PHRASE, Some("caf\u{00e9}"), Language::English).unwrap();
    let decomposed = mnemonic_to_seed_hex(PHRASE, Some("cafe\u{0301}"), Language::English).unwrap();
    let plain = mnemonic_to_seed_hex(PHRASE, Some("cafe"), Language::English).unwrap();
    assert_eq!(precomposed, decomposed);
    assert_ne!(precomposed, plain);

    let fullwidth = mnemonic_to_seed_hex(PHRASE, Some("\u{ff21}"), Language::English).unwrap();
    let ascii = mnemonic_to_seed_hex(PHRASE, Some("A"), Language::English).unwrap();
    assert_eq!(fullwidth, ascii, "NFKD maps fullwidth A to ASCII A");
}

#[test]
fn account_keys_normalize_passphrase_to_nfkd() {
    let precomposed = account_xpriv_from_mnemonic(
        PHRASE,
        Some("caf\u{00e9}"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    let decomposed = account_xpriv_from_mnemonic(
        PHRASE,
        Some("cafe\u{0301}"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    assert_eq!(precomposed.xpub.encoded, decomposed.xpub.encoded);
}

#[test]
fn japanese_bip39_reference_vector_with_compatibility_passphrase_matches_spec() {
    let words = ["あいこくしん"; 11]
        .iter()
        .chain(std::iter::once(&"あおぞら"))
        .copied()
        .collect::<Vec<_>>()
        .join("\u{3000}");
    let seed = mnemonic_to_seed_hex(
        &words,
        Some("㍍ガバヴァぱばぐゞちぢ十人十色"),
        Language::Japanese,
    )
    .unwrap();
    assert_eq!(
        seed,
        "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55"
    );
}
#[test]
fn signing_envelope_rejects_wif_that_controls_no_input() {
    let error = sign_signing_envelope(&p2pkh_envelope(), &foreign_wif()).unwrap_err();
    assert!(
        error.to_string().contains("does not control any input"),
        "{error}"
    );
}

#[test]
fn sign_p2pkh_transaction_rejects_script_pubkey_not_owned_by_wif() {
    let error = sign_p2pkh_transaction(
        Network::Mainnet,
        &parity_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &foreign_wif(),
        1,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not control any input"),
        "{error}"
    );
}

#[test]
fn sign_p2pkh_transaction_still_signs_one_input_of_a_multi_input_transaction() {
    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        &two_input_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        1,
    )
    .unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    assert!(!tx.input[0].script_sig.is_empty());
    assert!(
        tx.input[1].script_sig.is_empty(),
        "undescribed inputs stay untouched"
    );
}

#[test]
fn signing_envelope_signs_only_inputs_owned_by_each_wif() {
    let unsigned = two_input_unsigned_tx_hex();
    let multisig = two_of_two_fixture(&unsigned, 1);
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = unsigned;
    envelope.inputs.push(multisig.envelope.inputs[0].clone());

    let after_p2pkh = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(after_p2pkh.signatures.len(), 1);
    assert_eq!(after_p2pkh.signatures[0].input_index, 0);

    let after_first_cosigner = sign_signing_envelope(&after_p2pkh, &multisig.wifs[0]).unwrap();
    let complete = sign_signing_envelope(&after_first_cosigner, &multisig.wifs[1]).unwrap();
    assert_eq!(complete.signatures.len(), 3);
    assert!(complete.signatures[1..].iter().all(|s| s.input_index == 1));
    finalize_signing_envelope(&complete).unwrap();
}

#[test]
fn signing_envelope_does_not_duplicate_signatures_from_the_same_key() {
    let once = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let twice = sign_signing_envelope(&once, &parity_wif()).unwrap();
    assert_eq!(twice.signatures.len(), 1);
}

#[test]
fn signing_envelope_rejects_duplicate_and_out_of_range_input_descriptors() {
    let mut duplicated = p2pkh_envelope();
    duplicated.inputs.push(duplicated.inputs[0].clone());
    let error = sign_signing_envelope(&duplicated, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("more than once"), "{error}");

    let mut out_of_range = p2pkh_envelope();
    out_of_range.inputs[0].input_index = 5;
    let error = sign_signing_envelope(&out_of_range, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("out of range"), "{error}");
}

#[test]
fn finalize_rejects_tampered_signature_bytes() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let mut chars: Vec<char> = signed.signatures[0].signature_hex.chars().collect();
    // Byte 5 sits inside the DER `r` value; changing it keeps DER shape but breaks the math.
    chars[10] = if chars[10] == '0' { '1' } else { '0' };
    signed.signatures[0].signature_hex = chars.into_iter().collect();
    let error = finalize_signing_envelope(&signed).unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("does not verify") || text.contains("not valid DER"),
        "{text}"
    );
}

#[test]
fn finalize_rejects_signature_with_mismatched_sighash_flag() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let hex_value = &signed.signatures[0].signature_hex;
    assert!(hex_value.ends_with("01"));
    signed.signatures[0].signature_hex = format!("{}81", &hex_value[..hex_value.len() - 2]);
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(error.to_string().contains("uses sighash type"), "{error}");
}

#[test]
fn finalize_rejects_signature_from_key_that_does_not_control_input() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let foreign = address_from_wif(Network::Mainnet, &foreign_wif()).unwrap();
    let foreign_hash =
        hash160::Hash::hash(&hex::decode(foreign.public_key_hex).unwrap()).to_byte_array();
    signed.inputs[0].script_pubkey_hex = format!("76a914{}88ac", hex::encode(foreign_hash));
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(
        error.to_string().contains("does not control the input"),
        "{error}"
    );
}

#[test]
fn finalize_rejects_envelope_that_does_not_describe_every_input() {
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = two_input_unsigned_tx_hex();
    // Signing a partial envelope is allowed (co-signers may only know their inputs)...
    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(signed.signatures.len(), 1);
    // ...but finalizing requires every input to be described.
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(
        error.to_string().contains("every transaction input"),
        "{error}"
    );
}

#[test]
fn finalize_rejects_p2sh_script_pubkey_that_does_not_match_redeem_script() {
    let mut fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    fixture.envelope.inputs[0].script_pubkey_hex =
        "a914000000000000000000000000000000000000000087".to_owned();
    let error = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap_err();
    assert!(
        error.to_string().contains("does not match redeem script"),
        "{error}"
    );
}

#[test]
fn p2sh_multisig_cosigners_sign_separately_then_combine_and_finalize() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let first = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    let second = sign_signing_envelope(&fixture.envelope, &fixture.wifs[1]).unwrap();
    let combined = combine_signing_envelopes(&[first, second]).unwrap();
    assert_eq!(combined.signatures.len(), 2);
    let signed = finalize_signing_envelope(&combined).unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    assert_eq!(
        tx.input[0].script_sig.as_bytes()[0],
        0x00,
        "OP_0 must lead the scriptSig"
    );
}

#[test]
fn combine_rejects_envelope_carrying_forged_signature() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let genuine = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    let mut forged = fixture.envelope.clone();
    forged.signatures.push(SigningEnvelopeSignature {
        input_index: 0,
        public_key_hex: fixture.descriptor.public_keys_hex[1].clone(),
        signature_hex: "300602010102010101".to_owned(),
    });
    let error = combine_signing_envelopes(&[genuine, forged]).unwrap_err();
    assert!(
        error.to_string().contains("signature for input 0"),
        "{error}"
    );
}

#[test]
fn signing_envelope_keeps_signatures_for_inputs_it_does_not_describe() {
    // Mirrors the transaction builder, which signs one input at a time while
    // carrying the signatures already collected for other inputs.
    let unsigned = two_input_unsigned_tx_hex();
    let mut first_only = p2pkh_envelope();
    first_only.unsigned_tx_hex = unsigned.clone();
    let after_first = sign_signing_envelope(&first_only, &parity_wif()).unwrap();
    assert_eq!(after_first.signatures.len(), 1);

    let mut second_only = p2pkh_envelope();
    second_only.unsigned_tx_hex = unsigned;
    second_only.inputs[0].input_index = 1;
    second_only.signatures = after_first.signatures.clone();
    let after_second = sign_signing_envelope(&second_only, &parity_wif()).unwrap();
    assert_eq!(after_second.signatures.len(), 2);
    assert!(after_second.signatures.contains(&after_first.signatures[0]));

    // Signatures may reference inputs the envelope does not describe, but
    // never inputs the transaction does not have.
    let mut out_of_range = after_second.clone();
    out_of_range.signatures[0].input_index = 7;
    let error = sign_signing_envelope(&out_of_range, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("out of range"), "{error}");
}

#[test]
fn compose_builder_signs_every_input_of_a_multi_utxo_transaction() {
    let mut request = compose_request_base(
        "6666666666666666666666666666666666666666666666666666666666666666",
        100_000_000,
    );
    let mut second = request.utxos[0].clone();
    second.txid = "7777777777777777777777777777777777777777777777777777777777777777".to_owned();
    request.utxos.push(second);
    // Larger than either UTXO alone, so both must be selected and signed.
    request.outputs[0].value_koinu = 150_000_000;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.selected_inputs.len(), 2);
    let signed_tx_hex = result
        .signed_tx_hex
        .expect("both inputs are signed by the WIF");
    let tx: bitcoin::Transaction = deserialize(&hex::decode(&signed_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), 2);
    assert!(tx.input.iter().all(|input| !input.script_sig.is_empty()));
}

#[test]
fn compose_builder_rejects_duplicate_utxo_outpoint_instead_of_counting_it_twice() {
    let txid = "8888888888888888888888888888888888888888888888888888888888888888";
    let mut request = compose_request_base(txid, 100_000_000);
    request.utxos.push(request.utxos[0].clone());
    // More than one copy holds: only counting the same UTXO twice could fund this.
    request.outputs[0].value_koinu = 150_000_000;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("duplicate UTXO outpoint {txid}:0")),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_duplicate_utxo_outpoint_even_when_one_copy_funds_the_outputs() {
    let txid = "9999999999999999999999999999999999999999999999999999999999999999";
    let mut request = compose_request_base(txid, 100_000_000);
    request.utxos.push(request.utxos[0].clone());
    // The default 50_000_000 koinu output is funded by a single copy.
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("duplicate UTXO outpoint {txid}:0")),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_duplicate_utxo_outpoint_when_txid_hex_differs_only_in_letter_case() {
    let lowercase_txid = "abababababababababababababababababababababababababababababababab";
    let uppercase_txid = lowercase_txid.to_ascii_uppercase();
    let mut request = compose_request_base(lowercase_txid, 100_000_000);
    let mut second = request.utxos[0].clone();
    second.txid = uppercase_txid.clone();
    request.utxos.push(second);
    request.outputs[0].value_koinu = 150_000_000;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    // The message reports the txid as supplied by the second (rejected) copy.
    assert!(
        error
            .to_string()
            .contains(&format!("duplicate UTXO outpoint {uppercase_txid}:0")),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_duplicate_utxo_outpoint_that_is_not_manually_selected() {
    let txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut request = compose_request_base(txid, 100_000_000);
    request.coin_selection = CoinSelectionStrategy::ManualSelectedInputs;
    request.utxos[0].manually_selected = true;
    let mut unselected_copy = request.utxos[0].clone();
    unselected_copy.manually_selected = false;
    request.utxos.push(unselected_copy);
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("duplicate UTXO outpoint {txid}:0")),
        "{error}"
    );
}

#[test]
fn compose_builder_accepts_utxos_that_share_a_txid_but_differ_in_vout() {
    let txid = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut request = compose_request_base(txid, 100_000_000);
    let mut second = request.utxos[0].clone();
    second.vout = 1;
    request.utxos.push(second);
    // Larger than either UTXO alone, so both outpoints must be selected.
    request.outputs[0].value_koinu = 150_000_000;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.selected_inputs.len(), 2);
    assert_eq!(result.input_total_koinu, 200_000_000);
    let mut vouts = result
        .selected_inputs
        .iter()
        .map(|input| input.vout)
        .collect::<Vec<_>>();
    vouts.sort_unstable();
    assert_eq!(vouts, vec![0, 1]);
    assert!(result.signed_tx_hex.is_some());
}

/// Account-level xpubs for accounts `0..count` of the public parity mnemonic.
fn distinct_account_xpubs(count: u32) -> Vec<easydoge_km::Xpub> {
    (0..count)
        .map(|account| {
            account_xpriv_from_mnemonic(
                PHRASE,
                Some("TREZOR"),
                Language::English,
                Network::Mainnet,
                account,
            )
            .unwrap()
            .xpub
        })
        .collect()
}

/// Hand-assembles `OP_m <33-byte key>... OP_n OP_CHECKMULTISIG` so tests can
/// describe redeem scripts the SDK itself refuses to create.
fn multisig_redeem_script_hex(threshold: u8, public_keys_hex: &[String]) -> String {
    let pushes = public_keys_hex
        .iter()
        .map(|key| format!("21{key}"))
        .collect::<String>();
    format!(
        "{:02x}{pushes}{:02x}ae",
        0x50 + threshold,
        0x50 + public_keys_hex.len()
    )
}

/// A one-input P2SH multisig Signing Envelope over the parity transaction
/// whose script pubkey commits to `redeem_script_hex`.
fn p2sh_multisig_envelope(
    redeem_script_hex: &str,
    multisig_threshold: Option<u8>,
    multisig_public_keys_hex: Vec<String>,
) -> SigningEnvelope {
    let redeem_script = hex::decode(redeem_script_hex).unwrap();
    SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: parity_unsigned_tx_hex(),
        inputs: vec![SigningEnvelopeInput {
            input_index: 0,
            kind: SigningInputKind::P2shMultisig,
            script_pubkey_hex: format!(
                "a914{}87",
                hex::encode(hash160::Hash::hash(&redeem_script).to_byte_array())
            ),
            redeem_script_hex: Some(redeem_script_hex.to_owned()),
            sighash_type: 1,
            previous_output_value_koinu: Some(100_000_000),
            multisig_threshold,
            multisig_public_keys_hex,
        }],
        signatures: vec![],
    }
}

#[test]
fn multisig_descriptor_rejects_the_same_cosigner_xpub_twice() {
    let xpubs = distinct_account_xpubs(2);
    let repeated = vec![xpubs[0].clone(), xpubs[1].clone(), xpubs[0].clone()];
    for sorted in [true, false] {
        let error = create_multisig_descriptor(Network::Mainnet, 2, &repeated, "m/0/7", sorted)
            .unwrap_err();
        assert!(
            error.to_string().contains("duplicate cosigner public key"),
            "sorted={sorted}: {error}"
        );
    }
}

#[test]
fn multisig_descriptor_rejects_a_legacy_prefixed_copy_of_a_cosigner_xpub() {
    let xpubs = distinct_account_xpubs(2);
    // Same key and chain code, re-encoded with the Bitcoin `xpub` version
    // bytes the SDK also accepts: a different string, the same cosigner.
    let mut payload = bitcoin::base58::decode_check(&xpubs[0].encoded).unwrap();
    payload[0..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
    let legacy_copy = easydoge_km::Xpub {
        network: Network::Mainnet,
        encoded: bitcoin::base58::encode_check(&payload),
    };
    assert_ne!(legacy_copy.encoded, xpubs[0].encoded);

    let error = create_multisig_descriptor(
        Network::Mainnet,
        2,
        &[xpubs[0].clone(), xpubs[1].clone(), legacy_copy],
        "m/0/7",
        true,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("duplicate cosigner public key"),
        "{error}"
    );
}

#[test]
fn multisig_descriptor_rejects_more_than_fifteen_cosigners() {
    let error = create_multisig_descriptor(
        Network::Mainnet,
        2,
        &distinct_account_xpubs(16),
        "m/0/7",
        true,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("P2SH multisig supports at most 15 cosigners"),
        "{error}"
    );
}

#[test]
fn multisig_descriptor_accepts_fifteen_distinct_cosigners_within_the_p2sh_push_limit() {
    let descriptor = create_multisig_descriptor(
        Network::Mainnet,
        2,
        &distinct_account_xpubs(15),
        "m/0/7",
        true,
    )
    .unwrap();
    assert_eq!(descriptor.cosigner_count, 15);
    assert_eq!(descriptor.public_keys_hex.len(), 15);
    // 1 (OP_2) + 15 * 34 (push + compressed key) + 1 (OP_15) + 1 (OP_CHECKMULTISIG)
    assert_eq!(descriptor.redeem_script_hex.len() / 2, 513);

    // The largest descriptor the SDK creates is accepted by its own spend path.
    let envelope = p2sh_multisig_envelope(
        &descriptor.redeem_script_hex,
        Some(2),
        descriptor.public_keys_hex.clone(),
    );
    let error = finalize_signing_envelope(&envelope).unwrap_err();
    assert!(error.to_string().contains("has no signatures"), "{error}");
}

#[test]
fn signing_envelope_rejects_redeem_script_above_the_p2sh_push_limit() {
    let public_keys_hex = distinct_account_xpubs(16)
        .iter()
        .map(|xpub| {
            derive_address_from_xpub(xpub, "m/0/7")
                .unwrap()
                .public_key_hex
        })
        .collect::<Vec<_>>();
    let redeem_script_hex = multisig_redeem_script_hex(2, &public_keys_hex);
    assert_eq!(redeem_script_hex.len() / 2, 547);
    let envelope = p2sh_multisig_envelope(&redeem_script_hex, Some(2), public_keys_hex);

    let signing = sign_signing_envelope(&envelope, &parity_wif()).unwrap_err();
    assert!(
        signing.to_string().contains("exceeds 520 bytes"),
        "{signing}"
    );
    let combining = combine_signing_envelopes(std::slice::from_ref(&envelope)).unwrap_err();
    assert!(
        combining.to_string().contains("exceeds 520 bytes"),
        "{combining}"
    );
    let finalizing = finalize_signing_envelope(&envelope).unwrap_err();
    assert!(
        finalizing.to_string().contains("exceeds 520 bytes"),
        "{finalizing}"
    );
}

#[test]
fn signing_envelope_requires_public_key_metadata_to_list_exactly_the_redeem_script_keys() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let a = fixture.descriptor.public_keys_hex[0].clone();
    let b = fixture.descriptor.public_keys_hex[1].clone();

    // Script keys [A, A, B]; metadata [A, B, B] has the same length and only
    // names keys that appear in the script, but it is a different key list.
    let repeated_script = multisig_redeem_script_hex(2, &[a.clone(), a.clone(), b.clone()]);
    let wrong_counts = p2sh_multisig_envelope(
        &repeated_script,
        Some(2),
        vec![a.clone(), b.clone(), b.clone()],
    );
    let error = sign_signing_envelope(&wrong_counts, &fixture.wifs[0]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("multisig public key metadata does not match redeem script"),
        "{error}"
    );

    // Script keys [A, B]; metadata [A, A] hides cosigner B.
    let mut hidden_cosigner = fixture.envelope.clone();
    hidden_cosigner.inputs[0].multisig_public_keys_hex = vec![a.clone(), a.clone()];
    let error = sign_signing_envelope(&hidden_cosigner, &fixture.wifs[0]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("multisig public key metadata does not match redeem script"),
        "{error}"
    );

    // Order and hex case are not significant: the same keys still match.
    let mut reordered = fixture.envelope.clone();
    reordered.inputs[0].multisig_public_keys_hex = vec![b.to_uppercase(), a.to_uppercase()];
    let signed = sign_signing_envelope(&reordered, &fixture.wifs[0]).unwrap();
    assert_eq!(signed.signatures.len(), 1);
}

#[test]
fn finalize_counts_case_variant_copies_of_one_signature_as_one_signer() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let mut partial = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    let mut copy = partial.signatures[0].clone();
    copy.public_key_hex = copy.public_key_hex.to_uppercase();
    assert_ne!(copy.public_key_hex, partial.signatures[0].public_key_hex);
    partial.signatures.push(copy);

    let error = finalize_signing_envelope(&partial).unwrap_err();
    assert!(error.to_string().contains("threshold is 2"), "{error}");
}

#[test]
fn p2sh_multisig_with_a_repeated_key_finalizes_only_with_distinct_signers() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let a = fixture.descriptor.public_keys_hex[0].clone();
    let b = fixture.descriptor.public_keys_hex[1].clone();
    // A redeem script created elsewhere that lists cosigner A twice. The SDK
    // refuses to create it but can still spend from it.
    let redeem_script_hex = multisig_redeem_script_hex(2, &[a.clone(), a.clone(), b.clone()]);
    let envelope = p2sh_multisig_envelope(&redeem_script_hex, Some(2), vec![]);

    let only_a = sign_signing_envelope(&envelope, &fixture.wifs[0]).unwrap();
    assert_eq!(only_a.signatures.len(), 1, "a repeated key signs once");
    let error = finalize_signing_envelope(&only_a).unwrap_err();
    assert!(error.to_string().contains("threshold is 2"), "{error}");

    let both = sign_signing_envelope(&only_a, &fixture.wifs[1]).unwrap();
    let signed = finalize_signing_envelope(&both).unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    let pushes = tx.input[0]
        .script_sig
        .instructions()
        .map(|instruction| instruction.unwrap())
        .map(|instruction| {
            instruction
                .push_bytes()
                .map(|bytes| hex::encode(bytes.as_bytes()))
        })
        .collect::<Vec<_>>();
    let signature_by = |key: &str| {
        both.signatures
            .iter()
            .find(|signature| signature.public_key_hex == key)
            .unwrap()
            .signature_hex
            .clone()
    };
    // OP_0, one signature per distinct signer in redeem-script key order, then
    // the redeem script: OP_CHECKMULTISIG accepts exactly this shape.
    assert_eq!(
        pushes,
        vec![
            Some(String::new()),
            Some(signature_by(&a)),
            Some(signature_by(&b)),
            Some(redeem_script_hex),
        ]
    );
}

/// Public keys of the synthetic 2-of-3 redeem script used by the builder's
/// P2SH Multisig fee tests, in redeem-script order.
const FEE_FIXTURE_MULTISIG_KEYS: [&str; 3] = [
    "020000000000000000000000000000000000000000000000000000000000000001",
    "030000000000000000000000000000000000000000000000000000000000000002",
    "020000000000000000000000000000000000000000000000000000000000000003",
];

fn fee_fixture_multisig_keys() -> Vec<String> {
    FEE_FIXTURE_MULTISIG_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect()
}

/// A request that spends one 2-of-3 P2SH Multisig UTXO to a single 9_000 koinu
/// address output, with no change destination and no signers. The caller
/// chooses the UTXO value and the multisig metadata the UTXO declares.
fn two_of_three_p2sh_request(
    previous_output_value_koinu: u64,
    multisig_threshold: Option<u8>,
    multisig_public_keys_hex: Vec<String>,
) -> ComposeTransactionRequest {
    let txid = "8888888888888888888888888888888888888888888888888888888888888888";
    let mut request = compose_request_base(txid, previous_output_value_koinu);
    let redeem_script_hex = format!(
        "52{}53ae",
        FEE_FIXTURE_MULTISIG_KEYS
            .iter()
            .map(|public_key| format!("21{public_key}"))
            .collect::<String>()
    );
    let script_hash = hash160::Hash::hash(&hex::decode(&redeem_script_hex).unwrap());
    request.utxos[0] = SpendableUtxo {
        txid: txid.to_owned(),
        vout: 0,
        previous_output_value_koinu,
        script_pubkey_hex: format!("a914{}87", hex::encode(script_hash)),
        kind: SigningInputKind::P2shMultisig,
        redeem_script_hex: Some(redeem_script_hex),
        multisig_threshold,
        multisig_public_keys_hex,
        signers: vec![],
        manually_selected: false,
    };
    request.change = None;
    request.outputs[0].value_koinu = 9_000;
    request
}

#[test]
fn compose_builder_rejects_multisig_threshold_metadata_that_differs_from_redeem_script() {
    // The redeem script is 2-of-3. A declared threshold of 1 used to size the
    // transaction at 267 bytes instead of 343, so a 9_267 koinu UTXO "funded"
    // a 9_000 koinu spend whose real fee requirement is 343 koinu.
    for declared in [1u8, 3, 0] {
        let request = two_of_three_p2sh_request(9_267, Some(declared), fee_fixture_multisig_keys());
        let error = compose_and_sign_transaction(&request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("multisig threshold metadata does not match redeem script"),
            "declared threshold {declared}: {error}"
        );
    }
}

#[test]
fn compose_builder_derives_p2sh_multisig_fee_and_envelope_metadata_from_redeem_script() {
    let request = two_of_three_p2sh_request(9_343, None, vec![]);

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(result.estimated_size_bytes, 343);
    assert_eq!(result.fee_koinu, 343);
    assert!(result.signed_tx_hex.is_none());
    let envelope = result
        .signing_envelope
        .expect("no signers were supplied, so a signing envelope is returned");
    assert_eq!(envelope.inputs.len(), 1);
    assert_eq!(envelope.inputs[0].multisig_threshold, Some(2));
    assert_eq!(
        envelope.inputs[0].multisig_public_keys_hex,
        fee_fixture_multisig_keys()
    );
}

#[test]
fn compose_builder_emits_envelope_multisig_keys_in_redeem_script_order() {
    let mut reversed = fee_fixture_multisig_keys();
    reversed.reverse();
    let request = two_of_three_p2sh_request(9_343, Some(2), reversed);

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(result.estimated_size_bytes, 343);
    let envelope = result.signing_envelope.unwrap();
    assert_eq!(envelope.inputs[0].multisig_threshold, Some(2));
    assert_eq!(
        envelope.inputs[0].multisig_public_keys_hex,
        fee_fixture_multisig_keys()
    );
}

#[test]
fn compose_builder_rejects_multisig_public_key_metadata_that_differs_from_redeem_script() {
    let mut substituted = fee_fixture_multisig_keys();
    substituted[2] =
        "020000000000000000000000000000000000000000000000000000000000000004".to_owned();
    let mut truncated = fee_fixture_multisig_keys();
    truncated.pop();
    for declared in [substituted, truncated] {
        let request = two_of_three_p2sh_request(9_343, Some(2), declared);
        let error = compose_and_sign_transaction(&request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("multisig public key metadata does not match redeem script"),
            "{error}"
        );
    }
}

#[test]
fn compose_builder_signs_p2sh_multisig_without_metadata_within_the_estimated_size() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let mut request = compose_request_base(
        "9999999999999999999999999999999999999999999999999999999999999999",
        100_000_000,
    );
    let utxo = &mut request.utxos[0];
    utxo.kind = SigningInputKind::P2shMultisig;
    utxo.script_pubkey_hex = fixture.envelope.inputs[0].script_pubkey_hex.clone();
    utxo.redeem_script_hex = Some(fixture.descriptor.redeem_script_hex.clone());
    utxo.multisig_threshold = None;
    utxo.multisig_public_keys_hex = vec![];
    utxo.signers = fixture
        .wifs
        .iter()
        .map(|wif| UtxoSigner {
            kind: UtxoSignerKind::Wif,
            wif: Some(wif.clone()),
            xpriv: None,
            derivation_path: None,
        })
        .collect();

    let result = compose_and_sign_transaction(&request).unwrap();

    // 10 bytes of overhead + a 262-byte input (221-byte worst-case scriptSig)
    // + a 34-byte spend output + a 34-byte change output.
    assert_eq!(result.estimated_size_bytes, 340);
    assert_eq!(result.fee_koinu, 340);
    assert_eq!(result.change_amount_koinu, 100_000_000 - 50_000_000 - 340);
    assert!(result.signing_envelope.is_none());
    let signed_tx_hex = result.signed_tx_hex.expect("both cosigners signed");
    let actual_size_bytes = result
        .actual_size_bytes
        .expect("a signed transaction reports its size");
    assert_eq!(actual_size_bytes, signed_tx_hex.len() as u64 / 2);
    assert!(
        actual_size_bytes <= result.estimated_size_bytes,
        "actual size {actual_size_bytes} exceeds the estimate {}",
        result.estimated_size_bytes
    );
}

#[test]
fn compose_builder_rejects_p2pkh_utxo_whose_script_pubkey_is_not_pay_to_pubkey_hash() {
    for script_pubkey_hex in [
        // P2SH-shaped (23 bytes).
        "a914000000000000000000000000000000000000000087",
        // 25 bytes, but ends with OP_EQUAL OP_CHECKSIG instead of
        // OP_EQUALVERIFY OP_CHECKSIG.
        "76a914000000000000000000000000000000000000000087ac",
        // Empty script.
        "",
    ] {
        let mut request = compose_request_base(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            100_000_000,
        );
        request.utxos[0].script_pubkey_hex = script_pubkey_hex.to_owned();
        request.utxos[0].signers = vec![];
        let error = compose_and_sign_transaction(&request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("P2PKH UTXO script pubkey is not a pay-to-pubkey-hash script"),
            "script pubkey {script_pubkey_hex:?}: {error}"
        );
    }
}

#[test]
fn generated_mnemonic_debug_output_redacts_the_seed_phrase() {
    let fixed = GeneratedMnemonic {
        phrase: PHRASE.to_owned(),
        language: Language::English,
        word_count: 12,
    };
    for debug in [format!("{fixed:?}"), format!("{fixed:#?}")] {
        assert!(!debug.contains("abandon"), "leaked the seed phrase");
        assert!(debug.contains("[redacted]"), "no redaction marker");
        assert!(debug.contains("English"), "dropped the language");
        assert!(debug.contains("12"), "dropped the word count");
    }

    let generated = generate_mnemonic(MnemonicOptions {
        language: Language::English,
        word_count: 12,
    })
    .unwrap();
    let debug = format!("{generated:?}");
    assert!(!debug.contains(generated.phrase.as_str()));
    assert!(debug.contains("[redacted]"));
}

#[test]
fn generated_mnemonic_serialization_still_carries_the_seed_phrase() {
    // Serialization is the explicit export path (CLI `--reveal`, request
    // files). Only `Debug` is redacted.
    let fixed = GeneratedMnemonic {
        phrase: PHRASE.to_owned(),
        language: Language::English,
        word_count: 12,
    };
    let json = serde_json::to_value(&fixed).unwrap();
    assert_eq!(json["phrase"].as_str().unwrap(), PHRASE);
}

#[test]
fn account_key_set_debug_output_redacts_the_extended_private_key() {
    let vectors = vectors();
    let account = account_xpriv_from_mnemonic(
        PHRASE,
        Some("TREZOR"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    let xpriv = vectors["mnemonic"]["account"]["xpriv"].as_str().unwrap();
    let xpub = vectors["mnemonic"]["account"]["xpub"].as_str().unwrap();
    assert_eq!(account.xpriv.encoded, xpriv);
    for debug in [format!("{account:?}"), format!("{account:#?}")] {
        assert!(!debug.contains(xpriv), "leaked the xpriv");
        assert!(debug.contains("[redacted]"), "no redaction marker");
        assert!(debug.contains(xpub), "dropped the public xpub");
    }
}

#[test]
fn compose_request_debug_output_redacts_signer_and_change_secrets() {
    let vectors = vectors();
    let wif = parity_wif();
    let xpriv = easydoge_km::Xpriv {
        network: Network::Mainnet,
        encoded: vectors["mnemonic"]["account"]["xpriv"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let mut request = compose_request_base(
        "4444444444444444444444444444444444444444444444444444444444444444",
        100_000_000,
    );
    request.utxos[0].signers.push(UtxoSigner {
        kind: UtxoSignerKind::XprivDerivation,
        wif: None,
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/0/0".to_owned()),
    });
    request.change = Some(ChangeDestination {
        address: None,
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/1/0".to_owned()),
    });

    for debug in [
        format!("{request:?}"),
        format!("{request:#?}"),
        format!("{:?}", request.utxos[0]),
        format!("{:?}", request.utxos[0].signers),
        format!("{:?}", request.change),
    ] {
        assert!(!debug.contains(wif.as_str()), "leaked the WIF");
        assert!(!debug.contains(xpriv.encoded.as_str()), "leaked the xpriv");
        assert!(debug.contains("[redacted]"), "no redaction marker");
    }
}

// ---- Resource limits at request boundaries (`easydoge_km::limits`) ----

use easydoge_km::limits;

/// Error text of a call that must fail. Unlike `unwrap_err`, a missing limit
/// does not dump a megabyte-sized `Ok` value into the test output.
fn limit_error<T>(result: easydoge_km::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error, but the call succeeded"),
        Err(error) => error.to_string(),
    }
}

/// `count` copies of `template` with distinct outpoints (vout 0, 1, 2, ...)
/// and no signers, so the builder never signs and the tests stay fast.
fn unsigned_utxo_clones(template: &SpendableUtxo, count: usize) -> Vec<SpendableUtxo> {
    (0..count)
        .map(|vout| SpendableUtxo {
            vout: vout as u32,
            signers: vec![],
            ..template.clone()
        })
        .collect()
}

fn raw_script_output(script_hex: String) -> TransactionOutput {
    TransactionOutput {
        kind: TransactionOutputKind::ExpertRawScript,
        value_koinu: 1_000,
        address: None,
        op_return_data_hex: None,
        script_hex: Some(script_hex),
    }
}

/// The parity transaction plus one padding output, serialized to exactly
/// `target_len` bytes.
fn unsigned_tx_hex_with_serialized_len(target_len: usize) -> String {
    let mut tx: bitcoin::Transaction =
        deserialize(&hex::decode(parity_unsigned_tx_hex()).unwrap()).unwrap();
    tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(0),
        script_pubkey: bitcoin::ScriptBuf::new(),
    });
    // An empty script has a 1-byte length prefix; the padding script is longer
    // than 65,535 bytes and has a 5-byte prefix, hence the extra 4 bytes.
    let padding = target_len - serialize(&tx).len() - 4;
    tx.output[1].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x6a; padding]);
    let bytes = serialize(&tx);
    assert_eq!(bytes.len(), target_len);
    hex::encode(bytes)
}

#[test]
fn compose_builder_rejects_more_utxos_than_the_request_limit() {
    let mut request = compose_request_base(
        "8888888888888888888888888888888888888888888888888888888888888888",
        100_000_000,
    );
    let template = request.utxos[0].clone();

    request.utxos = unsigned_utxo_clones(&template, limits::MAX_REQUEST_UTXOS);
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.selected_inputs.len(), 1);

    request.utxos = unsigned_utxo_clones(&template, limits::MAX_REQUEST_UTXOS + 1);
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains("request has 10001 UTXOs, which exceeds the limit of 10000"),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_more_outputs_than_the_request_limit() {
    let mut request = compose_request_base(
        "9999999999999999999999999999999999999999999999999999999999999999",
        100_000_000,
    );
    request.utxos[0].signers = vec![];

    // One-byte scripts make 10-byte outputs, so 3,200 of them stay far below
    // the transaction size limit.
    request.outputs = vec![raw_script_output("51".to_owned()); limits::MAX_REQUEST_OUTPUTS];
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.spend_output_total_koinu, 3_200_000);

    request.outputs.push(raw_script_output("51".to_owned()));
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains("request has 3201 outputs, which exceeds the limit of 3200"),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_more_signers_on_one_utxo_than_the_limit() {
    let mut request = compose_request_base(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        100_000_000,
    );
    let signer = request.utxos[0].signers[0].clone();

    request.utxos[0].signers = vec![signer.clone(); limits::MAX_SIGNERS_PER_UTXO];
    let result = compose_and_sign_transaction(&request).unwrap();
    assert!(result.signed_tx_hex.is_some());

    request.utxos[0].signers.push(signer);
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains("UTXO at index 0 has 17 signers, which exceeds the limit of 16"),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_scripts_longer_than_the_script_size_limit() {
    let base = compose_request_base(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        100_000_000,
    );
    let at_limit = "51".repeat(limits::MAX_SCRIPT_BYTES);
    let over_limit = "51".repeat(limits::MAX_SCRIPT_BYTES + 1);
    let limit_text = "has 20002 hex characters, which exceeds the limit of 20000 (10000 bytes)";

    let mut request = base.clone();
    request.outputs.push(raw_script_output(at_limit));
    let result = compose_and_sign_transaction(&request).unwrap();
    assert!(result.estimated_size_bytes > 10_000);

    let mut request = base.clone();
    request.outputs.push(raw_script_output(over_limit.clone()));
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains(&format!("output at index 1 script {limit_text}")),
        "{error}"
    );

    let mut request = base.clone();
    request.utxos[0].script_pubkey_hex = over_limit.clone();
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains(&format!("UTXO at index 0 script pubkey {limit_text}")),
        "{error}"
    );

    let mut request = base;
    request.utxos[0].redeem_script_hex = Some(over_limit);
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains(&format!("UTXO at index 0 redeem script {limit_text}")),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_payment_that_needs_more_inputs_than_a_standard_transaction_holds() {
    // A P2PKH input is estimated at 149 bytes, so the 680 inputs this payment
    // needs cannot fit in 99,999 bytes.
    let mut request = compose_request_base(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        1_000_000,
    );
    request.coin_selection = CoinSelectionStrategy::LargestFirst;
    let template = request.utxos[0].clone();
    request.utxos = unsigned_utxo_clones(&template, 680);
    request.outputs[0].value_koinu = 679_500_000;
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(error.contains("estimated transaction size is"), "{error}");
    assert!(
        error.contains("which exceeds the limit of 99999 bytes"),
        "{error}"
    );
}

#[test]
fn compose_builder_accepts_transaction_estimated_at_exactly_the_size_limit() {
    // 670 P2PKH inputs, the address output, one padding output and change:
    // 12 + 670 * 149 + 34 + (9 + padding) + 34 bytes.
    let request_with_padding = |padding_bytes: usize| {
        let mut request = compose_request_base(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            1_000_000,
        );
        request.coin_selection = CoinSelectionStrategy::LargestFirst;
        let template = request.utxos[0].clone();
        request.utxos = unsigned_utxo_clones(&template, 670);
        request.outputs[0].value_koinu = 669_500_000;
        request
            .outputs
            .push(raw_script_output("51".repeat(padding_bytes)));
        request
    };

    let result = compose_and_sign_transaction(&request_with_padding(80)).unwrap();
    assert_eq!(result.selected_inputs.len(), 670);
    assert!(result.change_amount_koinu > 0);
    assert_eq!(
        result.estimated_size_bytes,
        limits::MAX_TRANSACTION_BYTES as u64
    );

    let error = limit_error(compose_and_sign_transaction(&request_with_padding(81)));
    assert!(
        error.contains(
            "estimated transaction size is 100000 bytes, which exceeds the limit of 99999 bytes"
        ),
        "{error}"
    );
}

#[test]
fn base58check_text_longer_than_an_extended_key_is_rejected_without_decoding() {
    let over_limit = "2".repeat(limits::MAX_BASE58CHECK_CHARS + 1);
    let error = limit_error(address_from_wif(Network::Mainnet, &over_limit));
    assert!(
        error.contains("base58check value has 113 characters, which exceeds the limit of 112"),
        "{error}"
    );

    // The limit is about length only: 112 characters are still decoded, and
    // rejected for what they are.
    let at_limit = "2".repeat(limits::MAX_BASE58CHECK_CHARS);
    let error = limit_error(address_from_wif(Network::Mainnet, &at_limit));
    assert!(!error.contains("exceeds the limit"), "{error}");

    // 100,000 characters take seconds to decode; with the limit they cost
    // nothing. Address validation keeps answering "not an address".
    let huge = "2".repeat(100_000);
    assert!(!easydoge_km::validate_address(Network::Mainnet, &huge).unwrap());
    assert!(inspect_address(&huge).unwrap().is_empty());
    let mut request = compose_request_base(
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        100_000_000,
    );
    request.outputs[0].address = Some(huge);
    let error = limit_error(compose_and_sign_transaction(&request));
    assert!(
        error.contains("base58check value has 100000 characters, which exceeds the limit of 112"),
        "{error}"
    );
}

#[test]
fn signing_envelope_rejects_unsigned_transaction_above_the_size_limit() {
    let mut envelope = p2pkh_envelope();

    envelope.unsigned_tx_hex = unsigned_tx_hex_with_serialized_len(limits::MAX_TRANSACTION_BYTES);
    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(signed.signatures.len(), 1);

    envelope.unsigned_tx_hex =
        unsigned_tx_hex_with_serialized_len(limits::MAX_TRANSACTION_BYTES + 1);
    let error = limit_error(sign_signing_envelope(&envelope, &parity_wif()));
    assert!(
        error.contains(
            "unsigned transaction has 200000 hex characters, which exceeds the limit of 199998 (99999 bytes)"
        ),
        "{error}"
    );
}

#[test]
fn signing_envelope_entry_points_check_transaction_size_before_decoding_hex() {
    // Not hex at all: getting the size error proves nothing was decoded.
    let oversized = "zz".repeat(limits::MAX_TRANSACTION_BYTES + 1);
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = oversized.clone();

    let errors = [
        limit_error(sign_signing_envelope(&envelope, &parity_wif())),
        limit_error(combine_signing_envelopes(std::slice::from_ref(&envelope))),
        limit_error(finalize_signing_envelope(&envelope)),
        limit_error(sign_p2pkh_transaction(
            Network::Mainnet,
            &oversized,
            0,
            &parity_script_pubkey_hex(),
            &parity_wif(),
            1,
        )),
    ];
    for error in errors {
        assert!(
            error.contains(
                "unsigned transaction has 200000 hex characters, which exceeds the limit of 199998 (99999 bytes)"
            ),
            "{error}"
        );
    }
}

#[test]
fn signing_envelope_rejects_more_signatures_than_its_inputs_allow_before_verifying_them() {
    let signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();

    // Sixteen copies of a valid signature on a one-input transaction are
    // redundant but within the limit.
    let mut at_limit = signed.clone();
    at_limit.signatures =
        vec![signed.signatures[0].clone(); limits::MAX_ENVELOPE_SIGNATURES_PER_INPUT];
    finalize_signing_envelope(&at_limit).unwrap();

    // Seventeen entries that are not signatures at all: getting the count
    // error proves none of them was decoded or verified.
    let mut over_limit = signed;
    over_limit.signatures = vec![
        SigningEnvelopeSignature {
            input_index: 0,
            public_key_hex: "00".to_owned(),
            signature_hex: "00".to_owned(),
        };
        limits::MAX_ENVELOPE_SIGNATURES_PER_INPUT + 1
    ];
    let errors = [
        limit_error(sign_signing_envelope(&over_limit, &parity_wif())),
        limit_error(combine_signing_envelopes(std::slice::from_ref(&over_limit))),
        limit_error(finalize_signing_envelope(&over_limit)),
    ];
    for error in errors {
        assert!(
            error.contains(
                "signing envelope has 17 signatures, which exceeds the limit of 16 (16 per transaction input)"
            ),
            "{error}"
        );
    }
}

#[test]
fn signing_envelope_rejects_descriptor_scripts_longer_than_the_script_size_limit() {
    let over_limit = "51".repeat(limits::MAX_SCRIPT_BYTES + 1);
    let limit_text = "has 20002 hex characters, which exceeds the limit of 20000 (10000 bytes)";

    let mut envelope = p2pkh_envelope();
    envelope.inputs[0].script_pubkey_hex = over_limit.clone();
    let error = limit_error(sign_signing_envelope(&envelope, &parity_wif()));
    assert!(
        error.contains(&format!("input 0 script pubkey {limit_text}")),
        "{error}"
    );

    let mut fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    fixture.envelope.inputs[0].redeem_script_hex = Some(over_limit);
    let error = limit_error(sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]));
    assert!(
        error.contains(&format!("input 0 redeem script {limit_text}")),
        "{error}"
    );
}

#[test]
fn combine_rejects_more_envelopes_than_the_limit() {
    let signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();

    let at_limit = vec![signed.clone(); limits::MAX_ENVELOPES_PER_COMBINE];
    let combined = combine_signing_envelopes(&at_limit).unwrap();
    assert_eq!(combined.signatures.len(), 1);

    let over_limit = vec![signed; limits::MAX_ENVELOPES_PER_COMBINE + 1];
    let error = limit_error(combine_signing_envelopes(&over_limit));
    assert!(
        error.contains("combine request has 65 signing envelopes, which exceeds the limit of 64"),
        "{error}"
    );
}

#[test]
fn combine_rejects_a_result_with_more_signatures_than_its_inputs_allow() {
    let signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let signature = signed.signatures[0].clone();
    // Hex is case-insensitive, so upper-casing one letter of the signature hex
    // gives an entry that still verifies but is a different string, which
    // combining keeps as a separate signature.
    let letter_positions = signature
        .signature_hex
        .char_indices()
        .filter(|(_, character)| character.is_ascii_lowercase())
        .map(|(position, _)| position)
        .take(limits::MAX_ENVELOPE_SIGNATURES_PER_INPUT)
        .collect::<Vec<_>>();
    assert_eq!(
        letter_positions.len(),
        limits::MAX_ENVELOPE_SIGNATURES_PER_INPUT,
        "the fixture signature needs at least 16 hex letters"
    );
    let mut envelopes = vec![signed.clone()];
    for position in letter_positions {
        let mut variant = signature.clone();
        let upper = signature.signature_hex[position..=position].to_ascii_uppercase();
        variant
            .signature_hex
            .replace_range(position..=position, &upper);
        let mut envelope = signed.clone();
        envelope.signatures = vec![variant];
        envelopes.push(envelope);
    }

    // Sixteen distinct entries for the single input are within the limit...
    let combined = combine_signing_envelopes(&envelopes[..16]).unwrap();
    assert_eq!(combined.signatures.len(), 16);
    // ...the seventeenth is not.
    let error = limit_error(combine_signing_envelopes(&envelopes));
    assert!(
        error.contains(
            "signing envelope has 17 signatures, which exceeds the limit of 16 (16 per transaction input)"
        ),
        "{error}"
    );
}

#[test]
fn derivation_deeper_than_bip32_allows_is_an_error_not_a_panic() {
    // Characterization test: the bitcoin crate stops at depth 255, so the SDK
    // needs no limit of its own. The account key sits at depth 3.
    let account =
        account_xpriv_from_mnemonic(PHRASE, None, Language::English, Network::Mainnet, 0).unwrap();
    let deepest = format!("m/{}", vec!["0"; 252].join("/"));
    derive_path_from_xpriv(&account.xpriv, &deepest).unwrap();
    let too_deep = format!("m/{}", vec!["0"; 253].join("/"));
    let error = limit_error(derive_path_from_xpriv(&account.xpriv, &too_deep));
    assert!(error.contains("depth 256"), "{error}");
    let error = limit_error(derive_address_from_xpub(&account.xpub, &too_deep));
    assert!(error.contains("depth 256"), "{error}");
}

// ---- Coin Selection and change funding ----
//
// Size arithmetic used by the tests below (serialized bytes, as estimated by
// the builder; with `fee_rate_koinu_per_kb = 1_000` the fee in koinu equals
// the size in bytes):
//   transaction overhead            4 + 1 + 1 + 4           =  10
//   one P2PKH output                8 + 1 + 25              =  34
//   one P2PKH input                 32 + 4 + 1 + 108 + 4    = 149
//   one 2-of-2 P2SH multisig input  32 + 4 + 1 + 221 + 4    = 262
//   1 P2PKH input, 1 output: 193    with a change output: 227
//   2 P2PKH inputs, 1 output: 342   with a change output: 376
//   3 P2PKH inputs, 1 output: 491   with a change output: 525
//   1 multisig input, 1 output: 306
//   1 multisig + 1 P2PKH input, 1 output: 455; with a change output: 489

/// A 2-of-2 P2SH multisig UTXO built from the shared fixture keys, without
/// signer material.
fn two_of_two_utxo(txid: &str, previous_output_value_koinu: u64) -> SpendableUtxo {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    SpendableUtxo {
        txid: txid.to_owned(),
        vout: 0,
        previous_output_value_koinu,
        script_pubkey_hex: fixture.envelope.inputs[0].script_pubkey_hex.clone(),
        kind: SigningInputKind::P2shMultisig,
        redeem_script_hex: Some(fixture.descriptor.redeem_script_hex.clone()),
        multisig_threshold: Some(2),
        multisig_public_keys_hex: fixture.descriptor.public_keys_hex.clone(),
        signers: vec![],
        manually_selected: false,
    }
}

/// Appends a copy of the request's first (P2PKH) UTXO with a new outpoint
/// and value.
fn push_p2pkh_utxo(
    request: &mut ComposeTransactionRequest,
    txid: &str,
    vout: u32,
    previous_output_value_koinu: u64,
) {
    let mut utxo = request.utxos[0].clone();
    utxo.txid = txid.to_owned();
    utxo.vout = vout;
    utxo.previous_output_value_koinu = previous_output_value_koinu;
    request.utxos.push(utxo);
}

fn selected_outpoints(result: &easydoge_km::ComposeTransactionResult) -> Vec<(String, u32)> {
    result
        .selected_inputs
        .iter()
        .map(|input| (input.txid.clone(), input.vout))
        .collect()
}

fn selected_values(result: &easydoge_km::ComposeTransactionResult) -> Vec<u64> {
    result
        .selected_inputs
        .iter()
        .map(|input| input.previous_output_value_koinu)
        .collect()
}

#[test]
fn compose_builder_min_inputs_prefers_one_cheap_input_over_a_larger_costlier_input() {
    let p2pkh_txid = "a1".repeat(32);
    let multisig_txid = "b2".repeat(32);
    // Spend 9_000. The P2PKH UTXO funds it alone: 9_193 = 9_000 + 193.
    // The multisig UTXO has the larger raw value but cannot: 9_250 < 9_000 + 306.
    // Net of its own input fee the multisig UTXO is worth less:
    //   P2PKH    9_193 - 149 = 9_044
    //   multisig 9_250 - 262 = 8_988
    let mut request = compose_request_base(&p2pkh_txid, 9_193);
    request.utxos.push(two_of_two_utxo(&multisig_txid, 9_250));
    request.outputs[0].value_koinu = 9_000;
    request.coin_selection = CoinSelectionStrategy::MinInputs;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(selected_outpoints(&result), vec![(p2pkh_txid, 0)]);
    assert_eq!(result.estimated_size_bytes, 193);
    assert_eq!(result.fee_koinu, 193);
    assert_eq!(result.change_amount_koinu, 0);
    assert!(!result.dust_change_folded_into_fee);
    assert_eq!(result.skipped_inputs.len(), 1);
    assert_eq!(result.skipped_inputs[0].txid, multisig_txid);
    assert_eq!(result.skipped_inputs[0].reason, "not selected by strategy");
    assert!(result.signed_tx_hex.is_some());
}

#[test]
fn compose_builder_largest_first_orders_mixed_input_kinds_by_raw_value() {
    let p2pkh_txid = "a1".repeat(32);
    let multisig_txid = "b2".repeat(32);
    // Same UTXOs as the MinInputs test above. LargestFirst is defined on raw
    // value, so it starts with the 9_250 multisig UTXO (not enough alone:
    // 9_250 < 9_000 + 306) and then adds the 9_193 P2PKH UTXO.
    let mut request = compose_request_base(&p2pkh_txid, 9_193);
    request.utxos.push(two_of_two_utxo(&multisig_txid, 9_250));
    request.outputs[0].value_koinu = 9_000;
    request.coin_selection = CoinSelectionStrategy::LargestFirst;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(
        selected_outpoints(&result),
        vec![(multisig_txid, 0), (p2pkh_txid, 0)]
    );
    assert_eq!(result.input_total_koinu, 18_443);
    // 10 + 262 + 149 + 34 + 34 = 489 bytes with the change output. This pins
    // the 262-byte estimate for a 2-of-2 multisig input used in this section.
    assert_eq!(result.estimated_size_bytes, 489);
    assert_eq!(result.fee_koinu, 489);
    assert_eq!(result.change_amount_koinu, 8_954);
    assert!(result.skipped_inputs.is_empty());
    // The multisig input has no signers, so the result is a Signing Envelope.
    assert!(result.signed_tx_hex.is_none());
    assert!(result.signing_envelope.is_some());
}

#[test]
fn compose_builder_strategies_keep_raw_value_order_for_equal_cost_inputs() {
    // Three P2PKH UTXOs cost the same to spend, so ordering by value net of
    // the input fee is the same as ordering by raw value.
    let mut request = compose_request_base(&"c1".repeat(32), 30_000_000);
    push_p2pkh_utxo(&mut request, &"c2".repeat(32), 0, 80_000_000);
    push_p2pkh_utxo(&mut request, &"c3".repeat(32), 0, 50_000_000);
    request.outputs[0].value_koinu = 100_000_000;

    for strategy in [
        CoinSelectionStrategy::MinInputs,
        CoinSelectionStrategy::LargestFirst,
    ] {
        request.coin_selection = strategy;
        let result = compose_and_sign_transaction(&request).unwrap();
        // 80M alone is short; 80M + 50M pays 100M + 376 with change.
        assert_eq!(
            selected_values(&result),
            vec![80_000_000, 50_000_000],
            "{strategy:?}"
        );
        assert_eq!(result.fee_koinu, 376, "{strategy:?}");
        assert_eq!(result.change_amount_koinu, 29_999_624, "{strategy:?}");
        assert_eq!(result.skipped_inputs.len(), 1, "{strategy:?}");
    }

    request.coin_selection = CoinSelectionStrategy::SmallestFirst;
    let result = compose_and_sign_transaction(&request).unwrap();
    // 30M and 30M + 50M are short; all three pay 100M + 525 with change.
    assert_eq!(
        selected_values(&result),
        vec![30_000_000, 50_000_000, 80_000_000]
    );
    assert_eq!(result.fee_koinu, 525);
    assert_eq!(result.change_amount_koinu, 59_999_475);
    assert!(result.skipped_inputs.is_empty());
}

#[test]
fn compose_builder_selection_is_deterministic_for_equal_value_utxos() {
    let low_txid = "aa".repeat(32);
    let high_txid = "bb".repeat(32);
    // Three equal P2PKH UTXOs; one is enough. Ties break by txid text, then
    // vout, whatever order the caller lists them in.
    let mut request = compose_request_base(&high_txid, 100_000_000);
    push_p2pkh_utxo(&mut request, &low_txid, 1, 100_000_000);
    push_p2pkh_utxo(&mut request, &low_txid, 0, 100_000_000);

    for strategy in [
        CoinSelectionStrategy::MinInputs,
        CoinSelectionStrategy::LargestFirst,
        CoinSelectionStrategy::SmallestFirst,
    ] {
        request.coin_selection = strategy;
        let listed = compose_and_sign_transaction(&request).unwrap();
        let mut reversed_request = request.clone();
        reversed_request.utxos.reverse();
        let reversed = compose_and_sign_transaction(&reversed_request).unwrap();

        assert_eq!(
            selected_outpoints(&listed),
            vec![(low_txid.clone(), 0)],
            "{strategy:?}"
        );
        assert_eq!(
            selected_outpoints(&reversed),
            selected_outpoints(&listed),
            "{strategy:?}"
        );
        assert_eq!(
            listed.unsigned_tx_hex, reversed.unsigned_tx_hex,
            "{strategy:?}"
        );
    }
}

#[test]
fn compose_builder_folds_a_remainder_that_cannot_pay_for_change_into_the_fee() {
    // One P2PKH input and one output need a fee of 193; a change output
    // would raise the fee by 34 to 227. `remainder` is what is left after
    // the spend and the 193 fee.
    //   remainder  0      -> exact, nothing folded
    //   remainder  1..=33 -> cannot pay for the change output: fold
    //   remainder  34     -> pays for the change output but leaves 0: fold
    //   remainder  35     -> change output of 1 koinu (dust threshold is 1)
    for (remainder, expected_fee, expected_change, expected_folded) in [
        (0u64, 193u64, 0u64, false),
        (1, 194, 0, true),
        (10, 203, 0, true),
        (33, 226, 0, true),
        (34, 227, 0, true),
        (35, 227, 1, false),
    ] {
        let request = compose_request_base(&"d1".repeat(32), 50_000_000 + 193 + remainder);

        let result = compose_and_sign_transaction(&request)
            .unwrap_or_else(|error| panic!("remainder {remainder}: {error}"));

        assert_eq!(result.selected_inputs.len(), 1, "remainder {remainder}");
        assert_eq!(result.fee_koinu, expected_fee, "remainder {remainder}");
        assert_eq!(
            result.change_amount_koinu, expected_change,
            "remainder {remainder}"
        );
        assert_eq!(
            result.dust_change_folded_into_fee, expected_folded,
            "remainder {remainder}"
        );
        assert_eq!(
            result.change_address.is_some(),
            expected_change > 0,
            "remainder {remainder}"
        );
        assert_eq!(
            result.estimated_size_bytes,
            if expected_change > 0 { 227 } else { 193 },
            "remainder {remainder}"
        );
        assert_eq!(
            result.input_total_koinu,
            result.spend_output_total_koinu + result.change_amount_koinu + result.fee_koinu,
            "remainder {remainder}"
        );
        assert!(result.signed_tx_hex.is_some(), "remainder {remainder}");
    }
}

#[test]
fn compose_builder_does_not_add_an_input_to_pay_for_a_change_output() {
    let funding_txid = "e1".repeat(32);
    // The first UTXO pays the spend and the 193 fee with 10 koinu left over.
    // The builder must fold those 10 koinu into the fee instead of pulling in
    // the second UTXO to afford a change output.
    let mut request = compose_request_base(&funding_txid, 50_000_203);
    push_p2pkh_utxo(&mut request, &"e2".repeat(32), 0, 1_000);

    for strategy in [
        CoinSelectionStrategy::MinInputs,
        CoinSelectionStrategy::LargestFirst,
    ] {
        request.coin_selection = strategy;
        let result = compose_and_sign_transaction(&request).unwrap();
        assert_eq!(
            selected_outpoints(&result),
            vec![(funding_txid.clone(), 0)],
            "{strategy:?}"
        );
        assert_eq!(result.fee_koinu, 203, "{strategy:?}");
        assert_eq!(result.change_amount_koinu, 0, "{strategy:?}");
        assert!(result.dust_change_folded_into_fee, "{strategy:?}");
        assert_eq!(result.skipped_inputs.len(), 1, "{strategy:?}");
    }
}

#[test]
fn compose_builder_every_strategy_funds_a_single_utxo_with_unaffordable_change() {
    for strategy in [
        CoinSelectionStrategy::MinInputs,
        CoinSelectionStrategy::SmallestFirst,
        CoinSelectionStrategy::LargestFirst,
        CoinSelectionStrategy::ManualSelectedInputs,
    ] {
        let mut request = compose_request_base(&"f1".repeat(32), 50_000_203);
        request.utxos[0].manually_selected = true;
        request.coin_selection = strategy;

        let result = compose_and_sign_transaction(&request)
            .unwrap_or_else(|error| panic!("{strategy:?}: {error}"));

        assert_eq!(result.selected_inputs.len(), 1, "{strategy:?}");
        assert!(result.skipped_inputs.is_empty(), "{strategy:?}");
        assert_eq!(result.fee_koinu, 203, "{strategy:?}");
        assert_eq!(result.change_amount_koinu, 0, "{strategy:?}");
        assert!(result.change_address.is_none(), "{strategy:?}");
        assert!(result.dust_change_folded_into_fee, "{strategy:?}");
    }
}

#[test]
fn compose_builder_with_zero_dust_threshold_neither_requires_nor_creates_empty_change() {
    // Exact funding, no change destination: nothing remains, so none is needed.
    let mut request = compose_request_base(&"0a".repeat(32), 50_000_193);
    request.fee_policy.dust_threshold_koinu = 0;
    request.change = None;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.fee_koinu, 193);
    assert_eq!(result.change_amount_koinu, 0);
    assert!(!result.dust_change_folded_into_fee);

    // Exact funding with a change destination: still no change output.
    let mut request = compose_request_base(&"0b".repeat(32), 50_000_193);
    request.fee_policy.dust_threshold_koinu = 0;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.fee_koinu, 193);
    assert!(result.change_address.is_none());
    assert!(!result.dust_change_folded_into_fee);

    // The remainder (34) pays exactly for a change output that would then be
    // worth 0 koinu: fold it instead of emitting a zero-value output.
    let mut request = compose_request_base(&"0c".repeat(32), 50_000_227);
    request.fee_policy.dust_threshold_koinu = 0;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.fee_koinu, 227);
    assert_eq!(result.change_amount_koinu, 0);
    assert!(result.change_address.is_none());
    assert!(result.change_script_pubkey_hex.is_none());
    assert!(result.dust_change_folded_into_fee);
    assert_eq!(result.estimated_size_bytes, 193);
}

#[test]
fn compose_builder_still_requires_a_change_destination_for_a_non_dust_remainder() {
    // 10 koinu remain and the dust threshold is 1. Without a change
    // destination the builder cannot measure a change output, so it refuses
    // rather than silently paying the remainder as fee.
    let mut request = compose_request_base(&"0d".repeat(32), 50_000_203);
    request.change = None;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("change destination is required when change is not dust"),
        "{error}"
    );
}

#[test]
fn compose_builder_reports_insufficient_funds_when_the_remaining_input_costs_more_than_it_adds() {
    // Spend 9_100. The first UTXO is 100 short of 9_100 + 193. The second is
    // worth 120 koinu but costs 149 to spend, so adding it cannot help:
    // 9_193 + 120 = 9_313 < 9_100 + 342.
    let mut request = compose_request_base(&"1a".repeat(32), 9_193);
    push_p2pkh_utxo(&mut request, &"1b".repeat(32), 0, 120);
    request.outputs[0].value_koinu = 9_100;

    for strategy in [
        CoinSelectionStrategy::MinInputs,
        CoinSelectionStrategy::SmallestFirst,
        CoinSelectionStrategy::LargestFirst,
    ] {
        request.coin_selection = strategy;
        let error = compose_and_sign_transaction(&request).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("insufficient funds for outputs and fee"),
            "{strategy:?}: {error}"
        );
    }
}

#[test]
fn compose_builder_min_inputs_still_rejects_a_reachable_utxo_without_a_redeem_script() {
    // The multisig UTXO has the largest value but no redeem script, so its
    // input size cannot be estimated. Ordering must not panic, and because
    // the UTXO is still the first candidate its validation error surfaces.
    let mut request = compose_request_base(&"2a".repeat(32), 100_000_000);
    let mut broken = two_of_two_utxo(&"2b".repeat(32), 200_000_000);
    broken.redeem_script_hex = None;
    request.utxos.push(broken);
    request.coin_selection = CoinSelectionStrategy::MinInputs;

    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("P2SH multisig UTXO requires redeem script"),
        "{error}"
    );
}

#[test]
fn compose_builder_min_inputs_matches_the_exhaustive_minimum_for_mixed_input_kinds() {
    // Deterministic pseudo-random requests mixing P2PKH (149-byte) and 2-of-2
    // multisig (262-byte) inputs. The expected input count comes from trying
    // every subset with the fee arithmetic written out independently here.
    let multisig_template = two_of_two_utxo(&"00".repeat(32), 0);
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % bound
    };

    for case in 0..200u32 {
        let fee_rate = [1_000u64, 2_500, 777][(case % 3) as usize];
        let utxo_count = 2 + next(5) as usize;
        let mut request = compose_request_base(&"00".repeat(32), 0);
        let p2pkh_template = request.utxos.remove(0);
        let mut candidates = Vec::new();
        for position in 0..utxo_count {
            let is_multisig = next(2) == 1;
            let value = 100 + next(1_400);
            let mut utxo = if is_multisig {
                multisig_template.clone()
            } else {
                p2pkh_template.clone()
            };
            utxo.txid = format!("{:064x}", (u64::from(case) << 8) | position as u64);
            utxo.previous_output_value_koinu = value;
            candidates.push((value, if is_multisig { 262u64 } else { 149u64 }));
            request.utxos.push(utxo);
        }
        let spend = 1 + next(2_500);
        request.outputs[0].value_koinu = spend;
        request.fee_policy.fee_rate_koinu_per_kb = fee_rate;
        request.coin_selection = CoinSelectionStrategy::MinInputs;

        let expected_minimum = (1u32..(1 << utxo_count))
            .filter(|subset| {
                let chosen = candidates
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| subset & (1 << position) != 0);
                let (total, size) = chosen.fold((0u64, 44u64), |(total, size), (_, utxo)| {
                    (total + utxo.0, size + utxo.1)
                });
                total >= spend + (size * fee_rate).div_ceil(1_000)
            })
            .map(u32::count_ones)
            .min();

        match (compose_and_sign_transaction(&request), expected_minimum) {
            (Ok(result), Some(minimum)) => {
                assert_eq!(result.selected_inputs.len() as u32, minimum, "case {case}");
            }
            (Err(error), None) => {
                assert!(
                    error.to_string().contains("insufficient funds"),
                    "case {case}: {error}"
                );
            }
            (outcome, expected) => panic!(
                "case {case}: builder {:?}, exhaustive minimum {expected:?}",
                outcome.map(|result| result.selected_inputs.len())
            ),
        }
    }
}

// --- Uncompressed WIF keys ---------------------------------------------------
//
// Known answers below come from outside this crate: the hash160 values of the
// secp256k1 generator point are long-published constants, and the message
// signature and signed transaction were produced with bitcoinjs-lib and
// tiny-secp256k1 (RFC 6979 deterministic signatures).

const KEY_ONE_UNCOMPRESSED_HASH160: &str = "91b24bf9f5288532960ac687abb035127b1d28a5";
const KEY_ONE_COMPRESSED_HASH160: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
const KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const KEY_ONE_COMPRESSED_PUBLIC_KEY_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const KEY_ONE_MESSAGE: &str = "EasyDoge KM uncompressed parity";
const KEY_ONE_UNCOMPRESSED_MESSAGE_SIGNATURE: &str =
    "GxtcrO1RKjW+hv4oTrtWV4UC5lqcWto7FaPive+hwhXnFIApjy9to6sJPUX1RkqBkAv8QgLvMEVBNOMKZnDYXgk=";
const KEY_ONE_COMPRESSED_MESSAGE_SIGNATURE: &str =
    "HxtcrO1RKjW+hv4oTrtWV4UC5lqcWto7FaPive+hwhXnFIApjy9to6sJPUX1RkqBkAv8QgLvMEVBNOMKZnDYXgk=";
const KEY_ONE_UNCOMPRESSED_SIGNED_TX_HEX: &str = "0100000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000008a4730440220152f88f6a4dad7239044d9ab57899707d9e04993969a8c3fbcf62608854d8af202206290d12c4b3b5820a44340979438e961a5075146c40a7ac36fbe293e0f8106d901410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ffffffff0100e1f505000000001976a914b68208afee956eedc5cfac4b1998ac0afa6f2ddd88ac00000000";

/// WIF for the private key scalar 1 (the secp256k1 generator's key). It is a
/// public throwaway used across Bitcoin-family test suites, built here so no
/// WIF literal is committed.
fn key_one_wif(compressed: bool) -> String {
    let mut payload = vec![Network::Mainnet.prefixes().wif];
    payload.extend_from_slice(&[0u8; 31]);
    payload.push(1);
    if compressed {
        payload.push(0x01);
    }
    bs58::encode(payload).with_check().into_string()
}

/// Re-encodes a compressed WIF without its `0x01` suffix.
fn without_compression_flag(wif: &str) -> String {
    let mut payload = bs58::decode(wif).with_check(None).into_vec().unwrap();
    assert_eq!(payload.pop(), Some(0x01), "expected a compressed WIF");
    bs58::encode(payload).with_check().into_string()
}

fn p2pkh_script_pubkey_hex(pubkey_hash_hex: &str) -> String {
    format!("76a914{pubkey_hash_hex}88ac")
}

fn p2pkh_payload_hex(address: &str) -> String {
    let matches = inspect_address(address).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].kind, AddressKind::P2pkh);
    matches[0].payload_hex.clone()
}

fn key_one_envelope(pubkey_hash_hex: &str) -> SigningEnvelope {
    let mut envelope = p2pkh_envelope();
    envelope.inputs[0].script_pubkey_hex = p2pkh_script_pubkey_hex(pubkey_hash_hex);
    envelope
}

fn key_one_compose_request(compressed: bool) -> ComposeTransactionRequest {
    let mut request = compose_request_base(
        "8888888888888888888888888888888888888888888888888888888888888888",
        150_000_000,
    );
    request.utxos[0].script_pubkey_hex = p2pkh_script_pubkey_hex(if compressed {
        KEY_ONE_COMPRESSED_HASH160
    } else {
        KEY_ONE_UNCOMPRESSED_HASH160
    });
    request.utxos[0].signers[0].wif = Some(key_one_wif(compressed));
    request
}

#[test]
fn uncompressed_wif_import_reports_the_uncompressed_public_key_and_its_address() {
    let info = address_from_wif(Network::Mainnet, &key_one_wif(false)).unwrap();
    assert!(!info.compressed);
    assert_eq!(info.public_key_hex, KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX);
    assert_eq!(info.public_key_hex.len(), 130);
    assert_eq!(
        p2pkh_payload_hex(&info.address),
        KEY_ONE_UNCOMPRESSED_HASH160
    );
}

#[test]
fn compressed_wif_import_still_reports_the_compressed_public_key_and_its_address() {
    let info = address_from_wif(Network::Mainnet, &key_one_wif(true)).unwrap();
    assert!(info.compressed);
    assert_eq!(info.public_key_hex, KEY_ONE_COMPRESSED_PUBLIC_KEY_HEX);
    assert_eq!(p2pkh_payload_hex(&info.address), KEY_ONE_COMPRESSED_HASH160);
}

#[test]
fn message_signing_with_uncompressed_wif_uses_the_uncompressed_header_and_address() {
    let wif = key_one_wif(false);
    let signature = sign_message(Network::Mainnet, &wif, KEY_ONE_MESSAGE).unwrap();
    assert_eq!(
        p2pkh_payload_hex(&signature.address),
        KEY_ONE_UNCOMPRESSED_HASH160
    );
    let compact = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &signature.signature_base64,
    )
    .unwrap();
    assert!(
        (27..=30).contains(&compact[0]),
        "uncompressed keys sign with header 27..=30, got {}",
        compact[0]
    );
    assert_eq!(
        signature.signature_base64,
        KEY_ONE_UNCOMPRESSED_MESSAGE_SIGNATURE
    );
    assert!(verify_message(
        Network::Mainnet,
        &signature.address,
        &signature.signature_base64,
        KEY_ONE_MESSAGE
    )
    .unwrap());
}

#[test]
fn message_signing_with_compressed_wif_keeps_the_compressed_header_and_address() {
    let signature = sign_message(Network::Mainnet, &key_one_wif(true), KEY_ONE_MESSAGE).unwrap();
    assert_eq!(
        p2pkh_payload_hex(&signature.address),
        KEY_ONE_COMPRESSED_HASH160
    );
    assert_eq!(
        signature.signature_base64,
        KEY_ONE_COMPRESSED_MESSAGE_SIGNATURE
    );
}

#[test]
fn verify_message_matches_the_address_form_named_by_the_signature_header() {
    let uncompressed = address_from_wif(Network::Mainnet, &key_one_wif(false))
        .unwrap()
        .address;
    let compressed = address_from_wif(Network::Mainnet, &key_one_wif(true))
        .unwrap()
        .address;
    let verify = |address: &str, signature: &str| {
        verify_message(Network::Mainnet, address, signature, KEY_ONE_MESSAGE).unwrap()
    };
    // Independently produced signature from the uncompressed key (header 27).
    assert!(verify(
        &uncompressed,
        KEY_ONE_UNCOMPRESSED_MESSAGE_SIGNATURE
    ));
    assert!(!verify(&compressed, KEY_ONE_UNCOMPRESSED_MESSAGE_SIGNATURE));
    // Same r and s with the compressed header (31) belongs to the other address.
    assert!(verify(&compressed, KEY_ONE_COMPRESSED_MESSAGE_SIGNATURE));
    assert!(!verify(&uncompressed, KEY_ONE_COMPRESSED_MESSAGE_SIGNATURE));
}

#[test]
fn verify_message_rejects_signature_headers_outside_27_to_34() {
    let address = address_from_wif(Network::Mainnet, &key_one_wif(true))
        .unwrap()
        .address;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut compact =
        base64::Engine::decode(&engine, KEY_ONE_COMPRESSED_MESSAGE_SIGNATURE).unwrap();
    for header in [0u8, 26, 35, 39, 255] {
        compact[0] = header;
        let tampered = base64::Engine::encode(&engine, &compact);
        let error =
            verify_message(Network::Mainnet, &address, &tampered, KEY_ONE_MESSAGE).unwrap_err();
        assert!(
            error.to_string().contains("invalid recovery header"),
            "header {header}: {error}"
        );
    }
}

#[test]
fn sign_p2pkh_with_uncompressed_wif_reveals_the_uncompressed_public_key() {
    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        &parity_unsigned_tx_hex(),
        0,
        &p2pkh_script_pubkey_hex(KEY_ONE_UNCOMPRESSED_HASH160),
        &key_one_wif(false),
        1,
    )
    .unwrap();
    assert_eq!(signed.signed_tx_hex, KEY_ONE_UNCOMPRESSED_SIGNED_TX_HEX);

    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    let script_sig = tx.input[0].script_sig.as_bytes();
    let signature_push_len = usize::from(script_sig[0]);
    assert_eq!(script_sig[1 + signature_push_len], 65, "65-byte key push");
    assert_eq!(
        hex::encode(&script_sig[2 + signature_push_len..]),
        KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX
    );
}

#[test]
fn signing_envelope_with_uncompressed_wif_records_the_uncompressed_key_and_finalizes() {
    let envelope = key_one_envelope(KEY_ONE_UNCOMPRESSED_HASH160);
    let signed = sign_signing_envelope(&envelope, &key_one_wif(false)).unwrap();
    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(
        signed.signatures[0].public_key_hex,
        KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX
    );
    let combined = combine_signing_envelopes(&[signed.clone(), signed]).unwrap();
    assert_eq!(combined.signatures.len(), 1);
    let finalized = finalize_signing_envelope(&combined).unwrap();
    assert_eq!(finalized.signed_tx_hex, KEY_ONE_UNCOMPRESSED_SIGNED_TX_HEX);
}

#[test]
fn wif_compression_decides_which_p2pkh_script_the_key_controls() {
    // Uncompressed WIF against the script locked to the compressed key hash.
    let error = sign_signing_envelope(
        &key_one_envelope(KEY_ONE_COMPRESSED_HASH160),
        &key_one_wif(false),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not control any input"),
        "{error}"
    );
    // Compressed WIF against the script locked to the uncompressed key hash.
    let error = sign_signing_envelope(
        &key_one_envelope(KEY_ONE_UNCOMPRESSED_HASH160),
        &key_one_wif(true),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not control any input"),
        "{error}"
    );
    // The compressed pairing still signs.
    sign_signing_envelope(
        &key_one_envelope(KEY_ONE_COMPRESSED_HASH160),
        &key_one_wif(true),
    )
    .unwrap();
}

#[test]
fn finalize_rejects_hybrid_encoded_public_key() {
    // Hybrid SEC1 encoding: prefix 06 (even y) or 07 (odd y) followed by x and y.
    let y_is_odd = u8::from_str_radix(&KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX[128..], 16).unwrap() & 1;
    let hybrid_hex = format!(
        "{:02x}{}",
        6 + y_is_odd,
        &KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX[2..]
    );
    let hybrid_hash = hash160::Hash::hash(&hex::decode(&hybrid_hex).unwrap()).to_byte_array();

    let mut signed = sign_signing_envelope(
        &key_one_envelope(KEY_ONE_UNCOMPRESSED_HASH160),
        &key_one_wif(false),
    )
    .unwrap();
    // Lock the input to the hybrid encoding's hash so only the encoding rule can reject it.
    signed.inputs[0].script_pubkey_hex = p2pkh_script_pubkey_hex(&hex::encode(hybrid_hash));
    signed.signatures[0].public_key_hex = hybrid_hex;
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported public key encoding"),
        "{error}"
    );
}

#[test]
fn uncompressed_wif_cannot_sign_p2sh_multisig_inputs() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let uncompressed_cosigner = without_compression_flag(&fixture.wifs[0]);
    let error = sign_signing_envelope(&fixture.envelope, &uncompressed_cosigner).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("uncompressed WIF keys cannot sign P2SH multisig inputs"),
        "{error}"
    );

    let mut request = compose_request_base(
        "9999999999999999999999999999999999999999999999999999999999999999",
        150_000_000,
    );
    let input = &fixture.envelope.inputs[0];
    request.utxos[0].kind = SigningInputKind::P2shMultisig;
    request.utxos[0].script_pubkey_hex = input.script_pubkey_hex.clone();
    request.utxos[0].redeem_script_hex = input.redeem_script_hex.clone();
    request.utxos[0].multisig_threshold = Some(2);
    request.utxos[0].multisig_public_keys_hex = fixture.descriptor.public_keys_hex.clone();
    request.utxos[0].signers[0].wif = Some(uncompressed_cosigner);
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("uncompressed WIF keys cannot sign P2SH multisig inputs"),
        "{error}"
    );
}

#[test]
fn compose_builder_signs_with_uncompressed_wif_and_sizes_the_fee_for_a_65_byte_key() {
    let result = compose_and_sign_transaction(&key_one_compose_request(false)).unwrap();
    // 10 bytes of framing, one 181-byte input (65-byte key push), two 34-byte outputs.
    assert_eq!(result.estimated_size_bytes, 259);
    assert_eq!(result.fee_koinu, 259);
    let actual = result.actual_size_bytes.expect("signed by the WIF signer");
    assert!(
        actual <= result.estimated_size_bytes,
        "actual {actual} must not exceed the estimate {}",
        result.estimated_size_bytes
    );
    // Sizing the wrong key form would be off by 32 bytes.
    assert!(result.estimated_size_bytes - actual < 32);
    let signed_tx_hex = result.signed_tx_hex.unwrap();
    assert!(signed_tx_hex.contains(&format!("41{KEY_ONE_UNCOMPRESSED_PUBLIC_KEY_HEX}")));
    assert!(result.signing_envelope.is_none());
}

#[test]
fn compose_builder_keeps_the_33_byte_key_estimate_for_compressed_and_unsigned_p2pkh_inputs() {
    let compressed = compose_and_sign_transaction(&key_one_compose_request(true)).unwrap();
    assert_eq!(compressed.estimated_size_bytes, 227);
    assert!(compressed.actual_size_bytes.unwrap() <= 227);

    // Without a signer the builder cannot know the key form and assumes compressed.
    let mut unsigned = key_one_compose_request(false);
    unsigned.utxos[0].signers.clear();
    let result = compose_and_sign_transaction(&unsigned).unwrap();
    assert_eq!(result.estimated_size_bytes, 227);
    assert!(result.signed_tx_hex.is_none());
    assert!(result.signing_envelope.is_some());
}

#[test]
fn compose_builder_rejects_wif_whose_compression_does_not_match_the_p2pkh_utxo() {
    let mut request = key_one_compose_request(false);
    request.utxos[0].script_pubkey_hex = p2pkh_script_pubkey_hex(KEY_ONE_COMPRESSED_HASH160);
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error.to_string().contains("does not match P2PKH UTXO"),
        "{error}"
    );
}

// ---- Funding and signing behavior pinned before the linear-time refactor ----
//
// These tests describe what the Compose-and-Sign Transaction Builder and the
// Signing Envelope functions did before their internals were restructured.
// They must pass unchanged before and after that change.

/// A copy of the request's first UTXO (the parity P2PKH UTXO and its WIF
/// signer) at a new outpoint: txid `serial + 1` as 64 hex digits, vout 0.
fn parity_utxo_with_serial(
    request: &ComposeTransactionRequest,
    serial: usize,
    previous_output_value_koinu: u64,
) -> SpendableUtxo {
    SpendableUtxo {
        txid: format!("{:064x}", serial + 1),
        vout: 0,
        previous_output_value_koinu,
        ..request.utxos[0].clone()
    }
}

/// A 2-of-2 P2SH Multisig UTXO from the shared fixture, signed by `wifs` in
/// the order given.
fn two_of_two_utxo_signed_by(
    fixture: &TwoOfTwoFixture,
    txid: &str,
    previous_output_value_koinu: u64,
    wifs: &[&str],
) -> SpendableUtxo {
    SpendableUtxo {
        txid: txid.to_owned(),
        vout: 0,
        previous_output_value_koinu,
        script_pubkey_hex: fixture.envelope.inputs[0].script_pubkey_hex.clone(),
        kind: SigningInputKind::P2shMultisig,
        redeem_script_hex: Some(fixture.descriptor.redeem_script_hex.clone()),
        multisig_threshold: Some(2),
        multisig_public_keys_hex: fixture.descriptor.public_keys_hex.clone(),
        signers: wifs
            .iter()
            .map(|wif| UtxoSigner {
                kind: UtxoSignerKind::Wif,
                wif: Some((*wif).to_owned()),
                xpriv: None,
                derivation_path: None,
            })
            .collect(),
        manually_selected: false,
    }
}

/// `(previous_output_value_koinu, reason)` of every skipped input, in the
/// order the result lists them.
fn skipped_values_and_reasons(
    result: &easydoge_km::ComposeTransactionResult,
) -> Vec<(u64, String)> {
    result
        .skipped_inputs
        .iter()
        .map(|skipped| (skipped.previous_output_value_koinu, skipped.reason.clone()))
        .collect()
}

fn selected_input_values(result: &easydoge_km::ComposeTransactionResult) -> Vec<u64> {
    result
        .selected_inputs
        .iter()
        .map(|input| input.previous_output_value_koinu)
        .collect()
}

/// `(input_index, public_key_hex)` of every signature, in envelope order.
fn signature_inputs_and_keys(envelope: &SigningEnvelope) -> Vec<(usize, String)> {
    envelope
        .signatures
        .iter()
        .map(|signature| (signature.input_index, signature.public_key_hex.clone()))
        .collect()
}

#[test]
fn compose_builder_reports_the_first_invalid_utxo_in_selection_order_and_ignores_unreached_ones() {
    // Three P2PKH UTXOs: a valid 300M one, a 200M one with a malformed txid,
    // and a 100M one that wrongly carries a redeem script. UTXOs are validated
    // only when Coin Selection reaches them, in selection order.
    let mut request = compose_request_base(&"a1".repeat(32), 300_000_000);
    let mut malformed_txid = parity_utxo_with_serial(&request, 1, 200_000_000);
    malformed_txid.txid = "zz".repeat(32);
    let mut stray_redeem_script = parity_utxo_with_serial(&request, 2, 100_000_000);
    stray_redeem_script.redeem_script_hex = Some("51".to_owned());
    request.utxos.push(malformed_txid);
    request.utxos.push(stray_redeem_script);

    // One input is enough: the two invalid UTXOs are never validated and are
    // reported as skipped.
    for strategy in [
        CoinSelectionStrategy::LargestFirst,
        CoinSelectionStrategy::MinInputs,
    ] {
        request.coin_selection = strategy;
        let result = compose_and_sign_transaction(&request).unwrap();
        assert_eq!(selected_input_values(&result), vec![300_000_000]);
        assert_eq!(
            skipped_values_and_reasons(&result),
            vec![
                (200_000_000, "not selected by strategy".to_owned()),
                (100_000_000, "not selected by strategy".to_owned()),
            ],
            "{strategy:?}"
        );
    }

    // Two inputs are needed: the second UTXO in selection order is the one
    // with the malformed txid, so its error surfaces, not the third UTXO's.
    request.outputs[0].value_koinu = 350_000_000;
    for strategy in [
        CoinSelectionStrategy::LargestFirst,
        CoinSelectionStrategy::MinInputs,
    ] {
        request.coin_selection = strategy;
        let error = compose_and_sign_transaction(&request).unwrap_err();
        assert!(
            error.to_string().contains("invalid display txid hex"),
            "{strategy:?}: {error}"
        );
    }

    // Smallest first reaches the 100M UTXO before anything else.
    request.coin_selection = CoinSelectionStrategy::SmallestFirst;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("P2PKH UTXO must not include redeem script"),
        "{error}"
    );
}

#[test]
fn compose_builder_validates_a_utxo_before_adding_its_value_to_the_input_total() {
    // The first UTXO is 193 koinu short of the spend plus fee, so a second one
    // is needed, and adding any second value overflows the input total.
    let first_value = u64::MAX - 1_000;
    let mut request = compose_request_base(&"b1".repeat(32), first_value);
    request.coin_selection = CoinSelectionStrategy::LargestFirst;
    request.outputs[0].value_koinu = first_value;
    let second = parity_utxo_with_serial(&request, 1, 5_000);
    request.utxos.push(second);

    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(error.to_string().contains("amount overflow"), "{error}");

    // When that second UTXO is also invalid, its validation error comes first.
    request.utxos[1].txid = "zz".repeat(32);
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error.to_string().contains("invalid display txid hex"),
        "{error}"
    );
}

#[test]
fn compose_builder_lists_skipped_inputs_in_request_order_for_every_value_strategy() {
    // Request order: 30M, 80M, 50M, 10M, 60M.
    let mut request = compose_request_base(&"c1".repeat(32), 30_000_000);
    for (serial, value) in [80_000_000u64, 50_000_000, 10_000_000, 60_000_000]
        .into_iter()
        .enumerate()
    {
        let utxo = parity_utxo_with_serial(&request, serial, value);
        request.utxos.push(utxo);
    }
    let not_selected = |values: &[u64]| {
        values
            .iter()
            .map(|value| (*value, "not selected by strategy".to_owned()))
            .collect::<Vec<_>>()
    };

    request.outputs[0].value_koinu = 100_000_000;
    for strategy in [
        CoinSelectionStrategy::LargestFirst,
        CoinSelectionStrategy::MinInputs,
    ] {
        request.coin_selection = strategy;
        let result = compose_and_sign_transaction(&request).unwrap();
        // Selected in selection order; skipped in request order.
        assert_eq!(
            selected_input_values(&result),
            vec![80_000_000, 60_000_000],
            "{strategy:?}"
        );
        assert_eq!(
            skipped_values_and_reasons(&result),
            not_selected(&[30_000_000, 50_000_000, 10_000_000]),
            "{strategy:?}"
        );
        assert!(result.signed_tx_hex.is_some(), "{strategy:?}");
    }

    request.outputs[0].value_koinu = 85_000_000;
    request.coin_selection = CoinSelectionStrategy::SmallestFirst;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(
        selected_input_values(&result),
        vec![10_000_000, 30_000_000, 50_000_000]
    );
    assert_eq!(
        skipped_values_and_reasons(&result),
        not_selected(&[80_000_000, 60_000_000])
    );
    assert_eq!(result.input_total_koinu, 90_000_000);
}

#[test]
fn compose_builder_manual_selection_reports_only_the_unselected_utxos_it_visited() {
    // Pins current behavior, which the maintainers are reviewing separately.
    // Request order: 40M (manual), 10M, 90M, 70M (manual), 20M (manual),
    // 95M (manual). Candidates are visited smallest first:
    //   10M  not manually selected -> reported, in visiting order
    //   20M  selected
    //   40M  selected; 60M now covers the 55M spend, so selection stops.
    // Manually selected UTXOs that were not needed (70M, 95M) are then
    // reported in request order. The 90M UTXO is not manually selected and
    // sorts after the stopping point, so it is not reported at all.
    let mut request = compose_request_base(&"d1".repeat(32), 40_000_000);
    request.utxos[0].manually_selected = true;
    for (serial, (value, manually_selected)) in [
        (10_000_000u64, false),
        (90_000_000, false),
        (70_000_000, true),
        (20_000_000, true),
        (95_000_000, true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut utxo = parity_utxo_with_serial(&request, serial, value);
        utxo.manually_selected = manually_selected;
        request.utxos.push(utxo);
    }
    request.coin_selection = CoinSelectionStrategy::ManualSelectedInputs;
    request.outputs[0].value_koinu = 55_000_000;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(selected_input_values(&result), vec![20_000_000, 40_000_000]);
    assert_eq!(
        skipped_values_and_reasons(&result),
        vec![
            (10_000_000, "not manually selected".to_owned()),
            (70_000_000, "not selected by strategy".to_owned()),
            (95_000_000, "not selected by strategy".to_owned()),
        ]
    );
    assert!(result.signed_tx_hex.is_some());
}

#[test]
fn compose_builder_emits_envelope_signatures_by_input_and_then_in_signer_order() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let parity_public_key_hex = address_from_wif(Network::Mainnet, &parity_wif())
        .unwrap()
        .public_key_hex;
    // Input 0: 2-of-2 multisig, signers listed second key first.
    // Input 1: P2PKH with its signer. Input 2: P2PKH without a signer, which
    // keeps the result a Signing Envelope.
    let mut request = compose_request_base(&"e1".repeat(32), 200_000_000);
    let mut unsigned_p2pkh = parity_utxo_with_serial(&request, 0, 100_000_000);
    unsigned_p2pkh.signers = vec![];
    request.utxos.push(unsigned_p2pkh);
    request.utxos.push(two_of_two_utxo_signed_by(
        &fixture,
        &"e2".repeat(32),
        300_000_000,
        &[&fixture.wifs[1], &fixture.wifs[0]],
    ));
    request.coin_selection = CoinSelectionStrategy::LargestFirst;
    request.outputs[0].value_koinu = 550_000_000;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(
        selected_input_values(&result),
        vec![300_000_000, 200_000_000, 100_000_000]
    );
    assert!(result.signed_tx_hex.is_none());
    assert!(result.actual_size_bytes.is_none());
    let envelope = result.signing_envelope.expect("incomplete result");
    assert_eq!(
        envelope
            .inputs
            .iter()
            .map(|input| input.input_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        signature_inputs_and_keys(&envelope),
        vec![
            (0, fixture.descriptor.public_keys_hex[1].clone()),
            (0, fixture.descriptor.public_keys_hex[0].clone()),
            (1, parity_public_key_hex.clone()),
        ]
    );

    // The envelope is usable as returned: the missing signer completes it.
    let completed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(
        signature_inputs_and_keys(&completed)[3],
        (2, parity_public_key_hex)
    );
    finalize_signing_envelope(&completed).unwrap();
}

#[test]
fn compose_builder_signs_each_input_once_per_distinct_signer_and_matches_the_envelope_path() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    // The first cosigner is listed three times; it must sign once.
    let mut request = compose_request_base(&"f1".repeat(32), 100_000_000);
    request.utxos = vec![two_of_two_utxo_signed_by(
        &fixture,
        &"f1".repeat(32),
        100_000_000,
        &[
            &fixture.wifs[0],
            &fixture.wifs[0],
            &fixture.wifs[1],
            &fixture.wifs[0],
        ],
    )];

    let result = compose_and_sign_transaction(&request).unwrap();
    let signed_tx_hex = result.signed_tx_hex.expect("both cosigners signed");
    assert!(result.signing_envelope.is_none());
    assert_eq!(
        result.actual_size_bytes,
        Some(signed_tx_hex.len() as u64 / 2)
    );

    // Signing the same unsigned transaction through the Signing Envelope
    // functions gives the same bytes.
    let mut envelope = two_of_two_fixture(&result.unsigned_tx_hex, 0).envelope;
    envelope = sign_signing_envelope(&envelope, &fixture.wifs[0]).unwrap();
    envelope = sign_signing_envelope(&envelope, &fixture.wifs[1]).unwrap();
    assert_eq!(
        finalize_signing_envelope(&envelope).unwrap().signed_tx_hex,
        signed_tx_hex
    );

    // With only one cosigner (listed twice) the envelope holds one signature.
    request.utxos[0]
        .signers
        .retain(|signer| signer.wif.as_deref() == Some(fixture.wifs[0].as_str()));
    assert_eq!(request.utxos[0].signers.len(), 3);
    let result = compose_and_sign_transaction(&request).unwrap();
    assert!(result.signed_tx_hex.is_none());
    let envelope = result.signing_envelope.expect("one of two signatures");
    assert_eq!(
        signature_inputs_and_keys(&envelope),
        vec![(0, fixture.descriptor.public_keys_hex[0].clone())]
    );
}

#[test]
fn signing_envelope_appends_new_signatures_in_input_index_order_after_existing_ones() {
    // Both inputs of the two-input transaction belong to the parity key.
    // Descriptors are listed input 1 first; signing still goes input 0 first.
    let descriptor = |input_index: usize| SigningEnvelopeInput {
        input_index,
        ..p2pkh_envelope().inputs[0].clone()
    };
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = two_input_unsigned_tx_hex();
    envelope.inputs = vec![descriptor(1), descriptor(0)];

    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(
        signed
            .signatures
            .iter()
            .map(|signature| signature.input_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(signed.inputs, envelope.inputs);

    // An envelope that already holds the input-1 signature keeps it first and
    // gains only the input-0 signature.
    let mut partially_signed = envelope.clone();
    partially_signed.signatures = vec![signed.signatures[1].clone()];
    let resigned = sign_signing_envelope(&partially_signed, &parity_wif()).unwrap();
    assert_eq!(
        resigned.signatures,
        vec![signed.signatures[1].clone(), signed.signatures[0].clone()]
    );

    // The key counts as having signed input 1 whatever the letter case of the
    // public key hex recorded with that signature.
    let mut upper_cased = partially_signed.clone();
    upper_cased.signatures[0].public_key_hex = upper_cased.signatures[0]
        .public_key_hex
        .to_ascii_uppercase();
    let resigned = sign_signing_envelope(&upper_cased, &parity_wif()).unwrap();
    assert_eq!(
        resigned.signatures,
        vec![
            upper_cased.signatures[0].clone(),
            signed.signatures[0].clone()
        ]
    );
}

#[test]
fn combine_keeps_the_first_envelope_as_is_and_appends_unseen_signatures_in_order() {
    let descriptor = |input_index: usize| SigningEnvelopeInput {
        input_index,
        ..p2pkh_envelope().inputs[0].clone()
    };
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = two_input_unsigned_tx_hex();
    envelope.inputs = vec![descriptor(0), descriptor(1)];
    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    let (input_0, input_1) = (signed.signatures[0].clone(), signed.signatures[1].clone());

    // The first envelope repeats one signature; combining does not tidy it.
    let mut first = envelope.clone();
    first.signatures = vec![input_1.clone(), input_1.clone()];
    // The second envelope repeats a new signature and one the first has.
    let mut second = envelope.clone();
    second.signatures = vec![input_0.clone(), input_1.clone(), input_0.clone()];

    let combined = combine_signing_envelopes(&[first, second]).unwrap();
    assert_eq!(combined.signatures, vec![input_1.clone(), input_1, input_0]);
    finalize_signing_envelope(&combined).unwrap();
}

#[test]
fn finalize_reports_the_first_invalid_signature_in_envelope_order() {
    let descriptor = |input_index: usize| SigningEnvelopeInput {
        input_index,
        ..p2pkh_envelope().inputs[0].clone()
    };
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = two_input_unsigned_tx_hex();
    envelope.inputs = vec![descriptor(0), descriptor(1)];
    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();

    // Swap the two signatures between inputs: each is a genuine signature by
    // the right key, but for the other input's hash. Listed input 1 first.
    let mut swapped = signed.clone();
    swapped.signatures = vec![
        SigningEnvelopeSignature {
            input_index: 1,
            ..signed.signatures[0].clone()
        },
        SigningEnvelopeSignature {
            input_index: 0,
            ..signed.signatures[1].clone()
        },
    ];
    let error = finalize_signing_envelope(&swapped).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("signature for input 1 does not verify against the transaction"),
        "{error}"
    );

    // A valid signature for input 0 followed by a copy that does not verify
    // and a bad signature for input 1: the copy is reported, because every
    // entry is verified, in order, even when its input already has a valid
    // signature.
    let mut mixed = signed.clone();
    mixed.signatures = vec![
        signed.signatures[0].clone(),
        SigningEnvelopeSignature {
            input_index: 0,
            ..signed.signatures[1].clone()
        },
        SigningEnvelopeSignature {
            input_index: 1,
            ..signed.signatures[0].clone()
        },
    ];
    let error = finalize_signing_envelope(&mixed).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("signature for input 0 does not verify against the transaction"),
        "{error}"
    );
}

#[test]
fn compose_builder_rejects_a_signer_whose_key_bytes_only_straddle_two_redeem_script_key_pushes() {
    // Pins a corner of current behavior. The builder's ownership check looks
    // for the signer's 33 public key bytes anywhere in the Redeem Script, so
    // it accepts a key whose bytes straddle two neighbouring key pushes.
    // Signing works from the parsed key list, finds that the key is not a
    // cosigner, and the request fails there instead of yielding an envelope.
    //
    // The signer is the private key scalar 16, a public throwaway value. Its
    // compressed public key contains the byte 0x21, the opcode that pushes a
    // 33-byte key, which is what lets its bytes span two pushes.
    let mut payload = vec![Network::Mainnet.prefixes().wif];
    payload.extend_from_slice(&[0u8; 31]);
    payload.extend_from_slice(&[16, 0x01]);
    let wif = bs58::encode(payload).with_check().into_string();
    let public_key = hex::decode(
        address_from_wif(Network::Mainnet, &wif)
            .unwrap()
            .public_key_hex,
    )
    .unwrap();
    assert_eq!(public_key.len(), 33);
    let split = 1 + public_key[1..]
        .iter()
        .position(|byte| *byte == 0x21)
        .expect("the public key of scalar 16 contains the byte 0x21");
    // First pushed key: filler, then the signer's key bytes before the 0x21.
    let mut first_key = vec![0x02u8; 33 - split];
    first_key.extend_from_slice(&public_key[..split]);
    // Second pushed key: the signer's key bytes after the 0x21, then filler.
    let mut second_key = public_key[split + 1..].to_vec();
    second_key.resize(33, 0x03);
    // OP_1 <first key> <second key> OP_2 OP_CHECKMULTISIG
    let redeem_script_hex = format!(
        "5121{}21{}52ae",
        hex::encode(&first_key),
        hex::encode(&second_key)
    );
    assert!(redeem_script_hex.contains(&hex::encode(&public_key)));
    let redeem_script = hex::decode(&redeem_script_hex).unwrap();

    let mut request = compose_request_base(&"ab".repeat(32), 100_000_000);
    let utxo = &mut request.utxos[0];
    utxo.kind = SigningInputKind::P2shMultisig;
    utxo.script_pubkey_hex = format!(
        "a914{}87",
        hex::encode(hash160::Hash::hash(&redeem_script).to_byte_array())
    );
    utxo.redeem_script_hex = Some(redeem_script_hex);
    utxo.signers[0].wif = Some(wif);

    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("WIF does not control any input in the signing envelope"),
        "{error}"
    );
}

// ---- Large requests: funding and signing stay proportional to their size ----
//
// These tests are functional. They assert results, never elapsed time, but
// their sizes are chosen so that repeated per-input or per-signature work
// (re-sizing every selected input for each candidate selection, re-hashing the
// transaction for each signature) makes them take many seconds instead of
// about one.

/// An unsigned transaction that spends `input_count` outputs of the parity
/// transaction's previous txid (vout 0, 1, 2, ...) and serializes to exactly
/// `target_len` bytes: the parity output is followed by one zero-value output
/// whose script is padding.
fn padded_unsigned_tx_hex(input_count: usize, target_len: usize) -> String {
    let mut tx: bitcoin::Transaction =
        deserialize(&hex::decode(parity_unsigned_tx_hex()).unwrap()).unwrap();
    let template = tx.input[0].clone();
    tx.input = (0..input_count as u32)
        .map(|vout| {
            let mut input = template.clone();
            input.previous_output.vout = vout;
            input
        })
        .collect();
    tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(0),
        script_pubkey: bitcoin::ScriptBuf::new(),
    });
    // An empty script has a 1-byte length prefix; the padding script is longer
    // than 65,535 bytes and has a 5-byte prefix, hence the extra 4 bytes.
    let padding = target_len - serialize(&tx).len() - 4;
    tx.output[1].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x6a; padding]);
    let bytes = serialize(&tx);
    assert_eq!(bytes.len(), target_len);
    hex::encode(bytes)
}

#[test]
fn finalize_accepts_sixteen_signatures_on_every_input_of_a_maximum_size_transaction() {
    const INPUTS: usize = 32;
    const COPIES: usize = 16;
    let descriptor = |input_index: usize| SigningEnvelopeInput {
        input_index,
        ..p2pkh_envelope().inputs[0].clone()
    };
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = padded_unsigned_tx_hex(INPUTS, 99_999);
    envelope.inputs = (0..INPUTS).map(descriptor).collect();

    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(signed.signatures.len(), INPUTS);

    // Sixteen entries per input, interleaved so that the signatures of one
    // input are never adjacent: 0, 1, ..., 31, 0, 1, ..., 31, ...
    let mut crowded = signed.clone();
    crowded.signatures = (0..COPIES)
        .flat_map(|_| signed.signatures.iter().cloned())
        .collect();
    assert_eq!(crowded.signatures.len(), INPUTS * COPIES);

    let combined = combine_signing_envelopes(&[signed.clone(), crowded.clone()]).unwrap();
    assert_eq!(combined.signatures, signed.signatures);

    let finalized = finalize_signing_envelope(&crowded).unwrap();
    assert_eq!(
        finalized.signed_tx_hex,
        finalize_signing_envelope(&signed).unwrap().signed_tx_hex
    );
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&finalized.signed_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), INPUTS);
    assert!(tx.input.iter().all(|input| !input.script_sig.is_empty()));

    // One entry that does not verify is still found among the 512.
    let mut tampered = crowded;
    let last = tampered.signatures.len() - 1;
    tampered.signatures[last].input_index = 0;
    let error = finalize_signing_envelope(&tampered).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("signature for input 0 does not verify against the transaction"),
        "{error}"
    );
}

#[test]
fn compose_builder_reports_the_size_limit_after_sizing_each_signer_bearing_input_once() {
    // 700 P2PKH UTXOs of 1,000,000 koinu, each with its WIF signer, and a
    // payment that needs all of them. A P2PKH input is estimated at 149 bytes,
    // so the 671st input takes the estimate to 12 + 671 * 149 + 34 = 100,025
    // bytes and funding stops there, before anything is signed.
    let mut request = compose_request_base(&"9a".repeat(32), 1_000_000);
    request.coin_selection = CoinSelectionStrategy::LargestFirst;
    request.utxos = (0..700)
        .map(|serial| parity_utxo_with_serial(&request, serial, 1_000_000))
        .collect();
    request.outputs[0].value_koinu = 699_000_000;

    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(
        error.to_string().contains(
            "estimated transaction size is 100025 bytes, which exceeds the limit of 99999 bytes"
        ),
        "{error}"
    );
}

#[test]
fn compose_builder_funds_and_signs_hundreds_of_inputs_chosen_from_thousands_of_candidates() {
    const CANDIDATES: usize = 3_000;
    const NEEDED: usize = 200;
    // Candidate values are 1,000,000 + serial koinu, so LargestFirst selects
    // the 200 highest serials, highest first.
    let mut request = compose_request_base(&"9b".repeat(32), 1_000_000);
    request.coin_selection = CoinSelectionStrategy::LargestFirst;
    request.utxos = (0..CANDIDATES)
        .map(|serial| parity_utxo_with_serial(&request, serial, 1_000_000 + serial as u64))
        .collect();
    let selected_total = (CANDIDATES - NEEDED..CANDIDATES)
        .map(|serial| 1_000_000 + serial as u64)
        .sum::<u64>();
    // 10 + 200 * 149 + 34 = 29,844 bytes without change, 29,878 with change.
    request.outputs[0].value_koinu = selected_total - 500_000;

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(
        selected_input_values(&result),
        (CANDIDATES - NEEDED..CANDIDATES)
            .rev()
            .map(|serial| 1_000_000 + serial as u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(result.input_total_koinu, selected_total);
    assert_eq!(result.estimated_size_bytes, 29_878);
    assert_eq!(result.fee_koinu, 29_878);
    assert_eq!(result.change_amount_koinu, 500_000 - 29_878);
    // Every other candidate is reported, in request order.
    assert_eq!(result.skipped_inputs.len(), CANDIDATES - NEEDED);
    assert!(result
        .skipped_inputs
        .iter()
        .enumerate()
        .all(
            |(serial, skipped)| skipped.previous_output_value_koinu == 1_000_000 + serial as u64
                && skipped.reason == "not selected by strategy"
        ));
    assert!(result.signing_envelope.is_none());
    let signed_tx_hex = result.signed_tx_hex.expect("every input has its signer");
    let tx: bitcoin::Transaction = deserialize(&hex::decode(&signed_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), NEEDED);
    assert!(tx.input.iter().all(|input| !input.script_sig.is_empty()));
    let actual_size_bytes = result.actual_size_bytes.unwrap();
    assert_eq!(actual_size_bytes, signed_tx_hex.len() as u64 / 2);
    assert!(actual_size_bytes <= result.estimated_size_bytes);
}

#[test]
fn compose_builder_sizes_thousands_of_outputs_once() {
    // 3,000 one-byte-script outputs (10 bytes each) funded by 300 of 350
    // unsigned P2PKH UTXOs: 4 + 3 + 3 + 4 + 300 * 149 + 3,000 * 10 = 74,714
    // bytes, plus 34 for the change output.
    let mut request = compose_request_base(&"9c".repeat(32), 1_000_000);
    request.coin_selection = CoinSelectionStrategy::SmallestFirst;
    request.utxos[0].signers = vec![];
    request.utxos = (0..350)
        .map(|serial| parity_utxo_with_serial(&request, serial, 1_000_000))
        .collect();
    request.outputs = vec![
        TransactionOutput {
            kind: TransactionOutputKind::ExpertRawScript,
            value_koinu: 99_800,
            address: None,
            op_return_data_hex: None,
            script_hex: Some("51".to_owned()),
        };
        3_000
    ];

    let result = compose_and_sign_transaction(&request).unwrap();

    assert_eq!(result.spend_output_total_koinu, 299_400_000);
    assert_eq!(result.selected_inputs.len(), 300);
    assert_eq!(result.skipped_inputs.len(), 50);
    assert_eq!(result.estimated_size_bytes, 74_748);
    assert_eq!(result.fee_koinu, 74_748);
    assert_eq!(result.change_amount_koinu, 600_000 - 74_748);
    let envelope = result.signing_envelope.expect("no signers were supplied");
    assert_eq!(envelope.inputs.len(), 300);
    assert!(envelope.signatures.is_empty());
}

// --- Secret memory hygiene (ADR 0008) -----------------------------------------
//
// Wiping on drop cannot be observed by a safe test: reading memory after it
// is freed is undefined behavior. These tests pin what is observable: the
// secret-bearing records implement `ZeroizeOnDrop`, an explicit `zeroize()`
// empties exactly the secret fields, and cloning, comparing, serializing and
// signing keep working.

/// Compiles only when `T` wipes its secret fields when dropped.
fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

fn parity_account_xpriv() -> easydoge_km::Xpriv {
    account_xpriv_from_mnemonic(
        PHRASE,
        Some("TREZOR"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap()
    .xpriv
}

#[test]
fn secret_bearing_records_wipe_their_secrets_when_dropped() {
    assert_zeroize_on_drop::<easydoge_km::Xpriv>();
    assert_zeroize_on_drop::<GeneratedMnemonic>();
    assert_zeroize_on_drop::<UtxoSigner>();
}

#[test]
fn zeroizing_an_extended_private_key_empties_the_encoded_key() {
    use zeroize::Zeroize;
    let mut xpriv = parity_account_xpriv();
    assert!(!xpriv.encoded.is_empty());
    xpriv.zeroize();
    assert!(xpriv.encoded.is_empty());
    assert_eq!(xpriv.network, Network::Mainnet);
}

#[test]
fn zeroizing_a_generated_mnemonic_empties_the_seed_phrase() {
    use zeroize::Zeroize;
    let mut generated = GeneratedMnemonic {
        phrase: PHRASE.to_owned(),
        language: Language::English,
        word_count: 12,
    };
    generated.zeroize();
    assert!(generated.phrase.is_empty());
    assert_eq!(generated.language, Language::English);
    assert_eq!(generated.word_count, 12);
}

#[test]
fn zeroizing_a_utxo_signer_clears_the_wif_and_the_extended_private_key() {
    use zeroize::Zeroize;
    let mut signer = UtxoSigner {
        kind: UtxoSignerKind::Wif,
        wif: Some(parity_wif()),
        xpriv: Some(parity_account_xpriv()),
        derivation_path: Some("m/0/0".to_owned()),
    };
    signer.zeroize();
    assert_eq!(signer.wif, None);
    assert_eq!(signer.xpriv, None);
    assert_eq!(signer.kind, UtxoSignerKind::Wif);
    assert_eq!(signer.derivation_path.as_deref(), Some("m/0/0"));
}

#[test]
fn secret_bearing_records_still_clone_compare_and_round_trip_through_serde() {
    let xpriv = parity_account_xpriv();
    let mut request = compose_request_base(
        "5555555555555555555555555555555555555555555555555555555555555555",
        150_000_000,
    );
    request.utxos[0].signers.push(UtxoSigner {
        kind: UtxoSignerKind::XprivDerivation,
        wif: None,
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/0/0".to_owned()),
    });
    request.change = Some(ChangeDestination {
        address: None,
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/1/0".to_owned()),
    });

    let cloned = request.clone();
    assert!(cloned == request, "a clone must equal its source");
    let json = serde_json::to_string(&request).unwrap();
    let restored: ComposeTransactionRequest = serde_json::from_str(&json).unwrap();
    assert!(restored == request, "serde must round-trip the request");
    assert_eq!(
        restored.utxos[0].signers[1].xpriv.as_ref().unwrap().encoded,
        xpriv.encoded
    );
    assert_eq!(restored.utxos[0].signers[0].wif, Some(parity_wif()));
}

#[test]
fn dropping_a_copy_of_a_request_does_not_disturb_the_original() {
    let request = compose_request_base(
        "6666666666666666666666666666666666666666666666666666666666666666",
        150_000_000,
    );
    let first = compose_and_sign_transaction(&request).unwrap();
    drop(request.clone());
    let second = compose_and_sign_transaction(&request).unwrap();
    assert!(first.signed_tx_hex.is_some());
    assert_eq!(first.signed_tx_hex, second.signed_tx_hex);
    assert_eq!(request.utxos[0].signers[0].wif, Some(parity_wif()));
}

#[test]
fn generated_seed_phrases_are_single_spaced_and_validate_in_every_language() {
    for language in [
        Language::English,
        Language::SimplifiedChinese,
        Language::TraditionalChinese,
        Language::Czech,
        Language::French,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Portuguese,
        Language::Spanish,
    ] {
        for word_count in [12, 15, 18, 21, 24] {
            let generated = generate_mnemonic(MnemonicOptions {
                language,
                word_count,
            })
            .unwrap();
            assert_eq!(generated.word_count, word_count);
            assert_eq!(generated.phrase.split(' ').count(), word_count);
            assert!(!generated.phrase.starts_with(' ') && !generated.phrase.ends_with(' '));
            assert!(validate_mnemonic(&generated.phrase, language).unwrap());
        }
    }
}
