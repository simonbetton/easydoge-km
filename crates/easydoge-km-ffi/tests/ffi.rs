use easydoge_km_ffi::{
    account_xpriv_from_mnemonic, combine_signing_envelopes, compose_and_sign_transaction,
    derive_address_from_xpub, derive_path_from_xpriv, finalize_signing_envelope, generate_mnemonic,
    sign_message, sign_p2pkh_transaction, sign_signing_envelope, validate_mnemonic,
    ChangeDestination, CoinSelectionStrategy, ComposeTransactionRequest, FeePolicy,
    GeneratedMnemonic, Language, MnemonicOptions, Network, SigningEnvelope, SigningEnvelopeInput,
    SigningInputKind, SpendableUtxo, TransactionOptions, TransactionOutput, TransactionOutputKind,
    UtxoSigner, UtxoSignerKind, Xpriv,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../test-vectors/parity.json")).expect("parity vectors")
}

#[test]
fn ffi_surface_delegates_to_rust_core() {
    let vectors = vectors();
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let account = account_xpriv_from_mnemonic(
        phrase.to_owned(),
        Some("TREZOR".to_owned()),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    let address = derive_address_from_xpub(account.xpub, "m/0/0".to_owned()).unwrap();
    assert_eq!(
        address.address,
        vectors["mnemonic"]["receive"]["address"].as_str().unwrap()
    );
}

#[test]
fn ffi_surface_exposes_signing_and_envelope_flows() {
    let vectors = vectors();
    let wif = vectors["mnemonic"]["account"]["wif"].as_str().unwrap();

    let message = sign_message(
        Network::Mainnet,
        wif.to_owned(),
        vectors["message"]["text"].as_str().unwrap().to_owned(),
    )
    .unwrap();
    assert_eq!(
        message.signature_base64,
        vectors["message"]["signature_base64"].as_str().unwrap()
    );

    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        vectors["transaction"]["unsigned_tx_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        vectors["transaction"]["input_index"].as_u64().unwrap(),
        vectors["transaction"]["script_pubkey_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        wif.to_owned(),
        vectors["transaction"]["sighash_type"].as_u64().unwrap() as u32,
    )
    .unwrap();
    assert_eq!(
        signed.signed_tx_hex,
        vectors["transaction"]["signed_tx_hex"].as_str().unwrap()
    );

    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: vectors["transaction"]["unsigned_tx_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index: vectors["transaction"]["input_index"].as_u64().unwrap(),
            kind: SigningInputKind::P2pkh,
            script_pubkey_hex: vectors["transaction"]["script_pubkey_hex"]
                .as_str()
                .unwrap()
                .to_owned(),
            redeem_script_hex: None,
            sighash_type: vectors["transaction"]["sighash_type"].as_u64().unwrap() as u32,
            previous_output_value_koinu: None,
            multisig_threshold: None,
            multisig_public_keys_hex: vec![],
        }],
        signatures: vec![],
    };
    let signed_envelope = sign_signing_envelope(envelope, wif.to_owned()).unwrap();
    assert_eq!(signed_envelope.signatures.len(), 1);

    let combined =
        combine_signing_envelopes(vec![signed_envelope.clone(), signed_envelope]).unwrap();
    assert_eq!(combined.signatures.len(), 1);

    let finalized = finalize_signing_envelope(combined).unwrap();
    assert_eq!(
        finalized.signed_tx_hex,
        vectors["transaction"]["signed_tx_hex"].as_str().unwrap()
    );
}

#[test]
fn ffi_surface_exposes_compose_and_sign_builder() {
    let vectors = vectors();
    let result = compose_and_sign_transaction(ComposeTransactionRequest {
        network: Network::Mainnet,
        utxos: vec![SpendableUtxo {
            txid: "4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
            vout: 0,
            previous_output_value_koinu: 100_000_000,
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
        options: TransactionOptions {
            version: 1,
            lock_time: 0,
            sequence: 0xffff_ffff,
            sighash_type: 1,
        },
    })
    .unwrap();
    assert!(result.signed_tx_hex.is_some());
    assert!(result.signing_envelope.is_none());
    assert_eq!(result.selected_inputs.len(), 1);
}

#[test]
fn ffi_secret_records_redact_debug_output() {
    let vectors = vectors();
    let phrase = vectors["mnemonic"]["phrase"].as_str().unwrap();
    let xpriv_text = vectors["mnemonic"]["account"]["xpriv"].as_str().unwrap();
    let xpub_text = vectors["mnemonic"]["account"]["xpub"].as_str().unwrap();
    let wif_text = vectors["mnemonic"]["account"]["wif"].as_str().unwrap();

    let mnemonic = GeneratedMnemonic {
        phrase: phrase.to_owned(),
        language: Language::English,
        word_count: 12,
    };
    let xpriv = Xpriv {
        network: Network::Mainnet,
        encoded: xpriv_text.to_owned(),
    };
    let keys = account_xpriv_from_mnemonic(
        phrase.to_owned(),
        Some("TREZOR".to_owned()),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    assert_eq!(keys.xpriv.encoded, xpriv_text);
    let signer = UtxoSigner {
        kind: UtxoSignerKind::Wif,
        wif: Some(wif_text.to_owned()),
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/0/0".to_owned()),
    };
    let change = ChangeDestination {
        address: None,
        xpriv: Some(xpriv.clone()),
        derivation_path: Some("m/1/0".to_owned()),
    };
    let utxo = SpendableUtxo {
        txid: "4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
        vout: 0,
        previous_output_value_koinu: 100_000_000,
        script_pubkey_hex: vectors["transaction"]["script_pubkey_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
        kind: SigningInputKind::P2pkh,
        redeem_script_hex: None,
        multisig_threshold: None,
        multisig_public_keys_hex: vec![],
        signers: vec![signer.clone()],
        manually_selected: false,
    };
    let request = ComposeTransactionRequest {
        network: Network::Mainnet,
        utxos: vec![utxo.clone()],
        outputs: vec![],
        fee_policy: FeePolicy {
            fee_rate_koinu_per_kb: 1_000,
            dust_threshold_koinu: 1,
        },
        coin_selection: CoinSelectionStrategy::MinInputs,
        change: Some(change.clone()),
        options: TransactionOptions {
            version: 1,
            lock_time: 0,
            sequence: 0xffff_ffff,
            sighash_type: 1,
        },
    };

    let rendered = [
        ("GeneratedMnemonic", format!("{mnemonic:?}")),
        ("Xpriv", format!("{xpriv:?}")),
        ("AccountKeySet", format!("{keys:?}")),
        ("UtxoSigner", format!("{signer:?}")),
        ("ChangeDestination", format!("{change:?}")),
        ("SpendableUtxo", format!("{utxo:?}")),
        ("ComposeTransactionRequest", format!("{request:?}")),
        ("ComposeTransactionRequest pretty", format!("{request:#?}")),
    ];
    for (record, debug) in &rendered {
        assert!(!debug.contains("abandon"), "{record} leaked the phrase");
        assert!(!debug.contains(xpriv_text), "{record} leaked the xpriv");
        assert!(!debug.contains(wif_text), "{record} leaked the WIF");
        assert!(debug.contains("[redacted]"), "{record} is not redacted");
    }

    // Public fields stay visible so the output remains useful for debugging.
    assert!(rendered[2].1.contains(xpub_text));
    assert!(rendered[2].1.contains("m/44'/3'/0'"));
    assert!(rendered[0].1.contains("English"));
}

#[test]
fn ffi_surface_reports_core_resource_limits() {
    // The FFI adds no limits of its own: it forwards the core's error text.
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: "zz".repeat(100_000),
        inputs: vec![],
        signatures: vec![],
    };
    let Err(error) = finalize_signing_envelope(envelope) else {
        panic!("expected the core transaction size limit to reject the envelope");
    };
    assert!(
        error
            .to_string()
            .contains("which exceeds the limit of 199998 (99999 bytes)"),
        "{error}"
    );
}

#[test]
fn ffi_secret_records_cross_the_boundary_with_their_values_intact() {
    // The core records wipe themselves when dropped, so the FFI conversions
    // must take the secret text out of them before that happens.
    let vectors = vectors();
    let phrase = vectors["mnemonic"]["phrase"].as_str().unwrap();
    let xpriv_text = vectors["mnemonic"]["account"]["xpriv"].as_str().unwrap();

    let generated = generate_mnemonic(MnemonicOptions {
        language: Language::English,
        word_count: 12,
    })
    .unwrap();
    assert_eq!(generated.phrase.split(' ').count(), 12);
    assert!(validate_mnemonic(generated.phrase.clone(), Language::English).unwrap());

    let keys = account_xpriv_from_mnemonic(
        phrase.to_owned(),
        Some("TREZOR".to_owned()),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    assert_eq!(keys.xpriv.encoded, xpriv_text);

    let child = derive_path_from_xpriv(keys.xpriv.clone(), "m/0/0".to_owned()).unwrap();
    let expected = easydoge_km::derive_path_from_xpriv(
        &easydoge_km::Xpriv {
            network: easydoge_km::Network::Mainnet,
            encoded: xpriv_text.to_owned(),
        },
        "m/0/0",
    )
    .unwrap();
    assert!(!child.encoded.is_empty());
    assert_eq!(child.encoded, expected.encoded);
}
