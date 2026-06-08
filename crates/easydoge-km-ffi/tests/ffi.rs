use easydoge_km_ffi::{
    account_xpriv_from_mnemonic, combine_signing_envelopes, derive_address_from_xpub,
    finalize_signing_envelope, sign_message, sign_p2pkh_transaction, sign_signing_envelope,
    Language, Network, SigningEnvelope, SigningEnvelopeInput, SigningInputKind,
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
