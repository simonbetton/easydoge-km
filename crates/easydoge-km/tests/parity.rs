use easydoge_km::{
    account_xpriv_from_mnemonic, create_multisig_descriptor, derive_address_from_xpriv,
    derive_address_from_xpub, inspect_xpriv, mnemonic_to_seed_hex, validate_mnemonic, Language,
    Network,
};
use serde_json::Value;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn network_constants_match_dogecoin_core() {
    let vectors: Value = serde_json::from_str(include_str!("../../../test-vectors/parity.json"))
        .expect("parity vectors");
    assert_eq!(
        Network::Mainnet.prefixes().p2pkh,
        vectors["networks"]["mainnet"]["p2pkh"]
    );
    assert_eq!(hex::encode(Network::Mainnet.prefixes().xpub), "02facafd");
    assert_eq!(Network::Testnet.prefixes().p2sh, 196);
    assert_eq!(Network::Regtest.prefixes().wif, 239);
}

#[test]
fn mnemonic_derives_account_extended_keys_and_watch_only_address() {
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
    assert!(account.xpriv.encoded.starts_with("dgpv"));
    assert!(account.xpub.encoded.starts_with("dgub"));

    let receive_from_private = derive_address_from_xpriv(&account.xpriv, "m/0/0").unwrap();
    let receive_from_public = derive_address_from_xpub(&account.xpub, "m/0/0").unwrap();
    assert_eq!(receive_from_private.address, receive_from_public.address);
    assert!(receive_from_public.address.starts_with('D'));
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
fn multisig_descriptor_is_deterministic_and_dogecoin_p2sh() {
    let first =
        account_xpriv_from_mnemonic(PHRASE, Some("a"), Language::English, Network::Mainnet, 0)
            .unwrap();
    let second =
        account_xpriv_from_mnemonic(PHRASE, Some("b"), Language::English, Network::Mainnet, 0)
            .unwrap();
    let descriptor = create_multisig_descriptor(
        Network::Mainnet,
        2,
        &[second.xpub, first.xpub],
        "m/0/7",
        true,
    )
    .unwrap();
    assert_eq!(descriptor.threshold, 2);
    assert!(descriptor.p2sh_address.starts_with('9') || descriptor.p2sh_address.starts_with('A'));
    assert_eq!(descriptor.public_keys_hex.len(), 2);
}
