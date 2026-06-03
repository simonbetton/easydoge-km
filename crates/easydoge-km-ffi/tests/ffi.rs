use easydoge_km_ffi::{account_xpriv_from_mnemonic, derive_address_from_xpub, Language, Network};

#[test]
fn ffi_surface_delegates_to_rust_core() {
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
    assert_eq!(address.address, "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM");
}
