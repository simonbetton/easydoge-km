#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{reason}")]
    Failure { reason: String },
}

type FfiResult<T> = Result<T, FfiError>;

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum Language {
    English,
    SimplifiedChinese,
    TraditionalChinese,
    Czech,
    French,
    Italian,
    Japanese,
    Korean,
    Portuguese,
    Spanish,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MnemonicOptions {
    pub language: Language,
    pub word_count: u16,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GeneratedMnemonic {
    pub phrase: String,
    pub language: Language,
    pub word_count: u16,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Xpriv {
    pub network: Network,
    pub encoded: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Xpub {
    pub network: Network,
    pub encoded: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountKeySet {
    pub network: Network,
    pub account: u32,
    pub account_path: String,
    pub xpriv: Xpriv,
    pub xpub: Xpub,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PathAddress {
    pub network: Network,
    pub path: String,
    pub public_key_hex: String,
    pub address: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ExtendedKeyInfo {
    pub network: Network,
    pub depth: u8,
    pub parent_fingerprint_hex: String,
    pub child_number: u32,
    pub public_key_hex: Option<String>,
    pub private_key_redacted: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct WifInfo {
    pub network: Network,
    pub public_key_hex: String,
    pub address: String,
    pub compressed: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MultisigDescriptor {
    pub network: Network,
    pub threshold: u8,
    pub cosigner_count: u8,
    pub child_path: String,
    pub sorted: bool,
    pub public_keys_hex: Vec<String>,
    pub redeem_script_hex: String,
    pub p2sh_address: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MessageSignature {
    pub network: Network,
    pub address: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedTransaction {
    pub network: Network,
    pub signed_tx_hex: String,
}

#[uniffi::export]
pub fn generate_mnemonic(options: MnemonicOptions) -> FfiResult<GeneratedMnemonic> {
    easydoge_km::generate_mnemonic(easydoge_km::MnemonicOptions {
        language: options.language.into(),
        word_count: options.word_count.into(),
    })
    .map(Into::into)
    .map_err(Into::into)
}

#[uniffi::export]
pub fn validate_mnemonic(phrase: String, language: Language) -> FfiResult<bool> {
    easydoge_km::validate_mnemonic(&phrase, language.into()).map_err(Into::into)
}

#[uniffi::export]
pub fn mnemonic_to_seed_hex(
    phrase: String,
    passphrase: Option<String>,
    language: Language,
) -> FfiResult<String> {
    easydoge_km::mnemonic_to_seed_hex(&phrase, passphrase.as_deref(), language.into())
        .map_err(Into::into)
}

#[uniffi::export]
pub fn account_xpriv_from_mnemonic(
    phrase: String,
    passphrase: Option<String>,
    language: Language,
    network: Network,
    account: u32,
) -> FfiResult<AccountKeySet> {
    easydoge_km::account_xpriv_from_mnemonic(
        &phrase,
        passphrase.as_deref(),
        language.into(),
        network.into(),
        account,
    )
    .map(Into::into)
    .map_err(Into::into)
}

#[uniffi::export]
pub fn derive_address_from_xpriv(xpriv: Xpriv, path: String) -> FfiResult<PathAddress> {
    easydoge_km::derive_address_from_xpriv(&xpriv.into(), &path)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn derive_address_from_xpub(xpub: Xpub, path: String) -> FfiResult<PathAddress> {
    easydoge_km::derive_address_from_xpub(&xpub.into(), &path)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn derive_path_from_xpriv(xpriv: Xpriv, path: String) -> FfiResult<Xpriv> {
    easydoge_km::derive_path_from_xpriv(&xpriv.into(), &path)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn derive_path_from_xpub(xpub: Xpub, path: String) -> FfiResult<Xpub> {
    easydoge_km::derive_path_from_xpub(&xpub.into(), &path)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn xpub_from_xpriv(xpriv: Xpriv) -> FfiResult<Xpub> {
    easydoge_km::xpub_from_xpriv(&xpriv.into())
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn inspect_xpriv(xpriv: Xpriv) -> FfiResult<ExtendedKeyInfo> {
    easydoge_km::inspect_xpriv(&xpriv.into())
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn inspect_xpub(xpub: Xpub) -> FfiResult<ExtendedKeyInfo> {
    easydoge_km::inspect_xpub(&xpub.into())
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn wif_from_xpriv(xpriv: Xpriv) -> FfiResult<String> {
    easydoge_km::wif_from_xpriv(&xpriv.into()).map_err(Into::into)
}

#[uniffi::export]
pub fn address_from_wif(network: Network, wif: String) -> FfiResult<WifInfo> {
    easydoge_km::address_from_wif(network.into(), &wif)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn validate_address(network: Network, address: String) -> FfiResult<bool> {
    easydoge_km::validate_address(network.into(), &address).map_err(Into::into)
}

#[uniffi::export]
pub fn create_multisig_descriptor(
    network: Network,
    threshold: u8,
    cosigner_xpubs: Vec<Xpub>,
    child_path: String,
    sorted: bool,
) -> FfiResult<MultisigDescriptor> {
    let xpubs = cosigner_xpubs
        .into_iter()
        .map(Into::into)
        .collect::<Vec<easydoge_km::Xpub>>();
    easydoge_km::create_multisig_descriptor(network.into(), threshold, &xpubs, &child_path, sorted)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn sign_message(network: Network, wif: String, message: String) -> FfiResult<MessageSignature> {
    easydoge_km::sign_message(network.into(), &wif, &message)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn verify_message(
    network: Network,
    address: String,
    signature_base64: String,
    message: String,
) -> FfiResult<bool> {
    easydoge_km::verify_message(network.into(), &address, &signature_base64, &message)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn sign_p2pkh_transaction(
    network: Network,
    unsigned_tx_hex: String,
    input_index: u64,
    script_pubkey_hex: String,
    wif: String,
    sighash_type: u32,
) -> FfiResult<SignedTransaction> {
    easydoge_km::sign_p2pkh_transaction(
        network.into(),
        &unsigned_tx_hex,
        usize::try_from(input_index).map_err(|_| FfiError::Failure {
            reason: "input index out of range".to_owned(),
        })?,
        &script_pubkey_hex,
        &wif,
        sighash_type,
    )
    .map(Into::into)
    .map_err(Into::into)
}

impl From<easydoge_km::Error> for FfiError {
    fn from(value: easydoge_km::Error) -> Self {
        FfiError::Failure {
            reason: value.to_string(),
        }
    }
}

impl From<Network> for easydoge_km::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => easydoge_km::Network::Mainnet,
            Network::Testnet => easydoge_km::Network::Testnet,
            Network::Regtest => easydoge_km::Network::Regtest,
        }
    }
}

impl From<easydoge_km::Network> for Network {
    fn from(value: easydoge_km::Network) -> Self {
        match value {
            easydoge_km::Network::Mainnet => Network::Mainnet,
            easydoge_km::Network::Testnet => Network::Testnet,
            easydoge_km::Network::Regtest => Network::Regtest,
        }
    }
}

impl From<Language> for easydoge_km::Language {
    fn from(value: Language) -> Self {
        match value {
            Language::English => easydoge_km::Language::English,
            Language::SimplifiedChinese => easydoge_km::Language::SimplifiedChinese,
            Language::TraditionalChinese => easydoge_km::Language::TraditionalChinese,
            Language::Czech => easydoge_km::Language::Czech,
            Language::French => easydoge_km::Language::French,
            Language::Italian => easydoge_km::Language::Italian,
            Language::Japanese => easydoge_km::Language::Japanese,
            Language::Korean => easydoge_km::Language::Korean,
            Language::Portuguese => easydoge_km::Language::Portuguese,
            Language::Spanish => easydoge_km::Language::Spanish,
        }
    }
}

impl From<easydoge_km::Language> for Language {
    fn from(value: easydoge_km::Language) -> Self {
        match value {
            easydoge_km::Language::English => Language::English,
            easydoge_km::Language::SimplifiedChinese => Language::SimplifiedChinese,
            easydoge_km::Language::TraditionalChinese => Language::TraditionalChinese,
            easydoge_km::Language::Czech => Language::Czech,
            easydoge_km::Language::French => Language::French,
            easydoge_km::Language::Italian => Language::Italian,
            easydoge_km::Language::Japanese => Language::Japanese,
            easydoge_km::Language::Korean => Language::Korean,
            easydoge_km::Language::Portuguese => Language::Portuguese,
            easydoge_km::Language::Spanish => Language::Spanish,
        }
    }
}

impl From<easydoge_km::GeneratedMnemonic> for GeneratedMnemonic {
    fn from(value: easydoge_km::GeneratedMnemonic) -> Self {
        Self {
            phrase: value.phrase,
            language: value.language.into(),
            word_count: value.word_count as u16,
        }
    }
}

impl From<easydoge_km::Xpriv> for Xpriv {
    fn from(value: easydoge_km::Xpriv) -> Self {
        Self {
            network: value.network.into(),
            encoded: value.encoded,
        }
    }
}

impl From<Xpriv> for easydoge_km::Xpriv {
    fn from(value: Xpriv) -> Self {
        Self {
            network: value.network.into(),
            encoded: value.encoded,
        }
    }
}

impl From<easydoge_km::Xpub> for Xpub {
    fn from(value: easydoge_km::Xpub) -> Self {
        Self {
            network: value.network.into(),
            encoded: value.encoded,
        }
    }
}

impl From<Xpub> for easydoge_km::Xpub {
    fn from(value: Xpub) -> Self {
        Self {
            network: value.network.into(),
            encoded: value.encoded,
        }
    }
}

impl From<easydoge_km::AccountKeySet> for AccountKeySet {
    fn from(value: easydoge_km::AccountKeySet) -> Self {
        Self {
            network: value.network.into(),
            account: value.account,
            account_path: value.account_path,
            xpriv: value.xpriv.into(),
            xpub: value.xpub.into(),
        }
    }
}

impl From<easydoge_km::PathAddress> for PathAddress {
    fn from(value: easydoge_km::PathAddress) -> Self {
        Self {
            network: value.network.into(),
            path: value.path,
            public_key_hex: value.public_key_hex,
            address: value.address,
        }
    }
}

impl From<easydoge_km::ExtendedKeyInfo> for ExtendedKeyInfo {
    fn from(value: easydoge_km::ExtendedKeyInfo) -> Self {
        Self {
            network: value.network.into(),
            depth: value.depth,
            parent_fingerprint_hex: value.parent_fingerprint_hex,
            child_number: value.child_number,
            public_key_hex: value.public_key_hex,
            private_key_redacted: value.private_key_redacted,
        }
    }
}

impl From<easydoge_km::WifInfo> for WifInfo {
    fn from(value: easydoge_km::WifInfo) -> Self {
        Self {
            network: value.network.into(),
            public_key_hex: value.public_key_hex,
            address: value.address,
            compressed: value.compressed,
        }
    }
}

impl From<easydoge_km::MultisigDescriptor> for MultisigDescriptor {
    fn from(value: easydoge_km::MultisigDescriptor) -> Self {
        Self {
            network: value.network.into(),
            threshold: value.threshold,
            cosigner_count: value.cosigner_count,
            child_path: value.child_path,
            sorted: value.sorted,
            public_keys_hex: value.public_keys_hex,
            redeem_script_hex: value.redeem_script_hex,
            p2sh_address: value.p2sh_address,
        }
    }
}

impl From<easydoge_km::MessageSignature> for MessageSignature {
    fn from(value: easydoge_km::MessageSignature) -> Self {
        Self {
            network: value.network.into(),
            address: value.address,
            signature_base64: value.signature_base64,
        }
    }
}

impl From<easydoge_km::SignedTransaction> for SignedTransaction {
    fn from(value: easydoge_km::SignedTransaction) -> Self {
        Self {
            network: value.network.into(),
            signed_tx_hex: value.signed_tx_hex,
        }
    }
}

uniffi::setup_scaffolding!();
