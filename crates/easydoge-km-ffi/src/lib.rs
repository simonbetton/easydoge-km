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

#[derive(Debug, Clone, uniffi::Record)]
pub struct SigningEnvelope {
    pub version: u8,
    pub network: Network,
    pub unsigned_tx_hex: String,
    pub inputs: Vec<SigningEnvelopeInput>,
    pub signatures: Vec<SigningEnvelopeSignature>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SigningEnvelopeInput {
    pub input_index: u64,
    pub kind: SigningInputKind,
    pub script_pubkey_hex: String,
    pub redeem_script_hex: Option<String>,
    pub sighash_type: u32,
    pub previous_output_value_koinu: Option<u64>,
    pub multisig_threshold: Option<u8>,
    pub multisig_public_keys_hex: Vec<String>,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum SigningInputKind {
    P2pkh,
    P2shMultisig,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SigningEnvelopeSignature {
    pub input_index: u64,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Clone, uniffi::Record)]
pub struct ComposeTransactionRequest {
    pub network: Network,
    pub utxos: Vec<SpendableUtxo>,
    pub outputs: Vec<TransactionOutput>,
    pub fee_policy: FeePolicy,
    pub coin_selection: CoinSelectionStrategy,
    pub change: Option<ChangeDestination>,
    pub options: TransactionOptions,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SpendableUtxo {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub script_pubkey_hex: String,
    pub kind: SigningInputKind,
    pub redeem_script_hex: Option<String>,
    pub multisig_threshold: Option<u8>,
    pub multisig_public_keys_hex: Vec<String>,
    pub signers: Vec<UtxoSigner>,
    pub manually_selected: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct UtxoSigner {
    pub kind: UtxoSignerKind,
    pub wif: Option<String>,
    pub xpriv: Option<Xpriv>,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum UtxoSignerKind {
    Wif,
    XprivDerivation,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TransactionOutput {
    pub kind: TransactionOutputKind,
    pub value_koinu: u64,
    pub address: Option<String>,
    pub op_return_data_hex: Option<String>,
    pub script_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum TransactionOutputKind {
    Address,
    OpReturn,
    ExpertRawScript,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FeePolicy {
    pub fee_rate_koinu_per_kb: u64,
    pub dust_threshold_koinu: u64,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum CoinSelectionStrategy {
    MinInputs,
    SmallestFirst,
    LargestFirst,
    ManualSelectedInputs,
}

#[derive(Clone, uniffi::Record)]
pub struct ChangeDestination {
    pub address: Option<String>,
    pub xpriv: Option<Xpriv>,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TransactionOptions {
    pub version: i32,
    pub lock_time: u32,
    pub sequence: u32,
    pub sighash_type: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
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

#[derive(Debug, Clone, uniffi::Record)]
pub struct AuditedInput {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub script_pubkey_hex: String,
    pub kind: SigningInputKind,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SkippedInput {
    pub txid: String,
    pub vout: u32,
    pub previous_output_value_koinu: u64,
    pub reason: String,
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

#[uniffi::export]
pub fn sign_signing_envelope(envelope: SigningEnvelope, wif: String) -> FfiResult<SigningEnvelope> {
    let envelope = envelope.try_into()?;
    easydoge_km::sign_signing_envelope(&envelope, &wif)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn combine_signing_envelopes(envelopes: Vec<SigningEnvelope>) -> FfiResult<SigningEnvelope> {
    let envelopes = envelopes
        .into_iter()
        .map(TryInto::try_into)
        .collect::<FfiResult<Vec<easydoge_km::SigningEnvelope>>>()?;
    easydoge_km::combine_signing_envelopes(&envelopes)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn finalize_signing_envelope(envelope: SigningEnvelope) -> FfiResult<SignedTransaction> {
    let envelope = envelope.try_into()?;
    easydoge_km::finalize_signing_envelope(&envelope)
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn compose_and_sign_transaction(
    request: ComposeTransactionRequest,
) -> FfiResult<ComposeTransactionResult> {
    let request = request.try_into()?;
    easydoge_km::compose_and_sign_transaction(&request)
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

impl From<easydoge_km::SigningEnvelope> for SigningEnvelope {
    fn from(value: easydoge_km::SigningEnvelope) -> Self {
        Self {
            version: value.version,
            network: value.network.into(),
            unsigned_tx_hex: value.unsigned_tx_hex,
            inputs: value.inputs.into_iter().map(Into::into).collect(),
            signatures: value.signatures.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<SigningEnvelope> for easydoge_km::SigningEnvelope {
    type Error = FfiError;

    fn try_from(value: SigningEnvelope) -> FfiResult<Self> {
        Ok(Self {
            version: value.version,
            network: value.network.into(),
            unsigned_tx_hex: value.unsigned_tx_hex,
            inputs: value
                .inputs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<FfiResult<Vec<_>>>()?,
            signatures: value
                .signatures
                .into_iter()
                .map(TryInto::try_into)
                .collect::<FfiResult<Vec<_>>>()?,
        })
    }
}

impl From<easydoge_km::SigningEnvelopeInput> for SigningEnvelopeInput {
    fn from(value: easydoge_km::SigningEnvelopeInput) -> Self {
        Self {
            input_index: value.input_index as u64,
            kind: value.kind.into(),
            script_pubkey_hex: value.script_pubkey_hex,
            redeem_script_hex: value.redeem_script_hex,
            sighash_type: value.sighash_type,
            previous_output_value_koinu: value.previous_output_value_koinu,
            multisig_threshold: value.multisig_threshold,
            multisig_public_keys_hex: value.multisig_public_keys_hex,
        }
    }
}

impl TryFrom<SigningEnvelopeInput> for easydoge_km::SigningEnvelopeInput {
    type Error = FfiError;

    fn try_from(value: SigningEnvelopeInput) -> FfiResult<Self> {
        Ok(Self {
            input_index: input_index_to_usize(value.input_index)?,
            kind: value.kind.into(),
            script_pubkey_hex: value.script_pubkey_hex,
            redeem_script_hex: value.redeem_script_hex,
            sighash_type: value.sighash_type,
            previous_output_value_koinu: value.previous_output_value_koinu,
            multisig_threshold: value.multisig_threshold,
            multisig_public_keys_hex: value.multisig_public_keys_hex,
        })
    }
}

impl From<easydoge_km::SigningInputKind> for SigningInputKind {
    fn from(value: easydoge_km::SigningInputKind) -> Self {
        match value {
            easydoge_km::SigningInputKind::P2pkh => SigningInputKind::P2pkh,
            easydoge_km::SigningInputKind::P2shMultisig => SigningInputKind::P2shMultisig,
        }
    }
}

impl From<SigningInputKind> for easydoge_km::SigningInputKind {
    fn from(value: SigningInputKind) -> Self {
        match value {
            SigningInputKind::P2pkh => easydoge_km::SigningInputKind::P2pkh,
            SigningInputKind::P2shMultisig => easydoge_km::SigningInputKind::P2shMultisig,
        }
    }
}

impl From<easydoge_km::SigningEnvelopeSignature> for SigningEnvelopeSignature {
    fn from(value: easydoge_km::SigningEnvelopeSignature) -> Self {
        Self {
            input_index: value.input_index as u64,
            public_key_hex: value.public_key_hex,
            signature_hex: value.signature_hex,
        }
    }
}

impl TryFrom<SigningEnvelopeSignature> for easydoge_km::SigningEnvelopeSignature {
    type Error = FfiError;

    fn try_from(value: SigningEnvelopeSignature) -> FfiResult<Self> {
        Ok(Self {
            input_index: input_index_to_usize(value.input_index)?,
            public_key_hex: value.public_key_hex,
            signature_hex: value.signature_hex,
        })
    }
}

impl std::fmt::Debug for UtxoSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtxoSigner")
            .field("kind", &self.kind)
            .field("wif", &self.wif.as_ref().map(|_| "[redacted]"))
            .field("xpriv", &self.xpriv.as_ref().map(|_| "[redacted]"))
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

impl std::fmt::Debug for ComposeTransactionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Debug for ChangeDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeDestination")
            .field("address", &self.address)
            .field("xpriv", &self.xpriv.as_ref().map(|_| "[redacted]"))
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

impl TryFrom<ComposeTransactionRequest> for easydoge_km::ComposeTransactionRequest {
    type Error = FfiError;

    fn try_from(value: ComposeTransactionRequest) -> FfiResult<Self> {
        Ok(Self {
            network: value.network.into(),
            utxos: value
                .utxos
                .into_iter()
                .map(TryInto::try_into)
                .collect::<FfiResult<Vec<_>>>()?,
            outputs: value.outputs.into_iter().map(Into::into).collect(),
            fee_policy: value.fee_policy.into(),
            coin_selection: value.coin_selection.into(),
            change: value.change.map(Into::into),
            options: value.options.into(),
        })
    }
}

impl TryFrom<SpendableUtxo> for easydoge_km::SpendableUtxo {
    type Error = FfiError;

    fn try_from(value: SpendableUtxo) -> FfiResult<Self> {
        Ok(Self {
            txid: value.txid,
            vout: value.vout,
            previous_output_value_koinu: value.previous_output_value_koinu,
            script_pubkey_hex: value.script_pubkey_hex,
            kind: value.kind.into(),
            redeem_script_hex: value.redeem_script_hex,
            multisig_threshold: value.multisig_threshold,
            multisig_public_keys_hex: value.multisig_public_keys_hex,
            signers: value.signers.into_iter().map(Into::into).collect(),
            manually_selected: value.manually_selected,
        })
    }
}

impl From<UtxoSigner> for easydoge_km::UtxoSigner {
    fn from(value: UtxoSigner) -> Self {
        Self {
            kind: value.kind.into(),
            wif: value.wif,
            xpriv: value.xpriv.map(Into::into),
            derivation_path: value.derivation_path,
        }
    }
}

impl From<UtxoSignerKind> for easydoge_km::UtxoSignerKind {
    fn from(value: UtxoSignerKind) -> Self {
        match value {
            UtxoSignerKind::Wif => easydoge_km::UtxoSignerKind::Wif,
            UtxoSignerKind::XprivDerivation => easydoge_km::UtxoSignerKind::XprivDerivation,
        }
    }
}

impl From<TransactionOutput> for easydoge_km::TransactionOutput {
    fn from(value: TransactionOutput) -> Self {
        Self {
            kind: value.kind.into(),
            value_koinu: value.value_koinu,
            address: value.address,
            op_return_data_hex: value.op_return_data_hex,
            script_hex: value.script_hex,
        }
    }
}

impl From<TransactionOutputKind> for easydoge_km::TransactionOutputKind {
    fn from(value: TransactionOutputKind) -> Self {
        match value {
            TransactionOutputKind::Address => easydoge_km::TransactionOutputKind::Address,
            TransactionOutputKind::OpReturn => easydoge_km::TransactionOutputKind::OpReturn,
            TransactionOutputKind::ExpertRawScript => {
                easydoge_km::TransactionOutputKind::ExpertRawScript
            }
        }
    }
}

impl From<FeePolicy> for easydoge_km::FeePolicy {
    fn from(value: FeePolicy) -> Self {
        Self {
            fee_rate_koinu_per_kb: value.fee_rate_koinu_per_kb,
            dust_threshold_koinu: value.dust_threshold_koinu,
        }
    }
}

impl From<CoinSelectionStrategy> for easydoge_km::CoinSelectionStrategy {
    fn from(value: CoinSelectionStrategy) -> Self {
        match value {
            CoinSelectionStrategy::MinInputs => easydoge_km::CoinSelectionStrategy::MinInputs,
            CoinSelectionStrategy::SmallestFirst => {
                easydoge_km::CoinSelectionStrategy::SmallestFirst
            }
            CoinSelectionStrategy::LargestFirst => easydoge_km::CoinSelectionStrategy::LargestFirst,
            CoinSelectionStrategy::ManualSelectedInputs => {
                easydoge_km::CoinSelectionStrategy::ManualSelectedInputs
            }
        }
    }
}

impl From<ChangeDestination> for easydoge_km::ChangeDestination {
    fn from(value: ChangeDestination) -> Self {
        Self {
            address: value.address,
            xpriv: value.xpriv.map(Into::into),
            derivation_path: value.derivation_path,
        }
    }
}

impl From<TransactionOptions> for easydoge_km::TransactionOptions {
    fn from(value: TransactionOptions) -> Self {
        Self {
            version: value.version,
            lock_time: value.lock_time,
            sequence: value.sequence,
            sighash_type: value.sighash_type,
        }
    }
}

impl From<easydoge_km::ComposeTransactionResult> for ComposeTransactionResult {
    fn from(value: easydoge_km::ComposeTransactionResult) -> Self {
        Self {
            network: value.network.into(),
            selected_inputs: value.selected_inputs.into_iter().map(Into::into).collect(),
            skipped_inputs: value.skipped_inputs.into_iter().map(Into::into).collect(),
            input_total_koinu: value.input_total_koinu,
            spend_output_total_koinu: value.spend_output_total_koinu,
            change_amount_koinu: value.change_amount_koinu,
            change_address: value.change_address,
            change_script_pubkey_hex: value.change_script_pubkey_hex,
            fee_koinu: value.fee_koinu,
            estimated_size_bytes: value.estimated_size_bytes,
            actual_size_bytes: value.actual_size_bytes,
            dust_change_folded_into_fee: value.dust_change_folded_into_fee,
            unsigned_tx_hex: value.unsigned_tx_hex,
            signed_tx_hex: value.signed_tx_hex,
            signing_envelope: value.signing_envelope.map(Into::into),
        }
    }
}

impl From<easydoge_km::AuditedInput> for AuditedInput {
    fn from(value: easydoge_km::AuditedInput) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
            previous_output_value_koinu: value.previous_output_value_koinu,
            script_pubkey_hex: value.script_pubkey_hex,
            kind: value.kind.into(),
        }
    }
}

impl From<easydoge_km::SkippedInput> for SkippedInput {
    fn from(value: easydoge_km::SkippedInput) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
            previous_output_value_koinu: value.previous_output_value_koinu,
            reason: value.reason,
        }
    }
}

fn input_index_to_usize(value: u64) -> FfiResult<usize> {
    usize::try_from(value).map_err(|_| FfiError::Failure {
        reason: "input index out of range".to_owned(),
    })
}

uniffi::setup_scaffolding!();
