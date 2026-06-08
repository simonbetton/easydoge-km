mod encoding;
mod keys;
mod message;
mod multisig;
mod network;
mod signing;

pub use keys::{
    account_xpriv_from_mnemonic, address_from_wif, derive_address_from_xpriv,
    derive_address_from_xpub, derive_path_from_xpriv, derive_path_from_xpub, generate_mnemonic,
    inspect_xpriv, inspect_xpub, mnemonic_to_seed_hex, validate_address, validate_mnemonic,
    wif_from_xpriv, xpub_from_xpriv, AccountKeySet, ExtendedKeyInfo, GeneratedMnemonic, Language,
    MnemonicOptions, PathAddress, WifInfo, Xpriv, Xpub,
};
pub use message::{sign_message, verify_message, MessageSignature};
pub use multisig::{create_multisig_descriptor, MultisigDescriptor};
pub use network::{Network, NetworkPrefixes};
pub use signing::{
    combine_signing_envelopes, finalize_signing_envelope, sign_p2pkh_transaction,
    sign_signing_envelope, SignedTransaction, SigningEnvelope, SigningEnvelopeInput,
    SigningEnvelopeSignature, SigningInputKind,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid network: {0}")]
    InvalidNetwork(String),
    #[error("invalid language: {0}")]
    InvalidLanguage(String),
    #[error("invalid mnemonic word count: {0}")]
    InvalidWordCount(usize),
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    #[error("hardened public derivation is not possible: {0}")]
    HardenedPublicDerivation(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
