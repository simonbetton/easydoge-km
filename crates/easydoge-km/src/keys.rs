use bip39::{Language as Bip39Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv as BtcXpriv, Xpub as BtcXpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use unicode_normalization::UnicodeNormalization;

use crate::encoding::{base58check_decode, p2pkh_address, wif};
use crate::{Error, Network, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnemonicOptions {
    pub language: Language,
    pub word_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedMnemonic {
    pub phrase: String,
    pub language: Language,
    pub word_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeySet {
    pub network: Network,
    pub account: u32,
    pub account_path: String,
    pub xpriv: Xpriv,
    pub xpub: Xpub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAddress {
    pub network: Network,
    pub path: String,
    pub public_key_hex: String,
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressKind {
    P2pkh,
    P2sh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressInfo {
    pub network: Network,
    pub kind: AddressKind,
    pub payload_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedKeyInfo {
    pub network: Network,
    pub depth: u8,
    pub parent_fingerprint_hex: String,
    pub child_number: u32,
    pub public_key_hex: Option<String>,
    pub private_key_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifInfo {
    pub network: Network,
    pub public_key_hex: String,
    pub address: String,
    pub compressed: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xpriv {
    pub network: Network,
    pub encoded: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xpub {
    pub network: Network,
    pub encoded: String,
}

impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.network)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for Xpub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xpub")
            .field("network", &self.network)
            .field("encoded", &self.encoded)
            .finish()
    }
}

impl Default for MnemonicOptions {
    fn default() -> Self {
        Self {
            language: Language::English,
            word_count: 24,
        }
    }
}

impl Language {
    fn to_bip39(self) -> Bip39Language {
        match self {
            Language::English => Bip39Language::English,
            Language::SimplifiedChinese => Bip39Language::SimplifiedChinese,
            Language::TraditionalChinese => Bip39Language::TraditionalChinese,
            Language::Czech => Bip39Language::Czech,
            Language::French => Bip39Language::French,
            Language::Italian => Bip39Language::Italian,
            Language::Japanese => Bip39Language::Japanese,
            Language::Korean => Bip39Language::Korean,
            Language::Portuguese => Bip39Language::Portuguese,
            Language::Spanish => Bip39Language::Spanish,
        }
    }
}

impl FromStr for Language {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "english" | "en" => Ok(Language::English),
            "simplified-chinese" | "chinese-simplified" | "zh-hans" => {
                Ok(Language::SimplifiedChinese)
            }
            "traditional-chinese" | "chinese-traditional" | "zh-hant" => {
                Ok(Language::TraditionalChinese)
            }
            "czech" | "cs" => Ok(Language::Czech),
            "french" | "fr" => Ok(Language::French),
            "italian" | "it" => Ok(Language::Italian),
            "japanese" | "ja" => Ok(Language::Japanese),
            "korean" | "ko" => Ok(Language::Korean),
            "portuguese" | "pt" => Ok(Language::Portuguese),
            "spanish" | "es" => Ok(Language::Spanish),
            other => Err(Error::InvalidLanguage(other.to_owned())),
        }
    }
}

pub fn generate_mnemonic(options: MnemonicOptions) -> Result<GeneratedMnemonic> {
    if !matches!(options.word_count, 12 | 15 | 18 | 21 | 24) {
        return Err(Error::InvalidWordCount(options.word_count));
    }
    let mnemonic = Mnemonic::generate_in(options.language.to_bip39(), options.word_count)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    Ok(GeneratedMnemonic {
        phrase: mnemonic.to_string(),
        language: options.language,
        word_count: options.word_count,
    })
}

pub fn validate_mnemonic(phrase: &str, language: Language) -> Result<bool> {
    let normalized = normalize(phrase);
    Ok(Mnemonic::parse_in(language.to_bip39(), normalized.as_str()).is_ok())
}

pub fn mnemonic_to_seed_hex(
    phrase: &str,
    passphrase: Option<&str>,
    language: Language,
) -> Result<String> {
    let mnemonic = parse_mnemonic(phrase, language)?;
    let seed = mnemonic.to_seed_normalized(passphrase.unwrap_or_default());
    Ok(hex::encode(seed))
}

pub fn account_xpriv_from_mnemonic(
    phrase: &str,
    passphrase: Option<&str>,
    language: Language,
    network: Network,
    account: u32,
) -> Result<AccountKeySet> {
    let mnemonic = parse_mnemonic(phrase, language)?;
    let seed = mnemonic.to_seed_normalized(passphrase.unwrap_or_default());
    let secp = Secp256k1::new();
    let master = BtcXpriv::new_master(network.bip32_kind(), &seed)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let account_path = format!("m/44'/3'/{}'", account);
    let path = DerivationPath::from_str(&account_path)
        .map_err(|err| Error::InvalidDerivationPath(err.to_string()))?;
    let account_key = master
        .derive_priv(&secp, &path)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    let account_xpub = BtcXpub::from_priv(&secp, &account_key);
    Ok(AccountKeySet {
        network,
        account,
        account_path,
        xpriv: Xpriv {
            network,
            encoded: encode_xpriv(network, &account_key),
        },
        xpub: Xpub {
            network,
            encoded: encode_xpub(network, &account_xpub),
        },
    })
}

pub fn derive_path_from_xpriv(xpriv: &Xpriv, path: &str) -> Result<Xpriv> {
    let key = decode_xpriv(xpriv.network, &xpriv.encoded)?;
    let secp = Secp256k1::new();
    let path = parse_path(path)?;
    let child = key
        .derive_priv(&secp, &path)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    Ok(Xpriv {
        network: xpriv.network,
        encoded: encode_xpriv(xpriv.network, &child),
    })
}

pub fn derive_path_from_xpub(xpub: &Xpub, path: &str) -> Result<Xpub> {
    if path_contains_hardened(path) {
        return Err(Error::HardenedPublicDerivation(path.to_owned()));
    }
    let key = decode_xpub(xpub.network, &xpub.encoded)?;
    let secp = Secp256k1::new();
    let path = parse_path(path)?;
    let child = key
        .derive_pub(&secp, &path)
        .map_err(|err| Error::Crypto(err.to_string()))?;
    Ok(Xpub {
        network: xpub.network,
        encoded: encode_xpub(xpub.network, &child),
    })
}

pub fn xpub_from_xpriv(xpriv: &Xpriv) -> Result<Xpub> {
    let key = decode_xpriv(xpriv.network, &xpriv.encoded)?;
    let secp = Secp256k1::new();
    let xpub = BtcXpub::from_priv(&secp, &key);
    Ok(Xpub {
        network: xpriv.network,
        encoded: encode_xpub(xpriv.network, &xpub),
    })
}

pub fn derive_address_from_xpriv(xpriv: &Xpriv, path: &str) -> Result<PathAddress> {
    let child = decode_xpriv(xpriv.network, &derive_path_from_xpriv(xpriv, path)?.encoded)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &child.private_key);
    let public_key_hex = hex::encode(public_key.serialize());
    Ok(PathAddress {
        network: xpriv.network,
        path: path.to_owned(),
        public_key_hex,
        address: p2pkh_address(xpriv.network, &public_key.serialize()),
    })
}

pub fn derive_address_from_xpub(xpub: &Xpub, path: &str) -> Result<PathAddress> {
    let child = decode_xpub(xpub.network, &derive_path_from_xpub(xpub, path)?.encoded)?;
    let public_key_hex = hex::encode(child.public_key.serialize());
    Ok(PathAddress {
        network: xpub.network,
        path: path.to_owned(),
        public_key_hex,
        address: p2pkh_address(xpub.network, &child.public_key.serialize()),
    })
}

pub fn wif_from_xpriv(xpriv: &Xpriv) -> Result<String> {
    let key = decode_xpriv(xpriv.network, &xpriv.encoded)?;
    Ok(wif(xpriv.network, &key.private_key.secret_bytes(), true))
}

pub fn address_from_wif(network: Network, wif_value: &str) -> Result<WifInfo> {
    let secret_key = secret_key_from_wif(wif_value, network)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();
    Ok(WifInfo {
        network,
        public_key_hex: hex::encode(public_key_bytes),
        address: p2pkh_address(network, &public_key_bytes),
        compressed: wif_is_compressed(wif_value, network)?,
    })
}

pub fn validate_address(network: Network, address: &str) -> Result<bool> {
    let data = match base58check_decode(address) {
        Ok(data) => data,
        Err(_) => return Ok(false),
    };
    if data.len() != 21 {
        return Ok(false);
    }
    let prefix = data[0];
    let prefixes = network.prefixes();
    Ok(prefix == prefixes.p2pkh || prefix == prefixes.p2sh)
}

pub fn inspect_address(address: &str) -> Result<Vec<AddressInfo>> {
    let data = match base58check_decode(address) {
        Ok(data) => data,
        Err(_) => return Ok(Vec::new()),
    };
    if data.len() != 21 {
        return Ok(Vec::new());
    }

    let prefix = data[0];
    let payload_hex = hex::encode(&data[1..]);
    let mut matches = Vec::new();
    for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let prefixes = network.prefixes();
        let kind = if prefix == prefixes.p2pkh {
            Some(AddressKind::P2pkh)
        } else if prefix == prefixes.p2sh {
            Some(AddressKind::P2sh)
        } else {
            None
        };
        if let Some(kind) = kind {
            matches.push(AddressInfo {
                network,
                kind,
                payload_hex: payload_hex.clone(),
            });
        }
    }
    Ok(matches)
}

pub fn inspect_xpriv(xpriv: &Xpriv) -> Result<ExtendedKeyInfo> {
    let key = decode_xpriv(xpriv.network, &xpriv.encoded)?;
    let secp = Secp256k1::new();
    let public = PublicKey::from_secret_key(&secp, &key.private_key);
    Ok(ExtendedKeyInfo {
        network: xpriv.network,
        depth: key.depth,
        parent_fingerprint_hex: hex::encode(key.parent_fingerprint),
        child_number: key.child_number.into(),
        public_key_hex: Some(hex::encode(public.serialize())),
        private_key_redacted: true,
    })
}

pub fn inspect_xpub(xpub: &Xpub) -> Result<ExtendedKeyInfo> {
    let key = decode_xpub(xpub.network, &xpub.encoded)?;
    Ok(ExtendedKeyInfo {
        network: xpub.network,
        depth: key.depth,
        parent_fingerprint_hex: hex::encode(key.parent_fingerprint),
        child_number: key.child_number.into(),
        public_key_hex: Some(hex::encode(key.public_key.serialize())),
        private_key_redacted: false,
    })
}

pub(crate) fn parse_mnemonic(phrase: &str, language: Language) -> Result<Mnemonic> {
    let normalized = normalize(phrase);
    Mnemonic::parse_in(language.to_bip39(), normalized.as_str())
        .map_err(|err| Error::InvalidKey(err.to_string()))
}

pub(crate) fn normalize(value: &str) -> String {
    value.nfkd().collect::<Cow<'_, str>>().to_string()
}

pub(crate) fn parse_path(path: &str) -> Result<DerivationPath> {
    DerivationPath::from_str(path).map_err(|err| Error::InvalidDerivationPath(err.to_string()))
}

fn path_contains_hardened(path: &str) -> bool {
    path.split('/')
        .skip(1)
        .any(|segment| segment.ends_with('\'') || segment.ends_with('h') || segment.ends_with('H'))
}

pub(crate) fn encode_xpriv(network: Network, xpriv: &BtcXpriv) -> String {
    let mut data = xpriv.encode();
    data[0..4].copy_from_slice(&network.prefixes().xpriv);
    bs58::encode(data).with_check().into_string()
}

pub(crate) fn encode_xpub(network: Network, xpub: &BtcXpub) -> String {
    let mut data = xpub.encode();
    data[0..4].copy_from_slice(&network.prefixes().xpub);
    bs58::encode(data).with_check().into_string()
}

pub(crate) fn decode_xpriv(network: Network, encoded: &str) -> Result<BtcXpriv> {
    let mut data = decode_extended_key_bytes(encoded)?;
    let prefixes = network.prefixes();
    if data[0..4] == prefixes.xpriv {
        data[0..4].copy_from_slice(match network {
            Network::Mainnet => &[0x04, 0x88, 0xad, 0xe4],
            Network::Testnet | Network::Regtest => &[0x04, 0x35, 0x83, 0x94],
        });
        BtcXpriv::decode(&data).map_err(|err| Error::InvalidKey(err.to_string()))
    } else if is_legacy_xpriv(&data[0..4]) {
        data[0..4].copy_from_slice(match network {
            Network::Mainnet => &[0x04, 0x88, 0xad, 0xe4],
            Network::Testnet | Network::Regtest => &[0x04, 0x35, 0x83, 0x94],
        });
        BtcXpriv::decode(&data).map_err(|err| Error::InvalidKey(err.to_string()))
    } else {
        Err(Error::InvalidKey(
            "extended private key prefix does not match network".to_owned(),
        ))
    }
}

pub(crate) fn decode_xpub(network: Network, encoded: &str) -> Result<BtcXpub> {
    let mut data = decode_extended_key_bytes(encoded)?;
    let prefixes = network.prefixes();
    if data[0..4] == prefixes.xpub {
        data[0..4].copy_from_slice(match network {
            Network::Mainnet => &[0x04, 0x88, 0xb2, 0x1e],
            Network::Testnet | Network::Regtest => &[0x04, 0x35, 0x87, 0xcf],
        });
        BtcXpub::decode(&data).map_err(|err| Error::InvalidKey(err.to_string()))
    } else if is_legacy_xpub(&data[0..4]) {
        data[0..4].copy_from_slice(match network {
            Network::Mainnet => &[0x04, 0x88, 0xb2, 0x1e],
            Network::Testnet | Network::Regtest => &[0x04, 0x35, 0x87, 0xcf],
        });
        BtcXpub::decode(&data).map_err(|err| Error::InvalidKey(err.to_string()))
    } else {
        Err(Error::InvalidKey(
            "extended public key prefix does not match network".to_owned(),
        ))
    }
}

fn decode_extended_key_bytes(encoded: &str) -> Result<Vec<u8>> {
    let data = base58check_decode(encoded)?;
    if data.len() != 78 {
        return Err(Error::InvalidKey(format!(
            "extended key payload must be 78 bytes, got {}",
            data.len()
        )));
    }
    Ok(data)
}

fn is_legacy_xpriv(prefix: &[u8]) -> bool {
    prefix == [0x04, 0x88, 0xad, 0xe4] || prefix == [0x04, 0x35, 0x83, 0x94]
}

fn is_legacy_xpub(prefix: &[u8]) -> bool {
    prefix == [0x04, 0x88, 0xb2, 0x1e] || prefix == [0x04, 0x35, 0x87, 0xcf]
}

pub(crate) fn secret_key_from_wif(value: &str, network: Network) -> Result<SecretKey> {
    let data = base58check_decode(value)?;
    if data.first().copied() != Some(network.prefixes().wif) {
        return Err(Error::InvalidKey(
            "WIF prefix does not match network".to_owned(),
        ));
    }
    let key_bytes: [u8; 32] = match data.len() {
        33 => data[1..33].try_into().expect("slice length checked"),
        34 if data[33] == 1 => data[1..33].try_into().expect("slice length checked"),
        _ => return Err(Error::InvalidKey("invalid WIF payload length".to_owned())),
    };
    SecretKey::from_slice(&key_bytes).map_err(|err| Error::InvalidKey(err.to_string()))
}

fn wif_is_compressed(value: &str, network: Network) -> Result<bool> {
    let data = base58check_decode(value)?;
    if data.first().copied() != Some(network.prefixes().wif) {
        return Err(Error::InvalidKey(
            "WIF prefix does not match network".to_owned(),
        ));
    }
    Ok(data.len() == 34 && data[33] == 1)
}
