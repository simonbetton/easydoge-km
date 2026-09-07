//! Classification of pasted wallet material and address derivation for the TUI.
//!
//! Everything here is pure: strings and SDK types go in, typed and
//! redaction-aware results come out for the app state and renderer to use.

use std::fmt;

use anyhow::{anyhow, Result};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, derive_address_from_xpub,
    derive_path_from_xpriv, inspect_address, inspect_xpriv, inspect_xpub, validate_mnemonic,
    xpub_from_xpriv, AddressInfo, AddressKind, ExtendedKeyInfo, Language, Network, WifInfo, Xpriv,
    Xpub,
};

/// Parity test phrase shared with `test-vectors/parity.json`.
pub const SAMPLE_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Passphrase paired with [`SAMPLE_PHRASE`] in the parity vector.
pub const SAMPLE_PASSPHRASE: &str = "TREZOR";
/// Networks in the order the network key cycles through them.
pub const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];
/// Largest non-hardened child index, which is also the largest account number.
pub const MAX_INDEX: u32 = HARDENED_OFFSET - 1;

const HARDENED_OFFSET: u32 = 1 << 31;
const ACCOUNT_DEPTH: u8 = 3;
const LANGUAGES: [Language; 10] = [
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
];

/// BIP44 change level: `0` for receive addresses, `1` for change addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    Receive,
    Change,
}

impl Branch {
    pub const fn component(self) -> u32 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Change => "change",
        }
    }

    pub const fn toggle(self) -> Self {
        match self {
            Self::Receive => Self::Change,
            Self::Change => Self::Receive,
        }
    }
}

/// A BIP39 seed phrase plus the optional passphrase that goes with it.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedPhrase {
    pub phrase: String,
    pub passphrase: Option<String>,
    pub language: Language,
    pub word_count: usize,
}

impl SeedPhrase {
    pub fn sample() -> Self {
        Self {
            phrase: SAMPLE_PHRASE.to_owned(),
            passphrase: Some(SAMPLE_PASSPHRASE.to_owned()),
            language: Language::English,
            word_count: 12,
        }
    }

    pub fn words(&self) -> Vec<&str> {
        self.phrase.split_whitespace().collect()
    }
}

impl fmt::Debug for SeedPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedPhrase")
            .field("phrase", &"[redacted]")
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[redacted]"),
            )
            .field("language", &self.language)
            .field("word_count", &self.word_count)
            .finish()
    }
}

/// Pasted material after classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Material {
    SeedPhrase(SeedPhrase),
    Xpriv {
        xpriv: Xpriv,
        info: ExtendedKeyInfo,
        xpub: Xpub,
    },
    Xpub {
        xpub: Xpub,
        info: ExtendedKeyInfo,
    },
    Address {
        address: String,
        matches: Vec<AddressInfo>,
    },
    Wif {
        info: WifInfo,
    },
}

impl Material {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SeedPhrase(_) => "seed phrase",
            Self::Xpriv { .. } => "xpriv",
            Self::Xpub { .. } => "xpub",
            Self::Address { .. } => "address",
            Self::Wif { .. } => "WIF",
        }
    }

    /// Network the material was decoded for, when its encoding pins one.
    pub fn network(&self) -> Option<Network> {
        match self {
            Self::Xpriv { info, .. } | Self::Xpub { info, .. } => Some(info.network),
            Self::Wif { info } => Some(info.network),
            Self::SeedPhrase(_) | Self::Address { .. } => None,
        }
    }

    /// Networks this material can be interpreted on, in cycling order.
    pub fn network_options(&self) -> Vec<Network> {
        match self {
            Self::SeedPhrase(_) => NETWORKS.to_vec(),
            Self::Xpriv { xpriv, .. } => candidate_networks(&xpriv.encoded)
                .into_iter()
                .filter(|network| {
                    inspect_xpriv(&Xpriv {
                        network: *network,
                        encoded: xpriv.encoded.clone(),
                    })
                    .is_ok()
                })
                .collect(),
            Self::Xpub { xpub, .. } => candidate_networks(&xpub.encoded)
                .into_iter()
                .filter(|network| {
                    inspect_xpub(&Xpub {
                        network: *network,
                        encoded: xpub.encoded.clone(),
                    })
                    .is_ok()
                })
                .collect(),
            Self::Wif { info } => vec![info.network],
            Self::Address { .. } => Vec::new(),
        }
    }

    /// Re-interpret an extended key on another compatible network.
    pub fn with_network(&self, network: Network) -> Result<Self> {
        match self {
            Self::Xpriv { xpriv, .. } => xpriv_material(Xpriv {
                network,
                encoded: xpriv.encoded.clone(),
            }),
            Self::Xpub { xpub, .. } => xpub_material(Xpub {
                network,
                encoded: xpub.encoded.clone(),
            }),
            other => Ok(other.clone()),
        }
    }

    /// Account number baked into an account-level extended key.
    pub fn fixed_account(&self) -> Option<u32> {
        match self {
            Self::Xpriv { info, .. } | Self::Xpub { info, .. } if info.depth == ACCOUNT_DEPTH => {
                Some(info.child_number & MAX_INDEX)
            }
            _ => None,
        }
    }
}

/// What the explorer currently derives addresses from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Sample,
    Generated(SeedPhrase),
    Pasted(Material),
}

/// Whether the account number can be changed for the current source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountControl {
    Free,
    Fixed(u32),
    Unavailable,
}

impl Source {
    pub fn label(&self) -> String {
        match self {
            Self::Sample => "sample mnemonic".to_owned(),
            Self::Generated(_) => "generated mnemonic".to_owned(),
            Self::Pasted(material) => format!("pasted {}", material.label()),
        }
    }

    /// The seed phrase behind this source, when it is mnemonic based.
    pub fn seed_phrase(&self) -> Option<SeedPhrase> {
        match self {
            Self::Sample => Some(SeedPhrase::sample()),
            Self::Generated(seed) | Self::Pasted(Material::SeedPhrase(seed)) => Some(seed.clone()),
            Self::Pasted(_) => None,
        }
    }

    pub fn network_options(&self) -> Vec<Network> {
        match self {
            Self::Sample | Self::Generated(_) => NETWORKS.to_vec(),
            Self::Pasted(material) => material.network_options(),
        }
    }

    pub fn account_control(&self) -> AccountControl {
        match self {
            Self::Sample | Self::Generated(_) | Self::Pasted(Material::SeedPhrase(_)) => {
                AccountControl::Free
            }
            Self::Pasted(Material::Xpriv { info, .. }) if info.depth == 0 => AccountControl::Free,
            Self::Pasted(material) => material
                .fixed_account()
                .map_or(AccountControl::Unavailable, AccountControl::Fixed),
        }
    }
}

/// Outcome of classifying pasted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// A valid seed phrase that still needs its optional passphrase.
    SeedPhrase(SeedPhrase),
    Material(Material),
}

pub fn normalize(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

const UNCLASSIFIED: &str =
    "Could not classify pasted material as a seed phrase, xpriv, xpub, address, or WIF.";

pub fn classify(input: &str) -> Result<Classified> {
    let input = normalize(input);
    if input.is_empty() {
        return Err(anyhow!("Paste or type material before inspecting."));
    }

    let word_count = input.split_whitespace().count();
    if matches!(word_count, 12 | 15 | 18 | 21 | 24) {
        for language in LANGUAGES {
            if validate_mnemonic(&input, language)? {
                return Ok(Classified::SeedPhrase(SeedPhrase {
                    phrase: input,
                    passphrase: None,
                    language,
                    word_count,
                }));
            }
        }
        return Err(anyhow!(
            "Seed phrase has {word_count} words but is not a valid BIP39 mnemonic."
        ));
    }
    // Addresses, WIFs, and extended keys are single Base58 tokens.
    if word_count > 1 {
        return Err(anyhow!(UNCLASSIFIED));
    }

    for network in candidate_networks(&input) {
        let xpriv = Xpriv {
            network,
            encoded: input.clone(),
        };
        if inspect_xpriv(&xpriv).is_ok() {
            return xpriv_material(xpriv).map(Classified::Material);
        }
    }
    for network in candidate_networks(&input) {
        let xpub = Xpub {
            network,
            encoded: input.clone(),
        };
        if inspect_xpub(&xpub).is_ok() {
            return xpub_material(xpub).map(Classified::Material);
        }
    }
    let matches = inspect_address(&input)?;
    if !matches.is_empty() {
        return Ok(Classified::Material(Material::Address {
            address: input,
            matches,
        }));
    }
    for network in NETWORKS {
        if let Ok(info) = address_from_wif(network, &input) {
            return Ok(Classified::Material(Material::Wif { info }));
        }
    }
    Err(anyhow!(UNCLASSIFIED))
}

/// Networks worth trying for an extended key, most plausible first.
///
/// Base58Check strings with a fixed four-byte version start with stable
/// characters: `dgpv`/`dgub` are Dogecoin mainnet, `tprv`/`tpub` are the shared
/// testnet and regtest prefixes, and anything else (such as legacy `xprv`/`xpub`)
/// is accepted on whichever network decodes it.
fn candidate_networks(encoded: &str) -> Vec<Network> {
    if encoded.starts_with("dg") {
        vec![Network::Mainnet]
    } else if encoded.starts_with("tp") {
        vec![Network::Testnet, Network::Regtest]
    } else {
        NETWORKS.to_vec()
    }
}

fn xpriv_material(xpriv: Xpriv) -> Result<Material> {
    let info = inspect_xpriv(&xpriv)?;
    let xpub = xpub_from_xpriv(&xpriv)?;
    Ok(Material::Xpriv { xpriv, info, xpub })
}

fn xpub_material(xpub: Xpub) -> Result<Material> {
    let info = inspect_xpub(&xpub)?;
    Ok(Material::Xpub { xpub, info })
}

/// Cached account-level public key that address rows derive from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountContext {
    pub xpub: Xpub,
    /// Displayed path prefix: the absolute account path for seed phrases and
    /// master keys, or `m` for pasted account-level keys.
    pub path_prefix: String,
}

impl AccountContext {
    pub fn is_relative(&self) -> bool {
        self.path_prefix == "m"
    }
}

/// Resolve the account xpub for a source, or explain why it has none.
pub fn account_context(
    source: &Source,
    network: Network,
    account: u32,
) -> Result<AccountContext, String> {
    if let Some(seed) = source.seed_phrase() {
        let keys = account_xpriv_from_mnemonic(
            &seed.phrase,
            seed.passphrase.as_deref(),
            seed.language,
            network,
            account,
        )
        .map_err(|error| error.to_string())?;
        return Ok(AccountContext {
            xpub: keys.xpub,
            path_prefix: keys.account_path,
        });
    }

    match source {
        Source::Pasted(Material::Xpriv { xpriv, info, xpub }) => match info.depth {
            0 => {
                let account_path = format!("m/44'/3'/{account}'");
                let account_xpriv = derive_path_from_xpriv(xpriv, &account_path)
                    .map_err(|error| error.to_string())?;
                let xpub = xpub_from_xpriv(&account_xpriv).map_err(|error| error.to_string())?;
                Ok(AccountContext {
                    xpub,
                    path_prefix: account_path,
                })
            }
            ACCOUNT_DEPTH => Ok(AccountContext {
                xpub: xpub.clone(),
                path_prefix: "m".to_owned(),
            }),
            depth => Err(format!(
                "Address derivation needs a master (depth 0) or account-level (depth 3) xpriv; this key has depth {depth}."
            )),
        },
        Source::Pasted(Material::Xpub { xpub, info }) => {
            if info.depth == ACCOUNT_DEPTH {
                Ok(AccountContext {
                    xpub: xpub.clone(),
                    path_prefix: "m".to_owned(),
                })
            } else {
                Err(format!(
                    "Address derivation needs an account-level xpub (depth 3); this key has depth {}.",
                    info.depth
                ))
            }
        }
        Source::Pasted(Material::Address { .. }) => Err(
            "An address has no keys to derive from. Paste an xpub, xpriv, or seed phrase to explore addresses."
                .to_owned(),
        ),
        Source::Pasted(Material::Wif { .. }) => Err(
            "A WIF is a single private key with one address; it has no child addresses.".to_owned(),
        ),
        Source::Sample | Source::Generated(_) | Source::Pasted(Material::SeedPhrase(_)) => {
            Err("Seed phrase derivation is unavailable.".to_owned())
        }
    }
}

/// One derived P2PKH address with its display path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAddress {
    pub path: String,
    pub address: String,
    pub public_key_hex: String,
}

/// Receive and change addresses at one index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRow {
    pub index: u32,
    pub receive: DerivedAddress,
    pub change: DerivedAddress,
}

impl AddressRow {
    pub const fn branch(&self, branch: Branch) -> &DerivedAddress {
        match branch {
            Branch::Receive => &self.receive,
            Branch::Change => &self.change,
        }
    }
}

/// Derive `count` consecutive rows starting at `start`, stopping at [`MAX_INDEX`].
pub fn derive_rows(context: &AccountContext, start: u32, count: u32) -> Result<Vec<AddressRow>> {
    let end = start.saturating_add(count).min(HARDENED_OFFSET);
    (start..end)
        .map(|index| {
            Ok(AddressRow {
                index,
                receive: derive_one(context, Branch::Receive, index)?,
                change: derive_one(context, Branch::Change, index)?,
            })
        })
        .collect()
}

fn derive_one(context: &AccountContext, branch: Branch, index: u32) -> Result<DerivedAddress> {
    let relative = format!("m/{}/{}", branch.component(), index);
    let derived = derive_address_from_xpub(&context.xpub, &relative)?;
    Ok(DerivedAddress {
        path: format!("{}/{}/{}", context.path_prefix, branch.component(), index),
        address: derived.address,
        public_key_hex: derived.public_key_hex,
    })
}

pub const fn language_label(language: Language) -> &'static str {
    match language {
        Language::English => "english",
        Language::SimplifiedChinese => "simplified chinese",
        Language::TraditionalChinese => "traditional chinese",
        Language::Czech => "czech",
        Language::French => "french",
        Language::Italian => "italian",
        Language::Japanese => "japanese",
        Language::Korean => "korean",
        Language::Portuguese => "portuguese",
        Language::Spanish => "spanish",
    }
}

pub const fn address_kind_label(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2pkh => "p2pkh",
        AddressKind::P2sh => "p2sh",
    }
}

/// Render a BIP32 child number with its hardened marker, e.g. `0' (2147483648)`.
pub fn child_number_label(child_number: u32) -> String {
    if child_number >= HARDENED_OFFSET {
        format!("{}' ({child_number})", child_number - HARDENED_OFFSET)
    } else {
        child_number.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARITY_XPUB: &str = "dgub8s3rDipXzSGxH4XrwJA2sfJu83D89FWordpJq7uNJmHL87LAFR5Jm95er4g4Wa64yvNNY193By1pFiGMixHYZvyZiftVabMqWK7r1m4TSFC";
    const PARITY_WIF: &str = "QS8wWhz1J58Ap7byfcEfGZHsWuTJAsB83XmAZLztEdCzYwbpCkT1";
    const RECEIVE_0: &str = "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM";
    const CHANGE_0: &str = "DJC5m9hUngm7SzvMJb26FcFWC7Ew14eQxH";

    #[test]
    fn classify_detects_sample_seed_phrase_and_waits_for_passphrase() -> Result<()> {
        let classified = classify(&format!("  {SAMPLE_PHRASE}\n"))?;
        match classified {
            Classified::SeedPhrase(seed) => {
                assert_eq!(seed.phrase, SAMPLE_PHRASE);
                assert_eq!(seed.language, Language::English);
                assert_eq!(seed.word_count, 12);
                assert_eq!(seed.passphrase, None);
            }
            other => panic!("expected a seed phrase, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn classify_rejects_seed_phrase_with_bad_checksum() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let error = classify(phrase).unwrap_err().to_string();
        assert!(error.contains("12 words"), "{error}");
        assert!(error.contains("not a valid BIP39 mnemonic"), "{error}");
    }

    #[test]
    fn classify_rejects_unrelated_text() {
        let error = classify("not wallet material").unwrap_err().to_string();
        assert!(error.contains("Could not classify"), "{error}");
        assert!(classify("   ")
            .unwrap_err()
            .to_string()
            .contains("before inspecting"));
    }

    #[test]
    fn classify_detects_address_with_every_network_match() -> Result<()> {
        match classify(RECEIVE_0)? {
            Classified::Material(Material::Address { address, matches }) => {
                assert_eq!(address, RECEIVE_0);
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].network, Network::Mainnet);
                assert_eq!(matches[0].kind, AddressKind::P2pkh);
            }
            other => panic!("expected an address, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn classify_detects_account_xpub_with_fixed_account_and_network() -> Result<()> {
        let Classified::Material(material) = classify(PARITY_XPUB)? else {
            panic!("expected material");
        };
        assert!(matches!(&material, Material::Xpub { info, .. } if info.depth == 3));
        assert_eq!(material.fixed_account(), Some(0));
        assert_eq!(material.network(), Some(Network::Mainnet));
        assert_eq!(material.network_options(), vec![Network::Mainnet]);
        Ok(())
    }

    #[test]
    fn classify_detects_wif_and_reports_its_address() -> Result<()> {
        match classify(PARITY_WIF)? {
            Classified::Material(Material::Wif { info }) => {
                assert_eq!(info.network, Network::Mainnet);
                assert!(info.compressed);
                assert_eq!(info.address, "DF9eh53onfjPVUHabRXPaFcrZqbDBLNgW8");
            }
            other => panic!("expected a WIF, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn sample_context_matches_parity_vector() -> Result<()> {
        let context = account_context(&Source::Sample, Network::Mainnet, 0).unwrap();
        assert_eq!(context.xpub.encoded, PARITY_XPUB);
        assert_eq!(context.path_prefix, "m/44'/3'/0'");

        let rows = derive_rows(&context, 0, 2)?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].receive.path, "m/44'/3'/0'/0/0");
        assert_eq!(rows[0].receive.address, RECEIVE_0);
        assert_eq!(rows[0].change.path, "m/44'/3'/0'/1/0");
        assert_eq!(rows[0].change.address, CHANGE_0);
        assert_eq!(rows[1].index, 1);
        Ok(())
    }

    #[test]
    fn pasted_account_xpub_uses_relative_paths() -> Result<()> {
        let Classified::Material(material) = classify(PARITY_XPUB)? else {
            panic!("expected material");
        };
        let source = Source::Pasted(material);
        assert_eq!(source.account_control(), AccountControl::Fixed(0));
        let context = account_context(&source, Network::Mainnet, 0).unwrap();
        assert!(context.is_relative());
        let rows = derive_rows(&context, 0, 1)?;
        assert_eq!(rows[0].receive.path, "m/0/0");
        assert_eq!(rows[0].receive.address, RECEIVE_0);
        Ok(())
    }

    #[test]
    fn branch_level_xpub_explains_why_it_cannot_derive() -> Result<()> {
        let context = account_context(&Source::Sample, Network::Mainnet, 0).unwrap();
        let branch_xpub = easydoge_km::derive_path_from_xpub(&context.xpub, "m/0")?;
        let Classified::Material(material) = classify(&branch_xpub.encoded)? else {
            panic!("expected material");
        };
        let source = Source::Pasted(material);
        assert_eq!(source.account_control(), AccountControl::Unavailable);
        let error = account_context(&source, Network::Mainnet, 0).unwrap_err();
        assert!(error.contains("account-level xpub"), "{error}");
        assert!(error.contains("depth 4"), "{error}");
        Ok(())
    }

    #[test]
    fn derive_rows_stops_at_the_last_non_hardened_index() -> Result<()> {
        let context = account_context(&Source::Sample, Network::Mainnet, 0).unwrap();
        let rows = derive_rows(&context, MAX_INDEX - 1, 10)?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].index, MAX_INDEX);
        Ok(())
    }

    #[test]
    fn testnet_style_xpub_classifies_as_testnet_not_mainnet() -> Result<()> {
        let keys = account_xpriv_from_mnemonic(
            SAMPLE_PHRASE,
            Some(SAMPLE_PASSPHRASE),
            Language::English,
            Network::Testnet,
            0,
        )?;
        assert!(keys.xpub.encoded.starts_with("tpub"));

        let Classified::Material(material) = classify(&keys.xpub.encoded)? else {
            panic!("expected material");
        };
        assert_eq!(material.network(), Some(Network::Testnet));
        assert_eq!(
            material.network_options(),
            vec![Network::Testnet, Network::Regtest]
        );

        let regtest = material.with_network(Network::Regtest)?;
        assert_eq!(regtest.network(), Some(Network::Regtest));
        let rows = derive_rows(
            &account_context(&Source::Pasted(regtest), Network::Regtest, 0).unwrap(),
            0,
            1,
        )?;
        assert!(rows[0].receive.address.starts_with(['m', 'n']));
        Ok(())
    }

    #[test]
    fn seed_phrase_debug_output_is_redacted() {
        let seed = SeedPhrase::sample();
        let debug = format!("{seed:?}");
        assert!(!debug.contains("abandon"));
        assert!(!debug.contains(SAMPLE_PASSPHRASE));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn child_number_label_marks_hardened_children() {
        assert_eq!(child_number_label(0), "0");
        assert_eq!(child_number_label(HARDENED_OFFSET), "0' (2147483648)");
        assert_eq!(child_number_label(HARDENED_OFFSET + 7), "7' (2147483655)");
    }
}
