use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPrefixes {
    pub p2pkh: u8,
    pub p2sh: u8,
    pub wif: u8,
    pub xpub: [u8; 4],
    pub xpriv: [u8; 4],
}

impl Network {
    pub fn prefixes(self) -> NetworkPrefixes {
        match self {
            Network::Mainnet => NetworkPrefixes {
                p2pkh: 30,
                p2sh: 22,
                wif: 158,
                xpub: [0x02, 0xfa, 0xca, 0xfd],
                xpriv: [0x02, 0xfa, 0xc3, 0x98],
            },
            Network::Testnet => NetworkPrefixes {
                p2pkh: 113,
                p2sh: 196,
                wif: 241,
                xpub: [0x04, 0x35, 0x87, 0xcf],
                xpriv: [0x04, 0x35, 0x83, 0x94],
            },
            Network::Regtest => NetworkPrefixes {
                p2pkh: 111,
                p2sh: 196,
                wif: 239,
                xpub: [0x04, 0x35, 0x87, 0xcf],
                xpriv: [0x04, 0x35, 0x83, 0x94],
            },
        }
    }

    pub fn bip32_kind(self) -> bitcoin::network::NetworkKind {
        match self {
            Network::Mainnet => bitcoin::network::NetworkKind::Main,
            Network::Testnet | Network::Regtest => bitcoin::network::NetworkKind::Test,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        };
        f.write_str(value)
    }
}

impl FromStr for Network {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Ok(Network::Mainnet),
            "test" | "testnet" => Ok(Network::Testnet),
            "regtest" | "local" => Ok(Network::Regtest),
            other => Err(Error::InvalidNetwork(other.to_owned())),
        }
    }
}
