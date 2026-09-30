use anyhow::Result;
use clap::{ArgGroup, Parser, Subcommand};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, combine_signing_envelopes,
    compose_and_sign_transaction, derive_address_from_xpriv, derive_address_from_xpub,
    derive_path_from_xpriv, finalize_signing_envelope, generate_mnemonic, inspect_xpriv,
    inspect_xpub, mnemonic_to_seed_hex, sign_message, sign_p2pkh_transaction,
    sign_signing_envelope, validate_address, validate_mnemonic, verify_message, wif_from_xpriv,
    xpub_from_xpriv, ComposeTransactionRequest, Language, MnemonicOptions, Network,
    SigningEnvelope, Xpriv, Xpub,
};
use std::fs;
use std::io;
use std::str::FromStr;

mod secret_input;
mod tui;

use secret_input::{read_bounded, SecretInput};

#[derive(Parser)]
#[command(name = "easydoge-km")]
#[command(about = "Dogecoin key-management SDK engineer CLI")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    reveal: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Mnemonic {
        #[command(subcommand)]
        command: MnemonicCommand,
    },
    Xpriv {
        #[command(subcommand)]
        command: XprivCommand,
    },
    Xpub {
        #[command(subcommand)]
        command: XpubCommand,
    },
    Address {
        #[command(subcommand)]
        command: AddressCommand,
    },
    Wif {
        #[command(subcommand)]
        command: WifCommand,
    },
    Multisig {
        #[command(subcommand)]
        command: MultisigCommand,
    },
    Tx {
        #[command(subcommand)]
        command: TxCommand,
    },
    Message {
        #[command(subcommand)]
        command: MessageCommand,
    },
    Tui,
}

#[derive(Subcommand)]
enum MnemonicCommand {
    Generate {
        #[arg(long, default_value = "english")]
        language: String,
        #[arg(long, default_value_t = 24)]
        words: usize,
    },
    #[command(group(ArgGroup::new("phrase_source").required(true).args(["phrase", "phrase_file"])))]
    Validate {
        /// Seed phrase as a literal value (visible in shell history and process listings; prefer --phrase-file)
        #[arg(long)]
        phrase: Option<String>,
        /// Read the seed phrase from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        phrase_file: Option<String>,
        #[arg(long, default_value = "english")]
        language: String,
    },
    #[command(group(ArgGroup::new("phrase_source").required(true).args(["phrase", "phrase_file"])))]
    ToSeed {
        /// Seed phrase as a literal value (visible in shell history and process listings; prefer --phrase-file)
        #[arg(long)]
        phrase: Option<String>,
        /// Read the seed phrase from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        phrase_file: Option<String>,
        /// BIP39 passphrase as a literal value (visible in shell history and process listings; prefer --passphrase-file)
        #[arg(long, conflicts_with = "passphrase_file")]
        passphrase: Option<String>,
        /// Read the BIP39 passphrase from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<String>,
        #[arg(long, default_value = "english")]
        language: String,
    },
}

#[derive(Subcommand)]
enum XprivCommand {
    #[command(group(ArgGroup::new("phrase_source").required(true).args(["phrase", "phrase_file"])))]
    FromMnemonic {
        /// Seed phrase as a literal value (visible in shell history and process listings; prefer --phrase-file)
        #[arg(long)]
        phrase: Option<String>,
        /// Read the seed phrase from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        phrase_file: Option<String>,
        /// BIP39 passphrase as a literal value (visible in shell history and process listings; prefer --passphrase-file)
        #[arg(long, conflicts_with = "passphrase_file")]
        passphrase: Option<String>,
        /// Read the BIP39 passphrase from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<String>,
        #[arg(long, default_value = "english")]
        language: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    #[command(group(ArgGroup::new("xpriv_source").required(true).args(["xpriv", "xpriv_file"])))]
    Inspect {
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    #[command(group(ArgGroup::new("xpriv_source").required(true).args(["xpriv", "xpriv_file"])))]
    DeriveAddress {
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    #[command(group(ArgGroup::new("xpriv_source").required(true).args(["xpriv", "xpriv_file"])))]
    Derive {
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    #[command(group(ArgGroup::new("xpriv_source").required(true).args(["xpriv", "xpriv_file"])))]
    ToXpub {
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum XpubCommand {
    Inspect {
        #[arg(long)]
        xpub: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    DeriveAddress {
        #[arg(long)]
        xpub: String,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum AddressCommand {
    #[command(group(ArgGroup::new("key_source").required(true).args(["xpub", "xpriv", "xpriv_file"])))]
    Derive {
        #[arg(long)]
        xpub: Option<String>,
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    Validate {
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum WifCommand {
    #[command(group(ArgGroup::new("xpriv_source").required(true).args(["xpriv", "xpriv_file"])))]
    Export {
        /// Extended private key as a literal value (visible in shell history and process listings; prefer --xpriv-file)
        #[arg(long)]
        xpriv: Option<String>,
        /// Read the extended private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        xpriv_file: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    #[command(group(ArgGroup::new("wif_source").required(true).args(["wif", "wif_file"])))]
    Import {
        /// WIF private key as a literal value (visible in shell history and process listings; prefer --wif-file)
        #[arg(long)]
        wif: Option<String>,
        /// Read the WIF private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        wif_file: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum MultisigCommand {
    Create {
        #[arg(long)]
        threshold: u8,
        #[arg(long = "xpub")]
        xpubs: Vec<String>,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, default_value_t = true)]
        sorted: bool,
    },
    #[command(group(ArgGroup::new("wif_source").required(true).args(["wif", "wif_file"])))]
    Sign {
        #[arg(long)]
        envelope_file: String,
        /// WIF private key as a literal value (visible in shell history and process listings; prefer --wif-file)
        #[arg(long)]
        wif: Option<String>,
        /// Read the WIF private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        wif_file: Option<String>,
    },
    Combine {
        #[arg(long = "envelope-file")]
        envelope_files: Vec<String>,
    },
    Finalize {
        #[arg(long)]
        envelope_file: String,
    },
}

#[derive(Subcommand)]
enum TxCommand {
    #[command(group(ArgGroup::new("wif_source").required(true).args(["wif", "wif_file"])))]
    SignP2pkh {
        #[arg(long)]
        unsigned_tx_hex: String,
        #[arg(long)]
        input_index: usize,
        #[arg(long)]
        script_pubkey_hex: String,
        /// WIF private key as a literal value (visible in shell history and process listings; prefer --wif-file)
        #[arg(long)]
        wif: Option<String>,
        /// Read the WIF private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        wif_file: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, default_value_t = 1)]
        sighash_type: u32,
    },
    Compose {
        #[arg(long)]
        request_file: String,
    },
}

#[derive(Subcommand)]
enum MessageCommand {
    #[command(group(ArgGroup::new("wif_source").required(true).args(["wif", "wif_file"])))]
    Sign {
        /// WIF private key as a literal value (visible in shell history and process listings; prefer --wif-file)
        #[arg(long)]
        wif: Option<String>,
        /// Read the WIF private key from this file, or from standard input when the path is "-"
        #[arg(long, value_name = "PATH")]
        wif_file: Option<String>,
        #[arg(long)]
        message: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    Verify {
        #[arg(long)]
        address: String,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        message: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Mnemonic { command } => handle_mnemonic(command, cli.json, cli.reveal),
        Command::Xpriv { command } => handle_xpriv(command, cli.json, cli.reveal),
        Command::Xpub { command } => handle_xpub(command, cli.json),
        Command::Address { command } => handle_address(command, cli.json),
        Command::Wif { command } => handle_wif(command, cli.json, cli.reveal),
        Command::Multisig { command } => handle_multisig(command, cli.json),
        Command::Tx { command } => handle_tx(command, cli.json),
        Command::Message { command } => handle_message(command, cli.json, cli.reveal),
        Command::Tui => tui::run(),
    }
}

fn handle_mnemonic(command: MnemonicCommand, json: bool, reveal: bool) -> Result<()> {
    match command {
        MnemonicCommand::Generate { language, words } => {
            let generated = generate_mnemonic(MnemonicOptions {
                language: Language::from_str(&language)?,
                word_count: words,
            })?;
            if json {
                let mut value = serde_json::to_value(&generated)?;
                if !reveal {
                    value["phrase"] = serde_json::Value::String("[redacted]".to_owned());
                }
                print_json(value)
            } else if reveal {
                println!("{}", generated.phrase);
                Ok(())
            } else {
                println!("[redacted] pass --reveal to display generated mnemonic");
                Ok(())
            }
        }
        MnemonicCommand::Validate {
            phrase,
            phrase_file,
            language,
        } => {
            let phrase = SecretInput::default().required("phrase", phrase, phrase_file)?;
            print_json(serde_json::json!({
                "valid": validate_mnemonic(&phrase, Language::from_str(&language)?)?
            }))
        }
        MnemonicCommand::ToSeed {
            phrase,
            phrase_file,
            passphrase,
            passphrase_file,
            language,
        } => {
            let mut secrets = SecretInput::default();
            let phrase = secrets.required("phrase", phrase, phrase_file)?;
            let passphrase = secrets.optional("passphrase", passphrase, passphrase_file)?;
            let seed_hex = mnemonic_to_seed_hex(
                &phrase,
                passphrase.as_deref(),
                Language::from_str(&language)?,
            )?;
            if reveal {
                print_json(serde_json::json!({ "seed_hex": seed_hex }))
            } else {
                print_json(serde_json::json!({ "seed_hex": "[redacted]" }))
            }
        }
    }
}

fn handle_xpriv(command: XprivCommand, json: bool, reveal: bool) -> Result<()> {
    match command {
        XprivCommand::FromMnemonic {
            phrase,
            phrase_file,
            passphrase,
            passphrase_file,
            language,
            network,
            account,
        } => {
            let mut secrets = SecretInput::default();
            let phrase = secrets.required("phrase", phrase, phrase_file)?;
            let passphrase = secrets.optional("passphrase", passphrase, passphrase_file)?;
            let keys = account_xpriv_from_mnemonic(
                &phrase,
                passphrase.as_deref(),
                Language::from_str(&language)?,
                Network::from_str(&network)?,
                account,
            )?;
            let mut value = serde_json::to_value(&keys)?;
            if !reveal {
                value["xpriv"]["encoded"] = serde_json::Value::String("[redacted]".to_owned());
            }
            if json {
                print_json(value)
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
                Ok(())
            }
        }
        XprivCommand::Inspect {
            xpriv,
            xpriv_file,
            network,
        } => {
            let xpriv = SecretInput::default().required("xpriv", xpriv, xpriv_file)?;
            let value = inspect_xpriv(&Xpriv {
                network: Network::from_str(&network)?,
                encoded: xpriv,
            })?;
            print_json(serde_json::to_value(value)?)
        }
        XprivCommand::DeriveAddress {
            xpriv,
            xpriv_file,
            path,
            network,
        } => {
            let xpriv = SecretInput::default().required("xpriv", xpriv, xpriv_file)?;
            let value = derive_address_from_xpriv(
                &Xpriv {
                    network: Network::from_str(&network)?,
                    encoded: xpriv,
                },
                &path,
            )?;
            if json {
                print_json(serde_json::to_value(value)?)
            } else {
                println!("{}", value.address);
                Ok(())
            }
        }
        XprivCommand::Derive {
            xpriv,
            xpriv_file,
            path,
            network,
        } => {
            let xpriv = SecretInput::default().required("xpriv", xpriv, xpriv_file)?;
            let value = derive_path_from_xpriv(
                &Xpriv {
                    network: Network::from_str(&network)?,
                    encoded: xpriv,
                },
                &path,
            )?;
            let output = if reveal {
                serde_json::to_value(value)?
            } else {
                serde_json::json!({ "network": network, "encoded": "[redacted]" })
            };
            print_json(output)
        }
        XprivCommand::ToXpub {
            xpriv,
            xpriv_file,
            network,
        } => {
            let xpriv = SecretInput::default().required("xpriv", xpriv, xpriv_file)?;
            let value = xpub_from_xpriv(&Xpriv {
                network: Network::from_str(&network)?,
                encoded: xpriv,
            })?;
            if json {
                print_json(serde_json::to_value(value)?)
            } else {
                println!("{}", value.encoded);
                Ok(())
            }
        }
    }
}

fn handle_xpub(command: XpubCommand, json: bool) -> Result<()> {
    match command {
        XpubCommand::Inspect { xpub, network } => {
            let value = inspect_xpub(&Xpub {
                network: Network::from_str(&network)?,
                encoded: xpub,
            })?;
            print_json(serde_json::to_value(value)?)
        }
        XpubCommand::DeriveAddress {
            xpub,
            path,
            network,
        } => {
            let value = derive_address_from_xpub(
                &Xpub {
                    network: Network::from_str(&network)?,
                    encoded: xpub,
                },
                &path,
            )?;
            if json {
                print_json(serde_json::to_value(value)?)
            } else {
                println!("{}", value.address);
                Ok(())
            }
        }
    }
}

fn handle_address(command: AddressCommand, json: bool) -> Result<()> {
    match command {
        AddressCommand::Derive {
            xpub,
            xpriv,
            xpriv_file,
            path,
            network,
        } => {
            let network = Network::from_str(&network)?;
            let xpriv = SecretInput::default().optional("xpriv", xpriv, xpriv_file)?;
            let value = match (xpub, xpriv) {
                (Some(xpub), None) => derive_address_from_xpub(
                    &Xpub {
                        network,
                        encoded: xpub,
                    },
                    &path,
                )?,
                (None, Some(xpriv)) => derive_address_from_xpriv(
                    &Xpriv {
                        network,
                        encoded: xpriv,
                    },
                    &path,
                )?,
                _ => anyhow::bail!("provide exactly one of --xpub, --xpriv, or --xpriv-file"),
            };
            if json {
                print_json(serde_json::to_value(value)?)
            } else {
                println!("{}", value.address);
                Ok(())
            }
        }
        AddressCommand::Validate { address, network } => print_json(serde_json::json!({
            "valid": validate_address(Network::from_str(&network)?, &address)?
        })),
    }
}

fn handle_wif(command: WifCommand, json: bool, reveal: bool) -> Result<()> {
    match command {
        WifCommand::Export {
            xpriv,
            xpriv_file,
            network,
        } => {
            let xpriv = SecretInput::default().required("xpriv", xpriv, xpriv_file)?;
            let wif = wif_from_xpriv(&Xpriv {
                network: Network::from_str(&network)?,
                encoded: xpriv,
            })?;
            let value = if reveal {
                serde_json::json!({ "wif": wif })
            } else {
                serde_json::json!({ "wif": "[redacted]" })
            };
            if json {
                print_json(value)
            } else if reveal {
                println!("{}", value["wif"].as_str().unwrap_or_default());
                Ok(())
            } else {
                println!("[redacted] pass --reveal to display WIF");
                Ok(())
            }
        }
        WifCommand::Import {
            wif,
            wif_file,
            network,
        } => {
            let wif = SecretInput::default().required("wif", wif, wif_file)?;
            let value = address_from_wif(Network::from_str(&network)?, &wif)?;
            print_json(serde_json::to_value(value)?)
        }
    }
}

fn handle_multisig(command: MultisigCommand, json: bool) -> Result<()> {
    match command {
        MultisigCommand::Create {
            threshold,
            xpubs,
            path,
            network,
            sorted,
        } => {
            let network = Network::from_str(&network)?;
            let xpubs = xpubs
                .into_iter()
                .map(|encoded| Xpub { network, encoded })
                .collect::<Vec<_>>();
            let descriptor =
                easydoge_km::create_multisig_descriptor(network, threshold, &xpubs, &path, sorted)?;
            if json {
                print_json(serde_json::to_value(descriptor)?)
            } else {
                println!("{}", descriptor.p2sh_address);
                Ok(())
            }
        }
        MultisigCommand::Sign {
            envelope_file,
            wif,
            wif_file,
        } => {
            let wif = SecretInput::default().required("wif", wif, wif_file)?;
            let envelope = read_envelope(&envelope_file)?;
            print_json(serde_json::to_value(sign_signing_envelope(
                &envelope, &wif,
            )?)?)
        }
        MultisigCommand::Combine { envelope_files } => {
            let envelopes = envelope_files
                .iter()
                .map(|path| read_envelope(path))
                .collect::<Result<Vec<_>>>()?;
            print_json(serde_json::to_value(combine_signing_envelopes(
                &envelopes,
            )?)?)
        }
        MultisigCommand::Finalize { envelope_file } => {
            let envelope = read_envelope(&envelope_file)?;
            print_json(serde_json::to_value(finalize_signing_envelope(&envelope)?)?)
        }
    }
}

fn handle_tx(command: TxCommand, json: bool) -> Result<()> {
    match command {
        TxCommand::SignP2pkh {
            unsigned_tx_hex,
            input_index,
            script_pubkey_hex,
            wif,
            wif_file,
            network,
            sighash_type,
        } => {
            let wif = SecretInput::default().required("wif", wif, wif_file)?;
            let signed = sign_p2pkh_transaction(
                Network::from_str(&network)?,
                &unsigned_tx_hex,
                input_index,
                &script_pubkey_hex,
                &wif,
                sighash_type,
            )?;
            if json {
                print_json(serde_json::to_value(signed)?)
            } else {
                println!("{}", signed.signed_tx_hex);
                Ok(())
            }
        }
        TxCommand::Compose { request_file } => {
            let request = read_compose_request(&request_file)?;
            let result = compose_and_sign_transaction(&request)?;
            if json {
                print_json(serde_json::to_value(result)?)
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
        }
    }
}

fn handle_message(command: MessageCommand, json: bool, reveal: bool) -> Result<()> {
    match command {
        MessageCommand::Sign {
            wif,
            wif_file,
            message,
            network,
        } => {
            let wif = SecretInput::default().required("wif", wif, wif_file)?;
            let signature = sign_message(Network::from_str(&network)?, &wif, &message)?;
            let mut value = serde_json::to_value(signature)?;
            if !reveal {
                value["signature_base64"] = serde_json::Value::String("[redacted]".to_owned());
            }
            if json {
                print_json(value)
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
                Ok(())
            }
        }
        MessageCommand::Verify {
            address,
            signature,
            message,
            network,
        } => print_json(serde_json::json!({
            "valid": verify_message(Network::from_str(&network)?, &address, &signature, &message)?
        })),
    }
}

fn print_json(value: serde_json::Value) -> Result<()> {
    let mut out = io::stdout();
    serde_json::to_writer_pretty(&mut out, &value)?;
    println!();
    Ok(())
}

/// Largest compose-request or Signing Envelope file the CLI reads (16 MiB).
/// CLI policy: comfortably above a request or envelope at the core limits in
/// `easydoge_km::limits`, and small enough to parse in memory.
const MAX_REQUEST_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Reads a UTF-8 text file, refusing anything larger than `max_bytes`. The
/// metadata check rejects an oversized regular file without reading it; the
/// bounded read covers inputs whose size is unknown up front (pipes, devices)
/// and files that grow while being read.
fn read_text_file_bounded(path: &str, max_bytes: u64) -> Result<String> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > max_bytes {
        anyhow::bail!("{path} exceeds the limit of {max_bytes} bytes");
    }
    let bytes = read_bounded(file, max_bytes).map_err(|error| {
        // `read_bounded` reports an over-limit input as `InvalidData`; reading
        // raw bytes produces no other `InvalidData` error.
        if error.kind() == io::ErrorKind::InvalidData {
            anyhow::anyhow!("{path} exceeds the limit of {max_bytes} bytes")
        } else {
            error.into()
        }
    })?;
    Ok(String::from_utf8(bytes)?)
}

fn read_envelope(path: &str) -> Result<SigningEnvelope> {
    let contents = read_text_file_bounded(path, MAX_REQUEST_FILE_BYTES)?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_compose_request(path: &str) -> Result<ComposeTransactionRequest> {
    let contents = read_text_file_bounded(path, MAX_REQUEST_FILE_BYTES)?;
    Ok(serde_json::from_str(&contents)?)
}
