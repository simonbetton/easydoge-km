use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, combine_signing_envelopes,
    derive_address_from_xpriv, derive_address_from_xpub, derive_path_from_xpriv,
    finalize_signing_envelope, generate_mnemonic, inspect_xpriv, inspect_xpub,
    mnemonic_to_seed_hex, sign_message, sign_p2pkh_transaction, sign_signing_envelope,
    validate_address, validate_mnemonic, verify_message, wif_from_xpriv, xpub_from_xpriv, Language,
    MnemonicOptions, Network, SigningEnvelope, Xpriv, Xpub,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use std::fs;
use std::io;
use std::str::FromStr;

#[derive(Debug, Parser)]
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

#[derive(Debug, Subcommand)]
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

#[derive(Debug, Subcommand)]
enum MnemonicCommand {
    Generate {
        #[arg(long, default_value = "english")]
        language: String,
        #[arg(long, default_value_t = 24)]
        words: usize,
    },
    Validate {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "english")]
        language: String,
    },
    ToSeed {
        #[arg(long)]
        phrase: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long, default_value = "english")]
        language: String,
    },
}

#[derive(Debug, Subcommand)]
enum XprivCommand {
    FromMnemonic {
        #[arg(long)]
        phrase: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long, default_value = "english")]
        language: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    Inspect {
        #[arg(long)]
        xpriv: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    DeriveAddress {
        #[arg(long)]
        xpriv: String,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    Derive {
        #[arg(long)]
        xpriv: String,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    ToXpub {
        #[arg(long)]
        xpriv: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Debug, Subcommand)]
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

#[derive(Debug, Subcommand)]
enum AddressCommand {
    Derive {
        #[arg(long)]
        xpub: Option<String>,
        #[arg(long)]
        xpriv: Option<String>,
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

#[derive(Debug, Subcommand)]
enum WifCommand {
    Export {
        #[arg(long)]
        xpriv: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    Import {
        #[arg(long)]
        wif: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Debug, Subcommand)]
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
    Sign {
        #[arg(long)]
        envelope_file: String,
        #[arg(long)]
        wif: String,
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

#[derive(Debug, Subcommand)]
enum TxCommand {
    SignP2pkh {
        #[arg(long)]
        unsigned_tx_hex: String,
        #[arg(long)]
        input_index: usize,
        #[arg(long)]
        script_pubkey_hex: String,
        #[arg(long)]
        wif: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, default_value_t = 1)]
        sighash_type: u32,
    },
}

#[derive(Debug, Subcommand)]
enum MessageCommand {
    Sign {
        #[arg(long)]
        wif: String,
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
        Command::Tui => run_tui(),
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
        MnemonicCommand::Validate { phrase, language } => print_json(serde_json::json!({
            "valid": validate_mnemonic(&phrase, Language::from_str(&language)?)?
        })),
        MnemonicCommand::ToSeed {
            phrase,
            passphrase,
            language,
        } => {
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
            passphrase,
            language,
            network,
            account,
        } => {
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
        XprivCommand::Inspect { xpriv, network } => {
            let value = inspect_xpriv(&Xpriv {
                network: Network::from_str(&network)?,
                encoded: xpriv,
            })?;
            print_json(serde_json::to_value(value)?)
        }
        XprivCommand::DeriveAddress {
            xpriv,
            path,
            network,
        } => {
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
            path,
            network,
        } => {
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
        XprivCommand::ToXpub { xpriv, network } => {
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
            path,
            network,
        } => {
            let network = Network::from_str(&network)?;
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
                _ => anyhow::bail!("provide exactly one of --xpub or --xpriv"),
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
        WifCommand::Export { xpriv, network } => {
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
        WifCommand::Import { wif, network } => {
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
        MultisigCommand::Sign { envelope_file, wif } => {
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
            network,
            sighash_type,
        } => {
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
    }
}

fn handle_message(command: MessageCommand, json: bool, reveal: bool) -> Result<()> {
    match command {
        MessageCommand::Sign {
            wif,
            message,
            network,
        } => {
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

fn run_tui() -> Result<()> {
    const SAMPLE_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mut app = TuiApp {
        reveal: false,
        status: "Press g/v/d/r/q. Secrets are redacted by default.".to_owned(),
        generated_secret: None,
    };
    let mut terminal = ratatui::init();
    let result = loop {
        terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Length(8),
                        Constraint::Min(6),
                    ])
                    .split(frame.area());

                frame.render_widget(
                    Paragraph::new("EasyDoge KM").block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Dogecoin SDK TUI"),
                    ),
                    chunks[0],
                );

                let menu = List::new([
                    ListItem::new("g  Generate 24-word mnemonic"),
                    ListItem::new("v  Validate BIP39 sample mnemonic"),
                    ListItem::new("d  Derive mainnet receive address from sample mnemonic"),
                    ListItem::new("r  Toggle reveal for generated mnemonic"),
                    ListItem::new("q  Quit"),
                ])
                .block(Block::default().borders(Borders::ALL).title("Methods"));
                frame.render_widget(menu, chunks[1]);

                let secret_line = match (&app.generated_secret, app.reveal) {
                    (Some(secret), true) => secret.as_str(),
                    (Some(_), false) => "[redacted]",
                    (None, _) => "No generated mnemonic yet",
                };
                let body = vec![
                    Line::from(vec![
                        Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(app.status.as_str()),
                    ]),
                    Line::from(vec![
                        Span::styled("Reveal: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(if app.reveal { "on" } else { "off" }),
                    ]),
                    Line::from(vec![
                        Span::styled("Generated: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(secret_line),
                    ]),
                ];
                frame.render_widget(
                    Paragraph::new(body)
                        .block(Block::default().borders(Borders::ALL).title("Output")),
                    chunks[2],
                );
            })
            .context("draw Ratatui frame")?;

        if let Event::Key(key) = event::read().context("read terminal event")? {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                KeyCode::Char('r') => {
                    app.reveal = !app.reveal;
                    app.status = "Reveal toggled for generated mnemonic.".to_owned();
                }
                KeyCode::Char('g') => {
                    let generated = generate_mnemonic(MnemonicOptions::default())?;
                    app.generated_secret = Some(generated.phrase);
                    app.status = "Generated a 24-word English mnemonic.".to_owned();
                }
                KeyCode::Char('v') => {
                    let valid = validate_mnemonic(SAMPLE_PHRASE, Language::English)?;
                    app.status = format!("Sample mnemonic valid: {valid}");
                }
                KeyCode::Char('d') => {
                    let keys = account_xpriv_from_mnemonic(
                        SAMPLE_PHRASE,
                        Some("TREZOR"),
                        Language::English,
                        Network::Mainnet,
                        0,
                    )?;
                    let address = derive_address_from_xpub(&keys.xpub, "m/0/0")?;
                    app.status = format!("Derived {}", address.address);
                }
                _ => {}
            }
        }
    };
    ratatui::restore();
    result
}

struct TuiApp {
    reveal: bool,
    status: String,
    generated_secret: Option<String>,
}

fn print_json(value: serde_json::Value) -> Result<()> {
    let mut out = io::stdout();
    serde_json::to_writer_pretty(&mut out, &value)?;
    println!();
    Ok(())
}

fn read_envelope(path: &str) -> Result<SigningEnvelope> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}
