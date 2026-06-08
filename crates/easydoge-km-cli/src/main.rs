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
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use std::fs;
use std::io;
use std::str::FromStr;

const TUI_SAMPLE_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    let mut app = TuiApp::new();
    let mut terminal = ratatui::init();
    let result = loop {
        terminal
            .draw(|frame| {
                render_tui(frame, &app);
            })
            .context("draw Ratatui frame")?;

        if let Event::Key(key) = event::read().context("read terminal event")? {
            if handle_tui_key(&mut app, key.code)? {
                break Ok(());
            }
        }
    };
    ratatui::restore();
    result
}

fn render_tui(frame: &mut ratatui::Frame<'_>, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(9),
        ])
        .split(frame.area());

    let header = vec![
        Line::from(vec![
            Span::styled(" / \\__", doge_style()),
            Span::raw("   "),
            Span::styled("EasyDoge KM", brand_style()),
        ]),
        Line::from(vec![
            Span::styled("(    @\\___", doge_style()),
            Span::raw("   "),
            Span::styled("Dogecoin key management", accent_style()),
        ]),
        Line::from(vec![
            Span::styled(" /         O", doge_style()),
            Span::raw("   "),
            Span::styled("Self-custody SDK TUI", muted_style()),
        ]),
        Line::from(vec![Span::styled("/   (_____/", doge_style())]),
        Line::from(vec![
            Span::styled("/_____/   U", doge_style()),
            Span::raw("   "),
            Span::styled("Such keys. Very custody.", muted_style()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(Span::styled(" Dogecoin SDK TUI ", title_style())),
        ),
        chunks[0],
    );

    let reveal_label = if app.reveal {
        "Hide generated mnemonic"
    } else {
        "Reveal generated mnemonic"
    };
    let question = vec![
        Line::from(vec![Span::styled(
            "What would you like to do?",
            question_style(),
        )]),
        Line::from(vec![
            key_span("g"),
            Span::raw(" Generate mnemonic"),
            Span::raw("    "),
            key_span("v"),
            Span::raw(" Validate sample"),
            Span::raw("    "),
            key_span("r"),
            Span::raw(format!(" {reveal_label}")),
        ]),
        Line::from(vec![key_span("i"), Span::raw(" Create incoming address")]),
        Line::from(vec![
            key_span("o"),
            Span::raw(" Create outgoing/change address"),
        ]),
        Line::from(vec![
            key_span("d"),
            Span::raw(" Create both addresses"),
            Span::raw("    "),
            key_span("a"),
            Span::raw("/"),
            key_span("z"),
            Span::raw(" Account +/-"),
            Span::raw("    "),
            key_span("n"),
            Span::raw("/"),
            key_span("p"),
            Span::raw(" Index +/-"),
        ]),
        Line::from(vec![
            Span::styled("Using ", muted_style()),
            Span::styled(
                if app.generated_secret.is_some() {
                    "generated mnemonic"
                } else {
                    "sample mnemonic"
                },
                accent_style(),
            ),
            Span::styled(" for derivations. Press ", muted_style()),
            key_span("q"),
            Span::styled(" to quit.", muted_style()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(question)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(" Question ", title_style())),
            )
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let source_line = if app.generated_secret.is_some() {
        "generated mnemonic"
    } else {
        "sample mnemonic"
    };
    let secret_line = match (&app.generated_secret, app.reveal) {
        (Some(secret), true) => secret.as_str(),
        (Some(_), false) => "[redacted]",
        (None, _) => "No generated mnemonic yet",
    };
    let incoming_path = app
        .incoming_address
        .as_ref()
        .map_or("not created", |address| address.path.as_str());
    let incoming_address = app
        .incoming_address
        .as_ref()
        .map_or("not created", |address| address.address.as_str());
    let outgoing_path = app
        .outgoing_address
        .as_ref()
        .map_or("not created", |address| address.path.as_str());
    let outgoing_address = app
        .outgoing_address
        .as_ref()
        .map_or("not created", |address| address.address.as_str());
    let body = vec![
        Line::from(vec![
            label_span("Status: "),
            Span::styled(app.status.as_str(), status_style(app.status.as_str())),
        ]),
        Line::from(vec![
            label_span("Source: "),
            Span::raw(source_line),
            Span::raw("   "),
            label_span("Account: "),
            Span::styled(app.account.to_string(), value_style()),
            Span::raw("   "),
            label_span("Index: "),
            Span::styled(app.address_index.to_string(), value_style()),
            Span::raw("   "),
            label_span("Reveal: "),
            Span::styled(if app.reveal { "on" } else { "off" }, value_style()),
        ]),
        Line::from(vec![label_span("Generated: "), Span::raw(secret_line)]),
        Line::from(vec![
            label_span("Incoming path: "),
            Span::raw(incoming_path),
        ]),
        Line::from(vec![
            label_span("Incoming address: "),
            Span::styled(incoming_address, address_style(incoming_address)),
        ]),
        Line::from(vec![
            label_span("Outgoing path: "),
            Span::raw(outgoing_path),
        ]),
        Line::from(vec![
            label_span("Outgoing address: "),
            Span::styled(outgoing_address, address_style(outgoing_address)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(" Answer ", title_style())),
            )
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}

fn brand_style() -> Style {
    Style::default()
        .fg(Color::LightYellow)
        .add_modifier(Modifier::BOLD)
}

fn doge_style() -> Style {
    Style::default().fg(Color::Yellow)
}

fn accent_style() -> Style {
    Style::default().fg(Color::LightCyan)
}

fn muted_style() -> Style {
    Style::default().fg(Color::Gray)
}

fn question_style() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

fn title_style() -> Style {
    Style::default()
        .fg(Color::LightYellow)
        .add_modifier(Modifier::BOLD)
}

fn value_style() -> Style {
    Style::default()
        .fg(Color::LightCyan)
        .add_modifier(Modifier::BOLD)
}

fn key_span(key: &'static str) -> Span<'static> {
    Span::styled(
        format!("[{key}]"),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn label_span(label: &'static str) -> Span<'static> {
    Span::styled(
        label,
        Style::default()
            .fg(Color::LightYellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn status_style(status: &str) -> Style {
    if status.starts_with("Created")
        || status.starts_with("Generated")
        || status.ends_with("true")
        || status.starts_with("Reveal")
    {
        Style::default().fg(Color::LightGreen)
    } else {
        Style::default().fg(Color::White)
    }
}

fn address_style(value: &str) -> Style {
    if value == "not created" {
        muted_style()
    } else {
        Style::default().fg(Color::LightGreen)
    }
}

fn handle_tui_key(app: &mut TuiApp, key: KeyCode) -> Result<bool> {
    match key {
        KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
        KeyCode::Char('r') => {
            app.reveal = !app.reveal;
            app.status = "Reveal toggled for generated mnemonic.".to_owned();
        }
        KeyCode::Char('g') => {
            let generated = generate_mnemonic(MnemonicOptions::default())?;
            app.generated_secret = Some(generated.phrase);
            app.clear_addresses();
            app.status = "Generated a 24-word English mnemonic.".to_owned();
        }
        KeyCode::Char('v') => {
            let valid = validate_mnemonic(TUI_SAMPLE_PHRASE, Language::English)?;
            app.status = format!("Sample mnemonic valid: {valid}");
        }
        KeyCode::Char('i') => {
            app.incoming_address = Some(derive_tui_address(app, TuiAddressBranch::Incoming)?);
            app.status = format!(
                "Created incoming address for account {} index {}.",
                app.account, app.address_index
            );
        }
        KeyCode::Char('o') => {
            app.outgoing_address = Some(derive_tui_address(app, TuiAddressBranch::Outgoing)?);
            app.status = format!(
                "Created outgoing address for account {} index {}.",
                app.account, app.address_index
            );
        }
        KeyCode::Char('d') => {
            app.incoming_address = Some(derive_tui_address(app, TuiAddressBranch::Incoming)?);
            app.outgoing_address = Some(derive_tui_address(app, TuiAddressBranch::Outgoing)?);
            app.status = format!(
                "Created incoming and outgoing addresses for account {} index {}.",
                app.account, app.address_index
            );
        }
        KeyCode::Char('n') => {
            app.address_index = app.address_index.saturating_add(1);
            app.clear_addresses();
            app.status = format!("Address index set to {}.", app.address_index);
        }
        KeyCode::Char('p') => {
            app.address_index = app.address_index.saturating_sub(1);
            app.clear_addresses();
            app.status = format!("Address index set to {}.", app.address_index);
        }
        KeyCode::Char('a') => {
            app.account = app.account.saturating_add(1);
            app.clear_addresses();
            app.status = format!("Account set to {}.", app.account);
        }
        KeyCode::Char('z') => {
            app.account = app.account.saturating_sub(1);
            app.clear_addresses();
            app.status = format!("Account set to {}.", app.account);
        }
        _ => {}
    }
    Ok(false)
}

fn derive_tui_address(app: &TuiApp, branch: TuiAddressBranch) -> Result<TuiDerivedAddress> {
    let (phrase, passphrase) = match app.generated_secret.as_deref() {
        Some(phrase) => (phrase, None),
        None => (TUI_SAMPLE_PHRASE, Some("TREZOR")),
    };
    let keys = account_xpriv_from_mnemonic(
        phrase,
        passphrase,
        Language::English,
        Network::Mainnet,
        app.account,
    )?;
    let relative_path = format!("m/{}/{}", branch.path_component(), app.address_index);
    let display_path = format!(
        "{}/{}/{}",
        keys.account_path,
        branch.path_component(),
        app.address_index
    );
    let address = derive_address_from_xpub(&keys.xpub, &relative_path)?;
    Ok(TuiDerivedAddress {
        path: display_path,
        address: address.address,
    })
}

#[derive(Debug, Clone, Copy)]
enum TuiAddressBranch {
    Incoming,
    Outgoing,
}

impl TuiAddressBranch {
    const fn path_component(self) -> u32 {
        match self {
            Self::Incoming => 0,
            Self::Outgoing => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiDerivedAddress {
    path: String,
    address: String,
}

struct TuiApp {
    reveal: bool,
    status: String,
    generated_secret: Option<String>,
    account: u32,
    address_index: u32,
    incoming_address: Option<TuiDerivedAddress>,
    outgoing_address: Option<TuiDerivedAddress>,
}

impl TuiApp {
    fn new() -> Self {
        Self {
            reveal: false,
            status: "Choose an action. Secrets stay redacted until reveal is enabled.".to_owned(),
            generated_secret: None,
            account: 0,
            address_index: 0,
            incoming_address: None,
            outgoing_address: None,
        }
    }

    fn clear_addresses(&mut self) {
        self.incoming_address = None;
        self.outgoing_address = None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;
    use ratatui::Terminal;

    #[test]
    fn tui_renders_question_based_dogecoin_layout_with_color() -> Result<()> {
        let app = TuiApp::new();
        let mut terminal = Terminal::new(TestBackend::new(84, 28))?;

        terminal.draw(|frame| render_tui(frame, &app))?;
        let buffer = terminal.backend().buffer();
        let lines = rendered_lines(buffer);
        let rendered = lines.join("\n");

        assert!(rendered.contains("What would you like to do?"));
        assert!(rendered.contains("[g] Generate mnemonic"));
        assert!(rendered.contains("[i] Create incoming address"));
        assert!(rendered.contains("[o] Create outgoing/change address"));
        assert!(rendered.contains(" / \\__"));
        assert!(!rendered.contains("Methods"));

        assert_text_color(buffer, "EasyDoge KM", Color::LightYellow);
        assert_text_color(buffer, "[g]", Color::Yellow);
        Ok(())
    }

    #[test]
    fn tui_output_wraps_long_values_for_copying() -> Result<()> {
        let long_value = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let app = TuiApp {
            reveal: true,
            status: "ready".to_owned(),
            generated_secret: Some(long_value.to_owned()),
            account: 0,
            address_index: 0,
            incoming_address: None,
            outgoing_address: None,
        };
        let mut terminal = Terminal::new(TestBackend::new(34, 24))?;

        terminal.draw(|frame| render_tui(frame, &app))?;

        let lines = rendered_lines(terminal.backend().buffer());
        let generated_line = lines
            .iter()
            .position(|line| line.contains("Generated:"))
            .context("generated output line should render")?;

        assert!(
            !lines[generated_line].contains("012345"),
            "test fragment should not fit on the first generated row"
        );
        assert!(
            lines
                .iter()
                .skip(generated_line + 1)
                .any(|line| line.contains("012345")),
            "long generated values must wrap onto later rows so users can copy the full value"
        );
        Ok(())
    }

    #[test]
    fn tui_can_create_incoming_and_outgoing_addresses_for_account() -> Result<()> {
        let mut app = TuiApp::new();

        handle_tui_key(&mut app, KeyCode::Char('i'))?;
        assert_eq!(
            app.incoming_address,
            Some(TuiDerivedAddress {
                path: "m/44'/3'/0'/0/0".to_owned(),
                address: "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM".to_owned(),
            })
        );

        handle_tui_key(&mut app, KeyCode::Char('o'))?;
        assert_eq!(
            app.outgoing_address,
            Some(TuiDerivedAddress {
                path: "m/44'/3'/0'/1/0".to_owned(),
                address: "DJC5m9hUngm7SzvMJb26FcFWC7Ew14eQxH".to_owned(),
            })
        );

        handle_tui_key(&mut app, KeyCode::Char('n'))?;
        assert_eq!(app.address_index, 1);
        assert!(app.incoming_address.is_none());
        assert!(app.outgoing_address.is_none());

        handle_tui_key(&mut app, KeyCode::Char('d'))?;
        assert_eq!(
            app.incoming_address.as_ref().unwrap().path,
            "m/44'/3'/0'/0/1"
        );
        assert_eq!(
            app.outgoing_address.as_ref().unwrap().path,
            "m/44'/3'/0'/1/1"
        );
        Ok(())
    }

    #[test]
    fn tui_renders_account_address_controls_and_results() -> Result<()> {
        let app = TuiApp {
            reveal: false,
            status: "created".to_owned(),
            generated_secret: None,
            account: 7,
            address_index: 42,
            incoming_address: Some(TuiDerivedAddress {
                path: "m/44'/3'/7'/0/42".to_owned(),
                address: "DINCOMINGCOPYVALUE1234567890".to_owned(),
            }),
            outgoing_address: Some(TuiDerivedAddress {
                path: "m/44'/3'/7'/1/42".to_owned(),
                address: "DOUTGOINGCOPYVALUE1234567890".to_owned(),
            }),
        };
        let mut terminal = Terminal::new(TestBackend::new(84, 24))?;

        terminal.draw(|frame| render_tui(frame, &app))?;
        let lines = rendered_lines(terminal.backend().buffer());
        let rendered = lines.join("\n");

        assert!(rendered.contains("[i] Create incoming address"));
        assert!(rendered.contains("[o] Create outgoing/change address"));
        assert!(rendered.contains("Account: 7"));
        assert!(rendered.contains("Index: 42"));
        assert!(rendered.contains("Incoming path: m/44'/3'/7'/0/42"));
        assert!(rendered.contains("Outgoing path: m/44'/3'/7'/1/42"));
        assert!(rendered.contains("Incoming address: DINCOMINGCOPYVALUE"));
        assert!(rendered.contains("Outgoing address: DOUTGOINGCOPYVALUE"));
        Ok(())
    }

    fn rendered_lines(buffer: &Buffer) -> Vec<String> {
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn assert_text_color(buffer: &Buffer, expected: &str, color: Color) {
        let lines = rendered_lines(buffer);
        for (y, line) in lines.iter().enumerate() {
            if let Some(byte_x) = line.find(expected) {
                let x = line[..byte_x].chars().count();
                for (offset, symbol) in expected.chars().enumerate() {
                    if symbol == ' ' {
                        continue;
                    }
                    assert_eq!(
                        buffer[(x as u16 + offset as u16, y as u16)].fg,
                        color,
                        "{expected} should render in {color:?}"
                    );
                }
                return;
            }
        }
        panic!("{expected} should render");
    }
}
