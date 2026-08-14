use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
};
use easydoge_km::{
    account_xpriv_from_mnemonic, address_from_wif, combine_signing_envelopes,
    compose_and_sign_transaction, derive_address_from_xpriv, derive_address_from_xpub,
    derive_path_from_xpriv, finalize_signing_envelope, generate_mnemonic, inspect_address,
    inspect_xpriv, inspect_xpub, mnemonic_to_seed_hex, sign_message, sign_p2pkh_transaction,
    sign_signing_envelope, validate_address, validate_mnemonic, verify_message, wif_from_xpriv,
    xpub_from_xpriv, AddressInfo, AddressKind, ComposeTransactionRequest, ExtendedKeyInfo,
    Language, MnemonicOptions, Network, SigningEnvelope, WifInfo, Xpriv, Xpub,
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
    Compose {
        #[arg(long)]
        request_file: String,
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
    if let Err(error) = crossterm::execute!(io::stdout(), EnableBracketedPaste)
        .context("enable terminal paste events")
    {
        ratatui::restore();
        return Err(error);
    }

    let result: Result<()> = loop {
        terminal
            .draw(|frame| {
                render_tui(frame, &app);
            })
            .context("draw Ratatui frame")?;

        match event::read().context("read terminal event")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if handle_tui_key(&mut app, key.code)? {
                    break Ok(());
                }
            }
            Event::Paste(contents) => handle_tui_paste(&mut app, &contents)?,
            _ => {}
        }
    };
    let cleanup_result = crossterm::execute!(io::stdout(), DisableBracketedPaste)
        .context("disable terminal paste events");
    ratatui::restore();
    result?;
    cleanup_result
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
    let question = tui_question_lines(app, reveal_label);
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

    let body = tui_answer_lines(app);
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

fn tui_question_lines(app: &TuiApp, reveal_label: &str) -> Vec<Line<'static>> {
    match app.mode {
        TuiMode::PasteInput => vec![
            Line::from(vec![Span::styled(
                "Paste or type an address, seed phrase, xpriv, xpub, or WIF.",
                question_style(),
            )]),
            Line::from(vec![
                key_span("Enter"),
                Span::raw(" Inspect"),
                Span::raw("    "),
                key_span("Backspace"),
                Span::raw(" Delete"),
                Span::raw("    "),
                key_span("Esc"),
                Span::raw(" Cancel"),
            ]),
            Line::from(vec![
                Span::styled("Buffered input: ", muted_style()),
                Span::styled(
                    format!("{} chars", app.input_buffer.chars().count()),
                    value_style(),
                ),
            ]),
            Line::from(vec![Span::styled(
                "Input is not echoed until it has been classified, because it may be secret.",
                muted_style(),
            )]),
        ],
        TuiMode::PassphraseInput => vec![
            Line::from(vec![Span::styled(
                "Seed phrase detected. Enter an optional BIP39 passphrase.",
                question_style(),
            )]),
            Line::from(vec![
                key_span("Enter"),
                Span::raw(" Continue"),
                Span::raw("    "),
                key_span("Backspace"),
                Span::raw(" Delete"),
                Span::raw("    "),
                key_span("Esc"),
                Span::raw(" Cancel"),
            ]),
            Line::from(vec![
                Span::styled("Passphrase: ", muted_style()),
                Span::styled(
                    if app.passphrase_buffer.is_empty() {
                        "[empty]"
                    } else {
                        "[redacted]"
                    },
                    value_style(),
                ),
            ]),
        ],
        TuiMode::Home | TuiMode::InspectResult => vec![
            Line::from(vec![Span::styled(
                "What would you like to do?",
                question_style(),
            )]),
            Line::from(vec![
                key_span("/"),
                Span::raw(" Paste/inspect"),
                Span::raw("    "),
                key_span("g"),
                Span::raw(" Generate mnemonic"),
                Span::raw("    "),
                key_span("v"),
                Span::raw(" Validate sample"),
                Span::raw("    "),
                key_span("r"),
                Span::raw(format!(" {reveal_label}")),
            ]),
            Line::from(vec![
                key_span("i"),
                Span::raw(" Create incoming address"),
                Span::raw("    "),
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
                Span::styled(active_source_label(app), accent_style()),
                Span::styled(" for derivations. Press ", muted_style()),
                key_span("q"),
                Span::styled(" to quit.", muted_style()),
            ]),
        ],
    }
}

fn tui_answer_lines(app: &TuiApp) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            label_span("Status: "),
            Span::styled(app.status.clone(), status_style(app.status.as_str())),
        ]),
        Line::from(vec![
            label_span("Source: "),
            Span::raw(active_source_label(app)),
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
    ];

    append_material_lines(app, &mut lines);
    append_address_lines(app, &mut lines);
    lines
}

fn append_material_lines(app: &TuiApp, lines: &mut Vec<Line<'static>>) {
    match &app.inspected_material {
        Some(TuiInspectedMaterial::Mnemonic {
            phrase,
            passphrase,
            language,
            word_count,
            account_xpub,
        }) => {
            lines.push(Line::from(vec![
                label_span("Material: "),
                Span::raw("seed phrase"),
                Span::raw("   "),
                label_span("Language: "),
                Span::styled(language_label(*language), value_style()),
                Span::raw("   "),
                label_span("Words: "),
                Span::styled(word_count.to_string(), value_style()),
            ]));
            lines.push(Line::from(vec![
                label_span("Seed phrase: "),
                Span::raw(if app.reveal {
                    phrase.clone()
                } else {
                    "[redacted]".to_owned()
                }),
            ]));
            lines.push(Line::from(vec![
                label_span("Passphrase: "),
                Span::raw(if let Some(passphrase) = passphrase {
                    if app.reveal {
                        passphrase.clone()
                    } else {
                        "[redacted]".to_owned()
                    }
                } else {
                    "[empty]".to_owned()
                }),
            ]));
            lines.push(Line::from(vec![
                label_span("Account xpub: "),
                Span::raw(account_xpub.clone()),
            ]));
        }
        Some(TuiInspectedMaterial::Xpriv { info, xpub, .. }) => {
            append_extended_key_lines(lines, "extended private key", info);
            lines.push(Line::from(vec![
                label_span("Xpriv: "),
                Span::raw("[redacted]"),
                Span::raw("   "),
                label_span("Xpub: "),
                Span::raw(xpub.clone()),
            ]));
        }
        Some(TuiInspectedMaterial::Xpub { xpub, info }) => {
            append_extended_key_lines(lines, "extended public key", info);
            lines.push(Line::from(vec![
                label_span("Xpub: "),
                Span::raw(xpub.encoded.clone()),
            ]));
        }
        Some(TuiInspectedMaterial::Address { address, matches }) => {
            lines.push(Line::from(vec![
                label_span("Material: "),
                Span::raw("address"),
                Span::raw("   "),
                label_span("Valid matches: "),
                Span::styled(matches.len().to_string(), value_style()),
            ]));
            lines.push(Line::from(vec![
                label_span("Address: "),
                Span::raw(address.clone()),
            ]));
            if matches.is_empty() {
                lines.push(Line::from(vec![
                    label_span("Networks: "),
                    Span::raw("none"),
                ]));
            } else {
                for info in matches {
                    lines.push(Line::from(vec![
                        label_span("Network: "),
                        Span::styled(info.network.to_string(), value_style()),
                        Span::raw("   "),
                        label_span("Kind: "),
                        Span::styled(address_kind_label(info.kind), value_style()),
                        Span::raw("   "),
                        label_span("Payload: "),
                        Span::raw(info.payload_hex.clone()),
                    ]));
                }
            }
        }
        Some(TuiInspectedMaterial::Wif { info }) => {
            lines.push(Line::from(vec![
                label_span("Material: "),
                Span::raw("WIF"),
                Span::raw("   "),
                label_span("Network: "),
                Span::styled(info.network.to_string(), value_style()),
                Span::raw("   "),
                label_span("Compressed: "),
                Span::styled(info.compressed.to_string(), value_style()),
            ]));
            lines.push(Line::from(vec![
                label_span("WIF: "),
                Span::raw("[redacted]"),
            ]));
            lines.push(Line::from(vec![
                label_span("Public key: "),
                Span::raw(info.public_key_hex.clone()),
            ]));
        }
        None => {
            let secret_line = match (&app.generated_secret, app.reveal) {
                (Some(secret), true) => secret.as_str(),
                (Some(_), false) => "[redacted]",
                (None, _) => "No generated mnemonic yet",
            };
            lines.push(Line::from(vec![
                label_span("Generated: "),
                Span::raw(secret_line.to_owned()),
            ]));
        }
    }
}

fn append_extended_key_lines(
    lines: &mut Vec<Line<'static>>,
    material_label: &'static str,
    info: &ExtendedKeyInfo,
) {
    lines.push(Line::from(vec![
        label_span("Material: "),
        Span::raw(material_label),
        Span::raw("   "),
        label_span("Network: "),
        Span::styled(info.network.to_string(), value_style()),
        Span::raw("   "),
        label_span("Depth: "),
        Span::styled(info.depth.to_string(), value_style()),
    ]));
    lines.push(Line::from(vec![
        label_span("Parent fingerprint: "),
        Span::raw(info.parent_fingerprint_hex.clone()),
        Span::raw("   "),
        label_span("Child number: "),
        Span::styled(info.child_number.to_string(), value_style()),
    ]));
    if let Some(public_key_hex) = &info.public_key_hex {
        lines.push(Line::from(vec![
            label_span("Public key: "),
            Span::raw(public_key_hex.clone()),
        ]));
    }
}

fn append_address_lines(app: &TuiApp, lines: &mut Vec<Line<'static>>) {
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
    lines.push(Line::from(vec![
        label_span("Incoming path: "),
        Span::raw(incoming_path.to_owned()),
    ]));
    lines.push(Line::from(vec![
        label_span("Incoming address: "),
        Span::styled(incoming_address.to_owned(), address_style(incoming_address)),
    ]));
    lines.push(Line::from(vec![
        label_span("Outgoing path: "),
        Span::raw(outgoing_path.to_owned()),
    ]));
    lines.push(Line::from(vec![
        label_span("Outgoing address: "),
        Span::styled(outgoing_address.to_owned(), address_style(outgoing_address)),
    ]));
}

fn active_source_label(app: &TuiApp) -> &'static str {
    if app.pending_mnemonic.is_some() {
        return "pasted seed phrase";
    }
    match app.inspected_material {
        Some(TuiInspectedMaterial::Mnemonic { .. }) => "pasted seed phrase",
        Some(TuiInspectedMaterial::Xpriv { .. }) => "pasted xpriv",
        Some(TuiInspectedMaterial::Xpub { .. }) => "pasted xpub",
        Some(TuiInspectedMaterial::Address { .. }) => "pasted address",
        Some(TuiInspectedMaterial::Wif { .. }) => "pasted WIF",
        None if app.generated_secret.is_some() => "generated mnemonic",
        None => "sample mnemonic",
    }
}

fn language_label(language: Language) -> &'static str {
    match language {
        Language::English => "english",
        Language::SimplifiedChinese => "simplified-chinese",
        Language::TraditionalChinese => "traditional-chinese",
        Language::Czech => "czech",
        Language::French => "french",
        Language::Italian => "italian",
        Language::Japanese => "japanese",
        Language::Korean => "korean",
        Language::Portuguese => "portuguese",
        Language::Spanish => "spanish",
    }
}

fn address_kind_label(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2pkh => "p2pkh",
        AddressKind::P2sh => "p2sh",
    }
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
        || status.starts_with("Inspected")
        || status.starts_with("Ready")
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
    match app.mode {
        TuiMode::PasteInput => handle_tui_paste_input_key(app, key),
        TuiMode::PassphraseInput => handle_tui_passphrase_key(app, key),
        TuiMode::Home | TuiMode::InspectResult => handle_tui_home_key(app, key),
    }
}

fn handle_tui_home_key(app: &mut TuiApp, key: KeyCode) -> Result<bool> {
    match key {
        KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
        KeyCode::Char('/') => {
            app.mode = TuiMode::PasteInput;
            app.clear_input();
            app.status = "Ready for pasted address, seed phrase, xpriv, xpub, or WIF.".to_owned();
        }
        KeyCode::Char('r') => {
            app.reveal = !app.reveal;
            app.status = "Reveal toggled for secret material.".to_owned();
        }
        KeyCode::Char('g') => {
            let generated = generate_mnemonic(MnemonicOptions::default())?;
            app.generated_secret = Some(generated.phrase);
            app.inspected_material = None;
            app.clear_addresses();
            app.status = "Generated a 24-word English mnemonic.".to_owned();
        }
        KeyCode::Char('v') => {
            let valid = validate_mnemonic(TUI_SAMPLE_PHRASE, Language::English)?;
            app.status = format!("Sample mnemonic valid: {valid}");
        }
        KeyCode::Char('i') => match derive_tui_address(app, TuiAddressBranch::Incoming) {
            Ok(address) => {
                app.incoming_address = Some(address);
                app.status = format!(
                    "Created incoming address for account {} index {}.",
                    app.account, app.address_index
                );
            }
            Err(error) => app.status = error.to_string(),
        },
        KeyCode::Char('o') => match derive_tui_address(app, TuiAddressBranch::Outgoing) {
            Ok(address) => {
                app.outgoing_address = Some(address);
                app.status = format!(
                    "Created outgoing address for account {} index {}.",
                    app.account, app.address_index
                );
            }
            Err(error) => app.status = error.to_string(),
        },
        KeyCode::Char('d') => match derive_tui_addresses(app) {
            Ok(()) => {
                app.status = format!(
                    "Created incoming and outgoing addresses for account {} index {}.",
                    app.account, app.address_index
                );
            }
            Err(error) => app.status = error.to_string(),
        },
        KeyCode::Char('n') => {
            app.address_index = app.address_index.saturating_add(1);
            app.clear_addresses();
            refresh_tui_derivations(app)?;
            app.status = format!("Address index set to {}.", app.address_index);
        }
        KeyCode::Char('p') => {
            app.address_index = app.address_index.saturating_sub(1);
            app.clear_addresses();
            refresh_tui_derivations(app)?;
            app.status = format!("Address index set to {}.", app.address_index);
        }
        KeyCode::Char('a') => {
            if tui_account_can_change(app) {
                app.account = app.account.saturating_add(1);
                app.clear_addresses();
                refresh_tui_derivations(app)?;
                app.status = format!("Account set to {}.", app.account);
            } else {
                app.status =
                    "Account control applies only to seed phrases and master xprivs.".to_owned();
            }
        }
        KeyCode::Char('z') => {
            if tui_account_can_change(app) {
                app.account = app.account.saturating_sub(1);
                app.clear_addresses();
                refresh_tui_derivations(app)?;
                app.status = format!("Account set to {}.", app.account);
            } else {
                app.status =
                    "Account control applies only to seed phrases and master xprivs.".to_owned();
            }
        }
        _ => {}
    }
    Ok(false)
}

fn handle_tui_paste_input_key(app: &mut TuiApp, key: KeyCode) -> Result<bool> {
    match key {
        KeyCode::Esc => cancel_tui_input(app),
        KeyCode::Enter => submit_tui_pasted_material(app)?,
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Char(ch) => app.input_buffer.push(ch),
        _ => {}
    }
    Ok(false)
}

fn handle_tui_passphrase_key(app: &mut TuiApp, key: KeyCode) -> Result<bool> {
    match key {
        KeyCode::Esc => cancel_tui_input(app),
        KeyCode::Enter => submit_tui_mnemonic_passphrase(app)?,
        KeyCode::Backspace => {
            app.passphrase_buffer.pop();
        }
        KeyCode::Char(ch) => app.passphrase_buffer.push(ch),
        _ => {}
    }
    Ok(false)
}

fn handle_tui_paste(app: &mut TuiApp, contents: &str) -> Result<()> {
    match app.mode {
        TuiMode::PasteInput => app.input_buffer.push_str(contents),
        TuiMode::PassphraseInput => app.passphrase_buffer.push_str(contents),
        TuiMode::Home | TuiMode::InspectResult => {
            app.mode = TuiMode::PasteInput;
            app.clear_input();
            app.input_buffer.push_str(contents);
            submit_tui_pasted_material(app)?;
        }
    }
    Ok(())
}

fn cancel_tui_input(app: &mut TuiApp) {
    app.clear_input();
    app.mode = if app.inspected_material.is_some() {
        TuiMode::InspectResult
    } else {
        TuiMode::Home
    };
    app.status = "Input cancelled.".to_owned();
}

fn submit_tui_pasted_material(app: &mut TuiApp) -> Result<()> {
    let input = normalize_tui_input(&app.input_buffer);
    if input.is_empty() {
        app.status = "Paste or type material before inspecting.".to_owned();
        return Ok(());
    }

    if let Some(pending) = classify_tui_mnemonic(&input)? {
        // Drop any previous inspect result so the Answer panel does not keep showing
        // e.g. "pasted address" while the seed passphrase prompt is active.
        app.inspected_material = None;
        app.generated_secret = None;
        app.clear_addresses();
        app.pending_mnemonic = Some(pending);
        app.passphrase_buffer.clear();
        app.mode = TuiMode::PassphraseInput;
        app.status =
            "Seed phrase detected. Enter optional passphrase, then press Enter.".to_owned();
        return Ok(());
    }

    let material = match classify_tui_non_mnemonic(&input) {
        Ok(material) => material,
        Err(error) => {
            app.status = error.to_string();
            return Ok(());
        }
    };
    app.clear_input();
    set_tui_inspected_material(app, material)?;
    Ok(())
}

fn submit_tui_mnemonic_passphrase(app: &mut TuiApp) -> Result<()> {
    let pending = app
        .pending_mnemonic
        .take()
        .context("pending mnemonic should exist before passphrase submit")?;
    let passphrase = if app.passphrase_buffer.is_empty() {
        None
    } else {
        Some(app.passphrase_buffer.clone())
    };
    let keys = account_xpriv_from_mnemonic(
        &pending.phrase,
        passphrase.as_deref(),
        pending.language,
        Network::Mainnet,
        app.account,
    )?;
    let material = TuiInspectedMaterial::Mnemonic {
        phrase: pending.phrase,
        passphrase,
        language: pending.language,
        word_count: pending.word_count,
        account_xpub: keys.xpub.encoded,
    };
    app.clear_input();
    set_tui_inspected_material(app, material)
}

fn set_tui_inspected_material(app: &mut TuiApp, material: TuiInspectedMaterial) -> Result<()> {
    let fixed_account = tui_material_fixed_account(&material);
    app.inspected_material = Some(material);
    if let Some(account) = fixed_account {
        app.account = account;
    }
    app.generated_secret = None;
    app.mode = TuiMode::InspectResult;
    app.clear_addresses();
    refresh_tui_derivations(app)?;
    app.status = if let Some(message) = app
        .inspected_material
        .as_ref()
        .and_then(unsupported_tui_derivation_message)
    {
        format!("Inspected {}. {message}", active_source_label(app))
    } else {
        format!("Inspected {}.", active_source_label(app))
    };
    Ok(())
}

fn refresh_tui_derivations(app: &mut TuiApp) -> Result<()> {
    if app
        .inspected_material
        .as_ref()
        .is_some_and(tui_material_supports_derivations)
    {
        derive_tui_addresses(app)?;
    }
    Ok(())
}

fn derive_tui_addresses(app: &mut TuiApp) -> Result<()> {
    let incoming = derive_tui_address(app, TuiAddressBranch::Incoming)?;
    let outgoing = derive_tui_address(app, TuiAddressBranch::Outgoing)?;
    app.incoming_address = Some(incoming);
    app.outgoing_address = Some(outgoing);
    Ok(())
}

fn derive_tui_address(app: &TuiApp, branch: TuiAddressBranch) -> Result<TuiDerivedAddress> {
    if let Some(material) = &app.inspected_material {
        return derive_inspected_tui_address(app, material, branch);
    }

    let (phrase, passphrase) = match app.generated_secret.as_deref() {
        Some(phrase) => (phrase, None),
        None => (TUI_SAMPLE_PHRASE, Some("TREZOR")),
    };
    derive_mnemonic_tui_address(
        phrase,
        passphrase,
        Language::English,
        Network::Mainnet,
        app.account,
        app.address_index,
        branch,
    )
}

fn derive_inspected_tui_address(
    app: &TuiApp,
    material: &TuiInspectedMaterial,
    branch: TuiAddressBranch,
) -> Result<TuiDerivedAddress> {
    match material {
        TuiInspectedMaterial::Mnemonic {
            phrase,
            passphrase,
            language,
            ..
        } => derive_mnemonic_tui_address(
            phrase,
            passphrase.as_deref(),
            *language,
            Network::Mainnet,
            app.account,
            app.address_index,
            branch,
        ),
        TuiInspectedMaterial::Xpriv { xpriv, info, .. } => {
            let path = tui_xpriv_derivation_path(app, info, branch)?;
            let address = derive_address_from_xpriv(xpriv, &path)?;
            Ok(TuiDerivedAddress {
                path,
                address: address.address,
            })
        }
        TuiInspectedMaterial::Xpub { xpub, info } => {
            let path = tui_xpub_derivation_path(app, info, branch)?;
            let address = derive_address_from_xpub(xpub, &path)?;
            Ok(TuiDerivedAddress {
                path,
                address: address.address,
            })
        }
        TuiInspectedMaterial::Address { .. } | TuiInspectedMaterial::Wif { .. } => Err(anyhow!(
            "address derivation does not apply to the inspected material"
        )),
    }
}

fn tui_material_supports_derivations(material: &TuiInspectedMaterial) -> bool {
    match material {
        TuiInspectedMaterial::Mnemonic { .. } => true,
        TuiInspectedMaterial::Xpriv { info, .. } => matches!(info.depth, 0 | 3),
        TuiInspectedMaterial::Xpub { info, .. } => info.depth == 3,
        TuiInspectedMaterial::Address { .. } | TuiInspectedMaterial::Wif { .. } => false,
    }
}

fn tui_account_can_change(app: &TuiApp) -> bool {
    match &app.inspected_material {
        Some(TuiInspectedMaterial::Xpriv { info, .. }) => info.depth == 0,
        Some(TuiInspectedMaterial::Xpub { .. })
        | Some(TuiInspectedMaterial::Address { .. })
        | Some(TuiInspectedMaterial::Wif { .. }) => false,
        Some(TuiInspectedMaterial::Mnemonic { .. }) | None => true,
    }
}

fn tui_material_fixed_account(material: &TuiInspectedMaterial) -> Option<u32> {
    match material {
        TuiInspectedMaterial::Xpriv { info, .. } | TuiInspectedMaterial::Xpub { info, .. } => {
            account_from_extended_key_info(info)
        }
        TuiInspectedMaterial::Mnemonic { .. }
        | TuiInspectedMaterial::Address { .. }
        | TuiInspectedMaterial::Wif { .. } => None,
    }
}

fn account_from_extended_key_info(info: &ExtendedKeyInfo) -> Option<u32> {
    const HARDENED_CHILD_OFFSET: u32 = 1 << 31;

    if info.depth == 3 && info.child_number >= HARDENED_CHILD_OFFSET {
        Some(info.child_number - HARDENED_CHILD_OFFSET)
    } else {
        None
    }
}

fn unsupported_tui_derivation_message(material: &TuiInspectedMaterial) -> Option<&'static str> {
    match material {
        TuiInspectedMaterial::Xpriv { info, .. } if !matches!(info.depth, 0 | 3) => {
            Some("Address derivation requires a master or account-level xpriv.")
        }
        TuiInspectedMaterial::Xpub { info, .. } if info.depth != 3 => {
            Some("Address derivation requires an account-level xpub.")
        }
        _ => None,
    }
}

fn tui_xpriv_derivation_path(
    app: &TuiApp,
    info: &ExtendedKeyInfo,
    branch: TuiAddressBranch,
) -> Result<String> {
    match info.depth {
        0 => Ok(format!(
            "m/44'/3'/{}'/{}/{}",
            app.account,
            branch.path_component(),
            app.address_index
        )),
        3 => Ok(format!(
            "m/{}/{}",
            branch.path_component(),
            app.address_index
        )),
        _ => Err(anyhow!(
            "Address derivation requires a master or account-level xpriv."
        )),
    }
}

fn tui_xpub_derivation_path(
    app: &TuiApp,
    info: &ExtendedKeyInfo,
    branch: TuiAddressBranch,
) -> Result<String> {
    if info.depth != 3 {
        return Err(anyhow!(
            "Address derivation requires an account-level xpub."
        ));
    }
    Ok(format!(
        "m/{}/{}",
        branch.path_component(),
        app.address_index
    ))
}

fn derive_mnemonic_tui_address(
    phrase: &str,
    passphrase: Option<&str>,
    language: Language,
    network: Network,
    account: u32,
    address_index: u32,
    branch: TuiAddressBranch,
) -> Result<TuiDerivedAddress> {
    let keys = account_xpriv_from_mnemonic(phrase, passphrase, language, network, account)?;
    let relative_path = format!("m/{}/{}", branch.path_component(), address_index);
    let display_path = format!(
        "{}/{}/{}",
        keys.account_path,
        branch.path_component(),
        address_index
    );
    let address = derive_address_from_xpub(&keys.xpub, &relative_path)?;
    Ok(TuiDerivedAddress {
        path: display_path,
        address: address.address,
    })
}

fn normalize_tui_input(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn classify_tui_mnemonic(input: &str) -> Result<Option<TuiPendingMnemonic>> {
    let word_count = input.split_whitespace().count();
    if !matches!(word_count, 12 | 15 | 18 | 21 | 24) {
        return Ok(None);
    }

    for language in TUI_LANGUAGES {
        if validate_mnemonic(input, language)? {
            return Ok(Some(TuiPendingMnemonic {
                phrase: input.to_owned(),
                language,
                word_count,
            }));
        }
    }
    Ok(None)
}

fn classify_tui_non_mnemonic(input: &str) -> Result<TuiInspectedMaterial> {
    let word_count = input.split_whitespace().count();
    // Addresses, WIFs, and extended keys are single Base58 tokens. Multi-word
    // paste is either an invalid/incomplete seed phrase or unrelated text.
    if word_count > 1 {
        if matches!(word_count, 12 | 15 | 18 | 21 | 24) {
            return Err(anyhow!(
                "Seed phrase has {word_count} words but is not a valid BIP39 mnemonic."
            ));
        }
        return Err(anyhow!(
            "Could not classify pasted material as a seed phrase, xpriv, xpub, address, or WIF."
        ));
    }

    if let Some(material) = inspect_tui_xpriv(input)? {
        return Ok(material);
    }
    if let Some(material) = inspect_tui_xpub(input)? {
        return Ok(material);
    }

    let address_matches = inspect_address(input)?;
    if !address_matches.is_empty() {
        return Ok(TuiInspectedMaterial::Address {
            address: input.to_owned(),
            matches: address_matches,
        });
    }

    if let Some(material) = inspect_tui_wif(input) {
        return Ok(material);
    }

    Err(anyhow!(
        "Could not classify pasted material as a seed phrase, xpriv, xpub, address, or WIF."
    ))
}

fn inspect_tui_xpriv(input: &str) -> Result<Option<TuiInspectedMaterial>> {
    for network in TUI_NETWORKS {
        let xpriv = Xpriv {
            network,
            encoded: input.to_owned(),
        };
        if let Ok(info) = inspect_xpriv(&xpriv) {
            let xpub = xpub_from_xpriv(&xpriv)?;
            return Ok(Some(TuiInspectedMaterial::Xpriv {
                xpriv,
                info,
                xpub: xpub.encoded,
            }));
        }
    }
    Ok(None)
}

fn inspect_tui_xpub(input: &str) -> Result<Option<TuiInspectedMaterial>> {
    for network in TUI_NETWORKS {
        let xpub = Xpub {
            network,
            encoded: input.to_owned(),
        };
        if let Ok(info) = inspect_xpub(&xpub) {
            return Ok(Some(TuiInspectedMaterial::Xpub { xpub, info }));
        }
    }
    Ok(None)
}

fn inspect_tui_wif(input: &str) -> Option<TuiInspectedMaterial> {
    for network in TUI_NETWORKS {
        if let Ok(info) = address_from_wif(network, input) {
            return Some(TuiInspectedMaterial::Wif { info });
        }
    }
    None
}

const TUI_NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

const TUI_LANGUAGES: [Language; 10] = [
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiMode {
    Home,
    PasteInput,
    PassphraseInput,
    InspectResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiPendingMnemonic {
    phrase: String,
    language: Language,
    word_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiInspectedMaterial {
    Mnemonic {
        phrase: String,
        passphrase: Option<String>,
        language: Language,
        word_count: usize,
        account_xpub: String,
    },
    Xpriv {
        xpriv: Xpriv,
        info: ExtendedKeyInfo,
        xpub: String,
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

struct TuiApp {
    mode: TuiMode,
    reveal: bool,
    status: String,
    generated_secret: Option<String>,
    input_buffer: String,
    passphrase_buffer: String,
    pending_mnemonic: Option<TuiPendingMnemonic>,
    inspected_material: Option<TuiInspectedMaterial>,
    account: u32,
    address_index: u32,
    incoming_address: Option<TuiDerivedAddress>,
    outgoing_address: Option<TuiDerivedAddress>,
}

impl TuiApp {
    fn new() -> Self {
        Self {
            mode: TuiMode::Home,
            reveal: false,
            status: "Choose an action. Secrets stay redacted until reveal is enabled.".to_owned(),
            generated_secret: None,
            input_buffer: String::new(),
            passphrase_buffer: String::new(),
            pending_mnemonic: None,
            inspected_material: None,
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

    fn clear_input(&mut self) {
        self.input_buffer.clear();
        self.passphrase_buffer.clear();
        self.pending_mnemonic = None;
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

fn read_compose_request(path: &str) -> Result<ComposeTransactionRequest> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use easydoge_km::derive_path_from_xpub;
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
            ..TuiApp::new()
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
            ..TuiApp::new()
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

    #[test]
    fn tui_paste_seed_after_address_clears_address_source() -> Result<()> {
        let mut app = TuiApp::new();
        handle_tui_paste(&mut app, "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM")?;
        assert_eq!(active_source_label(&app), "pasted address");
        assert!(matches!(
            app.inspected_material,
            Some(TuiInspectedMaterial::Address { .. })
        ));

        handle_tui_paste(&mut app, TUI_SAMPLE_PHRASE)?;
        assert_eq!(app.mode, TuiMode::PassphraseInput);
        assert!(app.pending_mnemonic.is_some());
        assert!(app.inspected_material.is_none());
        assert_eq!(active_source_label(&app), "pasted seed phrase");
        assert!(app.status.contains("Seed phrase detected"));
        Ok(())
    }

    #[test]
    fn tui_paste_inspects_address_without_derivation() -> Result<()> {
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM")?;

        assert_eq!(app.mode, TuiMode::InspectResult);
        assert!(matches!(
            app.inspected_material,
            Some(TuiInspectedMaterial::Address { .. })
        ));
        assert!(app.incoming_address.is_none());
        assert!(app.outgoing_address.is_none());
        Ok(())
    }

    #[test]
    fn tui_invalid_seed_phrase_does_not_classify_as_address() -> Result<()> {
        let mut app = TuiApp::new();
        // Valid word count, invalid checksum / last word.
        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        handle_tui_paste(&mut app, invalid_phrase)?;

        assert_eq!(app.mode, TuiMode::PasteInput);
        assert!(app.inspected_material.is_none());
        assert!(app.status.contains("not a valid BIP39 mnemonic"));
        Ok(())
    }

    #[test]
    fn tui_invalid_paste_keeps_input_editable() -> Result<()> {
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, "not wallet material")?;

        assert_eq!(app.mode, TuiMode::PasteInput);
        assert_eq!(app.input_buffer, "not wallet material");
        assert!(app.status.contains("Could not classify pasted material"));
        Ok(())
    }

    #[test]
    fn tui_paste_seed_phrase_uses_optional_passphrase_for_derivation() -> Result<()> {
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, TUI_SAMPLE_PHRASE)?;
        assert_eq!(app.mode, TuiMode::PassphraseInput);

        handle_tui_paste(&mut app, "TREZOR")?;
        handle_tui_key(&mut app, KeyCode::Enter)?;

        assert_eq!(app.mode, TuiMode::InspectResult);
        assert!(matches!(
            app.inspected_material,
            Some(TuiInspectedMaterial::Mnemonic { .. })
        ));
        assert_eq!(
            app.incoming_address,
            Some(TuiDerivedAddress {
                path: "m/44'/3'/0'/0/0".to_owned(),
                address: "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM".to_owned(),
            })
        );
        Ok(())
    }

    #[test]
    fn tui_paste_xpub_derives_watch_only_addresses_for_index_changes() -> Result<()> {
        let account = account_xpriv_from_mnemonic(
            TUI_SAMPLE_PHRASE,
            Some("TREZOR"),
            Language::English,
            Network::Mainnet,
            0,
        )?;
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, &account.xpub.encoded)?;

        assert_eq!(app.mode, TuiMode::InspectResult);
        assert!(matches!(
            app.inspected_material,
            Some(TuiInspectedMaterial::Xpub { .. })
        ));
        assert_eq!(
            app.incoming_address,
            Some(TuiDerivedAddress {
                path: "m/0/0".to_owned(),
                address: "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM".to_owned(),
            })
        );

        handle_tui_key(&mut app, KeyCode::Char('n'))?;
        assert_eq!(app.address_index, 1);
        assert_eq!(app.incoming_address.as_ref().unwrap().path, "m/0/1");
        Ok(())
    }

    #[test]
    fn tui_account_xpub_uses_fixed_account_metadata() -> Result<()> {
        let account = account_xpriv_from_mnemonic(
            TUI_SAMPLE_PHRASE,
            Some("TREZOR"),
            Language::English,
            Network::Mainnet,
            7,
        )?;
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, &account.xpub.encoded)?;

        assert_eq!(app.account, 7);
        assert!(app.incoming_address.is_some());

        handle_tui_key(&mut app, KeyCode::Char('a'))?;
        assert_eq!(app.account, 7);
        assert!(app.status.contains("master xprivs"));
        Ok(())
    }

    #[test]
    fn tui_branch_xpub_inspects_without_misleading_derivation() -> Result<()> {
        let account = account_xpriv_from_mnemonic(
            TUI_SAMPLE_PHRASE,
            Some("TREZOR"),
            Language::English,
            Network::Mainnet,
            0,
        )?;
        let branch_xpub = derive_path_from_xpub(&account.xpub, "m/0")?;
        let mut app = TuiApp::new();

        handle_tui_paste(&mut app, &branch_xpub.encoded)?;

        assert_eq!(app.mode, TuiMode::InspectResult);
        assert!(matches!(
            app.inspected_material,
            Some(TuiInspectedMaterial::Xpub { .. })
        ));
        assert!(app.incoming_address.is_none());
        assert!(app.outgoing_address.is_none());
        assert!(app.status.contains("account-level xpub"));

        handle_tui_key(&mut app, KeyCode::Char('i'))?;
        assert!(app.status.contains("account-level xpub"));
        assert!(app.incoming_address.is_none());
        Ok(())
    }

    #[test]
    fn tui_redacts_pasted_seed_phrase_in_rendered_result() -> Result<()> {
        let mut app = TuiApp::new();
        handle_tui_paste(&mut app, TUI_SAMPLE_PHRASE)?;
        handle_tui_key(&mut app, KeyCode::Enter)?;

        let mut terminal = Terminal::new(TestBackend::new(96, 32))?;
        terminal.draw(|frame| render_tui(frame, &app))?;
        let rendered = rendered_lines(terminal.backend().buffer()).join("\n");

        assert!(rendered.contains("Seed phrase: [redacted]"));
        assert!(!rendered.contains(TUI_SAMPLE_PHRASE));
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
