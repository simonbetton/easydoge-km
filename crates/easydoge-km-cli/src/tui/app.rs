//! Application state and key handling for the TUI explorer.
//!
//! The state machine knows nothing about the terminal, so every transition can
//! be exercised in tests by feeding it key and paste events.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use easydoge_km::{generate_mnemonic, MnemonicOptions, Network};
use ratatui::widgets::TableState;

use super::material::{
    account_context, classify, derive_rows, AccountContext, AccountControl, AddressRow, Branch,
    Classified, Material, SeedPhrase, Source, MAX_INDEX,
};

/// Number of consecutive indices kept derived around the selection.
pub const WINDOW: u32 = 64;
const MAX_JUMP_DIGITS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Explorer,
    Inspect,
    Passphrase,
    Jump,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    Success,
    Warning,
    Error,
}

/// Message shown in the status row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub kind: NoticeKind,
    pub text: String,
}

impl Notice {
    fn new(kind: NoticeKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Info, text)
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Success, text)
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Warning, text)
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self::new(NoticeKind::Error, text)
    }
}

pub struct App {
    pub mode: Mode,
    pub source: Source,
    pub network: Network,
    pub account: u32,
    pub branch: Branch,
    /// Address index the cursor is on.
    pub selected: u32,
    /// First index covered by `rows`.
    pub window_start: u32,
    pub rows: Vec<AddressRow>,
    /// Account xpub for the current source, or why there is none.
    pub context: Result<AccountContext, String>,
    pub reveal: bool,
    pub notice: Notice,
    pub input: String,
    pub input_error: Option<String>,
    pub passphrase: String,
    pub pending: Option<SeedPhrase>,
    pub jump: String,
    pub table_state: TableState,
    /// Address rows visible in the last frame; drives page navigation.
    pub viewport_rows: u16,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            mode: Mode::Explorer,
            source: Source::Sample,
            network: Network::Mainnet,
            account: 0,
            branch: Branch::Receive,
            selected: 0,
            window_start: 0,
            rows: Vec::new(),
            context: Err(String::new()),
            reveal: false,
            notice: Notice::info("Exploring the sample mnemonic. Press ? for keys."),
            input: String::new(),
            input_error: None,
            passphrase: String::new(),
            pending: None,
            jump: String::new(),
            table_state: TableState::default(),
            viewport_rows: 1,
            should_quit: false,
        };
        app.rebuild();
        app
    }

    pub fn selected_row(&self) -> Option<&AddressRow> {
        self.rows.iter().find(|row| row.index == self.selected)
    }

    /// Why the current source cannot derive addresses, if it cannot.
    pub fn derivation_note(&self) -> Option<&str> {
        self.context.as_ref().err().map(String::as_str)
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c' | 'C')) {
            self.should_quit = true;
            return;
        }
        match self.mode {
            Mode::Explorer => self.handle_explorer_key(key.code),
            Mode::Inspect => self.handle_inspect_key(key.code, ctrl),
            Mode::Passphrase => self.handle_passphrase_key(key.code, ctrl),
            Mode::Jump => self.handle_jump_key(key.code),
            Mode::Help => self.handle_help_key(key.code),
        }
    }

    pub fn handle_paste(&mut self, contents: &str) {
        match self.mode {
            Mode::Explorer => {
                self.open_inspector();
                self.input.push_str(contents);
                self.submit_input();
            }
            Mode::Inspect => {
                self.input.push_str(contents);
                self.input_error = None;
            }
            Mode::Passphrase => self.passphrase.push_str(contents),
            Mode::Jump => {
                let room = MAX_JUMP_DIGITS.saturating_sub(self.jump.len());
                self.jump
                    .extend(contents.chars().filter(char::is_ascii_digit).take(room));
                self.input_error = None;
            }
            Mode::Help => {}
        }
    }

    fn handle_explorer_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => self.escape(),
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('/') => self.open_inspector(),
            KeyCode::Char('g') => self.generate(),
            KeyCode::Char('r') => self.toggle_reveal(),
            KeyCode::Char('t') => self.cycle_network(),
            KeyCode::Char('x') => self.clear_source(),
            KeyCode::Char(':') => self.open_jump(),
            KeyCode::Char('a') => self.shift_account(1),
            KeyCode::Char('z') => self.shift_account(-1),
            KeyCode::Down | KeyCode::Char('j' | 'n') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k' | 'p') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(i64::from(self.viewport_rows.max(1))),
            KeyCode::PageUp => self.move_selection(-i64::from(self.viewport_rows.max(1))),
            KeyCode::Home => self.move_selection(-i64::from(self.selected)),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.toggle_branch();
            }
            _ => {}
        }
    }

    fn handle_inspect_key(&mut self, code: KeyCode, ctrl: bool) {
        match code {
            KeyCode::Esc => self.cancel_input(),
            KeyCode::Enter => self.submit_input(),
            KeyCode::Backspace => {
                self.input.pop();
                self.input_error = None;
            }
            KeyCode::Char('u' | 'U') if ctrl => {
                self.input.clear();
                self.input_error = None;
            }
            KeyCode::Char(ch) if !ctrl => {
                self.input.push(ch);
                self.input_error = None;
            }
            _ => {}
        }
    }

    fn handle_passphrase_key(&mut self, code: KeyCode, ctrl: bool) {
        match code {
            KeyCode::Esc => self.cancel_input(),
            KeyCode::Enter => self.submit_passphrase(),
            KeyCode::Backspace => {
                self.passphrase.pop();
            }
            KeyCode::Char('u' | 'U') if ctrl => self.passphrase.clear(),
            KeyCode::Char(ch) if !ctrl => self.passphrase.push(ch),
            _ => {}
        }
    }

    fn handle_jump_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.cancel_input(),
            KeyCode::Enter => self.submit_jump(),
            KeyCode::Backspace => {
                self.jump.pop();
                self.input_error = None;
            }
            KeyCode::Char(ch) if ch.is_ascii_digit() && self.jump.len() < MAX_JUMP_DIGITS => {
                self.jump.push(ch);
                self.input_error = None;
            }
            _ => {}
        }
    }

    fn handle_help_key(&mut self, code: KeyCode) {
        if matches!(
            code,
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?' | 'q')
        ) {
            self.mode = Mode::Explorer;
        }
    }

    fn escape(&mut self) {
        if self.reveal {
            self.reveal = false;
            self.notice = Notice::info("Secrets hidden.");
        } else {
            self.notice = Notice::info("Press q to quit or ? for keys.");
        }
    }

    fn open_inspector(&mut self) {
        self.input.clear();
        self.input_error = None;
        self.mode = Mode::Inspect;
    }

    fn open_jump(&mut self) {
        self.jump.clear();
        self.input_error = None;
        self.mode = Mode::Jump;
    }

    fn cancel_input(&mut self) {
        self.input.clear();
        self.passphrase.clear();
        self.pending = None;
        self.jump.clear();
        self.input_error = None;
        self.mode = Mode::Explorer;
        self.notice = Notice::info("Input cancelled.");
    }

    fn submit_input(&mut self) {
        match classify(&self.input) {
            Ok(Classified::SeedPhrase(seed)) => {
                self.input.clear();
                self.passphrase.clear();
                self.pending = Some(seed);
                self.mode = Mode::Passphrase;
            }
            Ok(Classified::Material(material)) => {
                self.input.clear();
                self.adopt(Source::Pasted(material));
            }
            Err(error) => self.input_error = Some(error.to_string()),
        }
    }

    fn submit_passphrase(&mut self) {
        let Some(mut seed) = self.pending.take() else {
            self.cancel_input();
            return;
        };
        if !self.passphrase.is_empty() {
            seed.passphrase = Some(std::mem::take(&mut self.passphrase));
        }
        self.adopt(Source::Pasted(Material::SeedPhrase(seed)));
    }

    fn submit_jump(&mut self) {
        match self.jump.parse::<u32>() {
            Ok(index) if index <= MAX_INDEX => {
                self.jump.clear();
                self.input_error = None;
                self.mode = Mode::Explorer;
                self.select(index);
                self.notice = Notice::success(format!("Jumped to index {index}."));
            }
            _ => {
                self.input_error = Some(format!("Enter a whole number between 0 and {MAX_INDEX}."));
            }
        }
    }

    /// Switch to a new source and re-derive everything that depends on it.
    fn adopt(&mut self, source: Source) {
        self.mode = Mode::Explorer;
        self.input_error = None;
        if let Source::Pasted(material) = &source {
            if let Some(network) = material.network() {
                self.network = network;
            }
            if let Some(account) = material.fixed_account() {
                self.account = account;
            }
        }
        let label = source.label();
        self.source = source;
        self.rebuild();
        self.notice = if self.context.is_ok() {
            Notice::success(format!("Inspected {label}."))
        } else {
            Notice::info(format!(
                "Inspected {label}. No address derivation; the Addresses panel says why."
            ))
        };
    }

    fn generate(&mut self) {
        match generate_mnemonic(MnemonicOptions::default()) {
            Ok(generated) => {
                let word_count = generated.word_count;
                self.source = Source::Generated(SeedPhrase {
                    phrase: generated.phrase,
                    passphrase: None,
                    language: generated.language,
                    word_count,
                });
                self.rebuild();
                self.notice = Notice::success(format!(
                    "Generated a {word_count}-word mnemonic. Press r to reveal it."
                ));
            }
            Err(error) => self.notice = Notice::error(format!("Generation failed: {error}")),
        }
    }

    fn clear_source(&mut self) {
        if self.source == Source::Sample {
            self.notice = Notice::info("Already exploring the sample mnemonic.");
            return;
        }
        let label = self.source.label();
        self.source = Source::Sample;
        self.rebuild();
        self.notice = Notice::success(format!("Cleared the {label}. Back to the sample mnemonic."));
    }

    fn toggle_reveal(&mut self) {
        self.reveal = !self.reveal;
        self.notice = if self.reveal {
            Notice::warning("Secrets revealed. Press r or Esc to hide them again.")
        } else {
            Notice::info("Secrets hidden.")
        };
    }

    fn cycle_network(&mut self) {
        let options = self.source.network_options();
        if options.len() < 2 {
            self.notice = match options.first() {
                Some(network) => Notice::info(format!(
                    "Network is fixed to {network} by the {}.",
                    self.source.label()
                )),
                None => Notice::info("The address panel already lists every matching network."),
            };
            return;
        }
        let position = options
            .iter()
            .position(|network| *network == self.network)
            .unwrap_or(0);
        let next = options[(position + 1) % options.len()];
        if let Source::Pasted(material) = &self.source {
            match material.with_network(next) {
                Ok(material) => self.source = Source::Pasted(material),
                Err(error) => {
                    self.notice = Notice::error(format!("Could not switch network: {error}"));
                    return;
                }
            }
        }
        self.network = next;
        self.rebuild();
        self.notice = Notice::success(format!("Switched to {next}."));
    }

    fn shift_account(&mut self, delta: i64) {
        match self.source.account_control() {
            AccountControl::Free => {
                let target = (i64::from(self.account) + delta).clamp(0, i64::from(MAX_INDEX));
                let target = u32::try_from(target).unwrap_or(MAX_INDEX);
                if target == self.account {
                    self.notice = Notice::info(format!("Account is already {target}."));
                    return;
                }
                self.account = target;
                self.rebuild();
                self.notice = Notice::success(format!("Account {target} (m/44'/3'/{target}')."));
            }
            AccountControl::Fixed(account) => {
                self.notice = Notice::info(format!(
                    "Account is fixed at {account} by the pasted account-level key."
                ));
            }
            AccountControl::Unavailable => {
                self.notice = Notice::info(
                    "Account applies to seed phrases, master xprivs, and account-level keys only.",
                );
            }
        }
    }

    fn toggle_branch(&mut self) {
        self.branch = self.branch.toggle();
        self.notice = Notice::info(format!(
            "Showing {} addresses (…/{}/index).",
            self.branch.label(),
            self.branch.component()
        ));
    }

    fn move_selection(&mut self, delta: i64) {
        if self.context.is_err() {
            self.notice = Notice::warning("No addresses to browse for this source.");
            return;
        }
        let target = (i64::from(self.selected) + delta).clamp(0, i64::from(MAX_INDEX));
        self.select(u32::try_from(target).unwrap_or(MAX_INDEX));
    }

    fn select(&mut self, index: u32) {
        self.selected = index.min(MAX_INDEX);
        let window_end = self.window_start.saturating_add(WINDOW);
        if self.selected < self.window_start || self.selected >= window_end {
            self.window_start = self
                .selected
                .saturating_sub(WINDOW / 2)
                .min(MAX_INDEX - WINDOW + 1);
            self.rebuild_rows();
        }
        self.sync_selection();
    }

    fn rebuild(&mut self) {
        self.context = account_context(&self.source, self.network, self.account);
        self.rebuild_rows();
    }

    fn rebuild_rows(&mut self) {
        let rows = match &self.context {
            Ok(context) => derive_rows(context, self.window_start, WINDOW)
                .map_err(|error| format!("Address derivation failed: {error}")),
            Err(_) => Ok(Vec::new()),
        };
        self.rows = match rows {
            Ok(rows) => rows,
            Err(error) => {
                self.notice = Notice::error(error);
                Vec::new()
            }
        };
        self.sync_selection();
    }

    fn sync_selection(&mut self) {
        if self.rows.is_empty() {
            self.table_state.select(None);
            return;
        }
        let relative = usize::try_from(self.selected.saturating_sub(self.window_start))
            .unwrap_or(0)
            .min(self.rows.len() - 1);
        self.table_state.select(Some(relative));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::material::{SAMPLE_PASSPHRASE, SAMPLE_PHRASE};
    use easydoge_km::{account_xpriv_from_mnemonic, derive_path_from_xpub, Language};

    const PARITY_XPUB: &str = "dgub8s3rDipXzSGxH4XrwJA2sfJu83D89FWordpJq7uNJmHL87LAFR5Jm95er4g4Wa64yvNNY193By1pFiGMixHYZvyZiftVabMqWK7r1m4TSFC";
    const RECEIVE_0: &str = "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM";
    const CHANGE_0: &str = "DJC5m9hUngm7SzvMJb26FcFWC7Ew14eQxH";

    fn press(app: &mut App, code: KeyCode) {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn press_ctrl(app: &mut App, ch: char) {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL));
    }

    fn type_text(app: &mut App, text: &str) {
        for ch in text.chars() {
            press(app, KeyCode::Char(ch));
        }
    }

    fn sample_account_xpub(network: Network, account: u32) -> String {
        account_xpriv_from_mnemonic(
            SAMPLE_PHRASE,
            Some(SAMPLE_PASSPHRASE),
            Language::English,
            network,
            account,
        )
        .unwrap()
        .xpub
        .encoded
    }

    #[test]
    fn new_app_explores_the_sample_mnemonic_immediately() {
        let app = App::new();

        assert_eq!(app.mode, Mode::Explorer);
        assert_eq!(app.source, Source::Sample);
        assert_eq!(app.network, Network::Mainnet);
        assert_eq!(app.rows.len(), WINDOW as usize);
        assert_eq!(app.selected, 0);
        assert_eq!(app.table_state.selected(), Some(0));
        let row = app.selected_row().unwrap();
        assert_eq!(row.receive.path, "m/44'/3'/0'/0/0");
        assert_eq!(row.receive.address, RECEIVE_0);
        assert_eq!(row.change.path, "m/44'/3'/0'/1/0");
        assert_eq!(row.change.address, CHANGE_0);
        assert!(!app.reveal);
    }

    #[test]
    fn index_keys_move_the_selection() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.selected, 1);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.selected, 3);
        assert_eq!(app.selected_row().unwrap().receive.path, "m/44'/3'/0'/0/3");
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Char('p'));
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.selected, 0);
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.selected, 0, "index never goes below zero");

        app.viewport_rows = 20;
        press(&mut app, KeyCode::PageDown);
        assert_eq!(app.selected, 20);
        press(&mut app, KeyCode::Char('n'));
        press(&mut app, KeyCode::Home);
        assert_eq!(app.selected, 0);
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn jumping_far_away_re_centres_the_derived_window() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char(':'));
        assert_eq!(app.mode, Mode::Jump);
        type_text(&mut app, "1000");
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Explorer);
        assert_eq!(app.selected, 1000);
        assert_eq!(app.window_start, 1000 - WINDOW / 2);
        assert_eq!(app.rows.first().unwrap().index, app.window_start);
        assert_eq!(
            app.selected_row().unwrap().receive.path,
            "m/44'/3'/0'/0/1000"
        );
        assert_eq!(app.table_state.selected(), Some((WINDOW / 2) as usize));

        press(&mut app, KeyCode::PageUp);
        assert_eq!(app.selected, 999);
        assert!(app.selected_row().is_some());
    }

    #[test]
    fn jump_rejects_indices_outside_the_non_hardened_range() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char(':'));
        type_text(&mut app, "9999999999x");
        assert_eq!(app.jump, "9999999999");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Jump);
        assert!(app
            .input_error
            .as_deref()
            .unwrap()
            .contains("between 0 and"));

        press(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Explorer);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn account_keys_re_derive_rows() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.account, 1);
        let row = app.selected_row().unwrap();
        assert_eq!(row.receive.path, "m/44'/3'/1'/0/0");
        assert_ne!(row.receive.address, RECEIVE_0);

        press(&mut app, KeyCode::Char('z'));
        assert_eq!(app.account, 0);
        assert_eq!(app.selected_row().unwrap().receive.address, RECEIVE_0);

        press(&mut app, KeyCode::Char('z'));
        assert_eq!(app.account, 0);
        assert!(app.notice.text.contains("already 0"));
    }

    #[test]
    fn branch_keys_toggle_between_receive_and_change() {
        let mut app = App::new();
        assert_eq!(app.branch, Branch::Receive);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.branch, Branch::Change);
        press(&mut app, KeyCode::Left);
        assert_eq!(app.branch, Branch::Receive);
    }

    #[test]
    fn pasting_an_address_inspects_it_without_derivation() {
        let mut app = App::new();

        app.handle_paste(RECEIVE_0);

        assert_eq!(app.mode, Mode::Explorer);
        assert!(matches!(
            app.source,
            Source::Pasted(Material::Address { .. })
        ));
        assert!(app.rows.is_empty());
        assert!(app.selected_row().is_none());
        assert!(app.derivation_note().unwrap().contains("no keys"));
        assert!(app.notice.text.contains("Inspected pasted address"));

        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.notice.kind, NoticeKind::Warning);
    }

    #[test]
    fn pasting_a_seed_phrase_prompts_for_the_passphrase_then_derives() {
        let mut app = App::new();

        app.handle_paste(SAMPLE_PHRASE);
        assert_eq!(app.mode, Mode::Passphrase);
        assert!(app.pending.is_some());
        assert_eq!(
            app.source,
            Source::Sample,
            "source changes only after the passphrase"
        );
        assert!(
            app.input.is_empty(),
            "the phrase must not linger in the input buffer"
        );

        app.handle_paste(SAMPLE_PASSPHRASE);
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Explorer);
        assert!(app.pending.is_none());
        assert!(app.passphrase.is_empty());
        match &app.source {
            Source::Pasted(Material::SeedPhrase(seed)) => {
                assert_eq!(seed.passphrase.as_deref(), Some(SAMPLE_PASSPHRASE));
                assert_eq!(seed.word_count, 12);
            }
            other => panic!("expected a pasted seed phrase, got {other:?}"),
        }
        assert_eq!(app.selected_row().unwrap().receive.address, RECEIVE_0);
    }

    #[test]
    fn empty_passphrase_derives_a_different_wallet() {
        let mut app = App::new();

        app.handle_paste(SAMPLE_PHRASE);
        press(&mut app, KeyCode::Enter);

        match &app.source {
            Source::Pasted(Material::SeedPhrase(seed)) => assert_eq!(seed.passphrase, None),
            other => panic!("expected a pasted seed phrase, got {other:?}"),
        }
        assert_ne!(app.selected_row().unwrap().receive.address, RECEIVE_0);
    }

    #[test]
    fn cancelling_the_passphrase_keeps_the_previous_source() {
        let mut app = App::new();
        app.handle_paste(RECEIVE_0);

        app.handle_paste(SAMPLE_PHRASE);
        assert_eq!(app.mode, Mode::Passphrase);
        type_text(&mut app, "secret");
        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::Explorer);
        assert!(app.pending.is_none());
        assert!(app.passphrase.is_empty());
        assert!(matches!(
            app.source,
            Source::Pasted(Material::Address { .. })
        ));
        assert_eq!(app.notice.text, "Input cancelled.");
    }

    #[test]
    fn invalid_seed_phrase_keeps_the_inspector_open_with_the_reason() {
        let mut app = App::new();
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        app.handle_paste(invalid);

        assert_eq!(app.mode, Mode::Inspect);
        assert_eq!(app.input, invalid);
        assert!(app
            .input_error
            .as_deref()
            .unwrap()
            .contains("not a valid BIP39 mnemonic"));
        assert_eq!(app.source, Source::Sample);
    }

    #[test]
    fn unclassified_paste_keeps_the_input_editable() {
        let mut app = App::new();

        app.handle_paste("not wallet material");
        assert_eq!(app.mode, Mode::Inspect);
        assert_eq!(app.input, "not wallet material");
        assert!(app
            .input_error
            .as_deref()
            .unwrap()
            .contains("Could not classify"));

        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.input, "not wallet materia");
        assert!(app.input_error.is_none());

        press_ctrl(&mut app, 'u');
        assert!(app.input.is_empty());

        press(&mut app, KeyCode::Enter);
        assert!(app
            .input_error
            .as_deref()
            .unwrap()
            .contains("before inspecting"));
    }

    #[test]
    fn typed_input_is_buffered_until_enter() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('/'));
        assert_eq!(app.mode, Mode::Inspect);
        type_text(&mut app, "q");
        assert!(!app.should_quit, "q is text inside the inspector");
        press(&mut app, KeyCode::Backspace);
        type_text(&mut app, RECEIVE_0);
        assert_eq!(app.source, Source::Sample);
        press(&mut app, KeyCode::Enter);

        assert!(matches!(
            app.source,
            Source::Pasted(Material::Address { .. })
        ));
        assert!(app.input.is_empty());
    }

    #[test]
    fn pasted_account_xpub_derives_watch_only_rows_with_relative_paths() {
        let mut app = App::new();

        app.handle_paste(PARITY_XPUB);

        assert_eq!(app.mode, Mode::Explorer);
        assert!(matches!(app.source, Source::Pasted(Material::Xpub { .. })));
        let row = app.selected_row().unwrap();
        assert_eq!(row.receive.path, "m/0/0");
        assert_eq!(row.receive.address, RECEIVE_0);
        assert_eq!(row.change.path, "m/1/0");

        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.selected, 1);
        assert_eq!(app.selected_row().unwrap().receive.path, "m/0/1");
    }

    #[test]
    fn account_level_xpub_fixes_the_account_number() {
        let mut app = App::new();

        app.handle_paste(&sample_account_xpub(Network::Mainnet, 7));

        assert_eq!(app.account, 7);
        assert!(app.selected_row().is_some());
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.account, 7);
        assert!(app.notice.text.contains("fixed at 7"));
    }

    #[test]
    fn branch_level_xpub_inspects_without_misleading_rows() {
        let context = account_context(&Source::Sample, Network::Mainnet, 0).unwrap();
        let branch_xpub = derive_path_from_xpub(&context.xpub, "m/0").unwrap();
        let mut app = App::new();

        app.handle_paste(&branch_xpub.encoded);

        assert!(matches!(app.source, Source::Pasted(Material::Xpub { .. })));
        assert!(app.rows.is_empty());
        assert!(app
            .derivation_note()
            .unwrap()
            .contains("account-level xpub"));
        assert!(app.notice.text.contains("No address derivation"));
        press(&mut app, KeyCode::Char('a'));
        assert!(app.notice.text.contains("account-level keys only"));
    }

    #[test]
    fn network_key_cycles_seed_phrase_sources_through_every_network() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.network, Network::Testnet);
        let testnet_address = app.selected_row().unwrap().receive.address.clone();
        assert!(testnet_address.starts_with('n'), "{testnet_address}");

        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.network, Network::Regtest);
        assert_ne!(app.selected_row().unwrap().receive.address, testnet_address);

        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.network, Network::Mainnet);
        assert_eq!(app.selected_row().unwrap().receive.address, RECEIVE_0);
    }

    #[test]
    fn network_is_fixed_by_a_dogecoin_mainnet_xpub() {
        let mut app = App::new();
        app.handle_paste(PARITY_XPUB);

        press(&mut app, KeyCode::Char('t'));

        assert_eq!(app.network, Network::Mainnet);
        assert!(app.notice.text.contains("fixed to mainnet"));
    }

    #[test]
    fn testnet_xpub_can_be_reinterpreted_as_regtest_and_back() {
        let mut app = App::new();
        app.handle_paste(&sample_account_xpub(Network::Testnet, 0));
        assert_eq!(app.network, Network::Testnet);
        let testnet_address = app.selected_row().unwrap().receive.address.clone();

        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.network, Network::Regtest);
        assert!(matches!(
            &app.source,
            Source::Pasted(Material::Xpub { xpub, info })
                if xpub.network == Network::Regtest && info.network == Network::Regtest
        ));
        assert_ne!(app.selected_row().unwrap().receive.address, testnet_address);

        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.network, Network::Testnet);
        assert_eq!(app.selected_row().unwrap().receive.address, testnet_address);
    }

    #[test]
    fn generate_then_clear_returns_to_the_sample_mnemonic() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('g'));
        match &app.source {
            Source::Generated(seed) => {
                assert_eq!(seed.word_count, 24);
                assert_eq!(seed.passphrase, None);
            }
            other => panic!("expected a generated mnemonic, got {other:?}"),
        }
        assert_ne!(app.selected_row().unwrap().receive.address, RECEIVE_0);
        assert!(app.notice.text.contains("24-word"));

        press(&mut app, KeyCode::Char('x'));
        assert_eq!(app.source, Source::Sample);
        assert_eq!(app.selected_row().unwrap().receive.address, RECEIVE_0);

        press(&mut app, KeyCode::Char('x'));
        assert!(app.notice.text.contains("Already"));
    }

    #[test]
    fn reveal_toggles_and_escape_hides_secrets_instead_of_quitting() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('r'));
        assert!(app.reveal);
        assert_eq!(app.notice.kind, NoticeKind::Warning);

        press(&mut app, KeyCode::Esc);
        assert!(!app.reveal);
        assert!(!app.should_quit);
        assert_eq!(app.notice.text, "Secrets hidden.");

        press(&mut app, KeyCode::Esc);
        assert!(!app.should_quit);
        assert!(app.notice.text.contains("q to quit"));

        press(&mut app, KeyCode::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_c_quits_from_every_mode() {
        for open in [KeyCode::Char('/'), KeyCode::Char(':'), KeyCode::Char('?')] {
            let mut app = App::new();
            press(&mut app, open);
            assert_ne!(app.mode, Mode::Explorer);
            press_ctrl(&mut app, 'c');
            assert!(app.should_quit, "Ctrl+C should quit after {open:?}");
        }
    }

    #[test]
    fn help_overlay_toggles() {
        let mut app = App::new();

        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.mode, Mode::Help);
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(
            app.selected, 0,
            "explorer keys are inert under the help overlay"
        );
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.mode, Mode::Explorer);

        press(&mut app, KeyCode::Char('?'));
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Explorer);
    }
}
