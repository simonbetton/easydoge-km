//! Rendering for the TUI explorer.
//!
//! Layout, top to bottom: a one-row title bar, the workspace, a status row,
//! and a row of context-sensitive key hints. The workspace puts the source
//! panel beside the address table on terminals at least 80 columns wide and
//! stacks them on narrower ones. Modal popups draw over the workspace.

use easydoge_km::ExtendedKeyInfo;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use super::app::{App, Mode, NoticeKind};
use super::material::{
    address_kind_label, child_number_label, language_label, AccountControl, Branch, DerivedAddress,
    Material, SeedPhrase, Source, MAX_INDEX,
};
use super::theme;

pub const MIN_WIDTH: u16 = 40;
pub const MIN_HEIGHT: u16 = 10;
const TWO_COLUMN_MIN_WIDTH: u16 = 80;
const ADDRESS_WIDTH: u16 = 34;
const LABEL_WIDTH: usize = 12;
const DETAIL_LABEL_WIDTH: usize = 8;
/// Source panels shorter than this skip explanatory notes.
const COMPACT_SOURCE_HEIGHT: u16 = 12;
const REDACTED: &str = "[redacted]";

pub fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let [title, body, status, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

    render_title(frame, title, app);
    render_body(frame, body, app);
    render_status(frame, status, app);
    render_hints(frame, hints, app);

    match app.mode {
        Mode::Explorer => {}
        Mode::Inspect => render_inspect_popup(frame, area, app),
        Mode::Passphrase => render_passphrase_popup(frame, area, app),
        Mode::Jump => render_jump_popup(frame, area, app),
        Mode::Help => render_help(frame, area),
    }
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled("Terminal too small", theme::title())).centered(),
        Line::from(Span::styled(
            format!("Resize to at least {MIN_WIDTH}x{MIN_HEIGHT}."),
            theme::muted(),
        ))
        .centered(),
    ];
    let target = area.centered(Constraint::Percentage(100), Constraint::Length(2));
    frame.render_widget(Paragraph::new(lines), target);
}

fn render_title(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let reveal = if app.reveal {
        Span::styled(" reveal on ", theme::reveal_badge())
    } else {
        Span::styled(" redacted ", theme::badge())
    };
    let right = Line::from(vec![
        Span::styled(format!(" {} ", app.network), theme::network(app.network)),
        Span::raw(" "),
        reveal,
        Span::raw(" "),
    ]);
    let right_width = u16::try_from(right.width()).unwrap_or(u16::MAX);
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(right_width)]).areas(area);
    let brand = " Ð EasyDoge KM ";
    let tagline = "  Dogecoin key management";
    let mut left = vec![Span::styled(brand, theme::brand())];
    if usize::from(left_area.width) >= brand.chars().count() + tagline.chars().count() {
        left.push(Span::styled(tagline, theme::muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(left)), left_area);
    frame.render_widget(Paragraph::new(right), right_area);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    if area.width >= TWO_COLUMN_MIN_WIDTH {
        let left_width = (u32::from(area.width) * 36 / 100).clamp(34, 52);
        let left_width = u16::try_from(left_width).unwrap_or(34);
        let [left, right] =
            Layout::horizontal([Constraint::Length(left_width), Constraint::Fill(1)]).areas(area);
        render_source(frame, left, app);
        render_addresses(frame, right, app, true);
    } else {
        let source_height = (u32::from(area.height) * 45 / 100).max(6);
        let source_height = u16::try_from(source_height).unwrap_or(6);
        let [top, bottom] =
            Layout::vertical([Constraint::Length(source_height), Constraint::Fill(1)]).areas(area);
        render_source(frame, top, app);
        render_addresses(frame, bottom, app, false);
    }
}

fn render_source(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Span::styled(" Source ", theme::title()))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    let lines = source_lines(app, inner.width, inner.height < COMPACT_SOURCE_HEIGHT);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// Lines for the source panel. `compact` drops notes and spacing so short
/// panels spend their rows on data.
fn source_lines(app: &App, width: u16, compact: bool) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &app.source {
        Source::Sample => {
            push_heading(&mut lines, "Sample mnemonic");
            push_note(
                &mut lines,
                "Public parity vector from test-vectors/parity.json. Never fund its addresses.",
                compact,
            );
            push_gap(&mut lines, compact);
            push_seed_lines(&mut lines, &SeedPhrase::sample(), app.reveal, width);
            push_gap(&mut lines, compact);
            push_account_lines(&mut lines, app, width);
        }
        Source::Generated(seed) => {
            push_heading(&mut lines, "Generated mnemonic");
            push_note(
                &mut lines,
                "Exists only in this session. Reveal it with r and back it up before relying on it.",
                compact,
            );
            push_gap(&mut lines, compact);
            push_seed_lines(&mut lines, seed, app.reveal, width);
            push_gap(&mut lines, compact);
            push_account_lines(&mut lines, app, width);
        }
        Source::Pasted(Material::SeedPhrase(seed)) => {
            push_heading(&mut lines, "Pasted seed phrase");
            push_note(&mut lines, "Valid BIP39 checksum.", compact);
            push_gap(&mut lines, compact);
            push_seed_lines(&mut lines, seed, app.reveal, width);
            push_gap(&mut lines, compact);
            push_account_lines(&mut lines, app, width);
        }
        Source::Pasted(Material::Xpriv { info, xpub, .. }) => {
            push_heading(&mut lines, "Extended private key");
            push_note(&mut lines, "Private key material is never echoed.", compact);
            push_key_lines(&mut lines, info, width);
            push_account_lines(&mut lines, app, width);
            push_field(&mut lines, "xpriv", REDACTED, theme::redacted(), width);
            if let Some(public_key_hex) = &info.public_key_hex {
                push_field(
                    &mut lines,
                    "public key",
                    public_key_hex,
                    theme::public(),
                    width,
                );
            }
            push_field(&mut lines, "xpub", &xpub.encoded, theme::public(), width);
        }
        Source::Pasted(Material::Xpub { xpub, info }) => {
            push_heading(&mut lines, "Extended public key");
            push_gap(&mut lines, compact);
            push_key_lines(&mut lines, info, width);
            push_account_lines(&mut lines, app, width);
            if let Some(public_key_hex) = &info.public_key_hex {
                push_field(
                    &mut lines,
                    "public key",
                    public_key_hex,
                    theme::public(),
                    width,
                );
            }
            push_field(&mut lines, "xpub", &xpub.encoded, theme::public(), width);
        }
        Source::Pasted(Material::Address { address, matches }) => {
            push_heading(&mut lines, "Address");
            push_note(
                &mut lines,
                "Every Dogecoin network whose prefix matches is listed.",
                compact,
            );
            push_gap(&mut lines, compact);
            push_field(&mut lines, "address", address, theme::public(), width);
            for info in matches {
                push_field(
                    &mut lines,
                    "network",
                    &format!("{} · {}", info.network, address_kind_label(info.kind)),
                    theme::value(),
                    width,
                );
            }
            if let Some(info) = matches.first() {
                push_field(
                    &mut lines,
                    "payload",
                    &info.payload_hex,
                    theme::public(),
                    width,
                );
            }
        }
        Source::Pasted(Material::Wif { info }) => {
            push_heading(&mut lines, "WIF private key");
            push_note(&mut lines, "Private key material is never echoed.", compact);
            push_gap(&mut lines, compact);
            push_field(
                &mut lines,
                "network",
                &info.network.to_string(),
                theme::value(),
                width,
            );
            push_field(
                &mut lines,
                "compressed",
                if info.compressed { "yes" } else { "no" },
                theme::value(),
                width,
            );
            push_field(&mut lines, "wif", REDACTED, theme::redacted(), width);
            push_field(
                &mut lines,
                "public key",
                &info.public_key_hex,
                theme::public(),
                width,
            );
            push_field(&mut lines, "address", &info.address, theme::public(), width);
        }
    }
    lines
}

fn push_seed_lines(lines: &mut Vec<Line<'static>>, seed: &SeedPhrase, reveal: bool, width: u16) {
    push_field(
        lines,
        "words",
        &format!("{} · {}", seed.word_count, language_label(seed.language)),
        theme::value(),
        width,
    );
    let (passphrase, style) = match (&seed.passphrase, reveal) {
        (None, _) => ("none".to_owned(), theme::muted()),
        (Some(_), false) => (REDACTED.to_owned(), theme::redacted()),
        (Some(passphrase), true) => (passphrase.clone(), theme::secret()),
    };
    push_field(lines, "passphrase", &passphrase, style, width);
    if reveal {
        lines.push(Line::from(Span::styled(
            format!("{:<LABEL_WIDTH$}", "phrase"),
            theme::muted(),
        )));
        push_phrase_grid(lines, &seed.words(), width);
    } else {
        push_field(
            lines,
            "phrase",
            "[redacted] press r",
            theme::redacted(),
            width,
        );
    }
}

fn push_phrase_grid(lines: &mut Vec<Line<'static>>, words: &[&str], width: u16) {
    let columns = (usize::from(width) / 14).clamp(1, 4);
    for (row, chunk) in words.chunks(columns).enumerate() {
        let mut spans = Vec::with_capacity(chunk.len() * 2);
        for (column, word) in chunk.iter().enumerate() {
            let number = row * columns + column + 1;
            spans.push(Span::styled(format!("{number:>2} "), theme::muted()));
            spans.push(Span::styled(format!("{word:<11}"), theme::secret()));
        }
        lines.push(Line::from(spans));
    }
}

fn push_key_lines(lines: &mut Vec<Line<'static>>, info: &ExtendedKeyInfo, width: u16) {
    push_field(
        lines,
        "network",
        &info.network.to_string(),
        theme::value(),
        width,
    );
    push_field(
        lines,
        "depth",
        &depth_label(info.depth),
        theme::value(),
        width,
    );
    push_field(
        lines,
        "child",
        &child_number_label(info.child_number),
        theme::value(),
        width,
    );
    push_field(
        lines,
        "fingerprint",
        &info.parent_fingerprint_hex,
        theme::value(),
        width,
    );
}

fn depth_label(depth: u8) -> String {
    match depth {
        0 => "0 · master".to_owned(),
        3 => "3 · account".to_owned(),
        other => other.to_string(),
    }
}

/// Account number, derivation paths, and (for absolute paths) the account
/// xpub. Sources without an account context add nothing.
fn push_account_lines(lines: &mut Vec<Line<'static>>, app: &App, width: u16) {
    let Ok(context) = &app.context else {
        return;
    };
    let account = match app.source.account_control() {
        AccountControl::Fixed(_) => format!("{} · fixed by key", app.account),
        AccountControl::Free | AccountControl::Unavailable => app.account.to_string(),
    };
    push_field(lines, "account", &account, theme::value(), width);
    if context.is_relative() {
        push_field(lines, "paths", "m/0/i · m/1/i", theme::value(), width);
    } else {
        push_field(lines, "path", &context.path_prefix, theme::value(), width);
        push_field(
            lines,
            "account xpub",
            &context.xpub.encoded,
            theme::public(),
            width,
        );
    }
}

fn push_heading(lines: &mut Vec<Line<'static>>, text: &'static str) {
    lines.push(Line::from(Span::styled(text, theme::title())));
}

fn push_note(lines: &mut Vec<Line<'static>>, text: &'static str, compact: bool) {
    if !compact {
        lines.push(Line::from(Span::styled(text, theme::muted())));
    }
}

fn push_gap(lines: &mut Vec<Line<'static>>, compact: bool) {
    if !compact {
        lines.push(Line::default());
    }
}

/// Push `label value` on one row, or on two rows when the value would wrap.
fn push_field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, style: Style, width: u16) {
    push_labelled(lines, label, LABEL_WIDTH, value, style, width);
}

fn push_labelled(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    label_width: usize,
    value: &str,
    style: Style,
    width: u16,
) {
    let label_span = Span::styled(format!("{label:<label_width$}"), theme::muted());
    if label_width + value.chars().count() <= usize::from(width) {
        lines.push(Line::from(vec![
            label_span,
            Span::styled(value.to_owned(), style),
        ]));
    } else {
        lines.push(Line::from(label_span));
        lines.push(Line::from(Span::styled(value.to_owned(), style)));
    }
}

/// Rows [`push_labelled`] needs for a value at the given inner width.
fn labelled_rows(label_width: usize, value: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let len = value.chars().count();
    if label_width + len <= width {
        1
    } else {
        1 + u16::try_from(len.div_ceil(width)).unwrap_or(u16::MAX)
    }
}

fn render_addresses(frame: &mut Frame<'_>, area: Rect, app: &mut App, with_detail: bool) {
    if let Some(note) = app.derivation_note() {
        let note = note.to_owned();
        render_no_addresses(frame, area, &note);
        app.viewport_rows = 1;
        return;
    }

    let detail_height = if with_detail {
        app.selected_row().map_or(0, |row| {
            detail_height(row.branch(app.branch), area.width.saturating_sub(4))
        })
    } else {
        0
    };
    let detail_height = detail_height.min(area.height / 2);
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(detail_height)]).areas(area);
    render_table(frame, table_area, app);
    if detail_height > 0 {
        render_detail(frame, detail_area, app);
    }
}

fn render_no_addresses(frame: &mut Frame<'_>, area: Rect, note: &str) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Span::styled(" Addresses ", theme::title()))
        .padding(Padding::horizontal(1));
    let lines = vec![
        Line::from(Span::styled(note.to_owned(), theme::warn())),
        Line::default(),
        Line::from(Span::styled(
            "Paste an xpub, xpriv, or seed phrase with /, or press x to return to the sample mnemonic.",
            theme::muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn render_table(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let Ok(context) = &app.context else {
        return;
    };
    let prefix = context.path_prefix.clone();
    let branch = app.branch;
    let last_index = app.rows.last().map_or(app.selected, |row| row.index);
    let index_width = digits(last_index).max(3);

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border_active())
        .title(Line::from(vec![
            Span::styled(" Addresses ", theme::title()),
            Span::styled(format!(" account {} ", app.account), theme::muted()),
        ]))
        .title_bottom(
            Line::from(Span::styled(
                format!(" index {} · {} ", app.selected, branch.label()),
                theme::muted(),
            ))
            .right_aligned(),
        );
    let inner = block.inner(area);
    let both = inner.width >= 1 + index_width + 1 + ADDRESS_WIDTH + 1 + ADDRESS_WIDTH;

    let header_cell = |column: Branch| {
        let style = if column == branch {
            theme::title()
        } else {
            theme::muted()
        };
        Cell::from(Span::styled(
            format!("{}  {}/{}/i", column.label(), prefix, column.component()),
            style,
        ))
    };
    let mut header = vec![Cell::from(Span::styled("#", theme::muted()))];
    let mut widths = vec![Constraint::Length(index_width)];
    if both {
        header.push(header_cell(Branch::Receive));
        header.push(header_cell(Branch::Change));
        widths.push(Constraint::Length(ADDRESS_WIDTH));
        widths.push(Constraint::Length(ADDRESS_WIDTH));
    } else {
        header.push(header_cell(branch));
        widths.push(Constraint::Fill(1));
    }

    let rows: Vec<Row<'static>> = app
        .rows
        .iter()
        .map(|row| {
            let mut cells = vec![Cell::from(Span::styled(
                format!("{:>width$}", row.index, width = usize::from(index_width)),
                theme::muted(),
            ))];
            if both {
                cells.push(address_cell(&row.receive));
                cells.push(address_cell(&row.change));
            } else {
                cells.push(address_cell(row.branch(branch)));
            }
            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(Row::new(header))
        .block(block)
        .column_spacing(1)
        .row_highlight_style(theme::selected())
        .highlight_symbol("▸")
        .highlight_spacing(HighlightSpacing::Always);

    app.viewport_rows = inner.height.saturating_sub(1).max(1);
    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn address_cell(derived: &DerivedAddress) -> Cell<'static> {
    Cell::from(Span::styled(derived.address.clone(), theme::public()))
}

fn digits(value: u32) -> u16 {
    value.checked_ilog10().map_or(1, |magnitude| {
        u16::try_from(magnitude).unwrap_or(u16::MAX) + 1
    })
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(row) = app.selected_row() else {
        return;
    };
    let derived = row.branch(app.branch);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Line::from(vec![
            Span::styled(" Selected ", theme::title()),
            Span::styled(
                format!(" {} · index {} ", app.branch.label(), row.index),
                theme::muted(),
            ),
        ]))
        .padding(Padding::horizontal(1));
    let width = block.inner(area).width;
    let mut lines = Vec::new();
    for (label, value, style) in [
        ("path", &derived.path, theme::value()),
        ("address", &derived.address, theme::public()),
        ("pubkey", &derived.public_key_hex, theme::public()),
    ] {
        push_labelled(&mut lines, label, DETAIL_LABEL_WIDTH, value, style, width);
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn detail_height(derived: &DerivedAddress, width: u16) -> u16 {
    [&derived.path, &derived.address, &derived.public_key_hex]
        .into_iter()
        .map(|value| labelled_rows(DETAIL_LABEL_WIDTH, value, width))
        .sum::<u16>()
        + 2
}

fn render_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let (glyph, style) = match app.notice.kind {
        NoticeKind::Info => ("·", theme::muted()),
        NoticeKind::Success => ("✓", theme::ok()),
        NoticeKind::Warning => ("!", theme::warn()),
        NoticeKind::Error => ("✗", theme::error()),
    };
    let text_style = match app.notice.kind {
        NoticeKind::Info => Style::default(),
        NoticeKind::Success | NoticeKind::Warning | NoticeKind::Error => style,
    };
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, style),
        Span::raw(" "),
        Span::styled(app.notice.text.clone(), text_style),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

struct Hint {
    key: &'static str,
    label: &'static str,
    /// Lower numbers survive longer when the bar runs out of room.
    priority: u8,
}

const fn hint(key: &'static str, label: &'static str, priority: u8) -> Hint {
    Hint {
        key,
        label,
        priority,
    }
}

fn hints_for(app: &App) -> Vec<Hint> {
    match app.mode {
        Mode::Explorer => vec![
            hint("/", "paste", 1),
            hint("g", "generate", 2),
            hint("r", if app.reveal { "hide" } else { "reveal" }, 2),
            hint("t", "network", 4),
            hint("↑↓", "index", 3),
            hint("Tab", "branch", 3),
            hint("a/z", "account", 4),
            hint(":", "go to", 5),
            hint("x", "clear", 5),
            hint("?", "help", 0),
            hint("q", "quit", 0),
        ],
        Mode::Inspect => vec![
            hint("Enter", "inspect", 0),
            hint("Bksp", "delete", 1),
            hint("^U", "clear", 1),
            hint("Esc", "cancel", 0),
        ],
        Mode::Passphrase => vec![
            hint("Enter", "continue", 0),
            hint("Bksp", "delete", 1),
            hint("^U", "clear", 1),
            hint("Esc", "cancel", 0),
        ],
        Mode::Jump => vec![hint("Enter", "go", 0), hint("Esc", "cancel", 0)],
        Mode::Help => vec![hint("Esc", "close", 0)],
    }
}

fn hints_width(hints: &[Hint]) -> usize {
    1 + hints
        .iter()
        .map(|hint| hint.key.chars().count() + hint.label.chars().count() + 3)
        .sum::<usize>()
}

fn render_hints(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut hints = hints_for(app);
    let width = usize::from(area.width);
    while hints_width(&hints) > width && hints.len() > 1 {
        let Some((drop_at, _)) = hints
            .iter()
            .enumerate()
            .max_by_key(|(_, hint)| hint.priority)
        else {
            break;
        };
        hints.remove(drop_at);
    }
    let mut spans = vec![Span::raw(" ")];
    for hint in &hints {
        spans.push(Span::styled(hint.key, theme::key()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint.label, theme::muted()));
        spans.push(Span::raw("  "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    area.centered(
        Constraint::Length(width.min(area.width)),
        Constraint::Length(height.min(area.height)),
    )
}

const POPUP_WIDTH: u16 = 72;
const POPUP_HEIGHT: u16 = 9;

struct InputPopup<'a> {
    title: &'a str,
    prompt: String,
    /// Field text as it should appear, already masked where needed.
    field: String,
    meta: String,
    error: Option<&'a str>,
    note: &'a str,
}

fn render_input_popup(frame: &mut Frame<'_>, area: Rect, popup: &InputPopup<'_>) {
    let popup_area = centered(area, POPUP_WIDTH, POPUP_HEIGHT);
    frame.render_widget(Clear, popup_area);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border_active())
        .title(Span::styled(format!(" {} ", popup.title), theme::title()))
        .padding(Padding::horizontal(1));
    let inner = block.inner(popup_area);
    let error_line = match popup.error {
        Some(error) => Line::from(vec![
            Span::styled("✗ ", theme::error()),
            Span::styled(error.to_owned(), theme::error()),
        ]),
        None => Line::default(),
    };
    let lines = vec![
        Line::from(Span::raw(popup.prompt.clone())),
        Line::default(),
        Line::from(Span::styled(popup.field.clone(), theme::value())),
        Line::from(Span::styled(popup.meta.clone(), theme::muted())),
        error_line,
        Line::from(Span::styled(popup.note.to_owned(), theme::muted())),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        popup_area,
    );

    let inner_width = usize::from(inner.width.max(1));
    let prompt_rows = popup.prompt.chars().count().div_ceil(inner_width).max(1);
    let field_width = popup.field.chars().count();
    let x = inner.x
        + u16::try_from(field_width)
            .unwrap_or(u16::MAX)
            .min(inner.width.saturating_sub(1));
    let y = inner.y + u16::try_from(prompt_rows).unwrap_or(u16::MAX) + 1;
    if y < inner.bottom() {
        frame.set_cursor_position(Position::new(x, y));
    }
}

/// Field width available inside the input popup at this terminal size.
fn popup_field_width(area: Rect) -> u16 {
    centered(area, POPUP_WIDTH, POPUP_HEIGHT)
        .width
        .saturating_sub(4)
}

fn masked_field(len: usize, width: u16) -> String {
    let capacity = usize::from(width.saturating_sub(4)).max(1);
    if len > capacity {
        format!("› …{}", "•".repeat(capacity - 1))
    } else {
        format!("› {}", "•".repeat(len))
    }
}

fn render_inspect_popup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chars = app.input.chars().count();
    let words = app.input.split_whitespace().count();
    let popup = InputPopup {
        title: "Inspect material",
        prompt: "Paste or type an address, seed phrase, xpriv, xpub, or WIF.".to_owned(),
        field: masked_field(chars, popup_field_width(area)),
        meta: format!("{chars} chars · {words} words"),
        error: app.input_error.as_deref(),
        note: "Input stays masked because it may be secret.",
    };
    render_input_popup(frame, area, &popup);
}

fn render_passphrase_popup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let detected = app.pending.as_ref().map_or_else(
        || "Seed phrase detected.".to_owned(),
        |seed| {
            format!(
                "Seed phrase detected: {} words · {}.",
                seed.word_count,
                language_label(seed.language)
            )
        },
    );
    let chars = app.passphrase.chars().count();
    let popup = InputPopup {
        title: "BIP39 passphrase",
        prompt: format!("{detected} Type the optional passphrase, or press Enter for none."),
        field: masked_field(chars, popup_field_width(area)),
        meta: format!("{chars} chars"),
        error: None,
        note: "The passphrase changes every derived key. It stays masked.",
    };
    render_input_popup(frame, area, &popup);
}

fn render_jump_popup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let popup = InputPopup {
        title: "Go to index",
        prompt: "Type an address index for the current account.".to_owned(),
        field: format!("› {}", app.jump),
        meta: format!("0 to {MAX_INDEX}"),
        error: app.input_error.as_deref(),
        note: "Both receive and change addresses move to this index.",
    };
    render_input_popup(frame, area, &popup);
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let popup = centered(area, 78, 26);
    frame.render_widget(Clear, popup);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border_active())
        .title(Span::styled(" Keys ", theme::title()))
        .title_bottom(
            Line::from(Span::styled(
                format!(" easydoge-km {} · Esc closes ", env!("CARGO_PKG_VERSION")),
                theme::muted(),
            ))
            .right_aligned(),
        )
        .padding(Padding::horizontal(1));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let keys = Paragraph::new(help_key_lines());
    if inner.width >= 70 {
        let [left, right] =
            Layout::horizontal([Constraint::Length(45), Constraint::Fill(1)]).areas(inner);
        frame.render_widget(keys, left);
        frame.render_widget(
            Paragraph::new(help_note_lines()).wrap(Wrap { trim: false }),
            right,
        );
    } else {
        frame.render_widget(keys, inner);
    }
}

fn help_key_lines() -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut section = |title: &'static str, entries: &[(&'static str, &'static str)]| {
        if !lines.is_empty() {
            lines.push(Line::default());
        }
        lines.push(Line::from(Span::styled(title, theme::title())));
        for (keys, action) in entries {
            lines.push(Line::from(vec![
                Span::styled(format!("  {keys:<13} "), theme::key()),
                Span::raw(*action),
            ]));
        }
    };
    section(
        "Navigation",
        &[
            ("↑ ↓  j k  n p", "move the address index"),
            ("PgUp PgDn", "move a page"),
            ("Home", "back to index 0"),
            (":", "go to an index"),
            ("Tab ← →", "receive / change"),
            ("a  z", "account + / -"),
        ],
    );
    section(
        "Material",
        &[
            ("/", "paste or type material"),
            ("g", "generate a 24-word mnemonic"),
            ("x", "back to the sample mnemonic"),
            ("t", "mainnet / testnet / regtest"),
            ("r", "reveal or hide secrets"),
        ],
    );
    section(
        "Session",
        &[
            ("?", "toggle this help"),
            ("Esc", "close popups, hide secrets"),
            ("q  Ctrl+C", "quit"),
        ],
    );
    lines
}

fn help_note_lines() -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled("Safety", theme::title()))];
    for note in [
        "Secrets stay redacted until you press r.",
        "Pasted xprivs and WIFs are never echoed back.",
        "The sample mnemonic is public test material. Never fund its addresses.",
        "Addresses derive from the account xpub at m/44'/3'/account'.",
    ] {
        lines.push(Line::from(vec![
            Span::styled("• ", theme::muted()),
            Span::raw(note),
        ]));
    }
    lines.push(Line::default());
    for art in [
        " / \\__",
        "(    @\\___",
        " /         O",
        "/   (_____/",
        "/_____/   U",
    ] {
        lines.push(Line::from(Span::styled(art, theme::title())));
    }
    lines.push(Line::from(Span::styled(
        "Such keys. Very custody.",
        theme::muted(),
    )));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::material::{SAMPLE_PASSPHRASE, SAMPLE_PHRASE};
    use anyhow::Result;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;
    use ratatui::Terminal;

    const PARITY_XPUB: &str = "dgub8s3rDipXzSGxH4XrwJA2sfJu83D89FWordpJq7uNJmHL87LAFR5Jm95er4g4Wa64yvNNY193By1pFiGMixHYZvyZiftVabMqWK7r1m4TSFC";
    const RECEIVE_0: &str = "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM";
    const CHANGE_0: &str = "DJC5m9hUngm7SzvMJb26FcFWC7Ew14eQxH";

    fn press(app: &mut App, code: KeyCode) {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn draw(app: &mut App, width: u16, height: u16) -> Result<Buffer> {
        let mut terminal = Terminal::new(TestBackend::new(width, height))?;
        terminal.draw(|frame| render(frame, app))?;
        Ok(terminal.backend().buffer().clone())
    }

    fn lines(buffer: &Buffer) -> Vec<String> {
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn text(buffer: &Buffer) -> String {
        lines(buffer).join("\n")
    }

    /// Foreground and background of the first cell where `needle` appears.
    fn colors_at(buffer: &Buffer, needle: &str) -> (Color, Color) {
        for (y, line) in lines(buffer).iter().enumerate() {
            if let Some(byte_x) = line.find(needle) {
                let x = line[..byte_x].chars().count();
                let cell = &buffer[(x as u16, y as u16)];
                return (cell.fg, cell.bg);
            }
        }
        panic!("{needle} should render");
    }

    #[test]
    fn explorer_at_80x24_shows_source_live_addresses_and_hints() -> Result<()> {
        let mut app = App::new();
        let buffer = draw(&mut app, 80, 24)?;
        let rendered = text(&buffer);

        assert!(rendered.contains("EasyDoge KM"));
        assert!(rendered.contains("mainnet"));
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("Sample mnemonic"));
        assert!(rendered.contains("Addresses"));
        assert!(rendered.contains("account 0"));
        assert!(rendered.contains("receive  m/44'/3'/0'/0/i"));
        assert!(rendered.contains(RECEIVE_0));
        assert!(!rendered.contains(CHANGE_0), "80 columns fit one branch");
        assert!(rendered.contains("path    m/44'/3'/0'/0/0"));
        assert!(rendered.contains("pubkey"));
        assert!(rendered.contains("? help"));
        assert!(rendered.contains("q quit"));
        assert!(
            !rendered.contains("x clear"),
            "low-priority hints drop first"
        );

        let (fg, bg) = colors_at(&buffer, "EasyDoge KM");
        assert_eq!((fg, bg), (Color::Black, theme::ACCENT));
        assert_eq!(
            colors_at(&buffer, RECEIVE_0).1,
            theme::ACCENT,
            "selected row"
        );
        assert_ne!(
            colors_at(&buffer, "Never fund").0,
            Color::DarkGray,
            "notes use the terminal foreground, not bright black"
        );
        Ok(())
    }

    #[test]
    fn wide_terminal_shows_receive_and_change_columns_and_every_hint() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('n'));
        let buffer = draw(&mut app, 140, 40)?;
        let rendered = text(&buffer);

        assert!(rendered.contains("receive  m/44'/3'/0'/0/i"));
        assert!(rendered.contains("change  m/44'/3'/0'/1/i"));
        assert!(rendered.contains(RECEIVE_0));
        assert!(rendered.contains(CHANGE_0));
        assert!(rendered.contains("index 1 · receive"));
        assert!(rendered.contains("x clear"));
        assert!(rendered.contains("t network"));
        assert_ne!(colors_at(&buffer, RECEIVE_0).1, theme::ACCENT);
        Ok(())
    }

    #[test]
    fn long_values_wrap_so_they_can_be_copied() -> Result<()> {
        let mut app = App::new();
        let buffer = draw(&mut app, 80, 24)?;
        let rows = lines(&buffer);

        let label_row = rows
            .iter()
            .position(|row| row.contains("account xpub"))
            .expect("account xpub label renders");
        let head = &PARITY_XPUB[..20];
        let tail = &PARITY_XPUB[PARITY_XPUB.len() - 20..];
        assert!(rows[label_row + 1].contains(head));
        assert!(rows
            .iter()
            .skip(label_row + 2)
            .any(|row| row.contains(tail)));
        Ok(())
    }

    #[test]
    fn secrets_stay_redacted_until_reveal() -> Result<()> {
        let mut app = App::new();
        app.handle_paste(SAMPLE_PHRASE);
        app.handle_paste(SAMPLE_PASSPHRASE);
        press(&mut app, KeyCode::Enter);

        let hidden = text(&draw(&mut app, 100, 30)?);
        assert!(hidden.contains("Pasted seed phrase"));
        assert!(hidden.contains("[redacted]"));
        assert!(!hidden.contains("abandon"));
        assert!(!hidden.contains(SAMPLE_PASSPHRASE));

        press(&mut app, KeyCode::Char('r'));
        let revealed = text(&draw(&mut app, 100, 30)?);
        assert!(revealed.contains("reveal on"));
        assert!(revealed.contains("12 about"));
        assert!(revealed.contains(" 1 abandon"));
        assert!(revealed.contains(SAMPLE_PASSPHRASE));
        Ok(())
    }

    #[test]
    fn inspector_popup_masks_typed_input() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('/'));
        for ch in "hunter2 words".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        let rendered = text(&draw(&mut app, 100, 30)?);

        assert!(rendered.contains("Inspect material"));
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("•••••••••••••"));
        assert!(rendered.contains("13 chars · 2 words"));
        assert!(rendered.contains("Enter inspect"));

        app.handle_paste("not wallet material");
        press(&mut app, KeyCode::Enter);
        let rendered = text(&draw(&mut app, 100, 30)?);
        assert!(rendered.contains("Could not classify"));
        assert!(!rendered.contains("wallet material"));
        Ok(())
    }

    #[test]
    fn passphrase_popup_masks_the_passphrase() -> Result<()> {
        let mut app = App::new();
        app.handle_paste(SAMPLE_PHRASE);
        app.handle_paste("correct horse");
        let rendered = text(&draw(&mut app, 100, 30)?);

        assert!(rendered.contains("BIP39 passphrase"));
        assert!(rendered.contains("12 words · english"));
        assert!(!rendered.contains("correct horse"));
        assert!(rendered.contains("13 chars"));
        Ok(())
    }

    #[test]
    fn jump_popup_shows_the_typed_index() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char(':'));
        for ch in "42".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        let rendered = text(&draw(&mut app, 100, 30)?);
        assert!(rendered.contains("Go to index"));
        assert!(rendered.contains("› 42"));
        Ok(())
    }

    #[test]
    fn help_overlay_lists_keys_and_safety_notes() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('?'));
        let rendered = text(&draw(&mut app, 100, 30)?);

        assert!(rendered.contains("Navigation"));
        assert!(rendered.contains("generate a 24-word mnemonic"));
        assert!(rendered.contains("Safety"));
        assert!(rendered.contains("Very custody"));
        assert!(rendered.contains("Esc close"));
        Ok(())
    }

    #[test]
    fn address_material_lists_matches_and_explains_missing_derivation() -> Result<()> {
        let mut app = App::new();
        app.handle_paste(RECEIVE_0);
        let rendered = text(&draw(&mut app, 100, 30)?);

        assert!(rendered.contains("mainnet · p2pkh"));
        assert!(rendered.contains("payload"));
        assert!(rendered.contains("no keys to derive from"));
        assert!(!rendered.contains("m/44'/3'/0'/0/0"));
        Ok(())
    }

    #[test]
    fn pasted_xpub_shows_key_metadata_and_relative_paths() -> Result<()> {
        let mut app = App::new();
        app.handle_paste(PARITY_XPUB);
        let rendered = text(&draw(&mut app, 100, 30)?);

        assert!(rendered.contains("Extended public key"));
        assert!(rendered.contains("3 · account"));
        assert!(rendered.contains("0' (2147483648)"));
        assert!(rendered.contains("783dcdb0"));
        assert!(rendered.contains("0 · fixed by key"));
        assert!(rendered.contains("receive  m/0/i"));
        Ok(())
    }

    #[test]
    fn narrow_and_tiny_terminals_render_without_panicking() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('r'));

        let narrow = text(&draw(&mut app, 60, 20)?);
        assert!(narrow.contains("EasyDoge KM"));
        assert!(
            !narrow.contains("key managemen"),
            "tagline is dropped, not cut"
        );
        assert!(narrow.contains("Addresses"));
        assert!(narrow.contains(RECEIVE_0));
        assert!(
            !narrow.contains("Selected"),
            "stacked layout drops the detail panel"
        );

        let tiny = text(&draw(&mut app, 30, 8)?);
        assert!(tiny.contains("Terminal too small"));

        for (width, height) in [(40, 10), (41, 11), (79, 12), (80, 10), (10, 3), (1, 1)] {
            draw(&mut app, width, height)?;
        }
        for mode in [KeyCode::Char('/'), KeyCode::Char(':'), KeyCode::Char('?')] {
            let mut app = App::new();
            press(&mut app, mode);
            for (width, height) in [(40, 10), (60, 12), (200, 60)] {
                draw(&mut app, width, height)?;
            }
        }
        Ok(())
    }

    #[test]
    fn network_badge_follows_the_network_key() -> Result<()> {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('t'));
        let buffer = draw(&mut app, 80, 24)?;
        let title = &lines(&buffer)[0];
        assert!(title.contains("testnet"));
        assert!(!title.contains("mainnet"));
        Ok(())
    }
}
