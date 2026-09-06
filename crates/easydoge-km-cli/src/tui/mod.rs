//! Interactive Ratatui explorer for the EasyDoge KM SDK.
//!
//! The module is split so that state transitions ([`app`]), material
//! classification ([`material`]), and rendering ([`ui`]) can each be tested
//! without a real terminal.

mod app;
mod material;
mod theme;
mod ui;

use std::io;

use anyhow::{Context, Result};
use crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use ratatui::DefaultTerminal;

use app::App;

/// Run the TUI until the user quits.
pub fn run() -> Result<()> {
    let mut terminal = ratatui::try_init().context("initialise terminal")?;
    let result = run_session(&mut terminal);
    ratatui::restore();
    result
}

fn run_session(terminal: &mut DefaultTerminal) -> Result<()> {
    crossterm::execute!(io::stdout(), EnableBracketedPaste)
        .context("enable terminal paste events")?;
    let result = event_loop(terminal);
    let cleanup = crossterm::execute!(io::stdout(), DisableBracketedPaste)
        .context("disable terminal paste events");
    result.and(cleanup)
}

fn event_loop(terminal: &mut DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    while !app.should_quit {
        terminal
            .draw(|frame| ui::render(frame, &mut app))
            .context("draw frame")?;
        match event::read().context("read terminal event")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => app.handle_key(key),
            Event::Paste(contents) => app.handle_paste(&contents),
            _ => {}
        }
    }
    Ok(())
}
