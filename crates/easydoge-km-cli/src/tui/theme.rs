//! Style vocabulary for the TUI.
//!
//! Only the sixteen terminal palette colours are used so the interface follows
//! the user's own light or dark terminal theme.

use easydoge_km::Network;
use ratatui::style::{Color, Modifier, Style};

/// Dogecoin gold, used for brand, focus, and selection.
pub const ACCENT: Color = Color::Yellow;

pub fn brand() -> Style {
    Style::new()
        .fg(Color::Black)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn title() -> Style {
    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn muted() -> Style {
    Style::new().fg(Color::DarkGray)
}

pub fn value() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

/// Public material such as xpubs, addresses, and public keys.
pub fn public() -> Style {
    Style::new().fg(Color::Cyan)
}

/// Revealed secret material.
pub fn secret() -> Style {
    Style::new().fg(Color::Magenta)
}

/// Placeholder shown where a secret is being withheld.
pub fn redacted() -> Style {
    Style::new().fg(Color::Magenta).add_modifier(Modifier::DIM)
}

pub fn ok() -> Style {
    Style::new().fg(Color::Green)
}

pub fn warn() -> Style {
    Style::new().fg(Color::Yellow)
}

pub fn error() -> Style {
    Style::new().fg(Color::Red)
}

pub fn key() -> Style {
    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn selected() -> Style {
    Style::new()
        .fg(Color::Black)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn border() -> Style {
    Style::new().fg(Color::DarkGray)
}

pub fn border_active() -> Style {
    Style::new().fg(ACCENT)
}

pub fn badge() -> Style {
    Style::new().fg(Color::Black).bg(Color::DarkGray)
}

pub fn reveal_badge() -> Style {
    Style::new()
        .fg(Color::Black)
        .bg(Color::Red)
        .add_modifier(Modifier::BOLD)
}

pub fn network(network: Network) -> Style {
    let color = match network {
        Network::Mainnet => ACCENT,
        Network::Testnet => Color::Cyan,
        Network::Regtest => Color::Magenta,
    };
    Style::new()
        .fg(Color::Black)
        .bg(color)
        .add_modifier(Modifier::BOLD)
}
