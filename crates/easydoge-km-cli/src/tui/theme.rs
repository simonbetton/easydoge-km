//! Style vocabulary for the TUI.
//!
//! Brand chips (black on yellow) and status colours stay in the sixteen-colour
//! palette. Secondary text uses the terminal's default foreground so labels,
//! notes, and inactive chrome stay readable on both light and dark backgrounds.
//! ANSI DarkGray (bright black) is never used for text: many dark palettes map
//! it onto a colour indistinguishable from the background.

use std::sync::OnceLock;

use easydoge_km::Network;
use ratatui::style::{Color, Modifier, Style};

/// Dogecoin gold, used for brand chips, focus, and selection.
pub const ACCENT: Color = Color::Yellow;

/// Terminal background inferred from `COLORFGBG`. Missing or unparseable values
/// are treated as dark, which is the common CLI default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Dark,
    Light,
}

fn surface() -> Surface {
    static SURFACE: OnceLock<Surface> = OnceLock::new();
    *SURFACE.get_or_init(|| {
        std::env::var("COLORFGBG")
            .ok()
            .as_deref()
            .and_then(surface_from_colorfgbg)
            .unwrap_or(Surface::Dark)
    })
}

/// Parse rxvt/xterm `COLORFGBG` (`fg;bg` or `fg;default;bg`).
///
/// Palette indices 7 and 9–15 are treated as light backgrounds; 0–6 and 8 as
/// dark. That matches how those terminals encode white vs black cells.
fn surface_from_colorfgbg(value: &str) -> Option<Surface> {
    let bg = value.split(';').next_back()?.trim().parse::<u8>().ok()?;
    Some(if matches!(bg, 7 | 9..=15) {
        Surface::Light
    } else {
        Surface::Dark
    })
}

/// Gold on dark terminals; default foreground on light ones, where yellow text
/// often fails contrast against a pale background.
fn heading_fg() -> Option<Color> {
    match surface() {
        Surface::Dark => Some(ACCENT),
        Surface::Light => None,
    }
}

fn with_heading_fg(mut style: Style) -> Style {
    if let Some(color) = heading_fg() {
        style = style.fg(color);
    }
    style
}

pub fn brand() -> Style {
    Style::new()
        .fg(Color::Black)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn title() -> Style {
    with_heading_fg(Style::new().add_modifier(Modifier::BOLD))
}

pub fn muted() -> Style {
    Style::new()
}

pub fn value() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

/// Public material such as xpubs, addresses, and public keys.
pub fn public() -> Style {
    Style::new().fg(match surface() {
        Surface::Dark => Color::Cyan,
        Surface::Light => Color::Blue,
    })
}

/// Revealed secret material.
pub fn secret() -> Style {
    Style::new().fg(Color::Magenta)
}

/// Placeholder shown where a secret is being withheld.
pub fn redacted() -> Style {
    Style::new().fg(Color::Magenta)
}

pub fn ok() -> Style {
    Style::new().fg(Color::Green)
}

pub fn warn() -> Style {
    with_heading_fg(Style::new())
}

pub fn error() -> Style {
    Style::new().fg(Color::Red)
}

pub fn key() -> Style {
    with_heading_fg(Style::new().add_modifier(Modifier::BOLD))
}

pub fn selected() -> Style {
    Style::new()
        .fg(Color::Black)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn border() -> Style {
    Style::new()
}

pub fn border_active() -> Style {
    with_heading_fg(Style::new())
}

/// Quiet status chip. Reverse video follows the terminal fg/bg, so the badge
/// stays readable on both light and dark palettes.
pub fn badge() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colorfgbg_treats_black_cells_as_dark_and_white_cells_as_light() {
        assert_eq!(surface_from_colorfgbg("15;0"), Some(Surface::Dark));
        assert_eq!(surface_from_colorfgbg("7;0"), Some(Surface::Dark));
        assert_eq!(surface_from_colorfgbg("0;8"), Some(Surface::Dark));
        assert_eq!(surface_from_colorfgbg("0;15"), Some(Surface::Light));
        assert_eq!(surface_from_colorfgbg("0;7"), Some(Surface::Light));
        assert_eq!(surface_from_colorfgbg("0;default;15"), Some(Surface::Light));
        assert_eq!(surface_from_colorfgbg("not-a-palette"), None);
    }

    #[test]
    fn secondary_text_is_not_dark_gray_or_dim() {
        assert_eq!(muted().fg, None);
        assert_eq!(border().fg, None);
        assert!(!redacted().add_modifier.contains(Modifier::DIM));
        assert_eq!(redacted().fg, Some(Color::Magenta));
        assert!(badge().add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn filled_chips_keep_black_on_a_saturated_background() {
        assert_eq!(brand().fg, Some(Color::Black));
        assert_eq!(brand().bg, Some(ACCENT));
        assert_eq!(selected().fg, Some(Color::Black));
        assert_eq!(selected().bg, Some(ACCENT));
        assert_eq!(reveal_badge().bg, Some(Color::Red));
        assert_eq!(network(Network::Mainnet).bg, Some(ACCENT));
    }
}
