//! The single source of truth for styling.
//!
//! Widget code must not construct `Color`/`Style` values inline — pull from here.
//! That keeps the palette swappable and stops one-off colors from drifting.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::BorderType;

pub struct Theme {
    pub accent: Color,
    pub text: Color,
    pub dim: Color,
    pub ok: Color,
    pub warn: Color,
    pub error: Color,
    pub selection_bg: Color,
    pub border: BorderType,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            accent: Color::Rgb(137, 180, 250),
            text: Color::Reset,
            dim: Color::DarkGray,
            ok: Color::Rgb(166, 227, 161),
            warn: Color::Rgb(249, 226, 175),
            error: Color::Rgb(243, 139, 168),
            selection_bg: Color::Rgb(49, 50, 68),
            border: BorderType::Rounded,
        }
    }
}

impl Theme {
    /// Deliberately leaves the background alone so the terminal's own theme,
    /// including transparency, shows through.
    pub fn base(&self) -> Style {
        Style::default().fg(self.text)
    }

    pub fn dimmed(&self) -> Style {
        Style::default().fg(self.dim)
    }

    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn selected(&self) -> Style {
        Style::default()
            .bg(self.selection_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border_style(&self) -> Style {
        Style::default().fg(self.dim)
    }

    pub fn ok_style(&self) -> Style {
        Style::default().fg(self.ok)
    }

    pub fn warn_style(&self) -> Style {
        Style::default().fg(self.warn)
    }

    pub fn error_style(&self) -> Style {
        Style::default().fg(self.error)
    }

    /// The scrollbar's moving part. Accent rather than text so it reads as
    /// chrome, like the borders and titles it sits among — and so it stays
    /// visible against the border it is drawn on top of.
    pub fn scroll_thumb(&self) -> Style {
        Style::default().fg(self.accent)
    }

    /// A filled cell, so the thumb is unmistakable regardless of the font.
    /// Weight-based alternatives like `┃` are a hair's difference from `│` in
    /// many terminal fonts, which defeats the point of an indicator.
    pub fn scroll_thumb_symbol(&self) -> &'static str {
        "█"
    }

    /// The glyph [`Self::border`] draws down a panel's sides. A scrollbar track
    /// uses it so the bar is invisible except for its thumb.
    pub fn border_vertical(&self) -> &'static str {
        match self.border {
            BorderType::Double => "║",
            BorderType::Thick => "┃",
            _ => "│",
        }
    }

    pub fn key_hint(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }
}
