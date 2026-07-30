//! Rendering. Pure functions of `&App` — no I/O, no mutation, no network.
//!
//! If a widget needs data it doesn't have, the fix is to put that data in `App`
//! before the frame starts, not to fetch it here.

pub mod theme;

use ratatui::Frame;
use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::execute;
use ratatui::crossterm::style::ResetColor;
use ratatui::crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, SetTitle};
use std::io::Write;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Row, Table, Wrap};

use crate::app::{App, BINDINGS, Mode, Status};
use crate::ssh;
use theme::Theme;

/// Give the terminal back to a live SSH session.
///
/// Leaves the alternate screen so session output lands in the user's normal
/// scrollback, but deliberately does *not* disable raw mode: the remote shell
/// needs keystrokes unbuffered and unechoed.
///
/// The cursor is shown again. ratatui hides it on every draw (this app paints
/// its own `▌` in text fields), and the remote shell has no idea it needs to
/// ask for it back — leaving it hidden means typing into a session with no
/// visible cursor.
pub fn suspend() -> std::io::Result<()> {
    // Reset before letting go, so our own styling cannot bleed into the first
    // thing the remote writes. On a *resume* nothing else clears it — the
    // "ctrl-] detaches" banner ends in a reset, but that only prints on a first
    // attach.
    suspend_to(&mut std::io::stdout())
}

/// Take the terminal back after a session ends. Must run on every exit path.
///
/// `ResetColor` is load-bearing rather than tidiness. `Theme::base` deliberately
/// sets no background so the terminal's own theme and transparency show through,
/// which means every cell we draw without one inherits whatever SGR state the
/// terminal is left in. A remote program that paints its own background and does
/// not reset on exit — `mc` is the obvious one, blue — hands us a terminal whose
/// default background *is* blue, and the host list comes back blue with it.
pub fn resume() -> std::io::Result<()> {
    resume_to(&mut std::io::stdout())
}

// Split out so the emitted bytes can be asserted. These go straight to stdout
// rather than through ratatui, so `TestBackend` never sees them and the reset
// below is exactly the kind of line a later tidy-up removes as redundant.
fn suspend_to(out: &mut impl Write) -> std::io::Result<()> {
    execute!(out, ResetColor, LeaveAlternateScreen, Show)
}

fn resume_to(out: &mut impl Write) -> std::io::Result<()> {
    execute!(out, EnterAlternateScreen, ResetColor, Hide)
}

/// The window title while browsing.
pub const APP_TITLE: &str = "luvienne";

/// Save the terminal's current title so it can be restored on exit.
///
/// XTWINOPS 22/23 — a stack the terminal keeps for exactly this. Terminals that
/// do not implement it ignore both, and the only consequence is that the title
/// stays as ours after quitting.
pub fn push_title() -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(b"\x1b[22;0t")?;
    out.flush()
}

/// Put the title the user had back.
pub fn pop_title() -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(b"\x1b[23;0t")?;
    out.flush()
}

pub fn set_title(title: &str) -> std::io::Result<()> {
    execute!(std::io::stdout(), SetTitle(title))
}

/// Make the cursor visible again.
///
/// `ratatui::restore` does not do this — it only disables raw mode and leaves
/// the alternate screen — so without this the shell you return to on quit has
/// an invisible cursor until you run `reset`.
pub fn show_cursor() -> std::io::Result<()> {
    execute!(std::io::stdout(), Show)
}

pub fn render(app: &App, frame: &mut Frame) {
    let theme = Theme::default();
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header / filter
            Constraint::Min(0),    // body
            Constraint::Length(1), // status
        ])
        .split(area);

    render_header(app, &theme, frame, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(chunks[1]);

    render_tags(app, &theme, frame, body[0]);
    if app.mode == Mode::SessionList {
        render_sessions(app, &theme, frame, body[1]);
    } else {
        render_hosts(app, &theme, frame, body[1]);
    }
    render_status(app, &theme, frame, chunks[2]);

    match app.mode {
        Mode::Help => render_help(&theme, frame, area),
        Mode::ConfirmHostKey => render_host_key_prompt(app, &theme, frame, area),
        Mode::Secret => render_secret_prompt(app, &theme, frame, area),
        Mode::Form => render_form(app, &theme, frame, area),
        Mode::ConfirmDelete => render_delete_prompt(app, &theme, frame, area),
        Mode::FilePicker => render_picker(app, &theme, frame, area),
        Mode::ConfirmImport => render_import_prompt(app, &theme, frame, area),
        _ => {}
    }
}

/// The import confirmation.
///
/// States what will be added *and* what will need attention afterwards, per
/// source. A migrated PuTTY config routinely has key paths from another
/// machine, and an ssh config is full of things that are not hosts at all —
/// finding that out one failed connection at a time is miserable.
fn render_import_prompt(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    if app.pending_import.is_empty() {
        return;
    }
    let total: usize = app.pending_import.iter().map(|i| i.hosts.len()).sum();

    let mut body = vec![Line::from(Span::styled(
        format!("  Import {total} hosts?"),
        theme.base(),
    ))];

    for source in &app.pending_import {
        body.push(Line::from(""));
        body.push(Line::from(vec![
            Span::styled(format!("  {} ", source.hosts.len()), theme.base()),
            Span::styled(format!("from {}", source.source), theme.dimmed()),
        ]));
        for note in &source.notes {
            body.push(Line::from(Span::styled(
                format!("    {note}"),
                theme.dimmed(),
            )));
        }
        if source.already_present > 0 {
            body.push(Line::from(Span::styled(
                format!(
                    "    {} already in the list, skipped",
                    source.already_present
                ),
                theme.dimmed(),
            )));
        }
    }

    body.push(Line::from(""));
    body.push(Line::from(vec![
        Span::styled("  y", theme.key_hint()),
        Span::styled(" import    ", theme.dimmed()),
        Span::styled("n/esc", theme.key_hint()),
        Span::styled(" cancel", theme.dimmed()),
    ]));

    let width = 68u16.min(area.width.saturating_sub(4));
    // Borders plus the lines actually built, so extra notes are never clipped.
    let height = (body.len() as u16 + 2).min(area.height);
    let popup = centered(width, height, area);

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(" import hosts ", theme.title()));

    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(body).block(block), popup);
}

/// The key file browser.
///
/// Shows the whole filesystem, not a fixed directory — keys live wherever the
/// user put them, and the previous free-text-only field made anything outside a
/// familiar path a blind typing exercise.
fn render_picker(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let Some(picker) = &app.picker else {
        return;
    };

    let width = 72u16.min(area.width.saturating_sub(4));
    let height = 20u16.min(area.height);
    let popup = centered(width, height, area);

    // Borders, the path header, and the footer.
    let viewport = height.saturating_sub(4) as usize;
    let offset = picker.selected.saturating_sub(viewport.saturating_sub(1));

    let mut lines = vec![
        Line::from(Span::styled(
            format!("  {}", compress_home(&picker.dir)),
            theme.dimmed(),
        )),
        Line::from(""),
    ];

    if let Some(error) = &picker.error {
        lines.push(Line::from(Span::styled(
            format!("  {error}"),
            theme.error_style(),
        )));
    } else if picker.entries.is_empty() {
        lines.push(Line::from(Span::styled("  (empty)", theme.dimmed())));
    }

    for (i, entry) in picker
        .entries
        .iter()
        .enumerate()
        .skip(offset)
        .take(viewport)
    {
        let style = if i == picker.selected {
            theme.selected()
        } else {
            theme.base()
        };
        // A trailing slash marks directories without needing colour, which the
        // user's terminal theme may not render the way we expect.
        let name = if entry.is_dir {
            format!("  {}/", entry.name)
        } else {
            format!("  {}", entry.name)
        };
        lines.push(Line::from(Span::styled(name, style)));
    }

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(" choose a key file ", theme.title()))
        .title_bottom(Line::from(vec![
            Span::styled(" ↵", theme.key_hint()),
            Span::styled(" open/choose  ", theme.dimmed()),
            Span::styled("←", theme.key_hint()),
            Span::styled(" up  ", theme.dimmed()),
            Span::styled(".", theme.key_hint()),
            Span::styled(
                if picker.show_hidden {
                    " hide dotfiles  "
                } else {
                    " show dotfiles  "
                },
                theme.dimmed(),
            ),
            Span::styled("esc", theme.key_hint()),
            Span::styled(" cancel ", theme.dimmed()),
        ]));

    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(block), popup);
    // Three rows above the first entry: the top border, the path, and the blank
    // line under it. The key hints sit *on* the bottom border as a title, not on
    // a row of their own — which is why the viewport subtracts four, not five.
    let track = scroll_track(popup, 3, viewport);
    render_scrollbar(theme, frame, track, picker.entries.len(), offset);
}

/// Render `/Users/someone/.ssh` as `~/.ssh`, so the header stays readable in a
/// narrow modal.
fn compress_home(path: &std::path::Path) -> String {
    let full = path.display().to_string();
    match directories::BaseDirs::new() {
        Some(dirs) => {
            let home = dirs.home_dir().display().to_string();
            match full.strip_prefix(&home) {
                Some("") => "~".into(),
                Some(rest) => format!("~{rest}"),
                None => full,
            }
        }
        None => full,
    }
}

/// The form's label column: the label itself, right-aligned, plus two spaces
/// either side. Derived rather than written twice — the render and the width
/// arithmetic must agree, and a literal in each is a drift waiting to happen.
const LABEL_TEXT: usize = 10;
const LABEL_COLUMN: usize = LABEL_TEXT + 4;

/// The part of a field's value that fits, anchored to its **end**.
///
/// Text fields here only ever append and backspace, so the caret is always at
/// the end — which makes the end the only part that has to stay visible. Show
/// the head instead and typing past the edge becomes invisible: the characters
/// land in the buffer, the display stops changing, and there is no way to tell
/// a key path with a typo from one without.
///
/// Anchored the same way whether or not the row has focus, so tabbing between
/// fields does not slide the text about. It also happens to be the right end
/// for the values that overflow: a path's filename identifies it far better
/// than its leading directories.
///
/// The leading `…` says something was cut, and costs one of the columns it is
/// reporting on.
///
/// Measured in **display columns, not characters**. A CJK character occupies two
/// columns, so counting characters keeps twice as much text as fits and the row
/// overflows exactly as it did before — the same bug, one metric further down.
fn visible_tail(value: &str, width: usize) -> String {
    if display_width(value) <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }

    let budget = width - 1; // the `…` takes a column of its own
    let mut taken = 0usize;
    let mut start = value.len();
    for (i, c) in value.char_indices().rev() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if taken + w > budget {
            break;
        }
        taken += w;
        start = i;
    }

    let mut out = String::with_capacity(width);
    out.push('…');
    out.push_str(&value[start..]);
    out
}

/// The same, anchored to the **start**.
///
/// For placeholder hints, which are read left to right and never edited — the
/// opposite of a value, whose end is where the caret lives. They need clipping
/// for the same reason values do: an unclipped hint pushes the caret off the
/// row, and an empty focused field is exactly where the caret matters most.
fn visible_head(text: &str, width: usize) -> String {
    if display_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }

    let budget = width - 1;
    let mut taken = 0usize;
    let mut end = 0usize;
    for (i, c) in text.char_indices() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if taken + w > budget {
            break;
        }
        taken += w;
        end = i + c.len_utf8();
    }

    let mut out = String::with_capacity(width);
    out.push_str(&text[..end]);
    out.push('…');
    out
}

fn display_width(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

/// The add/edit host form.
fn render_form(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    use crate::app::form::FormMode;

    let Some(form) = &app.form else {
        return;
    };
    let fields = form.fields();

    let width = 64u16.min(area.width.saturating_sub(4));
    // One row per field, plus borders, title spacing, and the footer.
    let height = (fields.len() as u16 + 5).min(area.height);
    let popup = centered(width, height, area);

    let mut lines: Vec<Line> = Vec::with_capacity(fields.len() + 2);

    // What is left of a row once the borders, the label column and the caret
    // have taken their share. Reserved for the caret whether or not this row
    // has focus, so the text does not shift sideways by one as focus moves.
    let value_width = (popup.width as usize)
        .saturating_sub(2)
        .saturating_sub(LABEL_COLUMN)
        .saturating_sub(1);

    for (i, field) in fields.iter().enumerate() {
        let focused = i == form.focus;
        let value = form.value(*field);

        let shown = if value.is_empty() && !field.is_choice() {
            // Clipped too: an over-long hint pushes the caret off the row, and
            // an empty focused field is where the caret matters most.
            Span::styled(visible_head(field.hint(), value_width), theme.dimmed())
        } else {
            Span::styled(visible_tail(value, value_width), theme.base())
        };

        let mut spans = vec![
            Span::styled(
                format!("  {:>LABEL_TEXT$}  ", field.label()),
                if focused {
                    theme.key_hint()
                } else {
                    theme.dimmed()
                },
            ),
            shown,
        ];
        if focused {
            spans.push(Span::styled("▌", theme.key_hint()));
        }
        // A choice field always has a value, so the empty-field placeholder
        // above never fires for one and its hint would never be seen at all.
        // Trailing it after the value is the only place it fits: the footer is
        // already near the popup's width, and `remember  no` on its own says
        // nothing about a passphrase being stored anywhere.
        if field.is_choice() {
            spans.push(Span::styled(format!("  {}", field.hint()), theme.dimmed()));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));
    lines.push(match &form.error {
        // The error replaces the key hints rather than sitting alongside them:
        // it is the only thing that matters until it is fixed.
        Some(message) => Line::from(Span::styled(format!("  {message}"), theme.error_style())),
        None => {
            let mut hints = vec![
                Span::styled("  ↵", theme.key_hint()),
                Span::styled(" save    ", theme.dimmed()),
                Span::styled("tab", theme.key_hint()),
                Span::styled(" next field    ", theme.dimmed()),
            ];
            // The placeholder that mentions ^O disappears as soon as anything is
            // typed, so the footer carries it while the path field has focus.
            if form.focused() == crate::app::form::Field::KeyPath {
                hints.push(Span::styled("^O", theme.key_hint()));
                hints.push(Span::styled(" browse    ", theme.dimmed()));
            }
            hints.push(Span::styled("esc", theme.key_hint()));
            hints.push(Span::styled(" cancel", theme.dimmed()));
            Line::from(hints)
        }
    });

    let title = match &form.mode {
        FormMode::Add => " add host ".to_string(),
        FormMode::Edit(_) => " edit host ".to_string(),
        // The count is the whole point: it is the difference between editing
        // one host and rewriting sixty.
        FormMode::Bulk(targets) => format!(" bulk edit — {} hosts ", targets.len()),
    };
    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(title, theme.title()));

    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

/// Delete confirmation. Names the host, because "are you sure?" is not enough
/// information to answer safely.
fn render_delete_prompt(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let name = app
        .pending_delete
        .and_then(|i| app.inventory.hosts.get(i))
        .map(|h| h.name.as_str())
        .unwrap_or("this host");

    let width = 56u16.min(area.width.saturating_sub(4));
    let height = 5u16.min(area.height);
    let popup = centered(width, height, area);

    let body = vec![
        Line::from(Span::styled(format!("  Delete {name}?"), theme.base())),
        Line::from(Span::styled("  This rewrites hosts.toml.", theme.dimmed())),
        Line::from(vec![
            Span::styled("  y", theme.key_hint()),
            Span::styled(" delete    ", theme.dimmed()),
            Span::styled("n/esc", theme.key_hint()),
            Span::styled(" keep", theme.dimmed()),
        ]),
    ];

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.warn_style())
        .title(Span::styled(" confirm delete ", theme.warn_style()));

    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(body).block(block), popup);
}

/// The secret-entry modal: key passphrase, password, or a keyboard-interactive
/// challenge.
///
/// Renders one bullet per character. The buffer's *contents* must never reach a
/// `Span` unless the request explicitly set `echo` — which only happens when the
/// server asked for a visible answer. There is a test asserting exactly that.
fn render_secret_prompt(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let Some(pending) = &app.secret_prompt else {
        return;
    };
    let request = &pending.request;

    let width = 66u16.min(area.width.saturating_sub(4));
    let height = 7u16.min(area.height);
    let popup = centered(width, height, area);

    let shown = if request.echo {
        app.secret_input.to_string()
    } else {
        "•".repeat(app.secret_input.chars().count())
    };
    let prompt_label = format!("  {}: ", request.prompt);

    let headline = if request.retry {
        Span::styled(
            format!("  {} rejected — try again", request.kind.title()),
            theme.error_style(),
        )
    } else {
        let what = match request.kind {
            ssh::SecretKind::Passphrase => "this key is encrypted",
            ssh::SecretKind::Password => "the server wants a password",
            ssh::SecretKind::Username => "no username saved for this host",
        };
        Span::styled(format!("  {what}"), theme.base())
    };

    let body = vec![
        Line::from(headline),
        Line::from(Span::styled(
            format!("  {}", request.subject),
            theme.dimmed(),
        )),
        Line::from(""),
        Line::from(vec![
            // Server-supplied text for keyboard-interactive, so it is shown
            // verbatim rather than replaced with wording of our own.
            Span::styled(prompt_label.clone(), theme.dimmed()),
            // Same rule as the form: keep the end, so the caret survives and a
            // long secret does not silently stop showing what you type. The
            // label is server-supplied and can be any length, so the room left
            // for the input has to be measured rather than assumed.
            Span::styled(
                visible_tail(
                    &shown,
                    (popup.width as usize)
                        .saturating_sub(2)
                        .saturating_sub(display_width(&prompt_label))
                        .saturating_sub(1),
                ),
                theme.base(),
            ),
            Span::styled("▌", theme.key_hint()),
        ]),
        Line::from(vec![
            Span::styled("  ↵", theme.key_hint()),
            Span::styled(" submit    ", theme.dimmed()),
            Span::styled("esc", theme.key_hint()),
            Span::styled(" cancel", theme.dimmed()),
        ]),
    ];

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(
            format!(" {} ", request.kind.title()),
            theme.title(),
        ));

    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(body).block(block), popup);
}

/// The unknown-host-key modal.
///
/// Shows the full fingerprint and offers no default. `y` accepts, anything else
/// refuses — see `App::answer_host_key`.
fn render_host_key_prompt(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let Some(pending) = &app.host_key_prompt else {
        return;
    };

    let width = 66u16.min(area.width.saturating_sub(4));
    let height = 9u16.min(area.height);
    let popup = centered(width, height, area);

    let body = vec![
        Line::from(Span::styled(
            format!("  {} is not in known_hosts.", pending.host),
            theme.base(),
        )),
        Line::from(""),
        Line::from(Span::styled("  fingerprint", theme.dimmed())),
        Line::from(Span::styled(
            format!("  {}", pending.fingerprint),
            theme.base(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Verify this out of band before accepting.",
            theme.dimmed(),
        )),
        Line::from(vec![
            Span::styled("  y", theme.key_hint()),
            Span::styled(" accept and remember    ", theme.dimmed()),
            Span::styled("n/esc", theme.key_hint()),
            Span::styled(" refuse", theme.dimmed()),
        ]),
    ];

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.warn_style())
        .title(Span::styled(" unknown host key ", theme.warn_style()));

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(body).wrap(Wrap { trim: false }).block(block),
        popup,
    );
}

fn render_header(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let content = match app.mode {
        // Same rule again: the end of the filter is what you are typing, and
        // the caret has to stay on the row.
        Mode::Filter => Line::from(vec![
            Span::styled("  /", theme.key_hint()),
            Span::styled(
                visible_tail(&app.filter, (area.width as usize).saturating_sub(2 + 3 + 1)),
                theme.base(),
            ),
            Span::styled("▌", theme.key_hint()),
        ]),
        Mode::SessionList => Line::from(vec![Span::styled(
            "  ↵ resume session   esc back to hosts",
            theme.dimmed(),
        )]),
        _ if !app.filter.is_empty() => Line::from(vec![
            Span::styled("  filter: ", theme.dimmed()),
            Span::styled(app.filter.clone(), theme.base()),
            Span::styled("   (esc to clear)", theme.dimmed()),
        ]),
        _ => Line::from(vec![Span::styled(
            "  press / to filter, ? for help",
            theme.dimmed(),
        )]),
    };

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(" luvienne ", theme.title()));

    frame.render_widget(Paragraph::new(content).block(block), area);
}

fn render_tags(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let tags = app.inventory.tags();

    let mut items = vec![ListItem::new(Line::from(Span::styled(
        "  all hosts",
        if app.tag_filter.is_none() {
            theme.selected()
        } else {
            theme.base()
        },
    )))];

    items.extend(tags.iter().map(|tag| {
        let active = app.tag_filter.as_deref() == Some(tag.as_str());
        let count = app
            .inventory
            .hosts
            .iter()
            .filter(|h| h.tags.contains(tag))
            .count();
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("  {tag} "),
                if active {
                    theme.selected()
                } else {
                    theme.base()
                },
            ),
            Span::styled(format!("{count}"), theme.dimmed()),
        ]))
    }));

    // Two rows of chrome. Same reasoning as the host list: with more categories
    // than fit, the active one has to stay on screen or there is no way to tell
    // what the list is filtered by.
    let viewport = area.height.saturating_sub(2) as usize;
    let active = match &app.tag_filter {
        // Index 0 is the "all hosts" row, so tags start at 1.
        Some(tag) => tags.iter().position(|t| t == tag).map_or(0, |i| i + 1),
        None => 0,
    };
    let offset = active.saturating_sub(viewport.saturating_sub(1));
    let visible: Vec<ListItem> = items.into_iter().skip(offset).take(viewport).collect();

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(" categories ", theme.title()));

    frame.render_widget(List::new(visible).block(block), area);
    // One row above the first category: the top border. No column header here.
    let track = scroll_track(area, 1, viewport);
    render_scrollbar(theme, frame, track, tags.len() + 1, offset);
}

/// The rows a list's items occupy, as a one-column strip on its right border.
///
/// `chrome_above` is how many rows sit between the top of `area` and the first
/// item: the border, plus a column header or a path line where a list has one.
/// Every list has a different amount, and getting it wrong slides the track out
/// of step with the rows it describes — so it is the caller's to state.
///
/// `viewport` is the item count the caller already computed to decide what to
/// draw. Reusing that exact value is the point: the track cannot disagree with
/// the list about how many rows there are.
fn scroll_track(area: Rect, chrome_above: u16, viewport: usize) -> Rect {
    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(1)),
        y: area.y.saturating_add(chrome_above),
        width: 1,
        height: viewport.min(u16::MAX as usize) as u16,
    }
}

/// Draw a scrollbar down `track`.
///
/// **Nothing is drawn when the list fits.** A track that is always full says
/// only "there is a list", which the user can already see, and it costs a
/// column of border to say it. Its appearing *is* the signal that there is more.
///
/// All arithmetic saturates: a 20x5 terminal must render without panicking.
fn render_scrollbar(theme: &Theme, frame: &mut Frame, track: Rect, total: usize, offset: usize) {
    use ratatui::widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState};

    let viewport = track.height as usize;
    if viewport == 0 || total <= viewport || track.width == 0 {
        return;
    }

    // ratatui measures the thumb from the scrollable *range* — how many
    // positions the offset can take — not from the item count. Passing the item
    // count draws a thumb that never reaches the bottom of a long list, so a
    // fully scrolled list still looks like it has more below.
    let mut state = ScrollbarState::new(total.saturating_sub(viewport)).position(offset);

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            // The track is the border. ratatui's default is `║`, which cuts a
            // double-ruled stripe down the side of a panel drawn in rounded
            // single lines — so the bar is drawn as the border character it
            // sits on and only the thumb is visible against it.
            .track_symbol(Some(theme.border_vertical()))
            .track_style(theme.border_style())
            .thumb_symbol(theme.scroll_thumb_symbol())
            .thumb_style(theme.scroll_thumb()),
        track,
        &mut state,
    );
}

/// Width for the name column: enough to show the longest name in the list,
/// bounded so it cannot squeeze the columns beside it off the screen.
///
/// It was a fixed 22 columns, which truncated two thirds of a name like
/// "Defenders Matrix Med Prod Workers" while a wide window had room to spare —
/// the other columns are `Min` constraints, so they absorbed all the slack and
/// the one column that needed it never grew.
///
/// Sized from the **whole inventory**, not the hosts currently on screen.
///
/// Fitting it to the filtered list packs the columns tighter, but the filter is
/// this app's primary way of getting around: sizing to it means the destination,
/// auth and tag columns jump sideways on every keystroke of the most common
/// interaction there is. A stable table costs a few columns when a filter
/// happens to leave only short names, and that is the cheaper of the two.
///
/// Deliberately **not** capped against the window width. An earlier version
/// reserved room for the other three columns by hand, and rendering it proved
/// the reservation changed nothing: ratatui's layout solver already holds a
/// `Min` column at its minimum against an oversized `Length`, cutting a
/// 302-column name request down to the same width the hand-rolled cap
/// computed. All the cap added was a second copy of the other columns'
/// minimums, waiting to drift out of step with them.
fn name_column_width(longest_name: usize) -> u16 {
    /// The `● ` / `  ` session marker each name is rendered behind.
    const MARKER: usize = 2;
    /// `"  name"`. Verified by rendering: one-character names without this
    /// floor shrink the column to three and clip the header to `n`.
    const FLOOR: u16 = 6;

    u16::try_from(longest_name.saturating_add(MARKER))
        .unwrap_or(u16::MAX)
        .max(FLOOR)
}

/// One label per session, in `app.sessions` order.
///
/// A host can hold several sessions now, and two rows reading `web-01` are a
/// list you cannot act on. Numbered by order of opening, and only where there is
/// something to tell apart — a lone session should not read `web-01 #1`.
fn session_labels(app: &App) -> Vec<String> {
    let mut totals: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for session in &app.sessions {
        *totals.entry(session.host.as_str()).or_default() += 1;
    }

    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    app.sessions
        .iter()
        .map(|session| {
            let host = session.host.as_str();
            let nth = seen.entry(host).or_default();
            *nth += 1;
            if totals[host] > 1 {
                format!("{host} #{nth}")
            } else {
                host.to_string()
            }
        })
        .collect()
}

fn render_sessions(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let viewport = area.height.saturating_sub(3) as usize;
    let offset = app
        .session_selected
        .saturating_sub(viewport.saturating_sub(1));

    let labels = session_labels(app);

    let rows: Vec<Row> = app
        .sessions
        .iter()
        .enumerate()
        .skip(offset)
        .take(viewport)
        .map(|(i, _)| {
            let style = if i == app.session_selected {
                theme.selected()
            } else {
                theme.base()
            };
            Row::new(vec![format!("  {}", labels[i]), "detached".to_string()]).style(style)
        })
        .collect();

    let title = format!(" sessions ({}) ", app.sessions.len());
    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(title, theme.title()));

    if app.sessions.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("no active sessions", theme.dimmed()))
                .alignment(Alignment::Center)
                .block(block),
            area,
        );
        return;
    }

    let table = Table::new(rows, [Constraint::Min(16), Constraint::Min(12)])
        .header(Row::new(vec!["  name", "state"]).style(theme.dimmed()))
        .block(block);

    frame.render_widget(table, area);
    let track = scroll_track(area, 2, viewport);
    render_scrollbar(theme, frame, track, app.sessions.len(), offset);
}

fn render_hosts(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let hosts = app.visible();

    // Three rows of chrome, not two: the top and bottom borders *and* the
    // column header. Counting only the borders renders one row more than fits,
    // and the row that falls off the bottom is the selected one — which is
    // exactly the row that has to stay visible.
    let viewport = area.height.saturating_sub(3) as usize;
    let offset = app.selected.saturating_sub(viewport.saturating_sub(1));

    let rows: Vec<Row> = hosts
        .iter()
        .enumerate()
        .skip(offset)
        .take(viewport)
        .map(|(i, host)| {
            let style = if i == app.selected {
                theme.selected()
            } else {
                theme.base()
            };
            // A live session is the difference between ↵ connecting and ↵
            // resuming, so it has to be visible in the list.
            let name = match app.session_for(&host.name) {
                Some(_) => format!("● {}", host.name),
                None => format!("  {}", host.name),
            };
            Row::new(vec![
                name,
                host.destination(),
                host.auth.label().to_string(),
                host.tags.join(" "),
            ])
            .style(style)
        })
        .collect();

    let title = format!(" hosts ({}) ", hosts.len());
    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(title, theme.title()));

    if hosts.is_empty() {
        let hint = if app.inventory.hosts.is_empty() {
            "no hosts yet — press a to add one"
        } else {
            "nothing matches the current filter"
        };
        frame.render_widget(
            Paragraph::new(Span::styled(hint, theme.dimmed()))
                .alignment(Alignment::Center)
                .block(block),
            area,
        );
        return;
    }

    // Every host, not `hosts` — see `name_column_width` for why the filter must
    // not resize the table.
    let longest = app
        .inventory
        .hosts
        .iter()
        .map(|h| h.name.chars().count())
        .max()
        .unwrap_or(0);
    let widths = [
        Constraint::Length(name_column_width(longest)),
        Constraint::Min(24),
        Constraint::Length(10),
        Constraint::Min(12),
    ];

    let table = Table::new(rows, widths)
        .header(Row::new(vec!["  name", "destination", "auth", "tags"]).style(theme.dimmed()))
        .block(block);

    frame.render_widget(table, area);
    // Two rows above the first host: the top border and the column header.
    let track = scroll_track(area, 2, viewport);
    render_scrollbar(theme, frame, track, hosts.len(), offset);
}

fn render_status(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) {
    let line = match &app.status {
        Status::Idle => Line::from(hints(theme)),
        Status::Busy(msg) => Line::from(Span::styled(format!(" ⠿ {msg}"), theme.warn_style())),
        Status::Ok(msg) => Line::from(Span::styled(format!(" ✓ {msg}"), theme.ok_style())),
        Status::Error(msg) => Line::from(Span::styled(format!(" ✗ {msg}"), theme.error_style())),
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// Footer hints, derived from the same binding table the dispatcher uses.
fn hints(theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw(" ")];
    for (_, label, help, _) in BINDINGS.iter().filter(|(_, label, ..)| !label.is_empty()) {
        spans.push(Span::styled(*label, theme.key_hint()));
        spans.push(Span::styled(format!(" {help}   "), theme.dimmed()));
    }
    spans
}

fn render_help(theme: &Theme, frame: &mut Frame, area: Rect) {
    let bindings: Vec<&(_, _, _, _)> = BINDINGS
        .iter()
        .filter(|(_, label, ..)| !label.is_empty())
        .collect();

    let width = 44u16.min(area.width.saturating_sub(4));
    let height = (bindings.len() as u16 + 2).min(area.height.saturating_sub(2));
    let popup = centered(width, height, area);

    let items: Vec<ListItem> = bindings
        .iter()
        .map(|(_, label, help, _)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("  {label:<8}"), theme.key_hint()),
                Span::styled(*help, theme.base()),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(theme.border)
        .border_style(theme.border_style())
        .title(Span::styled(" keys ", theme.title()));

    // Clear first — popups draw over whatever was underneath.
    frame.render_widget(Clear, popup);
    frame.render_widget(List::new(items).block(block), popup);
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::config::{AuthRef, Host, Inventory};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn draw(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(app, frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn app_with(hosts: Vec<Host>) -> App {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let handle = Box::leak(Box::new(runtime)).handle().clone();
        // Render tests never save, but point somewhere harmless regardless —
        // the real config path must never be reachable from the suite.
        let path = std::env::temp_dir().join("luvienne-ui-tests/hosts.toml");
        App::new(Inventory { hosts }, path, handle)
    }

    fn host(name: &str) -> Host {
        Host {
            name: name.into(),
            address: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            tags: vec!["prod".into()],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        }
    }

    #[test]
    fn empty_inventory_explains_where_to_add_hosts() {
        let app = app_with(vec![]);
        let out = draw(&app, 100, 20);
        assert!(out.contains("press a to add one"), "got:\n{out}");
    }

    /// With 73 imported hosts this is the normal case, not an edge case.
    #[test]
    fn the_selected_host_stays_visible_when_the_list_overflows() {
        let hosts: Vec<Host> = (0..40).map(|i| host(&format!("host-{i:02}"))).collect();
        let mut app = app_with(hosts);

        for selected in [0usize, 5, 20, 38, 39] {
            app.selected = selected;
            let out = draw(&app, 100, 20);
            let name = format!("host-{selected:02}");
            assert!(
                out.contains(&name),
                "selected {name} is not on screen:\n{out}"
            );
        }
    }

    /// The active category must be visible in the *sidebar*. Asserting on the
    /// whole screen is not enough — the tag also appears in the host table's
    /// tags column, which made an earlier version of this test pass even with
    /// no scrolling at all.
    #[test]
    fn the_active_category_stays_visible_when_the_sidebar_overflows() {
        let hosts: Vec<Host> = (0..40)
            .map(|i| {
                let mut h = host(&format!("h{i:02}"));
                h.tags = vec![format!("tag-{i:02}")];
                h
            })
            .collect();
        let mut app = app_with(hosts);

        for tag in ["tag-00", "tag-19", "tag-39"] {
            app.tag_filter = Some(tag.to_string());
            let sidebar: String = draw(&app, 100, 20)
                .lines()
                // The sidebar is the first 22 columns; the host table follows.
                .map(|line| line.chars().take(22).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                sidebar.contains(tag),
                "active {tag} missing from the sidebar:\n{sidebar}"
            );
        }
    }

    /// Same class of bug as the host list: a home directory easily overflows.
    #[test]
    fn the_picker_keeps_its_selection_visible_when_scrolling() {
        use crate::app::picker::FilePicker;

        let root = std::env::temp_dir().join("luvienne-picker-overflow");
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        for i in 0..40 {
            std::fs::write(root.join(format!("file-{i:02}")), "x").unwrap();
        }

        let mut app = app_with(vec![]);
        app.mode = Mode::FilePicker;

        for selected in [0usize, 10, 25, 39] {
            let mut picker = FilePicker::open(&root.display().to_string());
            picker.selected = selected;
            let name = picker.entries[selected].name.clone();
            app.picker = Some(picker);

            let out = draw(&app, 100, 20);
            assert!(
                out.contains(&name),
                "selected {name} is not on screen:\n{out}"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn renders_hosts_and_categories() {
        let app = app_with(vec![host("web-01")]);
        let out = draw(&app, 100, 20);
        assert!(out.contains("web-01"));
        assert!(out.contains("prod"), "tag shows in the sidebar");
        assert!(out.contains("deploy@10.0.0.1:22"));
    }

    #[test]
    fn help_overlay_lists_bindings() {
        let mut app = app_with(vec![host("web-01")]);
        app.mode = Mode::Help;
        let out = draw(&app, 100, 20);
        assert!(out.contains("keys"));
        assert!(out.contains("connect"));
    }

    /// A tiny terminal must not panic — every subtraction on width/height is
    /// saturating for exactly this reason.
    #[test]
    fn survives_a_tiny_terminal() {
        let mut app = app_with(vec![host("web-01")]);
        app.mode = Mode::Help;
        draw(&app, 8, 4);

        // A list long enough to want a scrollbar, in a window too small to
        // hold one. All the Rect arithmetic saturates, and the sizes below are
        // where it would otherwise wrap: a viewport of zero, and a panel whose
        // width leaves no column to draw a track in.
        let mut app = app_with((0..60).map(|i| host(&format!("h{i}"))).collect());
        for (w, h) in [(8, 4), (20, 5), (24, 6), (100, 5), (1, 1)] {
            draw(&app, w, h);
        }

        // The same, with each overlay that scrolls a list of its own.
        app.mode = Mode::FilePicker;
        app.picker = Some(crate::app::picker::FilePicker::open("/"));
        for (w, h) in [(8, 4), (20, 5), (40, 8)] {
            draw(&app, w, h);
        }
    }

    /// The passphrase must never reach the screen buffer. This asserts against
    /// the rendered cells, so it catches any accidental echo — not just the
    /// obvious one.
    /// Arm a secret prompt. The receiver is deliberately kept alive by the
    /// caller's binding so the prompt is not seen as cancelled mid-render.
    fn arm(
        app: &mut App,
        kind: ssh::SecretKind,
        echo: bool,
        retry: bool,
        typed: &str,
    ) -> tokio::sync::oneshot::Receiver<Option<zeroize::Zeroizing<String>>> {
        use crate::app::PendingSecret;
        let (reply, answer) = tokio::sync::oneshot::channel();
        app.mode = Mode::Secret;
        app.secret_prompt = Some(PendingSecret::for_test(
            ssh::SecretRequest {
                kind,
                subject: "deploy@10.0.0.1".into(),
                prompt: kind.title().into(),
                echo,
                retry,
            },
            reply,
        ));
        app.secret_input = zeroize::Zeroizing::new(typed.into());
        answer
    }

    /// `^O` must be advertised where it is usable. The placeholder hint vanishes
    /// once the field has content, so the footer is the only durable signpost.
    #[test]
    fn the_browse_shortcut_is_advertised_on_the_key_path_field() {
        use crate::app::form::HostForm;

        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.auth_choice = 1; // key auth, so the path field exists
        form.focus = form
            .fields()
            .iter()
            .position(|f| *f == crate::app::form::Field::KeyPath)
            .unwrap();
        form.key_path = "/already/typed/something".into();
        app.form = Some(form);
        app.mode = Mode::Form;

        let out = draw(&app, 100, 24);
        assert!(
            out.contains("browse"),
            "no ^O hint on the path field:\n{out}"
        );

        // And not advertised where it does nothing.
        let mut app = app_with(vec![]);
        app.form = Some(HostForm::add());
        app.mode = Mode::Form;
        let out = draw(&app, 100, 24);
        assert!(
            !out.contains("browse"),
            "^O offered on the name field:\n{out}"
        );
    }

    /// A choice field always has a value, so `Field::hint` never renders for
    /// one — leaving `remember  no` on screen with nothing saying what it does.
    /// The footer is the only place left to explain that a secret gets stored.
    // The row exists only where a keychain does.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_remember_field_says_where_the_passphrase_goes() {
        use crate::app::form::{Field, HostForm};

        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.auth_choice = 1; // key auth, so the field exists at all
        form.focus = form
            .fields()
            .iter()
            .position(|f| *f == Field::CachePassphrase)
            .unwrap();
        app.form = Some(form);
        app.mode = Mode::Form;

        let out = draw(&app, 100, 24);
        assert!(out.contains("remember"), "no field row:\n{out}");
        assert!(
            out.contains("Keychain"),
            "nothing says where the passphrase would be kept:\n{out}"
        );
    }

    /// The form's label column is a fixed width and `{:>10}` does not truncate,
    /// so an over-long label pushes its own row's value out of line with every
    /// other field's. Checked by rendering, because the layout is the thing
    /// that breaks — not the string.
    #[test]
    fn every_form_row_aligns_its_value_at_the_same_column() {
        use crate::app::form::HostForm;

        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.auth_choice = 1; // the widest form: every field visible
        form.name = "n".into();
        form.address = "a".into();
        form.user = "u".into();
        form.tags = "t".into();
        form.key_path = "k".into();
        form.jump = "j".into();
        app.form = Some(form);
        app.mode = Mode::Form;

        let out = draw(&app, 100, 24);
        // Taken from the form rather than written out here: the field list
        // differs by platform and changes as fields are added, and a stale
        // literal list would quietly stop covering the new ones.
        let labels: Vec<&str> = app
            .form
            .as_ref()
            .unwrap()
            .fields()
            .iter()
            .map(|f| f.label())
            .collect();

        // Matched on the *padded* label rather than the bare word: "user" and
        // "name" also appear in the host table behind the popup, and a looser
        // match picks those rows up and fails on a layout that is fine.
        let columns: Vec<(&str, usize)> = labels
            .iter()
            .map(|label| {
                let padded = format!("{label:>10}  ");
                let start = out
                    .find(&padded)
                    .unwrap_or_else(|| panic!("no form row for {label}:\n{out}"));
                let line_start = out[..start].rfind('\n').map_or(0, |n| n + 1);
                (*label, start + padded.len() - line_start)
            })
            .collect();

        let distinct: std::collections::HashSet<usize> =
            columns.iter().map(|(_, col)| *col).collect();
        assert_eq!(
            distinct.len(),
            1,
            "values start at different columns {columns:?}:\n{out}"
        );
    }

    /// The scrollbar's track is the same `│` the border already draws, so the
    /// thumb is the only thing that distinguishes one from the other — and the
    /// only thing worth asserting on.
    fn thumb_rows(app: &App, width: u16, height: u16) -> Vec<usize> {
        thumb_rows_at(app, width, height, width as usize - 1)
    }

    /// The same, for a panel whose right border is not the screen's.
    fn thumb_rows_at(app: &App, width: u16, height: u16, x: usize) -> Vec<usize> {
        let out = draw(app, width, height);
        out.lines()
            .enumerate()
            .filter(|(_, line)| line.chars().nth(x) == Some('█'))
            .map(|(y, _)| y)
            .collect()
    }

    /// A track that is always full says only "there is a list", which is
    /// already visible, and costs a column of border to say it.
    #[test]
    fn no_scrollbar_when_the_whole_list_fits() {
        let app = app_with((0..3).map(|i| host(&format!("h{i}"))).collect());
        assert!(
            thumb_rows(&app, 100, 24).is_empty(),
            "a scrollbar was drawn for a list that fits:\n{}",
            draw(&app, 100, 24)
        );
    }

    /// The whole point: with more hosts than rows, say so.
    #[test]
    fn the_scrollbar_appears_once_the_list_overflows() {
        let app = app_with((0..60).map(|i| host(&format!("h{i}"))).collect());
        assert!(
            !thumb_rows(&app, 100, 24).is_empty(),
            "no scrollbar on a 60-host list in 24 rows:\n{}",
            draw(&app, 100, 24)
        );
    }

    /// An indicator that does not move is decoration. Selecting the last host
    /// must put the thumb somewhere the first host does not.
    #[test]
    fn the_thumb_tracks_the_selection() {
        let mut app = app_with((0..60).map(|i| host(&format!("h{i}"))).collect());

        let top = thumb_rows(&app, 100, 24);
        app.selected = 59;
        let bottom = thumb_rows(&app, 100, 24);

        assert!(!top.is_empty() && !bottom.is_empty(), "no thumb drawn");
        assert!(
            top.iter().max() < bottom.iter().min(),
            "thumb did not move: top {top:?}, bottom {bottom:?}"
        );
    }

    /// The track has to line up with the rows it describes, at both ends.
    ///
    /// Asserted against the rows themselves rather than against fixed line
    /// numbers: the panel's chrome is exactly what this can get wrong, so a
    /// hard-coded row number moves in step with the bug and pins nothing. An
    /// earlier version of this test passed with the chrome count off by one.
    #[test]
    fn the_track_lines_up_with_the_host_rows() {
        let out_at = |app: &App| draw(app, 100, 24);
        let row_of = |out: &str, name: &str| {
            out.lines()
                .position(|line| line.contains(name))
                .unwrap_or_else(|| panic!("{name} is not on screen:\n{out}"))
        };

        // Scrolled to the top: the thumb starts on the first visible host.
        let app = app_with((0..60).map(|i| host(&format!("h{i}"))).collect());
        let out = out_at(&app);
        let top = thumb_rows(&app, 100, 24);
        assert_eq!(
            top.iter().min().copied(),
            Some(row_of(&out, "h0")),
            "thumb does not start on the first row:\n{out}"
        );

        // Scrolled to the bottom: it ends on the last one. A thumb measured
        // against the item count instead of the scrollable range stops short
        // here, leaving a fully scrolled list looking like it has more below.
        let mut app = app_with((0..60).map(|i| host(&format!("h{i}"))).collect());
        app.selected = 59;
        let out = out_at(&app);
        let bottom = thumb_rows(&app, 100, 24);
        assert_eq!(
            bottom.iter().max().copied(),
            Some(row_of(&out, "h59")),
            "thumb does not reach the last row:\n{out}"
        );
    }

    /// Each of the three scrolling lists has a different number of chrome rows
    /// above its first item — one, two and three — so each needs its own
    /// alignment check. Getting this wrong is silent: the bar still renders,
    /// just describing rows that are not where it says they are.
    #[test]
    fn the_sidebar_track_lines_up_with_the_categories() {
        // The sidebar is 22 columns wide, so its border is not the screen's.
        const SIDEBAR_BORDER: usize = 21;

        let hosts: Vec<Host> = (0..30)
            .map(|i| {
                let mut h = host(&format!("h{i}"));
                h.tags = vec![format!("tag{i:02}")];
                h
            })
            .collect();
        let app = app_with(hosts);

        let out = draw(&app, 100, 24);
        let rows = thumb_rows_at(&app, 100, 24, SIDEBAR_BORDER);
        assert!(!rows.is_empty(), "no sidebar scrollbar on 30 tags:\n{out}");

        let all_hosts_row = out
            .lines()
            .position(|line| line.contains("all hosts"))
            .expect("the 'all hosts' row is always first");
        assert_eq!(
            rows.iter().min().copied(),
            Some(all_hosts_row),
            "sidebar thumb does not start on the first category row:\n{out}"
        );
    }

    #[test]
    fn the_picker_track_lines_up_with_the_entries() {
        use crate::app::picker::FilePicker;

        let root = std::env::temp_dir().join("luvienne-ui-picker-scroll");
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        for i in 0..40 {
            std::fs::write(root.join(format!("file{i:02}")), "x").unwrap();
        }

        let mut app = app_with(vec![]);
        app.picker = Some(FilePicker::open(&root.display().to_string()));
        app.mode = Mode::FilePicker;

        // The popup is 72 wide, centred in 100 columns.
        let popup_x = (100 - 72) / 2;
        let out = draw(&app, 100, 24);
        let rows = thumb_rows_at(&app, 100, 24, popup_x + 71);
        assert!(!rows.is_empty(), "no picker scrollbar on 40 files:\n{out}");

        // `..` leads every listing except the filesystem root.
        let first_entry_row = out
            .lines()
            .position(|line| line.contains(".."))
            .expect("every listing leads with a .. row");
        assert_eq!(
            rows.iter().min().copied(),
            Some(first_entry_row),
            "picker thumb does not start on the first entry:\n{out}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// The bug: a wide window with room to spare still cut the name off,
    /// because the column was a fixed width and the columns beside it — all
    /// `Min` constraints — absorbed every spare column.
    #[test]
    fn a_long_name_is_shown_in_full_when_there_is_room() {
        let long = "Defenders Matrix Med Prod Workers";
        let app = app_with(vec![host(long), host("short")]);

        let out = draw(&app, 140, 12);
        assert!(
            out.contains(long),
            "the name is still truncated on a 140-column window:\n{out}"
        );
    }

    /// But not at the cost of the columns beside it.
    ///
    /// This pins an assumption about **ratatui**, not about our arithmetic:
    /// nothing here caps the requested width, because the solver holds a `Min`
    /// column at its minimum against an oversized `Length` on its own. If a
    /// ratatui upgrade ever changed that, one absurd name would push
    /// `destination` off the edge for every host, and this is what would say so.
    #[test]
    fn one_absurd_name_does_not_squeeze_the_other_columns() {
        let app = app_with(vec![host(&"x".repeat(300)), host("web-01")]);

        let out = draw(&app, 100, 12);
        assert!(
            out.contains("deploy@10.0.0.1:22"),
            "destination was squeezed out by a 300-character name:\n{out}"
        );
    }

    /// The filter is the primary way around this app, so the table must not
    /// resize while one is being typed — the other columns would slide
    /// sideways on every keystroke. Sizing to the visible list does exactly
    /// that, which is why the width comes from the whole inventory.
    #[test]
    fn filtering_does_not_resize_the_table() {
        let mut app = app_with(vec![
            host("Defenders Matrix Med Prod Workers"),
            host("web-01"),
        ]);

        // Where `destination` starts is the name column's width made visible.
        let column_of_destination = |app: &App| {
            let out = draw(app, 140, 12);
            out.lines()
                .find_map(|line| line.find("destination"))
                .expect("the header is always drawn")
        };

        let unfiltered = column_of_destination(&app);
        app.filter = "web".into();
        assert_eq!(
            column_of_destination(&app),
            unfiltered,
            "the columns moved when a filter narrowed the list to short names"
        );
    }

    /// And it gives space back. Short names should not reserve 22 columns.
    #[test]
    fn short_names_do_not_reserve_a_wide_column() {
        assert!(
            name_column_width(4) < name_column_width(30),
            "the column does not shrink for short names"
        );
    }

    /// The header is `"  name"`, and a column narrower than that clips it —
    /// confirmed by rendering one-character names, which produced `n`.
    #[test]
    fn the_name_column_never_clips_its_own_header() {
        for longest in [0usize, 1, 2, 3, 4, usize::MAX] {
            let w = name_column_width(longest);
            assert!(w >= 6, "width {w} for a longest name of {longest}");
        }
    }

    /// Typing past the edge of a field used to be invisible: the characters
    /// landed in the buffer, the display stopped changing, and there was no way
    /// to tell a key path with a typo from one without. The **end** is what has
    /// to stay on screen, because that is where the caret always is.
    #[test]
    fn a_long_value_shows_its_end_not_its_beginning() {
        use crate::app::form::{Field, HostForm};

        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.auth_choice = 1;
        form.key_path = "/Users/someone/Documents/Clients/somewhere/deep/private-key.ppk".into();
        form.focus = form
            .fields()
            .iter()
            .position(|f| *f == Field::KeyPath)
            .unwrap();
        app.form = Some(form);
        app.mode = Mode::Form;

        let out = draw(&app, 100, 24);
        assert!(
            out.contains("private-key.ppk"),
            "the end of the path is not visible:\n{out}"
        );
        assert!(out.contains('…'), "nothing says the value was cut:\n{out}");
    }

    /// The caret is the casualty of rendering the value in full: ratatui clips
    /// at the widget boundary, so the overflow is never visible as content
    /// running past the border — instead the `▌` that follows the value is
    /// pushed off the edge and silently dropped. You are then typing into a
    /// field with no caret and no visible change.
    ///
    /// An earlier version of this test looked for content past the border and
    /// passed against the unfixed code, because that is not what the bug looks
    /// like.
    #[test]
    fn the_caret_stays_visible_however_long_the_value_is() {
        use crate::app::form::{Field, HostForm};

        for width in [40u16, 64, 100, 140] {
            let mut app = app_with(vec![]);
            let mut form = HostForm::add();
            form.auth_choice = 1;
            form.key_path = "/very/long/path/segment/".repeat(20);
            form.focus = form
                .fields()
                .iter()
                .position(|f| *f == Field::KeyPath)
                .unwrap();
            app.form = Some(form);
            app.mode = Mode::Form;

            let out = draw(&app, width, 24);
            assert!(
                out.contains('▌'),
                "the caret was pushed off the edge at width {width}:\n{out}"
            );
        }
    }

    /// A field short enough to fit is left exactly as it is — no marker, no
    /// truncation.
    #[test]
    fn a_short_value_is_untouched() {
        assert_eq!(visible_tail("web-01", 40), "web-01");
        assert_eq!(visible_tail("", 40), "");
        // Exactly filling the space is not overflow.
        assert_eq!(visible_tail("abcde", 5), "abcde");
    }

    /// Degenerate widths must not panic or slice a character in half.
    #[test]
    fn the_tail_survives_a_window_with_no_room() {
        assert_eq!(visible_tail("abcdef", 0), "");
        assert_eq!(visible_tail("abcdef", 1), "…");
        assert_eq!(visible_tail("abcdef", 2), "…f");
        // Multi-byte characters are counted, not sliced.
        assert_eq!(visible_tail("aéîöü", 3), "…öü");
    }

    /// Every text input paints its own caret after the value, so every one of
    /// them loses it when the value fills the row. Fixing the form fields and
    /// stopping there would have left the two inputs used most often — the
    /// filter and the passphrase prompt — still going blind as you type.
    #[test]
    fn every_text_input_keeps_its_caret_when_the_value_is_long() {
        let mut app = app_with(vec![]);
        app.mode = Mode::Filter;
        app.filter = "f".repeat(200);
        let out = draw(&app, 60, 24);
        assert!(out.contains('\u{258C}'), "filter caret lost:\n{out}");

        // The secret prompt, whose label is server-supplied and any length.
        let mut app = app_with(vec![]);
        let _rx = arm(
            &mut app,
            ssh::SecretKind::Passphrase,
            false,
            false,
            &"x".repeat(200),
        );
        let out = draw(&app, 100, 24);
        assert!(out.contains('\u{258C}'), "secret prompt caret lost:\n{out}");
        assert!(
            !out.contains("xxxx"),
            "a long secret must still be masked:\n{out}"
        );

        // An empty field whose *placeholder* is longer than the row.
        use crate::app::form::{Field, HostForm};
        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.focus = form
            .fields()
            .iter()
            .position(|f| *f == Field::Jump)
            .unwrap();
        app.form = Some(form);
        app.mode = Mode::Form;
        let out = draw(&app, 44, 24);
        assert!(
            out.contains('\u{258C}'),
            "caret lost behind a placeholder:\n{out}"
        );
    }

    /// Width is measured in display columns, not characters. A CJK character
    /// takes two columns, so counting characters keeps twice as much text as
    /// fits — the same overflow, one metric further down.
    #[test]
    fn a_wide_character_counts_as_the_two_columns_it_occupies() {
        assert_eq!(
            display_width(&visible_tail("\u{5BFD}\u{5BFD}\u{5BFD}\u{5BFD}", 5)),
            5
        );
        assert_eq!(
            display_width(&visible_head("\u{5BFD}\u{5BFD}\u{5BFD}\u{5BFD}", 5)),
            5
        );

        use crate::app::form::HostForm;
        let mut app = app_with(vec![]);
        let mut form = HostForm::add();
        form.name = "\u{5BFD}".repeat(60);
        form.focus = 0;
        app.form = Some(form);
        app.mode = Mode::Form;

        let out = draw(&app, 100, 24);
        assert!(
            out.contains('\u{258C}'),
            "wide characters pushed the caret off the row:\n{out}"
        );
    }

    /// Hints are read left to right and never edited, so they keep their start
    /// — the opposite end from a value, whose caret lives at its end.
    #[test]
    fn a_clipped_hint_keeps_its_beginning() {
        assert_eq!(visible_head("name of a host", 8), "name of\u{2026}");
        assert_eq!(visible_head("short", 40), "short");
        assert_eq!(visible_head("abcdef", 1), "\u{2026}");
        assert_eq!(visible_head("abcdef", 0), "");
    }

    #[test]
    fn the_picker_lists_entries_and_marks_directories() {
        use crate::app::picker::FilePicker;

        let root = std::env::temp_dir().join("luvienne-ui-picker");
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("id_test.ppk"), "x").unwrap();

        let mut app = app_with(vec![]);
        app.picker = Some(FilePicker::open(&root.display().to_string()));
        app.mode = Mode::FilePicker;

        let out = draw(&app, 100, 24);
        assert!(out.contains("choose a key file"));
        assert!(
            out.contains("keys/"),
            "directories get a trailing slash:\n{out}"
        );
        assert!(out.contains("id_test.ppk"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn passphrase_is_masked_in_the_rendered_buffer() {
        let secret = "correct-horse-battery-staple";
        let mut app = app_with(vec![host("web-01")]);
        let _keep = arm(&mut app, ssh::SecretKind::Passphrase, false, false, secret);

        let out = draw(&app, 100, 24);

        assert!(
            !out.contains(secret),
            "passphrase leaked into the UI:\n{out}"
        );
        assert!(!out.contains("correct"), "not even a prefix may appear");
        assert!(
            out.contains(&"•".repeat(secret.chars().count())),
            "one bullet per character:\n{out}"
        );
    }

    /// Same masking rule for passwords. The modal is shared, so a regression in
    /// one is a regression in both.
    #[test]
    fn password_is_masked_in_the_rendered_buffer() {
        let secret = "s3cret-server-password";
        let mut app = app_with(vec![host("web-01")]);
        let _keep = arm(&mut app, ssh::SecretKind::Password, false, false, secret);

        let out = draw(&app, 100, 24);

        assert!(!out.contains(secret), "password leaked into the UI:\n{out}");
        assert!(out.contains("password"), "titled as a password");
        assert!(
            out.contains("deploy@10.0.0.1"),
            "says who it is authenticating"
        );
    }

    /// Keyboard-interactive prompts may ask for something that is not secret,
    /// and the server says so via `echo`. Honouring it is what makes a
    /// "Verification code" or "Username" challenge usable.
    #[test]
    fn an_echo_prompt_shows_what_is_typed() {
        let mut app = app_with(vec![host("web-01")]);
        let _keep = arm(&mut app, ssh::SecretKind::Password, true, false, "123456");

        let out = draw(&app, 100, 24);
        assert!(out.contains("123456"), "echo prompts are visible:\n{out}");
        assert!(!out.contains("••••"), "and not masked");
    }

    /// A username is not a secret. Masking it would make it needlessly hard to
    /// type, and it shares a modal with two things that *must* be masked — so
    /// the distinction is worth pinning.
    #[test]
    fn a_username_prompt_is_visible_not_masked() {
        let mut app = app_with(vec![host("web-01")]);
        let _keep = arm(&mut app, ssh::SecretKind::Username, true, false, "deploy");

        let out = draw(&app, 100, 24);
        assert!(
            out.contains("deploy"),
            "the username should be visible:\n{out}"
        );
        assert!(!out.contains("••"), "and never bulleted");
        assert!(out.contains("username"), "titled as a username");
    }

    #[test]
    fn secret_retry_says_the_previous_one_was_rejected() {
        let mut app = app_with(vec![host("web-01")]);
        let _keep = arm(&mut app, ssh::SecretKind::Password, false, true, "");

        let out = draw(&app, 100, 24);
        assert!(out.contains("rejected"), "got:\n{out}");
    }

    /// The fingerprint must be legible in full — a truncated one is useless for
    /// out-of-band verification, which is the entire point of the prompt.
    #[test]
    fn host_key_prompt_shows_the_full_fingerprint() {
        use crate::app::PendingHostKey;
        let fingerprint = "SHA256:uNiVuvpJ7Cv5rE4RxLcJ0aVoJZgAqhTPHVJ2sPWlaBc";

        let mut app = app_with(vec![host("web-01")]);
        let (reply, _answer) = tokio::sync::oneshot::channel();
        app.mode = Mode::ConfirmHostKey;
        app.host_key_prompt = Some(PendingHostKey::for_test("10.0.0.1", fingerprint, reply));

        let out = draw(&app, 100, 24);
        assert!(out.contains(fingerprint), "got:\n{out}");
        assert!(out.contains("not in known_hosts"));
        assert!(out.contains("accept and remember"));
    }

    /// Entering the alternate screen does not clear the terminal's SGR state, and
    /// `Theme::base` sets no background on purpose — so a remote program that
    /// paints its own background and exits without resetting (`mc`, blue) leaves
    /// us drawing the host list on *its* background. The reset has to come after
    /// we retake the screen, or there is nothing to reset yet.
    #[test]
    fn resume_resets_colour_after_retaking_the_screen() {
        let mut out = Vec::new();
        super::resume_to(&mut out).unwrap();
        let seq = String::from_utf8(out).unwrap();

        let enter = seq
            .find("\x1b[?1049h")
            .expect("does not enter the alternate screen");
        let reset = seq.find("\x1b[0m").expect("does not reset colour");
        assert!(
            reset > enter,
            "reset must follow entering the screen, got {seq:?}"
        );
    }

    /// The mirror case. Only a *first* attach prints the "ctrl-] detaches"
    /// banner, which ends in a reset — so on a resume this is the only thing
    /// stopping our styling bleeding into the remote's first output.
    #[test]
    fn suspend_resets_colour_before_handing_the_terminal_over() {
        let mut out = Vec::new();
        super::suspend_to(&mut out).unwrap();
        let seq = String::from_utf8(out).unwrap();

        let leave = seq
            .find("\x1b[?1049l")
            .expect("does not leave the alternate screen");
        let reset = seq.find("\x1b[0m").expect("does not reset colour");
        assert!(
            reset < leave,
            "reset must precede handing the terminal over, got {seq:?}"
        );
    }

    #[test]
    fn session_list_renders_active_sessions() {
        let mut app = app_with(vec![]);
        app.sessions.push(ssh::LiveSession::for_test("alpha").0);
        app.sessions.push(ssh::LiveSession::for_test("beta").0);
        app.mode = Mode::SessionList;

        let out = draw(&app, 100, 24);
        assert!(out.contains("sessions (2)"), "title with count:\n{out}");
        assert!(out.contains("alpha"), "first session shown:\n{out}");
        assert!(out.contains("beta"), "second session shown:\n{out}");
        assert!(out.contains("detached"), "state shown:\n{out}");
    }

    /// Two sessions on one host have to be told apart, and a lone session must
    /// not be numbered for no reason.
    #[test]
    fn several_sessions_on_one_host_are_numbered() {
        let mut app = app_with(vec![]);
        app.sessions.push(ssh::LiveSession::for_test("web-01").0);
        app.sessions
            .push(ssh::LiveSession::for_test("db-primary").0);
        app.sessions.push(ssh::LiveSession::for_test("web-01").0);
        app.mode = Mode::SessionList;

        let out = draw(&app, 100, 24);
        assert!(out.contains("web-01 #1"), "first web-01 unnumbered:\n{out}");
        assert!(
            out.contains("web-01 #2"),
            "second web-01 unnumbered:\n{out}"
        );
        assert!(
            !out.contains("db-primary #"),
            "numbered a host with one session:\n{out}"
        );
    }

    #[test]
    fn session_list_shows_a_hint_when_empty() {
        let mut app = app_with(vec![]);
        app.mode = Mode::SessionList;

        let out = draw(&app, 100, 24);
        assert!(out.contains("no active sessions"), "got:\n{out}");
    }

    #[test]
    fn session_list_header_hints_resume_and_back() {
        let mut app = app_with(vec![]);
        app.sessions.push(ssh::LiveSession::for_test("alpha").0);
        app.mode = Mode::SessionList;

        let out = draw(&app, 100, 24);
        assert!(out.contains("resume session"), "got:\n{out}");
        assert!(out.contains("esc back to hosts"), "got:\n{out}");
    }

    /// The same scrolling rule as the host list: the selected item must stay
    /// on screen when the list overflows.
    #[test]
    fn the_selected_session_stays_visible_when_the_list_overflows() {
        let mut app = app_with(vec![]);
        for i in 0..40 {
            app.sessions
                .push(ssh::LiveSession::for_test(&format!("session-{i:02}")).0);
        }
        app.mode = Mode::SessionList;

        for selected in [0usize, 5, 20, 38, 39] {
            app.session_selected = selected;
            let out = draw(&app, 100, 24);
            let name = format!("session-{selected:02}");
            assert!(
                out.contains(&name),
                "selected {name} is not on screen:\n{out}"
            );
        }
    }
}
