//! Application state and the event loop.
//!
//! The loop must never block. Terminal input is polled with a short timeout and
//! SSH progress arrives on a channel that is drained with `try_recv`. Anything
//! that could take more than a frame — DNS, key decryption, the handshake — runs
//! on the tokio runtime and reports back through [`SshEvent`].

pub mod form;
pub mod input;
pub mod picker;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use color_eyre::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Rect;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::config::{Host, Inventory};
use crate::ssh::{self, SshEvent};
use crate::ui;
use form::{Field, FormMode, HostForm};
use picker::FilePicker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Navigating the host list.
    Browse,
    /// Typing into the fuzzy filter.
    Filter,
    /// Help overlay is up.
    Help,
    /// Blocking on the user's answer to an unknown host key. A background task
    /// is parked on the oneshot in [`App::host_key_prompt`] until this resolves.
    ConfirmHostKey,
    /// Typing a secret — a key passphrase, a password, or a keyboard-interactive
    /// answer. Input is never rendered, logged, or stored beyond the pending
    /// prompt, and is masked unless the server explicitly asked for echo.
    Secret,
    /// Adding or editing a host.
    Form,
    /// Confirming a delete.
    ConfirmDelete,
    /// Browsing the filesystem for a key file. Returns to `Form` either way.
    FilePicker,
    /// Confirming a PuTTY import.
    ConfirmImport,
    /// Browsing active detached sessions.
    SessionList,
    /// Typing an `ssh`-style target to reach once, without saving it.
    QuickConnect,
    /// Confirming that a session should be disconnected.
    ConfirmClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Up,
    Down,
    Connect,
    StartFilter,
    ClearFilter,
    CycleTag,
    ToggleHelp,
    AddHost,
    EditHost,
    DeleteHost,
    ImportPutty,
    BulkEdit,
    ShowSessions,
    NewSession,
    QuickConnect,
    CloseSession,
}

/// The one place key bindings are declared. Dispatch reads it and so does the
/// help overlay, so the two cannot drift apart. Add new bindings here, not in a
/// `match` somewhere else.
///
/// Order matters for the footer: it is truncated at the window width, so the
/// entries that must survive truncation — help above all, since it lists the
/// rest — come first.
pub const BINDINGS: &[(KeyCode, &str, &str, Action)] = &[
    (KeyCode::Char('?'), "?", "help", Action::ToggleHelp),
    (KeyCode::Char('q'), "q", "quit", Action::Quit),
    (KeyCode::Char('k'), "k/↑", "move up", Action::Up),
    (KeyCode::Up, "", "move up", Action::Up),
    (KeyCode::Char('j'), "j/↓", "move down", Action::Down),
    (KeyCode::Down, "", "move down", Action::Down),
    (KeyCode::Enter, "↵", "connect", Action::Connect),
    (KeyCode::Char('/'), "/", "filter", Action::StartFilter),
    (KeyCode::Char('t'), "t", "cycle tag", Action::CycleTag),
    (
        KeyCode::Esc,
        "esc",
        "cancel / clear filter",
        Action::ClearFilter,
    ),
    (KeyCode::Char('a'), "a", "add host", Action::AddHost),
    (KeyCode::Char('e'), "e", "edit host", Action::EditHost),
    (KeyCode::Char('d'), "d", "delete host", Action::DeleteHost),
    (KeyCode::Char('i'), "i", "import hosts", Action::ImportPutty),
    (KeyCode::Char('b'), "b", "bulk edit shown", Action::BulkEdit),
    (KeyCode::Char('s'), "s", "sessions", Action::ShowSessions),
    (KeyCode::Char('n'), "n", "new session", Action::NewSession),
    (
        KeyCode::Char('c'),
        "c",
        "quick connect",
        Action::QuickConnect,
    ),
    // Not `d`: that deletes a host two rows up in this table, and muscle memory
    // should not be able to delete an inventory entry when you meant to drop a
    // connection.
    (
        KeyCode::Char('x'),
        "x",
        "disconnect session",
        Action::CloseSession,
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Idle,
    Busy(String),
    Ok(String),
    Error(String),
}

/// An unknown host key waiting on the user. Dropping this without sending
/// refuses the connection, which is the behaviour we want on any unexpected path.
pub struct PendingHostKey {
    pub host: String,
    pub fingerprint: String,
    /// Private on purpose: the only way to answer is `App::answer_host_key`,
    /// which takes the whole struct, so a prompt cannot be answered twice.
    reply: oneshot::Sender<bool>,
}

#[cfg(test)]
impl PendingHostKey {
    pub fn for_test(host: &str, fingerprint: &str, reply: oneshot::Sender<bool>) -> Self {
        Self {
            host: host.into(),
            fingerprint: fingerprint.into(),
            reply,
        }
    }
}

/// A secret the connect task is waiting on. Dropping this without sending
/// cancels the connect, which is the behaviour we want on any unexpected path.
pub struct PendingSecret {
    pub request: ssh::SecretRequest,
    reply: oneshot::Sender<Option<Zeroizing<String>>>,
}

#[cfg(test)]
impl PendingSecret {
    pub fn for_test(
        request: ssh::SecretRequest,
        reply: oneshot::Sender<Option<Zeroizing<String>>>,
    ) -> Self {
        Self { request, reply }
    }
}

pub struct App {
    pub inventory: Inventory,
    /// Where the inventory is read from and written back to. Held explicitly so
    /// load and save cannot disagree, and so tests never touch the real config.
    inventory_path: PathBuf,
    pub mode: Mode,
    pub filter: String,
    /// Index into the *visible* host list, not into `inventory.hosts`.
    pub selected: usize,
    /// Index into `sessions` for the dedicated session list view.
    pub session_selected: usize,
    /// Which session the terminal last belonged to, by id.
    ///
    /// Attaching a *different* one has to clear the screen first; see
    /// [`ssh::attach`]. Kept by id rather than index because rows shift as
    /// sessions end.
    last_attached: Option<u64>,
    /// What has been typed into quick connect. Not a secret and not saved.
    pub quick_input: String,
    /// Caret positions for the two single-line inputs, in characters.
    ///
    /// Clamped on every use, so a value replaced wholesale — or assigned by a
    /// test — cannot strand them past the end.
    pub filter_cursor: usize,
    pub quick_cursor: usize,
    /// The session a close is waiting on, by id.
    ///
    /// By id rather than index for the usual reason: a session ending while the
    /// prompt is up shifts the rows, and confirming would then close whichever
    /// session slid into that slot.
    pub pending_close: Option<u64>,
    /// Whether the close prompt was raised from the session list.
    ///
    /// Confirming goes back there while sessions remain: closing several is the
    /// point of the feature, and being dumped on the host list after each one
    /// means pressing `s` again to reach the next.
    close_from_list: bool,
    pub tag_filter: Option<String>,
    pub status: Status,
    pub host_key_prompt: Option<PendingHostKey>,
    /// The add/edit form, present only in `Mode::Form`.
    pub form: Option<HostForm>,
    /// Index into `inventory.hosts` of a host awaiting delete confirmation.
    pub pending_delete: Option<usize>,
    /// The file browser, present only in `Mode::FilePicker`.
    pub picker: Option<FilePicker>,
    /// Scanned imports awaiting confirmation, one per source that had anything.
    pub pending_import: Vec<crate::import::Imported>,
    pub secret_prompt: Option<PendingSecret>,
    /// The secret being typed. `Zeroizing` so it is wiped on every clear and on
    /// drop; unless the prompt asked for echo, the UI renders its *length* only.
    pub secret_input: Zeroizing<String>,
    /// Set when the main loop should attach on its next pass — either a fresh
    /// connect or a resume. Attaching happens in the foreground because it needs
    /// the terminal, and the terminal belongs to the render loop.
    pending_attach: Option<usize>,
    /// Sessions that are still running, attached or not. Indexed into by
    /// `pending_attach`.
    pub sessions: Vec<ssh::LiveSession>,
    /// Connects in flight, by host name, with the handle needed to abort them.
    ///
    /// Two jobs: without it, holding Enter opens a second connection to the same
    /// host — and a third — each with its own prompts; and without the join
    /// handle there is no way to give up on a host that is simply not answering.
    connecting: HashMap<String, tokio::task::JoinHandle<()>>,
    should_quit: bool,
    runtime: tokio::runtime::Handle,
    tx: UnboundedSender<SshEvent>,
    rx: UnboundedReceiver<SshEvent>,
}

/// What a run left for `main` to tidy up.
///
/// Returned rather than queried because `run` consumes the app, and the tidying
/// has to happen *after* ratatui has left the alternate screen — there is no
/// `App` left by then.
pub struct Outcome {
    /// Whether any session took over the primary screen and left output on it.
    /// False for a browse-only run, which leaves no trace to clean up.
    pub wrote_to_the_screen: bool,
}

impl App {
    pub fn new(
        inventory: Inventory,
        inventory_path: PathBuf,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            inventory,
            inventory_path,
            mode: Mode::Browse,
            filter: String::new(),
            selected: 0,
            session_selected: 0,
            last_attached: None,
            quick_input: String::new(),
            filter_cursor: 0,
            quick_cursor: 0,
            pending_close: None,
            close_from_list: false,
            tag_filter: None,
            status: Status::Idle,
            host_key_prompt: None,
            form: None,
            pending_delete: None,
            picker: None,
            pending_import: Vec::new(),
            secret_prompt: None,
            secret_input: Zeroizing::new(String::new()),
            pending_attach: None,
            sessions: Vec::new(),
            connecting: HashMap::new(),
            should_quit: false,
            runtime,
            tx,
            rx,
        }
    }

    pub fn run(mut self, terminal: &mut DefaultTerminal) -> Result<Outcome> {
        // Redraw only when something actually changed. Painting every pass
        // costs a few percent of a core around the clock for a UI that is
        // usually just sitting there, and this app is meant to stay open.
        let mut dirty = true;

        while !self.should_quit {
            // State first, then paint, so a change is never a frame late.
            dirty |= self.prune_dead_sessions();
            dirty |= self.drain_background();

            // Attaching takes over the terminal, so it runs here rather than on
            // the runtime — the render loop is paused for its whole duration.
            if let Some(index) = self.pending_attach.take() {
                self.attach(terminal, index)?;
                dirty = true;
            }

            if dirty {
                terminal.draw(|frame| ui::render(&self, frame))?;
                dirty = false;
            }

            // Short poll rather than a blocking read: background SSH events
            // still need to reach the screen when the user isn't typing.
            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        self.on_key(key);
                        dirty = true;
                    }
                    // Gating the draw means resizes must mark the frame dirty
                    // themselves; nothing else will notice the new size.
                    Event::Resize(..) => dirty = true,
                    _ => {}
                }
            }
        }
        Ok(Outcome {
            // `last_attached` is set by every attach and never cleared, so it is
            // exactly the question being asked: did a session ever hold the
            // primary screen?
            wrote_to_the_screen: self.last_attached.is_some(),
        })
    }

    /// Positions in `inventory.hosts` of the hosts currently shown.
    ///
    /// The single source of truth for filtering. `selected` indexes *this* list,
    /// so editing and deleting have to come back through here to find the real
    /// inventory position — with a filter active the two differ, and using the
    /// visible index directly would edit the wrong host.
    pub fn visible_indices(&self) -> Vec<usize> {
        self.inventory
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| match &self.tag_filter {
                Some(tag) => h.tags.contains(tag),
                None => true,
            })
            .filter(|(_, h)| h.matches(&self.filter))
            .map(|(i, _)| i)
            .collect()
    }

    /// Hosts matching the current tag and fuzzy filter, in inventory order.
    pub fn visible(&self) -> Vec<&Host> {
        self.visible_indices()
            .into_iter()
            .filter_map(|i| self.inventory.hosts.get(i))
            .collect()
    }

    pub fn selected_host(&self) -> Option<&Host> {
        self.visible().get(self.selected).copied()
    }

    /// Where the selected host actually lives in the inventory.
    fn selected_inventory_index(&self) -> Option<usize> {
        self.visible_indices().get(self.selected).copied()
    }

    /// Returns whether anything was received, so the caller knows to repaint.
    fn drain_background(&mut self) -> bool {
        let mut received = false;
        while let Ok(event) = self.rx.try_recv() {
            received = true;
            match event {
                SshEvent::Progress(msg) => self.status = Status::Busy(msg),
                SshEvent::Failed { host, message } => {
                    self.connecting.remove(&host);
                    self.status = Status::Error(message);
                }
                SshEvent::Ready(session) => {
                    self.connecting.remove(&session.host);
                    self.status = Status::Busy(format!("attaching to {}…", session.host));
                    self.sessions.push(*session);
                    self.pending_attach = Some(self.sessions.len() - 1);
                }
                SshEvent::HostKeyPrompt {
                    host,
                    fingerprint,
                    reply,
                } => {
                    self.mode = Mode::ConfirmHostKey;
                    self.host_key_prompt = Some(PendingHostKey {
                        host,
                        fingerprint,
                        reply,
                    });
                }
                SshEvent::SecretPrompt { request, reply } => {
                    self.mode = Mode::Secret;
                    self.secret_input.clear();
                    self.secret_prompt = Some(PendingSecret { request, reply });
                }
            }
        }
        received
    }

    /// Answer a pending secret prompt, or cancel it with `None`.
    ///
    /// The input buffer is cleared either way — `Zeroizing::clear` wipes it, so a
    /// secret never outlives the prompt that asked for it.
    fn answer_secret(&mut self, secret: Option<Zeroizing<String>>) {
        if let Some(pending) = self.secret_prompt.take() {
            let cancelled = secret.is_none();
            let _ = pending.reply.send(secret);
            if cancelled {
                self.status = Status::Error("cancelled".into());
            }
        }
        self.secret_input.clear();
        self.mode = Mode::Browse;
    }

    /// Suspend the TUI, run the session, restore the TUI.
    ///
    /// Raw mode stays enabled throughout — the remote shell needs unbuffered
    /// keystrokes — but we leave the alternate screen so the session scrolls in
    /// the user's normal buffer. The restore is unconditional: `attach`'s result
    /// is inspected only *after* the terminal is back, so an SSH failure can
    /// never strand the user in a half-suspended terminal.
    fn attach(&mut self, terminal: &mut DefaultTerminal, index: usize) -> Result<()> {
        let Some(session) = self.sessions.get(index) else {
            return Ok(());
        };
        let host = session.host.clone();

        // Name the window after the host while its session owns the terminal —
        // that is what you scan tabs for.
        let _ = ui::set_title(&format!("{host} — {}", ui::APP_TITLE));
        ui::suspend()?;

        // `attach` reads the window size itself via TIOCGWINSZ so it can also
        // pick up pixel dimensions and track later resizes.
        // Only when replacing *another session's* screen. On the very first
        // attach the leftover text is the user's own shell, which is context
        // rather than confusion — wiping it would be gratuitous.
        let switching = self.switching_to(session.id());
        let attached_id = session.id();
        let label = self.session_label(index);
        let result = self
            .runtime
            .block_on(ssh::attach(session, switching, &label));
        self.last_attached = Some(attached_id);

        ui::resume()?;
        let _ = ui::set_title(ui::APP_TITLE);

        // The alternate screen we just re-entered is already blank, so all that
        // is left is resetting ratatui's back buffer to force a full redraw.
        //
        // Deliberately *not* `Terminal::clear`: that asks the terminal for its
        // cursor position (DSR `ESC[6n`) and blocks waiting for a reply. Real
        // terminals answer, but some multiplexer configurations and every
        // headless harness do not — and it timed out in exactly that way during
        // testing, discarding a session that had otherwise succeeded. A cosmetic
        // repaint must never be able to fail a completed session. `resize` on a
        // fullscreen viewport resets the same buffers without asking.
        let size = terminal.size()?;
        terminal.resize(Rect::new(0, 0, size.width, size.height))?;

        // Read before the session can be removed below. A forward that never
        // came up has to be said *here*: the progress line that reported it was
        // replaced by "attaching…" seconds later, and a tunnel you believe in
        // but do not have is worse than one you know failed — you go on to use
        // the port and reach whatever else was listening on it.
        let forward_failures = self
            .sessions
            .get(index)
            .map(|s| s.forward_failures().to_vec())
            .unwrap_or_default();

        // A session that ended, or whose attach failed, must not stay in the
        // registry offering to resume something that is already gone.
        if !matches!(result, Ok(ssh::SessionOutcome::Detached)) {
            self.sessions.remove(index);
        }
        self.status = session_status(&result, &host, &forward_failures);
        Ok(())
    }

    /// Scan every source we know about and hold the results for confirmation.
    ///
    /// Scanning is separate from applying so the counts and caveats can be
    /// shown first — silently adding dozens of hosts to someone's config is not
    /// something to do on a single keystroke.
    fn scan_imports(&mut self) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        let mut already = 0;

        if let Some(dir) = crate::putty::sessions_dir() {
            match crate::putty::scan(&dir, &self.inventory.hosts) {
                Ok(import) => {
                    already += import.already_present;
                    if !import.is_empty() {
                        found.push(import);
                    }
                }
                Err(err) => errors.push(format!("{}: {err}", dir.display())),
            }
        }
        if let Some(path) = crate::sshconfig::config_path() {
            match crate::sshconfig::scan(&path, &self.inventory.hosts) {
                Ok(import) => {
                    already += import.already_present;
                    if !import.is_empty() {
                        found.push(import);
                    }
                }
                Err(err) => errors.push(format!("{}: {err}", path.display())),
            }
        }

        if !found.is_empty() {
            self.pending_import = found;
            self.mode = Mode::ConfirmImport;
        } else if !errors.is_empty() {
            self.status = Status::Error(format!("could not read {}", errors.join("; ")));
        } else if already > 0 {
            self.status = Status::Ok(format!("nothing new to import ({already} already present)"));
        } else {
            self.status = Status::Error("nothing to import from ~/.putty or ~/.ssh/config".into());
        }
    }

    fn apply_import(&mut self) {
        let sources = std::mem::take(&mut self.pending_import);
        self.mode = Mode::Browse;
        if sources.is_empty() {
            return;
        }

        let previous = self.inventory.hosts.clone();
        let mut added = 0;
        for source in sources {
            added += source.hosts.len();
            self.inventory.hosts.extend(source.hosts);
        }
        self.persist(previous, format!("imported {added} hosts"));
    }

    /// Abort any connects in flight. Returns whether there were any.
    ///
    /// Aborting drops the connect task mid-flight, which closes its half-open
    /// connection. If it was parked on a prompt, the oneshot receiver dies with
    /// it and the reply is discarded — the same path as answering "cancel".
    fn cancel_connects(&mut self) -> bool {
        if self.connecting.is_empty() {
            return false;
        }
        let names: Vec<String> = self.connecting.keys().cloned().collect();
        for (_, task) in self.connecting.drain() {
            task.abort();
        }
        self.status = Status::Error(match names.as_slice() {
            [one] => format!("cancelled connecting to {one}"),
            many => format!("cancelled {} connections", many.len()),
        });
        true
    }

    /// Index of the running session for a host, if there is one.
    ///
    /// Ended sessions are pruned here rather than polled: a detached session can
    /// die on its own (someone types `exit` elsewhere, the server reboots), and
    /// the list must not keep offering to resume it.
    pub fn session_for(&self, host: &str) -> Option<usize> {
        self.sessions
            .iter()
            .position(|s| s.host == host && !s.has_ended())
    }

    /// What to call one session, in a list where a host may hold several.
    ///
    /// Numbered by order of opening, and only where there is something to tell
    /// apart — a lone session should not read `web-01 #1`. Lives here rather
    /// than in the renderer because the rule drawn on a switch has to say the
    /// same thing the session list does; two spellings of the same session is
    /// worse than none.
    pub fn session_label(&self, index: usize) -> String {
        let Some(session) = self.sessions.get(index) else {
            return String::new();
        };
        let host = session.host.as_str();

        // Counts every row, including one that has just ended and not yet been
        // pruned — unlike `session_count`, which the `●` marker uses and which
        // means "resumable". They agree in practice because `prune_dead_sessions`
        // runs before any attach or render. Filtering here instead would number a
        // still-listed dead row as though it were absent, colliding with the next
        // live one.
        let total = self.sessions.iter().filter(|s| s.host == host).count();
        if total <= 1 {
            return host.to_string();
        }
        let nth = self.sessions[..=index]
            .iter()
            .filter(|s| s.host == host)
            .count();
        format!("{host} #{nth}")
    }

    /// How many live sessions this host holds.
    ///
    /// The host list shows it once there is more than one, because `↵` resumes
    /// the first and nothing else would say the others exist — `s` is how you
    /// reach them.
    pub fn session_count(&self, host: &str) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.host == host && !s.has_ended())
            .count()
    }

    /// Returns whether any session was removed, so the `●` markers get repainted.
    ///
    /// Says so when one goes. These are sessions that died while *detached* — a
    /// dropped connection, or a remote that closed the shell — and dropping the
    /// row silently means you press `s`, find nothing, and are left guessing.
    /// The foreground case is already reported by [`Self::attach`], which sees
    /// the outcome directly, so nothing is announced twice.
    fn prune_dead_sessions(&mut self) -> bool {
        let ended: Vec<String> = self
            .sessions
            .iter()
            .filter(|s| s.has_ended())
            .map(|s| s.host.clone())
            .collect();
        if ended.is_empty() {
            return false;
        }

        // A pending resume holds an *index*, and it was set on an earlier pass of
        // the loop — key handling runs after this. Dropping rows beneath it would
        // silently point it at a different session: ask for the second of three,
        // lose the first, attach the third. Remap before the retain, and give up
        // on it entirely if the session it named is the one that died.
        if let Some(pending) = self.pending_attach {
            self.pending_attach = match self.sessions.get(pending) {
                // Already stale; nothing to salvage.
                None => None,
                Some(session) if session.has_ended() => None,
                Some(_) => {
                    let gone_below = self.sessions[..pending]
                        .iter()
                        .filter(|s| s.has_ended())
                        .count();
                    Some(pending - gone_below)
                }
            };
        }

        self.sessions.retain(|s| !s.has_ended());
        self.clamp_session_selection();

        // `Error`, not `Ok`: a session you were relying on being there has gone,
        // which is the same reason the keepalive exists at all.
        self.status = Status::Error(match ended.as_slice() {
            [host] => format!("the session on {host} ended"),
            hosts => format!("{} sessions ended: {}", hosts.len(), hosts.join(", ")),
        });
        true
    }

    /// Answer a pending host key prompt. Taking the prompt out of `self` means a
    /// second answer cannot arrive for the same connection.
    fn answer_host_key(&mut self, accept: bool) {
        if let Some(pending) = self.host_key_prompt.take() {
            // Send failing means the connection already went away — nothing to do.
            let _ = pending.reply.send(accept);
            if !accept {
                self.status = Status::Error(format!("host key for {} refused", pending.host));
            }
        }
        self.mode = Mode::Browse;
    }

    fn on_key(&mut self, key: KeyEvent) {
        // Ctrl-C quits from any mode.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match self.mode {
            // In filter mode most keys are text, so the binding table doesn't apply.
            Mode::Filter => match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filter_cursor = 0;
                    self.mode = Mode::Browse;
                }
                KeyCode::Enter => self.mode = Mode::Browse,
                KeyCode::Left => input::left(&self.filter, &mut self.filter_cursor),
                KeyCode::Right => input::right(&self.filter, &mut self.filter_cursor),
                KeyCode::Home => self.filter_cursor = 0,
                KeyCode::End => self.filter_cursor = input::end(&self.filter),
                KeyCode::Delete => {
                    input::delete(&mut self.filter, self.filter_cursor);
                    self.clamp_selection();
                }
                KeyCode::Backspace => {
                    input::backspace(&mut self.filter, &mut self.filter_cursor);
                    self.clamp_selection();
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    input::insert(&mut self.filter, &mut self.filter_cursor, c);
                    self.clamp_selection();
                }
                _ => {}
            },
            // Explicit y/n only. Enter is deliberately not a yes — there is no
            // key that accepts an unknown host by reflex.
            Mode::ConfirmHostKey => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.answer_host_key(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.answer_host_key(false)
                }
                _ => {}
            },
            // Text entry. Deliberately no binding-table lookup: every printable
            // key is secret content, including 'q' and '/'.
            Mode::Secret => match key.code {
                KeyCode::Esc => self.answer_secret(None),
                KeyCode::Enter => {
                    let entered = std::mem::take(&mut *self.secret_input);
                    self.answer_secret(Some(Zeroizing::new(entered)));
                }
                KeyCode::Backspace => {
                    self.secret_input.pop();
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.secret_input.push(c)
                }
                _ => {}
            },
            Mode::ConfirmImport => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.apply_import(),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.pending_import.clear();
                    self.mode = Mode::Browse;
                }
                _ => {}
            },

            // Same rule as the host key prompt: explicit `y` only, so a delete
            // can never happen by reflex.
            Mode::ConfirmClose => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_close(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.confirm_close(false),
                _ => {}
            },

            Mode::ConfirmDelete => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_delete(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.confirm_delete(false)
                }
                _ => {}
            },

            // Text entry across several fields. No binding-table lookup: every
            // printable key belongs to whichever field has focus.
            Mode::Form => {
                let is_choice = self.form.as_ref().is_some_and(|f| f.focused().is_choice());
                match key.code {
                    KeyCode::Esc => self.close_form(),
                    // Browse for a key file. Only on the path field, so the
                    // chosen file has an unambiguous destination.
                    KeyCode::Char('o')
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && self
                                .form
                                .as_ref()
                                .is_some_and(|f| f.focused() == Field::KeyPath) =>
                    {
                        let current = self
                            .form
                            .as_ref()
                            .map(|f| f.key_path.clone())
                            .unwrap_or_default();
                        self.picker = Some(FilePicker::open(&current));
                        self.mode = Mode::FilePicker;
                    }
                    KeyCode::Enter => self.submit_form(),
                    KeyCode::Tab | KeyCode::Down => {
                        if let Some(form) = self.form.as_mut() {
                            form.next_field();
                        }
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        if let Some(form) = self.form.as_mut() {
                            form.prev_field();
                        }
                    }
                    // Text fields move the caret; only a selector cycles.
                    KeyCode::Left if !is_choice => {
                        if let Some(form) = self.form.as_mut() {
                            form.cursor_left();
                        }
                    }
                    KeyCode::Right if !is_choice => {
                        if let Some(form) = self.form.as_mut() {
                            form.cursor_right();
                        }
                    }
                    KeyCode::Home => {
                        if let Some(form) = self.form.as_mut() {
                            form.cursor_home();
                        }
                    }
                    KeyCode::End => {
                        if let Some(form) = self.form.as_mut() {
                            form.cursor_to_end();
                        }
                    }
                    KeyCode::Delete => {
                        if let Some(form) = self.form.as_mut() {
                            form.delete();
                        }
                    }
                    KeyCode::Left | KeyCode::Right if is_choice => {
                        if let Some(form) = self.form.as_mut() {
                            form.cycle_choice(key.code == KeyCode::Right);
                        }
                    }
                    // Space cycles a selector, but is an ordinary character
                    // everywhere else.
                    KeyCode::Char(' ') if is_choice => {
                        if let Some(form) = self.form.as_mut() {
                            form.cycle_choice(true);
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(form) = self.form.as_mut() {
                            form.backspace();
                        }
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(form) = self.form.as_mut() {
                            form.push(c);
                        }
                    }
                    _ => {}
                }
            }

            Mode::FilePicker => {
                let Some(picker) = self.picker.as_mut() else {
                    self.mode = Mode::Form;
                    return;
                };
                match key.code {
                    KeyCode::Esc => {
                        self.picker = None;
                        self.mode = Mode::Form;
                    }
                    KeyCode::Up | KeyCode::Char('k') => picker.up(),
                    KeyCode::Down | KeyCode::Char('j') => picker.down(),
                    KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => picker.go_up(),
                    KeyCode::Char('.') => picker.toggle_hidden(),
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        if let Some(chosen) = picker.activate() {
                            // Write the choice back into the field that asked
                            // for it, then return to the form.
                            if let Some(form) = self.form.as_mut() {
                                form.key_path = chosen.display().to_string();
                                // The value was replaced wholesale, so the caret
                                // has to follow it rather than sit mid-path.
                                form.cursor_to_end();
                                form.error = None;
                            }
                            self.picker = None;
                            self.mode = Mode::Form;
                        }
                    }
                    _ => {}
                }
            }

            Mode::SessionList => match key.code {
                KeyCode::Char('x') => self.ask_to_close(Some(self.session_selected)),
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Enter => self.resume_selected_session(),
                KeyCode::Up | KeyCode::Char('k') => {
                    self.session_selected = self.session_selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let last = self.sessions.len().saturating_sub(1);
                    self.session_selected = (self.session_selected + 1).min(last);
                }
                _ => {}
            },
            Mode::QuickConnect => match key.code {
                KeyCode::Esc => {
                    self.quick_input.clear();
                    self.quick_cursor = 0;
                    self.mode = Mode::Browse;
                }
                KeyCode::Enter => self.connect_typed_target(),
                KeyCode::Left => input::left(&self.quick_input, &mut self.quick_cursor),
                KeyCode::Right => input::right(&self.quick_input, &mut self.quick_cursor),
                KeyCode::Home => self.quick_cursor = 0,
                KeyCode::End => self.quick_cursor = input::end(&self.quick_input),
                KeyCode::Delete => input::delete(&mut self.quick_input, self.quick_cursor),
                KeyCode::Backspace => {
                    input::backspace(&mut self.quick_input, &mut self.quick_cursor)
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    input::insert(&mut self.quick_input, &mut self.quick_cursor, c)
                }
                _ => {}
            },
            Mode::Help => {
                // Any key dismisses help.
                self.mode = Mode::Browse;
            }
            Mode::Browse => {
                if let Some((_, _, _, action)) =
                    BINDINGS.iter().find(|(code, ..)| *code == key.code)
                {
                    self.dispatch(*action);
                }
            }
        }
    }

    fn dispatch(&mut self, action: Action) {
        match action {
            Action::Quit => {
                // Leaving them open would strand shells on the remote until it
                // timed them out.
                for session in &self.sessions {
                    session.close();
                }
                self.should_quit = true;
            }
            Action::Up => self.selected = self.selected.saturating_sub(1),
            Action::Down => {
                let last = self.visible().len().saturating_sub(1);
                self.selected = (self.selected + 1).min(last);
            }
            Action::StartFilter => {
                self.filter_cursor = input::end(&self.filter);
                self.mode = Mode::Filter;
            }
            Action::ClearFilter => {
                // Esc means "stop what is happening". A connect that is going
                // nowhere is the more urgent thing to stop, so it wins over
                // clearing a filter the user can also just retype.
                if self.cancel_connects() {
                    return;
                }
                self.filter.clear();
                self.filter_cursor = 0;
                self.tag_filter = None;
                self.clamp_selection();
            }
            Action::CycleTag => self.cycle_tag(),
            Action::ToggleHelp => self.mode = Mode::Help,
            Action::Connect => self.connect_selected(),
            Action::AddHost => {
                self.form = Some(HostForm::add());
                self.mode = Mode::Form;
            }
            Action::EditHost => {
                if let Some(index) = self.selected_inventory_index()
                    && let Some(host) = self.inventory.hosts.get(index)
                {
                    self.form = Some(HostForm::edit(index, host));
                    self.mode = Mode::Form;
                }
            }
            Action::ImportPutty => self.scan_imports(),
            Action::BulkEdit => {
                // The filter *is* the selection: narrow the list, then edit
                // what is left. That avoids inventing a second way to pick
                // hosts alongside one that already works.
                let targets = self.visible_indices();
                if targets.is_empty() {
                    self.status = Status::Error("no hosts shown to edit".into());
                } else {
                    self.form = Some(HostForm::bulk(targets));
                    self.mode = Mode::Form;
                }
            }
            Action::DeleteHost => {
                if let Some(index) = self.selected_inventory_index() {
                    self.pending_delete = Some(index);
                    self.mode = Mode::ConfirmDelete;
                }
            }
            Action::ShowSessions => self.show_sessions(),
            Action::NewSession => self.open_new_session(),
            Action::QuickConnect => {
                self.quick_input.clear();
                self.quick_cursor = 0;
                self.mode = Mode::QuickConnect;
            }
            // From the host list this closes the host's *first* session, the
            // same one `↵` resumes. The session list is where you pick among
            // several.
            Action::CloseSession => match self.selected_host().map(|h| h.name.clone()) {
                Some(name) => self.ask_to_close(self.session_for(&name)),
                None => self.status = Status::Error("no host selected".into()),
            },
        }
    }

    /// Open the session list, or explain why there is nothing to list.
    fn show_sessions(&mut self) {
        if self.sessions.is_empty() {
            self.status = Status::Error("no active sessions".into());
            return;
        }
        self.clamp_session_selection();
        self.mode = Mode::SessionList;
    }

    fn clamp_session_selection(&mut self) {
        let last = self.sessions.len().saturating_sub(1);
        self.session_selected = self.session_selected.min(last);
    }

    /// Resume whichever session is selected in the session list.
    fn resume_selected_session(&mut self) {
        self.clamp_session_selection();
        let Some(session) = self.sessions.get(self.session_selected) else {
            self.status = Status::Error("no active sessions".into());
            return;
        };
        self.status = Status::Busy(format!("resuming {}…", session.host));
        self.pending_attach = Some(self.session_selected);
        self.mode = Mode::Browse;
    }

    /// Validate the form, apply it, and persist.
    fn submit_form(&mut self) {
        let Some(form) = self.form.as_ref() else {
            return;
        };

        if let FormMode::Bulk(targets) = form.mode.clone() {
            self.submit_bulk(&targets);
            return;
        }

        let (form_mode, host) = match form.to_host() {
            Ok(host) => (form.mode.clone(), host),
            Err(message) => {
                // Stay in the form with the cursor where it was, so the fix is
                // one keystroke away rather than a re-entry of everything.
                if let Some(form) = self.form.as_mut() {
                    form.error = Some(message);
                }
                return;
            }
        };

        // Taken before any mutation — a snapshot of the already-edited list
        // would make the rollback in `persist` a no-op.
        let previous = self.inventory.hosts.clone();

        let description = match &form_mode {
            FormMode::Add => {
                let name = host.name.clone();
                self.inventory.hosts.push(host);
                format!("added {name}")
            }
            FormMode::Edit(index) => {
                let index = *index;
                let Some(slot) = self.inventory.hosts.get_mut(index) else {
                    self.status = Status::Error("that host no longer exists".into());
                    self.close_form();
                    return;
                };
                let name = host.name.clone();
                *slot = host;
                format!("saved {name}")
            }
            // Handled before this point; a bulk form never reaches here.
            FormMode::Bulk(_) => unreachable!("bulk submits take their own path"),
        };

        if self.persist(previous, description) {
            self.close_form();
        }
    }

    /// Apply the touched fields of a bulk form to every selected host.
    fn submit_bulk(&mut self, targets: &[usize]) {
        let Some(form) = self.form.as_ref() else {
            return;
        };
        if !form.touched_anything() {
            if let Some(form) = self.form.as_mut() {
                form.error = Some("change a field first, or esc to cancel".into());
            }
            return;
        }

        // Applied to a copy so a failure part-way through cannot leave half the
        // hosts edited.
        let mut updated = self.inventory.hosts.clone();
        for index in targets {
            let Some(host) = updated.get_mut(*index) else {
                continue;
            };
            if let Err(message) = form.apply_to(host) {
                if let Some(form) = self.form.as_mut() {
                    form.error = Some(message);
                }
                return;
            }
        }

        let previous = std::mem::replace(&mut self.inventory.hosts, updated);
        let count = targets.len();
        if self.persist(previous, format!("updated {count} hosts")) {
            self.close_form();
        }
    }

    /// Put up the close confirmation for the session at `index`.
    ///
    /// Confirmed because this kills a remote shell and whatever was running in
    /// it. `q` closes everything without asking, but `q` says what it does; `x`
    /// on a row does not.
    fn ask_to_close(&mut self, index: Option<usize>) {
        let Some(session) = index.and_then(|i| self.sessions.get(i)) else {
            self.status = Status::Error("no session on that host".into());
            return;
        };
        self.pending_close = Some(session.id());
        self.close_from_list = self.mode == Mode::SessionList;
        self.mode = Mode::ConfirmClose;
    }

    /// Disconnect the session the prompt was raised for.
    ///
    /// Resolved by id, not by the index the prompt was opened with: a session
    /// ending while the prompt is up shifts the rows, and closing by position
    /// would kill whichever one slid into that slot.
    fn confirm_close(&mut self, confirmed: bool) {
        let id = self.pending_close.take();

        if confirmed {
            match id.and_then(|id| self.sessions.iter().position(|s| s.id() == id)) {
                Some(index) => {
                    let label = self.session_label(index);
                    self.sessions[index].disconnect();
                    // Removed here rather than left to `prune_dead_sessions`,
                    // which would announce it as a session that died — this one
                    // was asked to go.
                    self.forget_session(index);
                    self.status = Status::Ok(format!("disconnected {label}"));
                }
                None => self.status = Status::Error("that session has already ended".into()),
            }
        }

        // Back where the prompt was raised, so closing several in a row does not
        // mean pressing `s` between each. The list is no place to be once it is
        // empty, though.
        self.mode = if self.close_from_list && !self.sessions.is_empty() {
            Mode::SessionList
        } else {
            Mode::Browse
        };
    }

    /// Drop a session from the list without disturbing a pending resume.
    ///
    /// The same hazard `prune_dead_sessions` handles: `pending_attach` is an
    /// index, so removing a row beneath it would point it at a different
    /// session.
    fn forget_session(&mut self, index: usize) {
        if let Some(pending) = self.pending_attach {
            self.pending_attach = match pending.cmp(&index) {
                std::cmp::Ordering::Equal => None,
                std::cmp::Ordering::Greater => Some(pending - 1),
                std::cmp::Ordering::Less => Some(pending),
            };
        }
        self.sessions.remove(index);
        self.clamp_session_selection();
    }

    fn confirm_delete(&mut self, confirmed: bool) {
        let index = self.pending_delete.take();
        self.mode = Mode::Browse;

        if !confirmed {
            return;
        }
        let Some(index) = index else {
            return;
        };
        if index >= self.inventory.hosts.len() {
            self.status = Status::Error("that host no longer exists".into());
            return;
        }

        let previous = self.inventory.hosts.clone();
        let removed = self.inventory.hosts.remove(index);
        self.persist(previous, format!("deleted {}", removed.name));
        self.clamp_selection();
    }

    /// Write the inventory to disk, rolling back on failure.
    ///
    /// The rollback matters: without it a failed write (read-only file, full
    /// disk) leaves the list on screen disagreeing with the file, and the next
    /// edit silently saves a state the user never reviewed. What is shown is
    /// what is on disk.
    fn persist(&mut self, previous: Vec<Host>, description: String) -> bool {
        match self.inventory.save_to(&self.inventory_path) {
            Ok(()) => {
                let forgotten = self.forget_orphaned_passphrases(&previous);
                self.status = Status::Ok(match forgotten {
                    0 => description,
                    1 => format!("{description}, and forgot 1 cached passphrase"),
                    n => format!("{description}, and forgot {n} cached passphrases"),
                });
                self.clamp_selection();
                true
            }
            Err(err) => {
                self.inventory.hosts = previous;
                self.status = Status::Error(format!("could not save: {err}"));
                false
            }
        }
    }

    /// Delete Keychain entries that the inventory no longer refers to.
    ///
    /// Turning caching off has to *remove* what was stored. An opt-out that only
    /// stopped reading would leave the passphrase in the Keychain while the form
    /// said caching was off — the one reading of the toggle nobody would expect.
    ///
    /// Expressed as a diff of the cached-key set rather than as a check on the
    /// flag, because every route to "no longer cached" has to be covered:
    /// switching to agent auth, repointing the key path, deleting the host, and
    /// a bulk edit doing any of those to sixty hosts at once. A per-case check
    /// would have to be repeated at each call site and would be forgotten at one
    /// of them.
    ///
    /// Runs after a successful write, so a rolled-back save cannot delete a
    /// secret the config still refers to. Blocking on purpose: the Keychain may
    /// put up a dialog, and this happens only when the user has just asked for
    /// it, so freezing the frame behind a prompt they are already answering is
    /// better than reporting the secret gone before it is.
    fn forget_orphaned_passphrases(&self, previous: &[Host]) -> usize {
        // Counts entries that were actually **removed**, not attempts. A host
        // can carry the flag without ever having stored anything — it was never
        // connected to, or the platform has no keychain at all — and counting
        // attempts announced "forgot 1 cached passphrase" for a secret that had
        // never existed. Saying a secret was deleted when it never was is the
        // wrong direction to be wrong in.
        //
        // A failure is not surfaced: the entry is either already absent, which
        // is the state we wanted, or the Keychain is unreachable, which the next
        // connect will report far more usefully than a status line here.
        orphaned_key_ids(previous, &self.inventory.hosts)
            .iter()
            .filter(|id| crate::keystore::forget(id).unwrap_or(false))
            .count()
    }

    fn close_form(&mut self) {
        self.form = None;
        self.mode = Mode::Browse;
    }

    /// Step through the tag list, wrapping back to "no filter" at the end.
    fn cycle_tag(&mut self) {
        let tags = self.inventory.tags();
        if tags.is_empty() {
            return;
        }
        self.tag_filter = match &self.tag_filter {
            None => tags.first().cloned(),
            Some(current) => match tags.iter().position(|t| t == current) {
                Some(i) if i + 1 < tags.len() => Some(tags[i + 1].clone()),
                _ => None,
            },
        };
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let last = self.visible().len().saturating_sub(1);
        self.selected = self.selected.min(last);
    }

    /// Select `name` and start connecting to it, as `luvienne <host>` does.
    ///
    /// Returns whether a host by that name was found. The caller checks the
    /// name against the inventory first, so a `false` here means the host is
    /// filtered out of view rather than missing — which cannot happen at
    /// startup, where no filter is set.
    pub fn connect_to(&mut self, name: &str) -> bool {
        let Some(index) = self.visible().iter().position(|host| host.name == name) else {
            return false;
        };
        self.selected = index;
        self.connect_selected();
        true
    }

    fn connect_selected(&mut self) {
        let Some(host) = self.selected_host().cloned() else {
            return;
        };

        // Already connected: resume rather than opening a second session. `n`
        // is how you ask for another one deliberately.
        if let Some(index) = self.session_for(&host.name) {
            self.status = Status::Busy(format!("resuming {}…", host.name));
            self.pending_attach = Some(index);
            return;
        }

        self.dial(&host);
    }

    /// Whether attaching session `id` means moving from a *different* one.
    ///
    /// Drives the rule [`ssh::attach`] draws to mark the seam. False on the very
    /// first attach: the text above is then the user's own shell, and announcing
    /// a boundary they did not cross would be noise.
    fn switching_to(&self, id: u64) -> bool {
        self.last_attached.is_some_and(|last| last != id)
    }

    /// Connect to whatever was typed into quick connect.
    ///
    /// A bad target leaves the prompt up with the text intact — the answer to a
    /// mistyped port is to fix the port, not to type the whole thing again.
    fn connect_typed_target(&mut self) {
        // A name you already have configured means the saved host, not a bare
        // address that happens to spell the same thing. It is both what was meant
        // and the only reading that can work: dialling `web-01` with the agent
        // would fail on a host that needs a key through a bastion, while its
        // settings sat in the inventory unused. `user@web-01` or `web-01:22` do
        // not match a *name*, so they still reach the literal host.
        let typed = self.quick_input.trim().to_string();
        if let Some(saved) = self
            .inventory
            .hosts
            .iter()
            // Case-insensitive, like the filter. DNS does not distinguish case
            // either, so `DB-PRIMARY` and `db-primary` name the same machine and
            // must resolve the same way — capitalisation should not decide
            // whether the saved key and bastion get used.
            .find(|host| host.name.eq_ignore_ascii_case(&typed))
            .cloned()
        {
            self.quick_input.clear();
            self.quick_cursor = 0;
            self.mode = Mode::Browse;

            if let Some(index) = self.session_for(&typed) {
                self.status = Status::Busy(format!("resuming {typed}…"));
                self.pending_attach = Some(index);
                return;
            }

            // `dial` resolves the chain from the inventory, so the jump hosts,
            // auth and forwards all come with it.
            self.dial(&saved);
            // Said out loud: the address dialled may be nothing like the name
            // typed, and silently reaching a different machine is the failure
            // this whole branch exists to avoid.
            if let Status::Busy(message) = &self.status {
                self.status = Status::Busy(format!("saved host: {message}"));
            }
            return;
        }

        let host = match Host::from_target(&self.quick_input) {
            Ok(host) => host,
            Err(err) => {
                self.status = Status::Error(err.to_string());
                return;
            }
        };

        // An identical target already open is resumed rather than dialled twice,
        // matching what `↵` does in the list. `n` is still the way to ask for a
        // second shell somewhere.
        if let Some(index) = self.session_for(&host.name) {
            self.status = Status::Busy(format!("resuming {}…", host.name));
            self.pending_attach = Some(index);
        } else {
            self.dial_chain(vec![host]);
        }

        self.quick_input.clear();
        self.quick_cursor = 0;
        self.mode = Mode::Browse;
    }

    /// Open an *additional* session to the selected host, instead of resuming
    /// the one already there.
    ///
    /// A build running in one shell while you edit in another is ordinary SSH
    /// work, and `↵` cannot serve both meanings — it has to keep resuming, or
    /// every stray Enter on a connected host would open another shell.
    fn open_new_session(&mut self) {
        let Some(host) = self.selected_host().cloned() else {
            return;
        };
        self.dial(&host);
    }

    /// Start a connection, whatever else is already open to this host.
    fn dial(&mut self, host: &Host) {
        // Already dialling. A connect can sit for a long time — an unroutable
        // address waits out the TCP timeout — and every extra Enter would start
        // another one. `connecting` is keyed by host, so this also caps a host
        // at one *in-flight* dial: a second session is something you ask for
        // once the first has actually come up.
        if self.connecting.contains_key(&host.name) {
            self.status = Status::Busy(format!("still connecting to {}…", host.name));
            return;
        }

        // Resolved here, where the inventory is, so an unresolvable jump chain
        // is reported before any connection is attempted.
        let chain = match self.inventory.connection_chain(&host.name) {
            Ok(chain) => chain,
            Err(err) => {
                self.status = Status::Error(err.to_string());
                return;
            }
        };

        self.dial_chain(chain);
    }

    /// Connect a chain that is already resolved.
    ///
    /// Split from [`Self::dial`] for quick connect, whose target is not in the
    /// inventory at all — `connection_chain` would rightly say it has never
    /// heard of it. The chain is always one hop there: somewhere you are reaching
    /// once has no jump host configured for it.
    fn dial_chain(&mut self, chain: Vec<Host>) {
        let Some(host) = chain.last().cloned() else {
            return;
        };
        if self.connecting.contains_key(&host.name) {
            self.status = Status::Busy(format!("still connecting to {}…", host.name));
            return;
        }

        self.status = match chain.len() {
            1 => Status::Busy(format!("connecting to {}… (esc cancels)", host.name)),
            n => Status::Busy(format!(
                "connecting to {} via {} host{}… (esc cancels)",
                host.name,
                n - 1,
                if n == 2 { "" } else { "s" }
            )),
        };

        let tx = self.tx.clone();
        let name = host.name.clone();
        let task = self.runtime.spawn(async move {
            match ssh::connect(&chain, &tx).await {
                Ok(session) => {
                    let _ = tx.send(SshEvent::Ready(Box::new(session)));
                }
                // `err` is already redacted at construction; see ssh::SshError.
                Err(err) => {
                    let _ = tx.send(SshEvent::Failed {
                        host: name,
                        message: err.to_string(),
                    });
                }
            }
        });
        self.connecting.insert(host.name.clone(), task);
    }
}

/// What the status line says once a session hands the terminal back.
///
/// Pure, and separate from `attach_session`, which cannot be called without a
/// terminal — this is where the decision that matters lives, so it is the part
/// worth testing.
///
/// A forward that never came up **outranks the session outcome**. How a shell
/// ended is routine and the user just watched it happen; a missing tunnel is
/// neither. It was reported once already, as a progress line during the
/// connect, and then buried under "attaching…" seconds later — so without this
/// the only durable record of it would be gone by the time anyone could read it.
fn session_status(
    result: &Result<ssh::SessionOutcome, ssh::SshError>,
    host: &str,
    forward_failures: &[String],
) -> Status {
    if !forward_failures.is_empty() {
        return Status::Error(forward_failures.join("; "));
    }
    match result {
        Ok(ssh::SessionOutcome::Detached) => {
            Status::Ok(format!("{host} still running — ↵ to resume"))
        }
        Ok(ssh::SessionOutcome::Ended(code)) => match code {
            Some(0) | None => Status::Ok(format!("{host} session ended")),
            Some(code) => Status::Ok(format!("{host} exited with status {code}")),
        },
        Err(err) => Status::Error(err.to_string()),
    }
}

/// Keychain entries `previous` referred to that `current` no longer does.
///
/// Kept pure and separate from the deletion so the rule can be tested without
/// writing to anyone's login keychain.
///
/// The load-bearing part is `kept`: entries are named by key file, so a key
/// shared by twenty hosts must survive one of them opting out. Diffing the flag
/// per host instead would delete a passphrase nineteen hosts still cache, and
/// they would silently start prompting again.
fn orphaned_key_ids(previous: &[Host], current: &[Host]) -> Vec<String> {
    let kept: std::collections::HashSet<String> =
        current.iter().filter_map(Host::cached_key_id).collect();

    let mut orphaned: Vec<String> = previous
        .iter()
        .filter_map(Host::cached_key_id)
        .filter(|id| !kept.contains(id))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    orphaned.sort();
    orphaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthRef, Host};
    use std::path::Path;

    /// Every app under test writes to its own temp file. Using the real config
    /// path here would have the suite overwrite the user's hosts.toml.
    fn app_with(hosts: Vec<Host>) -> App {
        app_at(hosts, temp_inventory("app"))
    }

    fn temp_inventory(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("luvienne-app-{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("hosts.toml")
    }

    fn app_at(hosts: Vec<Host>, path: PathBuf) -> App {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // Leak the runtime so the handle stays valid for the test's lifetime.
        let handle = Box::leak(Box::new(runtime)).handle().clone();
        App::new(Inventory { hosts }, path, handle)
    }

    fn host(name: &str, tags: &[&str]) -> Host {
        Host {
            name: name.into(),
            address: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            tags: tags.iter().map(|s| (*s).into()).collect(),
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        }
    }

    /// A tunnel that never came up has to outrank how the shell ended. It was
    /// reported once during the connect and then buried under "attaching…", so
    /// this is the only place the user can still find out — and believing in a
    /// forward you do not have means using the port and reaching whatever else
    /// was listening on it.
    #[test]
    fn a_failed_forward_is_reported_over_the_session_outcome() {
        let failures = vec!["could not listen on 127.0.0.1:8080: in use".to_string()];

        for outcome in [
            Ok(ssh::SessionOutcome::Detached),
            Ok(ssh::SessionOutcome::Ended(Some(0))),
            Ok(ssh::SessionOutcome::Ended(None)),
        ] {
            let status = session_status(&outcome, "web-01", &failures);
            match status {
                Status::Error(message) => assert!(message.contains("8080"), "got: {message}"),
                other => panic!("a failed forward was not reported: {other:?}"),
            }
        }
    }

    /// And with nothing wrong it stays out of the way.
    #[test]
    fn the_ordinary_outcome_survives_when_every_forward_came_up() {
        let status = session_status(&Ok(ssh::SessionOutcome::Detached), "web-01", &[]);
        match status {
            Status::Ok(message) => assert!(message.contains("still running"), "got: {message}"),
            other => panic!("expected the usual detach message, got {other:?}"),
        }

        let status = session_status(&Ok(ssh::SessionOutcome::Ended(Some(3))), "web-01", &[]);
        match status {
            Status::Ok(message) => assert!(message.contains('3'), "got: {message}"),
            other => panic!("expected the exit status, got {other:?}"),
        }
    }

    /// The count is entries actually removed, not entries we tried to remove.
    /// A host can carry the flag without ever having stored anything — never
    /// connected to, or a platform with no keychain — and counting attempts
    /// announced "forgot 1 cached passphrase" about a secret that never
    /// existed. Claiming a secret was deleted when it was not is the wrong
    /// direction to be wrong in.
    ///
    /// Safe to run for real: the id names a path that does not exist, so the
    /// only keychain call is a delete of something absent.
    #[test]
    fn nothing_is_claimed_forgotten_when_nothing_was_stored() {
        let before = vec![caching("web", "/nonexistent/luvienne-qa-key.ppk")];
        let app = app_with(vec![]);

        assert_eq!(
            app.forget_orphaned_passphrases(&before),
            0,
            "reported forgetting a passphrase that was never stored"
        );
    }

    /// A host that caches the passphrase for `key`.
    fn caching(name: &str, key: &str) -> Host {
        Host {
            auth: AuthRef::Key {
                path: PathBuf::from(key),
            },
            cache_passphrase: true,
            ..host(name, &[])
        }
    }

    /// The rule the whole cleanup rests on. Entries are named by key file, so
    /// twenty hosts sharing one `.ppk` share one entry — and one of them opting
    /// out must not delete the passphrase the other nineteen still use, or they
    /// all silently start prompting again.
    #[test]
    fn a_key_another_host_still_caches_is_not_forgotten() {
        let before = vec![
            caching("web", "~/keys/a.ppk"),
            caching("db", "~/keys/a.ppk"),
        ];
        let after = vec![host("web", &[]), caching("db", "~/keys/a.ppk")];

        assert!(
            orphaned_key_ids(&before, &after).is_empty(),
            "db still caches that key"
        );
    }

    /// The other half of the same rule: once the *last* holder opts out, the
    /// entry has to go. An opt-out that only stopped reading would leave the
    /// passphrase in the Keychain while the form said caching was off.
    #[test]
    fn the_last_host_to_opt_out_orphans_the_key() {
        let before = vec![
            caching("web", "~/keys/a.ppk"),
            caching("db", "~/keys/a.ppk"),
        ];
        let after = vec![host("web", &[]), host("db", &[])];

        assert_eq!(
            orphaned_key_ids(&before, &after),
            vec![crate::keystore::key_id(Path::new("~/keys/a.ppk"))],
            "one entry, named once, even though two hosts released it"
        );
    }

    /// Deleting the host is another route to "nothing refers to this any more",
    /// and it goes through the same diff rather than a check of its own.
    #[test]
    fn deleting_the_only_caching_host_orphans_the_key() {
        let before = vec![caching("web", "~/keys/a.ppk")];
        assert_eq!(orphaned_key_ids(&before, &[]).len(), 1);
    }

    /// So is repointing the key path — the old entry is now unreachable, and
    /// nothing else would ever clean it up.
    #[test]
    fn repointing_the_key_orphans_the_entry_for_the_old_one() {
        let before = vec![caching("web", "~/keys/old.ppk")];
        let after = vec![caching("web", "~/keys/new.ppk")];

        assert_eq!(
            orphaned_key_ids(&before, &after),
            vec![crate::keystore::key_id(Path::new("~/keys/old.ppk"))]
        );
    }

    /// An edit that changes something unrelated must not touch the Keychain at
    /// all — renaming a host would otherwise throw away its passphrase.
    #[test]
    fn an_unrelated_edit_orphans_nothing() {
        let before = vec![caching("web", "~/keys/a.ppk")];
        let mut after = before.clone();
        after[0].name = "web-01".into();
        after[0].port = 2222;

        assert!(orphaned_key_ids(&before, &after).is_empty());
    }

    /// Hosts that never cached anything cannot orphan anything, so the common
    /// edit does no Keychain work whatsoever.
    #[test]
    fn hosts_that_never_cached_orphan_nothing() {
        let before = vec![host("a", &[]), host("b", &["prod"])];
        assert!(orphaned_key_ids(&before, &[]).is_empty());
    }

    #[test]
    fn selection_cannot_run_past_the_visible_list() {
        let mut app = app_with(vec![host("a", &[]), host("b", &[])]);
        for _ in 0..10 {
            app.dispatch(Action::Down);
        }
        assert_eq!(app.selected, 1);
        for _ in 0..10 {
            app.dispatch(Action::Up);
        }
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn selection_is_clamped_when_the_filter_shrinks_the_list() {
        let mut app = app_with(vec![host("alpha", &[]), host("beta", &[])]);
        app.dispatch(Action::Down);
        assert_eq!(app.selected, 1);

        app.filter = "alpha".into();
        app.clamp_selection();
        assert_eq!(app.selected, 0, "stale index would index out of bounds");
    }

    #[test]
    fn cycling_tags_wraps_back_to_unfiltered() {
        let mut app = app_with(vec![host("a", &["db"]), host("b", &["web"])]);
        assert_eq!(app.tag_filter, None);
        app.dispatch(Action::CycleTag);
        assert_eq!(app.tag_filter.as_deref(), Some("db"));
        app.dispatch(Action::CycleTag);
        assert_eq!(app.tag_filter.as_deref(), Some("web"));
        app.dispatch(Action::CycleTag);
        assert_eq!(app.tag_filter, None, "wraps around");
    }

    #[test]
    fn tag_filter_narrows_the_visible_list() {
        let mut app = app_with(vec![host("a", &["db"]), host("b", &["web"])]);
        app.tag_filter = Some("db".into());
        let visible = app.visible();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "a");
    }

    #[test]
    fn empty_inventory_has_no_selected_host() {
        let app = app_with(vec![]);
        assert!(app.selected_host().is_none());
    }

    /// Arm a host key prompt and return the receiver the SSH task is parked on.
    fn arm_prompt(app: &mut App) -> oneshot::Receiver<bool> {
        let (reply, answer) = oneshot::channel();
        app.mode = Mode::ConfirmHostKey;
        app.host_key_prompt = Some(PendingHostKey {
            host: "10.0.0.1".into(),
            fingerprint: "SHA256:abc".into(),
            reply,
        });
        answer
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn y_accepts_an_unknown_host_key() {
        let mut app = app_with(vec![]);
        let mut answer = arm_prompt(&mut app);
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(answer.try_recv(), Ok(true));
        assert_eq!(app.mode, Mode::Browse);
    }

    #[test]
    fn n_refuses_an_unknown_host_key() {
        let mut app = app_with(vec![]);
        let mut answer = arm_prompt(&mut app);
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(answer.try_recv(), Ok(false));
    }

    /// The important one. Enter, space, and every other key must do nothing —
    /// an unknown host must never be accepted by reflex.
    #[test]
    fn no_other_key_accepts_an_unknown_host_key() {
        for code in [
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('q'),
            KeyCode::Tab,
        ] {
            let mut app = app_with(vec![]);
            let mut answer = arm_prompt(&mut app);
            press(&mut app, code);
            assert_eq!(
                answer.try_recv(),
                Err(oneshot::error::TryRecvError::Empty),
                "{code:?} must not answer the prompt"
            );
            assert_eq!(app.mode, Mode::ConfirmHostKey, "{code:?} must not dismiss");
        }
    }

    /// Quitting mid-prompt drops the sender. The waiting task sees `Err` and
    /// treats it as a refusal — abandonment fails closed, not open.
    #[test]
    fn abandoning_the_prompt_fails_closed() {
        let mut app = app_with(vec![]);
        let mut answer = arm_prompt(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        drop(app);
        assert_eq!(answer.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    }

    fn secret_request(kind: ssh::SecretKind, retry: bool) -> ssh::SecretRequest {
        ssh::SecretRequest {
            kind,
            subject: "~/keys/legacy.ppk".into(),
            prompt: kind.title().into(),
            echo: false,
            retry,
            note: None,
        }
    }

    fn arm_secret(app: &mut App, retry: bool) -> oneshot::Receiver<Option<Zeroizing<String>>> {
        let (reply, answer) = oneshot::channel();
        app.mode = Mode::Secret;
        app.secret_input.clear();
        app.secret_prompt = Some(PendingSecret::for_test(
            secret_request(ssh::SecretKind::Passphrase, retry),
            reply,
        ));
        answer
    }

    #[test]
    fn enter_submits_the_secret_and_clears_the_buffer() {
        let mut app = app_with(vec![]);
        let mut answer = arm_secret(&mut app, false);

        for c in "hunter2".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        let submitted = answer.try_recv().unwrap();
        assert_eq!(submitted.as_ref().map(|p| p.as_str()), Some("hunter2"));
        assert!(
            app.secret_input.is_empty(),
            "buffer must not outlive the prompt"
        );
        assert_eq!(app.mode, Mode::Browse);
    }

    #[test]
    fn esc_cancels_the_secret_prompt() {
        let mut app = app_with(vec![]);
        let mut answer = arm_secret(&mut app, false);

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Esc);

        assert_eq!(answer.try_recv().unwrap(), None, "cancel sends None");
        assert!(app.secret_input.is_empty());
    }

    /// Browse bindings must not leak into the passphrase field. `q` is a
    /// perfectly ordinary passphrase character; if it quit the app instead, a
    /// user could never type it.
    #[test]
    fn browse_bindings_do_not_apply_while_typing_a_secret() {
        let mut app = app_with(vec![]);
        let _answer = arm_secret(&mut app, false);

        for c in "q/tj?".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        assert_eq!(&*app.secret_input, "q/tj?");
        assert_eq!(app.mode, Mode::Secret, "still typing");
        assert!(!app.should_quit, "'q' must not quit mid-secret");
    }

    #[test]
    fn backspace_edits_the_secret() {
        let mut app = app_with(vec![]);
        let _answer = arm_secret(&mut app, false);

        for c in "abc".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Backspace);

        assert_eq!(&*app.secret_input, "ab");
    }

    /// Quitting mid-prompt drops the sender; the connect task sees `Err` and
    /// cancels. Same fail-closed rule as the host key prompt.
    #[test]
    fn abandoning_the_secret_prompt_cancels_the_connect() {
        let mut app = app_with(vec![]);
        let mut answer = arm_secret(&mut app, false);
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        drop(app);
        assert_eq!(answer.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    }

    fn fresh_app(tag: &str, hosts: Vec<Host>) -> App {
        let path = temp_inventory(tag);
        std::fs::remove_file(&path).ok();
        app_at(hosts, path)
    }

    #[test]
    fn a_adds_a_host_and_writes_it_to_disk() {
        let mut app = fresh_app("add", vec![]);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.mode, Mode::Form);

        for (field, text) in [
            (Field::Name, "web-01"),
            (Field::Address, "10.0.0.1"),
            (Field::User, "deploy"),
            (Field::Tags, "prod, web"),
        ] {
            if let Some(form) = app.form.as_mut() {
                form.focus_on(field);
            }
            for c in text.chars() {
                press(&mut app, KeyCode::Char(c));
            }
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Browse, "form closes on save");
        assert_eq!(app.inventory.hosts.len(), 1);
        assert_eq!(app.inventory.hosts[0].tags, vec!["prod", "web"]);

        let on_disk = Inventory::load_from(&app.inventory_path).unwrap();
        assert_eq!(on_disk.hosts.len(), 1, "not persisted");
        assert_eq!(on_disk.hosts[0].name, "web-01");
    }

    #[test]
    fn an_invalid_form_stays_open_and_explains_itself() {
        let mut app = fresh_app("invalid", vec![]);
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Form, "must not close on a bad save");
        let error = app.form.as_ref().unwrap().error.clone().unwrap();
        assert!(error.contains("name"), "got: {error}");
        assert!(app.inventory.hosts.is_empty(), "nothing was added");
    }

    /// The trap this feature is most likely to fall into. `selected` indexes the
    /// *visible* list; with a filter active, host 0 on screen can be host 2 in
    /// the inventory. Editing the wrong one silently corrupts a different host.
    #[test]
    fn editing_a_filtered_list_targets_the_right_host() {
        let mut app = fresh_app(
            "filtered",
            vec![host("alpha", &[]), host("beta", &[]), host("gamma", &[])],
        );
        app.filter = "gamma".into();
        assert_eq!(app.visible().len(), 1);
        app.selected = 0;

        press(&mut app, KeyCode::Char('e'));
        let form = app.form.as_ref().expect("form opened");
        assert_eq!(form.mode, FormMode::Edit(2), "must be inventory index 2");
        assert_eq!(form.name, "gamma");
    }

    #[test]
    fn deleting_from_a_filtered_list_removes_the_right_host() {
        let mut app = fresh_app(
            "delfiltered",
            vec![host("alpha", &[]), host("beta", &[]), host("gamma", &[])],
        );
        app.filter = "beta".into();
        app.selected = 0;

        press(&mut app, KeyCode::Char('d'));
        assert_eq!(app.mode, Mode::ConfirmDelete);
        press(&mut app, KeyCode::Char('y'));

        let names: Vec<&str> = app
            .inventory
            .hosts
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "gamma"], "removed the wrong host");
    }

    #[test]
    fn delete_requires_an_explicit_yes() {
        for code in [
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('d'),
            KeyCode::Tab,
        ] {
            let mut app = fresh_app("delkeys", vec![host("alpha", &[])]);
            press(&mut app, KeyCode::Char('d'));
            press(&mut app, code);
            assert_eq!(
                app.inventory.hosts.len(),
                1,
                "{code:?} must not delete anything"
            );
            assert_eq!(app.mode, Mode::ConfirmDelete, "{code:?} must not dismiss");
        }
    }

    #[test]
    fn n_and_esc_cancel_a_delete() {
        for code in [KeyCode::Char('n'), KeyCode::Esc] {
            let mut app = fresh_app("delcancel", vec![host("alpha", &[])]);
            press(&mut app, KeyCode::Char('d'));
            press(&mut app, code);
            assert_eq!(app.inventory.hosts.len(), 1);
            assert_eq!(app.mode, Mode::Browse);
            assert!(app.pending_delete.is_none());
        }
    }

    /// Browse bindings must not fire while typing into the form — `q` and `d`
    /// are ordinary characters in a hostname.
    #[test]
    fn browse_bindings_do_not_apply_while_filling_the_form() {
        let mut app = fresh_app("formkeys", vec![]);
        press(&mut app, KeyCode::Char('a'));
        for c in "qde/".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.form.as_ref().unwrap().name, "qde/");
        assert!(!app.should_quit, "'q' must not quit mid-form");
        assert_eq!(app.mode, Mode::Form);
    }

    #[test]
    fn esc_cancels_the_form_without_saving() {
        let mut app = fresh_app("formesc", vec![]);
        press(&mut app, KeyCode::Char('a'));
        for c in "web".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::Browse);
        assert!(app.form.is_none());
        assert!(app.inventory.hosts.is_empty());
    }

    /// An edit that does not touch `jump` must not drop it.
    #[test]
    fn editing_an_unrelated_field_keeps_the_jump_host() {
        let mut with_jump = host("beta", &[]);
        with_jump.jump = Some("alpha".into());
        let mut app = fresh_app("jump", vec![host("alpha", &[]), with_jump]);

        app.selected = 1;
        press(&mut app, KeyCode::Char('e'));
        assert_eq!(
            app.form.as_ref().unwrap().jump,
            "alpha",
            "the form should open prefilled with the existing jump host"
        );
        if let Some(form) = app.form.as_mut() {
            form.name = "beta-renamed".into();
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.inventory.hosts[1].name, "beta-renamed");
        assert_eq!(
            app.inventory.hosts[1].jump.as_deref(),
            Some("alpha"),
            "jump was dropped by an unrelated edit"
        );
    }

    /// And clearing the field must actually remove it, now that it is editable.
    #[test]
    fn clearing_the_jump_field_makes_the_connection_direct() {
        let mut with_jump = host("beta", &[]);
        with_jump.jump = Some("alpha".into());
        let mut app = fresh_app("jumpclear", vec![host("alpha", &[]), with_jump]);

        app.selected = 1;
        press(&mut app, KeyCode::Char('e'));
        if let Some(form) = app.form.as_mut() {
            form.jump.clear();
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.inventory.hosts[1].jump, None);
    }

    /// A failed write must leave memory matching disk, or the next edit saves a
    /// state the user never reviewed.
    #[test]
    fn a_failed_save_rolls_the_change_back() {
        // A directory where the file should be: the write cannot succeed.
        let dir = std::env::temp_dir().join("luvienne-app-badsave");
        std::fs::create_dir_all(dir.join("hosts.toml")).ok();
        let mut app = app_at(vec![host("alpha", &[])], dir.join("hosts.toml"));

        press(&mut app, KeyCode::Char('d'));
        press(&mut app, KeyCode::Char('y'));

        assert_eq!(
            app.inventory.hosts.len(),
            1,
            "delete should have rolled back"
        );
        assert!(matches!(app.status, Status::Error(_)), "and said so");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A key anywhere on the filesystem must be reachable — the browser exists
    /// because typing a long absolute path blind is the only alternative.
    #[test]
    fn ctrl_o_opens_the_browser_and_a_choice_lands_in_the_field() {
        let dir = std::env::temp_dir().join("luvienne-app-picker");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("somewhere-odd.ppk");
        std::fs::write(&key, "x").unwrap();

        let mut app = fresh_app("picker", vec![]);
        press(&mut app, KeyCode::Char('a'));

        // Switch to key auth so the path field exists, then focus it.
        if let Some(form) = app.form.as_mut() {
            form.auth_choice = 1;
            form.focus_on(Field::KeyPath);
            form.key_path = dir.display().to_string();
        }
        assert_eq!(app.form.as_ref().unwrap().focused(), Field::KeyPath);

        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert_eq!(app.mode, Mode::FilePicker, "^O should open the browser");

        let picker = app.picker.as_mut().expect("picker present");
        assert_eq!(picker.dir, dir, "opens beside the current value");
        let index = picker
            .entries
            .iter()
            .position(|e| e.name == "somewhere-odd.ppk")
            .expect("the key is listed");
        picker.selected = index;

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Form, "returns to the form");
        assert!(app.picker.is_none());
        assert_eq!(
            app.form.as_ref().unwrap().key_path,
            key.display().to_string()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn esc_leaves_the_browser_without_changing_the_field() {
        let mut app = fresh_app("pickeresc", vec![]);
        press(&mut app, KeyCode::Char('a'));
        if let Some(form) = app.form.as_mut() {
            form.auth_choice = 1;
            form.focus_on(Field::KeyPath);
            form.key_path = "/original/path".into();
        }

        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert_eq!(app.mode, Mode::FilePicker);
        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::Form);
        assert!(app.picker.is_none());
        assert_eq!(app.form.as_ref().unwrap().key_path, "/original/path");
    }

    /// `^O` is only meaningful on the path field, and must never be typed as a
    /// literal `o` anywhere.
    #[test]
    fn ctrl_o_on_another_field_does_nothing_and_types_nothing() {
        let mut app = fresh_app("pickerother", vec![]);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.form.as_ref().unwrap().focused(), Field::Name);

        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));

        assert_eq!(app.mode, Mode::Form, "no browser on a non-path field");
        assert_eq!(
            app.form.as_ref().unwrap().name,
            "",
            "^O must not insert a literal 'o'"
        );
    }

    /// Control chords are commands everywhere, never text.
    #[test]
    fn control_chords_are_not_typed_into_the_filter() {
        let mut app = fresh_app("ctrlfilter", vec![host("alpha", &[])]);
        press(&mut app, KeyCode::Char('/'));
        app.on_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(app.filter, "", "^W must not insert a 'w'");
    }

    #[test]
    fn a_live_session_is_offered_for_resume_and_a_dead_one_is_not() {
        let mut app = fresh_app("sessions", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        assert_eq!(app.session_for("web-01"), Some(0), "live session not found");
        assert_eq!(app.session_for("other"), None);

        // A detached session can die on its own; it must stop being offered.
        app.sessions[0].mark_ended_for_test();
        assert_eq!(
            app.session_for("web-01"),
            None,
            "dead session still offered"
        );

        app.prune_dead_sessions();
        assert!(app.sessions.is_empty(), "dead session was not pruned");
    }

    /// Enter on a host that already has a session resumes it instead of opening
    /// a second connection to the same box.
    #[test]
    fn enter_resumes_an_existing_session_instead_of_reconnecting() {
        let mut app = fresh_app("resume", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.pending_attach, Some(0), "should resume, not reconnect");
        assert_eq!(app.sessions.len(), 1, "no second session was opened");
    }

    #[test]
    fn s_opens_the_session_list_when_sessions_exist() {
        let mut app = fresh_app("sessionlist", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('s'));

        assert_eq!(app.mode, Mode::SessionList);
        assert_eq!(app.session_selected, 0);
    }

    #[test]
    fn s_reports_nothing_when_there_are_no_sessions() {
        let mut app = fresh_app("sessionempty", vec![host("web-01", &[])]);

        press(&mut app, KeyCode::Char('s'));

        assert_eq!(app.mode, Mode::Browse);
        assert!(matches!(&app.status, Status::Error(m) if m.contains("no active sessions")));
    }

    #[test]
    fn session_list_navigation_clamps_to_the_list() {
        let mut app = fresh_app("sessionnav", vec![]);
        app.sessions.push(ssh::LiveSession::for_test("alpha").0);
        app.sessions.push(ssh::LiveSession::for_test("beta").0);
        app.mode = Mode::SessionList;

        press(&mut app, KeyCode::Down);
        assert_eq!(app.session_selected, 1);

        press(&mut app, KeyCode::Down);
        assert_eq!(app.session_selected, 1, "should not run past the end");

        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.session_selected, 0, "should not underflow");
    }

    #[test]
    fn enter_in_session_list_resumes_the_selected_session() {
        let mut app = fresh_app("sessionresume", vec![]);
        app.sessions.push(ssh::LiveSession::for_test("alpha").0);
        app.sessions.push(ssh::LiveSession::for_test("beta").0);
        app.mode = Mode::SessionList;
        app.session_selected = 1;

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.pending_attach, Some(1), "should resume beta");
        assert_eq!(app.mode, Mode::Browse, "returns to the host list");
        assert!(matches!(&app.status, Status::Busy(m) if m.contains("beta")));
    }

    #[test]
    fn esc_leaves_the_session_list_without_resuming() {
        let mut app = fresh_app("sessionesc", vec![]);
        app.sessions.push(ssh::LiveSession::for_test("alpha").0);
        app.mode = Mode::SessionList;

        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::Browse);
        assert!(app.pending_attach.is_none());
    }

    #[test]
    fn session_selection_is_clamped_when_a_session_dies() {
        let mut app = fresh_app("sessionprune", vec![]);
        let (alpha, _keep_alpha) = ssh::LiveSession::for_test("alpha");
        let (beta, _keep_beta) = ssh::LiveSession::for_test("beta");
        app.sessions.push(alpha);
        app.sessions.push(beta);
        app.session_selected = 1;

        app.sessions[1].mark_ended_for_test();
        app.prune_dead_sessions();

        assert_eq!(app.sessions.len(), 1);
        assert_eq!(
            app.session_selected, 0,
            "selection must be clamped after prune"
        );
    }

    /// Adding dozens of hosts to someone's config must not happen on one
    /// keystroke, and `y` must be the only key that does it.
    #[test]
    fn importing_requires_confirmation() {
        for code in [KeyCode::Enter, KeyCode::Char(' '), KeyCode::Char('i')] {
            let mut app = fresh_app("import", vec![]);
            app.pending_import = vec![crate::import::Imported {
                hosts: vec![host("from-putty", &[])],
                ..crate::import::Imported::new("PuTTY")
            }];
            app.mode = Mode::ConfirmImport;

            press(&mut app, code);
            assert!(
                app.inventory.hosts.is_empty(),
                "{code:?} imported without confirmation"
            );
            assert_eq!(app.mode, Mode::ConfirmImport, "{code:?} dismissed it");
        }
    }

    #[test]
    fn y_applies_the_import_and_esc_discards_it() {
        let mut app = fresh_app("importyes", vec![]);
        app.pending_import = vec![crate::import::Imported {
            hosts: vec![host("from-putty", &[])],
            ..crate::import::Imported::new("PuTTY")
        }];
        app.mode = Mode::ConfirmImport;
        press(&mut app, KeyCode::Char('y'));

        assert_eq!(app.inventory.hosts.len(), 1);
        assert_eq!(app.mode, Mode::Browse);
        assert!(app.pending_import.is_empty());
        // And it reached disk, not just memory.
        let on_disk = Inventory::load_from(&app.inventory_path).unwrap();
        assert_eq!(on_disk.hosts.len(), 1);

        let mut app = fresh_app("importno", vec![]);
        app.pending_import = vec![crate::import::Imported {
            hosts: vec![host("from-putty", &[])],
            ..crate::import::Imported::new("PuTTY")
        }];
        app.mode = Mode::ConfirmImport;
        press(&mut app, KeyCode::Esc);

        assert!(app.inventory.hosts.is_empty(), "esc should discard");
        assert!(app.pending_import.is_empty());
    }

    /// The footer is cut off at the window width, so help — which lists
    /// everything else — has to be the first thing in it.
    #[test]
    fn help_leads_the_binding_table_so_it_survives_truncation() {
        let (_, label, help, _) = BINDINGS.first().expect("bindings are not empty");
        assert_eq!(*label, "?");
        assert_eq!(*help, "help");
    }

    /// A duplicate binding shows the same hint twice in the footer and the help
    /// overlay. Moving `?` to the front once left the old entry behind, and
    /// checking only `first()` did not notice.
    #[test]
    fn no_action_is_bound_twice_under_the_same_label() {
        let mut labelled: Vec<&str> = BINDINGS
            .iter()
            .filter(|(_, label, ..)| !label.is_empty())
            .map(|(_, label, ..)| *label)
            .collect();
        labelled.sort_unstable();
        let before = labelled.len();
        labelled.dedup();
        assert_eq!(
            before,
            labelled.len(),
            "a key label appears twice: {labelled:?}"
        );
    }

    /// Holding Enter on a slow host used to start a connect per keystroke,
    /// each with its own prompts, each landing as a duplicate session.
    #[test]
    fn a_second_enter_does_not_start_a_second_connect() {
        let mut app = fresh_app("dupeconnect", vec![host("web-01", &[])]);

        press(&mut app, KeyCode::Enter);
        assert!(
            app.connecting.contains_key("web-01"),
            "first connect not tracked"
        );

        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.connecting.len(), 1, "duplicate connects were started");
        assert!(
            matches!(&app.status, Status::Busy(m) if m.contains("still connecting")),
            "should say it is already dialling, got {:?}",
            app.status
        );
    }

    /// A pending resume is an index into `sessions`, set a pass of the loop
    /// before it is used, and `prune_dead_sessions` runs in between. Without a
    /// remap, losing a session below it attaches something else entirely — ask
    /// for the second of three, lose the first, get the third.
    #[test]
    fn a_pending_resume_still_points_at_its_own_session_after_a_death() {
        let mut app = fresh_app("qaprobe", vec![]);
        let (alpha, _ka) = ssh::LiveSession::for_test("alpha");
        let (beta, _kb) = ssh::LiveSession::for_test("beta");
        let (gamma, _kg) = ssh::LiveSession::for_test("gamma");
        app.sessions.push(alpha);
        app.sessions.push(beta);
        app.sessions.push(gamma);

        // The user picked beta (index 1) in the session list.
        app.session_selected = 1;
        app.mode = Mode::SessionList;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.pending_attach, Some(1));

        // alpha dies before the loop gets to the attach.
        app.sessions[0].mark_ended_for_test();
        app.prune_dead_sessions();

        let target = app
            .pending_attach
            .and_then(|i| app.sessions.get(i))
            .map(|s| s.host.clone());
        assert_eq!(
            target.as_deref(),
            Some("beta"),
            "pending resume now points at {target:?} instead of beta"
        );
    }

    /// And if the session it named is the one that died, the resume is given up
    /// rather than pointed at a neighbour.
    #[test]
    fn a_pending_resume_is_dropped_when_its_own_session_dies() {
        let mut app = fresh_app("qapendingdead", vec![]);
        let (alpha, _ka) = ssh::LiveSession::for_test("alpha");
        let (beta, _kb) = ssh::LiveSession::for_test("beta");
        app.sessions.push(alpha);
        app.sessions.push(beta);
        app.pending_attach = Some(1);

        app.sessions[1].mark_ended_for_test();
        app.prune_dead_sessions();

        assert_eq!(
            app.pending_attach, None,
            "should not fall through to another session"
        );
    }

    #[test]
    fn c_opens_quick_connect_empty() {
        let mut app = fresh_app("quickopen", vec![host("web-01", &[])]);
        app.quick_input.push_str("stale");

        press(&mut app, KeyCode::Char('c'));

        assert_eq!(app.mode, Mode::QuickConnect);
        assert!(
            app.quick_input.is_empty(),
            "left the previous target in the box"
        );
    }

    #[test]
    fn a_typed_target_dials_something_not_in_the_inventory() {
        let mut app = fresh_app("quickdial", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Char('c'));
        for c in "deploy@10.9.9.9:2222".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Browse, "should leave the prompt");
        assert!(
            app.connecting.contains_key("deploy@10.9.9.9:2222"),
            "dialled {:?}",
            app.connecting.keys().collect::<Vec<_>>()
        );
        // Reaching somewhere once must not add it to the inventory.
        assert_eq!(app.inventory.hosts.len(), 1, "the inventory grew");
    }

    /// Typing a name you have configured must use that entry, not a bare address
    /// spelled the same way. Dialling `db-primary` ad-hoc would go straight at it
    /// with the agent and fail, ignoring the key and the bastion in the inventory.
    #[test]
    fn a_typed_name_that_is_saved_uses_the_saved_host() {
        let mut bastion = host("bastion", &[]);
        bastion.address = "10.0.0.254".into();
        let mut target = host("db-primary", &[]);
        target.jump = Some("bastion".into());

        let mut app = fresh_app("quicksaved", vec![bastion, target]);
        press(&mut app, KeyCode::Char('c'));
        for c in "db-primary".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(
            app.connecting.contains_key("db-primary"),
            "dialled {:?}",
            app.connecting.keys().collect::<Vec<_>>()
        );
        // "via 1 host" only appears when the chain came from the inventory — an
        // ad-hoc target has no jump host to tunnel through.
        assert!(
            matches!(&app.status, Status::Busy(m) if m.contains("via 1 host")),
            "did not resolve the saved jump chain, got {:?}",
            app.status
        );
        // And it says so, because the address dialled need not resemble the name.
        assert!(
            matches!(&app.status, Status::Busy(m) if m.contains("saved host")),
            "did not say it used the inventory, got {:?}",
            app.status
        );
    }

    /// The escape hatch: adding a user or a port stops it matching a *name*, so
    /// the literal host is still reachable when an entry shares its spelling.
    #[test]
    fn a_user_or_port_reaches_the_literal_host_despite_a_saved_name() {
        let mut app = fresh_app("quickliteral", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Char('c'));
        for c in "root@web-01".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(
            app.connecting.contains_key("root@web-01"),
            "did not dial the literal host: {:?}",
            app.connecting.keys().collect::<Vec<_>>()
        );
        assert!(
            !matches!(&app.status, Status::Busy(m) if m.contains("saved host")),
            "treated it as the saved entry, got {:?}",
            app.status
        );
    }

    /// A saved name whose jump chain is broken has to report *that*, rather than
    /// quietly falling back to dialling the bare name.
    #[test]
    fn a_saved_name_with_a_broken_chain_reports_the_chain() {
        let mut target = host("db-primary", &[]);
        target.jump = Some("no-such-bastion".into());
        let mut app = fresh_app("quickbrokenchain", vec![target]);

        press(&mut app, KeyCode::Char('c'));
        for c in "db-primary".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(
            matches!(&app.status, Status::Error(m) if m.contains("no-such-bastion")),
            "got {:?}",
            app.status
        );
        assert!(app.connecting.is_empty(), "dialled anyway");
    }

    /// A mistyped port is fixed by editing the port, so the prompt and the text
    /// both have to survive the error.
    #[test]
    fn a_bad_target_keeps_the_prompt_up() {
        let mut app = fresh_app("quickbad", vec![]);
        press(&mut app, KeyCode::Char('c'));
        for c in "host:not-a-port".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::QuickConnect, "dropped out of the prompt");
        assert_eq!(app.quick_input, "host:not-a-port", "lost what was typed");
        assert!(matches!(&app.status, Status::Error(m) if m.contains("port")));
        assert!(
            app.connecting.is_empty(),
            "dialled a target it could not read"
        );
    }

    #[test]
    fn esc_abandons_quick_connect() {
        let mut app = fresh_app("quickesc", vec![]);
        press(&mut app, KeyCode::Char('c'));
        press(&mut app, KeyCode::Char('x'));

        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::Browse);
        assert!(app.quick_input.is_empty());
        assert!(app.connecting.is_empty());
    }

    /// Typing the same target twice should land back in the session you already
    /// have, the same way `↵` behaves in the list.
    #[test]
    fn a_typed_target_that_is_already_open_resumes_it() {
        let mut app = fresh_app("quickresume", vec![]);
        let (session, _keepalive) = ssh::LiveSession::for_test("deploy@10.9.9.9");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('c'));
        for c in "deploy@10.9.9.9".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.pending_attach, Some(0), "should resume, not redial");
        assert!(app.connecting.is_empty());
    }

    /// Sessions share the primary screen, so moving to another one is marked with
    /// a rule naming it — otherwise you cannot tell which machine you are typing
    /// at. Re-attaching the *same* session marks nothing: no boundary was crossed.
    #[test]
    fn switching_sessions_is_marked_but_resuming_one_is_not() {
        let mut app = fresh_app("clearscreen", vec![]);
        let (alpha, _ka) = ssh::LiveSession::for_test("alpha");
        let (beta, _kb) = ssh::LiveSession::for_test("beta");
        let (alpha_id, beta_id) = (alpha.id(), beta.id());
        app.sessions.push(alpha);
        app.sessions.push(beta);

        // Nothing attached yet: the leftover text is the user's own shell.
        assert!(!app.switching_to(alpha_id), "cleared on the first attach");

        app.last_attached = Some(alpha_id);
        assert!(!app.switching_to(alpha_id), "cleared on a plain re-attach");
        assert!(app.switching_to(beta_id), "did not clear when switching");
    }

    /// A session dying does not make the *next* attach a re-attach. Ids are never
    /// reused, so a reconnect to the same host is still a different session and
    /// still has to clear the previous one's screen.
    #[test]
    fn a_reconnect_after_a_death_still_counts_as_switching() {
        let mut app = fresh_app("clearafterdeath", vec![host("web-01", &[])]);
        let (first, _r1) = ssh::LiveSession::for_test("web-01");
        let first_id = first.id();
        app.sessions.push(first);
        app.last_attached = Some(first_id);

        app.sessions[0].mark_ended_for_test();
        app.prune_dead_sessions();

        let (second, _r2) = ssh::LiveSession::for_test("web-01");
        assert_ne!(second.id(), first_id, "ids must not be reused");
        assert!(
            app.switching_to(second.id()),
            "a fresh session on the same host was treated as a re-attach"
        );
    }

    /// Capitalisation must not decide whether the inventory is consulted.
    #[test]
    fn a_typed_name_matches_the_saved_host_whatever_the_case() {
        let mut target = host("db-primary", &[]);
        target.jump = Some("bastion".into());
        let mut bastion = host("bastion", &[]);
        bastion.address = "10.0.0.254".into();
        let mut app = fresh_app("quickcase", vec![bastion, target]);

        press(&mut app, KeyCode::Char('c'));
        for c in "DB-Primary".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(
            matches!(&app.status, Status::Busy(m) if m.contains("saved host")),
            "case defeated the inventory lookup, got {:?}",
            app.status
        );
    }

    /// Whitespace around a typed name still finds the saved host — the trim has to
    /// happen before the lookup, not only inside the parser.
    #[test]
    fn a_padded_typed_name_still_matches_the_saved_host() {
        let mut target = host("db-primary", &[]);
        target.jump = Some("bastion".into());
        let mut bastion = host("bastion", &[]);
        bastion.address = "10.0.0.254".into();
        let mut app = fresh_app("quickpadded", vec![bastion, target]);

        press(&mut app, KeyCode::Char('c'));
        for c in "  db-primary  ".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(
            matches!(&app.status, Status::Busy(m) if m.contains("saved host")),
            "padding defeated the inventory lookup, got {:?}",
            app.status
        );
    }

    /// Backspacing the whole target and pressing enter must not dial anything.
    #[test]
    fn an_emptied_quick_connect_prompt_dials_nothing() {
        let mut app = fresh_app("quickemptied", vec![]);
        press(&mut app, KeyCode::Char('c'));
        for c in "abc".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        for _ in 0..5 {
            press(&mut app, KeyCode::Backspace);
        }
        press(&mut app, KeyCode::Enter);

        assert!(app.quick_input.is_empty());
        assert!(app.connecting.is_empty(), "dialled an empty target");
        assert_eq!(app.mode, Mode::QuickConnect, "left the prompt on an error");
    }

    /// The rule drawn on a switch and the row in the session list have to name
    /// the session the same way, or `Ubuntu VM` three times over tells you
    /// nothing about which one you arrived in.
    #[test]
    fn a_session_label_numbers_only_where_a_host_repeats() {
        let mut app = fresh_app("labels", vec![]);
        let (a, _ra) = ssh::LiveSession::for_test("ubuntu-vm");
        let (b, _rb) = ssh::LiveSession::for_test("db-primary");
        let (c, _rc) = ssh::LiveSession::for_test("ubuntu-vm");
        app.sessions.push(a);
        app.sessions.push(b);
        app.sessions.push(c);

        assert_eq!(app.session_label(0), "ubuntu-vm #1");
        assert_eq!(
            app.session_label(2),
            "ubuntu-vm #2",
            "numbered by order opened"
        );
        assert_eq!(
            app.session_label(1),
            "db-primary",
            "a lone session is not numbered"
        );
        assert_eq!(
            app.session_label(99),
            "",
            "out of range is empty, not a panic"
        );
    }

    #[test]
    fn x_asks_before_disconnecting_and_esc_keeps_the_session() {
        let mut app = fresh_app("closeask", vec![host("web-01", &[])]);
        let (session, _keep) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('x'));
        assert_eq!(app.mode, Mode::ConfirmClose, "closed without asking");

        press(&mut app, KeyCode::Esc);
        assert_eq!(app.sessions.len(), 1, "esc still killed the session");
        assert_eq!(app.mode, Mode::Browse);
    }

    #[test]
    fn confirming_disconnects_and_drops_the_row() {
        let mut app = fresh_app("closedo", vec![host("web-01", &[])]);
        let (session, _keep) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Char('y'));

        assert!(
            app.sessions.is_empty(),
            "the session outlived the disconnect"
        );
        assert!(
            matches!(&app.status, Status::Ok(m) if m.contains("web-01")),
            "should name what it closed, got {:?}",
            app.status
        );
    }

    /// The prompt holds an id, so a session ending underneath it must not send
    /// the confirmation to whichever row slid into that slot.
    #[test]
    fn confirming_after_the_rows_shift_closes_the_right_session() {
        let mut app = fresh_app("closeshift", vec![]);
        let (alpha, _ka) = ssh::LiveSession::for_test("alpha");
        let (beta, _kb) = ssh::LiveSession::for_test("beta");
        app.sessions.push(alpha);
        app.sessions.push(beta);

        // Ask to close beta, then lose alpha before confirming.
        app.session_selected = 1;
        app.mode = Mode::SessionList;
        press(&mut app, KeyCode::Char('x'));
        app.sessions[0].mark_ended_for_test();
        app.prune_dead_sessions();

        press(&mut app, KeyCode::Char('y'));

        assert!(app.sessions.is_empty(), "beta should be gone");
    }

    /// Closing a session must not misdirect a resume that is already pending,
    /// the same hazard `prune_dead_sessions` handles.
    #[test]
    fn closing_a_session_keeps_a_pending_resume_pointed_at_its_own() {
        let mut app = fresh_app("closepending", vec![]);
        for host in ["alpha", "beta", "gamma"] {
            let (session, keep) = ssh::LiveSession::for_test(host);
            app.sessions.push(session);
            std::mem::forget(keep);
        }
        app.pending_attach = Some(2); // gamma

        app.forget_session(0); // alpha goes

        assert_eq!(
            app.pending_attach,
            Some(1),
            "the resume should follow gamma"
        );
        assert_eq!(app.sessions[1].host, "gamma");
    }

    /// Closing several is the point, so the prompt returns you to the list you
    /// raised it from — until there is nothing left to return to.
    #[test]
    fn closing_from_the_list_goes_back_to_the_list() {
        let mut app = fresh_app("closeback", vec![]);
        let (a, _ka) = ssh::LiveSession::for_test("alpha");
        let (b, _kb) = ssh::LiveSession::for_test("beta");
        app.sessions.push(a);
        app.sessions.push(b);
        app.mode = Mode::SessionList;

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(
            app.mode,
            Mode::SessionList,
            "bounced out with one still open"
        );
        assert_eq!(app.sessions.len(), 1);

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.mode, Mode::Browse, "stayed in an empty list");
        assert!(app.sessions.is_empty());
    }

    /// Cancelling returns you where you were too, rather than to the host list.
    #[test]
    fn cancelling_a_close_from_the_list_stays_in_the_list() {
        let mut app = fresh_app("closecancel", vec![]);
        let (a, _ka) = ssh::LiveSession::for_test("alpha");
        app.sessions.push(a);
        app.mode = Mode::SessionList;

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Esc);

        assert_eq!(app.mode, Mode::SessionList);
        assert_eq!(app.sessions.len(), 1, "esc killed the session");
    }

    /// From the host list it behaves the other way: there is no list to go back to.
    #[test]
    fn closing_from_the_host_list_stays_on_the_host_list() {
        let mut app = fresh_app("closehostlist", vec![host("web-01", &[])]);
        let (session, _keep) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Char('y'));

        assert_eq!(app.mode, Mode::Browse);
    }

    /// The whole point: fixing a typo in the middle without rubbing out
    /// everything after it. Before this the form was append-only.
    #[test]
    fn the_form_edits_in_the_middle_of_a_field() {
        let mut app = fresh_app("formedit", vec![]);
        press(&mut app, KeyCode::Char('a'));
        for c in "web-1".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        // Back over the "1" and insert a "0" before it.
        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Char('0'));

        assert_eq!(app.form.as_ref().unwrap().name, "web-01");
    }

    #[test]
    fn home_end_and_delete_work_in_a_field() {
        let mut app = fresh_app("formnav", vec![]);
        press(&mut app, KeyCode::Char('a'));
        for c in "web-01".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Home);
        press(&mut app, KeyCode::Delete);
        assert_eq!(
            app.form.as_ref().unwrap().name,
            "eb-01",
            "delete at the caret"
        );

        press(&mut app, KeyCode::End);
        press(&mut app, KeyCode::Char('x'));
        assert_eq!(
            app.form.as_ref().unwrap().name,
            "eb-01x",
            "end went to the end"
        );

        press(&mut app, KeyCode::Home);
        press(&mut app, KeyCode::Backspace);
        assert_eq!(
            app.form.as_ref().unwrap().name,
            "eb-01x",
            "backspace at the start should do nothing"
        );
    }

    /// Moving between fields has to take the caret with it, or typing in the
    /// next field inserts at an offset from the previous one.
    #[test]
    fn the_caret_follows_focus_between_fields() {
        let mut app = fresh_app("formfocus", vec![]);
        press(&mut app, KeyCode::Char('a'));
        for c in "web-01".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Home); // caret at 0 in `name`

        press(&mut app, KeyCode::Tab); // address, which is empty
        for c in "10.0.0.1".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        let form = app.form.as_ref().unwrap();
        assert_eq!(form.address, "10.0.0.1", "typed out of order");
        assert_eq!(form.name, "web-01", "the other field was disturbed");
    }

    /// Arrows still cycle a selector — they are the only way to change one.
    #[test]
    fn arrows_still_cycle_a_choice_field() {
        let mut app = fresh_app("formchoice", vec![]);
        press(&mut app, KeyCode::Char('a'));
        if let Some(form) = app.form.as_mut() {
            form.focus_on(Field::Auth);
        }
        let before = app.form.as_ref().unwrap().auth_choice;

        press(&mut app, KeyCode::Right);

        assert_ne!(
            app.form.as_ref().unwrap().auth_choice,
            before,
            "right no longer cycles the auth selector"
        );
    }

    /// The filter edits in place too — it was append-only for the same reason
    /// the form was.
    #[test]
    fn the_filter_edits_in_the_middle() {
        let mut app = fresh_app("filteredit", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Char('/'));
        for c in "web1".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Char('-'));
        assert_eq!(app.filter, "web-1");

        press(&mut app, KeyCode::Home);
        press(&mut app, KeyCode::Delete);
        assert_eq!(app.filter, "eb-1", "delete at the caret");

        press(&mut app, KeyCode::End);
        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.filter, "eb-", "end then backspace takes the last");
    }

    /// Entering the filter with something already in it puts the caret at the
    /// end, not back at the start.
    #[test]
    fn reopening_the_filter_puts_the_caret_at_the_end() {
        let mut app = fresh_app("filterreopen", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Char('/'));
        for c in "web".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter); // back to browse, filter kept

        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Char('x'));

        assert_eq!(app.filter, "webx", "typing landed somewhere else");
    }

    #[test]
    fn quick_connect_edits_in_the_middle() {
        let mut app = fresh_app("quickedit", vec![]);
        press(&mut app, KeyCode::Char('c'));
        for c in "deploy@10.0.0.".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Home);
        for c in "root".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.quick_input, "rootdeploy@10.0.0.");

        press(&mut app, KeyCode::Delete);
        assert_eq!(app.quick_input, "rooteploy@10.0.0.", "delete at the caret");
    }

    /// Clearing has to take the caret with it, or the next thing typed lands at
    /// an offset into an empty string.
    #[test]
    fn leaving_an_input_resets_its_caret() {
        let mut app = fresh_app("caretreset", vec![]);
        press(&mut app, KeyCode::Char('c'));
        for c in "abcdef".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Esc);

        press(&mut app, KeyCode::Char('c'));
        press(&mut app, KeyCode::Char('z'));
        assert_eq!(app.quick_input, "z");
        assert_eq!(app.quick_cursor, 1);
    }

    /// Every path that empties an input has to take its caret with it. This one
    /// returns early on a saved-host match and used to miss the reset.
    #[test]
    fn connecting_to_a_saved_name_resets_the_quick_caret() {
        let mut app = fresh_app("quickcaretsaved", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Char('c'));
        for c in "web-01".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert!(app.quick_input.is_empty());
        assert_eq!(app.quick_cursor, 0, "the caret outlived the value");
    }

    /// `↵` on a connected host must keep resuming. If it opened a second shell
    /// instead, every stray Enter would leave one behind on the remote.
    #[test]
    fn enter_on_a_connected_host_resumes_rather_than_opening_another() {
        let mut app = fresh_app("resumenotnew", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Enter);

        assert_eq!(
            app.pending_attach,
            Some(0),
            "should resume the existing one"
        );
        assert!(
            app.connecting.is_empty(),
            "started a second connection instead of resuming"
        );
    }

    /// `n` is the deliberate ask for another shell on a host that already has one.
    #[test]
    fn n_opens_a_second_session_on_a_connected_host() {
        let mut app = fresh_app("newsession", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);

        press(&mut app, KeyCode::Char('n'));

        assert!(
            app.connecting.contains_key("web-01"),
            "no second connection was started"
        );
        assert!(
            app.pending_attach.is_none(),
            "resumed the existing session instead of dialling"
        );
    }

    /// A session that dies while detached must be reported, not just dropped.
    /// The row vanishing on its own leaves you pressing `s`, finding nothing,
    /// and guessing why.
    #[test]
    fn a_session_that_dies_while_detached_is_announced() {
        let mut app = fresh_app("deadsession", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("db-primary");
        app.sessions.push(session);

        app.sessions[0].mark_ended_for_test();
        assert!(app.prune_dead_sessions(), "should report a change");

        assert!(app.sessions.is_empty());
        assert!(
            matches!(&app.status, Status::Error(m) if m.contains("db-primary")),
            "should name the host that went, got {:?}",
            app.status
        );
    }

    /// Nothing to say when nothing died — this runs on every pass of the loop.
    #[test]
    fn pruning_with_nothing_dead_says_nothing() {
        let mut app = fresh_app("nodeadsession", vec![host("web-01", &[])]);
        let (session, _keepalive) = ssh::LiveSession::for_test("web-01");
        app.sessions.push(session);
        app.status = Status::Ok("something else".into());

        assert!(!app.prune_dead_sessions());
        assert!(
            matches!(&app.status, Status::Ok(m) if m == "something else"),
            "clobbered an unrelated status, got {:?}",
            app.status
        );
    }

    /// `luvienne <host>` must dial the host it was given, not whichever one the
    /// list happens to open on. The selection follows too, so detaching lands on
    /// the host you just left rather than somewhere unrelated.
    #[test]
    fn connect_to_dials_the_named_host_rather_than_the_selected_one() {
        let mut app = fresh_app(
            "cliconnect",
            vec![host("web-01", &[]), host("db-primary", &[])],
        );
        assert_eq!(app.selected, 0, "expected to open on the first host");

        assert!(app.connect_to("db-primary"), "the host was not found");

        assert!(
            app.connecting.contains_key("db-primary"),
            "dialled {:?} instead",
            app.connecting.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            app.selected_host().map(|h| h.name.as_str()),
            Some("db-primary"),
            "the list selection did not follow"
        );
    }

    /// The binary checks the name against the inventory before it gets here, so
    /// this is the belt-and-braces case: report it and dial nothing.
    #[test]
    fn connect_to_an_absent_host_dials_nothing() {
        let mut app = fresh_app("cliabsent", vec![host("web-01", &[])]);

        assert!(!app.connect_to("no-such-box"));
        assert!(
            app.connecting.is_empty(),
            "started a connection for a host that does not exist"
        );
    }

    /// A failure has to clear the marker, or the host is stuck looking busy and
    /// can never be retried.
    #[test]
    fn a_failed_connect_can_be_retried() {
        let mut app = fresh_app("retry", vec![host("web-01", &[])]);
        app.connecting.remove("web-01");
        assert!(!app.connecting.contains_key("web-01"));

        press(&mut app, KeyCode::Enter);
        assert!(
            app.connecting.contains_key("web-01"),
            "a retry after failure should dial again"
        );
    }

    /// A host that is simply not answering has to be abandonable.
    #[test]
    fn esc_cancels_a_connect_in_flight() {
        let mut app = fresh_app("cancel", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Enter);
        assert!(app.connecting.contains_key("web-01"));

        press(&mut app, KeyCode::Esc);

        assert!(app.connecting.is_empty(), "the connect was not aborted");
        assert!(
            matches!(&app.status, Status::Error(m) if m.contains("cancelled")),
            "should say it was cancelled, got {:?}",
            app.status
        );
    }

    /// And after cancelling, the host must be dialable again.
    #[test]
    fn a_cancelled_host_can_be_dialled_again() {
        let mut app = fresh_app("recancel", vec![host("web-01", &[])]);
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Enter);
        assert!(
            app.connecting.contains_key("web-01"),
            "a cancelled host should be retryable"
        );
    }

    /// Esc keeps its old job when nothing is connecting.
    #[test]
    fn esc_still_clears_the_filter_when_nothing_is_connecting() {
        let mut app = fresh_app("escfilter", vec![host("web-01", &[])]);
        app.filter = "web".into();
        app.tag_filter = Some("prod".into());

        press(&mut app, KeyCode::Esc);

        assert_eq!(app.filter, "");
        assert_eq!(app.tag_filter, None);
    }

    /// The point of a bulk edit: change one field across many hosts without
    /// flattening everything else about them.
    #[test]
    fn bulk_edit_changes_only_the_touched_field() {
        let mut a = host("alpha", &["prod"]);
        a.user = "one".into();
        a.port = 2222;
        let mut b = host("beta", &["dev"]);
        b.user = "two".into();
        let mut app = fresh_app("bulk", vec![a, b]);

        press(&mut app, KeyCode::Char('b'));
        assert_eq!(app.mode, Mode::Form);

        // Focus the user field and type into it.
        if let Some(form) = app.form.as_mut() {
            form.focus_on(Field::User);
        }
        for c in "deploy".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.inventory.hosts[0].user, "deploy");
        assert_eq!(app.inventory.hosts[1].user, "deploy");
        // Untouched fields survive.
        assert_eq!(app.inventory.hosts[0].port, 2222, "port was flattened");
        assert_eq!(app.inventory.hosts[0].tags, vec!["prod"], "tags flattened");
        assert_eq!(app.inventory.hosts[1].tags, vec!["dev"]);
    }

    /// The filter is the selection, so a bulk edit must not touch hosts that
    /// are not on screen.
    #[test]
    fn bulk_edit_only_touches_visible_hosts() {
        let mut app = fresh_app("bulkfilter", vec![host("alpha", &[]), host("beta", &[])]);
        app.filter = "alpha".into();

        press(&mut app, KeyCode::Char('b'));
        if let Some(form) = app.form.as_mut() {
            form.focus_on(Field::User);
        }
        for c in "only".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.inventory.hosts[0].user, "only");
        assert_eq!(
            app.inventory.hosts[1].user, "deploy",
            "a filtered-out host was edited"
        );
    }

    /// Clearing a field has to be expressible — "non-empty means apply" could
    /// not set 60 hosts back to "ask for the username".
    #[test]
    fn bulk_edit_can_deliberately_clear_a_field() {
        let mut a = host("alpha", &[]);
        a.user = "someone".into();
        let mut app = fresh_app("bulkclear", vec![a]);

        press(&mut app, KeyCode::Char('b'));
        if let Some(form) = app.form.as_mut() {
            form.focus_on(Field::User);
        }
        // Typed and then rubbed out, which is how a field gets *deliberately*
        // emptied — assigning the value directly would leave the caret behind it.
        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Backspace);
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.inventory.hosts[0].user, "", "clearing did not apply");
    }

    /// Pressing enter with nothing changed should say so rather than silently
    /// rewriting every host with its own values.
    #[test]
    fn bulk_edit_with_no_changes_is_refused() {
        let mut app = fresh_app("bulknoop", vec![host("alpha", &[])]);
        press(&mut app, KeyCode::Char('b'));
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.mode, Mode::Form, "should stay open");
        let error = app.form.as_ref().unwrap().error.clone().unwrap();
        assert!(error.contains("change a field"), "got: {error}");
    }

    #[test]
    fn a_prompt_cannot_be_answered_twice() {
        let mut app = app_with(vec![]);
        let mut answer = arm_prompt(&mut app);
        press(&mut app, KeyCode::Char('y'));
        // Mode is Browse now, so 'n' is a normal browse key and cannot reach
        // the (already taken) prompt.
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(answer.try_recv(), Ok(true));
        assert!(app.host_key_prompt.is_none());
    }
}
