//! A live SSH session, owned by its own task.
//!
//! The session has to keep being serviced whether or not anyone is looking at
//! it. If the foreground simply stopped reading the channel while detached, the
//! channel's queue would fill, the russh session task would block inside that
//! send, and the whole connection — keepalives included — would stall until the
//! server gave up on it.
//!
//! So the channel is owned by a task that always drains it. Attaching just tells
//! that task where to send output; detaching tells it to buffer instead.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use russh::client::Handle;
use russh::{Channel, ChannelMsg, client};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// How much output to keep while detached, per session.
///
/// A cap is unavoidable — a detached `tail -f` would otherwise grow without
/// bound — so a chatty session loses its middle rather than its end. The tail is
/// what you want on return.
const BACKLOG_LIMIT: usize = 256 * 1024;

/// How much recent output each session keeps for a *switch*.
///
/// Different from the backlog, which holds only what arrived while detached and
/// is replayed on any attach. This is kept all the time, so that arriving from
/// another session lands on the shell's recent context rather than a blank space
/// below the rule: the remote already printed its prompt and will not print
/// another until a command finishes, so nothing else can put it back.
///
/// A screenful and a bit. Larger only costs memory; smaller starts cutting the
/// prompt off the top of what is replayed.
const TAIL_LIMIT: usize = 16 * 1024;

/// Handed out to distinguish one session from another.
///
/// Position in `App::sessions` cannot do it: rows shift as sessions end, and the
/// caller needs to know whether the session it is attaching to is the one it
/// attached to last — the answer decides whether the screen is cleared.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Why [`crate::ssh::attach`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    /// The remote closed. The session is gone.
    Ended(Option<u32>),
    /// The user pressed the detach key. The session is still running.
    Detached,
}

/// Output travelling from the session task to whoever is attached.
pub enum Output {
    Bytes(Vec<u8>),
    Ended(Option<u32>),
}

/// The bytes an attach is sent, and the backlog left behind.
///
/// The tail is a screenful of context; the backlog is everything actually
/// missed. Never trade the second for the first — arriving without context is a
/// nuisance, losing a build's output is a bug. So the tail only wins when it
/// already covers everything the backlog holds.
fn replay_bytes(replay: Replay, tail: &VecDeque<u8>, backlog: &mut VecDeque<u8>) -> Vec<u8> {
    match replay {
        Replay::Recent if backlog.len() <= tail.len() => {
            backlog.clear();
            // Repainting old output must not ring old bells or set titles and
            // clipboards a second time.
            strip_side_effects(&tail.iter().copied().collect::<Vec<_>>())
        }
        // Either nothing was missed and the tail is the context, or more was
        // missed than the tail holds. Both are first-arrival output, where a
        // bell is a real bell.
        Replay::Recent | Replay::Missed => backlog.drain(..).collect(),
    }
}

/// Which replay an attach should ask for.
///
/// A full-screen program is deliberately excluded from `Recent`. It repaints
/// itself from the resize nudge, so replaying is unnecessary — and dangerous,
/// because its output contains alternate-screen switches (`ESC[?1049h/l`) that
/// `strip_side_effects` does not remove: replaying those flips the terminal's
/// buffer underneath a remote that believes it is still in the other one.
pub fn replay_for(switching: bool, remote_in_alt_screen: bool) -> Replay {
    if switching && !remote_in_alt_screen {
        Replay::Recent
    } else {
        Replay::Missed
    }
}

/// What an attach wants replayed onto the screen it is landing on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Coming back to this session's own screen: only what it missed. The rest
    /// is already on the terminal, and re-sending it would print it twice.
    Missed,
    /// Arriving from a different session, below a rule, with this session's
    /// screen nowhere in sight. Replay its recent output so the prompt is there.
    Recent,
}

pub(crate) enum Command {
    Input(Vec<u8>),
    Resize {
        cols: u32,
        rows: u32,
        xpix: u32,
        ypix: u32,
    },
    /// Start forwarding output here, beginning with anything buffered.
    Attach(UnboundedSender<Output>, Replay),
    /// Stop forwarding; buffer instead.
    Detach,
    Close,
}

/// Tracks whether the remote has switched the terminal to its alternate screen.
///
/// The *only* place session bytes are inspected, and deliberately bounded to the
/// smcup/rmcup sequences. Without it, detaching from a full-screen program and
/// coming back leaves the terminal in the primary buffer while the program still
/// believes it is in the alternate one, and everything it draws lands in the
/// wrong place. This is a state flag, not a terminal emulator — nothing here
/// interprets content.
#[derive(Default)]
struct AltScreenTracker {
    /// Carry-over, in case a sequence is split across two reads.
    tail: Vec<u8>,
}

impl AltScreenTracker {
    /// Returns the new state if this chunk changed it.
    fn observe(&mut self, data: &[u8]) -> Option<bool> {
        let mut scan = std::mem::take(&mut self.tail);
        scan.extend_from_slice(data);

        let mut state = None;
        // Where an unterminated sequence starts, if the chunk ended mid-escape.
        let mut incomplete = None;
        let mut i = 0;

        while i < scan.len() {
            if !scan[i..].starts_with(b"\x1b[?") {
                // A trailing partial prefix still has to be carried over.
                if scan.len() - i < 3 && b"\x1b[?".starts_with(&scan[i..]) {
                    incomplete = Some(i);
                    break;
                }
                i += 1;
                continue;
            }

            let mut j = i + 3;
            while j < scan.len() && scan[j].is_ascii_digit() {
                j += 1;
            }
            if j >= scan.len() {
                incomplete = Some(i);
                break;
            }
            if matches!(scan[j], b'h' | b'l') {
                let mode = std::str::from_utf8(&scan[i + 3..j])
                    .ok()
                    .and_then(|digits| digits.parse::<u16>().ok());
                if matches!(mode, Some(47) | Some(1047) | Some(1049)) {
                    // Last switch in the chunk wins.
                    state = Some(scan[j] == b'h');
                }
            }
            i = j + 1;
        }

        // Only an *unfinished* sequence carries over. Keeping a fixed-size tail
        // would re-scan sequences already handled and report them twice.
        self.tail = match incomplete {
            Some(start) => scan[start..].to_vec(),
            None => Vec::new(),
        };
        state
    }
}

/// Stops the forward listeners when the session task ends.
///
/// A guard rather than a line at the end of `run`, because `run` has several
/// exits and a listener left behind holds both a port and an `Arc` on the
/// connection's handle — the session would look closed while its tunnels kept
/// the transport alive.
struct AbortOnDrop(Vec<crate::ssh::forward::Running>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for running in &self.0 {
            running.task.abort();
        }
    }
}

/// A handle to a running session. Cloneable only in the sense that the app holds
/// exactly one; dropping it does *not* close the session, so a handle must be
/// closed explicitly or deliberately leaked at exit.
pub struct LiveSession {
    /// Unique for the life of the process. See [`NEXT_ID`].
    id: u64,
    pub host: String,
    commands: UnboundedSender<Command>,
    ended: Arc<AtomicBool>,
    /// Whether the remote currently has the terminal in its alternate screen.
    remote_alt: Arc<AtomicBool>,
    /// Cleared after the first attach, so only a *re*-attach forces a repaint.
    first_attach: Arc<AtomicBool>,
    /// Kept so a wedged session can be killed outright. `Command::Close` is
    /// polite and needs the task's loop to be turning; a task blocked inside an
    /// await — the far end stopped reading, say — never sees it. Aborting drops
    /// the transport handles the task owns, which tears the connection down
    /// whatever it was waiting on.
    ///
    /// `Option` for the test constructor, which has no runtime to spawn on and
    /// no connection to tear down.
    task: Option<tokio::task::JoinHandle<()>>,
    /// Forwards the session asked for and did not get, kept so the failure can
    /// be shown after the connect status has been replaced.
    forward_failures: Vec<String>,
}

impl std::fmt::Debug for LiveSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveSession")
            .field("host", &self.host)
            .field("ended", &self.has_ended())
            .finish()
    }
}

impl LiveSession {
    /// Take ownership of an authenticated connection and start servicing it.
    ///
    /// The russh `Handle`s own the transport tasks, so they are moved into ours:
    /// the connections then live exactly as long as the session and are torn
    /// down when it ends. With a jump chain there is one per hop, and the outer
    /// ones must outlive the inner tunnels running through them.
    pub fn spawn(
        host: String,
        transports: Vec<Arc<Handle<crate::ssh::Client>>>,
        channel: Channel<client::Msg>,
        forwards: crate::ssh::forward::Started,
    ) -> Self {
        let (commands, rx) = unbounded_channel();
        let ended = Arc::new(AtomicBool::new(false));
        let remote_alt = Arc::new(AtomicBool::new(false));
        let forward_failures = forwards.failures;
        let task = tokio::spawn(run(
            transports,
            channel,
            rx,
            Arc::clone(&ended),
            Arc::clone(&remote_alt),
            forwards.running,
        ));
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            host,
            commands,
            ended,
            remote_alt,
            first_attach: Arc::new(AtomicBool::new(true)),
            task: Some(task),
            forward_failures,
        }
    }

    /// Identity, stable while the session lives.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Forwards that could not be raised. Empty when everything came up.
    pub fn forward_failures(&self) -> &[String] {
        &self.forward_failures
    }

    /// True if the remote left the terminal in its alternate screen.
    pub fn remote_in_alt_screen(&self) -> bool {
        self.remote_alt.load(Ordering::Relaxed)
    }

    /// True the first time, false on every resume afterwards.
    pub(super) fn take_first_attach(&self) -> bool {
        self.first_attach.swap(false, Ordering::Relaxed)
    }

    /// True once the remote has closed. A detached session can end on its own —
    /// someone types `exit` from another window, the server reboots — so this is
    /// checked before offering to resume.
    pub fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Relaxed) || self.commands.is_closed()
    }

    fn send(&self, command: Command) -> bool {
        self.commands.send(command).is_ok()
    }

    pub(super) fn attach_output(&self, sink: UnboundedSender<Output>, replay: Replay) -> bool {
        self.send(Command::Attach(sink, replay))
    }

    pub(super) fn detach_output(&self) -> bool {
        self.send(Command::Detach)
    }

    pub(super) fn write_input(&self, bytes: Vec<u8>) -> bool {
        self.send(Command::Input(bytes))
    }

    pub(super) fn resize(&self, cols: u32, rows: u32, xpix: u32, ypix: u32) -> bool {
        self.send(Command::Resize {
            cols,
            rows,
            xpix,
            ypix,
        })
    }

    /// Close the remote session. Used when quitting, so sessions are not left
    /// dangling on the server.
    pub fn close(&self) {
        self.send(Command::Close);
    }

    /// Close a session and make sure it is gone.
    ///
    /// Asks politely first, so a responsive session closes its channel cleanly
    /// and the server sees a normal disconnect. Then aborts regardless: this is
    /// reached because the user wants the session gone, and the sessions people
    /// want gone are exactly the ones too wedged to answer.
    ///
    /// `ended` is set here rather than left to the task, which by then may never
    /// run again — otherwise the session would linger in the list looking alive.
    pub fn disconnect(&self) {
        self.send(Command::Close);
        if let Some(task) = &self.task {
            task.abort();
        }
        self.ended.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
impl LiveSession {
    /// A session with no real connection behind it.
    ///
    /// The caller must keep the returned receiver alive for the session to look
    /// live: dropping it closes the command channel, which is exactly how
    /// `has_ended` notices a task that has gone away.
    pub fn for_test(host: &str) -> (Self, UnboundedReceiver<Command>) {
        let (commands, receiver) = unbounded_channel();
        (
            Self {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                // No task: the tests never run a real session, and spawning one
                // here would need a runtime in context that they do not have.
                task: None,
                host: host.into(),
                commands,
                ended: Arc::new(AtomicBool::new(false)),
                remote_alt: Arc::new(AtomicBool::new(false)),
                first_attach: Arc::new(AtomicBool::new(true)),
                forward_failures: Vec::new(),
            },
            receiver,
        )
    }

    pub fn mark_ended_for_test(&self) {
        self.ended.store(true, Ordering::Relaxed);
    }
}

/// Strip the sequences that *do* something, leaving the ones that draw.
///
/// A replay is a repaint, and a repaint must not re-run side effects. Raw bytes
/// re-run all of them: every prompt a real shell draws usually carries an OSC
/// title sequence terminated by `BEL`, so a tail holding a dozen prompts rings
/// the bell a dozen times — and OSC 52 would rewrite the clipboard. Titles are
/// ours anyway (`ui::set_title`), and a bell about something that happened
/// minutes ago is noise.
///
/// Only OSC and bare `BEL` are removed. CSI sequences are what paint the screen,
/// so they stay — which is also why this cannot be a blanket filter.
fn strip_side_effects(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // OSC: ESC ] … terminated by BEL or ST (ESC \).
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b']') {
            let mut j = i + 2;
            while j < bytes.len() {
                if bytes[j] == 0x07 {
                    j += 1;
                    break;
                }
                if bytes[j] == 0x1b && bytes.get(j + 1) == Some(&b'\\') {
                    j += 2;
                    break;
                }
                j += 1;
            }
            i = j;
            continue;
        }
        // A bell on its own: whatever rang it is long past.
        if bytes[i] == 0x07 {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Keep the tail trimmed to [`TAIL_LIMIT`], cutting at a line boundary.
///
/// Cutting mid-escape would replay half a control sequence and paint garbage.
/// A newline is not a guarantee — a sequence *can* span one — but escapes
/// overwhelmingly do not, and this is the cheap approximation. A grid would be
/// the guarantee, and that is a terminal emulator.
fn push_tail(tail: &mut VecDeque<u8>, data: &[u8]) {
    tail.extend(data.iter().copied());
    if tail.len() <= TAIL_LIMIT {
        return;
    }
    let excess = tail.len() - TAIL_LIMIT;
    tail.drain(..excess);
    // Then forward to just past the next newline, so the replay starts on a
    // fresh line rather than mid-sequence.
    if let Some(nl) = tail.iter().position(|b| *b == b'\n') {
        tail.drain(..=nl);
    }
}

fn push_backlog(backlog: &mut VecDeque<u8>, data: &[u8]) {
    backlog.extend(data.iter().copied());
    // Drop from the front: the tail is the part worth showing on return.
    while backlog.len() > BACKLOG_LIMIT {
        let excess = backlog.len() - BACKLOG_LIMIT;
        backlog.drain(..excess);
    }
}

async fn run(
    transports: Vec<Arc<Handle<crate::ssh::Client>>>,
    channel: Channel<client::Msg>,
    mut commands: UnboundedReceiver<Command>,
    ended: Arc<AtomicBool>,
    remote_alt: Arc<AtomicBool>,
    forwards: Vec<crate::ssh::forward::Running>,
) {
    let mut alt_tracker = AltScreenTracker::default();
    // Held, not used. Dropping any of these closes that hop's connection, and
    // every tunnel nested inside it, so the whole chain lives exactly as long as
    // the session does.
    let _transports = transports;
    // Aborted when this function returns, however it returns. Each listener
    // holds an `Arc` on the same handles, so leaving them running would keep
    // the connection — and its port — alive after the session that owns them
    // had gone, which is exactly what moving the handles in here prevents.
    let _forwards = AbortOnDrop(forwards);
    let mut channel = channel;
    let mut consumer: Option<UnboundedSender<Output>> = None;
    let mut backlog: VecDeque<u8> = VecDeque::new();
    let mut tail: VecDeque<u8> = VecDeque::new();
    let mut exit_status = None;

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None | Some(Command::Close) => {
                    let _ = channel.close().await;
                    break;
                }
                Some(Command::Input(bytes)) => {
                    if channel.data_bytes(bytes).await.is_err() {
                        break;
                    }
                }
                Some(Command::Resize { cols, rows, xpix, ypix }) => {
                    // A resize failing is not worth ending a session over.
                    let _ = channel.window_change(cols, rows, xpix, ypix).await;
                }
                Some(Command::Attach(sink, replay)) => {
                    // `Recent` supersedes the backlog: the tail already contains
                    // everything the backlog does, so sending both would print
                    // the missed output twice.
                    let bytes = replay_bytes(replay, &tail, &mut backlog);
                    if !bytes.is_empty() && sink.send(Output::Bytes(bytes)).is_err() {
                        continue;
                    }
                    consumer = Some(sink);
                }
                Some(Command::Detach) => consumer = None,
            },

            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if let Some(in_alt) = alt_tracker.observe(&data) {
                        remote_alt.store(in_alt, Ordering::Relaxed);
                    }
                    push_tail(&mut tail, &data);
                    match &consumer {
                        Some(sink) => {
                            if sink.send(Output::Bytes(data.to_vec())).is_err() {
                                // Whoever was attached went away without saying
                                // so; fall back to buffering rather than losing
                                // the bytes.
                                consumer = None;
                                push_backlog(&mut backlog, &data);
                            }
                        }
                        None => push_backlog(&mut backlog, &data),
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                _ => {}
            },
        }
    }

    ended.store(true, Ordering::Relaxed);
    if let Some(sink) = consumer {
        let _ = sink.send(Output::Ended(exit_status));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repaint must not re-run what the bytes originally *did*. Real prompts
    /// carry an OSC title sequence ending in BEL, so a tail of a dozen prompts
    /// rang the bell a dozen times on every switch.
    #[test]
    fn a_replay_paints_without_ringing_or_setting_titles() {
        let prompt = b"\x1b]0;tester@host: ~\x07user@host:~$ ";
        let stripped = strip_side_effects(prompt);

        assert_eq!(stripped, b"user@host:~$ ", "the title sequence survived");
        assert!(!stripped.contains(&0x07), "a bell survived");
    }

    /// OSC terminated by ST rather than BEL, and a bare bell on its own.
    #[test]
    fn both_osc_terminators_and_lone_bells_are_removed() {
        assert_eq!(strip_side_effects(b"a\x1b]52;c;Zm9v\x1b\\b"), b"ab");
        assert_eq!(strip_side_effects(b"ding\x07dong"), b"dingdong");
    }

    /// The sequences that *draw* have to survive, or the replay repaints nothing.
    #[test]
    fn colour_and_cursor_sequences_survive_the_strip() {
        let painted = b"\x1b[1;32mgreen\x1b[0m\x1b[2Kline\r\n";
        assert_eq!(strip_side_effects(painted), painted);
    }

    /// A full-screen program repaints itself, and replaying its bytes would flip
    /// the terminal's buffer under it — `ESC[?1049h/l` is not stripped, and is
    /// not the sort of thing that can be stripped safely.
    #[test]
    fn a_full_screen_session_is_never_sent_its_own_output_again() {
        assert_eq!(
            replay_for(true, false),
            Replay::Recent,
            "a shell wants context"
        );
        assert_eq!(
            replay_for(true, true),
            Replay::Missed,
            "a full-screen program must not be replayed into"
        );
        assert_eq!(replay_for(false, false), Replay::Missed, "a re-attach");
        assert_eq!(replay_for(false, true), Replay::Missed);
    }

    /// The tail is capped, and a trim starts on a fresh line — cutting mid-escape
    /// would replay half a control sequence and paint garbage.
    #[test]
    fn the_tail_is_capped_and_trimmed_to_a_line_boundary() {
        let mut tail = VecDeque::new();
        for i in 0..(TAIL_LIMIT * 2 / 8) {
            push_tail(&mut tail, format!("{i:07}\n").as_bytes());
        }

        assert!(tail.len() <= TAIL_LIMIT, "the cap did not hold");
        let text: Vec<u8> = tail.iter().copied().collect();
        assert!(
            !text.starts_with(b"\n") && text.contains(&b'\n'),
            "the trim did not land on a line boundary"
        );
        // The end is what matters: it is the most recent output.
        assert!(text.ends_with(b"\n"), "lost the end of the tail");
    }

    /// Switching must not cost you output. The tail is a screenful of context;
    /// when more was missed than that, the backlog is what has to be sent.
    #[test]
    fn a_switch_never_trades_missed_output_for_context() {
        let tail: VecDeque<u8> = b"context\x07 and a bell".iter().copied().collect();

        // Idle session: nothing was missed, so the tail is all there is —
        // stripped, because it repaints what was already shown once.
        let mut empty = VecDeque::new();
        let sent = replay_bytes(Replay::Recent, &tail, &mut empty);
        assert_eq!(
            sent, b"context and a bell",
            "the tail was not replayed clean"
        );

        // More missed than the tail holds: the backlog wins, and intact.
        let missed: Vec<u8> = std::iter::repeat_n(b'x', tail.len() + 1).collect();
        let mut backlog: VecDeque<u8> = missed.iter().copied().collect();
        let sent = replay_bytes(Replay::Recent, &tail, &mut backlog);
        assert_eq!(sent, missed, "a build's output was dropped for a screenful");
        assert!(backlog.is_empty(), "the backlog was sent but not drained");
    }

    /// Returning to a session's own screen sends only what it missed, or the
    /// output already on the terminal would be printed a second time.
    #[test]
    fn a_re_attach_sends_only_what_was_missed() {
        let tail: VecDeque<u8> = b"already on screen".iter().copied().collect();
        let mut backlog: VecDeque<u8> = b"arrived while away".iter().copied().collect();

        let sent = replay_bytes(Replay::Missed, &tail, &mut backlog);
        assert_eq!(sent, b"arrived while away");
        assert!(backlog.is_empty());
    }

    #[test]
    fn backlog_keeps_the_tail_and_drops_the_middle() {
        let mut backlog = VecDeque::new();
        // Twice the cap, so the first half must be gone.
        for i in 0..(BACKLOG_LIMIT * 2 / 8) {
            push_backlog(&mut backlog, format!("{:07}\n", i).as_bytes());
        }
        assert_eq!(backlog.len(), BACKLOG_LIMIT, "backlog grew past its cap");

        let tail: Vec<u8> = backlog.iter().copied().collect();
        let text = String::from_utf8_lossy(&tail);
        let last = format!("{:07}", (BACKLOG_LIMIT * 2 / 8) - 1);
        assert!(
            text.contains(&last),
            "the most recent output must survive; tail ends with {:?}",
            &text[text.len().saturating_sub(40)..]
        );
        assert!(
            !text.contains("0000000\n"),
            "the oldest output should have been dropped"
        );
    }

    #[test]
    fn alt_screen_tracking_follows_smcup_and_rmcup() {
        let mut t = AltScreenTracker::default();
        assert_eq!(t.observe(b"plain output"), None, "no change reported");
        assert_eq!(t.observe(b"\x1b[?1049h"), Some(true), "entered alt screen");
        assert_eq!(t.observe(b"drawing..."), None);
        assert_eq!(t.observe(b"\x1b[?1049l"), Some(false), "left alt screen");
    }

    /// The older smcup variants are still emitted by plenty of terminfo entries.
    #[test]
    fn alt_screen_tracking_handles_the_legacy_modes() {
        let mut t = AltScreenTracker::default();
        assert_eq!(t.observe(b"\x1b[?47h"), Some(true));
        assert_eq!(t.observe(b"\x1b[?47l"), Some(false));
        assert_eq!(t.observe(b"\x1b[?1047h"), Some(true));
    }

    /// Reads are arbitrary chunks, so a sequence can be cut in half.
    #[test]
    fn alt_screen_tracking_survives_a_split_sequence() {
        let mut t = AltScreenTracker::default();
        assert_eq!(t.observe(b"text\x1b[?10"), None, "incomplete so far");
        assert_eq!(t.observe(b"49h more"), Some(true), "completed across reads");
    }

    /// Unrelated private modes must not be mistaken for a screen switch —
    /// `?25h` (show cursor) and `?2004h` (bracketed paste) are everywhere.
    #[test]
    fn alt_screen_tracking_ignores_other_private_modes() {
        let mut t = AltScreenTracker::default();
        assert_eq!(t.observe(b"\x1b[?25h\x1b[?2004h\x1b[?1h"), None);
    }

    /// The last switch in a chunk wins, not the first.
    #[test]
    fn alt_screen_tracking_takes_the_final_state_in_a_chunk() {
        let mut t = AltScreenTracker::default();
        assert_eq!(t.observe(b"\x1b[?1049h...\x1b[?1049l"), Some(false));
    }

    #[test]
    fn a_short_backlog_is_kept_whole() {
        let mut backlog = VecDeque::new();
        push_backlog(&mut backlog, b"hello ");
        push_backlog(&mut backlog, b"world");
        let text: Vec<u8> = backlog.iter().copied().collect();
        assert_eq!(text, b"hello world");
    }
}
