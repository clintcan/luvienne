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

pub(crate) enum Command {
    Input(Vec<u8>),
    Resize {
        cols: u32,
        rows: u32,
        xpix: u32,
        ypix: u32,
    },
    /// Start forwarding output here, beginning with anything buffered.
    Attach(UnboundedSender<Output>),
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
        tokio::spawn(run(
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

    pub(super) fn attach_output(&self, sink: UnboundedSender<Output>) -> bool {
        self.send(Command::Attach(sink))
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
                Some(Command::Attach(sink)) => {
                    if !backlog.is_empty() {
                        let buffered: Vec<u8> = backlog.drain(..).collect();
                        if sink.send(Output::Bytes(buffered)).is_err() {
                            continue;
                        }
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
