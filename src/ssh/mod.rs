//! SSH session lifecycle.
//!
//! Everything here runs on the tokio runtime, never on the render thread.
//! Progress is reported back to the UI as [`SshEvent`] values.
//!
//! The split matters: [`connect`] runs in the background and may need to ask the
//! user a question (host key confirmation), which it does by sending a oneshot
//! back through the event channel. [`attach`] runs in the *foreground*, driven by
//! the main loop, because it takes over the terminal.

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::MethodKind;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, ssh_key};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zeroize::Zeroizing;

pub mod forward;
pub mod session;

pub use session::{LiveSession, SessionOutcome};

use crate::config::{AuthRef, Host};

/// Messages from a background SSH task to the event loop.
///
/// Not `Clone`: [`SshEvent::Ready`] carries an owned session and
/// [`SshEvent::HostKeyPrompt`] carries a oneshot sender.
#[derive(Debug)]
pub enum SshEvent {
    Progress(String),
    /// The connection is authenticated and a channel is open. The main loop must
    /// take this and call [`attach`].
    Ready(Box<LiveSession>),
    /// Carries the host so the app can clear its in-flight marker; a bare
    /// message would leave a failed connect looking permanently in progress.
    Failed {
        host: String,
        message: String,
    },
    /// A host is not in `known_hosts`. The UI must ask before this connection
    /// proceeds — replying `false` aborts it.
    HostKeyPrompt {
        host: String,
        fingerprint: String,
        reply: oneshot::Sender<bool>,
    },
    /// Something needs a secret typed in — a key passphrase, a password, or a
    /// keyboard-interactive challenge. Replying `None` cancels the connect.
    ///
    /// The reply is `Zeroizing` so it is wiped when the connect task drops it,
    /// however that task ends.
    SecretPrompt {
        request: SecretRequest,
        reply: oneshot::Sender<Option<Zeroizing<String>>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Unlocking a private key file.
    Passphrase,
    /// Authenticating to the server.
    Password,
    /// Who to log in as. Not a secret — this one is echoed.
    Username,
}

impl SecretKind {
    pub fn title(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::Password => "password",
            Self::Username => "username",
        }
    }
}

/// Everything the UI needs to render a secret prompt.
#[derive(Debug, Clone)]
pub struct SecretRequest {
    pub kind: SecretKind,
    /// What the secret is for: a key path, or `user@host`.
    pub subject: String,
    /// The label above the input. For keyboard-interactive this is the server's
    /// own prompt text, shown verbatim — it may say anything, including "Verification
    /// code" or a custom PAM message.
    pub prompt: String,
    /// Whether to echo what is typed. False for passwords and passphrases. The
    /// *server* decides for keyboard-interactive, where a prompt like "Username"
    /// is meant to be visible.
    pub echo: bool,
    /// Set when the previous attempt was rejected, so the UI can say so rather
    /// than silently re-prompting.
    pub retry: bool,
    /// Why this prompt appeared, when that is not obvious from the prompt alone.
    ///
    /// Set when authentication fell back from the agent: without it the user
    /// configured `auth = agent`, or typed a bare address into quick connect, and
    /// is suddenly asked for a password with no explanation. A status line cannot
    /// carry this — the prompt replaces it in the same frame.
    pub note: Option<String>,
}

/// Connection errors.
///
/// Every `Display` string here is safe to show on screen and safe to log. No
/// variant carries a key, passphrase, or password — redaction happens at
/// construction, not at the print site, so there is no way to accidentally
/// format a secret.
#[derive(Debug, Error)]
pub enum SshError {
    #[error("HOST KEY CHANGED for {host} (known_hosts line {line}) — refusing to connect")]
    HostKeyMismatch { host: String, line: usize },

    #[error("host key for {host} was not confirmed")]
    HostKeyRejected { host: String },

    /// Carries the method because the message is otherwise indistinguishable
    /// between auth paths — "authentication failed" on a password host that
    /// actually says "no agent identity was accepted" sends people hunting the
    /// wrong problem.
    #[error("{method} authentication failed for {user}@{host}")]
    AuthFailed {
        user: String,
        host: String,
        method: &'static str,
    },

    #[error("no SSH agent: SSH_AUTH_SOCK is unset or unreachable")]
    NoAgent,

    #[error("{host} does not offer password or keyboard-interactive authentication")]
    NoInteractiveAuth { host: String },

    #[error("authentication failed for {user}@{host} — the server rejected the key")]
    KeyRejected { user: String, host: String },

    #[error("cancelled")]
    PromptCancelled,

    #[error("timed out after {seconds}s connecting to {host}")]
    ConnectTimeout { host: String, seconds: u64 },

    #[error("{0}")]
    Auth(#[from] crate::auth::AuthError),

    #[error("{0}")]
    Chain(#[from] crate::config::ChainError),

    /// Much the most common jump-host failure: bastions frequently ship with
    /// `AllowTcpForwarding no`, and russh's own message for it is just
    /// "Failed to open channel (AdministrativelyProhibited)".
    #[error(
        "{jump} refused to forward a connection to {target} — it likely has AllowTcpForwarding disabled"
    )]
    ForwardRefused { jump: String, target: String },

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("ssh error: {0}")]
    Protocol(#[from] russh::Error),

    #[error("key error: {0}")]
    Key(#[from] russh::keys::Error),

    /// An internal invariant broke, or a helper task died.
    ///
    /// There is deliberately no `Unimplemented` variant any more: every use of
    /// it had become one of these, and keeping it around would have reported
    /// bugs as missing features, sending people to look for the wrong thing.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// russh callbacks. Holds the channel back to the UI so host key confirmation
/// can round-trip to the user.
pub struct Client {
    host: String,
    port: u16,
    tx: UnboundedSender<SshEvent>,
    /// The remote forwards this hop is expected to deliver.
    ///
    /// Only the final hop carries any. A connection the *server* opens arrives
    /// at the handler rather than anywhere we can await, so the routing table
    /// has to live here — there is no other place that sees those channels.
    remote_forwards: Vec<crate::config::Forward>,
}

impl client::Handler for Client {
    type Error = SshError;

    /// The security-critical callback. Three outcomes, and the distinction
    /// between them is the whole point:
    ///
    /// - key matches `known_hosts` → accept silently
    /// - key *changed* → hard error, no prompt, no override
    /// - host unknown → ask the user, and only learn the key on an explicit yes
    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        match russh::keys::check_known_hosts(&self.host, self.port, key) {
            Ok(true) => Ok(true),

            Err(russh::keys::Error::KeyChanged { line }) => Err(SshError::HostKeyMismatch {
                host: self.host.clone(),
                line,
            }),

            Ok(false) => {
                let (reply, answer) = oneshot::channel();
                let prompt = SshEvent::HostKeyPrompt {
                    host: self.host.clone(),
                    fingerprint: key.fingerprint(Default::default()).to_string(),
                    reply,
                };
                let refused = || {
                    Err(SshError::HostKeyRejected {
                        host: self.host.clone(),
                    })
                };

                if self.tx.send(prompt).is_err() {
                    // UI is gone; fail closed.
                    return refused();
                }

                // A dropped sender (UI quit mid-prompt) resolves to Err, which
                // is also a refusal. There is no path here that defaults to yes.
                //
                // Refusal returns Err rather than Ok(false) deliberately: both
                // abort the connection, but Ok(false) surfaces as russh's generic
                // "unknown key" and would overwrite the specific message the user
                // needs to see.
                match answer.await {
                    Ok(true) => {
                        russh::keys::known_hosts::learn_known_hosts(&self.host, self.port, key)?;
                        Ok(true)
                    }
                    _ => refused(),
                }
            }

            Err(other) => Err(SshError::Key(other)),
        }
    }

    /// A connection arriving on a remote (`-R`) forward.
    ///
    /// The server opened this channel, so there is nowhere else it could be
    /// picked up — no part of our code is awaiting it.
    ///
    /// **Only ports we asked for are accepted.** russh's default implementation
    /// accepts every channel a server offers, which would let a server we are
    /// merely logged into open connections to arbitrary addresses on this
    /// machine, through the firewall, as us. Matching against the forwards the
    /// user actually configured is what keeps this a tunnel we opened rather
    /// than a door the far end can walk through.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        match forward_for_port(&self.remote_forwards, connected_port) {
            Some(forward) => {
                reply.accept().await;
                forward::serve_remote(forward, channel);
            }
            None => {
                let _ = tx_progress(
                    &self.tx,
                    format!(
                        "refused an unrequested forwarded connection on {connected_address}:{connected_port}"
                    ),
                );
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
        }
        Ok(())
    }
}

/// Send a progress line, ignoring a closed channel.
fn tx_progress(tx: &UnboundedSender<SshEvent>, message: String) -> bool {
    tx.send(SshEvent::Progress(message)).is_ok()
}

/// Which configured forward, if any, a server-opened channel belongs to.
///
/// The security boundary for remote forwards, kept as a plain function so it can
/// be tested without standing up a hostile server. `None` means refuse: russh's
/// default handler accepts *every* channel a server offers, which would let a
/// machine we are merely logged into open connections to arbitrary addresses on
/// this side — through the firewall, as us. Only a port the user asked us to
/// forward is answered.
///
/// `forwards` holds remote forwards only. A local forward's port must never
/// match: those are sockets we opened here, and the server was never asked to
/// listen on them, so a channel naming one is unrequested by definition.
fn forward_for_port(
    forwards: &[crate::config::Forward],
    port: u32,
) -> Option<crate::config::Forward> {
    forwards
        .iter()
        .find(|f| {
            f.direction == crate::config::Direction::Remote && u32::from(f.listen_port) == port
        })
        .cloned()
}

/// Resolve, connect, verify the host key, authenticate, and start a session.
///
/// The PTY and shell are requested here, once, rather than in [`attach`] — a
/// session can be attached and detached many times, and each re-attach must not
/// start another shell on the remote.
///
/// Returns a [`LiveSession`] already being serviced by its own task. Does not
/// touch the terminal.
pub async fn connect(
    chain: &[Host],
    tx: &UnboundedSender<SshEvent>,
) -> Result<LiveSession, SshError> {
    let Some(target) = chain.last() else {
        return Err(SshError::Internal("empty connection chain"));
    };

    let config = Arc::new(client_config());

    // Every hop's connection has to stay open for the life of the session: the
    // tunnel to hop N runs *inside* hop N-1's connection, so dropping an earlier
    // handle collapses everything after it.
    let mut transports: Vec<Handle<Client>> = Vec::new();

    // Resolved before dialling anything: being asked who to log in as *after*
    // a connection is open is a strange order to answer questions in.
    let mut users: Vec<String> = Vec::with_capacity(chain.len());
    for hop in chain {
        users.push(resolve_user(hop, tx).await?);
    }

    for (i, hop) in chain.iter().enumerate() {
        let handler = Client {
            host: hop.address.clone(),
            port: hop.port,
            tx: tx.clone(),
            // Only the hop the session actually runs on. A jump host is a
            // tunnel, not a place we ask to open listening sockets.
            remote_forwards: if i + 1 == chain.len() {
                hop.forwards
                    .iter()
                    .filter(|f| f.direction == crate::config::Direction::Remote)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            },
        };

        let mut handle = match transports.last() {
            // First hop: an ordinary TCP connection.
            None => {
                let _ = tx.send(SshEvent::Progress(format!(
                    "connecting to {}…",
                    hop.address
                )));
                let dial =
                    client::connect(config.clone(), (hop.address.as_str(), hop.port), handler);
                tokio::time::timeout(CONNECT_TIMEOUT, dial)
                    .await
                    .map_err(|_| SshError::ConnectTimeout {
                        host: hop.address.clone(),
                        seconds: CONNECT_TIMEOUT.as_secs(),
                    })??
            }
            // Later hops: a direct-tcpip forward through the previous hop,
            // with our own SSH handshake run over it. The jump host moves
            // bytes it cannot read — this is a tunnel, not a second login.
            Some(via) => {
                let _ = tx.send(SshEvent::Progress(format!(
                    "tunnelling to {} via {}…",
                    hop.address,
                    chain[i - 1].name
                )));
                let open = via.channel_open_direct_tcpip(
                    hop.address.clone(),
                    u32::from(hop.port),
                    "127.0.0.1",
                    0,
                );
                let forward = tokio::time::timeout(CONNECT_TIMEOUT, open)
                    .await
                    .map_err(|_| SshError::ConnectTimeout {
                        host: hop.address.clone(),
                        seconds: CONNECT_TIMEOUT.as_secs(),
                    })?
                    .map_err(|_| SshError::ForwardRefused {
                        jump: chain[i - 1].name.clone(),
                        target: hop.address.clone(),
                    })?;
                client::connect_stream(config.clone(), forward.into_stream(), handler).await?
            }
        };

        // Each hop authenticates as itself, with its own credentials, and its
        // host key is checked against known_hosts like any other.
        let _ = tx.send(SshEvent::Progress(format!(
            "authenticating to {}…",
            hop.name
        )));
        authenticate(&mut handle, hop, &users[i], tx).await?;
        transports.push(handle);
    }

    // Shared from here on: each forwarded connection opens a channel on the
    // final hop's handle, and russh's `Handle` cannot be cloned. Wrapped only
    // after authentication, which needs `&mut`.
    let transports: Vec<Arc<Handle<Client>>> = transports.into_iter().map(Arc::new).collect();
    let session_handle = Arc::clone(transports.last().expect("chain is non-empty"));
    let channel = session_handle.channel_open_session().await?;

    // Raised before the shell, so a busy port is reported while the status line
    // is still describing the connect rather than after the session has taken
    // over the terminal.
    let forwards = forward::start(&target.forwards, Arc::clone(&session_handle), tx).await;

    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    // Fall back to the classic default if stdout isn't a tty — the session is
    // still usable, just sized conservatively until the first resize.
    let (cols, rows, xpix, ypix) = window_size().unwrap_or((80, 24, 0, 0));
    channel
        .request_pty(
            true,
            &term,
            cols as u32,
            rows as u32,
            xpix as u32,
            ypix as u32,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    Ok(LiveSession::spawn(
        target.name.clone(),
        transports,
        channel,
        forwards,
    ))
}

/// The username for a hop, asking if the host entry does not name one.
///
/// An empty `user` means "ask", the same way PuTTY prompts `login as:` for a
/// session that never stored one. Assuming a username instead would silently
/// try the wrong account and fail with an authentication error that says
/// nothing about the real cause.
async fn resolve_user(host: &Host, tx: &UnboundedSender<SshEvent>) -> Result<String, SshError> {
    if !host.user.trim().is_empty() {
        return Ok(host.user.trim().to_string());
    }

    let answer = ask_secret(
        tx,
        SecretRequest {
            kind: SecretKind::Username,
            subject: format!("{}:{}", host.address, host.port),
            prompt: "login as".into(),
            // A username is not a secret, and typing one blind is miserable.
            echo: true,
            retry: false,
            note: None,
        },
    )
    .await?;

    let user = answer.trim().to_string();
    if user.is_empty() {
        return Err(SshError::PromptCancelled);
    }
    Ok(user)
}

/// Authenticate one hop, honouring a server that demands more than one method.
///
/// `AuthenticationMethods publickey,keyboard-interactive` — standard on hardened
/// servers — accepts the first method and answers with a *partial success*:
/// "that counted, now do another one". Treating that as failure reports "the
/// server rejected the key" about a key the server just accepted, which is
/// exactly what this used to do.
async fn authenticate(
    handle: &mut Handle<Client>,
    host: &Host,
    user: &str,
    tx: &UnboundedSender<SshEvent>,
) -> Result<(), SshError> {
    // The host entry names the *first* method. Anything the server demands
    // after that is chosen from what it says it still wants.
    let mut outcome = match &host.auth {
        AuthRef::Agent => {
            fall_back_to_interactive(
                authenticate_with_agent(handle, user, &host.address).await,
                handle,
                user,
                &host.address,
                tx,
            )
            .await?
        }
        AuthRef::Key { path } => {
            let key = load_key_interactive(path, host.cache_passphrase, tx).await?;
            authenticate_with_key(handle, user, &host.address, key).await?
        }
        AuthRef::Password => {
            authenticate_with_password(handle, user, &host.address, tx, None).await?
        }
    };

    for _ in 0..MAX_AUTH_METHODS {
        let remaining = match outcome {
            Step::Done => return Ok(()),
            Step::More(remaining) => remaining,
        };

        // Prefer an interactive method: the key has just been used, and asking
        // for it again would only loop.
        outcome = if remaining.contains(&MethodKind::KeyboardInteractive) {
            authenticate_keyboard_interactive(handle, user, &host.address, tx, None).await?
        } else if remaining.contains(&MethodKind::Password) {
            authenticate_with_password(handle, user, &host.address, tx, None).await?
        } else {
            return Err(SshError::AuthFailed {
                user: user.to_string(),
                host: host.address.clone(),
                method: "additional factor",
            });
        };
    }

    Err(SshError::AuthFailed {
        user: user.to_string(),
        host: host.address.clone(),
        method: "multi-factor",
    })
}

/// Turn a dead end in agent authentication into a prompt, when the server will
/// take one.
///
/// `ssh(1)` walks publickey → keyboard-interactive → password, and stopping at
/// the first is what made quick connect unusable against a password-only server:
/// you type an address, the agent holds nothing the server wants, and there is
/// no way to say "ask me instead". A configured `auth = agent` host gets the same
/// courtesy — a prompt is strictly more useful than an error, and the server
/// still decides what it will accept.
///
/// Only a failure to *authenticate* falls through. Anything else — a cancelled
/// prompt, a dropped connection, a protocol error — is returned untouched,
/// because re-asking would paper over the real problem. And if the server offers
/// nothing interactive, the original agent error is what the user needs to read,
/// not a complaint about the fallback.
async fn fall_back_to_interactive(
    outcome: Result<Step, SshError>,
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    tx: &UnboundedSender<SshEvent>,
) -> Result<Step, SshError> {
    let original = match outcome {
        Ok(step) => return Ok(step),
        Err(err @ (SshError::NoAgent | SshError::AuthFailed { .. })) => err,
        Err(other) => return Err(other),
    };

    // Carried into the prompt itself rather than the status line, which the
    // prompt replaces in the same frame.
    let note = match &original {
        SshError::NoAgent => NO_AGENT_FELL_BACK,
        _ => AGENT_FELL_BACK,
    };

    match authenticate_with_password(handle, user, host, tx, Some(note)).await {
        Ok(step) => Ok(step),
        // The server wants neither: say why the *agent* failed, which is the
        // part the user can act on.
        Err(SshError::NoInteractiveAuth { .. }) => Err(original),
        Err(other) => Err(other),
    }
}

/// Why a password prompt appeared when the host asked for the agent.
///
/// Both are kept under the 62 columns a 66-wide prompt can show: a note that is
/// clipped mid-sentence is worse than no note, and the wording is the whole point.
pub const AGENT_FELL_BACK: &str = "the agent's keys were not accepted — asking instead";
pub const NO_AGENT_FELL_BACK: &str = "no SSH agent, so the server is asking instead";

/// How many authentication methods one hop may chain before we call it a loop.
const MAX_AUTH_METHODS: usize = 4;

/// The result of offering one authentication method.
enum Step {
    /// The server is satisfied.
    Done,
    /// The server counted it but wants another factor, from these methods.
    More(russh::MethodSet),
}

/// How often to poke an otherwise-silent connection, and how many unanswered
/// pokes to tolerate — the equivalent of OpenSSH's `ServerAliveInterval` and
/// `ServerAliveCountMax`, and chosen to match its common settings.
///
/// Without this a session that has gone away *looks* fine: NAT tables and
/// stateful firewalls between here and a cloud host drop idle flows silently,
/// and you find out by typing into a shell that is never coming back. It
/// matters most for a detached session, which is idle by design and may sit
/// that way for hours.
///
/// `inactivity_timeout` is deliberately left unset. That one garbage-collects
/// *quiet* connections, which is precisely what a parked session is.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const KEEPALIVE_MAX: usize = 3;

/// How long to wait to *reach* one hop — the TCP dial, or the forward through
/// the previous hop.
///
/// Scoped to the dial alone, and that boundary is load-bearing. The SSH
/// handshake is deliberately outside it, because `check_server_key` runs inside
/// the handshake and blocks on the user answering the host key prompt: a
/// timeout around the handshake is a stopwatch on a human reading a
/// fingerprint. Anything that hangs after the dial is escapable with `esc`
/// instead. Without any bound at all, an unroutable address sits on the OS TCP
/// timeout — over a minute of the UI saying "connecting" and nothing else.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// The client config every hop is dialled with.
fn client_config() -> client::Config {
    client::Config {
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..client::Config::default()
    }
}

/// How many tries before giving up, matching `ssh(1)`.
const MAX_ATTEMPTS: usize = 3;

/// Cap on keyboard-interactive rounds. A misbehaving or hostile server can keep
/// sending `InfoRequest` forever; without a bound that is an unbreakable prompt
/// loop the user cannot escape except by killing the app.
const MAX_KEYBOARD_ROUNDS: usize = 8;

/// Ask the UI for a secret. `Err(PromptCancelled)` means the user escaped, the
/// app quit, or the prompt channel is gone — every one of which aborts the connect.
async fn ask_secret(
    tx: &UnboundedSender<SshEvent>,
    request: SecretRequest,
) -> Result<Zeroizing<String>, SshError> {
    let (reply, answer) = oneshot::channel();
    if tx.send(SshEvent::SecretPrompt { request, reply }).is_err() {
        return Err(SshError::PromptCancelled);
    }
    // A dropped sender (the user quit mid-prompt) cancels, same as an explicit
    // escape. Nothing here can default to "keep going".
    match answer.await {
        Ok(Some(secret)) => Ok(secret),
        _ => Err(SshError::PromptCancelled),
    }
}

/// Load a key from disk, prompting for a passphrase only if one is needed.
///
/// Decryption runs on `spawn_blocking`: PPK v3's Argon2 derivation is measured in
/// hundreds of milliseconds and would otherwise stall a runtime worker. So does
/// every Keychain call — those can block on a system dialog asking the user to
/// allow access, which is unbounded.
///
/// The passphrase is `Zeroizing` end to end — from the UI's input buffer or the
/// Keychain, through the channel, into this function, and wiped when the attempt
/// ends.
///
/// `cache` is the host's opt-in. With it unset nothing here reads or writes the
/// Keychain at all; the flow is exactly what it was before caching existed.
async fn load_key_interactive(
    path: &std::path::Path,
    cache: bool,
    tx: &UnboundedSender<SshEvent>,
) -> Result<PrivateKey, SshError> {
    let path = path.to_path_buf();
    let label = path.display().to_string();

    // Unencrypted keys must not prompt, so always try without a passphrase
    // first. This also keeps an unencrypted key from ever reaching the
    // Keychain — there is no passphrase to store for one.
    let unlocked = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || crate::auth::load_private_key(&path, None))
            .await
            .map_err(|_| SshError::Internal("key loading task panicked"))?
    };

    let id = cache.then(|| crate::keystore::key_id(&path));

    match unlocked {
        Ok(key) => {
            // The key at this path needs no passphrase, so a stored one is
            // dead: nothing will ever read it again, and no later edit can
            // clean it up either — the host still names the same path with
            // caching on, so the orphan diff rightly leaves it alone. Only
            // reached when an encrypted key has been replaced by a plain one,
            // which costs the common path nothing.
            if let Some(id) = id {
                let _ = tokio::task::spawn_blocking(move || crate::keystore::forget(&id)).await;
            }
            return Ok(key);
        }
        Err(crate::auth::AuthError::PassphraseRequired(_)) => {}
        Err(other) => return Err(other.into()),
    }

    if let Some(id) = &id
        && let Some(cached) = read_cached_passphrase(id).await
    {
        let attempted = decrypt(&path, cached).await?;
        match attempted {
            Ok(key) => {
                let _ = tx.send(SshEvent::Progress(format!(
                    "unlocked {label} with the remembered passphrase"
                )));
                return Ok(key);
            }
            // The passphrase changed, or it was stored against a key that has
            // since been replaced at the same path. Drop it rather than
            // re-offering it on every connect, and fall through to asking.
            Err(crate::auth::AuthError::Undecryptable(_)) => {
                let id = id.clone();
                let _ = tokio::task::spawn_blocking(move || crate::keystore::forget(&id)).await;
                let _ = tx.send(SshEvent::Progress(format!(
                    "the remembered passphrase for {label} no longer works — forgetting it"
                )));
            }
            Err(other) => return Err(other.into()),
        }
    }

    for attempt in 0..MAX_ATTEMPTS {
        let passphrase = ask_secret(
            tx,
            SecretRequest {
                kind: SecretKind::Passphrase,
                subject: label.clone(),
                prompt: "passphrase".into(),
                echo: false,
                retry: attempt > 0,
                note: None,
            },
        )
        .await?;

        // Cloned so the passphrase can be stored after a successful decrypt;
        // both copies are `Zeroizing` and wiped when this scope ends.
        let to_cache = id.is_some().then(|| passphrase.clone());

        match decrypt(&path, passphrase).await? {
            Ok(key) => {
                if let (Some(id), Some(secret)) = (id.clone(), to_cache) {
                    let stored =
                        tokio::task::spawn_blocking(move || crate::keystore::set(&id, &secret))
                            .await;
                    // Reported either way. Storing a secret is not something to
                    // do quietly, and a Keychain that refused the write must not
                    // leave the user believing they will not be asked again.
                    // The reason is carried through rather than replaced with
                    // wording of our own: off macOS it says caching is not
                    // available at all, which "could not save it to the
                    // Keychain" would leave the user hunting for a Keychain.
                    let _ = tx.send(SshEvent::Progress(match stored {
                        Ok(Ok(())) => format!("remembered the passphrase for {label}"),
                        Ok(Err(why)) => {
                            format!("could not remember the passphrase for {label}: {why}")
                        }
                        Err(_) => format!("could not remember the passphrase for {label}"),
                    }));
                }
                return Ok(key);
            }
            // Wrong passphrase — loop and ask again.
            Err(crate::auth::AuthError::Undecryptable(_)) => continue,
            Err(other) => return Err(other.into()),
        }
    }

    Err(crate::auth::AuthError::Undecryptable(path).into())
}

/// Decrypt off the runtime worker. See [`load_key_interactive`] for why.
async fn decrypt(
    path: &std::path::Path,
    passphrase: Zeroizing<String>,
) -> Result<Result<PrivateKey, crate::auth::AuthError>, SshError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::auth::load_private_key(&path, Some(&passphrase)))
        .await
        .map_err(|_| SshError::Internal("key loading task panicked"))
}

/// Look up a remembered passphrase. Every failure — no entry, access denied, a
/// cancelled dialog — means the same thing to the caller: ask the user.
async fn read_cached_passphrase(id: &str) -> Option<Zeroizing<String>> {
    let id = id.to_string();
    tokio::task::spawn_blocking(move || crate::keystore::get(&id))
        .await
        .ok()?
        .ok()
}

/// Password authentication, falling back to keyboard-interactive.
///
/// Both are tried because "password auth" means different things to different
/// servers: a stock OpenSSH with `PasswordAuthentication yes` accepts the
/// `password` method, while a PAM-backed one often offers only
/// `keyboard-interactive` and would otherwise reject us with no explanation.
///
/// Note the unavoidable leak: `authenticate_password` takes `Into<String>`, so
/// the password is copied into a plain `String` inside russh that we cannot
/// zeroize. Ours is still wiped on drop; theirs is not.
async fn authenticate_with_password(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    tx: &UnboundedSender<SshEvent>,
    note: Option<&str>,
) -> Result<Step, SshError> {
    let subject = format!("{user}@{host}");

    // Ask the server what it accepts *before* prompting. Without this probe, a
    // keyboard-interactive-only server (any PAM-backed sshd with
    // `PasswordAuthentication no`) makes the user type their password, rejects
    // it, and then asks again through the other method — the same secret typed
    // twice for one login. `ssh(1)` sends this same "none" request for the same
    // reason.
    let methods = match handle.authenticate_none(user).await? {
        // Legal, if unusual: the server wants nothing at all.
        AuthResult::Success => return Ok(Step::Done),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };

    if !methods.contains(&MethodKind::Password) {
        return if methods.contains(&MethodKind::KeyboardInteractive) {
            authenticate_keyboard_interactive(handle, user, host, tx, note).await
        } else {
            // Prompting would be pointless: the server will not accept anything
            // we could type. Say so rather than asking for a password it has
            // already refused to consider.
            Err(SshError::NoInteractiveAuth {
                host: host.to_string(),
            })
        };
    }

    for attempt in 0..MAX_ATTEMPTS {
        let password = ask_secret(
            tx,
            SecretRequest {
                kind: SecretKind::Password,
                subject: subject.clone(),
                prompt: "password".into(),
                echo: false,
                retry: attempt > 0,
                note: if attempt == 0 {
                    note.map(str::to_string)
                } else {
                    None
                },
            },
        )
        .await?;

        match handle
            .authenticate_password(user, password.to_string())
            .await?
        {
            AuthResult::Success => return Ok(Step::Done),
            // Counted, but the server wants another factor too.
            AuthResult::Failure {
                remaining_methods,
                partial_success: true,
            } => return Ok(Step::More(remaining_methods)),
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                // The server does not do plain passwords but will talk
                // keyboard-interactive. Switch rather than burning our remaining
                // attempts on a method that cannot succeed.
                if !remaining_methods.contains(&MethodKind::Password)
                    && remaining_methods.contains(&MethodKind::KeyboardInteractive)
                {
                    return authenticate_keyboard_interactive(handle, user, host, tx, note).await;
                }
            }
        }
    }

    Err(SshError::AuthFailed {
        user: user.to_string(),
        host: host.to_string(),
        method: "password",
    })
}

/// Keyboard-interactive: the server sends prompts, we ask the user, we answer.
///
/// Prompt text comes from the server and is shown verbatim — it is how 2FA and
/// PAM messages reach the user. A prompt's `echo` flag decides whether input is
/// masked; not every challenge is a secret.
async fn authenticate_keyboard_interactive(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    tx: &UnboundedSender<SshEvent>,
    note: Option<&str>,
) -> Result<Step, SshError> {
    // Shown once. Repeating it above every round of a multi-prompt 2FA exchange
    // would turn an explanation into noise.
    let mut note = note;
    let subject = format!("{user}@{host}");
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;

    for _ in 0..MAX_KEYBOARD_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(Step::Done),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success: true,
            } => return Ok(Step::More(remaining_methods)),
            KeyboardInteractiveAuthResponse::Failure { .. } => break,
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let answer = ask_secret(
                        tx,
                        SecretRequest {
                            kind: SecretKind::Password,
                            subject: subject.clone(),
                            prompt: prompt.prompt.trim().trim_end_matches(':').to_string(),
                            echo: prompt.echo,
                            retry: false,
                            note: note.take().map(str::to_string),
                        },
                    )
                    .await?;
                    answers.push(answer.to_string());
                }
                // An empty prompt list is legal — the server is showing
                // instructions and expects an empty response, not a question.
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }

    Err(SshError::AuthFailed {
        user: user.to_string(),
        host: host.to_string(),
        method: "keyboard-interactive",
    })
}

/// Authenticate with a key we hold in memory.
///
/// RSA needs an explicit hash algorithm: `PrivateKeyWithHashAlg::new(key, None)`
/// means SHA-1 `ssh-rsa`, which OpenSSH 8.8+ refuses by default. So try SHA-512,
/// then SHA-256, then legacy SHA-1 for genuinely old servers. For every other key
/// type russh ignores the parameter, so the first attempt is the only one.
async fn authenticate_with_key(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    key: PrivateKey,
) -> Result<Step, SshError> {
    let key = Arc::new(key);
    let hash_algs: &[Option<HashAlg>] = if key.algorithm().is_rsa() {
        &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
    } else {
        &[None]
    };

    for hash_alg in hash_algs {
        let candidate = PrivateKeyWithHashAlg::new(key.clone(), *hash_alg);
        match handle.authenticate_publickey(user, candidate).await {
            Ok(AuthResult::Success) => return Ok(Step::Done),
            // The key counted, but the server wants another factor as well.
            Ok(AuthResult::Failure {
                remaining_methods,
                partial_success: true,
            }) => return Ok(Step::More(remaining_methods)),
            _ => continue,
        }
    }

    Err(SshError::KeyRejected {
        user: user.to_string(),
        host: host.to_string(),
    })
}

/// Try every identity the agent offers, in order, until one is accepted.
///
/// The private key never leaves the agent — russh sends the public key and the
/// agent returns a signature.
async fn authenticate_with_agent(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
) -> Result<Step, SshError> {
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|_| SshError::NoAgent)?;

    let identities = agent
        .request_identities()
        .await
        .map_err(|_| SshError::NoAgent)?;

    for identity in identities {
        let key: PublicKey = match &identity {
            russh::keys::agent::AgentIdentity::PublicKey { key, .. } => key.clone(),
            // Certificates need a different auth method; skip for now.
            _ => continue,
        };

        match handle
            .authenticate_publickey_with(user, key, None, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(Step::Done),
            Ok(AuthResult::Failure {
                remaining_methods,
                partial_success: true,
            }) => return Ok(Step::More(remaining_methods)),
            _ => continue,
        }
    }

    Err(SshError::AuthFailed {
        user: user.to_string(),
        host: host.to_string(),
        method: "agent",
    })
}

/// The terminal's current size, in cells and pixels.
///
/// Pixel dimensions matter for remote programs that draw images (sixel, kitty
/// graphics); reporting 0 is legal but tells them nothing, so pass through
/// whatever the kernel gives us.
fn window_size() -> std::io::Result<(u16, u16, u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid, correctly-sized winsize for the duration of the call.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((ws.ws_col, ws.ws_row, ws.ws_xpixel, ws.ws_ypixel))
}

/// Sets `O_NONBLOCK` on a descriptor and restores the original flags on drop.
///
/// The flag lives on the *file description*, which for stdin is shared with the
/// parent shell — leaving it set would break the shell we return to. Restoring
/// is the entire reason this is a guard type.
struct NonBlocking {
    fd: RawFd,
    saved_flags: libc::c_int,
}

impl NonBlocking {
    fn new(fd: RawFd) -> std::io::Result<Self> {
        // SAFETY: plain fcntl calls on a descriptor the caller holds open.
        let saved_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if saved_flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, saved_flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd, saved_flags })
    }
}

impl Drop for NonBlocking {
    fn drop(&mut self) {
        unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.saved_flags) };
    }
}

/// Where session input is read from.
enum RawSource {
    /// Our own open of the terminal. Preferred: `O_NONBLOCK` then applies to
    /// this file description alone.
    Owned(std::fs::File),
    /// Borrowed stdin, used only when the terminal cannot be opened by name.
    /// Deliberately not `OwnedFd` — dropping this must not close stdin.
    Borrowed(RawFd),
}

impl AsRawFd for RawSource {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Owned(file) => file.as_raw_fd(),
            Self::Borrowed(fd) => *fd,
        }
    }
}

/// The path of the terminal attached to `fd`, e.g. `/dev/ttys003`.
fn terminal_path(fd: RawFd) -> Option<PathBuf> {
    let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
    // SAFETY: `buf` is a valid writable buffer of the length passed.
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: on success ttyname_r wrote a NUL-terminated path into `buf`.
    let path = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

/// A cancel-safe reader over a raw descriptor.
///
/// `tokio::io::stdin` reads on a blocking thread, and a blocking read cannot be
/// cancelled: when `select!` drops the read future at end of session, that thread
/// is still parked inside `read(2)` and swallows the next keystroke the user
/// types — which by then belongs to the host list, not the session.
///
/// Readiness-based I/O has no such problem. Waiting for readability consumes
/// nothing, so dropping the future mid-wait loses no input. There is a test for
/// exactly that.
struct RawReader {
    fd: AsyncFd<RawSource>,
    /// Only set on the stdin fallback. Field order matters: restored after `fd`
    /// is deregistered.
    _nonblocking: Option<NonBlocking>,
}

impl RawReader {
    /// Open the terminal by name so `O_NONBLOCK` lands on a file description we
    /// own.
    ///
    /// This matters more than it looks. `stdin`, `stdout`, and `stderr` on a
    /// terminal normally share a *single* open file description, and
    /// `O_NONBLOCK` is a property of the description, not the descriptor. Setting
    /// it on fd 0 therefore makes **stdout** non-blocking too — and then the
    /// first burst of session output large enough to fill the terminal's buffer
    /// (a plain `ls` will do it, at around 1 KiB) fails the write with `EAGAIN`,
    /// ending the session and dropping the user back to the host list.
    ///
    /// Opening `/dev/ttysNNN` separately gives us our own description, leaving
    /// stdout blocking as it should be.
    fn open() -> std::io::Result<Self> {
        if let Some(path) = terminal_path(libc::STDIN_FILENO)
            && let Ok(reader) = Self::from_terminal_path(&path)
        {
            return Ok(reader);
        }
        // No terminal to open by name (stdin redirected, unusual sandbox).
        // Fall back to stdin, accepting the shared-description caveat above;
        // `write_all_tolerating_blocking` covers the resulting EAGAIN.
        Self::from_stdin()
    }

    fn from_terminal_path(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        Ok(Self {
            fd: AsyncFd::new(RawSource::Owned(file))?,
            _nonblocking: None,
        })
    }

    fn from_stdin() -> std::io::Result<Self> {
        Self::from_borrowed_fd(libc::STDIN_FILENO)
    }

    /// Read from an existing descriptor, flipping `O_NONBLOCK` on its file
    /// description. See [`RawReader::open`] for why that is a last resort.
    fn from_borrowed_fd(fd: RawFd) -> std::io::Result<Self> {
        let nonblocking = NonBlocking::new(fd)?;
        // On registration failure `nonblocking` drops here and restores the flags.
        let async_fd = AsyncFd::new(RawSource::Borrowed(fd))?;
        Ok(Self {
            fd: async_fd,
            _nonblocking: Some(nonblocking),
        })
    }

    /// Cancel-safe: the only await point is a readiness wait, which consumes
    /// nothing. Dropping this future cannot lose a byte.
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            let attempt = guard.try_io(|_| {
                // SAFETY: `buf` is valid for `buf.len()` bytes.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match attempt {
                Ok(result) => return result,
                // Spurious readiness; wait again.
                Err(_would_block) => continue,
            }
        }
    }
}

/// Write session output, tolerating a non-blocking stdout.
///
/// Only reachable on the stdin fallback in [`RawReader::open`], where stdout may
/// share a non-blocking file description with stdin. `EAGAIN` there means the
/// terminal is momentarily full, not that the session is over — treating it as
/// an error is what used to kill a session on the first `ls`.
async fn write_session_output(
    stdout: &mut tokio::io::Stdout,
    mut data: &[u8],
) -> std::io::Result<()> {
    while !data.is_empty() {
        match stdout.write(data).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "terminal accepted no output",
                ));
            }
            Ok(n) => data = &data[n..],
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // Give the terminal a moment to drain. A bare yield would spin
                // a core while it does.
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            Err(err) => return Err(err),
        }
    }
    stdout.flush().await
}

/// A rule naming the session the terminal has just been handed to.
///
/// CRLF at both ends because the terminal is in raw mode, and dim so it reads as
/// ours rather than as something the remote printed. Falls back to 80 columns if
/// the size cannot be read — a short rule is a cosmetic loss, and refusing to
/// draw one would leave the seam unmarked.
fn switch_rule(host: &str) -> Vec<u8> {
    let columns = window_size().map_or(80usize, |(cols, ..)| cols as usize);
    let label = format!("── {host} ");
    let fill = columns.saturating_sub(unicode_width::UnicodeWidthStr::width(label.as_str()));
    format!("\r\n\x1b[2m{label}{}\x1b[0m\r\n", "─".repeat(fill)).into_bytes()
}

/// The key that detaches from a session and returns to the host list.
///
/// `Ctrl-]`, the telnet escape. Chosen because shells and full-screen programs
/// essentially never bind it, so it can be intercepted without stealing a key
/// the remote side wanted.
pub const DETACH_KEY: u8 = 0x1d;

/// Split input at the detach key.
///
/// Returns the bytes that still belong to the remote, or `None` if the user did
/// not detach. Everything from the key onward is dropped: it is a command to
/// this client, not something the remote asked for.
fn split_at_detach(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .iter()
        .position(|byte| *byte == DETACH_KEY)
        .map(|at| &bytes[..at])
}

/// Hand the terminal to a live session until it ends or the user detaches.
///
/// The caller must have already left the alternate screen and must keep raw mode
/// enabled — the remote side expects unbuffered keystrokes. Bytes are piped in
/// both directions untouched: the user's own terminal emulator does the VT100
/// work.
///
/// Do not parse the byte stream, beyond looking for [`DETACH_KEY`]. Anything
/// more is the first step toward writing a terminal emulator, which is out of
/// scope.
pub async fn attach(session: &LiveSession, switching: bool) -> Result<SessionOutcome, SshError> {
    let (sink, mut output) = tokio::sync::mpsc::unbounded_channel();
    // Arriving from another session means this one's screen is not on the
    // terminal at all, so its recent output has to be put back — otherwise the
    // rule is followed by nothing until you press enter, because the remote
    // already printed its prompt and will not print another unprompted.
    let replay = if switching {
        session::Replay::Recent
    } else {
        session::Replay::Missed
    };
    if !session.attach_output(sink, replay) {
        // The task is gone, so the session ended while it was detached.
        return Ok(SessionOutcome::Ended(None));
    }

    let resuming = !session.take_first_attach();
    let mut stdout = tokio::io::stdout();

    // Sessions share the primary screen, so the text above belongs to whichever
    // one you left. A rule naming this host says where the boundary is, which was
    // the actual problem — not being able to tell which machine you are typing at.
    //
    // Clearing instead was worse: a shell has nothing to repaint, so switching
    // landed on a blank screen. Keeping the scrollback and marking the seam costs
    // one line and loses no context.
    //
    // Not into a full-screen program's buffer, though: it repaints on the resize
    // nudge below, and a line of ours in the middle of its display would corrupt
    // it — the same reason the detach banner is first-attach only.
    if switching && !session.remote_in_alt_screen() {
        write_session_output(&mut stdout, &switch_rule(&session.host)).await?;
    }

    if resuming {
        // Put the terminal back in the buffer the remote thinks it is using.
        // Detaching left us in the primary screen; a full-screen program that
        // had switched to the alternate one would otherwise paint into the
        // wrong buffer, over the user's scrollback.
        if session.remote_in_alt_screen() {
            write_session_output(&mut stdout, b"\x1b[?1049h").await?;
        }
    }

    if let Ok((cols, rows, xpix, ypix)) = window_size() {
        if resuming {
            // Force a repaint. The kernel raises SIGWINCH only when the size
            // actually *changes*, so re-sending the current size is silently
            // ignored — which is exactly why a resumed `mc` used to come back
            // to a blank or stale screen. Nudge by one row, then correct it.
            session.resize(
                cols as u32,
                rows.saturating_sub(1).max(1) as u32,
                xpix as u32,
                ypix as u32,
            );
        }
        session.resize(cols as u32, rows as u32, xpix as u32, ypix as u32);
    }

    // Registered before the loop so a resize during startup isn't missed.
    let mut resized = signal(SignalKind::window_change())?;

    let stdin = RawReader::open()?;
    let mut buf = vec![0u8; 8192];

    // The only place this is discoverable: once the terminal belongs to the
    // remote there is no UI of ours left to put a hint in. CRLF because the
    // terminal is in raw mode.
    //
    // First attach only. On a resume the remote may be mid-screen in a
    // full-screen program, and writing our own line into it would corrupt the
    // display we just went to some trouble to restore.
    if !resuming {
        write_session_output(
            &mut stdout,
            b"\r\n\x1b[2m[luvienne] ctrl-] detaches, leaving the session running\x1b[0m\r\n",
        )
        .await?;
    }

    loop {
        tokio::select! {
            read = stdin.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    // stdin closed under us; leave the session running rather
                    // than killing it on the way out.
                    session.detach_output();
                    return Ok(SessionOutcome::Detached);
                }

                match split_at_detach(&buf[..n]) {
                    Some(before) => {
                        if !before.is_empty() {
                            session.write_input(before.to_vec());
                        }
                        session.detach_output();
                        return Ok(SessionOutcome::Detached);
                    }
                    None => {
                        session.write_input(buf[..n].to_vec());
                    }
                }
            }

            // SIGWINCH: tell the remote its terminal changed shape, otherwise
            // full-screen programs on the far end keep drawing at the old size.
            _ = resized.recv() => {
                if let Ok((cols, rows, xpix, ypix)) = window_size() {
                    session.resize(cols as u32, rows as u32, xpix as u32, ypix as u32);
                }
            }

            message = output.recv() => match message {
                Some(session::Output::Bytes(bytes)) => {
                    write_session_output(&mut stdout, &bytes).await?;
                }
                Some(session::Output::Ended(code)) => return Ok(SessionOutcome::Ended(code)),
                // The task dropped the sink, which only happens when it exits.
                None => return Ok(SessionOutcome::Ended(None)),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    /// The security boundary for remote forwards. russh's default handler
    /// accepts every channel a server offers; without the override, a machine
    /// we are merely logged into could open connections to arbitrary addresses
    /// on this side, through the firewall, as us.
    #[test]
    fn only_ports_we_asked_to_forward_are_accepted() {
        use crate::config::Forward;

        let forwards = vec![Forward::parse("R 9000:127.0.0.1:3000").unwrap()];

        assert!(
            forward_for_port(&forwards, 9000).is_some(),
            "the port we asked for was refused"
        );
        assert!(
            forward_for_port(&forwards, 9001).is_none(),
            "a port we never requested was accepted"
        );
        assert!(
            forward_for_port(&[], 9000).is_none(),
            "a channel was accepted with no forwards configured at all"
        );
    }

    /// A local forward's port is a socket *we* opened. The server was never
    /// asked to listen on it, so a channel naming it is unrequested by
    /// definition — and must not be answered just because the number matches.
    #[test]
    fn a_local_forwards_port_never_matches_a_server_opened_channel() {
        use crate::config::Forward;

        let forwards = vec![Forward::parse("L 8080:db:5432").unwrap()];
        assert!(forward_for_port(&forwards, 8080).is_none());
    }
    use super::*;

    /// Guards the redaction rule: if someone adds a variant carrying key
    /// material, this test is where it should start failing.
    /// A silent connection must still be probed. Without this, a session whose
    /// network has gone away stays in the list looking alive, and resuming it
    /// drops the user into a shell that is never coming back — verified by
    /// freezing the server and watching an unguarded build resume into it.
    #[test]
    fn the_client_config_probes_idle_connections() {
        let config = client_config();
        assert_eq!(
            config.keepalive_interval,
            Some(KEEPALIVE_INTERVAL),
            "idle connections would never be probed"
        );
        assert!(config.keepalive_max >= 1);
        assert!(
            config.inactivity_timeout.is_none(),
            "an inactivity timeout would garbage-collect parked sessions, \
             which are idle by design"
        );
    }

    #[test]
    fn errors_do_not_leak_credentials() {
        let err = SshError::AuthFailed {
            user: "deploy".into(),
            host: "10.0.0.1".into(),
            method: "password",
        };
        let rendered = err.to_string();
        assert!(rendered.contains("deploy@10.0.0.1"));
        assert!(!rendered.to_lowercase().contains("passphrase"));
        assert!(!rendered.contains("BEGIN"));
    }

    /// The message must name the method that actually failed. A password host
    /// reporting "no agent identity was accepted" sends people after the wrong
    /// problem — which is exactly what happened before this field existed.
    #[test]
    fn auth_failure_names_the_method_that_failed() {
        for method in ["password", "agent", "keyboard-interactive"] {
            let err = SshError::AuthFailed {
                user: "deploy".into(),
                host: "10.0.0.1".into(),
                method,
            };
            let rendered = err.to_string();
            assert!(rendered.starts_with(method), "got: {rendered}");
        }
    }

    /// The raw protocol error for this is "AdministrativelyProhibited", which
    /// tells a user nothing about what to change.
    #[test]
    fn a_refused_forward_names_the_jump_host_and_the_likely_cause() {
        let err = SshError::ForwardRefused {
            jump: "bastion".into(),
            target: "10.0.0.5".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("bastion"), "got: {rendered}");
        assert!(rendered.contains("10.0.0.5"));
        assert!(
            rendered.contains("AllowTcpForwarding"),
            "no actionable hint"
        );
    }

    #[test]
    fn a_server_offering_neither_method_says_so() {
        let err = SshError::NoInteractiveAuth {
            host: "10.0.0.1".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("does not offer"), "got: {rendered}");
    }

    #[test]
    fn host_key_mismatch_is_loud_and_final() {
        let err = SshError::HostKeyMismatch {
            host: "10.0.0.1".into(),
            line: 42,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("HOST KEY CHANGED"));
        assert!(rendered.contains("refusing to connect"));
        assert!(rendered.contains("42"), "points at the known_hosts line");
    }

    #[test]
    fn a_refused_host_key_is_reported_as_refused() {
        let err = SshError::HostKeyRejected {
            host: "10.0.0.1".into(),
        };
        assert!(err.to_string().contains("not confirmed"));
    }

    /// A pipe, as a stand-in for the tty. Returns (read end, write end).
    fn pipe() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` is a valid array of two ints.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe() failed");
        (fds[0], fds[1])
    }

    fn write_all(fd: RawFd, bytes: &[u8]) {
        // SAFETY: `bytes` is valid for `bytes.len()` bytes.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(n, bytes.len() as isize, "short write");
    }

    fn flags(fd: RawFd) -> libc::c_int {
        unsafe { libc::fcntl(fd, libc::F_GETFL) }
    }

    /// A pseudo-terminal, as a stand-in for the real one. Returns
    /// (controlling side, session side).
    fn pty() -> (RawFd, RawFd) {
        let mut main: RawFd = 0;
        let mut replica: RawFd = 0;
        // SAFETY: both out-params are valid; the rest are documented nulls.
        let rc = unsafe {
            libc::openpty(
                &mut main,
                &mut replica,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        (main, replica)
    }

    #[test]
    fn nonblocking_guard_restores_the_original_flags() {
        let (read_fd, write_fd) = pipe();
        let before = flags(read_fd);
        assert_eq!(before & libc::O_NONBLOCK, 0, "pipe starts blocking");

        {
            let _guard = NonBlocking::new(read_fd).unwrap();
            assert_ne!(flags(read_fd) & libc::O_NONBLOCK, 0, "flag is set");
        }

        assert_eq!(flags(read_fd), before, "flag is restored on drop");
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    /// The regression this reader exists to prevent.
    ///
    /// A read future is created and then dropped without ever resolving — the
    /// same thing `select!` does when the session ends. The byte written
    /// afterwards must still arrive. With a blocking-thread reader the pending
    /// `read(2)` would have consumed it.
    #[tokio::test]
    async fn a_cancelled_read_consumes_nothing() {
        let (read_fd, write_fd) = pipe();
        let reader = RawReader::from_borrowed_fd(read_fd).unwrap();
        let mut buf = [0u8; 64];

        // Arm a read, let it park on readability, then drop it unresolved.
        {
            let pending = reader.read(&mut buf);
            tokio::pin!(pending);
            tokio::select! {
                _ = &mut pending => panic!("nothing was written yet"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
        }

        write_all(write_fd, b"keystroke");

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read(&mut buf))
            .await
            .expect("read timed out — the cancelled future ate the input")
            .unwrap();

        assert_eq!(&buf[..n], b"keystroke");

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    /// The bug this exists to prevent, stated as a property of the OS.
    ///
    /// `O_NONBLOCK` belongs to the open file description, not the descriptor.
    /// On a terminal, stdin/stdout/stderr share one description, so setting the
    /// flag "on stdin" silently made *stdout* non-blocking — and the first burst
    /// of session output large enough to fill the terminal buffer (a plain `ls`)
    /// failed the write with `EAGAIN`, ending the session.
    #[tokio::test]
    async fn borrowing_a_descriptor_makes_its_siblings_nonblocking_too() {
        let (read_fd, write_fd) = pipe();
        // A second descriptor onto the *same* description, as fd 1 is to fd 0.
        let sibling = unsafe { libc::dup(read_fd) };
        assert!(sibling >= 0);

        assert_eq!(flags(sibling) & libc::O_NONBLOCK, 0);
        let reader = RawReader::from_borrowed_fd(read_fd).unwrap();
        assert_ne!(
            flags(sibling) & libc::O_NONBLOCK,
            0,
            "the flag leaks to the sibling — this is why `open` opens the \
             terminal by name instead"
        );
        drop(reader);

        unsafe {
            libc::close(sibling);
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    /// And the fix: opening the terminal by name gives us our own description,
    /// so nothing else changes behaviour.
    #[tokio::test]
    async fn opening_by_path_leaves_other_descriptors_blocking() {
        let (main_fd, replica_fd) = pty();
        let name = terminal_path(replica_fd).expect("a pty has a name");

        // Stand-in for stdout: another descriptor on the replica's description.
        let sibling = unsafe { libc::dup(replica_fd) };
        assert!(sibling >= 0);
        assert_eq!(flags(sibling) & libc::O_NONBLOCK, 0);

        let reader = RawReader::from_terminal_path(&name).unwrap();
        assert_eq!(
            flags(sibling) & libc::O_NONBLOCK,
            0,
            "opening by name must not touch stdout's description"
        );
        assert_ne!(
            flags(reader.fd.get_ref().as_raw_fd()) & libc::O_NONBLOCK,
            0,
            "but our own descriptor is non-blocking"
        );
        drop(reader);

        unsafe {
            libc::close(sibling);
            libc::close(replica_fd);
            libc::close(main_fd);
        }
    }

    #[test]
    fn detach_key_splits_input_and_is_not_forwarded() {
        // Nothing typed before it.
        assert_eq!(split_at_detach(&[DETACH_KEY]), Some(&b""[..]));
    }

    /// The rule marks the seam between two sessions, so it has to name the host
    /// and it has to be ours to look at — dim, on its own lines, reset after.
    #[test]
    fn the_switch_rule_names_the_host_and_stands_alone() {
        let rule = String::from_utf8(switch_rule("db-primary")).unwrap();

        assert!(
            rule.contains("db-primary"),
            "does not name the host: {rule:?}"
        );
        assert!(
            rule.starts_with("\r\n"),
            "runs on from the previous line: {rule:?}"
        );
        assert!(
            rule.ends_with("\r\n"),
            "leaves the cursor on the rule: {rule:?}"
        );
        assert!(rule.contains("\x1b[2m"), "not dimmed: {rule:?}");
        assert!(rule.ends_with("\x1b[0m\r\n"), "leaves styling on: {rule:?}");
    }

    /// A long host name must not push the rule past the edge and wrap it onto a
    /// second line — the seam is one line or it reads as output.
    #[test]
    fn the_switch_rule_fits_one_line() {
        for host in ["a", "db-primary", &"very-long-hostname".repeat(8)] {
            let rule = String::from_utf8(switch_rule(host)).unwrap();
            let visible: String = rule
                .replace("\r\n", "")
                .replace("\x1b[2m", "")
                .replace("\x1b[0m", "");
            let width = unicode_width::UnicodeWidthStr::width(visible.as_str());
            // 80 is the fallback when the size cannot be read, which is the case
            // under the test harness.
            let limit = 80.max(unicode_width::UnicodeWidthStr::width(host) + 4);
            assert!(
                width <= limit,
                "rule is {width} wide for {host:?}, limit {limit}"
            );
        }
        // Typed mid-line: the remote still gets what came before.
        assert_eq!(split_at_detach(b"ls\x1d"), Some(&b"ls"[..]));
        // Anything after the key is dropped with it.
        assert_eq!(split_at_detach(b"ab\x1dcd"), Some(&b"ab"[..]));
        // Ordinary input is untouched.
        assert_eq!(split_at_detach(b"ls -la\r"), None);
        assert_eq!(split_at_detach(b""), None);
    }

    #[tokio::test]
    async fn reader_reports_eof_as_zero_bytes() {
        let (read_fd, write_fd) = pipe();
        let reader = RawReader::from_borrowed_fd(read_fd).unwrap();

        // Closing the write end is what ends the loop in `attach`.
        unsafe { libc::close(write_fd) };

        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();

        assert_eq!(n, 0, "EOF must surface as 0 so attach() breaks its loop");
        unsafe { libc::close(read_fd) };
    }
}
