//! Port forwards attached to a host.
//!
//! Two directions, matching `ssh -L` and `ssh -R`:
//!
//! - **local** — we listen here, and each connection is carried over the session
//!   and opened from the *server* to `to_host:to_port`. Reaching a database that
//!   only listens on the server's private network is the usual reason.
//! - **remote** — the *server* listens, and each connection there is carried back
//!   to us and opened to `to_host:to_port` from this machine. Exposing something
//!   running locally to the far end is the usual reason.
//!
//! Stored field-by-field rather than as an `ssh`-style spec string, so `u16`
//! rejects a bad port when the file is read rather than at connect time, and so
//! a hand-edited entry cannot be ambiguous. The terse `L 8080:db:5432` form is
//! how the *form field* reads and writes them — see [`Forward::parse`] and
//! [`Forward::spec`].

use serde::{Deserialize, Serialize};

/// Which end opens the listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Local,
    Remote,
}

impl Direction {
    /// The single letter used in the terse spec form.
    pub fn letter(self) -> char {
        match self {
            Self::Local => 'L',
            Self::Remote => 'R',
        }
    }
}

/// The address a forward listens on when the spec does not name one.
///
/// **Loopback, never `0.0.0.0`.** A local forward binding every interface puts
/// whatever is on the far end — a production database, an admin panel — on the
/// listener's network for anyone who can reach this machine. `ssh` defaults the
/// same way and makes you pass `-g` to change it; here you write the address out
/// in full, which is at least hard to do by accident.
pub const DEFAULT_BIND: &str = "127.0.0.1";

fn default_bind() -> String {
    DEFAULT_BIND.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forward {
    pub direction: Direction,
    /// Where the listening socket binds. Ours for a local forward, the server's
    /// for a remote one.
    #[serde(default = "default_bind")]
    pub listen_host: String,
    pub listen_port: u16,
    /// Where connections are delivered. Resolved by the server for a local
    /// forward, by us for a remote one.
    pub to_host: String,
    pub to_port: u16,
}

/// Why a forward spec could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ForwardError {
    #[error("{0:?} must start with L or R, for a local or remote forward")]
    NoDirection(String),

    #[error("{0:?} should look like L 8080:db.internal:5432")]
    Shape(String),

    #[error("{0:?} is not a port from 1 to 65535")]
    Port(String),

    #[error("a forward needs a host to connect to, as in L 8080:db.internal:5432")]
    NoTarget,
}

impl Forward {
    /// Read the terse form: `L [bind:]port:host:hostport`.
    ///
    /// Deliberately the same shape as `ssh -L`, because the people who want this
    /// already know that spelling and would otherwise have to learn ours.
    pub fn parse(spec: &str) -> Result<Self, ForwardError> {
        let spec = spec.trim();
        let (letter, rest) = spec
            .split_once(|c: char| c.is_whitespace() || c == ':')
            .ok_or_else(|| ForwardError::Shape(spec.to_string()))?;

        let direction = match letter.trim().to_ascii_lowercase().as_str() {
            "l" | "local" => Direction::Local,
            "r" | "remote" => Direction::Remote,
            _ => return Err(ForwardError::NoDirection(spec.to_string())),
        };

        let parts = split_outside_brackets(rest.trim());
        let (listen_host, listen_port, to_host, to_port) = match parts.as_slice() {
            [port, host, hostport] => (default_bind(), *port, *host, *hostport),
            [bind, port, host, hostport] => ((*bind).to_string(), *port, *host, *hostport),
            // Three fields is the common shape; two means the target is missing,
            // which is worth saying plainly rather than as a shape complaint.
            [_, _] | [_] => return Err(ForwardError::NoTarget),
            _ => return Err(ForwardError::Shape(spec.to_string())),
        };

        let to_host = to_host.trim_matches(['[', ']']).to_string();
        if to_host.is_empty() {
            return Err(ForwardError::NoTarget);
        }

        Ok(Self {
            direction,
            listen_host: listen_host.trim_matches(['[', ']']).to_string(),
            listen_port: port(listen_port)?,
            to_host,
            to_port: port(to_port)?,
        })
    }

    /// The terse form, as the form field shows it.
    ///
    /// The bind address is omitted when it is the loopback default, so the
    /// common case reads as `L 8080:db.internal:5432` rather than carrying a
    /// `127.0.0.1:` that every entry would share.
    pub fn spec(&self) -> String {
        let listen = bracket_if_needed(&self.listen_host);
        let to = bracket_if_needed(&self.to_host);
        if self.listen_host == DEFAULT_BIND {
            format!(
                "{} {}:{}:{}",
                self.direction.letter(),
                self.listen_port,
                to,
                self.to_port
            )
        } else {
            format!(
                "{} {}:{}:{}:{}",
                self.direction.letter(),
                listen,
                self.listen_port,
                to,
                self.to_port
            )
        }
    }

    /// Parse a comma-separated list, as typed into the form field.
    pub fn parse_list(text: &str) -> Result<Vec<Self>, ForwardError> {
        text.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Self::parse)
            .collect()
    }

    /// Render a list back into the field.
    pub fn render_list(forwards: &[Self]) -> String {
        forwards
            .iter()
            .map(Self::spec)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `listen_host:listen_port`, ready for `TcpListener::bind` or `tcpip_forward`.
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.listen_host, self.listen_port)
    }

    /// How the forward reads in the UI and in errors.
    pub fn describe(&self) -> String {
        match self.direction {
            Direction::Local => format!(
                "{} → {}:{} on the server",
                self.listen_addr(),
                self.to_host,
                self.to_port
            ),
            Direction::Remote => format!(
                "{} on the server → {}:{}",
                self.listen_addr(),
                self.to_host,
                self.to_port
            ),
        }
    }
}

/// Wrap a bare IPv6 literal in brackets so `host:port` stays unambiguous.
fn bracket_if_needed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn port(text: &str) -> Result<u16, ForwardError> {
    text.trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| ForwardError::Port(text.to_string()))
}

/// Split on `:`, ignoring colons inside `[...]`.
///
/// Without the bracket rule an IPv6 target — `L 8080:[::1]:80` — splits into
/// seven meaningless pieces, and the error would blame the shape of a spec that
/// is written exactly as `ssh` documents it.
fn split_outside_brackets(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (i, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_common_local_form() {
        let f = Forward::parse("L 8080:db.internal:5432").unwrap();
        assert_eq!(f.direction, Direction::Local);
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.to_host, "db.internal");
        assert_eq!(f.to_port, 5432);
    }

    /// The security default. A forward that binds every interface publishes
    /// whatever is on the far end to anyone who can reach this machine, so it
    /// has to be asked for explicitly and can never be what you get by default.
    #[test]
    fn the_bind_address_defaults_to_loopback() {
        assert_eq!(
            Forward::parse("L 8080:db:5432").unwrap().listen_host,
            "127.0.0.1"
        );
        assert_eq!(
            Forward::parse("R 9000:localhost:3000").unwrap().listen_host,
            "127.0.0.1"
        );
    }

    #[test]
    fn an_explicit_bind_address_is_kept() {
        let f = Forward::parse("L 0.0.0.0:8080:db:5432").unwrap();
        assert_eq!(f.listen_host, "0.0.0.0");
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.to_host, "db");
    }

    #[test]
    fn reads_a_remote_forward() {
        let f = Forward::parse("R 9000:127.0.0.1:3000").unwrap();
        assert_eq!(f.direction, Direction::Remote);
        assert_eq!(f.listen_port, 9000);
        assert_eq!(f.to_port, 3000);
    }

    #[test]
    fn the_direction_word_may_be_spelled_out_or_lowercase() {
        for spec in ["local 80:h:80", "LOCAL 80:h:80", "l 80:h:80", "L:80:h:80"] {
            assert_eq!(
                Forward::parse(spec).unwrap().direction,
                Direction::Local,
                "{spec}"
            );
        }
    }

    /// `ssh` documents IPv6 targets in brackets, and splitting naively on `:`
    /// turns one into a fistful of nonsense and then blames the user's spec.
    #[test]
    fn an_ipv6_target_in_brackets_survives_the_split() {
        let f = Forward::parse("L 8080:[::1]:80").unwrap();
        assert_eq!(f.to_host, "::1");
        assert_eq!(f.to_port, 80);

        let f = Forward::parse("L [::1]:8080:[fe80::1]:443").unwrap();
        assert_eq!(f.listen_host, "::1");
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.to_host, "fe80::1");
        assert_eq!(f.to_port, 443);
    }

    #[test]
    fn bad_specs_say_what_is_wrong() {
        assert!(matches!(
            Forward::parse("X 80:h:80"),
            Err(ForwardError::NoDirection(_))
        ));
        assert!(matches!(
            Forward::parse("L 8080"),
            Err(ForwardError::NoTarget)
        ));
        assert!(matches!(
            Forward::parse("L 8080:db"),
            Err(ForwardError::NoTarget)
        ));
        assert!(matches!(
            Forward::parse("L 99999:db:80"),
            Err(ForwardError::Port(_))
        ));
        // Port zero would bind whatever the OS handed out, which nobody can
        // then connect to — a forward that silently goes nowhere.
        assert!(matches!(
            Forward::parse("L 0:db:80"),
            Err(ForwardError::Port(_))
        ));
    }

    /// The field is edited as text, so what it renders has to read back as the
    /// same thing — otherwise opening and saving a host quietly rewrites it.
    #[test]
    fn a_spec_round_trips_through_the_field() {
        for spec in [
            "L 8080:db.internal:5432",
            "R 9000:127.0.0.1:3000",
            "L 0.0.0.0:8080:db:5432",
            "L 8080:[::1]:80",
        ] {
            let parsed = Forward::parse(spec).unwrap();
            assert_eq!(parsed.spec(), spec, "rendering changed {spec}");
            assert_eq!(
                Forward::parse(&parsed.spec()).unwrap(),
                parsed,
                "re-reading changed {spec}"
            );
        }
    }

    #[test]
    fn a_list_round_trips() {
        let text = "L 8080:db:5432, R 9000:127.0.0.1:3000";
        let list = Forward::parse_list(text).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(Forward::render_list(&list), text);
    }

    #[test]
    fn an_empty_list_is_not_an_error() {
        assert!(Forward::parse_list("").unwrap().is_empty());
        assert!(Forward::parse_list("  ,  ").unwrap().is_empty());
    }
    /// An IPv6 listen address has to produce something that actually binds.
    /// `"::1:45999"` looks malformed but resolves correctly, because the
    /// address resolver splits at the *last* colon — a future refactor to
    /// `SocketAddr::from_str` would reject it, so this pins the behaviour.
    #[tokio::test]
    async fn an_ipv6_listen_address_binds() {
        let forward = Forward::parse("L [::1]:45999:target:80").unwrap();
        let listener = tokio::net::TcpListener::bind(forward.listen_addr())
            .await
            .expect("an IPv6 forward produced an unbindable address");
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }
}
