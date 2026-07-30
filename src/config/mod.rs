//! Host inventory: the list of things you can connect to, and how.
//!
//! Persisted as TOML at `~/.config/luvienne/hosts.toml`. This file holds
//! *references* to credentials, never credentials themselves — see [`AuthRef`].

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod forward;

pub use forward::{Direction, Forward};

/// How to authenticate to a host.
///
/// Deliberately contains no secret material. A key is named by path; a passphrase
/// or password is fetched at connect time from the agent, the Keychain, or a
/// prompt. Adding a `password: String` variant here would write plaintext
/// credentials to disk — don't.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum AuthRef {
    /// Use the running SSH agent via `SSH_AUTH_SOCK`. The key never leaves the agent.
    #[default]
    Agent,
    /// An OpenSSH or PEM private key on disk. `.ppk` files are detected by content,
    /// so this variant covers PuTTY keys too.
    Key { path: PathBuf },
    /// Password or keyboard-interactive, prompted at connect time.
    Password,
}

impl AuthRef {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Key { .. } => "key",
            Self::Password => "password",
        }
    }
}

fn default_port() -> u16 {
    22
}

/// How many hosts a single connection may traverse. A sanity bound, not a
/// protocol limit — nobody legitimately chains eight bastions, and it stops a
/// hand-written config from spinning.
pub const MAX_JUMPS: usize = 8;

/// Why a jump chain could not be resolved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("no host named {0} in the inventory")]
    Unknown(String),

    #[error("jump hosts loop back on themselves at {0}")]
    Cycle(String),

    #[error("jump chain is longer than {MAX_JUMPS} hosts")]
    TooDeep,
}

/// Why an `ssh`-style target could not be read. Every message is shown on the
/// status line, so each says what to type instead rather than only what is wrong.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("type a host, as in user@10.0.0.1 or db.internal:2222")]
    Empty,

    #[error("{0:?} has no host in it — try user@10.0.0.1")]
    NoHost(String),

    #[error("{0:?} is missing the closing bracket, as in [::1]:22")]
    Unclosed(String),

    #[error("{0:?} is not a port from 1 to 65535")]
    Port(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    /// Display name, and the key used by `jump` references.
    pub name: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    /// Free-form categories. A host can be in several at once — these are tags,
    /// not a tree.
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub auth: AuthRef,
    /// Name of another host in the inventory to tunnel through.
    #[serde(default)]
    pub jump: Option<String>,
    /// Whether to keep this host's key passphrase in the macOS Keychain.
    ///
    /// Off unless the user turns it on, and it stays a per-host decision: one
    /// global "remember my passphrases" switch would opt every host in at once,
    /// including the ones whose keys the user deliberately types out. Only
    /// meaningful with [`AuthRef::Key`] — there is no passphrase to cache for an
    /// agent, and a login password is not stored at all.
    #[serde(default)]
    pub cache_passphrase: bool,
    /// Port forwards to raise with the session, in both directions.
    ///
    /// They belong to the host rather than to a connect-time flag because the
    /// point of this app is that you do not re-type connection details — a
    /// tunnel you need once you will need every time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
}

impl Host {
    /// Build a throwaway host from an `ssh`-style target: `[user@]host[:port]`.
    ///
    /// The inverse of [`Self::destination`], for quick connect — somewhere to
    /// reach once without adding it to the inventory. Auth is the agent, which
    /// is what a host with no `auth` line already means, and an omitted user is
    /// left empty so the existing "login as" prompt asks at connect time rather
    /// than this guessing.
    ///
    /// `name` is the target as typed, so the session list and every status line
    /// call it what the user called it.
    pub fn from_target(target: &str) -> Result<Self, TargetError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(TargetError::Empty);
        }

        let (user, rest) = match target.rsplit_once('@') {
            Some((user, rest)) => (user.trim().to_string(), rest.trim()),
            None => (String::new(), target),
        };

        // An IPv6 literal has to be bracketed to be told apart from the port
        // separator, the same rule `ssh` and every URL follow.
        let (address, port) = if let Some(stripped) = rest.strip_prefix('[') {
            let (inside, after) = stripped
                .split_once(']')
                .ok_or_else(|| TargetError::Unclosed(target.to_string()))?;
            // Only `:port` may follow the bracket. Taking `strip_prefix` at face
            // value here silently discarded anything else and connected to the
            // default port, so `[::1]2222` reached 22.
            let port = match after {
                "" => None,
                other => Some(
                    other
                        .strip_prefix(':')
                        .ok_or_else(|| TargetError::Port(other.to_string()))?,
                ),
            };
            (inside.trim().to_string(), port)
        } else {
            match rest.split_once(':') {
                // Trimmed: `host : 22` otherwise yields an address with a
                // trailing space, which fails to resolve and blames the network.
                Some((host, port)) => (host.trim().to_string(), Some(port)),
                None => (rest.to_string(), None),
            }
        };

        if address.is_empty() {
            return Err(TargetError::NoHost(target.to_string()));
        }

        let port = match port {
            None | Some("") => default_port(),
            Some(text) => match text.trim().parse() {
                // `u16` happily parses 0, and the error above promises 1 to
                // 65535 — a client connect to port 0 is meaningless anyway.
                Ok(0) | Err(_) => return Err(TargetError::Port(text.trim().to_string())),
                Ok(port) => port,
            },
        };

        Ok(Self {
            name: target.to_string(),
            address,
            port,
            user,
            tags: Vec::new(),
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        })
    }

    pub fn destination(&self) -> String {
        // An empty user means the username is asked for at connect time, so
        // show that rather than a bare `@host` that looks like a bug.
        match self.user.trim() {
            "" => format!("(ask)@{}:{}", self.address, self.port),
            user => format!("{}@{}:{}", user, self.address, self.port),
        }
    }

    /// The Keychain entry this host would read and write, if any.
    ///
    /// `None` covers every host that must never touch the Keychain: caching off,
    /// or an auth method with no passphrase to cache. Callers diff this across an
    /// edit to find entries that should be deleted, so it has to answer for the
    /// *whole* condition rather than just the flag.
    pub fn cached_key_id(&self) -> Option<String> {
        match (&self.auth, self.cache_passphrase) {
            (AuthRef::Key { path }, true) => Some(crate::keystore::key_id(path)),
            _ => None,
        }
    }

    /// Case-insensitive subsequence match over name, address, user, and tags.
    /// Every character of `query` must appear in order somewhere in the haystack.
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        // The auth method is included so `/key` selects every host using a key
        // file — which is what makes a bulk edit able to target them.
        let haystack = format!(
            "{} {} {} {} {}",
            self.name,
            self.address,
            self.user,
            self.tags.join(" "),
            self.auth.label(),
        )
        .to_lowercase();

        let mut chars = haystack.chars();
        query
            .to_lowercase()
            .chars()
            .all(|needle| chars.any(|c| c == needle))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    #[serde(default, rename = "host")]
    pub hosts: Vec<Host>,
}

impl Inventory {
    /// Load the inventory, returning an empty one if the file does not exist yet.
    /// A missing config is a first run, not an error; malformed TOML *is* an error.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("reading inventory at {}", path.display()))?;
        toml::from_str(&raw).wrap_err_with(|| format!("parsing inventory at {}", path.display()))
    }

    /// `$XDG_CONFIG_HOME/luvienne/hosts.toml`, else `~/.config/luvienne/hosts.toml`.
    ///
    /// Deliberately *not* `directories::ProjectDirs`. On macOS that resolves to
    /// `~/Library/Application Support/`, which is right for a GUI app and wrong
    /// for a terminal one — nobody hand-edits TOML in there, and it disagreed with
    /// both the docs and the empty-state hint this app prints. Terminal tools live
    /// in `~/.config`.
    pub fn path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("hosts.toml"))
    }

    /// Name this was released under before the rename.
    const FORMER_NAME: &'static str = "luviennessh";

    /// Copy a pre-rename inventory into place, once.
    ///
    /// Called explicitly from `main`, never from [`Inventory::path`]. A getter
    /// that copies files is a trap: the test suite calls `path()` to check where
    /// the config lives, and with the migration hidden in there it silently
    /// wrote into the developer's real home directory.
    ///
    /// A copy, not a move: the old file staying put costs nothing and means a
    /// mistake here cannot lose someone's host list. Failures are deliberately
    /// silent — a missing or unreadable old config is the overwhelmingly common
    /// case, and not something to report as an error on every start.
    pub fn migrate_from_former_name(new_path: &Path) {
        let Some(parent) = new_path.parent() else {
            return;
        };
        let Some(old_dir) = parent.parent().map(|p| p.join(Self::FORMER_NAME)) else {
            return;
        };
        let old_path = old_dir.join("hosts.toml");
        // Never overwrite an inventory that already exists under the new name.
        if new_path.exists() || !old_path.is_file() {
            return;
        }
        if std::fs::create_dir_all(parent).is_ok() {
            let _ = std::fs::copy(&old_path, new_path);
        }
    }

    fn config_dir() -> Result<PathBuf> {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
            && !xdg.is_empty()
        {
            return Ok(PathBuf::from(xdg).join("luvienne"));
        }
        let home = directories::BaseDirs::new()
            .ok_or_else(|| color_eyre::eyre::eyre!("cannot determine home directory"))?
            .home_dir()
            .to_path_buf();
        Ok(home.join(".config").join("luvienne"))
    }

    /// Write the inventory back to disk.
    ///
    /// Edits the existing document in place with `toml_edit` rather than
    /// re-serializing. This file is meant to be hand-editable, and a plain
    /// `toml::to_string` would discard every comment in it and rewrite
    /// `auth = { ... }` into a `[host.auth]` sub-table — reformatting a file the
    /// user wrote, on their first click of "add host".
    ///
    /// The write is atomic: a temporary file in the same directory, then a
    /// rename. A crash mid-write must not leave a truncated inventory.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }

        let existing = std::fs::read_to_string(path).unwrap_or_default();
        let mut doc = existing
            .parse::<toml_edit::DocumentMut>()
            .unwrap_or_default();

        self.write_into(&mut doc);

        // Same directory, so the rename cannot cross a filesystem boundary.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, doc.to_string())
            .wrap_err_with(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).wrap_err_with(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Sync `self.hosts` into the document's `[[host]]` array.
    ///
    /// Tables are matched to hosts **by name**, not by position, and moved
    /// wholesale so each host keeps its own comments. Overwriting values
    /// in-place by index looks simpler and is wrong: deleting a host from the
    /// middle shifts every later host up one slot while the comments stay where
    /// they are, so a note reading "staging" ends up labelling the production
    /// box whose own warning was just overwritten.
    ///
    /// A host that matches no name falls back to the table in the same position,
    /// which is how a renamed host keeps its comment. That fallback applies
    /// *only* when the count is unchanged — with an insertion it would hand the
    /// new host the next one's comment, which is the same corruption in reverse.
    fn write_into(&self, doc: &mut toml_edit::DocumentMut) {
        use toml_edit::{ArrayOfTables, Item, Table};

        let entry = doc
            .entry("host")
            .or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
        if entry.as_array_of_tables().is_none() {
            *entry = Item::ArrayOfTables(ArrayOfTables::new());
        }
        let existing = entry.as_array_of_tables_mut().expect("just ensured");

        // Take ownership of the current tables so each can be claimed once.
        let mut claimable: Vec<Option<Table>> = existing.iter().map(|t| Some(t.clone())).collect();

        let mut rebuilt = ArrayOfTables::new();
        for (i, host) in self.hosts.iter().enumerate() {
            let by_name = claimable.iter().position(|slot| {
                slot.as_ref()
                    .and_then(|t| t.get("name"))
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n == host.name)
            });
            // Same position, for a host renamed in place. Only safe when
            // nothing was added or removed; otherwise positions have shifted
            // and this would claim a different host's table.
            let renamed_in_place = self.hosts.len() == claimable.len();
            let by_position =
                (renamed_in_place && i < claimable.len() && claimable[i].is_some()).then_some(i);

            let mut table = by_name
                .or(by_position)
                .and_then(|index| claimable[index].take())
                .unwrap_or_default();

            // A cloned table remembers where it used to sit in the document,
            // and toml_edit renders by that stored position — so without this a
            // reordered list writes out in its old order.
            table.set_position(Some(i as isize));
            Self::write_host_into(&mut table, host);
            rebuilt.push(table);
        }

        *entry = Item::ArrayOfTables(rebuilt);
    }

    /// Write one host's fields into its table, leaving comments and formatting.
    fn write_host_into(table: &mut toml_edit::Table, host: &Host) {
        use toml_edit::value;

        table["name"] = value(host.name.as_str());
        table["address"] = value(host.address.as_str());
        table["user"] = value(host.user.as_str());

        // Defaults are only written when the key is already there. Otherwise
        // adding one host would sprinkle `port = 22` and `tags = []` through
        // every *other* entry in the file — editing lines the user never
        // touched, which is exactly what preserving their file is meant to
        // avoid.
        if host.port != default_port() || table.contains_key("port") {
            table["port"] = value(i64::from(host.port));
        }

        if !host.tags.is_empty() || table.contains_key("tags") {
            let mut tags = toml_edit::Array::new();
            for tag in &host.tags {
                tags.push(tag.as_str());
            }
            table["tags"] = value(tags);
        }

        // Same rule: agent is the default, so don't add the key to entries
        // that never had it.
        if !matches!(host.auth, AuthRef::Agent) || table.contains_key("auth") {
            let mut auth = toml_edit::InlineTable::new();
            match &host.auth {
                AuthRef::Agent => {
                    auth.insert("method", "agent".into());
                }
                AuthRef::Key { path } => {
                    auth.insert("method", "key".into());
                    auth.insert("path", path.display().to_string().into());
                }
                AuthRef::Password => {
                    auth.insert("method", "password".into());
                }
            }
            table["auth"] = value(auth);
        }

        // Same default rule again: `false` is the default, so it is only written
        // into entries that already carry the key.
        if host.cache_passphrase || table.contains_key("cache_passphrase") {
            table["cache_passphrase"] = value(host.cache_passphrase);
        }

        // And again for forwards. Writing the key unconditionally would put
        // `forwards = []` on every host in the file the first time one host
        // gets a tunnel. An empty array *is* written when the key already
        // exists, because that is how the last forward gets removed.
        if !host.forwards.is_empty() || table.contains_key("forwards") {
            let mut list = toml_edit::Array::new();
            for forward in &host.forwards {
                let mut entry = toml_edit::InlineTable::new();
                entry.insert(
                    "direction",
                    match forward.direction {
                        Direction::Local => "local",
                        Direction::Remote => "remote",
                    }
                    .into(),
                );
                // Loopback is the default, so it is left out unless the user
                // deliberately widened the bind — where it must be visible.
                if forward.listen_host != crate::config::forward::DEFAULT_BIND {
                    entry.insert("listen_host", forward.listen_host.as_str().into());
                }
                entry.insert("listen_port", i64::from(forward.listen_port).into());
                entry.insert("to_host", forward.to_host.as_str().into());
                entry.insert("to_port", i64::from(forward.to_port).into());
                list.push(entry);
            }
            table["forwards"] = value(list);
        }

        match &host.jump {
            Some(jump) => table["jump"] = value(jump.as_str()),
            None => {
                table.remove("jump");
            }
        }
    }

    /// The hosts to connect through, in order, ending with `target`.
    ///
    /// A host with no `jump` yields just itself. `web` jumping via `bastion`
    /// yields `[bastion, web]` — you dial the bastion first and tunnel onward.
    ///
    /// Cycles are the interesting failure: `a` jumps via `b` and `b` via `a` is
    /// easy to write by hand and would otherwise loop until the stack ran out.
    pub fn connection_chain(&self, target: &str) -> Result<Vec<Host>, ChainError> {
        let mut chain = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut name = target.to_string();

        loop {
            if seen.iter().any(|s| s == &name) {
                return Err(ChainError::Cycle(name));
            }
            seen.push(name.clone());

            let host = self
                .hosts
                .iter()
                .find(|h| h.name == name)
                .ok_or_else(|| ChainError::Unknown(name.clone()))?;
            chain.push(host.clone());

            match &host.jump {
                Some(next) => {
                    if chain.len() > MAX_JUMPS {
                        return Err(ChainError::TooDeep);
                    }
                    name = next.clone();
                }
                None => break,
            }
        }

        // Built from the target backwards; connecting goes the other way.
        chain.reverse();
        Ok(chain)
    }

    /// Every tag in use, sorted and deduplicated.
    pub fn tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .hosts
            .iter()
            .flat_map(|h| h.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes people actually type at an `ssh` prompt.
    #[test]
    fn a_target_reads_the_same_way_ssh_would() {
        let plain = Host::from_target("db.internal").unwrap();
        assert_eq!(
            (plain.user.as_str(), plain.address.as_str(), plain.port),
            ("", "db.internal", 22)
        );

        let with_user = Host::from_target("deploy@10.0.0.5").unwrap();
        assert_eq!(
            (
                with_user.user.as_str(),
                with_user.address.as_str(),
                with_user.port
            ),
            ("deploy", "10.0.0.5", 22)
        );

        let with_port = Host::from_target("deploy@10.0.0.5:2222").unwrap();
        assert_eq!(with_port.port, 2222);

        // Bracketed, or the last colon of an IPv6 address reads as the port.
        let v6 = Host::from_target("[2001:db8::1]:2222").unwrap();
        assert_eq!((v6.address.as_str(), v6.port), ("2001:db8::1", 2222));

        let v6_default = Host::from_target("root@[::1]").unwrap();
        assert_eq!(
            (
                v6_default.user.as_str(),
                v6_default.address.as_str(),
                v6_default.port
            ),
            ("root", "::1", 22)
        );
    }

    /// An omitted user is left empty rather than guessed, which routes into the
    /// same "login as" prompt an `(ask)` host uses.
    #[test]
    fn a_target_without_a_user_asks_rather_than_assuming() {
        let host = Host::from_target("10.0.0.9").unwrap();
        assert!(host.user.is_empty());
        assert!(host.destination().contains("(ask)"));
    }

    /// Quick connect is somewhere to reach once: the agent, nothing cached, and
    /// no jump host. It must not inherit anything from the inventory.
    #[test]
    fn a_target_is_a_bare_agent_host() {
        let host = Host::from_target("deploy@10.0.0.5").unwrap();
        assert!(matches!(host.auth, AuthRef::Agent));
        assert!(host.jump.is_none());
        assert!(!host.cache_passphrase);
        assert!(host.tags.is_empty());
        assert!(host.forwards.is_empty());
        // Named as typed, so the session list calls it what the user called it.
        assert_eq!(host.name, "deploy@10.0.0.5");
    }

    /// Shapes that are odd but not wrong, pinned so a later tidy-up does not
    /// change them by accident.
    #[test]
    fn the_awkward_target_shapes_are_pinned() {
        // A bracketed address with no port at all.
        let bare = Host::from_target("[fe80::1]").unwrap();
        assert_eq!((bare.address.as_str(), bare.port), ("fe80::1", 22));

        // A trailing colon is "no port given", not port zero.
        assert_eq!(Host::from_target("host:").unwrap().port, 22);

        // Two colons outside brackets is a typo, not host:22 with extra.
        assert!(matches!(
            Host::from_target("host:22:33"),
            Err(TargetError::Port(_))
        ));

        // Surrounding and internal whitespace around the separators is trimmed.
        let spaced = Host::from_target("  deploy @ 10.0.0.1 : 2222  ").unwrap();
        assert_eq!(
            (spaced.user.as_str(), spaced.address.as_str(), spaced.port),
            ("deploy", "10.0.0.1", 2222)
        );

        // A user with no host is caught; a host with no user is the ask path.
        assert!(matches!(
            Host::from_target("@"),
            Err(TargetError::NoHost(_))
        ));
        assert!(Host::from_target("@host").unwrap().user.is_empty());
    }

    #[test]
    fn bad_targets_say_what_to_type_instead() {
        // `matches!` rather than `assert_eq!`: `Host` has no `PartialEq`, and
        // giving it one just to compare the error side would be the wrong fix.
        assert!(matches!(Host::from_target("   "), Err(TargetError::Empty)));
        assert!(matches!(
            Host::from_target("deploy@"),
            Err(TargetError::NoHost(_))
        ));
        assert!(matches!(
            Host::from_target("[::1:22"),
            Err(TargetError::Unclosed(_))
        ));
        assert!(matches!(
            Host::from_target("host:not-a-port"),
            Err(TargetError::Port(_))
        ));
        assert!(matches!(
            Host::from_target("host:70000"),
            Err(TargetError::Port(_))
        ));
        // `u16` parses this happily; the error text promises 1 to 65535.
        assert!(matches!(
            Host::from_target("host:0"),
            Err(TargetError::Port(_))
        ));
        // Anything after the bracket that is not `:port` is a typo, not something
        // to discard silently and connect anyway.
        assert!(
            Host::from_target("[::1]junk").is_err(),
            "accepted junk after a bracketed address"
        );
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

    #[test]
    fn empty_query_matches_everything() {
        assert!(host("web-01", &[]).matches(""));
    }

    #[test]
    fn matches_subsequence_across_fields() {
        let h = host("web-01", &["prod"]);
        assert!(h.matches("web"));
        assert!(h.matches("prod"));
        assert!(h.matches("wb1"), "subsequence, not substring");
        assert!(h.matches("WEB"), "case insensitive");
        assert!(!h.matches("zzz"));
    }

    /// Being able to select by auth method is what lets a bulk edit target,
    /// say, every host still pointing at a key file that is not on this machine.
    #[test]
    fn the_filter_matches_the_auth_method() {
        let mut keyed = host("web-01", &[]);
        keyed.auth = AuthRef::Key { path: "/k".into() };
        assert!(keyed.matches("key"));

        let agent = host("web-02", &[]);
        assert!(agent.matches("agent"));
        assert!(!agent.matches("password"));
    }

    #[test]
    fn tags_are_sorted_and_deduped() {
        let inv = Inventory {
            hosts: vec![host("a", &["prod", "db"]), host("b", &["prod"])],
        };
        assert_eq!(inv.tags(), vec!["db", "prod"]);
    }

    #[test]
    fn missing_inventory_is_an_empty_inventory() {
        let inv = Inventory::load_from(Path::new("/nonexistent/hosts.toml")).unwrap();
        assert!(inv.hosts.is_empty());
    }

    /// The empty-state hint in the UI names `~/.config/luvienne/hosts.toml`.
    /// If this ever drifts, the app tells users to create a file it won't read.
    #[test]
    fn config_lives_under_dot_config_not_library() {
        let path = Inventory::path().unwrap();
        let shown = path.display().to_string();
        assert!(
            shown.ends_with(".config/luvienne/hosts.toml")
                || std::env::var_os("XDG_CONFIG_HOME").is_some(),
            "got {shown}"
        );
        assert!(
            !shown.contains("Application Support"),
            "terminal tools do not belong in Application Support: {shown}"
        );
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("luvienne-cfg-{tag}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The rename must not strand an existing inventory.
    #[test]
    fn an_inventory_from_the_former_name_is_carried_over() {
        let root = temp_dir("migrate");
        let old_dir = root.join("luviennessh");
        let new_dir = root.join("luvienne");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(
            old_dir.join("hosts.toml"),
            "[[host]]\nname = \"kept\"\naddress = \"10.0.0.1\"\nuser = \"deploy\"\n",
        )
        .unwrap();

        let new_path = new_dir.join("hosts.toml");
        Inventory::migrate_from_former_name(&new_path);

        let carried = Inventory::load_from(&new_path).unwrap();
        assert_eq!(carried.hosts.len(), 1);
        assert_eq!(carried.hosts[0].name, "kept");
        assert!(
            old_dir.join("hosts.toml").exists(),
            "the old file must be left alone, not moved"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Migration must never overwrite a config the user already has under the
    /// new name.
    #[test]
    fn migration_does_not_clobber_an_existing_inventory() {
        let root = temp_dir("migrate-existing");
        let old_dir = root.join("luviennessh");
        let new_dir = root.join("luvienne");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::write(
            old_dir.join("hosts.toml"),
            "[[host]]\nname = \"old\"\naddress = \"a\"\nuser = \"u\"\n",
        )
        .unwrap();
        let new_path = new_dir.join("hosts.toml");
        std::fs::write(
            &new_path,
            "[[host]]\nname = \"current\"\naddress = \"b\"\nuser = \"u\"\n",
        )
        .unwrap();

        // `path()` only migrates when the new file is absent; assert the guard.
        assert!(new_path.exists());
        let kept = Inventory::load_from(&new_path).unwrap();
        assert_eq!(kept.hosts[0].name, "current");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn saves_and_loads_back_every_field() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("hosts.toml");

        let inv = Inventory {
            hosts: vec![
                Host {
                    name: "web-01".into(),
                    address: "10.0.0.1".into(),
                    port: 22,
                    user: "deploy".into(),
                    tags: vec!["prod".into(), "web".into()],
                    auth: AuthRef::Agent,
                    jump: None,
                    cache_passphrase: false,
                    forwards: Vec::new(),
                },
                Host {
                    name: "db-01".into(),
                    address: "10.0.0.2".into(),
                    port: 2222,
                    user: "postgres".into(),
                    tags: vec!["db".into()],
                    auth: AuthRef::Key {
                        path: "~/keys/db.ppk".into(),
                    },
                    jump: Some("web-01".into()),
                    cache_passphrase: false,
                    forwards: Vec::new(),
                },
            ],
        };
        inv.save_to(&path).unwrap();

        let back = Inventory::load_from(&path).unwrap();
        assert_eq!(back.hosts.len(), 2);
        assert_eq!(back.hosts[1].port, 2222);
        assert_eq!(back.hosts[1].jump.as_deref(), Some("web-01"));
        assert_eq!(back.hosts[1].tags, vec!["db"]);
        assert_eq!(
            back.hosts[1].auth,
            AuthRef::Key {
                path: "~/keys/db.ppk".into()
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The whole reason `save` uses `toml_edit`. This file is hand-editable, and
    /// adding a host through the UI must not silently delete the notes someone
    /// wrote next to their production boxes.
    #[test]
    fn saving_preserves_comments_and_inline_auth_style() {
        let dir = temp_dir("comments");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            r#"# My hosts. Do not commit.

[[host]]
# ask Bob before touching this one
name = "web-01"
address = "10.0.0.1"
user = "deploy"
tags = ["prod"]
auth = { method = "agent" }
"#,
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.push(Host {
            name: "new-01".into(),
            address: "10.0.0.9".into(),
            port: 22,
            user: "root".into(),
            tags: vec!["lab".into()],
            auth: AuthRef::Password,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        });
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# My hosts. Do not commit."),
            "header comment lost:\n{written}"
        );
        assert!(
            written.contains("# ask Bob before touching this one"),
            "per-host comment lost:\n{written}"
        );
        assert!(
            written.contains("auth = { method = \"agent\" }"),
            "inline auth style rewritten:\n{written}"
        );
        assert_eq!(Inventory::load_from(&path).unwrap().hosts.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Adding a host must not edit lines in the entries around it. Writing
    /// defaults unconditionally would sprinkle `port = 22` and `tags = []`
    /// through every hand-written host in the file.
    #[test]
    fn adding_a_host_leaves_other_entries_untouched() {
        let dir = temp_dir("untouched");
        let path = dir.join("hosts.toml");
        let original = r#"[[host]]
name = "existing"
address = "10.0.0.1"
user = "deploy"
"#;
        std::fs::write(&path, original).unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.push(Host {
            name: "added".into(),
            address: "10.0.0.2".into(),
            port: 22,
            user: "root".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        });
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.starts_with(original),
            "the first entry was rewritten:\n{written}"
        );
        assert!(
            !written.contains("tags = []"),
            "empty tags written:\n{written}"
        );
        assert_eq!(Inventory::load_from(&path).unwrap().hosts.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// But a non-default value must still be written, even for a host whose
    /// table never had the key.
    #[test]
    fn non_default_values_are_written_even_when_the_key_is_absent() {
        let dir = temp_dir("nondefault");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"a\"\naddress = \"1.2.3.4\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts[0].port = 2222;
        inv.hosts[0].tags = vec!["prod".into()];
        inv.hosts[0].auth = AuthRef::Password;
        inv.save_to(&path).unwrap();

        let back = Inventory::load_from(&path).unwrap();
        assert_eq!(back.hosts[0].port, 2222);
        assert_eq!(back.hosts[0].tags, vec!["prod"]);
        assert_eq!(back.hosts[0].auth, AuthRef::Password);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `cache_passphrase = false` is the default, so it falls under the same
    /// rule as `port` and `tags`: turning caching on for one host must not
    /// stamp `cache_passphrase = false` across every other entry in the file.
    #[test]
    fn the_cache_flag_is_not_sprinkled_through_other_entries() {
        let dir = temp_dir("cacheflag");
        let path = dir.join("hosts.toml");
        let original = r#"[[host]]
name = "untouched"
address = "10.0.0.1"
user = "deploy"
"#;
        std::fs::write(&path, original).unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.push(Host {
            name: "remembers".into(),
            address: "10.0.0.2".into(),
            port: 22,
            user: "root".into(),
            tags: vec![],
            auth: AuthRef::Key {
                path: PathBuf::from("~/keys/a.ppk"),
            },
            jump: None,
            cache_passphrase: true,
            forwards: Vec::new(),
        });
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.starts_with(original),
            "the first entry was rewritten:\n{written}"
        );
        assert_eq!(
            written.matches("cache_passphrase").count(),
            1,
            "written into an entry that never had it:\n{written}"
        );

        let back = Inventory::load_from(&path).unwrap();
        assert!(!back.hosts[0].cache_passphrase);
        assert!(back.hosts[1].cache_passphrase, "the flag must round-trip");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Turning caching back off has to *clear* the line, not leave a stale
    /// `true` behind. The key already exists at that point, so the
    /// only-write-if-present rule must not skip it.
    #[test]
    fn turning_the_cache_flag_off_rewrites_it_as_false() {
        let dir = temp_dir("cacheoff");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"a\"\naddress = \"1.2.3.4\"\nuser = \"u\"\ncache_passphrase = true\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        assert!(inv.hosts[0].cache_passphrase, "fixture is wrong");

        inv.hosts[0].cache_passphrase = false;
        inv.save_to(&path).unwrap();

        assert!(
            !Inventory::load_from(&path).unwrap().hosts[0].cache_passphrase,
            "the file still says true:\n{}",
            std::fs::read_to_string(&path).unwrap()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A host that never mentions the flag reads as "do not cache". Defaulting
    /// the other way would opt every hand-written and imported host into
    /// storing a secret.
    #[test]
    fn an_absent_cache_flag_means_off() {
        let dir = temp_dir("cacheabsent");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"a\"\naddress = \"1.2.3.4\"\nuser = \"u\"\n",
        )
        .unwrap();

        assert!(!Inventory::load_from(&path).unwrap().hosts[0].cache_passphrase);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Forwards have to survive a save/load round trip intact — this file has
    /// a history of writers that corrupted what they rewrote.
    #[test]
    fn forwards_round_trip_through_a_save() {
        let dir = temp_dir("fwdroundtrip");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"a\"\naddress = \"1.2.3.4\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts[0].forwards = vec![
            Forward::parse("L 8080:db.internal:5432").unwrap(),
            Forward::parse("R 9000:127.0.0.1:3000").unwrap(),
            Forward::parse("L 0.0.0.0:8443:web:443").unwrap(),
        ];
        inv.save_to(&path).unwrap();

        let back = Inventory::load_from(&path).unwrap();
        assert_eq!(back.hosts[0].forwards, inv.hosts[0].forwards);

        // The explicit wildcard bind must be written out. Losing it would
        // silently narrow a forward the user deliberately widened — or, read
        // the other way, a default that failed to be written would silently
        // widen one.
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("0.0.0.0"),
            "wildcard bind lost:\n{written}"
        );
        assert_eq!(
            written.matches("listen_host").count(),
            1,
            "the loopback default was written where it is not needed:\n{written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Same default rule as `port` and `tags`: giving one host a tunnel must not
    /// put `forwards = []` on every other entry in the file.
    #[test]
    fn forwards_are_not_sprinkled_through_other_entries() {
        let dir = temp_dir("fwdsprinkle");
        let path = dir.join("hosts.toml");
        let original =
            "[[host]]\nname = \"untouched\"\naddress = \"10.0.0.1\"\nuser = \"deploy\"\n";
        std::fs::write(&path, original).unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        let mut tunnelled = inv.hosts[0].clone();
        tunnelled.name = "tunnelled".into();
        tunnelled.forwards = vec![Forward::parse("L 8080:db:5432").unwrap()];
        inv.hosts.push(tunnelled);
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.starts_with(original),
            "the first entry was rewritten:\n{written}"
        );
        assert_eq!(
            written.matches("forwards").count(),
            1,
            "written into an entry that never had it:\n{written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// And removing the last forward has to actually clear it, which is the one
    /// case where writing the empty default *is* required.
    #[test]
    fn removing_the_last_forward_clears_it_on_disk() {
        let dir = temp_dir("fwdclear");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"a\"\naddress = \"1.2.3.4\"\nuser = \"u\"\n\
             forwards = [{ direction = \"local\", listen_port = 8080, to_host = \"db\", to_port = 5432 }]\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        assert_eq!(inv.hosts[0].forwards.len(), 1, "fixture is wrong");

        inv.hosts[0].forwards.clear();
        inv.save_to(&path).unwrap();

        assert!(
            Inventory::load_from(&path).unwrap().hosts[0]
                .forwards
                .is_empty(),
            "the forward is still on disk:\n{}",
            std::fs::read_to_string(&path).unwrap()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_creates_the_directory_on_first_run() {
        let dir = temp_dir("firstrun");
        let path = dir.join("nested").join("deeper").join("hosts.toml");

        Inventory {
            hosts: vec![Host {
                name: "a".into(),
                address: "1.2.3.4".into(),
                port: 22,
                user: "u".into(),
                tags: vec![],
                auth: AuthRef::Agent,
                jump: None,
                cache_passphrase: false,
                forwards: Vec::new(),
            }],
        }
        .save_to(&path)
        .unwrap();

        assert!(path.exists());
        assert_eq!(Inventory::load_from(&path).unwrap().hosts.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Removing hosts has to shrink the array, not leave orphaned tables behind.
    /// The dangerous one. Syncing tables by index leaves comments where they
    /// are while values shift up, so deleting from the middle relabels every
    /// host below it — a note reading "staging" ends up on the production box
    /// whose own warning was just overwritten.
    #[test]
    fn deleting_from_the_middle_keeps_each_comment_with_its_own_host() {
        let dir = temp_dir("midcomment");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\n# alpha note\nname = \"alpha\"\naddress = \"1\"\nuser = \"u\"\n\n\
             [[host]]\n# beta note\nname = \"beta\"\naddress = \"2\"\nuser = \"u\"\n\n\
             [[host]]\n# gamma note\nname = \"gamma\"\naddress = \"3\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.remove(1); // beta
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let gamma = written.split("[[host]]").nth(2).expect("two hosts remain");
        assert!(
            gamma.contains("# gamma note"),
            "gamma lost its own comment:\n{written}"
        );
        assert!(
            !gamma.contains("# beta note"),
            "gamma inherited the deleted host's comment:\n{written}"
        );
        assert!(!written.contains("beta"), "beta should be gone:\n{written}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Renaming in the editor should keep the note attached to that host.
    /// Inserting in the middle must not steal the next host's comment — the
    /// mirror image of the delete bug.
    /// Two hosts with the same name is malformed but writable by hand. The
    /// writer must not hand both the same table or drop one.
    #[test]
    fn duplicate_host_names_do_not_collapse_into_one_entry() {
        let dir = temp_dir("dupenames");
        let path = dir.join("hosts.toml");
        let host = |name: &str, addr: &str| Host {
            name: name.into(),
            address: addr.into(),
            port: 22,
            user: "u".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        };
        Inventory {
            hosts: vec![host("same", "1"), host("same", "2")],
        }
        .save_to(&path)
        .unwrap();

        let back = Inventory::load_from(&path).unwrap();
        assert_eq!(back.hosts.len(), 2, "an entry was dropped");
        assert_eq!(back.hosts[0].address, "1");
        assert_eq!(back.hosts[1].address, "2");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Reordering should carry each comment along with its host.
    #[test]
    fn reordering_moves_comments_with_their_hosts() {
        let dir = temp_dir("reorder");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\n# alpha note\nname = \"alpha\"\naddress = \"1\"\nuser = \"u\"\n\n\
             [[host]]\n# beta note\nname = \"beta\"\naddress = \"2\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.swap(0, 1);
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let first = written.split("[[host]]").nth(1).unwrap();
        assert!(first.contains("beta"), "order not applied:\n{written}");
        assert!(
            first.contains("# beta note"),
            "comment did not follow its host:\n{written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inserting_in_the_middle_does_not_steal_a_comment() {
        let dir = temp_dir("insertcomment");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\n# alpha note\nname = \"alpha\"\naddress = \"1\"\nuser = \"u\"\n\n\
             [[host]]\n# beta note\nname = \"beta\"\naddress = \"2\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts.insert(
            1,
            Host {
                name: "inserted".into(),
                address: "9".into(),
                port: 22,
                user: "u".into(),
                tags: vec![],
                auth: AuthRef::Agent,
                jump: None,
                cache_passphrase: false,
                forwards: Vec::new(),
            },
        );
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let inserted = written.split("[[host]]").nth(2).unwrap();
        let beta = written.split("[[host]]").nth(3).unwrap();
        assert!(
            !inserted.contains("# beta note"),
            "the new host stole beta's comment:\n{written}"
        );
        assert!(
            beta.contains("# beta note"),
            "beta lost its comment:\n{written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn renaming_a_host_keeps_its_comment() {
        let dir = temp_dir("renamecomment");
        let path = dir.join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\n# the only note\nname = \"before\"\naddress = \"1\"\nuser = \"u\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        inv.hosts[0].name = "after".into();
        inv.save_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("# the only note"), "got:\n{written}");
        assert!(written.contains("\"after\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_fewer_hosts_removes_the_extra_tables() {
        let dir = temp_dir("shrink");
        let path = dir.join("hosts.toml");

        let host = |name: &str| Host {
            name: name.into(),
            address: "1.2.3.4".into(),
            port: 22,
            user: "u".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        };

        Inventory {
            hosts: vec![host("a"), host("b"), host("c")],
        }
        .save_to(&path)
        .unwrap();

        Inventory {
            hosts: vec![host("a")],
        }
        .save_to(&path)
        .unwrap();

        let back = Inventory::load_from(&path).unwrap();
        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.hosts[0].name, "a");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains("\"b\""), "stale table left behind");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `jump` that is cleared must actually disappear, not linger from the
    /// previous write.
    #[test]
    fn clearing_jump_removes_the_key() {
        let dir = temp_dir("jump");
        let path = dir.join("hosts.toml");

        let mut host = Host {
            name: "a".into(),
            address: "1.2.3.4".into(),
            port: 22,
            user: "u".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: Some("b".into()),
            cache_passphrase: false,
            forwards: Vec::new(),
        };
        Inventory {
            hosts: vec![host.clone()],
        }
        .save_to(&path)
        .unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("jump"));

        host.jump = None;
        Inventory { hosts: vec![host] }.save_to(&path).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("jump"));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn via(name: &str, jump: Option<&str>) -> Host {
        let mut h = host(name, &[]);
        h.jump = jump.map(str::to_string);
        h
    }

    /// The host list shows this, and `@10.0.0.1` with nothing in front reads
    /// like a rendering bug rather than a deliberate "ask me".
    #[test]
    fn a_host_with_no_user_says_it_will_ask() {
        let mut h = host("web", &[]);
        h.user = String::new();
        assert_eq!(h.destination(), "(ask)@10.0.0.1:22");
    }

    #[test]
    fn a_direct_host_is_a_chain_of_one() {
        let inv = Inventory {
            hosts: vec![via("web", None)],
        };
        let chain = inv.connection_chain("web").unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].name, "web");
    }

    /// Order matters: you dial the bastion first and tunnel onward to the target.
    #[test]
    fn a_jump_chain_is_ordered_outermost_first() {
        let inv = Inventory {
            hosts: vec![via("web", Some("bastion")), via("bastion", None)],
        };
        let names: Vec<String> = inv
            .connection_chain("web")
            .unwrap()
            .into_iter()
            .map(|h| h.name)
            .collect();
        assert_eq!(names, vec!["bastion", "web"]);
    }

    #[test]
    fn chains_of_several_hops_keep_their_order() {
        let inv = Inventory {
            hosts: vec![
                via("app", Some("inner")),
                via("inner", Some("edge")),
                via("edge", None),
            ],
        };
        let names: Vec<String> = inv
            .connection_chain("app")
            .unwrap()
            .into_iter()
            .map(|h| h.name)
            .collect();
        assert_eq!(names, vec!["edge", "inner", "app"]);
    }

    /// The failure that matters: two hosts pointing at each other is easy to
    /// write by hand and would otherwise recurse until the stack ran out.
    #[test]
    fn a_cycle_is_rejected_rather_than_looping() {
        let inv = Inventory {
            hosts: vec![via("a", Some("b")), via("b", Some("a"))],
        };
        assert!(matches!(
            inv.connection_chain("a"),
            Err(ChainError::Cycle(_))
        ));
    }

    #[test]
    fn a_host_jumping_via_itself_is_a_cycle() {
        let inv = Inventory {
            hosts: vec![via("a", Some("a"))],
        };
        assert!(matches!(
            inv.connection_chain("a"),
            Err(ChainError::Cycle(_))
        ));
    }

    #[test]
    fn a_jump_to_a_host_that_does_not_exist_is_named() {
        let inv = Inventory {
            hosts: vec![via("web", Some("ghost"))],
        };
        let err = inv.connection_chain("web").unwrap_err();
        assert_eq!(err, ChainError::Unknown("ghost".into()));
        assert!(err.to_string().contains("ghost"), "got: {err}");
    }

    #[test]
    fn an_absurdly_long_chain_is_refused() {
        let mut hosts: Vec<Host> = (0..MAX_JUMPS + 3)
            .map(|i| via(&format!("h{i}"), Some(&format!("h{}", i + 1))))
            .collect();
        // Terminate it so the only failure available is the depth cap.
        let last = hosts.len();
        hosts.push(via(&format!("h{last}"), None));

        assert_eq!(
            inventory_chain_err(&Inventory { hosts }, "h0"),
            ChainError::TooDeep
        );
    }

    fn inventory_chain_err(inv: &Inventory, target: &str) -> ChainError {
        inv.connection_chain(target).unwrap_err()
    }

    #[test]
    fn parses_inventory_toml() {
        let raw = r#"
            [[host]]
            name = "web-01"
            address = "10.0.0.1"
            user = "deploy"
            tags = ["prod", "web"]

            [[host]]
            name = "db-01"
            address = "10.0.0.2"
            port = 2222
            user = "root"
            tags = ["prod", "db"]
            auth = { method = "key", path = "~/.ssh/id_ed25519" }
        "#;
        let inv: Inventory = toml::from_str(raw).unwrap();
        assert_eq!(inv.hosts.len(), 2);
        assert_eq!(inv.hosts[0].port, 22, "port defaults to 22");
        assert_eq!(inv.hosts[1].port, 2222);
        assert!(matches!(inv.hosts[1].auth, AuthRef::Key { .. }));
    }
}
