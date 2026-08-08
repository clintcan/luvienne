//! The add/edit host form.
//!
//! Deliberately dumb: a list of text buffers plus a cursor. It knows how to
//! parse itself into a [`Host`] and how to explain why it can't. It performs no
//! I/O and holds no secrets — the key *path* is a field here, the key is not.

use std::path::PathBuf;

use crate::config::{AuthRef, Forward, Host};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Name,
    Address,
    Port,
    User,
    Tags,
    Auth,
    KeyPath,
    CachePassphrase,
    Jump,
    Forwards,
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Address => "address",
            Self::Port => "port",
            Self::User => "user",
            Self::Tags => "categories",
            Self::Auth => "auth",
            Self::KeyPath => "key path",
            // Ten characters is the width of the form's label column, and a
            // longer one pushes that single row out of line with the rest.
            Self::CachePassphrase => "remember",
            Self::Jump => "via",
            Self::Forwards => "forward",
        }
    }

    /// Shown dimmed when the field is empty.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Name => "what to call it",
            Self::Address => "hostname or IP",
            Self::Port => "22",
            Self::User => "leave empty to be asked on connect",
            Self::Tags => "comma separated, e.g. prod, db",
            Self::Auth => "←/→ or space to change",
            Self::KeyPath => "any path — ^O to browse",
            Self::CachePassphrase => "keep the passphrase in the macOS Keychain",
            Self::Jump => "name of a host to tunnel through",
            Self::Forwards => "e.g. L 8080:db:5432, R 9000:localhost:3000",
        }
    }

    /// Fields that cycle through fixed choices rather than accepting text.
    pub fn is_choice(self) -> bool {
        matches!(self, Self::Auth | Self::CachePassphrase)
    }
}

/// Auth choices in the order the selector cycles them.
const AUTH_CHOICES: [&str; 3] = ["agent", "key", "password"];

/// The remember-passphrase choices. "no" is first so it is what a new host gets.
const CACHE_CHOICES: [&str; 2] = ["no", "yes"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    /// Creating a host; on save it is appended.
    Add,
    /// Editing the host at this index in the inventory.
    Edit(usize),
    /// Editing every one of these inventory indices at once.
    ///
    /// Only fields the user actually touches are applied, so a bulk edit can
    /// change one field across 60 hosts without flattening the rest — and can
    /// deliberately *clear* a field, which a "non-empty means apply" rule could
    /// not express.
    Bulk(Vec<usize>),
}

#[derive(Debug, Clone)]
pub struct HostForm {
    pub mode: FormMode,
    /// Caret position in the focused field, in characters. See [`Self::cursor`].
    cursor: usize,
    pub name: String,
    pub address: String,
    pub port: String,
    pub user: String,
    pub tags: String,
    pub auth_choice: usize,
    pub key_path: String,
    /// Index into [`CACHE_CHOICES`]: whether to keep the key passphrase in the
    /// Keychain.
    pub cache_choice: usize,
    /// Name of another host to tunnel through. Empty means a direct connection.
    pub jump: String,
    /// Port forwards in the terse `L 8080:db:5432` form, comma separated.
    pub forwards: String,
    /// Private: moving focus has to take the caret with it, so it goes through
    /// [`Self::focus_on`] or the next/prev helpers. Setting it directly left the
    /// cursor pointing into the field you just left.
    focus: usize,
    /// Set when a save attempt failed validation.
    pub error: Option<String>,
    /// Fields the user has edited. Only meaningful for a bulk edit.
    touched: std::collections::HashSet<Field>,
}

impl HostForm {
    pub fn add() -> Self {
        Self {
            mode: FormMode::Add,
            // The first field starts empty, so the caret starts at its start.
            cursor: 0,
            name: String::new(),
            address: String::new(),
            // Prefilled because it is almost always right, and an empty port
            // field invites a validation error on the most common path.
            port: "22".into(),
            user: String::new(),
            tags: String::new(),
            auth_choice: 0,
            key_path: String::new(),
            // Caching is opt-in: a new host never starts out storing a secret.
            cache_choice: 0,
            jump: String::new(),
            forwards: String::new(),
            focus: 0,
            error: None,
            touched: std::collections::HashSet::new(),
        }
    }

    /// A form that edits many hosts at once.
    ///
    /// Name and address are deliberately absent: they identify a host, and
    /// setting sixty hosts to one name or address is never what anyone means.
    pub fn bulk(targets: Vec<usize>) -> Self {
        Self {
            mode: FormMode::Bulk(targets),
            port: String::new(),
            ..Self::add()
        }
    }

    pub fn edit(index: usize, host: &Host) -> Self {
        let (auth_choice, key_path) = match &host.auth {
            AuthRef::Agent => (0, String::new()),
            AuthRef::Key { path } => (1, path.display().to_string()),
            AuthRef::Password => (2, String::new()),
        };
        Self {
            mode: FormMode::Edit(index),
            // End of the name, which is the focused field — editing usually
            // means appending, and Home is one key away.
            cursor: host.name.chars().count(),
            name: host.name.clone(),
            address: host.address.clone(),
            port: host.port.to_string(),
            user: host.user.clone(),
            tags: host.tags.join(", "),
            auth_choice,
            key_path,
            cache_choice: usize::from(host.cache_passphrase),
            jump: host.jump.clone().unwrap_or_default(),
            forwards: Forward::render_list(&host.forwards),
            focus: 0,
            error: None,
            touched: std::collections::HashSet::new(),
        }
    }

    pub fn is_bulk(&self) -> bool {
        matches!(self.mode, FormMode::Bulk(_))
    }

    /// Visible fields. The key path only exists when the key method is selected,
    /// so an agent host is never asked for a path it will not use.
    pub fn fields(&self) -> Vec<Field> {
        let mut fields = if self.is_bulk() {
            vec![Field::Port, Field::User, Field::Tags, Field::Auth]
        } else {
            vec![
                Field::Name,
                Field::Address,
                Field::Port,
                Field::User,
                Field::Tags,
                Field::Auth,
            ]
        };
        // A path only exists for key auth: an agent host is never asked for one
        // it will not use.
        if self.auth_choice == 1 {
            fields.push(Field::KeyPath);
        }
        // The toggle follows the same rule when the form describes one host —
        // but a bulk edit does not know its targets' auth, and they may already
        // be key hosts with paths of their own. Hiding it behind `auth = key`
        // there would mean the only way to reach it is to cycle the method,
        // which stamps a single key path across every selected host. `apply_to`
        // gates on what the host actually ends up with.
        // And not at all where there is no keychain to put anything in: a
        // toggle that could only ever fail is worse than an absent feature.
        if (self.auth_choice == 1 || self.is_bulk()) && crate::keystore::is_supported() {
            fields.push(Field::CachePassphrase);
        }
        fields.push(Field::Jump);
        fields.push(Field::Forwards);
        fields
    }

    pub fn focused(&self) -> Field {
        let fields = self.fields();
        fields[self.focus.min(fields.len() - 1)]
    }

    pub fn value(&self, field: Field) -> &str {
        match field {
            Field::Name => &self.name,
            Field::Address => &self.address,
            Field::Port => &self.port,
            Field::User => &self.user,
            Field::Tags => &self.tags,
            Field::Auth => AUTH_CHOICES[self.auth_choice],
            Field::KeyPath => &self.key_path,
            Field::CachePassphrase => CACHE_CHOICES[self.cache_choice],
            Field::Jump => &self.jump,
            Field::Forwards => &self.forwards,
        }
    }

    fn value_mut(&mut self, field: Field) -> Option<&mut String> {
        match field {
            Field::Name => Some(&mut self.name),
            Field::Address => Some(&mut self.address),
            Field::Port => Some(&mut self.port),
            Field::User => Some(&mut self.user),
            Field::Tags => Some(&mut self.tags),
            Field::KeyPath => Some(&mut self.key_path),
            Field::Jump => Some(&mut self.jump),
            Field::Forwards => Some(&mut self.forwards),
            Field::Auth | Field::CachePassphrase => None,
        }
    }

    /// Which field has focus, as an index into [`Self::fields`].
    pub fn focus(&self) -> usize {
        self.focus
    }

    /// Move focus to a named field, taking the caret with it.
    ///
    /// Tests only: the app moves focus with tab and the arrow keys, which go
    /// through `next_field`/`prev_field`.
    #[cfg(test)]
    pub fn focus_on(&mut self, field: Field) {
        if let Some(index) = self.fields().iter().position(|f| *f == field) {
            self.focus = index;
            self.cursor_to_end();
        }
    }

    pub fn next_field(&mut self) {
        self.focus = (self.focus + 1) % self.fields().len();
        self.cursor_to_end();
    }

    pub fn prev_field(&mut self) {
        let len = self.fields().len();
        self.focus = (self.focus + len - 1) % len;
        self.cursor_to_end();
    }

    /// Where the caret sits in the focused field, counted in characters.
    ///
    /// One cursor rather than one per field: only the focused field can be
    /// edited, and arriving at a field puts the caret at its end — which is
    /// where you want it when tabbing through a form you are filling in.
    pub fn cursor(&self) -> usize {
        self.cursor.min(self.focused_len())
    }

    fn focused_len(&self) -> usize {
        self.value(self.focused()).chars().count()
    }

    pub fn cursor_to_end(&mut self) {
        self.cursor = self.focused_len();
    }

    pub fn cursor_left(&mut self) {
        self.cursor = self.cursor().saturating_sub(1);
    }

    pub fn cursor_right(&mut self) {
        self.cursor = (self.cursor() + 1).min(self.focused_len());
    }

    pub fn cursor_home(&mut self) {
        self.cursor = 0;
    }

    /// Byte offset of a character index, for `String` operations.
    fn byte_at(text: &str, chars: usize) -> usize {
        text.char_indices()
            .nth(chars)
            .map_or(text.len(), |(byte, _)| byte)
    }

    /// Delete the character *at* the cursor, leaving the cursor where it is.
    pub fn delete(&mut self) {
        let field = self.focused();
        let at = self.cursor();
        self.touched.insert(field);
        if let Some(buffer) = self.value_mut(field) {
            let byte = Self::byte_at(buffer, at);
            if byte < buffer.len() {
                buffer.remove(byte);
            }
        }
    }

    /// Advance whichever choice field has focus. Text fields ignore this.
    pub fn cycle_choice(&mut self, forward: bool) {
        match self.focused() {
            Field::Auth => self.cycle_auth(forward),
            // Two choices, so `forward` cannot distinguish anything here.
            Field::CachePassphrase => {
                self.touched.insert(Field::CachePassphrase);
                self.cache_choice = (self.cache_choice + 1) % CACHE_CHOICES.len();
            }
            _ => {}
        }
    }

    pub fn cycle_auth(&mut self, forward: bool) {
        self.touched.insert(Field::Auth);
        let len = AUTH_CHOICES.len();
        self.auth_choice = if forward {
            (self.auth_choice + 1) % len
        } else {
            (self.auth_choice + len - 1) % len
        };
        // Dropping the key-path field can leave focus past the end.
        let max = self.fields().len() - 1;
        self.focus = self.focus.min(max);
    }

    pub fn push(&mut self, c: char) {
        let field = self.focused();
        // Digits only in the port field: a typo there is otherwise only caught
        // at save, several fields later.
        if field == Field::Port && !c.is_ascii_digit() {
            return;
        }
        let at = self.cursor();
        self.touched.insert(field);
        if let Some(buffer) = self.value_mut(field) {
            let byte = Self::byte_at(buffer, at);
            buffer.insert(byte, c);
        }
        self.cursor = at + 1;
    }

    pub fn backspace(&mut self) {
        let field = self.focused();
        let at = self.cursor();
        if at == 0 {
            return;
        }
        self.touched.insert(field);
        if let Some(buffer) = self.value_mut(field) {
            let byte = Self::byte_at(buffer, at - 1);
            buffer.remove(byte);
        }
        self.cursor = at - 1;
    }

    /// Apply only the touched fields to an existing host.
    ///
    /// Returns an error for the same reasons `to_host` would, but only about
    /// fields the user actually edited.
    pub fn apply_to(&self, host: &mut Host) -> Result<(), String> {
        if self.touched.contains(&Field::Port) {
            let text = self.port.trim();
            host.port = if text.is_empty() {
                22
            } else {
                text.parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| format!("port must be a number from 1 to 65535, not {text:?}"))?
            };
        }
        if self.touched.contains(&Field::User) {
            host.user = self.user.trim().to_string();
        }
        if self.touched.contains(&Field::Tags) {
            host.tags = self
                .tags
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
        }
        if self.touched.contains(&Field::Auth) || self.touched.contains(&Field::KeyPath) {
            host.auth = match self.auth_choice {
                1 => {
                    let path = self.key_path.trim();
                    if path.is_empty() {
                        return Err("key path is required for key auth".into());
                    }
                    AuthRef::Key {
                        path: PathBuf::from(path),
                    }
                }
                2 => AuthRef::Password,
                _ => AuthRef::Agent,
            };
            // Moving a host off key auth leaves nothing to cache. Without this
            // the flag survives on an agent host, where `cached_key_id` reads
            // `None` and the Keychain entry it used to name is never cleaned up.
            if self.auth_choice != 1 {
                host.cache_passphrase = false;
            }
        }
        if self.touched.contains(&Field::CachePassphrase) {
            // Gated on the host's own method, not the form's. In a bulk edit
            // that left auth alone, the form still reads "agent" while the
            // host is a key host — checking the form here would quietly refuse
            // every edit this field exists for. The auth branch above has
            // already run, so this sees whatever the host ends up with.
            host.cache_passphrase =
                self.cache_choice == 1 && matches!(host.auth, AuthRef::Key { .. });
        }
        if self.touched.contains(&Field::Jump) {
            host.jump = match self.jump.trim() {
                "" => None,
                name => Some(name.to_string()),
            };
        }
        if self.touched.contains(&Field::Forwards) {
            host.forwards = Forward::parse_list(&self.forwards).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Whether anything would change.
    pub fn touched_anything(&self) -> bool {
        !self.touched.is_empty()
    }

    /// Validate and build a [`Host`], or explain what is wrong.
    ///
    /// The message names one problem at a time and is written to be shown in a
    /// one-line status bar.
    pub fn to_host(&self) -> Result<Host, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("name is required".into());
        }
        let address = self.address.trim();
        if address.is_empty() {
            return Err("address is required".into());
        }
        // An empty user is legal and means "ask at connect", the way PuTTY
        // prompts `login as:` for a session that never stored one.
        let user = self.user.trim();

        let port_text = self.port.trim();
        let port: u16 = if port_text.is_empty() {
            22
        } else {
            port_text
                .parse()
                .map_err(|_| format!("port must be a number from 1 to 65535, not {port_text:?}"))?
        };
        if port == 0 {
            return Err("port must be from 1 to 65535".into());
        }

        let auth = match self.auth_choice {
            1 => {
                let path = self.key_path.trim();
                if path.is_empty() {
                    return Err("key path is required for key auth".into());
                }
                AuthRef::Key {
                    path: PathBuf::from(path),
                }
            }
            2 => AuthRef::Password,
            _ => AuthRef::Agent,
        };

        let tags = self
            .tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();

        Ok(Host {
            name: name.to_string(),
            address: address.to_string(),
            port,
            user: user.to_string(),
            tags,
            auth,
            jump: match self.jump.trim() {
                "" => None,
                name => Some(name.to_string()),
            },
            // Only key auth has a passphrase, so the flag is gated on the method
            // rather than on the choice field alone — the field is hidden for
            // the other methods and would otherwise keep a stale `yes`.
            cache_passphrase: self.auth_choice == 1 && self.cache_choice == 1,
            forwards: Forward::parse_list(&self.forwards).map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> HostForm {
        let mut form = HostForm::add();
        form.name = "web-01".into();
        form.address = "10.0.0.1".into();
        form.user = "deploy".into();
        form
    }

    #[test]
    fn builds_a_host_from_a_filled_form() {
        let mut form = filled();
        form.tags = "prod, web".into();
        let host = form.to_host().unwrap();

        assert_eq!(host.name, "web-01");
        assert_eq!(host.port, 22, "prefilled default");
        assert_eq!(host.tags, vec!["prod", "web"]);
        assert_eq!(host.auth, AuthRef::Agent);
    }

    #[test]
    fn tags_are_split_trimmed_and_emptied() {
        let mut form = filled();
        form.tags = "  prod ,, web ,  ".into();
        assert_eq!(form.to_host().unwrap().tags, vec!["prod", "web"]);
    }

    #[test]
    fn required_fields_are_named_individually() {
        let mut form = HostForm::add();
        assert!(form.to_host().unwrap_err().contains("name"));
        form.name = "a".into();
        assert!(form.to_host().unwrap_err().contains("address"));
    }

    /// Empty is legal and means "ask at connect" — the PuTTY import relies on
    /// it, and so does anyone with a host they log into as different users.
    #[test]
    fn an_empty_user_is_allowed_and_means_ask() {
        let mut form = HostForm::add();
        form.name = "a".into();
        form.address = "b".into();
        form.user.clear();
        assert_eq!(form.to_host().unwrap().user, "");
    }

    #[test]
    fn an_empty_port_falls_back_to_22() {
        let mut form = filled();
        form.port = String::new();
        assert_eq!(form.to_host().unwrap().port, 22);
    }

    /// Out-of-range is the interesting case: `u16::parse` rejects 70000, and the
    /// message has to say something better than "invalid digit".
    #[test]
    fn an_out_of_range_port_is_rejected_with_a_readable_message() {
        let mut form = filled();
        form.port = "70000".into();
        let err = form.to_host().unwrap_err();
        assert!(err.contains("1 to 65535"), "got: {err}");

        form.port = "0".into();
        assert!(form.to_host().unwrap_err().contains("1 to 65535"));
    }

    #[test]
    fn the_port_field_refuses_non_digits() {
        let mut form = filled();
        form.port.clear();
        form.focus_on(Field::Port);
        for c in "2x2!".chars() {
            form.push(c);
        }
        assert_eq!(form.port, "22", "letters and punctuation never land");
    }

    #[test]
    fn key_auth_requires_a_path() {
        let mut form = filled();
        form.auth_choice = 1;
        assert!(form.to_host().unwrap_err().contains("key path"));

        form.key_path = "~/.ssh/id_ed25519".into();
        assert!(matches!(form.to_host().unwrap().auth, AuthRef::Key { .. }));
    }

    /// The key-path field appears only for key auth, so cycling away from it
    /// while focused there must not leave focus dangling past the end.
    #[test]
    fn cycling_auth_keeps_focus_in_range() {
        let mut form = filled();
        form.auth_choice = 1;
        form.focus_on(Field::KeyPath);
        assert_eq!(form.focused(), Field::KeyPath);

        form.cycle_auth(true);
        assert!(form.focus() < form.fields().len());
        assert_ne!(form.focused(), Field::KeyPath);
        assert!(
            !form.fields().contains(&Field::KeyPath),
            "the path field should be gone with a non-key method"
        );
    }

    #[test]
    fn auth_cycles_both_ways_and_wraps() {
        let mut form = filled();
        assert_eq!(form.value(Field::Auth), "agent");
        form.cycle_auth(true);
        assert_eq!(form.value(Field::Auth), "key");
        form.cycle_auth(false);
        assert_eq!(form.value(Field::Auth), "agent");
        form.cycle_auth(false);
        assert_eq!(form.value(Field::Auth), "password", "wraps backwards");
    }

    /// Caching is opt-in, so the thing to pin is the *default*: a host created
    /// without anyone touching the field must not store a secret.
    #[test]
    fn a_new_host_does_not_remember_its_passphrase() {
        let mut form = filled();
        form.auth_choice = 1;
        form.key_path = "~/.ssh/id_ed25519".into();
        assert!(!form.to_host().unwrap().cache_passphrase);
    }

    /// There is no passphrase to remember for an agent or a password host, so
    /// the field must not be offered for them. This is the *single-host* rule —
    /// a bulk form cannot know its targets' methods and always offers it.
    // The field itself only exists where a keychain does; the rule it
    // encodes is macOS-only, not the test being flaky.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_remember_field_only_exists_for_key_auth() {
        let mut form = filled();
        for choice in [0, 2] {
            form.auth_choice = choice;
            assert!(
                !form.fields().contains(&Field::CachePassphrase),
                "offered for {:?}",
                form.value(Field::Auth)
            );
        }
        form.auth_choice = 1;
        assert!(form.fields().contains(&Field::CachePassphrase));
    }

    /// The inverse of the case above, and the one that actually bites: turn
    /// caching on for a key host, then move it to the agent. The field
    /// disappears, so nothing re-reads it — and a flag left set would name a
    /// Keychain entry that `cached_key_id` no longer reports, leaking it past
    /// every cleanup path.
    #[test]
    fn moving_off_key_auth_stops_remembering() {
        let mut form = filled();
        form.auth_choice = 1;
        form.key_path = "~/.ssh/id_ed25519".into();
        form.cache_choice = 1;
        assert!(form.to_host().unwrap().cache_passphrase, "set up wrong");

        form.auth_choice = 0;
        assert!(
            !form.to_host().unwrap().cache_passphrase,
            "an agent host cannot remember a passphrase it never has"
        );
    }

    /// Same rule on the partial-apply path a bulk edit uses. Switching sixty
    /// key hosts to the agent has to clear the flag on all sixty, not just stop
    /// showing it.
    #[test]
    fn a_bulk_switch_to_agent_stops_remembering() {
        let mut host = Host {
            name: "web-01".into(),
            address: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            tags: vec![],
            auth: AuthRef::Key {
                path: PathBuf::from("~/.ssh/id_ed25519"),
            },
            jump: None,
            cache_passphrase: true,
            forwards: Vec::new(),
        };

        let mut form = HostForm::bulk(vec![0]);
        form.focus_on(Field::Auth);
        form.cycle_auth(true); // key
        form.cycle_auth(true); // password
        form.apply_to(&mut host).unwrap();

        assert_eq!(host.auth, AuthRef::Password);
        assert!(!host.cache_passphrase);
    }

    /// A bulk edit must be able to turn caching *off* without touching anything
    /// else — the whole point of tracking touched fields.
    // The field itself only exists where a keychain does; the rule it
    // encodes is macOS-only, not the test being flaky.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_bulk_edit_can_turn_remembering_off_on_its_own() {
        let mut host = Host {
            name: "web-01".into(),
            address: "10.0.0.1".into(),
            port: 2222,
            user: "deploy".into(),
            tags: vec!["prod".into()],
            auth: AuthRef::Key {
                path: PathBuf::from("~/keys/a.ppk"),
            },
            jump: None,
            cache_passphrase: true,
            forwards: Vec::new(),
        };

        let mut form = HostForm::bulk(vec![0]);
        // Reach the field the way the user does: pick key auth, then walk to it.
        form.focus_on(Field::Auth);
        form.cycle_auth(true);
        form.key_path = "~/keys/a.ppk".into();
        form.focus_on(Field::CachePassphrase);
        form.cycle_choice(true); // no -> yes
        form.cycle_choice(true); // yes -> no
        form.apply_to(&mut host).unwrap();

        assert!(!host.cache_passphrase);
        assert_eq!(host.port, 2222, "untouched fields stay put");
        assert_eq!(host.tags, vec!["prod"]);
    }

    /// The reason bulk editing exists: turning caching on across the key hosts
    /// you already have. Their key paths all differ, so this has to work
    /// *without* touching the auth method — otherwise reaching the toggle means
    /// cycling auth to "key", which stamps one path onto every selected host.
    // The field itself only exists where a keychain does; the rule it
    // encodes is macOS-only, not the test being flaky.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_bulk_edit_can_turn_remembering_on_without_touching_the_key() {
        let original = AuthRef::Key {
            path: PathBuf::from("~/keys/its-own.ppk"),
        };
        let mut host = Host {
            name: "web-01".into(),
            address: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            tags: vec![],
            auth: original.clone(),
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        };

        let mut form = HostForm::bulk(vec![0]);
        form.focus = form
            .fields()
            .iter()
            .position(|f| *f == Field::CachePassphrase)
            .expect("a bulk edit cannot reach the toggle at all");
        form.cycle_choice(true);
        form.apply_to(&mut host).unwrap();

        assert!(host.cache_passphrase);
        assert_eq!(host.auth, original, "the key path must be left alone");
    }

    /// And the same edit applied to a host that is *not* on key auth leaves it
    /// off — there is no passphrase to remember, so a blanket "yes" across a
    /// mixed selection must not set a flag that names nothing.
    // The field itself only exists where a keychain does; the rule it
    // encodes is macOS-only, not the test being flaky.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_bulk_remember_does_nothing_to_an_agent_host() {
        let mut host = Host {
            name: "web-01".into(),
            address: "10.0.0.1".into(),
            port: 22,
            user: "deploy".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        };

        let mut form = HostForm::bulk(vec![0]);
        form.focus_on(Field::CachePassphrase);
        form.cycle_choice(true);
        form.apply_to(&mut host).unwrap();

        assert!(!host.cache_passphrase);
    }

    /// Two fields vanish when the method changes now, not one, so the focus
    /// clamp has further to fall.
    #[test]
    fn cycling_away_from_the_last_key_field_keeps_focus_in_range() {
        let mut form = filled();
        form.auth_choice = 1;
        // The last field, whichever it is — the key-only fields differ by
        // platform and this test is about the clamp, not about which ones.
        form.focus = form.fields().len() - 1;
        let widest = form.fields().len();

        form.cycle_auth(true);
        assert!(form.focus() < form.fields().len());
        assert!(
            form.fields().len() < widest,
            "cycling away from key auth should drop at least one field"
        );
    }

    /// The label column is ten characters wide; a longer one silently pushes
    /// that row out of line with every other field.
    #[test]
    fn no_field_label_overflows_the_label_column() {
        for field in [
            Field::Name,
            Field::Address,
            Field::Port,
            Field::User,
            Field::Tags,
            Field::Auth,
            Field::KeyPath,
            Field::CachePassphrase,
            Field::Jump,
        ] {
            assert!(
                field.label().chars().count() <= 10,
                "{:?} is {} characters",
                field,
                field.label().chars().count()
            );
        }
    }

    #[test]
    fn edit_prefills_every_field() {
        let host = Host {
            name: "db-01".into(),
            address: "10.0.0.2".into(),
            port: 2222,
            user: "postgres".into(),
            tags: vec!["prod".into(), "db".into()],
            auth: AuthRef::Key {
                path: PathBuf::from("~/keys/db.ppk"),
            },
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        };
        let form = HostForm::edit(3, &host);

        assert_eq!(form.mode, FormMode::Edit(3));
        assert_eq!(form.port, "2222");
        assert_eq!(form.tags, "prod, db");
        assert_eq!(form.value(Field::Auth), "key");
        assert_eq!(form.key_path, "~/keys/db.ppk");

        // Round-trips back to an equivalent host.
        let rebuilt = form.to_host().unwrap();
        assert_eq!(rebuilt.name, host.name);
        assert_eq!(rebuilt.port, host.port);
        assert_eq!(rebuilt.tags, host.tags);
        assert_eq!(rebuilt.auth, host.auth);
    }
}
