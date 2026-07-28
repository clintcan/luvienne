//! Importing hosts from `~/.ssh/config`.
//!
//! Read-only, always: this file belongs to `ssh`, and a connection manager that
//! rewrites it would be overstepping. We take a copy of what it describes and
//! leave the original alone.
//!
//! The format is not a key-value file. `Host` opens a block, options are
//! inherited from earlier blocks, patterns are matchers rather than names, and
//! the first value obtained for an option wins. What is imported is therefore a
//! deliberately conservative reading: concrete host aliases only, with the
//! options that map onto something this app can act on.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::{AuthRef, Direction, Forward, Host};
use crate::import::Imported;

pub const SOURCE: &str = "~/.ssh/config";
pub const IMPORT_TAG: &str = "ssh-config";

pub fn config_path() -> Option<PathBuf> {
    let path = directories::BaseDirs::new()?
        .home_dir()
        .join(".ssh")
        .join("config");
    path.is_file().then_some(path)
}

/// An alias that selects hosts rather than naming one.
///
/// `Host *` is the near-universal way to set global options, and importing it
/// would create a host called `*` that resolves to nothing.
fn is_pattern(alias: &str) -> bool {
    alias.contains(['*', '?', '!'])
}

/// Split `Key value` or `Key=value`, case-folding the keyword.
fn split_option(line: &str) -> Option<(String, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, rest) = match line.find(['=', ' ', '\t']) {
        Some(at) => (
            &line[..at],
            line[at + 1..].trim_start_matches(['=', ' ', '\t']),
        ),
        None => (line, ""),
    };
    // ssh allows quoting values that contain spaces; the quotes are syntax.
    let value = rest.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    Some((key.to_ascii_lowercase(), value))
}

#[derive(Default, Clone)]
struct Options {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    /// A `Port` line was present but unusable.
    port_rejected: bool,
    /// `LocalForward` / `RemoteForward`. A list option in ssh, not a scalar:
    /// every line accumulates, including ones inherited from `Host *`.
    forwards: Vec<Forward>,
    /// Forward lines we could not read — a unix-socket forward, say.
    forwards_rejected: usize,
    /// `DynamicForward` lines. SOCKS is a different feature, not a tunnel we
    /// can express, so these are counted and reported rather than dropped.
    dynamic_forwards: usize,
}

impl Options {
    /// ssh takes the *first* value obtained for an option, so an inherited
    /// value never overwrites one already set on the block itself.
    fn fill_from(&mut self, other: &Options) {
        self.hostname = self.hostname.take().or_else(|| other.hostname.clone());
        self.user = self.user.take().or_else(|| other.user.clone());
        self.port = self.port.or(other.port);
        self.identity_file = self
            .identity_file
            .take()
            .or_else(|| other.identity_file.clone());
        self.proxy_jump = self.proxy_jump.take().or_else(|| other.proxy_jump.clone());
        self.port_rejected |= other.port_rejected;
        // Appended, not replaced: forwards accumulate in ssh rather than the
        // first one winning, so an inherited `LocalForward` applies *as well as*
        // the block's own.
        self.forwards.extend(other.forwards.iter().cloned());
        self.forwards_rejected += other.forwards_rejected;
        self.dynamic_forwards += other.dynamic_forwards;
    }

    fn apply(&mut self, key: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        match key {
            // First value wins, matching ssh.
            "hostname" if self.hostname.is_none() => self.hostname = Some(value.to_string()),
            "user" if self.user.is_none() => self.user = Some(value.to_string()),
            // A value out of range leaves this None and is counted by the
            // caller, rather than quietly becoming 22.
            "port" if self.port.is_none() => {
                self.port = value.parse().ok().filter(|p| *p > 0);
                self.port_rejected = self.port.is_none();
            }
            "identityfile" if self.identity_file.is_none() => {
                self.identity_file = Some(value.to_string());
            }
            "proxyjump" if self.proxy_jump.is_none() => {
                self.proxy_jump = Some(value.to_string());
            }
            "localforward" => match ssh_forward(Direction::Local, value) {
                Some(forward) => self.forwards.push(forward),
                None => self.forwards_rejected += 1,
            },
            "remoteforward" => match ssh_forward(Direction::Remote, value) {
                Some(forward) => self.forwards.push(forward),
                None => self.forwards_rejected += 1,
            },
            "dynamicforward" => self.dynamic_forwards += 1,
            _ => {}
        }
    }
}

/// Read an ssh config forward line into a [`Forward`].
///
/// The config file spells it `LocalForward 8080 db:5432` — two whitespace
/// separated fields — while the command line joins them with a colon. Both are
/// normalised into the colon form and handed to the parser we already have,
/// rather than growing a second implementation that could disagree with it
/// about ports or IPv6 brackets.
///
/// `None` for anything that will not fit: a unix-socket forward, or a line with
/// the wrong number of fields. The caller counts those and reports them.
fn ssh_forward(direction: Direction, value: &str) -> Option<Forward> {
    let letter = direction.letter();
    let joined = match value.split_whitespace().collect::<Vec<_>>().as_slice() {
        [listen, target] => format!("{letter} {listen}:{target}"),
        [single] => format!("{letter} {single}"),
        _ => return None,
    };
    Forward::parse(&joined).ok()
}

/// `user@host:port` or a bare alias — we only want the alias.
fn jump_alias(value: &str) -> Option<&str> {
    let alias = value.rsplit('@').next()?.split(':').next()?.trim();
    (!alias.is_empty() && !is_pattern(alias)).then_some(alias)
}

struct Parsed {
    hosts: Vec<Host>,
    patterns_skipped: usize,
    match_blocks_skipped: usize,
    includes_not_followed: usize,
    extra_aliases: usize,
    multi_hop_jumps: usize,
    bad_ports: usize,
    forwards_rejected: usize,
    dynamic_forwards: usize,
}

fn parse(text: &str) -> Parsed {
    let mut out = Parsed {
        hosts: Vec::new(),
        patterns_skipped: 0,
        match_blocks_skipped: 0,
        includes_not_followed: 0,
        extra_aliases: 0,
        multi_hop_jumps: 0,
        bad_ports: 0,
        forwards_rejected: 0,
        dynamic_forwards: 0,
    };

    // Options with no enclosing block, and those in a `Host *` block, apply to
    // everything. Options in a *narrower* pattern block (`Host prod-*`) apply
    // only to hosts matching it — which we cannot evaluate, so they are dropped
    // rather than leaked into unrelated hosts.
    let mut globals = Options::default();
    let mut collecting_globals = true;
    let mut current: Option<(String, Options)> = None;

    // Blocks are merged by alias before being turned into hosts: ssh allows the
    // same alias in several blocks and takes the first value obtained for each
    // option, rather than treating them as separate hosts.
    let mut blocks: Vec<(String, Options)> = Vec::new();

    fn close(current: Option<(String, Options)>, blocks: &mut Vec<(String, Options)>) {
        let Some((alias, options)) = current else {
            return;
        };
        match blocks.iter_mut().find(|(name, _)| *name == alias) {
            // Already seen: keep what it has, take only what it lacks.
            Some((_, existing)) => existing.fill_from(&options),
            None => blocks.push((alias, options)),
        }
    }

    for line in text.lines() {
        let Some((key, value)) = split_option(line) else {
            continue;
        };

        match key.as_str() {
            "host" => {
                close(current.take(), &mut blocks);

                let aliases: Vec<&str> = value.split_whitespace().collect();
                let concrete: Vec<&str> =
                    aliases.iter().copied().filter(|a| !is_pattern(a)).collect();
                out.patterns_skipped += aliases.len() - concrete.len();

                match concrete.first() {
                    Some(alias) => {
                        // The rest are alternative names for the same host.
                        out.extra_aliases += concrete.len() - 1;
                        current = Some(((*alias).to_string(), Options::default()));
                        collecting_globals = false;
                    }
                    None => {
                        // `Host *` is how global options are set; anything
                        // narrower selects hosts we cannot identify.
                        collecting_globals = aliases.contains(&"*");
                    }
                }
            }
            "match" => {
                close(current.take(), &mut blocks);
                current = None;
                // Conditional on runtime state we cannot evaluate.
                collecting_globals = false;
                out.match_blocks_skipped += 1;
            }
            "include" => out.includes_not_followed += 1,
            _ => match &mut current {
                Some((_, options)) => options.apply(&key, value),
                None if collecting_globals => globals.apply(&key, value),
                None => {}
            },
        }
    }
    close(current.take(), &mut blocks);

    for (alias, mut options) in blocks {
        // Globals are the lowest precedence, so they fill only what is missing.
        options.fill_from(&globals);

        let auth = match &options.identity_file {
            Some(path) => AuthRef::Key {
                path: PathBuf::from(path),
            },
            // No IdentityFile means ssh would try the agent and its defaults.
            None => AuthRef::Agent,
        };

        let jump = match options.proxy_jump.as_deref() {
            // A chain in one directive cannot be expressed as a single `jump`.
            Some(v) if v.contains(',') => {
                out.multi_hop_jumps += 1;
                None
            }
            Some(v) => jump_alias(v).map(str::to_string),
            None => None,
        };

        if options.port_rejected && options.port.is_none() {
            out.bad_ports += 1;
        }
        out.forwards_rejected += options.forwards_rejected;
        out.dynamic_forwards += options.dynamic_forwards;

        out.hosts.push(Host {
            // `HostName` is optional: without it ssh connects to the alias.
            address: options.hostname.unwrap_or_else(|| alias.clone()),
            name: alias,
            port: options.port.unwrap_or(22),
            // Empty means "ask", as with the PuTTY import.
            user: options.user.unwrap_or_default(),
            tags: vec![IMPORT_TAG.to_string()],
            auth,
            jump,
            // Opt-in only, and an import is not an opt-in. See the PuTTY one.
            cache_passphrase: false,
            forwards: options.forwards,
        });
    }

    out
}

/// Read `~/.ssh/config`, skipping hosts already in the inventory.
pub fn scan(path: &Path, existing: &[Host]) -> std::io::Result<Imported> {
    let text = std::fs::read_to_string(path)?;
    let parsed = parse(&text);

    let taken: HashSet<&str> = existing.iter().map(|h| h.name.as_str()).collect();
    let mut imported = Imported::new(SOURCE);

    // A jump target only means something if it will be resolvable.
    let known: HashSet<String> = parsed
        .hosts
        .iter()
        .map(|h| h.name.clone())
        .chain(existing.iter().map(|h| h.name.clone()))
        .collect();

    let mut dangling_jumps = 0;
    let mut asks_user = 0;

    for mut host in parsed.hosts {
        if taken.contains(host.name.as_str()) {
            imported.already_present += 1;
            continue;
        }
        if let Some(jump) = &host.jump
            && !known.contains(jump)
        {
            // Keeping it would make every connect fail on an unresolvable chain.
            host.jump = None;
            dangling_jumps += 1;
        }
        if host.user.is_empty() {
            asks_user += 1;
        }
        imported.hosts.push(host);
    }

    if asks_user > 0 {
        imported.notes.push(format!(
            "{asks_user} have no user — you will be asked on connect"
        ));
    }
    if parsed.includes_not_followed > 0 {
        imported.notes.push(format!(
            "{} Include directive(s) not followed",
            parsed.includes_not_followed
        ));
    }
    if parsed.match_blocks_skipped > 0 {
        imported.notes.push(format!(
            "{} Match block(s) skipped — conditional on runtime state",
            parsed.match_blocks_skipped
        ));
    }
    if parsed.patterns_skipped > 0 {
        imported.notes.push(format!(
            "{} wildcard pattern(s) skipped, not host names",
            parsed.patterns_skipped
        ));
    }
    if parsed.extra_aliases > 0 {
        imported.notes.push(format!(
            "{} extra alias(es) ignored — same host, other names",
            parsed.extra_aliases
        ));
    }
    if parsed.forwards_rejected > 0 {
        imported.notes.push(format!(
            "{} forward line(s) could not be read and were skipped",
            parsed.forwards_rejected
        ));
    }
    if parsed.dynamic_forwards > 0 {
        imported.notes.push(format!(
            "{} DynamicForward (SOCKS) line(s) skipped — not supported",
            parsed.dynamic_forwards
        ));
    }
    if parsed.bad_ports > 0 {
        imported.notes.push(format!(
            "{} unusable Port value(s) — defaulted to 22",
            parsed.bad_ports
        ));
    }
    if parsed.multi_hop_jumps > 0 {
        imported.notes.push(format!(
            "{} multi-hop ProxyJump(s) not imported",
            parsed.multi_hop_jumps
        ));
    }
    if dangling_jumps > 0 {
        imported.notes.push(format!(
            "{dangling_jumps} ProxyJump target(s) not in the config — imported without a jump"
        ));
    }

    Ok(imported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(text: &str) -> Vec<Host> {
        parse(text).hosts
    }

    #[test]
    fn reads_a_plain_block() {
        let h = &hosts("Host web\n  HostName 10.0.0.1\n  User deploy\n  Port 2222\n")[0];
        assert_eq!(h.name, "web");
        assert_eq!(h.address, "10.0.0.1");
        assert_eq!(h.user, "deploy");
        assert_eq!(h.port, 2222);
        assert_eq!(h.tags, vec![IMPORT_TAG]);
    }

    /// Without `HostName`, ssh connects to the alias itself.
    #[test]
    fn a_missing_hostname_falls_back_to_the_alias() {
        assert_eq!(
            hosts("Host example.com\n  User bob\n")[0].address,
            "example.com"
        );
    }

    #[test]
    fn keywords_are_case_insensitive_and_accept_equals() {
        let h = &hosts("HOST web\n  hostname=10.0.0.1\n  USER=bob\n")[0];
        assert_eq!(h.address, "10.0.0.1");
        assert_eq!(h.user, "bob");
    }

    /// `Host *` is how everyone sets global options; importing it would create
    /// a host named `*` that connects to nothing.
    #[test]
    fn wildcard_patterns_are_not_imported_as_hosts() {
        let parsed = parse("Host *\n  User bob\n\nHost web\n  HostName 10.0.0.1\n");
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].name, "web");
        assert_eq!(parsed.patterns_skipped, 1);
    }

    /// Options in a `Host *` block are inherited, so the user set there should
    /// reach the concrete hosts.
    /// `Host prod-*` applies only to hosts matching it. Its options must not
    /// leak into unrelated hosts declared later.
    #[test]
    fn options_in_a_narrow_pattern_block_do_not_leak() {
        let parsed =
            parse("Host prod-*\n  User deploy\n  Port 2200\n\nHost dev\n  HostName 10.0.0.9\n");
        let dev = parsed.hosts.iter().find(|h| h.name == "dev").unwrap();
        assert_ne!(dev.user, "deploy", "a narrow pattern's user leaked");
        assert_eq!(dev.port, 22, "a narrow pattern's port leaked");
    }

    /// `Host *` is the exception: it is how global options are set.
    #[test]
    fn options_in_a_star_block_are_inherited() {
        let parsed = parse("Host *\n  User everyone\n\nHost dev\n  HostName 10.0.0.9\n");
        assert_eq!(parsed.hosts[0].user, "everyone");
    }

    /// Two blocks with the same alias would produce two hosts of the same name,
    /// which makes resuming and jump resolution ambiguous.
    #[test]
    fn a_repeated_alias_yields_one_host() {
        let parsed = parse("Host web\n  HostName 10.0.0.1\n\nHost web\n  Port 2222\n");
        assert_eq!(parsed.hosts.len(), 1, "duplicate alias imported twice");
        assert_eq!(
            parsed.hosts[0].address, "10.0.0.1",
            "first value should win"
        );
    }

    #[test]
    fn options_set_before_any_host_are_inherited() {
        let parsed = parse("User globaluser\nPort 2200\n\nHost web\n  HostName 10.0.0.1\n");
        assert_eq!(parsed.hosts[0].user, "globaluser");
        assert_eq!(parsed.hosts[0].port, 2200);
    }

    /// ssh keeps the first value obtained, so a block's own setting wins over
    /// an inherited one.
    #[test]
    fn a_blocks_own_option_beats_the_inherited_one() {
        let parsed = parse("User globaluser\n\nHost web\n  HostName 10.0.0.1\n  User specific\n");
        assert_eq!(parsed.hosts[0].user, "specific");
    }

    #[test]
    fn identityfile_becomes_key_auth_and_its_absence_means_agent() {
        let with = &hosts("Host a\n  HostName 1\n  IdentityFile ~/.ssh/id_ed25519\n")[0];
        assert!(matches!(with.auth, AuthRef::Key { .. }));
        assert_eq!(hosts("Host b\n  HostName 2\n")[0].auth, AuthRef::Agent);
    }

    #[test]
    fn proxyjump_becomes_a_jump_host() {
        let parsed =
            parse("Host bastion\n  HostName 1\n\nHost web\n  HostName 2\n  ProxyJump bastion\n");
        let web = parsed.hosts.iter().find(|h| h.name == "web").unwrap();
        assert_eq!(web.jump.as_deref(), Some("bastion"));
    }

    #[test]
    fn a_proxyjump_with_user_and_port_keeps_only_the_alias() {
        let parsed = parse("Host web\n  HostName 2\n  ProxyJump bob@bastion:2222\n");
        assert_eq!(parsed.hosts[0].jump.as_deref(), Some("bastion"));
    }

    /// Our model chains through each host's own `jump`, so a comma-separated
    /// chain in one directive has nowhere to go.
    #[test]
    fn a_multi_hop_proxyjump_is_reported_rather_than_half_imported() {
        let parsed = parse("Host web\n  HostName 2\n  ProxyJump one,two\n");
        assert_eq!(parsed.hosts[0].jump, None);
        assert_eq!(parsed.multi_hop_jumps, 1);
    }

    /// `Match` is conditional on things like the local user or exit codes,
    /// none of which we can evaluate.
    #[test]
    fn match_blocks_are_skipped_entirely() {
        let parsed = parse(
            "Host web\n  HostName 1\n\nMatch host nas\n  User root\n  HostName 9\n\nHost db\n  HostName 2\n",
        );
        let names: Vec<&str> = parsed.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["web", "db"], "a Match block leaked in");
        assert_eq!(parsed.match_blocks_skipped, 1);
    }

    #[test]
    fn includes_are_counted_not_followed() {
        let parsed = parse("Include ~/.ssh/conf.d/*.conf\n\nHost web\n  HostName 1\n");
        assert_eq!(parsed.includes_not_followed, 1);
        assert_eq!(parsed.hosts.len(), 1);
    }

    #[test]
    fn extra_aliases_are_counted_not_duplicated() {
        let parsed = parse("Host web www web1\n  HostName 10.0.0.1\n");
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].name, "web");
        assert_eq!(parsed.extra_aliases, 2);
    }

    /// ssh allows quoting for values with spaces; the quotes are syntax, not
    /// part of the path.
    #[test]
    fn quoted_values_lose_their_quotes() {
        let h = &hosts("Host a\n  HostName 10.0.0.1\n  IdentityFile \"~/my keys/id_ed25519\"\n")[0];
        match &h.auth {
            AuthRef::Key { path } => assert_eq!(
                path.to_string_lossy(),
                "~/my keys/id_ed25519",
                "quotes were kept in the path"
            ),
            other => panic!("expected key auth, got {other:?}"),
        }
    }

    /// A port ssh itself would reject should not silently become 22.
    #[test]
    fn an_out_of_range_port_is_reported_rather_than_silently_defaulted() {
        let parsed = parse("Host a\n  HostName 1\n  Port 99999\n");
        assert_eq!(parsed.hosts[0].port, 22, "falls back");
        assert_eq!(parsed.bad_ports, 1, "and says so");
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let parsed = parse("# a comment\n\nHost web\n  # another\n  HostName 10.0.0.1\n");
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].address, "10.0.0.1");
    }

    #[test]
    fn an_empty_config_yields_nothing() {
        assert!(hosts("").is_empty());
        assert!(hosts("# only comments\n").is_empty());
    }

    fn write(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("luvienne-sshcfg-{tag}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn scanning_skips_hosts_already_present() {
        let path = write("dupes", "Host web\n  HostName 10.0.0.1\n  User u\n");
        let existing = vec![Host {
            name: "web".into(),
            address: "x".into(),
            port: 22,
            user: "u".into(),
            tags: vec![],
            auth: AuthRef::Agent,
            jump: None,
            cache_passphrase: false,
            forwards: Vec::new(),
        }];
        let imported = scan(&path, &existing).unwrap();
        assert!(imported.hosts.is_empty());
        assert_eq!(imported.already_present, 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// A jump pointing at something we did not import would fail the chain
    /// resolver on every connect, so it is dropped and reported.
    #[test]
    fn a_jump_to_an_unknown_host_is_dropped_and_reported() {
        let path = write("dangling", "Host web\n  HostName 1\n  ProxyJump ghost\n");
        let imported = scan(&path, &[]).unwrap();
        assert_eq!(imported.hosts[0].jump, None);
        assert!(
            imported
                .notes
                .iter()
                .any(|n| n.contains("not in the config")),
            "notes: {:?}",
            imported.notes
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn a_missing_user_is_reported_as_ask_on_connect() {
        let path = write("nouser", "Host web\n  HostName 1\n");
        let imported = scan(&path, &[]).unwrap();
        assert_eq!(imported.hosts[0].user, "");
        assert!(
            imported
                .notes
                .iter()
                .any(|n| n.contains("asked on connect"))
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Forwards are a list option: every line accumulates, and one inherited
    /// from `Host *` applies *as well as* the block's own rather than losing to
    /// it the way a scalar would.
    #[test]
    fn forward_lines_are_imported_and_accumulate() {
        let parsed = parse(
            "Host *\n  LocalForward 5000 metrics:9090\n\n\
             Host db\n  HostName 10.0.0.9\n  LocalForward 5432 127.0.0.1:5432\n  RemoteForward 9000 localhost:3000\n",
        );

        let db = parsed.hosts.iter().find(|h| h.name == "db").unwrap();
        let specs: Vec<String> = db.forwards.iter().map(|f| f.spec()).collect();

        assert!(
            specs.contains(&"L 5432:127.0.0.1:5432".to_string()),
            "own forward missing: {specs:?}"
        );
        assert!(
            specs.contains(&"R 9000:localhost:3000".to_string()),
            "remote forward missing: {specs:?}"
        );
        assert!(
            specs.contains(&"L 5000:metrics:9090".to_string()),
            "inherited forward was dropped rather than added: {specs:?}"
        );
    }

    /// The config file spells a forward with a space where the command line
    /// uses a colon, and an explicit bind address has to survive either way.
    #[test]
    fn both_spellings_of_a_forward_are_understood() {
        let spaced = ssh_forward(Direction::Local, "127.0.0.1:8080 db:5432").unwrap();
        let joined = ssh_forward(Direction::Local, "127.0.0.1:8080:db:5432").unwrap();
        assert_eq!(spaced, joined);
        assert_eq!(spaced.listen_port, 8080);
        assert_eq!(spaced.to_host, "db");
    }

    /// Nothing is dropped in silence. A forward we cannot express has to be
    /// counted and said out loud in the confirmation, like every other thing
    /// this importer declines to guess at.
    #[test]
    fn forwards_we_cannot_express_are_counted_not_ignored() {
        let parsed = parse(
            "Host a\n  HostName 1.2.3.4\n  DynamicForward 1080\n  \
             LocalForward /tmp/sock /tmp/remote.sock\n",
        );

        assert_eq!(parsed.dynamic_forwards, 1, "SOCKS line not counted");
        assert_eq!(parsed.forwards_rejected, 1, "socket forward not counted");
        assert!(
            parsed.hosts[0].forwards.is_empty(),
            "an unreadable forward must not become a bogus one"
        );
    }
}
