//! Importing saved sessions from PuTTY.
//!
//! On Unix, PuTTY keeps one file per session under `~/.putty/sessions`, named
//! after the session with `%XX` escapes, containing `Key=Value` lines. Sessions
//! migrated from Windows PuTTY keep their Windows values — notably key paths
//! like `D:\keys\server.ppk`, which obviously do not resolve here.
//!
//! The import is deliberately lossy in one direction only: it never invents
//! information, and never silently discards a reference it cannot resolve. A key
//! path that does not exist is still imported, because knowing *which* key a
//! host wanted is the useful part; the file browser makes repointing it easy.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::{AuthRef, Host};
use crate::import::Imported;

/// The tag every imported host gets, so they can be found and filtered as a group.
pub const IMPORT_TAG: &str = "putty";

pub const SOURCE: &str = "PuTTY";

pub fn sessions_dir() -> Option<PathBuf> {
    let home = directories::BaseDirs::new()?.home_dir().to_path_buf();
    let dir = home.join(".putty").join("sessions");
    dir.is_dir().then_some(dir)
}

/// Undo PuTTY's filename escaping: `clint%20storage` is `clint storage`.
pub fn decode_name(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(byte) = hex {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn field<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Turn one session file into a host. `None` means it is not an SSH session.
pub fn parse_session(name: &str, contents: &str) -> Option<Host> {
    // PuTTY writes `Protocol=ssh`; anything else is telnet/rlogin/serial/raw.
    if field(contents, "Protocol").unwrap_or("ssh").trim() != "ssh" {
        return None;
    }

    let address = field(contents, "HostName")?.trim();
    if address.is_empty() {
        return None;
    }

    let port = field(contents, "PortNumber")
        .and_then(|p| p.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(22);

    // Left empty when PuTTY has none, which means "ask at connect" — the same
    // `login as:` prompt PuTTY itself shows. Assuming a username here would
    // quietly try the wrong account and fail with an authentication error that
    // says nothing about the real cause.
    let user = field(contents, "UserName")
        .map(str::trim)
        .unwrap_or_default()
        .to_string();

    let auth = match field(contents, "PublicKeyFile").map(str::trim) {
        Some(path) if !path.is_empty() => AuthRef::Key {
            path: PathBuf::from(path),
        },
        _ => AuthRef::Agent,
    };

    Some(Host {
        name: decode_name(name),
        address: address.to_string(),
        port,
        user,
        tags: vec![IMPORT_TAG.to_string()],
        auth,
        // PuTTY's proxy settings are a different concept (SOCKS/HTTP/local
        // command), not an SSH jump host, so nothing maps here.
        jump: None,
        // An import is not consent to store secrets. Caching stays something
        // the user turns on per host, after the hosts exist.
        cache_passphrase: false,
        forwards: Vec::new(),
    })
}

/// Read every session in `dir`, skipping any whose name is already taken.
pub fn scan(dir: &Path, existing: &[Host]) -> std::io::Result<Imported> {
    let taken: HashSet<&str> = existing.iter().map(|h| h.name.as_str()).collect();
    let mut import = Imported::new(SOURCE);
    let (mut missing_keys, mut not_ssh, mut asks_user) = (0usize, 0usize, 0usize);

    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // Stable order, so a partial import is reproducible.
    entries.sort();

    for path in &entries {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };

        let Some(host) = parse_session(name, &contents) else {
            not_ssh += 1;
            continue;
        };
        if taken.contains(host.name.as_str()) {
            import.already_present += 1;
            continue;
        }

        if host.user.is_empty() {
            asks_user += 1;
        }
        if let AuthRef::Key { path } = &host.auth
            && !crate::auth::expand_tilde(path).exists()
        {
            missing_keys += 1;
        }

        import.hosts.push(host);
    }

    if asks_user > 0 {
        import.notes.push(format!(
            "{asks_user} have no username — you will be asked on connect"
        ));
    }
    if missing_keys > 0 {
        import.notes.push(format!(
            "{missing_keys} reference a key file not on this machine"
        ));
    }
    if not_ssh > 0 {
        import
            .notes
            .push(format!("{not_ssh} are not SSH sessions, skipped"));
    }

    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Protocol=ssh\nHostName=10.0.0.1\nPortNumber=2222\nUserName=deploy\nPublicKeyFile=/keys/a.ppk\n";

    #[test]
    fn decodes_putty_filename_escapes() {
        assert_eq!(decode_name("clint%20storage"), "clint storage");
        assert_eq!(decode_name("plain"), "plain");
        assert_eq!(decode_name("100%25"), "100%");
        // A stray percent must not eat the rest of the name.
        assert_eq!(decode_name("odd%"), "odd%");
        assert_eq!(decode_name("odd%zz"), "odd%zz");
    }

    #[test]
    fn maps_every_field_we_care_about() {
        let host = parse_session("web%2001", SAMPLE).unwrap();
        assert_eq!(host.name, "web 01");
        assert_eq!(host.address, "10.0.0.1");
        assert_eq!(host.port, 2222);
        assert_eq!(host.user, "deploy");
        assert_eq!(host.tags, vec![IMPORT_TAG]);
        assert_eq!(
            host.auth,
            AuthRef::Key {
                path: PathBuf::from("/keys/a.ppk")
            }
        );
    }

    /// Most real sessions have no username. PuTTY asks `login as:` at connect
    /// time, and so do we — an empty user means "ask", not "broken".
    #[test]
    fn an_absent_username_is_left_to_be_asked_for() {
        let host = parse_session("h", "Protocol=ssh\nHostName=10.0.0.1\nUserName=\n").unwrap();
        assert_eq!(host.user, "", "empty means ask at connect");

        let host = parse_session("h", "Protocol=ssh\nHostName=10.0.0.1\n").unwrap();
        assert_eq!(host.user, "");
    }

    #[test]
    fn an_absent_port_defaults_to_22() {
        let host = parse_session("h", "Protocol=ssh\nHostName=10.0.0.1\n").unwrap();
        assert_eq!(host.port, 22);
    }

    #[test]
    fn no_key_file_means_agent_auth() {
        let host = parse_session("h", "Protocol=ssh\nHostName=10.0.0.1\nPublicKeyFile=\n").unwrap();
        assert_eq!(host.auth, AuthRef::Agent);
    }

    /// Windows paths are the common case in migrated sessions. They are kept:
    /// knowing which key was meant is worth more than a tidy import.
    #[test]
    fn a_windows_key_path_is_preserved_not_discarded() {
        let host = parse_session(
            "h",
            "Protocol=ssh\nHostName=10.0.0.1\nPublicKeyFile=D:\\keys\\server.ppk\n",
        )
        .unwrap();
        assert_eq!(
            host.auth,
            AuthRef::Key {
                path: PathBuf::from("D:\\keys\\server.ppk")
            }
        );
    }

    #[test]
    fn non_ssh_sessions_are_skipped() {
        assert!(parse_session("h", "Protocol=telnet\nHostName=10.0.0.1\n").is_none());
        assert!(parse_session("h", "Protocol=serial\nHostName=\n").is_none());
    }

    #[test]
    fn a_session_without_a_hostname_is_skipped() {
        assert!(parse_session("h", "Protocol=ssh\nHostName=\n").is_none());
        assert!(parse_session("h", "Protocol=ssh\n").is_none());
    }

    fn fixture_dir(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("luvienne-putty-{tag}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn imports_a_directory_and_counts_what_it_found() {
        let dir = fixture_dir(
            "basic",
            &[
                ("alpha", SAMPLE),
                ("beta%20two", "Protocol=ssh\nHostName=10.0.0.2\n"),
                ("old", "Protocol=telnet\nHostName=10.0.0.3\n"),
            ],
        );

        let import = scan(&dir, &[]).unwrap();
        let names: Vec<&str> = import.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta two"]);
        assert!(import.notes.iter().any(|n| n.contains("not SSH sessions")));
        assert!(import.notes.iter().any(|n| n.contains("asked on connect")));
        assert!(
            import
                .notes
                .iter()
                .any(|n| n.contains("not on this machine")),
            "notes: {:?}",
            import.notes
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Re-importing must not pile up duplicates.
    #[test]
    fn sessions_already_in_the_inventory_are_skipped() {
        let dir = fixture_dir("dupes", &[("alpha", SAMPLE)]);
        let existing = vec![parse_session("alpha", SAMPLE).unwrap()];

        let import = scan(&dir, &existing).unwrap();
        assert!(import.hosts.is_empty());
        assert_eq!(import.already_present, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_panic() {
        assert!(scan(Path::new("/nonexistent-putty-dir"), &[]).is_err());
    }
}
