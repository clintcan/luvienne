//! Optional passphrase caching in the macOS Keychain.
//!
//! Caching is opt-in per host (`cache_passphrase` in `hosts.toml`) and nothing is
//! ever written without that flag set. Turning it off deletes what was stored —
//! an opt-out that only stopped *reading* would leave the secret on disk while
//! the UI said caching was off.
//!
//! **Items are keyed by key file, not by host.** A passphrase belongs to the key,
//! not to the machine you are logging into: twenty hosts sharing one `.ppk` share
//! one passphrase, and storing twenty copies would mean `forget` on one host left
//! nineteen behind while reporting the secret gone. The account string is the
//! path as written in the config with `~` expanded, so two hosts share a cache
//! entry when they spell the key the same way.
//!
//! Secrets cross this boundary as [`Zeroizing<String>`], the same type the
//! prompt, the channel, and the decrypt call use. One wrapper on one path — a
//! second secret type here would mean two sets of rules for the same passphrase.

use std::path::Path;

use thiserror::Error;
use zeroize::Zeroizing;

/// Only the macOS implementation names a keychain service.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SERVICE: &str = "luvienne";

/// Every variant exists on every platform, and each one is dead on the platform
/// that cannot produce it — so each carries the `allow` for the *other* side.
///
/// The alternative, `cfg`-ing the variants themselves, pushes the split into
/// every caller and every test that matches on them. Keeping the type identical
/// everywhere is worth two attributes, and it is what lets the tests below run
/// unchanged on both. `cargo clippy -- -D warnings` is expected to pass on
/// Linux as well as macOS, and without these it does not.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[error("no cached passphrase for {0}")]
    NotFound(String),

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[error("keychain access failed")]
    Access,

    /// Only ever constructed off macOS, where there is no Keychain.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    #[error("passphrase caching is only supported on macOS")]
    Unsupported,
}

/// Whether this platform can cache passphrases at all.
///
/// The UI asks so it does not offer a per-host toggle that could only ever
/// fail. A config that sets the flag anyway is left alone rather than quietly
/// cleared — the same file is likely synced to a Mac, where it does work.
pub const fn is_supported() -> bool {
    cfg!(target_os = "macos")
}

/// The Keychain account string for a key file.
///
/// Prefixed so a later cache of something else — a password, keyed by
/// `user@host` — cannot collide with a key path that happens to look like one.
pub fn key_id(path: &Path) -> String {
    format!("key:{}", crate::auth::expand_tilde(path).display())
}

/// Fetch a cached passphrase.
///
/// **Blocking, and possibly for a long time.** The Keychain may put up a system
/// dialog asking the user to allow access, and this call sits there until they
/// answer it. Callers on an async task must use `spawn_blocking`.
#[cfg(target_os = "macos")]
pub fn get(id: &str) -> Result<Zeroizing<String>, KeystoreError> {
    // Every failure — missing item, denied access, a cancelled dialog — is
    // reported the same way on purpose. The only thing a caller can do with any
    // of them is fall through to prompting, which is the safe direction.
    match security_framework::passwords::get_generic_password(SERVICE, id) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let text = std::str::from_utf8(&bytes).map_err(|_| KeystoreError::Access)?;
            Ok(Zeroizing::new(text.to_string()))
        }
        Err(_) => Err(KeystoreError::NotFound(id.to_string())),
    }
}

/// Store a passphrase, replacing any existing entry for the same key.
#[cfg(target_os = "macos")]
pub fn set(id: &str, passphrase: &str) -> Result<(), KeystoreError> {
    security_framework::passwords::set_generic_password(SERVICE, id, passphrase.as_bytes())
        .map_err(|_| KeystoreError::Access)
}

/// Delete a cached passphrase, reporting whether one was actually there.
///
/// Absent is not an error — the caller's intent is "make sure this is not
/// stored", and it already isn't — but it is not the same as having removed
/// something, and the caller says so out loud. Returning `Ok(())` either way
/// made turning caching off announce "forgot 1 cached passphrase" for a host
/// that had never connected and so had never stored one.
#[cfg(target_os = "macos")]
pub fn forget(id: &str) -> Result<bool, KeystoreError> {
    Ok(security_framework::passwords::delete_generic_password(SERVICE, id).is_ok())
}

#[cfg(not(target_os = "macos"))]
pub fn get(_id: &str) -> Result<Zeroizing<String>, KeystoreError> {
    Err(KeystoreError::Unsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn set(_id: &str, _passphrase: &str) -> Result<(), KeystoreError> {
    Err(KeystoreError::Unsupported)
}

/// Nothing can have been stored on a platform with no keychain, so nothing can
/// have been removed.
#[cfg(not(target_os = "macos"))]
pub fn forget(_id: &str) -> Result<bool, KeystoreError> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Reading a key that was never stored must not prompt or hang; it should
    /// fall straight through to a passphrase prompt in the UI.
    #[test]
    fn unknown_key_is_not_found() {
        let err = get("key:/nonexistent/luvienne-test-key").unwrap_err();
        assert!(matches!(
            err,
            KeystoreError::NotFound(_) | KeystoreError::Unsupported
        ));
    }

    /// Forgetting something that was never stored is the state the caller asked
    /// for, so it succeeds — but reports `false`, because nothing was removed.
    /// Saying otherwise made turning caching off announce that it had forgotten
    /// a passphrase for a host that had never stored one.
    #[test]
    fn forgetting_an_absent_entry_succeeds_but_removed_nothing() {
        assert_eq!(
            forget("key:/nonexistent/luvienne-test-key").ok(),
            Some(false)
        );
    }

    /// The id is what makes twenty hosts sharing a key share one entry, so the
    /// two spellings of the same path must not produce two ids.
    #[test]
    fn the_id_expands_a_tilde_so_both_spellings_agree() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();

        assert_eq!(
            key_id(Path::new("~/.ssh/id_ed25519")),
            key_id(&home.join(".ssh/id_ed25519")),
        );
    }

    /// Namespaced, so a future password cache keyed by `user@host` cannot
    /// collide with a key path.
    #[test]
    fn the_id_is_namespaced() {
        assert!(key_id(&PathBuf::from("/keys/a.ppk")).starts_with("key:"));
    }

    /// A round trip through the real Keychain. Ignored by default: it writes to
    /// the developer's login keychain and can put up an access dialog, which
    /// would hang CI. Run it by hand with `cargo test -- --ignored keychain`.
    #[test]
    #[ignore = "touches the real login keychain"]
    fn a_stored_passphrase_comes_back_and_can_be_forgotten() {
        let id = key_id(Path::new("/tmp/luvienne-roundtrip-test.ppk"));

        set(&id, "hunter2").unwrap();
        assert_eq!(get(&id).unwrap().as_str(), "hunter2");

        // Storing again must replace rather than duplicate.
        set(&id, "hunter3").unwrap();
        assert_eq!(get(&id).unwrap().as_str(), "hunter3");

        assert!(
            forget(&id).unwrap(),
            "removing a real entry must report true"
        );
        assert!(get(&id).is_err(), "forget must actually remove the item");
        assert!(
            !forget(&id).unwrap(),
            "forgetting it twice must not claim to have removed it twice"
        );
    }
}
