//! Loading private keys, including PuTTY `.ppk`.
//!
//! `russh::keys::decode_secret_key` sniffs the format by content and already
//! handles OpenSSH, PEM, and PuTTY v2/v3 (Argon2). There is no need for a
//! hand-rolled PPK parser — do not add one.
//!
//! PPK v3 uses Argon2 deliberately-slow key derivation. Calls here can take
//! hundreds of milliseconds and **must not** run on the render thread.

use std::path::{Path, PathBuf};

use russh::keys::PrivateKey;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("no key file at {0}")]
    Missing(PathBuf),

    #[error("key at {0} is encrypted — a passphrase is required")]
    PassphraseRequired(PathBuf),

    #[error("could not decrypt key at {0} — wrong passphrase, or unsupported format")]
    Undecryptable(PathBuf),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Expand a leading `~` to the user's home directory.
///
/// Config files are hand-written, so `~/.ssh/id_ed25519` is the form people
/// actually type. Nothing else in the path is touched — no globbing, no `$VAR`.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let Ok(rest) = path.strip_prefix("~") else {
        return path.to_path_buf();
    };
    match directories::BaseDirs::new() {
        Some(dirs) => dirs.home_dir().join(rest),
        None => path.to_path_buf(),
    }
}

/// Read and decrypt a private key. `~` in `path` is expanded.
///
/// The file contents and the decrypted key both hold secret material. Contents
/// are wrapped in [`Zeroizing`] so the buffer is wiped on drop; the returned
/// `PrivateKey` zeroizes itself.
///
/// Note the error mapping: a failure never distinguishes "wrong passphrase" from
/// "corrupt file" in a way that echoes the input, and never includes the key body.
///
/// **Blocking and potentially slow.** PPK v3 uses Argon2, which is deliberately
/// expensive — hundreds of milliseconds. Callers on an async task must wrap this
/// in `spawn_blocking` or they will stall a runtime worker.
pub fn load_private_key(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey, AuthError> {
    let path = expand_tilde(path);

    if !path.exists() {
        return Err(AuthError::Missing(path));
    }

    let contents = Zeroizing::new(std::fs::read_to_string(&path)?);

    russh::keys::decode_secret_key(&contents, passphrase).map_err(|_| {
        if passphrase.is_none() {
            AuthError::PassphraseRequired(path)
        } else {
            AuthError::Undecryptable(path)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_reported_as_missing() {
        let err = load_private_key(Path::new("/nonexistent/id_ed25519"), None).unwrap_err();
        assert!(matches!(err, AuthError::Missing(_)));
    }

    /// `~/.ssh/id_ed25519` is the form people actually write in hosts.toml, and
    /// an unexpanded `~` is a directory that does not exist.
    #[test]
    fn tilde_expands_to_the_home_directory() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();

        assert_eq!(
            expand_tilde(Path::new("~/.ssh/id_ed25519")),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(
            expand_tilde(Path::new("/absolute/key")),
            Path::new("/absolute/key"),
            "absolute paths are untouched"
        );
        assert_eq!(
            expand_tilde(Path::new("relative/key")),
            Path::new("relative/key"),
            "relative paths are untouched"
        );
        assert_eq!(
            expand_tilde(Path::new("/opt/~/key")),
            Path::new("/opt/~/key"),
            "only a leading tilde counts"
        );
    }

    /// The error names the expanded path, not the literal `~` form — otherwise
    /// "no key file at ~/keys/x.ppk" sends you looking in the wrong place.
    #[test]
    fn missing_key_error_names_the_expanded_path() {
        let err = load_private_key(Path::new("~/definitely-not-a-key"), None).unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains('~'), "got: {rendered}");
        assert!(rendered.contains("definitely-not-a-key"));
    }

    #[test]
    fn errors_never_echo_key_material() {
        let err = AuthError::Undecryptable(PathBuf::from("/home/u/.ssh/id_rsa"));
        let rendered = err.to_string();
        assert!(rendered.contains("id_rsa"));
        assert!(!rendered.contains("BEGIN"));
    }

    // Fixtures produced by real puttygen/ssh-keygen. See tests/fixtures/README.md
    // — throwaway keys, passphrase `hunter2`.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn loads_an_unencrypted_ppk_v3() {
        let key = load_private_key(&fixture("ed25519_v3_plain.ppk"), None).unwrap();
        assert_eq!(key.algorithm().to_string(), "ssh-ed25519");
    }

    /// PPK v3 with Argon2. This is the slow path that must stay off the render
    /// thread — and the reason `load_key_interactive` uses `spawn_blocking`.
    #[test]
    fn loads_an_encrypted_ppk_v3_with_the_right_passphrase() {
        let path = fixture("ed25519_v3_locked.ppk");

        let needs_pass = load_private_key(&path, None).unwrap_err();
        assert!(
            matches!(needs_pass, AuthError::PassphraseRequired(_)),
            "an encrypted key must ask rather than fail outright, got {needs_pass:?}"
        );

        let key = load_private_key(&path, Some("hunter2")).unwrap();
        assert_eq!(key.algorithm().to_string(), "ssh-ed25519");
    }

    #[test]
    fn loads_an_encrypted_ppk_v2() {
        let key = load_private_key(&fixture("rsa_v2_locked.ppk"), Some("hunter2")).unwrap();
        assert!(key.algorithm().is_rsa());
    }

    #[test]
    fn loads_an_encrypted_openssh_key() {
        let key = load_private_key(&fixture("openssh_ed25519_locked"), Some("hunter2")).unwrap();
        assert_eq!(key.algorithm().to_string(), "ssh-ed25519");
    }

    /// A wrong passphrase must be `Undecryptable`, not `PassphraseRequired` —
    /// that distinction is what drives the retry prompt in `load_key_interactive`.
    #[test]
    fn a_wrong_passphrase_is_distinguishable_from_a_missing_one() {
        let err = load_private_key(&fixture("ed25519_v3_locked.ppk"), Some("wrong")).unwrap_err();
        assert!(matches!(err, AuthError::Undecryptable(_)), "got {err:?}");
    }

    /// Format is detected by content, not by extension — a `.ppk` renamed to
    /// `id_rsa` still loads, and vice versa. Nothing in the codebase should ever
    /// branch on the filename.
    #[test]
    fn format_is_detected_by_content_not_extension() {
        let dir = std::env::temp_dir().join("luvienne-ext-test");
        std::fs::create_dir_all(&dir).unwrap();

        let misnamed = dir.join("id_rsa"); // actually a PPK
        std::fs::copy(fixture("ed25519_v3_plain.ppk"), &misnamed).unwrap();

        let key = load_private_key(&misnamed, None).unwrap();
        assert_eq!(key.algorithm().to_string(), "ssh-ed25519");

        std::fs::remove_dir_all(&dir).ok();
    }
}
