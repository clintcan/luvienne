//! The command-line surface: the flags, the optional host operand, and what a
//! bare run does when there is no terminal to draw on.
//!
//! These live here rather than as shell in the CI workflow so the wording of the
//! no-terminal message is owned by Rust and checked on every `cargo test`,
//! locally included. It was previously asserted only in `.github/workflows/ci.yml`
//! and in the Homebrew formula — two places that fail *after* the edit that broke
//! them, in repositories the author of the edit may not be looking at.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// The binary cargo built for this test — not whatever `luvienne` is on `PATH`,
/// which on a developer's machine is usually the last release they installed.
const LUVIENNE: &str = env!("CARGO_BIN_EXE_luvienne");

/// A throwaway `XDG_CONFIG_HOME` holding one inventory.
///
/// Every test that names a host runs against this rather than the real
/// `~/.config/luvienne/hosts.toml` — a test whose result depends on the
/// developer's own hosts is worse than no test, and one that could *connect* to
/// them is worse still.
fn config_home_with(hosts: &str) -> PathBuf {
    // A counter rather than a tempfile dev-dependency: these all run in one
    // process, so the pid plus a counter is unique enough.
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let home = std::env::temp_dir().join(format!(
        "luvienne-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(home.join("luvienne")).unwrap();
    std::fs::write(home.join("luvienne").join("hosts.toml"), hosts).unwrap();
    home
}

/// One host, reachable by name, pointing nowhere routable.
const ONE_HOST: &str = r#"
[[host]]
name = "example-box"
address = "10.255.255.1"
user = "someone"
"#;

fn luvienne_in(home: &Path) -> Command {
    let mut command = Command::new(LUVIENNE);
    command.env("XDG_CONFIG_HOME", home);
    command
}

#[test]
fn version_reports_the_crate_version() {
    let out = Command::new(LUVIENNE).arg("--version").output().unwrap();

    assert!(out.status.success(), "--version exited {}", out.status);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
    );
}

#[test]
fn help_names_every_flag_it_accepts() {
    let out = Command::new(LUVIENNE).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success(), "--help exited {}", out.status);
    for flag in ["-h", "--help", "-V", "--version"] {
        assert!(stdout.contains(flag), "--help does not mention {flag}");
    }
}

/// Short and long forms are the same code path, but a typo in the match arms
/// would only show up on whichever spelling is untested.
#[test]
fn the_short_forms_match_the_long_ones() {
    for (short, long) in [("-V", "--version"), ("-h", "--help")] {
        let a = Command::new(LUVIENNE).arg(short).output().unwrap();
        let b = Command::new(LUVIENNE).arg(long).output().unwrap();
        assert_eq!(a.stdout, b.stdout, "{short} and {long} disagree");
    }
}

/// Exit 2, not 1: a usage error is not a crash, and `main`'s `Result` can only
/// ever produce 1.
#[test]
fn an_unrecognised_argument_is_a_usage_error() {
    let out = Command::new(LUVIENNE).arg("--nope").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains("--nope"),
        "does not name the argument: {stderr}"
    );
    assert!(
        stderr.contains("--help"),
        "does not point at --help: {stderr}"
    );
}

/// A named host that is not in the inventory has to be reported *before* the
/// terminal is taken over. Getting this wrong is not a crash — it is a typo
/// answered by a full-screen app that then sits there waiting to be quit.
#[test]
fn an_unknown_host_is_reported_without_starting_the_ui() {
    let home = config_home_with(ONE_HOST);
    let out = luvienne_in(&home).arg("no-such-box").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "expected a non-zero exit");
    assert!(
        stderr.contains("no-such-box"),
        "does not name the host asked for: {stderr}"
    );
    // The tell that it never reached `ratatui::try_init`.
    assert!(
        !stderr.contains("needs a terminal"),
        "got as far as opening the terminal: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// The mirror image: a host that *does* exist gets past the inventory check and
/// fails at the terminal instead, which is what proves the check is a gate on
/// the name rather than on having a tty.
#[test]
fn a_known_host_gets_as_far_as_needing_a_terminal() {
    let home = config_home_with(ONE_HOST);
    let out = luvienne_in(&home).arg("example-box").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "expected a non-zero exit");
    assert!(
        stderr.contains("needs a terminal"),
        "stopped earlier than the terminal: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// There is one terminal to attach to, so a second name is a mistake worth
/// naming rather than silently ignoring.
#[test]
fn more_than_one_argument_is_a_usage_error() {
    let out = Command::new(LUVIENNE)
        .args(["example-box", "another-box"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--help"));
}

/// A mistyped flag must not be taken for a host name — "no host called
/// --verbose" would send the reader to the wrong file.
#[test]
fn a_mistyped_flag_is_not_treated_as_a_host() {
    let home = config_home_with(ONE_HOST);
    let out = luvienne_in(&home).arg("--verbose").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(2), "stderr was: {stderr}");
    assert!(
        !stderr.contains("no host"),
        "reported as a missing host: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// The one that matters for packaging. `Command::output` gives the child pipes
/// rather than a tty, which is the same situation as `brew test`, a CI runner,
/// or a cron job — and it must explain itself rather than report a panic from
/// somewhere inside ratatui.
#[test]
fn without_a_terminal_it_explains_itself_rather_than_panicking() {
    let out = Command::new(LUVIENNE).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "expected a non-zero exit");
    assert!(
        stderr.contains("needs a terminal"),
        "does not explain the real problem: {stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "reported as a panic: {stderr}"
    );
}
