//! The command-line surface: the two flags, and what a bare run does when there
//! is no terminal to draw on.
//!
//! These live here rather than as shell in the CI workflow so the wording of the
//! no-terminal message is owned by Rust and checked on every `cargo test`,
//! locally included. It was previously asserted only in `.github/workflows/ci.yml`
//! and in the Homebrew formula — two places that fail *after* the edit that broke
//! them, in repositories the author of the edit may not be looking at.

use std::process::Command;

/// The binary cargo built for this test — not whatever `luvienne` is on `PATH`,
/// which on a developer's machine is usually the last release they installed.
const LUVIENNE: &str = env!("CARGO_BIN_EXE_luvienne");

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
