//! `e6irc-load --help` is the complete usage: every flag the parser accepts,
//! read from the parser's own match arms, so a new flag cannot be left out of
//! the help, the source's usage header, or `tools/load/README.md`.

use std::collections::BTreeSet;
use std::process::Command;

const SOURCE: &str = include_str!("../src/main.rs");
const README: &str = include_str!("../../../tools/load/README.md");

/// The flags the parser's match arms accept (`"--flag" =>`, or
/// `"--flag" | "-f" =>`), long spellings only.
fn parser_flags() -> BTreeSet<&'static str> {
    let flags: BTreeSet<&'static str> = SOURCE
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("\"--") && line.contains("=>"))
        .map(|line| {
            let spelled = &line[1..];
            &spelled[..spelled.find('"').expect("a closing quote")]
        })
        .collect();
    assert!(
        flags.len() > 10 && flags.contains("--addr") && flags.contains("--help"),
        "the parser's match arms were not found: {flags:?}"
    );
    flags
}

/// The flags a help text lists, one per line that starts with `  --`.
fn listed_flags(help: &str) -> BTreeSet<&str> {
    help.lines()
        .filter(|line| line.starts_with("  --"))
        .filter_map(|line| line.split_whitespace().next())
        .collect()
}

fn run(argument: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_e6irc-load"))
        .arg(argument)
        .output()
        .expect("e6irc-load runs");
    assert!(
        output.status.success(),
        "{argument} exits 0: {:?}",
        output.status
    );
    assert!(
        output.stderr.is_empty(),
        "{argument} writes nothing to stderr"
    );
    String::from_utf8(output.stdout).expect("UTF-8 help")
}

#[test]
fn help_lists_every_flag_the_parser_accepts_and_exits_zero() {
    let help = run("--help");
    assert_eq!(
        listed_flags(&help),
        parser_flags(),
        "--help must list exactly the flags the parser accepts:\n{help}"
    );
    assert_eq!(run("-h"), help, "-h prints the same help");
}

#[test]
fn the_usage_header_and_the_readme_name_every_flag() {
    let header: String = SOURCE
        .lines()
        .filter_map(|line| line.strip_prefix("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    for flag in parser_flags() {
        let named = |text: &str| {
            text.match_indices(flag).any(|(at, _)| {
                !text[at + flag.len()..]
                    .starts_with(|next: char| next.is_ascii_alphanumeric() || next == '-')
            })
        };
        assert!(named(&header), "the usage header omits {flag}");
        assert!(named(README), "tools/load/README.md omits {flag}");
    }
}

#[test]
fn an_unknown_flag_points_at_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_e6irc-load"))
        .arg("--no-such-flag")
        .output()
        .expect("e6irc-load runs");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown argument: --no-such-flag"),
        "{stderr}"
    );
    assert!(stderr.contains("--help"), "{stderr}");
}
