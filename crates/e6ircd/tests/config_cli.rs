//! How the daemon binary takes its configuration, end to end: from a file, or
//! from the container's environment (`--config-from-environment`). The
//! production image has no shell, so everything a shell entrypoint used to
//! guarantee — a loud refusal by variable name, never a printed secret — is the
//! binary's to guarantee, and is checked on the binary.

use std::process::{Command, Output};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const SECRET: &str = "hunter2";

fn minimal() -> Vec<(&'static str, String)> {
    vec![
        ("E6IRC_SERVER_NAME", "irc.example.test".into()),
        ("E6IRC_PUBLIC_URL", "https://irc.example.test".into()),
        (
            "E6IRC_DATABASE_URL",
            format!("postgres://e6irc:{SECRET}@db.example.invalid/e6irc"),
        ),
        ("APPLICATION_RELEASE_REVISION", REVISION.into()),
    ]
}

/// Run `e6ircd` with exactly `environment` — nothing inherited, so a variable
/// exported in the developer's shell cannot decide the outcome.
fn e6ircd(arguments: &[&str], environment: &[(&'static str, String)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .args(arguments)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .output()
        .expect("run e6ircd")
}

fn report(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn the_environment_alone_states_a_valid_configuration() {
    let output = e6ircd(&["check-config", "--config-from-environment"], &minimal());
    assert!(output.status.success(), "{}", report(&output));

    let mut with_oidc = minimal();
    with_oidc.extend([
        ("E6IRC_OIDC_ISSUER", "https://auth.example.test".to_owned()),
        ("E6IRC_OIDC_CLIENT_ID", "e6irc".to_owned()),
        ("E6IRC_OIDC_CLIENT_SECRET", SECRET.to_owned()),
        (
            "E6IRC_OIDC_END_SESSION",
            "https://auth.example.test/logout".to_owned(),
        ),
        ("E6IRC_ADMIN_ACCOUNTS", "alice,,bob,".to_owned()),
    ]);
    let output = e6ircd(&["check-config", "--config-from-environment"], &with_oidc);
    assert!(output.status.success(), "{}", report(&output));
}

/// `[secrets].key_file` and `E6IRC_SECRET_KEY` are alternatives; stated
/// together, the refusal names both so the operator knows which to remove.
#[test]
fn a_key_file_and_an_environment_key_together_are_refused_by_name() {
    let genkey = e6ircd(&["genkey"], &[]);
    assert!(genkey.status.success(), "{}", report(&genkey));
    let key = String::from_utf8_lossy(&genkey.stdout).trim().to_string();
    let directory = std::env::temp_dir();
    let key_path = directory.join(format!("e6irc-cli-key-{}.b64", std::process::id()));
    let config_path = directory.join(format!("e6irc-cli-config-{}.toml", std::process::id()));
    std::fs::write(&key_path, &key).expect("write key");
    std::fs::write(
        &config_path,
        format!(
            "server_name = \"irc.example.test\"\nnetwork_name = \"ExampleNet\"\n[[listeners]]\naddr = \"127.0.0.1:0\"\n\
             [secrets]\nkey_file = {key_path:?}\n"
        ),
    )
    .expect("write config");
    let arguments = [
        "check-config",
        "--config",
        config_path.to_str().expect("utf-8"),
    ];

    let alone = e6ircd(&arguments, &[]);
    assert!(alone.status.success(), "{}", report(&alone));

    let both = e6ircd(&arguments, &[("E6IRC_SECRET_KEY", key.clone())]);
    let text = report(&both);
    assert!(!both.status.success(), "{text}");
    assert!(text.contains("E6IRC_SECRET_KEY"), "{text}");
    assert!(text.contains("key_file"), "{text}");
    assert!(!text.contains(&key), "never prints the key: {text}");
    std::fs::remove_file(key_path).ok();
    std::fs::remove_file(config_path).ok();
}

/// An `E6IRC_ADMIN_ACCOUNTS` entry that is not an account name — the second
/// half of an unsplit `"alice, bob"` — is refused by name rather than
/// accepted as a grant that can never match anyone.
#[test]
fn an_admin_accounts_entry_that_is_not_an_account_name_is_refused_by_name() {
    let mut environment = minimal();
    environment.push(("E6IRC_ADMIN_ACCOUNTS", "alice, bob".to_owned()));
    let output = e6ircd(&["check-config", "--config-from-environment"], &environment);
    let text = report(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("http.admin_accounts"), "{text}");
    assert!(text.contains("\" bob\""), "names the entry: {text}");
}

#[test]
fn a_missing_or_malformed_variable_is_refused_by_name_without_printing_any_value() {
    let cases: [(&str, Option<&str>, &str); 4] = [
        (
            "APPLICATION_RELEASE_REVISION",
            None,
            "APPLICATION_RELEASE_REVISION is required",
        ),
        (
            "E6IRC_DATABASE_URL",
            Some("postgres://e6irc:hunter2@db.example.invalid/e6irc\r"),
            "E6IRC_DATABASE_URL contains a control character",
        ),
        (
            "E6IRC_SECURE_COOKIES",
            Some("yes"),
            "E6IRC_SECURE_COOKIES must be exactly true or false",
        ),
        (
            "E6IRC_CONFIG_PATH",
            Some("/tmp/e6irc.toml"),
            "E6IRC_CONFIG_PATH is no longer honoured",
        ),
    ];
    for (variable, value, expected) in cases {
        let mut environment: Vec<_> = minimal()
            .into_iter()
            .filter(|(name, _)| *name != variable)
            .collect();
        if let Some(value) = value {
            environment.push((variable, value.to_owned()));
        }
        // Both the validating subcommand and the server itself refuse, and the
        // server does so before it opens a socket or a database connection.
        for arguments in [
            &["check-config", "--config-from-environment"][..],
            &["--config-from-environment"][..],
        ] {
            let output = e6ircd(arguments, &environment);
            let said = report(&output);
            assert!(!output.status.success(), "{variable}: {said}");
            assert!(said.contains(expected), "{variable}: {said}");
            assert!(
                !said.contains(SECRET),
                "{variable} printed a secret: {said}"
            );
        }
    }
}

/// A validation failure found after the document is built (here a public URL
/// that is not a URL) is reported like a file's would be, and still without
/// the database URL beside it.
#[test]
fn an_invalid_value_is_refused_by_the_same_validation_a_file_gets() {
    let environment: Vec<_> = minimal()
        .into_iter()
        .map(|(name, value)| match name {
            "E6IRC_PUBLIC_URL" => (name, "not a url".to_owned()),
            _ => (name, value),
        })
        .collect();
    let output = e6ircd(&["check-config", "--config-from-environment"], &environment);
    let said = report(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("invalid config"), "{said}");
    assert!(!said.contains(SECRET), "{said}");
}

#[test]
fn a_file_and_the_environment_cannot_both_be_the_configuration() {
    let output = e6ircd(
        &["--config", "e6irc.toml", "--config-from-environment"],
        &minimal(),
    );
    assert!(!output.status.success(), "{}", report(&output));
    assert!(report(&output).contains("usage:"), "{}", report(&output));
}

/// The daemon's own report of an unparsable file gives the position and the
/// reason, never the source line: that line is as likely a secret as not.
#[test]
fn an_unparsable_file_is_reported_by_position_and_never_by_its_text() {
    let path = std::env::temp_dir().join(format!("e6irc-unparsable-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "server_name = \"irc.example.test\"\n[database]\n\
             url = \"postgres://user:{SECRET}@example.invalid/e6irc\r\"\n"
        ),
    )
    .expect("write the unparsable configuration");
    let output = e6ircd(
        &[
            "check-config",
            "--config",
            path.to_str().expect("UTF-8 path"),
        ],
        &[],
    );
    std::fs::remove_file(&path).expect("remove the unparsable configuration");
    let said = report(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("line 3, column"), "{said}");
    assert!(!said.contains(SECRET), "{said}");
}
