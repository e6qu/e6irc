use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use e6ircd::config::{Config, ConfigError};
use e6ircd::net;
use e6ircd::secret::SecretKey;

const USAGE: &str = "usage:\n  \
    e6ircd [--config <path>]        run the server\n  \
    e6ircd check-config [--config <path>]\n  \
                                     validate configuration and exit\n  \
    e6ircd genkey                   print a new base64 master key\n  \
    e6ircd seal [--key-file <path>] seal stdin into an enc:v2: blob\n  \
    e6ircd rotate-secrets [--config <path>]\n  \
                                     atomically re-seal database secrets";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("genkey") => genkey(),
        Some("seal") => seal(&args[1..]),
        Some("rotate-secrets") => rotate_secrets(&args[1..]),
        Some("check-config") => check_config(&args[1..]),
        _ => run(&args),
    }
}

fn check_config(args: &[String]) -> ExitCode {
    match load_config_or_fail(args, "e6ircd check-config") {
        Ok(_) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn config_path(args: &[String]) -> Result<PathBuf, ()> {
    match args {
        [] => Ok(PathBuf::from("e6irc.toml")),
        [flag, path] if flag == "--config" => Ok(PathBuf::from(path)),
        _ => Err(()),
    }
}

/// Resolve the config path and load the config, or print a diagnostic and
/// return `FAILURE`. `context` is the error prefix (`"e6ircd"` for the main
/// command, `"e6ircd rotate-secrets"` for the subcommand).
fn load_config_or_fail(args: &[String], context: &str) -> Result<Config, ExitCode> {
    let config_path = match config_path(args) {
        Ok(path) => path,
        Err(()) => {
            eprintln!("{USAGE}");
            return Err(ExitCode::FAILURE);
        }
    };
    Config::load(&config_path).map_err(|error| {
        let failure = match error {
            ConfigError::Parse(parse) => {
                describe_parse_error(parse, std::fs::read_to_string(&config_path).ok().as_deref())
            }
            other => other.to_string(),
        };
        eprintln!("{context}: {failure} ({})", config_path.display());
        ExitCode::FAILURE
    })
}

/// Report an unparsable configuration by position and reason. The parser's own
/// rendering quotes the offending source line, and in this file that line is as
/// likely to hold the database URL or a client secret as anything else — a
/// carriage return pasted with the value is enough to make it the failing one.
fn describe_parse_error(mut error: toml::de::Error, source: Option<&str>) -> String {
    let position = match (error.span(), source) {
        (Some(span), Some(source)) => {
            let (line, column) = line_and_column(source, span.start);
            format!("line {line}, column {column}: ")
        }
        (Some(span), None) => format!("byte {}: ", span.start),
        (None, _) => String::new(),
    };
    // Detached from its input the error renders its reason and, for a value of
    // the wrong shape, the key it belongs to — and no excerpt.
    error.set_input(None);
    let reason = error.to_string();
    format!(
        "invalid config: {position}{}",
        reason.trim_end().replace('\n', " ")
    )
}

/// One-based line and column of a byte offset, counting columns in characters.
/// An offset at or past the end (an unterminated value) lands on the last line.
fn line_and_column(source: &str, offset: usize) -> (usize, usize) {
    let before = &source.as_bytes()[..offset.min(source.len())];
    let line_start = before
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let line = before.iter().filter(|&&byte| byte == b'\n').count() + 1;
    let column = String::from_utf8_lossy(&before[line_start..])
        .chars()
        .count()
        + 1;
    (line, column)
}

/// Atomically re-seal every database-owned credential with the configured
/// primary key. The deployment config must already name the new primary and
/// retain the old key under `previous_key_files`, so both ciphertext
/// generations remain readable before, during, and after the transaction.
fn rotate_secrets(args: &[String]) -> ExitCode {
    let config = match load_config_or_fail(args, "e6ircd rotate-secrets") {
        Ok(c) => c,
        Err(code) => return code,
    };
    let keys = match config.secret_keyring() {
        Ok(Some(keys)) if keys.key_count() >= 2 => keys,
        Ok(Some(_)) => {
            eprintln!(
                "e6ircd rotate-secrets: configure the new key_file primary and \
                 at least one previous_key_files entry before rotating"
            );
            return ExitCode::FAILURE;
        }
        Ok(None) => {
            eprintln!("e6ircd rotate-secrets: no secret keyring is configured");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("e6ircd rotate-secrets: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(database) = config.database else {
        eprintln!("e6ircd rotate-secrets: [database] is required");
        return ExitCode::FAILURE;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(async {
        let pool = e6ircd::db::connect_and_migrate(&database.url).await?;
        e6ircd::db::rotate_database_secrets(&pool, &keys, "rotate-secrets").await
    }) {
        Ok(report) => {
            println!(
                "re-sealed {} managed and {} account-network secrets",
                report.managed_config_secrets, report.account_network_secrets
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("e6ircd rotate-secrets: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Print a fresh base64 master key. The operator writes it to a file
/// (0600) referenced by `[secrets].key_file`, or exports it as
/// `E6IRC_SECRET_KEY`.
fn genkey() -> ExitCode {
    println!("{}", SecretKey::generate().to_base64());
    ExitCode::SUCCESS
}

/// Read plaintext from stdin and print its sealed `enc:v2:` form (bound to the
/// config-secret context), using the key from `--key-file` or the
/// `E6IRC_SECRET_KEY` env var. The output belongs in a config field (oper/OIDC/
/// server-network secret); per-account BNC passwords are sealed by the server.
fn seal(args: &[String]) -> ExitCode {
    let key = match load_seal_key(args) {
        Ok(k) => k,
        Err(msg) => {
            eprintln!("e6ircd seal: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut plaintext = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut plaintext) {
        eprintln!("e6ircd seal: cannot read stdin: {e}");
        return ExitCode::FAILURE;
    }
    // A trailing newline from a pipe or interactive entry is not part of
    // the secret.
    let plaintext = plaintext.strip_suffix('\n').unwrap_or(&plaintext);
    println!("{}", key.seal(plaintext, e6ircd::secret::CONFIG_CONTEXT));
    ExitCode::SUCCESS
}

fn load_seal_key(args: &[String]) -> Result<SecretKey, String> {
    match args {
        [] => {
            let v = std::env::var("E6IRC_SECRET_KEY")
                .map_err(|_| "no --key-file and E6IRC_SECRET_KEY is unset".to_string())?;
            SecretKey::from_base64(&v).map_err(|e| format!("E6IRC_SECRET_KEY: {e}"))
        }
        [flag, path] if flag == "--key-file" => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read key_file {path}: {e}"))?;
            SecretKey::from_base64(&raw).map_err(|e| format!("key_file: {e}"))
        }
        _ => Err(format!("bad arguments\n{USAGE}")),
    }
}

fn run(args: &[String]) -> ExitCode {
    let config = match load_config_or_fail(args, "e6ircd") {
        Ok(c) => c,
        Err(code) => return code,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        match net::start(config).await {
            Ok(running) => {
                let mut running = running;
                for addr in &running.addrs {
                    println!("listening on {addr}");
                }
                // Run until a termination signal arrives, then shut down
                // gracefully: stop accepting, notify clients, flush the PG write
                // queue (DESIGN §18). The flush is the correctness point — the
                // DB worker's buffered history must reach PostgreSQL, never be
                // dropped by an abrupt process exit.
                let critical_failure = tokio::select! {
                    () = wait_for_shutdown_signal() => None,
                    failure = running.shutdown.wait_for_critical_failure() => Some(failure),
                };
                if let Some(failure) = &critical_failure {
                    eprintln!("e6ircd: {failure}");
                } else {
                    eprintln!("e6ircd: shutting down");
                }
                match running.shutdown.run().await {
                    net::ShutdownOutcome::Flushed if critical_failure.is_none() => {
                        ExitCode::SUCCESS
                    }
                    net::ShutdownOutcome::Flushed => ExitCode::FAILURE,
                    net::ShutdownOutcome::FlushTimedOut => {
                        eprintln!(
                            "e6ircd: DB flush did not complete before timeout; \
                             buffered history may be lost"
                        );
                        ExitCode::FAILURE
                    }
                    net::ShutdownOutcome::WorkerPanicked => {
                        eprintln!("e6ircd: DB worker panicked during shutdown");
                        ExitCode::FAILURE
                    }
                    net::ShutdownOutcome::CoreTimedOut => {
                        eprintln!("e6ircd: a core worker did not stop before shutdown timeout");
                        ExitCode::FAILURE
                    }
                    net::ShutdownOutcome::CorePanicked => {
                        eprintln!("e6ircd: a core worker panicked during shutdown");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(e) => {
                eprintln!("e6ircd: failed to start: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Resolve once a shutdown signal is received. On Unix that is SIGTERM (what a
/// service manager or `docker stop` sends) or SIGINT (Ctrl-C). Elsewhere only
/// Ctrl-C is portable — Windows has no SIGTERM — and `ctrl_c` also covers the
/// Windows console close events, so the daemon still shuts down cleanly there
/// and, crucially, the workspace still compiles on the non-Unix CI targets.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // A failure to install a handler is a startup-class fault, not something
        // to swallow: without it we could never shut down cleanly.
        let mut sigterm =
            signal(SignalKind::terminate()).expect("install SIGTERM handler for graceful shutdown");
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.expect("install Ctrl-C handler for graceful shutdown");
            }
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler for graceful shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_failure(source: &str) -> String {
        let error = toml::from_str::<Config>(source).expect_err("unparsable configuration");
        describe_parse_error(error, Some(source))
    }

    #[test]
    fn a_parse_failure_names_the_position_and_never_quotes_the_line() {
        let pasted_with_carriage_return = "server_name = \"irc.example.test\"\n[database]\n\
             url = \"postgres://user:hunter2@db.example.test/e6irc\r\"\n";
        let failure = parse_failure(pasted_with_carriage_return);
        assert!(
            failure.starts_with("invalid config: line 3, column 53: "),
            "{failure}"
        );
        assert!(!failure.contains("hunter2"), "{failure}");
        assert!(!failure.contains('\n'), "{failure}");

        let unterminated = "server_name = \"irc.example.test\"\ntoken = \"hunter2";
        let failure = parse_failure(unterminated);
        assert!(failure.starts_with("invalid config: line 2, "), "{failure}");
        assert!(!failure.contains("hunter2"), "{failure}");
    }

    #[test]
    fn a_wrongly_shaped_value_names_its_key() {
        let failure = parse_failure("server_name = \"irc.example.test\"\nnetwork_name = 7\n");
        assert!(failure.contains("line 2, column 16"), "{failure}");
        assert!(failure.contains("expected a string"), "{failure}");

        let error = toml::from_str::<Config>("server_name = \"irc.example.test\"\n")
            .expect_err("a required field is missing");
        let failure = describe_parse_error(error, None);
        assert!(failure.contains("missing field"), "{failure}");
    }

    #[test]
    fn columns_count_characters_and_offsets_past_the_end_stay_on_the_last_line() {
        assert_eq!(line_and_column("", 0), (1, 1));
        assert_eq!(line_and_column("a = 1\nb = 2", 6), (2, 1));
        assert_eq!(line_and_column("a = \"é\" x", 9), (1, 9));
        assert_eq!(line_and_column("a = 1\nb = \"", 99), (2, 6));
    }
}
