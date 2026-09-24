use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use e6ircd::config::{Config, ConfigError};
use e6ircd::environment_config;
use e6ircd::net;
use e6ircd::secret::SecretKey;

const USAGE: &str = "usage:\n  \
    e6ircd [<configuration>]        run the server\n  \
    e6ircd check-config [<configuration>]\n  \
                                     validate configuration and exit\n  \
    e6ircd genkey                   print a new base64 master key\n  \
    e6ircd seal [--key-file <path>] seal stdin into an enc:v2: blob\n  \
    e6ircd rotate-secrets [<configuration>]\n  \
                                     atomically re-seal database secrets\n  \
    e6ircd recover-administrator --account <name> [<configuration>]\n  \
                                     lost every administrator login: give one\n  \
                                     existing account a new one-time password\n  \
                                     and administrator authority (audited)\n  \
    e6ircd healthcheck [--addr <ip:port>] [--ready]\n  \
                                     probe the running server's /healthz (or\n  \
                                     /readyz); exit 0 only on HTTP 200. The\n  \
                                     address is --addr, else E6IRC_HTTP_ADDR,\n  \
                                     else that variable's default\n\
<configuration> is one of:\n  \
    --config <path>                 a TOML file (default: e6irc.toml)\n  \
    --config-from-environment       the E6IRC_* variables a container is\n  \
                                     given, read in memory; nothing is written";

fn main() -> ExitCode {
    // Every subcommand handles secrets (the master key, sealed credentials, a
    // recovery password), so none of them may leave a core file behind.
    #[cfg(target_os = "linux")]
    if let Err(error) = e6ircd::secret::mark_process_non_dumpable() {
        eprintln!(
            "e6ircd: WARNING: could not mark the process non-dumpable \
             (prctl PR_SET_DUMPABLE): {error}; a core file or a same-user debugger \
             could read the master key and opened credentials"
        );
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("genkey") => genkey(),
        Some("seal") => seal(&args[1..]),
        Some("rotate-secrets") => rotate_secrets(&args[1..]),
        Some("recover-administrator") => recover_administrator(&args[1..]),
        Some("check-config") => check_config(&args[1..]),
        Some("healthcheck") => healthcheck(&args[1..]),
        _ => run(&args),
    }
}

/// The whole probe -- connect, write, read -- must finish inside this, so a
/// container runtime's own health timeout never has to kill it.
const HEALTHCHECK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// `e6ircd healthcheck`: the image's `HEALTHCHECK`. The runtime image has no
/// HTTP client, so this is the daemon probing itself: it takes the address from
/// the same environment variable, with the same default, as the server the
/// image runs, and speaks one plain HTTP request over `std::net`. Exit 0 only on 200, 1 with one reason line otherwise, 2 for
/// a usage error. It prints nothing taken from the environment but the address.
fn healthcheck(args: &[String]) -> ExitCode {
    let mut addr = None;
    let mut path = "/healthz";
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--ready" => path = "/readyz",
            "--addr" => match rest.next() {
                Some(value) => addr = Some(value.clone()),
                None => return usage_error(),
            },
            _ => return usage_error(),
        }
    }
    let configured = match addr {
        Some(addr) => addr,
        None => match environment_config::http_addr(&environment_config::process_environment) {
            Ok(addr) => addr,
            Err(error) => {
                eprintln!("e6ircd healthcheck: {error}");
                return ExitCode::from(2);
            }
        },
    };
    let Ok(listener) = configured.parse::<std::net::SocketAddr>() else {
        eprintln!("e6ircd healthcheck: {configured:?} is not an ip:port address");
        return ExitCode::from(2);
    };
    match probe(probe_target(listener), path, HEALTHCHECK_DEADLINE) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("e6ircd healthcheck: {path} on {listener}: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// A listener bound to the unspecified address is reached on loopback of the
/// same family; any other bind address is dialled as it is.
fn probe_target(listener: std::net::SocketAddr) -> std::net::SocketAddr {
    let ip = match listener.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    std::net::SocketAddr::new(ip, listener.port())
}

fn probe(
    target: std::net::SocketAddr,
    path: &str,
    deadline: std::time::Duration,
) -> Result<(), String> {
    use std::io::Write;
    let started = std::time::Instant::now();
    let remaining = || {
        deadline
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| "timed out".to_string())
    };
    let mut stream = std::net::TcpStream::connect_timeout(&target, remaining()?)
        .map_err(|error| format!("cannot connect: {}", error.kind()))?;
    let (write_timeout, read_timeout) = (remaining()?, remaining()?);
    stream
        .set_write_timeout(Some(write_timeout))
        .and_then(|()| stream.set_read_timeout(Some(read_timeout)))
        .map_err(|error| format!("cannot bound the probe: {}", error.kind()))?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|error| format!("cannot send the request: {}", error.kind()))?;
    // "HTTP/1.1 200" is twelve bytes; nothing after the status code matters.
    let mut head = [0u8; 12];
    let mut filled = 0;
    while filled < head.len() {
        stream
            .set_read_timeout(Some(remaining()?))
            .map_err(|error| format!("cannot bound the probe: {}", error.kind()))?;
        match stream.read(&mut head[filled..]) {
            Ok(0) => return Err("the server closed the connection without answering".into()),
            Ok(read) => filled += read,
            Err(error) => return Err(format!("no answer: {}", error.kind())),
        }
    }
    // Compared as bytes: the answer is untrusted, and slicing it as text at a
    // fixed offset would panic on a multi-byte character across that offset.
    match head.split_at(9) {
        (version, status) if version.starts_with(b"HTTP/1.") && version[8] == b' ' => {
            match status {
                b"200" => Ok(()),
                status => Err(format!("status {}", String::from_utf8_lossy(status))),
            }
        }
        _ => Err("the answer is not HTTP".into()),
    }
}

fn check_config(args: &[String]) -> ExitCode {
    match load_config_or_fail(args, "e6ircd check-config") {
        Ok(_) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Where the configuration is stated: exactly one of a file and the
/// environment. Every subcommand that needs the configuration takes either, so
/// each of them runs in a container that has no file to point at.
#[derive(Debug, PartialEq, Eq)]
enum ConfigSource {
    File(PathBuf),
    Environment,
}

impl ConfigSource {
    fn from_arguments(args: &[String]) -> Result<Self, ()> {
        match args {
            [] => Ok(Self::File(PathBuf::from("e6irc.toml"))),
            [flag, path] if flag == "--config" => Ok(Self::File(PathBuf::from(path))),
            [flag] if flag == "--config-from-environment" => Ok(Self::Environment),
            _ => Err(()),
        }
    }

    /// The configuration, or the one-line reason there is none. No reason
    /// quotes a value: a file's offending line and an environment variable's
    /// content are each as likely a secret as not.
    fn load(&self) -> Result<Config, String> {
        let (loaded, source, origin) = match self {
            Self::File(path) => (
                Config::load(path),
                std::fs::read_to_string(path).ok(),
                path.display().to_string(),
            ),
            Self::Environment => (
                environment_config::configuration_table(&environment_config::process_environment)
                    .map_err(|error| ConfigError::Invalid(error.to_string()))
                    .and_then(Config::from_table),
                None,
                "the environment".to_owned(),
            ),
        };
        loaded.map_err(|error| {
            let failure = match error {
                ConfigError::Parse(parse) => describe_parse_error(parse, source.as_deref()),
                other => other.to_string(),
            };
            format!("{failure} ({origin})")
        })
    }
}

/// Resolve where the configuration is stated and load it, or print a
/// diagnostic and return `FAILURE`. `context` is the error prefix (`"e6ircd"`
/// for the main command, `"e6ircd rotate-secrets"` for the subcommand).
fn load_config_or_fail(args: &[String], context: &str) -> Result<Config, ExitCode> {
    let Ok(source) = ConfigSource::from_arguments(args) else {
        eprintln!("{USAGE}");
        return Err(ExitCode::FAILURE);
    };
    source.load().map_err(|failure| {
        eprintln!("{context}: {failure}");
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
            // The repair differs by ingress: a file names key files, the
            // environment names the keys themselves.
            let repair = if args.iter().any(|arg| arg == "--config-from-environment") {
                "set E6IRC_SECRET_KEY to the new key and E6IRC_PREVIOUS_SECRET_KEYS to the \
                 old one(s)"
            } else {
                "configure the new key_file primary and at least one previous_key_files entry"
            };
            eprintln!("e6ircd rotate-secrets: {repair} before rotating");
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

/// The operator's way back in when no administrator can sign in: every
/// administrator credential is lost, or the identity provider behind them is
/// broken. Reaching it takes what only the host's operator has — this binary,
/// the configuration file, and through it the database — and nothing about it
/// is reachable from the network or happens by itself. One run recovers one
/// named account (see [`e6ircd::db::recover_administrator`]). The new password
/// and the administrator authority both work at once: a running server reads
/// an account's authority from the database on every request.
fn recover_administrator(args: &[String]) -> ExitCode {
    const CONTEXT: &str = "e6ircd recover-administrator";
    let (account, config_args) = match args {
        [flag, account, rest @ ..] if flag == "--account" && !account.is_empty() => (account, rest),
        _ => {
            eprintln!("{CONTEXT}: name the account to recover with --account <name>\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let config = match load_config_or_fail(config_args, CONTEXT) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let Some(database) = config.database else {
        eprintln!("{CONTEXT}: [database] is required; accounts live there");
        return ExitCode::FAILURE;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(async {
        let pool = e6ircd::db::connect_and_migrate(&database.url).await?;
        e6ircd::db::recover_administrator(&pool, account).await
    }) {
        Ok(recovery) => {
            eprintln!(
                "{CONTEXT}: account {} now has administrator authority and a new local \
                 password, printed once below. Every credential it held was revoked: its \
                 app passwords, personal access tokens, device grants, and browser \
                 sessions. The audit log records this. A running e6ircd honours the \
                 authority at once; sign in at /login and change the password.",
                recovery.account
            );
            println!("{}", recovery.password);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{CONTEXT}: {error}; nothing was changed");
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
            SecretKey::from_base64_text(v).map_err(|e| format!("E6IRC_SECRET_KEY: {e}"))
        }
        [flag, path] if flag == "--key-file" => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read key_file {path}: {e}"))?;
            SecretKey::from_base64_text(raw).map_err(|e| format!("key_file: {e}"))
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

    /// A one-shot HTTP peer answering every connection with `response`.
    fn answering(response: &'static [u8]) -> std::net::SocketAddr {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            if let Ok((mut peer, _)) = listener.accept() {
                let mut request = [0u8; 256];
                // The probe sends its request first; read some of it so the
                // close below is not a reset racing the client's write.
                drop(peer.read(&mut request));
                drop(peer.write_all(response));
            }
        });
        addr
    }

    #[test]
    fn the_health_probe_succeeds_only_on_200() {
        let second = std::time::Duration::from_secs(1);
        assert_eq!(
            probe(answering(b"HTTP/1.1 200 OK\r\n\r\nok"), "/healthz", second),
            Ok(())
        );
        assert_eq!(
            probe(
                answering(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"),
                "/readyz",
                second
            ),
            Err("status 503".to_string())
        );
        assert_eq!(
            probe(answering(b"SSH-2.0-OpenSSH_9\r\n"), "/healthz", second),
            Err("the answer is not HTTP".to_string())
        );
        // 'é' straddles byte 8, where a text slice at a fixed offset panics.
        assert_eq!(
            probe(
                answering("HTTP/1.é 200\r\n\r\n".as_bytes()),
                "/healthz",
                second
            ),
            Err("the answer is not HTTP".to_string())
        );
        assert_eq!(
            probe(answering(b""), "/healthz", second),
            Err("the server closed the connection without answering".to_string())
        );
    }

    #[test]
    fn the_health_probe_gives_up_at_its_deadline_and_on_a_closed_port() {
        // Accepts and then says nothing.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = silent.local_addr().expect("address");
        let started = std::time::Instant::now();
        let result = probe(addr, "/healthz", std::time::Duration::from_millis(300));
        assert!(result.is_err(), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        drop(silent);
        let refused = probe(addr, "/healthz", std::time::Duration::from_millis(300))
            .expect_err("nothing listens there any more");
        assert!(refused.starts_with("cannot connect"), "{refused}");
    }

    #[test]
    fn an_unspecified_bind_address_is_probed_on_loopback_of_its_family() {
        let target = |addr: &str| probe_target(addr.parse().expect("address")).to_string();
        assert_eq!(target("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(target("[::]:8080"), "[::1]:8080");
        assert_eq!(target("10.1.2.3:9000"), "10.1.2.3:9000");
    }

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
