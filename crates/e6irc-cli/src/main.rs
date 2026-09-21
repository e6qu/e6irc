//! e6irc — a scripting-oriented IRC CLI. Non-interactive subcommands
//! that connect, do one job, and exit with a clear status.

mod http;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use e6irc_client::credentials::{CredentialArguments, SecretSources, process_environment};
use e6irc_client::token_cache::default_token_path;
use e6irc_client::{
    CleartextCredentials, ClientEvent, Connection, ConnectionOptions, OwnedMessage, TerminalSafe,
    is_channel_target,
};
use serde::Serialize;

/// IRC numerics that mean a PRIVMSG was not delivered — `send` exists to
/// deliver one message, so any of these arriving during the post-send drain
/// must fail the command instead of exiting 0 on a message nobody received.
fn is_send_error(command: &str) -> bool {
    matches!(
        command,
        "400" | "401" | "402" | "404" | "407" | "411" | "412"
    )
}

/// Server-supplied text is untrusted (terminal control bytes retitle the
/// window / spoof output), so text printed for a person runs through the shared
/// [`TerminalSafe`] sanitizer. The two machine-readable outputs cannot — a
/// replacement character would change the data — and have their own rules:
/// [`tail_json`] escapes, and `e6irc api` decides by where stdout goes
/// ([`http::body_for_stdout`]).
fn terminal_safe(s: &str) -> TerminalSafe {
    TerminalSafe::from_untrusted(s)
}

/// The message in `event`, or a warning for input the client had to reject:
/// malformed input must neither disconnect the session nor disappear silently.
/// The warning is stderr so structured/stdout command output stays
/// machine-readable.
fn reported(event: ClientEvent) -> Option<OwnedMessage> {
    match event {
        ClientEvent::Message(message) => Some(message),
        ClientEvent::Rejected(rejected) => {
            eprintln!("warning: server input rejected: {rejected}");
            None
        }
    }
}

/// Read the next actionable message, reporting rejected input on the way.
async fn next_interactive_message(
    connection: &mut Connection,
) -> std::io::Result<Option<OwnedMessage>> {
    loop {
        match connection.next_event_lossy().await? {
            Some(event) => {
                if let Some(message) = reported(event) {
                    return Ok(Some(message));
                }
            }
            None => return Ok(None),
        }
    }
}

#[derive(Parser)]
#[command(name = "e6irc", about = "Scripting-oriented IRC client", version)]
struct Cli {
    /// Server address (host:port) for IRC commands.
    #[arg(long, short, global = true)]
    server: Option<String>,
    /// Nickname to register with IRC commands.
    #[arg(long, short, global = true)]
    nick: Option<String>,
    /// IRC user name (ident) sent in USER. When absent, --nick is used, and
    /// only if it is itself a legal user name (ASCII letters, digits, '_' and
    /// '-', starting with a letter or digit, at most 10 bytes). A nick that is
    /// not — `_bot`, `ada|away` — is never rewritten to fit: the command stops
    /// and asks for --username.
    #[arg(long, short, global = true)]
    username: Option<String>,
    /// SASL PLAIN account. Its password comes from --password-file, the
    /// E6IRC_PASSWORD environment variable, or --password.
    #[arg(long, global = true)]
    account: Option<String>,
    /// SASL PLAIN password. A value typed here is visible to every local user
    /// in the process list and is kept by the shell's history: prefer
    /// --password-file or E6IRC_PASSWORD.
    #[arg(long, global = true, conflicts_with = "password_file")]
    password: Option<String>,
    /// File holding the SASL PLAIN password (one trailing line break is
    /// dropped). Refused if group or other users can read it.
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,
    /// SASL OAUTHBEARER token; E6IRC_OAUTH_TOKEN when no flag is given. A value
    /// typed here is visible to other local users: prefer --oauth-token-file.
    #[arg(long, global = true, conflicts_with = "oauth_token_file")]
    oauth_token: Option<String>,
    /// File holding the SASL OAUTHBEARER token, under the same rules as
    /// --password-file.
    #[arg(long, global = true)]
    oauth_token_file: Option<PathBuf>,
    /// Load the SASL OAUTHBEARER token created by `e6irc login`.
    #[arg(long, global = true)]
    oauth_from_cache: bool,
    /// Token-cache path for login, API authentication, or --oauth-from-cache.
    /// Defaults to the current platform's private application-data directory.
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// Send SASL credentials over a connection without --tls to a server that
    /// is not this machine. Without this flag that is refused: the password or
    /// token would cross the network readable by anyone on the path.
    #[arg(long, global = true)]
    allow_cleartext_credentials: bool,
    /// Connect over TLS (validating against the public CA set).
    #[arg(long, global = true)]
    tls: bool,
    /// TLS server name (defaults to the host part of --server).
    #[arg(long, global = true)]
    tls_name: Option<String>,
    /// Seconds the server may take to finish registration, and afterwards to
    /// confirm a JOIN or answer a history request, before the command fails.
    #[arg(
        long,
        global = true,
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    response_timeout: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send one PRIVMSG to a target and exit.
    Send { target: String, message: String },
    /// Follow messages sent to a channel/nick, printing one per line.
    Tail {
        target: String,
        /// Stop after N messages (0 = forever).
        #[arg(long, default_value_t = 0)]
        count: usize,
        /// Emit one structured JSON object per message.
        #[arg(long)]
        json: bool,
    },
    /// Send raw lines read from stdin, then exit.
    Raw,
    /// Print the most recent history of a channel via CHATHISTORY.
    History {
        target: String,
        #[arg(long, default_value_t = 20)]
        count: usize,
    },
    /// Make one bounded authenticated HTTP/HTTPS REST API request and print
    /// the response body. Exit status is nonzero on a non-2xx response.
    Api {
        /// HTTP method (GET, POST, DELETE, …).
        method: String,
        /// Request path, e.g. /api/v1/me/networks.
        path: String,
        /// API base URL. Defaults to the cached login origin.
        #[arg(long)]
        base: Option<String>,
        /// Bearer token; E6IRC_API_TOKEN when no flag is given, then the login
        /// cache. A value typed here is visible to other local users: prefer
        /// --bearer-token-file or the environment.
        #[arg(long, conflicts_with = "bearer_token_file")]
        token: Option<String>,
        /// File holding the bearer token, under the same rules as
        /// --password-file. (The global --token-file names the login cache.)
        #[arg(long = "bearer-token-file")]
        bearer_token_file: Option<PathBuf>,
        /// JSON request body (for POST/PUT).
        #[arg(long)]
        body: Option<String>,
    },
    /// Authorize this client through the server's device login page and cache
    /// the resulting bearer token.
    Login {
        /// API origin hosting the device authorization endpoints.
        #[arg(long)]
        base: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("e6irc: runtime: {}", terminal_safe(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("e6irc: {}", terminal_safe(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> std::io::Result<()> {
    // HTTP-only commands run before any IRC transport is opened.
    if let Command::Login { base } = &cli.command {
        let cache_path = token_path(cli.token_file.as_deref())?;
        return http::login(base, &cache_path, cleartext_credentials(&cli)).await;
    }
    if let Command::Api {
        method,
        path,
        base,
        token,
        bearer_token_file,
        body,
    } = &cli.command
    {
        let token = SecretSources {
            argument: token.clone(),
            file: bearer_token_file.clone(),
        }
        .resolve(http::API_TOKEN_ENVIRONMENT, &process_environment)?;
        return http::api(
            method,
            path,
            base.as_deref(),
            token,
            body.clone(),
            cli.token_file.as_deref(),
            cleartext_credentials(&cli),
        )
        .await;
    }

    let server = irc_server(cli.server.as_deref())?;
    let nick = irc_nick(cli.nick.as_deref())?;
    let username = e6irc_client::stated_or_nick_username(cli.username.as_deref(), nick)?;
    let authentication = CredentialArguments {
        account: cli.account.clone(),
        password: SecretSources {
            argument: cli.password.clone(),
            file: cli.password_file.clone(),
        },
        oauth_token: SecretSources {
            argument: cli.oauth_token.clone(),
            file: cli.oauth_token_file.clone(),
        },
        oauth_from_cache: cli.oauth_from_cache,
        token_file: cli.token_file.clone(),
    }
    .resolve(&process_environment)?;
    let mut conn = ConnectionOptions {
        address: server.to_owned(),
        tls: cli.tls,
        tls_server_name: cli.tls_name.clone(),
        nick: nick.to_owned(),
        username,
        realname: "e6irc-cli".into(),
        authentication,
        response_deadline: std::time::Duration::from_secs(cli.response_timeout),
        cleartext_credentials: cleartext_credentials(&cli),
    }
    .connect_registered()
    .await?
    .connection;
    match cli.command {
        Command::Send { target, message } => {
            // Channels are +n by default, so join before speaking and
            // wait for the join to be confirmed.
            if is_channel_target(&target) {
                // A refused or unconfirmed join is an error here: falling
                // through to PRIVMSG would exit 0 on a message nobody got.
                for event in conn.join_with_latest_history(&target, 0).await? {
                    reported(event);
                }
            }
            conn.send_line(&format!("PRIVMSG {target} :{message}"))
                .await?;
            conn.send_line("QUIT :done").await?;
            // Drain until the server closes so the message is flushed — but a
            // delivery-failure numeric in this window (401 no such nick, 404
            // cannot send to channel, …) means nobody received the message,
            // and the exit code is this tool's product.
            while let Some(msg) = next_interactive_message(&mut conn).await? {
                if is_send_error(&msg.command) {
                    let reason = terminal_safe(&msg.params.last().cloned().unwrap_or_default());
                    return Err(std::io::Error::other(format!(
                        "cannot send to {target}: {reason}"
                    )));
                }
            }
        }
        Command::Tail {
            target,
            count,
            json,
        } => {
            let wanted = (count != 0).then_some(count);
            let mut seen = 0;
            let mut print = |message: &OwnedMessage| -> std::io::Result<bool> {
                // The server relays a channel message with the *sender's*
                // spelling of the target, so the comparison must fold case
                // under the server's rfc1459 mapping — a raw equality would
                // silently miss messages sent to a differently-cased name.
                if message.command != "PRIVMSG"
                    || !message
                        .params
                        .first()
                        .is_some_and(|t| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(t, &target))
                {
                    return Ok(false);
                }
                let from = message.source.as_deref().unwrap_or("?");
                let text = message.params.get(1).map(String::as_str).unwrap_or("");
                if json {
                    println!("{}", tail_json(message, from, text)?);
                } else {
                    println!("{}\t{}", terminal_safe(from), terminal_safe(text));
                }
                seen += 1;
                Ok(wanted.is_some_and(|wanted| seen >= wanted))
            };
            let mut done = false;
            if is_channel_target(&target) {
                // Messages relayed while the join is confirmed are part of the
                // stream being followed.
                for event in conn.join_with_latest_history(&target, 0).await? {
                    if let Some(message) = reported(event)
                        && !done
                    {
                        done = print(&message)?;
                    }
                }
            }
            while !done {
                let Some(message) = next_interactive_message(&mut conn).await? else {
                    break;
                };
                if message.command == "PING" {
                    let token = message.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                    continue;
                }
                done = print(&message)?;
            }
            // Only a bounded tail that printed everything it promised has a
            // successful end. One that was cut short delivered less than a
            // script reading N lines was told to expect, and an unbounded one
            // stops by itself only when the server goes away — which whatever
            // supervises it has to be able to see.
            if !done {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    match wanted {
                        Some(wanted) => {
                            format!("connection closed after {seen} of {wanted} messages")
                        }
                        None => format!("connection closed after {seen} messages"),
                    },
                ));
            }
        }
        Command::History { target, count } => {
            conn.require_capabilities(&["batch", "draft/chathistory", "server-time"])
                .await?;
            for event in conn.join_with_latest_history(&target, count).await? {
                let Some(message) = reported(event) else {
                    continue;
                };
                if matches!(message.command.as_str(), "PRIVMSG" | "NOTICE")
                    && message.params.first().is_some_and(|candidate| {
                        e6irc_proto::casemap::CaseMapping::Rfc1459.eq(candidate, &target)
                    })
                {
                    let from = message
                        .source
                        .as_deref()
                        .and_then(|source| source.split('!').next())
                        .unwrap_or("?");
                    let text = message.params.get(1).map(String::as_str).unwrap_or("");
                    println!("{}\t{}", terminal_safe(from), terminal_safe(text));
                }
            }
            conn.send_line("QUIT :done").await?;
            while next_interactive_message(&mut conn).await?.is_some() {}
        }
        Command::Raw => {
            use tokio::io::AsyncBufReadExt;
            // Read stdin asynchronously and keep servicing the socket between
            // lines — a blocking stdin read on this current-thread runtime
            // would leave server PINGs unanswered while a slow producer (a
            // pipe with pauses) feeds us, getting the session ping-timed-out
            // and the late lines written into a dead socket.
            let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            loop {
                tokio::select! {
                    line = stdin.next_line() => {
                        let Some(line) = line? else {
                            break; // stdin exhausted
                        };
                        conn.send_line(&line).await?;
                    }
                    msg = next_interactive_message(&mut conn) => {
                        let Some(msg) = msg? else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "server closed the connection before stdin was exhausted",
                            ));
                        };
                        if msg.command == "PING" {
                            let token = msg.params.first().cloned().unwrap_or_default();
                            conn.send_line(&format!("PONG :{token}")).await?;
                        }
                    }
                }
            }
            conn.send_line("QUIT :done").await?;
            while next_interactive_message(&mut conn).await?.is_some() {}
        }
        Command::Api { .. } | Command::Login { .. } => {
            unreachable!("handled before the IRC connect")
        }
    }
    Ok(())
}

fn cleartext_credentials(cli: &Cli) -> CleartextCredentials {
    if cli.allow_cleartext_credentials {
        CleartextCredentials::Allow
    } else {
        CleartextCredentials::Refuse
    }
}

fn irc_server(server: Option<&str>) -> std::io::Result<&str> {
    irc_argument(server, "--server")
}

fn irc_nick(nick: Option<&str>) -> std::io::Result<&str> {
    irc_argument(nick, "--nick")
}

fn irc_argument<'a>(value: Option<&'a str>, flag: &str) -> std::io::Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{flag} is required for IRC commands"),
            )
        })
}

fn token_path(explicit: Option<&Path>) -> std::io::Result<PathBuf> {
    explicit
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(default_token_path)
}

#[derive(Serialize)]
struct JsonTag<'a> {
    key: &'a str,
    value: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonTail<'a> {
    source: &'a str,
    target: &'a str,
    text: &'a str,
    tags: Vec<JsonTag<'a>>,
}

fn tail_json(
    message: &e6irc_client::OwnedMessage,
    source: &str,
    text: &str,
) -> std::io::Result<String> {
    let target = message.params.first().map(String::as_str).unwrap_or("");
    let tags = message
        .tags
        .iter()
        .map(|(key, value)| JsonTag {
            key,
            value: value.as_deref(),
        })
        .collect();
    let json = serde_json::to_string(&JsonTail {
        source,
        target,
        text,
        tags,
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(escape_remaining_controls(&json))
}

/// JSON obliges a serializer to escape only C0, so DEL and C1 — which includes
/// the one-byte CSI (U+009B) a terminal obeys — come out raw. In compact JSON a
/// control character can only be inside a string, where `\uXXXX` is the same
/// value: a consumer on a pipe decodes exactly what was sent, and a terminal
/// sees nothing it would act on. One output therefore serves both, with no
/// need to ask where stdout goes.
fn escape_remaining_controls(json: &str) -> String {
    let mut escaped = String::with_capacity(json.len());
    for character in json.chars() {
        if character.is_control() {
            escaped.push_str(&format!("\\u{:04x}", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `e6irc <options> send nick hello` parses.
    fn send_parses(options: &[&str]) -> bool {
        Cli::try_parse_from(
            ["e6irc"]
                .into_iter()
                .chain(options.iter().copied())
                .chain(["send", "nick", "hello"]),
        )
        .is_ok()
    }

    #[test]
    fn authentication_shapes_are_explicit() {
        let server = ["--server", "irc.example:6697"];
        let with = |extra: &[&str]| send_parses(&[&server, extra].concat());
        assert!(with(&[]));
        assert!(with(&["--account", "alice", "--password", "secret"]));
        assert!(with(&["--oauth-token", "token"]));
        assert!(with(&["--oauth-from-cache"]));
        // An account's password may come from the environment, which only
        // resolution can see; what parsing refuses is one secret given twice.
        assert!(with(&["--account", "alice"]));
        assert!(with(&["--account", "alice", "--password-file", "pw"]));
        assert!(!with(&["--password", "typed", "--password-file", "pw"]));
        assert!(!with(&[
            "--oauth-token",
            "typed",
            "--oauth-token-file",
            "token"
        ]));
        assert!(with(&["--allow-cleartext-credentials"]));
    }

    #[test]
    fn the_api_token_has_the_same_three_sources() {
        let api = |extra: &[&str]| {
            Cli::try_parse_from(
                ["e6irc", "api", "GET", "/api/v1/me"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .is_ok()
        };
        assert!(api(&[]));
        assert!(api(&["--token", "typed"]));
        assert!(api(&["--bearer-token-file", "token"]));
        assert!(!api(&["--token", "typed", "--bearer-token-file", "token"]));
    }

    #[test]
    fn the_response_timeout_is_bounded_at_argument_parsing() {
        assert!(send_parses(&["--response-timeout", "600"]));
        assert!(!send_parses(&["--response-timeout", "0"]));
        assert!(!send_parses(&["--response-timeout", "601"]));
    }

    #[test]
    fn irc_commands_require_a_server() {
        assert_eq!(
            irc_server(Some("irc.example:6697")).unwrap(),
            "irc.example:6697"
        );
        assert!(irc_server(None).is_err());
        assert!(irc_server(Some(" ")).is_err());
    }

    #[test]
    fn irc_commands_require_a_nickname() {
        assert_eq!(irc_nick(Some("alice")).unwrap(), "alice");
        assert!(irc_nick(None).is_err());
        assert!(irc_nick(Some(" ")).is_err());
    }

    #[test]
    fn login_requires_an_api_origin() {
        assert!(Cli::try_parse_from(["e6irc", "login"]).is_err());
        assert!(Cli::try_parse_from(["e6irc", "login", "--base", "https://irc.example"]).is_ok());
    }

    #[test]
    fn json_tail_is_structured_and_escapes_controls() {
        let message = e6irc_client::OwnedMessage {
            tags: vec![
                ("time".into(), Some("2026-07-30T00:00:00.000Z".into())),
                ("flag".into(), None),
            ],
            source: Some("alice!u@h".into()),
            command: "PRIVMSG".into(),
            params: vec!["#room".into(), "hello\u{1b}[2J".into()],
        };
        let output = tail_json(&message, "alice!u@h", &message.params[1]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["source"], "alice!u@h");
        assert_eq!(parsed["target"], "#room");
        assert_eq!(parsed["text"], "hello\u{1b}[2J");
        assert_eq!(parsed["tags"][1]["key"], "flag");
        assert_eq!(parsed["tags"][1]["value"], serde_json::Value::Null);
        assert!(!output.contains('\u{1b}'), "control must be JSON-escaped");
    }

    /// JSON only requires C0 to be escaped, so a serializer leaves DEL and C1
    /// raw — and C1 includes the one-byte CSI a terminal obeys. Escaping them is
    /// still the same JSON value, so a consumer on a pipe loses nothing.
    #[test]
    fn json_tail_escapes_every_control_character_without_changing_the_value() {
        let hostile = "a\u{7f}b\u{9b}2Jc\u{85}d";
        let message = e6irc_client::OwnedMessage {
            tags: vec![("+draft/label".into(), Some(hostile.into()))],
            source: Some("alice!u@h".into()),
            command: "PRIVMSG".into(),
            params: vec!["#room".into(), hostile.into()],
        };
        let output = tail_json(&message, "alice!u@h", hostile).unwrap();
        assert!(
            !output.chars().any(char::is_control),
            "a raw control character reached the terminal: {output:?}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["text"], hostile);
        assert_eq!(parsed["tags"][0]["value"], hostile);
    }
}
