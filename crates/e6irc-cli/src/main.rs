//! e6irc — a scripting-oriented IRC CLI. Non-interactive subcommands
//! that connect, do one job, and exit with a clear status.

mod http;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use e6irc_client::token_cache::{default_token_path, load_token};
use e6irc_client::{
    Authentication, ClientEvent, Connection, ConnectionOptions, OwnedMessage, TerminalSafe,
    is_join_refusal,
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
/// window / spoof output), so every display path runs it through the shared
/// [`TerminalSafe`] sanitizer before it reaches the user's terminal.
fn terminal_safe(s: &str) -> TerminalSafe {
    TerminalSafe::from_untrusted(s)
}

/// Read one actionable message without letting malformed input either
/// disconnect the session or disappear silently. The warning is stderr so
/// structured/stdout command output remains machine-readable.
async fn next_interactive_message(
    connection: &mut Connection,
) -> std::io::Result<Option<OwnedMessage>> {
    loop {
        match connection.next_event_lossy().await? {
            Some(ClientEvent::Message(message)) => return Ok(Some(message)),
            Some(ClientEvent::Rejected(rejected)) => {
                eprintln!("warning: server input rejected: {rejected}");
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
    /// SASL account (enables SASL PLAIN when set with --password).
    #[arg(
        long,
        global = true,
        requires = "password",
        conflicts_with_all = ["oauth_token", "oauth_from_cache"]
    )]
    account: Option<String>,
    /// SASL password.
    #[arg(
        long,
        global = true,
        requires = "account",
        conflicts_with_all = ["oauth_token", "oauth_from_cache"]
    )]
    password: Option<String>,
    /// SASL OAUTHBEARER token.
    #[arg(
        long,
        global = true,
        conflicts_with_all = ["account", "password", "oauth_from_cache"]
    )]
    oauth_token: Option<String>,
    /// Load the SASL OAUTHBEARER token created by `e6irc login`.
    #[arg(
        long,
        global = true,
        conflicts_with_all = ["account", "password", "oauth_token"]
    )]
    oauth_from_cache: bool,
    /// Token-cache path for login, API authentication, or --oauth-from-cache.
    /// Defaults to the current platform's private application-data directory.
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// Connect over TLS (validating against the public CA set).
    #[arg(long, global = true)]
    tls: bool,
    /// TLS server name (defaults to the host part of --server).
    #[arg(long, global = true)]
    tls_name: Option<String>,
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
        /// Bearer token; falls back to E6IRC_API_TOKEN, then the login cache.
        #[arg(long)]
        token: Option<String>,
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
        return http::login(base, &cache_path).await;
    }
    if let Command::Api {
        method,
        path,
        base,
        token,
        body,
    } = &cli.command
    {
        return http::api(
            method,
            path,
            base.as_deref(),
            token.clone(),
            body.clone(),
            cli.token_file.as_deref(),
        )
        .await;
    }

    let server = irc_server(cli.server.as_deref())?;
    let nick = irc_nick(cli.nick.as_deref())?;
    let authentication = match (
        &cli.account,
        &cli.password,
        &cli.oauth_token,
        cli.oauth_from_cache,
    ) {
        (Some(account), Some(password), None, false) => Authentication::Plain {
            account: account.clone(),
            password: password.clone(),
        },
        (None, None, Some(token), false) => Authentication::OAuthBearer {
            token: token.clone(),
        },
        (None, None, None, true) => {
            let path = token_path(cli.token_file.as_deref())?;
            let token = load_token(&path)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no cached token at {}; run e6irc login", path.display()),
                )
            })?;
            Authentication::OAuthBearer {
                token: token.access_token().to_owned(),
            }
        }
        (None, None, None, false) => Authentication::None,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "choose anonymous, paired --account/--password, --oauth-token, or --oauth-from-cache",
            ));
        }
    };
    let mut conn = ConnectionOptions {
        address: server.to_owned(),
        tls: cli.tls,
        tls_server_name: cli.tls_name.clone(),
        nick: nick.to_owned(),
        realname: "e6irc-cli".into(),
        authentication,
    }
    .connect_registered()
    .await?;
    match cli.command {
        Command::Send { target, message } => {
            // Channels are +n by default, so join before speaking and
            // wait for the join to be confirmed.
            if target.starts_with('#') {
                conn.send_line(&format!("JOIN {target}")).await?;
                loop {
                    // A close before 366 means the message was never sent —
                    // falling through to PRIVMSG would write into a dead
                    // socket and exit 0 on a delivery that never happened.
                    let Some(msg) = next_interactive_message(&mut conn).await? else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("connection closed before the join to {target} was confirmed"),
                        ));
                    };
                    if msg.command == "366" {
                        break; // end of NAMES = joined
                    }
                    if is_join_refusal(&msg.command) {
                        let reason = terminal_safe(&msg.params.last().cloned().unwrap_or_default());
                        return Err(std::io::Error::other(format!(
                            "cannot join {target}: {reason}"
                        )));
                    }
                    if msg.command == "PING" {
                        let token = msg.params.first().cloned().unwrap_or_default();
                        conn.send_line(&format!("PONG :{token}")).await?;
                    }
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
            if target.starts_with('#') {
                conn.send_line(&format!("JOIN {target}")).await?;
            }
            let mut seen = 0;
            while let Some(msg) = next_interactive_message(&mut conn).await? {
                if msg.command == "PING" {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                    continue;
                }
                // A refused JOIN must be reported, not waited on forever — the
                // same loud failure Send and History give.
                if target.starts_with('#') && is_join_refusal(&msg.command) {
                    let reason = terminal_safe(&msg.params.last().cloned().unwrap_or_default());
                    return Err(std::io::Error::other(format!(
                        "cannot join {target}: {reason}"
                    )));
                }
                // The server relays a channel message with the *sender's*
                // spelling of the target, so the comparison must fold case
                // under the server's rfc1459 mapping — a raw equality would
                // silently miss messages sent to a differently-cased name.
                if msg.command == "PRIVMSG"
                    && msg
                        .params
                        .first()
                        .is_some_and(|t| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(t, &target))
                {
                    let from = msg.source.as_deref().unwrap_or("?");
                    let text = msg.params.get(1).map(String::as_str).unwrap_or("");
                    if json {
                        println!("{}", tail_json(&msg, from, text)?);
                    } else {
                        println!("{}\t{}", terminal_safe(from), terminal_safe(text));
                    }
                    seen += 1;
                    if count != 0 && seen >= count {
                        break;
                    }
                }
            }
            // A bounded tail that ends early delivered less than it promised —
            // a script reading N lines must not see success on a truncation.
            if count != 0 && seen < count {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("connection closed after {seen} of {count} messages"),
                ));
            }
        }
        Command::History { target, count } => {
            conn.require_capabilities(&["batch", "draft/chathistory", "server-time"])
                .await?;
            for message in conn.join_with_latest_history(&target, count).await? {
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
    serde_json::to_string(&JsonTail {
        source,
        target,
        text,
        tags,
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_errors_are_recognized() {
        assert!(is_join_refusal("475"));
        assert!(!is_join_refusal("366"));
    }

    #[test]
    fn authentication_shapes_are_explicit() {
        assert!(
            Cli::try_parse_from([
                "e6irc",
                "--server",
                "irc.example:6697",
                "send",
                "nick",
                "hello"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc",
                "--server",
                "irc.example:6697",
                "--account",
                "alice",
                "--password",
                "secret",
                "send",
                "nick",
                "hello",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc",
                "--server",
                "irc.example:6697",
                "--oauth-token",
                "token",
                "send",
                "nick",
                "hello",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc",
                "--server",
                "irc.example:6697",
                "--oauth-from-cache",
                "send",
                "nick",
                "hello",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["e6irc", "--account", "alice", "send", "nick", "hello"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc",
                "--oauth-token",
                "token",
                "--oauth-from-cache",
                "send",
                "nick",
                "hello",
            ])
            .is_err()
        );
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
}
