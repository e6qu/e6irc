//! e6irc — a scripting-oriented IRC CLI. Non-interactive subcommands
//! that connect, do one job, and exit with a clear status.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use e6irc_client::Connection;

/// IRC numerics that mean a JOIN was refused — so a `send`/`history` client
/// bails with a clear error instead of waiting forever for a 366 that will
/// never arrive.
fn is_join_error(command: &str) -> bool {
    matches!(
        command,
        "403" | "405" | "471" | "473" | "474" | "475" | "476" | "477" | "480"
    )
}

/// IRC numerics that mean a PRIVMSG was not delivered — `send` exists to
/// deliver one message, so any of these arriving during the post-send drain
/// must fail the command instead of exiting 0 on a message nobody received.
fn is_send_error(command: &str) -> bool {
    matches!(
        command,
        "400" | "401" | "402" | "404" | "407" | "411" | "412"
    )
}

#[derive(Parser)]
#[command(name = "e6irc", about = "Scripting-oriented IRC client", version)]
struct Cli {
    /// Server address (host:port).
    #[arg(long, short, default_value = "127.0.0.1:6667", global = true)]
    server: String,
    /// Nickname to register with.
    #[arg(long, short, default_value = "e6irc", global = true)]
    nick: String,
    /// SASL account (enables SASL PLAIN when set with --password).
    #[arg(long, global = true)]
    account: Option<String>,
    /// SASL password.
    #[arg(long, global = true)]
    password: Option<String>,
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
    },
    /// Send raw lines read from stdin, then exit.
    Raw,
    /// Print the most recent history of a channel via CHATHISTORY.
    History {
        target: String,
        #[arg(long, default_value_t = 20)]
        count: usize,
    },
    /// Make one authenticated REST API request and print the response
    /// body. Plain HTTP only — front the API with a TLS-terminating proxy
    /// for remote use. Exit status is nonzero on a non-2xx response.
    Api {
        /// HTTP method (GET, POST, DELETE, …).
        method: String,
        /// Request path, e.g. /api/v1/me/networks.
        path: String,
        /// API base URL (http://host:port).
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        base: String,
        /// Bearer token; falls back to the E6IRC_API_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        /// JSON request body (for POST/PUT).
        #[arg(long)]
        body: Option<String>,
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
            eprintln!("e6irc: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("e6irc: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> std::io::Result<()> {
    // The `api` command speaks HTTP, not IRC — handle it before the IRC
    // connection is opened.
    if let Command::Api {
        method,
        path,
        base,
        token,
        body,
    } = &cli.command
    {
        return run_api(method, path, base, token.clone(), body.clone()).await;
    }

    let mut conn = if cli.tls {
        let name = cli.tls_name.clone().unwrap_or_else(|| {
            cli.server
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| cli.server.clone())
        });
        Connection::connect_tls(&cli.server, &name, e6irc_client::webpki_root_store()).await?
    } else {
        Connection::connect(&cli.server).await?
    };
    match (&cli.account, &cli.password) {
        (Some(account), Some(password)) => {
            conn.register_sasl(&cli.nick, "e6irc-cli", account, password)
                .await?;
        }
        (None, None) => {
            conn.register(&cli.nick, "e6irc-cli").await?;
        }
        // One credential without the other is a mistake — registering
        // unauthenticated instead of what the user asked for would be a silent
        // fallback of a client-observable option.
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--account and --password must be given together",
            ));
        }
    }
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
                    let Some(msg) = conn.next_message().await? else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("connection closed before the join to {target} was confirmed"),
                        ));
                    };
                    if msg.command == "366" {
                        break; // end of NAMES = joined
                    }
                    if is_join_error(&msg.command) {
                        let reason = msg.params.last().cloned().unwrap_or_default();
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
            while let Some(msg) = conn.next_message().await? {
                if is_send_error(&msg.command) {
                    let reason = msg.params.last().cloned().unwrap_or_default();
                    return Err(std::io::Error::other(format!(
                        "cannot send to {target}: {reason}"
                    )));
                }
            }
        }
        Command::Tail { target, count } => {
            if target.starts_with('#') {
                conn.send_line(&format!("JOIN {target}")).await?;
            }
            let mut seen = 0;
            while let Some(msg) = conn.next_message().await? {
                if msg.command == "PING" {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                    continue;
                }
                // A refused JOIN must be reported, not waited on forever — the
                // same loud failure Send and History give.
                if target.starts_with('#') && is_join_error(&msg.command) {
                    let reason = msg.params.last().cloned().unwrap_or_default();
                    return Err(std::io::Error::other(format!(
                        "cannot join {target}: {reason}"
                    )));
                }
                if msg.command == "PRIVMSG"
                    && msg.params.first().map(String::as_str) == Some(&target)
                {
                    let from = msg.source.as_deref().unwrap_or("?");
                    let text = msg.params.get(1).map(String::as_str).unwrap_or("");
                    println!("{from}\t{text}");
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
            // History playback needs batch + chathistory; the plain
            // register() above didn't negotiate them, so do it here.
            conn.send_line("CAP LS 302").await?;
            conn.send_line("CAP REQ :batch draft/chathistory server-time")
                .await?;
            // Wait for the ACK, failing loudly on NAK (the whole atomic REQ is
            // rejected if any cap is unsupported) or a mid-negotiation close —
            // otherwise this would block forever. Answer PINGs so the server
            // doesn't ping-timeout us while we wait.
            loop {
                let Some(m) = conn.next_message().await? else {
                    return Err(std::io::Error::other(
                        "connection closed during CAP negotiation",
                    ));
                };
                if m.command == "CAP" {
                    match m.params.get(1).map(String::as_str) {
                        Some("ACK") => break,
                        Some("NAK") => {
                            return Err(std::io::Error::other(
                                "server does not support the caps required for history \
                                 (batch, draft/chathistory, server-time)",
                            ));
                        }
                        _ => {}
                    }
                }
                if m.command == "PING" {
                    let token = m.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                }
            }
            // CHATHISTORY requires channel membership.
            conn.send_line(&format!("JOIN {target}")).await?;
            loop {
                // A close before 366 means no history was fetched — falling
                // through would run CHATHISTORY on a dead socket and exit 0
                // with empty output.
                let Some(m) = conn.next_message().await? else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("connection closed before the join to {target} was confirmed"),
                    ));
                };
                if m.command == "366" {
                    break;
                }
                if is_join_error(&m.command) {
                    let reason = m.params.last().cloned().unwrap_or_default();
                    return Err(std::io::Error::other(format!(
                        "cannot join {target}: {reason}"
                    )));
                }
                if m.command == "PING" {
                    let token = m.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                }
            }
            conn.send_line(&format!("CHATHISTORY LATEST {target} * {count}"))
                .await?;
            let mut in_batch = false;
            while let Some(m) = conn.next_message().await? {
                match m.command.as_str() {
                    "PING" => {
                        let token = m.params.first().cloned().unwrap_or_default();
                        conn.send_line(&format!("PONG :{token}")).await?;
                    }
                    "BATCH" => {
                        let opened = m
                            .params
                            .first()
                            .map(|p| p.starts_with('+'))
                            .unwrap_or(false);
                        in_batch = opened;
                        if !opened {
                            break; // batch closed
                        }
                    }
                    "PRIVMSG" | "NOTICE" if in_batch => {
                        let from = m
                            .source
                            .as_deref()
                            .and_then(|s| s.split('!').next())
                            .unwrap_or("?");
                        let text = m.params.get(1).map(String::as_str).unwrap_or("");
                        println!("{from}\t{text}");
                    }
                    "FAIL" => {
                        return Err(std::io::Error::other(format!(
                            "CHATHISTORY failed: {}",
                            m.params.join(" ")
                        )));
                    }
                    _ => {}
                }
            }
            conn.send_line("QUIT :done").await?;
            while conn.next_message().await?.is_some() {}
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
                    msg = conn.next_message() => {
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
            while conn.next_message().await?.is_some() {}
        }
        Command::Api { .. } => unreachable!("handled before the IRC connect"),
    }
    Ok(())
}

/// Largest API response body this will read. Generous for the JSON the API
/// returns; the point is that some number bounds it.
const MAX_API_RESPONSE: usize = 16 * 1024 * 1024;

/// Minimal HTTP/1.1 client for one request/response over a `Connection:
/// close` socket. Plain HTTP only; TLS termination belongs to a proxy.
async fn run_api(
    method: &str,
    path: &str,
    base: &str,
    token: Option<String>,
    body: Option<String>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let authority = base.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api base must start with http:// (use a TLS-terminating proxy for https)",
        )
    })?;
    let authority = authority.trim_end_matches('/');
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let token = token.or_else(|| std::env::var("E6IRC_API_TOKEN").ok());
    let body = body.unwrap_or_default();

    // These three go into the request head verbatim. This is a scripting CLI —
    // a path or token is routinely built from a shell variable — so a CR or LF
    // in one would let that variable append headers or a second request. Reject
    // it here rather than sending something other than what was asked for.
    for (what, value) in [
        ("method", method),
        ("path", path),
        ("token", token.as_deref().unwrap_or("")),
    ] {
        if value.contains(['\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{what} contains a line break"),
            ));
        }
    }

    let mut req = format!(
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        method.to_ascii_uppercase()
    );
    if let Some(t) = &token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req.push_str("\r\n");
    req.push_str(&body);

    let mut stream = TcpStream::connect(&addr).await?;
    stream.write_all(req.as_bytes()).await?;
    // Bounded: the response length is the server's choice, and reading to end
    // lets it decide how much memory this process uses. Over the cap is an
    // error, not a truncation — half a JSON document on a script's stdin is
    // worse than a failure.
    let mut buf = Vec::new();
    let read = (&mut stream)
        .take(MAX_API_RESPONSE as u64 + 1)
        .read_to_end(&mut buf)
        .await?;
    if read > MAX_API_RESPONSE {
        return Err(std::io::Error::other(format!(
            "API response exceeds {MAX_API_RESPONSE} bytes"
        )));
    }

    let text = String::from_utf8_lossy(&buf);
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    print!("{resp_body}");
    if !resp_body.ends_with('\n') {
        println!();
    }
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "API request failed: HTTP {status}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard runs before the socket is opened, so an injected line break is
    /// refused without a connection — which is also what makes this testable.
    #[tokio::test]
    async fn api_rejects_line_breaks_in_the_request_head() {
        for (method, path, token) in [
            ("GET\r\nX-Evil: 1", "/api/v1/me", None),
            ("GET", "/api/v1/me\r\nX-Evil: 1", None),
            ("GET", "/api/v1/me", Some("t\r\nX-Evil: 1".to_string())),
        ] {
            let err = run_api(method, path, "http://127.0.0.1:1", token, None)
                .await
                .expect_err("a line break must be refused");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{path}");
        }
    }

    #[test]
    fn join_errors_are_recognized() {
        assert!(is_join_error("475"));
        assert!(!is_join_error("366"));
    }
}
