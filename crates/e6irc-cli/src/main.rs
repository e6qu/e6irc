//! e6irc — a scripting-oriented IRC CLI. Non-interactive subcommands
//! that connect, do one job, and exit with a clear status.

mod http;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};
use e6irc_client::credentials::{
    CredentialArguments, SecretSources, process_environment, resolve_server_password,
};
use e6irc_client::liveness::{LIVENESS_WINDOW, Liveness};
use e6irc_client::token_cache::default_token_path;
use e6irc_client::{
    CleartextCredentials, ClientEvent, Connection, ConnectionOptions, NetworkNames, OwnedMessage,
    RelayEvent, TerminalSafe, is_refusal,
};
use serde::Serialize;

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

/// Whether the reader of an output is still there. A pipe whose reader went
/// away (`e6irc tail … | head -1`) is the end of the output, not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    Present,
    Gone,
}

/// Write one line to `out` (flushed, since each line is a unit a script may be
/// waiting on), reading a broken pipe as the reader going away.
fn emit(out: &mut impl std::io::Write, line: std::fmt::Arguments<'_>) -> std::io::Result<Reader> {
    match out
        .write_fmt(line)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
    {
        Ok(()) => Ok(Reader::Present),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(Reader::Gone),
        Err(error) => Err(error),
    }
}

/// `event`'s text for stdout: the raw line, neutralised for a terminal.
fn event_text(event: &RelayEvent) -> Option<(TerminalSafe, Option<&OwnedMessage>)> {
    match event {
        RelayEvent::Line { message, raw } => Some((terminal_safe(raw), message.as_ref())),
        RelayEvent::Rejected(rejected) => {
            eprintln!("warning: server input rejected: {rejected}");
            None
        }
    }
}

/// A refusal as one line for a person: what was refused and why, and the
/// numeric or `FAIL` that said so.
fn refusal_text(message: &OwnedMessage) -> TerminalSafe {
    let detail = message.params.get(1..).unwrap_or_default().join(" ");
    TerminalSafe::from_irc_text(&format!("{detail} ({})", message.command))
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
    /// SASL account (the strongest of SCRAM-SHA-512, SCRAM-SHA-256 and PLAIN
    /// the server offers). Its password comes from --password-file, the
    /// E6IRC_PASSWORD environment variable, or --password.
    #[arg(long, global = true)]
    account: Option<String>,
    /// SASL password. A value typed here is visible to every local user
    /// in the process list and is kept by the shell's history: prefer
    /// --password-file or E6IRC_PASSWORD.
    #[arg(long, global = true, conflicts_with = "password_file")]
    password: Option<String>,
    /// File holding the SASL password (one trailing line break is
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
    /// Load the SASL OAUTHBEARER token created by `e6irc login`. It is sent
    /// only to an IRC server on the host of the API origin that issued it.
    #[arg(long, global = true)]
    oauth_from_cache: bool,
    /// Send the cached token to an IRC server on another host than the API
    /// origin that issued it. That server receives the account's API
    /// credential and can use it against the API.
    #[arg(long, global = true, requires = "oauth_from_cache")]
    allow_oauth_token_for_other_server: bool,
    /// Token-cache path for login, API authentication, or --oauth-from-cache.
    /// Defaults to the current platform's private application-data directory.
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// The network's server password, sent as PASS before registration: only
    /// for a private server that requires one. A value typed here is visible
    /// to every local user in the process list and is kept by the shell's
    /// history: prefer --server-password-file or E6IRC_SERVER_PASSWORD.
    #[arg(long, global = true, conflicts_with = "server_password_file")]
    server_password: Option<String>,
    /// File holding the server password, under the same rules as
    /// --password-file.
    #[arg(long, global = true)]
    server_password_file: Option<PathBuf>,
    /// Send SASL credentials or a server password over a connection without
    /// --tls to a server that is not this machine. Without this flag that is
    /// refused: the password or token would cross the network readable by
    /// anyone on the path.
    #[arg(long, global = true)]
    allow_cleartext_credentials: bool,
    /// Connect over TLS (validating against the public CA set).
    #[arg(long, global = true)]
    tls: bool,
    /// TLS server name (defaults to the host part of --server). Only with
    /// --tls: a name for a plaintext connection would verify nothing.
    #[arg(long, global = true, requires = "tls")]
    tls_name: Option<String>,
    /// Seconds the server may take to finish registration, and afterwards to
    /// answer each request a command waits on — a JOIN, a history request,
    /// the verdict on a sent message, closing the connection after QUIT —
    /// before the command fails. For `api` and `login`, the bound on each HTTP
    /// request.
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
    /// Send one PRIVMSG to a target and exit once the server has confirmed
    /// it (by echo-message) or refused it. A server without echo-message
    /// cannot confirm delivery, and the command fails before sending.
    Send { target: String, message: String },
    /// Follow messages sent to a channel/nick, printing one per line. A server
    /// silent for three minutes is sent a PING; one silent for three more ends
    /// the command with a failure.
    Tail {
        target: String,
        /// Stop after N messages (0 = forever).
        #[arg(long, default_value_t = 0)]
        count: usize,
        /// Emit one structured JSON object per message.
        #[arg(long)]
        json: bool,
    },
    /// Send raw lines read from stdin, printing every line the server sends
    /// to stdout, and each refusal (an error numeric or FAIL) to stderr. Exits
    /// nonzero when any line was refused.
    Raw,
    /// Print the most recent history of a channel via CHATHISTORY.
    History {
        target: String,
        /// Lines to print: at most the server's CHATHISTORY limit, which a
        /// larger count is cut to with a warning.
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

/// The global options the HTTP-only commands (`api`, `login`) read. Every
/// other global option configures an IRC connection those commands never open,
/// so giving one to them is refused rather than silently ignored — and a global
/// option added later is refused there too until it is listed here.
const HTTP_GLOBAL_ARGUMENTS: [&str; 3] = [
    "token_file",
    "allow_cleartext_credentials",
    "response_timeout",
];

/// Refuse IRC-only global options given to an HTTP-only command.
fn reject_irc_only_arguments(cli: &Cli, matches: &ArgMatches) -> Result<(), clap::Error> {
    let subcommand = match cli.command {
        Command::Api { .. } => "api",
        Command::Login { .. } => "login",
        Command::Send { .. } | Command::Tail { .. } | Command::Raw | Command::History { .. } => {
            return Ok(());
        }
    };
    let mut command = Cli::command();
    let given: Vec<String> = command
        .get_arguments()
        .filter(|argument| argument.is_global_set())
        .filter(|argument| !HTTP_GLOBAL_ARGUMENTS.contains(&argument.get_id().as_str()))
        .filter(|argument| {
            matches.value_source(argument.get_id().as_str())
                == Some(clap::parser::ValueSource::CommandLine)
        })
        .map(|argument| match argument.get_long() {
            Some(long) => format!("--{long}"),
            None => argument.get_id().to_string(),
        })
        .collect();
    if given.is_empty() {
        return Ok(());
    }
    Err(command.error(
        clap::error::ErrorKind::ArgumentConflict,
        format!(
            "`e6irc {subcommand}` opens no IRC connection, so these IRC options would do nothing: {}",
            given.join(", ")
        ),
    ))
}

fn parse_arguments() -> Result<Cli, clap::Error> {
    let matches = Cli::command().try_get_matches()?;
    let cli = Cli::from_arg_matches(&matches)?;
    reject_irc_only_arguments(&cli, &matches)?;
    Ok(cli)
}

fn main() -> ExitCode {
    let cli = parse_arguments().unwrap_or_else(|error| error.exit());
    // One TLS stack for the process: the IRC transport and the HTTP client
    // both take this provider.
    e6irc_client::install_crypto_provider();
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
        return http::login(base, &cache_path, http_transport(&cli)).await;
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
            http_transport(&cli),
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
        allow_oauth_token_for_other_server: cli.allow_oauth_token_for_other_server,
    }
    .resolve(server, &process_environment)?;
    let server_password = resolve_server_password(
        SecretSources {
            argument: cli.server_password.clone(),
            file: cli.server_password_file.clone(),
        },
        &process_environment,
    )?;
    let response_timeout = std::time::Duration::from_secs(cli.response_timeout);
    let registered = ConnectionOptions {
        address: server.to_owned(),
        tls: cli.tls,
        tls_server_name: cli.tls_name.clone(),
        nick: nick.to_owned(),
        username,
        realname: "e6irc-cli".into(),
        authentication,
        response_deadline: response_timeout,
        cleartext_credentials: cleartext_credentials(&cli),
        server_password,
    }
    .connect_registered()
    .await?;
    let own_nick = registered.nick;
    let mut conn = registered.connection;
    // A mechanism the server refused before any credential, and the weaker
    // one used instead, is never a silent choice.
    for note in conn.sasl_notes() {
        eprintln!("warning: SASL: {}", terminal_safe(note));
    }
    let mut stdout = std::io::stdout().lock();
    match cli.command {
        Command::Send { target, message } => {
            for event in learn_network(&mut conn).await? {
                reported(event.into());
            }
            send(&mut conn, &own_nick, &target, &message, response_timeout).await?;
            finish_quietly(&mut conn, response_timeout).await
        }
        Command::Tail {
            target,
            count,
            json,
        } => {
            let early = learn_network(&mut conn).await?;
            let tail = Tail {
                target: &target,
                wanted: (count != 0).then_some(count),
                json,
                names: conn.names().clone(),
            };
            tail.follow(early, &mut conn, LIVENESS_WINDOW, &mut stdout)
                .await
        }
        Command::History { target, count } => {
            conn.require_capabilities(&["batch", "draft/chathistory", "server-time"], |event| {
                reported(event.into());
                Ok(())
            })
            .await?;
            for event in learn_network(&mut conn).await? {
                reported(event.into());
            }
            if let Some(limit) = conn.chathistory_limit().filter(|limit| count > *limit) {
                eprintln!(
                    "warning: the server returns at most {limit} lines per history request; \
                     printing the latest {limit}"
                );
            }
            let names = conn.names().clone();
            for event in conn.join_with_latest_history(&target, count).await? {
                let Some(message) = reported(event) else {
                    continue;
                };
                if matches!(message.command.as_str(), "PRIVMSG" | "NOTICE")
                    && message
                        .params
                        .first()
                        .is_some_and(|candidate| names.eq(candidate, &target))
                {
                    let from = message
                        .source
                        .as_deref()
                        .and_then(|source| source.split('!').next())
                        .unwrap_or("?");
                    let text = message.params.get(1).map(String::as_str).unwrap_or("");
                    let shown = format_args!(
                        "{}\t{}",
                        terminal_safe(from),
                        TerminalSafe::from_irc_text(text)
                    );
                    if emit(&mut stdout, shown)? == Reader::Gone {
                        return Ok(());
                    }
                }
            }
            finish_quietly(&mut conn, response_timeout).await
        }
        Command::Raw => raw(&mut conn, &mut stdout).await,
        Command::Api { .. } | Command::Login { .. } => {
            unreachable!("handled before the IRC connect")
        }
    }
}

/// Read the rest of the welcome burst, up to a round trip, and return what it
/// held. The network's 005 is in it, and until it is read nothing can say
/// which targets are channels on this network or when two names are the same
/// ([`Connection::names`]).
async fn learn_network(conn: &mut Connection) -> std::io::Result<Vec<RelayEvent>> {
    let mut early = Vec::new();
    conn.round_trip(|event| {
        early.push(event);
        Ok(())
    })
    .await?;
    if let Some(mapping) = conn.names().unrecognised_casemapping() {
        eprintln!(
            "warning: the server's CASEMAPPING={} is not one this client knows; names are \
             compared as ascii (letters only)",
            terminal_safe(mapping)
        );
    }
    Ok(early)
}

/// Deliver one PRIVMSG and wait for the server's verdict on it.
///
/// The verdict is the echo of the message (echo-message) or a refusal. Without
/// echo-message nothing tells a delivered message from one refused after the
/// connection closed (a bouncer attach closes on `QUIT` before the upstream's
/// refusal arrives), so the message is not sent at all rather than reported
/// delivered on no evidence.
async fn send(
    conn: &mut Connection,
    own_nick: &str,
    target: &str,
    message: &str,
    response_timeout: std::time::Duration,
) -> std::io::Result<()> {
    if !conn.offers("echo-message") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "delivery cannot be confirmed: the server does not offer echo-message, so a \
             refusal could arrive after the connection closed; the message was not sent",
        ));
    }
    conn.require_capabilities(&["echo-message"], |event| {
        reported(event.into());
        Ok(())
    })
    .await?;
    // Channels are +n by default, so join before speaking and wait for the
    // join to be confirmed. A refused or unconfirmed join is an error here.
    let names = conn.names().clone();
    if names.is_channel(target) {
        for event in conn.join_with_latest_history(target, 0).await? {
            reported(event);
        }
    }
    // Everything the server says about registration and the join (a missing
    // MOTD is a 422) is behind this round trip, so any refusal after the
    // PRIVMSG is about the PRIVMSG.
    conn.round_trip(|event| {
        reported(event.into());
        Ok(())
    })
    .await?;
    conn.send_line(&format!("PRIVMSG {target} :{message}"))
        .await?;
    let mut liveness = Liveness::new(LIVENESS_WINDOW);
    let verdict = async {
        loop {
            let event = liveness.next(conn).await?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "the server closed the connection before confirming the message to \
                         {target}; it may not have been delivered"
                    ),
                )
            })?;
            let Some(reply) = reported(event.into()) else {
                continue;
            };
            if is_refusal(&reply) {
                return Err(std::io::Error::other(format!(
                    "cannot send to {target}: {}",
                    refusal_text(&reply)
                )));
            }
            let from_self = reply
                .source
                .as_deref()
                .and_then(|source| source.split('!').next())
                .is_some_and(|nick| names.eq(nick, own_nick));
            if reply.command == "PRIVMSG"
                && from_self
                && reply
                    .params
                    .first()
                    .is_some_and(|echoed| names.eq(echoed, target))
            {
                return Ok(());
            }
        }
    };
    tokio::time::timeout(response_timeout, verdict)
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "the server neither confirmed nor refused the message to {target} within \
                     {response_timeout:?}; it may not have been delivered"
                ),
            ))
        })
}

/// `QUIT` after a command whose work is done and confirmed. A server that
/// then keeps the connection open past the response timeout changes nothing
/// about that work: it is said on stderr, and the connection is closed here.
async fn finish_quietly(
    conn: &mut Connection,
    response_timeout: std::time::Duration,
) -> std::io::Result<()> {
    match conn
        .quit_and_drain("done", |event| {
            reported(event.into());
            Ok(())
        })
        .await
    {
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            eprintln!(
                "warning: the server did not close the connection within {response_timeout:?} \
                 of QUIT; closing it"
            );
            Ok(())
        }
        other => other,
    }
}

/// What `tail` follows and how it prints.
struct Tail<'a> {
    target: &'a str,
    /// Stop after this many messages; `None` follows until the server goes.
    wanted: Option<usize>,
    json: bool,
    /// The network's naming rules, learned before the tail starts.
    names: NetworkNames,
}

impl Tail<'_> {
    /// Follow the target until the promised count is printed, the reader goes
    /// away, or the server does — the last being a failure: a server that
    /// closes, or stays silent through two liveness windows (the first ends
    /// with a PING), ends an unbounded tail that a supervisor must see end.
    /// `early` is what was read before the tail started, oldest first.
    async fn follow(
        &self,
        early: Vec<RelayEvent>,
        conn: &mut Connection,
        liveness_window: std::time::Duration,
        out: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        let mut seen = 0;
        for event in early {
            if let Some(message) = reported(event.into())
                && let Some(end) = self.print(&message, &mut seen, out)?
            {
                return end;
            }
        }
        if self.names.is_channel(self.target) {
            // Messages relayed while the join is confirmed are part of the
            // stream being followed.
            for event in conn.join_with_latest_history(self.target, 0).await? {
                if let Some(message) = reported(event)
                    && let Some(end) = self.print(&message, &mut seen, out)?
                {
                    return end;
                }
            }
        }
        let mut liveness = Liveness::new(liveness_window);
        loop {
            let event = match liveness.next(conn).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(self.cut_short(seen, "the server closed the connection")),
                Err(error) => return Err(self.cut_short(seen, &error.to_string())),
            };
            if let Some(message) = reported(event.into())
                && let Some(end) = self.print(&message, &mut seen, out)?
            {
                return end;
            }
        }
    }

    /// Print `message` when it is one being followed. `Some` is the end of the
    /// tail: the promised count reached, or the reader gone.
    fn print(
        &self,
        message: &OwnedMessage,
        seen: &mut usize,
        out: &mut impl std::io::Write,
    ) -> std::io::Result<Option<std::io::Result<()>>> {
        // The server relays a channel message with the *sender's* spelling of
        // the target, so the comparison must fold case under the network's
        // CASEMAPPING — a raw equality would silently miss messages sent to a
        // differently-cased name.
        if message.command != "PRIVMSG"
            || !message
                .params
                .first()
                .is_some_and(|target| self.names.eq(target, self.target))
        {
            return Ok(None);
        }
        let from = message.source.as_deref().unwrap_or("?");
        let text = message.params.get(1).map(String::as_str).unwrap_or("");
        let reader = if self.json {
            emit(out, format_args!("{}", tail_json(message, from, text)?))?
        } else {
            emit(
                out,
                format_args!(
                    "{}\t{}",
                    terminal_safe(from),
                    TerminalSafe::from_irc_text(text)
                ),
            )?
        };
        *seen += 1;
        if reader == Reader::Gone || self.wanted.is_some_and(|wanted| *seen >= wanted) {
            return Ok(Some(Ok(())));
        }
        Ok(None)
    }

    /// Only a bounded tail that printed everything it promised has a
    /// successful end. One cut short delivered less than a script reading N
    /// lines was told to expect.
    fn cut_short(&self, seen: usize, why: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            match self.wanted {
                Some(wanted) => format!("{why} after {seen} of {wanted} messages"),
                None => format!("{why} after {seen} messages"),
            },
        )
    }
}

/// Send each stdin line, printing every line the server sends — to stdout, or
/// to stderr when it is a refusal — and fail when any line was refused.
///
/// Stdin is read asynchronously and the socket serviced between lines: a
/// blocking read on this current-thread runtime would leave server PINGs
/// unanswered while a slow producer feeds us, and get the session
/// ping-timed-out.
async fn raw(conn: &mut Connection, out: &mut impl std::io::Write) -> std::io::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let mut refused = 0usize;
    let mut reader = Reader::Present;
    let mut show = |event: RelayEvent, count_refusals: bool| -> std::io::Result<()> {
        let Some((text, message)) = event_text(&event) else {
            return Ok(());
        };
        if message.is_some_and(is_refusal) {
            eprintln!("{text}");
            if count_refusals {
                refused += 1;
            }
        } else if reader == Reader::Present {
            reader = emit(out, format_args!("{text}"))?;
        }
        Ok(())
    };
    // The rest of the registration burst is printed, but a refusal in it (a
    // missing MOTD is a 422) is not about any line from stdin.
    conn.round_trip(|event| show(event, false)).await?;
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut liveness = Liveness::new(LIVENESS_WINDOW);
    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line? else {
                    break; // stdin exhausted
                };
                conn.send_line(&line).await?;
            }
            read = liveness.bound(conn.next_line_relayable()) => {
                match liveness.settle(conn, read).await? {
                    e6irc_client::liveness::Heard::Event(event) => show(event, true)?,
                    e6irc_client::liveness::Heard::Nothing => {}
                    e6irc_client::liveness::Heard::Closed => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "server closed the connection before stdin was exhausted",
                        ));
                    }
                }
            }
        }
    }
    // Replies to the last lines may still be on their way; they are read
    // until the server closes, within the response timeout.
    conn.quit_and_drain("done", |event| show(event, true))
        .await?;
    match refused {
        0 => Ok(()),
        count => Err(std::io::Error::other(format!(
            "the server refused {count} line(s); see the refusals above"
        ))),
    }
}

fn http_transport(cli: &Cli) -> http::Transport {
    http::Transport {
        cleartext: cleartext_credentials(cli),
        response_timeout: std::time::Duration::from_secs(cli.response_timeout),
    }
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

    /// A TLS server name without TLS verifies nothing; accepting it silently
    /// would let a user believe the connection was checked against it.
    #[test]
    fn transport_options_that_mean_nothing_alone_are_refused() {
        assert!(send_parses(&["--tls", "--tls-name", "irc.example"]));
        assert!(!send_parses(&["--tls-name", "irc.example"]));
        assert!(send_parses(&[
            "--oauth-from-cache",
            "--allow-oauth-token-for-other-server"
        ]));
        assert!(!send_parses(&["--allow-oauth-token-for-other-server"]));
    }

    /// A server that registers the client and then goes silent without
    /// closing: an unbounded tail asks after one window and fails after two,
    /// so whatever supervises it sees it end.
    #[tokio::test]
    async fn tail_gives_up_on_a_silent_server_after_probing_it() {
        use tokio::io::AsyncBufReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut lines = tokio::io::BufReader::new(socket).lines();
            let mut seen = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line);
            }
            seen
        });
        let mut connection = Connection::connect(&address).await.unwrap();
        let window = std::time::Duration::from_millis(150);
        let tail = Tail {
            target: "bob",
            wanted: None,
            json: false,
            names: NetworkNames::default(),
        };
        let mut out = Vec::new();
        let started = std::time::Instant::now();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tail.follow(Vec::new(), &mut connection, window, &mut out),
        )
        .await
        .expect("tail never gave up on a silent server")
        .expect_err("a silent server is a failed tail");
        assert!(started.elapsed() >= window * 2, "{:?}", started.elapsed());
        assert!(
            error.to_string().contains("server stopped responding"),
            "{error}"
        );
        drop(connection);
        assert_eq!(
            server.await.unwrap(),
            [format!("PING :{}", e6irc_client::liveness::KEEPALIVE_TOKEN)]
        );
    }

    #[test]
    fn a_reader_that_went_away_ends_the_output_without_an_error() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(emit(&mut Closed, format_args!("x")).unwrap(), Reader::Gone);
        let mut open = Vec::new();
        assert_eq!(emit(&mut open, format_args!("x")).unwrap(), Reader::Present);
        assert_eq!(open, b"x\n");
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

    /// Whether `arguments` parse and pass the IRC-only-option check.
    fn accepted(arguments: &[&str]) -> Result<(), String> {
        let matches = Cli::command()
            .try_get_matches_from(arguments)
            .map_err(|error| error.to_string())?;
        let cli = Cli::from_arg_matches(&matches).map_err(|error| error.to_string())?;
        reject_irc_only_arguments(&cli, &matches).map_err(|error| error.to_string())
    }

    /// `api` and `login` open no IRC connection: an IRC option given to them
    /// is refused by name, wherever it sits on the line, instead of being
    /// accepted and ignored. The options they do read stay accepted.
    #[test]
    fn http_commands_refuse_irc_only_options() {
        for command in [
            &["api", "GET", "/api/v1/me"][..],
            &["login", "--base", "https://irc.example"][..],
        ] {
            let with = |options: &[&str], after: bool| {
                let mut line = vec!["e6irc"];
                if after {
                    line.extend(command);
                    line.extend(options);
                } else {
                    line.extend(options);
                    line.extend(command);
                }
                accepted(&line)
            };
            for after in [false, true] {
                with(
                    &[
                        "--token-file",
                        "t.json",
                        "--allow-cleartext-credentials",
                        "--response-timeout",
                        "5",
                    ],
                    after,
                )
                .expect("the options HTTP commands read");
                for irc_only in [
                    &["--server", "irc.example:6697"][..],
                    &["--nick", "alice"],
                    &["--account", "alice"],
                    &["--password", "secret"],
                    &["--oauth-from-cache"],
                    &["--tls"],
                    &["--server-password-file", "pw"],
                ] {
                    let error = with(irc_only, after).expect_err("an IRC-only option");
                    assert!(error.contains(irc_only[0]), "{error}");
                    assert!(error.contains(command[0]), "{error}");
                }
            }
        }
        // IRC commands still take every global option.
        accepted(&["e6irc", "--server", "s:1", "--tls", "send", "n", "m"]).unwrap();
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
