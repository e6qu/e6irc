//! e6irc-tui — a ratatui IRC client with bounded multi-buffer state, TLS,
//! SASL, and reconnecting transport. Networking runs on a tokio task feeding
//! messages to the render loop over a channel.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event};
use e6irc_client::credentials::{
    CredentialArguments, SecretSources, process_environment, resolve_server_password,
};
use e6irc_client::liveness::{Heard, LIVENESS_WINDOW, Liveness};
use e6irc_client::{
    CleartextCredentials, ClientEvent, Connection, ConnectionOptions, HistoryCoverage,
    HistoryRefusal, JoinRefusal, NetworkNames, OwnedMessage, Registered, RelayEvent, TerminalSafe,
};
use e6irc_tui::app::{App, LogLine, SCROLLBACK_LINES, SessionStart};
use e6irc_tui::keys::{self, KeyOutcome};
use e6irc_tui::reconnect::{AfterFailure, ReconnectPolicy};
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout, Position};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Parser)]
#[command(name = "e6irc-tui", about = "Terminal IRC client", version)]
struct Cli {
    /// IRC server address (host:port).
    #[arg(long, short)]
    server: String,
    /// Nickname to register with.
    #[arg(long, short)]
    nick: String,
    /// IRC user name (ident) sent in USER. When absent, --nick is used, and
    /// only if it is itself a legal user name (ASCII letters, digits, '_' and
    /// '-', starting with a letter or digit, at most 10 bytes). A nick that is
    /// not — `_bot`, `ada|away` — is never rewritten to fit: the client stops
    /// and asks for --username.
    #[arg(long, short)]
    username: Option<String>,
    /// Initial channel to join.
    #[arg(long, short)]
    channel: String,
    /// SASL account (the strongest of SCRAM-SHA-512, SCRAM-SHA-256 and PLAIN
    /// the server offers). For BNC attachment use account/network. Its
    /// password comes from --password-file, E6IRC_PASSWORD, or --password.
    #[arg(long)]
    account: Option<String>,
    /// SASL password. A value typed here is visible to every local user
    /// in the process list and is kept by the shell's history: prefer
    /// --password-file or E6IRC_PASSWORD.
    #[arg(long, conflicts_with = "password_file")]
    password: Option<String>,
    /// File holding the SASL password (one trailing line break is
    /// dropped). Refused if group or other users can read it.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// SASL OAUTHBEARER token; E6IRC_OAUTH_TOKEN when no flag is given. A value
    /// typed here is visible to other local users: prefer --oauth-token-file.
    #[arg(long, conflicts_with = "oauth_token_file")]
    oauth_token: Option<String>,
    /// File holding the SASL OAUTHBEARER token, under the same rules as
    /// --password-file.
    #[arg(long)]
    oauth_token_file: Option<PathBuf>,
    /// Load the OAUTHBEARER token created by `e6irc login`. It is sent only to
    /// an IRC server on the host of the API origin that issued it.
    #[arg(long)]
    oauth_from_cache: bool,
    /// Token-cache path used by --oauth-from-cache.
    #[arg(long, requires = "oauth_from_cache")]
    token_file: Option<PathBuf>,
    /// Send the cached token to an IRC server on another host than the API
    /// origin that issued it. That server receives the account's API
    /// credential and can use it against the API.
    #[arg(long, requires = "oauth_from_cache")]
    allow_oauth_token_for_other_server: bool,
    /// The network's server password, sent as PASS before registration: only
    /// for a private server that requires one. A value typed here is visible
    /// to every local user in the process list and is kept by the shell's
    /// history: prefer --server-password-file or E6IRC_SERVER_PASSWORD.
    #[arg(long, conflicts_with = "server_password_file")]
    server_password: Option<String>,
    /// File holding the server password, under the same rules as
    /// --password-file.
    #[arg(long)]
    server_password_file: Option<PathBuf>,
    /// Send SASL credentials or a server password over a connection without
    /// --tls to a server that is not this machine. Without this flag that is
    /// refused: the password or token would cross the network readable by
    /// anyone on the path.
    #[arg(long)]
    allow_cleartext_credentials: bool,
    /// Connect over TLS using the public CA set.
    #[arg(long)]
    tls: bool,
    /// TLS certificate server name; defaults to the host in --server.
    #[arg(long, requires = "tls")]
    tls_name: Option<String>,
    /// Seconds before the first reconnect attempt after a live connection
    /// drops. Each further failed attempt doubles the wait, up to five minutes;
    /// rejected credentials and bans are not retried at all.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=300))]
    reconnect_delay: u64,
    /// Seconds the server may take to finish registration, and afterwards to
    /// confirm each JOIN with its history, before the attempt is abandoned.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    response_timeout: u64,
    /// Lines asked for per history request for each joined channel, and never
    /// more than the server's CHATHISTORY limit. With the server's shared read
    /// marker these are the lines after it, paged forward until a short page,
    /// for at most ten pages (and never more than the scrollback holds); a
    /// channel with unread lines beyond that says so, and its read marker
    /// stays at the last line loaded. Without a marker they are the latest
    /// lines. A channel whose history the server refuses is joined without
    /// it, and says so. Zero disables history.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(0..=1000))]
    history_lines: u64,
    /// Do not ask for draft/read-marker, for servers without it: read
    /// positions are then neither loaded nor sent.
    #[arg(long)]
    no_read_markers: bool,
}

/// Server events buffered between draws before the reader task waits on the
/// render loop. One screenful of scrollback is generous for a 50 ms poll.
const NET_QUEUE_DEPTH: usize = 1024;

/// Lines awaiting the socket writer. Keyboard input is local, but terminal
/// automation can still outrun a stalled socket; this bound makes admission
/// explicit and lets the UI refuse without a false local echo.
const OUT_QUEUE_DEPTH: usize = 256;

/// How long quitting waits for the network task to send what is queued and
/// its `QUIT`. Past it the client says so rather than claiming a clean exit.
const QUIT_BOUND: Duration = Duration::from_secs(5);

/// How long, after sending `QUIT`, the network task waits for the server to
/// close the connection.
const QUIT_GRACE: Duration = Duration::from_secs(2);

/// Events the render loop consumes.
enum Ev {
    Net(ClientEvent),
    /// A new session is registered.
    Connected(SessionStart),
    /// What SASL did on the way that its user should know: a mechanism the
    /// server refused before any credential, and the one offered instead.
    SaslNote(String),
    JoinRefused(JoinRefusal),
    /// The server refused this channel's history; the channel is joined.
    HistoryRefused(String, HistoryRefusal),
    /// This channel's unread history did not all load.
    HistoryGap(String),
    /// Every unread line of this channel loaded: a gap left by an earlier
    /// session is closed.
    HistoryCaughtUp(String),
    Reconnecting(String),
    /// The network task gave up for good; the text says why.
    Stopped(String),
    /// Lines admitted before the UI learned of a disconnect, never sent.
    DroppedOutbound(usize),
    /// A read marker admitted before the UI learned of a disconnect: it is
    /// still to be sent, on the next connection.
    ReadMarkerUnsent(String),
}

/// One line for the socket writer. A read marker is kept apart from what the
/// user typed: one that meets a disconnect is sent later, not lost, and never
/// counted as a lost message.
#[derive(Debug, PartialEq, Eq)]
enum Queued {
    Line(String),
    ReadMarker(String),
}

impl Queued {
    fn line(&self) -> &str {
        match self {
            Self::Line(line) | Self::ReadMarker(line) => line,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(async_main(cli)));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "e6irc-tui: {}",
                TerminalSafe::from_untrusted(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

async fn async_main(cli: Cli) -> io::Result<()> {
    let authentication = CredentialArguments {
        account: cli.account,
        password: SecretSources {
            argument: cli.password,
            file: cli.password_file,
        },
        oauth_token: SecretSources {
            argument: cli.oauth_token,
            file: cli.oauth_token_file,
        },
        oauth_from_cache: cli.oauth_from_cache,
        token_file: cli.token_file,
        allow_oauth_token_for_other_server: cli.allow_oauth_token_for_other_server,
    }
    .resolve(&cli.server, &process_environment)?;
    let server_password = resolve_server_password(
        SecretSources {
            argument: cli.server_password,
            file: cli.server_password_file,
        },
        &process_environment,
    )?;
    let connection_options = ConnectionOptions {
        address: cli.server,
        tls: cli.tls,
        tls_server_name: cli.tls_name,
        nick: cli.nick.clone(),
        username: e6irc_client::stated_or_nick_username(cli.username.as_deref(), &cli.nick)?,
        realname: "e6irc-tui".into(),
        authentication,
        response_deadline: Duration::from_secs(cli.response_timeout),
        cleartext_credentials: if cli.allow_cleartext_credentials {
            CleartextCredentials::Allow
        } else {
            CleartextCredentials::Refuse
        },
        server_password,
    };
    let history = HistoryWindow::new(cli.history_lines as usize);
    let read_markers = !cli.no_read_markers;
    let mut joined_channels = std::collections::BTreeSet::from([cli.channel.clone()]);
    // The UI state exists before the connection does: what the server says
    // while the client connects goes straight into it, never into a list.
    let mut app = App::new(
        cli.channel,
        SessionStart {
            nick: cli.nick.clone(),
            names: NetworkNames::default(),
            read_markers: false,
        },
    );
    let Registered {
        connection: conn,
        nick: confirmed_nick,
    } = connect_and_join(
        &connection_options,
        &mut joined_channels,
        history,
        read_markers,
        &mut Ui::Starting(&mut app),
    )
    .await?;

    // Bounded: the server decides how fast this fills, and the render loop
    // only drains it between draws. A full queue makes the reader task wait,
    // which stops reading the socket and lets TCP apply the backpressure —
    // the same shape as the daemon's SendQ, in the other direction.
    let (net_tx, mut net_rx) = mpsc::channel::<Ev>(NET_QUEUE_DEPTH);
    let (out_tx, out_rx) = mpsc::channel::<Queued>(OUT_QUEUE_DEPTH);

    let network = tokio::spawn(network_task(
        conn,
        out_rx,
        net_tx,
        joined_channels,
        confirmed_nick.clone(),
        Reconnect {
            options: connection_options.clone(),
            history,
            read_markers,
            policy: ReconnectPolicy::new(
                Duration::from_secs(cli.reconnect_delay),
                std::time::Instant::now(),
            ),
        },
    ));

    // Before the terminal is taken over: from then on a signal ends the UI
    // the way /quit does, through the teardown below, never mid-draw with the
    // terminal left raw.
    let mut signalled = quit_on_signal()?;
    let mut terminal = ratatui::init();
    restore_paste_on_panic();
    let result = match crossterm::execute!(io::stdout(), event::EnableBracketedPaste) {
        Ok(()) => {
            run_ui(
                &mut terminal,
                &mut app,
                &mut net_rx,
                &out_tx,
                &mut signalled,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let paste_restored = crossterm::execute!(io::stdout(), event::DisableBracketedPaste);
    let restore = ratatui::try_restore().and(paste_restored);
    let shutdown = shut_down_network(&mut app, out_tx, net_rx, network).await;
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(format!("UI failed: {error}"));
    }
    if let Err(error) = restore {
        failures.push(format!("terminal restoration failed: {error}"));
    }
    if let Err(error) = shutdown {
        failures.push(error.to_string());
    }
    match failures.len() {
        0 => Ok(()),
        _ => Err(io::Error::other(failures.join("; "))),
    }
}

/// Watch for the signals that ask a terminal program to end — SIGTERM (a
/// service manager, `kill`), SIGINT (`kill -INT`; Ctrl-C itself is a key in
/// raw mode) and SIGHUP (the terminal closing). Their default action kills the
/// process on the spot, leaving the terminal raw, on the alternate screen and
/// in bracketed-paste mode, and the server without a QUIT. The receiver
/// yields the signal's name once one arrives.
#[cfg(unix)]
fn quit_on_signal() -> io::Result<tokio::sync::oneshot::Receiver<&'static str>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let name = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
            _ = hangup.recv() => "SIGHUP",
        };
        // The UI may already have gone; then there is nothing left to end.
        sender.send(name).unwrap_or_default();
    });
    Ok(receiver)
}

/// Where there are no Unix signals, the console's Ctrl-C/Ctrl-Break event is
/// the request to end.
#[cfg(not(unix))]
fn quit_on_signal() -> io::Result<tokio::sync::oneshot::Receiver<&'static str>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            sender.send("Ctrl-C").unwrap_or_default();
        }
    });
    Ok(receiver)
}

/// Chain a panic hook onto ratatui's (which leaves raw mode and the alternate
/// screen) that first turns bracketed paste off: ratatui never turned it on,
/// so its hook leaves it on and every later paste into the shell arrives
/// wrapped in `ESC[200~`…`ESC[201~`.
fn restore_paste_on_panic() {
    let restore_terminal = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Nothing more can be done about a terminal that refuses the write
        // while the process is already panicking.
        drop(crossterm::execute!(
            io::stdout(),
            event::DisableBracketedPaste
        ));
        restore_terminal(info);
    }));
}

/// Hand the network task the last read marker, close the writer queue so it
/// sends everything still in it followed by `QUIT`, and wait for it — within
/// [`QUIT_BOUND`]. With no live connection there is nothing to send, and the
/// task is stopped where it stands.
async fn shut_down_network(
    app: &mut App,
    out_tx: mpsc::Sender<Queued>,
    net_rx: mpsc::Receiver<Ev>,
    network: tokio::task::JoinHandle<()>,
) -> io::Result<()> {
    if !app.connected() {
        drop(net_rx);
        drop(out_tx);
        network.abort();
        return Ok(());
    }
    let finished = async {
        if let Some(marker) = app.take_read_marker_command() {
            // A closed queue here means the connection ended meanwhile.
            drop(out_tx.send(Queued::ReadMarker(marker)).await);
        }
        drop(out_tx);
        // Nothing reads the UI's events any more; a network task blocked on
        // sending one is released into its shutdown path.
        drop(net_rx);
        network.await
    };
    match tokio::time::timeout(QUIT_BOUND, finished).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(io::Error::other(format!(
            "the network task failed while quitting: {error}"
        ))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the connection did not finish sending queued lines and QUIT within \
                 {QUIT_BOUND:?}; they may not have reached the server"
            ),
        )),
    }
}

/// How much history a join loads.
#[derive(Debug, Clone, Copy)]
struct HistoryWindow {
    /// Lines per CHATHISTORY request; zero disables history.
    page_lines: usize,
    /// The most lines one join loads across its pages: never more than the
    /// scrollback holds, so every loaded line can still be shown.
    max_lines: usize,
}

impl HistoryWindow {
    fn new(page_lines: usize) -> Self {
        Self {
            page_lines,
            max_lines: page_lines
                .saturating_mul(e6irc_client::MAX_HISTORY_PAGES)
                .min(SCROLLBACK_LINES),
        }
    }
}

/// Everything a reconnect repeats: the same explicit request, the same
/// history and read-marker choices, and the backoff between attempts.
struct Reconnect {
    options: ConnectionOptions,
    history: HistoryWindow,
    /// Whether `draft/read-marker` is asked for.
    read_markers: bool,
    policy: ReconnectPolicy,
}

/// Lines taken off the writer queue that no connection will send.
#[derive(Debug, Default, PartialEq, Eq)]
struct Stale {
    lines: usize,
    read_markers: Vec<String>,
}

impl Stale {
    fn take(&mut self, queued: Queued) {
        match queued {
            Queued::Line(_) => self.lines += 1,
            Queued::ReadMarker(marker) => self.read_markers.push(marker),
        }
    }

    /// Everything already in the queue.
    fn drain(&mut self, out_rx: &mut mpsc::Receiver<Queued>) {
        while let Ok(queued) = out_rx.try_recv() {
            self.take(queued);
        }
    }

    /// Tell the UI: lines were not sent, read markers go back to be sent on
    /// the next connection. `false` when the UI is gone.
    async fn report(&mut self, net_tx: &mpsc::Sender<Ev>) -> bool {
        let lines = std::mem::take(&mut self.lines);
        if lines > 0 && net_tx.send(Ev::DroppedOutbound(lines)).await.is_err() {
            return false;
        }
        for marker in std::mem::take(&mut self.read_markers) {
            if net_tx.send(Ev::ReadMarkerUnsent(marker)).await.is_err() {
                return false;
            }
        }
        true
    }
}

/// Networking: read messages up, write outbound lines down, and reconnect
/// with the same explicit transport/authentication request.
async fn network_task(
    mut conn: Connection,
    mut out_rx: mpsc::Receiver<Queued>,
    net_tx: mpsc::Sender<Ev>,
    mut joined_channels: std::collections::BTreeSet<String>,
    mut own_nick: String,
    reconnect: Reconnect,
) {
    let Reconnect {
        options,
        history,
        read_markers,
        mut policy,
    } = reconnect;
    loop {
        let failure = match relay_session(
            &mut conn,
            &mut out_rx,
            &net_tx,
            &mut joined_channels,
            &mut own_nick,
            LIVENESS_WINDOW,
        )
        .await
        {
            SessionEnd::Failed(failure) => failure,
            SessionEnd::UiGone => return,
        };
        if net_tx.send(Ev::Reconnecting(failure)).await.is_err() {
            return;
        }

        let mut delay = policy.session_ended(std::time::Instant::now());
        let mut stale = Stale::default();
        loop {
            // Lines that raced the disconnect notification are not delivered
            // after reconnect (a surprising delayed send), and their local
            // echo is qualified by saying so.
            stale.drain(&mut out_rx);
            if !stale.report(&net_tx).await {
                return;
            }
            if sleep_unless_ui_leaves(delay, &mut out_rx, &mut stale).await {
                return;
            }
            let attempt = connect_and_join(
                &options,
                &mut joined_channels,
                history,
                read_markers,
                &mut Ui::Running {
                    net_tx: &net_tx,
                    out_rx: &mut out_rx,
                    stale: &mut stale,
                },
            )
            .await;
            let registered = match attempt {
                Ok(registered) => registered,
                // The UI left while the client was connecting.
                Err(_) if net_tx.is_closed() => return,
                Err(error) => match policy.after(&error) {
                    // Dropping `out_rx` with this task is what makes the UI
                    // refuse further input instead of queueing it for nobody.
                    AfterFailure::Stop(status) => {
                        drop(net_tx.send(Ev::Stopped(status)).await);
                        return;
                    }
                    AfterFailure::RetryAfter(next) => {
                        delay = next;
                        let status = format!(
                            "reconnect failed: {error}; next attempt in {}s",
                            next.as_secs()
                        );
                        if net_tx.send(Ev::Reconnecting(status)).await.is_err() {
                            return;
                        }
                        continue;
                    }
                },
            };
            policy.connected(std::time::Instant::now());
            conn = registered.connection;
            own_nick = registered.nick;
            break;
        }
    }
}

/// Wait out a reconnect delay. `true` when the UI left meanwhile (its queue
/// closed); anything it queued on the way is stale.
async fn sleep_unless_ui_leaves(
    delay: Duration,
    out_rx: &mut mpsc::Receiver<Queued>,
    stale: &mut Stale,
) -> bool {
    let wake = tokio::time::Instant::now() + delay;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(wake) => return false,
            queued = out_rx.recv() => match queued {
                Some(queued) => stale.take(queued),
                None => return true,
            },
        }
    }
}

/// How a relayed session ended.
#[derive(Debug, PartialEq, Eq)]
enum SessionEnd {
    /// The connection failed; the text says why, and the reconnect path runs.
    Failed(String),
    /// The UI left: whatever it queued was sent, then `QUIT`.
    UiGone,
}

/// Relay one registered session: server messages up to the UI, outbound lines
/// down to the socket, until the session ends.
async fn relay_session(
    conn: &mut Connection,
    out_rx: &mut mpsc::Receiver<Queued>,
    net_tx: &mpsc::Sender<Ev>,
    joined_channels: &mut std::collections::BTreeSet<String>,
    own_nick: &mut String,
    liveness_window: Duration,
) -> SessionEnd {
    let mut liveness = Liveness::new(liveness_window);
    loop {
        tokio::select! {
            // Lossy steady-state read: one non-UTF-8 line (a Latin-1 channel
            // message any member can post) must not disconnect the session.
            // Bounded by the liveness window, measured from the server's last
            // sign of life: an outbound line also ends a turn of this loop and
            // must not make a silent server look alive while the user types.
            read = liveness.bound(conn.next_line_relayable()) => {
                let event = match liveness.settle(conn, read).await {
                    Ok(Heard::Event(event)) => ClientEvent::from(event),
                    Ok(Heard::Nothing) => continue,
                    Ok(Heard::Closed) => {
                        return SessionEnd::Failed("server closed the connection".into());
                    }
                    Err(error) => return SessionEnd::Failed(error.to_string()),
                };
                if let ClientEvent::Message(message) = &event {
                    track_own_state(joined_channels, own_nick, conn.names(), message);
                }
                if net_tx.send(Ev::Net(event)).await.is_err() {
                    return finish(conn, out_rx).await;
                }
            }
            queued = out_rx.recv() => match queued {
                Some(queued) => if let Err(error) = conn.send_line(queued.line()).await {
                    return SessionEnd::Failed(format!("message write failed: {error}"));
                },
                None => return finish(conn, out_rx).await,
            },
        }
    }
}

/// The UI left: send every line still queued, then `QUIT`, and give the
/// server [`QUIT_GRACE`] to close the connection.
async fn finish(conn: &mut Connection, out_rx: &mut mpsc::Receiver<Queued>) -> SessionEnd {
    while let Some(queued) = out_rx.recv().await {
        if let Err(error) = conn.send_line(queued.line()).await {
            return SessionEnd::Failed(format!("message write failed: {error}"));
        }
    }
    if let Err(error) = conn.send_line("QUIT :e6irc-tui").await {
        return SessionEnd::Failed(format!("QUIT write failed: {error}"));
    }
    // The server closes after QUIT; the wait only lets it read the line.
    drop(
        tokio::time::timeout(QUIT_GRACE, async {
            while let Ok(Some(_)) = conn.next_line_relayable().await {}
        })
        .await,
    );
    SessionEnd::UiGone
}

/// Where what the server says while the client connects goes, as each line
/// is read. None of it is held for later: a bouncer attach can replay
/// thousands of lines before the client has joined anything, and the server's
/// pace must never become the client's memory.
enum Ui<'a> {
    /// Before the first draw: straight into the UI state.
    Starting(&'a mut App),
    /// The running UI, through its bounded queue, which pushes back on the
    /// socket when full.
    Running {
        net_tx: &'a mpsc::Sender<Ev>,
        /// Lines the UI queued against the previous connection are set aside
        /// before it learns of this one, and never sent on it.
        out_rx: &'a mut mpsc::Receiver<Queued>,
        stale: &'a mut Stale,
    },
}

/// A line read while a request waits for its answer is the UI's, as it is
/// read.
impl e6irc_client::LineSink for &mut Ui<'_> {
    async fn take(&mut self, event: RelayEvent) -> io::Result<()> {
        self.deliver(Ev::Net(event.into())).await
    }
}

impl Ui<'_> {
    async fn deliver(&mut self, event: Ev) -> io::Result<()> {
        let ui_gone = || io::Error::new(io::ErrorKind::BrokenPipe, "the UI has closed");
        match self {
            Self::Starting(app) => {
                apply(app, event);
                Ok(())
            }
            Self::Running {
                net_tx,
                out_rx,
                stale,
            } => {
                if matches!(event, Ev::Connected(_)) {
                    stale.drain(out_rx);
                    if !stale.report(net_tx).await {
                        return Err(ui_gone());
                    }
                }
                net_tx.send(event).await.map_err(|_| ui_gone())
            }
        }
    }
}

/// What the UI must know about a channel's history: whether the read marker
/// is to be held short of a gap, or released because none remains.
fn coverage_event(channel: String, coverage: HistoryCoverage) -> Option<Ev> {
    match coverage {
        HistoryCoverage::UnreadBeyondLoaded => Some(Ev::HistoryGap(channel)),
        HistoryCoverage::AllUnread => Some(Ev::HistoryCaughtUp(channel)),
        HistoryCoverage::NoHistory | HistoryCoverage::Latest => None,
    }
}

/// Register and join `channels`, telling `ui` everything on the way as it
/// happens. A channel the server refuses is taken out of the set and
/// reported: one closed channel must not fail the whole session, or every
/// reconnect registers, is refused the same channel, and drops again. A
/// channel whose history the server refuses is joined without it, and said.
async fn connect_and_join(
    options: &ConnectionOptions,
    channels: &mut std::collections::BTreeSet<String>,
    history: HistoryWindow,
    read_markers: bool,
    ui: &mut Ui<'_>,
) -> io::Result<Registered> {
    let Registered {
        mut connection,
        nick,
    } = options.connect_registered().await?;
    for note in connection.sasl_notes() {
        ui.deliver(Ev::SaslNote(note.clone())).await?;
    }
    let mut capabilities = Vec::new();
    if history.page_lines > 0 {
        capabilities.extend(["batch", "draft/chathistory", "server-time"]);
    }
    if read_markers {
        capabilities.push("draft/read-marker");
    }
    // The welcome burst is still arriving — its MOTD and 005, a bouncer's
    // playback — and it is the UI's, up to a round trip, before any join.
    connection
        .require_capabilities(&capabilities, &mut *ui)
        .await?;
    connection.round_trip(&mut *ui).await?;
    ui.deliver(Ev::Connected(SessionStart {
        nick: nick.clone(),
        names: connection.names().clone(),
        read_markers: connection.enabled("draft/read-marker"),
    }))
    .await?;
    for channel in channels.clone() {
        match connection
            .join_with_history(&channel, history.page_lines, history.max_lines)
            .await
        {
            Ok(joined) => {
                for event in joined.events {
                    ui.deliver(Ev::Net(event)).await?;
                }
                if let Some(refusal) = joined.refusal {
                    ui.deliver(Ev::HistoryRefused(channel.clone(), refusal))
                        .await?;
                }
                if let Some(event) = coverage_event(channel, joined.coverage) {
                    ui.deliver(event).await?;
                }
            }
            Err(error) => {
                let Some(refusal) = JoinRefusal::from_error(&error) else {
                    return Err(error);
                };
                channels.remove(&channel);
                ui.deliver(Ev::JoinRefused(refusal)).await?;
            }
        }
    }
    Ok(Registered { connection, nick })
}

/// Keep what a reconnect needs in step with the server: the channels this
/// client is in, and the nickname it is known by — own JOIN, PART and KICK are
/// only recognisable under the current one.
fn track_own_state(
    channels: &mut std::collections::BTreeSet<String>,
    own_nick: &mut String,
    names: &NetworkNames,
    message: &OwnedMessage,
) {
    if message.command == "KICK"
        && message
            .params
            .get(1)
            .is_some_and(|nick| names.eq(nick, own_nick))
    {
        if let Some(channel) = message.params.first() {
            remove_channel(channels, names, channel);
        }
        return;
    }
    let source_nick = message
        .source
        .as_deref()
        .and_then(|source| source.split('!').next());
    if !source_nick.is_some_and(|nick| names.eq(nick, own_nick)) {
        return;
    }
    match (message.command.as_str(), message.params.first()) {
        // A JOIN of a channel already held under another spelling is the
        // same channel: one entry, or a reconnect joins it twice.
        ("JOIN", Some(channel)) if !channels.iter().any(|held| names.eq(held, channel)) => {
            channels.insert(channel.clone());
        }
        ("PART", Some(channel)) => remove_channel(channels, names, channel),
        ("NICK", Some(nick)) => own_nick.clone_from(nick),
        _ => {}
    }
}

fn remove_channel(
    channels: &mut std::collections::BTreeSet<String>,
    names: &NetworkNames,
    channel: &str,
) {
    let existing = channels
        .iter()
        .find(|candidate| names.eq(candidate, channel))
        .cloned();
    if let Some(existing) = existing {
        channels.remove(&existing);
    }
}

async fn run_ui<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    net_rx: &mut mpsc::Receiver<Ev>,
    out_tx: &mpsc::Sender<Queued>,
    signalled: &mut tokio::sync::oneshot::Receiver<&'static str>,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let mut dirty = true;
    loop {
        if let Ok(name) = signalled.try_recv() {
            app.status(format!("{name} received; quitting"));
            app.should_quit = true;
        }
        // Drain any pending network events.
        while let Ok(ev) = net_rx.try_recv() {
            dirty = true;
            apply(app, ev);
        }
        flush_read_marker(app, out_tx);
        if dirty {
            terminal.draw(|f| draw(f, app))?;
            dirty = false;
        }
        if app.should_quit {
            return Ok(());
        }
        // Poll for input with a short timeout so network events still flow.
        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        // Every event can change what is on screen: a resize most of all,
        // which must redraw at the new size now, not at the next keypress.
        dirty = true;
        match event::read()? {
            Event::Key(key) => match keys::dispatch(app, key) {
                KeyOutcome::Handled | KeyOutcome::Quit => {}
                KeyOutcome::Send(outbound) => {
                    match out_tx.try_send(Queued::Line(outbound.line().to_owned())) {
                        Ok(()) => app.outbound_accepted(&outbound),
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            app.outbound_refused(&outbound);
                            app.note_outbound_full();
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            app.outbound_refused(&outbound);
                            app.set_connected(false);
                            app.status("not connected — message not sent");
                        }
                    }
                }
            },
            Event::Paste(text) => app.on_paste(&text),
            Event::Resize(..) | Event::FocusGained | Event::FocusLost | Event::Mouse(_) => {}
        }
        flush_read_marker(app, out_tx);
    }
}

/// Fold one network-task event into the UI state.
fn apply(app: &mut App, event: Ev) {
    match event {
        Ev::Net(ClientEvent::Message(message)) => app.on_message(&message),
        Ev::Net(ClientEvent::Rejected(rejected)) => {
            app.status(format!("server input rejected: {rejected}"));
        }
        Ev::Connected(start) => {
            let status = format!("connected as {}", start.nick);
            app.begin_session(start);
            app.status(status);
        }
        Ev::SaslNote(note) => app.status(format!("SASL: {note}")),
        Ev::JoinRefused(refusal) => {
            app.status(format!("{refusal}; it will not be rejoined"));
        }
        Ev::HistoryRefused(channel, refusal) => {
            app.history_refused(&channel, &format!("{refusal}; joined without it"));
        }
        Ev::HistoryGap(channel) => app.hold_read_marker(&channel),
        Ev::HistoryCaughtUp(channel) => app.release_read_marker(&channel),
        Ev::Reconnecting(reason) => {
            app.set_connected(false);
            app.status(format!("{reason}; reconnecting"));
        }
        Ev::Stopped(reason) => {
            app.stop_reconnecting();
            app.status(reason);
        }
        Ev::DroppedOutbound(count) => {
            app.status(format!(
                "{count} outbound message(s) were not sent during disconnect"
            ));
        }
        Ev::ReadMarkerUnsent(marker) => app.requeue_read_marker_command(marker),
    }
}

/// Offer the pending read marker to the writer. While disconnected it stays
/// pending: a queued marker would only meet the disconnect, and it is sent on
/// the next connection instead.
fn flush_read_marker(app: &mut App, out_tx: &mpsc::Sender<Queued>) {
    if !app.connected() {
        return;
    }
    let Some(command) = app.take_read_marker_command() else {
        return;
    };
    match out_tx.try_send(Queued::ReadMarker(command)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(Queued::ReadMarker(command))) => {
            app.requeue_read_marker_command(command);
            app.note_outbound_full();
        }
        Err(mpsc::error::TrySendError::Full(Queued::Line(_))) => {
            unreachable!("the value offered was a read marker")
        }
        Err(mpsc::error::TrySendError::Closed(queued)) => {
            if let Queued::ReadMarker(command) = queued {
                app.requeue_read_marker_command(command);
            }
            app.set_connected(false);
            app.status("not connected — the read marker will be sent after reconnecting");
        }
    }
}

/// The styled pieces of one log line: who, a separator, and the text.
fn log_segments(line: &LogLine) -> [(String, Style); 3] {
    let route = if line.from.as_str() == "*" {
        (
            " route ".to_owned(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        (
            format!(" {} ", line.from),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };
    [
        route,
        ("│ ".to_owned(), Style::default().fg(Color::DarkGray)),
        (line.text.to_string(), Style::default()),
    ]
}

/// `line` wrapped into rows at most `width` columns wide, by display width
/// (a wide character never straddles two rows). Every row is shown; nothing
/// past the pane's edge is clipped away.
fn wrap_log_line(line: &LogLine, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0;
    for (text, style) in log_segments(line) {
        let mut piece = String::new();
        for character in text.chars() {
            let columns = character.width().unwrap_or(0);
            if used + columns > width && used > 0 {
                if !piece.is_empty() {
                    rows.last_mut()
                        .expect("a row")
                        .push(Span::styled(std::mem::take(&mut piece), style));
                }
                rows.push(Vec::new());
                used = 0;
            }
            piece.push(character);
            used += columns;
        }
        if !piece.is_empty() {
            rows.last_mut()
                .expect("a row")
                .push(Span::styled(piece, style));
        }
    }
    rows.into_iter().map(Line::from).collect()
}

/// The rows of the log pane: the lines ending at the scroll position, wrapped
/// to `width`, of which the last `height` rows are shown.
fn log_rows(buffer: &e6irc_tui::app::Buffer, width: usize, height: usize) -> Vec<Line<'static>> {
    let lines = buffer.visible_rows(height, |line| wrap_log_line(line, width).len());
    let mut rows: Vec<Line<'static>> = lines.flat_map(|line| wrap_log_line(line, width)).collect();
    let overflow = rows.len().saturating_sub(height);
    rows.drain(..overflow);
    rows
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(f.area());

    let buf = app.current();
    let connection = if app.connected() {
        Span::styled(
            "● CONNECTED",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else if app.gave_up() {
        Span::styled(
            "● DISCONNECTED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "● RECONNECTING",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };
    let mut header = vec![
        Span::styled(
            " e6/irc ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ROUTE ", Style::default().fg(Color::DarkGray)),
        Span::styled("→ ", Style::default().fg(Color::Yellow)),
        Span::styled(
            e6irc_client::TerminalSafe::from_untrusted(&buf.name).to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  ·  "),
        connection,
    ];
    if app.total_unread() > 0 {
        header.push(Span::styled(
            format!("  ·  {} unread", app.total_unread()),
            Style::default().fg(Color::Cyan),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(header)), chunks[0]);

    f.render_widget(
        Paragraph::new(conversation_rail_text(app)).style(Style::default().fg(Color::DarkGray)),
        chunks[1],
    );

    let height = chunks[2].height.saturating_sub(2) as usize;
    let width = chunks[2].width.saturating_sub(2) as usize;
    let lines = log_rows(buf, width, height);
    let position = format!(" {} / {} ", app.current + 1, app.buffers.len());
    let mut title = vec![
        Span::styled(
            format!(
                " {} ",
                e6irc_client::TerminalSafe::from_untrusted(&buf.name)
            ),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(position, Style::default().fg(Color::DarkGray)),
    ];
    if buf.scrolled_back() {
        title.push(Span::styled(
            format!(
                " SCROLLBACK · {} lines behind · {} new · Ctrl-End latest ",
                buf.lines_behind_latest(),
                buf.unread()
            ),
            Style::default().fg(Color::Yellow),
        ));
    } else {
        title.push(Span::styled(" LIVE ", Style::default().fg(Color::Green)));
    }
    let log = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Line::from(title)),
    );
    f.render_widget(log, chunks[2]);

    let composer_title = if app.connected() {
        Line::from(vec![
            Span::styled(
                " MESSAGE ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("→ ", Style::default().fg(Color::Yellow)),
            Span::styled(
                e6irc_client::TerminalSafe::from_untrusted(&buf.name).to_string(),
                Style::default().fg(Color::Yellow),
            ),
        ])
    } else {
        Line::from(Span::styled(
            " OFFLINE · INPUT RETAINED ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
    };
    let composer_inner_width = chunks[3].width.saturating_sub(2);
    let (horizontal_scroll, cursor_column) =
        composer_view(app.input(), app.input_cursor(), composer_inner_width);
    let input = Paragraph::new(app.input())
        .scroll((0, horizontal_scroll))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if app.connected() {
                    Color::Cyan
                } else {
                    Color::Red
                }))
                .title(composer_title),
        );
    f.render_widget(input, chunks[3]);
    let cursor_x = chunks[3]
        .x
        .saturating_add(1)
        .saturating_add(cursor_column)
        .min(chunks[3].right().saturating_sub(2));
    f.set_cursor_position(Position::new(cursor_x, chunks[3].y.saturating_add(1)));

    f.render_widget(
        Paragraph::new(keys::HINT).style(Style::default().fg(Color::DarkGray)),
        chunks[4],
    );
}

fn conversation_rail_text(app: &App) -> String {
    let mut labels = Vec::with_capacity(app.buffers.len());
    for offset in 0..app.buffers.len() {
        let index = (app.current + offset) % app.buffers.len();
        let buffer = &app.buffers[index];
        let name = e6irc_client::TerminalSafe::from_untrusted(&buffer.name);
        let unread = match buffer.unread() {
            0 => String::new(),
            count => format!(" · {count}"),
        };
        if offset == 0 {
            labels.push(format!("[{name}{unread}]"));
        } else {
            labels.push(format!("{name}{unread}"));
        }
    }
    format!(" CONVERSATIONS  {}", labels.join("  "))
}

/// The composer's horizontal scroll and the cursor's column within it, both in
/// display columns. The scroll always lands on a character boundary: scrolled
/// into the middle of a wide character, ratatui keeps the whole character and
/// shifts the rest of the line by a column, so the cursor would sit one column
/// off the text it edits.
fn composer_view(input: &str, cursor: usize, width: u16) -> (u16, u16) {
    let before_cursor = &input[..cursor];
    let input_width = UnicodeWidthStr::width(before_cursor);
    let visible_width = usize::from(width).saturating_sub(1);
    let needed_scroll = input_width.saturating_sub(visible_width);
    let horizontal_scroll = before_cursor
        .chars()
        .scan(0, |column, character| {
            *column += character.width().unwrap_or(0);
            Some(*column)
        })
        .chain(std::iter::once(input_width))
        .find(|&boundary| boundary >= needed_scroll)
        .filter(|_| needed_scroll > 0)
        .unwrap_or(0);
    let cursor_column = input_width.saturating_sub(horizontal_scroll);
    (
        u16::try_from(horizontal_scroll).unwrap_or(u16::MAX),
        u16::try_from(cursor_column).unwrap_or(u16::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ratatui::backend::TestBackend;

    /// An app on a connection with the default naming rules that keeps read
    /// markers.
    fn test_app(channel: &str, nick: &str) -> App {
        App::new(
            channel.to_owned(),
            SessionStart {
                nick: nick.to_owned(),
                names: NetworkNames::default(),
                read_markers: true,
            },
        )
    }

    fn parses(arguments: &[&str]) -> bool {
        Cli::try_parse_from(
            [
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--username",
                "alice",
                "--channel",
                "#chat",
            ]
            .into_iter()
            .chain(arguments.iter().copied()),
        )
        .is_ok()
    }

    #[test]
    fn authentication_shapes_are_explicit() {
        assert!(parses(&["--account", "alice/work", "--password", "secret"]));
        assert!(parses(&["--oauth-token", "device-token"]));
        assert!(parses(&["--oauth-from-cache"]));
        assert!(parses(&[
            "--oauth-from-cache",
            "--token-file",
            "token.json"
        ]));
        assert!(!parses(&["--token-file", "token.json"]));
        // An account's password may come from the environment, which only
        // resolution can see (`e6irc_client::credentials` owns and tests which
        // combinations are mistakes); parsing refuses one secret given twice.
        assert!(parses(&["--account", "alice"]));
        assert!(parses(&["--account", "alice", "--password-file", "pw"]));
        assert!(!parses(&["--password", "typed", "--password-file", "pw"]));
        assert!(!parses(&[
            "--oauth-token",
            "typed",
            "--oauth-token-file",
            "token",
        ]));
        assert!(parses(&["--allow-cleartext-credentials"]));
    }

    #[test]
    fn transport_and_reconnect_constraints_fail_at_argument_parsing() {
        assert!(parses(&[
            "--oauth-from-cache",
            "--allow-oauth-token-for-other-server"
        ]));
        assert!(!parses(&["--allow-oauth-token-for-other-server"]));
        assert!(parses(&["--tls"]));
        assert!(parses(&["--tls", "--tls-name", "irc.example"]));
        assert!(!parses(&["--tls-name", "irc.example"]));
        assert!(!parses(&["--reconnect-delay", "0"]));
        assert!(!parses(&["--reconnect-delay", "301"]));
        assert!(parses(&["--history-lines", "1000"]));
        assert!(!parses(&["--history-lines", "1001"]));
    }

    #[test]
    fn connection_arguments_are_required() {
        assert!(Cli::try_parse_from(["e6irc-tui"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--server", "irc.example:6697"]).is_err());
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
            ])
            .is_err()
        );
    }

    fn message(raw: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(raw).unwrap())
    }

    #[test]
    fn conversation_rail_keeps_the_active_buffer_first_and_exposes_unread() {
        let mut app = test_app("#home", "me");
        app.on_message(&message(":alice!u@h PRIVMSG #other :hello"));
        assert_eq!(
            conversation_rail_text(&app),
            " CONVERSATIONS  [#home]  #other · 1"
        );
        app.next_buffer();
        assert_eq!(
            conversation_rail_text(&app),
            " CONVERSATIONS  [#other]  #home"
        );
    }

    #[test]
    fn composer_view_follows_long_and_wide_input() {
        assert_eq!(composer_view("abc", 3, 4), (0, 3));
        assert_eq!(composer_view("abcdef", 6, 4), (3, 3));
        assert_eq!(composer_view("abcdef", 2, 4), (0, 2));
        assert_eq!(composer_view("界x", 4, 4), (0, 3));
        assert_eq!(composer_view("界x", 4, 0), (3, 0));
        // Scrolling 2 columns would split the first 界: round up past it.
        assert_eq!(composer_view("a界界", 7, 4), (3, 2));
    }

    /// Whatever the scroll, the cell just left of the cursor holds the
    /// character just before it: the cursor is never a column off the text.
    #[test]
    fn the_composer_cursor_follows_its_text_across_wide_characters() {
        let mut app = test_app("#home", "me");
        for character in "a界界界".chars() {
            app.on_char(character);
        }
        for width in 5..=12 {
            let backend = TestBackend::new(width, 10);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            let position = terminal.get_cursor_position().unwrap();
            let buffer = terminal.backend().buffer();
            // A wide character occupies two cells; its symbol is in the first.
            let symbol = buffer[(position.x - 2, position.y)].symbol().to_owned();
            assert_eq!(symbol, "界", "terminal width {width}");
        }
    }

    #[test]
    fn tiny_terminals_render_without_panicking() {
        let app = test_app("#home", "me");
        for (width, height) in [(1, 1), (10, 3), (24, 5)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
        }
    }

    /// A line longer than the pane wraps; its end is on screen, not clipped.
    #[test]
    fn a_long_line_wraps_so_its_last_word_is_shown() {
        let mut app = test_app("#home", "me");
        let long = format!("{} finalword", "x".repeat(189));
        app.on_message(&message(&format!(":alice!u@h PRIVMSG #home :{long}")));
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(screen.contains("finalword"), "{screen}");

        // Rows are counted by display width: wide characters never straddle.
        app.on_message(&message(&format!(
            ":alice!u@h PRIVMSG #home :{}",
            "界".repeat(10)
        )));
        let wide = app.current().log.back().expect("a line").clone();
        let rows = wrap_log_line(&wide, 11);
        assert!(rows.len() > 1);
        for row in &rows {
            assert!(row.width() <= 11, "{row:?}");
        }
    }

    /// A read marker queued while the connection is down is not a message
    /// lost in the disconnect: it stays pending and goes out on the next
    /// connection.
    #[test]
    fn a_read_marker_waits_out_a_disconnect_instead_of_being_lost() {
        let (out_tx, mut out_rx) = mpsc::channel::<Queued>(8);
        let mut app = test_app("#a", "me");
        app.set_connected(false);
        app.on_message(&message(
            "@time=2026-07-30T12:00:00.000Z :alice!u@h PRIVMSG #a :hi",
        ));
        flush_read_marker(&mut app, &out_tx);
        assert!(out_rx.try_recv().is_err(), "a marker was queued while down");
        app.set_connected(true);
        flush_read_marker(&mut app, &out_tx);
        assert_eq!(
            out_rx.try_recv().ok(),
            Some(Queued::ReadMarker(
                "MARKREAD #a timestamp=2026-07-30T12:00:00.000Z".into()
            ))
        );
    }

    /// What was queued against a connection that died is taken off the queue
    /// before the next connection sees it: typed lines are reported unsent,
    /// read markers go back to the UI to be sent again.
    #[tokio::test]
    async fn stale_lines_are_reported_and_stale_markers_are_requeued() {
        let (out_tx, mut out_rx) = mpsc::channel::<Queued>(8);
        let (net_tx, mut net_rx) = mpsc::channel::<Ev>(8);
        out_tx
            .send(Queued::Line("PRIVMSG #a :late".into()))
            .await
            .unwrap();
        out_tx
            .send(Queued::ReadMarker("MARKREAD #a timestamp=x".into()))
            .await
            .unwrap();
        let mut stale = Stale::default();
        stale.drain(&mut out_rx);
        assert!(stale.report(&net_tx).await);
        let mut app = test_app("#a", "me");
        while let Ok(event) = net_rx.try_recv() {
            apply(&mut app, event);
        }
        assert!(
            app.current().log.iter().any(|line| line.text.as_str()
                == "1 outbound message(s) were not sent during disconnect")
        );
        assert!(
            !app.current()
                .log
                .iter()
                .any(|line| line.text.as_str().contains("read marker"))
        );
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=x")
        );
    }

    /// Quitting sends what is still queued, then QUIT — the network task does
    /// not just vanish with the UI.
    #[tokio::test]
    async fn leaving_sends_the_queue_then_quit() {
        use tokio::io::AsyncBufReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut lines = tokio::io::BufReader::new(socket).lines();
            let mut seen = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                let quit = line.starts_with("QUIT");
                seen.push(line);
                if quit {
                    break;
                }
            }
            seen
        });
        let mut conn = Connection::connect(&address).await.unwrap();
        let (net_tx, _net_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel::<Queued>(8);
        out_tx
            .send(Queued::Line("PRIVMSG #a :last words".into()))
            .await
            .unwrap();
        out_tx
            .send(Queued::ReadMarker("MARKREAD #a timestamp=x".into()))
            .await
            .unwrap();
        drop(out_tx);
        let mut channels = std::collections::BTreeSet::new();
        let mut nick = "me".to_owned();
        let end = tokio::time::timeout(
            Duration::from_secs(5),
            relay_session(
                &mut conn,
                &mut out_rx,
                &net_tx,
                &mut channels,
                &mut nick,
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("leaving is bounded");
        assert_eq!(end, SessionEnd::UiGone);
        drop(conn);
        assert_eq!(
            server.await.unwrap(),
            [
                "PRIVMSG #a :last words",
                "MARKREAD #a timestamp=x",
                "QUIT :e6irc-tui"
            ]
        );
    }

    #[test]
    fn reconnect_channels_track_self_join_part_and_kick_case_insensitively() {
        let mut channels = std::collections::BTreeSet::from(["#Home".to_owned()]);
        let mut nick = "Me".to_owned();
        let names = NetworkNames::default();
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h JOIN #HOME"),
        );
        assert_eq!(channels.len(), 1, "one channel under two spellings");
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h JOIN #Other"),
        );
        assert!(channels.contains("#Other"));
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":ME!u@h PART #other :bye"),
        );
        assert!(
            !channels
                .iter()
                .any(|channel| channel.eq_ignore_ascii_case("#other"))
        );
        // Own joins are only recognisable under the current nickname.
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h NICK Renamed"),
        );
        assert_eq!(nick, "Renamed");
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":renamed!u@h JOIN #later"),
        );
        assert!(channels.contains("#later"));
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h JOIN #not-ours"),
        );
        assert!(!channels.contains("#not-ours"));
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":op!u@h KICK #home RENAMED :gone"),
        );
        assert_eq!(
            channels,
            std::collections::BTreeSet::from(["#later".to_owned()])
        );
    }

    /// On an `ascii` network `#a[` and `#a{` are two channels: parting one
    /// keeps the other in the set a reconnect rejoins.
    #[test]
    fn reconnect_channels_follow_the_networks_casemapping() {
        let mut names = NetworkNames::default();
        names.adopt_isupport(&message(
            ":srv 005 me CASEMAPPING=ascii :are supported by this server",
        ));
        let mut channels = std::collections::BTreeSet::from(["#a[".to_owned()]);
        let mut nick = "me".to_owned();
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h JOIN #a{"),
        );
        assert_eq!(channels.len(), 2);
        track_own_state(
            &mut channels,
            &mut nick,
            &names,
            &message(":me!u@h PART #a{"),
        );
        assert_eq!(
            channels,
            std::collections::BTreeSet::from(["#a[".to_owned()])
        );
    }

    /// One closed channel used to fail the whole connect, so every reconnect
    /// registered, was refused the same channel, and dropped again.
    #[tokio::test]
    async fn a_refused_channel_is_dropped_from_the_session_not_fatal_to_it() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = match line.as_str() {
                    "CAP LS 302" => ":bnc CAP * LS :",
                    "CAP END" => ":bnc 001 upstream :Welcome",
                    "JOIN #closed" => ":bnc 473 upstream #closed :Cannot join channel (+i)",
                    "JOIN #open" => ":bnc 366 upstream #open :End of NAMES",
                    "PING :e6irc-round-trip" => ":bnc PONG bnc :e6irc-round-trip",
                    _ => continue,
                };
                writer
                    .write_all(format!("{reply}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let options = ConnectionOptions {
            address,
            tls: false,
            tls_server_name: None,
            nick: "requested".into(),
            username: "ident".into(),
            realname: "real".into(),
            authentication: e6irc_client::Authentication::None,
            response_deadline: Duration::from_secs(5),
            cleartext_credentials: CleartextCredentials::Refuse,
            server_password: None,
        };
        let mut channels =
            std::collections::BTreeSet::from(["#closed".to_owned(), "#open".to_owned()]);
        let mut app = test_app("#open", "requested");
        let registered = connect_and_join(
            &options,
            &mut channels,
            HistoryWindow::new(0),
            false,
            &mut Ui::Starting(&mut app),
        )
        .await
        .expect("a refused channel does not fail the session");
        assert_eq!(registered.nick, "upstream");
        assert_eq!(app.nick, "upstream");
        assert_eq!(
            channels,
            std::collections::BTreeSet::from(["#open".to_owned()])
        );
        assert!(
            app.current().log.iter().any(|line| line.text
                == "cannot join #closed: Cannot join channel (+i); it will not be rejoined"),
            "{:?}",
            app.current().log
        );

        apply(
            &mut app,
            Ev::Stopped("the server banned this connection".into()),
        );
        assert!(app.gave_up() && !app.connected());
    }

    /// The welcome burst is still arriving when the client asks for its
    /// capabilities. A Latin-1 MOTD line in it must not fail the connect, and
    /// the burst is the UI's: the MOTD is shown, and the 005 decides how the
    /// UI names things from the first line on. A history page larger than the
    /// server's CHATHISTORY limit is never asked for, and a history request
    /// the server refuses costs the channel its history, not the connection.
    #[tokio::test]
    async fn the_welcome_burst_reaches_the_ui_and_a_refused_history_keeps_the_join() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            let mut seen = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply: &[u8] = match line.as_str() {
                    "CAP LS 302" => {
                        b":srv CAP * LS :batch draft/chathistory server-time draft/read-marker\r\n"
                    }
                    "CAP END" => {
                        b":srv 001 me :Welcome\r\n\
                          :srv 005 me CASEMAPPING=ascii STATUSMSG=@ CHATHISTORY=5 \
                          :are supported by this server\r\n\
                          :srv 372 me :- caf\xe9 au lait\r\n"
                    }
                    "CAP REQ :server-time" => b":srv CAP * ACK :server-time\r\n",
                    "CAP REQ :batch draft/chathistory server-time draft/read-marker" => {
                        b":srv CAP me ACK :batch draft/chathistory server-time draft/read-marker\r\n"
                    }
                    "JOIN #open" => b":me!u@h JOIN #open\r\n:srv 366 me #open :End of NAMES\r\n",
                    "CHATHISTORY LATEST #open * 5" => {
                        b":srv FAIL CHATHISTORY MESSAGE_ERROR #open :history store unavailable\r\n"
                    }
                    "PING :e6irc-round-trip" => b":srv PONG srv :e6irc-round-trip\r\n",
                    _ => b"",
                };
                seen.push(line);
                writer.write_all(reply).await.unwrap();
            }
            seen
        });
        let options = ConnectionOptions {
            address,
            tls: false,
            tls_server_name: None,
            nick: "me".into(),
            username: "ident".into(),
            realname: "real".into(),
            authentication: e6irc_client::Authentication::None,
            response_deadline: Duration::from_secs(5),
            cleartext_credentials: CleartextCredentials::Refuse,
            server_password: None,
        };
        let mut channels = std::collections::BTreeSet::from(["#open".to_owned()]);
        let mut app = App::new(
            "#open".into(),
            SessionStart {
                nick: "me".into(),
                names: NetworkNames::default(),
                read_markers: false,
            },
        );
        let registered = connect_and_join(
            &options,
            &mut channels,
            HistoryWindow::new(50),
            true,
            &mut Ui::Starting(&mut app),
        )
        .await
        .expect("a Latin-1 MOTD line and a refused history do not fail the connect");
        drop(registered);
        let seen = server.await.unwrap();
        assert!(
            seen.iter()
                .any(|line| line == "CHATHISTORY LATEST #open * 5"),
            "the page fits the server's limit: {seen:?}"
        );
        app.on_message(&message(
            "@time=2026-07-30T12:00:00.000Z :x!u@h PRIVMSG #open :hi",
        ));
        assert!(
            app.take_read_marker_command().is_some(),
            "the connection keeps read markers"
        );
        let shown = |app: &App, name: &str| -> Vec<String> {
            app.buffers
                .iter()
                .filter(|buffer| buffer.name == name)
                .flat_map(|buffer| buffer.log.iter().map(|line| line.text.to_string()))
                .collect()
        };
        assert!(
            shown(&app, "*server*")
                .iter()
                .any(|text| text.contains("caf\u{fffd} au lait")),
            "the MOTD is shown: {:?}",
            shown(&app, "*server*")
        );
        assert!(
            shown(&app, "#open")
                .iter()
                .any(|text| text.contains("history store unavailable")),
            "the refused history is said beside its channel: {:?}",
            shown(&app, "#open")
        );
        // STATUSMSG came from the connection's 005: `@#open` is #open's.
        app.on_message(&message(":op!o@h PRIVMSG @#open :ops only"));
        assert_eq!(
            shown(&app, "#open").last().map(String::as_str),
            Some("ops only")
        );
    }

    /// A bouncer attach can replay thousands of lines before it answers
    /// anything the client asked. What the server says while the client
    /// connects reaches the running UI as it is read, through the UI's bounded
    /// queue, and none of it is held on the way: this server answers the
    /// capability request only after the UI has received every line of its
    /// burst, and the queue holds four.
    #[tokio::test]
    async fn a_reconnect_streams_the_welcome_burst_to_the_ui_as_it_arrives() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        const LINES: usize = 3000;
        let (all_shown, shown) = tokio::sync::oneshot::channel::<()>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            let mut shown = Some(shown);
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = match line.as_str() {
                    "CAP LS 302" => ":bnc CAP * LS :draft/read-marker".to_owned(),
                    "CAP END" => ":bnc 001 me :Welcome".to_owned(),
                    "CAP REQ :draft/read-marker" => {
                        let mut burst = String::new();
                        for number in 0..LINES {
                            burst.push_str(&format!(":bnc 372 me :- playback {number}\r\n"));
                        }
                        writer.write_all(burst.as_bytes()).await.unwrap();
                        shown
                            .take()
                            .expect("one request")
                            .await
                            .expect("the UI received the whole burst first");
                        ":bnc CAP me ACK :draft/read-marker".to_owned()
                    }
                    "PING :e6irc-round-trip" => ":bnc PONG bnc :e6irc-round-trip".to_owned(),
                    "JOIN #open" => ":bnc 366 me #open :End of NAMES".to_owned(),
                    _ => continue,
                };
                writer
                    .write_all(format!("{reply}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let options = ConnectionOptions {
            address,
            tls: false,
            tls_server_name: None,
            nick: "me".into(),
            username: "ident".into(),
            realname: "real".into(),
            authentication: e6irc_client::Authentication::None,
            response_deadline: Duration::from_secs(10),
            cleartext_credentials: CleartextCredentials::Refuse,
            server_password: None,
        };
        let (net_tx, mut net_rx) = mpsc::channel(4);
        let (_out_tx, mut out_rx) = mpsc::channel::<Queued>(4);
        let ui = tokio::spawn(async move {
            let mut all_shown = Some(all_shown);
            let mut playback = 0;
            let mut connected = false;
            while let Some(event) = net_rx.recv().await {
                match event {
                    Ev::Net(ClientEvent::Message(message)) if message.command == "372" => {
                        playback += 1;
                        if playback == LINES {
                            all_shown.take().expect("once").send(()).unwrap_or_default();
                        }
                    }
                    Ev::Connected(start) => {
                        assert_eq!(playback, LINES, "the burst comes before the session");
                        assert!(start.read_markers);
                        connected = true;
                    }
                    _ => {}
                }
            }
            (playback, connected)
        });
        let mut channels = std::collections::BTreeSet::from(["#open".to_owned()]);
        let mut stale = Stale::default();
        let registered = tokio::time::timeout(
            Duration::from_secs(20),
            connect_and_join(
                &options,
                &mut channels,
                HistoryWindow::new(0),
                true,
                &mut Ui::Running {
                    net_tx: &net_tx,
                    out_rx: &mut out_rx,
                    stale: &mut stale,
                },
            ),
        )
        .await
        .expect("the burst was held until the request was answered")
        .expect("connected");
        drop(registered);
        drop(net_tx);
        assert_eq!(ui.await.unwrap(), (LINES, true));
        server.await.unwrap();
    }

    /// A half-open connection reads as nothing forever. The client asks after
    /// one silent window, and after a second declares the server gone so the
    /// reconnect path runs — instead of sitting CONNECTED with every message
    /// typed into it accepted and lost.
    #[tokio::test]
    async fn a_server_that_stops_answering_is_declared_dead_after_two_silent_windows() {
        use tokio::io::AsyncBufReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, _writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            // The first thing the client says is its probe; nothing is ever
            // answered.
            let first = lines.next_line().await.unwrap();
            drop(seen_tx.send(first));
            while let Ok(Some(_)) = lines.next_line().await {}
        });
        let mut conn = Connection::connect(&address).await.unwrap();
        let (net_tx, _net_rx) = mpsc::channel(8);
        let (_out_tx, mut out_rx) = mpsc::channel::<Queued>(8);
        let mut channels = std::collections::BTreeSet::new();
        let mut nick = "me".to_owned();
        let window = Duration::from_millis(150);
        let started = std::time::Instant::now();
        let reason = tokio::time::timeout(
            Duration::from_secs(5),
            relay_session(
                &mut conn,
                &mut out_rx,
                &net_tx,
                &mut channels,
                &mut nick,
                window,
            ),
        )
        .await
        .expect("a silent server ends the session");
        assert_eq!(
            reason,
            SessionEnd::Failed(e6irc_client::liveness::SERVER_STOPPED_RESPONDING.into())
        );
        assert!(started.elapsed() >= window * 2, "{:?}", started.elapsed());
        assert_eq!(
            seen_rx.await.unwrap(),
            Some(format!("PING :{}", e6irc_client::liveness::KEEPALIVE_TOKEN)),
            "the client asked before giving up"
        );
    }

    /// A server that answers the probe is alive: the session continues, and the
    /// answer to the client's own keepalive is bookkeeping, not conversation.
    #[tokio::test]
    async fn a_server_that_answers_the_probe_keeps_the_session_and_the_answer_stays_out_of_the_log()
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (probes_tx, mut probes_rx) = mpsc::channel(8);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            let mut close_rx = std::pin::pin!(close_rx);
            loop {
                tokio::select! {
                    line = lines.next_line() => {
                        let Ok(Some(line)) = line else { return };
                        if let Some(token) = line.strip_prefix("PING :") {
                            writer.write_all(format!("PONG :{token}\r\n").as_bytes()).await.unwrap();
                            if probes_tx.send(()).await.is_err() {
                                return;
                            }
                        }
                    }
                    _ = &mut close_rx => return,
                }
            }
        });
        let mut conn = Connection::connect(&address).await.unwrap();
        let (net_tx, mut net_rx) = mpsc::channel(8);
        let (_out_tx, mut out_rx) = mpsc::channel::<Queued>(8);
        let window = Duration::from_millis(100);
        let session = tokio::spawn(async move {
            let mut channels = std::collections::BTreeSet::new();
            let mut nick = "me".to_owned();
            relay_session(
                &mut conn,
                &mut out_rx,
                &net_tx,
                &mut channels,
                &mut nick,
                window,
            )
            .await
        });
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(5), probes_rx.recv())
                .await
                .expect("the client keeps probing an idle server")
                .expect("the server task is alive");
        }
        assert!(!session.is_finished(), "an answered probe is a live server");
        assert!(
            net_rx.try_recv().is_err(),
            "the keepalive answer reached the log"
        );
        drop(close_tx);
        let reason = tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("the session ends when the server closes")
            .expect("session task");
        assert_eq!(
            reason,
            SessionEnd::Failed("server closed the connection".into())
        );
    }
}
