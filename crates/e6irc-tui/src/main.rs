//! e6irc-tui — a ratatui IRC client with bounded multi-buffer state, TLS,
//! SASL, and reconnecting transport. Networking runs on a tokio task feeding
//! messages to the render loop over a channel.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use e6irc_client::token_cache::{default_token_path, load_token};
use e6irc_client::{Authentication, ClientEvent, Connection, ConnectionOptions, OwnedMessage};
use e6irc_tui::app::{Action, App};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "e6irc-tui", about = "Terminal IRC client", version)]
struct Cli {
    /// IRC server address (host:port).
    #[arg(long, short)]
    server: String,
    /// Nickname to register with.
    #[arg(long, short)]
    nick: String,
    /// Initial channel to join.
    #[arg(long, short)]
    channel: String,
    /// SASL PLAIN account. For BNC attachment use account/network.
    #[arg(long, requires = "password", conflicts_with = "oauth_token")]
    account: Option<String>,
    /// SASL PLAIN password.
    #[arg(long, requires = "account", conflicts_with = "oauth_token")]
    password: Option<String>,
    /// SASL OAUTHBEARER token.
    #[arg(long, conflicts_with_all = ["account", "password", "oauth_from_cache"])]
    oauth_token: Option<String>,
    /// Load the OAUTHBEARER token created by `e6irc login`.
    #[arg(
        long,
        conflicts_with_all = ["account", "password", "oauth_token"]
    )]
    oauth_from_cache: bool,
    /// Token-cache path used by --oauth-from-cache.
    #[arg(long, requires = "oauth_from_cache")]
    token_file: Option<PathBuf>,
    /// Connect over TLS using the public CA set.
    #[arg(long)]
    tls: bool,
    /// TLS certificate server name; defaults to the host in --server.
    #[arg(long, requires = "tls")]
    tls_name: Option<String>,
    /// Seconds between reconnect attempts after a live connection drops.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=300))]
    reconnect_delay: u64,
    /// Latest messages loaded for each joined channel. Zero disables history.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(0..=1000))]
    history_lines: u64,
    /// Disable draft/read-marker synchronization for servers without the cap.
    #[arg(long)]
    no_read_markers: bool,
}

/// Server events buffered between draws before the reader task waits on the
/// render loop. One screenful of scrollback is generous for a 50 ms poll.
const NET_QUEUE_DEPTH: usize = 1024;

/// Lines awaiting the socket writer. Keyboard input is local, but terminal
/// automation and paste can still outrun a stalled socket; this bound makes
/// admission explicit and lets the UI refuse without a false local echo.
const OUT_QUEUE_DEPTH: usize = 256;

/// Events the render loop consumes.
enum Ev {
    Net(OwnedMessage),
    RejectedInput(String),
    Connected,
    Reconnecting(String),
    DroppedOutbound(usize),
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> io::Result<()> {
    let authentication = match (
        cli.account,
        cli.password,
        cli.oauth_token,
        cli.oauth_from_cache,
    ) {
        (Some(account), Some(password), None, false) => Authentication::Plain { account, password },
        (None, None, Some(token), false) => Authentication::OAuthBearer { token },
        (None, None, None, true) => {
            let path = token_path(cli.token_file.as_deref())?;
            let cached = load_token(&path)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no cached token at {}; run e6irc login", path.display()),
                )
            })?;
            Authentication::OAuthBearer {
                token: cached.access_token().to_owned(),
            }
        }
        (None, None, None, false) => Authentication::None,
        // clap makes this unreachable for command-line input. Keeping the
        // validation here too protects programmatic/parser changes.
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "choose anonymous, paired --account/--password, --oauth-token, or --oauth-from-cache",
            ));
        }
    };
    let connection_options = ConnectionOptions {
        address: cli.server,
        tls: cli.tls,
        tls_server_name: cli.tls_name,
        nick: cli.nick.clone(),
        realname: "e6irc-tui".into(),
        authentication,
    };
    let read_markers = !cli.no_read_markers;
    let joined_channels = std::collections::BTreeSet::from([cli.channel.clone()]);
    let (mut conn, bootstrap) = connect_and_join(
        &connection_options,
        &joined_channels,
        cli.history_lines as usize,
        read_markers,
    )
    .await?;

    // Bounded: the server decides how fast this fills, and the render loop
    // only drains it between draws. A full queue makes the reader task wait,
    // which stops reading the socket and lets TCP apply the backpressure —
    // the same shape as the daemon's SendQ, in the other direction.
    let (net_tx, mut net_rx) = mpsc::channel::<Ev>(NET_QUEUE_DEPTH);
    let (out_tx, mut out_rx) = mpsc::channel::<String>(OUT_QUEUE_DEPTH);

    // Networking task: read messages up, write outbound lines down, and
    // reconnect with the same explicit transport/authentication request.
    let reconnect_delay = Duration::from_secs(cli.reconnect_delay);
    let reconnect_options = connection_options.clone();
    let reconnect_history_lines = cli.history_lines as usize;
    let reconnect_read_markers = read_markers;
    tokio::spawn(async move {
        let mut joined_channels = joined_channels;
        loop {
            let failure = loop {
                tokio::select! {
                    // Lossy steady-state read: one non-UTF-8 line (a Latin-1
                    // channel message any member can post) must not disconnect
                    // the session.
                    msg = conn.next_event_lossy() => match msg {
                        Ok(Some(ClientEvent::Message(m))) => {
                            if m.command == "PING" {
                                let token = m.params.first().cloned().unwrap_or_default();
                                if let Err(error) = conn.send_line(&format!("PONG :{token}")).await {
                                    break format!("PING response failed: {error}");
                                }
                            }
                            update_joined_channels(
                                &mut joined_channels,
                                &reconnect_options.nick,
                                &m,
                            );
                            if net_tx.send(Ev::Net(m)).await.is_err() { return; }
                        }
                        Ok(Some(ClientEvent::Rejected(rejected))) => {
                            if net_tx.send(Ev::RejectedInput(rejected.to_string())).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break "server closed the connection".into(),
                        Err(error) => break format!("connection read failed: {error}"),
                    },
                    line = out_rx.recv() => match line {
                        Some(line) => if let Err(error) = conn.send_line(&line).await {
                            break format!("message write failed: {error}");
                        },
                        None => return,
                    },
                }
            };
            if net_tx.send(Ev::Reconnecting(failure)).await.is_err() {
                return;
            }

            loop {
                // Reject anything that raced the disconnect notification.
                // Delivering it after reconnect would be a surprising delayed
                // send, while leaving its local echo unqualified would be false.
                let mut dropped = 0;
                while out_rx.try_recv().is_ok() {
                    dropped += 1;
                }
                if dropped > 0 && net_tx.send(Ev::DroppedOutbound(dropped)).await.is_err() {
                    return;
                }
                tokio::time::sleep(reconnect_delay).await;
                match connect_and_join(
                    &reconnect_options,
                    &joined_channels,
                    reconnect_history_lines,
                    reconnect_read_markers,
                )
                .await
                {
                    Ok((reconnected, bootstrap)) => {
                        conn = reconnected;
                        if net_tx.send(Ev::Connected).await.is_err() {
                            return;
                        }
                        for message in bootstrap {
                            if net_tx.send(Ev::Net(message)).await.is_err() {
                                return;
                            }
                        }
                        break;
                    }
                    Err(error) => {
                        if net_tx
                            .send(Ev::Reconnecting(format!("reconnect failed: {error}")))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        }
    });

    let mut terminal = ratatui::init();
    let mut app = App::new(cli.channel, cli.nick);
    for message in bootstrap {
        app.on_message(&message);
    }
    let result = run_ui(&mut terminal, &mut app, &mut net_rx, &out_tx).await;
    let restore = ratatui::try_restore();
    match (result, restore) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(run_error), Err(restore_error)) => Err(io::Error::other(format!(
            "UI failed: {run_error}; terminal restoration also failed: {restore_error}"
        ))),
    }
}

fn token_path(explicit: Option<&Path>) -> io::Result<PathBuf> {
    explicit
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(default_token_path)
}

async fn connect_and_join(
    options: &ConnectionOptions,
    channels: &std::collections::BTreeSet<String>,
    history_lines: usize,
    read_markers: bool,
) -> io::Result<(Connection, Vec<OwnedMessage>)> {
    let mut connection = options.connect_registered().await?;
    let mut capabilities = Vec::new();
    if history_lines > 0 {
        capabilities.extend(["batch", "draft/chathistory", "server-time"]);
    }
    if read_markers {
        capabilities.push("draft/read-marker");
    }
    connection.require_capabilities(&capabilities).await?;
    let mut bootstrap = Vec::new();
    for channel in channels {
        bootstrap.extend(connection.join_with_history(channel, history_lines).await?);
    }
    Ok((connection, bootstrap))
}

fn update_joined_channels(
    channels: &mut std::collections::BTreeSet<String>,
    own_nick: &str,
    message: &OwnedMessage,
) {
    if message.command == "KICK"
        && message
            .params
            .get(1)
            .is_some_and(|nick| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(nick, own_nick))
    {
        if let Some(channel) = message.params.first() {
            remove_channel(channels, channel);
        }
        return;
    }
    let source_nick = message
        .source
        .as_deref()
        .and_then(|source| source.split('!').next());
    if !source_nick
        .is_some_and(|nick| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(nick, own_nick))
    {
        return;
    }
    match message.command.as_str() {
        "JOIN" => {
            if let Some(channel) = message.params.first() {
                channels.insert(channel.clone());
            }
        }
        "PART" => {
            if let Some(channel) = message.params.first() {
                remove_channel(channels, channel);
            }
        }
        _ => {}
    }
}

fn remove_channel(channels: &mut std::collections::BTreeSet<String>, channel: &str) {
    let existing = channels
        .iter()
        .find(|candidate| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(candidate, channel))
        .cloned();
    if let Some(existing) = existing {
        channels.remove(&existing);
    }
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    net_rx: &mut mpsc::Receiver<Ev>,
    out_tx: &mpsc::Sender<String>,
) -> io::Result<()> {
    let mut dirty = true;
    loop {
        // Drain any pending network events.
        while let Ok(ev) = net_rx.try_recv() {
            dirty = true;
            match ev {
                Ev::Net(m) => app.on_message(&m),
                Ev::RejectedInput(reason) => {
                    app.status(format!("server input rejected: {reason}"));
                }
                Ev::Connected => {
                    app.set_connected(true);
                    app.status("reconnected");
                }
                Ev::Reconnecting(reason) => {
                    app.set_connected(false);
                    app.status(format!("{reason}; reconnecting"));
                }
                Ev::DroppedOutbound(count) => {
                    app.status(format!(
                        "{count} outbound message(s) were not sent during disconnect"
                    ));
                }
            }
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
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            dirty = true;
            use crossterm::event::KeyModifiers;
            let alt = key.modifiers.contains(KeyModifiers::ALT);
            match key.code {
                KeyCode::Left if alt => app.prev_buffer(),
                KeyCode::Right if alt => app.next_buffer(),
                KeyCode::PageUp => app.scroll_up(10),
                KeyCode::PageDown => app.scroll_down(10),
                KeyCode::Char(c) => app.on_char(c),
                KeyCode::Backspace => app.on_backspace(),
                KeyCode::Esc => return Ok(()),
                KeyCode::Enter => {
                    if let Action::Send(outbound) = app.on_enter() {
                        match out_tx.try_send(outbound.line().to_owned()) {
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
                }
                _ => {}
            }
            flush_read_marker(app, out_tx);
        }
    }
}

fn flush_read_marker(app: &mut App, out_tx: &mpsc::Sender<String>) {
    let Some(command) = app.take_read_marker_command() else {
        return;
    };
    match out_tx.try_send(command) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(command)) => {
            app.requeue_read_marker_command(command);
            app.note_outbound_full();
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            app.set_connected(false);
            app.status("not connected — read marker was not sent");
        }
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(f.area());

    let buf = app.current();
    let height = chunks[0].height.saturating_sub(2) as usize;
    let lines: Vec<Line> = buf
        .visible(height)
        .iter()
        .map(|l| Line::from(format!("<{}> {}", l.from, l.text)))
        .collect();
    // Title shows the buffer and its position; flags scrollback. The buffer
    // name is a server-supplied channel/nick, so neutralize its control bytes
    // for display (the name stays raw in the model for identity/lookup).
    let mut title = format!(
        "{} ({}/{})",
        e6irc_client::TerminalSafe::from_untrusted(&buf.name),
        app.current + 1,
        app.buffers.len()
    );
    if buf.scrolled_back() {
        title.push_str(" [scrollback — PgDn to resume]");
    }
    let log = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(log, chunks[0]);

    // A one-line buffer list makes Alt-←/→ switching discoverable.
    let bar: String = app
        .buffers
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let name = e6irc_client::TerminalSafe::from_untrusted(&b.name);
            let unread = match b.unread() {
                0 => String::new(),
                count => format!(" ({count})"),
            };
            if i == app.current {
                format!("[{name}{unread}]")
            } else {
                format!(" {name}{unread} ")
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("input — Esc quit, Alt-←/→ switch | {bar}")),
    );
    f.render_widget(input, chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn authentication_shapes_are_explicit() {
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--account",
                "alice/work",
                "--password",
                "secret",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--oauth-token",
                "device-token"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--oauth-from-cache"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--oauth-from-cache",
                "--token-file",
                "token.json",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["e6irc-tui", "--token-file", "token.json"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--account", "alice"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--password", "secret"]).is_err());
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--account",
                "alice",
                "--password",
                "secret",
                "--oauth-token",
                "device-token",
            ])
            .is_err()
        );
    }

    #[test]
    fn transport_and_reconnect_constraints_fail_at_argument_parsing() {
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--tls"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--tls",
                "--tls-name",
                "irc.example"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["e6irc-tui", "--tls-name", "irc.example"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--reconnect-delay", "0"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--reconnect-delay", "301"]).is_err());
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
                "alice",
                "--channel",
                "#chat",
                "--history-lines",
                "1000"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["e6irc-tui", "--history-lines", "1001"]).is_err());
    }

    #[test]
    fn server_is_required() {
        assert!(Cli::try_parse_from(["e6irc-tui"]).is_err());
    }

    fn message(raw: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(raw).unwrap())
    }

    #[test]
    fn reconnect_channels_track_self_join_part_and_kick_case_insensitively() {
        let mut channels = std::collections::BTreeSet::from(["#Home".to_owned()]);
        update_joined_channels(&mut channels, "Me", &message(":me!u@h JOIN #Other"));
        assert!(channels.contains("#Other"));
        update_joined_channels(&mut channels, "Me", &message(":ME!u@h PART #other :bye"));
        assert!(
            !channels
                .iter()
                .any(|channel| channel.eq_ignore_ascii_case("#other"))
        );
        update_joined_channels(&mut channels, "Me", &message(":op!u@h KICK #home mE :gone"));
        assert!(channels.is_empty());
    }
}
