//! e6irc-tui — a ratatui IRC client with bounded multi-buffer state, TLS,
//! SASL, and reconnecting transport. Networking runs on a tokio task feeding
//! messages to the render loop over a channel.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use e6irc_client::token_cache::{default_token_path, load_token};
use e6irc_client::{
    Authentication, ClientEvent, Connection, ConnectionOptions, JoinRefusal, OwnedMessage,
    Registered,
};
use e6irc_tui::app::{Action, App};
use e6irc_tui::reconnect::{AfterFailure, ReconnectPolicy};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Position};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;
use unicode_width::UnicodeWidthStr;

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
    /// Seconds before the first reconnect attempt after a live connection
    /// drops. Each further failed attempt doubles the wait, up to five minutes;
    /// rejected credentials and bans are not retried at all.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=300))]
    reconnect_delay: u64,
    /// Seconds the server may take to finish registration, and afterwards to
    /// confirm each JOIN with its history, before the attempt is abandoned.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    response_timeout: u64,
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
    Net(ClientEvent),
    /// A new session is registered under this server-confirmed nickname.
    Connected(String),
    JoinRefused(JoinRefusal),
    Reconnecting(String),
    /// The network task gave up for good; the text says why.
    Stopped(String),
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
        response_deadline: Duration::from_secs(cli.response_timeout),
    };
    let read_markers = !cli.no_read_markers;
    let mut joined_channels = std::collections::BTreeSet::from([cli.channel.clone()]);
    let Session {
        connection: mut conn,
        nick: confirmed_nick,
        bootstrap,
        refused,
    } = connect_and_join(
        &connection_options,
        &mut joined_channels,
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
    let mut policy = ReconnectPolicy::new(Duration::from_secs(cli.reconnect_delay));
    let mut own_nick = confirmed_nick.clone();
    let reconnect_options = connection_options.clone();
    let reconnect_history_lines = cli.history_lines as usize;
    let reconnect_read_markers = read_markers;
    tokio::spawn(async move {
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
                            track_own_state(&mut joined_channels, &mut own_nick, &m);
                            if net_tx.send(Ev::Net(ClientEvent::Message(m))).await.is_err() { return; }
                        }
                        Ok(Some(rejected @ ClientEvent::Rejected(_))) => {
                            if net_tx.send(Ev::Net(rejected)).await.is_err() {
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

            let mut delay = policy.first_delay();
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
                tokio::time::sleep(delay).await;
                let attempt = connect_and_join(
                    &reconnect_options,
                    &mut joined_channels,
                    reconnect_history_lines,
                    reconnect_read_markers,
                )
                .await;
                let outcome = match attempt {
                    Ok(session) => {
                        policy.connected();
                        conn = session.connection;
                        own_nick = session.nick.clone();
                        let mut events = vec![Ev::Connected(session.nick)];
                        events.extend(session.refused.into_iter().map(Ev::JoinRefused));
                        events.extend(session.bootstrap.into_iter().map(Ev::Net));
                        Ok(events)
                    }
                    Err(error) => match policy.after(&error) {
                        AfterFailure::Stop(status) => Err(Ev::Stopped(status)),
                        AfterFailure::RetryAfter(next) => {
                            delay = next;
                            Ok(vec![Ev::Reconnecting(format!(
                                "reconnect failed: {error}; next attempt in {}s",
                                next.as_secs()
                            ))])
                        }
                    },
                };
                match outcome {
                    Ok(events) => {
                        let connected = matches!(events.first(), Some(Ev::Connected(_)));
                        for event in events {
                            if net_tx.send(event).await.is_err() {
                                return;
                            }
                        }
                        if connected {
                            break;
                        }
                    }
                    // Dropping `out_rx` with this task is what makes the UI
                    // refuse further input instead of queueing it for nobody.
                    Err(stopped) => {
                        drop(net_tx.send(stopped).await);
                        return;
                    }
                }
            }
        }
    });

    let mut terminal = ratatui::init();
    let mut app = App::new(cli.channel, confirmed_nick);
    for refusal in refused {
        apply(&mut app, Ev::JoinRefused(refusal));
    }
    for event in bootstrap {
        apply(&mut app, Ev::Net(event));
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

/// A registered connection and everything the UI starts a session from.
struct Session {
    connection: Connection,
    /// The nickname the server confirmed, which is not always the one asked for.
    nick: String,
    bootstrap: Vec<ClientEvent>,
    refused: Vec<JoinRefusal>,
}

/// Register and join `channels`. A channel the server refuses is taken out of
/// the set and reported: one closed channel must not fail the whole session,
/// or every reconnect registers, is refused the same channel, and drops again.
async fn connect_and_join(
    options: &ConnectionOptions,
    channels: &mut std::collections::BTreeSet<String>,
    history_lines: usize,
    read_markers: bool,
) -> io::Result<Session> {
    let Registered {
        mut connection,
        nick,
    } = options.connect_registered().await?;
    let mut capabilities = Vec::new();
    if history_lines > 0 {
        capabilities.extend(["batch", "draft/chathistory", "server-time"]);
    }
    if read_markers {
        capabilities.push("draft/read-marker");
    }
    connection.require_capabilities(&capabilities).await?;
    let mut bootstrap = Vec::new();
    let mut refused = Vec::new();
    for channel in channels.clone() {
        match connection.join_with_history(&channel, history_lines).await {
            Ok(events) => bootstrap.extend(events),
            Err(error) => {
                let Some(refusal) = JoinRefusal::from_error(&error) else {
                    return Err(error);
                };
                channels.remove(&channel);
                refused.push(refusal);
            }
        }
    }
    Ok(Session {
        connection,
        nick,
        bootstrap,
        refused,
    })
}

/// Keep what a reconnect needs in step with the server: the channels this
/// client is in, and the nickname it is known by — own JOIN, PART and KICK are
/// only recognisable under the current one.
fn track_own_state(
    channels: &mut std::collections::BTreeSet<String>,
    own_nick: &mut String,
    message: &OwnedMessage,
) {
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    if message.command == "KICK"
        && message
            .params
            .get(1)
            .is_some_and(|nick| casemap.eq(nick, own_nick))
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
    if !source_nick.is_some_and(|nick| casemap.eq(nick, own_nick)) {
        return;
    }
    match (message.command.as_str(), message.params.first()) {
        ("JOIN", Some(channel)) => {
            channels.insert(channel.clone());
        }
        ("PART", Some(channel)) => remove_channel(channels, channel),
        ("NICK", Some(nick)) => own_nick.clone_from(nick),
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
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            dirty = true;
            use crossterm::event::KeyModifiers;
            let alt = key.modifiers.contains(KeyModifiers::ALT);
            let control = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Left if alt => app.prev_buffer(),
                KeyCode::Right if alt => app.next_buffer(),
                KeyCode::Left => app.move_input_left(),
                KeyCode::Right => app.move_input_right(),
                KeyCode::Home => app.move_input_home(),
                KeyCode::PageUp => app.scroll_up(10),
                KeyCode::PageDown => app.scroll_down(10),
                KeyCode::End if control => app.jump_latest(),
                KeyCode::End => app.move_input_end(),
                KeyCode::Char('c' | 'C') if control => return Ok(()),
                KeyCode::Char('u' | 'U') if control => app.clear_input(),
                KeyCode::Char(c) if !control => app.on_char(c),
                KeyCode::Backspace => app.on_backspace(),
                KeyCode::Delete => app.on_delete(),
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

/// Fold one network-task event into the UI state.
fn apply(app: &mut App, event: Ev) {
    match event {
        Ev::Net(ClientEvent::Message(message)) => app.on_message(&message),
        Ev::Net(ClientEvent::Rejected(rejected)) => {
            app.status(format!("server input rejected: {rejected}"));
        }
        Ev::Connected(nick) => {
            app.set_nick(&nick);
            app.set_connected(true);
            app.status(format!("reconnected as {nick}"));
        }
        Ev::JoinRefused(refusal) => {
            app.status(format!("{refusal}; it will not be rejoined"));
        }
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
    let lines: Vec<Line> = buf
        .visible(height)
        .iter()
        .map(|line| {
            let route = if line.from.as_str() == "*" {
                Span::styled(
                    " route ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!(" {} ", line.from),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            };
            Line::from(vec![
                route,
                Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                Span::raw(line.text.to_string()),
            ])
        })
        .collect();
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
        Paragraph::new(
            " Alt-←/→ switch · PgUp/PgDn scroll · Ctrl-End latest · /help commands · Esc/Ctrl-C quit",
        )
        .style(Style::default().fg(Color::DarkGray)),
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

fn composer_view(input: &str, cursor: usize, width: u16) -> (u16, u16) {
    let input_width = UnicodeWidthStr::width(&input[..cursor]);
    let visible_width = usize::from(width).saturating_sub(1);
    let horizontal_scroll = input_width.saturating_sub(visible_width);
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

    fn parses(arguments: &[&str]) -> bool {
        Cli::try_parse_from(
            [
                "e6irc-tui",
                "--server",
                "irc.example:6697",
                "--nick",
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
        assert!(!parses(&["--account", "alice"]));
        assert!(!parses(&["--password", "secret"]));
        assert!(!parses(&[
            "--account",
            "alice",
            "--password",
            "secret",
            "--oauth-token",
            "device-token",
        ]));
    }

    #[test]
    fn transport_and_reconnect_constraints_fail_at_argument_parsing() {
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
        let mut app = App::new("#home".into(), "me".into());
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
    }

    #[test]
    fn tiny_terminals_render_without_panicking() {
        let app = App::new("#home".into(), "me".into());
        for (width, height) in [(1, 1), (10, 3), (24, 5)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
        }
    }

    #[test]
    fn reconnect_channels_track_self_join_part_and_kick_case_insensitively() {
        let mut channels = std::collections::BTreeSet::from(["#Home".to_owned()]);
        let mut nick = "Me".to_owned();
        track_own_state(&mut channels, &mut nick, &message(":me!u@h JOIN #Other"));
        assert!(channels.contains("#Other"));
        track_own_state(
            &mut channels,
            &mut nick,
            &message(":ME!u@h PART #other :bye"),
        );
        assert!(
            !channels
                .iter()
                .any(|channel| channel.eq_ignore_ascii_case("#other"))
        );
        // Own joins are only recognisable under the current nickname.
        track_own_state(&mut channels, &mut nick, &message(":me!u@h NICK Renamed"));
        assert_eq!(nick, "Renamed");
        track_own_state(
            &mut channels,
            &mut nick,
            &message(":renamed!u@h JOIN #later"),
        );
        assert!(channels.contains("#later"));
        track_own_state(&mut channels, &mut nick, &message(":me!u@h JOIN #not-ours"));
        assert!(!channels.contains("#not-ours"));
        track_own_state(
            &mut channels,
            &mut nick,
            &message(":op!u@h KICK #home RENAMED :gone"),
        );
        assert_eq!(
            channels,
            std::collections::BTreeSet::from(["#later".to_owned()])
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
            realname: "real".into(),
            authentication: Authentication::None,
            response_deadline: Duration::from_secs(5),
        };
        let mut channels =
            std::collections::BTreeSet::from(["#closed".to_owned(), "#open".to_owned()]);
        let session = connect_and_join(&options, &mut channels, 0, false)
            .await
            .expect("a refused channel does not fail the session");
        assert_eq!(session.nick, "upstream");
        assert_eq!(
            channels,
            std::collections::BTreeSet::from(["#open".to_owned()])
        );
        assert_eq!(session.refused.len(), 1);

        let mut app = App::new("#open".into(), session.nick);
        for refusal in session.refused {
            apply(&mut app, Ev::JoinRefused(refusal));
        }
        let shown = app.current().log.last().expect("status").text.to_string();
        assert_eq!(
            shown,
            "cannot join #closed: Cannot join channel (+i); it will not be rejoined"
        );

        apply(
            &mut app,
            Ev::Stopped("the server banned this connection".into()),
        );
        assert!(app.gave_up() && !app.connected());
    }
}
