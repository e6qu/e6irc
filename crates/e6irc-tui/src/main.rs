//! e6irc-tui — a ratatui IRC client with bounded multi-buffer state, TLS,
//! SASL, and reconnecting transport. Networking runs on a tokio task feeding
//! messages to the render loop over a channel.

use std::io;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use e6irc_client::{Authentication, Connection, ConnectionOptions, OwnedMessage};
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
    #[arg(long, short, default_value = "127.0.0.1:6667")]
    server: String,
    #[arg(long, short, default_value = "e6irc")]
    nick: String,
    #[arg(long, short, default_value = "#e6irc")]
    channel: String,
    /// SASL PLAIN account. For BNC attachment use account/network.
    #[arg(long, requires = "password", conflicts_with = "oauth_token")]
    account: Option<String>,
    /// SASL PLAIN password.
    #[arg(long, requires = "account", conflicts_with = "oauth_token")]
    password: Option<String>,
    /// SASL OAUTHBEARER token.
    #[arg(long, conflicts_with_all = ["account", "password"])]
    oauth_token: Option<String>,
    /// Connect over TLS using the public CA set.
    #[arg(long)]
    tls: bool,
    /// TLS certificate server name; defaults to the host in --server.
    #[arg(long, requires = "tls")]
    tls_name: Option<String>,
    /// Seconds between reconnect attempts after a live connection drops.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=300))]
    reconnect_delay: u64,
}

/// Server events buffered between draws before the reader task waits on the
/// render loop. One screenful of scrollback is generous for a 50 ms poll.
const NET_QUEUE_DEPTH: usize = 1024;

/// Events the render loop consumes.
enum Ev {
    Net(OwnedMessage),
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
    let authentication = match (cli.account, cli.password, cli.oauth_token) {
        (Some(account), Some(password), None) => Authentication::Plain { account, password },
        (None, None, Some(token)) => Authentication::OAuthBearer { token },
        (None, None, None) => Authentication::None,
        // clap makes this unreachable for command-line input. Keeping the
        // validation here too protects programmatic/parser changes.
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--account and --password must be paired and cannot be combined with --oauth-token",
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
    let mut conn = connect_and_join(&connection_options, &cli.channel).await?;

    // Bounded: the server decides how fast this fills, and the render loop
    // only drains it between draws. A full queue makes the reader task wait,
    // which stops reading the socket and lets TCP apply the backpressure —
    // the same shape as the daemon's SendQ, in the other direction.
    let (net_tx, mut net_rx) = mpsc::channel::<Ev>(NET_QUEUE_DEPTH);
    // Outbound is unbounded because a human at a keyboard fills it.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    // Networking task: read messages up, write outbound lines down, and
    // reconnect with the same explicit transport/authentication request.
    let reconnect_delay = Duration::from_secs(cli.reconnect_delay);
    let reconnect_options = connection_options.clone();
    let reconnect_channel = cli.channel.clone();
    tokio::spawn(async move {
        loop {
            let failure = loop {
                tokio::select! {
                    // Lossy steady-state read: one non-UTF-8 line (a Latin-1
                    // channel message any member can post) must not disconnect
                    // the session.
                    msg = conn.next_message_lossy() => match msg {
                        Ok(Some(m)) => {
                            if m.command == "PING" {
                                let token = m.params.first().cloned().unwrap_or_default();
                                if let Err(error) = conn.send_line(&format!("PONG :{token}")).await {
                                    break format!("PING response failed: {error}");
                                }
                            }
                            if net_tx.send(Ev::Net(m)).await.is_err() { return; }
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
                match connect_and_join(&reconnect_options, &reconnect_channel).await {
                    Ok(reconnected) => {
                        conn = reconnected;
                        if net_tx.send(Ev::Connected).await.is_err() {
                            return;
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
    let result = run_ui(&mut terminal, &mut app, &mut net_rx, &out_tx).await;
    ratatui::restore();
    result
}

async fn connect_and_join(options: &ConnectionOptions, channel: &str) -> io::Result<Connection> {
    let mut connection = options.connect_registered().await?;
    connection.send_line(&format!("JOIN {channel}")).await?;
    Ok(connection)
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    net_rx: &mut mpsc::Receiver<Ev>,
    out_tx: &mpsc::UnboundedSender<String>,
) -> io::Result<()> {
    loop {
        // Drain any pending network events.
        while let Ok(ev) = net_rx.try_recv() {
            match ev {
                Ev::Net(m) => app.on_message(&m),
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
        terminal.draw(|f| draw(f, app))?;
        if app.should_quit {
            return Ok(());
        }
        // Poll for input with a short timeout so network events still flow.
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
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
                    if let Action::Send(line) = app.on_enter() {
                        // The app refuses input once it has observed a
                        // disconnect. Surface the narrower race where the
                        // network task has already ended.
                        if out_tx.send(line).is_err() {
                            app.status("not connected — message not sent");
                        }
                    }
                }
                _ => {}
            }
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
            if i == app.current {
                format!("[{name}]")
            } else {
                format!(" {name} ")
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
    use super::Cli;
    use clap::Parser;

    #[test]
    fn authentication_shapes_are_explicit() {
        assert!(
            Cli::try_parse_from([
                "e6irc-tui",
                "--account",
                "alice/work",
                "--password",
                "secret",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["e6irc-tui", "--oauth-token", "device-token"]).is_ok());
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
        assert!(Cli::try_parse_from(["e6irc-tui", "--tls"]).is_ok());
        assert!(Cli::try_parse_from(["e6irc-tui", "--tls", "--tls-name", "irc.example"]).is_ok());
        assert!(Cli::try_parse_from(["e6irc-tui", "--tls-name", "irc.example"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--reconnect-delay", "0"]).is_err());
        assert!(Cli::try_parse_from(["e6irc-tui", "--reconnect-delay", "301"]).is_err());
    }
}
