//! e6irc-tui — a minimal ratatui IRC client: one channel, a scrollback
//! pane, and an input line. Networking runs on a tokio task feeding
//! messages to the render loop over a channel.

use std::io;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use e6irc_client::{Connection, OwnedMessage};
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
}

/// Events the render loop consumes.
enum Ev {
    Net(OwnedMessage),
    Disconnected,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> io::Result<()> {
    let mut conn = Connection::connect(&cli.server).await?;
    conn.register(&cli.nick, "e6irc-tui").await?;
    conn.send_line(&format!("JOIN {}", cli.channel)).await?;

    let (net_tx, mut net_rx) = mpsc::unbounded_channel::<Ev>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    // Networking task: read messages up, write outbound lines down.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = conn.next_message() => match msg {
                    Ok(Some(m)) => {
                        if m.command == "PING" {
                            let token = m.params.first().cloned().unwrap_or_default();
                            let _ = conn.send_line(&format!("PONG :{token}")).await;
                        }
                        if net_tx.send(Ev::Net(m)).is_err() { break; }
                    }
                    _ => { let _ = net_tx.send(Ev::Disconnected); break; }
                },
                line = out_rx.recv() => match line {
                    Some(l) => { let _ = conn.send_line(&l).await; }
                    None => break,
                },
            }
        }
    });

    let mut terminal = ratatui::init();
    let mut app = App::new(cli.channel, cli.nick);
    let result = run_ui(&mut terminal, &mut app, &mut net_rx, &out_tx).await;
    ratatui::restore();
    result
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    net_rx: &mut mpsc::UnboundedReceiver<Ev>,
    out_tx: &mpsc::UnboundedSender<String>,
) -> io::Result<()> {
    loop {
        // Drain any pending network events.
        while let Ok(ev) = net_rx.try_recv() {
            match ev {
                Ev::Net(m) => app.on_message(&m),
                Ev::Disconnected => app.status("disconnected"),
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
                        let _ = out_tx.send(line);
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
    // Title shows the buffer and its position; flags scrollback.
    let mut title = format!("{} ({}/{})", buf.name, app.current + 1, app.buffers.len());
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
            if i == app.current {
                format!("[{}]", b.name)
            } else {
                format!(" {} ", b.name)
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
