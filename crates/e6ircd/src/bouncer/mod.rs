//! BNC (bouncer) subsystem: persistent connections to external IRC
//! networks on behalf of a user (DESIGN §10.3). Each network is an
//! always-on [`IrcNetwork`] driver running on its own task; the
//! buffering and attach logic above the drivers is shared.
//!
//! The [`Registry`] holds the running drivers keyed by (owner, name) and
//! is mutable at runtime, so accounts add and remove their own networks
//! (persisted in the `bnc_networks` table, upstream secrets sealed).
//! [`bnc_serve`] authenticates an attaching client with SASL PLAIN and
//! hands its socket to [`attach`], which replays the detached buffer and
//! relays live traffic both ways.

#[cfg(feature = "discord")]
mod discord;
mod irc_driver;
mod local_driver;
#[cfg(feature = "matrix")]
mod matrix;
mod serve;
#[cfg(feature = "slack")]
mod slack;

#[cfg(feature = "discord")]
pub use discord::{DiscordConfig, DiscordDriver};
pub use irc_driver::{IrcNetwork, NetworkConfig};
pub use local_driver::{CoreHandles, LocalDriver};
#[cfg(feature = "matrix")]
pub use matrix::{MatrixConfig, MatrixDriver};
pub use serve::{Registry, bnc_serve};
#[cfg(feature = "slack")]
pub use slack::{SlackConfig, SlackDriver};

/// Build a driver config from a stored network row, decrypting its
/// sealed upstream SASL password with the master key. Fails loudly if a
/// sealed secret is present but no key is configured, or it won't open.
pub fn network_config_from_row(
    row: &crate::db::BncNetworkRow,
    key: Option<&crate::secret::SecretKey>,
) -> Result<NetworkConfig, String> {
    let sasl = match (&row.sasl_account, &row.sasl_password_sealed) {
        (Some(account), Some(sealed)) => {
            let key =
                key.ok_or("stored upstream secret present but no master key is configured")?;
            let password = key.open(sealed).map_err(|e| e.to_string())?;
            Some((account.clone(), password))
        }
        _ => None,
    };
    Ok(NetworkConfig {
        addr: row.addr.clone(),
        tls: row.tls,
        nick: row.nick.clone(),
        realname: row.realname.clone().unwrap_or_else(|| row.nick.clone()),
        autojoin: row.autojoin.clone(),
        buffer_cap: 1000,
        sasl,
    })
}

use tokio::sync::mpsc;

/// Outcome of one driver session attempt, for the always-on drivers'
/// reconnect loops: the owner dropped the handle (stop for good), or the
/// upstream connection dropped and the driver should reconnect with backoff.
/// Reconnecting from scratch is intentionally simple (it re-syncs/re-joins
/// rather than resuming); losing that optimization is far better than the
/// task dying on the first disconnect and silently dropping all later
/// upstream traffic.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) enum SessionOutcome {
    Stopped,
    Dropped,
}

/// Classification of a downstream client command by a bridge, so a message
/// that can't be delivered upstream is surfaced rather than silently dropped.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RouteResult {
    /// A PRIVMSG mapped to `(upstream_id, text)`; deliver it.
    Deliver(String, String),
    /// A PRIVMSG to `target` that maps to no bridged channel — surface loss.
    Unmapped(String),
    /// Not a deliverable message command (control/other) — ignore quietly.
    Ignore,
}

/// Classify a downstream client line for a bridge: the single choke point all
/// three bridges share (Discord/Slack/Matrix), so the routing policy lives in
/// one place. `targets` maps a bridged channel name to its upstream id.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn route_privmsg(
    line: &str,
    targets: &std::collections::HashMap<String, String>,
) -> RouteResult {
    let Ok(msg) = e6irc_proto::message::Message::parse(line) else {
        return RouteResult::Ignore;
    };
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return RouteResult::Ignore;
    }
    let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) else {
        return RouteResult::Ignore;
    };
    match targets.get(*target) {
        Some(id) => RouteResult::Deliver(id.clone(), text.to_string()),
        None => RouteResult::Unmapped(target.to_string()),
    }
}

/// An event a driver emits upward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    /// The upstream connection registered successfully.
    Connected,
    /// One line received from upstream (CRLF stripped).
    Line(String),
    /// The upstream connection dropped; the driver will retry.
    Disconnected,
}

/// A handle to a running, always-on network driver. Events are
/// broadcast, so any number of clients can attach concurrently and the
/// driver keeps running while zero are attached.
pub struct NetworkHandle {
    events: tokio::sync::broadcast::Sender<DriverEvent>,
    commands: mpsc::UnboundedSender<String>,
    /// Detached buffer of recent upstream lines (newest last).
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    /// Sticky connection state: set on Connected, cleared on Disconnected.
    /// A live `Connected` event is broadcast-only and missed by a client
    /// that subscribes just after it fires; this flag lets any observer
    /// read the current state regardless of subscribe timing.
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Bounded ring of recent upstream lines, for playback on attach.
#[derive(Default)]
pub struct Buffer {
    lines: std::collections::VecDeque<String>,
    cap: usize,
}

impl Buffer {
    fn new(cap: usize) -> Self {
        Self {
            lines: std::collections::VecDeque::new(),
            cap,
        }
    }
    fn push(&mut self, line: String) {
        // `>=` (not `==`) so a zero/under-filled cap can never let the ring
        // grow without bound.
        while self.lines.len() >= self.cap.max(1) {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

/// Neutralize embedded CR/LF/NUL in a synthesized upstream line before it is
/// buffered or broadcast to attached clients. A bridge builds lines from
/// free-form remote text (Discord/Slack/Matrix message bodies); an embedded
/// newline would otherwise let that text inject a second, forged IRC line
/// into the client's stream. Real IRC-upstream lines never carry these bytes
/// (the framing splits on them), so this is a no-op fast path for them.
fn sanitize_upstream_line(line: String) -> String {
    if line.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        line.chars()
            .map(|c| {
                if matches!(c, '\r' | '\n' | '\0') {
                    ' '
                } else {
                    c
                }
            })
            .collect()
    } else {
        line
    }
}

impl NetworkHandle {
    /// Send a raw line to the upstream network.
    pub fn send(&self, line: &str) -> bool {
        self.commands.send(line.to_string()).is_ok()
    }

    /// A copy of the current detached buffer (for attach playback).
    pub fn buffer_snapshot(&self) -> Vec<String> {
        self.buffer.lock().expect("buffer poisoned").snapshot()
    }

    /// Prepend older (oldest-first) lines to the front of the buffer,
    /// used once at start to restore persisted backlog. Never evicts
    /// lines already present (they are newer); only the remaining
    /// capacity is filled, keeping the most recent of `older`.
    pub fn preload_front(&self, older: Vec<String>) {
        let mut buf = self.buffer.lock().expect("buffer poisoned");
        let room = buf.cap.saturating_sub(buf.lines.len());
        let skip = older.len().saturating_sub(room);
        for line in older[skip..].iter().rev() {
            buf.lines.push_front(line.clone());
        }
    }

    /// Subscribe to the driver's event stream (one receiver per attach).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DriverEvent> {
        self.events.subscribe()
    }

    /// The current upstream connection state. Unlike the `Connected` event
    /// this is not lost to subscribe timing — safe to poll after `start`.
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Build a handle and the driver-side endpoints. A driver spawns a
    /// task that reads commands, records lines to the buffer, and
    /// broadcasts events through the returned [`DriverEnds`].
    pub fn channels(buffer_cap: usize) -> (NetworkHandle, DriverEnds) {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Buffer::new(buffer_cap)));
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = NetworkHandle {
            events: events.clone(),
            commands: command_tx,
            buffer: buffer.clone(),
            connected: connected.clone(),
        };
        let ends = DriverEnds {
            events,
            commands: command_rx,
            buffer,
            connected,
        };
        (handle, ends)
    }
}

/// The driver-side endpoints of a [`NetworkHandle`]. A [`NetworkDriver`]
/// implementation owns these: it receives downstream commands, records
/// upstream lines to the detached buffer, and broadcasts live events.
pub struct DriverEnds {
    events: tokio::sync::broadcast::Sender<DriverEvent>,
    commands: mpsc::UnboundedReceiver<String>,
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl DriverEnds {
    /// Record a line to the detached buffer and broadcast it live. The line
    /// is neutralized first (see [`sanitize_upstream_line`]) so a bridge that
    /// builds it from free-form remote text cannot inject a second IRC line
    /// into an attached client's stream.
    pub fn emit_line(&self, line: String) {
        let line = sanitize_upstream_line(line);
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .push(line.clone());
        let _ = self.events.send(DriverEvent::Line(line));
    }

    /// Broadcast a non-line event (Connected/Disconnected), updating the
    /// sticky connection state so late subscribers can still read it.
    pub fn emit(&self, event: DriverEvent) {
        match event {
            DriverEvent::Connected => {
                self.connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            DriverEvent::Disconnected => {
                self.connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            DriverEvent::Line(_) => {}
        }
        let _ = self.events.send(event);
    }

    /// Await the next downstream command; `None` when every handle is
    /// dropped (the driver should then stop).
    pub async fn next_command(&mut self) -> Option<String> {
        self.commands.recv().await
    }
}

/// A network driver: an always-on connection to some upstream (IRC, or a
/// bridge to Matrix/Discord/Slack) presented to the user as a network.
/// `start` consumes the driver and spawns its task, returning the handle
/// clients attach to. (DESIGN §10.5)
pub trait NetworkDriver: Send + 'static {
    /// Stable kind name for logs/metrics (`irc`, `loopback`, …).
    fn kind(&self) -> &'static str;
    /// Spawn the always-on task and return its handle.
    fn start(self: Box<Self>) -> NetworkHandle;
}

/// The `irc` driver as a [`NetworkDriver`]: a persistent IRCv3 client.
pub struct IrcDriver {
    config: NetworkConfig,
}

impl IrcDriver {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for IrcDriver {
    fn kind(&self) -> &'static str {
        "irc"
    }
    fn start(self: Box<Self>) -> NetworkHandle {
        IrcNetwork::start(self.config)
    }
}

/// Reference driver used by the SPI test kit and as a template for real
/// bridges: it registers immediately and echoes every downstream command
/// back as an upstream line, so attach/buffer/relay can be exercised with
/// no external service.
pub struct LoopbackDriver {
    buffer_cap: usize,
}

impl LoopbackDriver {
    pub fn new(buffer_cap: usize) -> Self {
        Self { buffer_cap }
    }
}

impl NetworkDriver for LoopbackDriver {
    fn kind(&self) -> &'static str {
        "loopback"
    }
    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, mut ends) = NetworkHandle::channels(self.buffer_cap);
        tokio::spawn(async move {
            ends.emit(DriverEvent::Connected);
            while let Some(line) = ends.next_command().await {
                ends.emit_line(line);
            }
        });
        handle
    }
}

/// Attach a downstream client stream to a running network: replay the
/// detached buffer, then bidirectionally relay driver events to the
/// client and client lines to the upstream. Returns when either side
/// closes. This is the session multiplexer's core operation — the same
/// function will serve the `local` driver once that lands.
pub async fn attach<S>(stream: S, handle: &NetworkHandle) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use e6irc_proto::framing::{LineBuffer, LineEvent};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut read, mut write) = tokio::io::split(stream);

    // Subscribe BEFORE snapshotting the buffer, so a line the driver emits
    // during playback is caught by the subscription instead of falling into
    // the gap between the two (a duplicated backlog line is harmless; a lost
    // one is not). This mirrors the persistence task's ordering.
    let commands = handle.commands.clone();
    let mut events = handle.events.subscribe();

    // Playback: everything buffered while detached, in order.
    for line in handle.buffer_snapshot() {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    let mut framing = LineBuffer::new(4096 + 510);
    let mut read_buf = vec![0u8; 8192];
    let mut parsed = Vec::new();
    loop {
        tokio::select! {
            // Upstream -> client.
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    write.write_all(line.as_bytes()).await?;
                    write.write_all(b"\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Connected) => {
                    write.write_all(b":*bnc* NOTICE * :upstream connected\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Disconnected) => {
                    write.write_all(b":*bnc* NOTICE * :upstream disconnected\r\n").await?;
                    write.flush().await?;
                }
                // Lagged (slow client): the gap is unrecoverable, but surface
                // it rather than dropping upstream lines silently.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    write
                        .write_all(
                            format!(":*bnc* NOTICE * :dropped {n} line(s); client too slow\r\n")
                                .as_bytes(),
                        )
                        .await?;
                    write.flush().await?;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            // Client -> upstream.
            n = read.read(&mut read_buf) => match n {
                Ok(0) => break, // client detached
                Ok(n) => {
                    framing.feed(&read_buf[..n], &mut parsed);
                    for event in parsed.drain(..) {
                        match event {
                            LineEvent::Line(line) => match String::from_utf8(line) {
                                Ok(text) => {
                                    if commands.send(text).is_err() {
                                        return Ok(()); // driver gone
                                    }
                                }
                                // This relay is UTF-8, like the core ingest
                                // path; reject a non-UTF-8 line loudly rather
                                // than swallowing it.
                                Err(_) => {
                                    write
                                        .write_all(
                                            b":*bnc* NOTICE * :input was not valid UTF-8; not sent upstream\r\n",
                                        )
                                        .await?;
                                    write.flush().await?;
                                }
                            },
                            // The framing contract forbids silently dropping an
                            // over-long line; tell the client its line was not
                            // relayed rather than swallowing it.
                            LineEvent::TooLong => {
                                write
                                    .write_all(
                                        b":*bnc* NOTICE * :input line too long; not sent upstream\r\n",
                                    )
                                    .await?;
                                write.flush().await?;
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_neutralizes_embedded_crlf_and_nul() {
        // A bridge-synthesized line carrying an embedded newline must not be
        // able to inject a second IRC line into an attached client's stream.
        let injected =
            ":a!a@bridge PRIVMSG #c :hi\r\n:nickserv!s@svc PRIVMSG victim :give me your password";
        let safe = sanitize_upstream_line(injected.to_string());
        assert!(!safe.contains('\r') && !safe.contains('\n'));
        assert!(!safe.contains('\0'));
        // A clean line is returned unchanged (fast path).
        let clean = ":a!a@irc PRIVMSG #c :hello there".to_string();
        assert_eq!(sanitize_upstream_line(clean.clone()), clean);
    }

    #[test]
    fn buffer_never_grows_past_cap() {
        let mut b = Buffer::new(3);
        for i in 0..100 {
            b.push(format!("line{i}"));
        }
        assert_eq!(b.snapshot().len(), 3, "ring must stay bounded at cap");
        // A degenerate cap of 0 must still be bounded, not unbounded.
        let mut z = Buffer::new(0);
        for i in 0..100 {
            z.push(format!("line{i}"));
        }
        assert!(z.snapshot().len() <= 1, "cap 0 must not grow without bound");
    }
}
