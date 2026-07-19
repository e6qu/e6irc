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
        if self.lines.len() == self.cap {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
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

    /// Build a handle and the driver-side endpoints. A driver spawns a
    /// task that reads commands, records lines to the buffer, and
    /// broadcasts events through the returned [`DriverEnds`].
    pub fn channels(buffer_cap: usize) -> (NetworkHandle, DriverEnds) {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Buffer::new(buffer_cap)));
        let handle = NetworkHandle {
            events: events.clone(),
            commands: command_tx,
            buffer: buffer.clone(),
        };
        let ends = DriverEnds {
            events,
            commands: command_rx,
            buffer,
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
}

impl DriverEnds {
    /// Record a line to the detached buffer and broadcast it live.
    pub fn emit_line(&self, line: String) {
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .push(line.clone());
        let _ = self.events.send(DriverEvent::Line(line));
    }

    /// Broadcast a non-line event (Connected/Disconnected).
    pub fn emit(&self, event: DriverEvent) {
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

    // Playback: everything buffered while detached, in order.
    for line in handle.buffer_snapshot() {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    // A fresh subscription for live events; clone the command sender.
    let commands = handle.commands.clone();
    let mut events = handle.events.subscribe();

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
                // Lagged (slow client): skip the gap and keep going.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            // Client -> upstream.
            n = read.read(&mut read_buf) => match n {
                Ok(0) => break, // client detached
                Ok(n) => {
                    framing.feed(&read_buf[..n], &mut parsed);
                    for event in parsed.drain(..) {
                        if let LineEvent::Line(line) = event
                            && let Ok(text) = String::from_utf8(line)
                            && commands.send(text).is_err()
                        {
                            return Ok(()); // driver gone
                        }
                    }
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}
