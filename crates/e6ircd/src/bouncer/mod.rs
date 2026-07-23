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

/// Jittered exponential reconnect backoff shared by every always-on driver, so
/// their reconnect timing stays identical in one place. Starts at 200ms,
/// doubles per drop, caps at 30s, and resets once a session lasted long enough
/// (≥10s) to have clearly connected — otherwise a flapping-but-reachable
/// upstream would ratchet toward the cap forever. Jitter is a coarse
/// deterministic function of the delay (no RNG), enough to spread reconnects.
pub(crate) struct Backoff {
    current: std::time::Duration,
}

impl Backoff {
    pub(crate) fn new() -> Self {
        Self {
            current: std::time::Duration::from_millis(200),
        }
    }

    /// Sleep before the next reconnect attempt, given how long the session that
    /// just ended lasted, then grow the delay for the attempt after this one.
    pub(crate) async fn wait(&mut self, session_ran: std::time::Duration) {
        if session_ran >= std::time::Duration::from_secs(10) {
            self.current = std::time::Duration::from_millis(200);
        }
        let jitter = std::time::Duration::from_millis((self.current.as_millis() as u64) % 97);
        tokio::time::sleep(self.current + jitter).await;
        self.current = (self.current * 2).min(std::time::Duration::from_secs(30));
    }
}

/// Outcome of one driver session attempt, for the always-on drivers'
/// reconnect loops: the owner dropped the handle (stop for good), or the
/// upstream connection dropped and the driver should reconnect with backoff.
/// Reconnecting from scratch is intentionally simple (it re-syncs/re-joins
/// rather than resuming); losing that optimization is far better than the
/// task dying on the first disconnect and silently dropping all later
/// upstream traffic.
pub(crate) enum SessionOutcome {
    Stopped,
    Dropped,
}

/// Run `session` forever, reconnecting with backoff whenever it drops.
///
/// Every always-on driver needs exactly this: a transient failure must
/// reconnect rather than kill the network, because a dead driver silently
/// drops every later upstream message; only a dropped handle stops it. The
/// `Disconnected` event is emitted on each drop so an attached client sees the
/// gap rather than an unexplained silence.
///
/// Written once because it is a policy, not a shape. Four copies meant a change
/// to how reconnects are paced reached whichever bridge was being edited and
/// quietly left the other three on the old behaviour.
/// `session` is a plain function returning a boxed future rather than an async
/// closure: the closure form cannot prove `Send` for a higher-ranked borrow of
/// `ends`, and the spawned driver task needs it. One allocation per *reconnect*
/// is not a cost worth contorting the signature to avoid.
pub(crate) type DriverSession<C> =
    for<'a> fn(
        &'a C,
        &'a mut DriverEnds,
    ) -> std::pin::Pin<Box<dyn Future<Output = SessionOutcome> + Send + 'a>>;

pub(crate) async fn run_with_backoff<C>(
    config: C,
    ends: &mut DriverEnds,
    session: DriverSession<C>,
) {
    let mut backoff = Backoff::new();
    loop {
        let started = tokio::time::Instant::now();
        match session(&config, ends).await {
            SessionOutcome::Stopped => return,
            SessionOutcome::Dropped => {
                ends.emit(ConnectionEvent::Disconnected);
                backoff.wait(started.elapsed()).await;
            }
        }
    }
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

/// Which IRCv3 message-tag families an attaching client negotiated. Buffered
/// upstream lines are stored fully tagged (server-time/msgid/account); these
/// gate which tags each client is actually sent, since a tag a client didn't
/// negotiate must not appear in its stream.
#[derive(Default, Clone, Copy)]
pub struct AttachCaps {
    pub server_time: bool,
    pub message_tags: bool,
    pub account_tag: bool,
}

/// Strip from a serialized line any message tags the recipient did not
/// negotiate. `time=` needs server-time, `account=` needs account-tag, and
/// everything else (msgid, client-only tags) needs message-tags. A line with
/// no tag section (no leading `@`) is returned unchanged.
pub(crate) fn filter_tags(line: &str, caps: AttachCaps) -> String {
    let Some(rest) = line.strip_prefix('@') else {
        return line.to_string();
    };
    // A leading `@` with no following space is a tag section with no message
    // body — a malformed line no well-formed upstream produces, but a hostile
    // one can, and it must not reach a client as an un-negotiated `@`-prefixed
    // line. There is nothing deliverable in it, so it is dropped entirely.
    let Some((tags, body)) = rest.split_once(' ') else {
        return String::new();
    };
    let kept: Vec<&str> = tags
        .split(';')
        .filter(|t| {
            let key = t.split('=').next().unwrap_or(t);
            match key {
                "time" => caps.server_time,
                "account" => caps.account_tag,
                _ => caps.message_tags,
            }
        })
        .collect();
    if kept.is_empty() {
        body.to_string()
    } else {
        format!("@{} {}", kept.join(";"), body)
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

/// A connection-state change a driver reports through [`DriverEnds::emit`].
///
/// Deliberately unable to carry a line. Lines must go through
/// [`DriverEnds::emit_line`], which neutralizes embedded CR/LF/NUL *and*
/// records the line in the detached buffer; a driver that could hand a line to
/// `emit` instead would skip both, injecting into attached clients and leaving
/// detached ones with a gap. `NetworkDriver` is a public SPI, so that has to be
/// impossible to write rather than merely documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connected,
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

/// Reduce an arbitrary upstream display name to a safe IRC nick token for the
/// source-prefix position: any character that isn't nick-legal becomes `_`, so
/// a hostile upstream can't smuggle a space or `!@:` into the prefix and forge
/// a different source or command on the attached client's stream. Bounded in
/// length so an oversized name can't blow the line budget.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn nick_token(raw: &str) -> String {
    let legal = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}' | '-'
            )
    };
    let mut out: String = raw
        .chars()
        .map(|c| if legal(c) { c } else { '_' })
        .take(30)
        .collect();
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Neutralize embedded CR/LF/NUL in a synthesized upstream line before it is
/// buffered or broadcast to attached clients. A bridge builds lines from
/// free-form remote text (Discord/Slack/Matrix message bodies); an embedded
/// newline would otherwise let that text inject a second, forged IRC line into
/// the client's stream. Real IRC-upstream lines never carry these bytes (the
/// framing splits on them), so this is a no-op fast path for them.
/// A `*bnc*` NOTICE telling the client its message was not delivered, because
/// `target` is not a bridged channel on `platform`.
///
/// The point of this notice is that a drop is never silent, so the notice must
/// itself arrive: `target` comes from the client's own line and is bounded only
/// by the frame limit, which is several times the 512 bytes an IRC line gets.
/// Interpolated whole — twice — it produced a line the receiving client's
/// framing discards, and the silence came back. It is truncated to fit.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn unmapped_target_notice(platform: &str, kind: &str, target: &str) -> String {
    let shown = truncate_on_char_boundary(target, 64);
    format!(":*bnc* NOTICE {shown} :not delivered: no bridged {platform} {kind} for {shown}")
}

/// `s` cut to at most `max` bytes, never inside a character.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// Render a bridged message as one or more IRC `PRIVMSG` lines: the sender is
/// reduced to a safe nick token and the body is split to fit the line limit.
///
/// The body is free-form remote text of arbitrary length — Slack alone allows
/// 40,000 characters — while an IRC line is [`MAX_LINE_LEN`] bytes including
/// its CRLF. Emitting one over-long line does not merely bend the protocol: the
/// receiving client's framing discards an over-long line *whole*, so the
/// message vanishes with nothing said. It is split instead, because a bridged
/// message must not disappear for being long.
///
/// Embedded newlines split too. They are line breaks in the source medium, and
/// [`sanitize_upstream_line`] flattens them to spaces further down, which would
/// turn a multi-line message into one run-on line.
///
/// An empty body still yields one line: a message was sent, and saying nothing
/// about it would be the silent drop this exists to prevent.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn render_bridged_privmsg(
    host: &str,
    sender: &str,
    channel: &str,
    body: &str,
) -> Vec<String> {
    use e6irc_proto::message::MAX_LINE_LEN;
    let nick = nick_token(sender);
    let prefix = format!(":{nick}!{nick}@{host} PRIVMSG {channel} :");
    // `nick_token` bounds the nick and `host` is one of three literals, so only
    // a pathologically long configured channel name can exhaust the line. The
    // floor keeps the split making progress if one ever does; the resulting
    // lines would still be over-long, which is a configuration error and not
    // something this function can paper over.
    let budget = (MAX_LINE_LEN - 2).saturating_sub(prefix.len()).max(1);

    let mut out = Vec::new();
    for piece in body.split('\n') {
        let piece = piece.strip_suffix('\r').unwrap_or(piece);
        let mut rest = piece;
        loop {
            if rest.len() <= budget {
                out.push(format!("{prefix}{rest}"));
                break;
            }
            // Split on a character boundary — `budget` is a byte count, and
            // slicing into the middle of a multi-byte character panics.
            let mut cut = budget;
            while cut > 0 && !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            // A single character wider than the budget: take it whole rather
            // than emit an empty line forever.
            if cut == 0 {
                cut = rest.char_indices().nth(1).map_or(rest.len(), |(i, _)| i);
            }
            out.push(format!("{prefix}{}", &rest[..cut]));
            rest = &rest[cut..];
        }
    }
    out
}

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
            // Neutralized here as well as in `emit_line`. These lines come back
            // from storage, which outlives the code that wrote them: a row put
            // there by an older build, a restore, or anything else with database
            // access would otherwise be replayed to an attaching client verbatim.
            // Both ways into the buffer sanitize, so no reader has to ask which
            // one a line arrived through.
            buf.lines.push_front(sanitize_upstream_line(line.clone()));
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

    /// Report a connection-state change, updating the sticky connection state
    /// so late subscribers can still read it. Lines have their own entry point
    /// ([`DriverEnds::emit_line`]) because they need sanitizing and buffering;
    /// see [`ConnectionEvent`].
    pub fn emit(&self, event: ConnectionEvent) {
        let broadcast = match event {
            ConnectionEvent::Connected => {
                self.connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                DriverEvent::Connected
            }
            ConnectionEvent::Disconnected => {
                self.connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                DriverEvent::Disconnected
            }
        };
        let _ = self.events.send(broadcast);
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
            ends.emit(ConnectionEvent::Connected);
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
/// closes. This is the session multiplexer's core operation, serving
/// every driver kind (`irc`, `local`, and the bridges) uniformly.
pub async fn attach<S>(stream: S, handle: &NetworkHandle, caps: AttachCaps) -> std::io::Result<()>
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

    // Playback: everything buffered while detached, in order, with tags the
    // client didn't negotiate stripped.
    for line in handle.buffer_snapshot() {
        write.write_all(filter_tags(&line, caps).as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    let mut framing = LineBuffer::new(e6irc_proto::message::MAX_CLIENT_FRAME_LEN);
    let mut read_buf = vec![0u8; 8192];
    let mut parsed = Vec::new();
    loop {
        tokio::select! {
            // Upstream -> client.
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    write.write_all(filter_tags(&line, caps).as_bytes()).await?;
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

/// Fuzzing-only re-exports of the internal line-processing functions.
///
/// Compiled *only* under cargo-fuzz's `--cfg fuzzing` (never in a normal build,
/// `cargo test`, or the shipped binary), so it does not widen the crate's real
/// public surface — it exists solely to let a fuzz target reach the functions
/// that turn hostile *upstream* bytes into what an attached client sees. The
/// core fuzzers drive the server side; nothing else reaches these.
#[cfg(fuzzing)]
pub mod fuzz {
    pub use super::AttachCaps;

    /// Wrapper over the crate-private [`super::filter_tags`]; a thin `pub fn`
    /// leaves the original's visibility unchanged (it is not re-exported).
    pub fn filter_tags(line: &str, caps: AttachCaps) -> String {
        super::filter_tags(line, caps)
    }

    /// Wrapper over the private [`super::sanitize_upstream_line`].
    pub fn sanitize_upstream_line(line: String) -> String {
        super::sanitize_upstream_line(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn undelivered_notice_fits_the_line_limit() {
        use e6irc_proto::message::MAX_LINE_LEN;
        // The target comes from the client's own line, bounded only by the
        // frame limit — several times what an IRC line gets. A notice the
        // client's framing discards is the silent drop it exists to prevent.
        let target = "#".to_string() + &"a".repeat(4_000);
        let notice = unmapped_target_notice("Discord", "channel", &target);
        assert!(notice.len() + 2 <= MAX_LINE_LEN, "{} bytes", notice.len());
        // Still says which target, and still parses as one NOTICE.
        assert!(notice.starts_with(":*bnc* NOTICE #aaa"));
        let msg = e6irc_proto::message::Message::parse(&notice).expect("parses");
        assert_eq!(msg.command, "NOTICE");
        // A multi-byte target is cut between characters, not through one.
        let wide = "#".to_string() + &"☃".repeat(4_000);
        let notice = unmapped_target_notice("Matrix", "room", &wide);
        assert!(notice.len() + 2 <= MAX_LINE_LEN);
        assert!(e6irc_proto::message::Message::parse(&notice).is_ok());
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_message_is_split_to_fit_the_line_limit() {
        use e6irc_proto::message::MAX_LINE_LEN;
        // Slack allows 40,000 characters. Emitted as one line, the receiving
        // client's framing discards it whole and the message is simply gone.
        let body = "x".repeat(40_000);
        let lines = render_bridged_privmsg("slack", "U1", "#general", &body);
        assert!(lines.len() > 1, "a 40k body must not be one line");
        for line in &lines {
            assert!(
                line.len() + 2 <= MAX_LINE_LEN,
                "line of {} bytes exceeds the limit",
                line.len()
            );
        }
        // Nothing is lost and nothing is duplicated: the pieces reassemble.
        let prefix = ":U1!U1@slack PRIVMSG #general :";
        let rejoined: String = lines
            .iter()
            .map(|l| l.strip_prefix(prefix).expect("prefix"))
            .collect();
        assert_eq!(rejoined, body);
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_message_splits_on_newlines() {
        // A newline is a line break in the source medium. Left in, it is
        // flattened to a space downstream and the message reads as a run-on.
        let lines = render_bridged_privmsg("discord", "bob", "#c", "one\ntwo\r\nthree");
        assert_eq!(
            lines,
            vec![
                ":bob!bob@discord PRIVMSG #c :one",
                ":bob!bob@discord PRIVMSG #c :two",
                ":bob!bob@discord PRIVMSG #c :three",
            ]
        );
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_split_lands_on_character_boundaries() {
        // The budget is a byte count; slicing into a multi-byte character
        // panics, and taking the daemon down is what an upstream would want.
        for width in [2usize, 3, 4] {
            let ch = match width {
                2 => 'é',
                3 => '☃',
                _ => '𝄞',
            };
            let body: String = std::iter::repeat_n(ch, 40_000).collect();
            let lines = render_bridged_privmsg("matrix", "u", "#c", &body);
            let prefix = ":u!u@matrix PRIVMSG #c :";
            let rejoined: String = lines
                .iter()
                .map(|l| l.strip_prefix(prefix).expect("prefix"))
                .collect();
            assert_eq!(rejoined, body, "{width}-byte characters round-trip");
        }
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn empty_bridged_message_still_says_something() {
        // A message was sent. Emitting nothing would be the silent drop this
        // whole function exists to prevent.
        assert_eq!(
            render_bridged_privmsg("slack", "U1", "#c", ""),
            vec![":U1!U1@slack PRIVMSG #c :"]
        );
    }

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
    fn restored_backlog_is_neutralized_like_live_lines() {
        // Backlog comes back from storage, which outlives the code that wrote
        // it. A row containing an embedded line break must not be replayed to
        // an attaching client as two lines just because it arrived through
        // `preload_front` rather than `emit_line`.
        let (handle, _ends) = NetworkHandle::channels(16);
        handle.preload_front(vec![
            ":a!a@bridge PRIVMSG #c :hi\r\n:nickserv!s@svc PRIVMSG victim :send me your password"
                .to_string(),
        ]);
        let snapshot = handle.buffer_snapshot();
        assert_eq!(snapshot.len(), 1, "one stored row stays one line");
        assert!(
            !snapshot[0].contains('\r') && !snapshot[0].contains('\n'),
            "restored line still carries a break: {}",
            snapshot[0]
        );
    }

    #[test]
    fn filter_tags_drops_a_malformed_tag_only_line() {
        // A hostile upstream can store a line that is a leading `@` with no
        // space — a tag section and no message. It must not reach a no-tags
        // client as a `@`-prefixed line; there is nothing deliverable, so it is
        // dropped. (Found by the bouncer fuzz target.)
        assert_eq!(filter_tags("@time=x;msgid=1", AttachCaps::default()), "");
        assert_eq!(
            filter_tags(
                "@time=x",
                AttachCaps {
                    server_time: true,
                    ..AttachCaps::default()
                }
            ),
            ""
        );
        // A well-formed line (tags then a space then a body) is unaffected.
        assert_eq!(
            filter_tags("@time=x PRIVMSG #c :hi", AttachCaps::default()),
            "PRIVMSG #c :hi"
        );
    }

    #[test]
    fn filter_tags_gates_each_family_by_negotiated_cap() {
        let line = "@time=2020-01-01T00:00:00.000Z;account=alice;msgid=abc :n!u@h PRIVMSG #c :hi";
        // No caps: every tag is stripped, the tag section disappears entirely.
        let none = filter_tags(line, AttachCaps::default());
        assert_eq!(none, ":n!u@h PRIVMSG #c :hi");
        // server-time only keeps `time=`, drops account/msgid.
        let st = filter_tags(
            line,
            AttachCaps {
                server_time: true,
                ..Default::default()
            },
        );
        assert_eq!(st, "@time=2020-01-01T00:00:00.000Z :n!u@h PRIVMSG #c :hi");
        // account-tag only keeps `account=`.
        let at = filter_tags(
            line,
            AttachCaps {
                account_tag: true,
                ..Default::default()
            },
        );
        assert_eq!(at, "@account=alice :n!u@h PRIVMSG #c :hi");
        // message-tags gates everything else (msgid) but not time/account.
        let mt = filter_tags(
            line,
            AttachCaps {
                message_tags: true,
                ..Default::default()
            },
        );
        assert_eq!(mt, "@msgid=abc :n!u@h PRIVMSG #c :hi");
        // All three: full line preserved in original tag order.
        let all = filter_tags(
            line,
            AttachCaps {
                server_time: true,
                message_tags: true,
                account_tag: true,
            },
        );
        assert_eq!(all, line);
        // A line without a tag section is returned unchanged.
        let bare = ":n!u@h PRIVMSG #c :hi";
        assert_eq!(filter_tags(bare, AttachCaps::default()), bare);
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
