//! Client-side connection library shared by e6irc-cli and e6irc-tui.
//!
//! An async wrapper over plaintext or public-CA TLS sockets that frames IRC
//! lines with `e6irc-proto` and drives anonymous, SASL PLAIN, or SASL
//! OAUTHBEARER registration. [`ConnectionOptions`] is the single owned request
//! used by both native clients, including reconnects.

#![deny(clippy::let_underscore_must_use)]

pub mod token_cache;

use std::io;

use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_proto::message::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Metadata capabilities every registration mode asks for. They are optional
/// because this client also connects to older third-party servers, but the
/// request itself is not optional: anonymous, password, and bearer
/// authentication must produce the same message metadata when the server
/// supports it.
const METADATA_CAPABILITIES: [&str; 3] = ["server-time", "message-tags", "account-tag"];

/// Capabilities one server may advertise. `CAP LS` continues for as long as the
/// server keeps sending `*` lines, so without a bound the peer decides how much
/// this connection remembers. Real networks advertise a few dozen.
const MAX_ADVERTISED_CAPABILITIES: usize = 256;

/// Server-supplied text with every terminal control byte neutralized — the only
/// form untrusted text may take once it reaches the user's terminal.
///
/// The wire parser rejects only CR/LF/NUL, so every other control byte (the rest
/// of C0, DEL, and C1 — which includes the one-byte CSI `0x9B`) arrives verbatim
/// and could retitle the window, clear the screen, or spoof output. This newtype
/// is constructible only via [`TerminalSafe::from_untrusted`], which replaces
/// each control character with a visible `U+FFFD`; a field or display path typed
/// as `TerminalSafe` therefore cannot hold raw server text with a live escape
/// sequence. Shared by the CLI and the TUI so the sanitizer has one definition
/// rather than a per-crate copy (the TUI previously leaned on ratatui's internal
/// control-char filter — an upstream implementation detail, not a project
/// guarantee).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalSafe(String);

impl TerminalSafe {
    /// Neutralize control bytes in untrusted (server-supplied) text.
    pub fn from_untrusted(s: &str) -> Self {
        Self(
            s.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TerminalSafe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for TerminalSafe {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// One connection to an IRC server (plaintext or TLS).
pub struct Connection {
    reader: BoxRead,
    writer: BoxWrite,
    framing: LineBuffer,
    /// Framing events already parsed out of the read buffer. Rejections share
    /// the same queue as lines so returning one event can never discard later
    /// events from the same socket read.
    pending: std::collections::VecDeque<LineEvent>,
    read_buf: Vec<u8>,
    /// The bound on each request this library waits on, from
    /// [`ConnectionOptions::response_deadline`]. `None` for a connection built
    /// directly from a socket, whose owner bounds its own calls (the bouncer
    /// wraps every stage in its own timeout).
    response_deadline: Option<std::time::Duration>,
    /// What the server said it offers, recorded during capability discovery so
    /// registration asks only for what exists and can name what is missing.
    advertised: AdvertisedCapabilities,
}

/// The capability set a server advertised in `CAP LS`, with each capability's
/// value (`sasl=PLAIN,EXTERNAL`). Bounded by
/// [`MAX_ADVERTISED_CAPABILITIES`]; each entry is already bounded by the frame
/// limit of the line that carried it.
#[derive(Debug, Default)]
struct AdvertisedCapabilities(std::collections::HashMap<String, Option<String>>);

impl AdvertisedCapabilities {
    /// Fold one `CAP LS` line's space-separated `name[=value]` list in.
    fn record(&mut self, list: &str) -> io::Result<()> {
        for token in list.split_whitespace() {
            let (name, value) = match token.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (token, None),
            };
            if !self.0.contains_key(name) && self.0.len() >= MAX_ADVERTISED_CAPABILITIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "server advertised more than {MAX_ADVERTISED_CAPABILITIES} capabilities"
                    ),
                ));
            }
            self.0.insert(name.to_owned(), value.map(str::to_owned));
        }
        Ok(())
    }

    fn offers(&self, capability: &str) -> bool {
        self.0.contains_key(capability)
    }

    /// The advertised SASL mechanism list, or `None` when the server named no
    /// mechanisms (a pre-3.2 `sasl` without a value) and they are unknown.
    fn sasl_mechanisms(&self) -> Option<&str> {
        self.0
            .get("sasl")
            .and_then(|value| value.as_deref())
            .filter(|mechanisms| !mechanisms.is_empty())
    }

    /// 908 names the mechanisms authoritatively, after the fact.
    fn replace_sasl_mechanisms(&mut self, mechanisms: &str) {
        self.0
            .insert("sasl".to_owned(), Some(mechanisms.to_owned()));
    }

    /// `Err` with the offered list when a known mechanism list omits
    /// `mechanism`.
    fn sasl_mechanism_offered(&self, mechanism: &str) -> Result<(), SaslRejection> {
        match self.sasl_mechanisms() {
            Some(offered) if !offered.split(',').any(|candidate| candidate == mechanism) => {
                Err(SaslRejection::new(
                    SaslFailure::MechanismNotOffered,
                    &format!("requested {mechanism}; the server offers {offered}"),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Whether the server took part in capability negotiation at all. A server
/// that answers `CAP` with 421 has no negotiation to end, so `CAP END` must not
/// be sent to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityNegotiation {
    Open,
    Unsupported,
}

/// The server's answer to one `CAP REQ`.
#[derive(Debug, PartialEq, Eq)]
enum CapabilityVerdict {
    Acknowledged,
    /// NAK or 410, with the bounded reason.
    Refused(String),
}

/// Read `message` as the verdict on the one outstanding `CAP REQ` for
/// `requested`. Requests are sent serially, so a verdict that omits a requested
/// name is a malformed response, not permission to continue with an unknown
/// capability state. `Ok(None)` means the message is not a verdict.
fn capability_verdict(
    message: &OwnedMessage,
    requested: &[&str],
) -> io::Result<Option<CapabilityVerdict>> {
    if message.command == "410" {
        return Ok(Some(CapabilityVerdict::Refused(registration_diagnostic(
            message,
        ))));
    }
    if message.command != "CAP" {
        return Ok(None);
    }
    let Some(verdict @ ("ACK" | "NAK")) = message.params.get(1).map(String::as_str) else {
        return Ok(None);
    };
    let names = message.params.last().map(String::as_str).unwrap_or("");
    if let Some(omitted) = requested
        .iter()
        .find(|capability| !names.split_whitespace().any(|name| name == **capability))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("server capability {verdict} omitted requested capability {omitted}"),
        ));
    }
    Ok(Some(if verdict == "ACK" {
        CapabilityVerdict::Acknowledged
    } else {
        CapabilityVerdict::Refused("the server sent CAP NAK".to_owned())
    }))
}

/// An owned message read from the server (its borrowed form would tie
/// the caller to the read buffer).
#[derive(Debug, Clone)]
pub struct OwnedMessage {
    pub tags: Vec<(String, Option<String>)>,
    pub source: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

/// A recoverable server-line rejection.
///
/// These are deliberately distinct from I/O errors: one hostile or malformed
/// line must not disconnect an otherwise healthy interactive or bouncer
/// session, but dropping it without an observable event would make data loss
/// silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectedLine {
    /// The peer exceeded the accepted IRC server-frame limit (including its
    /// larger message-tag allowance). The framing layer discarded the entire
    /// line, so there is no safe partial value to relay.
    TooLong,
    /// Lossy UTF-8 decoding still did not produce a syntactically valid IRC
    /// message. Relays receive the raw lossy text instead; interactive clients
    /// receive this rejection because they cannot safely act on it.
    Unparseable,
}

impl std::fmt::Display for RejectedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => f.write_str("server line exceeds the accepted IRC frame limit"),
            Self::Unparseable => f.write_str("server line is not valid IRC syntax"),
        }
    }
}

/// One steady-state event for a relay.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// A line that can be relayed exactly as decoded. `message` is absent when
    /// the relay must forward it but must not act on its syntax.
    Line {
        message: Option<OwnedMessage>,
        raw: String,
    },
    /// A whole line that could not be retained safely.
    Rejected(RejectedLine),
}

/// One steady-state event for an interactive client.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Message(OwnedMessage),
    Rejected(RejectedLine),
}

impl OwnedMessage {
    /// Look up one IRCv3 tag without exposing representation details to every
    /// client state machine.
    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == key)
            .and_then(|(_, value)| value.as_deref())
    }
}

/// Authentication selected for a registered client connection.
///
/// Credentials are owned so a reconnecting client can reuse the exact explicit
/// choice. There is no `Option` pair whose half-filled state could silently
/// fall back to anonymous registration.
#[derive(Clone, Default)]
pub enum Authentication {
    #[default]
    None,
    Plain {
        account: String,
        password: String,
    },
    OAuthBearer {
        token: String,
    },
}

/// Complete transport and registration request shared by native clients.
#[derive(Clone)]
pub struct ConnectionOptions {
    pub address: String,
    pub tls: bool,
    /// Required for TLS when `address` is not a DNS name. When absent, the
    /// syntactic host portion of `address` is used.
    pub tls_server_name: Option<String>,
    pub nick: String,
    pub realname: String,
    pub authentication: Authentication,
    /// How long the server may take to finish registration, and afterwards to
    /// answer each request this library waits on (a capability request, a
    /// JOIN with its history). Required: a peer that holds the socket open
    /// while saying nothing relevant would otherwise hang a scripted client
    /// forever, and only the caller knows how long its user will wait.
    pub response_deadline: std::time::Duration,
}

/// A connection the server has welcomed, with the nickname it confirmed —
/// which is the server's to choose (a bouncer answers with the upstream's
/// nickname, a network may truncate or rename) and is the only name under
/// which this client will recognise its own JOINs and direct messages.
pub struct Registered {
    pub connection: Connection,
    pub nick: String,
}

impl ConnectionOptions {
    /// Connect, negotiate the selected transport/authentication, and return
    /// only after the server confirms registration.
    pub async fn connect_registered(&self) -> io::Result<Registered> {
        within(
            Some(self.response_deadline),
            "connecting and registering",
            self.connect_and_register(),
        )
        .await
    }

    async fn connect_and_register(&self) -> io::Result<Registered> {
        let mut connection = if self.tls {
            let name = match self.tls_server_name.as_deref() {
                Some(name) if !name.trim().is_empty() => name,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS server name cannot be empty",
                    ));
                }
                None => tls_server_name(&self.address)?,
            };
            Connection::connect_tls(&self.address, name, webpki_root_store()).await?
        } else {
            Connection::connect(&self.address).await?
        };
        let nick = match &self.authentication {
            Authentication::None => connection.register(&self.nick, &self.realname).await?,
            Authentication::Plain { account, password } => {
                connection
                    .register_sasl(&self.nick, &self.realname, account, password)
                    .await?
            }
            Authentication::OAuthBearer { token } => {
                connection
                    .register_oauthbearer(&self.nick, &self.realname, token)
                    .await?
            }
        };
        connection.response_deadline = Some(self.response_deadline);
        Ok(Registered { connection, nick })
    }
}

/// Run one exchange with the server under `deadline`. A peer that keeps the
/// socket open while sending lines that answer nothing defeats any per-read
/// timeout, so the bound is on the whole exchange.
async fn within<T>(
    deadline: Option<std::time::Duration>,
    what: &str,
    exchange: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let Some(deadline) = deadline else {
        return exchange.await;
    };
    tokio::time::timeout(deadline, exchange)
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the server did not finish {what} within {deadline:?}"),
            ))
        })
}

/// Extract a TLS validation name from `host:port`, including bracketed IPv6.
/// A bare IPv6 address is not a valid endpoint because its port is ambiguous.
pub fn tls_server_name(address: &str) -> io::Result<&str> {
    if let Some(bracketed) = address.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bracketed server address",
            )
        })?;
        if !suffix.starts_with(':') || suffix.len() == 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server address must include a port",
            ));
        }
        return Ok(host);
    }
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server address must be host:port",
        )
    })?;
    if host.is_empty() || host.contains(':') || port.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server address must be host:port (bracket IPv6 addresses)",
        ));
    }
    Ok(host)
}

/// The borrowed → owned conversion. Public because [`OwnedMessage`] is: a
/// caller holding a parsed [`Message`] (a test, a bridge, a replay tool) has no
/// other way to build one, and a second hand-written copy of this mapping is
/// free to drift from the one the connection actually uses.
impl From<&Message<'_>> for OwnedMessage {
    fn from(msg: &Message<'_>) -> Self {
        Self {
            tags: msg
                .tags
                .iter()
                .map(|t| (t.key.to_string(), t.value.as_ref().map(|v| v.to_string())))
                .collect(),
            source: msg.source.as_ref().map(|s| {
                let mut out = s.name.to_string();
                if let Some(u) = s.user {
                    out.push('!');
                    out.push_str(u);
                }
                if let Some(h) = s.host {
                    out.push('@');
                    out.push_str(h);
                }
                out
            }),
            // IRC command names are case-insensitive. Canonicalize at the
            // borrowed-to-owned boundary so every client state machine sees
            // one representation and cannot forget a per-comparison fold.
            command: msg.command.to_ascii_uppercase(),
            params: msg.params.iter().map(|p| p.to_string()).collect(),
        }
    }
}

impl Connection {
    /// Connect (plaintext) to `host:port`.
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_tcp(stream)
    }

    /// Build a plaintext IRC connection from an already-connected TCP stream.
    /// Dialers that must resolve, vet, and try concrete addresses themselves use
    /// this entry point without re-resolving the hostname after validation.
    pub fn from_tcp(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        Ok(Self::from_halves(Box::new(reader), Box::new(writer)))
    }

    /// Connect over TLS to `host:port`, validating the server
    /// certificate against `roots`. Pass [`webpki_root_store`] for the
    /// public Mozilla trust set, or a custom store for private CAs.
    pub async fn connect_tls(
        addr: &str,
        server_name: &str,
        roots: rustls::RootCertStore,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_tcp_tls(stream, server_name, roots).await
    }

    /// Establish TLS on an already-connected TCP stream, validating the
    /// certificate against `server_name`. This is the TLS counterpart to
    /// [`Connection::from_tcp`] for vetted custom dialers.
    pub async fn from_tcp_tls(
        stream: TcpStream,
        server_name: &str,
        roots: rustls::RootCertStore,
    ) -> io::Result<Self> {
        install_crypto_provider();
        stream.set_nodelay(true)?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let domain = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let tls = connector.connect(domain, stream).await?;
        let (reader, writer) = tokio::io::split(tls);
        Ok(Self::from_halves(Box::new(reader), Box::new(writer)))
    }

    fn from_halves(reader: BoxRead, writer: BoxWrite) -> Self {
        Self {
            reader,
            writer,
            framing: LineBuffer::new(e6irc_proto::message::MAX_SERVER_FRAME_LEN),
            pending: std::collections::VecDeque::new(),
            read_buf: vec![0u8; 8192],
            response_deadline: None,
            advertised: AdvertisedCapabilities::default(),
        }
    }

    /// Send one line (CRLF appended). This is the sole outbound funnel, so it
    /// rejects any embedded CR/LF/NUL before writing — the client-side
    /// analogue of the server's `WireLine` sanitization. Callers build commands
    /// with `format!` from values that may carry untrusted input (a scripted
    /// `PRIVMSG` body, a `--nick`, a channel name); without this, a value like
    /// `"hi\r\nJOIN #evil"` would forge a second command in the authenticated
    /// session. A legitimate single line never contains these bytes, so reject
    /// the whole value before writing rather than silently changing its meaning.
    pub async fn send_line(&mut self, line: &str) -> io::Result<()> {
        if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client line contains an IRC delimiter",
            ));
        }
        if !e6irc_proto::message::client_frame_fits(line.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client line exceeds an IRC wire budget",
            ));
        }
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.writer.flush().await
    }

    /// Read the next server message, blocking until one arrives or the
    /// connection closes (`None`). An over-long, non-UTF-8, or unparseable line
    /// is an error: the framing layer guarantees non-empty lines, so anything
    /// that still fails to parse means the peer is not speaking IRC — skipping it
    /// would silently drop protocol traffic with no observable trace. This strict
    /// contract is for the handshake and command/response flows; an interactive
    /// steady-state loop should use [`Connection::next_event_lossy`] so one bad
    /// line can't end the session.
    pub async fn next_message(&mut self) -> io::Result<Option<OwnedMessage>> {
        Ok(self.next_message_with_line().await?.map(|(msg, _)| msg))
    }

    /// Read from the transport and feed complete lines into `self.pending`.
    /// Returns `false` on EOF so the caller can return `Ok(None)`.
    async fn fill(&mut self) -> io::Result<bool> {
        let n = self.reader.read(&mut self.read_buf).await?;
        if n == 0 {
            return Ok(false);
        }
        let mut events = Vec::new();
        self.framing.feed(&self.read_buf[..n], &mut events);
        self.pending.extend(events);
        Ok(true)
    }

    /// As [`Connection::next_message`], but also returns the line exactly as
    /// the server sent it (CRLF stripped).
    ///
    /// For callers that relay or store what they receive rather than acting on
    /// it — a bouncer's detached buffer, a logger. Re-serializing the parsed
    /// message would be a second implementation of the wire format kept in step
    /// with `Message::to_line` by hand, and it cannot be more faithful than the
    /// bytes that arrived.
    pub async fn next_message_with_line(&mut self) -> io::Result<Option<(OwnedMessage, String)>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                match event {
                    LineEvent::Line(line) => {
                        if !e6irc_proto::message::server_frame_fits(&line) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "server sent an over-long line",
                            ));
                        }
                        let text = std::str::from_utf8(&line).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "server sent a non-UTF-8 line",
                            )
                        })?;
                        let msg = Message::parse(text).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("server sent an unparseable line: {e:?}"),
                            )
                        })?;
                        return Ok(Some((OwnedMessage::from(&msg), text.to_string())));
                    }
                    LineEvent::TooLong => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "server sent an over-long line",
                        ));
                    }
                }
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// Steady-state read for a *relay* (a bouncer): tolerant of lines it must
    /// forward rather than act on. Returns the raw line text with a
    /// *best-effort* parse — a non-UTF-8 or otherwise unparseable line comes
    /// back as `(None, lossy_text)` rather than an error, because a bouncer must
    /// forward the bytes the network sent and keep the link, never tear it down
    /// over one bad line. IRC message bodies are arbitrary bytes (Latin-1,
    /// Shift-JIS, … are routine on real networks), so a single high-byte channel
    /// message must not disconnect the whole session — which any channel member
    /// could then use to keep a victim's bouncer flapping.
    ///
    /// The distinct outcomes make both "a recoverable per-line error is fatal"
    /// and "a recoverable per-line error vanishes" unrepresentable at the call
    /// site: [`RelayEvent::Line`] is relayable, [`RelayEvent::Rejected`] must be
    /// surfaced, `Ok(None)` is genuine EOF, and `Err` is an I/O error. Kept
    /// separate from [`Connection::next_message_with_line`], whose strict
    /// error-on-bad-line contract the handshake relies on.
    pub async fn next_line_relayable(&mut self) -> io::Result<Option<RelayEvent>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                match event {
                    LineEvent::Line(line) => {
                        if !e6irc_proto::message::server_frame_fits(&line) {
                            return Ok(Some(RelayEvent::Rejected(RejectedLine::TooLong)));
                        }
                        // Lossy: an invalid byte sequence becomes U+FFFD
                        // instead of failing the whole read (mirrors the
                        // in-process local driver).
                        let text = String::from_utf8_lossy(&line).into_owned();
                        // Best-effort parse; `None` means "relay only, don't
                        // act on it".
                        let parsed = Message::parse(&text).ok().map(|m| OwnedMessage::from(&m));
                        return Ok(Some(RelayEvent::Line {
                            message: parsed,
                            raw: text,
                        }));
                    }
                    LineEvent::TooLong => {
                        return Ok(Some(RelayEvent::Rejected(RejectedLine::TooLong)));
                    }
                }
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// Steady-state read for an *interactive* client (the TUI, `tail`):
    /// tolerant of a single bad line without hiding it. A non-UTF-8 line is
    /// lossily decoded (invalid bytes → U+FFFD) and parsed — IRC bodies carry
    /// arbitrary bytes (Latin-1/Shift-JIS are routine), so a high-byte channel
    /// message any member can post must not disconnect the victim. A line that
    /// still will not parse becomes [`ClientEvent::Rejected`] rather than ending
    /// the connection or disappearing. Distinct from
    /// [`Connection::next_message`], whose strict handshake contract rejects
    /// malformed input as an I/O error.
    pub async fn next_event_lossy(&mut self) -> io::Result<Option<ClientEvent>> {
        match self.next_line_relayable().await? {
            None => Ok(None),
            Some(RelayEvent::Line {
                message: Some(message),
                ..
            }) => Ok(Some(ClientEvent::Message(message))),
            Some(RelayEvent::Line { message: None, .. }) => {
                Ok(Some(ClientEvent::Rejected(RejectedLine::Unparseable)))
            }
            Some(RelayEvent::Rejected(rejected)) => Ok(Some(ClientEvent::Rejected(rejected))),
        }
    }

    /// Receive the next message, or fail loudly if the peer closed the socket
    /// mid-handshake instead of hanging on a stream that will never speak.
    async fn recv(&mut self, context: &'static str) -> io::Result<OwnedMessage> {
        self.next_message()
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, context))
    }

    /// Answer a `PING` and report whether `msg` was one, so registration loops
    /// stay alive without duplicating the PONG dance at every match arm.
    async fn answer_ping(&mut self, msg: &OwnedMessage) -> io::Result<bool> {
        if msg.command == "PING" {
            let token = msg.params.first().cloned().unwrap_or_default();
            self.send_line(&format!("PONG :{token}")).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Discover what the server offers. A server with no capability
    /// negotiation (421 for `CAP`) advertises nothing; whether that is
    /// acceptable is the caller's decision, because only the caller knows
    /// whether authentication was required.
    async fn begin_cap(&mut self) -> io::Result<CapabilityNegotiation> {
        self.send_line("CAP LS 302").await?;
        loop {
            let msg = self.recv("closed during CAP discovery").await?;
            if let Some(err) = registration_refused(&msg) {
                return Err(err);
            }
            if msg.command == "421"
                && msg
                    .params
                    .get(1)
                    .is_some_and(|command| command.eq_ignore_ascii_case("CAP"))
            {
                return Ok(CapabilityNegotiation::Unsupported);
            }
            if msg.command == "CAP" && msg.params.get(1).map(String::as_str) == Some("LS") {
                self.advertised
                    .record(msg.params.last().map(String::as_str).unwrap_or(""))?;
                if msg.params.get(2).map(String::as_str) != Some("*") {
                    return Ok(CapabilityNegotiation::Open);
                }
            } else {
                self.answer_ping(&msg).await?;
            }
        }
    }

    /// Discover capabilities and enable `sasl` for `mechanism`. The shared
    /// prologue of every SASL path. Everything that makes SASL impossible is
    /// decided here, before any credential exchange starts, and is reported as
    /// what it is rather than as a credential failure.
    async fn negotiate_sasl_cap(&mut self, mechanism: &str) -> io::Result<()> {
        let unavailable = |diagnostic: &str| {
            Err(SaslRejection::new(SaslFailure::CapabilityNotOffered, diagnostic).into_error())
        };
        if self.begin_cap().await? == CapabilityNegotiation::Unsupported {
            return unavailable("the server does not support capability negotiation");
        }
        if !self.advertised.offers("sasl") {
            return unavailable("the server does not advertise the sasl capability");
        }
        self.advertised
            .sasl_mechanism_offered(mechanism)
            .map_err(SaslRejection::into_error)?;
        match self.request_capabilities(&["sasl"]).await? {
            CapabilityVerdict::Acknowledged => Ok(()),
            CapabilityVerdict::Refused(reason) => {
                unavailable(&format!("the server refused the sasl capability: {reason}"))
            }
        }
    }

    /// Ask, in one request, for the metadata capabilities the server
    /// advertised. They are optional, so a refusal is consumed and
    /// registration continues without them.
    async fn request_metadata_capabilities(&mut self) -> io::Result<()> {
        let wanted: Vec<&str> = METADATA_CAPABILITIES
            .into_iter()
            .filter(|capability| self.advertised.offers(capability))
            .collect();
        if wanted.is_empty() {
            return Ok(());
        }
        match self.request_capabilities(&wanted).await? {
            CapabilityVerdict::Acknowledged | CapabilityVerdict::Refused(_) => Ok(()),
        }
    }

    /// Request `capabilities` atomically and consume exactly their verdict.
    async fn request_capabilities(
        &mut self,
        capabilities: &[&str],
    ) -> io::Result<CapabilityVerdict> {
        self.send_line(&format!("CAP REQ :{}", capabilities.join(" ")))
            .await?;
        loop {
            let msg = self.recv("closed during capability negotiation").await?;
            if let Some(err) = registration_refused(&msg) {
                return Err(err);
            }
            if let Some(verdict) = capability_verdict(&msg, capabilities)? {
                return Ok(verdict);
            }
            self.answer_ping(&msg).await?;
        }
    }

    /// Wait for the server's empty `AUTHENTICATE +` challenge after a mechanism
    /// has been offered.
    async fn await_authenticate_challenge(&mut self, mechanism: &str) -> io::Result<()> {
        loop {
            let msg = self.recv_sasl_message(mechanism).await?;
            if msg.command == "AUTHENTICATE" {
                if msg.params.as_slice() == ["+"] {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "server sent an unexpected SASL challenge",
                ));
            }
        }
    }

    async fn recv_sasl_message(&mut self, mechanism: &str) -> io::Result<OwnedMessage> {
        let msg = self.recv("closed during SASL").await?;
        if let Some(err) = self.sasl_terminal_error(&msg, mechanism).await? {
            return Err(err);
        }
        Ok(msg)
    }

    /// In a SASL wait loop: the terminal errors — a registration-refusal
    /// numeric (a rejected NICK can arrive mid-SASL, before the welcome) or a
    /// SASL failure numeric. `Ok(None)` means keep looping; a PING was
    /// answered on the way.
    ///
    /// 908 is not a verdict: it lists the mechanisms and precedes the 904 that
    /// is. It is remembered so that 904 can be told apart — a 904 for a
    /// mechanism the server does not offer says nothing about the credentials.
    async fn sasl_terminal_error(
        &mut self,
        msg: &OwnedMessage,
        mechanism: &str,
    ) -> io::Result<Option<io::Error>> {
        if let Some(err) = registration_refused(msg) {
            return Ok(Some(err));
        }
        let failure = match msg.command.as_str() {
            "908" => {
                if let Some(mechanisms) = msg.params.get(1) {
                    self.advertised.replace_sasl_mechanisms(mechanisms);
                }
                return Ok(None);
            }
            "902" => SaslFailure::NickLocked,
            "904" => {
                if let Err(not_offered) = self.advertised.sasl_mechanism_offered(mechanism) {
                    return Ok(Some(not_offered.into_error()));
                }
                SaslFailure::Failed
            }
            "905" => SaslFailure::TooLong,
            "906" => SaslFailure::Aborted,
            "907" => SaslFailure::AlreadyAuthenticated,
            _ => {
                self.answer_ping(msg).await?;
                return Ok(None);
            }
        };
        Ok(Some(
            SaslRejection::new(failure, &registration_diagnostic(msg)).into_error(),
        ))
    }

    /// After the credential is sent: wait for the SASL verdict, finish CAP on
    /// success (903), then wait for the welcome (001). The shared epilogue of
    /// every SASL path — waiting for the verdict before `CAP END` so the server
    /// can't complete registration ahead of it and mask a failure.
    async fn finish_sasl_then_welcome(
        &mut self,
        nick: &str,
        mechanism: &str,
    ) -> io::Result<String> {
        loop {
            let msg = self.recv_sasl_message(mechanism).await?;
            // 903 RPL_SASLSUCCESS: authenticated — now finish CAP.
            if msg.command == "903" {
                self.send_line("CAP END").await?;
                break;
            }
        }
        self.await_welcome(nick).await
    }

    /// Wait for the `001` welcome, answering PINGs. Registration-refusal
    /// numerics are terminal — a server that reports the failure but holds the
    /// socket open would otherwise hang this loop forever; fail loudly instead.
    async fn await_welcome(&mut self, nick: &str) -> io::Result<String> {
        loop {
            let msg = self.recv("closed before welcome").await?;
            if let Some(err) = registration_refused(&msg) {
                return Err(err);
            }
            match msg.command.as_str() {
                "001" => {
                    return Ok(msg
                        .params
                        .first()
                        .cloned()
                        .unwrap_or_else(|| nick.to_string()));
                }
                _ => {
                    self.answer_ping(&msg).await?;
                }
            }
        }
    }

    /// Register with SASL PLAIN: authenticate as `account`/`password`
    /// during CAP negotiation, then register `nick`.
    pub async fn register_sasl(
        &mut self,
        nick: &str,
        realname: &str,
        account: &str,
        password: &str,
    ) -> io::Result<String> {
        self.begin_sasl("PLAIN").await?;
        let payload = {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(account.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(password.as_bytes());
            e6irc_proto::base64::encode(&bytes)
        };
        self.register_with_sasl(nick, realname, payload, "PLAIN")
            .await
    }

    /// Negotiate SASL, offer `mechanism`, and wait for the server's empty
    /// challenge — everything before the mechanism-specific payload.
    async fn begin_sasl(&mut self, mechanism: &str) -> io::Result<()> {
        self.negotiate_sasl_cap(mechanism).await?;
        self.request_metadata_capabilities().await?;
        self.send_line(&format!("AUTHENTICATE {mechanism}")).await?;
        self.await_authenticate_challenge(mechanism).await
    }

    /// Send the registration info while CAP is still open, then the
    /// credentials, and finish to the welcome burst — the shared tail of
    /// every SASL mechanism (the mechanism is already negotiated and its
    /// payload built, which is all that differs between them).
    async fn register_with_sasl(
        &mut self,
        nick: &str,
        realname: &str,
        payload: String,
        mechanism: &str,
    ) -> io::Result<String> {
        self.send_registration_identity(nick, realname).await?;
        self.send_sasl_payload(&payload).await?;
        self.finish_sasl_then_welcome(nick, mechanism).await
    }

    async fn send_sasl_payload(&mut self, payload: &str) -> io::Result<()> {
        use e6irc_proto::sasl::{MAX_AUTHENTICATE_CHUNK_LEN, MAX_AUTHENTICATE_PAYLOAD_LEN};

        if payload.len() > MAX_AUTHENTICATE_PAYLOAD_LEN || !payload.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encoded SASL response exceeds the supported payload limit",
            ));
        }
        for chunk in payload.as_bytes().chunks(MAX_AUTHENTICATE_CHUNK_LEN) {
            let chunk = std::str::from_utf8(chunk).expect("an ASCII SASL payload has ASCII chunks");
            self.send_line(&format!("AUTHENTICATE {chunk}")).await?;
        }
        if payload.is_empty() || payload.len().is_multiple_of(MAX_AUTHENTICATE_CHUNK_LEN) {
            self.send_line("AUTHENTICATE +").await?;
        }
        Ok(())
    }

    /// Register with SASL OAUTHBEARER: authenticate with `token` (an
    /// e6irc API token) during CAP negotiation, then register `nick`.
    pub async fn register_oauthbearer(
        &mut self,
        nick: &str,
        realname: &str,
        token: &str,
    ) -> io::Result<String> {
        self.begin_sasl("OAUTHBEARER").await?;
        // RFC 7628 client response: gs2 header, then the bearer credential.
        let payload =
            e6irc_proto::base64::encode(format!("n,,\x01auth=Bearer {token}\x01\x01").as_bytes());
        self.register_with_sasl(nick, realname, payload, "OAUTHBEARER")
            .await
    }

    /// Register with a nick and realname, answering PINGs, until the
    /// welcome (001) arrives. Returns the confirmed nick.
    pub async fn register(&mut self, nick: &str, realname: &str) -> io::Result<String> {
        match self.begin_cap().await? {
            CapabilityNegotiation::Open => {
                self.request_metadata_capabilities().await?;
                self.send_registration_identity(nick, realname).await?;
                self.send_line("CAP END").await?;
            }
            // Nothing is authenticated on this path, so a server without
            // capability negotiation costs only the optional metadata.
            CapabilityNegotiation::Unsupported => {
                self.send_registration_identity(nick, realname).await?;
            }
        }
        self.await_welcome(nick).await
    }

    async fn send_registration_identity(&mut self, nick: &str, realname: &str) -> io::Result<()> {
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!(
            "USER {} 0 * :{realname}",
            registration_username(nick)
        ))
        .await
    }

    /// Require an atomic set of capabilities on an already registered
    /// connection. A server NAK is a visible feature error, never a silent
    /// downgrade.
    pub async fn require_capabilities(&mut self, capabilities: &[&str]) -> io::Result<()> {
        if capabilities.is_empty() {
            return Ok(());
        }
        let verdict = within(
            self.response_deadline,
            "answering a capability request",
            self.request_capabilities(capabilities),
        )
        .await?;
        match verdict {
            CapabilityVerdict::Acknowledged => Ok(()),
            CapabilityVerdict::Refused(reason) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "server does not support required capabilities: {} ({reason})",
                    capabilities.join(" ")
                ),
            )),
        }
    }

    /// Join one channel, wait for confirmation, and load its latest
    /// CHATHISTORY batch. Messages observed during JOIN and playback are
    /// returned in wire order so a UI can build state before its first draw.
    pub async fn join_with_history(
        &mut self,
        target: &str,
        history_count: usize,
    ) -> io::Result<Vec<ClientEvent>> {
        self.join_history(target, history_count, true).await
    }

    /// Join one channel and load the latest bounded history window regardless
    /// of its shared read marker. This is the scripting/history-inspection
    /// shape; interactive clients normally want [`Connection::join_with_history`]
    /// so reconnect resumes where the user stopped reading.
    pub async fn join_with_latest_history(
        &mut self,
        target: &str,
        history_count: usize,
    ) -> io::Result<Vec<ClientEvent>> {
        self.join_history(target, history_count, false).await
    }

    async fn join_history(
        &mut self,
        target: &str,
        history_count: usize,
        resume_after_marker: bool,
    ) -> io::Result<Vec<ClientEvent>> {
        within(
            self.response_deadline,
            "confirming a JOIN and its history",
            self.join_and_replay(target, history_count, resume_after_marker),
        )
        .await
    }

    /// The next event of a JOIN or history exchange. Read as the steady-state
    /// stream is: a Latin-1 topic or an over-long history line is reported in
    /// place, because neither is a reason to abandon the connection.
    async fn next_join_event(
        &mut self,
        events: &mut Vec<ClientEvent>,
        limit: usize,
        context: &'static str,
    ) -> io::Result<Option<OwnedMessage>> {
        if events.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the server sent more than {limit} lines without finishing the exchange"),
            ));
        }
        let event = self
            .next_event_lossy()
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, context))?;
        match event {
            ClientEvent::Message(message) if self.answer_ping(&message).await? => Ok(None),
            ClientEvent::Message(message) => Ok(Some(message)),
            rejected @ ClientEvent::Rejected(_) => {
                events.push(rejected);
                Ok(None)
            }
        }
    }

    async fn join_and_replay(
        &mut self,
        target: &str,
        history_count: usize,
        resume_after_marker: bool,
    ) -> io::Result<Vec<ClientEvent>> {
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        self.send_line(&format!("JOIN {target}")).await?;
        let mut events = Vec::new();
        let mut read_marker = None;
        loop {
            let Some(msg) = self
                .next_join_event(
                    &mut events,
                    MAX_JOIN_BURST_LINES,
                    "closed before JOIN was confirmed",
                )
                .await?
            else {
                continue;
            };
            if let Some(refusal) = JoinRefusal::from_reply(target, &msg) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, refusal));
            }
            let joined =
                msg.command == "366" && msg.params.iter().any(|value| casemap.eq(value, target));
            if msg.command == "MARKREAD"
                && msg
                    .params
                    .first()
                    .is_some_and(|candidate| casemap.eq(candidate, target))
            {
                read_marker = msg
                    .params
                    .get(1)
                    .and_then(|marker| marker.strip_prefix("timestamp="))
                    .and_then(e6irc_proto::time::parse_server_time_millis)
                    .map(e6irc_proto::time::server_time);
            }
            events.push(ClientEvent::Message(msg));
            if joined {
                break;
            }
        }
        if history_count == 0 {
            return Ok(events);
        }

        let request = match read_marker.filter(|_| resume_after_marker) {
            Some(marker) => {
                format!("CHATHISTORY AFTER {target} timestamp={marker} {history_count}")
            }
            None => format!("CHATHISTORY LATEST {target} * {history_count}"),
        };
        self.send_line(&request).await?;
        let limit = events
            .len()
            .saturating_add(history_count)
            .saturating_add(MAX_JOIN_BURST_LINES);
        let mut history_batch = None;
        loop {
            let Some(msg) = self
                .next_join_event(&mut events, limit, "closed during CHATHISTORY playback")
                .await?
            else {
                continue;
            };
            if msg.command == "FAIL"
                && msg
                    .params
                    .first()
                    .is_some_and(|command| command == "CHATHISTORY")
            {
                return Err(io::Error::other(format!(
                    "CHATHISTORY failed: {}",
                    msg.params.join(" ")
                )));
            }
            if msg.command == "BATCH"
                && let Some(reference) = msg.params.first()
            {
                if let Some(opened) = reference.strip_prefix('+')
                    && msg.params.get(1).is_some_and(|kind| kind == "chathistory")
                {
                    history_batch = Some(opened.to_owned());
                    continue;
                }
                if let Some(closed) = reference.strip_prefix('-')
                    && history_batch.as_deref() == Some(closed)
                {
                    break;
                }
            }
            events.push(ClientEvent::Message(msg));
        }
        Ok(events)
    }
}

/// Lines a server may send between a `JOIN` and its end-of-names, or around a
/// history batch, before this client stops accumulating them. A large channel's
/// NAMES list is a few hundred lines; the bound only has to stop a peer from
/// choosing how much memory a join costs.
const MAX_JOIN_BURST_LINES: usize = 4096;

/// A server's refusal to let this client into a channel, typed so a caller can
/// tell "this one channel is closed to me" from a failed connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRefusal {
    channel: String,
    forwarded_to: Option<String>,
    diagnostic: String,
}

impl JoinRefusal {
    pub fn from_error(error: &io::Error) -> Option<Self> {
        typed_cause(error)
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Read `reply` as the server's refusal of a `JOIN` of `channel`. 470 is a
    /// refusal too: the server joined some other channel on its own initiative,
    /// and the 366 that follows names that one, never `channel`.
    fn from_reply(channel: &str, reply: &OwnedMessage) -> Option<Self> {
        let forwarded_to = (reply.command == "470")
            .then(|| reply.params.get(2))
            .flatten()
            .map(|forward| bounded_diagnostic(forward));
        (forwarded_to.is_some() || is_join_refusal(&reply.command)).then(|| Self {
            channel: channel.to_owned(),
            forwarded_to,
            diagnostic: registration_diagnostic(reply),
        })
    }

    /// The channel a 470 says the server moved this client to instead.
    pub fn forwarded_to(&self) -> Option<&str> {
        self.forwarded_to.as_deref()
    }
}

impl std::fmt::Display for JoinRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot join {}: {}", self.channel, self.diagnostic)?;
        match &self.forwarded_to {
            Some(forward) => write!(
                f,
                " (the server joined {forward} instead; this client did not ask for it)"
            ),
            None => Ok(()),
        }
    }
}

impl std::error::Error for JoinRefusal {}

/// Whether a message target names a channel rather than a nickname. `&` marks
/// a server-local channel and is as much a channel as `#`; the native clients
/// share this so none of them joins one kind and silently ignores the other.
pub fn is_channel_target(target: &str) -> bool {
    target.starts_with(['#', '&'])
}

/// The JOIN-refusal numerics: the replies that mean the 366 a join waits for
/// will never come. Every client joins through [`Connection::join_with_history`]
/// or its sibling, so this is read in exactly one place
/// ([`JoinRefusal::from_reply`]).
fn is_join_refusal(command: &str) -> bool {
    matches!(
        command,
        "403" | "405" | "471" | "473" | "474" | "475" | "476" | "477" | "480"
    )
}

/// Return a USER field that fits the portable ten-character limit.
fn registration_username(nick: &str) -> &str {
    let end = nick
        .char_indices()
        .map(|(start, character)| start + character.len_utf8())
        .take_while(|&end| end <= 10)
        .last()
        .unwrap_or(0);
    &nick[..end]
}

/// Map a registration-refusal numeric to a terminal error, if it is one. These
/// are the replies a server sends when it will not complete registration for
/// the requested nick/credentials; a client that keeps waiting for `001` after
/// one of them hangs forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationRefusal {
    InvalidNickname,
    InvalidUsername,
    NicknameInUse,
    ServerPasswordRejected,
    NetworkBanned,
    NotRegistered,
    /// The server does not offer the SASL capability or mechanism this
    /// connection was asked to authenticate with. Built only from a
    /// [`SaslRejection`].
    SaslUnavailable,
    /// SASL ended without a verdict on the credentials (a locked account, an
    /// aborted or over-long exchange). Built only from a [`SaslRejection`].
    SaslFailed,
}

/// A server-supplied registration refusal whose detail is bounded and safe to
/// show to the account owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRejection {
    refusal: RegistrationRefusal,
    diagnostic: String,
}

impl RegistrationRejection {
    /// Classify a refusal for which the upstream did not supply a message.
    pub fn without_diagnostic(refusal: RegistrationRefusal) -> Self {
        Self {
            refusal,
            diagnostic: "no detail from upstream".to_string(),
        }
    }

    pub fn from_error(error: &io::Error) -> Option<Self> {
        typed_cause::<RegistrationRefusalError>(error).map(|error| Self {
            refusal: error.refusal,
            diagnostic: error.diagnostic,
        })
    }

    pub const fn refusal(&self) -> RegistrationRefusal {
        self.refusal
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// The typed cause this library attached to `error`, when it is a `T`. Every
/// refusal a caller must act on differently travels this way, because an
/// `io::ErrorKind` cannot tell a rejected password from a missing mechanism.
fn typed_cause<T: std::error::Error + Clone + 'static>(error: &io::Error) -> Option<T> {
    error.get_ref()?.downcast_ref::<T>().cloned()
}

#[derive(Debug, Clone)]
struct RegistrationRefusalError {
    refusal: RegistrationRefusal,
    diagnostic: String,
}

impl std::fmt::Display for RegistrationRefusalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IRC registration refusal: {:?}: {}",
            self.refusal, self.diagnostic
        )
    }
}

impl std::error::Error for RegistrationRefusalError {}

impl RegistrationRefusal {
    pub fn from_error(error: &io::Error) -> Option<Self> {
        RegistrationRejection::from_error(error).map(|rejection| rejection.refusal())
    }

    fn error(self, message: &OwnedMessage) -> io::Error {
        let kind = match self {
            Self::NicknameInUse => io::ErrorKind::AlreadyExists,
            Self::InvalidNickname => io::ErrorKind::InvalidInput,
            Self::InvalidUsername => io::ErrorKind::InvalidInput,
            Self::ServerPasswordRejected => io::ErrorKind::PermissionDenied,
            Self::NetworkBanned => io::ErrorKind::ConnectionAborted,
            Self::NotRegistered | Self::SaslFailed => io::ErrorKind::Other,
            Self::SaslUnavailable => io::ErrorKind::Unsupported,
        };
        io::Error::new(
            kind,
            RegistrationRefusalError {
                refusal: self,
                diagnostic: registration_diagnostic(message),
            },
        )
    }
}

/// The one refusal predicate for every pre-welcome wait loop (capability
/// discovery, capability requests, SASL, and the welcome itself). `ERROR` is
/// the server closing the link with its reason — a connection throttle, a ban,
/// "SASL access only" — and it can arrive at any of those stages, so it is
/// classified here rather than by whichever loop happens to be running.
fn registration_refused(message: &OwnedMessage) -> Option<io::Error> {
    let refusal = match message.command.as_str() {
        "ERROR" => RegistrationRefusal::NotRegistered,
        "432" => RegistrationRefusal::InvalidNickname,
        "468" => RegistrationRefusal::InvalidUsername,
        "433" => RegistrationRefusal::NicknameInUse,
        "464" => RegistrationRefusal::ServerPasswordRejected,
        "465" => RegistrationRefusal::NetworkBanned,
        "451" => RegistrationRefusal::NotRegistered,
        _ => return None,
    };
    Some(refusal.error(message))
}

fn registration_diagnostic(message: &OwnedMessage) -> String {
    bounded_diagnostic(
        message
            .params
            .last()
            .map(String::as_str)
            .unwrap_or("no detail"),
    )
}

/// The one bound on server-influenced text carried inside a typed refusal:
/// short enough for a status line, and free of control characters so it can be
/// relayed as an IRC NOTICE or printed to a terminal.
fn bounded_diagnostic(detail: &str) -> String {
    detail
        .chars()
        .take(160)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Why SASL did not authenticate this connection.
///
/// Only [`SaslFailure::Failed`] says anything about the credentials. Every
/// other variant is a property of the server, the account's state, or the
/// exchange, and retyping a correct password can never clear it — which is why
/// callers must not collapse them into one "authentication failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslFailure {
    /// 904 for a mechanism the server does offer: the credentials are wrong.
    Failed,
    /// 902: the account is locked, held, or otherwise unavailable.
    NickLocked,
    /// 905: the server refused the length of the authentication message.
    TooLong,
    /// 906: the exchange was aborted.
    Aborted,
    /// 907: the connection had already authenticated.
    AlreadyAuthenticated,
    /// The server offers SASL, but not the mechanism this client was asked to
    /// use (its advertised `sasl=` list, or a 908 list, omits it).
    MechanismNotOffered,
    /// The server does not offer SASL at all: no `sasl` capability, a refused
    /// capability request, or no capability negotiation.
    CapabilityNotOffered,
}

/// A typed SASL failure with a bounded, control-free diagnostic, carried as the
/// inner value of the `io::Error` a registration call returns — the same shape
/// as [`RegistrationRejection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslRejection {
    failure: SaslFailure,
    diagnostic: String,
}

/// What a [`SaslRejection`] obliges its caller to do. A credential rejection
/// must never be retried (each attempt counts against the account upstream); any
/// other SASL failure is an ordinary registration refusal. Splitting them here
/// means no caller can route wrong credentials onto a retry schedule, or park a
/// correct password as "rejected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslRejectionClass {
    CredentialsRejected(SaslRejection),
    RegistrationRefused(RegistrationRejection),
}

impl SaslRejection {
    fn new(failure: SaslFailure, diagnostic: &str) -> Self {
        Self {
            failure,
            diagnostic: bounded_diagnostic(diagnostic),
        }
    }

    pub fn from_error(error: &io::Error) -> Option<Self> {
        typed_cause(error)
    }

    pub const fn failure(&self) -> SaslFailure {
        self.failure
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub fn class(self) -> SaslRejectionClass {
        let refusal = match self.failure {
            SaslFailure::Failed => return SaslRejectionClass::CredentialsRejected(self),
            SaslFailure::MechanismNotOffered | SaslFailure::CapabilityNotOffered => {
                RegistrationRefusal::SaslUnavailable
            }
            SaslFailure::NickLocked
            | SaslFailure::TooLong
            | SaslFailure::Aborted
            | SaslFailure::AlreadyAuthenticated => RegistrationRefusal::SaslFailed,
        };
        SaslRejectionClass::RegistrationRefused(RegistrationRejection {
            refusal,
            diagnostic: self.diagnostic,
        })
    }

    fn into_error(self) -> io::Error {
        let kind = match self.failure {
            SaslFailure::Failed => io::ErrorKind::PermissionDenied,
            SaslFailure::MechanismNotOffered | SaslFailure::CapabilityNotOffered => {
                io::ErrorKind::Unsupported
            }
            SaslFailure::NickLocked
            | SaslFailure::TooLong
            | SaslFailure::Aborted
            | SaslFailure::AlreadyAuthenticated => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl std::fmt::Display for SaslRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SASL {:?}: {}", self.failure, self.diagnostic)
    }
}

impl std::error::Error for SaslRejection {}

/// Install aws-lc-rs as the process rustls provider, once.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Another library in the process may already have installed rustls's
        // process-wide provider; the builder below uses that provider.
        drop(rustls::crypto::aws_lc_rs::default_provider().install_default());
    });
}

/// The public Mozilla CA trust set (webpki-roots) as a rustls store.
pub fn webpki_root_store() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_refusals_keep_the_server_cause() {
        for (numeric, expected) in [
            ("432", RegistrationRefusal::InvalidNickname),
            ("468", RegistrationRefusal::InvalidUsername),
            ("433", RegistrationRefusal::NicknameInUse),
            ("464", RegistrationRefusal::ServerPasswordRejected),
            ("465", RegistrationRefusal::NetworkBanned),
            ("451", RegistrationRefusal::NotRegistered),
        ] {
            let message = OwnedMessage::from(
                &Message::parse(&format!(":srv {numeric} nick :refused")).expect("numeric"),
            );
            let error = registration_refused(&message).expect("known refusal numeric");
            assert_eq!(RegistrationRefusal::from_error(&error), Some(expected));
            let rejection = RegistrationRejection::from_error(&error).expect("typed rejection");
            assert_eq!(rejection.refusal(), expected);
            assert_eq!(rejection.diagnostic(), "refused");
        }
    }

    #[test]
    fn registration_username_fits_the_portable_limit() {
        assert_eq!(registration_username("alice_updated"), "alice_upda");
        assert_eq!(registration_username("short"), "short");
        assert_eq!(registration_username("ééééééééééx"), "ééééé");
    }

    #[test]
    fn owned_messages_canonicalize_commands_and_use_the_final_duplicate_tag() {
        let message = OwnedMessage::from(
            &Message::parse("@example=old;example=new :srv pInG :token").expect("message"),
        );
        assert_eq!(message.command, "PING");
        assert_eq!(message.tag("example"), Some("new"));
    }

    #[test]
    fn registration_diagnostic_is_bounded_and_control_safe() {
        let message = OwnedMessage {
            tags: Vec::new(),
            source: None,
            command: "ERROR".into(),
            params: vec![format!("{}\r\nnext", "x".repeat(200))],
        };
        let diagnostic = registration_diagnostic(&message);
        assert_eq!(diagnostic.chars().count(), 160);
        assert!(!diagnostic.chars().any(char::is_control));
    }

    #[test]
    fn terminal_safe_neutralizes_control_bytes() {
        // ESC (C0), the one-byte CSI (C1, 0x9B), DEL, and a bare BEL all become
        // U+FFFD; ordinary text and non-ASCII pass through untouched.
        let s = TerminalSafe::from_untrusted("a\x1b[2Jb\u{9b}c\x7f\x07d\u{00e9}");
        assert_eq!(
            s.as_str(),
            "a\u{fffd}[2Jb\u{fffd}c\u{fffd}\u{fffd}d\u{00e9}"
        );
        assert!(!s.as_str().chars().any(|c| c.is_control()));
        assert_eq!(
            TerminalSafe::from_untrusted("plain #chan").as_str(),
            "plain #chan"
        );
    }

    #[test]
    fn owned_message_flattens_source_and_tags() {
        let msg = Message::parse("@time=x;msgid=1 :nick!user@host PRIVMSG #c :hi there").unwrap();
        let owned = OwnedMessage::from(&msg);
        assert_eq!(owned.command, "PRIVMSG");
        assert_eq!(owned.source.as_deref(), Some("nick!user@host"));
        assert_eq!(owned.params, vec!["#c", "hi there"]);
        assert!(
            owned
                .tags
                .iter()
                .any(|(k, v)| k == "msgid" && v.as_deref() == Some("1"))
        );
    }

    #[test]
    fn owned_message_server_source() {
        let owned = OwnedMessage::from(&Message::parse(":irc.example 001 nick :Welcome").unwrap());
        assert_eq!(owned.source.as_deref(), Some("irc.example"));
        assert_eq!(owned.command, "001");
    }

    #[test]
    fn tls_name_is_derived_without_misparsing_ipv6() {
        assert_eq!(tls_server_name("irc.example:6697").unwrap(), "irc.example");
        assert_eq!(tls_server_name("127.0.0.1:6697").unwrap(), "127.0.0.1");
        assert_eq!(
            tls_server_name("[2001:db8::1]:6697").unwrap(),
            "2001:db8::1"
        );
        assert!(tls_server_name("2001:db8::1:6697").is_err());
        assert!(tls_server_name("missing-port").is_err());
        assert!(tls_server_name("[2001:db8::1]").is_err());
    }

    async fn negotiate_sasl(
        server_io: tokio::io::DuplexStream,
        mechanism: &str,
    ) -> (
        tokio::io::Lines<tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        use tokio::io::AsyncBufReadExt;

        let (reader, mut writer) = tokio::io::split(server_io);
        let mut lines = tokio::io::BufReader::new(reader).lines();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP LS 302");
        writer
            .write_all(b":srv CAP * LS :sasl server-time message-tags account-tag\r\n")
            .await
            .unwrap();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP REQ :sasl");
        writer.write_all(b":srv CAP * ACK :sasl\r\n").await.unwrap();
        assert_eq!(
            lines.next_line().await.unwrap().unwrap(),
            "CAP REQ :server-time message-tags account-tag"
        );
        writer
            .write_all(b":srv CAP * ACK :server-time message-tags account-tag\r\n")
            .await
            .unwrap();
        assert_eq!(
            lines.next_line().await.unwrap().unwrap(),
            format!("AUTHENTICATE {mechanism}")
        );
        (lines, writer)
    }

    /// One step of a scripted server: a line it must receive next, or a line it
    /// sends.
    enum Step {
        Expect(&'static str),
        Send(&'static str),
    }
    use Step::{Expect, Send};

    /// A client wired to a server that plays `steps`, then reads to end of
    /// stream and yields every line the client sent that no step expected.
    fn scripted(steps: Vec<Step>) -> (Connection, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (connection, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_io);
            let mut lines = tokio::io::BufReader::new(reader).lines();
            for step in steps {
                match step {
                    Expect(line) => assert_eq!(
                        lines.next_line().await.unwrap().as_deref(),
                        Some(line),
                        "the client's next line"
                    ),
                    Send(line) => writer
                        .write_all(format!("{line}\r\n").as_bytes())
                        .await
                        .unwrap(),
                }
            }
            let mut unexpected = Vec::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                unexpected.push(line);
            }
            unexpected
        });
        (connection, server)
    }

    /// A server that answers capability discovery with `advertised`, then
    /// plays `rest`.
    fn after_discovery(advertised: &'static str, rest: Vec<Step>) -> Vec<Step> {
        let mut steps = vec![Expect("CAP LS 302"), Send(advertised)];
        steps.extend(rest);
        steps
    }

    /// How a registration against the scripted server must end.
    enum Ending {
        Welcomed,
        SaslRefused(SaslFailure, &'static str),
    }

    /// Register against `steps` — with SASL PLAIN when the ending is a SASL
    /// one — and require that ending, and that the client sent nothing the
    /// script did not expect. A registration that waits forever is the defect
    /// several of these tests exist to catch, so the wait is bounded.
    async fn assert_registration(steps: Vec<Step>, ending: Ending) -> Option<SaslRejection> {
        let (mut connection, server) = scripted(steps);
        let registration = async {
            match ending {
                Ending::Welcomed => connection.register("nick", "real").await,
                Ending::SaslRefused(..) => {
                    connection.register_sasl("nick", "real", "acct", "pw").await
                }
            }
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), registration)
            .await
            .expect("registration neither finished nor failed");
        let rejection = match ending {
            Ending::Welcomed => {
                assert_eq!(result.expect("registered"), "nick");
                None
            }
            Ending::SaslRefused(failure, diagnostic) => {
                let error = result.expect_err("SASL must be refused");
                let rejection = SaslRejection::from_error(&error)
                    .unwrap_or_else(|| panic!("not a typed SASL rejection: {error:?}"));
                assert_eq!(rejection.failure(), failure);
                assert_eq!(rejection.diagnostic(), diagnostic);
                Some(rejection)
            }
        };
        drop(connection);
        assert_eq!(
            server.await.unwrap(),
            Vec::<String>::new(),
            "the client sent lines the server never asked for"
        );
        rejection
    }

    const IDENTITY_THEN_WELCOME: [Step; 4] = [
        Expect("NICK nick"),
        Expect("USER nick 0 * :real"),
        Expect("CAP END"),
        Send(":srv 001 nick :Welcome"),
    ];

    #[tokio::test]
    async fn sasl_stops_before_authenticate_when_the_mechanism_is_not_advertised() {
        let rejection = assert_registration(
            after_discovery(
                ":srv CAP * LS :sasl=EXTERNAL,SCRAM-SHA-256 server-time",
                Vec::new(),
            ),
            Ending::SaslRefused(
                SaslFailure::MechanismNotOffered,
                "requested PLAIN; the server offers EXTERNAL,SCRAM-SHA-256",
            ),
        )
        .await
        .expect("a rejection");
        assert!(matches!(
            rejection.class(),
            SaslRejectionClass::RegistrationRefused(refused)
                if refused.refusal() == RegistrationRefusal::SaslUnavailable
        ));
    }

    #[tokio::test]
    async fn a_multi_line_capability_list_is_accumulated_and_metadata_is_one_request() {
        let mut steps = after_discovery(
            ":srv CAP * LS * :server-time message-tags unrelated=x",
            vec![
                Send(":srv CAP * LS :account-tag"),
                Expect("CAP REQ :server-time message-tags account-tag"),
                Send(":srv CAP * ACK :server-time message-tags account-tag"),
            ],
        );
        steps.extend(IDENTITY_THEN_WELCOME);
        assert_registration(steps, Ending::Welcomed).await;
    }

    #[tokio::test]
    async fn only_advertised_metadata_is_requested() {
        let mut one = after_discovery(
            ":srv CAP * LS :server-time",
            vec![
                Expect("CAP REQ :server-time"),
                Send(":srv CAP * ACK :server-time"),
            ],
        );
        one.extend(IDENTITY_THEN_WELCOME);
        assert_registration(one, Ending::Welcomed).await;

        let mut none = after_discovery(":srv CAP * LS :", Vec::new());
        none.extend(IDENTITY_THEN_WELCOME);
        assert_registration(none, Ending::Welcomed).await;
    }

    #[tokio::test]
    async fn the_sasl_mechanism_list_numeric_is_remembered_not_mistaken_for_the_verdict() {
        assert_registration(
            // No `sasl=` value: the mechanisms are unknown until 908.
            after_discovery(
                ":srv CAP * LS :sasl",
                vec![
                    Expect("CAP REQ :sasl"),
                    Send(":srv CAP * ACK :sasl"),
                    Expect("AUTHENTICATE PLAIN"),
                    Send(":srv 908 * EXTERNAL,SCRAM-SHA-256 :are available SASL mechanisms"),
                    Send(":srv 904 * :SASL authentication failed"),
                ],
            ),
            Ending::SaslRefused(
                SaslFailure::MechanismNotOffered,
                "requested PLAIN; the server offers EXTERNAL,SCRAM-SHA-256",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn sasl_failure_numerics_are_distinguished_and_keep_the_server_reason() {
        for (verdict, expected) in [
            (
                ":srv 902 * :the server's own words",
                SaslFailure::NickLocked,
            ),
            (":srv 904 * :the server's own words", SaslFailure::Failed),
            (":srv 905 * :the server's own words", SaslFailure::TooLong),
            (":srv 906 * :the server's own words", SaslFailure::Aborted),
            (
                ":srv 907 * :the server's own words",
                SaslFailure::AlreadyAuthenticated,
            ),
        ] {
            let rejection = assert_registration(
                after_discovery(
                    ":srv CAP * LS :sasl=PLAIN",
                    vec![
                        Expect("CAP REQ :sasl"),
                        Send(":srv CAP * ACK :sasl"),
                        Expect("AUTHENTICATE PLAIN"),
                        Send(verdict),
                    ],
                ),
                Ending::SaslRefused(expected, "the server's own words"),
            )
            .await
            .expect("a rejection");
            assert_eq!(
                matches!(
                    rejection.class(),
                    SaslRejectionClass::CredentialsRejected(_)
                ),
                expected == SaslFailure::Failed,
                "only a 904 for an offered mechanism is about the credentials"
            );
        }
    }

    #[tokio::test]
    async fn an_unavailable_sasl_capability_is_a_worded_refusal() {
        assert_registration(
            after_discovery(":srv CAP * LS :server-time message-tags", Vec::new()),
            Ending::SaslRefused(
                SaslFailure::CapabilityNotOffered,
                "the server does not advertise the sasl capability",
            ),
        )
        .await;
        for (refusal, diagnostic) in [
            (
                ":srv CAP * NAK :sasl",
                "the server refused the sasl capability: the server sent CAP NAK",
            ),
            (
                ":srv 410 * REQ :Invalid CAP command",
                "the server refused the sasl capability: Invalid CAP command",
            ),
        ] {
            assert_registration(
                after_discovery(
                    ":srv CAP * LS :sasl=PLAIN",
                    vec![Expect("CAP REQ :sasl"), Send(refusal)],
                ),
                Ending::SaslRefused(SaslFailure::CapabilityNotOffered, diagnostic),
            )
            .await;
        }
    }

    /// Configured SASL must never degrade to an unauthenticated registration,
    /// and `CAP END` means nothing to a server that does not know `CAP`.
    #[tokio::test]
    async fn a_server_without_capability_negotiation_registers_plainly_but_never_skips_sasl() {
        assert_registration(
            after_discovery(
                ":srv 421 * CAP :Unknown command",
                vec![
                    Expect("NICK nick"),
                    Expect("USER nick 0 * :real"),
                    Send(":srv 001 nick :Welcome"),
                ],
            ),
            Ending::Welcomed,
        )
        .await;
        assert_registration(
            after_discovery(":srv 421 * CAP :Unknown command", Vec::new()),
            Ending::SaslRefused(
                SaslFailure::CapabilityNotOffered,
                "the server does not support capability negotiation",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn an_endless_capability_list_is_refused_not_accumulated() {
        use tokio::io::AsyncWriteExt;

        let (mut connection, server_io) = duplex_connection(1024 * 1024);
        let server = tokio::spawn(async move {
            let (_reader, mut writer) = tokio::io::split(server_io);
            for line in 0..=MAX_ADVERTISED_CAPABILITIES {
                writer
                    .write_all(format!(":srv CAP * LS * :vendor/cap-{line}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            writer
        });
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connection.register("nick", "real"),
        )
        .await
        .expect("an endless list must end the registration")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        drop(server.await.unwrap());
    }

    fn duplex_connection(capacity: usize) -> (Connection, tokio::io::DuplexStream) {
        let (client_io, server_io) = tokio::io::duplex(capacity);
        let (reader, writer) = tokio::io::split(client_io);
        (
            Connection::from_halves(Box::new(reader), Box::new(writer)),
            server_io,
        )
    }

    #[tokio::test]
    async fn capability_request_requires_a_correlated_verdict() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (mut connection, server_io) = duplex_connection(4096);
        let server = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_io);
            let mut lines = tokio::io::BufReader::new(reader).lines();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "CAP REQ :server-time"
            );
            writer
                .write_all(b":srv CAP * ACK :message-tags\r\n")
                .await
                .unwrap();
        });

        let error = connection
            .request_capabilities(&["server-time"])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("server-time"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn register_sasl_fails_loudly_on_reject_numeric() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A server that ACKs sasl, then answers the AUTHENTICATE with a 904
        // failure numeric and holds the socket open. Without the terminal-numeric
        // handling in `await_authenticate_challenge`, this loops forever; with it,
        // register_sasl returns an error promptly.
        let (mut conn, server_io) = duplex_connection(16 * 1024);

        let server = tokio::spawn(async move {
            let (lines, mut sw) = negotiate_sasl(server_io, "PLAIN").await;
            sw.write_all(b":srv 904 * :SASL authentication failed\r\n")
                .await
                .unwrap();
            // Keep draining and holding the socket open so the client can't rely
            // on EOF to unblock — the failure must come from the numeric itself.
            let mut reader = lines.into_inner();
            let mut buf = vec![0u8; 1024];
            loop {
                if reader.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
            }
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            conn.register_sasl("nick", "real", "acct", "pw"),
        )
        .await;
        assert!(
            result.is_ok(),
            "register_sasl hung on a SASL-reject numeric"
        );
        assert!(
            result.unwrap().is_err(),
            "a SASL-reject numeric must surface as an error"
        );
        drop(conn); // closes the client side so the server task can end
        server.await.expect("mock server task");
    }

    #[tokio::test]
    async fn server_error_during_sasl_is_a_typed_refusal_with_its_reason() {
        let (mut conn, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(async move {
            let (_lines, mut writer) = negotiate_sasl(server_io, "PLAIN").await;
            writer
                .write_all(b"ERROR :Closing Link: client (Trying to reconnect too fast.)\r\n")
                .await
                .unwrap();
        });

        let error = conn
            .register_sasl("nick", "real", "acct", "pw")
            .await
            .unwrap_err();
        let rejection = RegistrationRejection::from_error(&error)
            .expect("a server ERROR during SASL is a typed refusal, not a lost connection");
        assert_eq!(rejection.refusal(), RegistrationRefusal::NotRegistered);
        assert!(
            rejection.diagnostic().contains("reconnect too fast"),
            "{rejection:?}"
        );
        server.await.expect("mock server task");
    }

    #[tokio::test]
    async fn register_fails_loudly_on_error_before_welcome() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut conn, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server_io);
            writer
                .write_all(b"ERROR :Closing Link: client [network policy]\r\n")
                .await
                .unwrap();
            let mut buffer = [0; 1024];
            while reader.read(&mut buffer).await.unwrap_or(0) != 0 {}
        });

        let error = conn.register("nick", "real").await.unwrap_err();
        let rejection = RegistrationRejection::from_error(&error)
            .expect("a server ERROR before CAP completes is a typed refusal");
        assert_eq!(rejection.refusal(), RegistrationRefusal::NotRegistered);
        assert_eq!(
            rejection.diagnostic(),
            "Closing Link: client [network policy]"
        );
        drop(conn);
        server.await.expect("mock server task");
    }

    #[tokio::test]
    async fn oauth_registration_requests_the_same_metadata_as_other_modes() {
        use tokio::io::AsyncWriteExt;

        let (mut connection, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(async move {
            let (mut lines, mut sw) = negotiate_sasl(server_io, "OAUTHBEARER").await;
            sw.write_all(b"AUTHENTICATE +\r\n").await.unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "NICK nick");
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "USER nick 0 * :real"
            );
            assert!(
                lines
                    .next_line()
                    .await
                    .unwrap()
                    .unwrap()
                    .starts_with("AUTHENTICATE ")
            );
            sw.write_all(b":srv 903 nick :SASL authentication successful\r\n")
                .await
                .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP END");
            sw.write_all(b":srv 001 nick :Welcome\r\n").await.unwrap();
        });

        assert_eq!(
            connection
                .register_oauthbearer("nick", "real", "token")
                .await
                .unwrap(),
            "nick"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sasl_payloads_are_chunked_and_exact_boundaries_get_an_empty_final_chunk() {
        use tokio::io::AsyncBufReadExt;

        let (mut connection, server_io) = duplex_connection(16 * 1024);
        connection
            .send_sasl_payload(&"a".repeat(801))
            .await
            .expect("chunked response");
        connection
            .send_sasl_payload(&"b".repeat(800))
            .await
            .expect("exact response");
        drop(connection);

        let (reader, _writer) = tokio::io::split(server_io);
        let mut reader = tokio::io::BufReader::new(reader).lines();
        let mut lines = Vec::new();
        while let Some(line) = reader.next_line().await.expect("wire line") {
            lines.push(line);
        }
        assert_eq!(lines[0], format!("AUTHENTICATE {}", "a".repeat(400)));
        assert_eq!(lines[1], format!("AUTHENTICATE {}", "a".repeat(400)));
        assert_eq!(lines[2], "AUTHENTICATE a");
        assert_eq!(lines[3], format!("AUTHENTICATE {}", "b".repeat(400)));
        assert_eq!(lines[4], format!("AUTHENTICATE {}", "b".repeat(400)));
        assert_eq!(lines[5], "AUTHENTICATE +");
        assert_eq!(lines.len(), 6);
    }

    #[tokio::test]
    async fn send_line_rejects_injected_crlf_and_nul_without_writing() {
        use tokio::io::AsyncReadExt;
        let (mut conn, server_io) = duplex_connection(8192);

        let error = conn
            .send_line("PRIVMSG #c :hi\r\nJOIN #evil\0tail")
            .await
            .expect_err("an injected line is invalid as a whole");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        drop(conn);

        let (mut sr, _sw) = tokio::io::split(server_io);
        let mut got = Vec::new();
        sr.read_to_end(&mut got).await.unwrap();
        assert!(
            got.is_empty(),
            "a rejected line must not be partially written"
        );
    }

    #[tokio::test]
    async fn send_line_rejects_each_wire_budget_before_writing() {
        use tokio::io::AsyncReadExt;

        let (mut conn, server_io) = duplex_connection(8192);
        let error = conn
            .send_line(&"x".repeat(e6irc_proto::message::MAX_LINE_LEN - 1))
            .await
            .expect_err("overlong traditional body");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        drop(conn);

        let (mut reader, _writer) = tokio::io::split(server_io);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "a rejected line must not be partially written"
        );
    }

    #[tokio::test]
    async fn relay_preserves_the_server_tag_allowance_but_rejects_an_overlong_body() {
        use tokio::io::AsyncWriteExt;

        let (mut conn, server_io) = duplex_connection(16 * 1024);
        let (_reader, mut writer) = tokio::io::split(server_io);
        let tagged = format!("@example={} :srv NOTICE nick :ok", "a".repeat(600));
        writer.write_all(tagged.as_bytes()).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();
        writer
            .write_all(&vec![b'x'; e6irc_proto::message::MAX_LINE_LEN - 1])
            .await
            .unwrap();
        writer.write_all(b"\r\n").await.unwrap();

        let Some(RelayEvent::Line { raw, .. }) = conn.next_line_relayable().await.unwrap() else {
            panic!("tagged server line was not relayed");
        };
        assert_eq!(raw, tagged);
        assert!(matches!(
            conn.next_line_relayable().await.unwrap(),
            Some(RelayEvent::Rejected(RejectedLine::TooLong))
        ));
    }

    #[tokio::test]
    async fn next_event_lossy_survives_non_utf8_line_and_surfaces_rejections() {
        use tokio::io::AsyncWriteExt;
        // A Latin-1 body (0xE9 = 'é') any channel member can post is not valid
        // UTF-8. Strict `next_message` errors on it (the handshake wants that);
        // the interactive steady-state read must lossily decode and keep going.
        let (mut conn, server_io) = duplex_connection(16 * 1024);

        let (_sr, mut sw) = tokio::io::split(server_io);
        sw.write_all(b":nick PRIVMSG #c :caf\xe9\r\n")
            .await
            .unwrap();
        sw.write_all(&vec![b'x'; e6irc_proto::message::MAX_SERVER_FRAME_LEN + 1])
            .await
            .unwrap();
        sw.write_all(b"\r\n:nick PRIVMSG #c :ok\r\n").await.unwrap();

        // The high-byte line comes back lossily decoded (é -> U+FFFD), not as an
        // error that would tear down the session.
        let ClientEvent::Message(first) = conn.next_event_lossy().await.unwrap().unwrap() else {
            panic!("valid lossy-decoded message was rejected");
        };
        assert_eq!(first.command, "PRIVMSG");
        assert_eq!(first.params.get(1).map(String::as_str), Some("caf\u{fffd}"));
        assert!(matches!(
            conn.next_event_lossy().await.unwrap().unwrap(),
            ClientEvent::Rejected(RejectedLine::TooLong)
        ));
        let ClientEvent::Message(second) = conn.next_event_lossy().await.unwrap().unwrap() else {
            panic!("valid message after rejected line was not delivered");
        };
        assert_eq!(second.params.get(1).map(String::as_str), Some("ok"));

        drop(conn);
        drop(sw);
    }

    fn messages_of(events: &[ClientEvent]) -> Vec<&OwnedMessage> {
        events
            .iter()
            .filter_map(|event| match event {
                ClientEvent::Message(message) => Some(message),
                ClientEvent::Rejected(_) => None,
            })
            .collect()
    }

    /// A peer that keeps the socket busy with lines that answer nothing.
    async fn chatter(mut writer: impl AsyncWrite + Unpin) {
        while writer
            .write_all(b":srv NOTICE * :still here\r\n")
            .await
            .is_ok()
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Bound a call this test expects to give up by itself, so the defect shows
    /// as a failure rather than a hung test run.
    async fn must_give_up<T>(call: impl Future<Output = io::Result<T>>) -> io::Error {
        tokio::time::timeout(std::time::Duration::from_secs(3), call)
            .await
            .expect("the call waited on the peer without a deadline")
            .err()
            .expect("the call cannot have succeeded")
    }

    fn anonymous(address: String, response_deadline: std::time::Duration) -> ConnectionOptions {
        ConnectionOptions {
            address,
            tls: false,
            tls_server_name: None,
            nick: "requested".into(),
            realname: "real".into(),
            authentication: Authentication::None,
            response_deadline,
        }
    }

    #[tokio::test]
    async fn registration_gives_up_at_the_response_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (_reader, writer) = socket.into_split();
            chatter(writer).await;
        });
        let options = anonymous(address, std::time::Duration::from_millis(150));
        let error = must_give_up(options.connect_registered()).await;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    }

    #[tokio::test]
    async fn requests_after_registration_give_up_at_the_response_deadline() {
        for join in [false, true] {
            let (mut connection, server_io) = duplex_connection(16 * 1024);
            connection.response_deadline = Some(std::time::Duration::from_millis(150));
            let (_reader, writer) = tokio::io::split(server_io);
            let peer = tokio::spawn(chatter(writer));
            let error = if join {
                must_give_up(connection.join_with_history("#room", 0)).await
            } else {
                must_give_up(connection.require_capabilities(&["batch"])).await
            };
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
            peer.abort();
        }
    }

    #[tokio::test]
    async fn the_server_confirmed_nick_is_returned() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                let reply: &[u8] = match line.as_str() {
                    "CAP LS 302" => b":bnc CAP * LS :\r\n",
                    "CAP END" => b":bnc 001 upstream_nick :Welcome\r\n",
                    _ => continue,
                };
                writer.write_all(reply).await.unwrap();
            }
        });
        let registered = anonymous(address, std::time::Duration::from_secs(5))
            .connect_registered()
            .await
            .expect("registered");
        assert_eq!(registered.nick, "upstream_nick");
    }

    /// Join `#room` against a server that answers with exactly `reply`. Bounded,
    /// because never finishing is one of the outcomes under test.
    async fn join_answered_with(reply: &'static [u8]) -> io::Result<Vec<ClientEvent>> {
        let (mut connection, server_io) = duplex_connection(16 * 1024);
        let (_reader, mut writer) = tokio::io::split(server_io);
        writer.write_all(reply).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connection.join_with_latest_history("#room", 0),
        )
        .await
        .expect("the join waited on the peer without a deadline")
    }

    /// A topic or history line in Latin-1 is routine on real networks. It is
    /// read like the steady-state stream reads it, not as a fatal error.
    #[tokio::test]
    async fn a_non_utf8_line_while_joining_is_delivered_not_fatal() {
        let events = join_answered_with(
            b":srv 332 nick #room :caf\xe9\r\n:srv 366 nick #room :End of NAMES\r\n",
        )
        .await
        .expect("a Latin-1 topic does not end the join");
        let messages = messages_of(&events);
        assert_eq!(
            messages[0].params.last().map(String::as_str),
            Some("caf\u{fffd}")
        );
    }

    /// 470 means the server put this client somewhere it did not ask to be.
    /// Waiting for a 366 that names the original channel never ends; treating
    /// the forward's 366 as success silently follows it.
    #[tokio::test]
    async fn a_channel_forward_is_a_loud_refusal_naming_the_forward() {
        let error = join_answered_with(
            b":srv 470 nick #room #overflow :Forwarding to another channel\r\n\
              :nick!u@h JOIN #overflow\r\n:srv 366 nick #overflow :End of NAMES\r\n",
        )
        .await
        .expect_err("a forward is not the channel that was asked for");
        let refusal = JoinRefusal::from_error(&error).expect("a typed join refusal");
        assert_eq!(refusal.channel(), "#room");
        assert_eq!(refusal.forwarded_to(), Some("#overflow"));
        assert!(error.to_string().contains("#overflow"), "{error}");
    }

    #[tokio::test]
    async fn a_join_burst_without_end_is_bounded() {
        let (mut connection, server_io) = duplex_connection(1024 * 1024);
        let (_reader, mut writer) = tokio::io::split(server_io);
        let flood = tokio::spawn(async move {
            for _ in 0..=MAX_JOIN_BURST_LINES {
                if writer
                    .write_all(b":srv NOTICE nick :noise\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
            }
            writer
        });
        let error = must_give_up(connection.join_with_latest_history("#room", 0)).await;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        drop(flood.await);
    }

    async fn assert_history_request(expected_request: &'static str, resume_after_marker: bool) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (mut conn, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server_io);
            let mut lines = tokio::io::BufReader::new(sr).lines();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "CAP REQ :batch draft/chathistory server-time draft/read-marker"
            );
            sw.write_all(
                b":srv CAP nick ACK :batch draft/chathistory server-time draft/read-marker\r\n",
            )
            .await
            .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "JOIN #Room");
            sw.write_all(b":nick!u@h JOIN #Room\r\n").await.unwrap();
            sw.write_all(b":srv MARKREAD #Room timestamp=2026-07-30T12:00:00.000Z\r\n")
                .await
                .unwrap();
            sw.write_all(b":srv 366 nick #Room :End of NAMES\r\n")
                .await
                .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), expected_request);
            sw.write_all(b":srv BATCH +history chathistory #Room\r\n")
                .await
                .unwrap();
            sw.write_all(
                b"@batch=history;time=2026-07-30T12:00:01.000Z :alice!u@h PRIVMSG #Room :unread\r\n",
            )
            .await
            .unwrap();
            sw.write_all(b":srv BATCH -history\r\n").await.unwrap();
        });

        conn.require_capabilities(&[
            "batch",
            "draft/chathistory",
            "server-time",
            "draft/read-marker",
        ])
        .await
        .unwrap();
        let messages = if resume_after_marker {
            conn.join_with_history("#Room", 50).await.unwrap()
        } else {
            conn.join_with_latest_history("#Room", 50).await.unwrap()
        };
        let messages = messages_of(&messages);
        assert!(messages.iter().any(|message| message.command == "MARKREAD"));
        assert!(messages.iter().any(|message| {
            message.command == "PRIVMSG"
                && message.params.get(1).is_some_and(|text| text == "unread")
        }));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn history_bootstrap_resumes_after_the_server_read_marker() {
        assert_history_request(
            "CHATHISTORY AFTER #Room timestamp=2026-07-30T12:00:00.000Z 50",
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn history_inspection_ignores_the_server_read_marker() {
        assert_history_request("CHATHISTORY LATEST #Room * 50", false).await;
    }

    #[tokio::test]
    async fn required_capability_nak_is_not_a_downgrade() {
        use tokio::io::AsyncWriteExt;

        let (mut conn, server_io) = duplex_connection(8192);
        let (_sr, mut sw) = tokio::io::split(server_io);
        sw.write_all(b":srv CAP nick NAK :draft/read-marker\r\n")
            .await
            .unwrap();
        let error = conn
            .require_capabilities(&["draft/read-marker"])
            .await
            .expect_err("NAK must be visible");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
