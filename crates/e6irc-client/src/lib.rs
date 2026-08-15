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
}

impl ConnectionOptions {
    /// Connect, negotiate the selected transport/authentication, and return
    /// only after the server confirms registration.
    pub async fn connect_registered(&self) -> io::Result<Connection> {
        let mut connection = if self.tls {
            let name = match self.tls_server_name.as_deref() {
                Some(name) if !name.trim().is_empty() => name,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS server name cannot be empty",
                    ));
                }
                None => address_host(&self.address)?,
            };
            Connection::connect_tls(&self.address, name, webpki_root_store()).await?
        } else {
            Connection::connect(&self.address).await?
        };
        match &self.authentication {
            Authentication::None => {
                connection.register(&self.nick, &self.realname).await?;
            }
            Authentication::Plain { account, password } => {
                connection
                    .register_sasl(&self.nick, &self.realname, account, password)
                    .await?;
            }
            Authentication::OAuthBearer { token } => {
                connection
                    .register_oauthbearer(&self.nick, &self.realname, token)
                    .await?;
            }
        }
        Ok(connection)
    }
}

/// Extract a TLS validation name from `host:port`, including bracketed IPv6.
/// A bare IPv6 address is not a valid endpoint because its port is ambiguous.
fn address_host(address: &str) -> io::Result<&str> {
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
            command: msg.command.to_string(),
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
        }
    }

    /// Send one line (CRLF appended). This is the sole outbound funnel, so it
    /// neutralizes any embedded CR/LF/NUL before writing — the client-side
    /// analogue of the server's `WireLine` sanitization. Callers build commands
    /// with `format!` from values that may carry untrusted input (a scripted
    /// `PRIVMSG` body, a `--nick`, a channel name); without this, a value like
    /// `"hi\r\nJOIN #evil"` would forge a second command in the authenticated
    /// session. A legitimate single line never contains these bytes, so removing
    /// them is lossless in practice and makes the injection unrepresentable here.
    pub async fn send_line(&mut self, line: &str) -> io::Result<()> {
        if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
            let cleaned: String = line
                .chars()
                .filter(|&c| c != '\r' && c != '\n' && c != '\0')
                .collect();
            self.writer.write_all(cleaned.as_bytes()).await?;
        } else {
            self.writer.write_all(line.as_bytes()).await?;
        }
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

    async fn begin_cap(&mut self) -> io::Result<()> {
        self.send_line("CAP LS 302").await?;
        loop {
            let msg = self.recv("closed during CAP discovery").await?;
            if msg.command == "ERROR" {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "server refused the connection during CAP discovery",
                ));
            }
            if msg.command == "CAP" && msg.params.get(1).map(String::as_str) == Some("LS") {
                if msg.params.get(2).map(String::as_str) != Some("*") {
                    return Ok(());
                }
            } else {
                self.answer_ping(&msg).await?;
            }
        }
    }

    /// Request `sasl` after capability discovery, returning once the server
    /// acknowledges it. The shared prologue of every SASL path.
    async fn negotiate_sasl_cap(&mut self) -> io::Result<()> {
        self.begin_cap().await?;
        self.send_line("CAP REQ :sasl").await?;
        loop {
            let msg = self.recv("closed during CAP").await?;
            match msg.params.get(1).map(String::as_str) {
                Some("ACK") if msg.command == "CAP" => return Ok(()),
                Some("NAK") if msg.command == "CAP" => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server refused SASL",
                    ));
                }
                // A server that refuses via an `ERROR` line (rather than CAP NAK)
                // while holding the socket open would otherwise hang this loop.
                _ if msg.command == "ERROR" => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "server refused the connection during CAP",
                    ));
                }
                // Answer PINGs so a strict server doesn't ping-timeout us mid-CAP.
                _ => {
                    self.answer_ping(&msg).await?;
                }
            }
        }
    }

    /// Ask for each optional metadata capability after discovery. A refusal is
    /// harmless, but its reply must be consumed before registration continues.
    async fn request_metadata_capabilities(&mut self) -> io::Result<()> {
        for capability in METADATA_CAPABILITIES {
            self.send_line(&format!("CAP REQ :{capability}")).await?;
            loop {
                let msg = self.recv("closed during capability negotiation").await?;
                if msg.command == "ERROR" {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "server refused the connection during capability negotiation",
                    ));
                }
                if msg.command == "CAP"
                    && matches!(msg.params.get(1).map(String::as_str), Some("ACK" | "NAK"))
                {
                    break;
                }
                self.answer_ping(&msg).await?;
            }
        }
        Ok(())
    }

    /// Wait for the server's empty `AUTHENTICATE +` challenge after a mechanism
    /// has been offered.
    async fn await_authenticate_challenge(&mut self) -> io::Result<()> {
        loop {
            let msg = self.recv_sasl_message().await?;
            if msg.command == "AUTHENTICATE" {
                return Ok(());
            }
        }
    }

    async fn recv_sasl_message(&mut self) -> io::Result<OwnedMessage> {
        let msg = self.recv("closed during SASL").await?;
        if let Some(err) = self.sasl_terminal_error(&msg).await? {
            return Err(err);
        }
        Ok(msg)
    }

    /// In a SASL wait loop: the terminal errors — a registration-refusal
    /// numeric (a rejected NICK can arrive mid-SASL, before the welcome) or a
    /// SASL failure numeric. `Ok(None)` means keep looping; a PING was
    /// answered on the way.
    async fn sasl_terminal_error(&mut self, msg: &OwnedMessage) -> io::Result<Option<io::Error>> {
        if let Some(err) = registration_refused(msg) {
            return Ok(Some(err));
        }
        if matches!(msg.command.as_str(), "902" | "904" | "905" | "906" | "908") {
            return Ok(Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SASL authentication failed",
            )));
        }
        self.answer_ping(msg).await?;
        Ok(None)
    }

    /// After the credential is sent: wait for the SASL verdict, finish CAP on
    /// success (903), then wait for the welcome (001). The shared epilogue of
    /// every SASL path — waiting for the verdict before `CAP END` so the server
    /// can't complete registration ahead of it and mask a failure.
    async fn finish_sasl_then_welcome(&mut self, nick: &str) -> io::Result<String> {
        loop {
            let msg = self.recv_sasl_message().await?;
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
            if msg.command == "ERROR" {
                return Err(RegistrationRefusal::NotRegistered.error(&msg));
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
        self.negotiate_sasl_cap().await?;
        self.request_metadata_capabilities().await?;
        self.send_line("AUTHENTICATE PLAIN").await?;
        self.await_authenticate_challenge().await?;
        let payload = {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(account.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(password.as_bytes());
            e6irc_proto::base64::encode(&bytes)
        };
        self.register_with_sasl(nick, realname, payload).await
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
    ) -> io::Result<String> {
        self.send_registration_identity(nick, realname).await?;
        self.send_line(&format!("AUTHENTICATE {payload}")).await?;
        self.finish_sasl_then_welcome(nick).await
    }

    /// Register with SASL OAUTHBEARER: authenticate with `token` (an
    /// e6irc API token) during CAP negotiation, then register `nick`.
    pub async fn register_oauthbearer(
        &mut self,
        nick: &str,
        realname: &str,
        token: &str,
    ) -> io::Result<String> {
        self.negotiate_sasl_cap().await?;
        self.request_metadata_capabilities().await?;
        self.send_line("AUTHENTICATE OAUTHBEARER").await?;
        self.await_authenticate_challenge().await?;
        // RFC 7628 client response: gs2 header, then the bearer credential.
        let payload =
            e6irc_proto::base64::encode(format!("n,,\x01auth=Bearer {token}\x01\x01").as_bytes());
        self.register_with_sasl(nick, realname, payload).await
    }

    /// Register with a nick and realname, answering PINGs, until the
    /// welcome (001) arrives. Returns the confirmed nick.
    pub async fn register(&mut self, nick: &str, realname: &str) -> io::Result<String> {
        self.begin_cap().await?;
        self.request_metadata_capabilities().await?;
        self.send_registration_identity(nick, realname).await?;
        self.send_line("CAP END").await?;
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

    /// Offer a replacement nick after the server refused the requested one
    /// (433) during registration. The connection is still pre-registration —
    /// the server holds it open after a 433 — so a fresh NICK is legal here;
    /// the welcome is awaited exactly as in [`Connection::register`].
    pub async fn retry_nick(&mut self, nick: &str) -> io::Result<String> {
        self.send_line(&format!("NICK {nick}")).await?;
        self.await_welcome(nick).await
    }

    /// Require an atomic set of capabilities on an already registered
    /// connection. A server NAK is a visible feature error, never a silent
    /// downgrade.
    pub async fn require_capabilities(&mut self, capabilities: &[&str]) -> io::Result<()> {
        if capabilities.is_empty() {
            return Ok(());
        }
        self.send_line(&format!("CAP REQ :{}", capabilities.join(" ")))
            .await?;
        loop {
            let msg = self.recv("closed during capability negotiation").await?;
            match msg.command.as_str() {
                "CAP" => match msg.params.get(1).map(String::as_str) {
                    Some("ACK") => {
                        let acknowledged = msg.params.last().map(String::as_str).unwrap_or("");
                        let all_acknowledged = capabilities.iter().all(|required| {
                            acknowledged
                                .split_whitespace()
                                .any(|capability| capability == *required)
                        });
                        if all_acknowledged {
                            return Ok(());
                        }
                        return Err(io::Error::other(format!(
                            "server capability ACK omitted a requested capability: {}",
                            capabilities.join(" ")
                        )));
                    }
                    Some("NAK") => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            format!(
                                "server does not support required capabilities: {}",
                                capabilities.join(" ")
                            ),
                        ));
                    }
                    _ => {}
                },
                "410" => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server rejected capability negotiation",
                    ));
                }
                _ => {
                    self.answer_ping(&msg).await?;
                }
            }
        }
    }

    /// Join one channel, wait for confirmation, and load its latest
    /// CHATHISTORY batch. Messages observed during JOIN and playback are
    /// returned in wire order so a UI can build state before its first draw.
    pub async fn join_with_history(
        &mut self,
        target: &str,
        history_count: usize,
    ) -> io::Result<Vec<OwnedMessage>> {
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
    ) -> io::Result<Vec<OwnedMessage>> {
        self.join_history(target, history_count, false).await
    }

    async fn join_history(
        &mut self,
        target: &str,
        history_count: usize,
        resume_after_marker: bool,
    ) -> io::Result<Vec<OwnedMessage>> {
        self.send_line(&format!("JOIN {target}")).await?;
        let mut messages = Vec::new();
        loop {
            let msg = self.recv("closed before JOIN was confirmed").await?;
            if is_join_refusal(&msg.command) {
                let detail = msg.params.last().map(String::as_str).unwrap_or("");
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("cannot join {target}: {detail}"),
                ));
            }
            let joined = msg.command == "366"
                && msg
                    .params
                    .iter()
                    .any(|value| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(value, target));
            self.answer_ping(&msg).await?;
            if msg.command != "PING" {
                messages.push(msg);
            }
            if joined {
                break;
            }
        }
        if history_count == 0 {
            return Ok(messages);
        }

        let read_marker = if resume_after_marker {
            messages.iter().rev().find_map(|message| {
                (message.command == "MARKREAD"
                    && message.params.first().is_some_and(|candidate| {
                        e6irc_proto::casemap::CaseMapping::Rfc1459.eq(candidate, target)
                    }))
                .then(|| message.params.get(1))
                .flatten()
                .and_then(|marker| marker.strip_prefix("timestamp="))
                .and_then(e6irc_proto::time::parse_server_time_millis)
                .map(e6irc_proto::time::server_time)
            })
        } else {
            None
        };
        let request = match read_marker {
            Some(marker) => {
                format!("CHATHISTORY AFTER {target} timestamp={marker} {history_count}")
            }
            None => format!("CHATHISTORY LATEST {target} * {history_count}"),
        };
        self.send_line(&request).await?;
        let mut history_batch = None;
        loop {
            let msg = self.recv("closed during CHATHISTORY playback").await?;
            self.answer_ping(&msg).await?;
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
            if msg.command != "PING" {
                messages.push(msg);
            }
        }
        Ok(messages)
    }
}

/// The JOIN-refusal numerics (the set a client waits on to know a JOIN was
/// rejected) — shared by the client crate's own drain loops and the CLI,
/// which must fail on the same conditions rather than wait for a 366 that
/// never comes.
pub fn is_join_refusal(command: &str) -> bool {
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
}

#[derive(Debug)]
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
        error
            .get_ref()?
            .downcast_ref::<RegistrationRefusalError>()
            .map(|error| error.refusal)
    }

    fn error(self, message: &OwnedMessage) -> io::Error {
        let kind = match self {
            Self::NicknameInUse => io::ErrorKind::AlreadyExists,
            Self::InvalidNickname => io::ErrorKind::InvalidInput,
            Self::InvalidUsername => io::ErrorKind::InvalidInput,
            Self::ServerPasswordRejected => io::ErrorKind::PermissionDenied,
            Self::NetworkBanned => io::ErrorKind::ConnectionAborted,
            Self::NotRegistered => io::ErrorKind::Other,
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

fn registration_refused(message: &OwnedMessage) -> Option<io::Error> {
    let refusal = match message.command.as_str() {
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
    let detail = message
        .params
        .last()
        .map(String::as_str)
        .unwrap_or("no detail");
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
        }
    }

    #[test]
    fn registration_username_fits_the_portable_limit() {
        assert_eq!(registration_username("alice_updated"), "alice_upda");
        assert_eq!(registration_username("short"), "short");
        assert_eq!(registration_username("ééééééééééx"), "ééééé");
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
        assert_eq!(address_host("irc.example:6697").unwrap(), "irc.example");
        assert_eq!(address_host("127.0.0.1:6697").unwrap(), "127.0.0.1");
        assert_eq!(address_host("[2001:db8::1]:6697").unwrap(), "2001:db8::1");
        assert!(address_host("2001:db8::1:6697").is_err());
        assert!(address_host("missing-port").is_err());
        assert!(address_host("[2001:db8::1]").is_err());
    }

    #[tokio::test]
    async fn register_sasl_fails_loudly_on_reject_numeric() {
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        // A server that ACKs sasl, then answers the AUTHENTICATE with a 904
        // failure numeric and holds the socket open. Without the terminal-numeric
        // handling in `await_authenticate_challenge`, this loops forever; with it,
        // register_sasl returns an error promptly.
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));

        let server = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server_io);
            let mut lines = tokio::io::BufReader::new(sr).lines();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP LS 302");
            sw.write_all(b":srv CAP * LS :sasl server-time message-tags account-tag\r\n")
                .await
                .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP REQ :sasl");
            sw.write_all(b":srv CAP * ACK :sasl\r\n").await.unwrap();
            for capability in METADATA_CAPABILITIES {
                assert_eq!(
                    lines.next_line().await.unwrap().unwrap(),
                    format!("CAP REQ :{capability}")
                );
                sw.write_all(format!(":srv CAP * ACK :{capability}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "AUTHENTICATE PLAIN"
            );
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
    async fn register_fails_loudly_on_error_before_welcome() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));
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
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        drop(conn);
        server.await.expect("mock server task");
    }

    #[tokio::test]
    async fn oauth_registration_requests_the_same_metadata_as_other_modes() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let mut connection = Connection::from_halves(Box::new(cr), Box::new(cw));
        let server = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server_io);
            let mut lines = tokio::io::BufReader::new(sr).lines();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP LS 302");
            sw.write_all(b":srv CAP * LS :sasl server-time message-tags account-tag\r\n")
                .await
                .unwrap();
            assert_eq!(lines.next_line().await.unwrap().unwrap(), "CAP REQ :sasl");
            sw.write_all(b":srv CAP * ACK :sasl\r\n").await.unwrap();
            for capability in METADATA_CAPABILITIES {
                assert_eq!(
                    lines.next_line().await.unwrap().unwrap(),
                    format!("CAP REQ :{capability}")
                );
                sw.write_all(format!(":srv CAP * ACK :{capability}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "AUTHENTICATE OAUTHBEARER"
            );
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
    async fn send_line_neutralizes_injected_crlf_and_nul() {
        use tokio::io::AsyncReadExt;
        // A value carrying embedded CR/LF/NUL — the classic command-injection
        // payload — must be flattened to a single wire frame, never split into a
        // second forged command in the authenticated session.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));

        conn.send_line("PRIVMSG #c :hi\r\nJOIN #evil\0tail")
            .await
            .unwrap();
        drop(conn); // flush + close so the server read sees EOF

        let (mut sr, _sw) = tokio::io::split(server_io);
        let mut got = Vec::new();
        sr.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8(got).unwrap();

        // Exactly one CRLF (the appended terminator), and no interior control
        // bytes survived — the injected JOIN is now inert text on the one line.
        assert_eq!(got, "PRIVMSG #c :hiJOIN #eviltail\r\n");
        assert_eq!(got.matches("\r\n").count(), 1);
        assert!(!got[..got.len() - 2].contains(['\r', '\n', '\0']));
    }

    #[tokio::test]
    async fn next_event_lossy_survives_non_utf8_line_and_surfaces_rejections() {
        use tokio::io::AsyncWriteExt;
        // A Latin-1 body (0xE9 = 'é') any channel member can post is not valid
        // UTF-8. Strict `next_message` errors on it (the handshake wants that);
        // the interactive steady-state read must lossily decode and keep going.
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));

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

    async fn assert_history_request(expected_request: &'static str, resume_after_marker: bool) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));
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

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));
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
