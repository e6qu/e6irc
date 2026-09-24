//! Client-side connection library shared by e6irc-cli and e6irc-tui.
//!
//! An async wrapper over plaintext or public-CA TLS sockets that frames IRC
//! lines with `e6irc-proto` and drives anonymous, SASL PLAIN, or SASL
//! OAUTHBEARER registration. [`ConnectionOptions`] is the single owned request
//! used by both native clients, including reconnects.

#![deny(clippy::let_underscore_must_use)]

pub mod credentials;
pub mod liveness;
mod scram;
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
/// is constructible only via [`TerminalSafe::from_untrusted`] (or
/// [`TerminalSafe::from_irc_text`], which first removes IRC formatting codes),
/// which replaces each control character — and each invisible Unicode format
/// character that reorders or hides text — with a visible `U+FFFD`; a field or display path typed
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
                .map(|c| {
                    if c.is_control() || is_invisible_formatting(c) {
                        '\u{FFFD}'
                    } else {
                        c
                    }
                })
                .collect(),
        )
    }

    /// Message text for a person to read: the mIRC formatting codes (bold,
    /// colour, italics, …) are removed first, because a terminal client that
    /// does not render them would otherwise show each as a replacement
    /// character, then the rest is neutralised as by
    /// [`TerminalSafe::from_untrusted`].
    pub fn from_irc_text(s: &str) -> Self {
        Self::from_untrusted(&strip_formatting(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `text` without mIRC formatting codes: bold (`^B`), colour (`^C` with up to
/// two digits of foreground and an optional comma and two digits of
/// background), hex colour (`^D` with six hex digits and an optional comma and
/// six more), reset (`^O`), monospace (`^Q`), reverse (`^V`), italics (`^]`),
/// strikethrough (`^^`) and underline (`^_`). A colour code's digits belong to
/// the code, so `^C4hello` is `hello`; a comma not followed by a colour is
/// text and stays.
pub fn strip_formatting(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    // Consume up to `limit` characters that satisfy `accept`.
    fn take(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        limit: usize,
        accept: fn(&char) -> bool,
    ) -> usize {
        let mut taken = 0;
        while taken < limit && chars.next_if(accept).is_some() {
            taken += 1;
        }
        taken
    }
    while let Some(c) = chars.next() {
        match c {
            '\x02' | '\x0f' | '\x11' | '\x16' | '\x1d' | '\x1e' | '\x1f' => {}
            '\x03' | '\x04' => {
                let (limit, accept): (usize, fn(&char) -> bool) = if c == '\x03' {
                    (2, char::is_ascii_digit)
                } else {
                    (6, char::is_ascii_hexdigit)
                };
                if take(&mut chars, limit, accept) > 0 {
                    // A background only when a comma is followed by a colour.
                    let mut lookahead = chars.clone();
                    if lookahead.next() == Some(',') && lookahead.peek().is_some_and(accept) {
                        chars.next();
                        take(&mut chars, limit, accept);
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether `message` is a server's refusal of something this client asked
/// for: an error reply (a three-digit numeric from 400 to 599) or an IRCv3
/// `FAIL`. The one predicate every native client uses to decide that a line
/// it sent did not do what it asked — a delivery, a join, a raw command.
pub fn is_refusal(message: &OwnedMessage) -> bool {
    message.command == "FAIL" || is_error_numeric(&message.command)
}

/// Whether `command` is an IRC error reply (400–599).
fn is_error_numeric(command: &str) -> bool {
    command.len() == 3
        && command.bytes().all(|byte| byte.is_ascii_digit())
        && command
            .parse::<u16>()
            .is_ok_and(|numeric| (400..600).contains(&numeric))
}

/// The Unicode format characters that change what a terminal *shows* without
/// being control bytes: the Arabic letter mark, the zero-width space, joiners
/// and direction marks (U+200B–200F), the bidirectional embeddings and
/// overrides (U+202A–202E), the word joiner, invisible operators and isolates
/// (U+2060–2069), and the byte-order mark used as a zero-width no-break space.
/// A right-to-left override in a nickname or message can make the rest of a
/// line read backwards, and a zero-width character can hide text or make two
/// names look identical, so each is neutralised like a control byte.
fn is_invisible_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
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
    /// Whether this connection sent a `PASS`, which decides what a `464`
    /// means.
    server_password_sent: ServerPasswordSent,
    /// The SASL mechanism the server's 903 confirmed, once it has.
    authenticated_with: Option<String>,
    /// Mechanisms the server refused before any credential, and what was
    /// offered instead.
    sasl_notes: Vec<String>,
    /// Whether a credential may be written to this connection, decided by how
    /// it was built ([`Transport`]).
    transport: Transport,
    /// Capabilities to ask for during registration when the server offers
    /// them, each in a request of its own ([`Connection::request_when_offered`]).
    requested_when_offered: Vec<&'static str>,
    /// Those of `requested_when_offered` the server acknowledged.
    enabled_when_offered: Vec<&'static str>,
}

/// Whether what is written to a connection can be read on the path — decided
/// by how the connection was built, never by a flag a caller passes. A
/// credential (a SASL password, a bearer token, a server password) is written
/// only to a [`Transport::Tls`] or [`Transport::Loopback`] connection, or to a
/// cleartext one whose user explicitly consented
/// ([`Connection::consent_to_cleartext_credentials`]). No other value can be
/// constructed outside this crate, so no caller — the bouncer's driver
/// included — can send one in cleartext to another machine by forgetting to
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// TLS, the server's certificate verified.
    Tls,
    /// Plaintext to a peer whose address is loopback: the bytes never leave
    /// this machine.
    Loopback,
    /// Plaintext to another machine.
    Cleartext,
    /// Plaintext to another machine, and the user said to send credentials
    /// anyway.
    CleartextConsented,
}

impl Transport {
    /// A plaintext connection's transport, from the address it is connected
    /// to — the address actually dialled, so a resolver cannot change it.
    fn of_plaintext_peer(peer: std::net::SocketAddr) -> Self {
        if peer.ip().to_canonical().is_loopback() {
            Self::Loopback
        } else {
            Self::Cleartext
        }
    }

    /// Refuse `credential` on a transport that could be overheard.
    fn admit(self, credential: &str) -> io::Result<()> {
        match self {
            Self::Tls | Self::Loopback | Self::CleartextConsented => Ok(()),
            Self::Cleartext => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to send {credential} in cleartext to a server that is not this \
                     machine; connect with TLS"
                ),
            )),
        }
    }
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

    /// `Err` with the offered list when a known mechanism list names none of
    /// `acceptable`.
    fn sasl_mechanism_offered(&self, acceptable: &[&str]) -> Result<(), SaslRejection> {
        match self.sasl_mechanisms() {
            Some(offered)
                if !offered
                    .split(',')
                    .any(|candidate| acceptable.contains(&candidate)) =>
            {
                let requested = match acceptable {
                    [one] => (*one).to_owned(),
                    several => format!("one of {}", several.join(", ")),
                };
                Err(SaslRejection::new(
                    SaslFailure::MechanismNotOffered,
                    &format!("requested {requested}; the server offers {offered}"),
                ))
            }
            _ => Ok(()),
        }
    }

    /// The strongest password mechanism the server offers. A server that names
    /// no mechanisms (a pre-3.2 bare `sasl`) gets PLAIN, the one every SASL
    /// server implements: guessing a stronger one would read its 904 as the
    /// credentials being wrong.
    fn password_mechanism(&self) -> PasswordMechanism {
        match self.sasl_mechanisms() {
            Some(offered) => PasswordMechanism::STRONGEST_FIRST
                .into_iter()
                .find(|mechanism| offered.split(',').any(|name| name == mechanism.name()))
                .unwrap_or(PasswordMechanism::Plain),
            None => PasswordMechanism::Plain,
        }
    }
}

/// A SASL mechanism that authenticates with an account and password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordMechanism {
    Scram(scram::ScramHash),
    Plain,
}

impl PasswordMechanism {
    const STRONGEST_FIRST: [Self; 3] = [
        Self::Scram(scram::ScramHash::Sha512),
        Self::Scram(scram::ScramHash::Sha256),
        Self::Plain,
    ];
    const NAMES: [&'static str; 3] = ["SCRAM-SHA-512", "SCRAM-SHA-256", "PLAIN"];

    const fn name(self) -> &'static str {
        match self {
            Self::Scram(hash) => hash.mechanism(),
            Self::Plain => "PLAIN",
        }
    }
}

/// Whether the server took part in capability negotiation at all. A server
/// that answers `CAP` with 421 or 451 has no negotiation to end, so `CAP END`
/// must not be sent to it. One that answers nothing within
/// [`CAP_DISCOVERY_DEADLINE`] is not known either way: it may be ignoring an
/// unknown command, or holding registration open for a `CAP END` it will
/// answer late, so registration proceeds and still ends the negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityNegotiation {
    Open,
    Unsupported,
    Unanswered,
}

/// How long the server has to say anything about `CAP LS`. A server without
/// capability negotiation may drop the command on the floor rather than answer
/// 421; without a bound the registration would hang until its own timeout and
/// then be misread as a lost connection. Many servers read nothing a client
/// sends until their ident and DNS checks end: Libera answered after 6.9 s
/// from a host whose firewall drops ident, past the 5 s this used to be, so a
/// SASL network there could never connect. Within the bouncer's 30 s
/// registration budget, with room left for SASL and the welcome.
const CAP_DISCOVERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a registration whose write found the server gone reads what the
/// server sent before leaving. Everything it sent is already buffered or in
/// flight on a closed connection, so this bounds only a peer that half-closed.
const PEER_GONE_READ: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the server has to acknowledge an abandoned SASL mechanism before
/// the next one is offered.
const SASL_ABORT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

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

/// An interactive client acts on a line's syntax, so a line that relays but
/// does not parse is a rejection for it.
impl From<RelayEvent> for ClientEvent {
    fn from(event: RelayEvent) -> Self {
        match event {
            RelayEvent::Line {
                message: Some(message),
                ..
            } => Self::Message(message),
            RelayEvent::Line { message: None, .. } => Self::Rejected(RejectedLine::Unparseable),
            RelayEvent::Rejected(rejected) => Self::Rejected(rejected),
        }
    }
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
    /// The user name (ident) sent in `USER`. Stated, never derived: a legal
    /// nickname (`_bot`) is not a legal user name, and servers answer a bad one
    /// by closing the link.
    pub username: String,
    pub realname: String,
    pub authentication: Authentication,
    /// How long the server may take to finish registration, and afterwards to
    /// answer each request this library waits on (a capability request, a
    /// JOIN with its history). Required: a peer that holds the socket open
    /// while saying nothing relevant would otherwise hang a scripted client
    /// forever, and only the caller knows how long its user will wait.
    pub response_deadline: std::time::Duration,
    /// Whether SASL credentials, or a server password, may cross a plaintext
    /// connection to a server that is not this machine. Required, so that
    /// sending a password in the clear is something a caller's user asked
    /// for, never a default.
    pub cleartext_credentials: CleartextCredentials,
    /// The network's connection password, sent as `PASS` before anything
    /// else. Distinct from SASL: it identifies the connection to a private
    /// server, not the user to an account.
    pub server_password: Option<ServerPassword>,
}

/// A network's connection password: the argument of the `PASS` a server that
/// requires one wants before `CAP LS`, `NICK` and `USER`, and answers with
/// `464` when it is wrong or missing.
///
/// Built only by [`ServerPassword::parse`], so a value that exists fits the
/// one line it travels on and cannot forge a second command inside it. Its
/// `Debug` form is redacted: an [`Identity`] or [`ConnectionOptions`] printed
/// into a log must not print the password with it.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerPassword(String);

/// Why a value cannot be a [`ServerPassword`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPasswordError {
    Empty,
    /// Longer than [`ServerPassword::MAX_LEN`] bytes.
    TooLong,
    /// Contains CR, LF or NUL: the bytes that end or corrupt an IRC line.
    Delimiter,
}

impl std::fmt::Display for ServerPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("a server password cannot be empty"),
            Self::TooLong => write!(
                f,
                "a server password cannot exceed {} bytes",
                ServerPassword::MAX_LEN
            ),
            Self::Delimiter => {
                f.write_str("a server password cannot contain a line break or a NUL byte")
            }
        }
    }
}

impl std::error::Error for ServerPasswordError {}

impl From<ServerPasswordError> for io::Error {
    fn from(error: ServerPasswordError) -> Self {
        Self::new(io::ErrorKind::InvalidInput, error)
    }
}

impl ServerPassword {
    /// The command and the trailing-parameter marker that share the password's
    /// line. The trailing form is used so a password with spaces stays whole.
    const LINE_PREFIX: &'static str = "PASS :";

    /// The longest password that fits one traditional IRC line with its
    /// command and CRLF: the wire budget, not a number chosen here.
    pub const MAX_LEN: usize = e6irc_proto::message::MAX_LINE_LEN - 2 - Self::LINE_PREFIX.len();

    pub fn parse(password: String) -> Result<Self, ServerPasswordError> {
        if password.is_empty() {
            return Err(ServerPasswordError::Empty);
        }
        if password.len() > Self::MAX_LEN {
            return Err(ServerPasswordError::TooLong);
        }
        if password
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
        {
            return Err(ServerPasswordError::Delimiter);
        }
        Ok(Self(password))
    }

    /// The password itself, for the one place that must store it (sealed) or
    /// send it. Never for a log line.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn line(&self) -> String {
        format!("{}{}", Self::LINE_PREFIX, self.0)
    }
}

impl std::fmt::Debug for ServerPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerPassword(<redacted>)")
    }
}

/// Whether a `PASS` went before registration. A `464` means two different
/// things depending on it — the network wants a password this connection has
/// none of, or it rejected the one sent — and only the client that did or did
/// not send one can tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPasswordSent {
    No,
    Yes,
}

/// See [`ConnectionOptions::cleartext_credentials`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleartextCredentials {
    Refuse,
    Allow,
}

/// Who a connection registers as. Named fields, because three adjacent strings
/// in a call are one transposition away from a real name sent as the user name.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub nick: &'a str,
    /// The `USER` name (ident). Stated by the caller; see
    /// [`ConnectionOptions::username`].
    pub username: &'a str,
    pub realname: &'a str,
    /// The network's connection password, sent as the first line. See
    /// [`ConnectionOptions::server_password`].
    pub server_password: Option<&'a ServerPassword>,
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
            self.connect_and_register(system_resolve),
        )
        .await
    }

    /// As [`ConnectionOptions::connect_registered`], with `resolve` turning
    /// `host:port` into addresses wherever this connection must decide by
    /// address — injectable so a test can stand in for DNS.
    async fn connect_and_register<Resolved>(
        &self,
        resolve: impl FnOnce(String) -> Resolved,
    ) -> io::Result<Registered>
    where
        Resolved: Future<Output = io::Result<Vec<std::net::SocketAddr>>>,
    {
        // SASL PLAIN is the password in base64 and OAUTHBEARER is the token
        // itself, so without TLS both are readable by everything on the path.
        // Decided before dialing: nothing leaves the machine first.
        // A server password travels as itself in `PASS`.
        let credentials = match (&self.authentication, &self.server_password) {
            (Authentication::None, None) => None,
            (Authentication::None, Some(_)) => Some("a server password"),
            (_, None) => Some("SASL credentials"),
            (_, Some(_)) => Some("SASL credentials and a server password"),
        };
        let plaintext_to = match credentials {
            Some(credentials)
                if !self.tls && self.cleartext_credentials == CleartextCredentials::Refuse =>
            {
                // "This machine" is decided by address, never by name: a name
                // under `.localhost` is whatever a resolver says it is. Every
                // address the name resolves to must be loopback, and exactly
                // those addresses are dialed, so nothing can re-resolve it to
                // somewhere else between the decision and the connection.
                match loopback_only(&self.address, resolve).await? {
                    Some(addresses) => Some(addresses),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "refusing to send {credentials} in cleartext to a server that \
                                 is not this machine; connect with --tls, or pass \
                                 --allow-cleartext-credentials to send them unprotected"
                            ),
                        ));
                    }
                }
            }
            _ => None,
        };
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
        } else if let Some(addresses) = plaintext_to {
            Connection::from_tcp(connect_first(&addresses).await?)?
        } else {
            Connection::connect(&self.address).await?
        };
        if self.cleartext_credentials == CleartextCredentials::Allow {
            connection.consent_to_cleartext_credentials();
        }
        let identity = Identity {
            nick: &self.nick,
            username: &self.username,
            realname: &self.realname,
            server_password: self.server_password.as_ref(),
        };
        let nick = match &self.authentication {
            Authentication::None => connection.register(&identity).await?,
            Authentication::Plain { account, password } => {
                connection
                    .register_sasl(&identity, account, password)
                    .await?
            }
            Authentication::OAuthBearer { token } => {
                connection.register_oauthbearer(&identity, token).await?
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

/// The addresses `address` (`host:port`) resolves to when every one of them is
/// loopback, else `None`: the one rule for "a plaintext connection that cannot
/// be overheard". The caller dials (or pins its HTTP client to) exactly these
/// addresses, so the name cannot be resolved again, differently, afterwards.
pub async fn loopback_addresses(address: &str) -> io::Result<Option<Vec<std::net::SocketAddr>>> {
    loopback_only(address, system_resolve).await
}

async fn loopback_only<Resolved>(
    address: &str,
    resolve: impl FnOnce(String) -> Resolved,
) -> io::Result<Option<Vec<std::net::SocketAddr>>>
where
    Resolved: Future<Output = io::Result<Vec<std::net::SocketAddr>>>,
{
    let resolved = resolve(address.to_owned()).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot resolve {address} to decide whether it is this machine: {error}"),
        )
    })?;
    let loopback = !resolved.is_empty()
        && resolved
            .iter()
            .all(|resolved| resolved.ip().to_canonical().is_loopback());
    Ok(loopback.then_some(resolved))
}

async fn system_resolve(address: String) -> io::Result<Vec<std::net::SocketAddr>> {
    Ok(tokio::net::lookup_host(address).await?.collect())
}

/// Connect to the first of `addresses` that accepts, in order; the error of
/// the last one when none does.
async fn connect_first(addresses: &[std::net::SocketAddr]) -> io::Result<TcpStream> {
    let mut last_error = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// Whether `word` is a `USER` name every server accepts: 1–10 bytes, an ASCII
/// letter or digit first, then ASCII letters, digits, `_` and `-`. A server
/// answers a user name it dislikes by closing the link rather than with a
/// numeric, so the portable grammar is the strict one. e6ircd's
/// `UpstreamUsername` is the same grammar with reasons, and is tested against
/// this predicate.
pub fn is_portable_username(word: &str) -> bool {
    let mut bytes = word.bytes();
    word.len() <= 10
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// The `USER` name of a native client: the one stated, else the nickname —
/// the one default both clients document — and that only when the nickname is
/// itself a portable user name. A nickname that is not (`_bot`, `ada|away`,
/// anything past ten bytes) is never shortened or rewritten into one; the
/// caller is told to state a user name instead.
pub fn stated_or_nick_username(stated: Option<&str>, nick: &str) -> io::Result<String> {
    match stated {
        Some(username) => Ok(username.to_owned()),
        None if is_portable_username(nick) => Ok(nick.to_owned()),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the nickname {nick} cannot double as the IRC user name (ASCII letters, digits, \
                 '_' and '-', starting with a letter or digit, at most 10 bytes); pass --username"
            ),
        )),
    }
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
        let transport = Transport::of_plaintext_peer(stream.peer_addr()?);
        let (reader, writer) = stream.into_split();
        Ok(Self::from_halves(
            Box::new(reader),
            Box::new(writer),
            transport,
        ))
    }

    /// Let credentials cross this plaintext connection to another machine:
    /// the user's explicit override (`--allow-cleartext-credentials`), and
    /// nothing else. No effect on a connection that already may carry them.
    pub fn consent_to_cleartext_credentials(&mut self) {
        if self.transport == Transport::Cleartext {
            self.transport = Transport::CleartextConsented;
        }
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
        Ok(Self::from_halves(
            Box::new(reader),
            Box::new(writer),
            Transport::Tls,
        ))
    }

    fn from_halves(reader: BoxRead, writer: BoxWrite, transport: Transport) -> Self {
        Self {
            transport,
            requested_when_offered: Vec::new(),
            enabled_when_offered: Vec::new(),
            reader,
            writer,
            framing: LineBuffer::new(e6irc_proto::message::MAX_SERVER_FRAME_LEN),
            pending: std::collections::VecDeque::new(),
            read_buf: vec![0u8; 8192],
            response_deadline: None,
            advertised: AdvertisedCapabilities::default(),
            server_password_sent: ServerPasswordSent::No,
            authenticated_with: None,
            sasl_notes: Vec::new(),
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
        Ok(self.next_line_relayable().await?.map(ClientEvent::from))
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
    /// negotiation answers `CAP` with 421 (unknown command) or 451 (a command
    /// it does not accept before registration) and advertises nothing; one
    /// that says nothing within [`CAP_DISCOVERY_DEADLINE`] is treated the same
    /// way. Whether that is acceptable is the caller's decision, because only
    /// the caller knows whether authentication was required.
    async fn begin_cap(&mut self) -> io::Result<CapabilityNegotiation> {
        self.send_line("CAP LS 302").await?;
        let first_reply_by = tokio::time::Instant::now() + CAP_DISCOVERY_DEADLINE;
        // The bound covers the wait for the first `CAP LS` reply only; the
        // continuation lines of a multi-line list follow at the server's pace.
        let mut listing_begun = false;
        loop {
            let msg = if listing_begun {
                self.recv("closed during CAP discovery").await?
            } else {
                match tokio::time::timeout_at(
                    first_reply_by,
                    self.recv("closed during CAP discovery"),
                )
                .await
                {
                    Ok(msg) => msg?,
                    Err(_) => return Ok(CapabilityNegotiation::Unanswered),
                }
            };
            if let Some(err) = self.registration_refused(&msg) {
                return Err(err);
            }
            // A 451 that names `PASS` answers the server password, not `CAP LS`:
            // negotiation is still open, and its answer is still to come.
            if msg.command == "451"
                && self.server_password_sent == ServerPasswordSent::Yes
                && msg
                    .params
                    .iter()
                    .any(|parameter| parameter.eq_ignore_ascii_case("PASS"))
            {
                continue;
            }
            // 421 names the command it did not know; 451 does not reliably
            // (`451 * :You have not registered`), and nothing but `CAP LS` (and
            // perhaps `PASS`, handled above) has been sent, so any other 451
            // here is the answer to it.
            if msg.command == "451"
                || (msg.command == "421"
                    && msg
                        .params
                        .get(1)
                        .is_some_and(|command| command.eq_ignore_ascii_case("CAP")))
            {
                return Ok(CapabilityNegotiation::Unsupported);
            }
            if msg.command == "CAP" && msg.params.get(1).map(String::as_str) == Some("LS") {
                listing_begun = true;
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
    async fn negotiate_sasl_cap(&mut self, acceptable: &[&str]) -> io::Result<()> {
        let unavailable = |diagnostic: &str| {
            Err(SaslRejection::new(SaslFailure::CapabilityNotOffered, diagnostic).into_error())
        };
        match self.begin_cap().await? {
            CapabilityNegotiation::Open => {}
            CapabilityNegotiation::Unsupported => {
                return unavailable("the server does not support capability negotiation");
            }
            // Silence is not a "no": the server may still be checking this
            // connection. It is a timeout, retried as one, never reported as
            // the server lacking SASL.
            CapabilityNegotiation::Unanswered => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "the server did not answer capability negotiation within {} s",
                        CAP_DISCOVERY_DEADLINE.as_secs()
                    ),
                ));
            }
        }
        if !self.advertised.offers("sasl") {
            return unavailable("the server does not advertise the sasl capability");
        }
        self.advertised
            .sasl_mechanism_offered(acceptable)
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
        if !wanted.is_empty() {
            match self.request_capabilities(&wanted).await? {
                CapabilityVerdict::Acknowledged | CapabilityVerdict::Refused(_) => {}
            }
        }
        // Each in a request of its own: a server that refuses one must not
        // take the others, or the metadata above, down with it.
        let optional: Vec<&'static str> = self
            .requested_when_offered
            .iter()
            .copied()
            .filter(|capability| self.advertised.offers(capability))
            .collect();
        for capability in optional {
            if self.request_capabilities(&[capability]).await? == CapabilityVerdict::Acknowledged {
                self.enabled_when_offered.push(capability);
            }
        }
        Ok(())
    }

    /// Ask for `capability` during registration when the server offers it,
    /// in a request of its own (a refusal costs only that capability).
    /// [`Connection::enabled`] says afterwards whether it was acknowledged.
    pub fn request_when_offered(&mut self, capability: &'static str) {
        if !self.requested_when_offered.contains(&capability) {
            self.requested_when_offered.push(capability);
        }
    }

    /// Whether a capability asked for with [`Connection::request_when_offered`]
    /// was acknowledged during registration.
    pub fn enabled(&self, capability: &str) -> bool {
        self.enabled_when_offered.contains(&capability)
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
            if let Some(err) = self.registration_refused(&msg) {
                return Err(err);
            }
            if let Some(verdict) = capability_verdict(&msg, capabilities)? {
                return Ok(verdict);
            }
            self.answer_ping(&msg).await?;
        }
    }

    /// Wait for the server's empty `AUTHENTICATE +` challenge after a mechanism
    /// has been offered: every mechanism this client speaks is client-first.
    async fn await_authenticate_challenge(&mut self, mechanism: &str) -> io::Result<()> {
        if self.read_sasl_challenge(mechanism).await?.is_empty() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server sent an unexpected SASL challenge",
        ))
    }

    /// One server challenge, reassembled and decoded: `AUTHENTICATE` lines of
    /// 400 characters continue, a shorter one ends it, and `+` alone is empty
    /// (or ends a challenge whose length was a multiple of 400).
    async fn read_sasl_challenge(&mut self, mechanism: &str) -> io::Result<Vec<u8>> {
        use e6irc_proto::sasl::{MAX_AUTHENTICATE_CHUNK_LEN, MAX_AUTHENTICATE_PAYLOAD_LEN};

        let mut encoded = String::new();
        loop {
            let msg = self.recv_sasl_message(mechanism).await?;
            if msg.command != "AUTHENTICATE" {
                continue;
            }
            let chunk = msg.params.first().map(String::as_str).unwrap_or("");
            if chunk == "+" {
                break;
            }
            encoded.push_str(chunk);
            if encoded.len() > MAX_AUTHENTICATE_PAYLOAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the server's SASL challenge exceeds the supported length",
                ));
            }
            if chunk.len() < MAX_AUTHENTICATE_CHUNK_LEN {
                break;
            }
        }
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        e6irc_proto::base64::decode(&encoded).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the server's SASL challenge is not base64",
            )
        })
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
        if let Some(err) = self.registration_refused(msg) {
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
                if let Err(not_offered) = self.advertised.sasl_mechanism_offered(&[mechanism]) {
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
                self.authenticated_with = Some(mechanism.to_owned());
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
            if let Some(err) = self.registration_refused(&msg) {
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

    /// Register with SASL as `account`/`password`, during CAP negotiation,
    /// then register `nick`. The mechanism is the strongest the server offers
    /// for a password (SCRAM-SHA-512, then SCRAM-SHA-256, then PLAIN);
    /// [`Connection::sasl_mechanism`] says afterwards which one it was. A
    /// failed SCRAM is never retried as PLAIN: that would be a downgrade.
    pub async fn register_sasl(
        &mut self,
        identity: &Identity<'_>,
        account: &str,
        password: &str,
    ) -> io::Result<String> {
        let outcome = self.register_sasl_steps(identity, account, password).await;
        self.told_before_it_left(outcome).await
    }

    async fn register_sasl_steps(
        &mut self,
        identity: &Identity<'_>,
        account: &str,
        password: &str,
    ) -> io::Result<String> {
        self.transport.admit("SASL credentials")?;
        self.send_server_password(identity).await?;
        self.negotiate_sasl_cap(&PasswordMechanism::NAMES).await?;
        self.request_metadata_capabilities().await?;
        let list_was_named = self.advertised.sasl_mechanisms().is_some();
        let mut mechanism = self.advertised.password_mechanism();
        if let Err(error) = self.offer_mechanism(mechanism.name()).await {
            // A server that named no mechanisms was offered PLAIN; its 908 names
            // them now. When one is stronger and this client speaks it, offer
            // that one, once, on the same connection (IRCv3 allows a new
            // AUTHENTICATE after 904).
            let learned = self.advertised.password_mechanism();
            let not_offered = SaslRejection::from_error(&error)
                .is_some_and(|rejection| rejection.failure() == SaslFailure::MechanismNotOffered);
            if list_was_named || !not_offered || learned == mechanism {
                return Err(error);
            }
            mechanism = learned;
            self.offer_mechanism(mechanism.name()).await?;
        }
        self.send_registration_identity(identity).await?;
        // A network may advertise a mechanism it cannot use for this account:
        // Libera answers SCRAM's first message with `e=other-error` when the
        // account's stored password predates SCRAM. That refusal arrives before
        // any credential is sent, so the next mechanism is offered on the same
        // connection — loudly (`sasl_notes`), and never after a verdict on the
        // password itself.
        let mut weaker = PasswordMechanism::STRONGEST_FIRST
            .into_iter()
            .skip_while(|candidate| *candidate != mechanism)
            .skip(1)
            .filter(|candidate| {
                self.advertised
                    .sasl_mechanism_offered(&[candidate.name()])
                    .is_ok()
            })
            .collect::<Vec<_>>()
            .into_iter();
        loop {
            let name = mechanism.name();
            let refused = match mechanism {
                PasswordMechanism::Plain => {
                    let mut bytes = vec![0u8];
                    bytes.extend_from_slice(account.as_bytes());
                    bytes.push(0);
                    bytes.extend_from_slice(password.as_bytes());
                    self.send_sasl_payload(&e6irc_proto::base64::encode(&bytes))
                        .await?;
                    None
                }
                PasswordMechanism::Scram(hash) => {
                    self.scram_exchange(hash, account, password).await?
                }
            };
            let Some(reason) = refused else {
                return self.finish_sasl_then_welcome(identity.nick, name).await;
            };
            let Some(next) = weaker.next() else {
                return Err(SaslRejection::new(
                    SaslFailure::Protocol,
                    &format!("{name}: {reason}; no other mechanism this client speaks is offered"),
                )
                .into_error());
            };
            self.sasl_notes.push(format!(
                "{name} was refused before any credential was sent ({reason}); offering {}",
                next.name()
            ));
            self.abort_sasl().await?;
            mechanism = next;
            self.offer_mechanism(mechanism.name()).await?;
        }
    }

    /// Abandon the mechanism in progress and consume the server's verdict on
    /// it, so the next `AUTHENTICATE` starts from a settled exchange. The 904
    /// that precedes the abort acknowledgement is the refused mechanism's, not
    /// a verdict on any credential: nothing was sent.
    async fn abort_sasl(&mut self) -> io::Result<()> {
        self.send_line("AUTHENTICATE *").await?;
        let settled_by = tokio::time::Instant::now() + SASL_ABORT_DEADLINE;
        loop {
            let msg =
                match tokio::time::timeout_at(settled_by, self.recv("closed during SASL")).await {
                    Ok(msg) => msg?,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the server did not answer the SASL abort",
                        ));
                    }
                };
            if let Some(err) = self.registration_refused(&msg) {
                return Err(err);
            }
            match msg.command.as_str() {
                // 906 acknowledges the abort; 904 is the abandoned mechanism's.
                "906" => return Ok(()),
                "904" => {}
                _ => {
                    self.answer_ping(&msg).await?;
                }
            }
        }
    }

    /// What this connection did on the way to authenticating that its owner
    /// should see: a mechanism the server refused before any credential, and
    /// the one offered instead.
    pub fn sasl_notes(&self) -> &[String] {
        &self.sasl_notes
    }

    /// Offer `mechanism` and wait for the server's empty initial challenge.
    async fn offer_mechanism(&mut self, mechanism: &str) -> io::Result<()> {
        self.send_line(&format!("AUTHENTICATE {mechanism}")).await?;
        self.await_authenticate_challenge(mechanism).await
    }

    /// The SCRAM messages after the empty initial challenge, up to the empty
    /// response that follows a verified server signature. `Some(reason)` is the
    /// server refusing the mechanism before any proof was sent.
    async fn scram_exchange(
        &mut self,
        hash: scram::ScramHash,
        account: &str,
        password: &str,
    ) -> io::Result<Option<String>> {
        let name = hash.mechanism();
        let failed = |error: scram::ScramError| {
            SaslRejection::new(SaslFailure::Protocol, &error.to_string()).into_error()
        };
        let client = scram::ScramClient::new(hash, account, password).map_err(failed)?;
        self.send_sasl_payload(&e6irc_proto::base64::encode(
            client.client_first().as_bytes(),
        ))
        .await?;
        let server_first = self.read_sasl_challenge(name).await?;
        let server_first = std::str::from_utf8(&server_first).map_err(|_| {
            failed(scram::ScramError::MalformedServerFirst(
                "not UTF-8".to_owned(),
            ))
        })?;
        let (client_final, awaiting) = match client.client_final(server_first) {
            Ok(exchange) => exchange,
            // The server refused the mechanism itself; no proof was sent.
            Err(scram::ScramError::ServerError(reason)) => return Ok(Some(reason)),
            Err(error) => return Err(failed(error)),
        };
        self.send_sasl_payload(&e6irc_proto::base64::encode(client_final.as_bytes()))
            .await?;
        let server_final = self.read_sasl_challenge(name).await?;
        let server_final = std::str::from_utf8(&server_final).map_err(|_| {
            failed(scram::ScramError::MalformedServerFinal(
                "not UTF-8".to_owned(),
            ))
        })?;
        awaiting.verify(server_final).map_err(failed)?;
        self.send_line("AUTHENTICATE +").await?;
        Ok(None)
    }

    /// The SASL mechanism that authenticated this connection, once it has.
    pub fn sasl_mechanism(&self) -> Option<&str> {
        self.authenticated_with.as_deref()
    }

    /// Negotiate SASL, offer `mechanism`, and wait for the server's empty
    /// challenge — everything before the mechanism-specific payload.
    async fn begin_sasl(&mut self, mechanism: &str) -> io::Result<()> {
        self.negotiate_sasl_cap(&[mechanism]).await?;
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
        identity: &Identity<'_>,
        payload: String,
        mechanism: &str,
    ) -> io::Result<String> {
        self.send_registration_identity(identity).await?;
        self.send_sasl_payload(&payload).await?;
        self.finish_sasl_then_welcome(identity.nick, mechanism)
            .await
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
        identity: &Identity<'_>,
        token: &str,
    ) -> io::Result<String> {
        let outcome = self.register_oauthbearer_steps(identity, token).await;
        self.told_before_it_left(outcome).await
    }

    async fn register_oauthbearer_steps(
        &mut self,
        identity: &Identity<'_>,
        token: &str,
    ) -> io::Result<String> {
        self.transport.admit("a bearer token")?;
        self.send_server_password(identity).await?;
        self.begin_sasl("OAUTHBEARER").await?;
        // RFC 7628 client response: gs2 header, then the bearer credential.
        let payload =
            e6irc_proto::base64::encode(format!("n,,\x01auth=Bearer {token}\x01\x01").as_bytes());
        self.register_with_sasl(identity, payload, "OAUTHBEARER")
            .await
    }

    /// Register with a nick and realname, answering PINGs, until the
    /// welcome (001) arrives. Returns the confirmed nick.
    pub async fn register(&mut self, identity: &Identity<'_>) -> io::Result<String> {
        let outcome = self.register_steps(identity).await;
        self.told_before_it_left(outcome).await
    }

    /// A registration that failed because the server went away is reported by
    /// what the server said before it left. A server that refuses (a wrong
    /// server password, a ban) sends its numeric or `ERROR` and closes; a
    /// client still writing its registration lines then fails on the write,
    /// and "broken pipe" would replace the reason already in its receive
    /// buffer.
    async fn told_before_it_left<T>(&mut self, outcome: io::Result<T>) -> io::Result<T> {
        let error = match outcome {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                error
            }
            other => return other,
        };
        let said = tokio::time::timeout(PEER_GONE_READ, async {
            while let Ok(Some(message)) = self.next_message().await {
                if let Some(refusal) = self.registration_refused(&message) {
                    return Some(refusal);
                }
            }
            None
        })
        .await
        .ok()
        .flatten();
        Err(said.unwrap_or(error))
    }

    async fn register_steps(&mut self, identity: &Identity<'_>) -> io::Result<String> {
        self.send_server_password(identity).await?;
        match self.begin_cap().await? {
            CapabilityNegotiation::Open => {
                self.request_metadata_capabilities().await?;
                self.send_registration_identity(identity).await?;
                self.send_line("CAP END").await?;
            }
            // Nothing is authenticated on this path, so a server without
            // capability negotiation costs only the optional metadata.
            CapabilityNegotiation::Unsupported => {
                self.send_registration_identity(identity).await?;
            }
            // Unknown either way: a server that does negotiate but answered
            // late is holding registration open for `CAP END`, and one that
            // never will answers it with a harmless 421.
            CapabilityNegotiation::Unanswered => {
                self.send_registration_identity(identity).await?;
                self.send_line("CAP END").await?;
            }
        }
        self.await_welcome(identity.nick).await
    }

    /// Send the network's connection password, when one is configured, as the
    /// first line: a server that requires one reads it before `CAP LS`,
    /// `NICK` and `USER`. The line is never logged; it goes straight to the
    /// socket.
    async fn send_server_password(&mut self, identity: &Identity<'_>) -> io::Result<()> {
        let Some(password) = identity.server_password else {
            return Ok(());
        };
        self.transport.admit("a server password")?;
        self.send_line(&password.line()).await?;
        self.server_password_sent = ServerPasswordSent::Yes;
        Ok(())
    }

    /// The one refusal predicate for every pre-welcome wait loop (capability
    /// discovery, capability requests, SASL, and the welcome itself). `ERROR`
    /// is the server closing the link with its reason — a connection throttle,
    /// a ban, "SASL access only" — and it can arrive at any of those stages,
    /// so it is classified here rather than by whichever loop happens to be
    /// running.
    fn registration_refused(&self, message: &OwnedMessage) -> Option<io::Error> {
        RegistrationRejection::from_reply(message, self.server_password_sent)
            .map(RegistrationRejection::into_error)
    }

    async fn send_registration_identity(&mut self, identity: &Identity<'_>) -> io::Result<()> {
        // `NICK` and the first `USER` parameter are single words on the wire;
        // an empty one, or one with a space in it, silently becomes a different
        // command (`USER 0 * :real` names the user "0").
        for (what, word) in [("nick", identity.nick), ("username", identity.username)] {
            if word.is_empty() || word.contains(char::is_whitespace) || word.starts_with(':') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the registration {what} must be one non-empty word"),
                ));
            }
        }
        self.send_line(&format!("NICK {}", identity.nick)).await?;
        self.send_line(&format!(
            "USER {} 0 * :{}",
            identity.username, identity.realname
        ))
        .await
    }

    /// Whether the server advertised `capability` during registration.
    pub fn offers(&self, capability: &str) -> bool {
        self.advertised.offers(capability)
    }

    /// Wait until the server has processed everything sent so far: a `PING`
    /// with a token of this client's own, answered by the matching `PONG`,
    /// which a server sends only after every earlier line. Every other line
    /// read on the way is handed to `each` (a server `PING` is answered and
    /// not handed on). Bounded by the response deadline.
    pub async fn round_trip(
        &mut self,
        mut each: impl FnMut(RelayEvent) -> io::Result<()>,
    ) -> io::Result<()> {
        const TOKEN: &str = "e6irc-round-trip";
        within(self.response_deadline, "answering a PING", async {
            self.send_line(&format!("PING :{TOKEN}")).await?;
            loop {
                let event = self.next_line_relayable().await?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection before answering a PING",
                    )
                })?;
                if let RelayEvent::Line {
                    message: Some(message),
                    ..
                } = &event
                {
                    if message.command == "PONG"
                        && message.params.last().map(String::as_str) == Some(TOKEN)
                    {
                        return Ok(());
                    }
                    if self.answer_ping(message).await? {
                        continue;
                    }
                }
                each(event)?;
            }
        })
        .await
    }

    /// Send `QUIT` and read until the server closes the connection, handing
    /// each line read on the way to `each`. Bounded by the response deadline:
    /// a server that keeps the socket open after `QUIT` ends the wait with
    /// [`io::ErrorKind::TimedOut`] instead of holding the caller forever.
    pub async fn quit_and_drain(
        &mut self,
        reason: &str,
        mut each: impl FnMut(RelayEvent) -> io::Result<()>,
    ) -> io::Result<()> {
        self.send_line(&format!("QUIT :{reason}")).await?;
        within(
            self.response_deadline,
            "closing the connection after QUIT",
            async {
                while let Some(event) = self.next_line_relayable().await? {
                    each(event)?;
                }
                Ok(())
            },
        )
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

    /// Join one channel, wait for confirmation, and load what its user has not
    /// read: the history after the channel's shared read marker, paged forward
    /// `page_lines` at a time until a page comes back short, for at most
    /// [`MAX_HISTORY_PAGES`] pages and `max_lines` lines. Without a marker it
    /// is the latest `page_lines` lines. Messages observed during JOIN and
    /// playback are returned in wire order so a UI can build state before its
    /// first draw, with whether unread lines remain beyond what was loaded.
    pub async fn join_with_history(
        &mut self,
        target: &str,
        page_lines: usize,
        max_lines: usize,
    ) -> io::Result<JoinedHistory> {
        self.join_history(
            target,
            HistoryRequest::Unread {
                page_lines,
                max_lines,
            },
        )
        .await
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
        Ok(self
            .join_history(target, HistoryRequest::Latest(history_count))
            .await?
            .events)
    }

    async fn join_history(
        &mut self,
        target: &str,
        request: HistoryRequest,
    ) -> io::Result<JoinedHistory> {
        within(
            self.response_deadline,
            "confirming a JOIN and its history",
            self.join_and_replay(target, request),
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
        request: HistoryRequest,
    ) -> io::Result<JoinedHistory> {
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

        let (page_lines, max_lines, marker) = match request {
            HistoryRequest::Latest(0) | HistoryRequest::Unread { page_lines: 0, .. } => {
                return Ok(JoinedHistory {
                    events,
                    coverage: HistoryCoverage::NoHistory,
                });
            }
            HistoryRequest::Latest(count) => {
                self.history_page(
                    &format!("CHATHISTORY LATEST {target} * {count}"),
                    count,
                    &mut events,
                )
                .await?;
                return Ok(JoinedHistory {
                    events,
                    coverage: HistoryCoverage::Latest,
                });
            }
            HistoryRequest::Unread {
                page_lines,
                max_lines,
            } => match read_marker {
                Some(marker) => (page_lines, max_lines, marker),
                None => {
                    self.history_page(
                        &format!("CHATHISTORY LATEST {target} * {page_lines}"),
                        page_lines,
                        &mut events,
                    )
                    .await?;
                    return Ok(JoinedHistory {
                        events,
                        coverage: HistoryCoverage::Latest,
                    });
                }
            },
        };

        // `AFTER <marker> N` returns the *oldest* N unread lines. Stopping at
        // one page would leave the rest unloaded, and the next live line would
        // then advance the marker over them on every device.
        let mut anchor = format!("timestamp={marker}");
        let mut loaded = 0usize;
        let mut pages = 0usize;
        loop {
            let wanted = page_lines.min(max_lines.saturating_sub(loaded));
            if wanted == 0 || pages == MAX_HISTORY_PAGES {
                // The last page was full and no more may be loaded.
                return Ok(JoinedHistory {
                    events,
                    coverage: HistoryCoverage::UnreadBeyondLoaded,
                });
            }
            let page = self
                .history_page(
                    &format!("CHATHISTORY AFTER {target} {anchor} {wanted}"),
                    wanted,
                    &mut events,
                )
                .await?;
            pages += 1;
            loaded += page.lines;
            if page.lines < wanted {
                return Ok(JoinedHistory {
                    events,
                    coverage: HistoryCoverage::AllUnread,
                });
            }
            match page.last_anchor {
                Some(next) => anchor = next,
                // A full page whose last line carries neither a msgid nor a
                // time cannot be continued from.
                None => {
                    return Ok(JoinedHistory {
                        events,
                        coverage: HistoryCoverage::UnreadBeyondLoaded,
                    });
                }
            }
        }
    }

    /// Send one CHATHISTORY `request` for at most `count` lines and read its
    /// batch into `events`.
    async fn history_page(
        &mut self,
        request: &str,
        count: usize,
        events: &mut Vec<ClientEvent>,
    ) -> io::Result<HistoryPage> {
        self.send_line(request).await?;
        let limit = events
            .len()
            .saturating_add(count)
            .saturating_add(MAX_JOIN_BURST_LINES);
        let mut history_batch: Option<String> = None;
        let mut page = HistoryPage {
            lines: 0,
            last_anchor: None,
        };
        loop {
            let Some(msg) = self
                .next_join_event(events, limit, "closed during CHATHISTORY playback")
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
                    return Ok(page);
                }
            }
            if history_batch.is_some() && msg.tag("batch") == history_batch.as_deref() {
                page.lines += 1;
                if let Some(msgid) = msg.tag("msgid") {
                    page.last_anchor = Some(format!("msgid={msgid}"));
                } else if let Some(time) = msg.tag("time") {
                    page.last_anchor = Some(format!("timestamp={time}"));
                }
            }
            events.push(ClientEvent::Message(msg));
        }
    }
}

/// The most CHATHISTORY pages one join loads while catching up on unread
/// lines. Past it the client says that more remain rather than paging on.
pub const MAX_HISTORY_PAGES: usize = 10;

/// What a join asks the history for.
enum HistoryRequest {
    /// The latest `n` lines, whatever the read marker says.
    Latest(usize),
    /// The unread lines after the read marker, paged forward.
    Unread { page_lines: usize, max_lines: usize },
}

/// One CHATHISTORY batch as read.
struct HistoryPage {
    /// Lines inside the batch.
    lines: usize,
    /// The selector naming the page's last line, to continue after it.
    last_anchor: Option<String>,
}

/// A confirmed join with its history.
#[derive(Debug)]
pub struct JoinedHistory {
    /// The join burst and the history, in wire order.
    pub events: Vec<ClientEvent>,
    /// How much of the channel's history the events hold.
    pub coverage: HistoryCoverage,
}

/// How much history a join loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryCoverage {
    /// None was asked for.
    NoHistory,
    /// The latest lines, with no read marker to resume from (or none asked
    /// about): older unread lines may exist before them.
    Latest,
    /// Every line after the read marker: nothing unread is missing.
    AllUnread,
    /// Unread lines remain after the last one loaded: paging stopped at its
    /// bound on a full page. A client must not advance the read marker past
    /// the last loaded line while this holds, or the unloaded lines would be
    /// marked read on every device.
    UnreadBeyondLoaded,
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
        if !is_join_refusal(channel, reply) {
            return None;
        }
        let forwarded_to = (reply.command == "470")
            .then(|| reply.params.get(2))
            .flatten()
            .map(|forward| bounded_diagnostic(forward));
        Some(Self {
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

/// Whether `reply` refuses a `JOIN` of `channel`: the replies that mean the 366
/// a join waits for will never come. Every client joins through
/// [`Connection::join_with_history`] or its sibling, so this is read in exactly
/// one place ([`JoinRefusal::from_reply`]).
///
/// There is no allow-list of numerics. Servers keep inventing their own join
/// refusals (479 bad name, 489 TLS-only, 520 operators-only, ...), and one this
/// client did not know about would otherwise leave the join waiting out its
/// deadline and the caller retrying forever. Any [`is_refusal`] reply about
/// `channel` is its refusal: an error numeric whose subject is `channel`, or a
/// `FAIL JOIN` whose context names `channel` or names nothing at all.
fn is_join_refusal(channel: &str, reply: &OwnedMessage) -> bool {
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    if !is_refusal(reply) {
        return false;
    }
    if reply.command == "FAIL" {
        // FAIL <command> <code> [<context>...] <description>
        return reply
            .params
            .first()
            .is_some_and(|command| command.eq_ignore_ascii_case("JOIN"))
            && match reply.params.get(2..reply.params.len().saturating_sub(1)) {
                Some(context) if !context.is_empty() => {
                    context.iter().any(|subject| casemap.eq(subject, channel))
                }
                _ => true,
            };
    }
    // An error numeric: <client> <channel> [...] :<reason>
    reply
        .params
        .get(1)
        .is_some_and(|subject| casemap.eq(subject, channel))
}

/// Map a registration-refusal numeric to a terminal error, if it is one. These
/// are the replies a server sends when it will not complete registration for
/// the requested nick/credentials; a client that keeps waiting for `001` after
/// one of them hangs forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationRefusal {
    /// 432: the server will not accept the requested nickname at all.
    InvalidNickname,
    /// 468: the server will not accept the `USER` name.
    InvalidUsername,
    /// 433, 436 or 437: the nickname is held, collided, or delayed after a
    /// recent holder; it becomes free without anything changing here.
    NicknameInUse,
    /// 464 after a `PASS`: the network rejected the configured server
    /// password.
    ServerPasswordRejected,
    /// 464 with no `PASS` sent: the network requires a server password and
    /// none is configured.
    ServerPasswordRequired,
    /// 465: the server refuses this connection by policy (a ban, a limit).
    NetworkBanned,
    /// A pre-welcome `ERROR`: the server closed the link with its reason (a
    /// connection throttle, a host limit, a ban, "SASL access only").
    NotRegistered,
    /// The server welcomed the connection under a nickname other than the one
    /// requested. Built only by [`RegistrationRejection::welcomed_as`].
    WelcomedAsAnotherNickname,
    /// The server does not offer the SASL capability or mechanism this
    /// connection was asked to authenticate with. Built only from a
    /// [`SaslRejection`].
    SaslUnavailable,
    /// 906: the server aborted the SASL exchange before a verdict (services
    /// going away mid-exchange). Built only from a [`SaslRejection`].
    SaslAborted,
    /// SASL ended without a verdict on the credentials (a locked account, an
    /// over-long exchange, a connection already authenticated). Built only
    /// from a [`SaslRejection`].
    SaslFailed,
}

/// What a client that keeps trying may do about a refusal. Decided by the
/// refusal's kind alone, so no caller can retype a policy answer as a
/// configuration error or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalRetry {
    /// The refusal ends by itself with nothing about the client's
    /// configuration changed: a throttle, a host limit, a ban that expires,
    /// services that are down. Whoever the client serves would have to notice
    /// and re-save settings that were never wrong, so it is retried, slowly,
    /// for as long as it lasts.
    UntilItClears,
    /// The refusal may be the client's own doing (a ghost of its previous
    /// session on the nickname) or a setting the server will not take. A slow
    /// schedule outlasts the former; a refusal that survives it is the latter.
    ScheduleThenPark,
    /// Nothing but a change to the configuration can end it: retrying changes
    /// nothing, so the client stops at once and says why.
    ParkNow,
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

    /// The server welcomed the connection, but under a nickname other than the
    /// one requested (a server truncating to its NICKLEN, say). Whether that is
    /// acceptable is the caller's decision — a bouncer's attach listener answers
    /// with the upstream's nickname on purpose — so this is a value a caller
    /// builds, not an error this library raises.
    pub fn welcomed_as(requested: &str, welcomed: &str) -> Self {
        Self {
            refusal: RegistrationRefusal::WelcomedAsAnotherNickname,
            diagnostic: bounded_diagnostic(&format!(
                "requested {requested}, but the server welcomed {welcomed}"
            )),
        }
    }

    /// Read a pre-welcome server reply as a refusal to register, if it is one.
    /// Public because not every registration goes through this library's
    /// socket: the bouncer's in-process network registers over a queue and must
    /// read the core's replies by the same table, not a second copy of it.
    ///
    /// 451 (`ERR_NOTREGISTERED`) is deliberately absent: it does not refuse
    /// registration, it answers a command the server does not take before
    /// registration — `CAP LS` on a server without capability negotiation,
    /// which [`Connection::register`] reads as such — and a client that ended
    /// on it registered nowhere it could have.
    ///
    /// `server_password` says whether a `PASS` preceded registration, which
    /// is the only thing that tells a missing server password from a rejected
    /// one.
    pub fn from_reply(message: &OwnedMessage, server_password: ServerPasswordSent) -> Option<Self> {
        let refusal = match message.command.as_str() {
            "ERROR" => RegistrationRefusal::NotRegistered,
            "432" => RegistrationRefusal::InvalidNickname,
            "468" => RegistrationRefusal::InvalidUsername,
            // 433 is held; 436 is a collision the server is resolving; 437 is
            // the nick delay after a recent holder. Each ends by itself.
            "433" | "436" | "437" => RegistrationRefusal::NicknameInUse,
            "464" => match server_password {
                ServerPasswordSent::Yes => RegistrationRefusal::ServerPasswordRejected,
                ServerPasswordSent::No => RegistrationRefusal::ServerPasswordRequired,
            },
            "465" => RegistrationRefusal::NetworkBanned,
            _ => return None,
        };
        Some(Self {
            refusal,
            diagnostic: registration_diagnostic(message),
        })
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
    /// What a client that keeps trying may do about this refusal.
    ///
    /// The network's capacity and policy answers never park: a pre-welcome
    /// `ERROR` (a throttle, "too many host connections", a ban that expires,
    /// "SASL access only" while services are down), a 465, services that
    /// withdraw `sasl` or abort the exchange. Only the server's prose tells a
    /// throttle from a permanent closure, and a permanent closure retried
    /// every few minutes costs the network one refused connection; a
    /// throttle parked on costs its owner a network that never comes back
    /// although nothing about it was wrong.
    ///
    /// A taken nickname is retried on the slow schedule, which outlasts the
    /// usual holder — a ghost of the client's own previous session — and
    /// parks when the holder stays. A nickname or user name the server will
    /// not take, and a server password it wants or rejects, take the same
    /// schedule. A
    /// welcome under another nickname parks at once: it cannot end without a
    /// shorter, or different, configured nickname.
    pub const fn retry_policy(self) -> RefusalRetry {
        match self {
            Self::NotRegistered
            | Self::NetworkBanned
            | Self::SaslUnavailable
            | Self::SaslAborted => RefusalRetry::UntilItClears,
            Self::NicknameInUse
            | Self::InvalidNickname
            | Self::InvalidUsername
            | Self::ServerPasswordRejected
            | Self::ServerPasswordRequired
            | Self::SaslFailed => RefusalRetry::ScheduleThenPark,
            Self::WelcomedAsAnotherNickname => RefusalRetry::ParkNow,
        }
    }

    pub fn from_error(error: &io::Error) -> Option<Self> {
        RegistrationRejection::from_error(error).map(|rejection| rejection.refusal())
    }

    const fn error_kind(self) -> io::ErrorKind {
        match self {
            Self::NicknameInUse => io::ErrorKind::AlreadyExists,
            Self::InvalidNickname | Self::WelcomedAsAnotherNickname => io::ErrorKind::InvalidInput,
            Self::InvalidUsername => io::ErrorKind::InvalidInput,
            Self::ServerPasswordRejected | Self::ServerPasswordRequired => {
                io::ErrorKind::PermissionDenied
            }
            Self::NetworkBanned => io::ErrorKind::ConnectionAborted,
            Self::NotRegistered | Self::SaslFailed | Self::SaslAborted => io::ErrorKind::Other,
            Self::SaslUnavailable => io::ErrorKind::Unsupported,
        }
    }
}

impl RegistrationRejection {
    fn into_error(self) -> io::Error {
        io::Error::new(
            self.refusal.error_kind(),
            RegistrationRefusalError {
                refusal: self.refusal,
                diagnostic: self.diagnostic,
            },
        )
    }
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
/// short enough to ride in one IRC NOTICE after its prefix, and free of control
/// characters so it can be relayed or printed to a terminal. Public so that a
/// caller with refusals of its own (the bouncer's bridges) bounds them
/// identically. 160 cut Libera's cloud-address refusal (about 240 characters)
/// before the words that say what to do.
pub const MAX_DIAGNOSTIC_CHARS: usize = 300;

pub fn bounded_diagnostic(detail: &str) -> String {
    detail
        .chars()
        .take(MAX_DIAGNOSTIC_CHARS)
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
    /// The mechanism's own exchange broke: a SCRAM server whose signature does
    /// not prove it knows the account, a malformed message, or a credential
    /// SASLprep cannot carry. Not a verdict on the password.
    Protocol,
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
            SaslFailure::Aborted => RegistrationRefusal::SaslAborted,
            SaslFailure::NickLocked
            | SaslFailure::TooLong
            | SaslFailure::AlreadyAuthenticated
            | SaslFailure::Protocol => RegistrationRefusal::SaslFailed,
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
            SaslFailure::Protocol => io::ErrorKind::InvalidData,
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

/// Install aws-lc-rs as the process rustls provider, once. Public so a binary
/// whose other TLS users (an HTTP client) take the process default gets this
/// one stack rather than a second.
pub fn install_crypto_provider() {
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
            ("436", RegistrationRefusal::NicknameInUse),
            ("437", RegistrationRefusal::NicknameInUse),
            ("465", RegistrationRefusal::NetworkBanned),
        ] {
            let message = OwnedMessage::from(
                &Message::parse(&format!(":srv {numeric} nick :refused")).expect("numeric"),
            );
            let error = RegistrationRejection::from_reply(&message, ServerPasswordSent::No)
                .expect("known refusal numeric")
                .into_error();
            assert_eq!(RegistrationRefusal::from_error(&error), Some(expected));
            let rejection = RegistrationRejection::from_error(&error).expect("typed rejection");
            assert_eq!(rejection.refusal(), expected);
            assert_eq!(rejection.diagnostic(), "refused");
        }
        // 451 answers a command, it does not refuse the registration.
        let not_registered = OwnedMessage::from(
            &Message::parse(":srv 451 * :You have not registered").expect("numeric"),
        );
        assert!(
            RegistrationRejection::from_reply(&not_registered, ServerPasswordSent::No).is_none()
        );
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
            params: vec![format!("{}\r\nnext", "x".repeat(MAX_DIAGNOSTIC_CHARS + 40))],
        };
        let diagnostic = registration_diagnostic(&message);
        assert_eq!(diagnostic.chars().count(), MAX_DIAGNOSTIC_CHARS);
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
        // Bidirectional overrides and isolates reorder what follows them, and
        // zero-width characters hide text: either lets a server line pose as
        // something else on the screen. Each is neutralised like a control.
        for invisible in [
            '\u{061c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}',
            '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}', '\u{2061}', '\u{2062}',
            '\u{2063}', '\u{2064}', '\u{2065}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{feff}',
        ] {
            let shown = TerminalSafe::from_untrusted(&format!("a{invisible}b"));
            assert_eq!(
                shown.as_str(),
                "a\u{fffd}b",
                "U+{:04X}",
                u32::from(invisible)
            );
        }
    }

    /// After a `PASS`, a server may answer it with 451 before capability
    /// discovery has been answered at all. That 451 is about `PASS`, not
    /// `CAP`: registration must keep negotiating, not conclude that the server
    /// has no capability negotiation.
    #[tokio::test]
    async fn a_451_about_pass_does_not_end_capability_negotiation() {
        let password = ServerPassword::parse("open sesame".to_owned()).expect("a valid password");
        let identity = Identity {
            server_password: Some(&password),
            ..TEST_IDENTITY
        };
        let mut steps = vec![
            Expect("PASS :open sesame"),
            Expect("CAP LS 302"),
            Send(":srv 451 * PASS :You have not registered"),
            Send(":srv CAP * LS :"),
        ];
        steps.extend(IDENTITY_THEN_WELCOME);
        let (mut connection, server) = scripted(steps);
        let welcomed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connection.register(&identity),
        )
        .await
        .expect("registration neither finished nor failed")
        .expect("welcomed");
        assert_eq!(welcomed, "nick");
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
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
        /// A line whose tail the test cannot predict (a random SCRAM nonce).
        ExpectStart(&'static str),
        Send(&'static str),
        /// The server says nothing for this long (paused-clock tests).
        Pause(std::time::Duration),
    }
    use Step::{Expect, ExpectStart, Pause, Send};

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
                    ExpectStart(prefix) => {
                        let line = lines.next_line().await.unwrap().unwrap_or_default();
                        assert!(
                            line.starts_with(prefix),
                            "the client's next line {line:?} does not start with {prefix:?}"
                        );
                    }
                    Send(line) => writer
                        .write_all(format!("{line}\r\n").as_bytes())
                        .await
                        .unwrap(),
                    Pause(duration) => tokio::time::sleep(duration).await,
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
                Ending::Welcomed => connection.register(&TEST_IDENTITY).await,
                Ending::SaslRefused(..) => {
                    connection.register_sasl(&TEST_IDENTITY, "acct", "pw").await
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
        Expect("USER ident 0 * :real"),
        Expect("CAP END"),
        Send(":srv 001 nick :Welcome"),
    ];

    #[tokio::test]
    async fn sasl_stops_before_authenticate_when_the_mechanism_is_not_advertised() {
        let rejection = assert_registration(
            after_discovery(
                ":srv CAP * LS :sasl=EXTERNAL,ECDSA-NIST256P-CHALLENGE server-time",
                Vec::new(),
            ),
            Ending::SaslRefused(
                SaslFailure::MechanismNotOffered,
                "requested one of SCRAM-SHA-512, SCRAM-SHA-256, PLAIN; \
                 the server offers EXTERNAL,ECDSA-NIST256P-CHALLENGE",
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

    /// What a scripted SCRAM server does with the client's proof.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ScramServerMode {
        /// Verify the proof and sign the answer.
        Honest,
        /// Verify the proof, then send a signature that proves nothing.
        ForgedSignature,
        /// Reject the proof with 904, as for a wrong password.
        RejectProof,
    }

    /// A server that advertises `offered`, expects the client to choose
    /// `expected`, and runs that SCRAM exchange for account `user` and password
    /// `pencil`: RFC 5802's server side, so a random client nonce is fine.
    /// Returns what the client sent after the exchange (nothing, for a forged
    /// signature: no second mechanism may follow).
    async fn scram_server(
        server_io: tokio::io::DuplexStream,
        offered: &str,
        expected: scram::ScramHash,
        mode: ScramServerMode,
    ) -> Vec<String> {
        use aws_lc_rs::{digest, hmac, pbkdf2};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (reader, mut writer) = tokio::io::split(server_io);
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut next = async || lines.next_line().await.unwrap().unwrap();
        assert_eq!(next().await, "CAP LS 302");
        writer
            .write_all(format!(":srv CAP * LS :sasl={offered}\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(next().await, "CAP REQ :sasl");
        writer.write_all(b":srv CAP * ACK :sasl\r\n").await.unwrap();
        assert_eq!(
            next().await,
            format!("AUTHENTICATE {}", expected.mechanism())
        );
        writer.write_all(b"AUTHENTICATE +\r\n").await.unwrap();
        assert_eq!(next().await, "NICK nick");
        assert_eq!(next().await, "USER ident 0 * :real");

        let payload = |line: String| {
            let encoded = line
                .strip_prefix("AUTHENTICATE ")
                .expect("an AUTHENTICATE line")
                .to_owned();
            String::from_utf8(e6irc_proto::base64::decode(&encoded).expect("base64")).unwrap()
        };
        let client_first = payload(next().await);
        let client_first_bare = client_first
            .strip_prefix("n,,")
            .expect("no channel binding")
            .to_owned();
        assert!(
            client_first_bare.starts_with("n=user,r="),
            "{client_first_bare}"
        );
        let client_nonce = client_first_bare.trim_start_matches("n=user,r=").to_owned();
        let salt = b"e6irc-test-salt";
        let server_first = format!(
            "r={client_nonce}srv,s={},i=4096",
            e6irc_proto::base64::encode(salt)
        );
        writer
            .write_all(
                format!(
                    "AUTHENTICATE {}\r\n",
                    e6irc_proto::base64::encode(server_first.as_bytes())
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let client_final = payload(next().await);
        let (without_proof, proof) = client_final.rsplit_once(",p=").expect("a proof");
        assert_eq!(without_proof, format!("c=biws,r={client_nonce}srv"));
        let (hmac_algorithm, digest_algorithm, pbkdf2_algorithm, len) = match expected {
            scram::ScramHash::Sha512 => (
                hmac::HMAC_SHA512,
                &digest::SHA512,
                pbkdf2::PBKDF2_HMAC_SHA512,
                64,
            ),
            scram::ScramHash::Sha256 => (
                hmac::HMAC_SHA256,
                &digest::SHA256,
                pbkdf2::PBKDF2_HMAC_SHA256,
                32,
            ),
        };
        let mut salted = vec![0u8; len];
        pbkdf2::derive(
            pbkdf2_algorithm,
            std::num::NonZeroU32::new(4096).unwrap(),
            salt,
            b"pencil",
            &mut salted,
        );
        let salted_key = hmac::Key::new(hmac_algorithm, &salted);
        let stored_key = digest::digest(
            digest_algorithm,
            hmac::sign(&salted_key, b"Client Key").as_ref(),
        );
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let client_signature = hmac::sign(
            &hmac::Key::new(hmac_algorithm, stored_key.as_ref()),
            auth_message.as_bytes(),
        );
        let recovered: Vec<u8> = e6irc_proto::base64::decode(proof)
            .expect("proof base64")
            .iter()
            .zip(client_signature.as_ref())
            .map(|(proof, signature)| proof ^ signature)
            .collect();
        assert_eq!(
            digest::digest(digest_algorithm, &recovered).as_ref(),
            stored_key.as_ref(),
            "the client's proof verifies"
        );
        if mode == ScramServerMode::RejectProof {
            writer
                .write_all(b":srv 904 nick :SASL authentication failed\r\n")
                .await
                .unwrap();
        } else {
            let server_key = hmac::sign(&salted_key, b"Server Key");
            let mut signature = hmac::sign(
                &hmac::Key::new(hmac_algorithm, server_key.as_ref()),
                auth_message.as_bytes(),
            )
            .as_ref()
            .to_vec();
            if mode == ScramServerMode::ForgedSignature {
                signature[0] ^= 1;
            }
            let server_final = format!("v={}", e6irc_proto::base64::encode(&signature));
            writer
                .write_all(
                    format!(
                        "AUTHENTICATE {}\r\n",
                        e6irc_proto::base64::encode(server_final.as_bytes())
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            if mode == ScramServerMode::Honest {
                assert_eq!(next().await, "AUTHENTICATE +");
                writer
                    .write_all(b":srv 903 nick :SASL authentication successful\r\n")
                    .await
                    .unwrap();
                assert_eq!(next().await, "CAP END");
                writer
                    .write_all(b":srv 001 nick :Welcome\r\n")
                    .await
                    .unwrap();
            }
        }
        let mut after = Vec::new();
        while let Some(line) = lines.next_line().await.unwrap() {
            after.push(line);
        }
        after
    }

    /// Libera advertises SCRAM-SHA-512 for every connection, but answers the
    /// client's first message with `e=other-error` when the account's stored
    /// password cannot do SCRAM. Nothing was sent yet, so the next mechanism is
    /// offered on the same connection and the owner is told.
    #[tokio::test]
    async fn a_mechanism_refused_before_any_credential_falls_back_and_says_so() {
        let (mut connection, server) = scripted(vec![
            Expect("CAP LS 302"),
            Send(":srv CAP * LS :sasl=EXTERNAL,PLAIN,SCRAM-SHA-512"),
            Expect("CAP REQ :sasl"),
            Send(":srv CAP * ACK :sasl"),
            Expect("AUTHENTICATE SCRAM-SHA-512"),
            Send("AUTHENTICATE +"),
            Expect("NICK nick"),
            Expect("USER ident 0 * :real"),
            // The client's first message carries a random nonce.
            ExpectStart("AUTHENTICATE "),
            Send("AUTHENTICATE ZT1vdGhlci1lcnJvcg=="),
            Expect("AUTHENTICATE *"),
            Send(":srv 904 * :SASL authentication failed"),
            Send(":srv 906 * :SASL authentication aborted"),
            Expect("AUTHENTICATE PLAIN"),
            Send("AUTHENTICATE +"),
            Expect("AUTHENTICATE AHVzZXIAcGVuY2ls"),
            Send(":srv 903 nick :SASL authentication successful"),
            Expect("CAP END"),
            Send(":srv 001 nick :Welcome"),
        ]);
        assert_eq!(
            connection
                .register_sasl(&TEST_IDENTITY, "user", "pencil")
                .await
                .expect("the weaker mechanism authenticates"),
            "nick"
        );
        assert_eq!(connection.sasl_mechanism(), Some("PLAIN"));
        assert_eq!(
            connection.sasl_notes(),
            [
                "SCRAM-SHA-512 was refused before any credential was sent (other-error); offering PLAIN"
            ]
        );
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
    }

    /// With nothing weaker offered, the refusal is the failure: there is
    /// nothing to fall back to, and it is not a verdict on the password.
    #[tokio::test]
    async fn a_refused_mechanism_with_no_alternative_fails_loudly() {
        let (mut connection, server) = scripted(vec![
            Expect("CAP LS 302"),
            Send(":srv CAP * LS :sasl=SCRAM-SHA-512"),
            Expect("CAP REQ :sasl"),
            Send(":srv CAP * ACK :sasl"),
            Expect("AUTHENTICATE SCRAM-SHA-512"),
            Send("AUTHENTICATE +"),
            Expect("NICK nick"),
            Expect("USER ident 0 * :real"),
            ExpectStart("AUTHENTICATE "),
            Send("AUTHENTICATE ZT1vdGhlci1lcnJvcg=="),
        ]);
        let error = connection
            .register_sasl(&TEST_IDENTITY, "user", "pencil")
            .await
            .expect_err("nothing else is offered");
        let rejection = SaslRejection::from_error(&error).expect("typed SASL rejection");
        assert_eq!(rejection.failure(), SaslFailure::Protocol);
        assert!(
            rejection.diagnostic().contains("other-error")
                && rejection.diagnostic().contains("no other mechanism"),
            "{}",
            rejection.diagnostic()
        );
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
    }

    /// Libera offers ECDSA, EXTERNAL, PLAIN and SCRAM-SHA-512: a password
    /// logs in with SCRAM-SHA-512, and the connection says so.
    #[tokio::test]
    async fn the_strongest_offered_password_mechanism_is_chosen_and_stated() {
        for (offered, expected) in [
            (
                "ECDSA-NIST256P-CHALLENGE,EXTERNAL,PLAIN,SCRAM-SHA-512",
                scram::ScramHash::Sha512,
            ),
            ("PLAIN,SCRAM-SHA-256", scram::ScramHash::Sha256),
        ] {
            let (mut connection, server_io) = duplex_connection(16 * 1024);
            let server = tokio::spawn(scram_server(
                server_io,
                offered,
                expected,
                ScramServerMode::Honest,
            ));
            assert_eq!(
                connection
                    .register_sasl(&TEST_IDENTITY, "user", "pencil")
                    .await
                    .expect("welcomed"),
                "nick"
            );
            assert_eq!(connection.sasl_mechanism(), Some(expected.mechanism()));
            drop(connection);
            assert_eq!(server.await.unwrap(), Vec::<String>::new());
        }
    }

    /// A server whose signature proves nothing is refused, and nothing else is
    /// tried: offering PLAIN next would hand the password to that server.
    #[tokio::test]
    async fn a_forged_scram_signature_fails_loudly_without_falling_back_to_plain() {
        let (mut connection, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(scram_server(
            server_io,
            "PLAIN,SCRAM-SHA-512",
            scram::ScramHash::Sha512,
            ScramServerMode::ForgedSignature,
        ));
        let error = connection
            .register_sasl(&TEST_IDENTITY, "user", "pencil")
            .await
            .expect_err("a forged signature is refused");
        let rejection = SaslRejection::from_error(&error).expect("typed SASL rejection");
        assert_eq!(rejection.failure(), SaslFailure::Protocol);
        assert!(
            rejection.diagnostic().contains("did not prove"),
            "{}",
            rejection.diagnostic()
        );
        assert_eq!(connection.sasl_mechanism(), None);
        drop(connection);
        assert_eq!(
            server.await.unwrap(),
            Vec::<String>::new(),
            "no fallback was offered"
        );
    }

    /// A 904 answering the proof is a verdict on the password.
    #[tokio::test]
    async fn a_rejected_scram_proof_is_rejected_credentials() {
        let (mut connection, server_io) = duplex_connection(16 * 1024);
        let server = tokio::spawn(scram_server(
            server_io,
            "SCRAM-SHA-512",
            scram::ScramHash::Sha512,
            ScramServerMode::RejectProof,
        ));
        let error = connection
            .register_sasl(&TEST_IDENTITY, "user", "pencil")
            .await
            .expect_err("the proof is rejected");
        let rejection = SaslRejection::from_error(&error).expect("typed SASL rejection");
        assert_eq!(rejection.failure(), SaslFailure::Failed);
        drop(connection);
        server.await.unwrap();
    }

    /// A server that named no mechanisms is offered PLAIN; when its 908 names
    /// a stronger one this client speaks, that one is offered once.
    #[tokio::test]
    async fn a_mechanism_list_learned_from_908_upgrades_the_offer_once() {
        let steps = after_discovery(
            ":srv CAP * LS :sasl",
            vec![
                Expect("CAP REQ :sasl"),
                Send(":srv CAP * ACK :sasl"),
                Expect("AUTHENTICATE PLAIN"),
                Send(":srv 908 * SCRAM-SHA-256 :are available SASL mechanisms"),
                Send(":srv 904 * :SASL authentication failed"),
                Expect("AUTHENTICATE SCRAM-SHA-256"),
                Send(":srv 904 * :SASL authentication failed"),
            ],
        );
        let (mut connection, server) = scripted(steps);
        let error = connection
            .register_sasl(&TEST_IDENTITY, "user", "pencil")
            .await
            .expect_err("the scripted server refuses the second offer too");
        let rejection = SaslRejection::from_error(&error).expect("typed SASL rejection");
        assert_eq!(rejection.failure(), SaslFailure::Failed);
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
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
                    Send(":srv 908 * EXTERNAL,ECDSA-NIST256P-CHALLENGE :are available SASL mechanisms"),
                    Send(":srv 904 * :SASL authentication failed"),
                ],
            ),
            Ending::SaslRefused(
                SaslFailure::MechanismNotOffered,
                "requested PLAIN; the server offers EXTERNAL,ECDSA-NIST256P-CHALLENGE",
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
            match rejection.class() {
                SaslRejectionClass::CredentialsRejected(_) => assert_eq!(
                    expected,
                    SaslFailure::Failed,
                    "only a 904 for an offered mechanism is about the credentials"
                ),
                SaslRejectionClass::RegistrationRefused(refused) => {
                    assert_ne!(expected, SaslFailure::Failed);
                    // Services that abort the exchange are a passing state of
                    // the network, not of this configuration.
                    let clears_by_itself =
                        refused.refusal().retry_policy() == RefusalRetry::UntilItClears;
                    assert_eq!(
                        clears_by_itself,
                        expected == SaslFailure::Aborted,
                        "{verdict}: {refused:?}"
                    );
                }
            }
        }
    }

    /// A server without capability negotiation may answer `CAP LS` with 451
    /// rather than 421 (it is a command it does not take before registration).
    /// Either way, registration proceeds plainly and no `CAP END` is sent.
    #[tokio::test]
    async fn a_451_to_capability_discovery_registers_plainly() {
        assert_registration(
            vec![
                Expect("CAP LS 302"),
                Send(":srv 451 * :You have not registered"),
                Expect("NICK nick"),
                Expect("USER ident 0 * :real"),
                Send(":srv 001 nick :Welcome"),
            ],
            Ending::Welcomed,
        )
        .await;
    }

    /// A server that ignores `CAP LS` would otherwise hold registration until
    /// the caller's own deadline and be misread as a lost connection. After
    /// the discovery bound the identity is sent anyway, and the negotiation is
    /// still ended for a server that merely answered late.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_capability_discovery_registers_and_still_ends_negotiation() {
        let (mut connection, server) = scripted(vec![
            Expect("CAP LS 302"),
            Expect("NICK nick"),
            Expect("USER ident 0 * :real"),
            Expect("CAP END"),
            Send(":srv 001 nick :Welcome"),
        ]);
        let started = tokio::time::Instant::now();
        let welcomed = tokio::time::timeout(
            CAP_DISCOVERY_DEADLINE * 3,
            connection.register(&TEST_IDENTITY),
        )
        .await
        .expect("registration neither finished nor failed")
        .expect("registered");
        assert_eq!(welcomed, "nick");
        assert!(started.elapsed() >= CAP_DISCOVERY_DEADLINE);
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
    }

    /// With SASL configured, the same silence fails loudly: registering
    /// unauthenticated would be a silent downgrade. It is a timeout, retried as
    /// one, and never reported as the server lacking SASL, which it may well
    /// offer once it has finished checking the connection.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_capability_discovery_is_a_timeout_for_sasl() {
        let (mut connection, server) = scripted(vec![Expect("CAP LS 302")]);
        let error = tokio::time::timeout(
            CAP_DISCOVERY_DEADLINE * 3,
            connection.register_sasl(&TEST_IDENTITY, "acct", "pw"),
        )
        .await
        .expect("registration neither finished nor failed")
        .expect_err("SASL cannot be negotiated with a silent server");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(SaslRejection::from_error(&error).is_none(), "{error}");
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
    }

    /// Libera read nothing until its ident check gave up, and answered `CAP LS`
    /// after 6.9 s from a host that drops ident. That is a slow server, not a
    /// silent one: SASL must still be negotiated.
    #[tokio::test(start_paused = true)]
    async fn a_capability_answer_held_behind_the_ident_check_still_negotiates_sasl() {
        let (mut connection, server) = scripted(vec![
            Expect("CAP LS 302"),
            Send(":srv NOTICE * :*** Checking Ident"),
            Pause(std::time::Duration::from_millis(6_900)),
            Send(":srv NOTICE * :*** No Ident response"),
            Send(":srv CAP * LS :sasl=PLAIN"),
            Expect("CAP REQ :sasl"),
            Send(":srv CAP * ACK :sasl"),
            Expect("AUTHENTICATE PLAIN"),
            Send("AUTHENTICATE +"),
            Expect("NICK nick"),
            Expect("USER ident 0 * :real"),
            Expect("AUTHENTICATE AGFjY3QAcHc="),
            Send(":srv 903 nick :SASL authentication successful"),
            Expect("CAP END"),
            Send(":srv 001 nick :Welcome"),
        ]);
        let welcomed = tokio::time::timeout(
            CAP_DISCOVERY_DEADLINE * 3,
            connection.register_sasl(&TEST_IDENTITY, "acct", "pw"),
        )
        .await
        .expect("registration neither finished nor failed")
        .expect("a slow capability answer still authenticates");
        assert_eq!(welcomed, "nick");
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
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
                    Expect("USER ident 0 * :real"),
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
            connection.register(&TEST_IDENTITY),
        )
        .await
        .expect("an endless list must end the registration")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        drop(server.await.unwrap());
    }

    /// A user name that is visibly not the nickname: nothing may derive one
    /// from the other.
    const TEST_IDENTITY: Identity<'static> = Identity {
        nick: "nick",
        username: "ident",
        realname: "real",
        server_password: None,
    };

    /// A `PASS` goes out before anything else — before `CAP LS`, on every
    /// registration path — and its trailing-parameter form keeps a password
    /// with spaces in it whole.
    #[tokio::test]
    async fn a_server_password_is_the_first_line_on_every_registration_path() {
        let password = ServerPassword::parse("open sesame".to_owned()).expect("a valid password");
        let identity = Identity {
            server_password: Some(&password),
            ..TEST_IDENTITY
        };
        let plain = {
            let mut steps = vec![Expect("PASS :open sesame"), Expect("CAP LS 302")];
            steps.push(Send(":srv CAP * LS :"));
            steps.extend(IDENTITY_THEN_WELCOME);
            steps
        };
        let (mut connection, server) = scripted(plain);
        assert_eq!(
            connection.register(&identity).await.expect("welcomed"),
            "nick"
        );
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());

        // The SASL paths: the scripted server refuses `sasl` once asked, which
        // ends each registration right after the lines that matter here.
        for mechanism in ["PLAIN", "OAUTHBEARER"] {
            let (mut connection, server) = scripted(vec![
                Expect("PASS :open sesame"),
                Expect("CAP LS 302"),
                Send(":srv CAP * LS :sasl"),
                Expect("CAP REQ :sasl"),
                Send(":srv CAP * NAK :sasl"),
            ]);
            let registration = async {
                if mechanism == "PLAIN" {
                    connection.register_sasl(&identity, "acct", "pw").await
                } else {
                    connection.register_oauthbearer(&identity, "token").await
                }
            };
            let error = tokio::time::timeout(std::time::Duration::from_secs(5), registration)
                .await
                .expect("registration neither finished nor failed")
                .expect_err("the scripted server refuses sasl");
            assert_eq!(
                SaslRejection::from_error(&error).map(|rejection| rejection.failure()),
                Some(SaslFailure::CapabilityNotOffered),
                "{mechanism}: {error:?}"
            );
            drop(connection);
            assert_eq!(server.await.unwrap(), Vec::<String>::new());
        }
    }

    /// The bound is decided before a byte leaves: an over-long password would
    /// otherwise be cut by the wire budget, and a delimiter would forge a
    /// second command inside the one line the server trusts most.
    #[test]
    fn a_server_password_is_bounded_and_delimiter_free_before_it_is_sent() {
        assert_eq!(ServerPassword::MAX_LEN, 504);
        assert!(ServerPassword::parse("x".repeat(ServerPassword::MAX_LEN)).is_ok());
        for (value, cause) in [
            (String::new(), ServerPasswordError::Empty),
            (
                "x".repeat(ServerPassword::MAX_LEN + 1),
                ServerPasswordError::TooLong,
            ),
            ("a\r\nQUIT".to_owned(), ServerPasswordError::Delimiter),
            ("a\nb".to_owned(), ServerPasswordError::Delimiter),
            ("a\0b".to_owned(), ServerPasswordError::Delimiter),
        ] {
            assert_eq!(ServerPassword::parse(value).expect_err("refused"), cause);
        }
        let password = ServerPassword::parse("hunter2".to_owned()).expect("valid");
        assert_eq!(password.as_str(), "hunter2");
        assert!(!format!("{password:?}").contains("hunter2"));
        assert!(
            !format!(
                "{:?}",
                Identity {
                    server_password: Some(&password),
                    ..TEST_IDENTITY
                }
            )
            .contains("hunter2")
        );
    }

    /// A server that refuses and closes can make the client's next write fail
    /// before the refusal is read. The failure is still reported as the refusal
    /// the server sent, not as the broken pipe it caused.
    #[tokio::test]
    async fn a_write_that_finds_the_server_gone_reports_what_it_said() {
        let (mut connection, server) = scripted(vec![Send(":srv 464 * :Password incorrect")]);
        connection.server_password_sent = ServerPasswordSent::Yes;
        let error = connection
            .told_before_it_left::<()>(Err(io::ErrorKind::BrokenPipe.into()))
            .await
            .expect_err("still a failure");
        assert_eq!(
            RegistrationRefusal::from_error(&error),
            Some(RegistrationRefusal::ServerPasswordRejected),
            "{error}"
        );
        drop(connection);
        server.await.expect("server");

        // With nothing said, the write failure itself is the report.
        let (mut connection, server) = scripted(vec![]);
        drop(server);
        let error = connection
            .told_before_it_left::<()>(Err(io::ErrorKind::BrokenPipe.into()))
            .await
            .expect_err("still a failure");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    /// A 464 means one of two things, and only the client knows which: with no
    /// `PASS` sent the network wants one; after a `PASS` it rejected the one
    /// sent. Each is a different repair, so each is a different refusal.
    #[tokio::test]
    async fn a_464_names_a_missing_password_or_a_rejected_one() {
        let refused = ":srv 464 nick :Password incorrect";
        let (mut connection, server) = scripted(vec![Expect("CAP LS 302"), Send(refused)]);
        let error = connection
            .register(&TEST_IDENTITY)
            .await
            .expect_err("464 refuses registration");
        assert_eq!(
            RegistrationRefusal::from_error(&error),
            Some(RegistrationRefusal::ServerPasswordRequired)
        );
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());

        let password = ServerPassword::parse("wrong".to_owned()).expect("valid");
        let (mut connection, server) = scripted(vec![
            Expect("PASS :wrong"),
            Expect("CAP LS 302"),
            Send(refused),
        ]);
        let error = connection
            .register(&Identity {
                server_password: Some(&password),
                ..TEST_IDENTITY
            })
            .await
            .expect_err("464 refuses registration");
        assert_eq!(
            RegistrationRefusal::from_error(&error),
            Some(RegistrationRefusal::ServerPasswordRejected)
        );
        assert!(!error.to_string().contains("wrong"), "{error}");
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
        assert_eq!(
            RegistrationRefusal::ServerPasswordRequired.retry_policy(),
            RegistrationRefusal::ServerPasswordRejected.retry_policy()
        );
    }

    fn duplex_connection(capacity: usize) -> (Connection, tokio::io::DuplexStream) {
        duplex_connection_over(capacity, Transport::Loopback)
    }

    fn duplex_connection_over(
        capacity: usize,
        transport: Transport,
    ) -> (Connection, tokio::io::DuplexStream) {
        let (client_io, server_io) = tokio::io::duplex(capacity);
        let (reader, writer) = tokio::io::split(client_io);
        (
            Connection::from_halves(Box::new(reader), Box::new(writer), transport),
            server_io,
        )
    }

    /// A credential — a SASL password, a bearer token, a server password — is
    /// written only to a connection whose transport cannot be overheard: TLS,
    /// or a plaintext socket whose peer is this machine's loopback address.
    /// The connection decides from how it was built; no caller can talk it
    /// into sending one in cleartext to another machine, and it refuses
    /// before a single byte is written.
    #[tokio::test]
    async fn credentials_are_written_only_to_a_transport_that_cannot_be_overheard() {
        let password = ServerPassword::parse("open sesame".into()).expect("valid");
        let identity = Identity {
            nick: "alice",
            username: "alice",
            realname: "Alice",
            server_password: None,
        };
        let with_password = Identity {
            server_password: Some(&password),
            ..identity
        };
        for attempt in 0..3 {
            let (mut connection, mut server) = duplex_connection_over(4096, Transport::Cleartext);
            let refused = match attempt {
                0 => connection.register_sasl(&identity, "alice", "secret").await,
                1 => connection.register_oauthbearer(&identity, "token").await,
                _ => connection.register(&with_password).await,
            }
            .expect_err("a cleartext transport to another machine carries no credential");
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{refused}");
            assert!(refused.to_string().contains("cleartext"), "{refused}");
            drop(connection);
            let mut written = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut server, &mut written)
                .await
                .expect("read what was written");
            assert!(
                written.is_empty(),
                "{:?}",
                String::from_utf8_lossy(&written)
            );
        }
        // With the user's explicit consent (`--allow-cleartext-credentials`)
        // the password is sent.
        let (mut connection, mut server) = duplex_connection_over(4096, Transport::Cleartext);
        connection.consent_to_cleartext_credentials();
        drop(connection.send_server_password(&with_password).await);
        drop(connection);
        let mut written = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut written)
            .await
            .expect("read");
        assert_eq!(written, b"PASS :open sesame\r\n");
    }

    #[test]
    fn a_plaintext_peer_is_loopback_by_its_address() {
        for peer in [
            "127.0.0.1:6667",
            "127.8.8.8:6667",
            "[::1]:6667",
            "[::ffff:127.0.0.1]:6667",
        ] {
            assert_eq!(
                Transport::of_plaintext_peer(peer.parse().unwrap()),
                Transport::Loopback,
                "{peer}"
            );
        }
        for peer in [
            "192.0.2.1:6667",
            "[2001:db8::1]:6667",
            "[::ffff:192.0.2.1]:6667",
        ] {
            assert_eq!(
                Transport::of_plaintext_peer(peer.parse().unwrap()),
                Transport::Cleartext,
                "{peer}"
            );
        }
    }

    /// `USER  0 * :real` names the user "0", and `USER al ice 0 * :real` shifts
    /// every parameter after it. Neither may reach the wire.
    #[tokio::test]
    async fn an_empty_or_spaced_registration_word_is_refused_before_it_is_sent() {
        for (nick, username) in [
            ("nick", ""),
            ("nick", "al ice"),
            ("", "ident"),
            ("nick", ":x"),
        ] {
            let (mut connection, server_io) = duplex_connection(4096);
            let identity = Identity {
                nick,
                username,
                realname: "real",
                server_password: None,
            };
            let error = connection
                .send_registration_identity(&identity)
                .await
                .expect_err("not one word");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            drop(connection);
            let mut sent = Vec::new();
            tokio::io::split(server_io)
                .0
                .read_to_end(&mut sent)
                .await
                .unwrap();
            assert!(sent.is_empty(), "{nick:?}/{username:?} reached the wire");
        }
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
            conn.register_sasl(&TEST_IDENTITY, "acct", "pw"),
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
            .register_sasl(&TEST_IDENTITY, "acct", "pw")
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

        let error = conn.register(&TEST_IDENTITY).await.unwrap_err();
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
                "USER ident 0 * :real"
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
                .register_oauthbearer(&TEST_IDENTITY, "token")
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
            username: "ident".into(),
            realname: "real".into(),
            authentication: Authentication::None,
            response_deadline,
            cleartext_credentials: CleartextCredentials::Refuse,
            server_password: None,
        }
    }

    /// SASL PLAIN is the password, base64-encoded; OAUTHBEARER is the token.
    /// Without TLS either is readable by everything on the path.
    #[tokio::test]
    async fn credentials_are_not_sent_in_cleartext_to_another_machine() {
        let plain = Authentication::Plain {
            account: "account".into(),
            password: "secret".into(),
        };
        let bearer = Authentication::OAuthBearer {
            token: "token".into(),
        };
        for authentication in [plain.clone(), bearer] {
            // TEST-NET-1: never dialed, because the refusal comes first.
            let mut options = anonymous("192.0.2.1:6667".into(), std::time::Duration::from_secs(2));
            options.authentication = authentication;
            let error = must_give_up(options.connect_registered()).await;
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert!(error.to_string().contains("cleartext"), "{error}");
        }
        // A server password is a credential too, even with no SASL.
        let mut options = anonymous("192.0.2.1:6667".into(), std::time::Duration::from_secs(2));
        options.server_password = Some(ServerPassword::parse("secret".into()).expect("valid"));
        let error = must_give_up(options.connect_registered()).await;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
        assert!(error.to_string().contains("server password"), "{error}");
        assert!(!error.to_string().contains("secret"), "{error}");

        // Loopback never leaves the machine; anonymous has nothing to protect;
        // and the caller's user may insist. None of these is refused up front
        // (the dial to a closed loopback port then fails as a dial).
        for (address, authentication, cleartext) in [
            ("127.0.0.1:1", plain.clone(), CleartextCredentials::Refuse),
            ("localhost:1", plain.clone(), CleartextCredentials::Refuse),
            ("[::1]:1", plain.clone(), CleartextCredentials::Refuse),
            (
                "192.0.2.1:1",
                Authentication::None,
                CleartextCredentials::Refuse,
            ),
            ("192.0.2.1:1", plain, CleartextCredentials::Allow),
        ] {
            let mut options = anonymous(address.into(), std::time::Duration::from_millis(200));
            options.authentication = authentication;
            options.cleartext_credentials = cleartext;
            let error = must_give_up(options.connect_registered()).await;
            assert_ne!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "{address}: {error}"
            );
        }
    }

    #[test]
    fn an_unstated_username_is_the_nick_only_when_the_nick_is_a_legal_one() {
        assert_eq!(
            stated_or_nick_username(None, "alice").unwrap(),
            "alice",
            "a nick that is a legal user name doubles as one"
        );
        assert_eq!(
            stated_or_nick_username(Some("ident"), "_bot").unwrap(),
            "ident",
            "a stated user name is used as stated"
        );
        // Never shortened, stripped or otherwise made to fit.
        for nick in ["_bot", "ada|away", "[away]", "adalovelace", "zoë", ""] {
            let error = stated_or_nick_username(None, nick).expect_err(nick);
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{nick}");
            assert!(error.to_string().contains("--username"), "{error}");
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
                must_give_up(connection.join_with_history("#room", 0, 0)).await
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

    /// A refusal numeric this client never heard of still ends the join loudly
    /// with the server's reason: an allow-list left 479/489/520 and `FAIL JOIN`
    /// waiting out the deadline, and the TUI reconnecting forever.
    #[tokio::test]
    async fn any_error_reply_about_the_channel_is_a_refusal_with_its_reason() {
        let replies: [&'static [u8]; 6] = [
            b":srv 479 nick #room :Illegal channel name\r\n",
            b":srv 489 nick #ROOM :Cannot join channel (+z)\r\n",
            b":srv 520 nick #room :Only IRC operators may join\r\n",
            b":srv 599 nick #room :Some future refusal\r\n",
            b":srv FAIL JOIN CHANNEL_CLOSED #room :Some future refusal\r\n",
            b":srv FAIL JOIN UNKNOWN_ERROR :Some future refusal\r\n",
        ];
        for reply in replies {
            let error = join_answered_with(reply)
                .await
                .expect_err("a refusal ends the join");
            let refusal = JoinRefusal::from_error(&error).expect("a typed join refusal");
            assert_eq!(refusal.channel(), "#room");
            assert_eq!(refusal.forwarded_to(), None);
            let text = error.to_string();
            assert!(
                text.contains("Illegal channel name")
                    || text.contains("(+z)")
                    || text.contains("IRC operators")
                    || text.contains("future refusal"),
                "the server's reason is carried: {text}"
            );
        }
    }

    /// An error about some other channel, or a `FAIL` for some other command,
    /// is not this join's refusal.
    #[tokio::test]
    async fn an_error_about_another_subject_does_not_end_the_join() {
        let events = join_answered_with(
            b":srv 404 nick #other :Cannot send to channel\r\n\
              :srv FAIL JOIN CHANNEL_CLOSED #other :closed\r\n\
              :srv FAIL CHATHISTORY INVALID_TARGET #room :no\r\n\
              :srv 366 nick #room :End of NAMES\r\n",
        )
        .await
        .expect("errors about other subjects do not refuse #room");
        assert_eq!(messages_of(&events).len(), 4);
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
            let joined = conn.join_with_history("#Room", 50, 500).await.unwrap();
            assert_eq!(
                joined.coverage,
                HistoryCoverage::AllUnread,
                "a short page is the end"
            );
            joined.events
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

    /// `AFTER <marker> N` answers with the *oldest* N unread lines. A full
    /// page means more may follow, so the client pages forward from the last
    /// line it received until a page comes back short.
    #[tokio::test]
    async fn unread_history_pages_forward_until_a_short_page() {
        let joined = |steps: &mut Vec<Step>| {
            steps.extend([
                Expect("JOIN #r"),
                Send(":me!u@h JOIN #r"),
                Send(":srv MARKREAD #r timestamp=2026-07-30T12:00:00.000Z"),
                Send(":srv 366 me #r :End of NAMES"),
            ]);
        };
        let page = |steps: &mut Vec<Step>, request: &'static str, lines: &[&'static str]| {
            steps.push(Expect(request));
            steps.push(Send(":srv BATCH +h chathistory #r"));
            steps.extend(lines.iter().map(|line| Send(line)));
            steps.push(Send(":srv BATCH -h"));
        };
        let mut steps = Vec::new();
        joined(&mut steps);
        page(
            &mut steps,
            "CHATHISTORY AFTER #r timestamp=2026-07-30T12:00:00.000Z 2",
            &[
                "@batch=h;msgid=a;time=2026-07-30T12:00:01.000Z :x!u@h PRIVMSG #r :1",
                "@batch=h;msgid=b;time=2026-07-30T12:00:02.000Z :x!u@h PRIVMSG #r :2",
            ],
        );
        page(
            &mut steps,
            "CHATHISTORY AFTER #r msgid=b 2",
            &[
                "@batch=h;msgid=c;time=2026-07-30T12:00:03.000Z :x!u@h PRIVMSG #r :3",
                "@batch=h;time=2026-07-30T12:00:04.000Z :x!u@h PRIVMSG #r :4",
            ],
        );
        page(
            &mut steps,
            "CHATHISTORY AFTER #r timestamp=2026-07-30T12:00:04.000Z 2",
            &["@batch=h;msgid=e;time=2026-07-30T12:00:05.000Z :x!u@h PRIVMSG #r :5"],
        );
        let (mut connection, server) = scripted(steps);
        let history = connection
            .join_with_history("#r", 2, 100)
            .await
            .expect("history");
        assert_eq!(history.coverage, HistoryCoverage::AllUnread);
        let texts: Vec<&str> = messages_of(&history.events)
            .into_iter()
            .filter(|message| message.command == "PRIVMSG")
            .map(|message| message.params[1].as_str())
            .collect();
        assert_eq!(texts, ["1", "2", "3", "4", "5"]);
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());

        // Paging is bounded: a page that is still full when the bound is
        // reached says that unread lines remain beyond what was loaded.
        let mut steps = Vec::new();
        joined(&mut steps);
        page(
            &mut steps,
            "CHATHISTORY AFTER #r timestamp=2026-07-30T12:00:00.000Z 2",
            &[
                "@batch=h;msgid=a :x!u@h PRIVMSG #r :1",
                "@batch=h;msgid=b :x!u@h PRIVMSG #r :2",
            ],
        );
        page(
            &mut steps,
            "CHATHISTORY AFTER #r msgid=b 1",
            &["@batch=h;msgid=c :x!u@h PRIVMSG #r :3"],
        );
        let (mut connection, server) = scripted(steps);
        let history = connection
            .join_with_history("#r", 2, 3)
            .await
            .expect("history");
        assert_eq!(history.coverage, HistoryCoverage::UnreadBeyondLoaded);
        drop(connection);
        assert_eq!(server.await.unwrap(), Vec::<String>::new());
    }

    /// A name under `.localhost` is whatever a resolver answers. Credentials
    /// cross in cleartext only when every resolved address is loopback, and
    /// then exactly those addresses are dialed.
    #[tokio::test]
    async fn a_localhost_name_is_trusted_only_for_what_it_resolves_to() {
        let mut options = anonymous(
            "irc.localhost:6667".into(),
            std::time::Duration::from_secs(2),
        );
        options.authentication = Authentication::Plain {
            account: "account".into(),
            password: "secret".into(),
        };
        for resolved in [
            vec!["192.0.2.1:6667"],
            vec!["127.0.0.1:6667", "192.0.2.1:6667"],
            vec!["[::ffff:192.0.2.1]:6667"],
            vec![],
        ] {
            let addresses: Vec<std::net::SocketAddr> =
                resolved.iter().map(|a| a.parse().unwrap()).collect();
            let error =
                must_give_up(options.connect_and_register(|_| async move { Ok(addresses) })).await;
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "{resolved:?}: {error}"
            );
            assert!(error.to_string().contains("cleartext"), "{error}");
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let loopback = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let (socket, _) = listener.accept().await.unwrap();
            let mut lines = tokio::io::BufReader::new(socket).lines();
            lines.next_line().await.unwrap()
        });
        let error = must_give_up(options.connect_and_register(|requested| async move {
            assert_eq!(requested, "irc.localhost:6667");
            Ok(vec![loopback])
        }))
        .await;
        assert_ne!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
        assert_eq!(
            accepted.await.unwrap().as_deref(),
            Some("CAP LS 302"),
            "the resolved loopback address is the one dialed"
        );
    }

    #[test]
    fn refusals_are_error_numerics_and_fail() {
        let parsed = |line: &str| OwnedMessage::from(&Message::parse(line).unwrap());
        for refusal in [
            ":srv 404 me #c :Cannot send to channel",
            ":srv 486 me bob :You must log in to message this user",
            ":srv 473 me #c :Cannot join channel (+i)",
            ":srv 599 me :x",
            ":srv FAIL PRIVMSG CANNOT_SEND #c :no",
        ] {
            assert!(is_refusal(&parsed(refusal)), "{refusal}");
        }
        for other in [
            ":srv 311 me bob u h * :Bob",
            ":srv 366 me #c :End",
            ":srv 600 me :x",
            ":srv WARN X Y :z",
            ":bob!u@h PRIVMSG #c :400",
        ] {
            assert!(!is_refusal(&parsed(other)), "{other}");
        }
    }

    #[test]
    fn irc_formatting_is_stripped_before_text_is_shown() {
        for (formatted, plain) in [
            ("\x02bold\x02 text", "bold text"),
            ("\x034red\x03 \x0304,12both\x03", "red both"),
            ("\x03,5comma\x03", ",5comma"),
            ("\x0312,x", ",x"),
            ("\x04ff0000hex\x04ff0000,00ff00bg", "hexbg"),
            (
                "\x1ditalic\x1f under\x1estrike\x11mono\x16rev\x0f",
                "italic understrikemonorev",
            ),
            ("\x03999", "9"),
        ] {
            assert_eq!(strip_formatting(formatted), plain, "{formatted:?}");
        }
        assert_eq!(
            TerminalSafe::from_irc_text("\x02hi\x02\x1b[2J").as_str(),
            "hi\u{fffd}[2J"
        );
    }

    /// Every wait after `QUIT` is bounded: a server that keeps the socket open
    /// ends it with a timeout rather than holding the caller forever.
    #[tokio::test]
    async fn the_wait_after_quit_is_bounded() {
        let (mut connection, server_io) = duplex_connection(16 * 1024);
        connection.response_deadline = Some(std::time::Duration::from_millis(150));
        let (_reader, writer) = tokio::io::split(server_io);
        let peer = tokio::spawn(chatter(writer));
        let mut seen = 0;
        let error = must_give_up(connection.quit_and_drain("done", |_| {
            seen += 1;
            Ok(())
        }))
        .await;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(seen > 0, "lines read on the way are handed on");
        peer.abort();
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
