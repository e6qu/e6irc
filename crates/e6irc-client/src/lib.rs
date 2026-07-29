//! Client-side connection library shared by e6irc-cli and e6irc-tui.
//!
//! A thin async wrapper over a TCP stream that frames IRC lines with
//! `e6irc-proto` and drives registration. TLS and SASL layer on top in
//! later work; this is the plaintext core the clients build against.

#![deny(clippy::let_underscore_must_use)]

use std::io;

use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_proto::message::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

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
    /// Complete lines already parsed out of the read buffer.
    pending: std::collections::VecDeque<Vec<u8>>,
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
    /// steady-state loop should use [`Connection::next_message_lossy`] so one bad
    /// line can't end the session.
    pub async fn next_message(&mut self) -> io::Result<Option<OwnedMessage>> {
        Ok(self.next_message_with_line().await?.map(|(msg, _)| msg))
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
            if let Some(line) = self.pending.pop_front() {
                let text = std::str::from_utf8(&line).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "server sent a non-UTF-8 line")
                })?;
                let msg = Message::parse(text).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("server sent an unparseable line: {e:?}"),
                    )
                })?;
                return Ok(Some((OwnedMessage::from(&msg), text.to_string())));
            }
            let n = self.reader.read(&mut self.read_buf).await?;
            if n == 0 {
                return Ok(None);
            }
            let mut events = Vec::new();
            self.framing.feed(&self.read_buf[..n], &mut events);
            for event in events {
                match event {
                    LineEvent::Line(line) => self.pending.push_back(line),
                    // The framing layer's contract (framing.rs) is that the
                    // caller must handle overflow loudly, never drop it.
                    LineEvent::TooLong => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "server sent an over-long line",
                        ));
                    }
                }
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
    /// The distinct outcomes make the "a recoverable per-line error is a fatal
    /// stream error" conflation unrepresentable at the call site: `Ok(Some(_))`
    /// is always a line to relay (parsed or not), `Ok(None)` is a genuine EOF,
    /// and `Err` is a real I/O error — only the last two end the stream. An
    /// over-long line, which cannot be relayed within the wire limit anyway, is
    /// skipped (the framing layer has already discarded its tail) without ending
    /// the stream. Kept separate from [`Connection::next_message_with_line`],
    /// whose strict error-on-bad-line contract the handshake relies on.
    pub async fn next_line_relayable(
        &mut self,
    ) -> io::Result<Option<(Option<OwnedMessage>, String)>> {
        loop {
            if let Some(line) = self.pending.pop_front() {
                // Lossy: an invalid byte sequence becomes U+FFFD instead of
                // failing the whole read (mirrors the in-process local driver).
                let text = String::from_utf8_lossy(&line).into_owned();
                // Best-effort parse; `None` means "relay only, don't act on it".
                let parsed = Message::parse(&text).ok().map(|m| OwnedMessage::from(&m));
                return Ok(Some((parsed, text)));
            }
            let n = self.reader.read(&mut self.read_buf).await?;
            if n == 0 {
                return Ok(None);
            }
            let mut events = Vec::new();
            self.framing.feed(&self.read_buf[..n], &mut events);
            for event in events {
                match event {
                    LineEvent::Line(line) => self.pending.push_back(line),
                    // Un-relayable within the wire limit; the framing already
                    // dropped its tail, so skip it and keep the link — never
                    // drop the whole connection over one over-long line.
                    LineEvent::TooLong => {}
                }
            }
        }
    }

    /// Steady-state read for an *interactive* client (the TUI, `tail`): tolerant
    /// of a single bad line, so a hostile or merely-noisy server cannot end the
    /// session with one. A non-UTF-8 line is lossily decoded (invalid bytes →
    /// U+FFFD) and parsed — IRC bodies carry arbitrary bytes (Latin-1/Shift-JIS
    /// are routine), so a high-byte channel message any member can post must not
    /// disconnect the victim. A line that still won't parse after lossy decoding
    /// is skipped (kept off the acted-on path) rather than tearing down the link.
    /// Distinct from [`Connection::next_message`], whose strict error-on-bad-line
    /// contract the handshake deliberately relies on.
    pub async fn next_message_lossy(&mut self) -> io::Result<Option<OwnedMessage>> {
        loop {
            match self.next_line_relayable().await? {
                None => return Ok(None),
                Some((Some(msg), _)) => return Ok(Some(msg)),
                // Lossy-decoded but unparseable: skip and keep the link alive.
                Some((None, _)) => continue,
            }
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

    /// `CAP LS` then request `sasl`, returning once the server ACKs it (or
    /// erroring on NAK). The shared prologue of every SASL path.
    async fn negotiate_sasl_cap(&mut self) -> io::Result<()> {
        self.send_line("CAP LS 302").await?;
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

    /// Wait for the server's empty `AUTHENTICATE +` challenge after a mechanism
    /// has been offered.
    async fn await_authenticate_challenge(&mut self) -> io::Result<()> {
        loop {
            let msg = self.recv("closed during SASL").await?;
            // A SASL-refusal or registration-refusal numeric here is terminal —
            // otherwise a server that rejects the mechanism (904/905/906/908) or
            // the nick (433, ...) and holds the socket open hangs this loop
            // forever. The sibling wait loops already do this; this one was
            // missed.
            if let Some(err) = registration_refused(&msg.command) {
                return Err(err);
            }
            match msg.command.as_str() {
                "AUTHENTICATE" => return Ok(()),
                "902" | "904" | "905" | "906" | "908" => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SASL authentication failed",
                    ));
                }
                // Answer PINGs so auth can't be ping-timeout-killed.
                _ => {
                    self.answer_ping(&msg).await?;
                }
            }
        }
    }

    /// After the credential is sent: wait for the SASL verdict, finish CAP on
    /// success (903), then wait for the welcome (001). The shared epilogue of
    /// every SASL path — waiting for the verdict before `CAP END` so the server
    /// can't complete registration ahead of it and mask a failure.
    async fn finish_sasl_then_welcome(&mut self, nick: &str) -> io::Result<String> {
        loop {
            let msg = self.recv("closed during SASL").await?;
            // A registration-refusal numeric can arrive here, before the
            // welcome — e.g. the server rejects the requested NICK (433) the
            // moment it is sent, mid-SASL. Treat it as terminal in this loop
            // too, or CAP END is sent and await_welcome blocks forever.
            if let Some(err) = registration_refused(&msg.command) {
                return Err(err);
            }
            match msg.command.as_str() {
                // 903 RPL_SASLSUCCESS: authenticated — now finish CAP.
                "903" => {
                    self.send_line("CAP END").await?;
                    break;
                }
                "902" | "904" | "905" | "906" | "908" => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SASL authentication failed",
                    ));
                }
                _ => {
                    self.answer_ping(&msg).await?;
                }
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
            if let Some(err) = registration_refused(&msg.command) {
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
        self.negotiate_sasl_cap().await?;
        // Best-effort: request the message-tag caps so the bouncer receives
        // server-time/msgid/account and can preserve them in backlog. Each is
        // requested separately (an atomic multi-cap REQ would lose all on one
        // NAK); a NAK just means that cap isn't enabled. The ACK/NAK replies
        // are ignored below — the server enables the ACKed caps regardless.
        for cap in ["server-time", "message-tags", "account-tag"] {
            self.send_line(&format!("CAP REQ :{cap}")).await?;
        }
        self.send_line("AUTHENTICATE PLAIN").await?;
        self.await_authenticate_challenge().await?;
        let payload = {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(account.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(password.as_bytes());
            e6irc_proto::base64::encode(&bytes)
        };
        // Send registration info while CAP is still open, then the credentials.
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
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
        self.send_line("AUTHENTICATE OAUTHBEARER").await?;
        self.await_authenticate_challenge().await?;
        // RFC 7628 client response: gs2 header, then the bearer credential.
        let payload =
            e6irc_proto::base64::encode(format!("n,,\x01auth=Bearer {token}\x01\x01").as_bytes());
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
        self.send_line(&format!("AUTHENTICATE {payload}")).await?;
        self.finish_sasl_then_welcome(nick).await
    }

    /// Register with a nick and realname, answering PINGs, until the
    /// welcome (001) arrives. Returns the confirmed nick.
    pub async fn register(&mut self, nick: &str, realname: &str) -> io::Result<String> {
        // Negotiate message-tag caps (best-effort) so an IRC upstream sends
        // server-time/msgid/account for backlog preservation, then register.
        // ACK/NAK replies are ignored below; the server enables the ACKed caps.
        self.send_line("CAP LS 302").await?;
        for cap in ["server-time", "message-tags", "account-tag"] {
            self.send_line(&format!("CAP REQ :{cap}")).await?;
        }
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
        self.send_line("CAP END").await?;
        self.await_welcome(nick).await
    }
}

/// Map a registration-refusal numeric to a terminal error, if it is one. These
/// are the replies a server sends when it will not complete registration for
/// the requested nick/credentials; a client that keeps waiting for `001` after
/// one of them hangs forever.
fn registration_refused(command: &str) -> Option<io::Error> {
    match command {
        "433" => Some(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "nickname in use",
        )),
        "432" | "451" | "464" | "465" => Some(io::Error::other(format!(
            "registration refused ({command})"
        ))),
        _ => None,
    }
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

    #[tokio::test]
    async fn register_sasl_fails_loudly_on_reject_numeric() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A server that ACKs sasl, then answers the AUTHENTICATE with a 904
        // failure numeric and holds the socket open. Without the terminal-numeric
        // handling in `await_authenticate_challenge`, this loops forever; with it,
        // register_sasl returns an error promptly.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));

        let server = tokio::spawn(async move {
            let (sr, mut sw) = tokio::io::split(server_io);
            sw.write_all(b":srv CAP * ACK :sasl\r\n").await.unwrap();
            sw.write_all(b":srv 904 * :SASL authentication failed\r\n")
                .await
                .unwrap();
            // Keep draining and holding the socket open so the client can't rely
            // on EOF to unblock — the failure must come from the numeric itself.
            let mut reader = sr;
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
    async fn next_message_lossy_survives_non_utf8_line() {
        use tokio::io::AsyncWriteExt;
        // A Latin-1 body (0xE9 = 'é') any channel member can post is not valid
        // UTF-8. Strict `next_message` errors on it (the handshake wants that);
        // the interactive steady-state read must lossily decode and keep going.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client_io);
        let mut conn = Connection::from_halves(Box::new(cr), Box::new(cw));

        let (_sr, mut sw) = tokio::io::split(server_io);
        sw.write_all(b":nick PRIVMSG #c :caf\xe9\r\n")
            .await
            .unwrap();
        sw.write_all(b":nick PRIVMSG #c :ok\r\n").await.unwrap();

        // The high-byte line comes back lossily decoded (é -> U+FFFD), not as an
        // error that would tear down the session.
        let first = conn.next_message_lossy().await.unwrap().unwrap();
        assert_eq!(first.command, "PRIVMSG");
        assert_eq!(first.params.get(1).map(String::as_str), Some("caf\u{fffd}"));
        let second = conn.next_message_lossy().await.unwrap().unwrap();
        assert_eq!(second.params.get(1).map(String::as_str), Some("ok"));

        drop(conn);
        drop(sw);
    }
}
