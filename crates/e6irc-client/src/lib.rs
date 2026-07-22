//! Client-side connection library shared by e6irc-cli and e6irc-tui.
//!
//! A thin async wrapper over a TCP stream that frames IRC lines with
//! `e6irc-proto` and drives registration. TLS and SASL layer on top in
//! later work; this is the plaintext core the clients build against.

use std::io;

use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_proto::message::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

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
        stream.set_nodelay(true).ok();
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
        install_crypto_provider();
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
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

    /// Send one raw line (CRLF appended).
    pub async fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.writer.flush().await
    }

    /// Read the next server message, blocking until one arrives or the
    /// connection closes (`None`). Over-long and malformed lines are
    /// skipped.
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
            while let Some(line) = self.pending.pop_front() {
                if let Ok(text) = std::str::from_utf8(&line)
                    && let Ok(msg) = Message::parse(text)
                {
                    return Ok(Some((OwnedMessage::from(&msg), text.to_string())));
                }
            }
            let n = self.reader.read(&mut self.read_buf).await?;
            if n == 0 {
                return Ok(None);
            }
            let mut events = Vec::new();
            self.framing.feed(&self.read_buf[..n], &mut events);
            for event in events {
                if let LineEvent::Line(line) = event {
                    self.pending.push_back(line);
                }
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
                _ => {}
            }
        }
    }

    /// Wait for the server's empty `AUTHENTICATE +` challenge after a mechanism
    /// has been offered.
    async fn await_authenticate_challenge(&mut self) -> io::Result<()> {
        loop {
            let msg = self.recv("closed during SASL").await?;
            if msg.command == "AUTHENTICATE" {
                return Ok(());
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
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
}
