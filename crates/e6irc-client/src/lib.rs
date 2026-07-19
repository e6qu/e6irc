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

impl OwnedMessage {
    fn from(msg: &Message) -> Self {
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
            framing: LineBuffer::new(4096 + 510),
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
        loop {
            while let Some(line) = self.pending.pop_front() {
                if let Ok(text) = std::str::from_utf8(&line)
                    && let Ok(msg) = Message::parse(text)
                {
                    return Ok(Some(OwnedMessage::from(&msg)));
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

    /// Register with SASL PLAIN: authenticate as `account`/`password`
    /// during CAP negotiation, then register `nick`.
    pub async fn register_sasl(
        &mut self,
        nick: &str,
        realname: &str,
        account: &str,
        password: &str,
    ) -> io::Result<String> {
        self.send_line("CAP LS 302").await?;
        self.send_line("CAP REQ :sasl").await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during CAP",
                ));
            };
            match msg.params.get(1).map(String::as_str) {
                Some("ACK") if msg.command == "CAP" => break,
                Some("NAK") if msg.command == "CAP" => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server refused SASL",
                    ));
                }
                _ => {}
            }
        }
        self.send_line("AUTHENTICATE PLAIN").await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during SASL",
                ));
            };
            if msg.command == "AUTHENTICATE" {
                break;
            }
        }
        let payload = {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(account.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(password.as_bytes());
            e6irc_proto::base64::encode(&bytes)
        };
        // Send registration info while CAP is still open, then the
        // credentials — but wait for the SASL *result* before CAP END,
        // so the server doesn't complete registration (001) ahead of the
        // verdict and mask a failure.
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
        self.send_line(&format!("AUTHENTICATE {payload}")).await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during SASL",
                ));
            };
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
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    self.send_line(&format!("PONG :{token}")).await?;
                }
                _ => {}
            }
        }
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed before welcome",
                ));
            };
            match msg.command.as_str() {
                "001" => {
                    return Ok(msg
                        .params
                        .first()
                        .cloned()
                        .unwrap_or_else(|| nick.to_string()));
                }
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    self.send_line(&format!("PONG :{token}")).await?;
                }
                _ => {}
            }
        }
    }

    /// Register with SASL OAUTHBEARER: authenticate with `token` (an
    /// e6irc API token) during CAP negotiation, then register `nick`.
    pub async fn register_oauthbearer(
        &mut self,
        nick: &str,
        realname: &str,
        token: &str,
    ) -> io::Result<String> {
        self.send_line("CAP LS 302").await?;
        self.send_line("CAP REQ :sasl").await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during CAP",
                ));
            };
            match msg.params.get(1).map(String::as_str) {
                Some("ACK") if msg.command == "CAP" => break,
                Some("NAK") if msg.command == "CAP" => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server refused SASL",
                    ));
                }
                _ => {}
            }
        }
        self.send_line("AUTHENTICATE OAUTHBEARER").await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during SASL",
                ));
            };
            if msg.command == "AUTHENTICATE" {
                break;
            }
        }
        // RFC 7628 client response: gs2 header, then the bearer credential.
        let payload =
            e6irc_proto::base64::encode(format!("n,,\x01auth=Bearer {token}\x01\x01").as_bytes());
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
        self.send_line(&format!("AUTHENTICATE {payload}")).await?;
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed during SASL",
                ));
            };
            match msg.command.as_str() {
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
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    self.send_line(&format!("PONG :{token}")).await?;
                }
                _ => {}
            }
        }
        loop {
            let Some(msg) = self.next_message().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed before welcome",
                ));
            };
            match msg.command.as_str() {
                "001" => {
                    return Ok(msg
                        .params
                        .first()
                        .cloned()
                        .unwrap_or_else(|| nick.to_string()));
                }
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    self.send_line(&format!("PONG :{token}")).await?;
                }
                _ => {}
            }
        }
    }

    /// Register with a nick and realname, answering PINGs, until the
    /// welcome (001) arrives. Returns the confirmed nick.
    pub async fn register(&mut self, nick: &str, realname: &str) -> io::Result<String> {
        self.send_line(&format!("NICK {nick}")).await?;
        self.send_line(&format!("USER {nick} 0 * :{realname}"))
            .await?;
        while let Some(msg) = self.next_message().await? {
            match msg.command.as_str() {
                "001" => {
                    return Ok(msg
                        .params
                        .first()
                        .cloned()
                        .unwrap_or_else(|| nick.to_string()));
                }
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    self.send_line(&format!("PONG :{token}")).await?;
                }
                "433" => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "nickname in use",
                    ));
                }
                _ => {}
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed before welcome",
        ))
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
