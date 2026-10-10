//! A bouncer attach as a session of the core link (DESIGN §19.1, §19.2): the
//! edge accepts the attaching client, terminates its TLS, frames its lines and
//! writes to it (`e6irc_edge::connection::serve_conn`, through the
//! [`AttachPort`]); the attach logic here — registration, SASL, the relay —
//! reads its lines ([`ClientLines`]) and writes to it through the session's
//! link ([`e6irc_edge::link::LineWriter`]).
//!
//! What the attach logic sees is what it saw of its socket. A write waits for
//! room and a flush for everything to be on the client socket, so a client
//! that stops reading holds the attachment's writer as its socket did, bounded
//! by the same write deadline, and is detached as too slow when it passes —
//! never killed for "SendQ exceeded". Its lines arrive in the batches the edge
//! framed them in; the client closing reads as the end of input, and a failed
//! read or write as the error it was.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use e6irc_edge::address::ClientIp;
use e6irc_edge::connection::{ConnId, ConnectionTransport, CorePort, SessionClosed};
use e6irc_edge::link::{EdgeSession, LineWriter};
use e6irc_edge::meter::CommandFlood;
use e6irc_edge::peer_write::{DeadlineWriter, PEER_WRITE_DEADLINE};
use e6irc_proto::framing::LineEvent;
use e6irc_queue::{Receiver, Sender};

/// The most bytes of an attached client's lines waiting for its attachment to
/// take them: the credit its reader at the edge waits for. As much as one read
/// of its socket framed before, so the edge reads ahead no further than the
/// attachment itself used to.
pub(crate) const ATTACH_INBOUND_BYTES: usize = 8 * 1024;

/// What the edge hands an attachment: a framed line, or how the client's side
/// ended (the `Line`, `OverlongLine` and `Closed` frames).
#[derive(Debug)]
enum Inbound {
    Line(LineEvent),
    Closed(SessionClosed),
}

fn inbound_weight(inbound: &Inbound) -> usize {
    match inbound {
        Inbound::Line(LineEvent::Line(line)) => line.len(),
        Inbound::Line(LineEvent::TooLong { .. }) | Inbound::Closed(_) => 1,
    }
}

/// One attaching client as its attachment reaches it: its lines, and the
/// bounded writer its output goes through.
pub struct AttachLink {
    pub(super) lines: ClientLines,
    pub(super) write: DeadlineWriter<LineWriter>,
    /// When its edge holds it for the next core (link version 2): what its
    /// record is written with.
    pub(super) holding: Option<super::AttachHolding>,
}

/// An attached client's lines, as the edge framed them.
pub struct ClientLines {
    inbound: Receiver<Inbound>,
    /// How the client's side ended, read behind lines not yet handed over.
    ended: Option<SessionClosed>,
    /// Takes this session out of its port when the attachment is over.
    _registration: Registration,
}

impl ClientLines {
    /// Wait for the client's next lines and add them to `events`: `Ok(true)`
    /// with lines, `Ok(false)` once the client has closed, the error once its
    /// connection failed. Cancelling it loses nothing: it takes lines only
    /// once it resolves.
    pub(crate) async fn next_lines(
        &mut self,
        events: &mut Vec<LineEvent>,
    ) -> std::io::Result<bool> {
        if let Some(end) = self.ended.take() {
            return ended(end);
        }
        let Some(first) = self.inbound.pop().await else {
            return Ok(false);
        };
        let before = events.len();
        let mut arrived = Some(first.payload);
        while let Some(inbound) = arrived.take() {
            match inbound {
                Inbound::Line(event) => events.push(event),
                Inbound::Closed(end) if events.len() == before => return ended(end),
                Inbound::Closed(end) => {
                    self.ended = Some(end);
                    break;
                }
            }
            arrived = self.inbound.try_pop().map(|envelope| envelope.payload);
        }
        Ok(true)
    }
}

/// The end of a client's input, as reading its socket reported it.
fn ended(end: SessionClosed) -> std::io::Result<bool> {
    match end {
        SessionClosed::ByClient => Ok(false),
        SessionClosed::ReadFailed(error) => Err(std::io::Error::other(error)),
        SessionClosed::WriteFailed(failure) => Err(failure.into_error()),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            other.to_string(),
        )),
    }
}

/// A session's place in its [`AttachPort`], given up when its attachment is
/// over, so a line arriving after that finds no attachment to go to.
struct Registration {
    conn: ConnId,
    sessions: Arc<Sessions>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.sessions.remove(self.conn);
    }
}

/// Each live attach session's queue of lines, by its identifier.
#[derive(Default)]
struct Sessions(Mutex<HashMap<ConnId, Sender<Inbound>>>);

impl Sessions {
    fn insert(&self, conn: ConnId, sender: Sender<Inbound>) {
        let previous = self
            .0
            .lock()
            .expect("attach sessions poisoned")
            .insert(conn, sender);
        assert!(previous.is_none(), "a session identifier is never reused");
    }

    fn get(&self, conn: ConnId) -> Option<Sender<Inbound>> {
        self.0
            .lock()
            .expect("attach sessions poisoned")
            .get(&conn)
            .cloned()
    }

    fn remove(&self, conn: ConnId) -> Option<Sender<Inbound>> {
        self.0
            .lock()
            .expect("attach sessions poisoned")
            .remove(&conn)
    }
}

/// The core as the attach listener's connections reach it: each session the
/// edge opens is handed, as an [`AttachLink`], to `serve` — the attach logic
/// in production — with its client's address; its lines go to that session's
/// own queue, whose room is the credit its reader waits for. Attach sessions
/// are not metered, as they were not.
#[derive(Clone)]
pub struct AttachPort {
    sessions: Arc<Sessions>,
    serve: Arc<dyn Fn(AttachLink, ClientIp) + Send + Sync>,
    /// What resumes an attachment a rebuild takes from its edge's record.
    resume: Arc<dyn Fn(AttachLink, ClientIp, crate::core::record::AttachRecord) + Send + Sync>,
}

/// How an attachment's link is handed over: to the attach logic from its
/// registration, or to resume from its record.
enum Handoff {
    Serve,
    Resume(Box<crate::core::record::AttachRecord>),
}

impl AttachPort {
    pub fn new(
        serve: impl Fn(AttachLink, ClientIp) + Send + Sync + 'static,
        resume: impl Fn(AttachLink, ClientIp, crate::core::record::AttachRecord) + Send + Sync + 'static,
    ) -> Self {
        Self {
            sessions: Arc::default(),
            serve: Arc::new(serve),
            resume: Arc::new(resume),
        }
    }

    /// Open an attachment whose edge holds it for the next core (link version
    /// 2), its record written in `format`.
    pub(crate) fn open_holding(
        &self,
        conn: ConnId,
        address: std::net::IpAddr,
        sendq_bytes: usize,
        format: crate::core::RecordFormatCell,
    ) -> EdgeSession {
        let (link, edge) =
            e6irc_edge::link::holding_waiting_session("attach-sendq", sendq_bytes, 0);
        self.hand_over(conn, address, link, Some(format), Handoff::Serve);
        edge
    }

    /// Resume an attachment a rebuild takes from `record`, with `in_flight`
    /// bytes its edge still holds unwritten.
    pub(crate) fn resume(
        &self,
        conn: ConnId,
        address: std::net::IpAddr,
        sendq_bytes: usize,
        in_flight: u64,
        format: crate::core::RecordFormatCell,
        record: crate::core::record::AttachRecord,
    ) -> EdgeSession {
        let (link, edge) =
            e6irc_edge::link::holding_waiting_session("attach-sendq", sendq_bytes, in_flight);
        self.hand_over(
            conn,
            address,
            link,
            Some(format),
            Handoff::Resume(Box::new(record)),
        );
        edge
    }

    fn hand_over(
        &self,
        conn: ConnId,
        address: std::net::IpAddr,
        link: e6irc_edge::link::SessionLink,
        format: Option<crate::core::RecordFormatCell>,
        handoff: Handoff,
    ) {
        let (sender, inbound) = e6irc_queue::weighted_queue(
            e6irc_queue::Config {
                name: "attach-inbound",
                capacity: ATTACH_INBOUND_BYTES,
                policy: e6irc_queue::Policy::Fifo,
            },
            inbound_weight,
        );
        self.sessions.insert(conn, sender);
        let lines = ClientLines {
            inbound,
            ended: None,
            _registration: Registration {
                conn,
                sessions: self.sessions.clone(),
            },
        };
        let link = AttachLink {
            lines,
            write: DeadlineWriter::new(LineWriter::new(link), PEER_WRITE_DEADLINE),
            holding: format.map(super::AttachHolding::unnamed),
        };
        match handoff {
            Handoff::Serve => (self.serve)(link, ClientIp::new(address)),
            Handoff::Resume(record) => (self.resume)(link, ClientIp::new(address), *record),
        }
    }
}

impl CorePort for AttachPort {
    async fn open(
        &self,
        conn: ConnId,
        host: String,
        _transport: ConnectionTransport,
        _tls: Option<e6irc_link::TlsFacts>,
        sendq_bytes: usize,
    ) -> Option<EdgeSession> {
        let address = host
            .parse::<std::net::IpAddr>()
            .expect("the edge opens a session under its client's address");
        let (link, edge) = e6irc_edge::link::waiting_session("attach-sendq", sendq_bytes);
        // Its own edge holds nothing for another core.
        self.hand_over(conn, address, link, None, Handoff::Serve);
        Some(edge)
    }

    fn command_flood(&self) -> Option<CommandFlood> {
        None
    }

    async fn push(&self, conn: ConnId, event: LineEvent) -> bool {
        match self.sessions.get(conn) {
            Some(sender) => sender.push(Inbound::Line(event)).await.is_ok(),
            // The attachment is over: the edge stops reading.
            None => false,
        }
    }

    async fn closed(&self, conn: ConnId, reason: SessionClosed) {
        if let Some(sender) = self.sessions.remove(conn) {
            // An attachment that is over has nothing to be told.
            drop(sender.push(Inbound::Closed(reason)).await);
        }
    }
}

/// An [`AttachLink`] for a client on `stream`, served by the edge exactly as
/// the attach listener serves an accepted connection.
#[cfg(test)]
pub(crate) async fn over_stream<S>(stream: S) -> AttachLink
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    struct Uncounted;
    impl e6irc_edge::connection::TransportTelemetry for Uncounted {
        fn record_error(&self, _kind: e6irc_edge::connection::TransportError) {}
        fn record_connection_rejected(&self) {}
    }
    let (opened, link) = tokio::sync::oneshot::channel();
    let opened = Mutex::new(Some(opened));
    let port = AttachPort::new(
        move |link, _client| {
            let opened = opened.lock().expect("test port").take();
            if let Some(opened) = opened {
                drop(opened.send(link));
            }
        },
        |_, _, _| unreachable!("the test port resumes nothing"),
    );
    tokio::spawn(e6irc_edge::connection::serve_conn(
        stream,
        e6irc_edge::connection::AcceptedConnection {
            conn: ConnId(1),
            peer: "192.0.2.1:6697".parse().expect("test peer"),
            transport: ConnectionTransport::Tcp,
            task: e6irc_edge::connection::ConnectionTasks::default().task(),
            tls: None,
        },
        port,
        e6irc_edge::connection::Outbound::with_sendq(64 * 1024),
        Arc::new(Uncounted),
    ));
    link.await.expect("the edge opened the session")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn port_handing_over(
        opened: tokio::sync::mpsc::UnboundedSender<(AttachLink, ClientIp)>,
    ) -> AttachPort {
        AttachPort::new(
            move |link, client| drop(opened.send((link, client))),
            |_, _, _| unreachable!("the test port resumes nothing"),
        )
    }

    /// Lines the edge handed over arrive in the batch they came in, the end
    /// read behind them is the end once they are taken, and each kind of end
    /// reads as reading the socket reported it.
    #[tokio::test]
    async fn lines_arrive_in_batches_and_each_end_reads_as_the_socket_did() {
        let (opened, mut sessions) = tokio::sync::mpsc::unbounded_channel();
        let port = port_handing_over(opened);
        let _edge = port
            .open(
                ConnId(7),
                "192.0.2.9".into(),
                ConnectionTransport::Tcp,
                None,
                4096,
            )
            .await
            .expect("opened");
        let (mut link, client) = sessions.recv().await.expect("handed over");
        assert_eq!(client.to_string(), "192.0.2.9");
        for line in ["NICK a", "USER a 0 * :a"] {
            assert!(port.push(ConnId(7), LineEvent::Line(line.into())).await);
        }
        port.closed(ConnId(7), SessionClosed::ByClient).await;
        let mut events = Vec::new();
        assert!(link.lines.next_lines(&mut events).await.expect("lines"));
        assert_eq!(events.len(), 2);
        assert!(!link.lines.next_lines(&mut events).await.expect("closed"));
        assert!(
            !port.push(ConnId(7), LineEvent::Line("late".into())).await,
            "a session told it ended takes no more lines"
        );

        for (conn, end, stalled) in [
            (
                8,
                SessionClosed::WriteFailed(e6irc_edge::peer_write::SendFailure::Stalled),
                true,
            ),
            (9, SessionClosed::ReadFailed("reset".into()), false),
        ] {
            let _edge = port
                .open(
                    ConnId(conn),
                    "192.0.2.9".into(),
                    ConnectionTransport::Tcp,
                    None,
                    4096,
                )
                .await
                .expect("opened");
            let (mut link, _) = sessions.recv().await.expect("handed over");
            port.closed(ConnId(conn), end).await;
            let error = link
                .lines
                .next_lines(&mut Vec::new())
                .await
                .expect_err("a failed connection");
            assert_eq!(e6irc_edge::peer_write::is_stalled(&error), stalled);
        }
    }

    /// An attachment that is over gives up its place: the edge's next line
    /// for it is refused, which stops the edge reading.
    #[tokio::test]
    async fn an_attachment_that_is_over_takes_no_lines() {
        let (opened, mut sessions) = tokio::sync::mpsc::unbounded_channel();
        let port = port_handing_over(opened);
        let _edge = port
            .open(
                ConnId(3),
                "192.0.2.9".into(),
                ConnectionTransport::Tcp,
                None,
                4096,
            )
            .await
            .expect("opened");
        drop(sessions.recv().await.expect("handed over"));
        assert!(!port.push(ConnId(3), LineEvent::Line("PING x".into())).await);
    }

    /// End to end over the edge: what the attach logic writes reaches the
    /// client, what the client sends reaches the attach logic, and the client
    /// closing reads as the end of its input.
    #[tokio::test]
    async fn an_attach_link_carries_both_ways_over_the_edge() {
        let (mut client, server) = tokio::io::duplex(4096);
        let AttachLink {
            mut lines,
            mut write,
            holding: _,
        } = over_stream(server).await;
        write
            .write_all(b":bnc NOTICE * :hello\r\n")
            .await
            .expect("write");
        write.flush().await.expect("on the socket");
        let mut greeting = [0u8; 22];
        client.read_exact(&mut greeting).await.expect("read");
        assert_eq!(&greeting, b":bnc NOTICE * :hello\r\n");
        client.write_all(b"PING :x\r\n").await.expect("send");
        let mut events = Vec::new();
        assert!(lines.next_lines(&mut events).await.expect("a line"));
        assert_eq!(events, [LineEvent::Line(b"PING :x".to_vec())]);
        client.shutdown().await.expect("close");
        assert!(!lines.next_lines(&mut events).await.expect("closed"));
    }
}
