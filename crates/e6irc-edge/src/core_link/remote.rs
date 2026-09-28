//! The edge's end of the core link when the core is another process (DESIGN
//! §19.2): [`RemoteCore`] keeps the edge linked to the core holding the
//! serving lease, and [`RemoteCorePort`] is the [`CorePort`] every session
//! opens through, so the accept, TLS, framing, meter and writer code is the
//! code the single process runs.
//!
//! Each session's link is still the in-process pair of [`crate::link`]: its
//! core end, held here, is fed by the core's frames (`Output`, `Kill`, `End`,
//! the flood exemption), and what the edge's writer reports written travels
//! back as `Drained`. The edge's copy of the send-queue bound is its own cap
//! on a core that over-sends: it never holds more than the core counts in
//! flight, so a refusal is that core's bug, closing the session loudly.
//!
//! Flow control. Lines of an `Irc` session spend one of their stream's
//! credits, which the core grants as it moves lines into the shard's queue;
//! out of credits, readers wait in turn (a fair semaphore), so one noisy
//! session cannot starve the rest. Lines of an `Attach` session and messages
//! of a `Ui` session spend their own session's credit, in bytes, granted as
//! the bouncer takes them.
//!
//! A core that goes — a restart, a crash, a link reset — closes every session
//! the link carried, loudly: an IRC client is sent `ERROR :Closing Link:
//! <host> (server restarting)`, a `/ws/ui` client the WebSocket close 1012
//! (service restart). A session opening while no core is linked waits
//! [`OPEN_WAIT`] for one, and is then closed as `(server unavailable)`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use e6irc_link::{
    ClosedReason, CoreFrame, Credit, EdgeFrame, EdgeName, Hello, ListenerReport, Open, Role,
    SessionId, SessionKind, Slot, Stream, Transport, UiMessage, VersionRange, Welcome,
    WriteFailure,
};
use e6irc_proto::framing::LineEvent;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_rustls::TlsConnector;

use super::io::{FrameReader, keep_alive, write_frame, write_frames};
use crate::connection::{
    ConnId, ConnectionIdAllocator, ConnectionTransport, CorePort, Output, SessionClosed,
    TransportError, TransportTelemetry,
};
use crate::link::{self, CloseFrame, DrainedWatch, EdgeSession, SessionLink};
use crate::meter::CommandFlood;
use crate::peer_write::SendFailure;

/// How long a session opening while no core is linked waits for one.
pub const OPEN_WAIT: Duration = Duration::from_secs(10);

/// How often an unlinked edge tries the next core address.
pub const DIAL_INTERVAL: Duration = Duration::from_millis(250);

/// How long one attempt to reach a core address may take, connection and TLS
/// handshake together.
const DIAL_DEADLINE: Duration = Duration::from_secs(5);

/// Frames queued to one link connection's writer.
const STREAM_QUEUE: usize = 1024;

/// The WebSocket close code a `/ws/ui` client is sent when its core goes
/// (RFC 6455 §7.4.1 registry: "Service Restart").
const CLOSE_SERVICE_RESTART: u16 = 1012;

/// The session-shard a connection identifier belongs to: the core shard that
/// owns it, whose stream carries its frames.
pub fn stream_of(conn: SessionId, streams: usize) -> usize {
    usize::try_from(conn.get() % streams as u64).expect("below the stream count")
}

/// The edge's rule that it speaks to at most one core: the one presenting the
/// highest serving-lease epoch it has accepted (DESIGN §2, `EdgeEpoch`).
#[derive(Debug, Default, Clone, Copy)]
pub struct EdgeEpoch {
    highest: u64,
}

/// A core that presented an epoch lower than one the edge already accepted:
/// it no longer holds the serving lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleCore {
    pub presented: u64,
    pub highest: u64,
}

impl std::fmt::Display for StaleCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the core presents serving-lease epoch {}, lower than epoch {} this edge already \
             accepted: it no longer holds the lease",
            self.presented, self.highest
        )
    }
}

impl EdgeEpoch {
    pub fn highest(self) -> u64 {
        self.highest
    }

    /// Accept a core presenting `epoch`, or refuse one presenting less than
    /// the highest accepted.
    pub fn admit(&mut self, epoch: u64) -> Result<(), StaleCore> {
        if epoch < self.highest {
            return Err(StaleCore {
                presented: epoch,
                highest: self.highest,
            });
        }
        self.highest = epoch;
        Ok(())
    }
}

/// How an edge reaches its core.
pub struct Dialing {
    pub edge: EdgeName,
    /// Each a `host:port`: every address a name resolves to is tried in turn.
    pub core: Vec<String>,
    pub connector: TlsConnector,
    /// What the console shows of this edge's listeners.
    pub listeners: Vec<ListenerReport>,
}

/// The edge's standing with the core: the current link, if any, and what the
/// edge keeps across links.
#[derive(Clone)]
pub struct RemoteCore {
    shared: Arc<Shared>,
}

struct Shared {
    current: watch::Sender<Option<Arc<Link>>>,
    telemetry: Arc<dyn TransportTelemetry>,
    /// Connection identifiers of this edge's slot, re-seeded at each link.
    ids: Arc<ConnectionIdAllocator>,
}

/// One link to one core: its terms and its session streams.
pub struct Link {
    welcome: Welcome,
    flood: Option<CommandFlood>,
    core: SocketAddr,
    /// Who this edge is and how it reaches the core, for the link's HTTP
    /// connections.
    edge: EdgeName,
    connector: TlsConnector,
    streams: Vec<Arc<LinkStream>>,
    over: watch::Sender<bool>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

/// One session stream of a link.
struct LinkStream {
    out: mpsc::Sender<EdgeFrame>,
    /// Lines the core has room for, for this stream's `Irc` sessions.
    credit: Semaphore,
    sessions: Mutex<Sessions>,
}

#[derive(Default)]
struct Sessions {
    live: HashMap<SessionId, RemoteSession>,
    /// The link is over: no session opens on it any more.
    closed: bool,
}

/// One session this edge holds for the core.
struct RemoteSession {
    /// The core's end, as the core's frames drive it.
    proxy: SessionLink,
    kind: SessionKind,
    /// The client's address, for the edge's own closing `ERROR`.
    host: String,
    /// An `Attach` or `Ui` session's own credit, in bytes, and the window the
    /// core granted first.
    credit: Arc<SessionCredit>,
}

struct SessionCredit {
    bytes: Semaphore,
    window: std::sync::atomic::AtomicU32,
}

impl Default for SessionCredit {
    fn default() -> Self {
        Self {
            bytes: Semaphore::new(0),
            window: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl SessionCredit {
    /// What one line or message of `weight` bytes spends: at most the
    /// window, so a line heavier than it still goes, alone.
    async fn spend(&self, weight: usize) -> bool {
        let window = loop {
            let window = self.window.load(std::sync::atomic::Ordering::Acquire);
            if window != 0 {
                break window;
            }
            // Before the first grant: wait for it, as for any other credit.
            match self.bytes.acquire().await {
                Ok(permit) => drop(permit),
                Err(_) => return false,
            }
        };
        let charge = u32::try_from(weight).unwrap_or(u32::MAX).min(window);
        match self.bytes.acquire_many(charge).await {
            Ok(permit) => {
                permit.forget();
                true
            }
            Err(_) => false,
        }
    }
}

/// What a line of `event` weighs against an `Attach` session's credit: the
/// weight its inbound queue gives it in the core.
pub fn attach_line_weight(event: &LineEvent) -> usize {
    match event {
        LineEvent::Line(line) => line.len(),
        LineEvent::TooLong { .. } => 1,
    }
}

/// What a `/ws/ui` message weighs against its session's credit and inbound
/// queues.
pub fn ui_message_weight(message: &UiMessage) -> usize {
    match message {
        UiMessage::Text(text) => text.len(),
        UiMessage::Binary => 1,
    }
}

fn transport_of(transport: ConnectionTransport) -> Transport {
    match transport {
        ConnectionTransport::Tcp => Transport::Tcp,
        ConnectionTransport::Tls => Transport::Tls,
        ConnectionTransport::WebSocket => Transport::WebSocket,
        ConnectionTransport::SecureWebSocket => Transport::SecureWebSocket,
        ConnectionTransport::Local => {
            unreachable!("a local session is the core's own and never crosses a link")
        }
    }
}

/// A session's end on the edge's side, as the link carries it.
pub fn closed_reason(reason: SessionClosed) -> ClosedReason {
    match reason {
        SessionClosed::ByClient => ClosedReason::ByClient,
        SessionClosed::ReadFailed(text) => {
            ClosedReason::ReadFailed(shortened(text, e6irc_link::MAX_CLOSED_TEXT_LEN))
        }
        SessionClosed::MessageTooBig => ClosedReason::MessageTooBig,
        SessionClosed::WriteFailed(SendFailure::Transport) => {
            ClosedReason::WriteFailed(WriteFailure::Transport)
        }
        SessionClosed::WriteFailed(SendFailure::Stalled) => {
            ClosedReason::WriteFailed(WriteFailure::Stalled)
        }
        SessionClosed::WriterPanicked => ClosedReason::WriterPanicked,
        SessionClosed::Stopped(reason) => ClosedReason::Stopped(shortened(
            reason.into_owned(),
            e6irc_link::MAX_CLOSED_TEXT_LEN,
        )),
    }
}

/// A session's end as the core reads it from the link.
pub fn session_closed(reason: ClosedReason) -> SessionClosed {
    match reason {
        ClosedReason::ByClient => SessionClosed::ByClient,
        ClosedReason::ReadFailed(text) => SessionClosed::ReadFailed(text),
        ClosedReason::MessageTooBig => SessionClosed::MessageTooBig,
        ClosedReason::WriteFailed(WriteFailure::Transport) => {
            SessionClosed::WriteFailed(SendFailure::Transport)
        }
        ClosedReason::WriteFailed(WriteFailure::Stalled) => {
            SessionClosed::WriteFailed(SendFailure::Stalled)
        }
        ClosedReason::WriterPanicked => SessionClosed::WriterPanicked,
        ClosedReason::Stopped(reason) => SessionClosed::Stopped(reason.into()),
    }
}

/// `text` cut to at most `bound` bytes on a character boundary.
fn shortened(mut text: String, bound: usize) -> String {
    if text.len() > bound {
        let mut end = bound;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The edge's own closing line for a session whose core cannot answer.
fn closing_line(host: &str, reason: &str) -> Output {
    Output(Bytes::from(format!(
        "ERROR :Closing Link: {host} ({reason})\r\n"
    )))
}

/// A session opened only to be closed at once with `reason`: what a client
/// arriving while no core is linked gets.
fn refused_session(host: &str, reason: &str) -> EdgeSession {
    let (mut proxy, edge) = link::session("edge-refused", 1);
    proxy.kill(closing_line(host, reason));
    edge
}

/// Why the edge closes the sessions a link carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkClose {
    /// The core went: a restart, a crash, or a link reset.
    ServerRestarting,
    /// This edge is stopping.
    EdgeStopping,
}

impl LinkClose {
    fn reason(self) -> &'static str {
        match self {
            Self::ServerRestarting => "server restarting",
            Self::EdgeStopping => "edge shutting down",
        }
    }

    fn close_frame(self) -> CloseFrame {
        match self {
            Self::ServerRestarting => CloseFrame {
                code: CLOSE_SERVICE_RESTART,
                reason: "Server restarting".into(),
            },
            // RFC 6455 §7.4.1: 1001, "going away" — a server going down.
            Self::EdgeStopping => CloseFrame {
                code: 1001,
                reason: "Edge shutting down".into(),
            },
        }
    }
}

impl RemoteSession {
    /// Close the session with the edge's own word: its core is gone, or this
    /// edge is stopping.
    fn end_loudly(mut self, why: LinkClose) {
        match self.kind {
            SessionKind::Ui => self.proxy.close_on_end(why.close_frame()),
            SessionKind::Irc | SessionKind::Attach => {
                let line = closing_line(&self.host, why.reason());
                if self.proxy.output(line.clone()).is_err() {
                    self.proxy.kill(line);
                }
            }
        }
    }
}

impl Link {
    /// The core's terms this link runs on.
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    fn stream(&self, session: SessionId) -> &Arc<LinkStream> {
        &self.streams[stream_of(session, self.streams.len())]
    }

    /// Whether the link is over.
    pub fn over_now(&self) -> bool {
        *self.over.borrow()
    }

    /// Resolves once the link is over.
    pub async fn over(&self) {
        let mut over = self.over.subscribe();
        // The sender lives as long as the link: `wait_for` ends only on the
        // value.
        drop(over.wait_for(|over| *over).await);
    }

    fn end(&self) {
        self.over.send_replace(true);
    }

    /// A new HTTP connection to the core on this link.
    pub async fn http_connection(
        &self,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
        let hello = Hello {
            versions: VersionRange::spoken(),
            role: Role::Serving,
            edge: self.edge.clone(),
            stream: Stream::Http,
            slot: Some(self.welcome.slot),
            highest_epoch: self.welcome.epoch,
            listeners: Vec::new(),
            cut: None,
        };
        let (connection, welcome) = connect(&self.connector, self.core, hello).await?;
        if welcome.epoch != self.welcome.epoch {
            return Err(format!(
                "the HTTP connection was welcomed by another core (epoch {})",
                welcome.epoch
            ));
        }
        Ok(connection)
    }

    /// Close every session the link carried, loudly, and stop its tasks.
    fn tear_down(&self, why: LinkClose) {
        self.end();
        for task in self.tasks.lock().expect("link tasks").drain(..) {
            task.abort();
        }
        for stream in &self.streams {
            stream.credit.close();
            let ended: Vec<RemoteSession> = {
                let mut sessions = stream.sessions.lock().expect("link sessions");
                sessions.closed = true;
                sessions.live.drain().map(|(_, session)| session).collect()
            };
            for session in ended {
                session.credit.bytes.close();
                session.end_loudly(why);
            }
        }
    }
}

impl RemoteCore {
    /// An edge not yet linked. `ids` is re-seeded at each link with the slot
    /// the core gives.
    pub fn new(telemetry: Arc<dyn TransportTelemetry>, ids: Arc<ConnectionIdAllocator>) -> Self {
        Self {
            shared: Arc::new(Shared {
                current: watch::Sender::new(None),
                telemetry,
                ids,
            }),
        }
    }

    /// The port sessions of `kind` open through.
    pub fn port(&self, kind: SessionKind) -> RemoteCorePort {
        RemoteCorePort {
            core: self.clone(),
            kind,
        }
    }

    /// The current link, if the edge is linked.
    pub fn current(&self) -> Option<Arc<Link>> {
        self.shared.current.borrow().clone()
    }

    /// Stop: close every session the current link carries, as this edge
    /// shutting down, and link no more.
    pub fn shut_down(&self) {
        if let Some(link) = self.shared.current.send_replace(None) {
            link.tear_down(LinkClose::EdgeStopping);
        }
    }

    /// The current link, waiting up to `bound` for one.
    pub async fn linked_within(&self, bound: Duration) -> Option<Arc<Link>> {
        let mut current = self.shared.current.subscribe();
        let linked = tokio::time::timeout(bound, current.wait_for(Option::is_some)).await;
        match linked {
            Ok(Ok(link)) => link.clone(),
            _ => None,
        }
    }

    /// Stay linked to the core for as long as the process runs: dial until a
    /// core accepts, serve through it until the link is over, close what it
    /// carried, and dial again. `linked` hears of each link as it is made.
    pub async fn maintain(self, dialing: Dialing, linked: mpsc::UnboundedSender<Arc<Link>>) {
        let mut epoch = EdgeEpoch::default();
        let mut slot: Option<Slot> = None;
        loop {
            let link = self.dial(&dialing, &mut epoch, &mut slot).await;
            eprintln!(
                "e6ircd edge {}: linked to the core at {} (serving-lease epoch {}, link version \
                 {}, slot {}, {} session streams)",
                dialing.edge,
                link.core,
                link.welcome.epoch,
                link.welcome.version,
                link.welcome.slot.get(),
                link.streams.len()
            );
            self.shared.current.send_replace(Some(link.clone()));
            drop(linked.send(link.clone()));
            link.over().await;
            self.shared.current.send_replace(None);
            let carried: usize = link
                .streams
                .iter()
                .map(|stream| stream.sessions.lock().expect("link sessions").live.len())
                .sum();
            link.tear_down(LinkClose::ServerRestarting);
            eprintln!(
                "e6ircd edge {}: the link to the core at {} is over; {carried} sessions were \
                 closed as the server restarting",
                dialing.edge, link.core
            );
        }
    }

    /// Try every core address in turn, every [`DIAL_INTERVAL`], until one
    /// accepts this edge.
    async fn dial(
        &self,
        dialing: &Dialing,
        epoch: &mut EdgeEpoch,
        slot: &mut Option<Slot>,
    ) -> Arc<Link> {
        let mut last_failure = String::new();
        loop {
            for name in &dialing.core {
                let addresses = match tokio::net::lookup_host(name.as_str()).await {
                    Ok(addresses) => addresses.collect::<Vec<_>>(),
                    Err(error) => {
                        note_failure(
                            &mut last_failure,
                            format!("{name} does not resolve: {error}"),
                        );
                        tokio::time::sleep(DIAL_INTERVAL).await;
                        continue;
                    }
                };
                for address in addresses {
                    match self.try_link(dialing, address, epoch, slot).await {
                        Ok(link) => return link,
                        Err(failure) => note_failure(
                            &mut last_failure,
                            format!("the core at {address}: {failure}"),
                        ),
                    }
                    tokio::time::sleep(DIAL_INTERVAL).await;
                }
            }
        }
    }

    /// One link: stream 0's handshake, then every other stream's.
    async fn try_link(
        &self,
        dialing: &Dialing,
        address: SocketAddr,
        epoch: &mut EdgeEpoch,
        slot: &mut Option<Slot>,
    ) -> Result<Arc<Link>, String> {
        let hello = |stream: Stream, slot: Option<Slot>, listeners: Vec<ListenerReport>| Hello {
            versions: VersionRange::spoken(),
            role: Role::Serving,
            edge: dialing.edge.clone(),
            stream,
            slot,
            highest_epoch: epoch.highest(),
            listeners,
            cut: None,
        };
        let (first, welcome) = connect(
            &dialing.connector,
            address,
            hello(
                Stream::Sessions { index: 0 },
                *slot,
                dialing.listeners.clone(),
            ),
        )
        .await?;
        let spoken = VersionRange::spoken();
        if !(spoken.oldest()..=spoken.newest()).contains(&welcome.version) {
            return Err(format!(
                "it chose link version {}, which this edge does not speak",
                welcome.version
            ));
        }
        let flood = match welcome.terms.command_flood {
            Some(terms) => Some(
                CommandFlood::new(terms.burst as usize, terms.rate as usize)
                    .map_err(|error| format!("its command-flood terms: {error}"))?,
            ),
            None => None,
        };
        let mut connections = vec![first];
        for index in 1..welcome.streams {
            let (stream, answer) = connect(
                &dialing.connector,
                address,
                hello(Stream::Sessions { index }, Some(welcome.slot), Vec::new()),
            )
            .await?;
            if answer.epoch != welcome.epoch || answer.slot != welcome.slot {
                return Err(format!(
                    "session stream {index} was welcomed by another core (epoch {}, slot {})",
                    answer.epoch,
                    answer.slot.get()
                ));
            }
            connections.push(stream);
        }
        epoch
            .admit(welcome.epoch)
            .map_err(|stale| stale.to_string())?;
        if *slot != Some(welcome.slot) {
            self.shared.ids.restart_at(seed_for(welcome.slot));
            *slot = Some(welcome.slot);
        }
        let (over, _) = watch::channel(false);
        // Each stream's writer takes the queue its `out` feeds.
        let mut queues = Vec::with_capacity(connections.len());
        let streams: Vec<Arc<LinkStream>> = connections
            .iter()
            .map(|_| {
                let (out, frames) = mpsc::channel(STREAM_QUEUE);
                queues.push(frames);
                Arc::new(LinkStream {
                    out,
                    credit: Semaphore::new(welcome.terms.line_credit as usize),
                    sessions: Mutex::default(),
                })
            })
            .collect();
        let link = Arc::new(Link {
            welcome,
            flood,
            core: address,
            edge: dialing.edge.clone(),
            connector: dialing.connector.clone(),
            streams,
            over,
            tasks: Mutex::default(),
        });
        for ((connection, mut frames), stream) in connections
            .into_iter()
            .zip(queues)
            .zip(link.streams.iter().cloned())
        {
            let (read_half, write_half) = tokio::io::split(connection);
            let writer_link = link.clone();
            let writer = tokio::spawn(async move {
                if let Err(error) = write_frames(write_half, &mut frames).await {
                    eprintln!("e6ircd edge: core link write failed: {error}");
                }
                writer_link.end();
            });
            let reader_link = link.clone();
            let telemetry = self.shared.telemetry.clone();
            let version = link.welcome.version;
            let reader = tokio::spawn(async move {
                if let Err(error) = read_stream(read_half, &stream, version, &*telemetry).await {
                    eprintln!("e6ircd edge: core link read failed: {error}");
                }
                reader_link.end();
            });
            let mut tasks = link.tasks.lock().expect("link tasks");
            tasks.push(writer.abort_handle());
            tasks.push(reader.abort_handle());
        }
        Ok(link)
    }

    /// Open a `/ws/ui` session: the edge's end, and where the client's
    /// messages go — a queue as large as the largest message, which the link
    /// drains as the core's credit allows. `None` when no core is linked
    /// within [`OPEN_WAIT`].
    pub async fn open_ui(
        &self,
        conn: ConnId,
        address: std::net::IpAddr,
        transport: ConnectionTransport,
    ) -> Option<(EdgeSession, e6irc_queue::Sender<UiMessage>)> {
        let link = self.linked_within(OPEN_WAIT).await?;
        let session = SessionId::new(conn.0)?;
        let (proxy, edge) = link::session("edge-ui-sendq", link.welcome.terms.sendq_bytes as usize);
        let watch = proxy.watch_drained();
        let credit = Arc::new(SessionCredit::default());
        let (inbound, messages) = e6irc_queue::weighted_queue(
            e6irc_queue::Config {
                name: "edge-ui-inbound",
                capacity: e6irc_link::MAX_UI_MESSAGE_LEN,
                policy: e6irc_queue::Policy::Fifo,
            },
            ui_message_weight,
        );
        let registered = register(
            &link,
            session,
            RemoteSession {
                proxy,
                kind: SessionKind::Ui,
                host: address.to_string(),
                credit: credit.clone(),
            },
        );
        if !registered {
            return None;
        }
        let stream = link.stream(session).clone();
        let open = EdgeFrame::Open(
            session,
            Open {
                kind: SessionKind::Ui,
                address,
                transport: transport_of(transport),
                tls: None,
            },
        );
        if stream.out.send(open).await.is_err() {
            return None;
        }
        // It ends with the session: its socket loop and writer end with the
        // link, which closes it loudly.
        tokio::spawn(relay_ui(stream, session, watch, messages, credit));
        Some((edge, inbound))
    }
}

/// Say a dial failure once, not once per attempt: an unlinked edge tries
/// every 250 ms.
fn note_failure(last: &mut String, failure: String) {
    if *last != failure {
        eprintln!("e6ircd edge: cannot link: {failure}; retrying");
        *last = failure;
    }
}

/// The first identifier of a fresh count in `slot`: random in the slot's lower
/// half, so the upper half is left to count into and the identifiers of one
/// link are not predictable from another's.
fn seed_for(slot: Slot) -> (NonZeroU64, u64) {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system random number generator");
    let counter = (u64::from_le_bytes(bytes) & ((1u64 << (e6irc_link::SLOT_SHIFT - 1)) - 1)) | 1;
    let first = NonZeroU64::new(slot.first_id() | counter).expect("a non-zero counter");
    let end = slot.first_id() + (1u64 << e6irc_link::SLOT_SHIFT);
    (first, end)
}

/// Connect to `address`, present `hello`, and read the core's answer.
async fn connect(
    connector: &TlsConnector,
    address: SocketAddr,
    hello: Hello,
) -> Result<
    (
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        Welcome,
    ),
    String,
> {
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| format!("cannot connect: {error}"))?;
        keep_alive(&tcp).map_err(|error| format!("cannot set up the connection: {error}"))?;
        connector
            .connect(super::tls::core_server_name(), tcp)
            .await
            .map_err(|error| format!("TLS handshake failed: {error}"))
    };
    let mut tls = tokio::time::timeout(DIAL_DEADLINE, attempt)
        .await
        .map_err(|_| "no answer within the dial deadline".to_string())??;
    let welcome = handshake(&mut tls, hello).await?;
    Ok((tls, welcome))
}

/// Present `hello` on a link connection and read the core's answer.
pub async fn handshake<S>(connection: &mut S, hello: Hello) -> Result<Welcome, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(connection, &EdgeFrame::Hello(hello))
        .await
        .map_err(|error| format!("cannot send Hello: {error}"))?;
    let mut reader = FrameReader::new(&mut *connection);
    let answer = reader
        .first::<CoreFrame>()
        .await
        .map_err(|error| format!("no Welcome: {error}"))?;
    reader
        .into_inner()
        .map_err(|error| format!("after Welcome: {error}"))?;
    match answer {
        CoreFrame::Welcome(welcome) => Ok(welcome),
        CoreFrame::Refused(reason) => Err(format!("refused: {reason}")),
        other => Err(format!("answered Hello with {other:?}")),
    }
}

/// Place `session` on its stream, unless the link is already over.
fn register(link: &Link, session: SessionId, remote: RemoteSession) -> bool {
    let stream = link.stream(session);
    let mut sessions = stream.sessions.lock().expect("link sessions");
    if sessions.closed || sessions.live.contains_key(&session) {
        return false;
    }
    sessions.live.insert(session, remote);
    true
}

/// Carry what the edge writes of `session`'s output back to the core. Once
/// the session's writer is gone the edge holds nothing more of it: whatever
/// the core still sends it is dropped here (its client heard, through
/// `Closed`, why it ended).
async fn report_drained(stream: Arc<LinkStream>, session: SessionId, mut watch: DrainedWatch) {
    while let Some(bytes) = watch.next().await {
        if stream
            .out
            .send(EdgeFrame::Drained(session, bytes))
            .await
            .is_err()
        {
            return;
        }
    }
    stream
        .sessions
        .lock()
        .expect("link sessions")
        .live
        .remove(&session);
}

/// A `/ws/ui` session's traffic to the core: what its client writes back
/// (`Drained`), each message it sends as its credit allows (`Message`), and
/// its end (`Closed`), once both its socket loop and its writer are done.
async fn relay_ui(
    stream: Arc<LinkStream>,
    session: SessionId,
    mut watch: DrainedWatch,
    mut messages: e6irc_queue::Receiver<UiMessage>,
    credit: Arc<SessionCredit>,
) {
    let mut writer_done = false;
    let mut client_done = false;
    while !(writer_done && client_done) {
        tokio::select! {
            written = watch.next(), if !writer_done => match written {
                Some(bytes) => {
                    if stream.out.send(EdgeFrame::Drained(session, bytes)).await.is_err() {
                        return;
                    }
                }
                None => writer_done = true,
            },
            message = messages.pop(), if !client_done => match message {
                Some(envelope) => {
                    let message = envelope.payload;
                    if !credit.spend(ui_message_weight(&message)).await
                        || stream.out.send(EdgeFrame::Message(session, message)).await.is_err()
                    {
                        return;
                    }
                }
                None => client_done = true,
            },
        }
    }
    let reason = match watch.writer_failure() {
        Some(failure) => closed_reason(SessionClosed::WriteFailed(failure)),
        None => ClosedReason::ByClient,
    };
    drop(stream.out.send(EdgeFrame::Closed(session, reason)).await);
}

/// Read one stream's frames from the core and apply each to its session.
async fn read_stream<R>(
    read_half: R,
    stream: &LinkStream,
    version: u16,
    telemetry: &dyn TransportTelemetry,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut reader = FrameReader::new(read_half);
    while let Some(frame) = reader.next::<CoreFrame>().await? {
        if frame.since() > version {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "core link: a frame of link version {} on a link of version {version}",
                    frame.since()
                ),
            ));
        }
        match frame {
            CoreFrame::Output(session, bytes) => {
                let overrun = {
                    let mut sessions = stream.sessions.lock().expect("link sessions");
                    match sessions.live.get_mut(&session) {
                        Some(remote) => match remote.proxy.output(Output(bytes)) {
                            Ok(_) => None,
                            Err(_) => sessions.live.remove(&session),
                        },
                        // Ended here, and the core has not heard yet.
                        None => None,
                    }
                };
                if let Some(mut remote) = overrun {
                    // The core sent past the bound it keeps: its bug, closed
                    // loudly on both sides.
                    telemetry.record_error(TransportError::Write);
                    eprintln!(
                        "e6ircd edge: the core sent session {} more than its send-queue bound; \
                         closing it",
                        session.get()
                    );
                    remote
                        .proxy
                        .kill(closing_line(&remote.host, "edge send queue overrun"));
                    drop(
                        stream
                            .out
                            .send(EdgeFrame::Closed(
                                session,
                                ClosedReason::Stopped("edge send queue overrun".into()),
                            ))
                            .await,
                    );
                }
            }
            CoreFrame::Kill(session, line) => {
                let removed = stream
                    .sessions
                    .lock()
                    .expect("link sessions")
                    .live
                    .remove(&session);
                if let Some(mut remote) = removed {
                    remote.proxy.kill(Output(line));
                }
            }
            CoreFrame::End(session, close) => {
                let removed = stream
                    .sessions
                    .lock()
                    .expect("link sessions")
                    .live
                    .remove(&session);
                if let Some(remote) = removed
                    && let Some(close) = close
                {
                    remote.proxy.close_on_end(CloseFrame {
                        code: close.code,
                        reason: close.reason.into(),
                    });
                }
            }
            CoreFrame::FloodExempt(session, exempt) => {
                let sessions = stream.sessions.lock().expect("link sessions");
                if let Some(remote) = sessions.live.get(&session) {
                    remote.proxy.set_flood_exempt(exempt);
                }
            }
            CoreFrame::Credit(Credit::Stream(lines)) => {
                grant(&stream.credit, lines)?;
            }
            CoreFrame::Credit(Credit::Session(session, bytes)) => {
                let credit = stream
                    .sessions
                    .lock()
                    .expect("link sessions")
                    .live
                    .get(&session)
                    .map(|remote| remote.credit.clone());
                if let Some(credit) = credit {
                    // The first grant is the window every later charge is
                    // bounded by; this reader is the only writer of it.
                    if credit.window.load(std::sync::atomic::Ordering::Acquire) == 0 {
                        credit
                            .window
                            .store(bytes, std::sync::atomic::Ordering::Release);
                    }
                    grant(&credit.bytes, bytes)?;
                }
            }
            CoreFrame::Welcome(_) | CoreFrame::Refused(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "core link: a handshake frame after the handshake",
                ));
            }
            CoreFrame::Pause
            | CoreFrame::Resume
            | CoreFrame::Ack(..)
            | CoreFrame::Record(..)
            | CoreFrame::Replica(_)
            | CoreFrame::CutState(_)
            | CoreFrame::Cut(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "core link: a frame of a cut this edge holds nothing for",
                ));
            }
        }
    }
    Ok(())
}

/// Add `amount` to `credit`; a grant past what a semaphore can hold is a
/// core that grants what it never had.
fn grant(credit: &Semaphore, amount: u32) -> std::io::Result<()> {
    let amount = amount as usize;
    if credit.available_permits().saturating_add(amount) > Semaphore::MAX_PERMITS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "core link: a credit past any bound",
        ));
    }
    credit.add_permits(amount);
    Ok(())
}

/// The core as sessions of one kind reach it across a link.
#[derive(Clone)]
pub struct RemoteCorePort {
    core: RemoteCore,
    kind: SessionKind,
}

impl CorePort for RemoteCorePort {
    /// The session's bound is the core's term, whatever the listener was
    /// configured with: the edge's buffer must be as large as the core's
    /// account of it.
    async fn open(
        &self,
        conn: ConnId,
        host: String,
        transport: ConnectionTransport,
        tls: Option<e6irc_link::TlsFacts>,
        _sendq_bytes: usize,
    ) -> Option<EdgeSession> {
        let Some(link) = self.core.linked_within(OPEN_WAIT).await else {
            return Some(refused_session(&host, "server unavailable"));
        };
        let Some(session) = SessionId::new(conn.0) else {
            return Some(refused_session(&host, "no connection identifier"));
        };
        let Ok(address) = host.parse::<std::net::IpAddr>() else {
            return Some(refused_session(&host, "no client address"));
        };
        let (proxy, edge) = link::session("edge-sendq", link.welcome.terms.sendq_bytes as usize);
        let watch = proxy.watch_drained();
        let registered = register(
            &link,
            session,
            RemoteSession {
                proxy,
                kind: self.kind,
                host: host.clone(),
                credit: Arc::default(),
            },
        );
        if !registered {
            return Some(refused_session(&host, "server restarting"));
        }
        let stream = link.stream(session).clone();
        let open = EdgeFrame::Open(
            session,
            Open {
                kind: self.kind,
                address,
                transport: transport_of(transport),
                // A version 1 core reads no TLS facts.
                tls: tls.filter(|_| link.welcome.version >= 2),
            },
        );
        // A link that ends here closes the session loudly as it tears down.
        // The report ends with the session's writer.
        if stream.out.send(open).await.is_ok() {
            tokio::spawn(report_drained(stream, session, watch));
        }
        Some(edge)
    }

    fn command_flood(&self) -> Option<CommandFlood> {
        self.core.current().and_then(|link| link.flood)
    }

    async fn push(&self, conn: ConnId, event: LineEvent) -> bool {
        let (Some(link), Some(session)) = (self.core.current(), SessionId::new(conn.0)) else {
            return false;
        };
        let stream = link.stream(session).clone();
        let credit = match stream
            .sessions
            .lock()
            .expect("link sessions")
            .live
            .get(&session)
        {
            Some(remote) => remote.credit.clone(),
            // Not on this link: the link it was on is over.
            None => return false,
        };
        let spent = match self.kind {
            SessionKind::Irc => match stream.credit.acquire().await {
                Ok(permit) => {
                    permit.forget();
                    true
                }
                Err(_) => false,
            },
            SessionKind::Attach | SessionKind::Ui => credit.spend(attach_line_weight(&event)).await,
        };
        if !spent {
            return false;
        }
        let frame = match event {
            LineEvent::Line(line) => EdgeFrame::Line(session, Bytes::from(line)),
            LineEvent::TooLong { label } => EdgeFrame::OverlongLine(session, label),
        };
        stream.out.send(frame).await.is_ok()
    }

    /// Told whether or not the edge still holds the session: its writer may
    /// have just gone, and the core must hear why. A core that already ended
    /// the session, or that never had it (a link since replaced), ignores it.
    async fn closed(&self, conn: ConnId, reason: SessionClosed) {
        let (Some(link), Some(session)) = (self.core.current(), SessionId::new(conn.0)) else {
            return;
        };
        let stream = link.stream(session).clone();
        drop(
            stream
                .out
                .send(EdgeFrame::Closed(session, closed_reason(reason)))
                .await,
        );
    }
}

#[cfg(test)]
mod tests;
