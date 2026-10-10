//! The edge's end of the core link when the core is another process (DESIGN
//! §19.2, §19.3): [`RemoteCore`] keeps the edge linked to the core holding the
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
//! Sessions outlive a link (link version 2). The edge holds every session it
//! serves, whichever link carries it, with what the core gave it to hold: the
//! session's newest record, the acknowledgement of its input — the lines not
//! yet acknowledged, and those the core retains for replay — the replicas of
//! its channels, and, once the core cuts, the cut state. A stream carries
//! input only while it is live: a core's `Pause` stops it (the `Paused`
//! answer follows every line sent before it), and a link's input starts at
//! its `Resume`, the retained lines first. A link the core cut on every
//! stream leaves its sessions held for the next core, for at most the
//! core-absence limit ([`Dialing::core_absence_limit`]); the edge presents the cut in its `Hello`, uploads what it
//! holds when asked to, and serves on at `Resume`, its clients none the
//! wiser.
//!
//! A core that goes without a cut — a crash, a link reset, a version 1 core
//! — closes every session the link carried, loudly: an IRC client is sent
//! `ERROR :Closing Link: <host> (server restarting)`, a `/ws/ui` client the
//! WebSocket close 1012 (service restart); so does a next core that does not
//! take the cut the edge holds. A session opening while no core serves waits
//! [`OPEN_WAIT`] for one, and is then closed as `(server unavailable)`.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use e6irc_link::{
    Ack, Admission, Body, ClosedReason, CoreFrame, Credit, Cut, CutId, CutPart, EdgeFrame,
    EdgeName, Hello, ListenerReport, Open, RecordPart, Replica, ReplicaChange, Role, SessionId,
    SessionKind, Slot, Stream, TlsFacts, Transport, UiMessage, Upload, VersionRange, Welcome,
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
use crate::link::{self, CloseFrame, DrainedWatch, EdgeSession, SessionLink, Written};
use crate::meter::CommandFlood;
use crate::peer_write::SendFailure;

/// How long a session opening while no core serves waits for one.
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
    /// How long the edge holds the sessions of a cut for the next core to
    /// take them — the core-absence limit (D12) — before it closes them,
    /// loudly.
    pub core_absence_limit: Duration,
}

/// The edge's standing with the core: the current link, if any, and the
/// sessions the edge holds across links.
#[derive(Clone)]
pub struct RemoteCore {
    shared: Arc<Shared>,
}

struct Shared {
    current: watch::Sender<Option<Arc<Link>>>,
    /// Bumped whenever a link comes or goes, or a stream's phase changes:
    /// what everything waiting for a live stream wakes on.
    changes: watch::Sender<u64>,
    telemetry: Arc<dyn TransportTelemetry>,
    /// Connection identifiers of this edge's slot, re-seeded when the slot
    /// changes.
    ids: Arc<ConnectionIdAllocator>,
    /// Every session this edge serves, on whichever link.
    sessions: Mutex<HashMap<SessionId, Arc<RemoteSession>>>,
    /// What the edge holds for the core beside its sessions.
    holding: Mutex<Holding>,
}

/// What the edge holds for the core beside its sessions: its channels'
/// replicas, the cut state, and the cut its sessions are held from.
#[derive(Default)]
struct Holding {
    /// The cut every session is held from, between the link the core cut and
    /// the next.
    cut: Option<HeldCut>,
    /// The replica of each channel with a member here, by its folded name.
    channels: HashMap<Bytes, HeldChannel>,
    /// The cut state the cutting core sent.
    cut_state: Option<(CutId, Body)>,
    /// The core's own sessions it homed here at the cut (`Home`, decision
    /// D13): no client is behind them, only the record held for the next
    /// core.
    homed: HashMap<SessionId, HeldRecord>,
}

/// A session's record as the core sends it in parts: the parts of one
/// revision gathering now, and the newest whole record.
#[derive(Default)]
struct HeldRecord {
    gathering: Option<(u64, Body)>,
    whole: Option<(u64, Body)>,
}

impl HeldRecord {
    fn gather(&mut self, part: RecordPart) -> Result<(), String> {
        let RecordPart { revision, part } = part;
        if part.index == 0 {
            self.gathering = Some((revision, Body::default()));
        }
        let Some((gathering, body)) = &mut self.gathering else {
            return Err("a record part with no first part".into());
        };
        if *gathering != revision {
            return Err(format!(
                "a part of record revision {revision} while revision {gathering} gathers"
            ));
        }
        body.gather(part).map_err(|error| error.to_string())?;
        if body.is_whole() {
            self.whole = self.gathering.take();
        }
        Ok(())
    }

    /// The newest whole record as the frames that upload it.
    fn upload(&self, session: SessionId) -> Vec<EdgeFrame> {
        let Some((revision, body)) = &self.whole else {
            return Vec::new();
        };
        body.parts()
            .into_iter()
            .map(|part| {
                EdgeFrame::RecordUpload(
                    session,
                    RecordPart {
                        revision: *revision,
                        part,
                    },
                )
            })
            .collect()
    }
}

/// A cut the edge holds sessions from.
#[derive(Debug, Clone, Copy)]
struct HeldCut {
    cut: CutId,
    /// The slot the sessions are numbered in.
    slot: Slot,
    /// When the edge gives up on a next core taking them.
    until: tokio::time::Instant,
}

/// One channel's replica: its state at the newest revision, and each member
/// here.
#[derive(Default)]
struct HeldChannel {
    state: Option<(u64, Bytes)>,
    members: HashMap<SessionId, Bytes>,
}

impl HeldChannel {
    /// The replica as the frames that rebuild it.
    fn replicas(&self, channel: &Bytes) -> Vec<Replica> {
        let revision = self.state.as_ref().map_or(0, |(revision, _)| *revision);
        let state = self.state.iter().map(|(revision, state)| Replica {
            channel: channel.clone(),
            revision: *revision,
            change: ReplicaChange::State(state.clone()),
        });
        let members = self.members.iter().map(|(member, entry)| Replica {
            channel: channel.clone(),
            revision,
            change: ReplicaChange::Member(*member, entry.clone()),
        });
        state.chain(members).collect()
    }
}

/// One session this edge serves for the core.
struct RemoteSession {
    id: SessionId,
    kind: SessionKind,
    /// The client's address, for the edge's own closing `ERROR`.
    host: String,
    address: IpAddr,
    transport: Transport,
    tls: Option<TlsFacts>,
    state: Mutex<SessionState>,
    /// Set once the edge's writer is gone.
    writer_gone: watch::Sender<bool>,
}

/// What of a session changes as its frames come and go.
struct SessionState {
    /// The core's end, as the core's frames drive it; `None` once the core
    /// ended the session.
    proxy: Option<SessionLink>,
    /// What the edge's writer wrote, to report as `Drained`.
    drained: DrainedWatch,
    /// An `Attach` or `Ui` session's credit on the current link.
    credit: Arc<SessionCredit>,
    /// Whether the core acknowledges this session's input: an IRC session on
    /// a link of version 2.
    acknowledged: bool,
    /// The number the next input line has on the current link.
    next_line: u64,
    /// The newest acknowledgement's `through`.
    acked_through: u64,
    /// Input lines sent and not acknowledged, or retained for replay, by
    /// number.
    unacked: VecDeque<(u64, InputLine)>,
    /// The record the core gave the edge to hold.
    record: HeldRecord,
    /// When the client last sent a line.
    last_input: tokio::time::Instant,
    /// The client's side ended, and why; and whether the core was told.
    closed: Option<ClosedReason>,
    closed_said: bool,
}

/// One input line, as the core is sent it.
#[derive(Debug, Clone)]
enum InputLine {
    Line(Bytes),
    Overlong(Option<String>),
}

impl InputLine {
    fn of(event: LineEvent) -> Self {
        match event {
            LineEvent::Line(line) => Self::Line(Bytes::from(line)),
            LineEvent::TooLong { label } => Self::Overlong(label),
        }
    }

    fn frame(&self, session: SessionId) -> EdgeFrame {
        match self {
            Self::Line(line) => EdgeFrame::Line(session, line.clone()),
            Self::Overlong(label) => EdgeFrame::OverlongLine(session, label.clone()),
        }
    }
}

impl SessionState {
    /// A session just opened on `proxy`, its core end.
    fn new(proxy: SessionLink) -> Self {
        Self {
            drained: proxy.watch_drained(),
            proxy: Some(proxy),
            credit: Arc::default(),
            acknowledged: false,
            next_line: 1,
            acked_through: 0,
            unacked: VecDeque::new(),
            record: HeldRecord::default(),
            last_input: tokio::time::Instant::now(),
            closed: None,
            closed_said: false,
        }
    }

    /// Number `line` as the next input line of the current link, keeping it
    /// until the core acknowledges it.
    fn number(&mut self, line: &InputLine) {
        if self.acknowledged {
            self.unacked.push_back((self.next_line, line.clone()));
        }
        self.next_line += 1;
    }

    /// Take back the line [`Self::number`] numbered last: it never reached
    /// the core.
    fn unnumber(&mut self) {
        self.next_line -= 1;
        if self.acknowledged {
            self.unacked.pop_back();
        }
    }

    /// Apply the core's acknowledgement: every line through `ack.through` is
    /// done with, but for those it retains.
    fn acknowledge(&mut self, ack: &Ack) -> Result<(), String> {
        if ack.through >= self.next_line {
            return Err(format!(
                "the core acknowledged line {} of a session sent {}",
                ack.through,
                self.next_line - 1
            ));
        }
        self.acked_through = ack.through;
        self.unacked.retain(|(number, _)| {
            *number > ack.through || ack.retained.binary_search(number).is_ok()
        });
        Ok(())
    }

    fn gather_record(&mut self, part: RecordPart) -> Result<(), String> {
        self.record.gather(part)
    }

    /// Hand the session to the next core, whose send queue is `sendq_bytes`:
    /// the bytes sent and not yet written, which that core counts in flight,
    /// and the lines sent that the last core neither acknowledged nor
    /// retained — of unknown fate, and dropped. The retained lines stay, to
    /// be replayed at `Resume`; the link's numbering and credit start over.
    /// `None` when the core ended the session.
    fn hand_over(&mut self, sendq_bytes: usize) -> Option<(u64, u32)> {
        let proxy = self.proxy.as_mut()?;
        let unwritten = self.drained.rebase(proxy);
        proxy.set_capacity(sendq_bytes);
        let acked_through = self.acked_through;
        let before = self.unacked.len();
        self.unacked.retain(|(number, _)| *number <= acked_through);
        let unconfirmed = u32::try_from(before - self.unacked.len()).unwrap_or(u32::MAX);
        self.next_line = 1;
        self.acked_through = 0;
        self.credit.bytes.close();
        self.credit = Arc::default();
        // The upload says it.
        self.closed_said = self.closed.is_some();
        Some((unwritten, unconfirmed))
    }

    /// Resume on a link whose core acknowledges this session's input or not:
    /// the lines to replay first, numbered afresh from 1, and the end of a
    /// client the core has not heard of yet.
    fn resume(&mut self, acknowledged: bool) -> (Vec<InputLine>, Option<ClosedReason>) {
        let retained: Vec<InputLine> = self.unacked.drain(..).map(|(_, line)| line).collect();
        self.acknowledged = acknowledged;
        self.next_line = 1;
        self.acked_through = 0;
        for line in &retained {
            self.number(line);
        }
        let closed = if self.closed_said {
            None
        } else {
            self.closed_said = self.closed.is_some();
            self.closed.clone()
        };
        (retained, closed)
    }
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
/// arriving while no core serves gets.
fn refused_session(host: &str, reason: &str) -> EdgeSession {
    let (mut proxy, edge) = link::session("edge-refused", 1);
    proxy.kill(closing_line(host, reason));
    edge
}

/// Why the edge closes the sessions it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkClose {
    /// The core went without a cut, or the next core does not take the cut
    /// the edge holds, or none came in time.
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
    fn end_loudly(&self, why: LinkClose) {
        let mut state = self.state.lock().expect("session state");
        state.credit.bytes.close();
        let Some(mut proxy) = state.proxy.take() else {
            return;
        };
        match self.kind {
            SessionKind::Ui => proxy.close_on_end(why.close_frame()),
            SessionKind::Irc | SessionKind::Attach => {
                let line = closing_line(&self.host, why.reason());
                if proxy.output(line.clone()).is_err() {
                    proxy.kill(line);
                }
            }
        }
    }
}

/// Where a stream is in its link's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Input waits: the core has not resumed the link yet.
    Held,
    /// Input flows.
    Live,
    /// The core paused input: a cut is coming.
    Paused,
    /// The link is over.
    Over,
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
    index: usize,
    out: mpsc::Sender<EdgeFrame>,
    /// Lines the core has room for, for this stream's `Irc` sessions.
    credit: Semaphore,
    phase: Mutex<Phase>,
    /// Held to send input, and taken whole to pause, so `Paused` follows
    /// every line sent before it; taken whole, too, from a `Resume` until its
    /// replay is sent and input flows.
    gate: Arc<tokio::sync::RwLock<()>>,
    /// The core's `Cut`, once it came.
    cut: Mutex<Option<Cut>>,
}

impl LinkStream {
    fn phase(&self) -> Phase {
        *self.phase.lock().expect("stream phase")
    }

    fn set_phase(&self, phase: Phase) {
        *self.phase.lock().expect("stream phase") = phase;
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
        for stream in &self.streams {
            stream.set_phase(Phase::Over);
            stream.credit.close();
        }
        self.over.send_replace(true);
    }

    /// The cut every stream of the link ended with, when each did: the one
    /// way a link leaves its sessions held.
    fn cut(&self) -> Option<Cut> {
        let mut cuts = self
            .streams
            .iter()
            .map(|stream| *stream.cut.lock().expect("stream cut"));
        let first = cuts.next()??;
        cuts.all(|cut| cut == Some(first)).then_some(first)
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

    /// Stop the link's tasks.
    fn stop_tasks(&self) {
        self.end();
        for task in self.tasks.lock().expect("link tasks").drain(..) {
            task.abort();
        }
    }
}

/// What sending a frame on a live stream spends first.
#[derive(Debug, Clone, Copy)]
enum Spend {
    Nothing,
    /// One of the stream's line credits.
    StreamLine,
    /// This many bytes of the session's credit.
    SessionBytes(usize),
}

impl RemoteCore {
    /// An edge not yet linked. `ids` is re-seeded with the slot the core
    /// gives.
    pub fn new(telemetry: Arc<dyn TransportTelemetry>, ids: Arc<ConnectionIdAllocator>) -> Self {
        Self {
            shared: Arc::new(Shared {
                current: watch::Sender::new(None),
                changes: watch::Sender::new(0),
                telemetry,
                ids,
                sessions: Mutex::default(),
                holding: Mutex::default(),
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

    /// How many sessions the edge serves, held ones included.
    pub fn sessions(&self) -> usize {
        self.shared.sessions.lock().expect("edge sessions").len()
    }

    /// Whether the edge holds sessions from a cut, for the next core.
    pub fn holding(&self) -> bool {
        self.shared
            .holding
            .lock()
            .expect("edge holding")
            .cut
            .is_some()
    }

    fn changed(&self) {
        self.shared.changes.send_modify(|count| *count += 1);
    }

    fn session(&self, id: SessionId) -> Option<Arc<RemoteSession>> {
        self.shared
            .sessions
            .lock()
            .expect("edge sessions")
            .get(&id)
            .cloned()
    }

    fn remove(&self, id: SessionId) -> Option<Arc<RemoteSession>> {
        self.shared
            .sessions
            .lock()
            .expect("edge sessions")
            .remove(&id)
    }

    /// Stop: close every session, as this edge shutting down, and link no
    /// more.
    pub fn shut_down(&self) {
        if let Some(link) = self.shared.current.send_replace(None) {
            link.stop_tasks();
        }
        self.close_every_session(LinkClose::EdgeStopping);
    }

    /// Close every session the edge serves or holds, loudly, and forget what
    /// it holds for them.
    fn close_every_session(&self, why: LinkClose) -> usize {
        let ended: Vec<Arc<RemoteSession>> = self
            .shared
            .sessions
            .lock()
            .expect("edge sessions")
            .drain()
            .map(|(_, session)| session)
            .collect();
        *self.shared.holding.lock().expect("edge holding") = Holding::default();
        for session in &ended {
            session.end_loudly(why);
        }
        self.changed();
        ended.len()
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

    /// Send the frame `make` gives on `session`'s stream of the current link
    /// once that stream is live — waiting until `deadline`, or for as long as
    /// it takes — having spent `spend` first. `make` runs with input held
    /// back from any pause, and may decline (`None`); `lost` undoes what it
    /// did when the link went before the frame was sent, and it is tried on
    /// the next. `false` when it declined or the wait ended.
    async fn send_live(
        &self,
        session: SessionId,
        deadline: Option<tokio::time::Instant>,
        spend: Spend,
        mut make: impl FnMut(&Link) -> Option<EdgeFrame>,
        mut lost: impl FnMut(),
    ) -> bool {
        let mut changes = self.shared.changes.subscribe();
        loop {
            changes.borrow_and_update();
            if let Some(link) = self.current()
                && link.stream(session).phase() == Phase::Live
            {
                let stream = link.stream(session).clone();
                let permit = match spend {
                    Spend::Nothing => None,
                    Spend::StreamLine => match stream.credit.acquire().await {
                        Ok(permit) => Some(permit),
                        // The link went while waiting.
                        Err(_) => continue,
                    },
                    Spend::SessionBytes(weight) => {
                        let Some(remote) = self.session(session) else {
                            return false;
                        };
                        let credit = remote.state.lock().expect("session state").credit.clone();
                        if !credit.spend(weight).await {
                            continue;
                        }
                        None
                    }
                };
                let gate = stream.gate.read().await;
                if stream.phase() == Phase::Live {
                    if let Some(permit) = permit {
                        permit.forget();
                    }
                    let Some(frame) = make(&link) else {
                        return false;
                    };
                    let sent = stream.out.send(frame).await.is_ok();
                    drop(gate);
                    if sent {
                        return true;
                    }
                    lost();
                }
                continue;
            }
            let changed = changes.changed();
            let waited = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, changed)
                    .await
                    .unwrap_or(Ok(())),
                None => changed.await,
            };
            if waited.is_err()
                || deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            {
                return false;
            }
        }
    }

    /// Stay linked to the core for as long as the process runs: dial until a
    /// core accepts, serve through it until the link is over, hold what it
    /// carried when the core cut it — close it otherwise — and dial again.
    /// `linked` hears of each link as it is made.
    pub async fn maintain(self, dialing: Dialing, linked: mpsc::UnboundedSender<Arc<Link>>) {
        let mut epoch = EdgeEpoch::default();
        let mut slot: Option<Slot> = None;
        loop {
            let held = self.shared.holding.lock().expect("edge holding").cut;
            let link = match held {
                Some(held) => tokio::select! {
                    link = self.dial(&dialing, &mut epoch, &mut slot) => link,
                    () = tokio::time::sleep_until(held.until) => {
                        let closed = self.close_every_session(LinkClose::ServerRestarting);
                        eprintln!(
                            "e6ircd edge {}: no core took cut {:#x} within {}s; its {closed} \
                             sessions were closed as the server restarting",
                            dialing.edge,
                            held.cut.get(),
                            dialing.core_absence_limit.as_secs()
                        );
                        continue;
                    }
                },
                None => self.dial(&dialing, &mut epoch, &mut slot).await,
            };
            eprintln!(
                "e6ircd edge {}: linked to the core at {} (serving-lease epoch {}, link version \
                 {}, slot {}, {} session streams, {:?})",
                dialing.edge,
                link.core,
                link.welcome.epoch,
                link.welcome.version,
                link.welcome.slot.get(),
                link.streams.len(),
                link.welcome.admission
            );
            self.take_up(&dialing.edge, &link, held);
            self.shared.current.send_replace(Some(link.clone()));
            self.changed();
            drop(linked.send(link.clone()));
            link.over().await;
            self.shared.current.send_replace(None);
            link.stop_tasks();
            self.changed();
            match link.cut() {
                Some(cut) if link.welcome.version >= 2 => {
                    let (sessions, homed) =
                        self.hold(cut, link.welcome.slot, dialing.core_absence_limit);
                    eprintln!(
                        "e6ircd edge {}: the core at {} cut the link (cut {:#x}); holding \
                         {sessions} sessions and {homed} of the core's own for the next core, \
                         for at most {}s",
                        dialing.edge,
                        link.core,
                        cut.cut.get(),
                        dialing.core_absence_limit.as_secs()
                    );
                }
                _ => {
                    let closed = self.close_every_session(LinkClose::ServerRestarting);
                    eprintln!(
                        "e6ircd edge {}: the link to the core at {} is over; {closed} sessions \
                         were closed as the server restarting",
                        dialing.edge, link.core
                    );
                }
            }
        }
    }

    /// Hold every session from `cut` for the next core, for at most `limit`:
    /// how many, and how many of the core's own it homed here.
    fn hold(&self, cut: Cut, slot: Slot, limit: Duration) -> (usize, usize) {
        let sessions: Vec<Arc<RemoteSession>> = self
            .shared
            .sessions
            .lock()
            .expect("edge sessions")
            .values()
            .cloned()
            .collect();
        for session in &sessions {
            // Its credit was the cut link's.
            session
                .state
                .lock()
                .expect("session state")
                .credit
                .bytes
                .close();
        }
        let mut holding = self.shared.holding.lock().expect("edge holding");
        holding.cut = Some(HeldCut {
            cut: cut.cut,
            slot,
            until: tokio::time::Instant::now() + limit,
        });
        (sessions.len(), holding.homed.len())
    }

    /// Start serving on a new link: upload what the edge holds when the core
    /// asks for it, close it when the core will not take it, and let input
    /// flow on a link the core serves at once.
    fn take_up(&self, edge: &EdgeName, link: &Arc<Link>, held: Option<HeldCut>) {
        let admission = link.welcome.admission;
        if admission == Admission::Serve {
            for stream in &link.streams {
                stream.set_phase(Phase::Live);
            }
        }
        let Some(held) = held else {
            return;
        };
        self.shared.holding.lock().expect("edge holding").cut = None;
        let upload = admission == Admission::Upload && held.slot == link.welcome.slot;
        if upload {
            let task = tokio::spawn(upload_held(self.clone(), link.clone(), held.cut));
            link.tasks
                .lock()
                .expect("link tasks")
                .push(task.abort_handle());
        } else {
            let closed = self.close_every_session(LinkClose::ServerRestarting);
            eprintln!(
                "e6ircd edge {edge}: the core does not take cut {:#x} ({admission:?}, slot {} \
                 for sessions of slot {}); its {closed} sessions were closed as the server \
                 restarting",
                held.cut.get(),
                link.welcome.slot.get(),
                held.slot.get()
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
        let cut = self
            .shared
            .holding
            .lock()
            .expect("edge holding")
            .cut
            .map(|held| held.cut);
        let hello = |stream: Stream, slot: Option<Slot>, listeners: Vec<ListenerReport>| Hello {
            versions: VersionRange::spoken(),
            role: Role::Serving,
            edge: dialing.edge.clone(),
            stream,
            slot,
            highest_epoch: epoch.highest(),
            listeners,
            cut,
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
            if answer.epoch != welcome.epoch
                || answer.slot != welcome.slot
                || answer.admission != welcome.admission
            {
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
            .enumerate()
            .map(|(index, _)| {
                let (out, frames) = mpsc::channel(STREAM_QUEUE);
                queues.push(frames);
                Arc::new(LinkStream {
                    index,
                    out,
                    credit: Semaphore::new(welcome.terms.line_credit as usize),
                    phase: Mutex::new(Phase::Held),
                    gate: Arc::default(),
                    cut: Mutex::default(),
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
            let core = self.clone();
            let reader = tokio::spawn(async move {
                if let Err(error) = core.read_stream(read_half, &reader_link, &stream).await {
                    eprintln!("e6ircd edge: core link read failed: {error}");
                }
                reader_link.end();
                core.changed();
            });
            let mut tasks = link.tasks.lock().expect("link tasks");
            tasks.push(writer.abort_handle());
            tasks.push(reader.abort_handle());
        }
        Ok(link)
    }

    /// Place a new session, unless one of its identifier is already here.
    fn register(&self, session: Arc<RemoteSession>) -> bool {
        let mut sessions = self.shared.sessions.lock().expect("edge sessions");
        if sessions.contains_key(&session.id) {
            return false;
        }
        sessions.insert(session.id, session);
        true
    }

    /// Open a session of `kind` and start reporting what its writer writes:
    /// the edge's end, or `None` when no stream went live for it in time.
    async fn open_session(
        &self,
        id: SessionId,
        kind: SessionKind,
        address: IpAddr,
        host: String,
        transport: ConnectionTransport,
        tls: Option<TlsFacts>,
    ) -> Option<EdgeSession> {
        let deadline = tokio::time::Instant::now() + OPEN_WAIT;
        let link = tokio::time::timeout_at(deadline, async {
            let mut current = self.shared.current.subscribe();
            current
                .wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|link| link.clone())
        })
        .await
        .ok()
        .flatten()?;
        let (proxy, edge) = link::session("edge-sendq", link.welcome.terms.sendq_bytes as usize);
        let transport = transport_of(transport);
        let session = Arc::new(RemoteSession {
            id,
            kind,
            host,
            address,
            transport,
            tls: tls.clone(),
            state: Mutex::new(SessionState::new(proxy)),
            writer_gone: watch::Sender::new(false),
        });
        if !self.register(session.clone()) {
            return None;
        }
        let opened = self
            .send_live(
                id,
                Some(deadline),
                Spend::Nothing,
                |link| {
                    let mut state = session.state.lock().expect("session state");
                    state.acknowledged = kind == SessionKind::Irc && link.welcome.version >= 2;
                    if let Some(proxy) = &mut state.proxy {
                        proxy.set_capacity(link.welcome.terms.sendq_bytes as usize);
                    }
                    // A new link's credit, fresh.
                    state.credit = Arc::default();
                    Some(EdgeFrame::Open(
                        id,
                        Open {
                            kind,
                            address,
                            transport,
                            // A version 1 core reads no TLS facts.
                            tls: tls.clone().filter(|_| link.welcome.version >= 2),
                        },
                    ))
                },
                || {},
            )
            .await;
        if !opened {
            self.remove(id);
            return None;
        }
        tokio::spawn(report_drained(self.clone(), session));
        Some(edge)
    }

    /// Open a `/ws/ui` session: the edge's end, and where the client's
    /// messages go — a queue as large as the largest message, which the link
    /// drains as the core's credit allows. `None` when no core serves within
    /// [`OPEN_WAIT`].
    pub async fn open_ui(
        &self,
        conn: ConnId,
        address: std::net::IpAddr,
        transport: ConnectionTransport,
    ) -> Option<(EdgeSession, e6irc_queue::Sender<UiMessage>)> {
        let session = SessionId::new(conn.0)?;
        let edge = self
            .open_session(
                session,
                SessionKind::Ui,
                address,
                address.to_string(),
                transport,
                None,
            )
            .await?;
        let (inbound, messages) = e6irc_queue::weighted_queue(
            e6irc_queue::Config {
                name: "edge-ui-inbound",
                capacity: e6irc_link::MAX_UI_MESSAGE_LEN,
                policy: e6irc_queue::Policy::Fifo,
            },
            ui_message_weight,
        );
        // It ends with the session: its socket loop and writer end when the
        // core ends it, or when the edge closes it loudly.
        tokio::spawn(relay_ui(self.clone(), session, messages));
        Some((edge, inbound))
    }

    /// Hand the core one input line of `session`'s once a stream is live for
    /// it: `false` once the edge serves the session no more.
    async fn push_line(&self, session: SessionId, kind: SessionKind, event: LineEvent) -> bool {
        let Some(remote) = self.session(session) else {
            return false;
        };
        remote.state.lock().expect("session state").last_input = tokio::time::Instant::now();
        let spend = match kind {
            SessionKind::Irc => Spend::StreamLine,
            SessionKind::Attach | SessionKind::Ui => {
                Spend::SessionBytes(attach_line_weight(&event))
            }
        };
        let line = InputLine::of(event);
        self.send_live(
            session,
            None,
            spend,
            |_| {
                let mut state = remote.state.lock().expect("session state");
                state.proxy.as_ref()?;
                state.number(&line);
                Some(line.frame(session))
            },
            || remote.state.lock().expect("session state").unnumber(),
        )
        .await
    }

    /// Note that `session`'s client side ended, and tell a live core; a core
    /// not live hears it in the upload, or at its `Resume`.
    async fn client_closed(&self, session: SessionId, reason: ClosedReason) {
        let Some(remote) = self.session(session) else {
            return;
        };
        remote.state.lock().expect("session state").closed = Some(reason.clone());
        let Some(link) = self.current() else {
            return;
        };
        let stream = link.stream(session).clone();
        let _gate = stream.gate.read().await;
        if stream.phase() == Phase::Live {
            remote.state.lock().expect("session state").closed_said = true;
            drop(stream.out.send(EdgeFrame::Closed(session, reason)).await);
        }
    }

    /// Read one stream's frames from the core and apply each.
    async fn read_stream<R>(
        &self,
        read_half: R,
        link: &Arc<Link>,
        stream: &Arc<LinkStream>,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let version = link.welcome.version;
        let invalid = |what: String| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
        let mut reader = FrameReader::new(read_half);
        while let Some(frame) = reader.next::<CoreFrame>().await? {
            if frame.since() > version {
                return Err(invalid(format!(
                    "core link: a frame of link version {} on a link of version {version}",
                    frame.since()
                )));
            }
            match frame {
                CoreFrame::Output(session, bytes) => self.output(stream, session, bytes).await,
                CoreFrame::Kill(session, line) => {
                    if let Some(remote) = self.remove(session) {
                        let mut state = remote.state.lock().expect("session state");
                        state.credit.bytes.close();
                        if let Some(mut proxy) = state.proxy.take() {
                            proxy.kill(Output(line));
                        }
                    }
                }
                CoreFrame::End(session, close) => {
                    if let Some(remote) = self.remove(session) {
                        let mut state = remote.state.lock().expect("session state");
                        state.credit.bytes.close();
                        if let Some(proxy) = state.proxy.take()
                            && let Some(close) = close
                        {
                            proxy.close_on_end(CloseFrame {
                                code: close.code,
                                reason: close.reason.into(),
                            });
                        }
                    }
                }
                CoreFrame::FloodExempt(session, exempt) => {
                    if let Some(remote) = self.session(session)
                        && let Some(proxy) = &remote.state.lock().expect("session state").proxy
                    {
                        proxy.set_flood_exempt(exempt);
                    }
                }
                CoreFrame::Credit(Credit::Stream(lines)) => {
                    grant(&stream.credit, lines)?;
                }
                CoreFrame::Credit(Credit::Session(session, bytes)) => {
                    let credit = self
                        .session(session)
                        .map(|remote| remote.state.lock().expect("session state").credit.clone());
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
                    return Err(invalid(
                        "core link: a handshake frame after the handshake".into(),
                    ));
                }
                CoreFrame::Pause => {
                    // Every line sent before this goes before `Paused` — a
                    // `Resume`'s replay before it too, which spends credit
                    // this reader grants: the pause waits on its own.
                    let task = tokio::spawn(pause(self.clone(), link.clone(), stream.clone()));
                    link.tasks
                        .lock()
                        .expect("link tasks")
                        .push(task.abort_handle());
                }
                CoreFrame::Resume => {
                    if stream.phase() != Phase::Held {
                        return Err(invalid("core link: Resume on a stream not held".into()));
                    }
                    // Taken before the next frame is read, so a `Pause` after
                    // this waits for the replay to be sent and input to flow.
                    let gate = stream.gate.clone().write_owned().await;
                    // Replaying spends credit, which this reader grants: the
                    // replay waits on its own.
                    let task =
                        tokio::spawn(resume(self.clone(), link.clone(), stream.clone(), gate));
                    link.tasks
                        .lock()
                        .expect("link tasks")
                        .push(task.abort_handle());
                }
                CoreFrame::Ack(session, ack) => {
                    if let Some(remote) = self.session(session) {
                        remote
                            .state
                            .lock()
                            .expect("session state")
                            .acknowledge(&ack)
                            .map_err(|error| invalid(format!("core link: {error}")))?;
                    }
                }
                CoreFrame::Record(session, part) => {
                    let gathered = match self.session(session) {
                        Some(remote) => remote
                            .state
                            .lock()
                            .expect("session state")
                            .gather_record(part),
                        None => match self
                            .shared
                            .holding
                            .lock()
                            .expect("edge holding")
                            .homed
                            .get_mut(&session)
                        {
                            Some(homed) => homed.gather(part),
                            // Ended here, and the core has not heard yet.
                            None => Ok(()),
                        },
                    };
                    gathered.map_err(|error| invalid(format!("core link: {error}")))?;
                }
                CoreFrame::Home(session) => {
                    if session.get() >> e6irc_link::SLOT_SHIFT != 0 {
                        return Err(invalid(format!(
                            "core link: session {} homed here is not the core's own",
                            session.get()
                        )));
                    }
                    let mut holding = self.shared.holding.lock().expect("edge holding");
                    if holding
                        .homed
                        .insert(session, HeldRecord::default())
                        .is_some()
                    {
                        return Err(invalid(format!(
                            "core link: session {} homed here twice",
                            session.get()
                        )));
                    }
                }
                CoreFrame::Replica(replica) => self.replica(replica),
                CoreFrame::CutState(CutPart { cut, part }) => {
                    let mut holding = self.shared.holding.lock().expect("edge holding");
                    let body = match &mut holding.cut_state {
                        Some((held, body)) if *held == cut => body,
                        state => &mut state.insert((cut, Body::default())).1,
                    };
                    body.gather(part)
                        .map_err(|error| invalid(format!("core link: the cut state: {error}")))?;
                }
                CoreFrame::Cut(cut) => {
                    *stream.cut.lock().expect("stream cut") = Some(cut);
                }
            }
        }
        Ok(())
    }

    /// Apply one `Output` frame.
    async fn output(&self, stream: &LinkStream, session: SessionId, bytes: Bytes) {
        let Some(remote) = self.session(session) else {
            // Ended here, and the core has not heard yet.
            return;
        };
        let overrun = {
            let mut state = remote.state.lock().expect("session state");
            match &mut state.proxy {
                Some(proxy) => proxy.output(Output(bytes)).is_err(),
                None => false,
            }
        };
        if !overrun {
            return;
        }
        // The core sent past the bound it keeps: its bug, closed loudly on
        // both sides.
        self.shared.telemetry.record_error(TransportError::Write);
        eprintln!(
            "e6ircd edge: the core sent session {} more than its send-queue bound; closing it",
            session.get()
        );
        if let Some(remote) = self.remove(session) {
            let mut state = remote.state.lock().expect("session state");
            if let Some(mut proxy) = state.proxy.take() {
                proxy.kill(closing_line(&remote.host, "edge send queue overrun"));
            }
        }
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

    /// Hold one change of a channel's replica.
    fn replica(&self, replica: Replica) {
        let Replica {
            channel,
            revision,
            change,
        } = replica;
        let mut holding = self.shared.holding.lock().expect("edge holding");
        match change {
            ReplicaChange::State(state) => {
                holding.channels.entry(channel).or_default().state = Some((revision, state));
            }
            ReplicaChange::Member(member, entry) => {
                holding
                    .channels
                    .entry(channel)
                    .or_default()
                    .members
                    .insert(member, entry);
            }
            ReplicaChange::MemberGone(member) => {
                if let Some(held) = holding.channels.get_mut(&channel) {
                    held.members.remove(&member);
                }
            }
            ReplicaChange::Gone => {
                holding.channels.remove(&channel);
            }
        }
    }
}

/// Upload what the edge holds from `cut` to the core `link` reaches: each
/// session on its stream, then — on the first stream — every replica and the
/// cut state, and `UploadDone` on every stream. The link's input starts at
/// the core's `Resume`.
async fn upload_held(core: RemoteCore, link: Arc<Link>, cut: CutId) {
    let (channels, cut_state, homed) = {
        let mut holding = core.shared.holding.lock().expect("edge holding");
        (
            std::mem::take(&mut holding.channels),
            holding.cut_state.take(),
            // The next core takes them, and homes them again at its own cut.
            std::mem::take(&mut holding.homed),
        )
    };
    let sessions: Vec<Arc<RemoteSession>> = core
        .shared
        .sessions
        .lock()
        .expect("edge sessions")
        .values()
        .cloned()
        .collect();
    let sendq_bytes = link.welcome.terms.sendq_bytes as usize;
    let mut uploaded = 0usize;
    for session in &sessions {
        let frames = {
            let mut state = session.state.lock().expect("session state");
            let Some((unwritten, unconfirmed)) = state.hand_over(sendq_bytes) else {
                continue;
            };
            let mut frames = vec![EdgeFrame::Upload(
                session.id,
                Upload {
                    kind: session.kind,
                    address: session.address,
                    transport: session.transport,
                    tls: session.tls.clone(),
                    since_input_ms: u64::try_from(state.last_input.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                    unwritten,
                    unconfirmed,
                    closed: state.closed.clone(),
                },
            )];
            frames.extend(state.record.upload(session.id));
            frames
        };
        let stream = link.stream(session.id);
        for frame in frames {
            if stream.out.send(frame).await.is_err() {
                return;
            }
        }
        uploaded += 1;
    }
    for (id, record) in &homed {
        let stream = link.stream(*id);
        for frame in std::iter::once(EdgeFrame::HomeUpload(*id)).chain(record.upload(*id)) {
            if stream.out.send(frame).await.is_err() {
                return;
            }
        }
    }
    let first = &link.streams[0];
    for (channel, held) in &channels {
        for replica in held.replicas(channel) {
            if first
                .out
                .send(EdgeFrame::ReplicaUpload(replica))
                .await
                .is_err()
            {
                return;
            }
        }
    }
    match cut_state {
        Some((state_cut, body)) if state_cut == cut && body.is_whole() => {
            for part in body.parts() {
                if first
                    .out
                    .send(EdgeFrame::CutUpload(CutPart { cut, part }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        _ => eprintln!(
            "e6ircd edge: holding no whole cut state for cut {:#x}; the core rebuilds without it",
            cut.get()
        ),
    }
    for stream in &link.streams {
        if stream.out.send(EdgeFrame::UploadDone).await.is_err() {
            return;
        }
    }
    eprintln!(
        "e6ircd edge: uploaded {uploaded} sessions, {} of the core's own and {} channels held \
         from cut {:#x}",
        homed.len(),
        channels.len(),
        cut.get()
    );
}

/// Resume a stream the core held: replay each of its sessions' retained
/// lines, numbered afresh for this link, tell the core of every client that
/// left while it could not hear, and let input flow.
async fn resume(
    core: RemoteCore,
    link: Arc<Link>,
    stream: Arc<LinkStream>,
    gate: tokio::sync::OwnedRwLockWriteGuard<()>,
) {
    let sessions: Vec<Arc<RemoteSession>> = core
        .shared
        .sessions
        .lock()
        .expect("edge sessions")
        .values()
        .filter(|session| stream_of(session.id, link.streams.len()) == stream.index)
        .cloned()
        .collect();
    for session in sessions {
        let (replay, closed) = session
            .state
            .lock()
            .expect("session state")
            .resume(session.kind == SessionKind::Irc && link.welcome.version >= 2);
        for line in replay {
            match stream.credit.acquire().await {
                Ok(permit) => permit.forget(),
                Err(_) => return,
            }
            if stream.out.send(line.frame(session.id)).await.is_err() {
                return;
            }
        }
        if let Some(reason) = closed
            && stream
                .out
                .send(EdgeFrame::Closed(session.id, reason))
                .await
                .is_err()
        {
            return;
        }
    }
    stream.set_phase(Phase::Live);
    drop(gate);
    core.changed();
}

/// Pause a stream for the core's cut once every line sent before is sent —
/// a `Resume`'s replay included — and answer `Paused`. A `Pause` on a stream
/// not live breaks the protocol: the link ends.
async fn pause(core: RemoteCore, link: Arc<Link>, stream: Arc<LinkStream>) {
    let gate = stream.gate.write().await;
    if stream.phase() != Phase::Live {
        drop(gate);
        eprintln!("e6ircd edge: core link: Pause on a stream not live; the link ends");
        link.end();
        core.changed();
        return;
    }
    stream.set_phase(Phase::Paused);
    drop(gate);
    core.changed();
    // A link that is gone needs no answer.
    drop(stream.out.send(EdgeFrame::Paused).await);
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

/// Carry what the edge writes of `session`'s output to the core serving it,
/// while its stream is live or pausing; a link not yet resumed hears what was
/// written since its upload once it is. Ends once the session's writer is
/// gone.
async fn report_drained(core: RemoteCore, session: Arc<RemoteSession>) {
    let wake = session.state.lock().expect("session state").drained.wake();
    let mut changes = core.shared.changes.subscribe();
    loop {
        changes.borrow_and_update();
        let stream = core.current().and_then(|link| {
            let stream = link.stream(session.id).clone();
            matches!(stream.phase(), Phase::Live | Phase::Paused).then_some(stream)
        });
        let (written, gone) = {
            let mut state = session.state.lock().expect("session state");
            let written = stream.as_ref().map(|_| state.drained.poll_written());
            (written, state.drained.edge_gone())
        };
        match (written, stream) {
            (Some(Written::More(bytes)), Some(stream)) => {
                // A link that went has no use for it; the next rebases.
                drop(stream.out.send(EdgeFrame::Drained(session.id, bytes)).await);
                continue;
            }
            (Some(Written::Over), _) => break,
            // Nobody to tell: a gone writer has nothing more to say.
            (None, _) if gone => break,
            _ => {}
        }
        tokio::select! {
            () = wake.notified() => {}
            changed = changes.changed() => if changed.is_err() {
                break;
            },
        }
    }
    session.writer_gone.send_replace(true);
}

/// A `/ws/ui` session's messages to the core, each as its credit allows, and
/// its end (`Closed`), once both its socket loop and its writer are done.
async fn relay_ui(
    core: RemoteCore,
    session: SessionId,
    mut messages: e6irc_queue::Receiver<UiMessage>,
) {
    while let Some(envelope) = messages.pop().await {
        let message = envelope.payload;
        let weight = ui_message_weight(&message);
        let sent = core
            .send_live(
                session,
                None,
                Spend::SessionBytes(weight),
                |_| {
                    let remote = core.session(session)?;
                    remote.state.lock().expect("session state").proxy.as_ref()?;
                    Some(EdgeFrame::Message(session, message.clone()))
                },
                || {},
            )
            .await;
        if !sent {
            return;
        }
    }
    let Some(remote) = core.session(session) else {
        return;
    };
    let mut gone = remote.writer_gone.subscribe();
    drop(gone.wait_for(|gone| *gone).await);
    let reason = match remote
        .state
        .lock()
        .expect("session state")
        .drained
        .writer_failure()
    {
        Some(failure) => closed_reason(SessionClosed::WriteFailed(failure)),
        None => ClosedReason::ByClient,
    };
    core.client_closed(session, reason).await;
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
        tls: Option<TlsFacts>,
        _sendq_bytes: usize,
    ) -> Option<EdgeSession> {
        let Some(session) = SessionId::new(conn.0) else {
            return Some(refused_session(&host, "no connection identifier"));
        };
        let Ok(address) = host.parse::<std::net::IpAddr>() else {
            return Some(refused_session(&host, "no client address"));
        };
        match self
            .core
            .open_session(session, self.kind, address, host.clone(), transport, tls)
            .await
        {
            Some(edge) => Some(edge),
            None => Some(refused_session(&host, "server unavailable")),
        }
    }

    fn command_flood(&self) -> Option<CommandFlood> {
        self.core.current().and_then(|link| link.flood)
    }

    async fn push(&self, conn: ConnId, event: LineEvent) -> bool {
        let Some(session) = SessionId::new(conn.0) else {
            return false;
        };
        self.core.push_line(session, self.kind, event).await
    }

    /// Told whether or not the edge still serves the session: its writer may
    /// have just gone, and the core must hear why. A session the core already
    /// ended is not the edge's any more, and needs no telling.
    async fn closed(&self, conn: ConnId, reason: SessionClosed) {
        let Some(session) = SessionId::new(conn.0) else {
            return;
        };
        self.core
            .client_closed(session, closed_reason(reason))
            .await;
    }
}

#[cfg(test)]
mod tests;
