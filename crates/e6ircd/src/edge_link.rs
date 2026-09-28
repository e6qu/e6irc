//! The core's end of the core link across processes (DESIGN §19.2): the
//! listener edges link to in edge mode, bound only while this process holds
//! the serving lease.
//!
//! Each link connection opens with the edge's `Hello`. The core answers
//! `Welcome` — the link version both speak, its serving-lease epoch, the
//! edge's slot and the terms the edge follows — or `Refused`, naming why: an
//! edge speaking no version this core does, the observer role (the warm
//! standby is not built into this release), a certificate not issued for the
//! edge the `Hello` names, or an edge that already accepted a newer epoch
//! than this core holds, which means this core lost the lease.
//!
//! A session stream carries the sessions of one core shard. For each session
//! the edge opens, the core builds the same pair of link ends the single
//! process does (`core::send_queue`, or the waiting pair of an attach or a
//! live chat socket) and opens it through the same ports; a pump task per
//! session plays the edge's writer on this side, sending what the core
//! queues as `Output` (`Kill`, `End`) and reporting as written only what the
//! edge reports written — so the send-queue bound still counts every byte
//! until it is on the client's socket.
//!
//! Input: the lines of a stream's `Irc` sessions go to its shard's queue in
//! order, through one pusher that returns a `Credit` for each line it moves,
//! so the edge never has more in flight than the window it was granted and
//! reading the link never waits on a full shard. An attach's lines and a live
//! chat socket's messages go to their own session's inbound queue, on their
//! own session's credit.
//!
//! A link that ends ends every session it carried: an IRC session quits as
//! `Edge link lost`, and the edge closes each client loudly on its side.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use e6irc_edge::address::{ClientIp, ConnLimiter, PeerRefusal};
use e6irc_edge::connection::{
    ConnId, ConnectionTasks, ConnectionTransport, CorePort, Output, SessionClosed,
};
use e6irc_edge::core_link::io::{
    FrameReader, HANDSHAKE_DEADLINE, keep_alive, write_frame, write_frames,
};
use e6irc_edge::core_link::remote::{attach_line_weight, session_closed, ui_message_weight};
use e6irc_edge::link::EdgeSession;
use e6irc_edge::peer_write::SendFailure;
use e6irc_link::{
    CloseFrame, CoreFrame, Credit, EdgeFrame, EdgeName, EdgeTerms, Hello, ListenerReport, Open,
    Role, SessionId, SessionKind, Slot, Stream, Transport, Welcome,
};
use e6irc_proto::framing::LineEvent;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;

use crate::core::{CoreIngress, Input};
use crate::observability::{ErrorKind, Telemetry};

/// Where edges link, and the core's link credentials (`[edge_link]`). Its
/// presence is edge mode: the core binds no client listener of its own.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeLinkConfig {
    /// The link listener's address, bound only while this process holds the
    /// serving lease.
    pub addr: SocketAddr,
    #[serde(flatten)]
    pub credentials: e6irc_edge::core_link::tls::LinkCredentialFiles,
}

/// Lines each session stream may have in flight to its shard's queue: as
/// many as the queue holds, at most this.
const MAX_LINE_CREDIT: usize = 1024;

/// Frames queued to one link connection's writer.
const STREAM_QUEUE: usize = 1024;

/// The quit reason of an IRC session whose edge link ended.
const LINK_LOST: &str = "Edge link lost";

/// What an edge that linked is, as `/readyz` and the console show it.
#[derive(Debug, Clone)]
pub(crate) struct LinkedEdgeView {
    pub(crate) name: EdgeName,
    pub(crate) slot: Slot,
    /// The link version this link speaks, and the newest the edge speaks.
    pub(crate) version: u16,
    pub(crate) newest_version: u16,
    pub(crate) listeners: Vec<ListenerReport>,
    pub(crate) linked_at: e6irc_proto::time::Millis,
}

impl LinkedEdgeView {
    /// Whether the edge must be upgraded before the next core release.
    pub(crate) fn upgrade_needed(&self) -> bool {
        e6irc_link::edge_upgrade_needed(self.newest_version)
    }
}

/// One edge's link: its first session stream made it, and it lasts until any
/// of its connections ends or a newer link of the same edge replaces it.
struct Registration {
    view: LinkedEdgeView,
    generation: u64,
    over: watch::Sender<Option<LinkEnd>>,
}

/// Why a link ends from the core's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkEnd {
    /// One of its connections failed or closed, or the edge linked again.
    Lost,
    /// The core is stopping and has ended every session: what they were last
    /// given is sent before the link closes.
    CoreStopping,
}

impl Registration {
    async fn over(&self) -> LinkEnd {
        let mut over = self.over.subscribe();
        match over.wait_for(Option::is_some).await {
            Ok(end) => end.unwrap_or(LinkEnd::Lost),
            // The sender lives as long as the registration.
            Err(_) => LinkEnd::Lost,
        }
    }

    fn end(&self, end: LinkEnd) {
        self.over.send_if_modified(|over| {
            let first = over.is_none();
            if first {
                *over = Some(end);
            }
            first
        });
    }
}

/// The edges linked to this core now.
#[derive(Default)]
pub(crate) struct LinkedEdges {
    live: Mutex<HashMap<EdgeName, Arc<Registration>>>,
    generations: AtomicU64,
}

impl LinkedEdges {
    /// Every linked edge, by name.
    pub(crate) fn views(&self) -> Vec<LinkedEdgeView> {
        let mut views: Vec<LinkedEdgeView> = self
            .live
            .lock()
            .expect("linked edges")
            .values()
            .map(|registration| registration.view.clone())
            .collect();
        views.sort_by(|left, right| left.name.cmp(&right.name));
        views
    }

    fn current(&self, name: &EdgeName) -> Option<Arc<Registration>> {
        self.live.lock().expect("linked edges").get(name).cloned()
    }

    /// End every link, as the core stops.
    fn end_all(&self) {
        for registration in self.live.lock().expect("linked edges").values() {
            registration.end(LinkEnd::CoreStopping);
        }
    }
}

/// Where each edge's slot is kept: the database's roster, or this process's
/// memory without one.
enum Roster {
    Database(sqlx::PgPool),
    Memory(Mutex<HashMap<EdgeName, Slot>>),
}

impl Roster {
    /// The slot `edge` links with, recorded as linked under `epoch`.
    async fn link(
        &self,
        edge: &EdgeName,
        wanted: Option<Slot>,
        epoch: i64,
        linked: &LinkedEdges,
    ) -> Result<Slot, String> {
        match self {
            Self::Database(pool) => {
                match crate::db::roster::link_edge(
                    pool,
                    edge.as_str(),
                    wanted.map(Slot::get),
                    epoch,
                )
                .await
                {
                    Ok(Some(slot)) => Slot::new(slot)
                        .ok_or_else(|| format!("the roster holds slot {slot} for {edge}")),
                    Ok(None) => Err("every connection slot is taken: the roster names 16383 \
                                     edges; remove the rows of edges that are gone from \
                                     core_edges"
                        .into()),
                    // An edge that has a slot keeps it through a database outage;
                    // its roster row is written when the database answers. A new
                    // edge must wait: only the roster can give it a slot no other
                    // edge holds.
                    Err(error) => match wanted {
                        Some(slot) => {
                            eprintln!(
                                "e6ircd: the roster could not record edge {edge} linking \
                                 (it keeps slot {}): {error}",
                                slot.get()
                            );
                            Ok(slot)
                        }
                        None => Err(format!(
                            "no slot can be given while the database is unreachable: {error}"
                        )),
                    },
                }
            }
            Self::Memory(slots) => {
                let mut slots = slots.lock().expect("edge slots");
                if let Some(slot) = slots.get(edge) {
                    return Ok(*slot);
                }
                let held = |slot: Slot| slots.values().any(|taken| *taken == slot);
                let live = linked.live.lock().expect("linked edges");
                let in_use = |slot: Slot| {
                    held(slot)
                        || live
                            .values()
                            .any(|registration| registration.view.slot == slot)
                };
                let slot = wanted
                    .filter(|slot| !in_use(*slot))
                    .or_else(|| {
                        (1..=e6irc_link::MAX_SLOT)
                            .filter_map(Slot::new)
                            .find(|slot| !in_use(*slot))
                    })
                    .ok_or_else(|| "every connection slot is taken".to_string())?;
                drop(live);
                slots.insert(edge.clone(), slot);
                Ok(slot)
            }
        }
    }

    async fn unlink(&self, edge: &EdgeName) {
        if let Self::Database(pool) = self
            && let Err(error) = crate::db::roster::unlink_edge(pool, edge.as_str()).await
        {
            eprintln!("e6ircd: the roster could not record edge {edge}'s link ending: {error}");
        }
    }
}

/// A WebSocket upgrade the core authorized for an edge to complete: what the
/// session it opens next is given.
pub(crate) enum UpgradeGrant {
    /// A `/ws/irc` session: its per-address slot, taken when it was
    /// authorized, and how it is shown.
    Irc {
        guard: e6irc_edge::address::ConnGuard,
        address: std::net::IpAddr,
        transport: ConnectionTransport,
    },
    /// A live chat socket: its whole authorization.
    Ui(Box<crate::http::UiGrant>),
}

/// How long a granted upgrade waits for the edge to open its session.
const GRANT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30);

/// The upgrades authorized and not yet opened, by the connection identifier
/// the edge will open them under.
#[derive(Default)]
pub(crate) struct EdgeUpgrades {
    granted: Mutex<HashMap<ConnId, (std::time::Instant, UpgradeGrant)>>,
}

impl EdgeUpgrades {
    pub(crate) fn grant(&self, conn: ConnId, grant: UpgradeGrant) {
        let now = std::time::Instant::now();
        let mut granted = self.granted.lock().expect("edge upgrades");
        // A grant never opened (the edge's client went away) holds its slots
        // only until it expires.
        granted.retain(|_, (at, _)| now.duration_since(*at) < GRANT_LIFETIME);
        granted.insert(conn, (now, grant));
    }

    fn take(&self, conn: ConnId) -> Option<UpgradeGrant> {
        let (at, grant) = self.granted.lock().expect("edge upgrades").remove(&conn)?;
        (at.elapsed() < GRANT_LIFETIME).then_some(grant)
    }
}

/// Everything the link listener serves edges with.
pub(crate) struct LinkServer {
    pub(crate) acceptor: TlsAcceptor,
    /// The serving-lease epoch this core holds (0 without a database).
    pub(crate) epoch: i64,
    pub(crate) streams: u16,
    pub(crate) terms: EdgeTerms,
    pub(crate) sendq_bytes: usize,
    pub(crate) core_tx: CoreIngress,
    pub(crate) attach: Option<crate::bouncer::AttachPort>,
    pub(crate) upgrades: Arc<EdgeUpgrades>,
    pub(crate) limiter: ConnLimiter,
    pub(crate) telemetry: Arc<Telemetry>,
    pub(crate) connections: ConnectionTasks,
    pub(crate) edges: Arc<LinkedEdges>,
    roster: Roster,
    pub(crate) http: Option<crate::http::LinkRouters>,
}

/// What [`LinkServer::new`] takes beyond its fields' own values.
pub(crate) struct LinkServerParts {
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) epoch: i64,
    pub(crate) terms: EdgeTerms,
    pub(crate) sendq_bytes: usize,
    pub(crate) core_tx: CoreIngress,
    pub(crate) attach: Option<crate::bouncer::AttachPort>,
    pub(crate) upgrades: Arc<EdgeUpgrades>,
    pub(crate) limiter: ConnLimiter,
    pub(crate) telemetry: Arc<Telemetry>,
    pub(crate) connections: ConnectionTasks,
    pub(crate) edges: Arc<LinkedEdges>,
    pub(crate) pool: Option<sqlx::PgPool>,
    pub(crate) http: Option<crate::http::LinkRouters>,
}

impl LinkServer {
    pub(crate) fn new(parts: LinkServerParts) -> Self {
        let streams = u16::try_from(parts.core_tx.shard_count().len())
            .ok()
            .filter(|streams| *streams <= e6irc_link::MAX_STREAMS)
            .expect("configuration validation bounds the core shards by the link's streams");
        Self {
            acceptor: parts.acceptor,
            epoch: parts.epoch,
            streams,
            terms: parts.terms,
            sendq_bytes: parts.sendq_bytes,
            core_tx: parts.core_tx,
            attach: parts.attach,
            upgrades: parts.upgrades,
            limiter: parts.limiter,
            telemetry: parts.telemetry,
            connections: parts.connections,
            edges: parts.edges,
            roster: match parts.pool {
                Some(pool) => Roster::Database(pool),
                None => Roster::Memory(Mutex::default()),
            },
            http: parts.http,
        }
    }

    /// End every edge's link: the core is stopping, and every session it
    /// carried has been ended.
    pub(crate) fn end_links(&self) {
        self.edges.end_all();
    }
}

/// The lines a stream may have in flight to a shard queue of `core_queue`.
pub(crate) fn line_credit(core_queue: usize) -> u32 {
    u32::try_from(core_queue.clamp(1, MAX_LINE_CREDIT)).expect("bounded above")
}

/// Accept edges on `listener` until the task is aborted.
pub(crate) async fn serve(listener: TcpListener, server: Arc<LinkServer>) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                server.telemetry.record_error(ErrorKind::Accept);
                eprintln!("e6ircd: core link accept failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        tokio::spawn(serve_connection(server.clone(), tcp, peer));
    }
}

/// Why a link connection was refused, as the edge is told and the log says.
fn refuse_log(peer: SocketAddr, edge: Option<&EdgeName>, reason: &str) {
    match edge {
        Some(edge) => {
            eprintln!("e6ircd: refused the core link of edge {edge} from {peer}: {reason}")
        }
        None => eprintln!("e6ircd: refused a core link from {peer}: {reason}"),
    }
}

async fn serve_connection(server: Arc<LinkServer>, tcp: tokio::net::TcpStream, peer: SocketAddr) {
    if let Err(error) = keep_alive(&tcp) {
        server.telemetry.record_error(ErrorKind::ConnectionSetup);
        refuse_log(
            peer,
            None,
            &format!("cannot set up the connection: {error}"),
        );
        return;
    }
    let tls = match tokio::time::timeout(HANDSHAKE_DEADLINE, server.acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => {
            server.telemetry.record_error(ErrorKind::TlsHandshake);
            refuse_log(peer, None, &format!("TLS handshake failed: {error}"));
            return;
        }
        Err(_) => {
            server.telemetry.record_error(ErrorKind::TlsHandshake);
            refuse_log(peer, None, "no TLS handshake within the deadline");
            return;
        }
    };
    let certificates: Vec<_> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let mut tls = tls;
    let hello = match FrameReader::new(&mut tls).first::<EdgeFrame>().await {
        Ok(EdgeFrame::Hello(hello)) => hello,
        Ok(other) => {
            server.telemetry.record_error(ErrorKind::Link);
            refuse_log(
                peer,
                None,
                &format!("its first frame was {other:?}, not Hello"),
            );
            return;
        }
        Err(error) => {
            server.telemetry.record_error(ErrorKind::Link);
            refuse_log(peer, None, &error.to_string());
            return;
        }
    };
    let admitted = match admit(&server, &hello, &certificates).await {
        Ok(admitted) => admitted,
        Err(reason) => {
            server.telemetry.record_error(ErrorKind::Link);
            refuse_log(peer, Some(&hello.edge), &reason);
            drop(write_frame(&mut tls, &CoreFrame::Refused(reason)).await);
            return;
        }
    };
    let welcome = Welcome {
        version: admitted.version,
        epoch: u64::try_from(server.epoch).expect("an epoch is never negative"),
        slot: admitted.registration.view.slot,
        streams: server.streams,
        terms: server.terms.clone(),
        admission: e6irc_link::Admission::Serve,
    };
    if let Err(error) = write_frame(&mut tls, &CoreFrame::Welcome(welcome)).await {
        server.telemetry.record_error(ErrorKind::Link);
        refuse_log(
            peer,
            Some(&hello.edge),
            &format!("cannot send Welcome: {error}"),
        );
        admitted.registration.end(LinkEnd::Lost);
        return;
    }
    match hello.stream {
        Stream::Sessions { index } => {
            let registration = admitted.registration.clone();
            SessionStream::run(server.clone(), registration.clone(), index, tls).await;
            // Any stream's end is the link's end.
            registration.end(LinkEnd::Lost);
            finish_registration(&server, &registration).await;
        }
        Stream::Http => match &server.http {
            Some(routers) => {
                crate::http::serve_link(tls, routers.clone(), admitted.registration.clone_over())
                    .await;
            }
            None => refuse_log(peer, Some(&hello.edge), "this core serves no HTTP"),
        },
    }
}

impl Registration {
    fn clone_over(self: &Arc<Self>) -> impl Future<Output = ()> + Send + 'static {
        let registration = self.clone();
        async move {
            registration.over().await;
        }
    }
}

/// A `Hello` this core accepts, and the link it joins.
struct Admitted {
    version: u16,
    registration: Arc<Registration>,
}

async fn admit(
    server: &LinkServer,
    hello: &Hello,
    certificates: &[tokio_rustls::rustls::pki_types::CertificateDer<'static>],
) -> Result<Admitted, String> {
    let version = e6irc_link::negotiate(hello.versions).map_err(|refused| refused.to_string())?;
    if hello.role == Role::Observer {
        return Err(
            "this core serves no observer link: the warm standby's observer role is \
                    not built into this release; link as a serving edge"
                .into(),
        );
    }
    if !e6irc_edge::core_link::tls::names_edge(certificates, &hello.edge) {
        return Err(format!(
            "the certificate presented is not issued for edge {}",
            hello.edge
        ));
    }
    let highest = i64::try_from(hello.highest_epoch).unwrap_or(i64::MAX);
    if highest > server.epoch {
        return Err(format!(
            "this core holds serving-lease epoch {}, older than epoch {} the edge already \
             accepted: this core no longer holds the lease",
            server.epoch, hello.highest_epoch
        ));
    }
    match hello.stream {
        Stream::Sessions { index: 0 } => {
            let slot = server
                .roster
                .link(&hello.edge, hello.slot, server.epoch, &server.edges)
                .await?;
            let registration = Arc::new(Registration {
                view: LinkedEdgeView {
                    name: hello.edge.clone(),
                    slot,
                    version,
                    newest_version: hello.versions.newest(),
                    listeners: hello.listeners.clone(),
                    linked_at: crate::net::wall_clock(),
                },
                generation: server.edges.generations.fetch_add(1, Ordering::SeqCst),
                over: watch::Sender::new(None),
            });
            let replaced = server
                .edges
                .live
                .lock()
                .expect("linked edges")
                .insert(hello.edge.clone(), registration.clone());
            if let Some(replaced) = replaced {
                eprintln!(
                    "e6ircd: edge {} linked again; its earlier link ends",
                    hello.edge
                );
                replaced.end(LinkEnd::Lost);
            }
            eprintln!(
                "e6ircd: edge {} linked (slot {}, link version {version})",
                hello.edge,
                slot.get()
            );
            Ok(Admitted {
                version,
                registration,
            })
        }
        Stream::Sessions { index } if index >= server.streams => Err(format!(
            "this core has {} session streams; there is no stream {index}",
            server.streams
        )),
        Stream::Sessions { .. } | Stream::Http => {
            let registration = server
                .edges
                .current(&hello.edge)
                .filter(|registration| Some(registration.view.slot) == hello.slot)
                .ok_or_else(|| {
                    format!(
                        "edge {} has no link to this core for this connection to join",
                        hello.edge
                    )
                })?;
            Ok(Admitted {
                version: registration.view.version,
                registration,
            })
        }
    }
}

/// Forget a link that ended, unless the edge linked again already.
async fn finish_registration(server: &LinkServer, registration: &Registration) {
    let removed = {
        let mut live = server.edges.live.lock().expect("linked edges");
        match live.get(&registration.view.name) {
            Some(current) if current.generation == registration.generation => {
                live.remove(&registration.view.name)
            }
            _ => None,
        }
    };
    if removed.is_some() {
        eprintln!("e6ircd: edge {}'s link ended", registration.view.name);
        server.roster.unlink(&registration.view.name).await;
    }
}

/// What the edge says about one session's client, for its pump.
enum Control {
    /// Bytes written to the client socket.
    Drained(u64),
    /// The edge's writer is done: the client closed or could not be written.
    EdgeGone(Option<SendFailure>),
}

/// What reaches an attach's or a live chat socket's own inbound queue.
enum SessionInput {
    Line(LineEvent),
    Message(e6irc_link::UiMessage),
    Closed(SessionClosed),
}

/// One session the core holds for an edge.
struct CoreSession {
    kind: SessionKind,
    control: mpsc::UnboundedSender<Control>,
    /// An attach's or live chat socket's input, which spends its own credit.
    input: Option<mpsc::UnboundedSender<SessionInput>>,
    /// The bytes of input on their way to that queue: at most the window.
    input_in_flight: Arc<AtomicU64>,
    window: u32,
}

/// The core's side of one session stream.
struct SessionStream {
    server: Arc<LinkServer>,
    index: u16,
    /// The link version the edge's link speaks.
    version: u16,
    /// The edge's slot: every session it opens is numbered in it.
    slot: Slot,
    out: mpsc::Sender<CoreFrame>,
    sessions: Arc<Mutex<HashMap<SessionId, CoreSession>>>,
    /// Lines of `Irc` sessions on their way to the shard: at most the window.
    lines_in_flight: Arc<AtomicU32>,
    pusher: mpsc::UnboundedSender<Input>,
    /// A peer that broke the protocol: the link ends.
    fault: watch::Sender<Option<String>>,
}

impl SessionStream {
    async fn run<S>(server: Arc<LinkServer>, registration: Arc<Registration>, index: u16, tls: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        // A stopping core waits for its links to send what their sessions
        // were last given, as it waits for its own clients' connections.
        let _task = server.connections.task();
        let (read_half, write_half) = tokio::io::split(tls);
        let (out, mut frames) = mpsc::channel(STREAM_QUEUE);
        let (pusher, inputs) = mpsc::unbounded_channel();
        let lines_in_flight = Arc::new(AtomicU32::new(0));
        let stream = Arc::new(SessionStream {
            server: server.clone(),
            index,
            version: registration.view.version,
            slot: registration.view.slot,
            out: out.clone(),
            sessions: Arc::default(),
            lines_in_flight: lines_in_flight.clone(),
            pusher,
            fault: watch::Sender::new(None),
        });
        let mut writer = tokio::spawn(async move { write_frames(write_half, &mut frames).await });
        let pushing = tokio::spawn(push_lines(
            server.core_tx.clone(),
            inputs,
            out,
            lines_in_flight,
            server.terms.line_credit,
        ));
        let mut faults = stream.fault.subscribe();
        let (ended, graceful) = tokio::select! {
            read = stream.clone().read(read_half) => match read {
                Ok(()) => ("the edge closed it".to_string(), false),
                Err(error) => (error.to_string(), false),
            },
            written = &mut writer => match written {
                Ok(Ok(())) => ("its writer stopped".to_string(), false),
                Ok(Err(error)) => (error.to_string(), false),
                Err(error) => (format!("its writer failed: {error}"), false),
            },
            end = registration.over() => match end {
                LinkEnd::CoreStopping => ("the core is stopping".to_string(), true),
                LinkEnd::Lost => ("the edge linked again, or another of its connections ended".to_string(), false),
            },
            fault = faults.wait_for(Option::is_some) => match fault {
                Ok(fault) => (fault.clone().unwrap_or_default(), false),
                Err(_) => ("its fault watch ended".to_string(), false),
            },
        };
        eprintln!(
            "e6ircd: session stream {index} of edge {} ended: {ended}",
            registration.view.name
        );
        if graceful {
            // The core ended every session: each pump sends what its session
            // was last given, then `End`, and the writer sends it all before
            // the link closes — bounded by the stop's connection drain, which
            // this task is one of.
            drop(stream);
            drop(pushing.await);
            drop(writer.await);
            return;
        }
        // Every session the stream carried ends here; its IRC sessions quit
        // behind whatever of theirs is still on its way to the shard.
        let ended: Vec<(SessionId, CoreSession)> = stream
            .sessions
            .lock()
            .expect("stream sessions")
            .drain()
            .collect();
        for (session, core_session) in ended {
            stream.end_session(
                session,
                core_session,
                SessionClosed::Stopped(LINK_LOST.into()),
            );
        }
        drop(stream);
        drop(pushing.await);
        writer.abort();
    }

    /// Break the link: the edge sent what the protocol does not allow.
    fn broken(&self, what: String) {
        self.server.telemetry.record_error(ErrorKind::Link);
        self.fault.send_replace(Some(what));
    }

    async fn read<R: AsyncRead + Unpin>(self: Arc<Self>, read_half: R) -> io::Result<()> {
        let mut reader = FrameReader::new(read_half);
        while let Some(frame) = reader.next::<EdgeFrame>().await? {
            if frame.since() > self.version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "core link: a frame of link version {} on a link of version {}",
                        frame.since(),
                        self.version
                    ),
                ));
            }
            match frame {
                EdgeFrame::Open(session, open) => self.open(session, open).await,
                EdgeFrame::Line(session, line) => {
                    self.input(session, LineEvent::Line(line.to_vec()));
                }
                EdgeFrame::OverlongLine(session, label) => {
                    self.input(session, LineEvent::TooLong { label });
                }
                EdgeFrame::Message(session, message) => self.message(session, message),
                EdgeFrame::Closed(session, reason) => self.closed(session, session_closed(reason)),
                EdgeFrame::Drained(session, bytes) => {
                    if let Some(core_session) =
                        self.sessions.lock().expect("stream sessions").get(&session)
                    {
                        drop(core_session.control.send(Control::Drained(bytes)));
                    }
                }
                EdgeFrame::Hello(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "core link: Hello after the handshake",
                    ));
                }
                EdgeFrame::Paused
                | EdgeFrame::Upload(..)
                | EdgeFrame::RecordUpload(..)
                | EdgeFrame::ReplicaUpload(_)
                | EdgeFrame::CutUpload(_)
                | EdgeFrame::UploadDone => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "core link: a frame of a cut this core did not make",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Refuse a session the edge opened, telling its client why.
    async fn refuse(
        &self,
        session: SessionId,
        address: std::net::IpAddr,
        kind: SessionKind,
        reason: &str,
    ) {
        let frame = match kind {
            SessionKind::Ui => CoreFrame::End(
                session,
                Some(CloseFrame {
                    code: 1008,
                    reason: reason.chars().take(60).collect(),
                }),
            ),
            SessionKind::Irc | SessionKind::Attach => CoreFrame::Kill(
                session,
                bytes::Bytes::from(format!(
                    "ERROR :Closing Link: {} ({reason})\r\n",
                    ClientIp::new(address)
                )),
            ),
        };
        drop(self.out.send(frame).await);
    }

    async fn open(self: &Arc<Self>, session: SessionId, open: Open) {
        let conn = ConnId(session.get());
        let in_slot = session.get() >> e6irc_link::SLOT_SHIFT == u64::from(self.slot.get());
        let on_stream =
            e6irc_edge::core_link::remote::stream_of(session, usize::from(self.server.streams))
                == usize::from(self.index);
        if !in_slot || !on_stream {
            self.broken(format!(
                "session {} is not in the edge's slot, or not on its shard's stream",
                session.get()
            ));
            return;
        }
        if self
            .sessions
            .lock()
            .expect("stream sessions")
            .contains_key(&session)
        {
            self.broken(format!("session {} opened twice", session.get()));
            return;
        }
        let transport = match open.transport {
            Transport::Tcp => ConnectionTransport::Tcp,
            Transport::Tls => ConnectionTransport::Tls,
            Transport::WebSocket => ConnectionTransport::WebSocket,
            Transport::SecureWebSocket => ConnectionTransport::SecureWebSocket,
        };
        let client = ClientIp::new(open.address);
        let websocket = matches!(
            transport,
            ConnectionTransport::WebSocket | ConnectionTransport::SecureWebSocket
        );
        match open.kind {
            SessionKind::Irc if websocket => {
                let Some(UpgradeGrant::Irc {
                    guard,
                    address,
                    transport,
                }) = self.server.upgrades.take(conn)
                else {
                    self.refuse(
                        session,
                        open.address,
                        open.kind,
                        "the WebSocket upgrade was not authorized",
                    )
                    .await;
                    return;
                };
                self.open_irc(session, ClientIp::new(address), transport, None, guard);
            }
            SessionKind::Irc => {
                let Some(guard) = self.server.limiter.try_acquire(client) else {
                    self.server
                        .limiter
                        .refusals()
                        .note(client, PeerRefusal::PerIpLimit, None);
                    self.server.telemetry.record_connection_rejected();
                    self.refuse(
                        session,
                        open.address,
                        open.kind,
                        "Too many connections from your address",
                    )
                    .await;
                    return;
                };
                self.open_irc(session, client, transport, open.tls, guard);
            }
            SessionKind::Attach => {
                let Some(port) = self.server.attach.clone() else {
                    self.refuse(
                        session,
                        open.address,
                        open.kind,
                        "this server has no bouncer to attach to",
                    )
                    .await;
                    return;
                };
                let Some(guard) = self.server.limiter.try_acquire(client) else {
                    self.server
                        .limiter
                        .refusals()
                        .note(client, PeerRefusal::PerIpLimit, None);
                    self.server.telemetry.record_connection_rejected();
                    self.refuse(
                        session,
                        open.address,
                        open.kind,
                        "Too many connections from your address",
                    )
                    .await;
                    return;
                };
                let edge = port
                    .open(
                        conn,
                        client.to_string(),
                        transport,
                        open.tls,
                        self.server.sendq_bytes,
                    )
                    .await
                    .expect("the attach port always opens");
                let window = u32::try_from(crate::bouncer::ATTACH_INBOUND_BYTES).expect("small");
                let (input, inputs) = mpsc::unbounded_channel();
                let in_flight = Arc::new(AtomicU64::new(0));
                tokio::spawn(feed_attach(
                    port,
                    conn,
                    session,
                    inputs,
                    self.out.clone(),
                    in_flight.clone(),
                    window,
                ));
                self.start(
                    session,
                    SessionKind::Attach,
                    edge,
                    Some((input, in_flight, window)),
                    guard.into(),
                );
                drop(
                    self.out
                        .send(CoreFrame::Credit(Credit::Session(session, window)))
                        .await,
                );
            }
            SessionKind::Ui => {
                let Some(UpgradeGrant::Ui(grant)) = self.server.upgrades.take(conn) else {
                    self.refuse(
                        session,
                        open.address,
                        open.kind,
                        "the WebSocket upgrade was not authorized",
                    )
                    .await;
                    return;
                };
                let (edge, inbound) = crate::http::open_granted_ui(*grant);
                let window = u32::try_from(e6irc_link::MAX_UI_MESSAGE_LEN).expect("small");
                let (input, inputs) = mpsc::unbounded_channel();
                let in_flight = Arc::new(AtomicU64::new(0));
                tokio::spawn(feed_ui(
                    inbound,
                    session,
                    inputs,
                    self.out.clone(),
                    in_flight.clone(),
                    window,
                ));
                self.start(
                    session,
                    SessionKind::Ui,
                    edge,
                    Some((input, in_flight, window)),
                    SessionHold::default(),
                );
                drop(
                    self.out
                        .send(CoreFrame::Credit(Credit::Session(session, window)))
                        .await,
                );
            }
        }
    }

    /// Open an IRC session on its shard, in order with its lines.
    fn open_irc(
        self: &Arc<Self>,
        session: SessionId,
        client: ClientIp,
        transport: ConnectionTransport,
        tls: Option<e6irc_link::TlsFacts>,
        guard: e6irc_edge::address::ConnGuard,
    ) {
        let (input, edge) = self.server.core_tx.open_input(
            ConnId(session.get()),
            client.to_string(),
            transport,
            tls,
            self.server.sendq_bytes,
        );
        if self.pusher.send(input).is_err() {
            return;
        }
        self.start(session, SessionKind::Irc, edge, None, guard.into());
    }

    /// Place `session` in the stream and start its pump.
    fn start(
        self: &Arc<Self>,
        session: SessionId,
        kind: SessionKind,
        edge: EdgeSession,
        input: Option<(mpsc::UnboundedSender<SessionInput>, Arc<AtomicU64>, u32)>,
        hold: SessionHold,
    ) {
        let (control, controls) = mpsc::unbounded_channel();
        let (input, input_in_flight, window) = match input {
            Some((input, in_flight, window)) => (Some(input), in_flight, window),
            None => (None, Arc::default(), 0),
        };
        self.sessions.lock().expect("stream sessions").insert(
            session,
            CoreSession {
                kind,
                control,
                input,
                input_in_flight,
                window,
            },
        );
        let pump = Pump {
            exemption: edge.flood_exemption(),
            edge,
            session,
            controls,
            out: self.out.clone(),
            stream: Arc::downgrade(self),
            _task: self.server.connections.task(),
            _hold: hold,
        };
        tokio::spawn(pump.run());
    }

    /// A line of `session`'s client.
    fn input(&self, session: SessionId, event: LineEvent) {
        let sessions = self.sessions.lock().expect("stream sessions");
        let Some(core_session) = sessions.get(&session) else {
            // A session ended here the edge had not yet heard of.
            return;
        };
        match core_session.kind {
            SessionKind::Irc => {
                let in_flight = self.lines_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                if in_flight > self.server.terms.line_credit {
                    drop(sessions);
                    self.broken("the edge sent lines past its credit".into());
                    return;
                }
                drop(
                    self.pusher
                        .send(Input::framed(ConnId(session.get()), event)),
                );
            }
            SessionKind::Attach => {
                let charge = u64::try_from(attach_line_weight(&event))
                    .unwrap_or(u64::MAX)
                    .min(u64::from(core_session.window));
                self.session_input(core_session, charge, SessionInput::Line(event));
            }
            SessionKind::Ui => {
                drop(sessions);
                self.broken("a live chat socket sent an IRC line".into());
            }
        }
    }

    fn message(&self, session: SessionId, message: e6irc_link::UiMessage) {
        let sessions = self.sessions.lock().expect("stream sessions");
        let Some(core_session) = sessions.get(&session) else {
            return;
        };
        if core_session.kind != SessionKind::Ui {
            drop(sessions);
            self.broken("an IRC session sent a WebSocket message".into());
            return;
        }
        let charge = u64::try_from(ui_message_weight(&message))
            .unwrap_or(u64::MAX)
            .min(u64::from(core_session.window));
        self.session_input(core_session, charge, SessionInput::Message(message));
    }

    /// Hand one input to its session's own queue, within its credit.
    fn session_input(&self, core_session: &CoreSession, charge: u64, input: SessionInput) {
        let in_flight = core_session
            .input_in_flight
            .fetch_add(charge, Ordering::SeqCst)
            + charge;
        if in_flight > u64::from(core_session.window) {
            self.broken("the edge sent a session's input past its credit".into());
            return;
        }
        if let Some(sender) = &core_session.input {
            drop(sender.send(input));
        }
    }

    /// The client's side of `session` ended. When the edge's writer is gone
    /// with it — it failed, or a live chat socket, whose end comes once its
    /// writer is done — the session is over here too; otherwise only its
    /// input is, and what the core still sends it (the answers to what it
    /// sent before closing, its closing `ERROR`) goes out until the core ends
    /// it, as a client that closes its sending side is owed.
    fn closed(&self, session: SessionId, reason: SessionClosed) {
        let mut sessions = self.sessions.lock().expect("stream sessions");
        let Some(core_session) = sessions.get_mut(&session) else {
            return;
        };
        let writer_gone = core_session.kind == SessionKind::Ui
            || matches!(
                reason,
                SessionClosed::WriteFailed(_) | SessionClosed::WriterPanicked
            );
        if writer_gone {
            let core_session = sessions.remove(&session).expect("present above");
            drop(sessions);
            self.end_session(session, core_session, reason);
            return;
        }
        let input = core_session.input.take();
        drop(sessions);
        self.end_input(session, input, reason);
    }

    /// No more input reaches `session`: the core hears why, behind whatever
    /// of its input is still on its way.
    fn end_input(
        &self,
        session: SessionId,
        input: Option<mpsc::UnboundedSender<SessionInput>>,
        reason: SessionClosed,
    ) {
        match input {
            // An attach's input goes to its own queue; a live chat socket has
            // no `Closed` input but the end of its queue, which dropping its
            // sender is.
            Some(input) => {
                drop(input.send(SessionInput::Closed(reason)));
            }
            None => {
                drop(self.pusher.send(Input::Closed {
                    conn: ConnId(session.get()),
                    reason: reason.to_string(),
                }));
            }
        }
    }

    /// `session` is over on the edge's side: its pump stops, and the core
    /// hears why, behind whatever of its input is still on its way.
    fn end_session(&self, session: SessionId, core_session: CoreSession, reason: SessionClosed) {
        let failure = match &reason {
            SessionClosed::WriteFailed(failure) => Some(failure.clone()),
            _ => None,
        };
        drop(core_session.control.send(Control::EdgeGone(failure)));
        match core_session.kind {
            SessionKind::Irc => self.end_input(session, None, reason),
            // An input already ended was told once.
            SessionKind::Attach | SessionKind::Ui => {
                if let Some(input) = core_session.input {
                    self.end_input(session, Some(input), reason);
                }
            }
        }
    }
}

/// What a session holds for as long as its pump runs: its per-address slot.
#[derive(Default)]
struct SessionHold {
    _guard: Option<e6irc_edge::address::ConnGuard>,
}

impl From<e6irc_edge::address::ConnGuard> for SessionHold {
    fn from(guard: e6irc_edge::address::ConnGuard) -> Self {
        Self {
            _guard: Some(guard),
        }
    }
}

/// Move a stream's IRC input into the shards' queues in order, granting the
/// edge a credit back for each line moved.
async fn push_lines(
    core_tx: CoreIngress,
    mut inputs: mpsc::UnboundedReceiver<Input>,
    out: mpsc::Sender<CoreFrame>,
    lines_in_flight: Arc<AtomicU32>,
    window: u32,
) {
    let batch = (window / 4).max(1);
    let mut returned = 0u32;
    while let Some(input) = inputs.recv().await {
        let line = matches!(input, Input::Line { .. } | Input::OverlongLine { .. });
        if core_tx.push(input).await.is_err() {
            // The core is gone; nothing more reaches it.
            return;
        }
        if line {
            lines_in_flight.fetch_sub(1, Ordering::SeqCst);
            returned += 1;
            if returned >= batch || inputs.is_empty() {
                if out
                    .send(CoreFrame::Credit(Credit::Stream(returned)))
                    .await
                    .is_err()
                {
                    // The link is over; the remaining input still reaches
                    // the core, which must hear each session's end.
                    returned = 0;
                    continue;
                }
                returned = 0;
            }
        }
    }
}

/// Hand an attach's lines to its session's queue, crediting each back once
/// it is taken in.
async fn feed_attach(
    port: crate::bouncer::AttachPort,
    conn: ConnId,
    session: SessionId,
    mut inputs: mpsc::UnboundedReceiver<SessionInput>,
    out: mpsc::Sender<CoreFrame>,
    in_flight: Arc<AtomicU64>,
    window: u32,
) {
    while let Some(input) = inputs.recv().await {
        match input {
            SessionInput::Line(event) => {
                let charge = u32::try_from(attach_line_weight(&event))
                    .unwrap_or(u32::MAX)
                    .min(window);
                if !port.push(conn, event).await {
                    return;
                }
                in_flight.fetch_sub(u64::from(charge), Ordering::SeqCst);
                drop(
                    out.send(CoreFrame::Credit(Credit::Session(session, charge)))
                        .await,
                );
            }
            SessionInput::Closed(reason) => {
                port.closed(conn, reason).await;
                return;
            }
            SessionInput::Message(_) => unreachable!("an attach's input is lines"),
        }
    }
}

/// Hand a live chat socket's messages to its session's queue, crediting each
/// back once it is taken in; its client closing ends the queue.
async fn feed_ui(
    inbound: e6irc_queue::Sender<e6irc_link::UiMessage>,
    session: SessionId,
    mut inputs: mpsc::UnboundedReceiver<SessionInput>,
    out: mpsc::Sender<CoreFrame>,
    in_flight: Arc<AtomicU64>,
    window: u32,
) {
    while let Some(input) = inputs.recv().await {
        match input {
            SessionInput::Message(message) => {
                let charge = u32::try_from(ui_message_weight(&message))
                    .unwrap_or(u32::MAX)
                    .min(window);
                if inbound.push(message).await.is_err() {
                    return;
                }
                in_flight.fetch_sub(u64::from(charge), Ordering::SeqCst);
                drop(
                    out.send(CoreFrame::Credit(Credit::Session(session, charge)))
                        .await,
                );
            }
            SessionInput::Closed(_) => return,
            SessionInput::Line(_) => unreachable!("a live chat socket's input is messages"),
        }
    }
}

/// One session's output, carried to its edge: the edge's writer, as this
/// side of the link plays it.
struct Pump {
    edge: EdgeSession,
    exemption: e6irc_edge::meter::FloodExemption,
    session: SessionId,
    controls: mpsc::UnboundedReceiver<Control>,
    out: mpsc::Sender<CoreFrame>,
    stream: std::sync::Weak<SessionStream>,
    _task: e6irc_edge::connection::ConnectionTask,
    _hold: SessionHold,
}

impl Pump {
    async fn run(mut self) {
        let mut controls_open = true;
        loop {
            tokio::select! {
                taken = self.edge.take() => match taken {
                    Some(envelope) => {
                        let final_line = self.edge.is_final(&envelope);
                        let Output(bytes) = envelope.payload;
                        let frame = if final_line {
                            CoreFrame::Kill(self.session, bytes)
                        } else {
                            CoreFrame::Output(self.session, bytes)
                        };
                        if self.out.send(frame).await.is_err() {
                            return;
                        }
                    }
                    None => {
                        let close = self.edge.close_frame().map(|close| CloseFrame {
                            code: close.code,
                            reason: close.reason.into_owned(),
                        });
                        drop(self.out.send(CoreFrame::End(self.session, close)).await);
                        if let Some(stream) = self.stream.upgrade() {
                            stream.sessions.lock().expect("stream sessions").remove(&self.session);
                        }
                        return;
                    }
                },
                control = self.controls.recv(), if controls_open => match control {
                    Some(Control::Drained(bytes)) => {
                        if bytes > self.edge.unreported() {
                            if let Some(stream) = self.stream.upgrade() {
                                stream.broken(format!(
                                    "session {} reported {bytes} bytes written of {} sent",
                                    self.session.get(),
                                    self.edge.unreported()
                                ));
                            }
                            return;
                        }
                        self.edge.written(usize::try_from(bytes).expect("at most what was sent"));
                    }
                    Some(Control::EdgeGone(failure)) => {
                        if let Some(failure) = failure {
                            self.edge.writer_failed(failure);
                        }
                        return;
                    }
                    // The stream stopped reading (the core is stopping): what
                    // the session was last given still goes out.
                    None => controls_open = false,
                },
                () = self.exemption.changed() => {
                    let exempt = self.exemption.exempt();
                    if self.out.send(CoreFrame::FloodExempt(self.session, exempt)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
