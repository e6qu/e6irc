//! The graceful cut and the rebuild (DESIGN §19.3), the core's half: what a
//! stopping core does so its edges hold every session for the next, and what
//! the next core does to resume them.
//!
//! **The cut** ([`Handover`]): the core stops taking links, asks every edge
//! to pause its input and waits for each stream's `Paused`; waits until
//! nothing is in flight — every line handed to its shard, nothing passing
//! between shards, no database round trip awaited
//! ([`crate::core::CoreIngress::unsettled`]) — closing loudly any session
//! still waiting when the bound passes; then cuts every shard, which
//! republishes every record and replica and handles nothing more; each
//! stream's pumps send what their sessions were last given and stop without
//! ending them; the first stream carries the cut state, and every stream
//! ends with `Cut`. The edges hold their sessions for the next core.
//!
//! **The rebuild** ([`RebuildGate`]): the next core holds every edge that
//! links while it waits for those holding the cut — named by the roster, or,
//! without a database, by the cut state the first of them uploads — for at
//! most [`ROSTER_WAIT`] (D12). An edge holding the cut uploads each session
//! it holds (what it knows of it, and the core's record), each channel
//! replica, and the cut state. The core then decodes each record (a body it
//! cannot read closes that one session loudly), merges the replicas — the
//! highest revision's state, every edge's members — and hands each shard its
//! channels, then its sessions, in the records' original directory order;
//! re-authorizes every login against the database (§2) and every address
//! against the server bans; and resumes every edge.
//!
//! **The core's own sessions** (decision D13; [`crate::core::local_home`]):
//! the `local` bouncer network's in-process sessions have no edge of their
//! own, so a cut homes them on the first edge that holds it — their records
//! (`Home`, then `Record`) and their channel memberships (slot 0's replicas)
//! — and the rebuild hands each back to its network's driver, which takes it
//! up instead of registering again. Without an edge to home them on they
//! end before the cut, as any session no edge holds.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use e6irc_edge::address::ClientIp;
use e6irc_edge::connection::ConnId;
use e6irc_edge::core_link::remote::session_closed;
use e6irc_link::{
    Admission, Body, BodyPart, CoreFrame, Cut, CutId, CutPart, EdgeName, RecordPart, Replica,
    ReplicaChange, SessionId, SessionKind, Upload,
};
use tokio::sync::mpsc;

use super::{LinkEnd, LinkServer, LinkedEdges, Registration, SessionStream};
use crate::core::local_home::{LocalHomeKey, ResumedLocal};
use crate::core::record::{
    AttachRecord, ChannelState, ClockOrigin, CutState, LocalRecord, MemberEntry,
    RecordedRegistration, SessionRecord, UiRecord,
};
use crate::core::{CoreShardId, Input};

/// How long the next core waits for the edges holding a cut (D12).
pub(crate) const ROSTER_WAIT: Duration = Duration::from_secs(30);

/// Without a roster to name them, how long a core waits for an edge holding a
/// cut to link before it serves: every edge dials every 250 ms, so one that
/// holds a cut links within it.
const DISCOVERY_WAIT: Duration = Duration::from_secs(1);

/// How long a cut waits for each stream's `Paused`.
const PAUSE_WAIT: Duration = Duration::from_secs(5);

/// How long a cut asked of a core still rebuilding waits for the rebuild: the
/// wait for the edges, then the rebuild itself.
const REBUILD_FINISH_WAIT: Duration = Duration::from_secs(2 * ROSTER_WAIT.as_secs());

/// How long a cut waits for the work in flight to settle before it closes
/// the sessions still waiting.
const SETTLE_WAIT: Duration = Duration::from_secs(10);

/// How long a cut waits for each stream's pumps to send what is left, and
/// for the core's own sessions to take their records.
const FLUSH_WAIT: Duration = Duration::from_secs(10);

/// How long a session of the core's own that a rebuild resumed waits for its
/// network's driver — which starts once the rebuild is over — before it is
/// closed: its network is gone from this core's configuration.
const LOCAL_CLAIM_WAIT: Duration = Duration::from_secs(10);

/// The cut the roster says the edges hold: its identifier and the edges it
/// was sent to.
#[derive(Debug, Clone)]
pub(crate) struct PendingCut {
    pub(crate) cut: CutId,
    pub(crate) edges: Vec<EdgeName>,
}

/// Where the shards' replicas go: to the edge holding a slot, on the stream
/// of the shard that owns the channel.
pub(crate) struct ReplicaRoutes(pub(crate) Arc<LinkedEdges>);

impl crate::core::ReplicaSink for ReplicaRoutes {
    fn send(&self, slot: u16, shard: CoreShardId, replica: Replica) {
        // Slot 0 is the core's own: its sessions' memberships go to the edge
        // a cut homes them on, and nowhere before.
        let slot = match slot {
            0 => match *self.0.local_home.lock().expect("local home") {
                Some(home) => home,
                None => return,
            },
            slot => slot,
        };
        let registration = self
            .0
            .live
            .lock()
            .expect("linked edges")
            .values()
            .find(|registration| registration.view.slot.get() == slot)
            .cloned();
        // An edge that is not linked, or links at version 1, holds no replica:
        // the rebuild asks the edges that hold the cut for theirs.
        let Some(registration) = registration.filter(|registration| registration.view.version >= 2)
        else {
            return;
        };
        let index = u16::try_from(shard.index()).expect("a shard index fits a stream index");
        let stream = registration
            .streams
            .lock()
            .expect("link streams")
            .get(&index)
            .cloned();
        if let Some(stream) = stream
            && let Some(queue) = stream.replicas.lock().expect("stream replicas").as_ref()
        {
            // Closed only when the stream ends, whose edge then holds nothing.
            drop(queue.send(replica));
        }
    }
}

/// Carry a stream's replicas to its writer, in the order they were published.
pub(super) async fn forward_replicas(
    mut replicas: mpsc::UnboundedReceiver<Replica>,
    out: mpsc::Sender<CoreFrame>,
) {
    while let Some(replica) = replicas.recv().await {
        if out.send(CoreFrame::Replica(replica)).await.is_err() {
            return;
        }
    }
}

/// What one stream uploaded of the cut its edge holds.
#[derive(Default)]
pub(super) struct StreamUploads {
    sessions: HashMap<SessionId, (Upload, Body)>,
    /// The core's own sessions the last core homed on this edge.
    homed: HashMap<SessionId, Body>,
    replicas: Vec<Replica>,
    cut: Option<(CutId, Body)>,
    done: bool,
}

impl SessionStream {
    fn uploading(&self) -> io::Result<()> {
        if self.registration.admission != Admission::Upload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "core link: an upload from an edge not asked to upload",
            ));
        }
        if self.uploads.lock().expect("stream uploads").done {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "core link: an upload after UploadDone",
            ));
        }
        Ok(())
    }

    pub(super) fn upload(&self, session: SessionId, upload: Upload) -> io::Result<()> {
        self.uploading()?;
        self.check_owned(session, self.slot.get())?;
        let mut uploads = self.uploads.lock().expect("stream uploads");
        if uploads
            .sessions
            .insert(session, (upload, Body::default()))
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "core link: a session uploaded twice",
            ));
        }
        Ok(())
    }

    /// A session of the last core's own, homed on this edge at its cut.
    pub(super) fn upload_home(&self, session: SessionId) -> io::Result<()> {
        self.uploading()?;
        self.check_owned(session, 0)?;
        let mut uploads = self.uploads.lock().expect("stream uploads");
        if uploads.homed.insert(session, Body::default()).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "core link: a homed session uploaded twice",
            ));
        }
        Ok(())
    }

    pub(super) fn upload_record(&self, session: SessionId, part: RecordPart) -> io::Result<()> {
        self.uploading()?;
        let mut uploads = self.uploads.lock().expect("stream uploads");
        let uploads = &mut *uploads;
        let body = match uploads.sessions.get_mut(&session) {
            Some((_, body)) => body,
            None => uploads.homed.get_mut(&session).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "core link: a record uploaded for a session not uploaded",
                )
            })?,
        };
        body.gather(part.part)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    pub(super) fn upload_replica(&self, replica: Replica) -> io::Result<()> {
        self.uploading()?;
        self.uploads
            .lock()
            .expect("stream uploads")
            .replicas
            .push(replica);
        Ok(())
    }

    pub(super) fn upload_cut(&self, part: CutPart) -> io::Result<()> {
        self.uploading()?;
        let mut uploads = self.uploads.lock().expect("stream uploads");
        let (cut, body) = uploads
            .cut
            .get_or_insert_with(|| (part.cut, Body::default()));
        if *cut != part.cut {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "core link: the cut state of two cuts",
            ));
        }
        body.gather(part.part)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    pub(super) fn upload_done(self: &Arc<Self>) -> io::Result<()> {
        self.uploading()?;
        self.uploads.lock().expect("stream uploads").done = true;
        self.server.rebuild.stream_uploaded(&self.server);
        Ok(())
    }

    /// A session of this stream's: numbered in `slot` — its edge's, or the
    /// core's own (0) for a homed one — on this stream's shard.
    fn check_owned(&self, session: SessionId, slot: u16) -> io::Result<()> {
        let in_slot = session.get() >> e6irc_link::SLOT_SHIFT == u64::from(slot);
        let on_stream =
            e6irc_edge::core_link::remote::stream_of(session, usize::from(self.server.streams))
                == usize::from(self.index);
        if in_slot && on_stream {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "core link: session {} is not this stream's to upload",
                    session.get()
                ),
            ))
        }
    }

    /// Stop carrying replicas: the forwarder sends what is queued, then ends.
    pub(super) fn close_replicas(&self) {
        drop(self.replicas.lock().expect("stream replicas").take());
    }

    /// Send `Resume`, once, unless a cut paused the stream first: the edge
    /// sends input again.
    async fn resume(&self) {
        let mut control = self.control.lock().await;
        if *control == StreamControl::Held {
            *control = StreamControl::Flowing;
            // A link that is gone has no input to resume.
            drop(self.out.send(CoreFrame::Resume).await);
        }
    }

    /// Stop the edge's input on this stream for a cut.
    async fn pause(&self) -> Pausing {
        let mut control = self.control.lock().await;
        let was = std::mem::replace(&mut *control, StreamControl::Paused);
        if was != StreamControl::Flowing {
            return Pausing::NeverResumed;
        }
        if self.out.send(CoreFrame::Pause).await.is_ok() {
            Pausing::Asked
        } else {
            Pausing::Gone
        }
    }
}

/// How a stream was paused for a cut.
enum Pausing {
    /// `Pause` was sent: the edge answers `Paused`.
    Asked,
    /// Its input never flowed, so it is paused as it is.
    NeverResumed,
    /// Its link is gone.
    Gone,
}

/// Whether an edge's input flows on one stream, as the core has said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamControl {
    /// Admitted to hold or upload: input waits for `Resume`.
    Held,
    Flowing,
    /// A cut paused it: nothing resumes it again.
    Paused,
}

impl StreamControl {
    /// A stream of a link admitted with `admission`.
    pub(super) fn of(admission: Admission) -> Self {
        match admission {
            Admission::Serve => Self::Flowing,
            Admission::Hold | Admission::Upload => Self::Held,
        }
    }
}

use std::io;

/// One edge's part in a rebuild.
struct EdgeUpload {
    registration: Arc<Registration>,
}

enum GateState {
    /// Waiting for the edges holding the cut, until `deadline`.
    Waiting {
        cut: Option<CutId>,
        expected: HashSet<EdgeName>,
        uploading: HashMap<EdgeName, EdgeUpload>,
        deadline: tokio::time::Instant,
    },
    /// The rebuild is running.
    Rebuilding,
    /// Every edge is served.
    Open,
}

/// Whether this core rebuilds from a cut, and how far it has got.
pub(super) struct RebuildGate {
    state: Mutex<GateState>,
}

impl RebuildGate {
    /// The gate of a core whose roster names `pending`, or — for a core with
    /// no roster to ask (`discover`) — one that waits a moment for an edge
    /// holding a cut to link. A database-backed core whose roster names no
    /// cut rebuilds nothing, and serves at once.
    pub(super) fn new(pending: Option<PendingCut>, discover: bool) -> Self {
        let now = tokio::time::Instant::now();
        let waiting = |cut, expected, deadline| GateState::Waiting {
            cut,
            expected,
            uploading: HashMap::new(),
            deadline,
        };
        let state = match pending {
            Some(pending) => waiting(
                Some(pending.cut),
                pending.edges.into_iter().collect(),
                now + ROSTER_WAIT,
            ),
            None if discover => waiting(None, HashSet::new(), now + DISCOVERY_WAIT),
            None => GateState::Open,
        };
        Self {
            state: Mutex::new(state),
        }
    }

    /// Whether every edge is served.
    pub(super) fn is_open(&self) -> bool {
        matches!(*self.state.lock().expect("rebuild gate"), GateState::Open)
    }

    /// How the core admits edge `edge`, speaking `version`, holding `cut`.
    pub(super) fn admit(&self, edge: &EdgeName, version: u16, cut: Option<CutId>) -> Admission {
        if version < 2 {
            // A version 1 edge holds nothing and knows no hold: it serves.
            return Admission::Serve;
        }
        let mut state = self.state.lock().expect("rebuild gate");
        let GateState::Waiting {
            cut: expected_cut,
            expected,
            deadline,
            ..
        } = &mut *state
        else {
            if cut.is_some() {
                eprintln!(
                    "e6ircd: edge {edge} holds sessions from a cut this core did not wait for; \
                     it closes them"
                );
            }
            return if matches!(*state, GateState::Open) {
                Admission::Serve
            } else {
                Admission::Hold
            };
        };
        match cut {
            Some(cut) if expected_cut.is_none_or(|expected| expected == cut) => {
                if expected_cut.is_none() {
                    // The first edge holding a cut names it; the edges it was
                    // sent to are learnt from the cut state it uploads.
                    *expected_cut = Some(cut);
                    *deadline = tokio::time::Instant::now() + ROSTER_WAIT;
                }
                expected.insert(edge.clone());
                Admission::Upload
            }
            Some(cut) => {
                eprintln!(
                    "e6ircd: edge {edge} holds sessions from cut {:#x}, not the cut this core \
                     rebuilds; it closes them",
                    cut.get()
                );
                Admission::Hold
            }
            None => Admission::Hold,
        }
    }

    /// Note that a registration joined the rebuild with `admission`: one
    /// that uploads is waited for. Every edge linked when the rebuild is over
    /// is resumed then.
    fn joined(&self, registration: &Arc<Registration>) {
        let mut state = self.state.lock().expect("rebuild gate");
        if let GateState::Waiting { uploading, .. } = &mut *state
            && registration.admission == Admission::Upload
        {
            uploading.insert(
                registration.view.name.clone(),
                EdgeUpload {
                    registration: registration.clone(),
                },
            );
        }
    }

    /// A stream sent `UploadDone`: rebuild once every edge expected has.
    fn stream_uploaded(&self, server: &Arc<LinkServer>) {
        if self.ready(server.streams) {
            spawn_rebuild(server.clone());
        }
    }

    /// Whether every edge expected has uploaded every stream; the gate then
    /// moves on to rebuilding, once.
    fn ready(&self, streams: u16) -> bool {
        let state = self.state.lock().expect("rebuild gate");
        let GateState::Waiting {
            cut: Some(_),
            expected,
            uploading,
            ..
        } = &*state
        else {
            return false;
        };
        let uploaded = |upload: &EdgeUpload| {
            let streams_done = upload
                .registration
                .streams
                .lock()
                .expect("link streams")
                .values()
                .filter(|stream| stream.uploads.lock().expect("stream uploads").done)
                .count();
            streams_done == usize::from(streams)
        };
        // Every expected edge that uploaded is done, and the edges named by
        // an uploaded cut state have all linked.
        let named: HashSet<EdgeName> = uploading
            .values()
            .flat_map(|upload| named_edges(&upload.registration))
            .collect();
        expected
            .iter()
            .chain(named.iter())
            .all(|edge| uploading.get(edge).is_some_and(uploaded))
    }

    /// Take what the edges uploaded, and the cut, and close the gate to
    /// further uploads.
    fn take_for_rebuild(&self) -> Option<TakenForRebuild> {
        let mut state = self.state.lock().expect("rebuild gate");
        match std::mem::replace(&mut *state, GateState::Rebuilding) {
            GateState::Waiting { cut, uploading, .. } => Some(TakenForRebuild {
                cut,
                uploaded: uploading
                    .into_values()
                    .map(|upload| upload.registration)
                    .collect(),
            }),
            other => {
                *state = other;
                None
            }
        }
    }

    fn deadline(&self) -> Option<tokio::time::Instant> {
        match &*self.state.lock().expect("rebuild gate") {
            GateState::Waiting { deadline, .. } => Some(*deadline),
            GateState::Rebuilding | GateState::Open => None,
        }
    }

    fn opened(&self) {
        *self.state.lock().expect("rebuild gate") = GateState::Open;
    }
}

/// What a rebuild takes from the gate.
struct TakenForRebuild {
    cut: Option<CutId>,
    uploaded: Vec<Arc<Registration>>,
}

/// The edges a registration's uploaded cut state names.
fn named_edges(registration: &Registration) -> Vec<EdgeName> {
    let origin = ClockOrigin::of(crate::net::wall_clock(), crate::net::mono_clock());
    let streams = registration.streams.lock().expect("link streams");
    streams
        .values()
        .filter_map(|stream| {
            let uploads = stream.uploads.lock().expect("stream uploads");
            let (_, body) = uploads.cut.as_ref()?;
            CutState::decode(body.joined()?, origin).ok()
        })
        .flat_map(|state| state.edges)
        .filter_map(|name| EdgeName::new(&name).ok())
        .collect()
}

impl LinkServer {
    /// Run the rebuild once the gate's wait is over, whatever has uploaded
    /// by then: a core started to rebuild spawns this beside its listener.
    pub(crate) async fn wait_for_rebuild(self: Arc<Self>) {
        let Some(deadline) = self.rebuild.deadline() else {
            return;
        };
        tokio::time::sleep_until(deadline).await;
        spawn_rebuild(self);
    }

    /// Note a registration's admission with the gate; one admitted to hold
    /// after the gate opened is resumed at once.
    pub(super) fn joined(&self, registration: &Arc<Registration>) {
        self.rebuild.joined(registration);
    }

    /// A stream of a link admitted to hold or upload that started after the
    /// rebuild: resume it.
    pub(super) async fn resume_if_open(&self, stream: &SessionStream) {
        if self.rebuild.is_open() {
            stream.resume().await;
        }
    }
}

fn spawn_rebuild(server: Arc<LinkServer>) {
    let Some(TakenForRebuild { cut, uploaded }) = server.rebuild.take_for_rebuild() else {
        return;
    };
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let mut rebuilt = rebuild(&server, &uploaded).await;
        // Every shard has handled what the rebuild pushed it before any input
        // flows: a session's first line meets the others rebuilt.
        if let Err(error) = server.core_tx.caught_up().await {
            eprintln!(
                "e6ircd: the shards did not finish the rebuild in time ({error}); edges resume"
            );
        }
        if let Some(cut) = cut {
            server.roster.clear_cut(cut).await;
        }
        // The core's own sessions are taken up by their drivers before any
        // edge's input flows, so an attachment's first line meets its
        // network's session; one no driver takes up is closed.
        let homes = server.core_tx.directories().held.homes;
        server.core_tx.directories().held.rebuilt.done();
        if rebuilt.local > 0 {
            homes.restored_within(LOCAL_CLAIM_WAIT).await;
            close_unclaimed(&server).await;
        }
        let attachments = std::mem::take(&mut rebuilt.attachments);
        let resumed_attachments = attachments.len();
        for (stream, id, upload, record) in attachments {
            resume_attachment(&server, &stream, id, &upload, record).await;
        }
        server.rebuild.opened();
        // Every edge linked now — those that uploaded, those held, and any
        // that linked while the rebuild ran — is resumed; one whose stream
        // starts after `opened` resumes it itself (`resume_if_open`).
        let registrations: Vec<Arc<Registration>> = server
            .edges
            .live
            .lock()
            .expect("linked edges")
            .values()
            .cloned()
            .collect();
        for registration in registrations {
            let streams: Vec<Arc<SessionStream>> = registration
                .streams
                .lock()
                .expect("link streams")
                .values()
                .cloned()
                .collect();
            for stream in streams {
                stream.resume().await;
            }
        }
        eprintln!(
            "e6ircd: rebuilt {} sessions ({} of the core's own), {} live chat sockets, {} \
             attachments and {} channels from {} edges in {} ms; every edge is resumed",
            rebuilt.sessions,
            rebuilt.local,
            rebuilt.sockets,
            resumed_attachments,
            rebuilt.channels,
            uploaded.len(),
            started.elapsed().as_millis()
        );
    });
}

/// Close each session of the core's own that the rebuild resumed and no
/// driver took up within [`LOCAL_CLAIM_WAIT`]: its network is not this
/// core's.
async fn close_unclaimed(server: &LinkServer) {
    for (key, resumed) in server.core_tx.directories().held.homes.unclaimed() {
        eprintln!(
            "e6ircd: no local network {key} took up its session {} within {}s of the rebuild; \
             it is closed",
            resumed.conn.0,
            LOCAL_CLAIM_WAIT.as_secs()
        );
        close(server, resumed.conn, "local network removed").await;
    }
}

/// What a rebuild resumed.
#[derive(Default)]
struct Rebuilt {
    sessions: usize,
    /// Of the sessions, the core's own.
    local: usize,
    channels: usize,
    /// Live chat sockets resumed.
    sockets: usize,
    /// Bouncer attachments to resume once the core's own sessions are taken
    /// up: one attached to a `local` network is then shown its session as it
    /// stands, never a network still connecting.
    attachments: Vec<(Arc<SessionStream>, SessionId, Upload, AttachRecord)>,
}

/// One session an edge uploaded, with the stream it came on.
struct UploadedSession {
    stream: Arc<SessionStream>,
    id: SessionId,
    origin: Uploaded,
    record: SessionRecord,
}

/// Whose a session an edge uploaded is.
enum Uploaded {
    /// A client's, as the edge knows it.
    Client(Upload),
    /// The core's own, of this `local` network, registered under `nick` and
    /// `user`, which the last core homed on the edge.
    Home {
        key: LocalHomeKey,
        nick: String,
        user: String,
    },
}

impl UploadedSession {
    /// The address the session opened with: its client's, or the host the
    /// core's own sessions open with.
    fn address(&self) -> String {
        match &self.origin {
            Uploaded::Client(upload) => ClientIp::new(upload.address).to_string(),
            Uploaded::Home { .. } => self.record.host.clone(),
        }
    }

    /// Resume it no further, saying why: its client is told; a session of
    /// the core's own is named in the log, and its driver registers anew.
    async fn refuse(&self, reason: &str) {
        match &self.origin {
            Uploaded::Client(upload) => refuse_held(&self.stream, self.id, upload, reason).await,
            Uploaded::Home { key, .. } => refuse_home(key, self.id, reason),
        }
    }
}

/// Resume a session of the core's own no further: its driver registers anew.
fn refuse_home(key: &LocalHomeKey, id: SessionId, reason: &str) {
    eprintln!(
        "e6ircd: the session {} of local network {key} is not resumed ({reason}); its driver \
         registers anew",
        id.get()
    );
}

/// One channel as the edges' replicas hold it.
#[derive(Default)]
struct MergedChannel {
    /// The state of the highest revision seen, and that revision.
    state: Option<(u64, Bytes)>,
    members: HashMap<SessionId, Bytes>,
}

impl MergedChannel {
    /// Apply one edge's replica change.
    fn apply(&mut self, replica: Replica) {
        match replica.change {
            ReplicaChange::State(state) => {
                if self
                    .state
                    .as_ref()
                    .is_none_or(|(revision, _)| replica.revision >= *revision)
                {
                    self.state = Some((replica.revision, state));
                }
            }
            ReplicaChange::Member(session, entry) => {
                self.members.insert(session, entry);
            }
            ReplicaChange::MemberGone(session) => {
                self.members.remove(&session);
            }
            // An edge holds no replica it was told is gone; the core's
            // uploads never carry one.
            ReplicaChange::Gone => {}
        }
    }
}

async fn rebuild(server: &Arc<LinkServer>, uploaded: &[Arc<Registration>]) -> Rebuilt {
    let directories = server.core_tx.directories();
    let origin = ClockOrigin::of(crate::net::wall_clock(), crate::net::mono_clock());
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let mut rebuilt = Rebuilt::default();
    let mut sessions: Vec<UploadedSession> = Vec::new();
    let mut sockets: Vec<(Arc<SessionStream>, SessionId, Upload, UiRecord)> = Vec::new();
    let mut attachments: Vec<(Arc<SessionStream>, SessionId, Upload, AttachRecord)> = Vec::new();
    let mut channels: HashMap<Bytes, MergedChannel> = HashMap::new();
    let mut cut_state: Option<CutState> = None;
    for registration in uploaded {
        let streams: Vec<Arc<SessionStream>> = registration
            .streams
            .lock()
            .expect("link streams")
            .values()
            .cloned()
            .collect();
        // Each edge's replicas apply in the order it uploaded them.
        let mut edge_channels: HashMap<Bytes, MergedChannel> = HashMap::new();
        for stream in streams {
            let uploads = std::mem::take(&mut *stream.uploads.lock().expect("stream uploads"));
            if cut_state.is_none()
                && let Some((_, body)) = &uploads.cut
                && let Some(bytes) = body.joined()
            {
                match CutState::decode(bytes, origin) {
                    Ok(state) => cut_state = Some(state),
                    Err(error) => eprintln!(
                        "e6ircd: the cut state edge {} holds is unreadable ({error}): WHOWAS, \
                         the LUSERS maximum and the account-creation buckets start empty",
                        registration.view.name
                    ),
                }
            }
            for replica in uploads.replicas {
                edge_channels
                    .entry(replica.channel.clone())
                    .or_default()
                    .apply(replica);
            }
            for (id, (upload, body)) in uploads.sessions {
                let unreadable = |error: crate::core::record::RecordError| {
                    eprintln!(
                        "e6ircd: session {} held by edge {}: {error}",
                        id.get(),
                        registration.view.name
                    );
                    "server upgrade: session state unreadable"
                };
                let Some(bytes) = body.joined() else {
                    refuse_held(
                        &stream,
                        id,
                        &upload,
                        "server restarting: session state missing",
                    )
                    .await;
                    continue;
                };
                match upload.kind {
                    SessionKind::Irc => match SessionRecord::decode(bytes, origin) {
                        Ok(record) => sessions.push(UploadedSession {
                            stream: stream.clone(),
                            id,
                            origin: Uploaded::Client(upload),
                            record,
                        }),
                        Err(error) => refuse_held(&stream, id, &upload, unreadable(error)).await,
                    },
                    SessionKind::Ui => match UiRecord::decode(bytes, origin) {
                        Ok(record) => sockets.push((stream.clone(), id, upload, record)),
                        Err(error) => refuse_held(&stream, id, &upload, unreadable(error)).await,
                    },
                    SessionKind::Attach => match AttachRecord::decode(bytes, origin) {
                        Ok(record) => attachments.push((stream.clone(), id, upload, record)),
                        Err(error) => refuse_held(&stream, id, &upload, unreadable(error)).await,
                    },
                }
            }
            for (id, body) in uploads.homed {
                match homed_session(body, origin) {
                    Ok((origin, record)) => sessions.push(UploadedSession {
                        stream: stream.clone(),
                        id,
                        origin,
                        record,
                    }),
                    Err(reason) => eprintln!(
                        "e6ircd: the session {} of the core's own held by edge {} is not \
                         resumed: {reason}; its driver registers anew",
                        id.get(),
                        registration.view.name
                    ),
                }
            }
        }
        for (key, merged) in edge_channels {
            let into = channels.entry(key).or_default();
            if let Some((revision, state)) = merged.state {
                into.apply(Replica {
                    channel: Bytes::new(),
                    revision,
                    change: ReplicaChange::State(state),
                });
            }
            into.members.extend(merged.members);
        }
    }
    match cut_state {
        Some(state) => {
            crate::core::adopt_shared(&directories, casemap, state.whowas, state.most_users);
            if server
                .core_tx
                .adopt_buckets(state.registration_buckets)
                .await
                .is_err()
            {
                eprintln!("e6ircd: a core shard is gone; the rebuild cannot hand it its buckets");
            }
        }
        None if !uploaded.is_empty() => eprintln!(
            "e6ircd: no edge uploaded the cut state: WHOWAS, the LUSERS maximum and the \
             account-creation buckets start empty"
        ),
        None => {}
    }
    // Directory keys are given again in the records' original order, so a
    // directory walk still meets the sessions in the order they opened.
    sessions.sort_by_key(|session| session.record.directory_key);
    // Two records cannot name one nick after a graceful cut; if they do, the
    // one that opened first keeps it.
    let mut nicks = HashSet::new();
    let mut resumed = Vec::with_capacity(sessions.len());
    for session in sessions {
        let nick = match &session.record.registration {
            crate::core::record::RecordedRegistration::Registered { nick, .. } => Some(nick),
            crate::core::record::RecordedRegistration::Registering { nick, .. } => nick.as_ref(),
        };
        if let Some(nick) = nick
            && !nicks.insert(casemap.casefold(nick))
        {
            session.refuse("server restarting: nick taken").await;
            continue;
        }
        resumed.push(session);
    }
    let shards = server.core_tx.shard_count();
    let idle: HashMap<SessionId, crate::core::IdleSince> = resumed
        .iter()
        .map(|session| {
            (
                session.id,
                crate::core::IdleSince::new(session.record.idle_since),
            )
        })
        .collect();
    let records: HashMap<SessionId, &UploadedSession> = resumed
        .iter()
        .map(|session| (session.id, session))
        .collect();
    // Channels first, on their owners, so a session's shard finds its
    // channels there.
    let mut session_channels: HashMap<SessionId, Vec<String>> = HashMap::new();
    // The channels' names as spelled, for the core's own sessions' drivers.
    let mut channel_names: HashMap<SessionId, Vec<String>> = HashMap::new();
    for (key, merged) in channels {
        let Some((revision, state)) = merged.state else {
            continue;
        };
        let state = match ChannelState::decode(state, origin) {
            Ok(state) => state,
            Err(error) => {
                eprintln!(
                    "e6ircd: the replica of channel {} is unreadable ({error}); its members \
                     are resumed without it",
                    String::from_utf8_lossy(&key)
                );
                continue;
            }
        };
        let chan_key = crate::core::FoldedChannel::fold(casemap, &state.name);
        let name = state.name.clone();
        let mut members = Vec::new();
        for (member, entry) in merged.members {
            let Some(session) = records.get(&member) else {
                continue;
            };
            let Ok(entry) = MemberEntry::decode(entry, origin) else {
                continue;
            };
            let conn = ConnId(member.get());
            let address = session.address();
            if let Some(member) = crate::core::RebuiltMember::of(
                conn,
                shards.session_owner(conn).shard(),
                &session.record,
                &address,
                entry,
                idle[&session.id].clone(),
            ) {
                members.push(member);
                session_channels
                    .entry(session.id)
                    .or_default()
                    .push(chan_key.as_str().to_owned());
                channel_names
                    .entry(session.id)
                    .or_default()
                    .push(name.clone());
            }
        }
        if members.is_empty() {
            continue;
        }
        rebuilt.channels += 1;
        let rebuild = crate::core::ChannelRebuild {
            key: chan_key,
            state,
            revision,
            members,
        };
        if server
            .core_tx
            .push(Input::RebuildChannel(Box::new(rebuild)))
            .await
            .is_err()
        {
            eprintln!("e6ircd: a core shard is gone; the rebuild stops");
            return rebuilt;
        }
    }
    let logins: Vec<(ConnId, String, crate::identity::CredentialId)> = resumed
        .iter()
        .filter_map(|session| {
            session.record.login.as_ref().map(|login| {
                (
                    ConnId(session.id.get()),
                    login.account.clone(),
                    login.credential,
                )
            })
        })
        .collect();
    for session in resumed {
        let address = session.address();
        let UploadedSession {
            stream,
            id,
            origin,
            record,
        } = session;
        let conn = ConnId(id.get());
        let (tx, resumed_local) = match &origin {
            Uploaded::Client(upload) => match stream.resume_irc(id, upload) {
                Some(tx) => (tx, None),
                None => continue,
            },
            Uploaded::Home { key, nick, user } => {
                // Its identifier is the last core's: this core must never
                // give it out again.
                if !server.next_conn.claim(conn) {
                    refuse_home(key, id, "its identifier may be another session's here");
                    continue;
                }
                let (tx, edge) = crate::core::holding_send_queue("sendq", server.sendq_bytes, 0);
                let resumed = ResumedLocal {
                    conn,
                    edge,
                    nick: nick.clone(),
                    user: user.clone(),
                    channels: channel_names.remove(&id).unwrap_or_default(),
                    restoring: directories.held.homes.restoring(),
                };
                (tx, Some((key.clone(), resumed)))
            }
        };
        let (since_input_ms, unconfirmed, closed) = match origin {
            Uploaded::Client(upload) => (upload.since_input_ms, upload.unconfirmed, upload.closed),
            Uploaded::Home { .. } => (0, 0, None),
        };
        let rebuild = crate::core::SessionRebuild {
            conn,
            record,
            tx,
            directory_key: directories.directory_keys.next(),
            address,
            since_input_ms,
            channels: session_channels.remove(&id).unwrap_or_default(),
            idle_since: idle[&id].clone(),
            unconfirmed,
        };
        if server
            .core_tx
            .push(Input::RebuildSession(Box::new(rebuild)))
            .await
            .is_err()
        {
            eprintln!("e6ircd: a core shard is gone; the rebuild stops");
            return rebuilt;
        }
        rebuilt.sessions += 1;
        if let Some((key, resumed)) = resumed_local {
            directories.held.homes.resume(key, resumed);
            rebuilt.local += 1;
        }
        // A client that left while no core was there has its session end
        // now, as it would have: its channels see it go.
        if let Some(reason) = closed {
            stream.closed(id, session_closed(reason));
        }
    }
    reauthorize(server, logins).await;
    for (stream, id, upload, record) in sockets {
        resume_socket(server, &stream, id, &upload, record).await;
        rebuilt.sockets += 1;
    }
    let attachment_logins: Vec<(ConnId, String, crate::identity::CredentialId)> = attachments
        .iter()
        .map(|(_, id, _, record)| (ConnId(id.get()), record.account.clone(), record.credential))
        .collect();
    let revoked: HashMap<ConnId, &'static str> = revoked_logins(server, attachment_logins)
        .await
        .into_iter()
        .collect();
    for (stream, id, upload, record) in attachments {
        match revoked.get(&ConnId(id.get())) {
            Some(reason) => refuse_held(&stream, id, &upload, reason).await,
            None => rebuilt.attachments.push((stream, id, upload, record)),
        }
    }
    rebuilt
}

/// A session of the core's own as its edge held it: its network, and its
/// record — one not yet registered is not resumed, as its driver registers
/// anew anyway.
fn homed_session(body: Body, origin: ClockOrigin) -> Result<(Uploaded, SessionRecord), String> {
    let bytes = body.joined().ok_or("its record is missing")?;
    let homed = LocalRecord::decode(bytes, origin).map_err(|error| error.to_string())?;
    let record = SessionRecord::decode(homed.session, origin).map_err(|error| error.to_string())?;
    let RecordedRegistration::Registered { nick, user, .. } = &record.registration else {
        return Err("it was not registered yet".into());
    };
    let origin = Uploaded::Home {
        key: LocalHomeKey::new(homed.owner.as_deref(), &homed.network),
        nick: nick.clone(),
        user: user.clone(),
    };
    Ok((origin, record))
}

/// Resume a bouncer attachment on this core from its record; one this core
/// has no bouncer for is closed, saying so.
async fn resume_attachment(
    server: &LinkServer,
    stream: &Arc<SessionStream>,
    id: SessionId,
    upload: &Upload,
    record: AttachRecord,
) {
    let Some(port) = server.attach.clone() else {
        refuse_held(
            stream,
            id,
            upload,
            "this server has no bouncer to attach to",
        )
        .await;
        return;
    };
    let client = ClientIp::new(upload.address);
    let Some(guard) = server.limiter.try_acquire(client) else {
        refuse_held(stream, id, upload, "Too many connections from your address").await;
        return;
    };
    let edge = port.resume(
        ConnId(id.get()),
        upload.address,
        server.sendq_bytes,
        upload.unwritten,
        server.core_tx.directories().held.format.clone(),
        record,
    );
    stream.feed_attach_session(id, port, edge, guard).await;
    if let Some(reason) = upload.closed.clone() {
        stream.closed(id, session_closed(reason));
    }
}

/// Resume a live chat socket on this core: its account's network, its
/// credential read again, its replay after the cursor its record holds. One
/// that cannot resume is closed, saying why.
async fn resume_socket(
    server: &LinkServer,
    stream: &Arc<SessionStream>,
    id: SessionId,
    upload: &Upload,
    record: UiRecord,
) {
    let Some(http) = &server.http else {
        refuse_held(stream, id, upload, "server restarting").await;
        return;
    };
    match crate::http::resume_ui(&http.state, record).await {
        Ok(grant) => {
            stream.start_ui(id, grant, upload.unwritten).await;
            if let Some(reason) = upload.closed.clone() {
                stream.closed(id, session_closed(reason));
            }
        }
        Err(reason) => refuse_held(stream, id, upload, reason).await,
    }
}

/// Check every rebuilt IRC login against the database as the live
/// revocation paths do (DESIGN §2), ending each that is no longer good.
async fn reauthorize(
    server: &LinkServer,
    logins: Vec<(ConnId, String, crate::identity::CredentialId)>,
) {
    for (conn, reason) in revoked_logins(server, logins).await {
        close(server, conn, reason).await;
    }
}

/// The logins of `logins` that are no longer good, each with why: a deleted
/// or suspended account, or a revoked app password or personal access token.
/// Without an answer from the database no login can be trusted, and each is
/// named. A core without a database has no accounts to check.
async fn revoked_logins(
    server: &LinkServer,
    logins: Vec<(ConnId, String, crate::identity::CredentialId)>,
) -> Vec<(ConnId, &'static str)> {
    let super::Roster::Database(pool) = &server.roster else {
        return Vec::new();
    };
    if logins.is_empty() {
        return Vec::new();
    }
    let authorities = match crate::db::every_account_authority(pool).await {
        Ok(authorities) => authorities,
        Err(error) => {
            eprintln!(
                "e6ircd: the rebuild could not re-check account standing ({error}); every \
                 rebuilt login is ended"
            );
            return logins
                .into_iter()
                .map(|(conn, _, _)| (conn, "server restarting: login could not be re-checked"))
                .collect();
        }
    };
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let standing: HashMap<String, bool> = authorities
        .into_iter()
        .map(|authority| (authority.folded, authority.suspended))
        .collect();
    let issued: Vec<crate::identity::IssuedCredential> = logins
        .iter()
        .filter_map(|(_, _, credential)| match credential {
            crate::identity::CredentialId::Issued(issued) => Some(*issued),
            crate::identity::CredentialId::AccountPassword => None,
        })
        .collect();
    let stored = match crate::db::issued_credentials_stored(pool, &issued).await {
        Ok(stored) => stored,
        Err(error) => {
            eprintln!(
                "e6ircd: the rebuild could not re-check issued credentials ({error}); every \
                 login they signed is ended"
            );
            HashSet::new()
        }
    };
    logins
        .into_iter()
        .filter_map(|(conn, account, credential)| {
            let reason = match standing.get(&casemap.casefold(&account)) {
                None => Some("Account permanently deleted"),
                Some(true) => Some("Account suspended"),
                Some(false) => match credential {
                    crate::identity::CredentialId::Issued(issued) if !stored.contains(&issued) => {
                        Some(issued.revocation_reason())
                    }
                    _ => None,
                },
            };
            reason.map(|reason| (conn, reason))
        })
        .collect()
}

async fn close(server: &LinkServer, conn: ConnId, reason: &str) {
    drop(
        server
            .core_tx
            .push(Input::CloseSession {
                conn,
                reason: reason.to_owned(),
            })
            .await,
    );
}

/// The frames that home one of the core's own sessions on an edge: `Home`,
/// then its record in parts. `None`, said, when the record cannot be sent.
fn home_frames(
    record: &crate::core::local_home::HomedRecord,
    format: crate::core::record::RecordFormat,
    origin: ClockOrigin,
) -> Option<Vec<CoreFrame>> {
    let id = SessionId::new(record.conn.0).expect("a session identifier is never 0");
    let homed = LocalRecord {
        owner: record.key.owner.clone(),
        network: record.key.network.clone(),
        session: record.body.clone(),
    };
    let parts = homed
        .encode(format, origin)
        .map_err(|error| error.to_string())
        .and_then(|body| {
            BodyPart::split(&body).ok_or_else(|| "past the body part count".to_owned())
        });
    match parts {
        Ok(parts) => Some(
            std::iter::once(CoreFrame::Home(id))
                .chain(parts.into_iter().map(|part| {
                    CoreFrame::Record(
                        id,
                        RecordPart {
                            revision: record.revision,
                            part,
                        },
                    )
                }))
                .collect(),
        ),
        Err(error) => {
            eprintln!(
                "e6ircd: the session {} of local network {} cannot be homed ({error}); it ends \
                 with this core",
                record.conn.0, record.key
            );
            None
        }
    }
}

/// Close a session the edge held that this core does not resume, telling
/// its client why.
async fn refuse_held(stream: &SessionStream, id: SessionId, upload: &Upload, reason: &str) {
    stream.refuse(id, upload.address, upload.kind, reason).await;
}

impl SessionStream {
    /// Open the core's end of a session a rebuild resumes: its per-address
    /// slot, its link — with what the edge has not yet written counted in
    /// flight — and its pump. `None` when it cannot be resumed; its client is
    /// told why.
    fn resume_irc(
        self: &Arc<Self>,
        id: SessionId,
        upload: &Upload,
    ) -> Option<crate::core::SendQueue> {
        let client = ClientIp::new(upload.address);
        let Some(guard) = self.server.limiter.try_acquire(client) else {
            let stream = self.clone();
            let upload = upload.clone();
            tokio::spawn(async move {
                stream
                    .refuse(
                        id,
                        upload.address,
                        upload.kind,
                        "Too many connections from your address",
                    )
                    .await;
            });
            return None;
        };
        let (tx, edge) =
            crate::core::holding_send_queue("sendq", self.server.sendq_bytes, upload.unwritten);
        self.start(id, SessionKind::Irc, edge, None, guard.into());
        Some(tx)
    }
}

/// How a cut went.
#[derive(Debug, Default)]
pub(crate) struct Handover {
    /// Edges that held their sessions for the next core.
    pub(crate) edges: Vec<EdgeName>,
    /// Sessions closed because the work they waited on did not settle.
    pub(crate) unsettled: usize,
    /// Sessions closed because no edge holds them.
    pub(crate) unheld: usize,
    /// The core's own sessions homed on an edge (D13).
    pub(crate) homed: usize,
}

impl LinkServer {
    /// Cut every link gracefully: pause, settle, cut the shards, flush and
    /// send the cut. The core's shards handle nothing afterwards.
    pub(crate) async fn cut(&self, cut: CutId, epoch: u64) -> Handover {
        let registrations: Vec<Arc<Registration>> = self
            .edges
            .live
            .lock()
            .expect("linked edges")
            .values()
            .cloned()
            .collect();
        let (holding, closing): (Vec<Arc<Registration>>, Vec<Arc<Registration>>) = registrations
            .into_iter()
            .partition(|registration| registration.view.version >= 2);
        for registration in &closing {
            eprintln!(
                "e6ircd: edge {} speaks link version {}, which holds no session: its clients \
                 are told the server is shutting down",
                registration.view.name, registration.view.version
            );
        }
        let mut handover = Handover::default();
        // 0. A core still rebuilding what its edges hold finishes first: what
        //    it cuts is then whole, and the streams it resumes are resumed
        //    before they are paused.
        let rebuilt = self.core_tx.directories().held.rebuilt;
        if tokio::time::timeout(REBUILD_FINISH_WAIT, rebuilt.wait())
            .await
            .is_err()
        {
            eprintln!(
                "e6ircd: the rebuild did not finish within {}s of the cut being asked; the cut \
                 goes ahead without what it had not rebuilt",
                REBUILD_FINISH_WAIT.as_secs()
            );
        }
        // 1. Pause every stream, and hear it pause.
        let mut paused = Vec::new();
        for registration in &holding {
            let streams: Vec<Arc<SessionStream>> = registration
                .streams
                .lock()
                .expect("link streams")
                .values()
                .cloned()
                .collect();
            for stream in streams {
                let (answer, answered) = tokio::sync::oneshot::channel();
                *stream.paused.lock().expect("pause answer") = Some(answer);
                paused.push((registration.clone(), stream, answered));
            }
        }
        let mut holding_paused = Vec::new();
        for (registration, stream, answered) in paused {
            let heard = match stream.pause().await {
                Pausing::Asked => {
                    matches!(tokio::time::timeout(PAUSE_WAIT, answered).await, Ok(Ok(())))
                }
                Pausing::NeverResumed => true,
                Pausing::Gone => false,
            };
            if !heard {
                eprintln!(
                    "e6ircd: edge {} did not pause within {}s; its link is not cut, and its \
                     sessions end with this core",
                    registration.view.name,
                    PAUSE_WAIT.as_secs()
                );
                registration.end(LinkEnd::Lost);
            } else if !holding_paused
                .iter()
                .any(|kept: &Arc<Registration>| Arc::ptr_eq(kept, &registration))
            {
                holding_paused.push(registration);
            }
        }
        let holding: Vec<Arc<Registration>> = holding_paused
            .into_iter()
            .filter(|registration| !matches!(*registration.over.borrow(), Some(LinkEnd::Lost)))
            .collect();
        // 2. Settle: every line handed to its shard, nothing between shards,
        //    no database round trip awaited.
        handover.unsettled = self.settle(&holding).await;
        // 2b. The core's own sessions — the `local` driver's — are homed on
        //     the first edge that holds the cut, and their memberships (slot
        //     0's replicas) go there from now on (D13). A session no edge
        //     holds — one on a version 1 link, or the core's own with no edge
        //     to home it on — ends now, loudly, so its channels see it go
        //     before the cut rather than keep it with no session behind it;
        //     then the quits settle.
        let home = holding.first().cloned();
        *self.edges.local_home.lock().expect("local home") = home
            .as_ref()
            .map(|registration| registration.view.slot.get());
        match self
            .core_tx
            .close_unheld("server restarting", home.is_some())
            .await
        {
            Ok(0) => {}
            Ok(closed) => {
                handover.unheld = closed;
                handover.unsettled += self.settle(&holding).await;
            }
            Err(error) => {
                eprintln!("e6ircd: the sessions no edge holds could not be closed: {error}")
            }
        }
        // 3. Cut every shard: the records and replicas are published whole,
        //    and nothing is handled afterwards.
        let buckets = match self.core_tx.cut().await {
            Ok(buckets) => buckets,
            Err(error) => {
                eprintln!("e6ircd: the core could not be cut ({error}); every session ends");
                for registration in &holding {
                    registration.end(LinkEnd::Lost);
                }
                return handover;
            }
        };
        let (whowas, most_users) = crate::core::export_shared(&self.core_tx.directories());
        let state = CutState {
            whowas,
            most_users,
            registration_buckets: buckets,
            edges: holding
                .iter()
                .map(|registration| registration.view.name.as_str().to_owned())
                .collect(),
        };
        let format = self.core_tx.directories().held.format.get();
        let origin = ClockOrigin::of(crate::net::wall_clock(), crate::net::mono_clock());
        let body = state
            .encode(format, origin)
            .expect("the cut state is within every body bound");
        let parts = BodyPart::split(&body).expect("the cut state is within the body part count");
        // 3b. The core's own sessions, once their drivers have taken the
        //     records the cut published: each is homed on its stream of the
        //     home edge.
        let mut homed: HashMap<u16, Vec<CoreFrame>> = HashMap::new();
        if home.is_some() {
            let records = self
                .core_tx
                .directories()
                .held
                .homes
                .gathered(FLUSH_WAIT)
                .await;
            for record in records {
                let Some(frames) = home_frames(&record, format, origin) else {
                    continue;
                };
                let id = SessionId::new(record.conn.0).expect("a session identifier is never 0");
                let index = e6irc_edge::core_link::remote::stream_of(id, usize::from(self.streams));
                homed
                    .entry(u16::try_from(index).expect("a stream index fits"))
                    .or_default()
                    .extend(frames);
                handover.homed += 1;
            }
        }
        // 4. Each stream: its pumps send what is left and stop; the first
        //    stream carries the cut state; every stream ends with the cut.
        for registration in &holding {
            let streams: Vec<Arc<SessionStream>> = registration
                .streams
                .lock()
                .expect("link streams")
                .values()
                .cloned()
                .collect();
            for stream in streams {
                stream.cutting.send_replace(true);
                drop(stream.pumps.lock().expect("stream pumps").take());
                let flushed = tokio::time::timeout(FLUSH_WAIT, async {
                    stream.pumps_done.lock().await.recv().await;
                })
                .await
                .is_ok();
                stream.close_replicas();
                let forwarder = stream
                    .replica_forwarder
                    .lock()
                    .expect("replica forwarder")
                    .take();
                if let Some(forwarder) = forwarder {
                    drop(tokio::time::timeout(FLUSH_WAIT, forwarder).await);
                }
                if !flushed {
                    eprintln!(
                        "e6ircd: a session stream of edge {} did not send everything within \
                         {}s; the edge holds what arrived",
                        registration.view.name,
                        FLUSH_WAIT.as_secs()
                    );
                }
                if home
                    .as_ref()
                    .is_some_and(|home| Arc::ptr_eq(home, registration))
                {
                    for frame in homed.remove(&stream.index).unwrap_or_default() {
                        drop(stream.out.send(frame).await);
                    }
                }
                if stream.index == 0 {
                    for part in &parts {
                        drop(
                            stream
                                .out
                                .send(CoreFrame::CutState(CutPart {
                                    cut,
                                    part: part.clone(),
                                }))
                                .await,
                        );
                    }
                }
                drop(stream.out.send(CoreFrame::Cut(Cut { cut, epoch })).await);
            }
            registration.end(LinkEnd::Cut);
            handover.edges.push(registration.view.name.clone());
        }
        self.roster.record_cut(&handover.edges, cut).await;
        handover
    }

    /// Wait until the work in flight settles, within [`SETTLE_WAIT`]; then
    /// close each session still waiting, loudly. How many were closed.
    async fn settle(&self, holding: &[Arc<Registration>]) -> usize {
        let deadline = tokio::time::Instant::now() + SETTLE_WAIT;
        loop {
            let pushed = holding.iter().all(|registration| {
                registration
                    .streams
                    .lock()
                    .expect("link streams")
                    .values()
                    .all(|stream| {
                        stream
                            .lines_in_flight
                            .load(std::sync::atomic::Ordering::SeqCst)
                            == 0
                    })
            });
            let unsettled = if pushed && self.core_tx.cross_shard_idle() {
                match self.core_tx.unsettled().await {
                    Ok(unsettled) if unsettled.iter().all(crate::core::Unsettled::is_empty) => {
                        return 0;
                    }
                    Ok(unsettled) => Some(unsettled),
                    Err(error) => {
                        eprintln!("e6ircd: the core could not say what is in flight: {error}");
                        return 0;
                    }
                }
            } else {
                None
            };
            if tokio::time::Instant::now() >= deadline {
                let Some(unsettled) = unsettled else {
                    eprintln!(
                        "e6ircd: input was still on its way to the shards after {}s; the cut \
                         goes ahead",
                        SETTLE_WAIT.as_secs()
                    );
                    return 0;
                };
                let mut closed = 0;
                for shard in unsettled {
                    for what in shard.shard {
                        eprintln!("e6ircd: the cut goes ahead with {what} unsettled");
                    }
                    for (conn, what) in shard.sessions {
                        eprintln!(
                            "e6ircd: session {} still waited on {what} at the cut; it is closed",
                            conn.0
                        );
                        close(self, conn, "server restarting: a request did not complete").await;
                        closed += 1;
                    }
                }
                // Their QUITs reach their channels before the cut.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return closed;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
