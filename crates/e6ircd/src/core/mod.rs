//! The IRC core: a single-threaded, share-nothing worker that owns all
//! chat state. Inputs arrive as events (from connection I/O tasks, via
//! `e6irc-queue`); outputs are pushed into per-connection send queues.
//! The worker itself is synchronous — `Core::handle` is a pure state
//! transition — which is what makes deterministic simulation and
//! step-debugging possible.
//!
//! Workers can run as N hash-sharded instances. Each instance owns its local
//! session state and its assigned channel state.

mod banmask;
mod handler;
mod hot_history;
pub(crate) mod line_meter;
mod list;
mod paced;
mod state;
mod timer;

pub(crate) use handler::{
    HistoryFail, cap_reply_lines, cap_version_302, fail_line, fit_trailing, fitted_line,
    invalid_utf8_fail, server_notice,
};

/// How long an unregistered connection may hold its slot before the core
/// closes it: the soonest a per-address connection slot is certain to free.
pub(crate) const REGISTRATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(handler::REGISTRATION_TIMEOUT_MS);
pub(crate) use timer::TimerWheel;

pub use state::{
    ChannelOwner, CommandFlood, CommandFloodError, ConnId, CoreConfig, dm_conversation_key,
};

use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
#[cfg(test)]
use e6irc_queue::Envelope;
use e6irc_queue::{PushError, QueueMonitor, Receiver, Sender};
use state::{
    ChanKey, ChannelActor, ChannelCommand, ChannelCommandResult, ChannelJoinResult, ChannelKick,
    ChannelKickResult, ChannelListRequest, ChannelListResult, ChannelMemberUpdate, ChannelMessage,
    ChannelMessageResult, ChannelMultiline, ChannelMultilineResult, ChannelPartResult, ChannelQuit,
    ChannelTagmsg, ChannelTagmsgResult, ChannelTopic, ChannelTopicResult,
};
use state::{CoreDirectories, ServerState};

use crate::observability::{LatencyKind, Telemetry};

/// One process-wide source of live connection identifiers.
///
/// Production seeds this counter from the operating system's cryptographically
/// secure random number generator on every boot. All ingress paths share the
/// allocator, so identifiers remain ordered for keyset pagination, cannot
/// collide within a process, and do not predictably name a different
/// connection after a restart. Exhaustion is an explicit error instead of
/// wrapping onto an existing identifier.
#[derive(Debug)]
pub struct ConnectionIdAllocator {
    next: AtomicU64,
}

/// Number of core shards. Zero shards cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreShardCount(NonZeroUsize);

impl CoreShardCount {
    pub fn new(count: NonZeroUsize) -> Self {
        Self(count)
    }

    pub fn single() -> Self {
        Self(NonZeroUsize::MIN)
    }

    pub(crate) fn len(self) -> usize {
        self.0.get()
    }

    fn shard_for(self, conn: ConnId) -> CoreShardId {
        CoreShardId((conn.0 as usize) % self.0.get())
    }

    pub fn session_owner(self, conn: ConnId) -> SessionOwner {
        SessionOwner::new(conn, self.shard_for(conn))
    }

    pub(crate) fn shard_for_channel(self, key: &state::ChanKey) -> CoreShardId {
        self.shard_for_folded_channel(key.as_str())
    }

    fn shard_for_channel_name(self, name: &str) -> CoreShardId {
        self.shard_for_folded_channel(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(name))
    }

    fn shard_for_folded_channel(self, name: &str) -> CoreShardId {
        let hash = name.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        });
        CoreShardId((hash as usize) % self.0.get())
    }
}

/// Index of one configured core shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CoreShardId(usize);

impl CoreShardId {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }
}

/// The connection and worker that own one live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOwner {
    conn: ConnId,
    shard: CoreShardId,
}

impl SessionOwner {
    pub(crate) fn new(conn: ConnId, shard: CoreShardId) -> Self {
        Self { conn, shard }
    }

    pub(crate) fn conn(self) -> ConnId {
        self.conn
    }

    pub fn connection_id(self) -> ConnId {
        self.conn
    }

    pub(crate) fn shard(self) -> CoreShardId {
        self.shard
    }
}

/// The only ingress path into core state.
#[derive(Clone)]
pub struct CoreIngress {
    shards: Arc<[Sender<Input>]>,
    count: CoreShardCount,
    directories: CoreDirectories,
    traffic: Arc<CrossShardTraffic>,
    /// Every connection's command allowance ([`line_meter`]); `None` only for
    /// the test harnesses' ingress, which nothing meters.
    command_flood: Option<CommandFlood>,
}

/// What the workers know together about the events passing between them. It
/// is what lets shutdown be a drain: no worker closes its queue while another
/// may still send to it.
#[derive(Default)]
struct CrossShardTraffic {
    /// Events one worker has addressed to another that the other has not yet
    /// finished handling. An event stops counting only after whatever it
    /// caused has itself been counted, so zero means nothing is on its way and
    /// nothing will be.
    in_flight: std::sync::atomic::AtomicUsize,
    /// Workers that have handled [`Input::Shutdown`].
    stopping: std::sync::atomic::AtomicUsize,
    /// Signalled whenever either of those may have completed the drain.
    changed: tokio::sync::Notify,
}

impl CrossShardTraffic {
    fn sent(&self) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    fn settled(&self) {
        if self.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.changed.notify_waiters();
        }
    }

    fn worker_stopping(&self) {
        self.stopping.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// Every worker has seen shutdown and nothing is passing between them.
    fn drained(&self, workers: usize) -> bool {
        self.stopping.load(Ordering::SeqCst) == workers
            && self.in_flight.load(Ordering::SeqCst) == 0
    }
}

impl CoreIngress {
    pub fn single(sender: Sender<Input>) -> Self {
        Self {
            shards: Arc::from([sender]),
            count: CoreShardCount::single(),
            directories: CoreDirectories::default(),
            traffic: Arc::default(),
            command_flood: None,
        }
    }

    /// Build ingress for a nonempty set of core shards.
    pub fn with_shards(first: Sender<Input>, mut rest: Vec<Sender<Input>>) -> Self {
        let capacity = rest
            .len()
            .checked_add(1)
            .expect("allocated shard list cannot exceed usize");
        let count = NonZeroUsize::new(capacity)
            .expect("mandatory first shard keeps the core shard count nonzero");
        let mut shards = Vec::with_capacity(capacity);
        shards.push(first);
        shards.append(&mut rest);
        Self {
            shards: shards.into(),
            count: CoreShardCount::new(count),
            directories: CoreDirectories::default(),
            traffic: Arc::default(),
            command_flood: None,
        }
    }

    /// Meter every connection's lines with `flood`.
    pub fn with_command_flood(self, flood: CommandFlood) -> Self {
        Self {
            command_flood: Some(flood),
            ..self
        }
    }

    /// A new connection's meter, which whatever hands its lines to this
    /// ingress spends a token of for each ([`line_meter`]).
    pub(crate) fn line_meter(&self, conn: ConnId) -> line_meter::LineMeter {
        line_meter::LineMeter::new(
            conn,
            self.command_flood,
            self.directories.flood_exemptions.clone(),
            tokio::time::Instant::now(),
        )
    }

    pub async fn push(&self, input: Input) -> Result<u64, Box<Input>> {
        let shard = input.owner_shard(self.count);
        self.shards[shard.0].push(input).await.map_err(Box::new)
    }

    pub fn monitor(&self) -> QueueMonitor {
        self.shards[0].monitor()
    }

    pub(crate) fn monitors(&self) -> Vec<QueueMonitor> {
        self.shards.iter().map(Sender::monitor).collect()
    }

    pub(crate) fn shard_count(&self) -> CoreShardCount {
        self.count
    }

    pub(crate) async fn broadcast_tick(
        &self,
        now: e6irc_proto::time::MonoMillis,
    ) -> Result<(), ()> {
        self.broadcast(|| Input::Tick { now }).await
    }

    pub(crate) async fn broadcast_shutdown(&self) -> Result<(), ()> {
        self.broadcast(|| Input::Shutdown).await
    }

    pub(crate) async fn broadcast_read_markers_expired(
        &self,
        markers: Arc<[ExpiredReadMarker]>,
    ) -> Result<(), ()> {
        self.broadcast(|| Input::ReadMarkersExpired {
            markers: markers.clone(),
        })
        .await
    }

    /// Tell every shard that `account` was permanently deleted, so each drops
    /// what it mirrors of the rows that went with it — read markers, hot
    /// history lines and conversations, channel access entries: the database
    /// purged or cascaded them away, and nothing would otherwise evict them
    /// before a restart.
    pub(crate) async fn broadcast_account_deleted(
        &self,
        account: &str,
        successions: &[crate::db::ChannelSuccession],
    ) -> Result<(), ()> {
        self.broadcast(|| Input::AccountDeleted {
            account: account.to_owned(),
            successions: successions.to_vec(),
        })
        .await
    }

    /// Put one administrative request to the core and wait for its answer,
    /// for at most five seconds: a control-plane caller must not hang on a
    /// wedged core.
    pub(crate) async fn admin_reply(&self, req: AdminRequest) -> Result<AdminReply, String> {
        const CORE_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.push(Input::Admin { req, reply: tx }).await.is_err() {
            return Err("core worker unavailable".into());
        }
        match tokio::time::timeout(CORE_REPLY_TIMEOUT, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_closed)) => Err("core worker dropped the request".into()),
            Err(_elapsed) => Err("core worker did not answer within 5 seconds".into()),
        }
    }

    /// [`Self::admin_reply`] for a mutation, whose answer is a confirmation
    /// or a refusal.
    pub(crate) async fn admin_action(&self, req: AdminRequest) -> Result<String, String> {
        match self.admin_reply(req).await? {
            AdminReply::Ok(message) => Ok(message),
            AdminReply::Err(message)
            | AdminReply::ChannelErr { message, .. }
            | AdminReply::BanErr { message, .. } => Err(message),
            AdminReply::Connections(_) => {
                Err("unexpected live-connection reply for a mutation".into())
            }
            AdminReply::ConnectionMissing => Err("no such live connection".into()),
            AdminReply::AuditUnavailable => Err(
                "the action could not be recorded in the audit trail, so it was not taken".into(),
            ),
        }
    }

    /// Offer every shard its copy. One closed shard does not excuse the rest:
    /// during shutdown the others still need theirs.
    async fn broadcast(&self, mut input: impl FnMut() -> Input) -> Result<(), ()> {
        let mut delivered = Ok(());
        for shard in self.shards.iter() {
            if shard.push(input()).await.is_err() {
                delivered = Err(());
            }
        }
        delivered
    }

    pub(crate) fn directories(&self) -> CoreDirectories {
        self.directories.clone()
    }
}

impl Input {
    /// The one shard whose worker may handle this event. Ingress routes by it
    /// and a worker uses it to tell an effect for another shard from one it
    /// must handle itself, so the two can never disagree about an owner.
    ///
    /// Panics on an event that has no single owner: those are broadcast.
    pub(crate) fn owner_shard(&self, shards: CoreShardCount) -> CoreShardId {
        match self {
            Input::FromShard(input) => input.owner_shard(shards),
            Input::Open { conn, .. }
            | Input::Line { conn, .. }
            | Input::OverlongLine { conn }
            | Input::Closed { conn, .. }
            | Input::Delivery { conn, .. }
            | Input::DbReply { conn, .. }
            | Input::HistoryPage { conn, .. }
            | Input::TargetsPage { conn, .. } => shards.session_owner(*conn).shard(),
            Input::ChannelJoin { owner, .. } | Input::ChannelMemberVanished { owner, .. } => {
                owner.shard()
            }
            Input::ChannelJoinResult { session, .. }
            | Input::ConversationEntry { session, .. }
            | Input::SessionAction { session, .. } => session.shard(),
            Input::ChannelPart { owner, .. } => owner.shard(),
            Input::ChannelPartResult { session, .. } => session.shard(),
            Input::ChannelQuit { quit } => quit.shard(),
            Input::ChannelUserEvent { report } => report.shard(),
            Input::UserEventPart { part } => part.shard(),
            Input::ChannelTopic { topic } => topic.owner().shard(),
            Input::ChannelTopicResult { session, .. } => session.shard(),
            Input::ChannelTopicPersisted { owner, .. } => owner.shard(),
            Input::ChannelServicePersisted { owner, .. } => owner.shard(),
            Input::ChannelServiceResult { session, .. } => session.shard(),
            Input::ChannelCommand { command } => command.owner().shard(),
            Input::ChannelCommandResult { session, .. } => session.shard(),
            Input::ChannelRegistrationPersisted { owner, .. } => owner.shard(),
            Input::ChannelListResult { result } => result.session.shard(),
            Input::ChannelList { request } => request.shard(),
            Input::ChannelSessionEvent { session, .. } => session.shard(),
            Input::ChannelMemberUpdate { update } => update.shard(),
            Input::ChannelKick { kick } => kick.owner().shard(),
            Input::ChannelKickResult { session, .. } => session.shard(),
            Input::SessionChannelRemoved { session, .. } => session.shard(),
            Input::ChannelMessage { message } => message.owner().shard(),
            Input::ChannelMessageResult { session, .. } => session.shard(),
            Input::ChannelMultiline { message } => message.owner().shard(),
            Input::ChannelMultilineResult { session, .. } => session.shard(),
            Input::ChannelTagmsg { tagmsg } => tagmsg.owner().shard(),
            Input::ChannelTagmsgResult { session, .. } => session.shard(),
            Input::PaceReplies => {
                panic!("a worker paces its own LIST and WHO replies, through its own queue")
            }
            Input::Tick { .. }
            | Input::Shutdown
            | Input::ReadMarkersExpired { .. }
            | Input::AccountDeleted { .. } => {
                panic!("broadcast core event must use its dedicated ingress method")
            }
            Input::ServerBanResult { requester, .. } => match requester {
                ServerBanRequester::Oper { session, .. } => session.shard(),
                ServerBanRequester::Admin { .. } => CoreShardId(0),
            },
            Input::ServerBanApplied { .. } => {
                panic!("committed server-ban event must be broadcast by a core worker")
            }
            Input::AccountSuspensionApplied { .. } => {
                panic!("account-suspension event must be broadcast by a core worker")
            }
            Input::ReadMarkerApplied { .. } => {
                panic!("read-marker event must be broadcast by a core worker")
            }
            Input::UnauthenticatedIdentityReleased { .. } => {
                panic!("identity-released event must be broadcast by a core worker")
            }
            Input::AdminConnectionList { .. } => {
                panic!("connection-list event must be broadcast by a core worker")
            }
            Input::AdminConnectionListResult { .. } => CoreShardId(0),
            Input::Admin { req, .. } => req.shard(shards),
            Input::ChannelDropResult { owner, .. } => owner.shard(),
            Input::ChannelDropReply { session, .. } => session.shard(),
            Input::ChannelControlResult { owner, .. }
            | Input::OwnedChannelRegistrationResult { owner, .. } => owner.shard(),
        }
    }
}

/// One event delivered from a shard queue to its owning worker.
pub(crate) struct ScheduledInput {
    pub shard: CoreShardId,
    pub sequence: u64,
    pub input: Input,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoreTraceStep {
    shard: CoreShardId,
    sequence: u64,
}

#[cfg(test)]
impl ScheduledInput {
    pub(crate) fn trace_step(&self) -> CoreTraceStep {
        CoreTraceStep {
            shard: self.shard,
            sequence: self.sequence,
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct CoreTrace {
    steps: Vec<CoreTraceStep>,
}

#[cfg(test)]
impl CoreTrace {
    pub(crate) fn steps(&self) -> &[CoreTraceStep] {
        &self.steps
    }

    fn record(&mut self, input: &ScheduledInput) {
        self.steps.push(input.trace_step());
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayError {
    ShardMissing,
    EventMissing,
    SequenceMismatch { expected: u64, actual: u64 },
}

/// Round-robin core queue selection for deterministic tests.
///
/// A step records both the selected shard and that queue's sequence number,
/// which is sufficient to replay a fixed set of queued inputs.
#[cfg(test)]
pub(crate) struct CoreScheduler {
    receivers: Vec<Receiver<Input>>,
    count: CoreShardCount,
    next: CoreShardId,
    #[cfg(test)]
    trace: CoreTrace,
}

#[cfg(test)]
impl CoreScheduler {
    fn with_shards(first: Receiver<Input>, mut rest: Vec<Receiver<Input>>) -> Self {
        let capacity = rest
            .len()
            .checked_add(1)
            .expect("allocated shard list cannot exceed usize");
        let count = NonZeroUsize::new(capacity)
            .expect("mandatory first shard keeps the core shard count nonzero");
        let mut receivers = Vec::with_capacity(capacity);
        receivers.push(first);
        receivers.append(&mut rest);
        Self {
            receivers,
            count: CoreShardCount::new(count),
            next: CoreShardId(0),
            trace: CoreTrace::default(),
        }
    }

    pub(crate) fn try_step(&mut self) -> Option<ScheduledInput> {
        for _ in 0..self.count.0.get() {
            let shard = self.next;
            self.next = CoreShardId((self.next.0 + 1) % self.count.0.get());
            if let Some(Envelope {
                seq,
                payload: input,
            }) = self.receivers[shard.0].try_pop()
            {
                let scheduled = ScheduledInput {
                    shard,
                    sequence: seq,
                    input,
                };
                #[cfg(test)]
                self.trace.record(&scheduled);
                return Some(scheduled);
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn trace(&self) -> &CoreTrace {
        &self.trace
    }

    #[cfg(test)]
    pub(crate) fn replay_step(
        &mut self,
        step: CoreTraceStep,
    ) -> Result<ScheduledInput, ReplayError> {
        let receiver = self
            .receivers
            .get_mut(step.shard.0)
            .ok_or(ReplayError::ShardMissing)?;
        let Envelope {
            seq,
            payload: input,
        } = receiver.try_pop().ok_or(ReplayError::EventMissing)?;
        if seq != step.sequence {
            return Err(ReplayError::SequenceMismatch {
                expected: step.sequence,
                actual: seq,
            });
        }
        Ok(ScheduledInput {
            shard: step.shard,
            sequence: seq,
            input,
        })
    }
}

impl ConnectionIdAllocator {
    pub fn new(first: NonZeroU64) -> Self {
        Self {
            next: AtomicU64::new(first.get()),
        }
    }

    pub fn allocate(&self) -> Result<ConnId, ConnectionIdExhausted> {
        self.next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map(ConnId)
            .map_err(|_| ConnectionIdExhausted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionIdExhausted;

impl std::fmt::Display for ConnectionIdExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("live connection identifier space exhausted")
    }
}

impl std::error::Error for ConnectionIdExhausted {}

/// One stored read marker that storage maintenance deleted: the account's
/// display name as stored, the folded target, and the value deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredReadMarker {
    pub account: String,
    pub target: String,
    pub marker_ms: e6irc_proto::time::Millis,
}

/// Events into the core worker.
#[derive(Debug)]
pub enum Input {
    /// An event one core worker addressed to another, as it travels. Only a
    /// worker wraps and unwraps it. The wrapper is what tells the workers'
    /// own traffic — which shutdown must drain — from input arriving from
    /// outside, which shutdown stops taking.
    FromShard(Box<Input>),
    /// A connection was accepted; `tx` is its send queue.
    Open {
        conn: ConnId,
        tx: SendQueue,
        host: String,
        transport: ConnectionTransport,
    },
    /// One complete line from the connection (terminator stripped).
    Line {
        conn: ConnId,
        line: Vec<u8>,
    },
    /// The connection sent an over-long line (framing already dropped it).
    OverlongLine {
        conn: ConnId,
    },
    Delivery {
        conn: ConnId,
        line: Bytes,
    },
    /// A parsed JOIN that may run only on its channel owner.
    ChannelJoin {
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        join_key: Option<String>,
        label: Option<String>,
    },
    /// The channel owner's typed answer, processed only by the session owner.
    /// `requested` is the channel the JOIN named, keyed as the session owner
    /// keyed it when it counted the request against the channel limit
    /// (`Session::pending_joins`), so that reservation is released whatever
    /// the answer says.
    ChannelJoinResult {
        session: SessionOwner,
        requested: ChanKey,
        result: ChannelJoinResult,
        label: Option<String>,
    },
    ChannelPart {
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        reason: Option<String>,
        label: Option<String>,
    },
    ChannelPartResult {
        session: SessionOwner,
        result: ChannelPartResult,
        label: Option<String>,
    },
    ChannelQuit {
        quit: ChannelQuit,
    },
    ChannelTopic {
        topic: ChannelTopic,
    },
    ChannelTopicResult {
        session: SessionOwner,
        result: ChannelTopicResult,
        label: Option<String>,
    },
    ChannelTopicPersisted {
        owner: ChannelOwner,
        conn: ConnId,
        session: Option<SessionOwner>,
        result: ChannelTopicPersistence,
    },
    /// A durable ChanServ verdict applied by the channel owner before the
    /// requester receives its response.
    ChannelServicePersisted {
        owner: ChannelOwner,
        session: SessionOwner,
        result: ChannelServicePersistence,
    },
    /// A ChanServ persistence response delivered only by the requester session.
    ChannelServiceResult {
        session: SessionOwner,
        result: ChannelServicePersistence,
    },
    /// One direct message, for the ring of the shard its recipient lives on.
    /// The sender's shard has recorded (and persisted) it already; a ring
    /// belongs to a shard, and the recipient reads its history from its own.
    ConversationEntry {
        session: SessionOwner,
        key: state::HistoryKey,
        entry: state::HistoryEntry,
    },
    /// An unauthenticated identity left on another shard (broadcast).
    UnauthenticatedIdentityReleased {
        identity: String,
    },
    /// A JOIN was answered after its session had gone; the channel's owner
    /// takes the member back out.
    ChannelMemberVanished {
        owner: ChannelOwner,
        conn: ConnId,
    },
    /// Something one user may do *to* another's session — KILL, NickServ
    /// GHOST, SETHOST — carried out by the shard that session lives on.
    SessionAction {
        session: SessionOwner,
        action: state::SessionAction,
    },
    /// Something happened to a user; the owner of some of their channels
    /// reports who among its members should hear of it.
    ChannelUserEvent {
        report: state::ChannelUserEvent,
    },
    /// One reporter's share of a user event's audience, for the shard those
    /// sessions live on, which tells each of them once.
    UserEventPart {
        part: state::UserEventPart,
    },
    /// A channel command whose mutation and authorization belong to its owner.
    ChannelCommand {
        command: ChannelCommand,
    },
    /// A channel command answer, processed only by the requester's session owner.
    ChannelCommandResult {
        session: SessionOwner,
        result: ChannelCommandResult,
        label: Option<String>,
    },
    /// The database's verdict on a ChanServ REGISTER, for the channel's owner.
    /// `founder_account` is echoed from the request (the account the row was
    /// written with), not re-read from the session when the verdict arrives: a
    /// LOGOUT or IDENTIFY in between would otherwise put the wrong account, or
    /// none, into the hot founder map until restart.
    ChannelRegistrationPersisted {
        owner: ChannelOwner,
        session: SessionOwner,
        channel: String,
        founder_account: String,
        topic: Option<(String, String, u64)>,
        label: Option<String>,
        result: ChannelRegistrationResult,
    },
    /// One channel shard's page of a LIST, for the shard of its connection.
    ChannelListResult {
        result: ChannelListResult,
    },
    /// A LIST's request for one page of the channel shard it names.
    ChannelList {
        request: ChannelListRequest,
    },
    ChannelSessionEvent {
        session: SessionOwner,
        event: state::ChannelSessionEvent,
    },
    ChannelMemberUpdate {
        update: ChannelMemberUpdate,
    },
    ChannelKick {
        kick: ChannelKick,
    },
    ChannelKickResult {
        session: SessionOwner,
        result: ChannelKickResult,
        label: Option<String>,
    },
    SessionChannelRemoved {
        session: SessionOwner,
        key: state::ChanKey,
    },
    ChannelMessage {
        message: ChannelMessage,
    },
    ChannelMessageResult {
        session: SessionOwner,
        result: ChannelMessageResult,
        label: Option<String>,
    },
    ChannelMultiline {
        message: ChannelMultiline,
    },
    ChannelMultilineResult {
        session: SessionOwner,
        result: ChannelMultilineResult,
    },
    ChannelTagmsg {
        tagmsg: ChannelTagmsg,
    },
    ChannelTagmsgResult {
        session: SessionOwner,
        result: ChannelTagmsgResult,
        label: Option<String>,
    },
    /// The socket closed or errored; `reason` is used in the QUIT
    /// broadcast if the session was registered.
    Closed {
        conn: ConnId,
        reason: String,
    },
    /// A periodic timer tick carrying the current **monotonic** millisecond,
    /// driving the liveness reaper (registration deadline + idle PING/PONG
    /// timeout). Monotonic, not wall-clock, so an NTP step can't make the reaper
    /// mass-close live connections or freeze.
    Tick {
        now: e6irc_proto::time::MonoMillis,
    },
    /// A worker's own reminder, every [`PACE_INTERVAL`] while it has a LIST
    /// or WHO reply being paced out and nothing else to do: the reply's
    /// client may have read enough for more of its rows.
    PaceReplies,
    /// Read markers storage maintenance deleted as past the history
    /// retention, broadcast to every shard so its mirror drops them too. The
    /// mirror counts toward the per-account marker cap: a marker the database
    /// no longer holds, still counted here, would refuse a new target the
    /// database would admit.
    ReadMarkersExpired {
        markers: Arc<[ExpiredReadMarker]>,
    },
    /// An account was permanently deleted, broadcast to every shard so it
    /// drops its mirror of the account's rows: read markers, hot history,
    /// channel access, grouped nicks — and moves the founder of each channel
    /// that passed to its successor (see
    /// [`state::ServerState::forget_deleted_account`]).
    AccountDeleted {
        account: String,
        successions: Vec<crate::db::ChannelSuccession>,
    },
    /// An answer from the DB worker to an earlier [`DbRequest`].
    DbReply {
        conn: ConnId,
        reply: DbReply,
    },
    /// A resolved CHATHISTORY page from PostgreSQL. `Err` means there is no
    /// page — the store failed, or does not know the msgid asked about — and
    /// the handler answers a CHATHISTORY FAIL rather than an empty batch, so
    /// neither is ever indistinguishable from a buffer with no history.
    HistoryPage {
        conn: ConnId,
        display: String,
        batch_ref: String,
        /// Capabilities that affect history rendering, captured at request
        /// time so a later CAP change cannot alter a deferred reply.
        caps: HistoryResponseCaps,
        rows: Result<Vec<HistoryRow>, HistoryFault>,
        /// Labeled-response label to place on the batch, if the command that
        /// triggered this deferred page was labeled.
        label: Option<String>,
    },
    /// Resolved CHATHISTORY TARGETS from PostgreSQL: `(target, latest ts)`
    /// pairs for the buffers with activity in the requested window. `Err` means
    /// the store failed — answered with a FAIL, not an empty batch.
    TargetsPage {
        conn: ConnId,
        batch_ref: String,
        /// Request-time capabilities for deferred framing.
        caps: HistoryResponseCaps,
        targets: Result<Vec<(String, e6irc_proto::time::Millis)>, ()>,
        /// Labeled-response label to place on the batch, if the command that
        /// triggered this deferred page was labeled.
        label: Option<String>,
    },
    /// Graceful-shutdown request, injected by the signal handler. The core
    /// notifies every connected client with a terminal `ERROR`, after which the
    /// worker loop stops and the `Core` is dropped — dropping the sole
    /// `Sender<DbRequest>` and letting the DB worker drain and flush its
    /// buffered history before the process exits (DESIGN §18).
    Shutdown,
    /// An administrative action from the HTTP console, run on the core thread
    /// like any other input (so it sees and mutates live state consistently).
    /// There is no IRC session behind it — the acting admin account is named in
    /// the request — and the outcome is returned over the oneshot `reply`.
    Admin {
        req: AdminRequest,
        reply: tokio::sync::oneshot::Sender<AdminReply>,
    },
    /// A registered-channel deletion verdict. Unlike ordinary DB replies this
    /// may belong to an IRC connection or an HTTP admin request, so its typed
    /// requester travels with it instead of inventing a sentinel `ConnId`.
    ChannelDropResult {
        owner: ChannelOwner,
        channel: String,
        requester: ChannelDropRequester,
        result: ChannelDropResult,
    },
    ChannelDropReply {
        session: SessionOwner,
        display: String,
        label: Option<String>,
        result: ChannelDropResult,
    },
    /// A server-ban add/remove verdict. Like channel deletion, the requester
    /// may be an IRC operator or an HTTP admin request.
    ServerBanResult {
        mutation: ServerBanMutation,
        requester: ServerBanRequester,
        result: ServerBanResult,
    },
    /// A database-confirmed server-ban transition applied on every core shard.
    ServerBanApplied {
        mutation: ServerBanMutation,
    },
    /// A durable account-suspension transition applied on every core shard.
    AccountSuspensionApplied {
        account: String,
        suspended: bool,
        reason: String,
        actor: String,
    },
    /// A stored account read marker applied on every non-origin core shard.
    ReadMarkerApplied {
        account: String,
        target: String,
        display: String,
        marker_ms: e6irc_proto::time::Millis,
    },
    /// One shard's bounded contribution to an administrator connection list.
    AdminConnectionList {
        request_id: u64,
        query: LiveConnectionQuery,
    },
    AdminConnectionListResult {
        request_id: u64,
        entries: Vec<LiveConnectionInfo>,
    },
    /// A founder-owned registered-channel mutation verdict. The database
    /// re-checks ownership before writing; only an applied verdict changes the
    /// core's hot founder/topic/mode/access mirrors.
    ChannelControlResult {
        owner: ChannelOwner,
        request_id: u64,
        result: ChannelControlResult,
    },
    /// A founder registration requested through the owner REST/console
    /// control plane. Authorization happens against live operator membership;
    /// the typed verdict applies the same hot founder/topic transition as
    /// ChanServ only after PostgreSQL confirms the insert.
    OwnedChannelRegistrationResult {
        owner: ChannelOwner,
        request_id: u64,
        result: ChannelRegistrationResult,
    },
}

/// Drain framed line events into the core queue as [`Input`] lines. Returns
/// `false` when the core is gone, so the connection stops directly rather
/// than queueing into a void. Shared by the TCP and WebSocket read loops.
pub(crate) async fn push_framed(
    core_tx: &CoreIngress,
    meter: &mut line_meter::LineMeter,
    conn: ConnId,
    events: &mut Vec<e6irc_proto::framing::LineEvent>,
) -> bool {
    for event in events.drain(..) {
        let input = match event {
            e6irc_proto::framing::LineEvent::Line(line) => Input::Line { conn, line },
            e6irc_proto::framing::LineEvent::TooLong => Input::OverlongLine { conn },
        };
        meter.spend().await;
        if core_tx.push(input).await.is_err() {
            return false;
        }
    }
    true
}

/// A mutation or live-state query requested by an authenticated HTTP console
/// or API surface (DESIGN §9.4). Processed on the core thread via
/// [`Input::Admin`], reusing the same live state, hot lists and persistence
/// path as the equivalent IRC oper/services command.
#[derive(Debug)]
pub enum AdminRequest {
    /// Add a K/D/X-line (`kind` is "kline"/"dline"/"xline"). Persisted,
    /// enforced, and matching sessions disconnected — exactly like oper KLINE.
    AddServerBan {
        mask: String,
        kind: String,
        reason: String,
        actor: String,
        /// A temporary ban's length; `None` for a permanent one.
        duration_minutes: Option<std::num::NonZeroU32>,
    },
    /// Remove a K/D/X-line by (mask, kind).
    RemoveServerBan {
        expected_id: Option<i64>,
        mask: String,
        kind: String,
        actor: String,
    },
    /// Unregister a registered channel (like ChanServ DROP, founder-agnostic).
    DropChannel { channel: String, actor: String },
    /// Query a bounded, stable page of live registered connections.
    ListConnections { query: LiveConnectionQuery },
    /// Disconnect the exact live connection identified by its immutable
    /// resource id.
    DisconnectConnection {
        connection_id: u64,
        reason: String,
        actor: String,
    },
    /// Disconnect an immutable live connection id only when it is currently
    /// authenticated as `account`.
    DisconnectOwnConnection {
        connection_id: u64,
        reason: String,
        account: String,
    },
    /// Reconcile one durable account suspension into the ordered live core.
    /// Suspending installs the authentication deny gate before disconnecting
    /// every current session; reactivation removes the gate.
    SetAccountSuspended {
        account: String,
        suspended: bool,
        reason: String,
        actor: String,
    },
    /// Mutate one registered channel owned by `actor`. This is the shared
    /// control-plane entry used by the owner API and console.
    MutateOwnedChannel {
        channel: String,
        actor: String,
        mutation: ChannelMutation,
    },
    /// Register a live channel currently operated by an authenticated session
    /// belonging to `actor`.
    RegisterOwnedChannel { channel: String, actor: String },
}

impl AdminRequest {
    fn channel(&self) -> Option<&str> {
        match self {
            Self::DropChannel { channel, .. }
            | Self::MutateOwnedChannel { channel, .. }
            | Self::RegisterOwnedChannel { channel, .. } => Some(channel),
            _ => None,
        }
    }

    fn shard(&self, shards: CoreShardCount) -> CoreShardId {
        match self {
            Self::DisconnectConnection { connection_id, .. }
            | Self::DisconnectOwnConnection { connection_id, .. } => {
                shards.session_owner(ConnId(*connection_id)).shard()
            }
            _ => self.channel().map_or(CoreShardId(0), |channel| {
                shards.shard_for_channel_name(channel)
            }),
        }
    }
}

/// User-facing registered-channel mutations accepted by the HTTP control
/// plane. The core validates and converts these into
/// [`PersistedChannelMutation`] before they cross the database queue.
#[derive(Debug)]
pub enum ChannelMutation {
    SetTopic {
        topic: Option<String>,
    },
    SetKeeptopic {
        enabled: bool,
    },
    SetMlock {
        mlock: Option<String>,
    },
    SetAccess {
        account: String,
        flags: Option<String>,
    },
    TransferFounder {
        account: String,
    },
    Drop,
}

/// A validated registered-channel mutation ready for persistence and hot-state
/// application. Topic provenance and canonical MLOCK/access values are fixed
/// here, so the database and live core cannot interpret the same request
/// differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedChannelMutation {
    SetTopic {
        topic: Option<(String, String, u64)>,
    },
    SetKeeptopic {
        enabled: bool,
        topic: Option<(String, String, u64)>,
    },
    SetMlock {
        mlock: Option<String>,
    },
    SetAccess {
        account: String,
        flags: Option<String>,
    },
    TransferFounder {
        account: String,
    },
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelControlResult {
    /// Stored. `account` is the account an access change or founder transfer
    /// named, as storage resolved it (a grouped nick names its account).
    Applied {
        account: Option<String>,
    },
    MissingOrNotOwner,
    AccountMissing,
    AccessLimitReached,
    /// The transfer's receiving account already founds
    /// [`crate::db::CHANNEL_FOUNDER_LIMIT`] channels.
    FounderLimitReached,
    KeeptopicDisabled,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRegistrationResult {
    Registered,
    Exists,
    AccountMissing,
    /// The founder already founds [`crate::db::CHANNEL_FOUNDER_LIMIT`]
    /// channels — counted where every shard's registrations meet.
    LimitReached,
    Unavailable,
}

/// The ingress path that owns one live core connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTransport {
    Tcp,
    Tls,
    /// A WebSocket whose upgrade did not come over HTTPS through a trusted
    /// proxy: plaintext somewhere between the client and this server.
    WebSocket,
    /// A WebSocket a trusted proxy says its client reached over HTTPS (every
    /// `X-Forwarded-Proto` entry is `https`); the listener itself never
    /// terminates TLS.
    SecureWebSocket,
    Local,
}

impl ConnectionTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::WebSocket => "websocket",
            Self::SecureWebSocket => "wss",
            Self::Local => "local",
        }
    }
}

/// A non-zero connection-directory page size capped at the public API maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveConnectionPageSize(usize);

impl LiveConnectionPageSize {
    pub const MAX: usize = 1_000;

    pub fn new(value: usize) -> Option<Self> {
        (1..=Self::MAX).contains(&value).then_some(Self(value))
    }

    pub const fn value(self) -> usize {
        self.0
    }
}

/// Validated filters for a bounded live-connection snapshot. Connection ids
/// increase for the process lifetime, so `before_id` gives newest-first
/// keyset pagination that concurrent accepts cannot disturb.
#[derive(Debug, Clone)]
pub struct LiveConnectionQuery {
    pub before_id: Option<u64>,
    pub exact_nick: Option<String>,
    pub exact_account: Option<String>,
    pub transport: Option<ConnectionTransport>,
    pub oper: Option<bool>,
    pub page_size: LiveConnectionPageSize,
}

/// A snapshot of one live registered client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveConnectionInfo {
    pub id: u64,
    pub nick: String,
    pub user: String,
    pub host: String,
    pub account: Option<String>,
    pub oper: bool,
    pub transport: ConnectionTransport,
    pub connected_at: e6irc_proto::time::Millis,
    pub idle_seconds: u64,
    pub channels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveConnectionPage {
    pub entries: Vec<LiveConnectionInfo>,
    pub next_before_id: Option<u64>,
}

/// The outcome of an [`AdminRequest`], returned over its oneshot reply.
#[derive(Debug)]
pub enum AdminReply {
    /// Success, with a human-readable one-line summary.
    Ok(String),
    /// Rejected: bad input, nothing matched, or persistence unavailable.
    Err(String),
    /// A founder channel-control rejection with a stable machine category for
    /// the REST problem response.
    ChannelErr {
        kind: ChannelControlError,
        message: String,
    },
    /// A server-ban control rejection with a stable machine category for the
    /// REST problem response.
    BanErr {
        kind: BanControlError,
        message: String,
    },
    /// A bounded live-connection page.
    Connections(LiveConnectionPage),
    /// An exact connection-id mutation found no eligible live connection.
    ConnectionMissing,
    /// The action's audit row could not be queued, so the action was not
    /// taken.
    AuditUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelControlError {
    Invalid,
    NotFound,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanControlError {
    Invalid,
    NotFound,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelDropRequester {
    ChanServ {
        session: SessionOwner,
        display: String,
        label: Option<String>,
        /// The founder's account, recorded as the drop's actor.
        actor: String,
    },
    Admin {
        request_id: u64,
        actor: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDropResult {
    Dropped,
    Missing,
    /// The ChanServ requester no longer founds the channel (a transfer
    /// committed after the core's check).
    NotFounder,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerBanRequester {
    Oper {
        session: SessionOwner,
        label: Option<String>,
        /// The configured operator name the session opered up as — who the
        /// audit row records, whatever nick the session holds.
        operator: String,
    },
    Admin {
        request_id: u64,
        actor: String,
    },
}

impl ServerBanRequester {
    /// Who the audit trail records as having made the change: an operator
    /// by its configured name, an administrator by account.
    pub fn audit_actor(&self) -> crate::db::AuditPrincipal {
        match self {
            Self::Oper { operator, .. } => crate::db::AuditPrincipal::operator(operator),
            Self::Admin { actor, .. } => crate::db::AuditPrincipal::account(actor),
        }
    }
}

/// How long a temporary server ban lasts: set for `minutes`, in force until
/// `expires_at_secs` (Unix seconds on the wall clock). Decided once, where the
/// ban was set, and carried to the database and every shard, so they all lift
/// it at the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerBanExpiry {
    pub minutes: u32,
    pub expires_at_secs: u64,
}

impl ServerBanExpiry {
    /// The longest temporary ban, in minutes: 52 weeks, Solanum's
    /// `MAX_TEMP_TIME`. A longer request is held to it, as Solanum holds it.
    pub const MAX_MINUTES: u32 = 52 * 7 * 24 * 60;

    /// A ban of `minutes` (at most [`Self::MAX_MINUTES`]) set at `now_secs`.
    pub fn starting(now_secs: u64, minutes: std::num::NonZeroU32) -> Self {
        let minutes = minutes.get().min(Self::MAX_MINUTES);
        Self {
            minutes,
            expires_at_secs: now_secs.saturating_add(u64::from(minutes) * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerBanMutation {
    Add {
        mask: String,
        mask_display: String,
        reason: String,
        set_by: String,
        kind: String,
        /// `None` for a permanent ban.
        expiry: Option<ServerBanExpiry>,
    },
    Remove {
        expected_id: Option<i64>,
        mask: String,
        mask_display: String,
        kind: String,
        actor: String,
    },
}

impl ServerBanMutation {
    pub fn key(&self) -> (&str, &str) {
        match self {
            Self::Add { mask, kind, .. } | Self::Remove { mask, kind, .. } => (kind, mask),
        }
    }

    /// An `Add` mutation from a validated mask and its context. Every
    /// construction — oper KLINE and the admin console alike — serializes the
    /// folded/display mask and kind the same way, so they cannot drift.
    pub fn add(
        mask: &state::MaskKey,
        kind: state::BanKind,
        reason: String,
        set_by: String,
        expiry: Option<ServerBanExpiry>,
    ) -> Self {
        Self::Add {
            mask: mask.folded().to_string(),
            mask_display: mask.as_str().to_string(),
            reason,
            set_by,
            kind: kind.as_str().to_string(),
            expiry,
        }
    }

    /// A `Remove` mutation from a validated mask and the acting identity.
    pub fn remove(mask: &state::MaskKey, kind: state::BanKind, actor: String) -> Self {
        Self::remove_with_id(mask, kind, actor, None)
    }

    pub fn remove_with_id(
        mask: &state::MaskKey,
        kind: state::BanKind,
        actor: String,
        expected_id: Option<i64>,
    ) -> Self {
        Self::Remove {
            expected_id,
            mask: mask.folded().to_string(),
            mask_display: mask.as_str().to_string(),
            kind: kind.as_str().to_string(),
            actor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerBanResult {
    Stored,
    Missing,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTopicFailure {
    MissingRegistration,
    PersistenceUnavailable,
}

/// A durable TOPIC verdict that must be applied by the channel owner.
#[derive(Debug)]
pub enum ChannelTopicPersistence {
    Set {
        channel: String,
        display: String,
        prefix: String,
        origin: state::Originator,
        topic: Option<(String, String, u64)>,
        revision: u64,
        retained: bool,
        label: Option<String>,
    },
    Failed {
        channel: String,
        display: String,
        revision: u64,
        label: Option<String>,
        failure: ChannelTopicFailure,
    },
}

/// A database-confirmed ChanServ mutation. The channel owner applies its live
/// state before the requester receives a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelServicePersistence {
    FounderChanged {
        channel: String,
        account: String,
        display: String,
        label: Option<String>,
    },
    FounderMissing {
        channel: String,
        display: String,
        label: Option<String>,
    },
    FounderUnavailable {
        channel: String,
        display: String,
        label: Option<String>,
    },
    /// The named account already founds [`crate::db::CHANNEL_FOUNDER_LIMIT`]
    /// channels; the channel was not transferred.
    FounderLimitReached {
        display: String,
        label: Option<String>,
    },
    /// An access entry now holds `flags` (`None`: it is gone).
    AccessSet {
        channel: String,
        display: String,
        /// The account the requested name resolved to (a grouped nick
        /// resolves to its account), as its display name.
        account: String,
        flags: Option<String>,
        /// What the entry held before (`None`: there was no entry).
        previous: Option<String>,
        /// Which command asked, so the verdict speaks its language.
        frontend: AccessFrontend,
        label: Option<String>,
    },
    /// No account has the name an access change named.
    AccessAccountMissing {
        display: String,
        account: String,
        frontend: AccessFrontend,
        label: Option<String>,
    },
    AccessUnavailable {
        channel: String,
        display: String,
        label: Option<String>,
    },
    AccessMissing {
        display: String,
        label: Option<String>,
    },
    AccessLimitReached {
        channel: String,
        display: String,
        label: Option<String>,
    },
    KeeptopicSet {
        channel: String,
        display: String,
        keeptopic: bool,
        topic: Option<(String, String, u64)>,
        label: Option<String>,
    },
    KeeptopicUnavailable {
        channel: String,
        display: String,
        label: Option<String>,
    },
    KeeptopicMissing {
        display: String,
        label: Option<String>,
    },
    MlockSet {
        channel: String,
        display: String,
        mlock: Option<String>,
        label: Option<String>,
    },
    MlockUnavailable {
        channel: String,
        display: String,
        label: Option<String>,
    },
    MlockMissing {
        display: String,
        label: Option<String>,
    },
    MlockInvalid {
        label: Option<String>,
    },
    /// The verdict of a ChanServ SET SUCCESSOR; `outcome` is `None` when the
    /// store failed.
    SuccessorSet {
        display: String,
        /// The successor as requested (`None`: clear it).
        successor: Option<String>,
        outcome: Option<crate::db::SuccessorChange>,
        label: Option<String>,
    },
    /// A founder-only change (SET FOUNDER, access, KEEPTOPIC, MLOCK) found,
    /// with the channel row locked, that the channel is gone or its requester
    /// no longer founds it.
    Refused {
        display: String,
        refusal: crate::db::ChannelRefusal,
        label: Option<String>,
    },
}

/// Which ChanServ command changed a channel access entry: FLAGS, or the
/// ACCESS front end over the same flags (Atheme's role names, `role` being the
/// role granted or removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessFrontend {
    Flags,
    AccessAdd { role: &'static str },
    AccessDel { role: &'static str },
}

/// Work the core asks the DB worker to do. The worker returns a typed core
/// event; the core never blocks on the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbRequest {
    VerifyPassword {
        conn: ConnId,
        account: String,
        password: String,
        /// Which command asked, echoed onto the reply so it routes itself.
        origin: CredentialOrigin,
    },
    /// Verify a bearer token (SASL OAUTHBEARER); answered with the same
    /// `PasswordVerified`/`PasswordRejected` replies as a password. A token is
    /// only ever presented by SASL, so its reply origin is always `Sasl`.
    VerifyToken { conn: ConnId, token: String },
    CreateAccount {
        conn: ConnId,
        name: String,
        contact_email: Option<crate::identity::ContactEmail>,
        password: crate::identity::NewPassword,
        /// Which command asked, so the answer speaks that command's language.
        origin: AccountOrigin,
    },
    RegisterChannel {
        owner: ChannelOwner,
        session: SessionOwner,
        channel: String,
        founder_account: String,
        /// The live topic at request time. Registration and its initial retained
        /// topic are one database transition, never two independently failing
        /// writes.
        topic: Option<(String, String, u64)>,
        /// Escaped labeled-response label carried onto the deferred verdict.
        label: Option<String>,
    },
    /// Register a channel through the owner HTTP control plane. The core has
    /// already verified that an `actor` session operates the live channel.
    RegisterOwnedChannel {
        owner: ChannelOwner,
        request_id: u64,
        channel: String,
        founder_account: String,
        topic: Option<(String, String, u64)>,
    },
    /// Unregister a channel (ChanServ DROP).
    DropChannel {
        owner: ChannelOwner,
        /// Casefolded channel name.
        channel: String,
        requester: ChannelDropRequester,
    },
    /// Transfer a registered channel's founder (ChanServ SET FOUNDER).
    SetChannelFounder {
        owner: ChannelOwner,
        session: SessionOwner,
        /// Channel name as typed (for the reply notice).
        channel: String,
        /// New founder account, casefolded.
        new_founder: String,
        label: Option<String>,
        /// The founder's account, recorded as the transfer's actor.
        actor: String,
    },
    /// Page history from PostgreSQL when the request reaches past the
    /// in-memory ring. Answered with [`Input::HistoryPage`].
    QueryHistory {
        conn: ConnId,
        /// The stored buffer: a folded channel name, or the conversation key
        /// of two *accounts*. Never a conversation with an unauthenticated
        /// (`~nick`) party — those are not stored (see `record_history`).
        target: String,
        /// The oldest history this reader may see.
        floor: HistoryFloor,
        display: String,
        batch_ref: String,
        /// Request-time capabilities that affect history rendering.
        caps: HistoryResponseCaps,
        query: HistoryQuery,
        /// Escaped labeled-response label to carry onto the deferred batch, if
        /// the originating command was labeled.
        label: Option<String>,
    },
    /// Enumerate the buffers (among `channels`, the requester's memberships)
    /// with messages in `[min_ts, max_ts]`. Answered with
    /// [`Input::TargetsPage`].
    QueryTargets {
        conn: ConnId,
        /// Casefolded channel targets the requester may see, each with the
        /// oldest history the requester may see of it: a channel whose only
        /// activity is older is not the requester's buffer.
        channels: Vec<(String, HistoryFloor)>,
        /// The requester's account identity, used to find the stored
        /// direct-message conversations they take part in. Their correspondents
        /// are buffers too, and a bouncer reconnecting needs them alongside
        /// channels. `None` for an unauthenticated requester, who has no stored
        /// conversations: `~nick` is whoever holds the nick now.
        me: Option<String>,
        /// Conversations in the window that exist only in this session's rings
        /// (one party is unauthenticated), as `(correspondent identity, latest)`.
        /// The database cannot know them; they are merged into its answer.
        session_only: Vec<(String, e6irc_proto::time::Millis)>,
        min_ts: e6irc_proto::time::Millis,
        max_ts: e6irc_proto::time::Millis,
        limit: usize,
        batch_ref: String,
        /// Request-time capabilities that affect history rendering.
        caps: HistoryResponseCaps,
        /// Escaped labeled-response label to carry onto the deferred batch, if
        /// the originating command was labeled.
        label: Option<String>,
    },
    /// Persist a read marker. Answered with [`DbReply::ReadMarkerStored`],
    /// [`DbReply::ReadMarkerLimitReached`] or
    /// [`DbReply::ReadMarkerUnavailable`]; the core updates its hot mirror and
    /// acknowledges the command only after that verdict.
    SetReadMarker {
        conn: ConnId,
        account: String,
        /// Casefolded target.
        target: String,
        /// Validated target spelling from the command, for the reply.
        display: String,
        marker_ms: e6irc_proto::time::Millis,
        /// Escaped labeled-response label carried onto the deferred reply.
        label: Option<String>,
    },
    /// Persist a registered channel's retained topic. The worker reports
    /// whether the row still exists and has KEEPTOPIC enabled; the live topic
    /// and retained hot mirror change only after that verdict.
    SetChannelTopic {
        owner: ChannelOwner,
        session: SessionOwner,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the eventual TOPIC line.
        display: String,
        /// Prefix captured when the command was authorized.
        prefix: String,
        /// The setter's originator tags, for the TOPIC line's tags.
        origin: state::Originator,
        topic: Option<(String, String, u64)>,
        revision: u64,
        label: Option<String>,
    },
    /// Persist a registered channel's KEEPTOPIC option and the retained topic
    /// it implies as one database transition.
    SetChannelKeeptopic {
        owner: ChannelOwner,
        session: SessionOwner,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the service verdict.
        display: String,
        keeptopic: bool,
        /// Current live topic when enabling; ignored when disabling.
        topic: Option<(String, String, u64)>,
        label: Option<String>,
        /// The founder's account, recorded as the change's actor.
        actor: String,
    },
    /// Persist a registered channel's mode lock. `mlock` is the canonical spec
    /// string; `None` clears the lock.
    SetChannelMlock {
        owner: ChannelOwner,
        session: SessionOwner,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the service verdict.
        display: String,
        mlock: Option<String>,
        label: Option<String>,
        /// The founder's account, recorded as the change's actor.
        actor: String,
    },
    /// Persist one channel access entry, then answer with `ChannelAccessSet` so
    /// the hot map is updated only on a confirmed write (a grant to an
    /// unregistered account writes nothing and must not become a phantom
    /// entry). `flags: None` removes the entry. `channel`/`account` are as
    /// typed; the worker folds them.
    SetChannelAccess {
        owner: ChannelOwner,
        session: SessionOwner,
        channel: String,
        display: String,
        account: String,
        flags: Option<String>,
        frontend: AccessFrontend,
        label: Option<String>,
        /// The founder's account, recorded as the change's actor.
        actor: String,
    },
    /// Name (`Some`, casefolded) or clear (`None`) a registered channel's
    /// successor (ChanServ SET SUCCESSOR).
    SetChannelSuccessor {
        owner: ChannelOwner,
        session: SessionOwner,
        /// Channel name as typed, for the verdict.
        channel: String,
        successor: Option<String>,
        label: Option<String>,
        /// The founder's account, recorded as the change's actor.
        actor: String,
    },
    /// Group `nick` to `account` (NickServ GROUP). Answered with
    /// [`DbReply::NickGroup`].
    GroupNick {
        conn: ConnId,
        account: String,
        nick: String,
        label: Option<String>,
    },
    /// Remove a grouped nick from `account` (NickServ UNGROUP). Answered with
    /// [`DbReply::NickUngroup`].
    UngroupNick {
        conn: ConnId,
        account: String,
        nick: String,
        label: Option<String>,
    },
    /// Turn `account`'s nick protection on or off (NickServ SET ENFORCE).
    /// Answered with [`DbReply::NickEnforce`].
    SetNickEnforce {
        conn: ConnId,
        account: String,
        enforce: bool,
        label: Option<String>,
    },
    /// Look up the account a nick or account name belongs to (NickServ INFO).
    /// Answered with [`DbReply::AccountInfo`].
    AccountInfo {
        conn: ConnId,
        target: String,
        label: Option<String>,
    },
    /// Permanently delete `account` once its primary password verifies
    /// (NickServ DROP), through the same succession-checked deletion the
    /// console uses. Answered with [`DbReply::AccountDrop`].
    DropAccount {
        conn: ConnId,
        account: String,
        password: String,
        label: Option<String>,
    },
    /// Persist a founder-owned HTTP control-plane mutation. The numeric request
    /// id maps the verdict back to a core-owned oneshot sender without putting
    /// the non-clonable sender on this queue.
    MutateOwnedChannel {
        owner: ChannelOwner,
        request_id: u64,
        channel: String,
        actor: String,
        mutation: PersistedChannelMutation,
    },
    /// Persist a server-ban mutation and its audit row atomically, then return
    /// a typed verdict before the core mutates or enforces its hot list.
    MutateServerBan {
        mutation: ServerBanMutation,
        requester: ServerBanRequester,
    },
    /// Record a privileged (oper) action in the audit log. Fire-and-forget.
    AuditLog {
        actor: crate::db::AuditPrincipal,
        action: String,
        target: crate::db::AuditPrincipal,
        detail: String,
    },
    /// Append one chat message to history. Fire-and-forget: no reply.
    LogMessage {
        msgid: String,
        /// Casefolded target: a channel name, or a direct-message
        /// conversation key (both participants' nicks, sorted).
        target: String,
        /// For a direct message, the conversation's two casefolded
        /// participants; empty for a channel. CHATHISTORY TARGETS needs to
        /// find the conversations a given user takes part in, which the
        /// composite conversation key cannot be searched for.
        dm_peers: Vec<String>,
        sender_prefix: String,
        sender_account: Option<String>,
        kind: HistoryKind,
        body: String,
        /// The sender was a bot (+B) at send time (replayed as the `bot` tag).
        sender_is_bot: bool,
        /// Encoded `draft/multiline` lines, or `None` for a single-line message
        /// (see `HistoryEntry::multiline`). Persisted so replay reconstructs the
        /// multiline message under its one msgid.
        multiline: Option<String>,
        /// The client-only tags the message was relayed with (see
        /// `HistoryRow::client_tags`); empty for none.
        client_tags: String,
        /// Unix milliseconds.
        ts: e6irc_proto::time::Millis,
    },
}

/// Which command asked for an account to be created. Carried on the request
/// and echoed on the reply, so the answer is phrased in the language of the
/// command that asked: NickServ speaks in notices, the
/// `draft/account-registration` REGISTER command in `REGISTER`/`FAIL`. Tracking
/// this on the session instead would go wrong the moment a client used both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOrigin {
    NickServ,
    RegisterCommand,
}

/// Which command asked for a credential verification. The reply carries this
/// back so `db_reply` routes on the origin the request *was*, not on session
/// flags that guess it: `sasl == Verifying` and `pending_identify` can both be
/// set at once (a registered client may interleave `AUTHENTICATE` with a
/// NickServ `IDENTIFY`), and inferring the origin from them mis-routed an
/// IDENTIFY verdict as a SASL one. The origin routes; the session flag only
/// says whether that path is still live (not aborted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOrigin {
    /// A SASL `AUTHENTICATE` — PLAIN password or OAUTHBEARER token.
    Sasl,
    /// A NickServ `IDENTIFY`.
    NickServIdentify,
}

/// A resolved CHATHISTORY window.
/// Why the database has no page for a CHATHISTORY request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryFault {
    /// The store failed; the window may well exist.
    Unavailable { subcommand: &'static str },
    /// The store answered, and holds no message with this id in the requested
    /// buffer. Not an empty page: a client resuming from a msgid that is gone
    /// would read "nothing newer" as "up to date".
    UnknownMsgid { subcommand: &'static str },
}

/// The oldest history a read may return, decided by who is reading. A
/// channel's name outlives its occupants: once the last member leaves it is
/// gone, and whoever joins the name next creates a new incarnation. The stored
/// record of the old one is not theirs to read — only the founder and the
/// access list of a registered channel keep the whole record, as over REST.
/// Every history read takes one of these, so none can forget the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryFloor {
    /// The whole stored record: a conversation (its key is derived from the
    /// reader), or a registered channel read by its founder or an access-list
    /// member.
    Whole,
    /// Only messages stamped at or after this time: the current incarnation
    /// of a channel, for everyone else.
    Since(e6irc_proto::time::Millis),
}

impl HistoryFloor {
    /// Whether a message stamped `ts` is readable under this floor.
    pub fn admits(self, ts: e6irc_proto::time::Millis) -> bool {
        match self {
            Self::Whole => true,
            Self::Since(since) => ts >= since,
        }
    }

    /// The bound as the millisecond value the history queries compare `ts`
    /// against (`ts >= to_timestamp(bound / 1000)`): the epoch for the whole
    /// record, before which no message can be stamped.
    pub fn millis(self) -> e6irc_proto::time::Millis {
        match self {
            Self::Whole => e6irc_proto::time::Millis::from_millis(0),
            Self::Since(since) => since,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryQuery {
    Latest {
        limit: usize,
    },
    /// `LATEST` with a non-`*` selector: the *newest* `limit` messages that
    /// are strictly newer than the bound. Deliberately distinct from
    /// [`HistoryQuery::After`], which returns the *oldest* `limit` after the
    /// bound — the two coincide only when fewer than `limit` messages follow
    /// it, and draft/chathistory specifies LATEST as most-recent-first.
    LatestAfter {
        after_ts: e6irc_proto::time::Millis,
        limit: usize,
    },
    LatestAfterMsgid {
        msgid: String,
        limit: usize,
    },
    Before {
        before_ts: e6irc_proto::time::Millis,
        limit: usize,
    },
    After {
        after_ts: e6irc_proto::time::Millis,
        limit: usize,
    },
    /// Up to `limit` messages centred on `around_ts` (about half older,
    /// half newer), oldest-first.
    Around {
        around_ts: e6irc_proto::time::Millis,
        limit: usize,
    },
    /// Up to `limit` messages strictly between the two selectors, always
    /// returned oldest-first. Each selector is resolved to its `(ts, id)`
    /// position *in the database* (a `msgid=` pivot may have scrolled out of the
    /// in-memory ring), so the span's bounds and the paging direction don't
    /// depend on the ring holding either pivot. The window walks from `first`
    /// toward `second`: when `first` is the newer bound the `limit` keeps the
    /// newest messages in the span rather than the oldest.
    BetweenSelectors {
        first: SelectorBound,
        second: SelectorBound,
        limit: usize,
    },
    /// Msgid-pivoted variants. Timestamps are millisecond-granular, but two
    /// messages can still land in the same millisecond; paging by timestamp
    /// alone would skip one of them. These page on the composite `(ts, id)`
    /// relative to the pivot row, so ties are ordered definitively by the
    /// unique id.
    BeforeMsgid {
        msgid: String,
        limit: usize,
    },
    AfterMsgid {
        msgid: String,
        limit: usize,
    },
    AroundMsgid {
        msgid: String,
        limit: usize,
    },
}

impl HistoryQuery {
    /// The subcommand a client used to ask for this window.
    pub(crate) fn subcommand(&self) -> &'static str {
        match self {
            Self::Latest { .. } | Self::LatestAfter { .. } | Self::LatestAfterMsgid { .. } => {
                "LATEST"
            }
            Self::Before { .. } | Self::BeforeMsgid { .. } => "BEFORE",
            Self::After { .. } | Self::AfterMsgid { .. } => "AFTER",
            Self::Around { .. } | Self::AroundMsgid { .. } => "AROUND",
            Self::BetweenSelectors { .. } => "BETWEEN",
        }
    }

    /// The message ids this window is positioned by.
    pub(crate) fn msgid_pivots(&self) -> Vec<&str> {
        match self {
            Self::LatestAfterMsgid { msgid, .. }
            | Self::BeforeMsgid { msgid, .. }
            | Self::AfterMsgid { msgid, .. }
            | Self::AroundMsgid { msgid, .. } => vec![msgid],
            Self::BetweenSelectors { first, second, .. } => [first, second]
                .into_iter()
                .filter_map(|bound| match bound {
                    SelectorBound::Msgid(msgid) => Some(msgid.as_str()),
                    SelectorBound::Timestamp(_) => None,
                })
                .collect(),
            Self::Latest { .. }
            | Self::LatestAfter { .. }
            | Self::Before { .. }
            | Self::After { .. }
            | Self::Around { .. } => Vec::new(),
        }
    }
}

/// One resolved CHATHISTORY BETWEEN endpoint: a message id or a timestamp. The
/// database resolves each to a `(ts, id)` position, so a `msgid=` pivot that is
/// no longer in the ring is still paged correctly (unlike a ring-only lookup,
/// which would lose the bound or mis-order the two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorBound {
    Msgid(String),
    Timestamp(e6irc_proto::time::Millis),
}

/// PRIVMSG or NOTICE — the only two message kinds that carry a body. A single
/// type instead of a `&str` so the forms of the name cannot drift: the
/// uppercase wire verb ([`MessageKind::wire`]) and the "does it trigger
/// automatic replies" rule ([`MessageKind::is_loud`] — NOTICE never does).
/// Before this they were carried as a string that was uppercased in one place
/// and lowercased in another, so the ring and the database stored different
/// casings of the same message; now the casing exists only at the edges where
/// it is asked for (the storage token is [`HistoryKind::db`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Privmsg,
    Notice,
}

impl MessageKind {
    /// The uppercase verb as it appears on the wire.
    pub fn wire(self) -> &'static str {
        match self {
            MessageKind::Privmsg => "PRIVMSG",
            MessageKind::Notice => "NOTICE",
        }
    }

    /// PRIVMSG triggers automatic replies (error numerics, away auto-reply);
    /// NOTICE must never trigger any (Modern IRC), so it is silent.
    pub fn is_loud(self) -> bool {
        matches!(self, MessageKind::Privmsg)
    }
}

/// What a history entry is: a message with text, or a `TAGMSG` — nothing but
/// its client-only tags (a reaction, say). Both are
/// stored and replayed under the msgid they were delivered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    Privmsg,
    Notice,
    Tagmsg,
}

impl From<MessageKind> for HistoryKind {
    fn from(kind: MessageKind) -> Self {
        match kind {
            MessageKind::Privmsg => HistoryKind::Privmsg,
            MessageKind::Notice => HistoryKind::Notice,
        }
    }
}

impl HistoryKind {
    /// The uppercase verb as it appears on the wire.
    pub fn wire(self) -> &'static str {
        match self {
            HistoryKind::Privmsg => MessageKind::Privmsg.wire(),
            HistoryKind::Notice => MessageKind::Notice.wire(),
            HistoryKind::Tagmsg => "TAGMSG",
        }
    }

    /// The lowercase token stored in the `messages.kind` column.
    pub fn db(self) -> &'static str {
        match self {
            HistoryKind::Privmsg => "privmsg",
            HistoryKind::Notice => "notice",
            HistoryKind::Tagmsg => "tagmsg",
        }
    }

    /// Parse the stored [`HistoryKind::db`] token; `None` for anything else,
    /// so a corrupt or unexpected `kind` column surfaces rather than defaulting.
    pub fn from_db(token: &str) -> Option<Self> {
        match token {
            "privmsg" => Some(HistoryKind::Privmsg),
            "notice" => Some(HistoryKind::Notice),
            "tagmsg" => Some(HistoryKind::Tagmsg),
            _ => None,
        }
    }
}

/// Which stored history entries a reader can be sent. A stored `TAGMSG` is
/// nothing but tags, so a reader without `message-tags` — and the REST API,
/// which serves text — cannot receive one at all. A page is cut in the
/// reader's scope, so its `LIMIT` counts only entries it can be sent: excluding
/// them after the cut would return fewer than asked for, which reads as the
/// end of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryScope {
    /// PRIVMSG and NOTICE only.
    Text,
    /// Everything, `TAGMSG` included.
    TextAndTags,
}

impl HistoryScope {
    pub fn admits(self, kind: HistoryKind) -> bool {
        self == HistoryScope::TextAndTags || kind != HistoryKind::Tagmsg
    }
}

impl From<HistoryResponseCaps> for HistoryScope {
    fn from(caps: HistoryResponseCaps) -> Self {
        if caps.message_tags {
            HistoryScope::TextAndTags
        } else {
            HistoryScope::Text
        }
    }
}

/// One history entry, as the hot ring keeps it and the database returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub msgid: String,
    /// Unix **milliseconds** (see `Config::clock`): CHATHISTORY pages by this,
    /// so second granularity would make same-second messages unorderable.
    pub ts: e6irc_proto::time::Millis,
    pub sender_prefix: String,
    /// The sender's account at send time (`None` if unauthenticated). Used to
    /// re-address a replayed DM row by *identity* — which survives a nick
    /// change — instead of by the sender's historical nick, so a requester who
    /// renamed mid-conversation still sees their own lines addressed to the
    /// correspondent, not to themselves.
    pub sender_account: Option<String>,
    pub kind: HistoryKind,
    /// The text; empty for a `TAGMSG`, and for a multiline message, whose text
    /// is `multiline` alone (held once, not twice: see [`Self::plain_body`]).
    pub body: String,
    /// The sender was a bot (+B) at send time; replay re-emits the `bot` tag.
    pub sender_is_bot: bool,
    /// For a `draft/multiline` message: its lines encoded as one string
    /// (`crate::core::handler::message::encode_multiline`), so the whole message
    /// is one history entry with one msgid — not one row per line with fresh,
    /// never-delivered msgids. `None` for an ordinary single-line message;
    /// `body` then holds the text. On replay a `Some` reconstructs the multiline
    /// batch (or flattens) reusing the single msgid, as live delivery did.
    pub multiline: Option<String>,
    /// The client-only tags the message was relayed with, escaped and
    /// `;`-joined as on the wire (empty for none), less the ephemeral ones
    /// (`crate::sanitize::history_client_tags`). Replayed to a reader that
    /// negotiated `message-tags`, as live delivery sent them, so a reply or a
    /// reaction keeps what it refers to.
    pub client_tags: String,
}

impl HistoryRow {
    /// The text as one plain line: `body`, or a multiline message's lines
    /// joined with spaces — what the database's `body` column and the REST
    /// history carry.
    pub(crate) fn plain_body(&self) -> std::borrow::Cow<'_, str> {
        match &self.multiline {
            Some(encoded) => {
                std::borrow::Cow::Owned(handler::message::multiline_plain_text(encoded))
            }
            None => std::borrow::Cow::Borrowed(&self.body),
        }
    }
}

/// Capability state that determines the wire shape of a CHATHISTORY reply.
///
/// Database-backed replies are asynchronous, so this is captured when the
/// command is accepted rather than re-reading mutable session capabilities
/// when the rows eventually arrive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryResponseCaps {
    pub batch: bool,
    pub message_tags: bool,
    pub server_time: bool,
    pub account_tag: bool,
    pub multiline: bool,
}

impl HistoryResponseCaps {
    /// [`state::event_tags`] for a reader with these capabilities.
    pub(crate) fn event_tags(
        self,
        ts: e6irc_proto::time::Millis,
        msgid: Option<&str>,
        account: Option<&str>,
        bot: bool,
    ) -> Vec<String> {
        let caps = state::Caps {
            message_tags: self.message_tags,
            server_time: self.server_time,
            account_tag: self.account_tag,
            ..state::Caps::default()
        };
        state::event_tags(caps, ts, msgid, account, bot)
    }
}

impl From<state::Caps> for HistoryResponseCaps {
    fn from(caps: state::Caps) -> Self {
        Self {
            batch: caps.batch,
            message_tags: caps.message_tags,
            server_time: caps.server_time,
            account_tag: caps.account_tag,
            multiline: caps.multiline,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbReply {
    PasswordVerified {
        account: String,
        origin: CredentialOrigin,
    },
    PasswordRejected {
        origin: CredentialOrigin,
    },
    /// The account name has spent its password attempts for the current
    /// window; nothing was verified.
    PasswordThrottled {
        origin: CredentialOrigin,
        retry_after: crate::db::LoginRetryAfter,
    },
    AccountCreated {
        account: String,
        origin: AccountOrigin,
    },
    AccountExists {
        origin: AccountOrigin,
    },
    /// A NickServ/REGISTER-command account registration could not be persisted
    /// (DB down/errored). Carries the origin so the client gets the loud
    /// failure appropriate to how it asked, never a silent hang.
    AccountRegisterUnavailable {
        origin: AccountOrigin,
    },
    /// A read marker was durably stored. `marker_ms` is the value PostgreSQL
    /// returned after applying the monotonic `GREATEST`, not merely the value
    /// the client requested.
    ReadMarkerStored {
        account: String,
        /// Casefolded target used by the hot map.
        target: String,
        /// Validated target spelling from the command, for the reply.
        display: String,
        marker_ms: e6irc_proto::time::Millis,
        label: Option<String>,
    },
    /// A read-marker write failed. The account/target pair is carried so the
    /// core can release its pending-target reservation even if the requesting
    /// connection vanished during the database round trip.
    ReadMarkerUnavailable {
        account: String,
        target: String,
        display: String,
        label: Option<String>,
    },
    /// The write named a new target and the account already holds the
    /// database's read-marker cap — counted across every shard, which the
    /// per-shard hot mirror cannot see. Refused like the in-memory cap.
    ReadMarkerLimitReached {
        account: String,
        target: String,
        display: String,
        label: Option<String>,
    },
    /// A credential verification could not be attempted — the database is
    /// unreachable or errored. Carries the origin so the client gets the loud
    /// failure appropriate to how it asked (SASL FAIL vs NickServ notice),
    /// never a silent hang, and never a verdict routed to the wrong command.
    Unavailable {
        origin: CredentialOrigin,
    },
    /// The verdict of a NickServ GROUP. `None` means the store failed.
    NickGroup {
        account: String,
        nick: String,
        outcome: Option<crate::db::NickGroupOutcome>,
        label: Option<String>,
    },
    /// The verdict of a NickServ UNGROUP: whether the account held the nick,
    /// or `None` when the store failed.
    NickUngroup {
        account: String,
        nick: String,
        removed: Option<bool>,
        label: Option<String>,
    },
    /// The verdict of a NickServ SET ENFORCE. `None` means the store failed.
    NickEnforce {
        account: String,
        enforce: bool,
        outcome: Option<crate::db::NickEnforceChange>,
        label: Option<String>,
    },
    /// The answer to a NickServ INFO: the account, `Ok(None)` when no account
    /// holds the name, `Err` when the store failed.
    AccountInfo {
        target: String,
        info: Result<Option<crate::db::NickServAccountInfo>, ()>,
        label: Option<String>,
    },
    /// The verdict of a NickServ DROP.
    AccountDrop {
        account: String,
        outcome: AccountDropOutcome,
        label: Option<String>,
    },
}

/// What became of a NickServ DROP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountDropOutcome {
    /// The account and everything it owned are gone; its name is retired.
    Dropped,
    /// The password did not verify.
    Rejected,
    /// The account name has spent its password attempts for now.
    Throttled(crate::db::LoginRetryAfter),
    /// The deletion was refused, for the reason given (a founded channel with
    /// no successor, or the last administrator).
    Refused(String),
    /// A store or a live component failed; nothing was deleted.
    Unavailable,
}

/// One wire line out to a connection I/O task, CRLF included. Socket
/// close is signaled by dropping the session's queue Sender, never by
/// an in-band event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output(pub Bytes);

/// The core's end of one connection's send queue: bounded in the bytes its
/// lines hold (`sendq_bytes`), like Solanum's class `sendq`, never in their
/// number — a count lets a few maximum-size lines pin as much as a thousand
/// short ones. Made only by [`send_queue`], so no connection can be given a
/// queue measured in anything else.
#[derive(Debug)]
pub struct SendQueue(pub(crate) Sender<Output>);

/// A connection's send queue of `bytes` bytes (named `name` in diagnostics):
/// the core's end, and the receiver its writer drains.
pub fn send_queue(name: &'static str, bytes: usize) -> (SendQueue, Receiver<Output>) {
    let (tx, rx) = e6irc_queue::weighted_queue(
        e6irc_queue::Config {
            name,
            capacity: bytes,
            policy: e6irc_queue::Policy::Fifo,
        },
        |output: &Output| output.0.len(),
    );
    (SendQueue(tx), rx)
}

/// Output withheld behind a deferred reply (see `Session::deferred_replies`),
/// with the bytes it holds counted where lines enter it, so the bound on it is
/// the send queue's own, in the send queue's unit.
#[derive(Debug, Default)]
pub(crate) struct HeldOutput {
    lines: Vec<Bytes>,
    bytes: usize,
}

impl HeldOutput {
    /// Hold `line` if the held output stays within `sendq_bytes`; `false`
    /// (and nothing held) when it would not, which is a SendQ kill.
    pub(crate) fn hold(&mut self, line: Bytes, sendq_bytes: usize) -> bool {
        if self.bytes + line.len() > sendq_bytes {
            return false;
        }
        self.bytes += line.len();
        self.lines.push(line);
        true
    }
}

impl IntoIterator for HeldOutput {
    type Item = Bytes;
    type IntoIter = std::vec::IntoIter<Bytes>;

    fn into_iter(self) -> Self::IntoIter {
        self.lines.into_iter()
    }
}

/// A wire line with no embedded CR, LF, or NUL.
///
/// [`deliver`] accepts only this type. [`WireLine::sanitized`] preserves the
/// trailing CRLF and replaces unsafe content bytes with spaces.
pub(crate) struct WireLine(Bytes);

impl WireLine {
    pub(crate) fn sanitized(bytes: Bytes) -> Self {
        let end = bytes.len() - if bytes.ends_with(b"\r\n") { 2 } else { 0 };
        if !bytes[..end].iter().any(|&b| matches!(b, b'\r' | b'\n' | 0)) {
            return WireLine(bytes);
        }
        let mut out = bytes.to_vec();
        for b in &mut out[..end] {
            if matches!(*b, b'\r' | b'\n' | 0) {
                *b = b' ';
            }
        }
        WireLine(Bytes::from(out))
    }
}

pub struct Core {
    state: ServerState,
    shard: CoreShardId,
    shards: CoreShardCount,
    /// Events for other shards, waiting for the worker to send them.
    outbound: Vec<Routed>,
    next_sequence: u64,
    reported_gauges: (usize, usize, usize),
}

/// Work a core hands to its worker for OTHER shards. An effect addressed to
/// the emitting shard never appears here: [`Core::handle`] runs it inline, so
/// a worker is never asked to push into the queue only it can drain.
pub(crate) enum CoreEffect {
    /// A typed event for another core owner. Boxed: an `Input` is several
    /// times the size of any broadcast here.
    Input(Box<Input>),
    BroadcastServerBan {
        mutation: ServerBanMutation,
    },
    BroadcastAccountSuspension {
        account: String,
        suspended: bool,
        reason: String,
        actor: String,
    },
    BroadcastReadMarker {
        account: String,
        target: String,
        display: String,
        marker_ms: e6irc_proto::time::Millis,
    },
    BroadcastAdminConnectionList {
        request_id: u64,
        query: LiveConnectionQuery,
    },
    /// An unauthenticated (`~nick`) identity left; every shard frees the
    /// conversations it kept with it.
    BroadcastIdentityReleased {
        identity: String,
    },
    Delivery {
        owner: SessionOwner,
        line: Bytes,
    },
}

impl CoreEffect {
    pub(crate) fn input(input: Input) -> Self {
        Self::Input(Box::new(input))
    }

    /// One shard's copy of a broadcast, and whether the emitting shard needs a
    /// copy too (it does unless the code that emitted it already applied it
    /// there). `None` for an effect that has a single owner.
    fn broadcast_copy(&self) -> Option<(Input, bool)> {
        Some(match self {
            CoreEffect::Input(_) | CoreEffect::Delivery { .. } => return None,
            CoreEffect::BroadcastAdminConnectionList { request_id, query } => (
                Input::AdminConnectionList {
                    request_id: *request_id,
                    query: query.clone(),
                },
                true,
            ),
            CoreEffect::BroadcastIdentityReleased { identity } => (
                Input::UnauthenticatedIdentityReleased {
                    identity: identity.clone(),
                },
                false,
            ),
            CoreEffect::BroadcastServerBan { mutation } => (
                Input::ServerBanApplied {
                    mutation: mutation.clone(),
                },
                false,
            ),
            CoreEffect::BroadcastAccountSuspension {
                account,
                suspended,
                reason,
                actor,
            } => (
                Input::AccountSuspensionApplied {
                    account: account.clone(),
                    suspended: *suspended,
                    reason: reason.clone(),
                    actor: actor.clone(),
                },
                false,
            ),
            CoreEffect::BroadcastReadMarker {
                account,
                target,
                display,
                marker_ms,
            } => (
                Input::ReadMarkerApplied {
                    account: account.clone(),
                    target: target.clone(),
                    display: display.clone(),
                    marker_ms: *marker_ms,
                },
                false,
            ),
        })
    }
}

/// One event with the other shard it is for.
pub(crate) struct Routed {
    pub to: CoreShardId,
    pub input: Input,
}

/// Why a core worker's loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreWorkerExit {
    /// Shutdown was requested and every shard's cross-shard traffic has drained.
    Stopped,
    /// Every producer into this worker's queue is gone.
    IngressClosed,
    /// Another shard's queue closed while this server was still serving.
    PeerClosed { destination: CoreShardId },
    /// Events for another shard piled up past [`CROSS_SHARD_BACKLOG_LIMIT`]:
    /// that shard has stopped taking them. The worker stops rather than grow
    /// without bound or silently drop what clients were promised.
    Backlogged {
        destination: CoreShardId,
        pending: usize,
    },
}

/// Most events one worker may hold for other shards whose queues are full.
///
/// A worker never waits on another worker's full queue: two workers each
/// waiting for room in the other's queue, neither reading its own, is a
/// deadlock ordinary channel traffic can produce. It keeps such events itself,
/// in order, and carries on reading its own queue — which is what makes room
/// in it for the other worker. That backlog needs a bound, because one client
/// line can fan out into thousands of deliveries. It matches the ingress
/// queues' capacity: a shard with a full queue *and* this much waiting behind
/// it has stopped, and [`CoreWorkerExit::Backlogged`] says so loudly.
pub(crate) const CROSS_SHARD_BACKLOG_LIMIT: usize = 65_536;

/// How long a worker with a LIST or WHO reply being paced out waits, idle,
/// before giving it another turn: at the default send queue, half of it — 512
/// rows — per turn.
pub(crate) const PACE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// One core and the only queue allowed to drive its state transitions.
pub(crate) struct CoreWorker {
    core: Core,
    receiver: Receiver<Input>,
    ingress: CoreIngress,
    /// Events for each other shard, oldest first, that did not fit its queue.
    backlog: Vec<VecDeque<Input>>,
    /// This worker has handled [`Input::Shutdown`]: it takes no more input
    /// from outside, and stops once the workers' own traffic has drained.
    stopping: bool,
}

impl CoreWorker {
    pub(crate) fn new(core: Core, receiver: Receiver<Input>, ingress: CoreIngress) -> Self {
        let backlog = (0..ingress.shards.len()).map(|_| VecDeque::new()).collect();
        Self {
            core,
            receiver,
            ingress,
            backlog,
            stopping: false,
        }
    }

    pub(crate) async fn run(mut self) -> CoreWorkerExit {
        let traffic = self.ingress.traffic.clone();
        let shards = self.ingress.shards.clone();
        loop {
            if let Err(exit) = self.send_backlog() {
                return exit;
            }
            // Armed before the check, so a change between the check and the
            // wait below still wakes it.
            let changed = traffic.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.stopping && traffic.drained(shards.len()) {
                return CoreWorkerExit::Stopped;
            }
            let blocked = self.backlog.iter().position(|events| !events.is_empty());
            let room = async {
                match blocked {
                    Some(destination) => shards[destination].room().await,
                    None => std::future::pending().await,
                }
            };
            // A LIST or WHO reply being paced out needs a turn once its
            // client has read some of it, even if nothing else happens
            // meanwhile.
            let pacing = !self.core.state.pacing.is_empty();
            let pace = tokio::time::sleep(PACE_INTERVAL);
            let mut paced = false;
            let popped = tokio::select! {
                envelope = self.receiver.pop() => Some(envelope),
                () = room => None,
                () = &mut changed, if self.stopping => None,
                () = pace, if pacing => {
                    paced = true;
                    None
                }
            };
            match popped {
                Some(Some(envelope)) => self.accept(envelope),
                Some(None) => return CoreWorkerExit::IngressClosed,
                None => {}
            }
            if paced {
                // Through the queue like any event; a full queue already
                // holds events enough to pace on.
                drop(shards[self.core.shard.0].try_push(Input::PaceReplies));
            }
        }
    }

    fn accept(&mut self, envelope: e6irc_queue::Envelope<Input>) {
        let (input, from_shard) = match envelope.payload {
            Input::FromShard(input) => (*input, true),
            input => (input, false),
        };
        // Once stopping, only the workers' own traffic is still served: it is
        // finite, and the others rely on it being handled. Input from outside
        // (client lines, database replies, ticks) is refused from here on, as
        // it was when a worker stopped the moment it saw the shutdown.
        if self.stopping && !from_shard {
            self.core.skip_scheduled(envelope.seq);
            return;
        }
        let shutdown = matches!(input, Input::Shutdown);
        self.core.handle_scheduled(ScheduledInput {
            shard: self.core.shard,
            sequence: envelope.seq,
            input,
        });
        for Routed { to, input } in self.core.take_effects() {
            self.ingress.traffic.sent();
            self.backlog[to.0].push_back(Input::FromShard(Box::new(input)));
        }
        // Only now: what this event caused is counted, so the count cannot
        // touch zero while its consequences are still unsent.
        if from_shard {
            self.ingress.traffic.settled();
        }
        if shutdown {
            self.stopping = true;
            self.ingress.traffic.worker_stopping();
        }
    }

    /// Offer each shard its waiting events, in order, until its queue is full.
    fn send_backlog(&mut self) -> Result<(), CoreWorkerExit> {
        for (destination, events) in self.backlog.iter_mut().enumerate() {
            while let Some(input) = events.pop_front() {
                match self.ingress.shards[destination].try_push(input) {
                    Ok(_) => {}
                    Err(PushError::Full(input)) => {
                        events.push_front(input);
                        break;
                    }
                    // A shard that is gone cannot be owed anything. While
                    // stopping that is just the order workers left in; while
                    // serving, its state is lost and so is this server.
                    Err(PushError::Closed(_)) => {
                        self.ingress.traffic.settled();
                        if !self.stopping {
                            return Err(CoreWorkerExit::PeerClosed {
                                destination: CoreShardId(destination),
                            });
                        }
                    }
                }
            }
            if events.len() > CROSS_SHARD_BACKLOG_LIMIT {
                return Err(CoreWorkerExit::Backlogged {
                    destination: CoreShardId(destination),
                    pending: events.len(),
                });
            }
        }
        Ok(())
    }
}

impl Core {
    pub fn new(config: CoreConfig, db_tx: Sender<DbRequest>) -> Self {
        Self::with_telemetry(config, db_tx, Arc::new(Telemetry::new()))
    }

    pub(crate) fn with_telemetry(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        Self::with_telemetry_with_directories(config, db_tx, telemetry, CoreDirectories::default())
    }

    pub(crate) fn with_telemetry_with_directories(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
        directories: CoreDirectories,
    ) -> Self {
        Self::with_telemetry_on_shard_with_directories(
            config,
            db_tx,
            telemetry,
            CoreShardId(0),
            CoreShardCount::single(),
            directories,
        )
    }

    fn with_telemetry_on_shard_with_directories(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
        shard: CoreShardId,
        shards: CoreShardCount,
        directories: CoreDirectories,
    ) -> Self {
        telemetry.expect_core_shards(shards.len());
        Self {
            state: ServerState::new(shard, shards, config, db_tx, telemetry, directories),
            shard,
            shards,
            outbound: Vec::new(),
            next_sequence: 0,
            reported_gauges: (0, 0, 0),
        }
    }

    pub(crate) fn on_shard(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
        shard: CoreShardId,
        shards: CoreShardCount,
        directories: CoreDirectories,
    ) -> Self {
        Self::with_telemetry_on_shard_with_directories(
            config,
            db_tx,
            telemetry,
            shard,
            shards,
            directories,
        )
    }

    /// Process the next event delivered to this worker.
    pub(crate) fn handle_scheduled(&mut self, event: ScheduledInput) {
        debug_assert_eq!(event.shard, self.shard);
        debug_assert_eq!(event.sequence, self.next_sequence);
        self.next_sequence = event
            .sequence
            .checked_add(1)
            .expect("core queue sequence exhausted");
        self.handle(event.input);
    }

    /// What the events handled so far caused on other shards.
    fn take_effects(&mut self) -> Vec<Routed> {
        std::mem::take(&mut self.outbound)
    }

    /// An event this worker took from its queue without handling it.
    fn skip_scheduled(&mut self, sequence: u64) {
        debug_assert_eq!(sequence, self.next_sequence);
        self.next_sequence = sequence
            .checked_add(1)
            .expect("core queue sequence exhausted");
    }

    /// Keep what this shard must handle itself; address the rest to its
    /// shard. A broadcast is one copy per shard.
    fn sort_effect(&mut self, effect: CoreEffect, local: &mut VecDeque<Input>) {
        if let Some((_, here)) = effect.broadcast_copy() {
            for shard in (0..self.shards.len()).map(CoreShardId) {
                let (input, _) = effect.broadcast_copy().expect("still a broadcast");
                if shard != self.shard {
                    self.outbound.push(Routed { to: shard, input });
                } else if here {
                    local.push_back(input);
                }
            }
            return;
        }
        let input = match effect {
            CoreEffect::Input(input) => *input,
            CoreEffect::Delivery { owner, line } => Input::Delivery {
                conn: owner.conn(),
                line,
            },
            _ => unreachable!("broadcasts are handled above"),
        };
        let to = input.owner_shard(self.shards);
        if to == self.shard {
            local.push_back(input);
        } else {
            self.outbound.push(Routed { to, input });
        }
    }

    /// Seed the hot channel-ownership map from persisted rows before the
    /// worker loop starts (see [`ServerState::preload_founders`]).
    pub fn preload_founders(&mut self, rows: Vec<(String, String)>) {
        self.state.preload_founders(rows);
    }

    /// Seed each registered channel's successor, after
    /// [`Self::preload_founders`] (see [`ServerState::preload_successors`]).
    pub fn preload_successors(&mut self, rows: Vec<(String, String)>) {
        self.state.preload_successors(rows);
    }

    /// Seed the retained-topic map from persisted rows before the worker
    /// loop starts (see [`ServerState::preload_topics`]).
    pub fn preload_topics(&mut self, rows: Vec<(String, String, String, u64)>) {
        self.state.preload_topics(rows);
    }

    /// Seed the KEEPTOPIC-off set from persisted folded channel names.
    pub fn preload_keeptopic_off(&mut self, names: Vec<String>) {
        self.state.preload_keeptopic_off(names);
    }

    /// Seed the mode-lock map from persisted `(name_folded, spec)` rows.
    pub fn preload_mlock(&mut self, rows: Vec<(String, String)>) -> Result<(), String> {
        self.state.preload_mlock(rows)
    }

    /// Seed the channel-access map from persisted rows before the worker
    /// loop starts (see [`ServerState::preload_access`]).
    pub fn preload_access(&mut self, rows: Vec<(String, String, String)>) {
        self.state.preload_access(rows);
    }

    /// Seed server bans from persisted rows before the worker loop starts
    /// (see [`ServerState::preload_server_bans`]).
    pub fn preload_server_bans(
        &mut self,
        rows: Vec<crate::db::PersistedServerBan>,
    ) -> Result<(), String> {
        self.state.preload_server_bans(rows)
    }

    /// Seed the read-marker mirror from persisted rows before the worker loop
    /// starts (see [`ServerState::preload_read_markers`]).
    pub fn preload_read_markers(&mut self, rows: Vec<(String, String, e6irc_proto::time::Millis)>) {
        self.state.preload_read_markers(rows);
    }

    /// Seed the durable suspension deny set before the worker loop starts.
    pub fn preload_suspended_accounts(&mut self, accounts: Vec<String>) {
        self.state.preload_suspended_accounts(accounts);
    }

    /// Seed grouped nicks and nick protection before the worker loop starts
    /// (see [`ServerState::preload_nick_registrations`]).
    pub fn preload_nick_registrations(&mut self, registrations: crate::db::NickRegistrations) {
        self.state
            .preload_nick_registrations(registrations.grouped, registrations.enforced);
    }

    /// Process one event and everything it causes on this shard. All state
    /// transitions happen here, on one thread, in queue order.
    ///
    /// An effect addressed to this shard runs here, before the next queued
    /// event, and is never pushed back through the queue: this worker is the
    /// only task that drains that queue, so awaiting room in it would park the
    /// worker — and every tick and the shutdown flush behind it — forever.
    pub fn handle(&mut self, input: Input) {
        let mut local = VecDeque::from([match input {
            // A core driven directly (tests, fuzzers) is handed what a worker
            // would have unwrapped.
            Input::FromShard(input) => *input,
            input => input,
        }]);
        while let Some(input) = local.pop_front() {
            self.handle_one(input);
            for effect in self.state.take_effects() {
                self.sort_effect(effect, &mut local);
            }
        }
    }

    fn handle_one(&mut self, input: Input) {
        let started = Instant::now();
        let sessions_before = self.state.sessions.len();
        let opened = matches!(input, Input::Open { .. });
        if let Input::Line { line, .. } = &input {
            self.state.telemetry.record_irc_input(line.len());
        }
        if opened {
            self.state.telemetry.record_connection_opened();
        }
        match input {
            Input::FromShard(_) => unreachable!("unwrapped before it is handled"),
            Input::Open {
                conn,
                tx,
                host,
                transport,
            } => self.state.open(conn, tx, host, transport),
            Input::Line { conn, line } => {
                handler::dispatch(&mut self.state, conn, &line);
                // A line is what makes (or unmakes) an IRC operator, whose
                // lines are not metered.
                self.state.sync_flood_exemption(conn);
            }
            Input::OverlongLine { conn } => handler::overlong(&mut self.state, conn),
            Input::Delivery { conn, line } => self.state.send_bytes_uncaptured(conn, line),
            Input::ChannelJoin {
                owner,
                actor,
                name,
                join_key,
                label,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "JOIN reached wrong channel shard"
                );
                handler::channel_join(&mut self.state, actor, &name, join_key.as_deref(), label);
            }
            Input::ChannelJoinResult {
                session,
                requested,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "JOIN result reached wrong session shard"
                );
                handler::channel_join_result(
                    &mut self.state,
                    session.conn(),
                    requested,
                    result,
                    label,
                );
            }
            Input::ChannelPart {
                owner,
                actor,
                name,
                reason,
                label,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "PART reached wrong channel shard"
                );
                handler::channel_part(&mut self.state, actor, &name, reason.as_deref(), label);
            }
            Input::ChannelPartResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "PART result reached wrong session shard"
                );
                handler::channel_part_result(&mut self.state, session.conn(), result, label);
            }
            Input::ChannelQuit { quit } => self.state.quit_channel_member(quit),
            Input::UnauthenticatedIdentityReleased { identity } => {
                self.state.forget_unauthenticated_identity(&identity);
            }
            Input::ChannelMemberVanished { owner, conn } => {
                self.state.remove_vanished_member(&owner, conn);
            }
            Input::SessionAction { session, action } => {
                handler::session_action(&mut self.state, session.conn(), action);
            }
            Input::ChannelUserEvent { report } => self.state.report_user_event(report),
            Input::UserEventPart { part } => self.state.deliver_user_event_part(part),
            Input::ConversationEntry { key, entry, .. } => self.state.push_history(&key, entry),
            Input::ChannelTopic { topic } => {
                assert_eq!(
                    topic.owner().shard(),
                    self.shard,
                    "TOPIC reached wrong channel shard"
                );
                handler::channel_topic(&mut self.state, topic);
            }
            Input::ChannelTopicResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "TOPIC result reached wrong session shard"
                );
                handler::channel_topic_result(&mut self.state, session.conn(), result, label);
            }
            Input::ChannelTopicPersisted {
                owner,
                conn,
                session,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "TOPIC verdict reached wrong channel shard"
                );
                handler::channel_topic_persisted(&mut self.state, conn, session, result);
            }
            Input::ChannelServicePersisted {
                owner,
                session,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "ChanServ verdict reached wrong channel shard"
                );
                handler::services::channel_service_persisted(&mut self.state, session, result);
            }
            Input::ChannelServiceResult { session, result } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "ChanServ verdict reached wrong session shard"
                );
                handler::services::channel_service_result(&mut self.state, session.conn(), result);
            }
            Input::ChannelCommand { command } => {
                assert_eq!(
                    command.owner().shard(),
                    self.shard,
                    "channel command reached wrong channel shard"
                );
                handler::channel_command(&mut self.state, command);
            }
            Input::ChannelCommandResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "channel command result reached wrong session shard"
                );
                handler::channel_command_result(&mut self.state, session.conn(), result, label);
            }
            Input::ChannelRegistrationPersisted {
                owner,
                session,
                channel,
                founder_account,
                topic,
                label,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "registration reached wrong channel shard"
                );
                handler::services::channel_registration_persisted(
                    &mut self.state,
                    session,
                    channel,
                    founder_account,
                    topic,
                    label,
                    result,
                );
            }
            Input::ChannelList { request } => {
                handler::channel_list(&mut self.state, request);
            }
            Input::ChannelListResult { result } => {
                assert_eq!(
                    result.session.shard(),
                    self.shard,
                    "LIST result reached wrong session shard"
                );
                handler::channel_list_result(&mut self.state, result);
            }
            Input::ChannelSessionEvent { session, event } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "channel event reached wrong session shard"
                );
                handler::channel_session_event(&mut self.state, session.conn(), event);
            }
            Input::ChannelMemberUpdate { update } => {
                self.state.apply_channel_member_update(update);
            }
            Input::SessionChannelRemoved { session, key } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "session update reached wrong shard"
                );
                self.state.remove_session_channel(session.conn(), &key);
            }
            Input::ChannelKick { kick } => {
                assert_eq!(
                    kick.owner().shard(),
                    self.shard,
                    "KICK reached wrong channel shard"
                );
                handler::channel_kick(&mut self.state, kick);
            }
            Input::ChannelKickResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "KICK result reached wrong session shard"
                );
                handler::channel_kick_result(&mut self.state, session.conn(), result, label);
            }
            Input::ChannelMessage { message } => {
                assert_eq!(
                    message.owner().shard(),
                    self.shard,
                    "message reached wrong channel shard"
                );
                handler::channel_message(&mut self.state, message);
            }
            Input::ChannelMessageResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "message result reached wrong session shard"
                );
                handler::channel_message_result(&mut self.state, session.conn(), result, label);
            }
            Input::ChannelMultiline { message } => {
                assert_eq!(
                    message.owner().shard(),
                    self.shard,
                    "multiline reached wrong channel shard"
                );
                handler::channel_multiline(&mut self.state, message);
            }
            Input::ChannelMultilineResult { session, result } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "multiline result reached wrong session shard"
                );
                handler::channel_multiline_result(&mut self.state, session.conn(), result);
            }
            Input::ChannelTagmsg { tagmsg } => {
                assert_eq!(
                    tagmsg.owner().shard(),
                    self.shard,
                    "TAGMSG reached wrong channel shard"
                );
                handler::channel_tagmsg(&mut self.state, tagmsg);
            }
            Input::ChannelTagmsgResult {
                session,
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "TAGMSG result reached wrong session shard"
                );
                handler::channel_tagmsg_result(&mut self.state, session.conn(), result, label);
            }
            Input::Closed { conn, reason } => self.state.close(conn, &reason),
            // Its whole work is the pacing every event ends with, below.
            Input::PaceReplies => {}
            Input::Tick { now } => {
                handler::reap_idle(&mut self.state, now);
                handler::services::enforce_nick_protection(&mut self.state, now);
                handler::oper::expire_server_bans(&mut self.state);
            }
            Input::ReadMarkersExpired { markers } => self.state.expire_read_markers(&markers),
            Input::AccountDeleted {
                account,
                successions,
            } => self.state.forget_deleted_account(&account, &successions),
            Input::DbReply { conn, reply } => handler::db_reply(&mut self.state, conn, reply),
            Input::HistoryPage {
                conn,
                display,
                batch_ref,
                caps,
                rows,
                label,
            } => {
                // The batch is what the connection's held output is waiting
                // behind, so it is emitted through the hold, which is then
                // released in the order the client issued its commands.
                self.state.history_request_finished(conn);
                self.state.emit_deferred(conn, |state| {
                    handler::history_page(
                        state,
                        conn,
                        &display,
                        &batch_ref,
                        caps,
                        rows,
                        label.as_deref(),
                    );
                });
            }
            Input::TargetsPage {
                conn,
                batch_ref,
                caps,
                targets,
                label,
            } => {
                self.state.history_request_finished(conn);
                self.state.emit_deferred(conn, |state| {
                    handler::targets_page(state, conn, &batch_ref, caps, targets, label.as_deref());
                });
            }
            // Notify clients; the worker loop breaks right after this event
            // (see `net::core_worker`), which drops the `Core` and closes the
            // DB write path so the buffered history flushes.
            Input::Shutdown => self.state.broadcast_shutdown("Server shutting down"),
            Input::Admin { req, reply } => {
                if let Some(channel) = req.channel() {
                    let owner = self.state.channel_owner(channel);
                    if owner.shard() != self.shard {
                        self.state.route_input(Input::Admin { req, reply });
                        return;
                    }
                }
                handler::admin::handle(&mut self.state, req, reply);
            }
            Input::ChannelDropResult {
                owner,
                channel,
                requester,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "DROP verdict reached wrong channel shard"
                );
                handler::services::channel_drop_result(&mut self.state, channel, requester, result);
            }
            Input::ChannelDropReply {
                session,
                display,
                label,
                result,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "DROP reply reached wrong session shard"
                );
                handler::services::channel_drop_reply(
                    &mut self.state,
                    session,
                    display,
                    label,
                    result,
                );
            }
            Input::ServerBanResult {
                mutation,
                requester,
                result,
            } => {
                match handler::oper::server_ban_result(&mut self.state, mutation, requester, result)
                {
                    handler::oper::ServerBanVerdict::Nothing => {}
                    handler::oper::ServerBanVerdict::Committed(mutation) => {
                        handler::oper::commit_server_ban(&mut self.state, mutation);
                    }
                    handler::oper::ServerBanVerdict::Unstored(mutation) => {
                        handler::oper::reconcile_server_ban_everywhere(&mut self.state, mutation);
                    }
                }
            }
            Input::ServerBanApplied { mutation } => {
                handler::oper::apply_committed_server_ban(&mut self.state, mutation);
            }
            Input::AccountSuspensionApplied {
                account,
                suspended,
                reason,
                actor,
            } => {
                handler::admin::apply_account_suspension(
                    &mut self.state,
                    &account,
                    suspended,
                    &reason,
                    &actor,
                );
            }
            Input::ReadMarkerApplied {
                account,
                target,
                display,
                marker_ms,
            } => handler::apply_stored_marker(
                &mut self.state,
                &account,
                &target,
                &display,
                marker_ms,
            ),
            Input::AdminConnectionList { request_id, query } => {
                let entries = handler::admin::connection_list_entries(&self.state, &query);
                self.state.route_input(Input::AdminConnectionListResult {
                    request_id,
                    entries,
                });
            }
            Input::AdminConnectionListResult {
                request_id,
                entries,
            } => handler::admin::connection_list_result(&mut self.state, request_id, entries),
            Input::ChannelControlResult {
                owner,
                request_id,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "channel control reached wrong shard"
                );
                handler::admin::channel_control_result(&mut self.state, request_id, result);
            }
            Input::OwnedChannelRegistrationResult {
                owner,
                request_id,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "channel registration reached wrong shard"
                );
                handler::admin::owned_channel_registration_result(
                    &mut self.state,
                    request_id,
                    result,
                );
            }
        }
        // Any event is a chance for a paced LIST or WHO reply to use the room
        // its client's send queue has made since.
        handler::pace_replies(&mut self.state);
        // Sweep connections whose SendQ overflowed while handling the
        // event: the slow client dies (may cascade if its QUIT broadcast
        // overflows someone else's queue — hence the loop). Dropping the
        // session drops its queue Sender, which is what closes the
        // socket: write_loop drains, flushes, and shuts down on None.
        while let Some(conn) = self.state.doomed.pop() {
            if self.state.sessions.contains_key(&conn) {
                self.state.telemetry.record_sendq_kill();
            }
            self.state.close(conn, "SendQ exceeded");
        }
        self.state.publish_changed_channels();
        self.state.publish_census();
        self.state.publish_changed_sessions();
        let sessions_after = self.state.sessions.len();
        self.state.telemetry.record_connections_closed(
            (sessions_before + usize::from(opened)).saturating_sub(sessions_after),
        );
        let gauges = (
            sessions_after,
            self.state.sessions.registered_len(),
            self.state.channels.len(),
        );
        self.state
            .telemetry
            .adjust_core_gauges(self.shard.0, self.reported_gauges, gauges);
        self.reported_gauges = gauges;
        self.state
            .telemetry
            .observe_latency(LatencyKind::Core, started.elapsed());
    }
}

/// The one way output reaches a connection: its send queue, and whether the
/// connection has been told goodbye.
///
/// Once the closing `ERROR` has been written nothing more may follow it: a line
/// after `ERROR :Closing Link` is something a strict client or a test harness
/// can trip on. A session usually disappears in the same event that says
/// goodbye, but not at shutdown — shutdown is a drain, and a shard that has
/// sent its clients the `ERROR` keeps serving what other shards send it until
/// they have all stopped. The marker lives here, on the handle every path must
/// use, so no delivery site has to remember it.
pub(crate) struct SessionOutput {
    tx: SendQueue,
    said_goodbye: bool,
}

/// What became of a line offered to a [`SessionOutput`].
pub(crate) enum Written {
    Queued,
    /// Discarded: the connection's closing `ERROR` has already been written.
    AfterGoodbye,
}

impl SessionOutput {
    pub(crate) fn new(tx: SendQueue) -> Self {
        Self {
            tx,
            said_goodbye: false,
        }
    }

    /// Queue one line. A full send queue means the client is too slow and the
    /// connection must die — the classic SendQ-exceeded kill. Never silently
    /// dropped.
    pub(crate) fn write(&self, line: WireLine) -> Result<Written, SendqExceeded> {
        if self.said_goodbye {
            return Ok(Written::AfterGoodbye);
        }
        match self.tx.0.try_push(Output(line.0)) {
            Ok(_) => Ok(Written::Queued),
            Err(PushError::Full(_)) => Err(SendqExceeded),
            // Receiver gone: the I/O task is already dead. On the common
            // reader-first close a `Closed{conn}` event is already in flight to
            // us. On a writer-first close (write half RSTs while the read half
            // hangs) there is no such event and outbound lines are dropped for
            // now — but the liveness reaper PINGs the idle session and reaps it
            // once the PONG deadline passes, so this can't leave a permanent
            // zombie.
            Err(PushError::Closed(_)) => Ok(Written::Queued),
        }
    }

    /// How many more bytes the queue takes before it is half full: the most a
    /// paced reply (a LIST, a long WHO) may occupy, leaving the other half for
    /// whatever else the connection is sent meanwhile. Solanum's SAFELIST
    /// bound. A paced reply sends while any room is left, so it may pass the
    /// half by at most the one line that crossed it.
    pub(crate) fn paced_room(&self) -> usize {
        self.tx
            .0
            .capacity()
            .div_ceil(2)
            .saturating_sub(self.tx.0.depth())
    }

    /// Queue the connection's closing line; nothing is written after it.
    /// Best-effort: a queue too full for it is a connection already lost.
    pub(crate) fn write_goodbye(&mut self, line: WireLine) {
        drop(self.write(line));
        self.said_goodbye = true;
    }
}

pub(crate) struct SendqExceeded;

#[cfg(test)]
mod wire_line_tests {
    use super::{Bytes, WireLine};

    #[test]
    fn sanitized_neutralizes_injection_and_keeps_terminator() {
        // Embedded CR/LF in the content (a forged second line) become spaces;
        // the single trailing CRLF terminator is preserved.
        let injected = Bytes::from(&b"PRIVMSG #c :hi\r\nQUIT :forged\r\n"[..]);
        assert_eq!(
            &WireLine::sanitized(injected).0[..],
            &b"PRIVMSG #c :hi  QUIT :forged\r\n"[..]
        );
        // An embedded NUL becomes a space too.
        assert_eq!(
            &WireLine::sanitized(Bytes::from(&b"a\0b\r\n"[..])).0[..],
            b"a b\r\n"
        );
        // A clean line is returned unchanged (fast path).
        let clean = Bytes::from(&b"PING :token\r\n"[..]);
        assert_eq!(WireLine::sanitized(clean.clone()).0, clean);
    }
}

#[cfg(test)]
mod connection_id_allocator_tests {
    use std::num::NonZeroU64;

    use super::ConnectionIdAllocator;

    #[test]
    fn allocation_is_ordered_and_refuses_to_wrap() {
        let allocator =
            ConnectionIdAllocator::new(NonZeroU64::new(7).expect("non-zero test start"));
        assert_eq!(allocator.allocate().expect("first identifier").0, 7);
        assert_eq!(allocator.allocate().expect("second identifier").0, 8);

        let exhausted =
            ConnectionIdAllocator::new(NonZeroU64::new(u64::MAX - 1).expect("non-zero"));
        assert_eq!(
            exhausted.allocate().expect("last identifier").0,
            u64::MAX - 1
        );
        assert!(exhausted.allocate().is_err());
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::{
        ConnId, ConnectionTransport, Core, CoreConfig, CoreDirectories, CoreIngress, CoreScheduler,
        CoreShardCount, CoreShardId, CoreTraceStep, CoreWorker, Input, Output, ReplayError,
        SessionOwner,
    };
    use crate::core::state::{
        Caps, ChanModes, Channel, ChannelActor, ChannelCommand, ChannelCommandOperation,
        ChannelMemberProfile, MemberIdentity, MemberModes, Recipient,
    };
    use bytes::Bytes;
    use e6irc_queue::{Config, Envelope, Policy, Receiver, Sender, queue};
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::time::Duration;

    fn wall_clock() -> e6irc_proto::time::Millis {
        e6irc_proto::time::Millis::from_millis(0)
    }

    fn mono_clock() -> e6irc_proto::time::MonoMillis {
        e6irc_proto::time::MonoMillis::from_millis(0)
    }

    fn core_config() -> CoreConfig {
        CoreConfig {
            server_name: "irc.test".into(),
            network_name: "test".into(),
            description: "test".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq_bytes: 512,
            motd: Vec::new(),
            nicklen: 30,
            sasl_enabled: false,
            max_hot_channels: 1,
            max_history_ring_bytes: crate::config::DEFAULT_HISTORY_RING_BYTES,
            max_hot_history_bytes: crate::config::DEFAULT_HOT_HISTORY_BYTES,
            opers: Vec::new(),
            clock: wall_clock,
            mono_clock,
            registration_burst: None,
            sasl_requirement: Default::default(),
            reserved_account_names: crate::identity::ReservedAccountNames::default(),
        }
    }

    struct TwoWorkerHarness {
        first: Core,
        second: Core,
        first_tx: Sender<Input>,
        first_rx: Receiver<Input>,
        second_tx: Sender<Input>,
        second_rx: Receiver<Input>,
        ingress: CoreIngress,
    }

    fn two_worker_harness() -> TwoWorkerHarness {
        let config = Config {
            name: "two-worker-routing",
            capacity: 64,
            policy: Policy::Fifo,
        };
        let (first_tx, first_rx) = queue(config);
        let (second_tx, second_rx) = queue(config);
        let ingress = CoreIngress::with_shards(first_tx.clone(), vec![second_tx.clone()]);
        let shards = CoreShardCount::new(NonZeroUsize::new(2).expect("two shards"));
        let directories = ingress.directories();
        let (first_db, _first_db_rx) = queue(Config {
            name: "two-worker-first-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let (second_db, _second_db_rx) = queue(Config {
            name: "two-worker-second-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let first = Core::with_telemetry_on_shard_with_directories(
            core_config(),
            first_db,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(0),
            shards,
            directories.clone(),
        );
        let second = Core::with_telemetry_on_shard_with_directories(
            core_config(),
            second_db,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(1),
            shards,
            directories,
        );
        TwoWorkerHarness {
            first,
            second,
            first_tx,
            first_rx,
            second_tx,
            second_rx,
            ingress,
        }
    }

    fn channel_on_second(core: &Core) -> &'static str {
        ["#alpha", "#beta", "#gamma"]
            .into_iter()
            .find(|name| core.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a channel owned by shard one")
    }

    fn open_session_on_first(
        first: &mut Core,
        name: &'static str,
    ) -> (SessionOwner, Receiver<Output>) {
        let (output_tx, output_rx) = crate::core::send_queue(name, 2 * 512);
        let session = SessionOwner::new(ConnId(2), CoreShardId(0));
        first.state.open(
            session.conn(),
            output_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        (session, output_rx)
    }

    fn take_service_result(core: &mut Core, session: SessionOwner) -> Input {
        let mut effects = core.take_effects();
        match effects.pop().map(|routed| routed.input) {
            Some(
                result @ Input::ChannelServiceResult {
                    session: received, ..
                },
            ) if received == session && effects.is_empty() => result,
            _ => panic!("owner did not produce one requester result"),
        }
    }

    #[test]
    fn registered_channel_ownership_is_shared_by_core_shards() {
        let TwoWorkerHarness {
            mut first, second, ..
        } = two_worker_harness();
        first.preload_founders(vec![("#chat".into(), "alice".into())]);
        let key = second.state.chan_key("#chat");
        assert!(second.state.is_founder(&key, "alice"));
        assert!(second.state.is_registered(&key));
    }

    #[test]
    fn retained_topics_are_shared_by_core_shards() {
        let TwoWorkerHarness {
            mut first, second, ..
        } = two_worker_harness();
        first.preload_topics(vec![(
            "#chat".into(),
            "Retained topic".into(),
            "alice".into(),
            42,
        )]);
        let key = second.state.chan_key("#chat");
        assert_eq!(
            second.state.registered_topics.get(&key).map(|topic| (
                topic.text,
                topic.set_by,
                topic.set_at_secs
            )),
            Some(("Retained topic".into(), "alice".into(), 42))
        );
    }

    #[test]
    fn durable_channel_options_are_shared_by_core_shards() {
        let TwoWorkerHarness {
            mut first, second, ..
        } = two_worker_harness();
        first.preload_keeptopic_off(vec!["#chat".into()]);
        first
            .preload_mlock(vec![("#chat".into(), "+im".into())])
            .expect("valid mode lock");
        first.preload_access(vec![("#chat".into(), "alice".into(), "ov".into())]);

        let key = second.state.chan_key("#chat");
        assert!(!second.state.channel_options.keeptopic_enabled(&key));
        assert_eq!(
            second
                .state
                .channel_options
                .mlock(&key)
                .map(|modes| modes.render()),
            Some("+im".into())
        );
        assert_eq!(second.state.access_modes(&key, "alice"), (true, true));
    }

    /// Each worker indexes the accounts of its own sessions; the index equals
    /// a scan of that worker's sessions after login, logout and close, and a
    /// login on one worker is invisible to the other.
    #[test]
    fn account_index_is_per_worker_and_equals_a_scan_on_each() {
        fn scan(core: &Core, account: &str) -> Vec<ConnId> {
            let want = core.state.casemap.casefold(account);
            let mut out: Vec<ConnId> = core
                .state
                .sessions
                .iter()
                .filter(|(_, s)| {
                    s.account()
                        .is_some_and(|a| core.state.casemap.casefold(a) == want)
                })
                .map(|(c, _)| *c)
                .collect();
            out.sort_by_key(|c| c.0);
            out
        }
        fn indexed(core: &Core, account: &str) -> Vec<ConnId> {
            let mut out = core.state.account_connections(account);
            out.sort_by_key(|c| c.0);
            out
        }
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let (session, _output) = open_session_on_first(&mut first, "account-index-first");
        let (second_tx, _second_output) = crate::core::send_queue("account-index-second", 2 * 512);
        second.state.open(
            ConnId(9),
            second_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        let check = |first: &Core, second: &Core| {
            for core in [first, second] {
                for account in ["alice", "ALICE", "nobody"] {
                    assert_eq!(indexed(core, account), scan(core, account), "{account}");
                }
            }
        };
        check(&first, &second);
        first.state.set_account(session.conn(), "Alice".into());
        second.state.set_account(ConnId(9), "alice".into());
        check(&first, &second);
        assert_eq!(indexed(&first, "alice"), vec![session.conn()]);
        assert_eq!(indexed(&second, "alice"), vec![ConnId(9)]);
        first.state.clear_account(session.conn());
        check(&first, &second);
        assert!(indexed(&first, "alice").is_empty());
        assert_eq!(indexed(&second, "alice"), vec![ConnId(9)]);
        second.state.close(ConnId(9), "bye");
        check(&first, &second);
        assert!(indexed(&second, "alice").is_empty());
    }

    #[test]
    fn corrupt_persisted_server_ban_aborts_preload() {
        let TwoWorkerHarness { mut first, .. } = two_worker_harness();
        let error = first
            .preload_server_bans(vec![crate::db::PersistedServerBan {
                mask: "bad@host".into(),
                reason: "reason".into(),
                set_by: "oper".into(),
                kind: "unknown".into(),
                expires_at: None,
            }])
            .expect_err("unknown server-ban kind must abort startup");
        assert!(error.contains("server-ban kind"), "{error}");
    }

    #[test]
    fn owner_channel_admin_request_reaches_its_channel_shard() {
        let TwoWorkerHarness {
            mut first, second, ..
        } = two_worker_harness();
        let channel = ["#alpha", "#beta", "#gamma"]
            .into_iter()
            .find(|name| first.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a channel owned by shard one");
        let (reply, _response) = tokio::sync::oneshot::channel();
        first.handle(Input::Admin {
            req: super::AdminRequest::RegisterOwnedChannel {
                channel: channel.into(),
                actor: "alice".into(),
            },
            reply,
        });
        assert!(matches!(
            first.take_effects().as_slice(),
            [super::Routed {
                to: CoreShardId(1),
                input: Input::Admin { .. }
            }]
        ));
        assert_eq!(second.shard, CoreShardId(1));
    }

    async fn next_output(rx: &mut Receiver<super::Output>) -> Envelope<super::Output> {
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.pop())
            .await
            .expect("core test timed out waiting for output")
            .expect("core output queue closed")
    }

    #[tokio::test]
    async fn connection_events_keep_one_deterministic_owner() {
        let (first, mut first_rx) = queue(Config {
            name: "first-core-shard",
            capacity: 3,
            policy: Policy::Fifo,
        });
        let (second, mut second_rx) = queue(Config {
            name: "second-core-shard",
            capacity: 3,
            policy: Policy::Fifo,
        });
        let ingress = CoreIngress::with_shards(first, vec![second]);

        ingress
            .push(Input::Line {
                conn: ConnId(4),
                line: b"PING :one".to_vec(),
            })
            .await
            .expect("first shard event routed");
        ingress
            .push(Input::OverlongLine { conn: ConnId(5) })
            .await
            .expect("second shard event routed");
        ingress
            .push(Input::Delivery {
                conn: ConnId(5),
                line: Bytes::from_static(b"NOTICE * :delivered\r\n"),
            })
            .await
            .expect("second shard delivery routed");

        let first = first_rx.pop().await.expect("first routed event");
        let second = second_rx.pop().await.expect("second routed event");
        assert!(matches!(
            first.payload,
            Input::Line {
                conn: ConnId(4),
                ..
            }
        ));
        assert!(matches!(
            second.payload,
            Input::OverlongLine { conn: ConnId(5) }
        ));
        let second = second_rx.pop().await.expect("second routed delivery");
        assert!(matches!(
            second.payload,
            Input::Delivery {
                conn: ConnId(5),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn persistence_callbacks_follow_channel_then_session_owners() {
        let config = Config {
            name: "persistence-callback-routing",
            capacity: 2,
            policy: Policy::Fifo,
        };
        let (first_tx, mut first_rx) = queue(config);
        let (second_tx, mut second_rx) = queue(config);
        let ingress = CoreIngress::with_shards(first_tx, vec![second_tx]);
        let shards = CoreShardCount::new(NonZeroUsize::new(2).expect("two shards"));
        let (db_tx, _db_rx) = queue(Config {
            name: "persistence-callback-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let core = Core::with_telemetry_on_shard_with_directories(
            core_config(),
            db_tx,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(0),
            shards,
            ingress.directories(),
        );
        let owner = ["#alpha", "#beta", "#gamma"]
            .into_iter()
            .map(|name| core.state.channel_owner(name))
            .find(|owner| owner.shard() == CoreShardId(1))
            .expect("a channel owned by shard one");
        let session = SessionOwner::new(ConnId(2), CoreShardId(0));
        let result = super::ChannelServicePersistence::FounderUnavailable {
            channel: "#alpha".into(),
            display: "#alpha".into(),
            label: None,
        };

        ingress
            .push(Input::ChannelServicePersisted {
                owner: owner.clone(),
                session,
                result: result.clone(),
            })
            .await
            .expect("owner callback routed");
        assert!(matches!(
            second_rx.pop().await.expect("owner callback").payload,
            Input::ChannelServicePersisted { owner: received, .. } if received == owner
        ));

        ingress
            .push(Input::ChannelServiceResult { session, result })
            .await
            .expect("session reply routed");
        assert!(matches!(
            first_rx.pop().await.expect("session reply").payload,
            Input::ChannelServiceResult { session: received, .. } if received == session
        ));
    }

    #[test]
    fn persistence_commits_on_the_channel_owner_after_requester_disconnects() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let channel = channel_on_second(&second);
        first.preload_founders(vec![(channel.into(), "boss".into())]);
        let (session, mut output_rx) =
            open_session_on_first(&mut first, "persistence-disconnect-output");

        second.handle(Input::ChannelServicePersisted {
            owner: second.state.channel_owner(channel),
            session,
            result: super::ChannelServicePersistence::AccessSet {
                channel: channel.into(),
                display: channel.into(),
                account: "alice".into(),
                flags: Some("o".into()),
                previous: None,
                frontend: super::AccessFrontend::Flags,
                label: None,
            },
        });
        assert_eq!(
            second
                .state
                .access_modes(&second.state.chan_key(channel), "alice"),
            (true, false)
        );
        let result = take_service_result(&mut second, session);

        first.handle(Input::Closed {
            conn: session.conn(),
            reason: "gone".into(),
        });
        first.handle(result);
        assert!(
            output_rx.try_pop().is_none(),
            "a disconnected session received a stale reply"
        );
    }

    #[test]
    fn persistence_failure_returns_only_to_the_requester_session() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let channel = channel_on_second(&second);
        let (session, mut output_rx) =
            open_session_on_first(&mut first, "persistence-failure-output");
        second.handle(Input::ChannelServicePersisted {
            owner: second.state.channel_owner(channel),
            session,
            result: super::ChannelServicePersistence::AccessUnavailable {
                channel: channel.into(),
                display: channel.into(),
                label: None,
            },
        });
        let result = take_service_result(&mut second, session);
        first.handle(result);
        let output = output_rx
            .try_pop()
            .expect("requester receives persistence failure");
        assert!(
            std::str::from_utf8(&output.payload.0)
                .expect("wire output")
                .contains("temporarily unavailable")
        );
    }

    /// Carry every routed event one core produced to the other core.
    fn relay(from: &mut Core, to: &mut Core) {
        for routed in from.take_effects() {
            assert_eq!(routed.to, to.shard);
            to.handle(routed.input);
        }
    }

    #[test]
    fn remote_chathistory_with_nothing_to_send_releases_the_requester() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let channel = channel_on_second(&second);
        let (alice, mut alice_rx) = register_on_first(&mut first, "alice");
        // draft/chathistory without batch: an empty page is no lines at all.
        first
            .state
            .sessions
            .get_mut(&alice)
            .expect("alice session")
            .caps
            .chathistory = true;
        first.handle(Input::Line {
            conn: alice,
            line: format!("JOIN {channel}").into_bytes(),
        });
        relay(&mut first, &mut second);
        relay(&mut second, &mut first);
        first.handle(Input::Line {
            conn: alice,
            line: format!("CHATHISTORY LATEST {channel} * 10").into_bytes(),
        });
        relay(&mut first, &mut second);
        relay(&mut second, &mut first);
        while alice_rx.try_pop().is_some() {}

        first.handle(Input::Line {
            conn: alice,
            line: b"PING after-history".to_vec(),
        });
        let pong = alice_rx
            .try_pop()
            .expect("the connection is held behind a history page that will never come");
        assert!(pong.payload.0.ends_with(b"after-history\r\n"));
    }

    /// `close()` releases output withheld behind a deferred reply before the
    /// closing ERROR, because the reply it waited on can no longer arrive.
    /// Shutdown ends the session just as finally, so it owes the client the
    /// same: what was produced, in order, then the ERROR.
    #[test]
    fn shutdown_flushes_output_held_behind_a_deferred_reply_before_the_closing_error() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let channel = channel_on_second(&second);
        let (alice, mut alice_rx) = register_on_first(&mut first, "alice");
        first
            .state
            .sessions
            .get_mut(&alice)
            .expect("alice session")
            .caps
            .chathistory = true;
        first.handle(Input::Line {
            conn: alice,
            line: format!("JOIN {channel}").into_bytes(),
        });
        relay(&mut first, &mut second);
        relay(&mut second, &mut first);
        // The history page is asked of the other shard and never comes back.
        first.handle(Input::Line {
            conn: alice,
            line: format!("CHATHISTORY LATEST {channel} * 10").into_bytes(),
        });
        while alice_rx.try_pop().is_some() {}
        first.handle(Input::Line {
            conn: alice,
            line: b"PING before-shutdown".to_vec(),
        });
        assert!(alice_rx.try_pop().is_none(), "the PONG is held");

        first.handle(Input::Shutdown);
        let mut written = Vec::new();
        while let Some(output) = alice_rx.try_pop() {
            written.push(
                String::from_utf8_lossy(&output.payload.0)
                    .trim_end()
                    .to_string(),
            );
        }
        assert_eq!(written.len(), 2, "{written:?}");
        assert!(written[0].ends_with("before-shutdown"), "{written:?}");
        assert!(
            written[1].starts_with("ERROR :Closing Link:"),
            "{written:?}"
        );
    }

    /// Open and register `nick` as connection 2 on the first shard.
    fn register_on_first(first: &mut Core, nick: &str) -> (ConnId, Receiver<Output>) {
        let (tx, rx) = crate::core::send_queue("registered-on-first-output", 64 * 512);
        let conn = ConnId(2);
        first
            .state
            .open(conn, tx, "host.test".into(), ConnectionTransport::Tcp);
        for line in [format!("NICK {nick}"), format!("USER {nick} 0 * :{nick}")] {
            first.handle(Input::Line {
                conn,
                line: line.into_bytes(),
            });
        }
        (conn, rx)
    }

    #[test]
    fn invitation_for_a_session_that_has_closed_is_dropped() {
        let mut core = single_core();
        let (bob, mut bob_rx) = register_on_first(&mut core, "bob");
        core.handle(Input::Closed {
            conn: bob,
            reason: "gone".into(),
        });
        while bob_rx.try_pop().is_some() {}
        // The invitee disconnected while the invitation crossed shards.
        core.handle(Input::ChannelSessionEvent {
            session: SessionOwner::new(ConnId(2), CoreShardId(0)),
            event: crate::core::state::ChannelSessionEvent::Invitation {
                inviter_prefix: "alice!alice@host.test".into(),
                inviter: Default::default(),
                ts: e6irc_proto::time::Millis::from_millis(0),
                channel: "#chat".into(),
            },
        });
        assert!(
            bob_rx.try_pop().is_none(),
            "nothing is written for a closed session"
        );
        assert!(
            core.state.sessions.get(&bob).is_none(),
            "the invitation does not bring the session back"
        );
        assert!(
            core.state
                .channels
                .get(&core.state.chan_key("#chat"))
                .is_none(),
            "nor does it create the channel or an invitation to it"
        );
    }

    #[test]
    fn remote_member_setting_a_registered_channel_topic_is_answered() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            ..
        } = two_worker_harness();
        let channel = channel_on_second(&second);
        second.preload_founders(vec![(channel.into(), "founder".into())]);
        let (alice, mut alice_rx) = register_on_first(&mut first, "alice");
        // alice is the founder: arriving first in a registered channel opens
        // no ops, so only the founder can set its (+t) topic.
        first.state.set_account(alice, "founder".into());
        first.handle(Input::Line {
            conn: alice,
            line: format!("JOIN {channel}").into_bytes(),
        });
        relay(&mut first, &mut second);
        relay(&mut second, &mut first);
        while alice_rx.try_pop().is_some() {}

        // The channel's owner builds the persistence request for a requester
        // whose session lives on the other shard.
        first.handle(Input::Line {
            conn: alice,
            line: format!("TOPIC {channel} :from another shard").into_bytes(),
        });
        relay(&mut first, &mut second);
        relay(&mut second, &mut first);
        let answer = alice_rx.try_pop().expect("the TOPIC is answered");
        // The harness has no database worker, so the honest answer is a refusal.
        assert!(
            std::str::from_utf8(&answer.payload.0)
                .expect("wire output")
                .contains("Topic could not be persisted")
        );
    }

    /// Two running workers over queues of `capacity`, as `net` starts them.
    struct LivePair {
        ingress: CoreIngress,
        workers: Vec<tokio::task::JoinHandle<super::CoreWorkerExit>>,
        /// A channel each shard owns: `owned[0]` by shard 0, `owned[1]` by shard 1.
        owned: [&'static str; 2],
    }

    fn live_pair(capacity: usize) -> LivePair {
        let config = Config {
            name: "live-pair",
            capacity,
            policy: Policy::Fifo,
        };
        let (first_tx, first_rx) = queue(config);
        let (second_tx, second_rx) = queue(config);
        let ingress = CoreIngress::with_shards(first_tx, vec![second_tx]);
        let shards = CoreShardCount::new(NonZeroUsize::new(2).expect("two shards"));
        let mut cores = Vec::new();
        for shard in 0..2 {
            let (db, _db_rx) = queue(Config {
                name: "live-pair-db",
                capacity: 1,
                policy: Policy::Fifo,
            });
            let mut config = core_config();
            config.sendq_bytes = 4096 * 512;
            config.max_hot_channels = 16;
            cores.push(Core::with_telemetry_on_shard_with_directories(
                config,
                db,
                Arc::new(crate::observability::Telemetry::new()),
                CoreShardId(shard),
                shards,
                ingress.directories(),
            ));
        }
        let owned_by = |shard: usize| {
            ["#alpha", "#beta", "#gamma", "#delta", "#epsilon"]
                .into_iter()
                .find(|name| cores[0].state.channel_owner(name).shard() == CoreShardId(shard))
                .expect("a channel owned by each shard")
        };
        let owned = [owned_by(0), owned_by(1)];
        let workers = cores
            .into_iter()
            .zip([first_rx, second_rx])
            .map(|(core, rx)| tokio::spawn(CoreWorker::new(core, rx, ingress.clone()).run()))
            .collect();
        LivePair {
            ingress,
            workers,
            owned,
        }
    }

    impl LivePair {
        /// Connect and register `nick` as connection `conn` (its shard is
        /// `conn % 2`), returning its output.
        async fn client(&self, conn: u64, nick: &str) -> Receiver<Output> {
            let (tx, mut rx) = crate::core::send_queue("live-pair-client", 4096 * 512);
            self.ingress
                .push(Input::Open {
                    conn: ConnId(conn),
                    tx,
                    host: "host.test".into(),
                    transport: ConnectionTransport::Tcp,
                })
                .await
                .expect("open");
            self.line(conn, &format!("NICK {nick}")).await;
            self.line(conn, &format!("USER {nick} 0 * :{nick}")).await;
            await_line(&mut rx, " 422 ").await;
            rx
        }

        async fn line(&self, conn: u64, line: &str) {
            self.ingress
                .push(Input::Line {
                    conn: ConnId(conn),
                    line: line.as_bytes().to_vec(),
                })
                .await
                .expect("line");
        }

        async fn stop(self) {
            self.ingress
                .broadcast_shutdown()
                .await
                .expect("workers alive");
            for worker in self.workers {
                let exit = tokio::time::timeout(Duration::from_secs(5), worker)
                    .await
                    .expect("worker stops")
                    .expect("worker does not panic");
                assert_eq!(exit, super::CoreWorkerExit::Stopped);
            }
        }
    }

    /// The next output line containing `needle`.
    async fn await_line(rx: &mut Receiver<Output>, needle: &str) -> String {
        loop {
            let line = next_output(rx).await.payload.0;
            let line = String::from_utf8_lossy(&line).trim_end().to_string();
            if line.contains(needle) {
                return line;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn workers_flooding_each_other_through_full_queues_keep_moving() {
        // One slot per queue: every cross-shard event finds the other queue
        // full while that worker is itself trying to send back.
        let pair = live_pair(1);
        let [here, there] = pair.owned;
        let mut outputs = Vec::new();
        for conn in 1..=6 {
            let mut rx = pair.client(conn, &format!("user{conn}")).await;
            for channel in [here, there] {
                pair.line(conn, &format!("JOIN {channel}")).await;
                await_line(&mut rx, " 366 ").await;
            }
            outputs.push(rx);
        }
        let flood = |conn: u64, channel: &'static str| {
            let ingress = pair.ingress.clone();
            tokio::spawn(async move {
                for n in 0..40 {
                    ingress
                        .push(Input::Line {
                            conn: ConnId(conn),
                            line: format!("PRIVMSG {channel} :flood {n}").into_bytes(),
                        })
                        .await
                        .expect("line");
                }
            })
        };
        // Connection 2 lives on shard 0 and floods shard 1's channel, and the
        // other way round: both workers fan out toward each other at once.
        let floods = [flood(2, there), flood(1, here)];
        let watcher = outputs.last_mut().expect("connection 6");
        for _ in 0..2 {
            await_line(watcher, ":flood 39").await;
        }
        for flood in floods {
            flood.await.expect("flood task");
        }
        pair.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_shard_that_has_seen_shutdown_still_serves_the_others_until_all_have() {
        let pair = live_pair(64);
        let [here, _] = pair.owned;
        let mut bob = pair.client(1, "bob").await;
        // Shard 0 is told to stop first. It must not close its queue while
        // shard 1 can still send to it — that was a panic on shard 1, and a
        // shutdown that skipped the database flush.
        pair.ingress.shards[0]
            .push(Input::Shutdown)
            .await
            .expect("shard 0 alive");
        tokio::time::sleep(Duration::from_millis(100)).await;
        pair.line(1, &format!("JOIN {here}")).await;
        await_line(&mut bob, " 366 ").await;
        pair.ingress.shards[1]
            .push(Input::Shutdown)
            .await
            .expect("shard 1 alive");
        for worker in pair.workers {
            let exit = tokio::time::timeout(Duration::from_secs(5), worker)
                .await
                .expect("worker stops")
                .expect("worker does not panic");
            assert_eq!(exit, super::CoreWorkerExit::Stopped);
        }
    }

    thread_local! {
        /// The monotonic clock of the [`Shards`] built on this test's thread.
        static MONO_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn thread_mono_clock() -> e6irc_proto::time::MonoMillis {
        e6irc_proto::time::MonoMillis::from_millis(MONO_NOW.with(std::cell::Cell::get))
    }

    /// The wall clock of those cores follows the same thread-local time, from
    /// a fixed origin: each message a test sends after advancing it has its own
    /// timestamp, so anything ordered by time is ordered the same on every run.
    fn thread_wall_clock() -> e6irc_proto::time::Millis {
        e6irc_proto::time::Millis::from_millis(1_000_000 + MONO_NOW.with(std::cell::Cell::get))
    }

    /// Cores stepped by hand — two unless a test asks otherwise: every line is
    /// handled, and whatever it causes is carried between the shards until all
    /// are quiet, so a test reads like the single-shard ones. Connection `n`
    /// lives on shard `n % workers`.
    struct Shards {
        cores: Vec<Core>,
        /// A channel each shard owns: `owned[0]` by shard 0, `owned[1]` by shard 1.
        owned: [&'static str; 2],
        outputs: std::collections::HashMap<u64, Receiver<Output>>,
        /// Each shard's requests to the database worker (there is none).
        database: Vec<Receiver<super::DbRequest>>,
    }

    impl Shards {
        fn new() -> Self {
            Self::build(2, false)
        }

        /// With a database configured, so history falls through to it.
        fn with_database() -> Self {
            Self::build(2, true)
        }

        /// The same server on one worker: what every answer must equal.
        fn on_one_worker() -> Self {
            Self::build(1, false)
        }

        fn build(workers: usize, database: bool) -> Self {
            let mut senders: Vec<_> = (0..workers)
                .map(|_| {
                    queue(Config {
                        name: "shards",
                        capacity: 1,
                        policy: Policy::Fifo,
                    })
                    .0
                })
                .collect();
            let ingress = CoreIngress::with_shards(senders.remove(0), senders);
            let shards = CoreShardCount::new(NonZeroUsize::new(workers).expect("a worker"));
            let mut requests = Vec::new();
            let cores: Vec<Core> = (0..workers)
                .map(|shard| {
                    let (db, db_rx) = queue(Config {
                        name: "shards-db",
                        capacity: 64,
                        policy: Policy::Fifo,
                    });
                    if database {
                        requests.push(db_rx);
                    }
                    let mut config = core_config();
                    config.sasl_enabled = database;
                    config.sendq_bytes = 256 * 512;
                    config.max_hot_channels = 16;
                    config.mono_clock = thread_mono_clock;
                    config.clock = thread_wall_clock;
                    config.opers = vec![("root".into(), "secret".into())];
                    Core::with_telemetry_on_shard_with_directories(
                        config,
                        db,
                        Arc::new(crate::observability::Telemetry::new()),
                        CoreShardId(shard),
                        shards,
                        ingress.directories(),
                    )
                })
                .collect();
            let owned_by = |shard: usize| {
                ["#alpha", "#beta", "#gamma", "#delta", "#epsilon"]
                    .into_iter()
                    .find(|name| cores[0].state.channel_owner(name).shard() == CoreShardId(shard))
                    .expect("a channel owned by each shard")
            };
            Self {
                owned: [owned_by(0), owned_by(workers - 1)],
                cores,
                outputs: std::collections::HashMap::new(),
                database: requests,
            }
        }

        fn advance_clock(seconds: u64) {
            MONO_NOW.with(|now| now.set(now.get() + seconds * 1000));
        }

        /// Connect and register `nick` as connection `conn`, requesting `caps`.
        fn client(&mut self, conn: u64, nick: &str, caps: &str) {
            let (tx, rx) = crate::core::send_queue("shards-client", 256 * 512);
            self.outputs.insert(conn, rx);
            let shard = conn as usize % self.cores.len();
            self.cores[shard].handle(Input::Open {
                conn: ConnId(conn),
                tx,
                host: "host.test".into(),
                transport: ConnectionTransport::Tcp,
            });
            if !caps.is_empty() {
                self.line(conn, &format!("CAP REQ :{caps}"));
            }
            self.line(conn, &format!("NICK {nick}"));
            self.line(conn, &format!("USER {nick} 0 * :Real {nick}"));
            self.line(conn, "CAP END");
            self.drain(conn);
        }

        fn line(&mut self, conn: u64, line: &str) {
            self.push_line(conn, line);
            self.settle();
        }

        /// Hand `conn`'s shard a line without carrying what it causes to the
        /// other shards: several of these in a row are a pipelined burst whose
        /// answers are all still in flight until the next `settle`.
        fn push_line(&mut self, conn: u64, line: &str) {
            let shard = conn as usize % self.cores.len();
            self.cores[shard].handle(Input::Line {
                conn: ConnId(conn),
                line: line.as_bytes().to_vec(),
            });
        }

        /// The shard `conn` lives on.
        fn shard_of(&self, conn: u64) -> usize {
            conn as usize % self.cores.len()
        }

        /// The next request `shard` sent the database worker of a given kind,
        /// discarding the ones before it.
        fn database_request<T>(
            &mut self,
            shard: usize,
            pick: impl Fn(super::DbRequest) -> Option<T>,
        ) -> T {
            std::iter::from_fn(|| self.database[shard].try_pop())
                .find_map(|request| pick(request.payload))
                .expect("the shard asked the database")
        }

        fn close(&mut self, conn: u64) {
            let shard = conn as usize % self.cores.len();
            self.cores[shard].handle(Input::Closed {
                conn: ConnId(conn),
                reason: "Connection closed".into(),
            });
            self.settle();
        }

        /// Carry events between the shards until neither has any to send.
        fn settle(&mut self) {
            loop {
                let routed: Vec<super::Routed> = self
                    .cores
                    .iter_mut()
                    .flat_map(|core| core.take_effects())
                    .collect();
                if routed.is_empty() {
                    return;
                }
                for super::Routed { to, input } in routed {
                    self.cores[to.0].handle(input);
                }
            }
        }

        fn drain(&mut self, conn: u64) -> Vec<String> {
            let rx = self.outputs.get_mut(&conn).expect("connected client");
            let mut lines = Vec::new();
            while let Some(output) = rx.try_pop() {
                lines.push(
                    String::from_utf8_lossy(&output.payload.0)
                        .trim_end()
                        .to_string(),
                );
            }
            lines
        }
    }

    /// Idle time is the session's own clock, read where it is asked about. A
    /// line must not cost one member update per channel the sender is in.
    #[test]
    fn activity_is_not_fanned_out_to_every_channel_and_a_remote_who_still_sees_idle() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(2, "alice", "");
        shards.client(1, "bob", "");
        shards.line(2, &format!("JOIN {there}"));
        shards.line(1, &format!("JOIN {there}"));
        Shards::advance_clock(60);
        shards.cores[0].handle(Input::Line {
            conn: ConnId(2),
            line: b"VERSION".to_vec(),
        });
        assert!(
            shards.cores[0].take_effects().is_empty(),
            "a line unrelated to any channel was sent to the shard owning one"
        );
        Shards::advance_clock(30);
        shards.drain(1);
        shards.line(1, &format!("WHO {there} %nl"));
        let out = shards.drain(1);
        assert!(
            out.iter().any(|line| line.ends_with(" alice 30")),
            "the channel's owner must report alice idle since her last line: {out:#?}"
        );
    }

    fn lines_with<'a>(out: &'a [String], needle: &str) -> Vec<&'a str> {
        out.iter()
            .map(String::as_str)
            .filter(|line| line.contains(needle))
            .collect()
    }

    /// alice is connection 2 (shard 0), bob connection 1 (shard 1).
    fn alice_and_bob(caps: &str) -> Shards {
        let mut shards = Shards::new();
        shards.client(2, "alice", caps);
        shards.client(1, "bob", caps);
        shards
    }

    /// A ban set on the shard that owns the channel stops a member whose
    /// session lives on the other shard from renaming out from under it.
    #[test]
    fn a_ban_on_another_shard_refuses_the_members_nick_change() {
        let mut shards = alice_and_bob("");
        let there = shards.owned[0];
        assert_ne!(shards.shard_of(1), 0, "bob's session is not the owner's");
        shards.line(2, &format!("JOIN {there}"));
        shards.line(1, &format!("JOIN {there}"));
        shards.line(2, &format!("MODE {there} +b bob!*@*"));
        shards.drain(1);
        shards.line(1, "NICK bobby");
        let out = shards.drain(1);
        assert_eq!(
            lines_with(
                &out,
                &format!(" 435 bob bobby {there} :Cannot change nickname while banned on channel")
            )
            .len(),
            1,
            "{out:#?}"
        );
        shards.line(2, &format!("MODE {there} -b bob!*@*"));
        shards.drain(1);
        shards.line(1, "NICK bobby");
        assert_eq!(lines_with(&shards.drain(1), " NICK bobby").len(), 1);
    }

    #[test]
    fn a_message_reaches_a_nick_on_another_shard() {
        let mut shards = alice_and_bob("message-tags");
        shards.line(2, "PRIVMSG bob :hello");
        shards.line(2, "NOTICE bob :psst");
        shards.line(2, "@+typing=active TAGMSG bob");
        assert!(shards.drain(2).is_empty(), "no such nick?");
        let out = shards.drain(1);
        for expected in ["PRIVMSG bob :hello", "NOTICE bob :psst", "TAGMSG bob"] {
            assert_eq!(lines_with(&out, expected).len(), 1, "{expected}: {out:#?}");
        }
        // The away reply comes from the recipient's state, wherever it lives.
        shards.line(1, "AWAY :gone fishing");
        shards.line(2, "PRIVMSG bob :you there?");
        let out = shards.drain(2);
        assert_eq!(
            lines_with(&out, " 301 alice bob :gone fishing").len(),
            1,
            "{out:#?}"
        );
    }

    #[test]
    fn a_direct_conversation_is_readable_from_both_shards() {
        let mut shards = alice_and_bob("batch draft/chathistory");
        shards.line(2, "PRIVMSG bob :one");
        shards.line(1, "PRIVMSG alice :two");
        for (conn, peer) in [(2, "bob"), (1, "alice")] {
            shards.drain(conn);
            shards.line(conn, &format!("CHATHISTORY LATEST {peer} * 10"));
            let out = shards.drain(conn);
            assert!(
                lines_with(&out, ":one").len() == 1 && lines_with(&out, ":two").len() == 1,
                "connection {conn} sees only its own half: {out:#?}"
            );
        }
    }

    #[test]
    fn whois_ison_and_userhost_answer_for_a_nick_on_another_shard() {
        let mut shards = alice_and_bob("");
        let [here, there] = shards.owned;
        // bob: an operator of a channel each shard owns, one of them secret.
        shards.line(1, &format!("JOIN {here},{there},#hidden"));
        shards.line(1, "MODE #hidden +s");
        shards.line(1, "AWAY :out");
        Shards::advance_clock(42);
        shards.drain(2);

        shards.line(2, "WHOIS bob");
        let out = shards.drain(2);
        assert_eq!(
            lines_with(&out, " 311 alice bob bob host.test * :Real bob").len(),
            1,
            "{out:#?}"
        );
        let channels = lines_with(&out, " 319 ");
        assert_eq!(channels.len(), 1, "{out:#?}");
        assert!(
            channels[0].contains(&format!("@{here}")) && channels[0].contains(&format!("@{there}")),
            "channels owned by either shard, with bob's rank: {channels:?}"
        );
        assert!(!channels[0].contains("#hidden"), "a secret channel leaked");
        assert_eq!(lines_with(&out, " 317 alice bob 42 ").len(), 1, "{out:#?}");
        assert_eq!(lines_with(&out, " 301 alice bob :out").len(), 1, "{out:#?}");
        assert!(lines_with(&out, " 401 ").is_empty(), "{out:#?}");

        // Sharing the secret channel discloses it, as on one shard.
        shards.line(1, "MODE #hidden +o bob");
        shards.line(2, "JOIN #hidden");
        shards.drain(2);
        shards.line(2, "WHOIS bob");
        assert_eq!(lines_with(&shards.drain(2), "#hidden").len(), 1);

        shards.line(2, "ISON bob nobody");
        assert_eq!(lines_with(&shards.drain(2), " 303 alice :bob").len(), 1);
        shards.line(2, "USERHOST bob");
        assert_eq!(
            lines_with(&shards.drain(2), " 302 alice :bob=-bob@host.test").len(),
            1
        );
    }

    /// The ring copy a peer's shard keeps is purged with the original when an
    /// unauthenticated party leaves: the next holder of the nick may connect to
    /// either shard.
    #[test]
    fn an_unauthenticated_conversation_is_purged_from_every_shard() {
        let mut shards = alice_and_bob("batch draft/chathistory");
        shards.line(1, "PRIVMSG alice :between us");
        shards.close(1);
        // A stranger takes the nick, on the shard alice's copy lives on.
        shards.client(4, "bob", "batch draft/chathistory");
        shards.line(4, "CHATHISTORY LATEST alice * 10");
        let out = shards.drain(4);
        assert!(
            lines_with(&out, "between us").is_empty(),
            "the previous bob's conversation was served to the next: {out:#?}"
        );
    }

    #[test]
    fn kill_and_ghost_reach_a_session_on_another_shard() {
        let mut shards = alice_and_bob("");
        shards.line(2, "OPER root secret");
        shards.line(2, "KILL bob :enough");
        assert!(
            shards.cores[1].state.sessions.get(&ConnId(1)).is_none(),
            "bob survived a KILL from the other shard"
        );
        assert!(lines_with(&shards.drain(2), " 401 ").is_empty());

        // carol's account owns the nick a stale connection still holds.
        shards.client(3, "carol", "");
        shards.client(4, "visitor", "");
        shards.cores[0].state.set_account(ConnId(4), "carol".into());
        shards.settle();
        shards.line(4, "PRIVMSG NickServ :GHOST carol");
        assert!(
            shards.cores[1].state.sessions.get(&ConnId(3)).is_none(),
            "the ghost on the other shard is still connected"
        );
        assert_eq!(lines_with(&shards.drain(4), "has been ghosted").len(), 1);
    }

    #[test]
    fn monitor_follows_a_nick_on_another_shard() {
        let mut shards = Shards::new();
        shards.client(1, "bob", "");
        shards.line(1, "MONITOR + alice");
        assert_eq!(lines_with(&shards.drain(1), " 731 bob :alice").len(), 1);
        shards.client(2, "alice", "");
        assert_eq!(
            lines_with(&shards.drain(1), " 730 bob :alice!alice@host.test").len(),
            1,
            "online on the other shard"
        );
        shards.line(1, "MONITOR S");
        assert_eq!(lines_with(&shards.drain(1), " 730 bob :alice!").len(), 1);
        shards.close(2);
        assert_eq!(lines_with(&shards.drain(1), " 731 bob :alice").len(), 1);
    }

    /// One user, however many channels they share with you and whichever
    /// shards own those channels: each of their events reaches you once.
    #[test]
    fn a_users_events_reach_each_peer_once_across_channel_owners() {
        let caps = "away-notify account-notify setname chghost";
        let mut shards = alice_and_bob(caps);
        let [here, there] = shards.owned;
        for conn in [1, 2] {
            shards.line(conn, &format!("JOIN {here},{there}"));
        }
        shards.client(3, "watcher", "extended-monitor away-notify");
        shards.line(3, "MONITOR + alice");
        shards.drain(1);
        shards.drain(3);

        shards.line(2, "AWAY :brb");
        assert_eq!(lines_with(&shards.drain(1), " AWAY :brb").len(), 1);
        assert_eq!(
            lines_with(&shards.drain(3), " AWAY :brb").len(),
            1,
            "an extended-monitor watcher on the other shard"
        );
        shards.line(2, "SETNAME :Alice Again");
        assert_eq!(
            lines_with(&shards.drain(1), " SETNAME :Alice Again").len(),
            1
        );
        shards.line(1, "OPER root secret");
        shards.drain(1);
        shards.line(1, "SETHOST alice cloak.test");
        assert_eq!(
            lines_with(&shards.drain(1), " CHGHOST alice cloak.test").len(),
            1
        );
        shards.line(2, "NICK alicia");
        assert_eq!(lines_with(&shards.drain(1), " NICK alicia").len(), 1);
        shards.line(2, "QUIT :bye");
        assert_eq!(lines_with(&shards.drain(1), " QUIT :").len(), 1);
    }

    /// A peer without `chghost` sharing channels owned by both shards is told
    /// of a host change by one QUIT, then one rejoin per shared channel — the
    /// QUIT first, whichever shard's report arrives first.
    #[test]
    fn a_host_change_rejoins_every_shared_channel_after_one_quit() {
        let mut shards = alice_and_bob("");
        let [here, there] = shards.owned;
        for conn in [2, 1] {
            shards.line(conn, &format!("JOIN {here},{there}"));
        }
        shards.drain(1);
        shards.line(1, "OPER root secret");
        shards.drain(1);
        shards.line(1, "SETHOST alice cloak.test");
        let out = shards.drain(1);
        let quits = lines_with(&out, " QUIT :Changing host");
        assert_eq!(quits.len(), 1, "{out:#?}");
        let quit_at = out
            .iter()
            .position(|line| line.contains(" QUIT :Changing host"));
        for channel in [here, there] {
            let join = format!("@cloak.test JOIN {channel}");
            assert_eq!(lines_with(&out, &join).len(), 1, "{out:#?}");
            let join_at = out.iter().position(|line| line.contains(&join));
            assert!(quit_at < join_at, "the QUIT must come first: {out:#?}");
        }
    }

    #[test]
    fn a_labeled_kick_of_several_targets_is_one_labeled_response() {
        let mut shards = Shards::new();
        let [here, there] = shards.owned;
        shards.client(2, "alice", "batch labeled-response");
        shards.client(1, "bob", "");
        for conn in [2, 1] {
            shards.line(conn, &format!("JOIN {here},{there}"));
        }
        shards.drain(2);
        shards.line(2, &format!("@label=k1 KICK {here},{there} bob,nobody"));
        let out = shards.drain(2);
        let labeled = lines_with(&out, "label=k1");
        assert_eq!(labeled.len(), 1, "one labeled response: {out:#?}");
        assert!(
            labeled[0].contains("BATCH +"),
            "several lines make a batch: {out:#?}"
        );
        assert_eq!(
            lines_with(&out, &format!("KICK {here} bob")).len(),
            1,
            "{out:#?}"
        );
        assert_eq!(lines_with(&out, " 441 ").len(), 1, "{out:#?}");
        assert_eq!(lines_with(&out, "BATCH -").len(), 1, "{out:#?}");
    }

    #[test]
    fn a_labeled_join_answered_in_pieces_is_one_labeled_response() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(2, "alice", "batch labeled-response");
        // One target is refused on the spot, the other is answered by its owner.
        shards.line(2, &format!("@label=j1 JOIN {there},not-a-channel"));
        let out = shards.drain(2);
        let labeled = lines_with(&out, "label=j1");
        assert_eq!(labeled.len(), 1, "one labeled response: {out:#?}");
        assert!(labeled[0].contains("BATCH +"), "{out:#?}");
        assert_eq!(
            lines_with(&out, &format!(" JOIN {there}")).len(),
            1,
            "{out:#?}"
        );
        assert_eq!(lines_with(&out, "not-a-channel").len(), 1, "{out:#?}");
    }

    #[test]
    fn lusers_and_whowas_count_the_whole_server() {
        let mut shards = alice_and_bob("");
        let [here, there] = shards.owned;
        shards.line(2, &format!("JOIN {here}"));
        shards.line(1, &format!("JOIN {there}"));
        shards.line(1, "MODE bob +i");
        shards.drain(2);
        shards.line(2, "LUSERS");
        let out = shards.drain(2);
        assert_eq!(
            lines_with(&out, ":There are 1 users and 1 invisible on 1 servers").len(),
            1,
            "{out:#?}"
        );
        assert_eq!(lines_with(&out, " 254 alice 2 :").len(), 1, "{out:#?}");
        assert_eq!(lines_with(&out, ":I have 2 clients").len(), 1, "{out:#?}");

        shards.close(1);
        shards.line(2, "WHOWAS bob");
        let out = shards.drain(2);
        assert_eq!(
            lines_with(&out, " 314 alice bob bob host.test").len(),
            1,
            "{out:#?}"
        );
    }

    /// The per-session cap on database history requests is kept where the
    /// session is. The shard that owns the channel — and asks the database on
    /// the session's behalf — has no such session to count against.
    #[test]
    fn history_of_a_channel_on_another_shard_still_reaches_the_database() {
        let mut shards = Shards::with_database();
        let there = shards.owned[1];
        shards.client(2, "alice", "batch draft/chathistory");
        shards.line(2, &format!("JOIN {there}"));
        shards.drain(2);
        while shards.database[1].try_pop().is_some() {}
        shards.line(2, &format!("CHATHISTORY LATEST {there} * 10"));
        assert!(shards.drain(2).is_empty(), "answered by the database page");
        assert!(
            matches!(
                shards.database[1].try_pop().map(|request| request.payload),
                Some(super::DbRequest::QueryHistory { .. })
            ),
            "the channel's owner did not ask the database"
        );
    }

    /// alice joins a channel owned by each shard, speaks in both, and asks
    /// which of her buffers have history. Returns the TARGETS lines.
    fn targets_after_speaking_in(mut shards: Shards, channels: [&str; 2]) -> Vec<String> {
        shards.client(2, "alice", "batch draft/chathistory server-time");
        for channel in channels {
            shards.line(2, &format!("JOIN {channel}"));
            Shards::advance_clock(1);
            shards.line(2, &format!("PRIVMSG {channel} :hello"));
        }
        shards.drain(2);
        shards.line(
            2,
            "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:01.000Z \
             timestamp=2999-01-01T00:00:00.000Z 10",
        );
        shards
            .drain(2)
            .into_iter()
            .filter(|line| line.contains("CHATHISTORY TARGETS"))
            .map(|line| {
                line.split_once(" CHATHISTORY ")
                    .expect("targets line")
                    .1
                    .to_string()
            })
            .collect()
    }

    /// With no database the rings are the record, and a channel's ring lives on
    /// the shard that owns the channel. TARGETS must still find it.
    #[test]
    fn targets_from_the_rings_lists_a_channel_owned_by_another_shard() {
        let two = Shards::new();
        let channels = two.owned;
        let from_two_workers = targets_after_speaking_in(two, channels);
        assert_eq!(
            from_two_workers
                .iter()
                .map(|line| line.split(' ').nth(1).expect("target"))
                .collect::<Vec<_>>(),
            channels,
            "oldest activity first, whichever shard owns the channel"
        );
        MONO_NOW.with(|now| now.set(0));
        assert_eq!(
            from_two_workers,
            targets_after_speaking_in(Shards::on_one_worker(), channels),
            "the answer on two workers is the answer on one"
        );
    }

    /// Identify `conn` to `account` through NickServ, answering the verify.
    fn identify_on(shards: &mut Shards, conn: u64, account: &str) {
        shards.line(conn, &format!("PRIVMSG NickServ :IDENTIFY {account} pw"));
        let shard = shards.shard_of(conn);
        shards.database_request(shard, |request| {
            matches!(request, super::DbRequest::VerifyPassword { .. }).then_some(())
        });
        shards.cores[shard].handle(Input::DbReply {
            conn: ConnId(conn),
            reply: super::DbReply::PasswordVerified {
                account: account.into(),
                origin: super::CredentialOrigin::NickServIdentify,
            },
        });
        shards.settle();
        shards.drain(conn);
    }

    /// REGAIN reaches a holder on another shard: its shard renames it to a
    /// Guest nick, then hands the nick back to the regaining session's shard.
    /// Nick protection, turned on from one shard, renames an unidentified
    /// holder on the other when its own shard's tick finds the delay run out.
    #[test]
    fn regain_and_nick_protection_act_across_shards() {
        let mut shards = Shards::with_database();
        shards.client(1, "alice", "");
        shards.client(2, "owner", "");
        assert_ne!(shards.shard_of(1), shards.shard_of(2));
        identify_on(&mut shards, 2, "alice");

        shards.line(2, "PRIVMSG NickServ :REGAIN alice");
        let holder = shards.drain(1);
        assert_eq!(lines_with(&holder, " has regained your nickname.").len(), 1);
        assert_eq!(
            lines_with(&holder, ":alice!alice@host.test NICK Guest1").len(),
            1
        );
        let owner = shards.drain(2);
        assert_eq!(
            lines_with(&owner, ":owner!owner@host.test NICK alice").len(),
            1
        );
        assert_eq!(
            lines_with(&owner, "\x02alice\x02 has been regained.").len(),
            1
        );

        shards.line(2, "PRIVMSG NickServ :SET ENFORCE ON");
        let shard = shards.shard_of(2);
        shards.database_request(shard, |request| {
            matches!(request, super::DbRequest::SetNickEnforce { .. }).then_some(())
        });
        shards.cores[shard].handle(Input::DbReply {
            conn: ConnId(2),
            reply: super::DbReply::NickEnforce {
                account: "alice".into(),
                enforce: true,
                outcome: Some(crate::db::NickEnforceChange::Changed),
                label: None,
            },
        });
        shards.settle();
        shards.line(2, "NICK owner");
        shards.drain(2);

        shards.line(1, "NICK alice");
        assert_eq!(
            lines_with(&shards.drain(1), "This nickname is registered.").len(),
            1
        );
        Shards::advance_clock(30);
        let now = thread_mono_clock();
        for core in &mut shards.cores {
            core.handle(Input::Tick { now });
        }
        shards.settle();
        let renamed = shards.drain(1);
        assert_eq!(
            lines_with(&renamed, ":alice!alice@host.test NICK Guest1").len(),
            1,
            "{renamed:#?}"
        );
    }

    /// alice, not logged in, confides in bob, then identifies to her account
    /// and leaves. A stranger takes the nick `alice` and asks for the
    /// conversation with bob. Returns what CHATHISTORY shows the stranger and
    /// the ring conversations TARGETS hands the database on their behalf.
    fn conversation_after_login_and_nick_reuse(
        mut shards: Shards,
    ) -> (Vec<String>, Vec<(String, e6irc_proto::time::Millis)>) {
        let caps = "batch draft/chathistory";
        shards.client(2, "alice", caps);
        shards.client(1, "bob", caps);
        shards.line(2, "PRIVMSG bob :the secret");
        assert_eq!(lines_with(&shards.drain(1), ":the secret").len(), 1);
        shards.line(2, "PRIVMSG NickServ :IDENTIFY alice pw");
        let shard = shards.shard_of(2);
        shards.database_request(shard, |request| {
            matches!(request, super::DbRequest::VerifyPassword { .. }).then_some(())
        });
        shards.cores[shard].handle(Input::DbReply {
            conn: ConnId(2),
            reply: super::DbReply::PasswordVerified {
                account: "alice".into(),
                origin: super::CredentialOrigin::NickServIdentify,
            },
        });
        shards.settle();
        assert_eq!(
            lines_with(&shards.drain(2), "You are now identified").len(),
            1
        );
        shards.close(2);
        // The stranger lands on bob's shard, which keeps its own copy of the
        // rings of every conversation bob is in.
        shards.client(3, "alice", caps);
        shards.line(3, "CHATHISTORY LATEST bob * 10");
        // The messages inside the batch; its reference is a per-shard counter.
        let history: Vec<String> = shards
            .drain(3)
            .into_iter()
            .filter(|line| line.contains(" PRIVMSG "))
            .collect();
        shards.line(
            3,
            "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:01.000Z \
             timestamp=2999-01-01T00:00:00.000Z 10",
        );
        let stranger = shards.shard_of(3);
        let session_only = shards.database_request(stranger, |request| match request {
            super::DbRequest::QueryTargets { session_only, .. } => Some(session_only),
            _ => None,
        });
        (history, session_only)
    }

    /// `~alice` is whoever holds the nick without an account. The moment alice
    /// logs in she is `alice`, and `~alice` is free for the next holder — so
    /// the conversations kept under it are freed then, on every shard, exactly
    /// as they are when she disconnects or changes nick without logging in.
    #[test]
    fn logging_in_frees_the_conversations_of_the_unauthenticated_nick() {
        let on_two_workers = conversation_after_login_and_nick_reuse(Shards::with_database());
        assert!(
            lines_with(&on_two_workers.0, "the secret").is_empty(),
            "the stranger read alice's conversation: {:#?}",
            on_two_workers.0
        );
        assert!(
            on_two_workers.1.is_empty(),
            "TARGETS still lists alice's conversation: {:?}",
            on_two_workers.1
        );
        MONO_NOW.with(|now| now.set(0));
        assert_eq!(
            on_two_workers,
            conversation_after_login_and_nick_reuse(Shards::build(1, true)),
            "the answer on two workers is the answer on one"
        );
    }

    /// alice joins 240 channels one at a time, then sends eleven JOINs for
    /// channels owned by the shard she is not on before any of them is
    /// answered. Returns how many she joined and which targets were refused.
    fn join_burst_answer(mut shards: Shards) -> (usize, Vec<String>) {
        shards.client(2, "alice", "");
        for i in 0..240 {
            shards.line(2, &format!("JOIN #fill{i}"));
            if i % 10 == 9 {
                shards.drain(2);
            }
        }
        shards.drain(2);
        let remote_shard = CoreShardId(shards.cores.len() - 1);
        let burst: Vec<String> = (0..)
            .map(|i| format!("#burst{i}"))
            .filter(|name| shards.cores[0].state.channel_owner(name).shard() == remote_shard)
            .take(11)
            .collect();
        for name in &burst {
            shards.push_line(2, &format!("JOIN {name}"));
        }
        shards.settle();
        let out = shards.drain(2);
        let joined = out
            .iter()
            .filter(|line| line.starts_with(":alice!") && line.contains(" JOIN #burst"))
            .count();
        let refused = out
            .iter()
            .filter(|line| line.contains(" 405 alice "))
            .map(|line| line.split(' ').nth(3).expect("refused target").to_string())
            .collect();
        (joined, refused)
    }

    /// CHANLIMIT is enforced by the shard that holds the session, and a JOIN
    /// it routed to another shard counts from the moment it is sent — not
    /// from when the answer comes back — or a pipelined burst is unbounded.
    #[test]
    fn a_burst_of_joins_to_another_shard_is_capped_like_local_ones() {
        let (joined, refused) = join_burst_answer(Shards::new());
        assert_eq!(joined, 10, "ten of the eleven fit under the limit");
        assert_eq!(
            refused.len(),
            1,
            "the eleventh is ERR_TOOMANYCHANNELS: {refused:?}"
        );
        MONO_NOW.with(|now| now.set(0));
        let on_one_worker = join_burst_answer(Shards::on_one_worker());
        assert_eq!(
            (joined, refused.len()),
            (on_one_worker.0, on_one_worker.1.len()),
            "the answer on two workers is the answer on one"
        );
    }

    /// alice (on shard 0) joins the channel shard 1 owns, then joins it again
    /// under three spellings and NAMES it under three. Returns what the second
    /// JOIN and the NAMES produced.
    fn rejoin_and_names_answer(mut shards: Shards) -> (Vec<String>, Vec<String>) {
        let remote = shards.owned[1];
        shards.client(2, "alice", "");
        shards.line(2, &format!("JOIN {remote}"));
        shards.drain(2);
        let upper = remote.to_ascii_uppercase();
        shards.line(2, &format!("JOIN {remote},{upper},{remote}"));
        let rejoin = shards.drain(2);
        shards.line(2, &format!("NAMES {remote},{upper},{remote}"));
        let names = shards.drain(2);
        (rejoin, names)
    }

    /// A JOIN of a channel already joined is silent, and a NAMES list is one
    /// channel once — whether the channel's owner is the session's shard or
    /// another: the owner answers `AlreadyMember`, and the session's shard
    /// deduplicates and caps the list before routing.
    #[test]
    fn a_rejoin_across_shards_is_silent_and_names_is_served_once() {
        let (rejoin, names) = rejoin_and_names_answer(Shards::new());
        assert!(rejoin.is_empty(), "a rejoin replays nothing: {rejoin:#?}");
        assert_eq!(lines_with(&names, " 353 ").len(), 1, "{names:#?}");
        assert_eq!(lines_with(&names, " 366 ").len(), 1, "{names:#?}");
        MONO_NOW.with(|now| now.set(0));
        let on_one_worker = rejoin_and_names_answer(Shards::on_one_worker());
        assert_eq!(
            (rejoin.len(), names.len()),
            (on_one_worker.0.len(), on_one_worker.1.len()),
            "the answer on two workers is the answer on one"
        );
    }

    /// Two operators, one per shard.
    fn operators_on_each_shard(mut shards: Shards) -> Shards {
        shards.client(2, "alice", "");
        shards.client(1, "bob", "");
        for conn in [2, 1] {
            shards.line(conn, "OPER root secret");
            shards.drain(conn);
        }
        shards
    }

    fn server_ban_notices<'a>(out: &'a [String], change: &str) -> Vec<&'a str> {
        lines_with(
            out,
            &format!("Notice -- alice {change} K-Line for bad@host.example"),
        )
    }

    /// A server ban is one event, whichever shard commits it: every operator
    /// hears of it once, not once per shard that reconciled its hot list.
    #[test]
    fn a_server_ban_is_announced_to_each_operator_once() {
        let mut shards = operators_on_each_shard(Shards::new());
        shards.line(2, "KLINE bad@host.example :spam");
        for conn in [2, 1] {
            let out = shards.drain(conn);
            assert_eq!(
                server_ban_notices(&out, "added").len(),
                1,
                "connection {conn}: {out:#?}"
            );
        }
        assert!(
            shards
                .cores
                .iter()
                .all(|core| core.state.server_bans.len() == 1),
            "every shard enforces the ban"
        );
        shards.line(2, "UNKLINE bad@host.example");
        for conn in [2, 1] {
            let out = shards.drain(conn);
            assert_eq!(
                server_ban_notices(&out, "removed").len(),
                1,
                "connection {conn}: {out:#?}"
            );
        }
        assert!(
            shards
                .cores
                .iter()
                .all(|core| core.state.server_bans.is_empty()),
            "every shard stopped enforcing the ban"
        );
    }

    /// A temporary ban lapses on every shard on the same tick, and each
    /// operator hears of it once — from the shard its own session lives on.
    #[test]
    fn a_temporary_server_ban_lapses_on_every_shard() {
        let mut shards = operators_on_each_shard(Shards::new());
        shards.line(2, "KLINE 1 bad@host.example :spam");
        for conn in [2, 1] {
            shards.drain(conn);
        }
        assert!(
            shards
                .cores
                .iter()
                .all(|core| core.state.server_bans.len() == 1),
            "every shard enforces the ban"
        );
        Shards::advance_clock(60);
        let now = thread_mono_clock();
        for core in &mut shards.cores {
            core.handle(Input::Tick { now });
        }
        shards.settle();
        for conn in [2, 1] {
            let out = shards.drain(conn);
            assert_eq!(
                lines_with(&out, "Temporary K-Line for bad@host.example expired").len(),
                1,
                "connection {conn}: {out:#?}"
            );
        }
        assert!(
            shards
                .cores
                .iter()
                .all(|core| core.state.server_bans.is_empty()),
            "every shard stopped enforcing the ban"
        );
    }

    /// Answer the one server-ban mutation alice's shard queued.
    fn answer_server_ban(shards: &mut Shards, result: super::ServerBanResult) {
        let shard = shards.shard_of(2);
        let (mutation, requester) = shards.database_request(shard, |request| match request {
            super::DbRequest::MutateServerBan {
                mutation,
                requester,
            } => Some((mutation, requester)),
            _ => None,
        });
        shards.cores[shard].handle(Input::ServerBanResult {
            mutation,
            requester,
            result,
        });
        shards.settle();
    }

    /// A removal the database could not find still makes every shard stop
    /// enforcing the ban, but there is nothing to announce: the requester was
    /// told there was no stored ban, and no other operator is told a ban was
    /// removed.
    #[test]
    fn a_removal_that_found_no_stored_ban_reconciles_without_an_announcement() {
        let mut shards = operators_on_each_shard(Shards::with_database());
        shards.line(2, "KLINE bad@host.example :spam");
        answer_server_ban(&mut shards, super::ServerBanResult::Stored);
        for conn in [2, 1] {
            let out = shards.drain(conn);
            assert_eq!(
                server_ban_notices(&out, "added").len(),
                1,
                "connection {conn}: {out:#?}"
            );
        }
        shards.line(2, "UNKLINE bad@host.example");
        answer_server_ban(&mut shards, super::ServerBanResult::Missing);
        let out = shards.drain(2);
        assert_eq!(
            lines_with(&out, "No stored K-Line for bad@host.example").len(),
            1,
            "{out:#?}"
        );
        assert!(
            server_ban_notices(&out, "removed").is_empty(),
            "alice: {out:#?}"
        );
        let out = shards.drain(1);
        assert!(
            server_ban_notices(&out, "removed").is_empty(),
            "bob: {out:#?}"
        );
        assert!(
            shards
                .cores
                .iter()
                .all(|core| core.state.server_bans.is_empty()),
            "every shard stopped enforcing the ban the database does not hold"
        );
    }

    /// Shutdown is a drain: a shard that has told its clients goodbye still
    /// serves what the other shards send it. None of that may reach a client
    /// after its closing ERROR — the ERROR is the last line of the connection.
    #[test]
    fn nothing_is_written_to_a_session_after_its_closing_error() {
        let mut shards = alice_and_bob("");
        let there = shards.owned[1];
        for conn in [2, 1] {
            shards.line(conn, &format!("JOIN {there}"));
        }
        shards.drain(1);
        // bob's shard is told to stop first; alice's is still serving.
        shards.cores[1].handle(Input::Shutdown);
        shards.line(2, &format!("PRIVMSG {there} :are you still there?"));
        shards.line(2, "PRIVMSG bob :hello?");
        shards.line(2, "QUIT :bye");
        let out = shards.drain(1);
        assert_eq!(
            out,
            ["ERROR :Closing Link: irc.test (Server shutting down)"],
            "the closing ERROR must be the last thing the connection is sent"
        );
    }

    /// A change a user makes while its JOIN is on the way to another shard
    /// reaches the member that JOIN creates: the channel's owner admitted it
    /// from the snapshot the JOIN carried, and without the update it kept the
    /// old nick, away state and real name for good.
    #[test]
    fn a_change_made_during_a_remote_join_reaches_the_new_member() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(1, "bob", "away-notify setname");
        shards.line(1, &format!("JOIN {there}"));
        shards.client(2, "alice", "");
        shards.drain(1);
        // All three before the owner has answered the JOIN.
        shards.push_line(2, &format!("JOIN {there}"));
        shards.push_line(2, "NICK alicia");
        shards.push_line(2, "AWAY :gone");
        shards.settle();
        let out = shards.drain(1);
        let join_at = out
            .iter()
            .position(|l| l.contains(&format!(" JOIN {there}")));
        let nick_at = out
            .iter()
            .position(|l| l.contains(" NICK ") && l.ends_with("alicia"));
        assert!(
            join_at.is_some() && join_at < nick_at,
            "bob sees the JOIN, then the NICK: {out:#?}"
        );
        assert_eq!(lines_with(&out, " AWAY :gone").len(), 1, "{out:#?}");
        shards.line(1, &format!("NAMES {there}"));
        let names = shards.drain(1);
        assert_eq!(lines_with(&names, "alicia").len(), 1, "{names:#?}");
        let key = shards.cores[1].state.chan_key(there);
        let (_, _, identity, profile) = shards.cores[1].state.channels[&key]
            .member_profiles()
            .find(|(conn, ..)| *conn == ConnId(2))
            .expect("alicia is a member");
        assert_eq!(identity.nick, "alicia");
        assert!(profile.away, "the owner holds the away state");
    }

    /// A NICK while a JOIN is in flight to a shard that then refuses it tells
    /// that channel's members nothing: the user never shared it with them.
    #[test]
    fn a_change_made_during_a_refused_remote_join_is_not_told_to_its_members() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(1, "bob", "");
        shards.line(1, &format!("JOIN {there}"));
        shards.line(1, &format!("MODE {there} +i"));
        shards.client(2, "alice", "");
        shards.drain(1);
        shards.push_line(2, &format!("JOIN {there}"));
        shards.push_line(2, "NICK alicia");
        shards.settle();
        assert!(lines_with(&shards.drain(1), "alicia").is_empty());
        assert_eq!(lines_with(&shards.drain(2), " 473 ").len(), 1);
    }

    /// `JOIN 0` parts every channel, whichever shard owns it — and a JOIN
    /// still in flight when it was sent is parted once it is answered, so the
    /// user ends up in no channel, as the client asked, on two workers as on
    /// one.
    #[test]
    fn join_zero_parts_remote_and_in_flight_channels() {
        for mut shards in [Shards::new(), Shards::on_one_worker()] {
            let [here, there] = shards.owned;
            shards.client(1, "bob", "");
            shards.line(1, &format!("JOIN {here},{there}"));
            shards.client(2, "alice", "");
            shards.line(2, &format!("JOIN {here},{there}"));
            shards.drain(1);
            shards.drain(2);
            shards.line(2, "JOIN 0");
            let out = shards.drain(2);
            for channel in [here, there] {
                assert_eq!(
                    lines_with(&out, &format!(" PART {channel}")).len(),
                    1,
                    "{out:#?}"
                );
            }
            shards.drain(1);

            shards.push_line(2, &format!("JOIN {there}"));
            shards.push_line(2, "JOIN 0");
            shards.settle();
            let out = shards.drain(2);
            let join_at = out
                .iter()
                .position(|l| l.contains(&format!(" JOIN {there}")));
            let part_at = out
                .iter()
                .position(|l| l.contains(&format!(" PART {there}")));
            assert!(
                join_at.is_some() && join_at < part_at,
                "the JOIN, then its PART: {out:#?}"
            );
            shards.drain(1);
            shards.line(1, &format!("NAMES {there}"));
            let names = shards.drain(1);
            assert!(lines_with(&names, "alice").is_empty(), "{names:#?}");
        }
    }

    #[test]
    fn a_join_that_outlives_its_session_leaves_no_member_behind() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(2, "alice", "");
        // The JOIN is on its way to the owner when the connection drops.
        shards.cores[0].handle(Input::Line {
            conn: ConnId(2),
            line: format!("JOIN {there}").into_bytes(),
        });
        shards.cores[0].handle(Input::Closed {
            conn: ConnId(2),
            reason: "Connection reset".into(),
        });
        shards.settle();
        let key = shards.cores[1].state.chan_key(there);
        assert!(
            shards.cores[1].state.channels.get(&key).is_none(),
            "the channel is held open by a member whose session is gone"
        );
    }

    /// Four hundred channels, `#room000` on, spread over both shards: two
    /// members on shard 0 hold two hundred each (the channel limit is 250).
    /// The lister is connection 1, on shard 1.
    fn four_hundred_channels() -> Shards {
        let mut shards = Shards::new();
        shards.client(2, "member", "");
        shards.client(4, "other", "");
        for room in 0..400 {
            let member = if room < 200 { 2 } else { 4 };
            shards.line(member, &format!("JOIN #room{room:03}"));
            shards.drain(member);
        }
        shards.client(1, "lister", "");
        shards
    }

    /// The channels of `out`'s `RPL_LIST` rows, in order.
    fn listed(out: &[String]) -> Vec<String> {
        out.iter()
            .filter(|line| line.split(' ').nth(1) == Some("322"))
            .map(|line| line.split(' ').nth(3).expect("channel").to_string())
            .collect()
    }

    /// Pace the lister's LIST to its end, reading everything it is sent.
    fn read_list_to_the_end(shards: &mut Shards, mut out: Vec<String>) -> Vec<String> {
        while !out.iter().any(|line| line.contains(" 323 ")) {
            shards.cores[1].handle(Input::PaceReplies);
            shards.settle();
            let more = shards.drain(1);
            assert!(!more.is_empty(), "a paced LIST makes progress: {out:#?}");
            out.extend(more);
        }
        out
    }

    /// Rows a LIST holds on its session, waiting to be sent.
    fn held_rows(shards: &Shards) -> usize {
        shards.cores[1].state.sessions[&ConnId(1)]
            .channel_list
            .as_ref()
            .expect("a LIST in progress")
            .held_rows()
    }

    /// A LIST keeps a cursor, not a copy: what its session holds is at most a
    /// page — the room its send queue had — however many channels there are,
    /// and the rows of both shards still come out whole, merged in order.
    #[test]
    fn a_list_holds_at_most_a_page_and_is_complete_and_ordered_across_shards() {
        let mut shards = four_hundred_channels();
        shards.line(1, "LIST");
        let first = shards.drain(1);
        // The client's queue holds 256 lines: half of it goes at once, the
        // reply's start and 127 rows.
        assert_eq!(listed(&first).len(), 127, "{first:#?}");
        assert!(
            held_rows(&shards) <= 128,
            "a page, not the channel list: {}",
            held_rows(&shards)
        );
        let out = read_list_to_the_end(&mut shards, first);
        let expected: Vec<String> = (0..400).map(|room| format!("#room{room:03}")).collect();
        assert_eq!(listed(&out), expected);
        assert!(
            shards.cores[1].state.sessions[&ConnId(1)]
                .channel_list
                .is_none()
        );
    }

    /// A channel is listed if it exists when the LIST's cursor reaches its
    /// name: one created past the cursor is, one removed before it is reached
    /// is not, and one created behind the cursor is not. None is listed twice.
    #[test]
    fn channels_created_or_removed_during_a_list_are_listed_as_the_cursor_finds_them() {
        let mut shards = four_hundred_channels();
        shards.line(1, "LIST");
        let first = shards.drain(1);
        assert_eq!(listed(&first).last().map(String::as_str), Some("#room126"));
        // Behind the cursor, ahead of it, and removed ahead of it.
        shards.line(2, "JOIN #room000a");
        shards.line(2, "JOIN #room999");
        shards.line(4, "PART #room390");
        shards.drain(2);
        shards.drain(4);
        let out = read_list_to_the_end(&mut shards, first);
        let mut expected: Vec<String> = (0..400)
            .filter(|room| *room != 390)
            .map(|room| format!("#room{room:03}"))
            .collect();
        expected.push("#room999".into());
        assert_eq!(listed(&out), expected);
    }

    /// A LIST sent while another's page is still on its way from the other
    /// shard aborts that one at once; the page, when it lands, finds no LIST
    /// to join and is dropped, and nothing more of the aborted one is sent.
    #[test]
    fn a_list_during_a_cross_shard_list_aborts_it_before_its_pages_are_in() {
        let mut shards = four_hundred_channels();
        shards.push_line(1, "LIST");
        shards.push_line(1, "LIST");
        let out = shards.drain(1);
        assert!(out[0].contains(" 321 lister "), "{out:#?}");
        assert!(
            out.ends_with(&[
                ":irc.test NOTICE lister :/LIST aborted".to_string(),
                ":irc.test 323 lister :End of /LIST".to_string(),
            ]),
            "{out:#?}"
        );
        assert!(
            listed(&out).is_empty(),
            "no row can go before every shard's first page: {out:#?}"
        );
        shards.settle();
        shards.cores[1].handle(Input::PaceReplies);
        shards.settle();
        assert!(shards.drain(1).is_empty());
        assert!(
            shards.cores[1].state.sessions[&ConnId(1)]
                .channel_list
                .is_none()
        );
        shards.line(1, "LIST #room001");
        assert_eq!(listed(&shards.drain(1)), ["#room001"]);
    }

    /// A WHO or LIST answered by another shard after the asking connection
    /// closed finds no session to send to or pace for: the answer goes with
    /// the session, and the shard goes on serving everyone else.
    #[test]
    fn a_remote_who_or_list_answered_after_its_session_closed_is_dropped() {
        let mut shards = Shards::new();
        let here = shards.owned[0];
        shards.client(2, "alice", "");
        shards.line(2, &format!("JOIN {here}"));
        shards.client(1, "bob", "batch labeled-response");
        shards.push_line(1, &format!("WHO {here}"));
        shards.push_line(1, &format!("@label=w1 WHO {here}"));
        shards.push_line(1, "LIST");
        shards.cores[1].handle(Input::Closed {
            conn: ConnId(1),
            reason: "Connection reset".into(),
        });
        shards.settle();
        assert!(
            shards.cores[1].state.pacing.is_empty(),
            "nothing is paced to a connection that is gone"
        );
        shards.client(3, "carol", "");
        shards.line(3, &format!("WHO {here}"));
        let out = shards.drain(3);
        assert_eq!(lines_with(&out, " 352 ").len(), 1, "{out:#?}");
        assert_eq!(lines_with(&out, " 315 ").len(), 1, "{out:#?}");
    }

    /// Two JOINs to one channel on another shard, the first refused: the
    /// channel is still in flight until the second is answered, so a NICK
    /// sent between the two answers still reaches the owner that admits it.
    #[test]
    fn a_second_join_in_flight_to_one_channel_still_hears_member_updates() {
        let mut shards = Shards::new();
        let there = shards.owned[1];
        shards.client(1, "bob", "");
        shards.line(1, &format!("JOIN {there}"));
        shards.line(1, &format!("MODE {there} +k sekrit"));
        shards.client(2, "alice", "");
        shards.drain(1);
        shards.push_line(2, &format!("JOIN {there} wrong"));
        shards.push_line(2, &format!("JOIN {there} sekrit"));
        for super::Routed { to, input } in shards.cores[0].take_effects() {
            shards.cores[to.0].handle(input);
        }
        let mut answers = shards.cores[1].take_effects().into_iter();
        let refused = answers.next().expect("the first JOIN is answered");
        assert!(
            matches!(refused.input, Input::ChannelJoinResult { .. }),
            "the refusal comes first: {:?}",
            refused.input
        );
        shards.cores[refused.to.0].handle(refused.input);
        // The refusal is in; the second JOIN is not answered yet.
        shards.push_line(2, "NICK alicia");
        for super::Routed { to, input } in answers {
            shards.cores[to.0].handle(input);
        }
        shards.settle();
        let out = shards.drain(1);
        assert_eq!(
            lines_with(&out, " NICK ")
                .iter()
                .filter(|l| l.ends_with("alicia"))
                .count(),
            1,
            "bob hears the NICK: {out:#?}"
        );
        let key = shards.cores[1].state.chan_key(there);
        let (_, _, identity, _) = shards.cores[1].state.channels[&key]
            .member_profiles()
            .find(|(conn, ..)| *conn == ConnId(2))
            .expect("alicia is a member");
        assert_eq!(identity.nick, "alicia", "the owner holds the new nick");
    }

    /// `JOIN #c wrong; JOIN #c right; JOIN 0`: the refused JOIN admitted
    /// nothing, so it is the admitted one the `JOIN 0` parts — the user ends
    /// in no channel, on two workers as on one.
    #[test]
    fn join_zero_parts_the_join_that_was_admitted_not_the_first_answered() {
        for mut shards in [Shards::new(), Shards::on_one_worker()] {
            let there = shards.owned[1];
            shards.client(1, "bob", "");
            shards.line(1, &format!("JOIN {there}"));
            shards.line(1, &format!("MODE {there} +k sekrit"));
            shards.client(2, "alice", "");
            shards.drain(1);
            shards.push_line(2, &format!("JOIN {there} wrong"));
            shards.push_line(2, &format!("JOIN {there} sekrit"));
            shards.push_line(2, "JOIN 0");
            shards.settle();
            let out = shards.drain(2);
            let join_at = out
                .iter()
                .position(|l| l.contains(&format!(" JOIN {there}")));
            let part_at = out
                .iter()
                .position(|l| l.contains(&format!(" PART {there}")));
            assert!(
                join_at.is_some() && join_at < part_at,
                "the JOIN, then its PART: {out:#?}"
            );
            shards.drain(1);
            shards.line(1, &format!("NAMES {there}"));
            let names = shards.drain(1);
            assert!(lines_with(&names, "alice").is_empty(), "{names:#?}");
            let session = &shards.cores[shards.shard_of(2)].state.sessions[&ConnId(2)];
            assert_eq!(session.joins_in_flight().count(), 0);
        }
    }

    /// Batch references name the shard that opened them; everything else a
    /// labeled response says must not depend on how many workers there are.
    fn without_batch_references(out: Vec<String>) -> Vec<String> {
        out.into_iter()
            .map(|line| {
                line.split(' ')
                    .map(|word| match word.find("batch=") {
                        Some(at) => format!("{}batch=*", &word[..at]),
                        None if word.starts_with('+') || word.starts_with('-') => {
                            if line.contains(" BATCH ") {
                                word[..1].to_string()
                            } else {
                                word.to_string()
                            }
                        }
                        None => word.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    /// What a labeled MODE, KICK or JOIN answers the operator who sent it —
    /// including its own copy of what the channel is told — is the same on
    /// one worker and on two, where the channel lives on another shard.
    fn labeled_channel_changes(mut shards: Shards, there: &str, registered: &str) -> Vec<String> {
        let folded = shards.cores[0]
            .state
            .chan_key(registered)
            .as_str()
            .to_string();
        for core in &mut shards.cores {
            core.preload_founders(vec![(folded.clone(), "nobody".into())]);
            core.preload_mlock(vec![(folded.clone(), "+m".into())])
                .expect("a valid mode lock");
        }
        shards.client(2, "alice", "batch labeled-response");
        shards.client(1, "bob", "");
        shards.client(3, "carol", "");
        shards.line(2, &format!("JOIN {there}"));
        shards.line(1, &format!("JOIN {there}"));
        shards.line(3, &format!("JOIN {there}"));
        shards.drain(2);
        let mut answers = Vec::new();
        for line in [
            format!("@label=m1 MODE {there} +v bob"),
            format!("@label=m2 MODE {there} +m-t"),
            format!("@label=m3 MODE {there} +o nobody"),
            format!("@label=k1 KICK {there} bob :out"),
            format!("@label=k2 KICK {there} carol,nobody"),
            format!("@label=j1 JOIN {registered}"),
        ] {
            shards.line(2, &line);
            answers.extend(without_batch_references(shards.drain(2)));
        }
        answers
    }

    #[test]
    fn labeled_mode_kick_and_join_answer_the_actor_alike_on_one_worker_and_two() {
        // Both channels live on the shard alice's session does not.
        let two = Shards::new();
        let there = two.owned[1];
        let registered = [
            "#registered",
            "#enrolled",
            "#recorded",
            "#listed",
            "#signed",
        ]
        .into_iter()
        .find(|name| two.cores[0].state.channel_owner(name).shard() == CoreShardId(1))
        .expect("a channel owned by the second shard");
        let one = labeled_channel_changes(Shards::on_one_worker(), there, registered);
        let two = labeled_channel_changes(two, there, registered);
        assert_eq!(one, two);
        for label in ["m1", "m2", "k1"] {
            let tagged = lines_with(&two, &format!("@label={label} "));
            assert_eq!(tagged.len(), 1, "{label}: {two:#?}");
            assert!(
                tagged[0].contains(" MODE ") || tagged[0].contains(" KICK "),
                "{label} is answered by the actor's own echo: {two:#?}"
            );
        }
        assert!(lines_with(&two, " ACK").is_empty(), "{two:#?}");
        let start = two
            .iter()
            .position(|l| l.contains("label=j1"))
            .expect("the JOIN is answered");
        let join_at = two[start..].iter().position(|l| l.contains(" JOIN #"));
        let lock_at = two[start..]
            .iter()
            .position(|l| l.contains(":ChanServ!ChanServ@services.irc.test MODE #"));
        assert!(
            join_at.is_some() && join_at < lock_at,
            "the joiner hears its JOIN, then the lock it brought about: {two:#?}"
        );
    }

    /// A labeled ChanServ VOICE of a channel on another shard answers with
    /// the requester's own copy of the MODE inside its labeled response, as
    /// on one worker.
    #[test]
    fn a_labeled_chanserv_voice_answers_alike_on_one_worker_and_two() {
        let answer = |mut shards: Shards, there: &str| {
            let folded = shards.cores[0].state.chan_key(there).as_str().to_string();
            for core in &mut shards.cores {
                core.preload_founders(vec![(folded.clone(), "alice".into())]);
            }
            shards.client(2, "alice", "batch labeled-response");
            identify_on(&mut shards, 2, "alice");
            shards.line(2, &format!("JOIN {there}"));
            shards.drain(2);
            shards.line(2, &format!("@label=v1 PRIVMSG ChanServ :VOICE {there}"));
            without_batch_references(shards.drain(2))
        };
        let two = Shards::with_database();
        let there = two.owned[1];
        let one = answer(Shards::build(1, true), there);
        let two = answer(two, there);
        assert_eq!(one, two);
        assert_eq!(lines_with(&two, "label=v1").len(), 1, "{two:#?}");
        assert_eq!(
            lines_with(&two, "@batch=* :ChanServ!ChanServ@services.irc.test MODE ").len(),
            1,
            "{two:#?}"
        );
    }

    fn single_core() -> Core {
        let (db, _db_rx) = queue(Config {
            name: "single-core-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        Core::new(core_config(), db)
    }

    fn unavailable_verdict_for(core: &Core, session: SessionOwner) -> Input {
        Input::ChannelServicePersisted {
            owner: core.state.channel_owner("#chat"),
            session,
            result: super::ChannelServicePersistence::AccessUnavailable {
                channel: "#chat".into(),
                display: "#chat".into(),
                label: None,
            },
        }
    }

    #[test]
    fn an_effect_for_this_shard_is_handled_inline_and_never_returned_for_routing() {
        let mut core = single_core();
        let (session, mut output_rx) = open_session_on_first(&mut core, "inline-effect-output");
        let verdict = unavailable_verdict_for(&core, session);
        core.handle(verdict);
        let output = output_rx
            .try_pop()
            .expect("the requester on this shard is answered by the same event");
        assert!(
            std::str::from_utf8(&output.payload.0)
                .expect("wire output")
                .contains("temporarily unavailable")
        );
        assert!(
            core.take_effects().is_empty(),
            "a worker was handed an effect addressed to its own queue"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_answers_a_verdict_for_its_own_session_while_its_queue_stays_full() {
        let (tx, rx) = queue(Config {
            name: "self-targeted-verdict",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let ingress = CoreIngress::single(tx.clone());
        let mut core = single_core();
        let (session, mut output_rx) = open_session_on_first(&mut core, "full-queue-output");
        let verdict = unavailable_verdict_for(&core, session);
        tx.push(verdict).await.expect("verdict queued");

        // A producer that refills the only slot the instant the worker frees
        // it: the queue is full whenever the worker finishes an event.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let filler = {
            let tx = tx.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // A full queue hands the event back; the loop offers it again.
                    drop(tx.try_push(Input::OverlongLine { conn: ConnId(99) }));
                }
            })
        };
        let worker = tokio::spawn(CoreWorker::new(core, rx, ingress.clone()).run());

        let output = next_output(&mut output_rx).await;
        assert!(
            std::str::from_utf8(&output.payload.0)
                .expect("wire output")
                .contains("temporarily unavailable")
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        filler.join().expect("filler thread");
        ingress.broadcast_shutdown().await.expect("worker alive");
        worker.await.expect("worker stops on shutdown");
    }

    #[tokio::test]
    async fn ingress_returns_the_rejected_event_when_its_owner_queue_is_closed() {
        let config = Config {
            name: "closed-ingress",
            capacity: 1,
            policy: Policy::Fifo,
        };
        let (sender, receiver) = queue(config);
        drop(receiver);
        let ingress = CoreIngress::single(sender);

        let rejected = ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"PING :preserved".to_vec(),
            })
            .await
            .expect_err("closed ingress must return the event");

        assert!(matches!(
            *rejected,
            Input::Line { conn: ConnId(1), line } if line == b"PING :preserved"
        ));
    }

    #[tokio::test]
    async fn ingress_backpressure_preserves_the_owner_queue_order() {
        let config = Config {
            name: "ingress-backpressure",
            capacity: 1,
            policy: Policy::Fifo,
        };
        let (first_tx, mut first_rx) = queue(config);
        let (second_tx, _second_rx) = queue(config);
        let ingress = CoreIngress::with_shards(first_tx, vec![second_tx]);
        ingress
            .push(Input::Line {
                conn: ConnId(2),
                line: b"PING :first".to_vec(),
            })
            .await
            .expect("first event queued");
        let second = ingress.push(Input::Line {
            conn: ConnId(2),
            line: b"PING :second".to_vec(),
        });
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut second)
                .await
                .is_err(),
            "a full owner queue must apply backpressure"
        );
        assert!(matches!(
            first_rx.pop().await.expect("first event").payload,
            Input::Line { line, .. } if line == b"PING :first"
        ));
        second
            .await
            .expect("second event queued after capacity frees");
        assert!(matches!(
            first_rx.pop().await.expect("second event").payload,
            Input::Line { line, .. } if line == b"PING :second"
        ));
    }

    #[tokio::test]
    async fn channel_commands_reach_their_channel_owner() {
        let config = Config {
            name: "channel-command-routing",
            capacity: 2,
            policy: Policy::Fifo,
        };
        let (first_tx, _first_rx) = queue(config);
        let (second_tx, mut second_rx) = queue(config);
        let ingress = CoreIngress::with_shards(first_tx, vec![second_tx]);
        let shards = CoreShardCount::new(NonZeroUsize::new(2).expect("two shards"));
        let (db_tx, _db_rx) = queue(Config {
            name: "channel-command-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let core = Core::with_telemetry_on_shard_with_directories(
            core_config(),
            db_tx,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(0),
            shards,
            ingress.directories(),
        );
        let target = ["#alpha", "#beta", "#gamma"]
            .into_iter()
            .find(|name| core.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a target owned by shard one");
        let command = ChannelCommand::new(
            core.state.channel_owner(target),
            ChannelActor {
                recipient: Recipient::new(
                    SessionOwner::new(ConnId(2), CoreShardId(0)),
                    Caps::default(),
                ),
                identity: MemberIdentity::new(
                    "requester".into(),
                    "requester!u@host.test".into(),
                    false,
                ),
                account: None,
                realname: "Requester".into(),
                away: None,
                bot: false,
                profile: ChannelMemberProfile {
                    user: "u".into(),
                    host: "host.test".into(),
                    real_ip: None,
                    realname: "Requester".into(),
                    account: None,
                    away: false,
                    oper: false,
                    bot: false,
                    last_active: crate::core::state::LastActive::new(mono_clock()),
                },
            },
            target.into(),
            ChannelCommandOperation::ChanServStatus {
                target_nick: "target".into(),
                change: crate::core::state::StatusChange::Op,
            },
            None,
        );

        ingress
            .push(Input::ChannelCommand { command })
            .await
            .expect("channel command routed");
        assert!(matches!(
            second_rx.pop().await.expect("channel owner event").payload,
            Input::ChannelCommand { command }
                if matches!(
                    command.operation(),
                    ChannelCommandOperation::ChanServStatus { .. }
                )
        ));
    }

    /// Read `rx` up to and including the line that ends with `end`.
    async fn output_until(rx: &mut Receiver<super::Output>, end: &str) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line =
                String::from_utf8(next_output(rx).await.payload.0.to_vec()).expect("utf8 output");
            let done = line.trim_end().ends_with(end);
            lines.push(line.trim_end().to_string());
            if done {
                return lines;
            }
        }
    }

    /// LIST's conditions reach the channels of every shard, and a reply larger
    /// than half the lister's send queue is paced out by the worker as the
    /// client reads it rather than overflowing the queue.
    #[tokio::test]
    async fn list_conditions_and_pacing_span_the_shards() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            first_tx,
            first_rx,
            second_tx,
            second_rx,
            ingress,
        } = two_worker_harness();
        // Four kilobytes: room for the registration burst, while a LIST of a
        // hundred and twenty rows of some thirty-five bytes needs several turns.
        let (alice_tx, mut alice_rx) = crate::core::send_queue("list-output", 4096);
        let (bob_tx, mut bob_rx) = crate::core::send_queue("list-output", 4096);
        first.state.open(
            ConnId(2),
            alice_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        second.state.open(
            ConnId(1),
            bob_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        for (core, conn, nick, rx) in [
            (&mut first, ConnId(2), "alice", &mut alice_rx),
            (&mut second, ConnId(1), "bob", &mut bob_rx),
        ] {
            for line in [format!("NICK {nick}"), format!("USER {nick} 0 * :{nick}")] {
                core.handle(Input::Line {
                    conn,
                    line: line.into_bytes(),
                });
                while rx.try_pop().is_some() {}
            }
        }
        // Sixty channels on each shard, more than the queue holds, and a
        // secret one.
        let on_shard = |shard: usize, count: usize| -> Vec<String> {
            (0..)
                .map(|index| format!("#room{index}"))
                .filter(|name| first.state.channel_owner(name).shard() == CoreShardId(shard))
                .take(count)
                .collect()
        };
        let mut rooms = on_shard(0, 60);
        rooms.extend(on_shard(1, 60));
        rooms.sort();
        let secret = (0..)
            .map(|index| format!("#secret{index}"))
            .find(|name| first.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a channel on shard one");
        let first_worker = tokio::spawn(CoreWorker::new(first, first_rx, ingress.clone()).run());
        let second_worker = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        let send = |tx: &Sender<Input>, conn: ConnId, line: &str| {
            tx.try_push(Input::Line {
                conn,
                line: line.as_bytes().to_vec(),
            })
            .expect("line queued");
        };
        for room in rooms.iter().chain([&secret]) {
            send(&second_tx, ConnId(1), &format!("JOIN {room}"));
            output_until(&mut bob_rx, ":End of /NAMES list").await;
        }
        send(&second_tx, ConnId(1), &format!("MODE {secret} +s"));
        output_until(&mut bob_rx, "+s").await;
        // A second member for the first room.
        send(&first_tx, ConnId(2), &format!("JOIN {}", rooms[0]));
        output_until(&mut alice_rx, ":End of /NAMES list").await;

        let listed = |lines: &[String]| -> Vec<String> {
            assert!(lines[0].contains(" 321 alice "), "{lines:#?}");
            lines
                .iter()
                .filter(|line| line.split(' ').nth(1) == Some("322"))
                .map(|line| line.split(' ').nth(3).expect("channel").to_string())
                .collect()
        };
        send(&first_tx, ConnId(2), "LIST");
        let everything = output_until(&mut alice_rx, ":End of /LIST").await;
        assert_eq!(listed(&everything), rooms, "{everything:#?}");
        send(&first_tx, ConnId(2), "LIST >1");
        let crowded = output_until(&mut alice_rx, ":End of /LIST").await;
        assert_eq!(listed(&crowded), [rooms[0].clone()]);
        let last = &rooms[119];
        send(&first_tx, ConnId(2), &format!("LIST #room*,!{last},<2"));
        let narrowed = output_until(&mut alice_rx, ":End of /LIST").await;
        assert_eq!(listed(&narrowed), rooms[1..119]);
        send(&first_tx, ConnId(2), "LIST #secret*");
        let hidden = output_until(&mut alice_rx, ":End of /LIST").await;
        assert!(listed(&hidden).is_empty(), "{hidden:#?}");
        // Its member lists it from the other shard.
        send(&second_tx, ConnId(1), "LIST #secret*");
        let shown = output_until(&mut bob_rx, ":End of /LIST").await;
        assert!(
            shown
                .iter()
                .any(|line| line.contains(&format!(" 322 bob {secret} 1 ")))
        );

        first_tx.try_push(Input::Shutdown).expect("stop first");
        second_tx.try_push(Input::Shutdown).expect("stop second");
        first_worker.await.expect("first worker");
        second_worker.await.expect("second worker");
    }

    /// A WHO of a channel another shard owns, larger than half the asker's
    /// send queue, is paced out on the asker's shard as it reads — plain, and
    /// labeled as one batch — rather than overflowing the queue.
    #[tokio::test]
    async fn a_remote_channel_who_is_paced_on_the_askers_shard() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            first_tx,
            first_rx,
            second_tx,
            second_rx,
            ingress,
        } = two_worker_harness();
        let crowd = (0..)
            .map(|index| format!("#crowd{index}"))
            .find(|name| first.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a channel on shard one");
        // Three kilobytes: room for the registration burst, while a WHO of
        // forty members at some eighty-five bytes a row needs several turns.
        let (alice_tx, mut alice_rx) = crate::core::send_queue("who-output", 3072);
        first.state.open(
            ConnId(2),
            alice_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        for line in [
            "CAP LS 302",
            "CAP REQ :batch labeled-response",
            "NICK alice",
            "USER alice 0 * :alice",
            "CAP END",
        ] {
            first.handle(Input::Line {
                conn: ConnId(2),
                line: line.as_bytes().to_vec(),
            });
            while alice_rx.try_pop().is_some() {}
        }
        let mut members = Vec::new();
        for index in 0..40 {
            let conn = ConnId(10 + index);
            let (tx, mut rx) = crate::core::send_queue("who-member-output", 128 * 512);
            second
                .state
                .open(conn, tx, "host.test".into(), ConnectionTransport::Tcp);
            for line in [
                format!("NICK member{index}"),
                format!("USER member{index} 0 * :member{index}"),
            ] {
                second.handle(Input::Line {
                    conn,
                    line: line.into_bytes(),
                });
                while rx.try_pop().is_some() {}
            }
            members.push((conn, rx));
        }
        let first_worker = tokio::spawn(CoreWorker::new(first, first_rx, ingress.clone()).run());
        let second_worker = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        let send = |tx: &Sender<Input>, conn: ConnId, line: &str| {
            tx.try_push(Input::Line {
                conn,
                line: line.as_bytes().to_vec(),
            })
            .expect("line queued");
        };
        for (conn, rx) in &mut members {
            send(&second_tx, *conn, &format!("JOIN {crowd}"));
            output_until(rx, ":End of /NAMES list").await;
        }
        send(&first_tx, ConnId(2), &format!("JOIN {crowd}"));
        output_until(&mut alice_rx, ":End of /NAMES list").await;

        let rows = |lines: &[String]| {
            lines
                .iter()
                .filter(|line| line.contains(&format!(" 352 alice {crowd} ")))
                .count()
        };
        send(&first_tx, ConnId(2), &format!("WHO {crowd}"));
        let plain = output_until(&mut alice_rx, ":End of /WHO list").await;
        assert_eq!(rows(&plain), 41, "{plain:#?}");
        assert_eq!(plain.len(), 42, "{plain:#?}");

        send(&first_tx, ConnId(2), &format!("@label=crowd WHO {crowd}"));
        let mut labeled = Vec::new();
        while !labeled
            .last()
            .is_some_and(|line: &String| line.contains(" BATCH -"))
        {
            let line = String::from_utf8(next_output(&mut alice_rx).await.payload.0.to_vec())
                .expect("utf8 output");
            labeled.push(line.trim_end().to_string());
        }
        assert!(
            labeled[0].starts_with("@label=crowd ") && labeled[0].contains(" BATCH +"),
            "{labeled:#?}"
        );
        assert_eq!(rows(&labeled), 41, "{labeled:#?}");
        assert!(
            labeled[1..labeled.len() - 1]
                .iter()
                .all(|line| line.starts_with("@batch=")),
            "{labeled:#?}"
        );
        send(&first_tx, ConnId(2), "PING after-who");
        output_until(&mut alice_rx, "after-who").await;

        first_tx.try_push(Input::Shutdown).expect("stop first");
        second_tx.try_push(Input::Shutdown).expect("stop second");
        first_worker.await.expect("first worker");
        second_worker.await.expect("second worker");
    }

    #[tokio::test]
    async fn remote_knock_runs_on_the_channel_owner() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            first_tx,
            first_rx,
            second_tx,
            second_rx,
            ingress,
        } = two_worker_harness();
        let (alice_tx, mut alice_rx) = crate::core::send_queue("remote-knock-output", 64 * 512);
        let (bob_tx, mut bob_rx) = crate::core::send_queue("remote-knock-output", 64 * 512);
        first.state.open(
            ConnId(2),
            alice_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        second.state.open(
            ConnId(1),
            bob_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        for (core, conn, nick) in [
            (&mut first, ConnId(2), "alice"),
            (&mut second, ConnId(1), "bob"),
        ] {
            core.handle(Input::Line {
                conn,
                line: format!("NICK {nick}").into_bytes(),
            });
            core.handle(Input::Line {
                conn,
                line: format!("USER {nick} 0 * :{nick}").into_bytes(),
            });
        }
        while alice_rx.try_pop().is_some() {}
        while bob_rx.try_pop().is_some() {}
        {
            let bob = second
                .state
                .sessions
                .get_mut(&ConnId(1))
                .expect("bob session");
            bob.caps.batch = true;
            bob.caps.chathistory = true;
        }
        let key = first.state.chan_key("#chat");
        assert_eq!(first.state.channel_owner("#chat").shard(), CoreShardId(0));
        let modes = ChanModes {
            invite_only: true,
            ..ChanModes::default()
        };
        let mut channel = Channel::for_test("#chat", modes);
        channel.add_member(
            Recipient::new(
                SessionOwner::new(ConnId(2), CoreShardId(0)),
                Caps::default(),
            ),
            MemberIdentity::new("alice".into(), "alice!alice@host.test".into(), false),
            MemberModes {
                op: true,
                voice: false,
            },
            e6irc_proto::time::MonoMillis::from_millis(1),
        );
        first.state.channels.entry(key).or_insert(channel);
        let other = ["#delta", "#echo", "#foxtrot"]
            .into_iter()
            .find(|name| second.state.channel_owner(name).shard() == CoreShardId(1))
            .expect("a channel owned by shard one");
        let other_key = second.state.chan_key(other);
        second
            .state
            .channels
            .entry(other_key)
            .or_insert(Channel::for_test(other, ChanModes::default()));
        let first_worker = tokio::spawn(CoreWorker::new(first, first_rx, ingress.clone()).run());
        let second_worker = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"KNOCK #chat".to_vec(),
            })
            .expect("knock queued");
        let operator = next_output(&mut alice_rx).await;
        assert!(
            operator
                .payload
                .0
                .ends_with(b" 710 #chat #chat bob!bob@host.test :has asked for an invite.\r\n")
        );
        let result = next_output(&mut bob_rx).await;
        assert!(
            result
                .payload
                .0
                .ends_with(b" 711 bob #chat :Your KNOCK has been delivered\r\n")
        );
        first_tx
            .try_push(Input::Line {
                conn: ConnId(2),
                line: b"INVITE bob #chat".to_vec(),
            })
            .expect("invite queued");
        let inviter = next_output(&mut alice_rx).await;
        assert!(inviter.payload.0.ends_with(b" 341 alice bob #chat\r\n"));
        let invitee = next_output(&mut bob_rx).await;
        assert!(
            invitee
                .payload
                .0
                .ends_with(b":alice!alice@host.test INVITE bob :#chat\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"JOIN #chat".to_vec(),
            })
            .expect("join queued");
        loop {
            let output = next_output(&mut bob_rx).await;
            if output
                .payload
                .0
                .ends_with(b" 366 bob #chat :End of /NAMES list\r\n")
            {
                break;
            }
        }
        let joined = next_output(&mut alice_rx).await;
        assert!(
            joined
                .payload
                .0
                .ends_with(b":bob!bob@host.test JOIN #chat\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"NICK robert".to_vec(),
            })
            .expect("nick queued");
        let renamed_self = next_output(&mut bob_rx).await;
        assert!(
            renamed_self
                .payload
                .0
                .ends_with(b":bob!bob@host.test NICK robert\r\n")
        );
        let renamed = next_output(&mut alice_rx).await;
        assert!(
            renamed
                .payload
                .0
                .ends_with(b":bob!bob@host.test NICK robert\r\n")
        );
        first_tx
            .try_push(Input::Line {
                conn: ConnId(2),
                line: b"MODE #chat +b bad!*@*".to_vec(),
            })
            .expect("mode change queued");
        let _ = next_output(&mut alice_rx).await;
        let _ = next_output(&mut bob_rx).await;
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"MODE #chat +b".to_vec(),
            })
            .expect("mode list queued");
        let ban = next_output(&mut bob_rx).await;
        // The row names who set the ban (the time is the wall clock's).
        let ban = String::from_utf8_lossy(&ban.payload.0).into_owned();
        assert!(
            ban.contains(" 367 robert #chat bad!*@* alice!alice@host.test "),
            "{ban}"
        );
        let end = next_output(&mut bob_rx).await;
        assert!(
            end.payload
                .0
                .ends_with(b" 368 robert #chat :End of Channel Ban List\r\n")
        );
        first_tx
            .try_push(Input::Line {
                conn: ConnId(2),
                line: b"MODE #chat +o robert".to_vec(),
            })
            .expect("grant operator queued");
        let _ = next_output(&mut alice_rx).await;
        let _ = next_output(&mut bob_rx).await;
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"MODE #chat +k".to_vec(),
            })
            .expect("remote mode error queued");
        let mode_error = next_output(&mut bob_rx).await;
        assert!(
            mode_error
                .payload
                .0
                .ends_with(b" 461 robert MODE :Not enough parameters\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"MODE #chat +m".to_vec(),
            })
            .expect("remote mode change queued");
        let changed = next_output(&mut bob_rx).await;
        assert!(
            changed
                .payload
                .0
                .ends_with(b":robert!bob@host.test MODE #chat +m\r\n")
        );
        let observed = next_output(&mut alice_rx).await;
        assert!(
            observed
                .payload
                .0
                .ends_with(b":robert!bob@host.test MODE #chat +m\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"NAMES #chat".to_vec(),
            })
            .expect("remote names queued");
        let names = next_output(&mut bob_rx).await;
        assert!(
            names
                .payload
                .0
                .ends_with(b" 353 robert = #chat :@alice @robert\r\n")
        );
        let end = next_output(&mut bob_rx).await;
        assert!(
            end.payload
                .0
                .ends_with(b" 366 robert #chat :End of /NAMES list\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"AWAY :testing".to_vec(),
            })
            .expect("remote away queued");
        let away = next_output(&mut bob_rx).await;
        assert!(
            away.payload
                .0
                .ends_with(b" 306 robert :You have been marked as being away\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"WHO #chat".to_vec(),
            })
            .expect("remote who queued");
        let first_who = next_output(&mut bob_rx).await;
        let second_who = next_output(&mut bob_rx).await;
        let who_end = next_output(&mut bob_rx).await;
        let who_rows = [first_who.payload.0, second_who.payload.0];
        assert!(who_rows.iter().any(|line| {
            line.ends_with(b" 352 robert #chat alice host.test irc.test alice H@ :0 alice\r\n")
        }));
        assert!(who_rows.iter().any(|line| {
            line.ends_with(b" 352 robert #chat bob host.test irc.test robert G@ :0 bob\r\n")
        }));
        assert!(
            who_end
                .payload
                .0
                .ends_with(b" 315 robert #chat :End of /WHO list\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"PRIVMSG #chat :historic".to_vec(),
            })
            .expect("remote history message queued");
        let historic = next_output(&mut alice_rx).await;
        assert!(historic.payload.0.ends_with(b"PRIVMSG #chat :historic\r\n"));
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"CHATHISTORY LATEST #chat * 1".to_vec(),
            })
            .expect("remote chathistory queued");
        let history = [
            next_output(&mut bob_rx).await,
            next_output(&mut bob_rx).await,
            next_output(&mut bob_rx).await,
        ];
        assert!(history.iter().any(|output| {
            output
                .payload
                .0
                .windows(17)
                .any(|part| part == b"chathistory #chat")
        }));
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"LIST #chat".to_vec(),
            })
            .expect("remote list queued");
        let list_start = next_output(&mut bob_rx).await;
        let list_row = next_output(&mut bob_rx).await;
        let list_end = next_output(&mut bob_rx).await;
        assert!(
            list_start
                .payload
                .0
                .ends_with(b" 321 robert Channel :Users  Name\r\n")
        );
        assert!(list_row.payload.0.ends_with(b" 322 robert #chat 2 :\r\n"));
        assert!(
            list_end
                .payload
                .0
                .ends_with(b" 323 robert :End of /LIST\r\n")
        );
        second_tx
            .try_push(Input::Line {
                conn: ConnId(1),
                line: b"LIST".to_vec(),
            })
            .expect("whole-network list queued");
        let list_start = next_output(&mut bob_rx).await;
        let first_row = next_output(&mut bob_rx).await;
        let second_row = next_output(&mut bob_rx).await;
        let list_end = next_output(&mut bob_rx).await;
        assert!(
            list_start
                .payload
                .0
                .ends_with(b" 321 robert Channel :Users  Name\r\n")
        );
        assert!(first_row.payload.0.ends_with(b" 322 robert #chat 2 :\r\n"));
        assert!(
            first_row
                .payload
                .0
                .ends_with(format!(" 322 robert {other} 0 :\r\n").as_bytes())
                || second_row
                    .payload
                    .0
                    .ends_with(format!(" 322 robert {other} 0 :\r\n").as_bytes())
        );
        assert!(
            first_row.payload.0.ends_with(b" 322 robert #chat 2 :\r\n")
                || second_row.payload.0.ends_with(b" 322 robert #chat 2 :\r\n")
        );
        assert!(
            list_end
                .payload
                .0
                .ends_with(b" 323 robert :End of /LIST\r\n")
        );
        first_tx.try_push(Input::Shutdown).expect("stop first");
        second_tx.try_push(Input::Shutdown).expect("stop second");
        first_worker.await.expect("first worker");
        second_worker.await.expect("second worker");
    }

    #[tokio::test]
    async fn remote_channel_message_reaches_the_destination_workers_sendq() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            first_tx,
            first_rx,
            second_tx: _,
            second_rx,
            ingress,
        } = two_worker_harness();
        let (out_tx, mut out_rx) = crate::core::send_queue("remote-member-sendq", 8 * 512);
        second.state.open(
            ConnId(1),
            out_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        let (sender_tx, _sender_rx) = crate::core::send_queue("local-member-sendq", 64 * 512);
        first.state.open(
            ConnId(2),
            sender_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        first.handle(Input::Line {
            conn: ConnId(2),
            line: b"NICK sender".to_vec(),
        });
        first.handle(Input::Line {
            conn: ConnId(2),
            line: b"USER sender 0 * :Sender".to_vec(),
        });
        let key = first.state.chan_key("#chat");
        let mut channel = Channel::for_test("#chat", ChanModes::default());
        channel.add_member(
            Recipient::new(
                SessionOwner::new(ConnId(1), CoreShardId(1)),
                Caps {
                    server_time: true,
                    extended_join: true,
                    ..Caps::default()
                },
            ),
            MemberIdentity::new("remote".into(), "remote!u@host.test".into(), false),
            MemberModes::default(),
            e6irc_proto::time::MonoMillis::from_millis(1),
        );
        first.state.channels.entry(key.clone()).or_insert(channel);
        first_tx
            .try_push(Input::Line {
                conn: ConnId(2),
                line: b"JOIN #chat".to_vec(),
            })
            .expect("queue source join");
        first_tx
            .try_push(Input::Line {
                conn: ConnId(2),
                line: b"PRIVMSG #chat :hello".to_vec(),
            })
            .expect("queue source message");
        let destination = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        let source = tokio::spawn(CoreWorker::new(first, first_rx, ingress.clone()).run());
        let join = out_rx.pop().await.expect("remote join delivered");
        assert!(join.payload.0.starts_with(b"@time="));
        assert!(join.payload.0.ends_with(b"JOIN #chat * :Sender\r\n"));
        let message = out_rx.pop().await.expect("remote message delivered");
        assert!(message.payload.0.starts_with(b"@time="));
        assert!(message.payload.0.ends_with(b"PRIVMSG #chat :hello\r\n"));
        ingress.broadcast_shutdown().await.expect("workers alive");
        source.await.expect("source worker");
        destination.await.expect("destination worker");
    }

    #[tokio::test]
    async fn remote_join_returns_to_the_session_owner() {
        let TwoWorkerHarness {
            mut first,
            mut second,
            first_tx,
            first_rx,
            second_tx,
            second_rx,
            ingress,
        } = two_worker_harness();
        assert_eq!(first.state.channel_owner("#chat").shard(), CoreShardId(0));

        let (peer_tx, mut peer_rx) = crate::core::send_queue("join-peer-sendq", 8 * 512);
        first.state.open(
            ConnId(2),
            peer_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        let key = first.state.chan_key("#chat");
        let mut channel = Channel::for_test("#chat", ChanModes::default());
        channel.add_member(
            Recipient::new(
                SessionOwner::new(ConnId(2), CoreShardId(0)),
                Caps {
                    message_tags: true,
                    ..Caps::default()
                },
            ),
            MemberIdentity::new("peer".into(), "peer!u@host.test".into(), false),
            MemberModes::default(),
            e6irc_proto::time::MonoMillis::from_millis(1),
        );
        first.state.channels.entry(key).or_insert(channel);

        let (joiner_tx, mut joiner_rx) = crate::core::send_queue("joiner-sendq", 16 * 512);
        second.state.open(
            ConnId(1),
            joiner_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        second.handle(Input::Line {
            conn: ConnId(1),
            line: b"NICK joiner".to_vec(),
        });
        second.handle(Input::Line {
            conn: ConnId(1),
            line: b"USER joiner 0 * :Joiner".to_vec(),
        });
        second
            .state
            .sessions
            .get_mut(&ConnId(1))
            .expect("joiner session")
            .caps
            .labeled_response = true;
        second
            .state
            .sessions
            .get_mut(&ConnId(1))
            .expect("joiner session")
            .caps
            .echo_message = true;
        second
            .state
            .sessions
            .get_mut(&ConnId(1))
            .expect("joiner session")
            .caps
            .message_tags = true;
        second
            .state
            .sessions
            .get_mut(&ConnId(1))
            .expect("joiner session")
            .caps
            .batch = true;
        second
            .state
            .sessions
            .get_mut(&ConnId(1))
            .expect("joiner session")
            .caps
            .multiline = true;
        while joiner_rx.try_pop().is_some() {}

        let first_worker = tokio::spawn(CoreWorker::new(first, first_rx, ingress.clone()).run());
        let second_worker = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=join JOIN #chat".to_vec(),
            })
            .await
            .expect("queue join");

        let peer = peer_rx.pop().await.expect("peer receives JOIN");
        assert!(
            peer.payload
                .0
                .ends_with(b":joiner!joiner@host.test JOIN #chat\r\n")
        );
        let batch = joiner_rx
            .pop()
            .await
            .expect("joiner receives labeled batch");
        assert!(
            batch
                .payload
                .0
                .starts_with(b"@label=join :irc.test BATCH +")
        );
        let join = joiner_rx.pop().await.expect("joiner receives own JOIN");
        assert!(
            join.payload
                .0
                .ends_with(b":joiner!joiner@host.test JOIN #chat\r\n")
        );
        let names = joiner_rx.pop().await.expect("joiner receives NAMES");
        assert!(
            names
                .payload
                .0
                .ends_with(b" 353 joiner = #chat :joiner peer\r\n")
        );
        let end_names = joiner_rx.pop().await.expect("joiner receives end of NAMES");
        assert!(
            end_names
                .payload
                .0
                .windows(b" 366 joiner #chat ".len())
                .any(|window| window == b" 366 joiner #chat ")
        );
        let close = joiner_rx.pop().await.expect("joiner closes labeled batch");
        assert!(close.payload.0.starts_with(b":irc.test BATCH -"));

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"TOPIC #chat".to_vec(),
            })
            .await
            .expect("queue cross-shard TOPIC query");
        let topic = joiner_rx.pop().await.expect("joiner receives TOPIC result");
        assert!(
            topic
                .payload
                .0
                .ends_with(b" 331 joiner #chat :No topic is set\r\n")
        );

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=message PRIVMSG #chat :hello".to_vec(),
            })
            .await
            .expect("queue cross-shard message");
        let message = peer_rx.pop().await.expect("peer receives channel message");
        assert!(
            message
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test PRIVMSG #chat :hello\r\n")
        );
        let echo = joiner_rx.pop().await.expect("joiner receives labeled echo");
        assert!(echo.payload.0.starts_with(b"@label=message;msgid="));
        assert!(
            echo.payload
                .0
                .ends_with(b":joiner!joiner@host.test PRIVMSG #chat :hello\r\n")
        );

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=multi BATCH +m draft/multiline #chat".to_vec(),
            })
            .await
            .expect("open cross-shard multiline");
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@batch=m PRIVMSG #chat :one".to_vec(),
            })
            .await
            .expect("collect cross-shard multiline");
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"BATCH -m".to_vec(),
            })
            .await
            .expect("close cross-shard multiline");
        let multiline_peer = peer_rx
            .pop()
            .await
            .expect("peer receives flattened multiline");
        assert!(
            multiline_peer
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test PRIVMSG #chat :one\r\n")
        );
        let multiline_open = joiner_rx
            .pop()
            .await
            .expect("joiner receives multiline open");
        assert!(multiline_open.payload.0.starts_with(b"@label=multi;msgid="));
        assert!(
            multiline_open
                .payload
                .0
                .windows(b" BATCH +".len())
                .any(|part| part == b" BATCH +")
        );
        let multiline_line = joiner_rx
            .pop()
            .await
            .expect("joiner receives multiline line");
        assert!(
            multiline_line
                .payload
                .0
                .ends_with(b" PRIVMSG #chat :one\r\n")
        );
        let multiline_close = joiner_rx
            .pop()
            .await
            .expect("joiner receives multiline close");
        assert!(multiline_close.payload.0.starts_with(b":irc.test BATCH -"));

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"CAP REQ :-echo-message".to_vec(),
            })
            .await
            .expect("disable echo-message");
        let cap_ack = joiner_rx.pop().await.expect("echo-message CAP ACK");
        assert!(
            cap_ack
                .payload
                .0
                .ends_with(b" CAP joiner ACK :-echo-message\r\n")
        );
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=noecho BATCH +n draft/multiline #chat".to_vec(),
            })
            .await
            .expect("open no-echo multiline");
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@batch=n PRIVMSG #chat :two".to_vec(),
            })
            .await
            .expect("collect no-echo multiline");
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"BATCH -n".to_vec(),
            })
            .await
            .expect("close no-echo multiline");
        let noecho_peer = peer_rx
            .pop()
            .await
            .expect("peer receives no-echo multiline");
        assert!(
            noecho_peer
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test PRIVMSG #chat :two\r\n")
        );
        let noecho_ack = joiner_rx
            .pop()
            .await
            .expect("opening label is acknowledged");
        assert!(
            noecho_ack
                .payload
                .0
                .starts_with(b"@label=noecho :irc.test ACK\r\n")
        );
        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"CAP REQ :echo-message".to_vec(),
            })
            .await
            .expect("restore echo-message");
        joiner_rx.pop().await.expect("echo-message CAP ACK");

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=tag;+typing=active TAGMSG #chat".to_vec(),
            })
            .await
            .expect("queue cross-shard TAGMSG");
        let tagmsg = peer_rx.pop().await.expect("peer receives channel TAGMSG");
        assert!(tagmsg.payload.0.starts_with(b"@msgid="));
        assert!(
            tagmsg
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test TAGMSG #chat\r\n")
        );
        let tag_echo = joiner_rx
            .pop()
            .await
            .expect("joiner receives labeled TAGMSG echo");
        assert!(tag_echo.payload.0.starts_with(b"@label=tag;msgid="));
        assert!(
            tag_echo
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test TAGMSG #chat\r\n")
        );

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"@label=part PART #chat :bye".to_vec(),
            })
            .await
            .expect("queue part");
        let peer_part = peer_rx.pop().await.expect("peer receives PART");
        assert!(
            peer_part
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test PART #chat :bye\r\n")
        );
        let part = joiner_rx.pop().await.expect("joiner receives labeled PART");
        assert!(
            part.payload
                .0
                .starts_with(b"@label=part :joiner!joiner@host.test PART #chat :bye")
        );

        ingress
            .push(Input::Line {
                conn: ConnId(1),
                line: b"JOIN #chat".to_vec(),
            })
            .await
            .expect("queue second join");
        let peer_rejoin = peer_rx.pop().await.expect("peer receives second JOIN");
        assert!(
            peer_rejoin
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test JOIN #chat\r\n")
        );
        let own_rejoin = joiner_rx.pop().await.expect("joiner receives second JOIN");
        assert!(
            own_rejoin
                .payload
                .0
                .ends_with(b":joiner!joiner@host.test JOIN #chat\r\n")
        );
        joiner_rx.pop().await.expect("joiner receives second NAMES");
        joiner_rx
            .pop()
            .await
            .expect("joiner receives second end of NAMES");

        ingress
            .push(Input::Closed {
                conn: ConnId(1),
                reason: "bye".into(),
            })
            .await
            .expect("queue close");
        let quit = peer_rx.pop().await.expect("peer receives remote QUIT");
        assert!(
            quit.payload
                .0
                .ends_with(b":joiner!joiner@host.test QUIT :bye\r\n")
        );

        first_tx.try_push(Input::Shutdown).expect("stop first");
        second_tx.try_push(Input::Shutdown).expect("stop second");
        first_worker.await.expect("first worker");
        second_worker.await.expect("second worker");
    }

    #[test]
    fn scheduler_round_robins_nonempty_shards_with_queue_sequences() {
        let (first, first_rx) = queue(Config {
            name: "scheduled-first",
            capacity: 2,
            policy: Policy::Fifo,
        });
        let (second, second_rx) = queue(Config {
            name: "scheduled-second",
            capacity: 2,
            policy: Policy::Fifo,
        });
        first.try_push(Input::Shutdown).expect("first event");
        second.try_push(Input::Shutdown).expect("second event");
        let mut scheduler = CoreScheduler::with_shards(first_rx, vec![second_rx]);

        let first = scheduler.try_step().expect("first scheduled event");
        let second = scheduler.try_step().expect("second scheduled event");
        assert_eq!(first.shard, CoreShardId(0));
        assert_eq!(second.shard, CoreShardId(1));
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 0);
    }

    #[tokio::test]
    async fn worker_delivers_events_to_its_own_shard() {
        let (db_tx, _db_rx) = queue(Config {
            name: "nonzero-core-shard-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let core = Core::with_telemetry_on_shard_with_directories(
            core_config(),
            db_tx,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(1),
            CoreShardCount::new(NonZeroUsize::new(2).expect("nonzero shard count")),
            CoreDirectories::default(),
        );
        let (tx, rx) = queue(Config {
            name: "nonzero-core-shard-input",
            capacity: 1,
            policy: Policy::Fifo,
        });
        tx.try_push(Input::Shutdown).expect("shutdown event queued");

        CoreWorker::new(core, rx, CoreIngress::single(tx))
            .run()
            .await;
    }

    #[test]
    fn scheduler_trace_replays_the_same_shard_sequences() {
        let (first, first_rx) = queue(Config {
            name: "trace-first",
            capacity: 2,
            policy: Policy::Fifo,
        });
        let (second, second_rx) = queue(Config {
            name: "trace-second",
            capacity: 2,
            policy: Policy::Fifo,
        });
        first.try_push(Input::Shutdown).expect("first event");
        second.try_push(Input::Shutdown).expect("second event");
        let mut recorded = CoreScheduler::with_shards(first_rx, vec![second_rx]);
        recorded.try_step().expect("first recorded event");
        recorded.try_step().expect("second recorded event");
        let trace = recorded.trace().steps().to_vec();

        let (first, first_rx) = queue(Config {
            name: "replay-first",
            capacity: 2,
            policy: Policy::Fifo,
        });
        let (second, second_rx) = queue(Config {
            name: "replay-second",
            capacity: 2,
            policy: Policy::Fifo,
        });
        first.try_push(Input::Shutdown).expect("first replay event");
        second
            .try_push(Input::Shutdown)
            .expect("second replay event");
        let mut replay = CoreScheduler::with_shards(first_rx, vec![second_rx]);

        for step in trace {
            let event = replay.replay_step(step).expect("replay event");
            assert_eq!(event.trace_step(), step);
        }
        assert!(matches!(
            replay.replay_step(CoreTraceStep {
                shard: CoreShardId(0),
                sequence: 1,
            }),
            Err(ReplayError::EventMissing)
        ));
    }
}
