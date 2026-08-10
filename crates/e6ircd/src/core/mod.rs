//! The IRC core: a single-threaded, share-nothing worker that owns all
//! chat state. Inputs arrive as events (from connection I/O tasks, via
//! `e6irc-queue`); outputs are pushed into per-connection send queues.
//! The worker itself is synchronous — `Core::handle` is a pure state
//! transition — which is what makes deterministic simulation and
//! step-debugging possible.
//!
//! Workers can run as N hash-sharded instances. Each instance owns its local
//! session state and its assigned channel state.

mod handler;
mod state;
mod timer;

pub(crate) use timer::TimerWheel;

pub use state::{ConnId, CoreConfig, dm_conversation_key};

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
#[cfg(test)]
use e6irc_queue::Envelope;
use e6irc_queue::{PushError, QueueMonitor, Receiver, Sender};
use state::{
    ChannelActor, ChannelCommand, ChannelCommandResult, ChannelJoinResult, ChannelKick,
    ChannelKickResult, ChannelListRequest, ChannelListResult, ChannelMemberUpdate, ChannelMessage,
    ChannelMessageResult, ChannelMultiline, ChannelMultilineResult, ChannelOwner,
    ChannelPartResult, ChannelQuit, ChannelTagmsg, ChannelTagmsgResult, ChannelTopic,
    ChannelTopicResult,
};
use state::{
    ChannelOptionsDirectory, FounderDirectory, MembershipDirectory, NickDirectory,
    RetainedTopicDirectory, ServerState,
};

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

    pub(crate) fn session_owner(self, conn: ConnId) -> SessionOwner {
        SessionOwner::new(conn, self.shard_for(conn))
    }

    pub(crate) fn shard_for_channel(self, key: &state::ChanKey) -> CoreShardId {
        let hash = key
            .as_str()
            .bytes()
            .fold(0xcbf29ce484222325u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            });
        CoreShardId((hash as usize) % self.0.get())
    }
}

/// Index of one configured core shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoreShardId(usize);

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

    pub(crate) fn shard(self) -> CoreShardId {
        self.shard
    }
}

/// The only ingress path into core state.
#[derive(Clone)]
pub struct CoreIngress {
    shards: Arc<[Sender<Input>]>,
    count: CoreShardCount,
    nicks: NickDirectory,
    memberships: MembershipDirectory,
    founders: FounderDirectory,
    topics: RetainedTopicDirectory,
    channel_options: ChannelOptionsDirectory,
}

impl CoreIngress {
    pub fn single(sender: Sender<Input>) -> Self {
        Self {
            shards: Arc::from([sender]),
            count: CoreShardCount::single(),
            nicks: NickDirectory::default(),
            memberships: MembershipDirectory::default(),
            founders: FounderDirectory::default(),
            topics: RetainedTopicDirectory::default(),
            channel_options: ChannelOptionsDirectory::default(),
        }
    }

    /// Build an ingress with a mandatory first shard.
    #[cfg(test)]
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
            nicks: NickDirectory::default(),
            memberships: MembershipDirectory::default(),
            founders: FounderDirectory::default(),
            topics: RetainedTopicDirectory::default(),
            channel_options: ChannelOptionsDirectory::default(),
        }
    }

    pub async fn push(&self, input: Input) -> Result<u64, Input> {
        let shard = match &input {
            Input::Open { conn, .. }
            | Input::Line { conn, .. }
            | Input::OverlongLine { conn }
            | Input::Closed { conn, .. }
            | Input::Delivery { conn, .. }
            | Input::DbReply { conn, .. }
            | Input::HistoryPage { conn, .. }
            | Input::TargetsPage { conn, .. } => self.count.session_owner(*conn).shard(),
            Input::ChannelJoin { owner, .. } => owner.shard(),
            Input::ChannelJoinResult { session, .. } => session.shard(),
            Input::ChannelPart { owner, .. } => owner.shard(),
            Input::ChannelPartResult { session, .. } => session.shard(),
            Input::ChannelQuit { quit } => quit.owner().shard(),
            Input::ChannelTopic { topic } => topic.owner().shard(),
            Input::ChannelTopicResult { session, .. } => session.shard(),
            Input::ChannelTopicPersisted { owner, .. } => owner.shard(),
            Input::ChannelCommand { command } => command.owner().shard(),
            Input::ChannelCommandResult { session, .. } => session.shard(),
            Input::ChannelListResult { result } => result.session.shard(),
            Input::ChannelList { .. } => panic!("whole-network LIST must be broadcast"),
            Input::ChannelSessionEvent { session, .. } => session.shard(),
            Input::ChannelMemberUpdate { update } => update.owner().shard(),
            Input::ChannelKick { kick } => kick.owner().shard(),
            Input::ChannelKickResult { session, .. } => session.shard(),
            Input::SessionChannelRemoved { session, .. } => session.shard(),
            Input::ChannelMessage { message } => message.owner().shard(),
            Input::ChannelMessageResult { session, .. } => session.shard(),
            Input::ChannelMultiline { message } => message.owner().shard(),
            Input::ChannelMultilineResult { session, .. } => session.shard(),
            Input::ChannelTagmsg { tagmsg } => tagmsg.owner().shard(),
            Input::ChannelTagmsgResult { session, .. } => session.shard(),
            Input::Tick { .. }
            | Input::Shutdown
            | Input::ChannelDropResult { .. }
            | Input::ServerBanResult { .. }
            | Input::Admin { .. } => CoreShardId(0),
            Input::ChannelControlResult { owner, .. }
            | Input::OwnedChannelRegistrationResult { owner, .. } => owner.shard(),
        };
        self.shards[shard.0].push(input).await
    }

    pub fn monitor(&self) -> QueueMonitor {
        self.shards[0].monitor()
    }

    pub(crate) fn nick_directory(&self) -> NickDirectory {
        self.nicks.clone()
    }

    pub(crate) fn membership_directory(&self) -> MembershipDirectory {
        self.memberships.clone()
    }

    pub(crate) fn founder_directory(&self) -> FounderDirectory {
        self.founders.clone()
    }

    pub(crate) fn retained_topic_directory(&self) -> RetainedTopicDirectory {
        self.topics.clone()
    }

    pub(crate) fn channel_options_directory(&self) -> ChannelOptionsDirectory {
        self.channel_options.clone()
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

/// Events into the core worker.
#[derive(Debug)]
pub enum Input {
    /// A connection was accepted; `tx` is its send queue.
    Open {
        conn: ConnId,
        tx: Sender<Output>,
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
    ChannelJoinResult {
        session: SessionOwner,
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
    /// One shard's answer to a whole-network LIST request.
    ChannelListResult {
        result: ChannelListResult,
    },
    /// A whole-network LIST request, delivered once to every channel shard.
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
    /// An answer from the DB worker to an earlier [`DbRequest`].
    DbReply {
        conn: ConnId,
        reply: DbReply,
    },
    /// A resolved CHATHISTORY page from PostgreSQL. `Err` means the store
    /// failed — the handler answers a CHATHISTORY FAIL rather than an empty
    /// batch, so a transient DB fault is never indistinguishable from a buffer
    /// with no history.
    HistoryPage {
        conn: ConnId,
        display: String,
        batch_ref: String,
        rows: Result<Vec<HistoryRow>, ()>,
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
        channel: String,
        requester: ChannelDropRequester,
        result: ChannelDropResult,
    },
    /// A server-ban add/remove verdict. Like channel deletion, the requester
    /// may be an IRC operator or an HTTP admin request.
    ServerBanResult {
        mutation: ServerBanMutation,
        requester: ServerBanRequester,
        result: ServerBanResult,
    },
    /// A founder-owned registered-channel mutation verdict. The database
    /// re-checks ownership before writing; only an applied verdict changes the
    /// core's hot founder/topic/mode/access mirrors.
    ChannelControlResult {
        owner: ChannelOwner,
        request_id: u64,
        channel: String,
        mutation: PersistedChannelMutation,
        result: ChannelControlResult,
    },
    /// A founder registration requested through the owner REST/console
    /// control plane. Authorization happens against live operator membership;
    /// the typed verdict applies the same hot founder/topic transition as
    /// ChanServ only after PostgreSQL confirms the insert.
    OwnedChannelRegistrationResult {
        owner: ChannelOwner,
        request_id: u64,
        channel: String,
        founder_account: String,
        topic: Option<(String, String, u64)>,
        result: ChannelRegistrationResult,
    },
}

/// Drain framed line events into the core queue as [`Input`] lines. Returns
/// `false` when the core is gone, so the connection stops directly rather
/// than queueing into a void. Shared by the TCP and WebSocket read loops.
pub(crate) async fn push_framed(
    core_tx: &CoreIngress,
    conn: ConnId,
    events: &mut Vec<e6irc_proto::framing::LineEvent>,
) -> bool {
    for event in events.drain(..) {
        let input = match event {
            e6irc_proto::framing::LineEvent::Line(line) => Input::Line { conn, line },
            e6irc_proto::framing::LineEvent::TooLong => Input::OverlongLine { conn },
        };
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelControlResult {
    Applied,
    MissingOrNotOwner,
    AccountMissing,
    AccessLimitReached,
    KeeptopicDisabled,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRegistrationResult {
    Registered,
    Exists,
    AccountMissing,
    Unavailable,
}

/// The ingress path that owns one live core connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTransport {
    Tcp,
    Tls,
    WebSocket,
    Local,
}

impl ConnectionTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::WebSocket => "websocket",
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
        conn: ConnId,
        display: String,
        label: Option<String>,
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
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerBanRequester {
    Oper { conn: ConnId, label: Option<String> },
    Admin { request_id: u64, actor: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerBanMutation {
    Add {
        mask: String,
        mask_display: String,
        reason: String,
        set_by: String,
        kind: String,
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
    ) -> Self {
        Self::Add {
            mask: mask.folded().to_string(),
            mask_display: mask.as_str().to_string(),
            reason,
            set_by,
            kind: kind.as_str().to_string(),
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

/// Work the core asks the DB worker to do. The worker answers by
/// pushing an [`Input::DbReply`] back into the core queue — the core
/// itself never blocks on the database.
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
        password: String,
        /// Which command asked, so the answer speaks that command's language.
        origin: AccountOrigin,
    },
    RegisterChannel {
        conn: ConnId,
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
        /// Casefolded channel name.
        channel: String,
        requester: ChannelDropRequester,
    },
    /// Transfer a registered channel's founder (ChanServ SET FOUNDER).
    /// Answered with `FounderChanged` or `FounderChangeFailed`.
    SetChannelFounder {
        conn: ConnId,
        /// Channel name as typed (for the reply notice).
        channel: String,
        /// New founder account, casefolded.
        new_founder: String,
    },
    /// Page history from PostgreSQL when the request reaches past the
    /// in-memory ring. Answered with [`Input::HistoryPage`].
    QueryHistory {
        conn: ConnId,
        targets: HistoryTargets,
        display: String,
        batch_ref: String,
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
        /// Casefolded channel targets the requester may see.
        channels: Vec<String>,
        /// The requester's casefolded nick, used to find the direct-message
        /// conversations they take part in. Their correspondents are buffers
        /// too, and a bouncer reconnecting needs them alongside channels.
        me: String,
        min_ts: e6irc_proto::time::Millis,
        max_ts: e6irc_proto::time::Millis,
        limit: usize,
        batch_ref: String,
        /// Escaped labeled-response label to carry onto the deferred batch, if
        /// the originating command was labeled.
        label: Option<String>,
    },
    /// Persist a read marker. Answered with [`DbReply::ReadMarkerStored`] or
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
        conn: ConnId,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the eventual TOPIC line.
        display: String,
        /// Prefix captured when the command was authorized.
        prefix: String,
        topic: Option<(String, String, u64)>,
        revision: u64,
        label: Option<String>,
    },
    /// Persist a registered channel's KEEPTOPIC option and the retained topic
    /// it implies as one database transition.
    SetChannelKeeptopic {
        conn: ConnId,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the service verdict.
        display: String,
        keeptopic: bool,
        /// Current live topic when enabling; ignored when disabling.
        topic: Option<(String, String, u64)>,
        label: Option<String>,
    },
    /// Persist a registered channel's mode lock. `mlock` is the canonical spec
    /// string; `None` clears the lock.
    SetChannelMlock {
        conn: ConnId,
        /// Casefolded channel name.
        channel: String,
        /// Display spelling used in the service verdict.
        display: String,
        mlock: Option<String>,
        label: Option<String>,
    },
    /// Persist one channel access entry, then answer with `ChannelAccessSet` so
    /// the hot map is updated only on a confirmed write (a grant to an
    /// unregistered account writes nothing and must not become a phantom
    /// entry). `flags: None` removes the entry. `channel`/`account` are as
    /// typed; the worker folds them.
    SetChannelAccess {
        conn: ConnId,
        channel: String,
        account: String,
        flags: Option<String>,
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
        actor: String,
        action: String,
        target: String,
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
        kind: MessageKind,
        body: String,
        /// The sender was a bot (+B) at send time (replayed as the `bot` tag).
        sender_is_bot: bool,
        /// Encoded `draft/multiline` lines, or `None` for a single-line message
        /// (see `HistoryEntry::multiline`). Persisted so replay reconstructs the
        /// multiline message under its one msgid.
        multiline: Option<String>,
        /// Unix milliseconds.
        ts: e6irc_proto::time::Millis,
    },
}

/// Stored targets that may back one CHATHISTORY request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryTargets {
    /// A channel or an online direct-message peer resolves exactly.
    Exact(String),
    /// An offline nick may name an account or an unauthenticated `~nick`.
    PreferExisting { primary: String, fallback: String },
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

/// One resolved CHATHISTORY BETWEEN endpoint: a message id or a timestamp. The
/// database resolves each to a `(ts, id)` position, so a `msgid=` pivot that is
/// no longer in the ring is still paged correctly (unlike a ring-only lookup,
/// which would lose the bound or mis-order the two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorBound {
    Msgid(String),
    Timestamp(e6irc_proto::time::Millis),
}

/// PRIVMSG or NOTICE — the only two message kinds that carry a body, are
/// delivered to an audience, and enter history. A single type instead of a
/// `&str` so the three forms of the name cannot drift: the uppercase wire verb
/// ([`MessageKind::wire`]), the lowercase storage token ([`MessageKind::db`],
/// the `messages.kind` column), and the "does it trigger automatic replies"
/// rule ([`MessageKind::is_loud`] — NOTICE never does). Before this they were
/// carried as a string that was uppercased in one place and lowercased in
/// another, so the ring and the database stored different casings of the same
/// message; now the casing exists only at the edges where it is asked for.
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

    /// The lowercase token stored in the `messages.kind` column.
    pub fn db(self) -> &'static str {
        match self {
            MessageKind::Privmsg => "privmsg",
            MessageKind::Notice => "notice",
        }
    }

    /// PRIVMSG triggers automatic replies (error numerics, away auto-reply);
    /// NOTICE must never trigger any (Modern IRC), so it is silent.
    pub fn is_loud(self) -> bool {
        matches!(self, MessageKind::Privmsg)
    }

    /// Parse the stored [`MessageKind::db`] token; `None` for anything else,
    /// so a corrupt or unexpected `kind` column surfaces rather than defaulting.
    pub fn from_db(token: &str) -> Option<Self> {
        match token {
            "privmsg" => Some(MessageKind::Privmsg),
            "notice" => Some(MessageKind::Notice),
            _ => None,
        }
    }
}

/// One rendered history row, newest-last, as the DB returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub msgid: String,
    pub ts: e6irc_proto::time::Millis,
    pub sender_prefix: String,
    /// The sender's account at send time (`None` if unauthenticated). Used to
    /// re-address a replayed DM row by *identity* — which survives a nick
    /// change — instead of by the sender's historical nick, so a requester who
    /// renamed mid-conversation still sees their own lines addressed to the
    /// correspondent, not to themselves.
    pub sender_account: Option<String>,
    pub kind: MessageKind,
    pub body: String,
    /// The sender was a bot (+B) at send time; replay re-emits the `bot` tag.
    pub sender_is_bot: bool,
    /// Encoded `draft/multiline` lines (see `HistoryEntry::multiline`); `None`
    /// for a single-line message. Reconstructed into a multiline batch (or
    /// flattened) on replay, reusing this row's single msgid.
    pub multiline: Option<String>,
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
    AccountCreated {
        account: String,
        origin: AccountOrigin,
    },
    AccountExists {
        origin: AccountOrigin,
    },
    /// A channel was registered. `founder_account` is echoed from the request
    /// (the account the DB row was actually written with), not re-read from the
    /// session at reply time — a mid-flight LOGOUT/IDENTIFY would otherwise put
    /// the wrong account (or none) into the hot founder map, diverging it from
    /// the DB until restart.
    ChannelRegistered {
        channel: String,
        founder_account: String,
        topic: Option<(String, String, u64)>,
        label: Option<String>,
    },
    ChannelExists {
        channel: String,
        label: Option<String>,
    },
    /// A NickServ/REGISTER-command account registration could not be persisted
    /// (DB down/errored). Carries the origin so the client gets the loud
    /// failure appropriate to how it asked, never a silent hang.
    AccountRegisterUnavailable {
        origin: AccountOrigin,
    },
    /// A ChanServ channel registration could not be persisted (DB down/errored).
    ChannelRegisterUnavailable {
        channel: String,
        label: Option<String>,
    },
    /// A founder transfer succeeded: `channel` as typed, `account`
    /// casefolded (updates the hot ownership map).
    FounderChanged {
        channel: String,
        account: String,
    },
    /// A founder transfer failed — the target account or channel is gone (a
    /// definitive negative, distinct from a store fault).
    FounderChangeFailed {
        channel: String,
    },
    /// A founder transfer could not be attempted — the store failed. Kept
    /// separate from `FounderChangeFailed` so a DB fault is never reported to
    /// the founder as "no such account".
    FounderChangeUnavailable {
        channel: String,
    },
    /// A ChanServ FLAGS change was persisted (or not). The hot access map is
    /// updated only when `applied` is true, so a grant to an unregistered
    /// account can't leave a phantom entry that would auto-op a later
    /// registration of that name. `channel`/`account` are as typed (the reply
    /// re-folds them for the map key and shows them in the notice).
    ChannelAccessSet {
        channel: String,
        account: String,
        flags: Option<String>,
        applied: bool,
    },
    /// A ChanServ FLAGS change could not be attempted — the store failed.
    /// Kept separate from `applied: false` (a definitive "no such account")
    /// for the same reason `FounderChangeUnavailable` exists: reporting a DB
    /// fault as "account is not registered" tells the operator a lie they
    /// might act on.
    ChannelAccessUnavailable {
        channel: String,
    },
    /// A ChanServ FLAGS grant was refused because the channel's access list is at
    /// its cap. Distinct from `ChannelAccessUnavailable` (a store fault) and from
    /// `applied: false` (account not registered) so the founder is told the real
    /// reason and can revoke an entry rather than retry.
    ChannelAccessLimitReached {
        channel: String,
    },
    /// A TOPIC request reached the registered-channel row. `retained` is the
    /// row's KEEPTOPIC value: the live topic is valid either way, while only a
    /// retained topic enters the restart-surviving hot mirror.
    ChannelTopicSet {
        channel: String,
        display: String,
        prefix: String,
        topic: Option<(String, String, u64)>,
        revision: u64,
        retained: bool,
        label: Option<String>,
    },
    ChannelTopicFailed {
        channel: String,
        display: String,
        revision: u64,
        label: Option<String>,
        failure: ChannelTopicFailure,
    },
    ChannelKeeptopicSet {
        channel: String,
        display: String,
        keeptopic: bool,
        topic: Option<(String, String, u64)>,
        applied: bool,
        label: Option<String>,
    },
    ChannelKeeptopicUnavailable {
        display: String,
        label: Option<String>,
    },
    ChannelMlockSet {
        channel: String,
        display: String,
        mlock: Option<String>,
        applied: bool,
        label: Option<String>,
    },
    ChannelMlockUnavailable {
        display: String,
        label: Option<String>,
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
    /// A credential verification could not be attempted — the database is
    /// unreachable or errored. Carries the origin so the client gets the loud
    /// failure appropriate to how it asked (SASL FAIL vs NickServ notice),
    /// never a silent hang, and never a verdict routed to the wrong command.
    Unavailable {
        origin: CredentialOrigin,
    },
}

/// One wire line out to a connection I/O task, CRLF included. Socket
/// close is signaled by dropping the session's queue Sender, never by
/// an in-band event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output(pub Bytes);

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
    next_sequence: u64,
}

pub(crate) enum CoreEffect {
    /// A typed event for another core owner.
    Input(Input),
    BroadcastChannelList {
        request: ChannelListRequest,
    },
    Delivery {
        owner: SessionOwner,
        line: Bytes,
    },
    ChannelJoin {
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        join_key: Option<String>,
        label: Option<String>,
    },
    ChannelJoinResult {
        session: SessionOwner,
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
    ChannelQuit(ChannelQuit),
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
}

/// One core and the only queue allowed to drive its state transitions.
pub(crate) struct CoreWorker {
    core: Core,
    receiver: Receiver<Input>,
    ingress: CoreIngress,
}

impl CoreWorker {
    pub(crate) fn new(core: Core, receiver: Receiver<Input>, ingress: CoreIngress) -> Self {
        Self {
            core,
            receiver,
            ingress,
        }
    }

    pub(crate) async fn run(mut self) {
        while let Some(envelope) = self.receiver.pop().await {
            let stop = matches!(&envelope.payload, Input::Shutdown);
            self.core.handle_scheduled(ScheduledInput {
                shard: self.core.shard,
                sequence: envelope.seq,
                input: envelope.payload,
            });
            for effect in self.core.take_effects() {
                if let CoreEffect::BroadcastChannelList { request } = effect {
                    for shard in self.ingress.shards.iter() {
                        if shard
                            .push(Input::ChannelList {
                                request: request.clone(),
                            })
                            .await
                            .is_err()
                        {
                            panic!("cross-shard target closed");
                        }
                    }
                    continue;
                }
                let input = match effect {
                    CoreEffect::Input(input) => input,
                    CoreEffect::Delivery { owner, line } => Input::Delivery {
                        conn: owner.conn(),
                        line,
                    },
                    CoreEffect::ChannelJoin {
                        owner,
                        actor,
                        name,
                        join_key,
                        label,
                    } => Input::ChannelJoin {
                        owner,
                        actor,
                        name,
                        join_key,
                        label,
                    },
                    CoreEffect::ChannelJoinResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelJoinResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::ChannelPart {
                        owner,
                        actor,
                        name,
                        reason,
                        label,
                    } => Input::ChannelPart {
                        owner,
                        actor,
                        name,
                        reason,
                        label,
                    },
                    CoreEffect::ChannelPartResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelPartResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::ChannelQuit(quit) => Input::ChannelQuit { quit },
                    CoreEffect::ChannelTopic { topic } => Input::ChannelTopic { topic },
                    CoreEffect::ChannelTopicResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelTopicResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::ChannelTopicPersisted {
                        owner,
                        conn,
                        session,
                        result,
                    } => Input::ChannelTopicPersisted {
                        owner,
                        conn,
                        session,
                        result,
                    },
                    CoreEffect::SessionChannelRemoved { session, key } => {
                        Input::SessionChannelRemoved { session, key }
                    }
                    CoreEffect::ChannelKick { kick } => Input::ChannelKick { kick },
                    CoreEffect::ChannelKickResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelKickResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::ChannelMessage { message } => Input::ChannelMessage { message },
                    CoreEffect::ChannelMessageResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelMessageResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::ChannelMultiline { message } => Input::ChannelMultiline { message },
                    CoreEffect::ChannelMultilineResult { session, result } => {
                        Input::ChannelMultilineResult { session, result }
                    }
                    CoreEffect::ChannelTagmsg { tagmsg } => Input::ChannelTagmsg { tagmsg },
                    CoreEffect::ChannelTagmsgResult {
                        session,
                        result,
                        label,
                    } => Input::ChannelTagmsgResult {
                        session,
                        result,
                        label,
                    },
                    CoreEffect::BroadcastChannelList { .. } => unreachable!("handled above"),
                };
                if self.ingress.push(input).await.is_err() {
                    panic!("cross-shard target closed");
                }
            }
            if stop {
                return;
            }
        }
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
        Self::with_telemetry_with_nicks(
            config,
            db_tx,
            telemetry,
            NickDirectory::default(),
            MembershipDirectory::default(),
            FounderDirectory::default(),
            RetainedTopicDirectory::default(),
            ChannelOptionsDirectory::default(),
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn with_telemetry_with_nicks(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
        nicks: NickDirectory,
        memberships: MembershipDirectory,
        founders: FounderDirectory,
        topics: RetainedTopicDirectory,
        channel_options: ChannelOptionsDirectory,
    ) -> Self {
        Self::with_telemetry_on_shard_with_nicks(
            config,
            db_tx,
            telemetry,
            CoreShardId(0),
            CoreShardCount::single(),
            nicks,
            memberships,
            founders,
            topics,
            channel_options,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn with_telemetry_on_shard_with_nicks(
        config: CoreConfig,
        db_tx: Sender<DbRequest>,
        telemetry: Arc<Telemetry>,
        shard: CoreShardId,
        shards: CoreShardCount,
        nicks: NickDirectory,
        memberships: MembershipDirectory,
        founders: FounderDirectory,
        topics: RetainedTopicDirectory,
        channel_options: ChannelOptionsDirectory,
    ) -> Self {
        Self {
            state: ServerState::new(
                shard,
                shards,
                config,
                db_tx,
                telemetry,
                nicks,
                memberships,
                founders,
                topics,
                channel_options,
            ),
            shard,
            next_sequence: 0,
        }
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

    fn take_effects(&mut self) -> Vec<CoreEffect> {
        self.state.take_effects()
    }

    /// Seed the hot channel-ownership map from persisted rows before the
    /// worker loop starts (see [`ServerState::preload_founders`]).
    pub fn preload_founders(&mut self, rows: Vec<(String, String)>) {
        self.state.preload_founders(rows);
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
    pub fn preload_server_bans(&mut self, rows: Vec<(String, String, String, String)>) {
        self.state.preload_server_bans(rows);
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

    /// Process one event. All state transitions happen here, on one
    /// thread, in queue order.
    pub fn handle(&mut self, input: Input) {
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
            Input::Open {
                conn,
                tx,
                host,
                transport,
            } => self.state.open(conn, tx, host, transport),
            Input::Line { conn, line } => handler::dispatch(&mut self.state, conn, &line),
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
                result,
                label,
            } => {
                assert_eq!(
                    session.shard(),
                    self.shard,
                    "JOIN result reached wrong session shard"
                );
                handler::channel_join_result(&mut self.state, session.conn(), result, label);
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
            Input::ChannelQuit { quit } => {
                self.state
                    .quit_channel_member(quit.owner(), quit.conn(), quit.line());
            }
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
                assert_eq!(
                    update.owner().shard(),
                    self.shard,
                    "member update reached wrong channel shard"
                );
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
            Input::Tick { now } => handler::reap_idle(&mut self.state, now),
            Input::DbReply { conn, reply } => handler::db_reply(&mut self.state, conn, reply),
            Input::HistoryPage {
                conn,
                display,
                batch_ref,
                rows,
                label,
            } => {
                // The batch is what the connection's held output is waiting
                // behind, so it is emitted through the hold, which is then
                // released in the order the client issued its commands.
                self.state.emit_deferred(conn, |state| {
                    handler::history_page(
                        state,
                        conn,
                        &display,
                        &batch_ref,
                        rows,
                        label.as_deref(),
                    );
                });
            }
            Input::TargetsPage {
                conn,
                batch_ref,
                targets,
                label,
            } => {
                self.state.emit_deferred(conn, |state| {
                    handler::targets_page(state, conn, &batch_ref, targets, label.as_deref());
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
                channel,
                requester,
                result,
            } => {
                handler::services::channel_drop_result(&mut self.state, channel, requester, result);
            }
            Input::ServerBanResult {
                mutation,
                requester,
                result,
            } => {
                handler::oper::server_ban_result(&mut self.state, mutation, requester, result);
            }
            Input::ChannelControlResult {
                owner,
                request_id,
                channel,
                mutation,
                result,
            } => {
                assert_eq!(
                    owner.shard(),
                    self.shard,
                    "channel control reached wrong shard"
                );
                handler::admin::channel_control_result(
                    &mut self.state,
                    request_id,
                    channel,
                    mutation,
                    result,
                );
            }
            Input::OwnedChannelRegistrationResult {
                owner,
                request_id,
                channel,
                founder_account,
                topic,
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
                    channel,
                    founder_account,
                    topic,
                    result,
                );
            }
        }
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
        let sessions_after = self.state.sessions.len();
        self.state.telemetry.record_connections_closed(
            (sessions_before + usize::from(opened)).saturating_sub(sessions_after),
        );
        let registered = self
            .state
            .sessions
            .values()
            .filter(|session| session.is_registered())
            .count();
        self.state.telemetry.update_core_gauges(
            sessions_after,
            registered,
            self.state.channels.len(),
        );
        self.state
            .telemetry
            .observe_latency(LatencyKind::Core, started.elapsed());
    }
}

/// Deliver one output event; a full/closed send queue means the client
/// is too slow (or gone) and the connection must die — the classic
/// SendQ-exceeded kill. Never silently dropped.
fn deliver(tx: &Sender<Output>, line: WireLine) -> Result<(), SendqExceeded> {
    match tx.try_push(Output(line.0)) {
        Ok(_) => Ok(()),
        Err(PushError::Full(_)) => Err(SendqExceeded),
        // Receiver gone: the I/O task is already dead. On the common
        // reader-first close a `Closed{conn}` event is already in flight to us.
        // On a writer-first close (write half RSTs while the read half hangs)
        // there is no such event and outbound lines are dropped for now — but
        // the liveness reaper PINGs the idle session and reaps it once the PONG
        // deadline passes, so this can't leave a permanent zombie.
        Err(PushError::Closed(_)) => Ok(()),
    }
}

struct SendqExceeded;

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
        ChannelOptionsDirectory, ConnId, ConnectionTransport, Core, CoreConfig, CoreIngress,
        CoreScheduler, CoreShardCount, CoreShardId, CoreTraceStep, CoreWorker, FounderDirectory,
        Input, MembershipDirectory, NickDirectory, ReplayError, RetainedTopicDirectory,
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
            sendq: 1,
            motd: Vec::new(),
            nicklen: 30,
            sasl_enabled: false,
            max_hot_channels: 1,
            opers: Vec::new(),
            clock: wall_clock,
            mono_clock,
            command_burst: None,
            registration_burst: None,
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
        let nicks = ingress.nick_directory();
        let memberships = ingress.membership_directory();
        let founders = ingress.founder_directory();
        let topics = ingress.retained_topic_directory();
        let channel_options = ingress.channel_options_directory();
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
        let first = Core::with_telemetry_on_shard_with_nicks(
            core_config(),
            first_db,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(0),
            shards,
            nicks.clone(),
            memberships.clone(),
            founders.clone(),
            topics.clone(),
            channel_options.clone(),
        );
        let second = Core::with_telemetry_on_shard_with_nicks(
            core_config(),
            second_db,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(1),
            shards,
            nicks,
            memberships,
            founders,
            topics,
            channel_options,
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
            [super::CoreEffect::Input(Input::Admin { .. })]
        ));
        assert_eq!(second.shard, CoreShardId(1));
    }

    async fn next_output(rx: &mut Receiver<super::Output>) -> Envelope<super::Output> {
        loop {
            if let Some(output) = rx.try_pop() {
                return output;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn connection_events_keep_one_deterministic_owner() {
        let (first, mut first_rx) = queue(Config {
            name: "first-core-shard",
            capacity: 2,
            policy: Policy::Fifo,
        });
        let (second, mut second_rx) = queue(Config {
            name: "second-core-shard",
            capacity: 2,
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
        let core = Core::with_telemetry_on_shard_with_nicks(
            core_config(),
            db_tx,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(0),
            shards,
            ingress.nick_directory(),
            ingress.membership_directory(),
            ingress.founder_directory(),
            ingress.retained_topic_directory(),
            ingress.channel_options_directory(),
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
                    realname: "Requester".into(),
                    account: None,
                    away: false,
                    oper: false,
                    bot: false,
                    last_active: mono_clock(),
                },
            },
            target.into(),
            ChannelCommandOperation::Knock,
            None,
        );

        ingress
            .push(Input::ChannelCommand { command })
            .await
            .expect("channel command routed");
        assert!(matches!(
            second_rx.pop().await.expect("channel owner event").payload,
            Input::ChannelCommand { .. }
        ));
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
        let output_config = Config {
            name: "remote-knock-output",
            capacity: 64,
            policy: Policy::Fifo,
        };
        let (alice_tx, mut alice_rx) = queue(output_config);
        let (bob_tx, mut bob_rx) = queue(output_config);
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
        let mut channel = Channel::new("#chat".into(), None, modes, 0);
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
            .or_insert(Channel::new(other.into(), None, ChanModes::default(), 0));
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
                .ends_with(b" 710 alice #chat bob!bob@host.test :has asked for an invite\r\n")
        );
        let result = next_output(&mut bob_rx).await;
        assert!(
            result
                .payload
                .0
                .ends_with(b" 711 bob :Your KNOCK has been delivered\r\n")
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
        assert!(ban.payload.0.ends_with(b" 367 robert #chat bad!*@*\r\n"));
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
            second_tx,
            second_rx,
            ingress,
        } = two_worker_harness();
        let (out_tx, mut out_rx) = queue(Config {
            name: "remote-member-sendq",
            capacity: 8,
            policy: Policy::Fifo,
        });
        second.state.open(
            ConnId(1),
            out_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        let (sender_tx, _sender_rx) = queue(Config {
            name: "local-member-sendq",
            capacity: 64,
            policy: Policy::Fifo,
        });
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
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
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
        first_tx.try_push(Input::Shutdown).expect("stop source");

        let destination = tokio::spawn(CoreWorker::new(second, second_rx, ingress.clone()).run());
        CoreWorker::new(first, first_rx, ingress.clone())
            .run()
            .await;
        let join = out_rx.pop().await.expect("remote join delivered");
        assert!(join.payload.0.starts_with(b"@time="));
        assert!(join.payload.0.ends_with(b"JOIN #chat * :Sender\r\n"));
        let message = out_rx.pop().await.expect("remote message delivered");
        assert!(message.payload.0.starts_with(b"@time="));
        assert!(message.payload.0.ends_with(b"PRIVMSG #chat :hello\r\n"));
        second_tx
            .try_push(Input::Shutdown)
            .expect("stop destination");
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

        let (peer_tx, mut peer_rx) = queue(Config {
            name: "join-peer-sendq",
            capacity: 8,
            policy: Policy::Fifo,
        });
        first.state.open(
            ConnId(2),
            peer_tx,
            "host.test".into(),
            ConnectionTransport::Tcp,
        );
        let key = first.state.chan_key("#chat");
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
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
        );
        first.state.channels.entry(key).or_insert(channel);

        let (joiner_tx, mut joiner_rx) = queue(Config {
            name: "joiner-sendq",
            capacity: 16,
            policy: Policy::Fifo,
        });
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
        let core = Core::with_telemetry_on_shard_with_nicks(
            core_config(),
            db_tx,
            Arc::new(crate::observability::Telemetry::new()),
            CoreShardId(1),
            CoreShardCount::new(NonZeroUsize::new(2).expect("nonzero shard count")),
            NickDirectory::default(),
            MembershipDirectory::default(),
            FounderDirectory::default(),
            RetainedTopicDirectory::default(),
            ChannelOptionsDirectory::default(),
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
