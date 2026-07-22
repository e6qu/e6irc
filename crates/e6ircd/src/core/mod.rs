//! The IRC core: a single-threaded, share-nothing worker that owns all
//! chat state. Inputs arrive as events (from connection I/O tasks, via
//! `e6irc-queue`); outputs are pushed into per-connection send queues.
//! The worker itself is synchronous — `Core::handle` is a pure state
//! transition — which is what makes deterministic simulation and
//! step-debugging possible.
//!
//! Today one worker owns everything; the design splits the same worker
//! into N hash-sharded instances when scale demands it.

mod handler;
mod state;

pub use state::{ConnId, CoreConfig, dm_conversation_key};

use bytes::Bytes;
use e6irc_queue::{PushError, Sender};
use state::ServerState;

/// Events into the core worker.
#[derive(Debug)]
pub enum Input {
    /// A connection was accepted; `tx` is its send queue.
    Open {
        conn: ConnId,
        tx: Sender<Output>,
        host: String,
    },
    /// One complete line from the connection (terminator stripped).
    Line { conn: ConnId, line: Vec<u8> },
    /// The connection sent an over-long line (framing already dropped it).
    OverlongLine { conn: ConnId },
    /// The socket closed or errored; `reason` is used in the QUIT
    /// broadcast if the session was registered.
    Closed { conn: ConnId, reason: String },
    /// A periodic timer tick carrying the current wall-clock millisecond,
    /// driving the liveness reaper (registration deadline + idle PING/PONG
    /// timeout).
    Tick { now: u64 },
    /// An answer from the DB worker to an earlier [`DbRequest`].
    DbReply { conn: ConnId, reply: DbReply },
    /// A resolved CHATHISTORY page from PostgreSQL.
    HistoryPage {
        conn: ConnId,
        display: String,
        batch_ref: String,
        rows: Vec<HistoryRow>,
        /// Labeled-response label to place on the batch, if the command that
        /// triggered this deferred page was labeled.
        label: Option<String>,
    },
    /// Resolved CHATHISTORY TARGETS from PostgreSQL: `(target, latest ts)`
    /// pairs for the buffers with activity in the requested window.
    TargetsPage {
        conn: ConnId,
        batch_ref: String,
        targets: Vec<(String, u64)>,
        /// Labeled-response label to place on the batch, if the command that
        /// triggered this deferred page was labeled.
        label: Option<String>,
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
    },
    /// Verify a bearer token (SASL OAUTHBEARER); answered with the same
    /// `PasswordVerified`/`PasswordRejected` replies as a password.
    VerifyToken { conn: ConnId, token: String },
    CreateAccount {
        conn: ConnId,
        name: String,
        password: String,
        /// Which command asked, so the answer speaks that command's language.
        origin: AccountOrigin,
    },
    RegisterChannel {
        conn: ConnId,
        channel: String,
        founder_account: String,
    },
    /// Unregister a channel (ChanServ DROP). Fire-and-forget: the core
    /// already removed it from its hot maps.
    DropChannel {
        /// Casefolded channel name.
        channel: String,
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
        /// Casefolded target.
        target: String,
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
        min_ts: u64,
        max_ts: u64,
        limit: usize,
        batch_ref: String,
        /// Escaped labeled-response label to carry onto the deferred batch, if
        /// the originating command was labeled.
        label: Option<String>,
    },
    /// Persist a read marker (fire-and-forget).
    SetReadMarker {
        account: String,
        /// Casefolded target.
        target: String,
        marker_ms: u64,
    },
    /// Persist a registered channel's retained topic (fire-and-forget).
    /// `topic` is `(text, setter, set_at_secs)`; `None` clears it.
    SetChannelTopic {
        /// Casefolded channel name.
        channel: String,
        topic: Option<(String, String, u64)>,
    },
    /// Persist a registered channel's KEEPTOPIC option (fire-and-forget).
    SetChannelKeeptopic {
        /// Casefolded channel name.
        channel: String,
        keeptopic: bool,
    },
    /// Persist a registered channel's mode lock (fire-and-forget). `mlock`
    /// is the canonical spec string; `None` clears the lock.
    SetChannelMlock {
        /// Casefolded channel name.
        channel: String,
        mlock: Option<String>,
    },
    /// Persist one channel access entry (fire-and-forget). `flags: None`
    /// removes the entry.
    SetChannelAccess {
        /// Casefolded channel name.
        channel: String,
        /// Casefolded account name.
        account: String,
        flags: Option<String>,
    },
    /// Persist a server ban (oper KLINE/DLINE/XLINE). Fire-and-forget.
    AddServerBan {
        mask: String,
        reason: String,
        set_by: String,
        kind: String,
    },
    /// Remove a server ban by (mask, kind) (oper UN*LINE). Fire-and-forget.
    RemoveServerBan { mask: String, kind: String },
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
        /// "privmsg" or "notice".
        kind: &'static str,
        body: String,
        /// Unix milliseconds.
        ts: u64,
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
        after_ts: u64,
        limit: usize,
    },
    LatestAfterMsgid {
        msgid: String,
        limit: usize,
    },
    Before {
        before_ts: u64,
        limit: usize,
    },
    After {
        after_ts: u64,
        limit: usize,
    },
    /// Up to `limit` messages centred on `around_ts` (about half older,
    /// half newer), oldest-first.
    Around {
        around_ts: u64,
        limit: usize,
    },
    /// Up to `limit` messages strictly between the two timestamps, always
    /// returned oldest-first. `newest_first` selects which end `limit` cuts
    /// from: CHATHISTORY BETWEEN walks from its first selector toward its
    /// second, so a reversed (newer-first) request keeps the newest messages
    /// in the span rather than the oldest.
    Between {
        after_ts: u64,
        before_ts: u64,
        limit: usize,
        newest_first: bool,
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
    BetweenMsgid {
        after_msgid: String,
        before_msgid: String,
        limit: usize,
        /// See [`HistoryQuery::Between::newest_first`].
        newest_first: bool,
    },
}

/// One rendered history row, newest-last, as the DB returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub msgid: String,
    pub ts: u64,
    pub sender_prefix: String,
    pub kind: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbReply {
    PasswordVerified {
        account: String,
    },
    PasswordRejected,
    AccountCreated {
        account: String,
        origin: AccountOrigin,
    },
    AccountExists {
        origin: AccountOrigin,
    },
    ChannelRegistered {
        channel: String,
    },
    ChannelExists,
    /// A founder transfer succeeded: `channel` as typed, `account`
    /// casefolded (updates the hot ownership map).
    FounderChanged {
        channel: String,
        account: String,
    },
    /// A founder transfer failed — the target account or channel is gone.
    FounderChangeFailed {
        channel: String,
    },
    /// The database is unreachable or errored; the client gets a loud
    /// failure, never a silent hang.
    Unavailable,
}

/// One wire line out to a connection I/O task, CRLF included. Socket
/// close is signaled by dropping the session's queue Sender, never by
/// an in-band event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output(pub Bytes);

pub struct Core {
    state: ServerState,
}

impl Core {
    pub fn new(config: CoreConfig, db_tx: Sender<DbRequest>) -> Self {
        Self {
            state: ServerState::new(config, db_tx),
        }
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
    pub fn preload_mlock(&mut self, rows: Vec<(String, String)>) {
        self.state.preload_mlock(rows);
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
    pub fn preload_read_markers(&mut self, rows: Vec<(String, String, u64)>) {
        self.state.preload_read_markers(rows);
    }

    /// Process one event. All state transitions happen here, on one
    /// thread, in queue order.
    pub fn handle(&mut self, input: Input) {
        match input {
            Input::Open { conn, tx, host } => self.state.open(conn, tx, host),
            Input::Line { conn, line } => handler::dispatch(&mut self.state, conn, &line),
            Input::OverlongLine { conn } => handler::overlong(&mut self.state, conn),
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
        }
        // Sweep connections whose SendQ overflowed while handling the
        // event: the slow client dies (may cascade if its QUIT broadcast
        // overflows someone else's queue — hence the loop). Dropping the
        // session drops its queue Sender, which is what closes the
        // socket: write_loop drains, flushes, and shuts down on None.
        while let Some(conn) = self.state.doomed.pop() {
            self.state.close(conn, "SendQ exceeded");
        }
    }
}

/// Deliver one output event; a full/closed send queue means the client
/// is too slow (or gone) and the connection must die — the classic
/// SendQ-exceeded kill. Never silently dropped.
fn deliver(tx: &Sender<Output>, out: Output) -> Result<(), SendqExceeded> {
    match tx.try_push(out) {
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
