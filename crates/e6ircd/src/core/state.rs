//! All chat state, owned exclusively by the core worker.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use e6irc_proto::casemap::CaseMapping;
use e6irc_queue::Sender;

use super::{Output, deliver};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// Casefolded channel-name key. Constructible only via
/// [`ServerState::chan_key`], so a display-cased name can never index
/// the channel table — that bug class is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChanKey(String);

impl ChanKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Casefolded nick key; same rationale as [`ChanKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NickKey(String);

impl NickKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct CoreConfig {
    pub server_name: String,
    pub network_name: String,
    /// This server's own description, as RPL_LINKS reports it. The network
    /// name identifies the network; this identifies the server on it.
    pub description: String,
    /// `draft/account-registration`: allow REGISTER before the connection
    /// has completed registration, and require an email address. Advertised
    /// as the capability's value so a client knows the rules up front.
    pub registration_before_connect: bool,
    pub registration_require_email: bool,
    /// Per-connection outbound queue capacity. The queue itself enforces this,
    /// but output *withheld* behind a deferred reply has not reached the queue
    /// yet, so the same bound is applied to it here — otherwise a connection
    /// waiting on the database could accumulate lines without limit and escape
    /// the SendQ kill entirely.
    pub sendq: usize,
    pub motd: Vec<String>,
    pub nicklen: usize,
    /// Advertise and accept SASL. Off when no database is configured —
    /// a cap we cannot honor is never advertised.
    pub sasl_enabled: bool,
    /// (name, password) operator credentials.
    pub opers: Vec<(String, String)>,
    /// Cap on channels holding an in-memory history ring; least-recently
    /// active channels beyond this evict their ring and serve
    /// CHATHISTORY from Postgres. Bounds hot-history RAM independently
    /// of total channel count (DESIGN §7.4, §11.3).
    pub max_hot_channels: usize,
    /// Unix-**milliseconds** clock, injected so tests are deterministic.
    /// Millisecond resolution is required, not cosmetic: `server-time` is
    /// specified to milliseconds and CHATHISTORY pages by timestamp, so a
    /// whole-second clock makes messages sent in the same second
    /// indistinguishable and unpageable.
    pub clock: fn() -> u64,
    /// Per-session command-flood bucket size; `None` disables the
    /// throttle. Registered non-oper sessions spend one token per
    /// command (PING/PONG exempt) and refill one token per second.
    pub command_burst: Option<usize>,
}

/// SASL negotiation progress of one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SaslState {
    #[default]
    Idle,
    /// `AUTHENTICATE PLAIN` received; awaiting the payload line.
    PlainPending,
    /// `AUTHENTICATE OAUTHBEARER` received; awaiting the payload line.
    BearerPending,
    /// Payload forwarded to the DB worker; awaiting the verdict.
    Verifying,
}

/// Negotiated IRCv3 capabilities of one client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Caps {
    pub server_time: bool,
    pub echo_message: bool,
    pub message_tags: bool,
    pub cap_notify: bool,
    pub multi_prefix: bool,
    pub userhost_in_names: bool,
    pub extended_join: bool,
    pub away_notify: bool,
    pub account_notify: bool,
    pub account_tag: bool,
    pub setname: bool,
    pub invite_notify: bool,
    pub batch: bool,
    pub chathistory: bool,
    pub read_marker: bool,
    pub labeled_response: bool,
    /// chghost: receive CHGHOST when a user's host changes (SETHOST).
    pub chghost: bool,
    /// Not in [`CAP_NAMES`]: advertised conditionally (`sasl_enabled`).
    pub sasl: bool,
    /// Not in [`CAP_NAMES`] either: advertised conditionally, with a value
    /// describing the policy (`draft/account-registration`).
    pub account_registration: bool,
    /// Also advertised with a value (its limits): `draft/multiline`.
    pub multiline: bool,
}

/// Field accessor into [`Caps`], used by the CAP REQ machinery.
pub(crate) type CapAccessor = fn(&mut Caps) -> &mut bool;

/// (wire name, accessor) for every capability we offer.
pub(crate) const CAP_NAMES: &[(&str, CapAccessor)] = &[
    ("server-time", |c| &mut c.server_time),
    ("echo-message", |c| &mut c.echo_message),
    ("message-tags", |c| &mut c.message_tags),
    ("cap-notify", |c| &mut c.cap_notify),
    ("multi-prefix", |c| &mut c.multi_prefix),
    ("userhost-in-names", |c| &mut c.userhost_in_names),
    ("extended-join", |c| &mut c.extended_join),
    ("away-notify", |c| &mut c.away_notify),
    ("account-notify", |c| &mut c.account_notify),
    ("account-tag", |c| &mut c.account_tag),
    ("setname", |c| &mut c.setname),
    ("invite-notify", |c| &mut c.invite_notify),
    ("batch", |c| &mut c.batch),
    ("draft/chathistory", |c| &mut c.chathistory),
    ("draft/read-marker", |c| &mut c.read_marker),
    ("labeled-response", |c| &mut c.labeled_response),
    ("chghost", |c| &mut c.chghost),
];

pub(crate) struct Session {
    pub tx: Sender<Output>,
    pub host: String,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub registered: bool,
    /// Mid-CAP-negotiation: registration is held until CAP END.
    pub cap_negotiating: bool,
    pub caps: Caps,
    /// Services account this connection is authenticated to.
    pub account: Option<String>,
    pub sasl: SaslState,
    /// Accumulates 400-byte AUTHENTICATE continuation chunks (SASL spec)
    /// until a short line completes the payload.
    pub sasl_buf: String,
    /// Credential-verification attempts made on this connection, capped so a
    /// single socket can't drive unbounded argon2 work (unauth CPU DoS / online
    /// brute-force). Never reset — the budget is per connection lifetime.
    pub sasl_attempts: u32,
    /// A NickServ IDENTIFY is awaiting its DB verdict.
    pub pending_identify: bool,
    /// Away message, when set.
    pub away: Option<String>,
    /// IRC operator (umode +o).
    pub oper: bool,
    /// Invisible (umode +i): hidden from WHO/WHOIS mask queries by
    /// users who share no channel.
    pub invisible: bool,
    /// Wallops recipient (umode +w).
    pub wallops: bool,
    /// Bot (umode +B).
    pub bot: bool,
    /// Channels this session was INVITEd to (clears on join).
    pub invited: HashSet<ChanKey>,
    /// Joined channels.
    pub channels: HashSet<ChanKey>,
    /// Nicks this session MONITORs (display form as given).
    pub monitoring: HashMap<NickKey, String>,
    /// The `draft/multiline` batch this connection is filling, if any.
    pub multiline: Option<MultilineBatch>,
    /// Read markers for a client that isn't logged in: per-connection and not
    /// persisted (there is no account to key them to). A logged-in client uses
    /// the account-keyed `ServerState::read_markers` instead.
    pub anon_read_markers: HashMap<ChanKey, u64>,
    /// Command-flood token bucket (only used when `command_burst` is set):
    /// tokens remaining, and the clock-millisecond through which refill has
    /// already been credited (it advances by whole seconds only, so a
    /// sub-second remainder carries forward instead of being discarded).
    pub flood_tokens: u32,
    pub flood_refilled_to_ms: u64,
    /// Wall-clock millisecond of the last non-keepalive command (for WHOIS
    /// idle / WHOX `l`), and of connection open (WHOIS signon).
    pub last_active: u64,
    pub signon: u64,
    /// Wall-clock millisecond the connection opened, for the registration
    /// deadline (an unregistered connection that never completes is reaped).
    pub opened_at: u64,
    /// A server-initiated liveness PING is outstanding (set by the reaper,
    /// cleared on PONG); if still set at the pong deadline the socket is reaped.
    pub awaiting_pong: bool,
    /// Wall-clock millisecond the outstanding liveness PING was sent.
    pub last_ping_sent: u64,
    /// How many database-backed replies this connection is still waiting on,
    /// and the output withheld behind them.
    ///
    /// A client's replies must reach it in the order it issued the commands.
    /// CHATHISTORY can only be answered after a round trip to PostgreSQL, and
    /// everything produced in the meantime — including the PONG to a PING the
    /// client pipelined right after — would otherwise overtake the batch. A
    /// client that treats that PONG as a sync point then concludes the history
    /// was empty, which is indistinguishable from the server having no history
    /// at all.
    pub deferred_replies: usize,
    pub held: Vec<Bytes>,
}

impl Session {
    /// `nick!user@host` — only valid once registered.
    pub fn prefix(&self) -> String {
        format!(
            "{}!{}@{}",
            self.nick.as_deref().expect("registered session has nick"),
            self.user.as_deref().expect("registered session has user"),
            self.host,
        )
    }
}

#[derive(Default)]
pub(crate) struct MemberModes {
    pub op: bool,
    pub voice: bool,
}

#[derive(Default)]
pub(crate) struct ChanModes {
    pub invite_only: bool,
    pub moderated: bool,
    pub no_external: bool,
    pub topic_ops_only: bool,
    pub secret: bool,
    /// +C: block CTCP (except ACTION).
    pub no_ctcp: bool,
    pub key: Option<String>,
    pub limit: Option<u32>,
}

impl ChanModes {
    /// `+nt`-style string with key/limit args appended. `reveal_key` gates
    /// the `+k` argument: only channel members may see the key, so that
    /// `MODE #chan` from an outsider cannot disclose it and bypass `+k`.
    /// The limit is not secret and is always shown.
    pub fn to_string_with_args(&self, reveal_key: bool) -> String {
        let mut modes = String::from("+");
        let mut args = String::new();
        for (set, c) in [
            (self.invite_only, 'i'),
            (self.moderated, 'm'),
            (self.no_external, 'n'),
            (self.secret, 's'),
            (self.topic_ops_only, 't'),
            (self.no_ctcp, 'C'),
        ] {
            if set {
                modes.push(c);
            }
        }
        if let Some(k) = &self.key {
            // Members see the key; outsiders see `*` (Solanum behaviour) so
            // MODE #chan reveals that +k is set without disclosing the value.
            modes.push('k');
            args.push(' ');
            args.push_str(if reveal_key { k } else { "*" });
        }
        if let Some(l) = self.limit {
            modes.push('l');
            args.push_str(&format!(" {l}"));
        }
        modes + &args
    }
}

/// A ChanServ mode lock: boolean channel modes forced on (`on`) or off
/// (`off`). Attempts to change a locked mode the wrong way are refused, and
/// the lock is (re)applied when the channel is created.
#[derive(Clone, Default)]
pub(crate) struct MlockModes {
    pub on: String,
    pub off: String,
}

impl MlockModes {
    /// Boolean channel modes that MLOCK can lock (args-carrying modes like
    /// `k`/`l` and list modes are deliberately out of scope).
    pub const LOCKABLE: &'static [char] = &['i', 'm', 'n', 's', 't', 'C'];

    /// Parse a spec like `+nt-i`. `Err(bad_char)` for any character that is
    /// neither a sign nor a lockable boolean mode. A mode named twice keeps
    /// its last sign.
    pub fn parse(spec: &str) -> Result<MlockModes, char> {
        let mut m = MlockModes::default();
        let mut adding = true;
        for c in spec.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                c if Self::LOCKABLE.contains(&c) => {
                    m.on.retain(|x| x != c);
                    m.off.retain(|x| x != c);
                    if adding {
                        m.on.push(c);
                    } else {
                        m.off.push(c);
                    }
                }
                other => return Err(other),
            }
        }
        Ok(m)
    }

    /// Canonical `+on-off` rendering (empty when nothing is locked).
    pub fn render(&self) -> String {
        let mut s = String::new();
        if !self.on.is_empty() {
            s.push('+');
            s.push_str(&self.on);
        }
        if !self.off.is_empty() {
            s.push('-');
            s.push_str(&self.off);
        }
        s
    }

    pub fn is_empty(&self) -> bool {
        self.on.is_empty() && self.off.is_empty()
    }
}

/// One line of channel history in the hot ring.
#[derive(Clone)]
pub(crate) struct HistoryEntry {
    pub msgid: String,
    /// Unix **milliseconds** (see `Config::clock`): CHATHISTORY pages by this,
    /// so second granularity would make same-second messages unorderable.
    pub ts: u64,
    pub sender_prefix: String,
    /// "PRIVMSG" or "NOTICE" as sent on the wire.
    pub kind: &'static str,
    pub body: String,
}

/// Ring capacity per target; older entries live only in PostgreSQL.
pub(crate) const HISTORY_RING_CAP: usize = 500;

/// The storage key and participants for the direct-message conversation between
/// two identities, from already-casefolded inputs.
///
/// Free-standing because the REST history endpoint needs the identical key: two
/// implementations that must agree is exactly how a privacy boundary drifts,
/// and this one decides who can read whose conversation.
pub fn dm_conversation_key(a: &str, b: &str) -> (String, Vec<String>) {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let key = format!("{lo}!{hi}");
    let peers = if lo == hi {
        vec![lo.to_string()]
    } else {
        vec![lo.to_string(), hi.to_string()]
    };
    (key, peers)
}

/// Casefolded key for anything that can hold history: a channel, or the
/// direct-message conversation between two nicks.
///
/// A conversation key is the two casefolded nicks sorted and joined by `!`,
/// which is invalid in a nick (it delimits `nick!user@host`), so a
/// conversation can never collide with a nick; and channel names start with
/// `#`/`&`, which is not a legal nick start, so it can never collide with a
/// channel either. Sorting is what makes the key *symmetric*: both
/// participants derive the identical key, so one stored copy serves both
/// sides of the conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HistoryKey(String);

impl HistoryKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&ChanKey> for HistoryKey {
    fn from(key: &ChanKey) -> Self {
        HistoryKey(key.as_str().to_string())
    }
}

/// A `draft/multiline` batch a client has opened and is still filling.
///
/// Held per session because a client may have only one open at a time; the
/// lines are buffered rather than delivered as they arrive, since a multiline
/// message is one message — it gets one msgid and one timestamp, and a client
/// that abandons the batch must deliver nothing at all.
pub(crate) struct MultilineBatch {
    /// The client's batch reference, as given after `+`.
    pub reference: String,
    /// The target, as the client spelled it.
    pub target: String,
    /// Client-only tags from the opening BATCH, replayed on the relayed one.
    pub client_tags: String,
    /// Labeled-response label from the opening BATCH. The batch *is* the
    /// response to that command, so the label rides the echoed BATCH open
    /// rather than an empty ACK at the time the batch was opened.
    pub label: Option<String>,
    /// `(text, concatenate-with-previous)` in the order sent.
    pub lines: Vec<(String, bool)>,
    /// Total bytes of line text so far, bounded by `MULTILINE_MAX_BYTES`.
    pub bytes: usize,
    /// PRIVMSG or NOTICE, taken from the first line; the batch is one message,
    /// so it cannot change kind partway through.
    pub kind: Option<&'static str>,
}

/// One target's newest-last hot history.
pub(crate) struct HistoryRing {
    pub entries: std::collections::VecDeque<HistoryEntry>,
    /// True while the ring holds *every* message this target has ever seen
    /// (never overflowed, never evicted). When false, older history lives
    /// only in Postgres and CHATHISTORY must fall back.
    pub complete: bool,
}

#[derive(Clone)]
pub(crate) struct Topic {
    pub text: String,
    pub set_by: String,
    /// Unix **seconds** — RPL_TOPICWHOTIME reports whole seconds and the
    /// column persists seconds, so this is deliberately coarser than the
    /// millisecond `Config::clock` it is derived from.
    pub set_at_secs: u64,
}

/// Which part of a connecting session a [`ServerBan`] mask is tested
/// against. The kind is the only thing that differs between a K/D/X-line —
/// the storage, matching, and enforcement are otherwise identical.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BanKind {
    /// `user@host` glob (KLINE).
    Kline,
    /// bare host / IP glob (DLINE).
    Dline,
    /// realname (gecos) glob (XLINE).
    Xline,
}

impl BanKind {
    /// The wire/DB token for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            BanKind::Kline => "kline",
            BanKind::Dline => "dline",
            BanKind::Xline => "xline",
        }
    }

    /// Parse a DB/wire token. `None` for anything unrecognized — callers
    /// surface the bad value rather than silently defaulting.
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "kline" => Some(BanKind::Kline),
            "dline" => Some(BanKind::Dline),
            "xline" => Some(BanKind::Xline),
            _ => None,
        }
    }

    /// Human label used in NOTICE/ERROR lines ("K-Line", "D-Line", …).
    pub fn label(self) -> &'static str {
        match self {
            BanKind::Kline => "K-Line",
            BanKind::Dline => "D-Line",
            BanKind::Xline => "X-Line",
        }
    }
}

/// A server ban: a glob `mask` and its `reason`, tested against the
/// session field named by `kind`.
#[derive(Clone)]
pub struct ServerBan {
    pub mask: String,
    pub reason: String,
    pub set_by: String,
    pub kind: BanKind,
}

pub(crate) struct Channel {
    /// Display name (creator's casing).
    pub name: String,
    pub topic: Option<Topic>,
    pub members: HashMap<ConnId, MemberModes>,
    pub modes: ChanModes,
    pub bans: Vec<String>,
    pub quiets: Vec<String>,
    pub ban_exceptions: Vec<String>,
    pub invite_exceptions: Vec<String>,
    /// Unix **seconds** — RPL_CREATIONTIME reports whole seconds, so this is
    /// deliberately coarser than the millisecond `Config::clock`.
    pub created_at_secs: u64,
}

impl Channel {
    fn any_match(casemap: CaseMapping, masks: &[String], subject: &str) -> bool {
        masks
            .iter()
            .any(|m| e6irc_proto::mask::matches(casemap, m, subject))
    }

    pub fn is_banned(&self, casemap: CaseMapping, prefix: &str) -> bool {
        Self::any_match(casemap, &self.bans, prefix)
            && !Self::any_match(casemap, &self.ban_exceptions, prefix)
    }

    /// Quiets share the ban-exception machinery (Solanum semantics).
    pub fn is_quieted(&self, casemap: CaseMapping, prefix: &str) -> bool {
        Self::any_match(casemap, &self.quiets, prefix)
            && !Self::any_match(casemap, &self.ban_exceptions, prefix)
    }

    pub fn is_invite_excepted(&self, casemap: CaseMapping, prefix: &str) -> bool {
        Self::any_match(casemap, &self.invite_exceptions, prefix)
    }
}

pub(crate) struct ServerState {
    pub config: CoreConfig,
    pub casemap: CaseMapping,
    pub sessions: HashMap<ConnId, Session>,
    pub nicks: HashMap<NickKey, ConnId>,
    pub channels: HashMap<ChanKey, Channel>,
    /// Connections whose SendQ overflowed during this event; swept (and
    /// killed) by `Core::handle` after the event completes.
    pub doomed: Vec<ConnId>,
    /// Requests to the DB worker (answered via `Input::DbReply`).
    pub db_tx: Sender<super::DbRequest>,
    /// High-water mark of simultaneously registered users (LUSERS max).
    pub max_users: usize,
    /// Wall-clock millisecond the server state was created (STATS u uptime,
    /// which reports the difference in whole seconds).
    pub started_at: u64,
    /// Monotonic per-process counter for msgid uniqueness.
    pub msgid_counter: u64,
    /// MONITOR: watched nick → watching connections.
    pub monitors: HashMap<NickKey, HashSet<ConnId>>,
    /// Read markers: (account, target) → epoch millis. Mirrors the
    /// PostgreSQL table; this is the hot copy the core serves.
    pub read_markers: HashMap<(String, ChanKey), u64>,
    /// Registered channels → founder account (both casefolded). The hot
    /// copy of the `channels` table's ownership, boot-loaded and updated
    /// on registration; a founder rejoining their channel is re-opped.
    pub registered_founders: HashMap<ChanKey, String>,
    /// Registered channels → retained topic. Boot-loaded and kept in sync
    /// on TOPIC; restored when a registered channel is recreated so its
    /// topic survives the channel going empty.
    pub registered_topics: HashMap<ChanKey, Topic>,
    /// Registered channels whose ChanServ KEEPTOPIC option is OFF. Topic
    /// retention is on by default (absence ⇒ on), so only the exceptions
    /// live here; boot-loaded and updated on `SET KEEPTOPIC`.
    pub keeptopic_off: HashSet<ChanKey>,
    /// Registered channels with a ChanServ mode lock. Boot-loaded and
    /// updated on `SET MLOCK`; enforced on MODE and on channel creation.
    pub channel_mlock: HashMap<ChanKey, MlockModes>,
    /// Per-channel access: channel → (folded account → flag chars, e.g.
    /// "ov"). Boot-loaded and kept in sync on ChanServ FLAGS; drives
    /// auto-op / auto-voice on join.
    pub channel_access: HashMap<ChanKey, HashMap<String, String>>,
    /// Server bans (oper K/D/X-lines) refused at registration. Boot-loaded
    /// and kept in sync on KLINE/DLINE/XLINE and their removals.
    pub server_bans: Vec<ServerBan>,
    /// Recent nick departures/changes for WHOWAS, newest-first.
    pub whowas: std::collections::VecDeque<WhowasEntry>,
    /// Hot history rings, keyed by channel or direct-message conversation.
    /// Channels and conversations share one store, one LRU and one cap, so
    /// the ring, overflow and eviction rules cannot drift apart between them.
    pub history: HashMap<HistoryKey, HistoryRing>,
    /// Targets holding a hot history ring, most-recently-active first.
    pub hot_history: std::collections::VecDeque<HistoryKey>,
    /// When set, direct sends to this connection are captured instead
    /// of delivered — the labeled-response machinery frames them.
    pub capture: Option<Capture>,
    /// While set, output to this connection bypasses its deferred-reply hold:
    /// it is the deferred reply itself, which the held output waits behind.
    pub emitting_deferred: Option<ConnId>,
}

/// Buffered direct responses to a labeled command.
pub(crate) struct Capture {
    pub conn: ConnId,
    pub lines: Vec<Bytes>,
    /// The escaped `label` value, so a command whose response is produced
    /// asynchronously (CHATHISTORY falling back to PostgreSQL) can carry the
    /// label into that deferred reply instead of losing it.
    pub label: Option<String>,
    /// Set by a handler that defers its response to an async path; tells the
    /// labeled-response framer not to ACK the command as empty — the deferred
    /// reply will emit the labeled batch itself.
    pub deferred: bool,
}

/// A historical nick record for WHOWAS.
#[derive(Clone)]
pub(crate) struct WhowasEntry {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub realname: String,
}

pub(crate) const WHOWAS_CAP: usize = 1000;

impl ServerState {
    pub fn new(config: CoreConfig, db_tx: Sender<super::DbRequest>) -> Self {
        let started_at = (config.clock)();
        Self {
            config,
            casemap: CaseMapping::Rfc1459,
            sessions: HashMap::new(),
            nicks: HashMap::new(),
            channels: HashMap::new(),
            doomed: Vec::new(),
            db_tx,
            max_users: 0,
            started_at,
            msgid_counter: 0,
            monitors: HashMap::new(),
            read_markers: HashMap::new(),
            registered_founders: HashMap::new(),
            registered_topics: HashMap::new(),
            keeptopic_off: HashSet::new(),
            channel_mlock: HashMap::new(),
            channel_access: HashMap::new(),
            server_bans: Vec::new(),
            whowas: std::collections::VecDeque::new(),
            history: HashMap::new(),
            hot_history: std::collections::VecDeque::new(),
            emitting_deferred: None,
            capture: None,
        }
    }

    /// Append to a target's hot ring, creating it if absent, and keep the
    /// global LRU within `max_hot_channels`: this target is touched to MRU and
    /// the least-recently-active ring is evicted once the cap is exceeded. An
    /// evicted or overflowed ring is marked incomplete, so CHATHISTORY pages
    /// the remainder from Postgres rather than reporting a short history.
    ///
    /// One implementation serves channels and direct-message conversations
    /// alike — the eviction discipline that bounds hot-history RAM must not
    /// differ by target kind.
    pub fn push_history(&mut self, key: &HistoryKey, entry: HistoryEntry) {
        {
            // A ring being created now is the *entire* record only when no
            // database backs it. With a DB this target may have rows in
            // `messages` already — an earlier incarnation of the channel
            // (they are dropped when they empty), or an earlier stretch of
            // the same conversation — so the ring is not authoritative and
            // CHATHISTORY must be able to fall back rather than report an
            // empty batch. One rule for channels and conversations alike.
            let whole_record = !self.config.sasl_enabled;
            let ring = self
                .history
                .entry(key.clone())
                .or_insert_with(|| HistoryRing {
                    entries: std::collections::VecDeque::new(),
                    complete: whole_record,
                });
            if ring.entries.len() == HISTORY_RING_CAP {
                ring.entries.pop_front();
                ring.complete = false;
            }
            ring.entries.push_back(entry);
        }
        // Move to MRU.
        self.hot_history.retain(|k| k != key);
        self.hot_history.push_front(key.clone());
        // Evict cold rings beyond the cap. An evicted target keeps no ring at
        // all; its history is served from Postgres.
        while self.hot_history.len() > self.config.max_hot_channels {
            if let Some(cold) = self.hot_history.pop_back() {
                self.history.remove(&cold);
            }
        }
    }

    /// A target's hot ring, or an empty incomplete one when it has never been
    /// created or was evicted — an absent ring is never "the whole record".
    pub fn history_ring(&self, key: &HistoryKey) -> (Vec<HistoryEntry>, bool) {
        match self.history.get(key) {
            Some(ring) => (ring.entries.iter().cloned().collect(), ring.complete),
            None => (Vec::new(), false),
        }
    }

    /// Mark a target's ring as no longer the whole record (a message was
    /// delivered but could not be persisted, so a gap exists that only
    /// Postgres could fill — and it does not have it either).
    pub fn mark_history_incomplete(&mut self, key: &HistoryKey) {
        if let Some(ring) = self.history.get_mut(key) {
            ring.complete = false;
        }
    }

    /// Destroy an emptied channel: drop it from `channels` and its LRU slot in
    /// `hot_channels` together, so the two can't desync — a stale `hot_channels`
    /// key would otherwise inflate the length and evict a still-live channel's
    /// ring early under the `max_hot_channels` cap.
    pub fn remove_channel(&mut self, key: &ChanKey) {
        self.channels.remove(key);
        let hist = HistoryKey::from(key);
        self.history.remove(&hist);
        self.hot_history.retain(|k| k != &hist);
    }

    /// Record a nick's details into the WHOWAS ring (on quit/nick change).
    pub fn record_whowas(&mut self, conn: ConnId) {
        let Some(session) = self.sessions.get(&conn) else {
            return;
        };
        let (Some(nick), Some(user), Some(realname)) =
            (&session.nick, &session.user, &session.realname)
        else {
            return; // never fully registered; nothing worth recording
        };
        let entry = WhowasEntry {
            nick: nick.clone(),
            user: user.clone(),
            host: session.host.clone(),
            realname: realname.clone(),
        };
        if self.whowas.len() == WHOWAS_CAP {
            self.whowas.pop_back();
        }
        self.whowas.push_front(entry);
    }

    /// Whether two connections share at least one channel.
    pub fn share_channel(&self, a: ConnId, b: ConnId) -> bool {
        let (Some(sa), Some(sb)) = (self.sessions.get(&a), self.sessions.get(&b)) else {
            return false;
        };
        sa.channels.intersection(&sb.channels).next().is_some()
    }

    /// All connections currently identified to `account`.
    pub fn account_connections(&self, account: &str) -> Vec<ConnId> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.account.as_deref() == Some(account))
            .map(|(c, _)| *c)
            .collect()
    }

    /// Key a channel name for lookup/storage.
    pub fn chan_key(&self, name: &str) -> ChanKey {
        ChanKey(self.casemap.casefold(name))
    }

    /// The channel key for `target`, or `None` when it does not name a
    /// channel at all — so a caller handling both channels and users cannot
    /// accidentally casefold a nick into the channel table.
    pub fn chan_key_if_channel(&self, target: &str) -> Option<ChanKey> {
        target.starts_with('#').then(|| self.chan_key(target))
    }

    /// Load persisted channel ownership as `(name_folded, founder_folded)`
    /// rows (both already casefolded, so they key directly).
    pub fn preload_founders(&mut self, rows: Vec<(String, String)>) {
        self.registered_founders = rows
            .into_iter()
            .map(|(name_folded, founder)| (ChanKey(name_folded), founder))
            .collect();
    }

    /// Record a channel's founder (called when registration succeeds).
    pub fn set_founder(&mut self, channel: &str, founder_account: &str) {
        let key = self.chan_key(channel);
        let founder = self.casemap.casefold(founder_account);
        self.registered_founders.insert(key, founder);
    }

    /// Whether `account` is the registered founder of channel `key`.
    pub fn is_founder(&self, key: &ChanKey, account: &str) -> bool {
        self.registered_founders
            .get(key)
            .is_some_and(|f| *f == self.casemap.casefold(account))
    }

    /// Whether channel `key` is registered (ownership recorded).
    pub fn is_registered(&self, key: &ChanKey) -> bool {
        self.registered_founders.contains_key(key)
    }

    /// Load persisted channel topics as `(name_folded, text, setter,
    /// set_at_secs)` rows into the hot retained-topic map.
    pub fn preload_topics(&mut self, rows: Vec<(String, String, String, u64)>) {
        self.registered_topics = rows
            .into_iter()
            .map(|(name_folded, text, set_by, set_at_secs)| {
                (
                    ChanKey(name_folded),
                    Topic {
                        text,
                        set_by,
                        set_at_secs,
                    },
                )
            })
            .collect();
    }

    /// Load the registered channels whose KEEPTOPIC is OFF (by folded name).
    pub fn preload_keeptopic_off(&mut self, names: Vec<String>) {
        self.keeptopic_off = names.into_iter().map(ChanKey).collect();
    }

    /// Whether `key` retains its topic across empty→recreate (default on).
    pub fn keeptopic(&self, key: &ChanKey) -> bool {
        !self.keeptopic_off.contains(key)
    }

    /// Load persisted mode locks as `(name_folded, spec)`. A row whose spec
    /// won't parse (unlockable char) is dropped loudly rather than silently
    /// enforcing a partial lock.
    pub fn preload_mlock(&mut self, rows: Vec<(String, String)>) {
        self.channel_mlock = rows
            .into_iter()
            .filter_map(|(name, spec)| match MlockModes::parse(&spec) {
                Ok(m) if !m.is_empty() => Some((ChanKey(name), m)),
                Ok(_) => None,
                Err(bad) => {
                    eprintln!("mlock: dropping {name:?} with unlockable char {bad:?}");
                    None
                }
            })
            .collect();
    }

    /// Whether setting boolean mode `c` to `adding` would violate `key`'s
    /// mode lock (locked-off mode set on, or locked-on mode set off).
    pub fn mlock_conflict(&self, key: &ChanKey, c: char, adding: bool) -> bool {
        match self.channel_mlock.get(key) {
            Some(m) => (adding && m.off.contains(c)) || (!adding && m.on.contains(c)),
            None => false,
        }
    }

    /// Load persisted channel access as `(name_folded, account_folded,
    /// flags)` rows into the hot access map.
    pub fn preload_access(&mut self, rows: Vec<(String, String, String)>) {
        self.channel_access.clear();
        for (name_folded, account, flags) in rows {
            self.channel_access
                .entry(ChanKey(name_folded))
                .or_default()
                .insert(account, flags);
        }
    }

    /// Seed the read-marker mirror from persisted `(account, target, millis)`
    /// rows at boot. The stored target is already the casefolded `ChanKey`
    /// string (it was written from `ChanKey::as_str`), so it is wrapped
    /// directly — matching the key MARKREAD builds at runtime.
    pub fn preload_read_markers(&mut self, rows: Vec<(String, String, u64)>) {
        self.read_markers.clear();
        for (account, target, ms) in rows {
            self.read_markers.insert((account, ChanKey(target)), ms);
        }
    }

    /// The `(auto_op, auto_voice)` flags `account` holds on channel `key`.
    pub fn access_modes(&self, key: &ChanKey, account: &str) -> (bool, bool) {
        let folded = self.casemap.casefold(account);
        match self.channel_access.get(key).and_then(|m| m.get(&folded)) {
            Some(flags) => (flags.contains('o'), flags.contains('v')),
            None => (false, false),
        }
    }

    /// Load persisted server bans as `(mask, reason, set_by, kind)` rows.
    /// A row whose kind token is unrecognized is skipped loudly — bans are
    /// security-critical, so a corrupt kind must not silently become a
    /// default that bans (or fails to ban) the wrong sessions.
    pub fn preload_server_bans(&mut self, rows: Vec<(String, String, String, String)>) {
        self.server_bans = rows
            .into_iter()
            .filter_map(
                |(mask, reason, set_by, kind)| match BanKind::from_token(&kind) {
                    Some(kind) => Some(ServerBan {
                        mask,
                        reason,
                        set_by,
                        kind,
                    }),
                    None => {
                        eprintln!(
                            "server ban: dropping row with unknown kind {kind:?} (mask {mask:?})"
                        );
                        None
                    }
                },
            )
            .collect();
    }

    /// The subject a ban of `kind` is tested against, from a session's
    /// `user` / `host` / `realname`.
    pub fn ban_subject(kind: BanKind, user: &str, host: &str, realname: &str) -> String {
        match kind {
            BanKind::Kline => format!("{user}@{host}"),
            BanKind::Dline => host.to_string(),
            BanKind::Xline => realname.to_string(),
        }
    }

    /// The `(kind, reason)` of the first server ban matching a session's
    /// `user` / `host` / `realname`, if any.
    pub fn ban_match(&self, user: &str, host: &str, realname: &str) -> Option<(BanKind, String)> {
        self.server_bans.iter().find_map(|b| {
            let subject = Self::ban_subject(b.kind, user, host, realname);
            e6irc_proto::mask::matches(self.casemap, &b.mask, &subject)
                .then(|| (b.kind, b.reason.clone()))
        })
    }

    /// Key a nick for lookup/storage.
    pub fn nick_key(&self, nick: &str) -> NickKey {
        NickKey(self.casemap.casefold(nick))
    }

    /// A casefolded nick rendered for display: the online user's actual nick
    /// casing when they are connected, otherwise the casefolded form itself
    /// (the only spelling still on record once they have gone).
    pub fn display_nick(&self, folded: &str) -> String {
        self.nicks
            .get(&NickKey(folded.to_string()))
            .and_then(|&conn| self.sessions.get(&conn))
            .and_then(|s| s.nick.clone())
            .unwrap_or_else(|| folded.to_string())
    }

    /// A conversation participant rendered as a nick for display: the `~`
    /// marker is stripped from an unauthenticated identity, and an account is
    /// shown as the nick currently using it when its owner is online.
    pub fn identity_nick(&self, identity: &str) -> String {
        match identity.strip_prefix('~') {
            Some(nick) => self.display_nick(nick),
            None => self
                .sessions
                .values()
                .find(|s| {
                    s.account
                        .as_deref()
                        .is_some_and(|a| self.casemap.casefold(a) == identity)
                })
                .and_then(|s| s.nick.clone())
                .unwrap_or_else(|| identity.to_string()),
        }
    }

    /// Who a connection *is*, for the purpose of owning direct-message
    /// history: its services account, or — when it has not authenticated —
    /// a `~`-prefixed form of its nick.
    ///
    /// A nick is not an identity: it is released on disconnect and anyone may
    /// then take it. Keying conversations by nick alone would mean registering
    /// a nick handed you the previous holder's private messages. `~` cannot
    /// occur in a nick or an account name, so an unauthenticated identity can
    /// never be claimed later by an account of the same name.
    ///
    /// Two successive *unauthenticated* holders of a nick do still share the
    /// `~nick` identity — without accounts there is nothing stronger to key on,
    /// and scoping it to the connection instead would cut the other participant
    /// off from their own conversation the moment the peer disconnected. The
    /// account boundary is the one that carries privilege, and it is the one
    /// enforced here; irctest's `testChathistoryDMs` covers the regression.
    pub fn conn_identity(&self, conn: ConnId) -> String {
        match self.sessions.get(&conn) {
            Some(s) => match &s.account {
                Some(account) => self.casemap.casefold(account),
                None => format!(
                    "~{}",
                    self.casemap.casefold(s.nick.as_deref().unwrap_or(""))
                ),
            },
            None => String::new(),
        }
    }

    /// The identity behind a nick. An online nick resolves through its session
    /// (so an unauthenticated user resolves to their unclaimable `~` identity);
    /// an offline one is taken to be an account name, which is what lets a
    /// conversation with a registered user be read while they are away.
    pub fn nick_identity(&self, nick: &str) -> String {
        match self.registered_peer(&self.nick_key(nick)) {
            Some(conn) => self.conn_identity(conn),
            None => self.casemap.casefold(nick),
        }
    }

    /// The history key for the direct-message conversation between two
    /// identities (see [`ServerState::conn_identity`]), with its participants.
    ///
    /// Both are returned from one place so they cannot disagree: the key is
    /// exactly the participants joined, and a mismatch between "where the
    /// message is stored" and "who is allowed to find it" would either hide a
    /// conversation from a participant or expose it to a stranger.
    ///
    /// Sorting makes the key symmetric — both participants derive the same one,
    /// so a single stored copy serves both sides. A message to oneself yields a
    /// single participant.
    pub fn dm_conversation(&self, a: &str, b: &str) -> (HistoryKey, Vec<String>) {
        let (key, peers) = dm_conversation_key(a, b);
        (HistoryKey(key), peers)
    }

    /// Resolve a nick to the connection that owns it, but only once that
    /// session is fully registered. A pre-registration session reserves its
    /// nick (so the nick collides for others) yet has no `user`/`realname`
    /// and is not a user, so it resolves to `None` here. Every user-facing
    /// lookup (WHOIS/USERHOST/MONITOR/SETHOST) goes through this instead of
    /// `nicks` directly, which keeps `Session::prefix()`'s "registered"
    /// expectations honest — an unregistered holder can never be prefix-built
    /// (that would panic the shared core worker and take down the server).
    pub fn registered_peer(&self, key: &NickKey) -> Option<ConnId> {
        self.nicks
            .get(key)
            .copied()
            .filter(|c| self.sessions.get(c).is_some_and(|s| s.registered))
    }

    pub fn open(&mut self, conn: ConnId, tx: Sender<Output>, host: String) {
        let opened_at = (self.config.clock)();
        let prev = self.sessions.insert(
            conn,
            Session {
                tx,
                host,
                nick: None,
                user: None,
                realname: None,
                registered: false,
                cap_negotiating: false,
                caps: Caps::default(),
                account: None,
                sasl: SaslState::default(),
                sasl_buf: String::new(),
                sasl_attempts: 0,
                pending_identify: false,
                away: None,
                oper: false,
                invisible: false,
                wallops: false,
                bot: false,
                invited: HashSet::new(),
                channels: HashSet::new(),
                monitoring: HashMap::new(),
                multiline: None,
                anon_read_markers: HashMap::new(),
                flood_tokens: 0,
                flood_refilled_to_ms: 0,
                last_active: 0,
                signon: 0,
                opened_at,
                awaiting_pong: false,
                deferred_replies: 0,
                held: Vec::new(),
                last_ping_sent: 0,
            },
        );
        assert!(prev.is_none(), "duplicate ConnId {conn:?} from acceptor");
    }

    // ---- output helpers -------------------------------------------------

    /// Send one already-formatted line (no CRLF) to a connection.
    pub fn send(&mut self, conn: ConnId, line: &str) {
        let bytes = Bytes::from(format!("{line}\r\n"));
        self.send_bytes(conn, bytes);
    }

    pub fn send_bytes(&mut self, conn: ConnId, bytes: Bytes) {
        if let Some(capture) = &mut self.capture
            && capture.conn == conn
        {
            capture.lines.push(bytes);
            return;
        }
        self.send_bytes_uncaptured(conn, bytes);
    }

    /// Deliver bypassing labeled-response capture. Used for messages a
    /// connection *receives* (deliveries), which are never part of the
    /// labeled response to its own command — only direct replies are.
    pub fn send_bytes_uncaptured(&mut self, conn: ConnId, bytes: Bytes) {
        // Hold this line behind an in-flight deferred reply, unless it *is*
        // that reply being emitted right now. Held output is bounded exactly
        // like the queue it is waiting to enter: overflowing it is a SendQ
        // kill, not unbounded growth.
        if self.emitting_deferred != Some(conn) {
            let sendq = self.config.sendq;
            match self.sessions.get_mut(&conn) {
                Some(session) if session.deferred_replies > 0 => {
                    if session.held.len() < sendq {
                        session.held.push(bytes);
                    } else {
                        self.doomed.push(conn);
                    }
                    return;
                }
                _ => {}
            }
        }
        let Some(session) = self.sessions.get(&conn) else {
            return; // events may race a close; the session is gone
        };
        if deliver(&session.tx, Output(bytes)).is_err() {
            self.doomed.push(conn);
        }
    }

    /// Note that a connection is now waiting on a database-backed reply, so
    /// its later output queues behind it.
    pub fn defer_reply(&mut self, conn: ConnId) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.deferred_replies += 1;
        }
    }

    /// Emit a reply the connection has been waiting on: it bypasses that
    /// connection's hold — it *is* what the hold is waiting for — and releases
    /// one slot afterwards, letting the output queued behind it through.
    pub fn emit_deferred(&mut self, conn: ConnId, emit: impl FnOnce(&mut Self)) {
        let previous = self.emitting_deferred.replace(conn);
        emit(self);
        self.emitting_deferred = previous;
        self.release_deferred(conn);
    }

    /// One deferred reply has been emitted: release the output withheld behind
    /// it, in the order it was produced.
    pub fn release_deferred(&mut self, conn: ConnId) {
        let Some(session) = self.sessions.get_mut(&conn) else {
            return;
        };
        session.deferred_replies = session.deferred_replies.saturating_sub(1);
        if session.deferred_replies > 0 {
            return;
        }
        for bytes in std::mem::take(&mut session.held) {
            self.send_bytes_uncaptured(conn, bytes);
        }
    }

    /// `:<server> <code> <target> <params…>`; the last param gets the
    /// trailing `:` if given as `trailing`.
    pub fn numeric(&mut self, conn: ConnId, code: u16, middle: &[&str], trailing: Option<&str>) {
        let target = self
            .sessions
            .get(&conn)
            .and_then(|s| s.nick.clone())
            .unwrap_or_else(|| "*".into());
        let mut line = format!(
            ":{} {} {}",
            self.config.server_name,
            e6irc_proto::numerics::code_str(code),
            target
        );
        for p in middle {
            line.push(' ');
            line.push_str(p);
        }
        if let Some(t) = trailing {
            line.push_str(" :");
            line.push_str(t);
        }
        self.send(conn, &line);
    }

    /// Stamp a new event: a single clock read yielding both the wall-clock
    /// millisecond and the unique msgid derived from it. Live delivery, the
    /// history ring and the `messages` row all take this one value, so a
    /// message can never be replayed by CHATHISTORY bearing a different
    /// `time=` than the one it was delivered with. Reading the clock twice
    /// for the same message is exactly the bug this exists to prevent.
    pub fn stamp(&mut self) -> (u64, String) {
        let now = (self.config.clock)();
        self.msgid_counter += 1;
        (now, format!("{}-{}", now, self.msgid_counter))
    }

    /// Unique reference for a batch (no associated event timestamp).
    pub fn next_msgid(&mut self) -> String {
        self.stamp().1
    }

    /// The `@time=` tag value for events emitted now.
    pub fn time_tag(&self) -> String {
        e6irc_proto::time::server_time((self.config.clock)())
    }

    /// Send a line to one recipient, honoring its `server-time` cap.
    pub fn send_timed(&mut self, conn: ConnId, line: &str) {
        let tagged = self.sessions.get(&conn).is_some_and(|s| s.caps.server_time);
        if tagged {
            let line = format!("@time={} {line}", self.time_tag());
            self.send(conn, &line);
        } else {
            self.send(conn, line);
        }
    }

    /// Serialize once per capability variant, deliver to every member of
    /// a channel except `except`.
    pub fn broadcast_channel(&mut self, chan_key: &ChanKey, line: &str, except: Option<ConnId>) {
        let Some(chan) = self.channels.get(chan_key) else {
            return;
        };
        let members: Vec<ConnId> = chan
            .members
            .keys()
            .copied()
            .filter(|c| Some(*c) != except)
            .collect();
        let plain = Bytes::from(format!("{line}\r\n"));
        // Built lazily: channels with no server-time member pay nothing.
        let mut timed: Option<Bytes> = None;
        for m in members {
            let wants_time = self.sessions.get(&m).is_some_and(|s| s.caps.server_time);
            let bytes = if wants_time {
                timed
                    .get_or_insert_with(|| {
                        Bytes::from(format!("@time={} {line}\r\n", self.time_tag()))
                    })
                    .clone()
            } else {
                plain.clone()
            };
            self.send_bytes(m, bytes);
        }
    }

    /// Everyone sharing at least one channel with `conn`, deduplicated,
    /// excluding `conn` itself.
    pub fn channel_peers(&self, conn: ConnId) -> Vec<ConnId> {
        let Some(session) = self.sessions.get(&conn) else {
            return Vec::new();
        };
        let mut seen = HashSet::new();
        for key in &session.channels {
            if let Some(chan) = self.channels.get(key) {
                seen.extend(chan.members.keys().copied());
            }
        }
        seen.remove(&conn);
        seen.into_iter().collect()
    }

    /// A notice from a services pseudo-client (NickServ, ChanServ).
    pub fn service_notice(&mut self, conn: ConnId, service: &str, text: &str) {
        let nick = self
            .sessions
            .get(&conn)
            .and_then(|s| s.nick.clone())
            .unwrap_or_else(|| "*".into());
        let host = format!("services.{}", self.config.server_name);
        let line = format!(":{service}!{service}@{host} NOTICE {nick} :{text}");
        self.send_timed(conn, &line);
    }

    // ---- teardown -------------------------------------------------------

    /// Remove a session: broadcast QUIT to channel peers, free the nick,
    /// drop memberships and empty channels.
    pub fn close(&mut self, conn: ConnId, reason: &str) {
        let Some(session) = self.sessions.get(&conn) else {
            return;
        };
        let was_registered = session.registered;
        if was_registered {
            self.record_whowas(conn);
        }
        let session = &self.sessions[&conn];
        let quit_line = was_registered.then(|| format!(":{} QUIT :{}", session.prefix(), reason));
        let joined: Vec<ChanKey> = session.channels.iter().cloned().collect();

        if let Some(line) = quit_line {
            // send_timed per peer so server-time clients get an @time= tag,
            // consistent with every other membership event (a raw send_bytes
            // loop would omit it for QUIT alone).
            let peers = self.channel_peers(conn);
            for p in peers {
                self.send_timed(p, &line);
            }
        }
        for key in joined {
            if let Some(chan) = self.channels.get_mut(&key) {
                chan.members.remove(&conn);
                if chan.members.is_empty() {
                    self.remove_channel(&key);
                }
            }
        }
        let session = self.sessions.remove(&conn).expect("checked above");
        for key in session.monitoring.keys() {
            if let Some(watchers) = self.monitors.get_mut(key) {
                watchers.remove(&conn);
                if watchers.is_empty() {
                    self.monitors.remove(key);
                }
            }
        }
        if let Some(nick) = &session.nick {
            let nick_key = NickKey(self.casemap.casefold(nick));
            self.nicks.remove(&nick_key);
            if was_registered {
                super::handler::monitor_notify(self, nick, false);
            }
        }
    }
}
