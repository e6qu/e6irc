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
    /// Unix-seconds clock, injected so tests are deterministic.
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
    /// Not in [`CAP_NAMES`]: advertised conditionally (`sasl_enabled`).
    pub sasl: bool,
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
    /// Command-flood token bucket (only used when `command_burst` is set):
    /// tokens remaining and the clock-second of the last refill.
    pub flood_tokens: u32,
    pub flood_last_sec: u64,
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
    /// `+nt`-style string with key/limit args appended.
    pub fn to_string_with_args(&self) -> String {
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
            modes.push('k');
            args.push(' ');
            args.push_str(k);
        }
        if let Some(l) = self.limit {
            modes.push('l');
            args.push_str(&format!(" {l}"));
        }
        modes + &args
    }
}

/// One line of channel history in the hot ring.
#[derive(Clone)]
pub(crate) struct HistoryEntry {
    pub msgid: String,
    pub ts: u64,
    pub sender_prefix: String,
    /// "PRIVMSG" or "NOTICE" as sent on the wire.
    pub kind: &'static str,
    pub body: String,
}

/// Ring capacity per channel; older entries live only in PostgreSQL.
pub(crate) const HISTORY_RING_CAP: usize = 500;

#[derive(Clone)]
pub(crate) struct Topic {
    pub text: String,
    pub set_by: String,
    pub set_at: u64,
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
    pub created_at: u64,
    /// Newest-last hot history ring for CHATHISTORY.
    pub history: std::collections::VecDeque<HistoryEntry>,
    /// True while the ring holds *every* message the channel has ever
    /// seen (never overflowed, never evicted). When false, older
    /// history lives only in Postgres and CHATHISTORY must fall back.
    pub history_complete: bool,
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
    /// Recent nick departures/changes for WHOWAS, newest-first.
    pub whowas: std::collections::VecDeque<WhowasEntry>,
    /// Channels holding a hot history ring, most-recently-active first.
    pub hot_channels: std::collections::VecDeque<ChanKey>,
    /// When set, direct sends to this connection are captured instead
    /// of delivered — the labeled-response machinery frames them.
    pub capture: Option<Capture>,
}

/// Buffered direct responses to a labeled command.
pub(crate) struct Capture {
    pub conn: ConnId,
    pub lines: Vec<Bytes>,
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
        Self {
            config,
            casemap: CaseMapping::Rfc1459,
            sessions: HashMap::new(),
            nicks: HashMap::new(),
            channels: HashMap::new(),
            doomed: Vec::new(),
            db_tx,
            max_users: 0,
            msgid_counter: 0,
            monitors: HashMap::new(),
            read_markers: HashMap::new(),
            registered_founders: HashMap::new(),
            registered_topics: HashMap::new(),
            whowas: std::collections::VecDeque::new(),
            hot_channels: std::collections::VecDeque::new(),
            capture: None,
        }
    }

    /// Append a message to a channel's hot ring, managing the global
    /// hot-channel LRU: touches this channel to MRU, evicts the ring of
    /// the least-recently-active channel once the cap is exceeded. An
    /// evicted or overflowed ring is marked incomplete so CHATHISTORY
    /// pages the remainder from Postgres.
    pub fn push_channel_history(&mut self, key: &ChanKey, entry: HistoryEntry) {
        {
            let Some(chan) = self.channels.get_mut(key) else {
                return;
            };
            if chan.history.len() == HISTORY_RING_CAP {
                chan.history.pop_front();
                chan.history_complete = false;
            }
            chan.history.push_back(entry);
        }
        // Move to MRU.
        self.hot_channels.retain(|k| k != key);
        self.hot_channels.push_front(key.clone());
        // Evict cold rings beyond the cap.
        while self.hot_channels.len() > self.config.max_hot_channels {
            if let Some(cold) = self.hot_channels.pop_back()
                && let Some(chan) = self.channels.get_mut(&cold)
            {
                chan.history.clear();
                chan.history.shrink_to_fit();
                chan.history_complete = false;
            }
        }
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
            .map(|(name_folded, text, set_by, set_at)| {
                (
                    ChanKey(name_folded),
                    Topic {
                        text,
                        set_by,
                        set_at,
                    },
                )
            })
            .collect();
    }

    /// Key a nick for lookup/storage.
    pub fn nick_key(&self, nick: &str) -> NickKey {
        NickKey(self.casemap.casefold(nick))
    }

    pub fn open(&mut self, conn: ConnId, tx: Sender<Output>, host: String) {
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
                pending_identify: false,
                away: None,
                oper: false,
                invisible: false,
                wallops: false,
                bot: false,
                invited: HashSet::new(),
                channels: HashSet::new(),
                monitoring: HashMap::new(),
                flood_tokens: 0,
                flood_last_sec: 0,
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
        let Some(session) = self.sessions.get(&conn) else {
            return; // events may race a close; the session is gone
        };
        if deliver(&session.tx, Output(bytes)).is_err() {
            self.doomed.push(conn);
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

    /// Unique message id: process-scoped counter + timestamp.
    pub fn next_msgid(&mut self) -> String {
        self.msgid_counter += 1;
        format!("{}-{}", (self.config.clock)(), self.msgid_counter)
    }

    /// The `@time=` tag value for events emitted now.
    pub fn time_tag(&self) -> String {
        e6irc_proto::time::server_time((self.config.clock)() * 1000)
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
            let peers = self.channel_peers(conn);
            let bytes = Bytes::from(format!("{line}\r\n"));
            for p in peers {
                self.send_bytes(p, bytes.clone());
            }
        }
        for key in joined {
            if let Some(chan) = self.channels.get_mut(&key) {
                chan.members.remove(&conn);
                if chan.members.is_empty() {
                    self.channels.remove(&key);
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
