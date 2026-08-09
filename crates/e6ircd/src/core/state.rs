//! All chat state, owned exclusively by the core worker.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Index;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::numerics::{
    ERR_NEEDMOREPARAMS, ERR_NOSUCHCHANNEL, ERR_NOSUCHNICK, ERR_NOTONCHANNEL,
};
use e6irc_queue::Sender;

use super::{CoreEffect, CoreShardCount, CoreShardId, Output, SessionOwner, WireLine, deliver};
use crate::observability::Telemetry;

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

/// Process-wide nick reservations and their session owners.
#[derive(Clone, Default)]
pub(crate) struct NickDirectory {
    by_key: Arc<Mutex<HashMap<NickKey, NickReservation>>>,
}

#[derive(Clone, Copy)]
struct NickReservation {
    owner: SessionOwner,
    registered: bool,
}

impl NickDirectory {
    pub(crate) fn owner(&self, key: &NickKey) -> Option<SessionOwner> {
        self.by_key
            .lock()
            .expect("nick directory poisoned")
            .get(key)
            .map(|reservation| reservation.owner)
    }

    pub(crate) fn registered_owner(&self, key: &NickKey) -> Option<SessionOwner> {
        self.by_key
            .lock()
            .expect("nick directory poisoned")
            .get(key)
            .and_then(|reservation| reservation.registered.then_some(reservation.owner))
    }

    pub(crate) fn claim(&self, key: NickKey, owner: SessionOwner, registered: bool) -> bool {
        let mut by_key = self.by_key.lock().expect("nick directory poisoned");
        match by_key.get(&key) {
            Some(existing) if existing.owner.conn() != owner.conn() => false,
            _ => {
                by_key.insert(key, NickReservation { owner, registered });
                true
            }
        }
    }

    pub(crate) fn release_if_owned(&self, key: &NickKey, conn: ConnId) -> bool {
        let mut by_key = self.by_key.lock().expect("nick directory poisoned");
        if by_key
            .get(key)
            .is_some_and(|owner| owner.owner.conn() == conn)
        {
            by_key.remove(key);
            return true;
        }
        false
    }

    pub(crate) fn mark_registered(&self, key: &NickKey, conn: ConnId) {
        if let Some(reservation) = self
            .by_key
            .lock()
            .expect("nick directory poisoned")
            .get_mut(key)
            && reservation.owner.conn() == conn
        {
            reservation.registered = true;
        }
    }
}

/// A channel list-mode mask (`+b`/`+q`/`+e`/`+I`), carrying both the casefolded
/// form used for equality and the original casing used for display and matching.
///
/// Extends the key-newtype discipline to the two places identities live in a
/// `Vec` rather than a map key (channel `+b`/`+q`/`+e`/`+I` lists and the
/// server-ban list): without it, dedup and removal fold *by hand* while
/// enforcement folds too, and a single site that forgets the fold silently
/// double-stores a ban or fails to remove one the matcher still enforces — the
/// class sweeps 54/67 fixed by hand. `PartialEq`/`Eq`/`Hash`
/// compare the folded form, so `#foo` and `#FOO` are one entry *by construction*
/// and `contains`/`retain` can't get it wrong; [`MaskKey::as_str`] returns the
/// original casing for `RPL_BANLIST` and for `mask::matches` (which folds the
/// mask itself). Build only via [`MaskKey::new`].
#[derive(Debug, Clone)]
pub struct MaskKey {
    folded: String,
    display: String,
}

impl MaskKey {
    pub fn new(mask: &str, casemap: CaseMapping) -> Self {
        Self {
            folded: casemap.casefold(mask),
            display: mask.to_string(),
        }
    }

    /// The mask in its stored (original) casing — for display and for
    /// `mask::matches`, which applies the casemapping to the mask itself.
    pub fn as_str(&self) -> &str {
        &self.display
    }

    /// The casefolded form — the identity key. Used where a mask is persisted
    /// with its fold as the storage/uniqueness key (server bans), so the DB key
    /// and the in-core equality agree.
    pub fn folded(&self) -> &str {
        &self.folded
    }
}

impl PartialEq for MaskKey {
    fn eq(&self, other: &Self) -> bool {
        self.folded == other.folded
    }
}
impl Eq for MaskKey {}
impl std::hash::Hash for MaskKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.folded.hash(state);
    }
}

/// Casefolded account key; same rationale as [`ChanKey`]. Account names are
/// compared case-insensitively (the DB enforces uniqueness on `name_folded`), so
/// every in-core map keyed by an account uses this rather than a raw `String` —
/// a display-cased account name can't index an account map, making the
/// "markers/founder/access split across two casings" bug class unrepresentable.
/// Build only via [`ServerState::account_key`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountKey(String);

impl AccountKey {
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
    pub clock: fn() -> e6irc_proto::time::Millis,
    /// **Monotonic**-milliseconds clock, injected separately from the wall
    /// clock above and used for every *timer* decision — the ping/registration
    /// reaper deadlines and the flood-bucket refill. Kept distinct (in source
    /// and in type, [`e6irc_proto::time::MonoMillis`]) so a timer can never be
    /// compared against wall-clock time, which an NTP step or VM resume can
    /// jump forward (mass-reaping every connection) or backward (freezing the
    /// reaper). The wall clock stays the source only for real timestamps
    /// (`server-time`, msgids, signon).
    pub mono_clock: fn() -> e6irc_proto::time::MonoMillis,
    /// Per-session command-flood bucket size; `None` disables the
    /// throttle. Registered non-oper sessions spend one token per
    /// command (PING/PONG exempt) and refill one token per second.
    pub command_burst: Option<usize>,
    /// Per-client-IP account-creation bucket size; `None` disables the throttle.
    /// One token is spent per REGISTER/NickServ-REGISTER that reaches account
    /// creation; the bucket refills to full over an hour (account creation is
    /// rare per real client, so a small burst suffices to blunt bulk-account
    /// abuse without hindering a genuine sign-up).
    pub registration_burst: Option<usize>,
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
    /// extended-monitor: MONITOR watchers also receive AWAY, ACCOUNT,
    /// SETNAME, and CHGHOST for monitored nicks (each still gated on the
    /// watcher holding that event's own cap).
    pub extended_monitor: bool,
    /// standard-replies: the client opted into the FAIL/WARN/NOTE reply
    /// framework. The server already emits FAIL lines for the error
    /// conditions that define them; the flag exists so CAP negotiation is
    /// explicit about the contract.
    pub standard_replies: bool,
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
    ("extended-monitor", |c| &mut c.extended_monitor),
    ("standard-replies", |c| &mut c.standard_replies),
    // The ratified name aliases the draft: same command, same negotiation.
    ("chathistory", |c| &mut c.chathistory),
];

/// A connection's registration state. Held as a sum type rather than a
/// `registered: bool` beside three `Option` identity fields so the invalid combo
/// "registered but no nick" is unrepresentable: `Registered` *has* a nick, user,
/// and realname by construction, so [`Session::prefix`] and every other
/// "a registered session has a nick" site is total, not `.expect()`-guarded.
pub(crate) enum Registration {
    /// Pre-registration: the nick and/or USER have not both arrived (or CAP END
    /// is still pending). Each identity field fills in independently.
    Registering {
        nick: Option<String>,
        user: Option<String>,
        realname: Option<String>,
    },
    /// Registration complete: the connection has a nick, user, and realname.
    Registered {
        nick: String,
        user: String,
        realname: String,
    },
}

#[derive(Debug)]
pub(crate) struct PendingServiceReply {
    label: Option<String>,
}

impl PendingServiceReply {
    pub(crate) fn new(label: Option<String>) -> Self {
        Self { label }
    }

    pub(crate) fn into_label(self) -> Option<String> {
        self.label
    }
}

pub(crate) struct Session {
    pub tx: Sender<Output>,
    pub host: String,
    pub transport: crate::core::ConnectionTransport,
    /// Registration state and the identity fields, as one sum type (see
    /// [`Registration`]): a registered connection *has* a nick/user/realname.
    pub reg: Registration,
    /// Mid-CAP-negotiation: registration is held until CAP END.
    pub cap_negotiating: bool,
    pub caps: Caps,
    /// Services account this connection is authenticated to.
    pub account: Option<String>,
    pub sasl: SaslState,
    /// A SASL credential verify is genuinely outstanding (dispatched, reply not
    /// yet seen). Unlike `sasl == Verifying`, this survives an `AUTHENTICATE *`
    /// abort — the abort clears the state machine but cannot un-send the DB
    /// request, so the reply still comes. It gates a *new* SASL verify and an
    /// IDENTIFY until that stale reply is drained, so a reply can never be
    /// attributed to a different attempt than the one that produced it.
    pub sasl_verify_pending: bool,
    /// Accumulates 400-byte AUTHENTICATE continuation chunks (SASL spec)
    /// until a short line completes the payload.
    pub sasl_buf: String,
    /// Credential-verification attempts made on this connection, capped so a
    /// single socket can't drive unbounded argon2 work (unauth CPU DoS / online
    /// brute-force). Never reset — the budget is per connection lifetime.
    pub credential_attempts: u32,
    /// Deferred NickServ IDENTIFY reply.
    pub pending_identify: Option<PendingServiceReply>,
    /// Deferred NickServ REGISTER reply.
    pub pending_register: Option<PendingServiceReply>,
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
    /// Joined channels.
    pub channels: HashSet<ChanKey>,
    /// Nicks this session MONITORs (display form as given).
    pub monitoring: HashMap<NickKey, String>,
    /// The `draft/multiline` batch this connection is filling, if any.
    pub multiline: Option<MultilineBatch>,
    /// Read markers for a client that isn't logged in: per-connection and not
    /// persisted (there is no account to key them to). A logged-in client uses
    /// the account-keyed `ServerState::read_markers` instead. A marker set here
    /// *before* a mid-session login is intentionally not migrated into the account
    /// map on IDENTIFY/SASL: it was unattributable when set, and carrying it over
    /// would write a persisted marker the client never asked to associate with the
    /// account (same reason the DM-history identity key is not back-filled).
    pub anon_read_markers: HashMap<ChanKey, e6irc_proto::time::Millis>,
    /// Command-flood token bucket (only used when `command_burst` is set):
    /// tokens remaining, and the clock-millisecond through which refill has
    /// already been credited (it advances by whole seconds only, so a
    /// sub-second remainder carries forward instead of being discarded).
    pub flood_tokens: u32,
    /// Monotonic — the flood refill is a timer, not a timestamp.
    pub flood_refilled_to_ms: e6irc_proto::time::MonoMillis,
    /// Monotonic millisecond of the last non-keepalive command — the elapsed
    /// idle duration since it (WHOIS idle / WHOX `l`) and the reaper's idle-ping
    /// cadence both read it. (WHOIS *signon*, a real timestamp, is `signon`.)
    pub last_active: e6irc_proto::time::MonoMillis,
    pub signon: e6irc_proto::time::Millis,
    /// Monotonic millisecond the connection opened, for the registration
    /// deadline (an unregistered connection that never completes is reaped).
    pub opened_at: e6irc_proto::time::MonoMillis,
    /// A server-initiated liveness PING is outstanding (set by the reaper,
    /// cleared on PONG); if still set at the pong deadline the socket is reaped.
    pub awaiting_pong: bool,
    /// Monotonic millisecond the outstanding liveness PING was sent.
    pub last_ping_sent: e6irc_proto::time::MonoMillis,
    /// How many database-backed replies this connection is still waiting on,
    /// and the output withheld behind them.
    ///
    /// The invariant this enforces: **ambiguous output never overtakes a
    /// deferred reply.** CHATHISTORY can only be answered after a round trip to
    /// PostgreSQL, and everything produced in the meantime — including the PONG
    /// to a PING the client pipelined right after — is held until every pending
    /// deferred reply resolves (the counter returns to 0). Without the hold, a
    /// client that treats that PONG as a sync point concludes the history was
    /// empty, which is indistinguishable from the server having no history at
    /// all.
    ///
    /// What this does *not* promise: strict issue-order between two *deferred*
    /// replies on the same connection. Each releases via the `emitting_deferred`
    /// bypass the moment its own DB round trip completes, so if a client
    /// pipelines two DB-backed commands whose completions race — e.g. a REGISTER
    /// (offloaded ~100ms argon2, see `db::CreateAccount`) then a CHATHISTORY
    /// (serial, ~ms) — the second may emit before the first. That is benign:
    /// both are *self-identifying* (a REGISTER SUCCESS/FAIL cannot be mistaken
    /// for a chathistory BATCH), ambiguous sync output stays held behind *both*
    /// (it flushes only at count 0), and a labeled-response client correlates
    /// each reply by its own label regardless of arrival order. Only the
    /// ambiguous-overtake case above is a real hazard, and that one is closed.
    pub deferred_replies: usize,
    pub held: Vec<Bytes>,
}

#[derive(Clone, Copy)]
struct SessionHandle {
    slot: usize,
    generation: u32,
}

struct SessionSlot {
    generation: u32,
    session: Option<Session>,
}

/// Dense sessions with generation-checked connection lookup.
pub(crate) struct SessionStore {
    by_conn: HashMap<ConnId, SessionHandle>,
    slots: Vec<SessionSlot>,
    free: Vec<usize>,
    len: usize,
}

pub(crate) struct SessionIter<'a> {
    by_conn: std::collections::hash_map::Iter<'a, ConnId, SessionHandle>,
    slots: &'a [SessionSlot],
}

impl<'a> Iterator for SessionIter<'a> {
    type Item = (&'a ConnId, &'a Session);

    fn next(&mut self) -> Option<Self::Item> {
        self.by_conn.find_map(|(conn, handle)| {
            let slot = self.slots.get(handle.slot)?;
            (slot.generation == handle.generation)
                .then_some(slot.session.as_ref())
                .flatten()
                .map(|session| (conn, session))
        })
    }
}

impl SessionStore {
    pub(crate) fn new() -> Self {
        Self {
            by_conn: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    pub(crate) fn get(&self, conn: &ConnId) -> Option<&Session> {
        let handle = self.by_conn.get(conn)?;
        let slot = self.slots.get(handle.slot)?;
        (slot.generation == handle.generation)
            .then_some(slot.session.as_ref())
            .flatten()
    }

    pub(crate) fn get_mut(&mut self, conn: &ConnId) -> Option<&mut Session> {
        let handle = *self.by_conn.get(conn)?;
        let slot = self.slots.get_mut(handle.slot)?;
        (slot.generation == handle.generation)
            .then_some(slot.session.as_mut())
            .flatten()
    }

    pub(crate) fn contains_key(&self, conn: &ConnId) -> bool {
        self.get(conn).is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Session> {
        self.slots.iter().filter_map(|slot| slot.session.as_ref())
    }

    pub(crate) fn iter(&self) -> SessionIter<'_> {
        SessionIter {
            by_conn: self.by_conn.iter(),
            slots: &self.slots,
        }
    }

    pub(crate) fn insert(&mut self, conn: ConnId, session: Session) -> Option<Session> {
        let previous = self.remove(&conn);
        let (slot_index, generation) = match self.free.pop() {
            Some(index) => (index, self.slots[index].generation),
            None => {
                self.slots.push(SessionSlot {
                    generation: 0,
                    session: None,
                });
                (self.slots.len() - 1, 0)
            }
        };
        self.slots[slot_index].session = Some(session);
        self.by_conn.insert(
            conn,
            SessionHandle {
                slot: slot_index,
                generation,
            },
        );
        self.len += 1;
        previous
    }

    pub(crate) fn remove(&mut self, conn: &ConnId) -> Option<Session> {
        let handle = self.by_conn.remove(conn)?;
        let slot = self.slots.get_mut(handle.slot)?;
        if slot.generation != handle.generation {
            return None;
        }
        let session = slot.session.take()?;
        self.len -= 1;
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            self.free.push(handle.slot);
        }
        Some(session)
    }
}

impl<'a> IntoIterator for &'a SessionStore {
    type Item = (&'a ConnId, &'a Session);
    type IntoIter = SessionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Index<&ConnId> for SessionStore {
    type Output = Session;

    fn index(&self, conn: &ConnId) -> &Self::Output {
        self.get(conn).expect("indexed session is present")
    }
}

impl Session {
    /// Whether registration has completed.
    pub fn is_registered(&self) -> bool {
        matches!(self.reg, Registration::Registered { .. })
    }

    /// The current nick, in either registration state (`None` before NICK).
    pub fn nick(&self) -> Option<&str> {
        match &self.reg {
            Registration::Registering { nick, .. } => nick.as_deref(),
            Registration::Registered { nick, .. } => Some(nick),
        }
    }

    /// The username, in either state (`None` before USER).
    pub fn user(&self) -> Option<&str> {
        match &self.reg {
            Registration::Registering { user, .. } => user.as_deref(),
            Registration::Registered { user, .. } => Some(user),
        }
    }

    /// The realname, in either state (`None` before USER).
    pub fn realname(&self) -> Option<&str> {
        match &self.reg {
            Registration::Registering { realname, .. } => realname.as_deref(),
            Registration::Registered { realname, .. } => Some(realname),
        }
    }

    /// Set (or, once registered, rename) the nick — valid in both states, since a
    /// NICK rename happens after registration too.
    pub fn set_nick(&mut self, value: String) {
        match &mut self.reg {
            Registration::Registering { nick, .. } => *nick = Some(value),
            Registration::Registered { nick, .. } => *nick = value,
        }
    }

    /// Set the username (only meaningful pre-registration; USER is sent once).
    pub fn set_user(&mut self, value: String) {
        if let Registration::Registering { user, .. } = &mut self.reg {
            *user = Some(value);
        }
    }

    /// Set the realname — valid in both states (SETNAME changes it post-registration).
    pub fn set_realname(&mut self, value: String) {
        match &mut self.reg {
            Registration::Registering { realname, .. } => *realname = Some(value),
            Registration::Registered { realname, .. } => *realname = value,
        }
    }

    /// Transition `Registering → Registered` once a nick and user are present.
    /// The caller (`maybe_complete_registration`) verifies both first; realname is
    /// set alongside user, so it defaults to empty only defensively. A no-op if
    /// already registered or the identity is incomplete.
    pub fn complete_registration(&mut self) {
        let placeholder = Registration::Registering {
            nick: None,
            user: None,
            realname: None,
        };
        self.reg = match std::mem::replace(&mut self.reg, placeholder) {
            Registration::Registering {
                nick: Some(nick),
                user: Some(user),
                realname,
            } => Registration::Registered {
                nick,
                user,
                realname: realname.unwrap_or_default(),
            },
            // Already registered, or not yet complete: restore unchanged.
            other => other,
        };
    }

    /// `nick!user@host` — total on a registered session (its nick/user exist by
    /// construction). Calling it on an unregistered session is a caller bug.
    pub fn prefix(&self) -> String {
        match &self.reg {
            Registration::Registered { nick, user, .. } => {
                format!("{nick}!{user}@{}", self.host)
            }
            Registration::Registering { .. } => {
                unreachable!("prefix() on an unregistered session")
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MemberModes {
    pub op: bool,
    pub voice: bool,
}

/// A channel recipient and the worker that owns its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recipient {
    owner: SessionOwner,
    caps: Caps,
}

impl Recipient {
    pub(crate) fn new(owner: SessionOwner, caps: Caps) -> Self {
        Self { owner, caps }
    }

    pub(crate) fn conn(self) -> ConnId {
        self.owner.conn()
    }

    pub(crate) fn shard(self) -> CoreShardId {
        self.owner.shard()
    }

    pub(crate) fn owner(self) -> SessionOwner {
        self.owner
    }

    pub(crate) fn caps(self) -> Caps {
        self.caps
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MemberIdentity {
    pub(crate) nick: String,
    pub(crate) prefix: String,
    pub(crate) invisible: bool,
}

impl MemberIdentity {
    pub(crate) fn new(nick: String, prefix: String, invisible: bool) -> Self {
        Self {
            nick,
            prefix,
            invisible,
        }
    }
}

/// Immutable session data a channel operation may use.
#[derive(Debug, Clone)]
pub struct ChannelActor {
    pub(crate) recipient: Recipient,
    pub(crate) identity: MemberIdentity,
    pub(crate) account: Option<String>,
    pub(crate) realname: String,
    pub(crate) away: Option<String>,
    pub(crate) bot: bool,
}

impl ChannelActor {
    pub(crate) fn session_owner(&self) -> SessionOwner {
        self.recipient.owner
    }
}

/// A channel owner's complete answer to a JOIN request.
///
/// This crosses back to the session owner instead of giving the channel owner
/// access to another shard's session table.
#[derive(Debug, Clone)]
pub enum ChannelJoinResult {
    Joined(ChannelJoinSuccess),
    Rejected(ChannelJoinFailure),
}

#[derive(Debug, Clone)]
pub struct ChannelJoinSuccess {
    pub(crate) key: ChanKey,
    pub(crate) display: String,
    pub(crate) topic: Option<Topic>,
    pub(crate) secret: bool,
    pub(crate) members: Vec<(MemberModes, MemberIdentity)>,
    pub(crate) own_join: String,
    pub(crate) own_mode: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ChannelJoinFailure {
    NoSuchChannel { name: String },
    InviteOnly { name: String },
    Banned { name: String },
    BadKey { name: String },
    Full { name: String },
}

#[derive(Debug, Clone)]
pub enum ChannelPartResult {
    Parted { key: ChanKey, line: String },
    NotOnChannel { name: String },
}

/// A complete QUIT request for one channel owner.
#[derive(Debug)]
pub struct ChannelQuit {
    owner: ChannelOwner,
    conn: ConnId,
    line: String,
}

/// A parsed request, owned by its channel shard.
#[derive(Debug, Clone)]
pub struct ChannelRequest<Operation> {
    owner: ChannelOwner,
    actor: ChannelActor,
    target: String,
    operation: Operation,
    label: Option<String>,
}

pub type ChannelTopic = ChannelRequest<ChannelTopicOperation>;

/// A channel command that must execute on the channel owner.
pub type ChannelCommand = ChannelRequest<ChannelCommandOperation>;

/// Closed channel-command operations.
#[derive(Debug, Clone)]
pub enum ChannelCommandOperation {
    Knock,
    Invite(ChannelInvitee),
    ModeQuery,
    ModeListQuery(String),
}

#[derive(Debug, Clone)]
pub struct ChannelInvitee {
    owner: SessionOwner,
    requested_nick: String,
}

impl ChannelInvitee {
    pub(crate) fn new(owner: SessionOwner, requested_nick: String) -> Self {
        Self {
            owner,
            requested_nick,
        }
    }

    pub(crate) fn owner(&self) -> SessionOwner {
        self.owner
    }

    pub(crate) fn requested_nick(&self) -> &str {
        &self.requested_nick
    }
}

impl<Operation> ChannelRequest<Operation> {
    pub(crate) fn new(
        owner: ChannelOwner,
        actor: ChannelActor,
        target: String,
        operation: Operation,
        label: Option<String>,
    ) -> Self {
        Self {
            owner,
            actor,
            target,
            operation,
            label,
        }
    }

    pub(crate) fn owner(&self) -> &ChannelOwner {
        &self.owner
    }

    pub(crate) fn actor(&self) -> &ChannelActor {
        &self.actor
    }

    pub(crate) fn label(&self) -> Option<String> {
        self.label.clone()
    }

    pub(crate) fn into_parts(self) -> (ChannelOwner, ChannelActor, String, Operation) {
        (self.owner, self.actor, self.target, self.operation)
    }
}

impl<Operation: Clone> ChannelRequest<Operation> {
    pub(crate) fn operation(&self) -> Operation {
        self.operation.clone()
    }
}

/// A channel command's reply to its requester.
#[derive(Debug)]
pub enum ChannelCommandResult {
    Knock(ChannelKnockResult),
    Invite(ChannelInviteResult),
    ModeQuery(ChannelModeQueryResult),
    ModeListQuery(ChannelModeListQueryResult),
}

#[derive(Debug)]
pub enum ChannelKnockResult {
    KnockDelivered,
    NoSuchChannel { target: String },
    Hidden { target: String },
    AlreadyOnChannel { display: String },
    ChannelOpen { display: String },
    CannotSend { display: String },
}

#[derive(Debug)]
pub enum ChannelInviteResult {
    Invited { invitee: String, channel: String },
    NoSuchChannel { target: String },
    NotOnChannel { target: String },
    NotOperator { target: String },
    UserOnChannel { invitee: String, channel: String },
}

#[derive(Debug)]
pub enum ChannelModeQueryResult {
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
    },
    Modes {
        display: String,
        modes: String,
        created: String,
    },
}

#[derive(Debug)]
pub enum ChannelModeListQueryResult {
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
    },
    NotOperator {
        target: String,
    },
    Lists {
        display: String,
        lists: Vec<ChannelModeList>,
    },
}

#[derive(Debug)]
pub struct ChannelModeList {
    pub(crate) mode: char,
    pub(crate) masks: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ChannelSessionEvent {
    Invitation {
        inviter_prefix: String,
        inviter_account: Option<String>,
        channel: String,
    },
}

/// A TOPIC request has exactly one operation.
#[derive(Debug, Clone)]
pub enum ChannelTopicOperation {
    Query,
    Set(String),
}

/// A channel owner's TOPIC answer, delivered only to the requester's session owner.
#[derive(Debug)]
pub enum ChannelTopicResult {
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
    },
    Topic {
        display: String,
        topic: Option<Topic>,
    },
    Set {
        line: String,
    },
    NotOnChannel {
        target: String,
    },
    NotOperator {
        target: String,
    },
    CannotSend {
        target: String,
    },
    Unavailable {
        display: String,
        message: String,
    },
    PersistenceFailed {
        display: String,
        failure: crate::core::ChannelTopicFailure,
    },
}

#[derive(Debug, Clone)]
pub struct ChannelKick {
    owner: ChannelOwner,
    actor: ChannelActor,
    target: String,
    victim: String,
    reason: Option<String>,
    label: Option<String>,
}

impl ChannelKick {
    pub(crate) fn new(
        owner: ChannelOwner,
        actor: ChannelActor,
        target: String,
        victim: String,
        reason: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            owner,
            actor,
            target,
            victim,
            reason,
            label,
        }
    }
    pub(crate) fn owner(&self) -> &ChannelOwner {
        &self.owner
    }
    pub(crate) fn actor(&self) -> &ChannelActor {
        &self.actor
    }
    pub(crate) fn label(&self) -> Option<String> {
        self.label.clone()
    }
    pub(crate) fn into_parts(self) -> (ChannelOwner, ChannelActor, String, String, Option<String>) {
        (
            self.owner,
            self.actor,
            self.target,
            self.victim,
            self.reason,
        )
    }
}

#[derive(Debug)]
pub enum ChannelKickResult {
    Kicked,
    NoSuchChannel { target: String },
    NotOnChannel { target: String },
    NotOperator { target: String },
    UserNotInChannel { victim: String, channel: String },
}

/// A parsed channel PRIVMSG or NOTICE, owned by its channel shard.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    owner: ChannelOwner,
    actor: ChannelActor,
    target: String,
    text: String,
    kind: crate::core::MessageKind,
    client_tags: String,
    label: Option<String>,
}

impl ChannelMessage {
    pub(crate) fn new(
        owner: ChannelOwner,
        actor: ChannelActor,
        target: String,
        text: String,
        kind: crate::core::MessageKind,
        client_tags: String,
        label: Option<String>,
    ) -> Self {
        Self {
            owner,
            actor,
            target,
            text,
            kind,
            client_tags,
            label,
        }
    }

    pub(crate) fn owner(&self) -> &ChannelOwner {
        &self.owner
    }

    pub(crate) fn actor(&self) -> &ChannelActor {
        &self.actor
    }

    pub(crate) fn label(&self) -> Option<String> {
        self.label.clone()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ChannelOwner,
        ChannelActor,
        String,
        String,
        crate::core::MessageKind,
        String,
    ) {
        (
            self.owner,
            self.actor,
            self.target,
            self.text,
            self.kind,
            self.client_tags,
        )
    }
}

/// The channel owner's complete answer to a parsed channel message.
#[derive(Debug)]
pub enum ChannelMessageResult {
    Delivered {
        echo: Option<Bytes>,
    },
    NoSuchChannel {
        target: String,
        loud: bool,
    },
    CannotSend {
        target: String,
        no_ctcp: bool,
        loud: bool,
    },
}

/// A completed channel multiline message.
#[derive(Debug)]
pub struct ChannelMultiline {
    owner: ChannelOwner,
    actor: ChannelActor,
    batch: MultilineBatch,
}

impl ChannelMultiline {
    pub(crate) fn new(owner: ChannelOwner, actor: ChannelActor, batch: MultilineBatch) -> Self {
        Self {
            owner,
            actor,
            batch,
        }
    }

    pub(crate) fn owner(&self) -> &ChannelOwner {
        &self.owner
    }
    pub(crate) fn actor(&self) -> &ChannelActor {
        &self.actor
    }
    pub(crate) fn into_parts(self) -> (ChannelOwner, ChannelActor, MultilineBatch) {
        (self.owner, self.actor, self.batch)
    }
}

/// A channel-owner multiline outcome delivered to the sender's session owner.
#[derive(Debug)]
pub enum ChannelMultilineResult {
    Delivered {
        echo: Vec<Bytes>,
        label: Option<String>,
    },
    NoSuchChannel {
        target: String,
        loud: bool,
        label: Option<String>,
    },
    CannotSend {
        target: String,
        no_ctcp: bool,
        loud: bool,
        label: Option<String>,
    },
}

/// A parsed channel TAGMSG, owned by its channel shard.
pub type ChannelTagmsg = ChannelRequest<String>;

/// The channel owner's answer to a parsed channel TAGMSG.
#[derive(Debug)]
pub enum ChannelTagmsgResult {
    Delivered { echo: Option<Bytes> },
    NoSuchChannel { target: String },
    CannotSend { target: String },
}

impl ChannelQuit {
    pub(crate) fn new(owner: ChannelOwner, conn: ConnId, line: String) -> Self {
        Self { owner, conn, line }
    }

    pub(crate) fn owner(&self) -> &ChannelOwner {
        &self.owner
    }

    pub(crate) fn conn(&self) -> ConnId {
        self.conn
    }

    pub(crate) fn line(&self) -> &str {
        &self.line
    }
}

struct ChannelMember {
    modes: MemberModes,
    recipient: Recipient,
    identity: MemberIdentity,
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
        // Render equal policies identically regardless of input order.
        m.on = Self::LOCKABLE
            .iter()
            .copied()
            .filter(|mode| m.on.contains(*mode))
            .collect();
        m.off = Self::LOCKABLE
            .iter()
            .copied()
            .filter(|mode| m.off.contains(*mode))
            .collect();
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
    pub ts: e6irc_proto::time::Millis,
    pub sender_prefix: String,
    /// The sender's account at send time (`None` if unauthenticated); lets DM
    /// replay re-address by stable identity rather than by the sender's nick.
    pub sender_account: Option<String>,
    /// "PRIVMSG" or "NOTICE" as sent on the wire.
    pub kind: crate::core::MessageKind,
    pub body: String,
    /// The sender was a bot (+B) at send time, so replay re-emits the `bot`
    /// message tag a message-tags recipient saw live.
    pub sender_is_bot: bool,
    /// For a `draft/multiline` message: its lines encoded as one string
    /// (`crate::core::handler::message::encode_multiline`), so the whole message
    /// is one history entry with one msgid — not one row per line with fresh,
    /// never-delivered msgids. `None` for an ordinary single-line message;
    /// `body` then holds the text. On replay a `Some` reconstructs the multiline
    /// batch (or flattens) reusing the single msgid, as live delivery did.
    pub multiline: Option<String>,
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
#[derive(Debug)]
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
    pub kind: Option<crate::core::MessageKind>,
}

/// One target's newest-last hot history.
pub(crate) struct HistoryRing {
    pub entries: std::collections::VecDeque<HistoryEntry>,
    /// True while the ring holds *every* message this target has ever seen
    /// (never overflowed, never evicted). When false, older history lives
    /// only in Postgres and CHATHISTORY must fall back.
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct Topic {
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
/// session field named by `kind`. `mask` is a [`MaskKey`], so removal compares
/// the folded form (a `KLINE Baddie@Host` is lifted by `UNKLINE baddie@host`)
/// by construction, while STATS and the confirmation show the operator's
/// original casing — the same discipline the channel `+b`/`+q`/`+e`/`+I` lists
/// use, rather than a fold-by-hand `String` plus a `mask::eq` at each site.
#[derive(Clone)]
pub struct ServerBan {
    pub mask: MaskKey,
    pub reason: String,
    pub set_by: String,
    pub kind: BanKind,
}

pub(crate) struct Channel {
    /// Display name (creator's casing).
    pub name: String,
    pub topic: Option<Topic>,
    members: HashMap<ConnId, ChannelMember>,
    recipients: RefCell<Option<Arc<[Recipient]>>>,
    pub modes: ChanModes,
    pub bans: Vec<MaskKey>,
    pub quiets: Vec<MaskKey>,
    pub ban_exceptions: Vec<MaskKey>,
    pub invite_exceptions: Vec<MaskKey>,
    /// Connections holding a pending INVITE into this channel (consumed on
    /// join). Lives on the channel — not the invitee's session — so channel
    /// teardown revokes it: an invite is a grant by an op of *this* channel
    /// incarnation, and a session-side set keyed by name would let it
    /// authorize entry into an unrelated later channel reusing the name
    /// (a +i bypass). Bounded by `INVITE_LIMIT` per channel.
    pub invited: HashSet<ConnId>,
    /// Unix **seconds** — RPL_CREATIONTIME reports whole seconds, so this is
    /// deliberately coarser than the millisecond `Config::clock`.
    pub created_at_secs: u64,
}

/// Proof that a `+s` (secret) channel must look non-existent to a connection.
/// Constructible only by [`Channel::hidden_from`] and consumed only by the
/// handler's `deny_hidden`, which answers `ERR_NOSUCHCHANNEL`. So every surface
/// that denies access to a hidden channel reports the *same* "no such channel"
/// — none can hand-pick a numeric (like 442 `ERR_NOTONCHANNEL`) that would
/// instead confirm the channel exists, which is exactly how a `TOPIC`-query
/// existence oracle slipped in.
pub(crate) struct Hidden(());

impl Channel {
    pub fn new(name: String, topic: Option<Topic>, modes: ChanModes, created_at_secs: u64) -> Self {
        Self {
            name,
            topic,
            members: HashMap::new(),
            recipients: RefCell::new(None),
            modes,
            bans: Vec::new(),
            quiets: Vec::new(),
            ban_exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            invited: HashSet::new(),
            created_at_secs,
        }
    }

    pub fn is_member(&self, conn: ConnId) -> bool {
        self.members.contains_key(&conn)
    }

    pub fn member(&self, conn: ConnId) -> Option<&MemberModes> {
        self.members.get(&conn).map(|member| &member.modes)
    }

    pub fn member_mut(&mut self, conn: ConnId) -> Option<&mut MemberModes> {
        self.members.get_mut(&conn).map(|member| &mut member.modes)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn has_members(&self) -> bool {
        !self.members.is_empty()
    }

    pub fn members(&self) -> impl Iterator<Item = (ConnId, &MemberModes)> {
        self.members
            .iter()
            .map(|(conn, member)| (*conn, &member.modes))
    }

    pub fn recipients_where(
        &self,
        mut include: impl FnMut(ConnId, &MemberModes) -> bool,
    ) -> Vec<Recipient> {
        self.members
            .iter()
            .filter(|(conn, member)| include(**conn, &member.modes))
            .map(|(_, member)| member.recipient)
            .collect()
    }

    /// Immutable recipients, rebuilt only after a join or part.
    pub fn recipients(&self) -> Arc<[Recipient]> {
        let mut cached = self.recipients.borrow_mut();
        if let Some(recipients) = cached.as_ref() {
            return Arc::clone(recipients);
        }
        let recipients = self
            .members
            .values()
            .map(|member| member.recipient)
            .collect();
        *cached = Some(Arc::clone(&recipients));
        recipients
    }

    pub fn add_member(
        &mut self,
        recipient: Recipient,
        identity: MemberIdentity,
        modes: MemberModes,
    ) {
        self.members.insert(
            recipient.conn(),
            ChannelMember {
                modes,
                recipient,
                identity,
            },
        );
        self.recipients.get_mut().take();
    }

    pub fn remove_member(&mut self, conn: ConnId) -> Option<MemberModes> {
        let removed = self.members.remove(&conn).map(|member| member.modes);
        if removed.is_some() {
            self.recipients.get_mut().take();
        }
        removed
    }

    pub fn update_recipient(&mut self, recipient: Recipient) {
        let Some(member) = self.members.get_mut(&recipient.conn()) else {
            return;
        };
        if member.recipient != recipient {
            member.recipient = recipient;
            self.recipients.get_mut().take();
        }
    }

    pub fn member_identities(
        &self,
    ) -> impl Iterator<Item = (ConnId, &MemberModes, &MemberIdentity)> {
        self.members
            .iter()
            .map(|(conn, member)| (*conn, &member.modes, &member.identity))
    }

    pub fn operator_recipients(&self) -> Vec<(Recipient, String)> {
        self.members
            .values()
            .filter(|member| member.modes.op)
            .map(|member| (member.recipient, member.identity.nick.clone()))
            .collect()
    }

    /// Resolve a member from channel-owned identity data.
    pub fn member_named(
        &self,
        casemap: CaseMapping,
        nick: &str,
    ) -> Option<(ConnId, Recipient, &MemberIdentity)> {
        let nick = casemap.casefold(nick);
        self.members.iter().find_map(|(conn, member)| {
            (casemap.casefold(&member.identity.nick) == nick).then_some((
                *conn,
                member.recipient,
                &member.identity,
            ))
        })
    }

    /// Is this secret channel invisible to `conn`? A `+s` channel is hidden from
    /// non-members on every query surface — its existence, modes, topic, and
    /// member lists all. The single source of that predicate: deny surfaces
    /// (`MODE`/`KNOCK`/`TOPIC`) take the returned [`Hidden`] to `deny_hidden`;
    /// content-listing surfaces (`NAMES`/`WHO`/`WHOIS`/`LIST`) test `.is_some()`
    /// and simply omit the channel's rows.
    pub(crate) fn hidden_from(&self, conn: ConnId) -> Option<Hidden> {
        (self.modes.secret && !self.is_member(conn)).then_some(Hidden(()))
    }

    fn any_match(casemap: CaseMapping, masks: &[MaskKey], subject: &str) -> bool {
        masks
            .iter()
            .any(|m| e6irc_proto::mask::matches(casemap, m.as_str(), subject))
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

    /// Whether a sender with membership `member` (its `MemberModes`, or `None`
    /// when off-channel) and hostmask `prefix` may send to this channel.
    ///
    /// The single gate for text (PRIVMSG/NOTICE) and tags (TAGMSG) alike: a
    /// client that cannot speak must not be able to relay typing/reaction tags
    /// it could not relay as a message, and the two paths drifting apart is
    /// exactly how that would happen. Op/voice bypass +m and bans; an ordinary
    /// or off-channel sender is subject to +m, bans and quiets, and an
    /// off-channel one additionally to +n. STATUSMSG/CTCP are checked by the
    /// caller — they are message-shape concerns, not membership ones.
    pub fn may_speak(
        &self,
        member: Option<&MemberModes>,
        casemap: CaseMapping,
        prefix: &str,
    ) -> bool {
        match member {
            Some(m) if m.op || m.voice => true,
            Some(_) => {
                !self.modes.moderated
                    && !self.is_banned(casemap, prefix)
                    && !self.is_quieted(casemap, prefix)
            }
            None => {
                !self.modes.no_external
                    && !self.modes.moderated
                    && !self.is_banned(casemap, prefix)
                    && !self.is_quieted(casemap, prefix)
            }
        }
    }
}

/// The local worker's channel state and its ownership boundary.
/// A channel key paired with the only core shard allowed to mutate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOwner {
    key: ChanKey,
    shard: CoreShardId,
}

impl ChannelOwner {
    pub(crate) fn shard(&self) -> CoreShardId {
        self.shard
    }

    pub(crate) fn key(&self) -> &ChanKey {
        &self.key
    }
}

pub(crate) struct ChannelDirectory {
    shards: CoreShardCount,
    channels: HashMap<ChanKey, Channel>,
}

impl ChannelDirectory {
    pub(crate) fn new(shards: CoreShardCount) -> Self {
        Self {
            shards,
            channels: HashMap::new(),
        }
    }

    pub(crate) fn owner(&self, key: &ChanKey) -> ChannelOwner {
        ChannelOwner {
            key: key.clone(),
            shard: self.shards.shard_for_channel(key),
        }
    }

    pub(crate) fn get(&self, key: &ChanKey) -> Option<&Channel> {
        self.channels.get(key)
    }

    pub(crate) fn get_mut(&mut self, key: &ChanKey) -> Option<&mut Channel> {
        self.channels.get_mut(key)
    }

    pub(crate) fn contains_key(&self, key: &ChanKey) -> bool {
        self.channels.contains_key(key)
    }

    pub(crate) fn entry(
        &mut self,
        key: ChanKey,
    ) -> std::collections::hash_map::Entry<'_, ChanKey, Channel> {
        self.channels.entry(key)
    }

    pub(crate) fn remove(&mut self, key: &ChanKey) -> Option<Channel> {
        self.channels.remove(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.channels.len()
    }

    pub(crate) fn iter(&self) -> std::collections::hash_map::Iter<'_, ChanKey, Channel> {
        self.channels.iter()
    }
}

impl Index<&ChanKey> for ChannelDirectory {
    type Output = Channel;

    fn index(&self, key: &ChanKey) -> &Self::Output {
        &self.channels[key]
    }
}

pub(crate) struct ServerState {
    shard: CoreShardId,
    pub telemetry: Arc<Telemetry>,
    pub config: CoreConfig,
    pub casemap: CaseMapping,
    pub sessions: SessionStore,
    nicks: NickDirectory,
    pub channels: ChannelDirectory,
    /// Connections whose SendQ overflowed during this event; swept (and
    /// killed) by `Core::handle` after the event completes.
    pub doomed: Vec<ConnId>,
    effects: Vec<CoreEffect>,
    /// Durably suspended accounts. This gate lives on the same ordered core
    /// thread as credential verdicts and administrative disconnects, so a
    /// verification already in flight cannot re-authenticate after the
    /// suspension event has run.
    pub suspended_accounts: HashSet<AccountKey>,
    /// Requests to the DB worker (answered via `Input::DbReply`).
    pub db_tx: Sender<super::DbRequest>,
    /// High-water mark of simultaneously registered users (LUSERS max).
    pub max_users: usize,
    /// Wall-clock millisecond the server state was created (STATS u uptime,
    /// which reports the difference in whole seconds).
    pub started_at: e6irc_proto::time::Millis,
    /// Monotonic per-process counter for msgid uniqueness.
    pub msgid_counter: u64,
    /// MONITOR: watched nick → watching connections.
    pub monitors: HashMap<NickKey, HashSet<ConnId>>,
    /// Read markers: (account, target) → epoch millis. Mirrors the
    /// PostgreSQL table; this is the hot copy the core serves.
    pub read_markers: HashMap<(AccountKey, ChanKey), e6irc_proto::time::Millis>,
    /// Number of database writes in flight for each account/target. A target
    /// is reserved here before its first durable write completes, so pipelined
    /// MARKREAD commands cannot evade the per-account distinct-target cap.
    pub pending_read_markers: HashMap<(AccountKey, ChanKey), usize>,
    /// Registered channels → founder account (both casefolded). The hot
    /// copy of the `channels` table's ownership, boot-loaded and updated
    /// on registration; a founder rejoining their channel is re-opped.
    pub registered_founders: HashMap<ChanKey, AccountKey>,
    /// Channel registrations waiting for a database verdict, keyed by channel
    /// and carrying the founder reservation. A pending name cannot be queued
    /// twice, and pending reservations count toward the per-account cap.
    pub pending_channel_registrations: HashMap<ChanKey, AccountKey>,
    /// Registered channels → retained topic. Boot-loaded and kept in sync
    /// on TOPIC; restored when a registered channel is recreated so its
    /// topic survives the channel going empty.
    pub registered_topics: HashMap<ChanKey, Topic>,
    /// Latest requested TOPIC per registered channel while its database
    /// verdict is pending. The revision prevents an older reply from clearing
    /// a newer request. SET KEEPTOPIC reads this overlay instead of a stale
    /// committed live topic when the two commands are pipelined.
    pub pending_channel_topics: HashMap<ChanKey, (u64, Option<Topic>)>,
    /// Monotonic revision source for `pending_channel_topics`.
    pub channel_topic_revision: u64,
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
    pub channel_access: HashMap<ChanKey, HashMap<AccountKey, String>>,
    /// Server bans (oper K/D/X-lines) refused at registration. Boot-loaded
    /// and kept in sync on KLINE/DLINE/XLINE and their removals.
    pub server_bans: Vec<ServerBan>,
    /// `(kind, folded mask)` server-ban mutations awaiting a database verdict.
    /// A second mutation of the same durable row is refused explicitly instead
    /// of making authorization/existence decisions against stale hot state.
    pub pending_server_bans: HashSet<(String, String)>,
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
    /// Per-client-IP account-creation token buckets (only used when
    /// `registration_burst` is set): folded host → (tokens, monotonic
    /// millisecond refill has been credited through). Bounds bulk-account
    /// abuse from one address; hard-capped at `MAX_REGISTRATION_BUCKETS` so
    /// a distinct-IP flood can't grow it without bound.
    pub registration_buckets: HashMap<String, (f64, e6irc_proto::time::MonoMillis)>,
    /// HTTP admin requests waiting for a registered-channel delete verdict.
    /// The DB queue carries only the numeric ID, keeping `DbRequest` clonable
    /// and comparable while the one-shot responder remains core-owned.
    pub pending_admin_channel_drops: HashMap<u64, tokio::sync::oneshot::Sender<super::AdminReply>>,
    /// Monotonic request ID source for `pending_admin_channel_drops`.
    pub admin_channel_drop_id: u64,
    /// HTTP admin server-ban mutations awaiting their database verdict.
    pub pending_admin_server_bans: HashMap<u64, tokio::sync::oneshot::Sender<super::AdminReply>>,
    /// Monotonic request ID source for `pending_admin_server_bans`.
    pub admin_server_ban_id: u64,
    /// Founder-owned HTTP channel mutations awaiting a database verdict.
    pub pending_channel_controls: HashMap<u64, tokio::sync::oneshot::Sender<super::AdminReply>>,
    /// Monotonic request ID source for `pending_channel_controls`.
    pub channel_control_id: u64,
}

/// Hard ceiling on the account-creation bucket map, mirroring the HTTP
/// `auth_rate_ok` limiter: the refill window is long (an hour), so a flood
/// from many distinct IPs keeps every entry below full and nothing prunes —
/// this cap bounds the map by evicting the least-recently-seen entry.
pub(crate) const MAX_REGISTRATION_BUCKETS: usize = 4096;

/// Account creation is rare per genuine client, so the bucket refills to full
/// slowly (one hour). A small burst absorbs a legitimate retry while capping
/// how fast one address can mint accounts.
const REGISTRATION_REFILL_WINDOW_MS: u64 = 60 * 60 * 1000;

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
    /// When the entry was recorded (departure/nick-change), for the
    /// RPL_WHOISSERVER "last seen" info field.
    pub signoff: e6irc_proto::time::Millis,
}

pub(crate) const WHOWAS_CAP: usize = 1000;

impl ServerState {
    pub fn local_recipient(&self, conn: ConnId) -> Recipient {
        Recipient::new(
            SessionOwner::new(conn, self.shard),
            self.sessions[&conn].caps,
        )
    }

    pub fn local_member_identity(&self, conn: ConnId) -> MemberIdentity {
        let session = &self.sessions[&conn];
        MemberIdentity::new(
            session.nick().expect("registered member").to_string(),
            session.prefix(),
            session.invisible,
        )
    }

    pub fn channel_actor(&self, conn: ConnId) -> ChannelActor {
        let session = &self.sessions[&conn];
        ChannelActor {
            recipient: self.local_recipient(conn),
            identity: self.local_member_identity(conn),
            account: session.account.clone(),
            realname: session.realname().expect("registered session").to_string(),
            away: session.away.clone(),
            bot: session.bot,
        }
    }

    pub fn channel_owner(&self, name: &str) -> ChannelOwner {
        self.channels.owner(&self.chan_key(name))
    }

    pub fn owns_channel(&self, owner: &ChannelOwner) -> bool {
        owner.shard() == self.shard
    }

    pub fn channel_reply_label(&mut self, conn: ConnId, owner: &ChannelOwner) -> Option<String> {
        if self.owns_channel(owner) {
            self.capture
                .as_ref()
                .and_then(|capture| capture.label.clone())
        } else {
            self.defer_channel_reply(conn)
        }
    }

    pub fn owns_session(&self, owner: SessionOwner) -> bool {
        owner.shard() == self.shard
    }

    pub fn route_join(
        &mut self,
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        join_key: Option<String>,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelJoin {
            owner,
            actor,
            name,
            join_key,
            label,
        });
    }

    pub fn route_join_result(
        &mut self,
        session: SessionOwner,
        result: ChannelJoinResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelJoinResult {
            session,
            result,
            label,
        });
    }

    pub fn route_part(
        &mut self,
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        reason: Option<String>,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelPart {
            owner,
            actor,
            name,
            reason,
            label,
        });
    }

    pub fn route_part_result(
        &mut self,
        session: SessionOwner,
        result: ChannelPartResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelPartResult {
            session,
            result,
            label,
        });
    }

    pub fn route_quit(&mut self, quit: ChannelQuit) {
        self.effects.push(CoreEffect::ChannelQuit(quit));
    }

    pub fn route_topic(&mut self, topic: ChannelTopic) {
        self.effects.push(CoreEffect::ChannelTopic { topic });
    }

    pub fn route_topic_result(
        &mut self,
        session: SessionOwner,
        result: ChannelTopicResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelTopicResult {
            session,
            result,
            label,
        });
    }

    pub fn route_topic_persisted(
        &mut self,
        owner: ChannelOwner,
        conn: ConnId,
        session: Option<SessionOwner>,
        result: crate::core::ChannelTopicPersistence,
    ) {
        self.effects
            .push(crate::core::CoreEffect::ChannelTopicPersisted {
                owner,
                conn,
                session,
                result,
            });
    }

    pub fn route_channel_command(&mut self, command: ChannelCommand) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelCommand {
                command,
            }));
    }

    pub fn route_channel_command_result(
        &mut self,
        session: SessionOwner,
        result: ChannelCommandResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::Input(
            crate::core::Input::ChannelCommandResult {
                session,
                result,
                label,
            },
        ));
    }

    pub fn route_channel_session_event(
        &mut self,
        session: SessionOwner,
        event: ChannelSessionEvent,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelSessionEvent {
                session,
                event,
            }));
    }

    pub fn route_session_channel_removed(&mut self, session: SessionOwner, key: ChanKey) {
        self.effects
            .push(crate::core::CoreEffect::SessionChannelRemoved { session, key });
    }

    pub fn route_kick(&mut self, kick: ChannelKick) {
        self.effects
            .push(crate::core::CoreEffect::ChannelKick { kick });
    }

    pub fn route_kick_result(
        &mut self,
        session: SessionOwner,
        result: ChannelKickResult,
        label: Option<String>,
    ) {
        self.effects
            .push(crate::core::CoreEffect::ChannelKickResult {
                session,
                result,
                label,
            });
    }

    pub fn remove_session_channel(&mut self, conn: ConnId, key: &ChanKey) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.channels.remove(key);
        }
    }

    pub fn route_message(&mut self, message: ChannelMessage) {
        self.effects.push(CoreEffect::ChannelMessage { message });
    }

    pub fn route_message_result(
        &mut self,
        session: SessionOwner,
        result: ChannelMessageResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelMessageResult {
            session,
            result,
            label,
        });
    }

    pub fn route_multiline(&mut self, message: ChannelMultiline) {
        self.effects.push(CoreEffect::ChannelMultiline { message });
    }

    pub fn route_multiline_result(
        &mut self,
        session: SessionOwner,
        result: ChannelMultilineResult,
    ) {
        self.effects
            .push(CoreEffect::ChannelMultilineResult { session, result });
    }

    pub fn route_tagmsg(&mut self, tagmsg: ChannelTagmsg) {
        self.effects.push(CoreEffect::ChannelTagmsg { tagmsg });
    }

    pub fn route_tagmsg_result(
        &mut self,
        session: SessionOwner,
        result: ChannelTagmsgResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::ChannelTagmsgResult {
            session,
            result,
            label,
        });
    }

    pub fn refresh_recipient(&mut self, conn: ConnId) {
        let recipient = self.local_recipient(conn);
        let channels: Vec<_> = self.sessions[&conn].channels.iter().cloned().collect();
        for key in channels {
            if let Some(channel) = self.channels.get_mut(&key) {
                channel.update_recipient(recipient);
            }
        }
    }

    pub(crate) fn take_effects(&mut self) -> Vec<CoreEffect> {
        std::mem::take(&mut self.effects)
    }

    pub fn new(
        shard: CoreShardId,
        shards: CoreShardCount,
        config: CoreConfig,
        db_tx: Sender<super::DbRequest>,
        telemetry: Arc<Telemetry>,
        nicks: NickDirectory,
    ) -> Self {
        let started_at = (config.clock)();
        Self {
            shard,
            telemetry,
            config,
            casemap: CaseMapping::Rfc1459,
            sessions: SessionStore::new(),
            nicks,
            channels: ChannelDirectory::new(shards),
            doomed: Vec::new(),
            effects: Vec::new(),
            suspended_accounts: HashSet::new(),
            db_tx,
            max_users: 0,
            started_at,
            msgid_counter: 0,
            monitors: HashMap::new(),
            read_markers: HashMap::new(),
            pending_read_markers: HashMap::new(),
            registered_founders: HashMap::new(),
            pending_channel_registrations: HashMap::new(),
            registered_topics: HashMap::new(),
            pending_channel_topics: HashMap::new(),
            channel_topic_revision: 0,
            keeptopic_off: HashSet::new(),
            channel_mlock: HashMap::new(),
            channel_access: HashMap::new(),
            server_bans: Vec::new(),
            pending_server_bans: HashSet::new(),
            whowas: std::collections::VecDeque::new(),
            history: HashMap::new(),
            hot_history: std::collections::VecDeque::new(),
            emitting_deferred: None,
            capture: None,
            registration_buckets: HashMap::new(),
            pending_admin_channel_drops: HashMap::new(),
            admin_channel_drop_id: 0,
            pending_admin_server_bans: HashMap::new(),
            admin_server_ban_id: 0,
            pending_channel_controls: HashMap::new(),
            channel_control_id: 0,
        }
    }

    /// Spend one token from `host`'s account-creation bucket. Returns `false`
    /// (rate-limited) when the bucket is empty; always `true` when
    /// `registration_burst` is unset. The bucket refills to full over
    /// `REGISTRATION_REFILL_WINDOW_MS`; fully-refilled entries are pruned, and
    /// the map is hard-capped at `MAX_REGISTRATION_BUCKETS` so it can't grow
    /// without bound even under a distinct-IP flood. Mirrors the HTTP
    /// `auth_rate_ok` limiter, but on the core's monotonic clock.
    pub fn registration_rate_ok(&mut self, host: &str) -> bool {
        let Some(burst) = self.config.registration_burst else {
            return true;
        };
        let burst = burst as f64;
        let now = (self.config.mono_clock)();
        let refill_per_ms = burst / REGISTRATION_REFILL_WINDOW_MS as f64;
        let buckets = &mut self.registration_buckets;
        if buckets.len() > MAX_REGISTRATION_BUCKETS {
            buckets.retain(|_, (tokens, last)| {
                *tokens + now.saturating_sub(*last).as_millis() as f64 * refill_per_ms < burst
            });
            // A distinct-IP flood leaves nothing for the retain to prune (every
            // entry is below full). Evict the least-recently-seen entry to make
            // room — its bucket simply resets to a fresh burst next time, which
            // is harmless — so memory stays bounded regardless of source spread.
            if buckets.len() >= MAX_REGISTRATION_BUCKETS
                && !buckets.contains_key(host)
                && let Some(oldest) = buckets
                    .iter()
                    .min_by_key(|(_, (_, last))| *last)
                    .map(|(k, _)| k.clone())
            {
                buckets.remove(&oldest);
            }
        }
        let entry = buckets.entry(host.to_string()).or_insert((burst, now));
        // The refill watermark is monotonic; guard against a non-monotonic
        // source as defense in depth (same as the command-flood bucket).
        if now < entry.1 {
            entry.1 = now;
        }
        entry.0 =
            (entry.0 + now.saturating_sub(entry.1).as_millis() as f64 * refill_per_ms).min(burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
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
            (session.nick(), session.user(), session.realname())
        else {
            return; // never fully registered; nothing worth recording
        };
        let entry = WhowasEntry {
            nick: nick.to_string(),
            user: user.to_string(),
            host: session.host.clone(),
            realname: realname.to_string(),
            signoff: (self.config.clock)(),
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

    /// All connections currently identified to `account`, compared under the
    /// server casemapping. This is the one account comparison that must fold
    /// rather than use raw `==`: everywhere else accounts are folded before use
    /// (`is_founder`, `access_modes`, `identity_nick`), and a raw compare here
    /// would silently fail to sync a sibling connection (e.g. MARKREAD) if any
    /// session ever held a non-canonical account label.
    pub fn account_connections(&self, account: &str) -> Vec<ConnId> {
        let want = self.casemap.casefold(account);
        self.sessions
            .iter()
            .filter(|(_, s)| {
                s.account
                    .as_deref()
                    .is_some_and(|a| self.casemap.casefold(a) == want)
            })
            .map(|(c, _)| *c)
            .collect()
    }

    /// Key a channel name for lookup/storage.
    pub fn chan_key(&self, name: &str) -> ChanKey {
        ChanKey(self.casemap.casefold(name))
    }

    /// Key an account name for an in-core account map, under the server
    /// casemapping. The one constructor for [`AccountKey`] — a raw account
    /// string can't reach these maps without folding.
    pub fn account_key(&self, name: &str) -> AccountKey {
        AccountKey(self.casemap.casefold(name))
    }

    pub fn preload_suspended_accounts(&mut self, accounts: Vec<String>) {
        self.suspended_accounts = accounts
            .into_iter()
            .map(|account| self.account_key(&account))
            .collect();
    }

    pub fn is_account_suspended(&self, account: &str) -> bool {
        self.suspended_accounts.contains(&self.account_key(account))
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
            .map(|(name_folded, founder)| (ChanKey(name_folded), AccountKey(founder)))
            .collect();
    }

    /// Record a channel's founder (called when registration succeeds).
    pub fn set_founder(&mut self, channel: &str, founder_account: &str) {
        let key = self.chan_key(channel);
        let founder = self.account_key(founder_account);
        self.registered_founders.insert(key, founder);
    }

    /// Whether `account` is the registered founder of channel `key`.
    pub fn is_founder(&self, key: &ChanKey, account: &str) -> bool {
        self.registered_founders
            .get(key)
            .is_some_and(|f| *f == self.account_key(account))
    }

    /// Whether channel `key` is registered (ownership recorded).
    pub fn is_registered(&self, key: &ChanKey) -> bool {
        self.registered_founders.contains_key(key)
    }

    /// How many channels `account` currently founds or has reserved by an
    /// in-flight registration. Counting both prevents a pipelined REGISTER
    /// burst from stepping around the permanent-map cap before verdicts land.
    pub fn channels_founded_by(&self, account: &str) -> usize {
        let account_key = self.account_key(account);
        let committed = self
            .registered_founders
            .values()
            .filter(|f| **f == account_key)
            .count();
        let pending = self
            .pending_channel_registrations
            .iter()
            .filter(|(channel, founder)| {
                **founder == account_key && !self.registered_founders.contains_key(*channel)
            })
            .count();
        committed + pending
    }

    /// Whether registration of this channel is waiting for PostgreSQL.
    pub fn channel_registration_pending(&self, key: &ChanKey) -> bool {
        self.pending_channel_registrations.contains_key(key)
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

    /// Load persisted mode locks as `(name_folded, spec)`. Corrupt storage
    /// aborts startup instead of silently running without the promised lock.
    pub fn preload_mlock(&mut self, rows: Vec<(String, String)>) -> Result<(), String> {
        let mut locks = HashMap::with_capacity(rows.len());
        for (name, spec) in rows {
            let modes = MlockModes::parse(&spec)
                .map_err(|bad| format!("invalid persisted MLOCK for {name:?}: {bad:?}"))?;
            if modes.is_empty() {
                return Err(format!("empty persisted MLOCK for {name:?}"));
            }
            let canonical = modes.render();
            if canonical != spec {
                return Err(format!(
                    "non-canonical persisted MLOCK for {name:?}: {spec:?}"
                ));
            }
            locks.insert(ChanKey(name), modes);
        }
        self.channel_mlock = locks;
        Ok(())
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
        for (name_folded, account_folded, flags) in rows {
            self.channel_access
                .entry(ChanKey(name_folded))
                .or_default()
                .insert(AccountKey(account_folded), flags);
        }
    }

    /// Seed the read-marker mirror from persisted `(account, target, millis)`
    /// rows at boot. The dump returns the display-cased account name, so it is
    /// folded here into an `AccountKey` — matching the key MARKREAD builds at
    /// runtime. The stored target is already the casefolded `ChanKey` string (it
    /// was written from `ChanKey::as_str`), so it is wrapped directly.
    pub fn preload_read_markers(&mut self, rows: Vec<(String, String, e6irc_proto::time::Millis)>) {
        self.read_markers.clear();
        for (account, target, ms) in rows {
            let account = self.account_key(&account);
            self.read_markers.insert((account, ChanKey(target)), ms);
        }
    }

    /// The `(auto_op, auto_voice)` flags `account` holds on channel `key`.
    pub fn access_modes(&self, key: &ChanKey, account: &str) -> (bool, bool) {
        let account = self.account_key(account);
        match self.channel_access.get(key).and_then(|m| m.get(&account)) {
            Some(flags) => (flags.contains('o'), flags.contains('v')),
            None => (false, false),
        }
    }

    /// Load persisted server bans as `(mask, reason, set_by, kind)` rows.
    /// A row whose kind token is unrecognized is skipped loudly — bans are
    /// security-critical, so a corrupt kind must not silently become a
    /// default that bans (or fails to ban) the wrong sessions.
    pub fn preload_server_bans(&mut self, rows: Vec<(String, String, String, String)>) {
        let casemap = self.casemap;
        self.server_bans = rows
            .into_iter()
            .filter_map(
                |(mask, reason, set_by, kind)| match BanKind::from_token(&kind) {
                    // `mask` is the stored *display* form (`COALESCE(mask_display,
                    // mask)`); `MaskKey::new` folds it for comparison, so removal
                    // matches regardless of casing while STATS shows the original.
                    // A legacy/externally-inserted row surfaces its stored casing;
                    // its fold still governs enforcement and `UNKLINE`.
                    Some(kind) => Some(ServerBan {
                        mask: MaskKey::new(&mask, casemap),
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
            e6irc_proto::mask::matches(self.casemap, b.mask.as_str(), &subject)
                .then(|| (b.kind, b.reason.clone()))
        })
    }

    /// Key a nick for lookup/storage.
    pub fn nick_key(&self, nick: &str) -> NickKey {
        NickKey(self.casemap.casefold(nick))
    }

    /// Claim `key` for this connection if no other connection owns it.
    pub fn claim_nick(&self, key: NickKey, conn: ConnId) -> bool {
        self.nicks.claim(
            key,
            SessionOwner::new(conn, self.shard),
            self.sessions[&conn].is_registered(),
        )
    }

    /// The reservation for `key`, including a remote worker assignment.
    pub fn nick_reservation(&self, key: &NickKey) -> Option<SessionOwner> {
        self.nicks.owner(key)
    }

    pub fn registered_nick_owner(&self, key: &NickKey) -> Option<SessionOwner> {
        self.nicks.registered_owner(key)
    }

    pub fn mark_nick_registered(&self, conn: ConnId) {
        if let Some(nick) = self.sessions[&conn].nick() {
            self.nicks.mark_registered(&self.nick_key(nick), conn);
        }
    }

    /// The local connection owning `key`.
    pub fn nick_connection(&self, key: &NickKey) -> Option<ConnId> {
        self.nick_reservation(key)
            .filter(|owner| owner.shard() == self.shard)
            .map(SessionOwner::conn)
    }

    /// Release `key` only when `conn` still owns it.
    pub fn release_nick(&mut self, key: &NickKey, conn: ConnId) -> bool {
        self.nicks.release_if_owned(key, conn)
    }

    /// A casefolded nick rendered for display: the online user's actual nick
    /// casing when they are connected, otherwise the casefolded form itself
    /// (the only spelling still on record once they have gone).
    pub fn display_nick(&self, folded: &str) -> String {
        self.nick_connection(&NickKey(folded.to_string()))
            .and_then(|conn| self.sessions.get(&conn))
            .and_then(|s| s.nick().map(String::from))
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
                .and_then(|s| s.nick().map(String::from))
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
                None => format!("~{}", self.casemap.casefold(s.nick().unwrap_or(""))),
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
        self.registered_nick_owner(key)
            .filter(|owner| owner.shard() == self.shard)
            .map(SessionOwner::conn)
    }

    pub fn open(
        &mut self,
        conn: ConnId,
        tx: Sender<Output>,
        host: String,
        transport: crate::core::ConnectionTransport,
    ) {
        let opened_at = (self.config.mono_clock)();
        let prev = self.sessions.insert(
            conn,
            Session {
                tx,
                host,
                transport,
                reg: Registration::Registering {
                    nick: None,
                    user: None,
                    realname: None,
                },
                cap_negotiating: false,
                caps: Caps::default(),
                account: None,
                sasl: SaslState::default(),
                sasl_verify_pending: false,
                sasl_buf: String::new(),
                credential_attempts: 0,
                pending_identify: None,
                pending_register: None,
                away: None,
                oper: false,
                invisible: false,
                wallops: false,
                bot: false,
                channels: HashSet::new(),
                monitoring: HashMap::new(),
                multiline: None,
                anon_read_markers: HashMap::new(),
                // Seed the flood bucket full, with its refill watermark at the
                // open time — NOT a zero `MonoMillis` sentinel. The monotonic
                // clock's epoch is process start, so a zero watermark makes the
                // first refill credit `now - 0 = uptime` seconds: within the
                // first `command_burst` seconds of uptime the bucket would start
                // at only `min(uptime, burst)` tokens and wrongly kill a client
                // that pipelines a legitimate burst — worst exactly during a
                // post-restart reconnect storm.
                flood_tokens: self.config.command_burst.unwrap_or(0) as u32,
                flood_refilled_to_ms: opened_at,
                // Every monotonic watermark is seeded from the open time, never a
                // zero `MonoMillis` sentinel. A zero would be indistinguishable
                // from a real early reading (the mono epoch IS process start), so
                // the first `now - 0 = uptime` read would misbehave in the first
                // moments of uptime — the class that flood-killed fresh clients a
                // sweep ago. Both are re-stamped before they gate anything
                // (`last_active` at registration, `last_ping_sent` when a PING is
                // actually sent), so open-time is a correct, sentinel-free floor.
                last_active: opened_at,
                signon: e6irc_proto::time::Millis::from_millis(0),
                opened_at,
                awaiting_pong: false,
                deferred_replies: 0,
                held: Vec::new(),
                last_ping_sent: opened_at,
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

    pub fn send_recipient(&mut self, recipient: Recipient, bytes: Bytes) {
        assert_eq!(
            recipient.shard(),
            self.shard,
            "captured output crossed shard"
        );
        self.send_bytes(recipient.conn(), bytes);
    }

    /// Deliver received output to its owning worker.
    pub fn send_recipient_uncaptured(&mut self, recipient: Recipient, bytes: Bytes) {
        if recipient.shard() == self.shard {
            self.send_bytes_uncaptured(recipient.conn(), bytes);
        } else {
            self.effects.push(CoreEffect::Delivery {
                owner: recipient.owner,
                line: bytes,
            });
        }
    }

    /// Debug-build invariant: every outbound line fits what the recipient's
    /// framing will accept. Sweeps 33–39 fixed this class site by site —
    /// bridges, MONITOR, MODE, message relay, multiline egress — each found by
    /// hand. This check makes the class machine-checked at the one funnel all
    /// output passes through: any new path that builds an over-long line fails
    /// the first test (or fuzz run — cargo-fuzz builds with debug assertions)
    /// that exercises it, instead of shipping a line the client silently drops.
    ///
    /// Compiled out of release builds deliberately: one worker serves every
    /// client, so a production panic here would be worse than the over-long
    /// line it flags. Tests and fuzzers are where the invariant bites.
    #[cfg(debug_assertions)]
    fn debug_check_wire_line(&self, conn: ConnId, bytes: &Bytes) {
        let multiline = self.sessions.get(&conn).is_some_and(|s| s.caps.multiline);
        if let Some(violation) = wire_line_violation(bytes, multiline) {
            panic!("{violation}: {:?}", String::from_utf8_lossy(bytes));
        }
    }

    /// Deliver bypassing labeled-response capture. Used for messages a
    /// connection *receives* (deliveries), which are never part of the
    /// labeled response to its own command — only direct replies are.
    pub fn send_bytes_uncaptured(&mut self, conn: ConnId, bytes: Bytes) {
        #[cfg(debug_assertions)]
        self.debug_check_wire_line(conn, &bytes);
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
        let byte_count = bytes.strip_suffix(b"\r\n").unwrap_or(&bytes).len();
        if deliver(&session.tx, WireLine::sanitized(bytes)).is_err() {
            self.doomed.push(conn);
        } else {
            self.telemetry.record_irc_output(byte_count);
        }
    }

    /// Note that a connection is now waiting on a database-backed reply, so
    /// its later output queues behind it.
    pub fn defer_reply(&mut self, conn: ConnId) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.deferred_replies += 1;
        }
    }

    /// Hold later output behind an asynchronous verdict and tell the active
    /// labeled-response capture that its reply will be emitted by that verdict.
    pub fn defer_captured_reply(&mut self, conn: ConnId) {
        self.defer_reply(conn);
        if let Some(capture) = self.capture.as_mut()
            && capture.label.is_some()
        {
            capture.deferred = true;
        }
    }

    /// Start a cross-shard command. Its result owns the deferred slot and,
    /// when present, the captured label.
    pub fn defer_channel_reply(&mut self, conn: ConnId) -> Option<String> {
        let label = self.capture.as_ref().and_then(|capture| {
            (capture.conn == conn)
                .then(|| capture.label.clone())
                .flatten()
        });
        self.defer_captured_reply(conn);
        label
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

    /// Emit a deferred reply that must be framed under `label` if the command
    /// that triggered it was labeled. Reuses the same labeled-response framer a
    /// synchronous command uses, so the async `SUCCESS`/`FAIL` gets the `@label`
    /// tag (single line) or a labeled batch (many) — identical framing whether
    /// the answer came back inline or from a database round trip. With no label
    /// this is exactly `emit_deferred`.
    pub fn emit_deferred_labeled(
        &mut self,
        conn: ConnId,
        label: Option<String>,
        emit: impl FnOnce(&mut Self),
    ) {
        let Some(label) = label else {
            return self.emit_deferred(conn, emit);
        };
        let previous = self.emitting_deferred.replace(conn);
        // Capture the emitted lines (they route to `capture` because it targets
        // this conn) so the framer can tag/batch them, exactly as a synchronous
        // labeled command's direct replies are captured in `dispatch`.
        debug_assert!(self.capture.is_none(), "deferred reply nested in a capture");
        self.capture = Some(Capture {
            conn,
            lines: Vec::new(),
            label: Some(label.clone()),
            deferred: false,
        });
        emit(self);
        let captured = self.capture.take().map(|c| c.lines).unwrap_or_default();
        super::handler::frame_labeled(self, conn, &label, captured);
        self.emitting_deferred = previous;
        self.release_deferred(conn);
    }

    /// Emit an async reply framed under `label` (if any) that was NOT held behind
    /// a [`Self::defer_reply`] — so it consumes no deferred slot and does not gate
    /// the connection's other output on itself. Used for a NickServ verdict, which
    /// (unlike a REGISTER `SUCCESS`) interleaves with the client's other output the
    /// way a real server sends it, while still carrying the label of the
    /// `PRIVMSG NickServ :IDENTIFY` that triggered it so a labeled client can
    /// correlate the result. The `emitting_deferred` bypass keeps it from being
    /// withheld behind any *unrelated* deferred reply (e.g. a pending CHATHISTORY)
    /// without touching that reply's hold count.
    pub fn emit_labeled_unheld(
        &mut self,
        conn: ConnId,
        label: Option<String>,
        emit: impl FnOnce(&mut Self),
    ) {
        let previous = self.emitting_deferred.replace(conn);
        match label {
            None => emit(self),
            Some(label) => {
                debug_assert!(
                    self.capture.is_none(),
                    "labeled verdict nested in a capture"
                );
                self.capture = Some(Capture {
                    conn,
                    lines: Vec::new(),
                    label: Some(label.clone()),
                    deferred: false,
                });
                emit(self);
                let captured = self.capture.take().map(|c| c.lines).unwrap_or_default();
                super::handler::frame_labeled(self, conn, &label, captured);
            }
        }
        self.emitting_deferred = previous;
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
    /// Longest middle parameter `numeric` passes through unclipped. Every
    /// legitimate middle is a short token by construction — a nick (≤ nicklen),
    /// a channel display name (≤ 50), a mode/ISUPPORT string, a number, a
    /// USERLEN-bounded username or 63-byte host. Anything longer is a
    /// client-supplied token being echoed for attribution (an unknown command,
    /// a bad target, a rejected list), whose length is bounded only by the
    /// input frame; unclipped it can push the reply explaining an error past
    /// the wire limit, and the recipient's framing then discards that very
    /// reply. Clipping at this one funnel closes the whole echo family rather
    /// than each numeric separately.
    const NUMERIC_MIDDLE_MAX: usize = 100;

    pub fn numeric(&mut self, conn: ConnId, code: u16, middle: &[&str], trailing: Option<&str>) {
        let target = self
            .sessions
            .get(&conn)
            .and_then(|s| s.nick().map(String::from))
            .unwrap_or_else(|| "*".into());
        let mut line = format!(
            ":{} {} {}",
            self.config.server_name,
            e6irc_proto::numerics::code_str(code),
            target
        );
        // The whole line must fit the wire limit including CRLF. Per-middle and
        // per-trailing clips alone don't guarantee that: a numeric like WHOX
        // (RPL_WHOSPCRPL) packs up to a dozen middles whose *sum* — driven by the
        // configured `server_name` and nick maxima (each appears in both the head
        // and a middle) plus a client-supplied WHOX token — can exceed 512 on its
        // own, before any trailing. Bounding the running line as middles are
        // appended (reserving room for the trailing's " :" when there is one) is
        // the total-length guard that keeps every numeric ≤ 512 at this one choke
        // point, so no row is ever discarded whole by the recipient's framing.
        const WIRE_BUDGET: usize = e6irc_proto::message::MAX_LINE_LEN - 2; // minus CRLF
        let reserve = if trailing.is_some() { 2 } else { 0 };
        for p in middle {
            // Room left for this middle, including its leading space. Stop before
            // an over-long line rather than emit one that vanishes on the wire.
            let avail = WIRE_BUDGET
                .saturating_sub(reserve)
                .saturating_sub(line.len());
            if avail <= 1 {
                break;
            }
            line.push(' ');
            // A middle that can't stand as a wire parameter would corrupt the
            // reply's framing — an empty one collapses into the separator, a
            // ':'-leading one opens the trailing early, CR/LF/NUL break the line
            // (the WHOX-token class, and every error numeric that echoes a raw
            // client target/nick/mode-char). Since one worker serves every
            // client, the funnel renders such a segment as the conventional "*"
            // placeholder rather than ship a line the client misparses — the
            // same wire-safety normalization as the length clip right below it,
            // and it makes the whole framing-corruption class unrepresentable at
            // this single choke point instead of one echo site at a time. A
            // segment carrying a mode-string joined to its (space-validated)
            // args is unaffected: only the leading byte and control bytes matter.
            if numeric_middle_violation(p).is_some() {
                line.push('*');
                continue;
            }
            let cap = Self::NUMERIC_MIDDLE_MAX.min(avail - 1);
            line.push_str(e6irc_proto::message::truncate_on_char_boundary(p, cap));
        }
        if let Some(t) = trailing {
            line.push_str(" :");
            // Fit the trailing into whatever the (already-bounded) middles left.
            // The middle loop above reserved 2 bytes for this " :", so there is
            // always room for the separator; the trailing itself is clipped to
            // the remaining budget. (A `numeric_list` page is already built to
            // fit, so this is a no-op for it.)
            let budget =
                e6irc_proto::message::MAX_LINE_LEN.saturating_sub(line.len() + 2 /* CRLF */);
            line.push_str(e6irc_proto::message::truncate_on_char_boundary(t, budget));
        }
        self.send(conn, &line);
    }

    /// `ERR_NEEDMOREPARAMS (<cmd>) :Not enough parameters`.
    pub fn err_needmoreparams(&mut self, conn: ConnId, cmd: &str) {
        self.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &[cmd],
            Some("Not enough parameters"),
        );
    }

    /// `ERR_NOSUCHNICK (<nick>) :No such nick/channel`.
    pub fn err_nosuchnick(&mut self, conn: ConnId, nick: &str) {
        self.numeric(conn, ERR_NOSUCHNICK, &[nick], Some("No such nick/channel"));
    }

    /// `ERR_NOSUCHCHANNEL (<chan>) :No such channel`.
    pub fn err_nosuchchannel(&mut self, conn: ConnId, chan: &str) {
        self.numeric(conn, ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
    }

    /// `ERR_NOTONCHANNEL (<chan>) :You're not on that channel`.
    pub fn err_notonchannel(&mut self, conn: ConnId, chan: &str) {
        self.numeric(
            conn,
            ERR_NOTONCHANNEL,
            &[chan],
            Some("You're not on that channel"),
        );
    }

    /// Emit `code` one or more times, packing `items` into the trailing
    /// parameter (joined by `sep`) so that no emitted line exceeds the 512-byte
    /// wire limit including CRLF. `middle` is the fixed parameters that precede
    /// the list on every line.
    ///
    /// A reply whose trailing parameter is an unbounded list — NAMES members,
    /// WHOIS channels, MONITOR targets — must split: the receiving client's
    /// framing discards an over-long line *whole*, so the listed entries vanish
    /// with nothing said. The budget arithmetic is easy to get subtly wrong, so
    /// it lives here once rather than at each call site.
    ///
    /// Nothing is emitted for an empty `items`. A caller that must always send
    /// something (an empty NAMES is still closed by its own ENDOF numeric) does
    /// that itself.
    pub fn numeric_list(
        &mut self,
        conn: ConnId,
        code: u16,
        middle: &[&str],
        items: &[String],
        sep: char,
    ) {
        // Measure the fixed part of every line exactly as `numeric` frames it —
        // ":{server} {code} {target}" + each middle + " :" + CRLF — so the
        // budget can never drift from the line actually sent.
        let target = self
            .sessions
            .get(&conn)
            .and_then(|s| s.nick().map(String::from))
            .unwrap_or_else(|| "*".into());
        let mut overhead = 1
            + self.config.server_name.len()
            + 1
            + e6irc_proto::numerics::code_str(code).len()
            + 1
            + target.len();
        for m in middle {
            overhead += 1 + m.len();
        }
        overhead += 2 /* " :" */ + 2 /* CRLF */;
        let budget = 512usize.saturating_sub(overhead).max(1);

        let mut line = String::new();
        for item in items {
            if !line.is_empty() && line.len() + 1 + item.len() > budget {
                self.numeric(conn, code, middle, Some(&line));
                line.clear();
            }
            if !line.is_empty() {
                line.push(sep);
            }
            line.push_str(item);
        }
        if !line.is_empty() {
            self.numeric(conn, code, middle, Some(&line));
        }
    }

    /// Stamp a new event: a single clock read yielding both the wall-clock
    /// millisecond and the unique msgid derived from it. Live delivery, the
    /// history ring and the `messages` row all take this one value, so a
    /// message can never be replayed by CHATHISTORY bearing a different
    /// `time=` than the one it was delivered with. Reading the clock twice
    /// for the same message is exactly the bug this exists to prevent.
    pub fn stamp(&mut self) -> (e6irc_proto::time::Millis, String) {
        let now = (self.config.clock)();
        self.msgid_counter += 1;
        (now, format!("{}-{}", now.as_millis(), self.msgid_counter))
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

    pub fn send_timed_recipient(&mut self, recipient: Recipient, line: &str) {
        let tagged = recipient.caps().server_time;
        if tagged {
            let line = format!("@time={} {line}", self.time_tag());
            self.send_recipient_uncaptured(recipient, Bytes::from(format!("{line}\r\n")));
        } else {
            self.send_recipient_uncaptured(recipient, Bytes::from(format!("{line}\r\n")));
        }
    }

    /// Serialize once per capability variant, deliver to every member of
    /// a channel except `except`.
    pub fn broadcast_channel(&mut self, chan_key: &ChanKey, line: &str, except: Option<ConnId>) {
        let Some(chan) = self.channels.get(chan_key) else {
            return;
        };
        debug_assert_eq!(self.channels.owner(chan_key).shard(), self.shard);
        let members = chan.recipients();
        let plain = Bytes::from(format!("{line}\r\n"));
        // Built lazily: channels with no server-time member pay nothing.
        let mut timed: Option<Bytes> = None;
        for recipient in members
            .iter()
            .copied()
            .filter(|recipient| Some(recipient.conn()) != except)
        {
            let bytes = if recipient.caps().server_time {
                timed
                    .get_or_insert_with(|| {
                        Bytes::from(format!("@time={} {line}\r\n", self.time_tag()))
                    })
                    .clone()
            } else {
                plain.clone()
            };
            if recipient.shard() != self.shard {
                self.effects.push(CoreEffect::Delivery {
                    owner: recipient.owner,
                    line: bytes,
                });
                continue;
            }
            let m = recipient.conn();
            self.send_bytes(m, bytes);
        }
    }

    /// Graceful shutdown: send every connected client a terminal `ERROR` line so
    /// a clean close reason reaches them instead of a bare TCP reset (DESIGN §18,
    /// "notify clients").
    ///
    /// Delivered straight into each send queue, deliberately bypassing both the
    /// labeled-response capture and the deferred-reply hold: this is the last
    /// line the session will ever see, and no later reply will arrive to release
    /// output held behind an in-flight deferred page — so a held ERROR would
    /// simply be lost. The sockets close when the `Core` is dropped immediately
    /// after this call, which drops every session's `Sender<Output>`; each write
    /// task then drains its queue — flushing this ERROR — before shutting the
    /// socket down.
    pub fn broadcast_shutdown(&mut self, reason: &str) {
        let line = format!(
            "ERROR :Closing Link: {} ({reason})",
            self.config.server_name
        );
        let bytes = Bytes::from(format!("{line}\r\n"));
        for session in self.sessions.values() {
            // Best-effort per client: a peer already gone just means its send
            // queue is closed, which `deliver` treats as a no-error close.
            let _ = deliver(&session.tx, WireLine::sanitized(bytes.clone()));
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
                seen.extend(chan.recipients().iter().map(|recipient| recipient.conn()));
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
            .and_then(|s| s.nick().map(String::from))
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
        let was_registered = session.is_registered();
        // Output withheld behind an in-flight deferred DB reply (a CHATHISTORY
        // ring miss, say) would be dropped with the session — including the
        // terminal ERROR a QUIT or kill path sent just before this close. The
        // reply it was waiting on can never be delivered usefully now, so
        // release the hold and flush what it withheld, in production order,
        // while the connection can still receive it. The sibling of the
        // capture flush below.
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.deferred_replies = 0;
            for line in std::mem::take(&mut session.held) {
                self.send_bytes_uncaptured(conn, line);
            }
        }
        // A teardown initiated from inside a labeled command (QUIT, flood
        // kill, credential-budget close) has its terminal `ERROR` sitting in
        // the labeled-response capture buffer; the dispatch wrapper would only
        // try to deliver it after this session is gone and silently drop it.
        // Flush the capture now, while the connection can still receive the
        // loud close those paths exist to provide.
        if self.capture.as_ref().is_some_and(|c| c.conn == conn) {
            let capture = self.capture.take().expect("checked");
            for line in capture.lines {
                self.send_bytes_uncaptured(conn, line);
            }
        }
        if was_registered {
            self.record_whowas(conn);
        }
        let session = &self.sessions[&conn];
        let quit_line = was_registered.then(|| {
            // The relay adds the prefix the sender never wrote; fit the reason
            // so the line survives every recipient's framing.
            let head = format!(":{} QUIT :", session.prefix());
            let reason = crate::core::handler::fit_trailing(&head, reason);
            format!("{head}{reason}")
        });
        let joined: Vec<ChanKey> = session.channels.iter().cloned().collect();

        if let Some(line) = quit_line {
            for key in joined {
                let owner = self.channels.owner(&key);
                if self.owns_channel(&owner) {
                    self.quit_channel_member(&owner, conn, &line);
                } else {
                    self.route_quit(ChannelQuit::new(owner, conn, line.clone()));
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
        if let Some(nick) = session.nick() {
            let nick_key = NickKey(self.casemap.casefold(nick));
            self.release_nick(&nick_key, conn);
            if was_registered {
                super::handler::monitor_notify(self, nick, false);
            }
            // Free the direct-message history rings keyed on this connection's
            // *unauthenticated* identity (`~nick`). That identity is unclaimable
            // and reusable: the moment this connection leaves, the next person to
            // take the nick derives the same `~nick`, and would otherwise read
            // the prior occupant's DM rings until LRU eviction — a privacy leak.
            // An authenticated identity is an account (stable, DB-backed) and is
            // deliberately retained.
            if session.account.is_none() {
                let my_identity = format!("~{}", self.casemap.casefold(nick));
                self.history
                    .retain(|k, _| match k.as_str().split_once('!') {
                        // A DM key is `lo!hi` where each side is an identity
                        // (`~<foldednick>` for an unauthenticated peer); keep it
                        // only if neither side is us. A channel name *can* legally
                        // contain `!` (sanitize::valid_channel_name allows it), so
                        // a channel key can also split here — but the key is
                        // casefolded and `~` folds to `^` under rfc1459, so a
                        // folded channel key never contains the `~`-prefixed
                        // `my_identity` and is thus always retained.
                        Some((lo, hi)) => lo != my_identity && hi != my_identity,
                        // No `!`: not a DM key, always kept.
                        None => true,
                    });
                self.hot_history.retain(|k| self.history.contains_key(k));
            }
        }
    }

    /// Apply a registered session's departure on the channel-owning shard.
    /// A preceding PART can have removed the member while its response was in
    /// flight to the closing session; that makes this departure already applied.
    pub fn quit_channel_member(&mut self, owner: &ChannelOwner, conn: ConnId, line: &str) {
        assert_eq!(
            owner.shard(),
            self.shard,
            "QUIT reached wrong channel shard"
        );
        let key = owner.key();
        let removed = self
            .channels
            .get_mut(key)
            .and_then(|channel| channel.remove_member(conn));
        let Some(_) = removed else {
            return;
        };
        self.broadcast_channel(key, line, Some(conn));
        if !self.channels[key].has_members() {
            self.remove_channel(key);
        }
    }
}

/// The structural rule for a numeric *middle* segment, pure so it can be pinned
/// by unit tests: `Some(reason)` when `middle` cannot stand where `numeric`
/// places it and would corrupt the reply's framing. [`ServerState::numeric`]
/// consults it to render such a segment safely (as `*`) rather than emit a
/// mis-framed line — making the framing-corruption class unrepresentable at
/// that one funnel.
///
/// A middle precedes the trailing and is space-delimited, so it must be
/// **non-empty** (an empty one collapses into the adjacent separator, shifting
/// every later field left a column — the WHOX empty-token bug), must **not begin
/// with `:`** (which starts the trailing early, swallowing the rest of the line —
/// the WHOX `:`-leading-token bug), and must carry **no CR/LF/NUL** (which break
/// the line or inject a second one). These are exactly the numeric-framing
/// corruptions found and fixed by hand across the sweeps; the funnel now closes
/// the class for every present and future echo site at once.
///
/// An internal space is deliberately *allowed*: a few replies pass a
/// mode-string joined to its space-separated arguments as one segment
/// (`RPL_CHANNELMODEIS` "+ntk sekrit", `RPL_MYINFO`), which frames correctly —
/// each sub-argument is itself space-validated at its own ingress (a `+k` key or
/// `+l` limit with a space is refused). Forbidding the space would only force a
/// join-then-resplit at those call sites for no framing benefit. Callers with
/// genuine free text (a realname, a message, a reason) pass it as the
/// *trailing*, which has none of these restrictions.
fn numeric_middle_violation(middle: &str) -> Option<&'static str> {
    if middle.is_empty() {
        return Some("numeric middle parameter is empty (collapses into the field separator)");
    }
    if middle.starts_with(':') {
        return Some("numeric middle parameter starts with ':' (starts the trailing early)");
    }
    if middle.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Some("numeric middle parameter contains CR/LF/NUL (breaks or injects a line)");
    }
    None
}

/// The wire-limit rule behind [`ServerState::debug_check_wire_line`], pure so
/// it can be pinned by unit tests: `Some(description)` when `line` (CRLF
/// included) would be discarded by the recipient's framing. A recipient that
/// negotiated `draft/multiline` accepts the batch form's longer inner lines —
/// that is the capability's whole point — so its traditional-part budget grows
/// by the multiline byte cap.
#[cfg(debug_assertions)]
fn wire_line_violation(line: &[u8], multiline_capable: bool) -> Option<String> {
    use e6irc_proto::message::{MAX_LINE_LEN, MAX_SERVER_TAGS_LEN};
    let (tags_len, body) = match line.first() {
        Some(b'@') => match line.iter().position(|&b| b == b' ') {
            Some(sp) => (sp + 1, &line[sp + 1..]),
            None => (0, line),
        },
        _ => (0, line),
    };
    if tags_len > MAX_SERVER_TAGS_LEN {
        return Some(format!(
            "outbound tag section is {tags_len} bytes (limit {MAX_SERVER_TAGS_LEN})"
        ));
    }
    let budget = if multiline_capable {
        MAX_LINE_LEN + crate::core::handler::message::MULTILINE_MAX_BYTES
    } else {
        MAX_LINE_LEN
    };
    if body.len() > budget {
        return Some(format!(
            "outbound line's traditional part is {} bytes (limit {budget}) — a client's \
             framing discards over-long lines whole",
            body.len()
        ));
    }
    // Injection (an embedded CR/LF/NUL in the content) is deliberately NOT a
    // debug panic here, only a length violation is. The two differ in kind: an
    // over-long line is a *code* bug (a formatting path lost track of the wire
    // budget), so panicking finds it in tests. An injection byte, by contrast,
    // can ride legitimate *data* the core relays from an untrusted store or
    // bridge (a history body, an upstream line) — real inputs reject those bytes
    // up front, but the core must handle a dirty one gracefully, which is to
    // *neutralize* it, not abort the shared worker. That neutralization is the
    // unconditional guarantee of `WireLine::sanitized` at the delivery funnel;
    // asserting "no line ever carries one" would fire on that legitimate data.
    None
}

#[cfg(test)]
mod mlock_tests {
    use super::MlockModes;

    #[test]
    fn equivalent_mode_locks_have_one_canonical_spelling() {
        assert_eq!(MlockModes::parse("+tn-i").unwrap().render(), "+nt-i");
        assert_eq!(MlockModes::parse("-i+tn").unwrap().render(), "+nt-i");
        assert_eq!(MlockModes::parse("+n+t-i").unwrap().render(), "+nt-i");
    }
}

#[cfg(test)]
mod numeric_middle_tests {
    use super::numeric_middle_violation;

    #[test]
    fn accepts_ordinary_middles_and_rejects_frame_breakers() {
        // Ordinary middle parameters pass.
        for ok in ["alice", "#chan", "+o", "0", "255.255.255.255", "H@", "*"] {
            assert!(
                numeric_middle_violation(ok).is_none(),
                "rejected a valid middle: {ok:?}"
            );
        }
        // A pre-joined modestring+args segment is allowed — it frames correctly.
        assert!(
            numeric_middle_violation("+ntk sekrit").is_none(),
            "a pre-joined modestring+args segment must be allowed"
        );
        // The frame-breaking shapes each fail — the exact WHOX-token class.
        assert!(numeric_middle_violation("").is_some(), "empty must fail");
        assert!(
            numeric_middle_violation(":x").is_some(),
            "leading colon must fail"
        );
        assert!(numeric_middle_violation("a\rb").is_some());
        assert!(numeric_middle_violation("a\nb").is_some());
        assert!(numeric_middle_violation("a\0b").is_some());
    }
}

#[cfg(all(test, debug_assertions))]
mod wire_line_tests {
    use super::wire_line_violation;

    #[test]
    fn holds_the_traditional_limit_and_the_multiline_allowance() {
        let fits = format!(":s PRIVMSG #c :{}\r\n", "x".repeat(490));
        assert!(fits.len() <= 512);
        assert!(wire_line_violation(fits.as_bytes(), false).is_none());

        let over = format!(":s PRIVMSG #c :{}\r\n", "x".repeat(500));
        assert!(over.len() > 512);
        assert!(wire_line_violation(over.as_bytes(), false).is_some());
        // The same line is legal for a recipient that negotiated multiline.
        assert!(wire_line_violation(over.as_bytes(), true).is_none());

        // Tags spend the tag budget, not the traditional one.
        let tagged = format!("@time=x;msgid=y :s PRIVMSG #c :{}\r\n", "x".repeat(490));
        assert!(wire_line_violation(tagged.as_bytes(), false).is_none());
        let huge_tags = format!("@a={} :s PING\r\n", "t".repeat(9000));
        assert!(wire_line_violation(huge_tags.as_bytes(), false).is_some());
    }
}

#[cfg(test)]
mod session_store_tests {
    use super::*;
    use e6irc_queue::{Config as QueueConfig, Policy, queue};

    fn wall_clock() -> e6irc_proto::time::Millis {
        e6irc_proto::time::Millis::from_millis(0)
    }

    fn mono_clock() -> e6irc_proto::time::MonoMillis {
        e6irc_proto::time::MonoMillis::from_millis(0)
    }

    fn state() -> ServerState {
        let (db_tx, _db_rx) = queue(QueueConfig {
            name: "session-store-db",
            capacity: 1,
            policy: Policy::Fifo,
        });
        ServerState::new(
            CoreShardId(0),
            CoreShardCount::single(),
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
            },
            db_tx,
            Arc::new(Telemetry::new()),
            NickDirectory::default(),
        )
    }

    fn open(state: &mut ServerState, conn: ConnId) {
        let (tx, _rx) = queue(QueueConfig {
            name: "session-store-output",
            capacity: 1,
            policy: Policy::Fifo,
        });
        state.open(
            conn,
            tx,
            "host.test".into(),
            crate::core::ConnectionTransport::Tcp,
        );
    }

    #[test]
    fn nick_reservation_retains_its_worker() {
        let directory = NickDirectory::default();
        let key = NickKey("alice".into());
        let owner = SessionOwner::new(ConnId(7), CoreShardId(3));

        assert!(directory.claim(key.clone(), owner, true));

        assert_eq!(directory.owner(&key), Some(owner));
        assert_eq!(
            directory.owner(&key).map(SessionOwner::shard),
            Some(CoreShardId(3))
        );
        assert!(!directory.release_if_owned(&key, ConnId(8)));
        assert_eq!(directory.owner(&key), Some(owner));
        assert!(directory.release_if_owned(&key, ConnId(7)));
        assert_eq!(directory.owner(&key), None);
    }

    #[test]
    fn nick_claim_cannot_replace_another_session() {
        let directory = NickDirectory::default();
        let key = NickKey("alice".into());
        let first = SessionOwner::new(ConnId(7), CoreShardId(0));
        let second = SessionOwner::new(ConnId(8), CoreShardId(1));

        assert!(directory.claim(key.clone(), first, true));
        assert!(!directory.claim(key.clone(), second, true));
        assert_eq!(directory.owner(&key), Some(first));
    }

    #[test]
    fn nick_reservation_is_not_registered_until_marked() {
        let directory = NickDirectory::default();
        let key = NickKey("alice".into());
        let owner = SessionOwner::new(ConnId(7), CoreShardId(1));

        assert!(directory.claim(key.clone(), owner, false));
        assert_eq!(directory.registered_owner(&key), None);
        directory.mark_registered(&key, ConnId(7));
        assert_eq!(directory.registered_owner(&key), Some(owner));
    }

    #[test]
    fn channel_owner_is_stable_for_the_folded_key() {
        let shards =
            CoreShardCount::new(std::num::NonZeroUsize::new(3).expect("nonzero shard count"));
        let directory = ChannelDirectory::new(shards);
        let first = directory.owner(&ChanKey("#chat".into()));
        let again = directory.owner(&ChanKey("#chat".into()));

        assert_eq!(first, again);
        assert_eq!(first.key.as_str(), "#chat");
        assert!(first.shard().0 < 3);
    }

    #[test]
    fn recipient_snapshot_is_shared_until_membership_changes() {
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
        channel.add_member(
            Recipient {
                owner: SessionOwner::new(ConnId(1), CoreShardId(0)),
                caps: Caps::default(),
            },
            MemberIdentity::new("one".into(), "one!u@h".into(), false),
            MemberModes {
                op: true,
                voice: false,
            },
        );

        let first = channel.recipients();
        let again = channel.recipients();
        assert!(Arc::ptr_eq(&first, &again));

        channel.add_member(
            Recipient {
                owner: SessionOwner::new(ConnId(2), CoreShardId(0)),
                caps: Caps::default(),
            },
            MemberIdentity::new("two".into(), "two!u@h".into(), false),
            MemberModes {
                op: false,
                voice: false,
            },
        );
        let changed = channel.recipients();
        assert!(!Arc::ptr_eq(&first, &changed));
        assert_eq!(changed.len(), 2);
        assert!(
            changed
                .iter()
                .any(|recipient| recipient.conn() == ConnId(1)
                    && recipient.shard() == CoreShardId(0))
        );
        assert!(
            changed
                .iter()
                .any(|recipient| recipient.conn() == ConnId(2)
                    && recipient.shard() == CoreShardId(0))
        );
    }

    #[test]
    fn member_lookup_uses_channel_identity_and_casemapping() {
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
        channel.add_member(
            Recipient::new(
                SessionOwner::new(ConnId(2), CoreShardId(1)),
                Caps::default(),
            ),
            MemberIdentity::new("[Alice]".into(), "[Alice]!u@h".into(), false),
            MemberModes::default(),
        );

        let (conn, recipient, identity) = channel
            .member_named(CaseMapping::Rfc1459, "{alice}")
            .expect("casefolded member");
        assert_eq!(conn, ConnId(2));
        assert_eq!(recipient.shard(), CoreShardId(1));
        assert_eq!(identity.nick, "[Alice]");
    }

    #[test]
    fn refreshing_a_member_updates_its_delivery_capabilities() {
        let mut state = state();
        open(&mut state, ConnId(1));
        let key = state.chan_key("#chat");
        let recipient = state.local_recipient(ConnId(1));
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
        channel.add_member(
            recipient,
            MemberIdentity::new("one".into(), "one!u@h".into(), false),
            MemberModes::default(),
        );
        state.channels.entry(key.clone()).or_insert(channel);
        state
            .sessions
            .get_mut(&ConnId(1))
            .expect("open session")
            .channels
            .insert(key);

        state
            .sessions
            .get_mut(&ConnId(1))
            .expect("open session")
            .caps
            .server_time = true;
        state.refresh_recipient(ConnId(1));

        assert!(
            state.channels[&state.chan_key("#chat")].recipients()[0]
                .caps()
                .server_time
        );
    }

    #[test]
    fn remote_recipient_becomes_a_typed_delivery_effect() {
        let mut state = state();
        let key = state.chan_key("#chat");
        let mut channel = Channel::new("#chat".into(), None, ChanModes::default(), 0);
        channel.add_member(
            Recipient {
                owner: SessionOwner::new(ConnId(9), CoreShardId(1)),
                caps: Caps {
                    server_time: true,
                    ..Caps::default()
                },
            },
            MemberIdentity::new("remote".into(), "remote!u@h".into(), false),
            MemberModes::default(),
        );
        state.channels.entry(key.clone()).or_insert(channel);

        state.broadcast_channel(&key, ":nick PRIVMSG #chat :hello", None);

        let effects = state.take_effects();
        assert_eq!(effects.len(), 1);
        let crate::core::CoreEffect::Delivery { owner, line } = &effects[0] else {
            panic!("expected delivery effect");
        };
        assert_eq!(*owner, SessionOwner::new(ConnId(9), CoreShardId(1)));
        assert!(line.starts_with(b"@time="));
        assert!(line.ends_with(b":nick PRIVMSG #chat :hello\r\n"));
    }

    #[test]
    fn reused_slot_has_a_new_generation() {
        let mut state = state();
        open(&mut state, ConnId(1));
        let old = state.sessions.by_conn[&ConnId(1)];
        state.sessions.remove(&ConnId(1));
        open(&mut state, ConnId(2));
        let current = state.sessions.by_conn[&ConnId(2)];

        assert_eq!(old.slot, current.slot);
        assert_ne!(old.generation, current.generation);
        assert!(state.sessions.get(&ConnId(1)).is_none());
        assert!(state.sessions.get(&ConnId(2)).is_some());
    }
}
