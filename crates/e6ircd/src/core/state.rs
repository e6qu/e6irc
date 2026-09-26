//! All chat state, owned exclusively by the core worker.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::ops::Index;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::numerics::{
    ERR_NEEDMOREPARAMS, ERR_NOSUCHCHANNEL, ERR_NOSUCHNICK, ERR_NOTONCHANNEL, ERR_USERNOTINCHANNEL,
    RPL_LOGGEDIN, RPL_LOGGEDOUT,
};
use e6irc_queue::Sender;

use super::banmask::{MaskShape, MaskSubject};
use super::hot_history::HotHistory;
use super::{
    CoreEffect, CoreShardCount, CoreShardId, SessionOutput, SessionOwner, WireLine, Written,
};
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

    /// A key from a name the test has already folded.
    #[cfg(test)]
    pub(crate) fn for_test(folded: &str) -> Self {
        ChanKey(folded.to_string())
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

#[derive(Clone, Default)]
pub(crate) struct MembershipDirectory {
    by_conn: Arc<Mutex<HashMap<ConnId, HashSet<ChanKey>>>>,
    /// What a channel's owner publishes about it for the shards that do not
    /// hold it: enough to list a user's channels in WHOIS with their rank, to
    /// keep a secret channel out of that list, and to say when the channel's
    /// history ring last saw a message.
    channels: Arc<Mutex<HashMap<ChanKey, PublicChannel>>>,
}

/// A channel as any shard may describe it; see [`MembershipDirectory`].
pub(crate) struct PublicChannel {
    name: String,
    secret: bool,
    /// Members holding op or voice. Everyone else is a plain member.
    ranks: HashMap<ConnId, MemberModes>,
    /// The newest entry in the channel's history ring, in every scope. The
    /// ring lives with the channel's owner; with no database it is the whole
    /// record, and CHATHISTORY TARGETS is answered from this on every shard.
    latest_message: crate::core::hot_history::Latest,
    /// When this incarnation was created ([`Channel::created_at`]), so a
    /// shard that does not own the channel bounds its history the same way.
    created_at: e6irc_proto::time::Millis,
    /// The masks that silence a plain member, so the shard holding a session
    /// can refuse its NICK while it is banned or quieted in a channel another
    /// shard owns (ERR_BANNICKCHANGE) without a round trip.
    silencing: SilencingMasks,
}

/// A channel's `+b`, `+q` and `+e` lists, as published for [`PublicChannel`].
struct SilencingMasks {
    bans: Vec<MaskKey>,
    quiets: Vec<MaskKey>,
    exceptions: Vec<MaskKey>,
}

impl SilencingMasks {
    /// Whether `subject` is banned or quieted here — [`Channel::is_banned`] or
    /// [`Channel::is_quieted`], which share the ban-exception list.
    fn silences(&self, casemap: CaseMapping, subject: &MaskSubject<'_>) -> bool {
        (Channel::any_match(casemap, &self.bans, subject)
            || Channel::any_match(casemap, &self.quiets, subject))
            && !Channel::any_match(casemap, &self.exceptions, subject)
    }
}

impl MembershipDirectory {
    fn publish_channel(&self, key: &ChanKey, channel: Option<PublicChannel>) {
        let mut channels = self.channels.lock().expect("membership directory poisoned");
        match channel {
            Some(channel) => channels.insert(key.clone(), channel),
            None => channels.remove(key),
        };
    }

    /// Update only the newest-message time of `key`'s published record.
    /// Whether there was a record to update.
    fn publish_latest_message(
        &self,
        key: &ChanKey,
        latest: crate::core::hot_history::Latest,
    ) -> bool {
        let mut channels = self.channels.lock().expect("membership directory poisoned");
        match channels.get_mut(key) {
            Some(channel) => {
                channel.latest_message = latest;
                true
            }
            None => false,
        }
    }

    /// A channel's display name and the time of the newest entry in its
    /// history ring a reader in `scope` can be sent, when it has one.
    pub(crate) fn channel_activity(
        &self,
        key: &ChanKey,
        scope: crate::core::HistoryScope,
    ) -> Option<(String, e6irc_proto::time::Millis)> {
        let channels = self.channels.lock().expect("membership directory poisoned");
        let channel = channels.get(key)?;
        Some((
            channel.name.clone(),
            channel.latest_message.in_scope(scope)?,
        ))
    }

    /// When a channel's current incarnation was created.
    fn channel_created_at(&self, key: &ChanKey) -> Option<e6irc_proto::time::Millis> {
        let channels = self.channels.lock().expect("membership directory poisoned");
        channels.get(key).map(|channel| channel.created_at)
    }

    /// `target`'s channels as WHOIS shows them to `requester`: rank sigils (all
    /// of them for a `multi_prefix` requester) and display name, sorted,
    /// without the secret channels the two do not share.
    pub(crate) fn whois_channels(
        &self,
        target: ConnId,
        requester: ConnId,
        multi_prefix: bool,
    ) -> Vec<String> {
        let by_conn = self.by_conn.lock().expect("membership directory poisoned");
        let channels = self.channels.lock().expect("membership directory poisoned");
        let shared = by_conn.get(&requester);
        let mut shown: Vec<String> = by_conn
            .get(&target)
            .into_iter()
            .flatten()
            .filter_map(|key| {
                let channel = channels.get(key)?;
                // A +s (secret) channel is disclosed only to a requester who
                // also shares it, so WHOIS can't enumerate hidden channels a
                // target is in.
                if channel.secret && !shared.is_some_and(|shared| shared.contains(key)) {
                    return None;
                }
                let sigil = channel
                    .ranks
                    .get(&target)
                    .map_or("", |modes| modes.sigils(multi_prefix));
                Some(format!("{sigil}{}", channel.name))
            })
            .collect();
        shown.sort();
        shown
    }

    /// The display name of a channel `conn` is in where it holds neither op
    /// nor voice and `subject` is banned or quieted — the channel a
    /// NICK must be refused for (Solanum: a banned member cannot change nick,
    /// or it could escape the ban and speak). `None` when there is none.
    pub(crate) fn silenced_in(
        &self,
        conn: ConnId,
        casemap: CaseMapping,
        subject: &MaskSubject<'_>,
    ) -> Option<String> {
        let by_conn = self.by_conn.lock().expect("membership directory poisoned");
        let channels = self.channels.lock().expect("membership directory poisoned");
        let mut silenced: Vec<&str> = by_conn
            .get(&conn)
            .into_iter()
            .flatten()
            .filter_map(|key| channels.get(key))
            .filter(|channel| {
                !channel
                    .ranks
                    .get(&conn)
                    .is_some_and(|modes| modes.op || modes.voice)
                    && channel.silencing.silences(casemap, subject)
            })
            .map(|channel| channel.name.as_str())
            .collect();
        // The set iterates in hash order; name the same channel every time.
        silenced.sort_unstable();
        silenced.first().map(|name| name.to_string())
    }

    pub(crate) fn join(&self, conn: ConnId, key: ChanKey) {
        self.by_conn
            .lock()
            .expect("membership directory poisoned")
            .entry(conn)
            .or_default()
            .insert(key);
    }

    pub(crate) fn part(&self, conn: ConnId, key: &ChanKey) {
        let mut by_conn = self.by_conn.lock().expect("membership directory poisoned");
        let Some(channels) = by_conn.get_mut(&conn) else {
            return;
        };
        channels.remove(key);
        if channels.is_empty() {
            by_conn.remove(&conn);
        }
    }

    pub(crate) fn release(&self, conn: ConnId) {
        self.by_conn
            .lock()
            .expect("membership directory poisoned")
            .remove(&conn);
    }

    pub(crate) fn shares(&self, a: ConnId, b: ConnId) -> bool {
        let by_conn = self.by_conn.lock().expect("membership directory poisoned");
        let (Some(a), Some(b)) = (by_conn.get(&a), by_conn.get(&b)) else {
            return false;
        };
        a.intersection(b).next().is_some()
    }

    pub(crate) fn contains(&self, conn: ConnId, key: &ChanKey) -> bool {
        self.by_conn
            .lock()
            .expect("membership directory poisoned")
            .get(&conn)
            .is_some_and(|channels| channels.contains(key))
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
///
/// It also carries what the mask *means* ([`MaskShape`]: a glob, a CIDR host,
/// an account extban), decided once here rather than on every match. The
/// strict decision — refusing a mask that could never match as written — is
/// made where a mask is *added* (`channel_list_mask`, `BanMask::parse`), before
/// this is built; a mask reaching here unvalidated (a removal's argument, a
/// server ban persisted before validation existed) that does not parse keeps
/// the meaning every mask had before shapes existed, a literal glob.
#[derive(Debug, Clone)]
pub struct MaskKey {
    folded: String,
    display: String,
    shape: MaskShape,
}

impl MaskKey {
    pub fn new(mask: &str, casemap: CaseMapping) -> Self {
        Self {
            folded: casemap.casefold(mask),
            display: mask.to_string(),
            shape: MaskShape::parse(mask).unwrap_or(MaskShape::Glob),
        }
    }

    /// Whether `subject` matches this mask, by its [`MaskShape`].
    pub(crate) fn matches(&self, casemap: CaseMapping, subject: &MaskSubject<'_>) -> bool {
        self.shape.matches(casemap, &self.display, subject)
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

/// Process-wide authoritative registered-channel ownership: each registered
/// channel's founder and successor (ChanServ SET SUCCESSOR).
#[derive(Clone, Default)]
pub(crate) struct FounderDirectory {
    by_channel: Arc<Mutex<HashMap<ChanKey, ChannelOwnership>>>,
}

/// Who owns a registered channel, and who inherits it.
#[derive(Clone)]
struct ChannelOwnership {
    founder: AccountKey,
    successor: Option<AccountKey>,
}

impl FounderDirectory {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ChanKey, ChannelOwnership>> {
        self.by_channel.lock().expect("founder directory poisoned")
    }

    /// Seed founders (without successors; see [`Self::replace_successors`]).
    pub(crate) fn replace(&self, rows: impl IntoIterator<Item = (ChanKey, AccountKey)>) {
        *self.lock() = rows
            .into_iter()
            .map(|(channel, founder)| {
                (
                    channel,
                    ChannelOwnership {
                        founder,
                        successor: None,
                    },
                )
            })
            .collect();
    }

    /// Seed the successors of already-seeded channels.
    pub(crate) fn replace_successors(&self, rows: impl IntoIterator<Item = (ChanKey, AccountKey)>) {
        let mut channels = self.lock();
        for ownership in channels.values_mut() {
            ownership.successor = None;
        }
        for (channel, successor) in rows {
            if let Some(ownership) = channels.get_mut(&channel) {
                ownership.successor = Some(successor);
            }
        }
    }

    pub(crate) fn founder(&self, key: &ChanKey) -> Option<AccountKey> {
        self.lock()
            .get(key)
            .map(|ownership| ownership.founder.clone())
    }

    pub(crate) fn successor(&self, key: &ChanKey) -> Option<AccountKey> {
        self.lock()
            .get(key)
            .and_then(|ownership| ownership.successor.clone())
    }

    /// A newly registered channel: its founder, and no successor yet.
    pub(crate) fn register(&self, key: ChanKey, founder: AccountKey) {
        self.lock().insert(
            key,
            ChannelOwnership {
                founder,
                successor: None,
            },
        );
    }

    /// A registered channel passed to `founder` (a transfer, or the
    /// succession an account deletion performs): as in storage, it has no
    /// successor from then on. Passing a channel to the founder it already has
    /// changes nothing, so every shard may apply the same succession broadcast.
    pub(crate) fn transfer(&self, key: ChanKey, founder: AccountKey) {
        let mut channels = self.lock();
        if channels
            .get(&key)
            .is_some_and(|ownership| ownership.founder == founder)
        {
            return;
        }
        channels.insert(
            key,
            ChannelOwnership {
                founder,
                successor: None,
            },
        );
    }

    pub(crate) fn set_successor(&self, key: &ChanKey, successor: Option<AccountKey>) {
        if let Some(ownership) = self.lock().get_mut(key) {
            ownership.successor = successor;
        }
    }

    /// `account` was deleted: it succeeds no channel any more (its references
    /// were set to NULL with it).
    pub(crate) fn forget_successor(&self, account: &AccountKey) {
        for ownership in self.lock().values_mut() {
            if ownership.successor.as_ref() == Some(account) {
                ownership.successor = None;
            }
        }
    }

    pub(crate) fn remove(&self, key: &ChanKey) {
        self.lock().remove(key);
    }

    pub(crate) fn count(&self, account: &AccountKey) -> usize {
        self.lock()
            .values()
            .filter(|ownership| ownership.founder == *account)
            .count()
    }
}

/// Process-wide retained topics for registered channels.
#[derive(Clone, Default)]
pub(crate) struct RetainedTopicDirectory {
    by_channel: Arc<Mutex<HashMap<ChanKey, Topic>>>,
}

impl RetainedTopicDirectory {
    pub(crate) fn replace(&self, rows: impl IntoIterator<Item = (ChanKey, Topic)>) {
        *self
            .by_channel
            .lock()
            .expect("retained topic directory poisoned") = rows.into_iter().collect();
    }

    pub(crate) fn get(&self, key: &ChanKey) -> Option<Topic> {
        self.by_channel
            .lock()
            .expect("retained topic directory poisoned")
            .get(key)
            .cloned()
    }

    pub(crate) fn set(&self, key: ChanKey, topic: Topic) {
        self.by_channel
            .lock()
            .expect("retained topic directory poisoned")
            .insert(key, topic);
    }

    pub(crate) fn remove(&self, key: &ChanKey) {
        self.by_channel
            .lock()
            .expect("retained topic directory poisoned")
            .remove(key);
    }
}

/// Process-wide durable options for registered channels.
#[derive(Clone, Default)]
pub(crate) struct ChannelOptionsDirectory {
    inner: Arc<Mutex<ChannelOptions>>,
}

#[derive(Default)]
struct ChannelOptions {
    keeptopic_off: HashSet<ChanKey>,
    mlock: HashMap<ChanKey, MlockModes>,
    access: HashMap<ChanKey, HashMap<AccountKey, String>>,
}

impl ChannelOptionsDirectory {
    pub(crate) fn replace_keeptopic_off(&self, names: impl IntoIterator<Item = ChanKey>) {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .keeptopic_off = names.into_iter().collect();
    }

    pub(crate) fn set_keeptopic(&self, key: ChanKey, enabled: bool) {
        let mut options = self
            .inner
            .lock()
            .expect("channel options directory poisoned");
        if enabled {
            options.keeptopic_off.remove(&key);
        } else {
            options.keeptopic_off.insert(key);
        }
    }

    #[cfg(test)]
    pub(crate) fn keeptopic_enabled(&self, key: &ChanKey) -> bool {
        !self
            .inner
            .lock()
            .expect("channel options directory poisoned")
            .keeptopic_off
            .contains(key)
    }

    pub(crate) fn replace_mlock(&self, mlock: HashMap<ChanKey, MlockModes>) {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .mlock = mlock;
    }

    pub(crate) fn mlock(&self, key: &ChanKey) -> Option<MlockModes> {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .mlock
            .get(key)
            .cloned()
    }

    pub(crate) fn set_mlock(&self, key: ChanKey, mlock: Option<MlockModes>) {
        let mut options = self
            .inner
            .lock()
            .expect("channel options directory poisoned");
        match mlock {
            Some(mlock) => {
                options.mlock.insert(key, mlock);
            }
            None => {
                options.mlock.remove(&key);
            }
        }
    }

    pub(crate) fn replace_access(
        &self,
        rows: impl IntoIterator<Item = (ChanKey, AccountKey, String)>,
    ) {
        let mut access = HashMap::<ChanKey, HashMap<AccountKey, String>>::new();
        for (channel, account, flags) in rows {
            access.entry(channel).or_default().insert(account, flags);
        }
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .access = access;
    }

    pub(crate) fn access_entries(&self, key: &ChanKey) -> Vec<(AccountKey, String)> {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .access
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(a, f)| (a.clone(), f.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn access_flags(&self, key: &ChanKey, account: &AccountKey) -> Option<String> {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .access
            .get(key)
            .and_then(|entries| entries.get(account))
            .cloned()
    }

    pub(crate) fn set_access(&self, key: ChanKey, account: AccountKey, flags: Option<String>) {
        let mut options = self
            .inner
            .lock()
            .expect("channel options directory poisoned");
        match flags {
            Some(flags) => {
                options
                    .access
                    .entry(key)
                    .or_default()
                    .insert(account, flags);
            }
            None => {
                if let Some(entries) = options.access.get_mut(&key) {
                    entries.remove(&account);
                    if entries.is_empty() {
                        options.access.remove(&key);
                    }
                }
            }
        }
    }

    /// Drop `account` from every channel's access list: its rows cascaded
    /// away with the account. A pass over every registered channel, paid only
    /// by an account's permanent deletion.
    pub(crate) fn remove_account(&self, account: &AccountKey) {
        self.inner
            .lock()
            .expect("channel options directory poisoned")
            .access
            .retain(|_, entries| {
                entries.remove(account);
                !entries.is_empty()
            });
    }

    pub(crate) fn remove(&self, key: &ChanKey) {
        let mut options = self
            .inner
            .lock()
            .expect("channel options directory poisoned");
        options.keeptopic_off.remove(key);
        options.mlock.remove(key);
        options.access.remove(key);
    }
}

/// Process-wide NickServ nick registrations the core acts on: the nicks
/// grouped to an account (NickServ GROUP), and the accounts that protect their
/// nicks (SET ENFORCE). An account's own name is its nick without an entry
/// here. Boot-loaded, and changed only after PostgreSQL confirms a change, so a
/// shard never enforces a registration storage does not hold.
#[derive(Clone, Default)]
pub(crate) struct NickRegistrationDirectory {
    inner: Arc<Mutex<NickRegistrations>>,
}

#[derive(Default)]
struct NickRegistrations {
    grouped: HashMap<NickKey, AccountKey>,
    enforced: HashSet<AccountKey>,
}

impl NickRegistrationDirectory {
    fn lock(&self) -> std::sync::MutexGuard<'_, NickRegistrations> {
        self.inner
            .lock()
            .expect("nick registration directory poisoned")
    }

    pub(crate) fn replace(
        &self,
        grouped: impl IntoIterator<Item = (NickKey, AccountKey)>,
        enforced: impl IntoIterator<Item = AccountKey>,
    ) {
        let mut registrations = self.lock();
        registrations.grouped = grouped.into_iter().collect();
        registrations.enforced = enforced.into_iter().collect();
    }

    pub(crate) fn group(&self, nick: NickKey, account: AccountKey) {
        self.lock().grouped.insert(nick, account);
    }

    /// `nick` is no longer grouped to `account`; a grouping to another
    /// account is left alone.
    pub(crate) fn ungroup_from(&self, nick: &NickKey, account: &AccountKey) {
        let mut registrations = self.lock();
        if registrations.grouped.get(nick) == Some(account) {
            registrations.grouped.remove(nick);
        }
    }

    pub(crate) fn set_enforce(&self, account: AccountKey, enforce: bool) {
        let mut registrations = self.lock();
        if enforce {
            registrations.enforced.insert(account);
        } else {
            registrations.enforced.remove(&account);
        }
    }

    /// Drop every registration of a permanently deleted account: its grouped
    /// nicks cascaded away with it.
    pub(crate) fn forget_account(&self, account: &AccountKey) {
        let mut registrations = self.lock();
        registrations.grouped.retain(|_, owner| owner != account);
        registrations.enforced.remove(account);
    }

    /// The account `nick` is grouped to, if it is a grouped nick.
    pub(crate) fn grouped_owner(&self, nick: &NickKey) -> Option<AccountKey> {
        self.lock().grouped.get(nick).cloned()
    }

    /// The account protecting `nick`: the one it is grouped to, or else the
    /// account spelled like it (`named`), when that account has ENFORCE on.
    pub(crate) fn protector(&self, nick: &NickKey, named: AccountKey) -> Option<AccountKey> {
        let registrations = self.lock();
        let owner = registrations.grouped.get(nick).cloned().unwrap_or(named);
        registrations.enforced.contains(&owner).then_some(owner)
    }
}

/// A session's nick-protection clocks (NickServ ENFORCE): the protected nick
/// it holds without identifying to its account, if any, and the earliest
/// deadline each protected nick it has held got. A clock never restarts:
/// leaving a nick and coming back — or cycling through protected nicks —
/// finds the deadline it already had, and a session returning to a nick whose
/// deadline has passed is renamed at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NickEnforcement {
    held: Option<NickKey>,
    /// At most [`Self::TRACKED`] entries, one per nick.
    deadlines: Vec<(NickKey, e6irc_proto::time::MonoMillis)>,
}

impl NickEnforcement {
    /// Most nicks whose clocks one session keeps. Past it a new nick's clock
    /// starts at the earliest one kept, so a session cannot buy fresh clocks
    /// by cycling through more nicks than that.
    const TRACKED: usize = 8;

    /// The deadline for holding `nick` unidentified: the one it already has,
    /// or else `fresh`.
    pub(crate) fn deadline(
        &mut self,
        nick: &NickKey,
        fresh: e6irc_proto::time::MonoMillis,
    ) -> e6irc_proto::time::MonoMillis {
        if let Some((_, deadline)) = self.deadlines.iter().find(|(held, _)| held == nick) {
            return *deadline;
        }
        let mut deadline = fresh;
        if self.deadlines.len() >= Self::TRACKED {
            let earliest = self
                .deadlines
                .iter()
                .map(|(_, deadline)| *deadline)
                .min()
                .expect("full");
            deadline = deadline.min(earliest);
            let latest = self
                .deadlines
                .iter()
                .enumerate()
                .max_by_key(|(_, (_, deadline))| *deadline)
                .map(|(index, _)| index)
                .expect("full");
            self.deadlines.swap_remove(latest);
        }
        self.deadlines.push((nick.clone(), deadline));
        deadline
    }

    /// The protected nick held unidentified, if any.
    pub(crate) fn held(&self) -> Option<&NickKey> {
        self.held.as_ref()
    }

    pub(crate) fn hold(&mut self, nick: NickKey) {
        self.held = Some(nick);
    }

    /// The session holds no protected nick unidentified any more; the clocks
    /// are kept.
    pub(crate) fn release(&mut self) {
        self.held = None;
    }

    /// The held nick, when its deadline is at or before `now`.
    pub(crate) fn due(&self, now: e6irc_proto::time::MonoMillis) -> Option<&NickKey> {
        let held = self.held.as_ref()?;
        self.deadlines
            .iter()
            .any(|(nick, deadline)| nick == held && *deadline <= now)
            .then_some(held)
    }

    /// The nicks with a clock, for dropping those an identify has settled.
    pub(crate) fn clocked(&self) -> Vec<NickKey> {
        self.deadlines
            .iter()
            .map(|(nick, _)| nick.clone())
            .collect()
    }

    /// Forget `nick`'s clock (and stop holding it): the session proved it may
    /// use it.
    pub(crate) fn settle(&mut self, nick: &NickKey) {
        self.deadlines.retain(|(held, _)| held != nick);
        if self.held.as_ref() == Some(nick) {
            self.held = None;
        }
    }
}

/// What any shard may know about a registered user: the public face of a
/// session, as WHOIS, WHO, ISON, USERHOST, MONITOR and message delivery see it.
///
/// A session lives on one shard; the people asking about it live on all of
/// them. The owning shard publishes this record whenever the session's public
/// state changes (see [`ServerState::publish_changed_sessions`]), and every
/// shard — the owning one included — answers from it. One record, one answer:
/// a single-worker server and a many-worker one cannot differ.
#[derive(Debug)]
pub(crate) struct PublicUser {
    pub(crate) recipient: Recipient,
    pub(crate) nick: String,
    pub(crate) user: String,
    pub(crate) host: String,
    /// The address the connection came from ([`Session::real_ip`]); never
    /// shown, only matched by bans.
    pub(crate) real_ip: Option<std::net::IpAddr>,
    pub(crate) realname: String,
    pub(crate) account: Option<String>,
    pub(crate) away: Option<String>,
    pub(crate) oper: bool,
    pub(crate) bot: bool,
    pub(crate) invisible: bool,
    pub(crate) wallops: bool,
    /// Umode +R: see [`Session::registered_only`].
    pub(crate) registered_only: bool,
    /// Umode +Z: the connection is TLS end to end ([`Session::secure`]).
    pub(crate) secure: bool,
    pub(crate) signon: e6irc_proto::time::Millis,
    pub(crate) last_active: LastActive,
}

impl PublicUser {
    fn of(session: &Session, recipient: Recipient) -> Self {
        Self {
            recipient,
            nick: session.nick().expect("registered").to_string(),
            user: session.user().expect("registered").to_string(),
            host: session.host.clone(),
            real_ip: session.real_ip,
            realname: session.realname().expect("registered").to_string(),
            account: session.account.clone(),
            away: session.away.clone(),
            oper: session.oper.is_some(),
            bot: session.bot,
            invisible: session.invisible,
            wallops: session.wallops,
            registered_only: session.registered_only,
            secure: session.secure(),
            signon: session.signon,
            last_active: session.last_active.clone(),
        }
    }

    /// Whether this is still what `session` looks like from outside.
    fn describes(&self, session: &Session) -> bool {
        self.recipient.caps() == session.caps
            && Some(self.nick.as_str()) == session.nick()
            && Some(self.user.as_str()) == session.user()
            && self.host == session.host
            && Some(self.realname.as_str()) == session.realname()
            && self.account == session.account
            && self.away == session.away
            && self.oper == session.oper.is_some()
            && self.bot == session.bot
            && self.invisible == session.invisible
            && self.wallops == session.wallops
            && self.registered_only == session.registered_only
            && self.secure == session.secure()
            && self.signon == session.signon
    }

    pub(crate) fn conn(&self) -> ConnId {
        self.recipient.conn()
    }

    /// Whether this user's `+R` refuses a message, notice, TAGMSG or INVITE
    /// from `sender` (Solanum's `um_regonlymsg`): only a sender logged in to
    /// an account, an operator, or the user itself gets through.
    pub(crate) fn refuses_unregistered(&self, sender_conn: ConnId, sender: &Session) -> bool {
        self.registered_only
            && sender_conn != self.conn()
            && sender.account().is_none()
            && sender.oper.is_none()
    }

    pub(crate) fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }

    /// Who this user *is* for owning direct-message history; see
    /// [`ServerState::conn_identity`].
    pub(crate) fn identity(&self, casemap: CaseMapping) -> String {
        match &self.account {
            Some(account) => casemap.casefold(account),
            None => format!("~{}", casemap.casefold(&self.nick)),
        }
    }

    fn member_identity(&self) -> MemberIdentity {
        MemberIdentity::new(self.nick.clone(), self.prefix(), self.invisible)
    }

    fn member_profile(&self) -> ChannelMemberProfile {
        ChannelMemberProfile {
            user: self.user.clone(),
            host: self.host.clone(),
            real_ip: self.real_ip,
            realname: self.realname.clone(),
            account: self.account.clone(),
            away: self.away.is_some(),
            oper: self.oper,
            bot: self.bot,
            last_active: self.last_active.clone(),
        }
    }
}

/// Process-wide [`PublicUser`] records, by connection, with the indexes the
/// per-event questions about them need.
#[derive(Clone, Default)]
pub(crate) struct UserDirectory {
    inner: Arc<Mutex<Users>>,
}

/// How many registered users there are, and how many of them are invisible
/// or operators (LUSERS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct UserCounts {
    pub(crate) users: usize,
    pub(crate) invisible: usize,
    pub(crate) opers: usize,
}

/// The directory's contents. Every index is kept by [`Users::insert`] and
/// [`Users::remove`], the only two places a record comes or goes, so LUSERS
/// and resolving an account to a nick are lookups rather than a copy or scan
/// of every user under the process-wide lock.
#[derive(Default)]
struct Users {
    by_conn: HashMap<ConnId, Arc<PublicUser>>,
    /// Casefolded account → connections logged in to it.
    by_account: HashMap<String, HashSet<ConnId>>,
    counts: UserCounts,
}

impl Users {
    fn account_key(user: &PublicUser) -> Option<String> {
        user.account
            .as_deref()
            .map(|account| CaseMapping::Rfc1459.casefold(account))
    }

    fn insert(&mut self, user: Arc<PublicUser>) {
        self.remove(user.conn());
        let conn = user.conn();
        if let Some(account) = Self::account_key(&user) {
            self.by_account.entry(account).or_default().insert(conn);
        }
        self.counts.users += 1;
        self.counts.invisible += usize::from(user.invisible);
        self.counts.opers += usize::from(user.oper);
        self.by_conn.insert(conn, user);
    }

    fn remove(&mut self, conn: ConnId) {
        let Some(user) = self.by_conn.remove(&conn) else {
            return;
        };
        if let Some(account) = Self::account_key(&user) {
            let std::collections::hash_map::Entry::Occupied(mut entry) =
                self.by_account.entry(account)
            else {
                unreachable!("a published account is indexed");
            };
            entry.get_mut().remove(&conn);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
        self.counts.users -= 1;
        self.counts.invisible -= usize::from(user.invisible);
        self.counts.opers -= usize::from(user.oper);
    }

    /// Recount every index from `by_conn` and assert it matches.
    #[cfg(test)]
    fn assert_consistent(&self) {
        let mut by_account: HashMap<String, HashSet<ConnId>> = HashMap::new();
        for user in self.by_conn.values() {
            if let Some(account) = Self::account_key(user) {
                by_account.entry(account).or_default().insert(user.conn());
            }
        }
        assert_eq!(self.by_account, by_account);
        assert_eq!(
            self.counts,
            UserCounts {
                users: self.by_conn.len(),
                invisible: self.by_conn.values().filter(|user| user.invisible).count(),
                opers: self.by_conn.values().filter(|user| user.oper).count(),
            }
        );
    }
}

impl UserDirectory {
    fn lock(&self) -> std::sync::MutexGuard<'_, Users> {
        self.inner.lock().expect("user directory poisoned")
    }

    fn publish(&self, user: Arc<PublicUser>) {
        self.lock().insert(user);
    }

    fn withdraw(&self, conn: ConnId) {
        self.lock().remove(conn);
    }

    pub(crate) fn get(&self, conn: ConnId) -> Option<Arc<PublicUser>> {
        self.lock().by_conn.get(&conn).cloned()
    }

    fn counts(&self) -> UserCounts {
        self.lock().counts
    }

    fn all(&self) -> Vec<Arc<PublicUser>> {
        self.lock().by_conn.values().cloned().collect()
    }

    /// Some online user logged in to `account` (casefolded), if any.
    fn logged_in_as(&self, account: &str) -> Option<Arc<PublicUser>> {
        let users = self.lock();
        let conn = users.by_account.get(account)?.iter().next()?;
        users.by_conn.get(conn).cloned()
    }

    #[cfg(test)]
    fn assert_consistent(&self) {
        self.lock().assert_consistent();
    }
}

#[derive(Default)]
struct UserEventProgress {
    parts_heard: usize,
    told: HashSet<ConnId>,
}

/// Process-wide MONITOR lists: who watches each nick. The watcher and the
/// watched may live on different shards, and it is the watched nick's shard
/// that sees it come, go and change.
#[derive(Clone, Default)]
pub(crate) struct MonitorDirectory {
    by_nick: Arc<Mutex<HashMap<NickKey, HashSet<ConnId>>>>,
}

impl MonitorDirectory {
    pub(crate) fn watch(&self, key: NickKey, watcher: ConnId) {
        self.by_nick
            .lock()
            .expect("monitor directory poisoned")
            .entry(key)
            .or_default()
            .insert(watcher);
    }

    pub(crate) fn unwatch(&self, key: &NickKey, watcher: ConnId) {
        let mut by_nick = self.by_nick.lock().expect("monitor directory poisoned");
        if let Some(watchers) = by_nick.get_mut(key) {
            watchers.remove(&watcher);
            if watchers.is_empty() {
                by_nick.remove(key);
            }
        }
    }

    pub(crate) fn watchers(&self, key: &NickKey) -> Vec<ConnId> {
        self.by_nick
            .lock()
            .expect("monitor directory poisoned")
            .get(key)
            .map(|watchers| watchers.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// Server-wide head counts (LUSERS), which no one shard can take alone. Each
/// shard adds what changed on it after every event.
#[derive(Clone, Default)]
pub(crate) struct Census {
    connections: Arc<std::sync::atomic::AtomicUsize>,
    channels: Arc<std::sync::atomic::AtomicUsize>,
    most_users: Arc<std::sync::atomic::AtomicUsize>,
}

/// The server-wide WHOWAS ring: a nick may be asked about from any shard.
#[derive(Clone, Default)]
pub(crate) struct WhowasDirectory {
    newest_first: Arc<Mutex<std::collections::VecDeque<WhowasEntry>>>,
}

impl WhowasDirectory {
    fn record(&self, entry: WhowasEntry) {
        let mut ring = self.newest_first.lock().expect("whowas directory poisoned");
        if ring.len() == WHOWAS_CAP {
            ring.pop_back();
        }
        ring.push_front(entry);
    }

    /// Up to `limit` records of `key`, newest first.
    pub(crate) fn of(&self, casemap: CaseMapping, key: &NickKey, limit: usize) -> Vec<WhowasEntry> {
        self.newest_first
            .lock()
            .expect("whowas directory poisoned")
            .iter()
            .filter(|entry| casemap.casefold(&entry.nick) == key.as_str())
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Process-wide directories shared by all core shards.
#[derive(Clone, Default)]
pub(crate) struct CoreDirectories {
    pub(crate) census: Census,
    pub(crate) whowas: WhowasDirectory,
    pub(crate) users: UserDirectory,
    pub(crate) monitors: MonitorDirectory,
    pub(crate) nicks: NickDirectory,
    pub(crate) memberships: MembershipDirectory,
    pub(crate) founders: FounderDirectory,
    pub(crate) topics: RetainedTopicDirectory,
    pub(crate) channel_options: ChannelOptionsDirectory,
    pub(crate) nick_registrations: NickRegistrationDirectory,
}

/// A validated command-flood bucket shape: `burst` tokens at most, refilling
/// `rate` per second. Constructed only through [`CommandFlood::new`], so a
/// bucket that never refills (`rate = 0`), that kills every command
/// (`burst = 0`), or that cannot hold one second of its own rate
/// (`burst < rate`) cannot reach the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFlood {
    burst: u32,
    rate: u32,
}

/// Why a burst/rate pair is not a usable flood bucket; the message names the
/// configuration keys because the configuration validator reports it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandFloodError {
    RateZero,
    BurstZero,
    BurstBelowRate { burst: usize, rate: usize },
    AboveMaximum { maximum: usize },
}

impl std::fmt::Display for CommandFloodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateZero => {
                write!(
                    f,
                    "limits.command_rate must be at least 1 (0 never refills the bucket)"
                )
            }
            Self::BurstZero => write!(
                f,
                "limits.command_burst must be at least 1 (0 flood-kills every command)"
            ),
            Self::BurstBelowRate { burst, rate } => write!(
                f,
                "limits.command_burst ({burst}) must be at least limits.command_rate ({rate}): \
                 the bucket must hold one second of its own refill"
            ),
            Self::AboveMaximum { maximum } => write!(
                f,
                "limits.command_burst and limits.command_rate must be at most {maximum}"
            ),
        }
    }
}

impl std::error::Error for CommandFloodError {}

impl CommandFlood {
    pub fn new(burst: usize, rate: usize) -> Result<Self, CommandFloodError> {
        let maximum = crate::config::MAX_COMMAND_FLOOD_TOKENS;
        if rate == 0 {
            return Err(CommandFloodError::RateZero);
        }
        if burst == 0 {
            return Err(CommandFloodError::BurstZero);
        }
        if burst < rate {
            return Err(CommandFloodError::BurstBelowRate { burst, rate });
        }
        if burst > maximum || rate > maximum {
            return Err(CommandFloodError::AboveMaximum { maximum });
        }
        let narrow =
            |value: usize| u32::try_from(value).expect("bounded by MAX_COMMAND_FLOOD_TOKENS");
        Ok(Self {
            burst: narrow(burst),
            rate: narrow(rate),
        })
    }

    /// The bucket's capacity: the tokens a fresh session starts with.
    pub const fn burst(self) -> u32 {
        self.burst
    }

    /// Tokens regained per second of elapsed monotonic time.
    pub const fn rate(self) -> u32 {
        self.rate
    }
}

#[derive(Clone)]
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
    /// Per-connection outbound queue capacity, in bytes (`sendq_bytes`). The
    /// queue itself enforces this, but output *withheld* behind a deferred
    /// reply has not reached the queue yet, so the same bound is applied to it
    /// here — otherwise a connection waiting on the database could accumulate
    /// lines without limit and escape the SendQ kill entirely.
    pub sendq_bytes: usize,
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
    /// Bytes one history ring may hold before its oldest entries go.
    pub max_history_ring_bytes: usize,
    /// Bytes every history ring together may hold before the least recently
    /// active rings are evicted, as beyond `max_hot_channels`.
    pub max_hot_history_bytes: usize,
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
    /// Per-session command-flood bucket. Registered non-oper sessions spend
    /// one token per command (PING/PONG exempt) and are closed with Excess
    /// Flood when the bucket is empty. The server always sets it (see
    /// `limits.command_burst`/`limits.command_rate`); `None` exists for the
    /// in-process drivers of the test and fuzz harnesses, which pipeline
    /// whole scripted sessions in one clock instant.
    pub command_flood: Option<CommandFlood>,
    /// Per-client-IP account-creation bucket size; `None` disables the throttle.
    /// One token is spent per REGISTER/NickServ-REGISTER that reaches account
    /// creation; the bucket refills to full over an hour (account creation is
    /// rare per real client, so a small burst suffices to blunt bulk-account
    /// abuse without hindering a genuine sign-up).
    pub registration_burst: Option<usize>,
    /// Which clients must have logged in by the end of registration
    /// (`limits.require_sasl`, `limits.require_sasl_from`).
    pub sasl_requirement: crate::config::SaslRequirement,
    /// Account names account registration refuses: the configured
    /// administrators (see [`crate::identity::ReservedAccountNames`]).
    pub reserved_account_names: crate::identity::ReservedAccountNames,
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

/// Who originated an event, as far as a recipient's tags are concerned: the
/// `account` (account-tag) and `bot` (bot-mode) the line carries. A JOIN, a
/// NICK, a MODE a user set bears these exactly as a PRIVMSG does — the
/// account-tag spec puts the tag on *every* message a user originates, not
/// only on messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Originator {
    pub(crate) account: Option<String>,
    pub(crate) bot: bool,
}

/// Every tag the server itself attaches to a line, for one recipient: `msgid`
/// (a message's only), `time`, the originator's `account` and `bot` — in that
/// order, each gated on the recipient's capabilities. The one renderer, shared
/// by the message paths (PRIVMSG/NOTICE/TAGMSG/multiline/INVITE) and every
/// other event line ([`EventLine`]), so no delivery path can omit a tag another
/// path carries.
pub(crate) fn event_tags(
    caps: Caps,
    ts: e6irc_proto::time::Millis,
    msgid: Option<&str>,
    account: Option<&str>,
    bot: bool,
) -> Vec<String> {
    let mut tags = Vec::new();
    if caps.message_tags
        && let Some(msgid) = msgid
    {
        tags.push(format!("msgid={msgid}"));
    }
    if caps.server_time {
        tags.push(format!("time={}", e6irc_proto::time::server_time(ts)));
    }
    if caps.account_tag
        && let Some(account) = account
    {
        // An account name can hold `\` (a legal nick char), an escape
        // introducer in a tag value: escape it so a client decodes the account
        // that actually spoke.
        tags.push(format!(
            "account={}",
            e6irc_proto::message::escape_tag_value(account)
        ));
    }
    if caps.message_tags && bot {
        tags.push("bot".to_string());
    }
    tags
}

/// A line reporting an event — a JOIN, a NICK, a MODE, a QUIT — with what
/// each recipient's tags are rendered from: the event's single timestamp and
/// who originated it. Every event delivery helper takes one of these rather
/// than a bare string, and the only ways to build one name the originator
/// ([`EventLine::by`]) or declare the server the source
/// ([`EventLine::by_server`]), so a user's line can no longer reach a
/// recipient without its `account`/`bot` tags.
#[derive(Debug, Clone)]
pub struct EventLine {
    body: Arc<str>,
    ts: e6irc_proto::time::Millis,
    origin: Option<Originator>,
}

impl EventLine {
    /// A line a user originated.
    pub(crate) fn by(
        origin: Originator,
        ts: e6irc_proto::time::Millis,
        body: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            body: body.into(),
            ts,
            origin: Some(origin),
        }
    }

    /// A line the server (or a services pseudo-client) originated.
    pub(crate) fn by_server(ts: e6irc_proto::time::Millis, body: impl Into<Arc<str>>) -> Self {
        Self {
            body: body.into(),
            ts,
            origin: None,
        }
    }

    pub(crate) fn ts(&self) -> e6irc_proto::time::Millis {
        self.ts
    }

    /// The same event with another body (the extended-join form of a JOIN).
    pub(crate) fn with_body(&self, body: impl Into<Arc<str>>) -> Self {
        Self {
            body: body.into(),
            ts: self.ts,
            origin: self.origin.clone(),
        }
    }

    /// The wire form for a recipient with `caps`, CRLF included.
    pub(crate) fn render(&self, caps: Caps) -> Bytes {
        let (account, bot) = self.origin.as_ref().map_or((None, false), |origin| {
            (origin.account.as_deref(), origin.bot)
        });
        let tags = event_tags(caps, self.ts, None, account, bot);
        if tags.is_empty() {
            Bytes::from(format!("{}\r\n", self.body))
        } else {
            Bytes::from(format!("@{} {}\r\n", tags.join(";"), self.body))
        }
    }

    /// Which of `caps` change the rendered form: recipients agreeing on these
    /// receive identical bytes, so a broadcast renders once per variant.
    fn variant(&self, caps: Caps) -> usize {
        usize::from(caps.server_time)
            | usize::from(caps.account_tag) << 1
            | usize::from(caps.message_tags) << 2
    }
}

/// A shard's source of message ids: unique across the shards of one process
/// (each id names its shard) and across restarts (each names a random
/// per-process boot value), so no two messages ever share one. The `messages`
/// table keys on the msgid and keeps the first row of a duplicate, so an id
/// shared by two messages — two shards counting from zero in the same
/// millisecond, or a restart whose clock stepped back — silently loses the
/// second from history. The id is opaque to every reader (CHATHISTORY pivots,
/// the bouncer, clients all compare it whole); the leading millisecond only
/// keeps ids roughly time-ordered for a human reading them.
#[derive(Debug)]
struct MsgidSource {
    /// `{shard}-{boot}-`, fixed for the process.
    stem: String,
    counter: u64,
}

impl MsgidSource {
    fn new(shard: CoreShardId) -> Self {
        use aws_lc_rs::rand::SecureRandom;
        let mut boot = [0u8; 8];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut boot)
            .expect("the system RNG must seed message-id uniqueness across restarts");
        Self::with_boot(shard, u64::from_le_bytes(boot))
    }

    fn with_boot(shard: CoreShardId, boot: u64) -> Self {
        Self {
            stem: format!("{}-{boot:016x}-", shard.0),
            counter: 0,
        }
    }

    fn next(&mut self, now: e6irc_proto::time::Millis) -> String {
        self.counter += 1;
        format!("{}-{}{}", now.as_millis(), self.stem, self.counter)
    }
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
        /// The nick last refused because another session holds it, while no
        /// nick has been taken since: what `REGISTER *` would have named.
        refused_nick: Option<String>,
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
    output: SessionOutput,
    pub host: String,
    /// The address the connection came from, fixed when it opened: what a
    /// D-line, an address-shaped K-line and a channel ban on an address or
    /// CIDR range match. A `SETHOST` changes `host`, never this, so a cloak is
    /// no way out of a ban on the address. `None` for a session opened
    /// in-process under a name rather than an address.
    pub(crate) real_ip: Option<std::net::IpAddr>,
    /// What this session's per-address limits are charged to, fixed from the
    /// host it opened with (a later SETHOST changes only what is shown).
    limit_key: crate::net::SessionLimitKey,
    pub transport: crate::core::ConnectionTransport,
    /// Registration state and the identity fields, as one sum type (see
    /// [`Registration`]): a registered connection *has* a nick/user/realname.
    reg: Registration,
    /// Mid-CAP-negotiation: registration is held until CAP END.
    pub cap_negotiating: bool,
    /// The client sent `CAP LS 302` (or later): it gets capability values,
    /// multi-line CAP replies, and `cap-notify` it cannot turn off.
    pub cap_302: bool,
    pub caps: Caps,
    /// Services account this connection is authenticated to. Written only by
    /// [`ServerState::set_account`] and [`ServerState::clear_account`]: a
    /// login changes the connection's identity (see
    /// [`ServerState::conn_identity`]), and what the old identity owned must
    /// be dealt with in the same step.
    account: Option<String>,
    pub sasl: SaslState,
    /// A SASL credential verify is genuinely outstanding (dispatched, reply not
    /// yet seen). Unlike `sasl == Verifying`, this survives an `AUTHENTICATE *`
    /// abort — the abort clears the state machine but cannot un-send the DB
    /// request, so the reply still comes. It gates a *new* SASL verify and an
    /// IDENTIFY until that stale reply is drained, so a reply can never be
    /// attributed to a different attempt than the one that produced it. It
    /// carries the label of the `AUTHENTICATE` that completed the payload: the
    /// verdict is that command's labeled response.
    pub sasl_verify: Option<PendingServiceReply>,
    /// Accumulates 400-byte AUTHENTICATE continuation chunks (SASL spec)
    /// until a short line completes the payload.
    pub sasl_buf: String,
    /// Credential-verification attempts made on this connection, capped so a
    /// single socket can't drive unbounded argon2 work (unauth CPU DoS / online
    /// brute-force). Never reset — the budget is per connection lifetime.
    pub credential_attempts: crate::identity::CredentialAttemptBudget,
    /// Deferred NickServ IDENTIFY reply.
    pub pending_identify: Option<PendingServiceReply>,
    /// Deferred NickServ REGISTER reply.
    pub pending_register: Option<PendingServiceReply>,
    /// The protected nick this session holds without having identified to
    /// its account, and the clocks of those it has held (NickServ ENFORCE).
    pub(crate) nick_enforcement: NickEnforcement,
    /// The confirmation key NickServ DROP last gave this session, with the
    /// account it is for: the drop proceeds only when it is repeated.
    pub(crate) drop_confirmation: Option<(AccountKey, String)>,
    /// Away message, when set.
    pub away: Option<String>,
    /// IRC operator (umode +o): the configured operator name the session
    /// authenticated as with OPER, which the audit trail records as the actor
    /// of its privileged actions.
    pub oper: Option<String>,
    /// Invisible (umode +i): hidden from WHO/WHOIS mask queries by
    /// users who share no channel.
    pub invisible: bool,
    /// Wallops recipient (umode +w).
    pub wallops: bool,
    /// Bot (umode +B).
    pub bot: bool,
    /// Only users logged in to an account may message, notice, TAGMSG or
    /// invite this one (umode +R, Solanum's `um_regonlymsg`).
    pub registered_only: bool,
    /// Joined channels.
    pub channels: HashSet<ChanKey>,
    /// JOINs routed to a channel owned by another shard and not yet answered,
    /// counted per channel: a client may send several to one channel before
    /// the first is answered (a wrong key, then the right one), and the
    /// channel is in flight until the last of them is. They count towards the
    /// per-session channel limit from the moment they are sent: the limit is
    /// enforced here, before routing, and a pipelined burst would otherwise
    /// be admitted without bound while its answers are in flight. A channel
    /// this shard owns is joined in the same step and never appears here.
    /// Written only through [`Session::join_sent`] and
    /// [`Session::join_answered`].
    pending_joins: HashMap<ChanKey, NonZeroUsize>,
    /// How many of a channel's `pending_joins` — the oldest, as the owner
    /// answers in order — a later `JOIN 0` must part once answered: each
    /// reached its owner first, so it is honoured, then left. Never more than
    /// the channel's `pending_joins`.
    part_on_join: HashMap<ChanKey, NonZeroUsize>,
    /// When this session's last KNOCK was delivered, on the monotonic clock: a
    /// user may knock once per `KNOCK_DELAY` (Solanum's `knock_delay`).
    pub last_knock: Option<e6irc_proto::time::MonoMillis>,
    /// Nicks this session MONITORs (display form as given).
    pub monitoring: HashMap<NickKey, String>,
    /// The `draft/multiline` batch this connection is filling, if any.
    pub multiline: Option<MultilineBatch>,
    /// This connection's LIST still answering, gathering or sending. On the
    /// session, so a LIST cannot be paced to a connection that is gone.
    pub(crate) channel_list: Option<crate::core::list::ListProgress>,
    /// This connection's WHO replies too long to queue at once, still going
    /// out as its send queue drains. On the session for the same reason.
    pub(crate) paced_who: Option<crate::core::paced::PacedReplies>,
    /// Labeled commands whose one response is being assembled from several
    /// channel owners' answers, by label.
    pub(crate) label_groups: HashMap<String, LabelGroup>,
    /// Read markers for a client that isn't logged in: per-connection and not
    /// persisted (there is no account to key them to). A logged-in client uses
    /// the account-keyed `ServerState::read_markers` instead. A marker set here
    /// *before* a mid-session login is intentionally not migrated into the account
    /// map on IDENTIFY/SASL: it was unattributable when set, and carrying it over
    /// would write a persisted marker the client never asked to associate with the
    /// account (same reason the DM-history identity key is not back-filled).
    pub anon_read_markers: HashMap<ChanKey, e6irc_proto::time::Millis>,
    /// Command-flood token bucket: tokens remaining, and the clock-millisecond
    /// through which refill has already been credited (it advances by whole
    /// tokens' worth only, so a sub-token remainder carries forward instead of
    /// being discarded).
    pub flood_tokens: u32,
    /// Monotonic — the flood refill is a timer, not a timestamp.
    pub flood_refilled_to_ms: e6irc_proto::time::MonoMillis,
    /// Monotonic millisecond of the last non-keepalive command — the elapsed
    /// idle duration since it (WHOIS idle / WHOX `l`) and the reaper's idle-ping
    /// cadence both read it. (WHOIS *signon*, a real timestamp, is `signon`.)
    pub last_active: LastActive,
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
    pub held: crate::core::HeldOutput,
    /// CHATHISTORY requests this session has waiting on the database, bounded
    /// by [`MAX_HISTORY_REQUESTS_IN_FLIGHT`].
    history_requests_in_flight: usize,
    /// What the rest of the server currently believes about this session: the
    /// record in the [`UserDirectory`], also copied into every channel it is
    /// in. `None` until it registers.
    published: Option<Arc<PublicUser>>,
}

/// Most CHATHISTORY requests one session may have waiting on the database at
/// once. Every request the ring cannot answer takes a slot in the one database
/// queue that logins, registrations, read markers and message logging share, so
/// without a bound a single client pipelining such requests fills it and those
/// fail for everyone. Eight is far beyond what a client paging its open buffers
/// on reconnect keeps outstanding.
pub(crate) const MAX_HISTORY_REQUESTS_IN_FLIGHT: usize = 8;

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
    /// How many stored sessions are registered. Kept at the only two places
    /// that number can change — a session completing registration, and a
    /// registered session leaving the store — because the core reports it after
    /// every event, and counting every session each time is O(sessions) per
    /// event.
    registered: usize,
    /// Sessions handed out mutably, or removed, since the last
    /// [`SessionStore::take_touched`]: the only ones whose public state can
    /// have changed.
    touched: Vec<ConnId>,
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
            registered: 0,
            touched: Vec::new(),
        }
    }

    /// The sessions that may have changed since the last call, each once.
    fn take_touched(&mut self) -> Vec<ConnId> {
        let mut touched = std::mem::take(&mut self.touched);
        touched.sort_unstable_by_key(|conn| conn.0);
        touched.dedup();
        touched
    }

    /// Mutable access for the output path alone — queueing or holding a line
    /// for the connection. It is not recorded as a possible change to what
    /// others see, because a delivery to ten thousand members would otherwise
    /// queue ten thousand sessions for a comparison none of them can fail.
    fn output_mut(&mut self, conn: &ConnId) -> Option<&mut Session> {
        self.lookup_mut(conn)
    }

    /// Every session, for writing its last output; like [`Self::output_mut`],
    /// not a change to what others see.
    fn closing_sessions_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        self.slots
            .iter_mut()
            .filter_map(|slot| slot.session.as_mut())
    }

    /// The number of registered sessions.
    pub(crate) fn registered_len(&self) -> usize {
        debug_assert_eq!(
            self.registered,
            self.values().filter(|s| s.is_registered()).count(),
            "registered-session count drifted from the sessions it counts"
        );
        self.registered
    }

    /// Complete `conn`'s registration if its nick and user are both present.
    /// The only way a session becomes registered, so the count cannot miss it.
    pub(crate) fn complete_registration(&mut self, conn: &ConnId) {
        let Some(session) = self.get_mut(conn) else {
            return;
        };
        let was_registered = session.is_registered();
        session.complete_registration();
        if !was_registered && session.is_registered() {
            self.registered += 1;
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
        self.touched.push(*conn);
        self.lookup_mut(conn)
    }

    fn lookup_mut(&mut self, conn: &ConnId) -> Option<&mut Session> {
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
        self.registered += usize::from(session.is_registered());
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
        self.touched.push(*conn);
        self.len -= 1;
        self.registered -= usize::from(session.is_registered());
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
    /// A JOIN to `key` was routed to the shard that owns it.
    pub(crate) fn join_sent(&mut self, key: ChanKey) {
        self.pending_joins
            .entry(key)
            .and_modify(|count| *count = count.checked_add(1).expect("JOINs in flight counted"))
            .or_insert(NonZeroUsize::MIN);
    }

    /// Whether a JOIN to `key` is still waiting for its answer.
    pub(crate) fn join_in_flight(&self, key: &ChanKey) -> bool {
        self.pending_joins.contains_key(key)
    }

    /// The channels with a JOIN still waiting for its answer.
    pub(crate) fn joins_in_flight(&self) -> impl Iterator<Item = &ChanKey> {
        self.pending_joins.keys()
    }

    /// `JOIN 0`: every JOIN still in flight is parted once it is answered.
    pub(crate) fn part_joins_in_flight(&mut self) {
        self.part_on_join.clone_from(&self.pending_joins);
    }

    /// The oldest JOIN to `key` still in flight was answered — the owner
    /// answers a session's JOINs to one channel in the order they were sent.
    /// Whether a `JOIN 0` was sent after it, so what it admitted must be
    /// parted.
    pub(crate) fn join_answered(&mut self, key: &ChanKey) -> bool {
        fn take_one(counts: &mut HashMap<ChanKey, NonZeroUsize>, key: &ChanKey) -> bool {
            let Some(count) = counts.get_mut(key) else {
                return false;
            };
            match NonZeroUsize::new(count.get() - 1) {
                Some(left) => *count = left,
                None => {
                    counts.remove(key);
                }
            }
            true
        }
        assert!(
            take_one(&mut self.pending_joins, key),
            "a JOIN was answered that this session never sent"
        );
        take_one(&mut self.part_on_join, key)
    }

    /// How many more bytes this connection's send queue takes before it is
    /// half full: the most a paced reply may occupy.
    pub(crate) fn paced_room(&self) -> usize {
        self.output.paced_room()
    }

    /// Whether registration has completed.
    pub fn is_registered(&self) -> bool {
        matches!(self.reg, Registration::Registered { .. })
    }

    /// The services account this connection is logged in to.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
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
            Registration::Registering {
                nick, refused_nick, ..
            } => {
                *nick = Some(value);
                *refused_nick = None;
            }
            Registration::Registered { nick, .. } => *nick = value,
        }
    }

    /// Remember, before registration, that `value` was refused because another
    /// session holds it (see [`Registration::Registering::refused_nick`]).
    pub(crate) fn note_nick_in_use(&mut self, value: &str) {
        if let Registration::Registering { refused_nick, .. } = &mut self.reg {
            *refused_nick = Some(value.to_string());
        }
    }

    /// The nick refused as in use before registration, if no nick was taken
    /// since.
    pub(crate) fn refused_nick(&self) -> Option<&str> {
        match &self.reg {
            Registration::Registering { refused_nick, .. } => refused_nick.as_deref(),
            Registration::Registered { .. } => None,
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
    /// already registered or the identity is incomplete. Reached only through
    /// [`SessionStore::complete_registration`], which keeps the registered count.
    fn complete_registration(&mut self) {
        let placeholder = Registration::Registering {
            nick: None,
            user: None,
            realname: None,
            refused_nick: None,
        };
        self.reg = match std::mem::replace(&mut self.reg, placeholder) {
            Registration::Registering {
                nick: Some(nick),
                user: Some(user),
                realname,
                ..
            } => Registration::Registered {
                nick,
                user,
                realname: realname.unwrap_or_default(),
            },
            // Already registered, or not yet complete: restore unchanged.
            other => other,
        };
    }

    /// What a server ban is tested against for this session.
    /// Umode +Z: whether this connection is TLS all the way to its client —
    /// a TLS listener, or a WebSocket a trusted proxy says reached it over
    /// HTTPS. Derived from the transport, so no client can set or clear it.
    pub(crate) fn secure(&self) -> bool {
        matches!(
            self.transport,
            crate::core::ConnectionTransport::Tls
                | crate::core::ConnectionTransport::SecureWebSocket
        )
    }

    pub(crate) fn server_ban_subject(&self) -> ServerBanSubject<'_> {
        ServerBanSubject {
            user: self.user().unwrap_or("*"),
            host: &self.host,
            real_ip: self.real_ip,
            realname: self.realname().unwrap_or(""),
        }
    }

    /// Who this session is to a channel's masks, given its `prefix()` (taken
    /// by the caller so the subject can borrow it).
    pub(crate) fn mask_subject<'a>(&'a self, prefix: &'a str) -> MaskSubject<'a> {
        MaskSubject::new(prefix, self.real_ip, self.account.as_deref())
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

    /// `nick!user@host` as far as it is known — `*` for a part a registering
    /// session has not sent yet — for RPL_LOGGEDIN and RPL_LOGGEDOUT, which a
    /// connect-time SASL login reaches before registration completes.
    pub(crate) fn login_mask(&self) -> String {
        format!(
            "{}!{}@{}",
            self.nick().unwrap_or("*"),
            self.user().unwrap_or("*"),
            self.host
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MemberModes {
    pub op: bool,
    pub voice: bool,
}

impl MemberModes {
    /// The rank sigils NAMES, WHO and WHOIS show for this member: every rank
    /// held, highest first, to a requester that negotiated `multi-prefix`;
    /// the highest alone to any other. The one renderer, so no reply can
    /// honour the capability where another ignores it.
    pub(crate) fn sigils(&self, multi_prefix: bool) -> &'static str {
        match (self.op, self.voice, multi_prefix) {
            (true, true, true) => "@+",
            (true, _, _) => "@",
            (false, true, _) => "+",
            (false, false, _) => "",
        }
    }
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

/// When a session last did something, on the monotonic clock: the one value
/// behind every "seconds idle" answer.
///
/// It is a shared handle, not a copied timestamp, because it changes with
/// every line a client sends. The session writes it; whoever answers about the
/// user — this shard's WHOIS, another shard's WHO for a channel it owns — reads
/// the same value. Copying it into each channel's member record instead meant
/// one update per channel per line.
#[derive(Debug, Clone)]
pub(crate) struct LastActive(Arc<std::sync::atomic::AtomicU64>);

impl LastActive {
    pub(crate) fn new(at: e6irc_proto::time::MonoMillis) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicU64::new(at.as_millis())))
    }

    pub(crate) fn set(&self, at: e6irc_proto::time::MonoMillis) {
        self.0
            .store(at.as_millis(), std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> e6irc_proto::time::MonoMillis {
        e6irc_proto::time::MonoMillis::from_millis(
            self.0.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelMemberProfile {
    pub(crate) user: String,
    pub(crate) host: String,
    /// The member's real address, which channel bans match alongside `host`.
    pub(crate) real_ip: Option<std::net::IpAddr>,
    pub(crate) realname: String,
    pub(crate) account: Option<String>,
    pub(crate) away: bool,
    pub(crate) oper: bool,
    pub(crate) bot: bool,
    pub(crate) last_active: LastActive,
}

impl ChannelMemberProfile {
    #[cfg(test)]
    fn derived(identity: &MemberIdentity, last_active: e6irc_proto::time::MonoMillis) -> Self {
        let (_, user_host) = identity
            .prefix
            .split_once('!')
            .unwrap_or((&identity.nick, ""));
        let (user, host) = user_host.split_once('@').unwrap_or(("", ""));
        Self {
            user: user.to_string(),
            host: host.to_string(),
            real_ip: None,
            realname: identity.nick.clone(),
            account: None,
            away: false,
            oper: false,
            bot: false,
            last_active: LastActive::new(last_active),
        }
    }
}

impl ChannelMemberProfile {
    /// The member's originator tags, as its channel owner knows them.
    pub(crate) fn originator(&self) -> Originator {
        Originator {
            account: self.account.clone(),
            bot: self.bot,
        }
    }
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
    pub(crate) profile: ChannelMemberProfile,
}

impl ChannelActor {
    pub(crate) fn session_owner(&self) -> SessionOwner {
        self.recipient.owner
    }

    /// Who this actor is to a channel's ban, quiet and exception masks.
    pub(crate) fn mask_subject(&self) -> MaskSubject<'_> {
        MaskSubject::new(
            &self.identity.prefix,
            self.profile.real_ip,
            self.account.as_deref(),
        )
    }

    pub(crate) fn originator(&self) -> Originator {
        self.profile.originator()
    }

    /// A line this actor originated, stamped at `ts`.
    pub(crate) fn line(
        &self,
        ts: e6irc_proto::time::Millis,
        body: impl Into<Arc<str>>,
    ) -> EventLine {
        EventLine::by(self.originator(), ts, body)
    }
}

/// A channel owner's complete answer to a JOIN request.
///
/// This crosses back to the session owner instead of giving the channel owner
/// access to another shard's session table.
#[derive(Debug, Clone)]
pub enum ChannelJoinResult {
    Joined(Box<ChannelJoinSuccess>),
    /// The session was a member already: nothing changed, nothing is sent
    /// (Solanum / Modern). Distinct from `Joined` so the no-op cannot be
    /// answered with a JOIN echo and a NAMES replay.
    AlreadyMember,
    Rejected(ChannelJoinFailure),
}

#[derive(Debug, Clone)]
pub struct ChannelJoinSuccess {
    pub(crate) key: ChanKey,
    pub(crate) display: String,
    pub(crate) topic: Option<Topic>,
    pub(crate) secret: bool,
    pub(crate) members: Vec<(MemberModes, MemberIdentity)>,
    pub(crate) own_join: EventLine,
    /// The MODE lines the joining brought about, in order — the joiner's
    /// automatic op or voice, a mode lock enforced on the channel it created
    /// — which the broadcast left the joiner out of: they follow its JOIN.
    pub(crate) own_modes: Vec<EventLine>,
}

#[derive(Debug, Clone)]
pub enum ChannelJoinFailure {
    NoSuchChannel { name: String },
    InviteOnly { name: String },
    Banned { name: String },
    BadKey { name: String },
    Full { name: String },
}

#[derive(Debug)]
pub enum ChannelPartResult {
    Parted { key: ChanKey, line: EventLine },
    NotOnChannel { name: String },
    NoSuchChannel { name: String },
    Hidden { name: String, proof: Hidden },
}

/// Everyone who shares a channel with one user, each counted once: the
/// audience of a change to the user rather than to any one channel. A peer
/// told of a host change by quit-and-rejoin (it lacks `chghost`) also
/// collects the rejoin lines of each shared channel this reporter owns.
struct Peers {
    subject: ConnId,
    recipients: HashMap<ConnId, (Recipient, Vec<EventLine>)>,
}

impl Peers {
    fn of(subject: ConnId) -> Self {
        Self {
            subject,
            recipients: HashMap::new(),
        }
    }

    /// Add those of `members` the event is for.
    fn extend(&mut self, members: &[Recipient], audience: UserEventAudience) {
        for recipient in members {
            if recipient.conn() != self.subject && audience.admits(&recipient.caps()) {
                self.recipients
                    .entry(recipient.conn())
                    .or_insert((*recipient, Vec::new()));
            }
        }
    }

    /// Add `channel`'s members the event is for; with a host-change
    /// fallback, those it is not for (no `chghost`) are added too, owed this
    /// channel's rejoin.
    fn extend_channel(&mut self, channel: &Channel, event: &UserEvent, server_name: &str) {
        let members = channel.recipients();
        self.extend(&members, event.audience);
        let Some(fallback) = &event.host_change else {
            return;
        };
        let modes = channel.member(self.subject).cloned().unwrap_or_default();
        for recipient in members.iter() {
            if recipient.conn() == self.subject || event.audience.admits(&recipient.caps()) {
                continue;
            }
            let rejoin = fallback.rejoin(&channel.name, &modes, recipient.caps(), server_name);
            self.recipients
                .entry(recipient.conn())
                .or_insert((*recipient, Vec::new()))
                .1
                .extend(rejoin);
        }
    }
}

/// How a peer without `chghost` learns that a user's host changed: the user
/// appears to quit and rejoin each shared channel under the new hostmask (with
/// its away state and channel status restored), the fallback the chghost spec
/// prescribes. Without it such a peer keeps matching the old hostmask forever.
#[derive(Debug, Clone)]
pub(crate) struct HostChangeFallback {
    pub(crate) quit: EventLine,
    /// The user's new `nick!user@host`.
    pub(crate) prefix: String,
    pub(crate) nick: String,
    pub(crate) account: Option<String>,
    pub(crate) realname: String,
    pub(crate) away: Option<String>,
}

impl HostChangeFallback {
    /// The lines re-introducing the user to `channel` for a peer with `caps`.
    fn rejoin(
        &self,
        channel: &str,
        modes: &MemberModes,
        caps: Caps,
        server_name: &str,
    ) -> Vec<EventLine> {
        let prefix = &self.prefix;
        let join = if caps.extended_join {
            let account = self.account.as_deref().unwrap_or("*");
            crate::core::handler::fitted_line(
                format!(":{prefix} JOIN {channel} {account} :"),
                &self.realname,
            )
        } else {
            format!(":{prefix} JOIN {channel}")
        };
        let mut lines = vec![self.quit.with_body(join)];
        if caps.away_notify
            && let Some(away) = &self.away
        {
            lines.push(self.quit.with_body(crate::core::handler::fitted_line(
                format!(":{prefix} AWAY :"),
                away,
            )));
        }
        let letters: String = [(modes.op, 'o'), (modes.voice, 'v')]
            .iter()
            .filter_map(|(set, letter)| set.then_some(*letter))
            .collect();
        if !letters.is_empty() {
            let nicks = vec![self.nick.as_str(); letters.len()].join(" ");
            lines.push(EventLine::by_server(
                self.quit.ts(),
                format!(":{server_name} MODE {channel} +{letters} {nicks}"),
            ));
        }
        lines
    }
}

/// What one user may do to another user's session. The session may live on
/// any shard; [`ServerState::act_on_session`] gets it there.
#[derive(Debug)]
pub enum SessionAction {
    /// Oper KILL: `killer` is the name the reason and the audit attribute it
    /// to, `killer_prefix` the source of the `KILL` line the victim is sent.
    Kill {
        comment: String,
        killer: String,
        killer_prefix: String,
    },
    /// NickServ GHOST, by the owner of the nick's account.
    Ghost { by: String },
    /// NickServ REGAIN of `nick`, which this session holds, by the session
    /// `by` (whose prefix is `by_mask`): this one is renamed to a Guest nick
    /// and `by` is then given `nick` ([`SessionAction::TakeNick`]).
    Regain {
        nick: String,
        by: SessionOwner,
        by_mask: String,
    },
    /// The second half of a REGAIN: take `nick`, which its holder has let go.
    TakeNick { nick: String },
    /// Oper SETHOST; `oper` is told the outcome.
    SetHost {
        host: String,
        oper: SessionOwner,
        oper_nick: String,
    },
}

/// Which of a user's peers an event about them is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserEventAudience {
    /// QUIT and NICK: everyone who can see the user.
    Everyone,
    AwayNotify,
    AccountNotify,
    Setname,
    Chghost,
}

impl UserEventAudience {
    fn admits(self, caps: &Caps) -> bool {
        match self {
            Self::Everyone => true,
            Self::AwayNotify => caps.away_notify,
            Self::AccountNotify => caps.account_notify,
            Self::Setname => caps.setname,
            Self::Chghost => caps.chghost,
        }
    }
}

/// One thing that happened to a user — they quit, changed nick, went away —
/// that everyone who can see them is told exactly once.
///
/// Who can see them is spread over the shards that own their channels, and a
/// peer may share channels owned by several. So each of those shards reports
/// the peers it knows of — one [`UserEventPart`] per shard the peers live on —
/// and the shard a peer's session lives on, which alone sees every part that
/// names it, delivers the line the first time and ignores the rest. Electing
/// one channel to speak for a pair would be cheaper and could *miss* a peer who
/// leaves that channel at the wrong moment; a missed QUIT is a ghost in a
/// client's nick list, which is worse than any duplicate.
#[derive(Debug, Clone)]
pub struct UserEvent {
    id: (CoreShardId, u64),
    subject: ConnId,
    line: EventLine,
    audience: UserEventAudience,
    /// For a host change: what a peer outside `audience` is told instead.
    host_change: Option<Arc<HostChangeFallback>>,
    /// How many parts each shard will receive. With one, nothing can repeat.
    parts: usize,
}

/// One reporter's share of a [`UserEvent`]'s audience, for one session shard.
#[derive(Debug)]
pub struct UserEventPart {
    shard: CoreShardId,
    event: UserEvent,
    /// Each recipient, with the rejoin lines it is owed besides the event.
    recipients: Vec<(Recipient, Vec<EventLine>)>,
}

impl UserEventPart {
    pub(crate) fn shard(&self) -> CoreShardId {
        self.shard
    }
}

/// A user event for the owner of some of the user's channels to report on.
#[derive(Debug)]
pub struct ChannelUserEvent {
    channels: ShardChannels,
    event: UserEvent,
}

impl ChannelUserEvent {
    pub(crate) fn shard(&self) -> CoreShardId {
        self.channels.shard()
    }
}

/// A session's channels that one shard owns. A change to the user — a QUIT,
/// a new nick — is one event per owning shard rather than one per channel, so
/// the shard can tell each peer once however many of those channels they share.
#[derive(Debug, Clone)]
pub struct ShardChannels(Vec<ChannelOwner>);

impl ShardChannels {
    pub(crate) fn shard(&self) -> CoreShardId {
        self.0[0].shard()
    }

    fn keys(&self) -> impl Iterator<Item = &ChanKey> {
        self.0.iter().map(ChannelOwner::key)
    }
}

/// A complete QUIT request for one owning shard.
#[derive(Debug)]
pub struct ChannelQuit {
    channels: ShardChannels,
    event: UserEvent,
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
    /// `user_throttled`: the knocker's own knock delay has not run out, as its
    /// session knows; the owner reports it only after the checks Solanum makes
    /// first.
    Knock {
        user_throttled: bool,
    },
    Invite(ChannelInvitee),
    ChanServRegister,
    ChanServStatus {
        target_nick: String,
        change: StatusChange,
    },
    Names,
    Who(ChannelWhoQuery),
    History(ChannelHistoryRequest),
    ModeQuery,
    ModeListQuery(String),
    ModeChange(ChannelModeChange),
}

#[derive(Debug, Clone)]
pub struct ChannelWhoQuery {
    pub(crate) argument: String,
}

#[derive(Debug, Clone)]
pub struct ChannelHistoryRequest {
    pub(crate) parameters: Vec<String>,
}

/// One whole-network LIST request. Each channel shard answers once.
#[derive(Debug, Clone)]
pub struct ChannelListRequest {
    id: ChannelListRequestId,
    session: SessionOwner,
    actor: ChannelActor,
    filter: crate::core::list::ListFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelListRequestId(u64);

impl ChannelListRequest {
    fn new(
        id: ChannelListRequestId,
        session: SessionOwner,
        actor: ChannelActor,
        filter: crate::core::list::ListFilter,
    ) -> Self {
        Self {
            id,
            session,
            actor,
            filter,
        }
    }

    pub(crate) fn id(&self) -> ChannelListRequestId {
        self.id
    }

    pub(crate) fn session(&self) -> SessionOwner {
        self.session
    }

    pub(crate) fn actor(&self) -> &ChannelActor {
        &self.actor
    }

    pub(crate) fn filter(&self) -> &crate::core::list::ListFilter {
        &self.filter
    }
}

/// One visible channel row returned by a channel shard.
#[derive(Debug, Clone)]
pub struct ChannelListRow {
    pub(crate) name: String,
    pub(crate) members: usize,
    pub(crate) topic: String,
}

/// A channel shard's complete contribution to a whole-network LIST request.
#[derive(Debug)]
pub struct ChannelListResult {
    pub(crate) id: ChannelListRequestId,
    pub(crate) session: SessionOwner,
    pub(crate) rows: Vec<ChannelListRow>,
}

/// A parsed channel MODE mutation, with its mode token separate from arguments.
#[derive(Debug, Clone)]
pub struct ChannelModeChange {
    pub(crate) modes: String,
    pub(crate) arguments: Vec<String>,
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
    ChanServRegister(ChanServRegisterResult),
    ChanServStatus(ChanServStatusResult),
    Names(ChannelCommandReplies),
    Who(crate::core::paced::WhoReply<Bytes>),
    History(ChannelHistoryResult),
    ModeQuery(ChannelModeQueryResult),
    ModeListQuery(ChannelModeListQueryResult),
    ModeChange(ChannelCommandReplies),
}

#[derive(Debug)]
pub enum ChanServRegisterResult {
    NotChannelOperator { channel: String },
    RegistrationPending { channel: String },
    RegistrationLimit,
    Registered { channel: String },
    Exists,
    Unavailable,
}

/// Direct replies produced by the channel owner for the session owner.
#[derive(Debug)]
pub struct ChannelCommandReplies {
    pub(crate) lines: Vec<Bytes>,
}

#[derive(Debug)]
pub enum ChannelHistoryResult {
    Replies(ChannelCommandReplies),
    Deferred,
}

#[derive(Debug)]
pub enum ChannelKnockResult {
    KnockDelivered {
        display: String,
    },
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
        proof: Hidden,
    },
    AlreadyOnChannel {
        display: String,
    },
    ChannelOpen {
        display: String,
    },
    CannotSend {
        display: String,
    },
    /// Inside the knock delay; `scope` is `user` or `channel`, as Solanum's
    /// ERR_TOOMANYKNOCK names it.
    TooManyKnocks {
        display: String,
        scope: &'static str,
    },
}

#[derive(Debug)]
pub enum ChannelInviteResult {
    Invited { invitee: String, channel: String },
    NoSuchChannel { target: String },
    Hidden { target: String, proof: Hidden },
    NotOnChannel { target: String },
    NotOperator { target: String },
    UserOnChannel { invitee: String, channel: String },
}

/// The member status a ChanServ OP, DEOP, VOICE or DEVOICE changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusChange {
    Op,
    Deop,
    Voice,
    Devoice,
}

impl StatusChange {
    /// The ChanServ command that asks for it.
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::Op => "OP",
            Self::Deop => "DEOP",
            Self::Voice => "VOICE",
            Self::Devoice => "DEVOICE",
        }
    }

    /// Whether it changes operator status (rather than voice).
    pub(crate) fn is_op(self) -> bool {
        matches!(self, Self::Op | Self::Deop)
    }

    /// Whether the member holds the status afterwards.
    pub(crate) fn grants(self) -> bool {
        matches!(self, Self::Op | Self::Voice)
    }

    /// The audit event recording it.
    pub(crate) fn audit_action(self) -> &'static str {
        match self {
            Self::Op => "CHANNEL_OP",
            Self::Deop => "CHANNEL_DEOP",
            Self::Voice => "CHANNEL_VOICE",
            Self::Devoice => "CHANNEL_DEVOICE",
        }
    }

    /// The channel mode change it announces.
    pub(crate) fn mode(self) -> &'static str {
        match self {
            Self::Op => "+o",
            Self::Deop => "-o",
            Self::Voice => "+v",
            Self::Devoice => "-v",
        }
    }
}

#[derive(Debug)]
pub enum ChanServStatusResult {
    NotRegistered {
        channel: String,
    },
    NoAccess {
        channel: String,
        change: StatusChange,
    },
    TargetOffline {
        target: String,
    },
    TargetNotOnChannel {
        target: String,
        channel: String,
    },
    /// The member already had (or already lacked) the status.
    Unchanged {
        target: String,
        change: StatusChange,
    },
    Changed {
        target: String,
        channel: String,
        change: StatusChange,
        /// The requester's own copy of the MODE, when it is a member: the
        /// broadcast left it out, as it is part of the command's response.
        echo: Option<EventLine>,
    },
    /// The change could not be recorded in the audit trail, so it was not
    /// made.
    AuditUnavailable,
}

#[derive(Debug)]
pub enum ChannelModeQueryResult {
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
        proof: Hidden,
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
        proof: Hidden,
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
    pub(crate) entries: Vec<ListEntry>,
}

#[derive(Debug, Clone)]
pub enum ChannelSessionEvent {
    Invitation {
        inviter_prefix: String,
        inviter: Originator,
        /// When the INVITE was accepted: the invitee's copy bears this time.
        ts: e6irc_proto::time::Millis,
        channel: String,
    },
}

/// A current session snapshot applied by the owner of one of its channels.
#[derive(Debug, Clone)]
pub struct ChannelMemberUpdate {
    channels: ShardChannels,
    recipient: Recipient,
    identity: MemberIdentity,
    profile: ChannelMemberProfile,
    /// The NICK line to relay, when the update is a change of nick.
    event: Option<UserEvent>,
}

#[derive(Debug, Clone)]
pub enum ChannelMemberChange {
    Identity,
    /// The session changed nick; `line` is its NICK, relayed to every peer.
    Nick {
        line: EventLine,
    },
}

impl ChannelMemberUpdate {
    fn new(
        channels: ShardChannels,
        recipient: Recipient,
        identity: MemberIdentity,
        profile: ChannelMemberProfile,
        event: Option<UserEvent>,
    ) -> Self {
        Self {
            channels,
            recipient,
            identity,
            profile,
            event,
        }
    }

    pub(crate) fn shard(&self) -> CoreShardId {
        self.channels.shard()
    }
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
        proof: Hidden,
    },
    Topic {
        display: String,
        topic: Option<Topic>,
    },
    Set {
        line: EventLine,
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
    /// The kicker's own copy of the KICK, which the broadcast left out: it
    /// is the command's response, emitted by the kicker's session.
    Kicked {
        echo: EventLine,
    },
    NoSuchChannel {
        target: String,
    },
    Hidden {
        target: String,
        proof: Hidden,
    },
    NotOnChannel {
        target: String,
    },
    NotOperator {
        target: String,
    },
    UserNotInChannel {
        victim: String,
        channel: String,
    },
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
        why: SpeakRefusal,
        loud: bool,
    },
}

/// Why a channel refused a message (PRIVMSG/NOTICE, multiline, TAGMSG).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeakRefusal {
    /// Banned, quieted, `+m` without voice, or `+n` from outside.
    CannotSend,
    /// A CTCP other than ACTION into a `+C` channel.
    NoCtcp,
    /// A STATUSMSG (`@#c`/`+#c`) from a sender without op or voice there.
    NotPrivileged,
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
        why: SpeakRefusal,
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
    CannotSend { target: String, why: SpeakRefusal },
}

impl ChannelQuit {
    fn new(channels: ShardChannels, event: UserEvent) -> Self {
        Self { channels, event }
    }

    pub(crate) fn shard(&self) -> CoreShardId {
        self.channels.shard()
    }
}

struct ChannelMember {
    modes: MemberModes,
    recipient: Recipient,
    identity: MemberIdentity,
    profile: ChannelMemberProfile,
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
    /// +g: free invite — any member may INVITE, not only an operator.
    pub free_invite: bool,
    pub key: Option<String>,
    pub limit: Option<u32>,
}

impl ChanModes {
    /// The flag (ISUPPORT `CHANMODES` type D) modes, in the order a mode string
    /// renders them. The one table: `CHANMODES`, RPL_MYINFO, the MODE apply
    /// loop and MLOCK all read it, and [`Self::flag`] / [`Self::flag_mut`] know
    /// exactly these (a unit test pins that).
    pub(crate) const FLAGS: &'static str = "gimnstC";

    /// A flag mode's current value by its mode char; `None` for a char that is
    /// not a flag.
    pub(crate) fn flag(&self, c: char) -> Option<bool> {
        Some(match c {
            'g' => self.free_invite,
            'i' => self.invite_only,
            'm' => self.moderated,
            'n' => self.no_external,
            's' => self.secret,
            't' => self.topic_ops_only,
            'C' => self.no_ctcp,
            _ => return None,
        })
    }

    /// The flag mode `c` itself, to set; `None` for a char that is not a flag.
    pub(crate) fn flag_mut(&mut self, c: char) -> Option<&mut bool> {
        Some(match c {
            'g' => &mut self.free_invite,
            'i' => &mut self.invite_only,
            'm' => &mut self.moderated,
            'n' => &mut self.no_external,
            's' => &mut self.secret,
            't' => &mut self.topic_ops_only,
            'C' => &mut self.no_ctcp,
            _ => return None,
        })
    }

    /// `+nt`-style string with key/limit args appended. `member` gates both
    /// arguments, as Solanum's `channel_modes` does: a member sees
    /// `+kl key 10`, an outsider `+kl` — told that a key and a limit are set,
    /// but shown neither the key (which would bypass `+k`) nor the limit.
    pub fn to_string_with_args(&self, member: bool) -> String {
        let mut modes = String::from("+");
        let mut args = String::new();
        for c in Self::FLAGS.chars() {
            if self.flag(c) == Some(true) {
                modes.push(c);
            }
        }
        if let Some(k) = &self.key {
            modes.push('k');
            if member {
                args.push(' ');
                args.push_str(k);
            }
        }
        if let Some(l) = self.limit {
            modes.push('l');
            if member {
                args.push_str(&format!(" {l}"));
            }
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
    /// Boolean channel modes that MLOCK can lock: every flag mode
    /// ([`ChanModes::FLAGS`]); args-carrying modes like `k`/`l` and list modes
    /// are deliberately out of scope.
    pub const LOCKABLE: &'static str = ChanModes::FLAGS;

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
                c if Self::LOCKABLE.contains(c) => {
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
            .chars()
            .filter(|mode| m.on.contains(*mode))
            .collect();
        m.off = Self::LOCKABLE
            .chars()
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

/// One entry of history in the hot ring: the same record a database row
/// decodes to, so the ring and the database cannot keep different facts about
/// a message.
pub type HistoryEntry = crate::core::HistoryRow;

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

    /// The two identities of a conversation key (`lo`, `hi`; equal for a
    /// conversation with oneself), or `None` for a channel's. The one place a
    /// key is taken apart: a channel name may itself contain `!`, but it starts
    /// with `#`, which no identity does.
    pub(crate) fn participants(&self) -> Option<(&str, &str)> {
        if self.0.starts_with('#') {
            return None;
        }
        self.0.split_once('!')
    }

    /// The channel this key is the history of, if it is a channel's.
    fn channel(&self) -> Option<ChanKey> {
        self.0.starts_with('#').then(|| ChanKey(self.0.clone()))
    }

    #[cfg(test)]
    pub(crate) fn channel_for_test(name: &str) -> Self {
        HistoryKey(name.to_string())
    }

    #[cfg(test)]
    pub(crate) fn conversation_for_test(a: &str, b: &str) -> Self {
        HistoryKey(dm_conversation_key(a, b).0)
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
    /// `user@host` glob (KLINE); an address or CIDR host matches the real
    /// address, and a glob host is tried against both the shown host and it.
    Kline,
    /// An address, a CIDR range, or an address glob (DLINE), matched against
    /// the connection's real address only.
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
    /// `public|private`: what follows the first `|` is the operators' note,
    /// never shown to the banned user or their peers (Solanum's oper reason).
    pub reason: String,
    pub set_by: String,
    pub kind: BanKind,
    /// When a temporary ban lapses, in Unix seconds on the wall clock;
    /// `None` for a permanent ban.
    pub expires_at_secs: Option<u64>,
}

/// The part of a server-ban `reason` the banned user and their peers are
/// shown: everything before the first `|` (Solanum's user/oper reason split).
/// The whole reason stays in the operator listing and the audit trail.
pub(crate) fn public_ban_reason(reason: &str) -> &str {
    reason
        .split_once('|')
        .map_or(reason, |(public, _)| public)
        .trim_end()
}

/// What a server ban is tested against: one connection, as a K-line, D-line
/// or X-line sees it.
pub(crate) struct ServerBanSubject<'a> {
    pub(crate) user: &'a str,
    pub(crate) host: &'a str,
    pub(crate) real_ip: Option<std::net::IpAddr>,
    pub(crate) realname: &'a str,
}

impl ServerBan {
    /// Whether this ban is enforced at `now_secs` (Unix seconds): a permanent
    /// ban always, a temporary one until the second it lapses.
    pub(crate) fn in_force(&self, now_secs: u64) -> bool {
        self.expires_at_secs.is_none_or(|at| now_secs < at)
    }

    /// Whole minutes left of a temporary ban at `now_secs`, rounded up so a
    /// ban in force never reads as 0; `None` for a permanent ban.
    pub(crate) fn minutes_left(&self, now_secs: u64) -> Option<u64> {
        self.expires_at_secs
            .map(|at| at.saturating_sub(now_secs).div_ceil(60))
    }

    /// Whether this ban matches `subject`. A K-line is a `user@host` mask whose
    /// host may be an address or CIDR range (matched against the real
    /// address) or a glob (tried against the shown host and the address); a
    /// D-line is matched against the real address alone, so a cloak is no way
    /// out of either; an X-line is a glob over the realname.
    pub(crate) fn matches(&self, casemap: CaseMapping, subject: &ServerBanSubject<'_>) -> bool {
        match self.kind {
            BanKind::Kline => {
                let shown = format!("{}@{}", subject.user, subject.host);
                self.mask
                    .matches(casemap, &MaskSubject::new(&shown, subject.real_ip, None))
            }
            BanKind::Dline => subject.real_ip.is_some_and(|address| {
                let address_text = address.to_string();
                self.mask.matches(
                    casemap,
                    &MaskSubject::new(&address_text, Some(address), None),
                )
            }),
            BanKind::Xline => {
                e6irc_proto::mask::matches(casemap, self.mask.as_str(), subject.realname)
            }
        }
    }
}

/// One entry of a channel's `+b`/`+q`/`+e`/`+I` list: the mask, and who set
/// it when, as RPL_BANLIST and its siblings report them (Solanum's
/// `367 <me> <channel> <mask> <setter> <set-at>`).
#[derive(Clone, Debug)]
pub(crate) struct ListEntry {
    pub mask: MaskKey,
    /// The setter's `nick!user@host`.
    pub set_by: String,
    /// Unix seconds, as the list replies report it.
    pub set_at_secs: u64,
}

pub(crate) struct Channel {
    /// Display name (creator's casing).
    pub name: String,
    pub topic: Option<Topic>,
    members: HashMap<ConnId, ChannelMember>,
    recipients: RefCell<Option<Arc<[Recipient]>>>,
    pub modes: ChanModes,
    pub bans: Vec<ListEntry>,
    pub quiets: Vec<ListEntry>,
    pub ban_exceptions: Vec<ListEntry>,
    pub invite_exceptions: Vec<ListEntry>,
    /// Connections holding a pending INVITE into this channel (consumed on
    /// join), which admits past `+i` and `+l`. Recorded only while the channel
    /// has one of those, from an operator or, on a `+g` channel, any member.
    /// Lives on the channel — not the invitee's session — so channel
    /// teardown revokes it: an invite is a grant by an op of *this* channel
    /// incarnation, and a session-side set keyed by name would let it
    /// authorize entry into an unrelated later channel reusing the name
    /// (a +i bypass). Bounded by `INVITE_LIMIT` per channel.
    pub invited: HashSet<ConnId>,
    /// When the last KNOCK on this channel was delivered, on the monotonic
    /// clock: a channel takes one per `KNOCK_DELAY_CHANNEL` (Solanum's
    /// `knock_delay_channel`), so a crowd cannot flood its operators.
    pub last_knock: Option<e6irc_proto::time::MonoMillis>,
    /// When this incarnation of the channel was created, on the same
    /// millisecond clock that stamps its messages: RPL_CREATIONTIME reports it
    /// in whole seconds, and it is the oldest history a reader without a
    /// registered relationship to the channel may see ([`HistoryFloor`]).
    ///
    /// [`HistoryFloor`]: crate::core::HistoryFloor
    pub created_at: e6irc_proto::time::Millis,
}

/// Proof that a `+s` (secret) channel must look non-existent to a connection.
/// Constructible only by [`Channel::hidden_from`] and consumed only by the
/// handler's `deny_hidden`, which answers `ERR_NOSUCHCHANNEL`. So every surface
/// that denies access to a hidden channel reports the *same* "no such channel"
/// — none can hand-pick a numeric (like 442 `ERR_NOTONCHANNEL`) that would
/// instead confirm the channel exists, which is exactly how a `TOPIC`-query
/// existence oracle slipped in. A channel owner's `Hidden` answer carries the
/// proof to the requester's shard, so the rule holds across that hop too.
#[derive(Debug)]
pub struct Hidden(());

impl Channel {
    pub fn new(
        name: String,
        topic: Option<Topic>,
        modes: ChanModes,
        created_at: e6irc_proto::time::Millis,
    ) -> Self {
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
            last_knock: None,
            created_at,
        }
    }

    /// A channel named `name` with `modes`, created at the epoch.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, modes: ChanModes) -> Self {
        Self::new(
            name.to_string(),
            None,
            modes,
            e6irc_proto::time::Millis::from_millis(0),
        )
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

    #[cfg(test)]
    pub fn add_member(
        &mut self,
        recipient: Recipient,
        identity: MemberIdentity,
        modes: MemberModes,
        last_active: e6irc_proto::time::MonoMillis,
    ) {
        self.add_member_with_profile(
            recipient,
            ChannelMemberProfile::derived(&identity, last_active),
            identity,
            modes,
        );
    }

    pub fn add_member_with_profile(
        &mut self,
        recipient: Recipient,
        profile: ChannelMemberProfile,
        identity: MemberIdentity,
        modes: MemberModes,
    ) {
        self.members.insert(
            recipient.conn(),
            ChannelMember {
                modes,
                recipient,
                identity,
                profile,
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

    pub fn update_member(
        &mut self,
        recipient: Recipient,
        identity: MemberIdentity,
        profile: ChannelMemberProfile,
    ) -> bool {
        let Some(member) = self.members.get_mut(&recipient.conn()) else {
            return false;
        };
        if member.recipient.owner() != recipient.owner() {
            return false;
        }
        if member.recipient != recipient {
            member.recipient = recipient;
            self.recipients.get_mut().take();
        }
        member.identity = identity;
        member.profile = profile;
        true
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

    pub fn member_profiles(
        &self,
    ) -> impl Iterator<Item = (ConnId, &MemberModes, &MemberIdentity, &ChannelMemberProfile)> {
        self.members
            .iter()
            .map(|(conn, member)| (*conn, &member.modes, &member.identity, &member.profile))
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
    /// (`MODE`/`KNOCK`/`TOPIC`/`KICK`/`INVITE`) take the returned [`Hidden`] to
    /// `deny_hidden`;
    /// content-listing surfaces (`NAMES`/`WHO`/`WHOIS`/`LIST`) test `.is_some()`
    /// and simply omit the channel's rows.
    pub(crate) fn hidden_from(&self, conn: ConnId) -> Option<Hidden> {
        (self.modes.secret && !self.is_member(conn)).then_some(Hidden(()))
    }

    fn any_match<'a>(
        casemap: CaseMapping,
        masks: impl IntoIterator<Item = &'a MaskKey>,
        subject: &MaskSubject<'_>,
    ) -> bool {
        masks.into_iter().any(|m| m.matches(casemap, subject))
    }

    /// The masks of one of this channel's lists.
    fn masks(list: &[ListEntry]) -> impl Iterator<Item = &MaskKey> {
        list.iter().map(|entry| &entry.mask)
    }

    pub(crate) fn is_banned(&self, casemap: CaseMapping, subject: &MaskSubject<'_>) -> bool {
        Self::any_match(casemap, Self::masks(&self.bans), subject)
            && !Self::any_match(casemap, Self::masks(&self.ban_exceptions), subject)
    }

    /// Quiets share the ban-exception machinery (Solanum semantics).
    pub(crate) fn is_quieted(&self, casemap: CaseMapping, subject: &MaskSubject<'_>) -> bool {
        Self::any_match(casemap, Self::masks(&self.quiets), subject)
            && !Self::any_match(casemap, Self::masks(&self.ban_exceptions), subject)
    }

    pub(crate) fn is_invite_excepted(
        &self,
        casemap: CaseMapping,
        subject: &MaskSubject<'_>,
    ) -> bool {
        Self::any_match(casemap, Self::masks(&self.invite_exceptions), subject)
    }

    /// Whether a sender with membership `member` (its `MemberModes`, or `None`
    /// when off-channel) matched against the masks as `subject` may send to
    /// this channel.
    ///
    /// The single gate for text (PRIVMSG/NOTICE) and tags (TAGMSG) alike: a
    /// client that cannot speak must not be able to relay typing/reaction tags
    /// it could not relay as a message, and the two paths drifting apart is
    /// exactly how that would happen. Op/voice bypass +m and bans; an ordinary
    /// or off-channel sender is subject to +m, bans and quiets, and an
    /// off-channel one additionally to +n. STATUSMSG/CTCP are checked by the
    /// caller — they are message-shape concerns, not membership ones.
    pub(crate) fn may_speak(
        &self,
        member: Option<&MemberModes>,
        casemap: CaseMapping,
        subject: &MaskSubject<'_>,
    ) -> bool {
        match member {
            Some(m) if m.op || m.voice => true,
            Some(_) => !self.modes.moderated && !self.is_silenced(casemap, subject),
            None => {
                !self.modes.no_external
                    && !self.modes.moderated
                    && !self.is_silenced(casemap, subject)
            }
        }
    }

    /// Banned or quieted (and not excepted): the ban/quiet half of
    /// [`Channel::may_speak`], without `+m`/`+n`.
    pub(crate) fn is_silenced(&self, casemap: CaseMapping, subject: &MaskSubject<'_>) -> bool {
        self.is_banned(casemap, subject) || self.is_quieted(casemap, subject)
    }
}

/// The local worker's channel state and its ownership boundary.
/// A channel key paired with the only core shard allowed to mutate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOwner {
    key: ChanKey,
    shard: CoreShardId,
}

pub(crate) enum PendingChannelControlKind {
    Mutation {
        channel: ChanKey,
        mutation: super::PersistedChannelMutation,
    },
    Registration {
        channel: ChanKey,
        founder_account: String,
        topic: Option<(String, String, u64)>,
    },
}

pub(crate) struct PendingChannelControl {
    pub(crate) reply: tokio::sync::oneshot::Sender<super::AdminReply>,
    pub(crate) kind: PendingChannelControlKind,
}

pub(crate) struct PendingConnectionList {
    pub(crate) query: super::LiveConnectionQuery,
    pub(crate) remaining: usize,
    pub(crate) entries: Vec<super::LiveConnectionInfo>,
    pub(crate) reply: tokio::sync::oneshot::Sender<super::AdminReply>,
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
    /// Channels handed out mutably, or removed, since the last
    /// [`ChannelDirectory::take_touched`]: the only ones whose published
    /// description can have changed.
    touched: Vec<ChanKey>,
    /// Channels whose history ring changed since the last
    /// [`ChannelDirectory::take_activity_touched`]: only their newest-message
    /// time can have changed, which is republished alone — a message must not
    /// cost rebuilding the channel's whole published record.
    activity_touched: Vec<ChanKey>,
}

impl ChannelDirectory {
    pub(crate) fn new(shards: CoreShardCount) -> Self {
        Self {
            shards,
            channels: HashMap::new(),
            touched: Vec::new(),
            activity_touched: Vec::new(),
        }
    }

    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
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
        self.touched.push(key.clone());
        self.channels.get_mut(key)
    }

    /// `key`'s history ring, which is kept beside the channel, changed: its
    /// newest-message time may have too.
    fn touch_activity(&mut self, key: ChanKey) {
        self.activity_touched.push(key);
    }

    fn take_touched(&mut self) -> Vec<ChanKey> {
        sorted_unique(std::mem::take(&mut self.touched))
    }

    fn take_activity_touched(&mut self) -> Vec<ChanKey> {
        sorted_unique(std::mem::take(&mut self.activity_touched))
    }

    pub(crate) fn contains_key(&self, key: &ChanKey) -> bool {
        self.channels.contains_key(key)
    }

    pub(crate) fn entry(
        &mut self,
        key: ChanKey,
    ) -> std::collections::hash_map::Entry<'_, ChanKey, Channel> {
        self.touched.push(key.clone());
        self.channels.entry(key)
    }

    pub(crate) fn remove(&mut self, key: &ChanKey) -> Option<Channel> {
        self.touched.push(key.clone());
        self.channels.remove(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.channels.len()
    }

    pub(crate) fn iter(&self) -> std::collections::hash_map::Iter<'_, ChanKey, Channel> {
        self.channels.iter()
    }
}

fn sorted_unique(mut keys: Vec<ChanKey>) -> Vec<ChanKey> {
    keys.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    keys.dedup();
    keys
}

impl Index<&ChanKey> for ChannelDirectory {
    type Output = Channel;

    fn index(&self, key: &ChanKey) -> &Self::Output {
        &self.channels[key]
    }
}

pub(crate) struct ServerState {
    shard: CoreShardId,
    shards: CoreShardCount,
    pub telemetry: Arc<Telemetry>,
    pub config: CoreConfig,
    pub casemap: CaseMapping,
    pub sessions: SessionStore,
    users: UserDirectory,
    nicks: NickDirectory,
    memberships: MembershipDirectory,
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
    /// Accounts permanently deleted while this process runs. A write already
    /// in flight when one was deleted (MARKREAD, NickServ GROUP or SET
    /// ENFORCE) can answer after its mirror was emptied; the confirmation adds
    /// nothing back for an account that no longer exists (see
    /// [`Self::account_deleted`]). One entry per deletion: the names are
    /// retired.
    deleted_accounts: HashSet<AccountKey>,
    /// Requests to the DB worker (answered via `Input::DbReply`).
    pub db_tx: Sender<super::DbRequest>,
    /// High-water mark of simultaneously registered users (LUSERS max).
    /// Wall-clock millisecond the server state was created (STATS u uptime,
    /// which reports the difference in whole seconds).
    pub started_at: e6irc_proto::time::Millis,
    /// Where this shard's message ids come from.
    msgids: MsgidSource,
    /// MONITOR: watched nick → watching connections, on every shard.
    pub(crate) monitors: MonitorDirectory,
    user_event_sequence: u64,
    /// Events some of whose reporters this shard has yet to hear from, with
    /// the recipients already told.
    user_events_in_progress: HashMap<(CoreShardId, u64), UserEventProgress>,
    /// Read markers: (account, target) → epoch millis. Mirrors the
    /// PostgreSQL table; this is the hot copy the core serves. Private, with
    /// `pending_read_markers`: every write goes through the slot-counting
    /// methods (`store_read_marker`, `reserve_read_marker`,
    /// `release_read_marker`, `preload_read_markers`) so
    /// `read_marker_slots` can never drift from the maps.
    read_markers: HashMap<(AccountKey, ChanKey), e6irc_proto::time::Millis>,
    /// Number of database writes in flight for each account/target. A target
    /// is reserved here before its first durable write completes, so pipelined
    /// MARKREAD commands cannot evade the per-account distinct-target cap.
    pending_read_markers: HashMap<(AccountKey, ChanKey), usize>,
    /// Distinct targets each account holds a marker for, confirmed or
    /// pending — the operand of the per-account MARKREAD cap. Kept at every
    /// write so a MARKREAD costs a lookup, not a scan of every account's
    /// markers (the `pending_joins` pattern: count at the mutation site).
    read_marker_slots: HashMap<AccountKey, usize>,
    /// Connections logged in to each account, under the server casemapping.
    /// Maintained by the three places a session's account changes
    /// (`set_account`, `clear_account`, `close`), so a sibling sync
    /// (MARKREAD, account-notify) is a lookup rather than a fold of every
    /// session's account.
    account_sessions: HashMap<AccountKey, HashSet<ConnId>>,
    /// Registered channels → founder account (both casefolded). The hot
    /// copy of the `channels` table's ownership, boot-loaded and updated
    /// on registration; a founder rejoining their channel is re-opped.
    pub registered_founders: FounderDirectory,
    /// Channel registrations waiting for a database verdict, keyed by channel
    /// and carrying the founder reservation. A pending name cannot be queued
    /// twice, and pending reservations count toward the per-account cap.
    pub pending_channel_registrations: HashMap<ChanKey, AccountKey>,
    /// Registered channels → retained topic. Boot-loaded and kept in sync
    /// on TOPIC; restored when a registered channel is recreated so its
    /// topic survives the channel going empty.
    pub registered_topics: RetainedTopicDirectory,
    /// Latest requested TOPIC per registered channel while its database
    /// verdict is pending. The revision prevents an older reply from clearing
    /// a newer request. SET KEEPTOPIC reads this overlay instead of a stale
    /// committed live topic when the two commands are pipelined.
    pub pending_channel_topics: HashMap<ChanKey, (u64, Option<Topic>)>,
    /// Monotonic revision source for `pending_channel_topics`.
    pub channel_topic_revision: u64,
    /// Process-wide durable KEEPTOPIC, MLOCK, and access state.
    pub channel_options: ChannelOptionsDirectory,
    /// Process-wide grouped nicks and nick protection (NickServ GROUP, SET
    /// ENFORCE).
    pub(crate) nick_registrations: NickRegistrationDirectory,
    /// Server bans (oper K/D/X-lines) refused at registration. Boot-loaded
    /// and kept in sync on KLINE/DLINE/XLINE and their removals.
    pub server_bans: Vec<ServerBan>,
    /// `(kind, folded mask)` server-ban mutations awaiting a database verdict.
    /// A second mutation of the same durable row is refused explicitly instead
    /// of making authorization/existence decisions against stale hot state.
    pub pending_server_bans: HashSet<(String, String)>,
    /// Recent nick departures/changes for WHOWAS, newest-first.
    pub(crate) whowas: WhowasDirectory,
    census: Census,
    /// What this shard last added to the [`Census`]: connections, channels.
    census_reported: (usize, usize),
    /// Hot history rings, keyed by channel or direct-message conversation,
    /// with their LRU order and conversation index ([`HotHistory`]).
    pub(crate) history: HotHistory,
    /// When set, direct sends to this connection are captured instead
    /// of delivered — the labeled-response machinery frames them.
    pub capture: Option<Capture>,
    /// While set, output to this connection bypasses its deferred-reply hold:
    /// it is the deferred reply itself, which the held output waits behind.
    pub emitting_deferred: Option<ConnId>,
    /// Per-client-IP account-creation token buckets (only used when
    /// `registration_burst` is set): the session's limit key (an IPv6
    /// client's whole `/64`) → (tokens, monotonic
    /// millisecond refill has been credited through). Bounds bulk-account
    /// abuse from one address; hard-capped at `MAX_REGISTRATION_BUCKETS` so
    /// a distinct-IP flood can't grow it without bound.
    pub registration_buckets:
        HashMap<crate::net::SessionLimitKey, (f64, e6irc_proto::time::MonoMillis)>,
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
    pub pending_connection_lists: HashMap<u64, PendingConnectionList>,
    pub admin_connection_list_id: u64,
    /// Founder-owned HTTP channel controls awaiting a matching database verdict.
    pub pending_channel_controls: HashMap<u64, PendingChannelControl>,
    /// Monotonic request ID source for `pending_channel_controls`.
    pub channel_control_id: u64,
    channel_list_id: u64,
    /// The connections with a LIST or WHO reply being paced out: which
    /// sessions the pacing turn visits. The paced output itself lives on the
    /// session ([`Session::channel_list`], [`Session::paced_who`]), so it
    /// cannot outlive the connection it answers.
    pub(crate) pacing: HashSet<ConnId>,
}

/// Hard ceiling on the account-creation bucket map, mirroring the HTTP
/// `spend_auth_budget` limiter: the refill window is long (an hour), so a flood
/// from many distinct IPs keeps every entry below full and nothing prunes —
/// this cap bounds the map by evicting the least-recently-seen entry.
pub(crate) const MAX_REGISTRATION_BUCKETS: usize = 4096;

/// Account creation is rare per genuine client, so the bucket refills to full
/// slowly (one hour). A small burst absorbs a legitimate retry while capping
/// how fast one address can mint accounts.
const REGISTRATION_REFILL_WINDOW_MS: u64 = 60 * 60 * 1000;

/// The one response to a labeled command that is answered in several pieces:
/// a multi-target JOIN, PART, KICK or PRIVMSG whose targets are owned by other
/// shards, each of which answers on its own. labeled-response promises exactly
/// one response per label, so the pieces are gathered here — with whatever the
/// command answered on the spot — and framed together, as a batch if they are
/// several lines, when the last one arrives.
pub(crate) struct LabelGroup {
    pub(crate) outstanding: usize,
    pub(crate) lines: Vec<Bytes>,
}

/// A read-marker database reply arrived for a key with no write in flight.
#[derive(Debug)]
pub(crate) struct ReadMarkerNotReserved;

/// Buffered direct responses to a labeled command.
pub(crate) struct Capture {
    pub conn: ConnId,
    pub lines: Vec<Bytes>,
    /// The nick used in replies when the connection lives on another shard.
    pub reply_target: Option<String>,
    pub reply_caps: Option<Caps>,
    /// The escaped `label` value, so a command whose response is produced
    /// asynchronously (CHATHISTORY falling back to PostgreSQL) can carry the
    /// label into that deferred reply instead of losing it.
    pub label: Option<String>,
    /// How many separate answers the command left to asynchronous paths. Only
    /// [`Capture::defer`] raises it, so "the command is deferred" and "how many
    /// answers it awaits" are one value: no path can mark a capture deferred
    /// without counting the answer it awaits.
    deferrals: usize,
}

impl Capture {
    pub(crate) fn new(
        conn: ConnId,
        label: Option<String>,
        reply_target: Option<String>,
        reply_caps: Option<Caps>,
    ) -> Self {
        Self {
            conn,
            lines: Vec::new(),
            reply_target,
            reply_caps,
            label,
            deferrals: 0,
        }
    }

    /// One answer to this command will arrive asynchronously; returns the
    /// label it must carry. Whoever reads the capture then must not take "no
    /// lines" for the answer: the labeled-response framer must not ACK the
    /// command as empty, and a channel owner must not release the requester.
    fn defer(&mut self) -> Option<String> {
        self.deferrals += 1;
        self.label.clone()
    }

    pub(crate) fn is_deferred(&self) -> bool {
        self.deferrals > 0
    }
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

    pub fn local_member_profile(&self, conn: ConnId) -> ChannelMemberProfile {
        let session = &self.sessions[&conn];
        ChannelMemberProfile {
            user: session.user().expect("registered member").to_string(),
            host: session.host.clone(),
            real_ip: session.real_ip,
            realname: session.realname().expect("registered member").to_string(),
            account: session.account.clone(),
            away: session.away.is_some(),
            oper: session.oper.is_some(),
            bot: session.bot,
            last_active: session.last_active.clone(),
        }
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
            profile: self.local_member_profile(conn),
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
            self.defer_captured_reply(conn)
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
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelJoin {
                owner,
                actor,
                name,
                join_key,
                label,
            }));
    }

    pub fn route_join_result(
        &mut self,
        session: SessionOwner,
        requested: ChanKey,
        result: ChannelJoinResult,
        label: Option<String>,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelJoinResult {
                session,
                requested,
                result,
                label,
            }));
    }

    pub fn route_part(
        &mut self,
        owner: ChannelOwner,
        actor: ChannelActor,
        name: String,
        reason: Option<String>,
        label: Option<String>,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelPart {
                owner,
                actor,
                name,
                reason,
                label,
            }));
    }

    pub fn route_part_result(
        &mut self,
        session: SessionOwner,
        result: ChannelPartResult,
        label: Option<String>,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelPartResult {
                session,
                result,
                label,
            }));
    }

    pub fn route_quit(&mut self, quit: ChannelQuit) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelQuit { quit }));
    }

    pub fn route_topic(&mut self, topic: ChannelTopic) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelTopic {
                topic,
            }));
    }

    pub fn route_topic_result(
        &mut self,
        session: SessionOwner,
        result: ChannelTopicResult,
        label: Option<String>,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelTopicResult {
                session,
                result,
                label,
            }));
    }

    pub fn route_channel_command(&mut self, command: ChannelCommand) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelCommand {
                command,
            }));
    }

    pub(crate) fn route_input(&mut self, input: crate::core::Input) {
        self.effects.push(CoreEffect::Input(input));
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

    /// Ask every channel shard for `conn`'s LIST rows; the connection has no
    /// LIST in progress.
    pub fn start_channel_list(
        &mut self,
        conn: ConnId,
        label: Option<String>,
        filter: crate::core::list::ListFilter,
    ) -> ChannelListRequest {
        let id = ChannelListRequestId(self.channel_list_id);
        self.channel_list_id = self
            .channel_list_id
            .checked_add(1)
            .expect("channel LIST request identifiers exhausted");
        let session = SessionOwner::new(conn, self.shard);
        let request = ChannelListRequest::new(id, session, self.channel_actor(conn), filter);
        let remaining = self.channels.shard_count();
        let session = self
            .sessions
            .output_mut(&conn)
            .expect("a LIST is started by the session sending it");
        let previous = session
            .channel_list
            .replace(crate::core::list::ListProgress::Gathering {
                id,
                label,
                remaining,
                rows: Vec::new(),
                aborted: false,
            });
        assert!(previous.is_none(), "a connection has one LIST in progress");
        request
    }

    pub fn route_channel_list(&mut self, request: ChannelListRequest) {
        self.effects
            .push(CoreEffect::BroadcastChannelList { request });
    }

    pub(crate) fn has_single_core_shard(&self) -> bool {
        self.channels.shard_count() == 1
    }

    pub fn route_channel_list_result(&mut self, result: ChannelListResult) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelListResult {
                result,
            }));
    }

    /// Add one shard's rows to the LIST they answer: the whole LIST once the
    /// last shard's are in. `None` while others are outstanding, or when the
    /// connection closed in the meantime.
    pub fn take_channel_list(
        &mut self,
        result: ChannelListResult,
    ) -> Option<crate::core::list::GatheredList> {
        use crate::core::list::{GatheredList, ListProgress};
        let conn = result.session.conn();
        // A closed connection's LIST went with its session.
        let session = self.sessions.output_mut(&conn)?;
        // Rows reach only a connection still gathering them: it has at most
        // one LIST, which stops gathering once the last shard's rows are in.
        let Some(ListProgress::Gathering {
            id,
            remaining,
            rows,
            ..
        }) = session.channel_list.as_mut()
        else {
            panic!("LIST rows reached a connection that is not gathering them");
        };
        assert_eq!(*id, result.id, "LIST rows reached another LIST");
        *remaining = remaining
            .checked_sub(1)
            .expect("LIST received too many shard results");
        rows.extend(result.rows);
        if *remaining > 0 {
            return None;
        }
        let Some(ListProgress::Gathering {
            label,
            rows,
            aborted,
            ..
        }) = session.channel_list.take()
        else {
            unreachable!("the LIST was gathering a moment ago");
        };
        Some(GatheredList {
            label,
            rows,
            aborted,
        })
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
        self.effects.push(crate::core::CoreEffect::Input(
            crate::core::Input::SessionChannelRemoved { session, key },
        ));
    }

    pub fn route_kick(&mut self, kick: ChannelKick) {
        self.effects.push(crate::core::CoreEffect::Input(
            crate::core::Input::ChannelKick { kick },
        ));
    }

    pub fn route_kick_result(
        &mut self,
        session: SessionOwner,
        result: ChannelKickResult,
        label: Option<String>,
    ) {
        self.effects.push(crate::core::CoreEffect::Input(
            crate::core::Input::ChannelKickResult {
                session,
                result,
                label,
            },
        ));
    }

    pub fn remove_session_channel(&mut self, conn: ConnId, key: &ChanKey) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.channels.remove(key);
        }
        self.memberships.part(conn, key);
    }

    pub fn membership_join(&self, conn: ConnId, key: ChanKey) {
        self.memberships.join(conn, key);
    }

    pub fn membership_part(&self, conn: ConnId, key: &ChanKey) {
        self.memberships.part(conn, key);
    }

    pub fn is_channel_member(&self, conn: ConnId, key: &ChanKey) -> bool {
        self.memberships.contains(conn, key)
            || self
                .channels
                .get(key)
                .is_some_and(|channel| channel.is_member(conn))
    }

    pub fn route_message(&mut self, message: ChannelMessage) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelMessage {
                message,
            }));
    }

    pub fn route_message_result(
        &mut self,
        session: SessionOwner,
        result: ChannelMessageResult,
        label: Option<String>,
    ) {
        self.effects.push(CoreEffect::Input(
            crate::core::Input::ChannelMessageResult {
                session,
                result,
                label,
            },
        ));
    }

    pub fn route_multiline(&mut self, message: ChannelMultiline) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelMultiline {
                message,
            }));
    }

    pub fn route_multiline_result(
        &mut self,
        session: SessionOwner,
        result: ChannelMultilineResult,
    ) {
        self.effects.push(CoreEffect::Input(
            crate::core::Input::ChannelMultilineResult { session, result },
        ));
    }

    pub fn route_tagmsg(&mut self, tagmsg: ChannelTagmsg) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelTagmsg {
                tagmsg,
            }));
    }

    pub fn route_tagmsg_result(
        &mut self,
        session: SessionOwner,
        result: ChannelTagmsgResult,
        label: Option<String>,
    ) {
        self.effects
            .push(CoreEffect::Input(crate::core::Input::ChannelTagmsgResult {
                session,
                result,
                label,
            }));
    }

    pub fn refresh_recipient(&mut self, conn: ConnId) {
        if !self.sessions[&conn].is_registered() {
            let recipient = self.local_recipient(conn);
            let channels: Vec<_> = self.sessions[&conn].channels.iter().cloned().collect();
            for key in channels {
                if let Some(channel) = self.channels.get_mut(&key) {
                    channel.update_recipient(recipient);
                }
            }
            return;
        }
        self.sync_channel_member(conn, ChannelMemberChange::Identity);
    }

    /// Publish `conn`'s public state as it is now: to the user directory, and
    /// to the owner of every channel it is in. `change` says what, beyond the
    /// record itself, the channels must do about it (relay a NICK line).
    pub fn sync_channel_member(&mut self, conn: ConnId, change: ChannelMemberChange) {
        if !self.sessions[&conn].is_registered() {
            return;
        }
        let recipient = self.local_recipient(conn);
        let user = Arc::new(PublicUser::of(&self.sessions[&conn], recipient));
        self.users.publish(user.clone());
        self.sessions
            .output_mut(&conn)
            .expect("indexed above")
            .published = Some(user.clone());
        let owners = self.session_channels_by_shard(conn);
        let event = match change {
            ChannelMemberChange::Identity => None,
            ChannelMemberChange::Nick { line } => {
                Some(self.user_event(conn, line, UserEventAudience::Everyone, owners.len()))
            }
        };
        for channels in owners {
            let update = ChannelMemberUpdate::new(
                channels,
                recipient,
                user.member_identity(),
                user.member_profile(),
                event.clone(),
            );
            if update.shard() == self.shard {
                self.apply_channel_member_update(update);
            } else {
                self.effects
                    .push(CoreEffect::Input(crate::core::Input::ChannelMemberUpdate {
                        update,
                    }));
            }
        }
    }

    /// Publish what this event changed about the channels this shard owns, for
    /// the shards that answer WHOIS about their members. It costs a pass over
    /// the members of each channel the event changed — and every event that
    /// changes a channel (a join, a part, a mode, a topic) already costs one,
    /// to tell those members.
    pub(crate) fn publish_changed_channels(&mut self) {
        let touched = self.channels.take_touched();
        for key in &touched {
            let published = self.channels.get(key).map(|channel| PublicChannel {
                name: channel.name.clone(),
                secret: channel.modes.secret,
                ranks: channel
                    .members()
                    .filter(|(_, modes)| modes.op || modes.voice)
                    .map(|(conn, modes)| (conn, modes.clone()))
                    .collect(),
                latest_message: self.latest_channel_message(key),
                created_at: channel.created_at,
                silencing: SilencingMasks {
                    bans: Channel::masks(&channel.bans).cloned().collect(),
                    quiets: Channel::masks(&channel.quiets).cloned().collect(),
                    exceptions: Channel::masks(&channel.ban_exceptions).cloned().collect(),
                },
            });
            self.memberships.publish_channel(key, published);
        }
        // A channel whose only change is its ring — a message — republishes
        // just its newest-message time. One also touched above was published
        // whole, and one that no longer exists was withdrawn there.
        for key in self.channels.take_activity_touched() {
            if touched
                .binary_search_by(|k| k.as_str().cmp(key.as_str()))
                .is_ok()
                || !self.channels.contains_key(&key)
            {
                continue;
            }
            let latest = self.latest_channel_message(&key);
            let published = self.memberships.publish_latest_message(&key, latest);
            assert!(
                published,
                "a live channel's record is published by the event that created it"
            );
        }
    }

    /// The newest entry time in channel `key`'s ring, in every scope (none
    /// when it has no ring).
    fn latest_channel_message(&self, key: &ChanKey) -> crate::core::hot_history::Latest {
        self.history
            .get(&HistoryKey::from(key))
            .map(crate::core::hot_history::HistoryRing::latest)
            .unwrap_or_default()
    }

    /// Bring the rest of the server up to date with every session this event
    /// changed. Run once after each event, over the sessions it touched, so a
    /// handler cannot change what others see — an account, operator status, a
    /// host, a real name — and forget to say so. (Each used to have to call
    /// `sync_channel_member` itself; several never did, and were papered over
    /// by a sync on every line the client sent.)
    pub(crate) fn publish_changed_sessions(&mut self) {
        for conn in self.sessions.take_touched() {
            match self.sessions.get(&conn) {
                None => self.users.withdraw(conn),
                Some(session) if !session.is_registered() => {}
                Some(session) => {
                    let current = session
                        .published
                        .as_ref()
                        .is_some_and(|published| published.describes(session));
                    if !current {
                        self.sync_channel_member(conn, ChannelMemberChange::Identity);
                    }
                }
            }
        }
    }

    /// The session's channels, grouped by the shard that owns them — with the
    /// JOINs still on their way to another shard. A change made while a JOIN
    /// is in flight (a NICK, AWAY, SETNAME, a host change) must reach that
    /// channel too: the owner admits the member from the snapshot the JOIN
    /// carried, and the owner's queue is FIFO, so an update sent after the JOIN
    /// arrives after it and corrects the member it created. Sending it only to
    /// joined channels left the channel holding the old nick or host for good.
    /// An owner that refused the JOIN finds no member and ignores the update.
    fn session_channels_by_shard(&self, conn: ConnId) -> Vec<ShardChannels> {
        let mut by_shard: std::collections::BTreeMap<usize, Vec<ChannelOwner>> =
            std::collections::BTreeMap::new();
        let session = &self.sessions[&conn];
        // A channel rejoined while a member is in both: it is named once.
        let in_flight = session
            .joins_in_flight()
            .filter(|key| !session.channels.contains(*key));
        for key in session.channels.iter().chain(in_flight) {
            let owner = self.channels.owner(key);
            by_shard.entry(owner.shard().0).or_default().push(owner);
        }
        by_shard.into_values().map(ShardChannels).collect()
    }

    pub fn apply_channel_member_update(&mut self, update: ChannelMemberUpdate) {
        assert_eq!(
            update.shard(),
            self.shard,
            "member update reached wrong shard"
        );
        for key in update.channels.keys() {
            if let Some(channel) = self.channels.get_mut(key) {
                channel.update_member(
                    update.recipient,
                    update.identity.clone(),
                    update.profile.clone(),
                );
            }
        }
        if let Some(event) = update.event {
            self.report_user_event(ChannelUserEvent {
                channels: update.channels,
                event,
            });
        }
    }

    /// A new event about `subject`, to be reported on by `reporters` parties.
    fn user_event(
        &mut self,
        subject: ConnId,
        line: EventLine,
        audience: UserEventAudience,
        reporters: usize,
    ) -> UserEvent {
        self.user_event_sequence += 1;
        UserEvent {
            id: (self.shard, self.user_event_sequence),
            subject,
            line,
            audience,
            host_change: None,
            parts: reporters,
        }
    }

    /// Tell everyone who can see `subject` — the peers in its channels, and
    /// for anything but QUIT/NICK the extended-monitor watchers of its nick —
    /// about something that happened to it, once each. `include_self` also
    /// tells the subject (CHGHOST, which the user did not originate).
    pub(crate) fn notify_user_event(
        &mut self,
        subject: ConnId,
        line: &EventLine,
        audience: UserEventAudience,
        include_self: bool,
    ) {
        self.notify_user_event_with(subject, line, audience, include_self, None);
    }

    /// [`Self::notify_user_event`] for a host change: peers outside the
    /// `chghost` audience are told by `fallback`'s quit-and-rejoin instead.
    pub(crate) fn notify_host_change(
        &mut self,
        subject: ConnId,
        line: &EventLine,
        include_self: bool,
        fallback: HostChangeFallback,
    ) {
        self.notify_user_event_with(
            subject,
            line,
            UserEventAudience::Chghost,
            include_self,
            Some(Arc::new(fallback)),
        );
    }

    fn notify_user_event_with(
        &mut self,
        subject: ConnId,
        line: &EventLine,
        audience: UserEventAudience,
        include_self: bool,
        host_change: Option<Arc<HostChangeFallback>>,
    ) {
        let owners = self.session_channels_by_shard(subject);
        // The watchers are one more reporter, alongside each channel owner.
        let mut event = self.user_event(subject, line.clone(), audience, owners.len() + 1);
        event.host_change = host_change;
        for channels in owners {
            let report = ChannelUserEvent {
                channels,
                event: event.clone(),
            };
            if report.shard() == self.shard {
                self.report_user_event(report);
            } else {
                self.route_input(crate::core::Input::ChannelUserEvent { report });
            }
        }
        let mut watchers = Peers::of(subject);
        if let Some(nick) = self.sessions.get(&subject).and_then(Session::nick) {
            let watching: Vec<Recipient> = self
                .monitors
                .watchers(&self.nick_key(nick))
                .into_iter()
                .filter_map(|watcher| Some(self.users.get(watcher)?.recipient))
                .filter(|recipient| recipient.caps().extended_monitor)
                .collect();
            watchers.extend(&watching, audience);
        }
        self.send_user_event_parts(&event, watchers);
        if include_self {
            self.send_event(subject, line);
        }
    }

    /// Report the peers of an event's subject among the channels this shard owns.
    pub(crate) fn report_user_event(&mut self, report: ChannelUserEvent) {
        assert_eq!(report.shard(), self.shard, "user event reached wrong shard");
        let mut peers = Peers::of(report.event.subject);
        for key in report.channels.keys() {
            // Only a channel the subject is in shares it with anyone: the
            // report may name one whose JOIN was in flight and then refused.
            if let Some(channel) = self.channels.get(key)
                && channel.is_member(report.event.subject)
            {
                peers.extend_channel(channel, &report.event, &self.config.server_name);
            }
        }
        self.send_user_event_parts(&report.event, peers);
    }

    /// Hand each shard the part of `peers` whose sessions it holds. When other
    /// reporters exist every shard gets a part, even an empty one: a shard
    /// forgets an event once it has heard from all of them.
    fn send_user_event_parts(&mut self, event: &UserEvent, peers: Peers) {
        let mut by_shard: Vec<Vec<(Recipient, Vec<EventLine>)>> =
            vec![Vec::new(); self.channels.shard_count()];
        for (recipient, rejoin) in peers.recipients.into_values() {
            by_shard[recipient.shard().0].push((recipient, rejoin));
        }
        for (shard, recipients) in by_shard.into_iter().enumerate() {
            if event.parts == 1 && recipients.is_empty() {
                continue;
            }
            let part = UserEventPart {
                shard: CoreShardId(shard),
                event: event.clone(),
                recipients,
            };
            if part.shard == self.shard {
                self.deliver_user_event_part(part);
            } else {
                self.route_input(crate::core::Input::UserEventPart { part });
            }
        }
    }

    /// Deliver an event to those of `part`'s recipients who have not had it.
    pub(crate) fn deliver_user_event_part(&mut self, part: UserEventPart) {
        assert_eq!(
            part.shard, self.shard,
            "user event part reached wrong shard"
        );
        let UserEventPart {
            event, recipients, ..
        } = part;
        // With several reporters, who has been told lives across parts.
        let mut pending = (event.parts > 1).then(|| {
            let mut pending = self
                .user_events_in_progress
                .remove(&event.id)
                .unwrap_or_default();
            pending.parts_heard += 1;
            pending
        });
        let mut told = Vec::new();
        for (recipient, rejoin) in recipients {
            let fresh = pending
                .as_mut()
                .is_none_or(|pending| pending.told.insert(recipient.conn()));
            if rejoin.is_empty() {
                if fresh {
                    told.push(recipient);
                }
                continue;
            }
            // A peer outside the event's audience, told by quit-and-rejoin:
            // the QUIT once, before the first rejoin; each reporter's rejoins.
            let quit = &event
                .host_change
                .as_ref()
                .expect("only a host change owes rejoins")
                .quit;
            if fresh {
                self.send_event_recipient(recipient, quit);
            }
            for line in &rejoin {
                self.send_event_recipient(recipient, line);
            }
        }
        if let Some(pending) = pending
            && pending.parts_heard != event.parts
        {
            self.user_events_in_progress.insert(event.id, pending);
        }
        self.broadcast_recipients(told, &event.line);
    }

    pub(crate) fn take_effects(&mut self) -> Vec<CoreEffect> {
        std::mem::take(&mut self.effects)
    }

    pub(crate) fn broadcast_server_ban_after_local_apply(
        &mut self,
        mutation: super::ServerBanMutation,
    ) {
        self.effects
            .push(CoreEffect::BroadcastServerBan { mutation });
    }

    pub(crate) fn broadcast_account_suspension(
        &mut self,
        account: String,
        suspended: bool,
        reason: String,
        actor: String,
    ) {
        self.effects.push(CoreEffect::BroadcastAccountSuspension {
            account,
            suspended,
            reason,
            actor,
        });
    }

    pub(crate) fn broadcast_read_marker(
        &mut self,
        account: String,
        target: String,
        display: String,
        marker_ms: e6irc_proto::time::Millis,
    ) {
        self.effects.push(CoreEffect::BroadcastReadMarker {
            account,
            target,
            display,
            marker_ms,
        });
    }

    pub(crate) fn broadcast_connection_list(
        &mut self,
        request_id: u64,
        query: super::LiveConnectionQuery,
    ) {
        self.effects
            .push(CoreEffect::BroadcastAdminConnectionList { request_id, query });
    }

    pub(crate) fn session_owner(&self, conn: ConnId) -> SessionOwner {
        SessionOwner::new(conn, self.shard)
    }

    pub fn new(
        shard: CoreShardId,
        shards: CoreShardCount,
        config: CoreConfig,
        db_tx: Sender<super::DbRequest>,
        telemetry: Arc<Telemetry>,
        directories: CoreDirectories,
    ) -> Self {
        let started_at = (config.clock)();
        Self {
            shard,
            telemetry,
            config,
            casemap: CaseMapping::Rfc1459,
            sessions: SessionStore::new(),
            users: directories.users,
            nicks: directories.nicks,
            memberships: directories.memberships,
            shards,
            channels: ChannelDirectory::new(shards),
            doomed: Vec::new(),
            effects: Vec::new(),
            suspended_accounts: HashSet::new(),
            deleted_accounts: HashSet::new(),
            db_tx,
            started_at,
            msgids: MsgidSource::new(shard),
            monitors: directories.monitors,
            user_event_sequence: 0,
            user_events_in_progress: HashMap::new(),
            read_markers: HashMap::new(),
            pending_read_markers: HashMap::new(),
            read_marker_slots: HashMap::new(),
            account_sessions: HashMap::new(),
            registered_founders: directories.founders,
            pending_channel_registrations: HashMap::new(),
            registered_topics: directories.topics,
            pending_channel_topics: HashMap::new(),
            channel_topic_revision: 0,
            channel_options: directories.channel_options,
            nick_registrations: directories.nick_registrations,
            server_bans: Vec::new(),
            pending_server_bans: HashSet::new(),
            whowas: directories.whowas,
            census: directories.census,
            census_reported: (0, 0),
            history: HotHistory::default(),
            emitting_deferred: None,
            capture: None,
            registration_buckets: HashMap::new(),
            pending_admin_channel_drops: HashMap::new(),
            admin_channel_drop_id: 0,
            pending_admin_server_bans: HashMap::new(),
            admin_server_ban_id: 0,
            pending_connection_lists: HashMap::new(),
            admin_connection_list_id: 0,
            pending_channel_controls: HashMap::new(),
            channel_control_id: 0,
            pacing: HashSet::new(),
            channel_list_id: 0,
        }
    }

    /// Spend one token from `conn`'s account-creation bucket, charged to the
    /// limit key the session opened with. Returns `false`
    /// (rate-limited) when the bucket is empty; always `true` when
    /// `registration_burst` is unset. The bucket refills to full over
    /// `REGISTRATION_REFILL_WINDOW_MS`; fully-refilled entries are pruned, and
    /// the map is hard-capped at `MAX_REGISTRATION_BUCKETS` so it can't grow
    /// without bound even under a distinct-IP flood. Mirrors the HTTP
    /// `spend_auth_budget` limiter, but on the core's monotonic clock.
    pub fn registration_rate_ok(&mut self, conn: ConnId) -> bool {
        let Some(burst) = self.config.registration_burst else {
            return true;
        };
        let key = self.sessions[&conn].limit_key.clone();
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
                && !buckets.contains_key(&key)
                && let Some(oldest) = buckets
                    .iter()
                    .min_by_key(|(_, (_, last))| *last)
                    .map(|(k, _)| k.clone())
            {
                buckets.remove(&oldest);
            }
        }
        let entry = buckets.entry(key).or_insert((burst, now));
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
    /// global LRU within `max_hot_channels` and `max_hot_history_bytes`: this
    /// target is touched to MRU and the least-recently-active rings are
    /// evicted once either is exceeded, as its own oldest entries are past
    /// `max_history_ring_bytes`. An
    /// evicted or overflowed ring is marked incomplete, so CHATHISTORY pages
    /// the remainder from Postgres rather than reporting a short history.
    ///
    /// One implementation serves channels and direct-message conversations
    /// alike — the eviction discipline that bounds hot-history RAM must not
    /// differ by target kind.
    pub fn push_history(&mut self, key: &HistoryKey, entry: HistoryEntry) {
        // A ring being created now is the *entire* record only when no
        // database backs it. With a DB this target may have rows in
        // `messages` already — an earlier incarnation of the channel (they
        // are dropped when they empty), or an earlier stretch of the same
        // conversation — so the ring is not authoritative and CHATHISTORY
        // must be able to fall back rather than report an empty batch. One
        // rule for channels and conversations alike.
        let whole_record = !self.config.sasl_enabled;
        // Evicted targets keep no ring at all; their history is served from
        // Postgres.
        let bounds = crate::core::hot_history::HotHistoryBounds {
            rings: self.config.max_hot_channels,
            ring_bytes: self.config.max_history_ring_bytes,
            bytes: self.config.max_hot_history_bytes,
        };
        let evicted = self.history.push(key, entry, whole_record, bounds);
        self.channel_ring_changed(key);
        for cold in evicted {
            self.channel_ring_changed(&cold);
        }
    }

    /// A target's hot ring, or an empty incomplete one when it has never been
    /// created or was evicted — an absent ring is never "the whole record".
    pub fn history_ring(&self, key: &HistoryKey) -> (Vec<HistoryEntry>, bool) {
        match self.history.get(key) {
            Some(ring) => (ring.entries().iter().cloned().collect(), ring.complete()),
            None => (Vec::new(), false),
        }
    }

    /// Mark a target's ring as no longer the whole record (a message was
    /// delivered but could not be persisted, so a gap exists that only
    /// Postgres could fill — and it does not have it either).
    pub fn mark_history_incomplete(&mut self, key: &HistoryKey) {
        self.history.mark_incomplete(key);
    }

    /// Destroy an emptied channel: drop it from `channels` and its ring (with
    /// its LRU slot) together, so the two can't desync — a stale LRU key would
    /// otherwise inflate the count and evict a still-live channel's ring early
    /// under the `max_hot_channels` cap.
    pub fn remove_channel(&mut self, key: &ChanKey) {
        self.channels.remove(key);
        self.history.remove(&HistoryKey::from(key));
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
        self.whowas.record(entry);
    }

    /// Add this event's change in this shard's connections and channels to
    /// the server-wide counts.
    pub(crate) fn publish_census(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = (self.sessions.len(), self.channels.len());
        let (connections, channels) = self.census_reported;
        // Wrapping add of the difference: adds or subtracts as needed.
        self.census
            .connections
            .fetch_add(now.0.wrapping_sub(connections), Relaxed);
        self.census
            .channels
            .fetch_add(now.1.wrapping_sub(channels), Relaxed);
        self.census_reported = now;
    }

    /// The server-wide `(connections, channels, most users ever)`, counting
    /// this shard as it is *now* — mid-event — rather than as last published.
    pub(crate) fn census(&self) -> (usize, usize, usize) {
        use std::sync::atomic::Ordering::Relaxed;
        let (connections, channels) = self.census_reported;
        let users = self.users.counts().users;
        (
            self.census
                .connections
                .load(Relaxed)
                .wrapping_sub(connections)
                .wrapping_add(self.sessions.len()),
            self.census
                .channels
                .load(Relaxed)
                .wrapping_sub(channels)
                .wrapping_add(self.channels.len()),
            self.census.most_users.fetch_max(users, Relaxed).max(users),
        )
    }

    /// Whether two connections share at least one channel.
    pub fn share_channel(&self, a: ConnId, b: ConnId) -> bool {
        if self.memberships.shares(a, b) {
            return true;
        }
        let (Some(sa), Some(sb)) = (self.sessions.get(&a), self.sessions.get(&b)) else {
            return false;
        };
        sa.channels.intersection(&sb.channels).next().is_some()
    }

    /// Whether any session, on any shard, is logged in to `account`.
    pub(crate) fn account_online(&self, account: &AccountKey) -> bool {
        self.users.logged_in_as(account.as_str()).is_some()
    }

    /// All connections currently identified to `account`, compared under the
    /// server casemapping. This is the one account comparison that must fold
    /// rather than use raw `==`: everywhere else accounts are folded before use
    /// (`is_founder`, `access_modes`, `identity_nick`), and a raw compare here
    /// would silently fail to sync a sibling connection (e.g. MARKREAD) if any
    /// session ever held a non-canonical account label.
    pub fn account_connections(&self, account: &str) -> Vec<ConnId> {
        self.account_sessions
            .get(&self.account_key(account))
            .map(|connections| connections.iter().copied().collect())
            .unwrap_or_default()
    }

    /// `conn` is no longer logged in to `account`: drop it from the index,
    /// and the account's entry once it is empty.
    fn forget_account_session(&mut self, account: &str, conn: ConnId) {
        let key = self.account_key(account);
        let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.account_sessions.entry(key)
        else {
            unreachable!("a session's account is always indexed while it is set");
        };
        let removed = entry.get_mut().remove(&conn);
        debug_assert!(removed, "a session's account is indexed while it is set");
        if entry.get().is_empty() {
            entry.remove();
        }
    }

    /// The confirmed read marker for `key`, if any.
    pub(crate) fn read_marker(
        &self,
        key: &(AccountKey, ChanKey),
    ) -> Option<e6irc_proto::time::Millis> {
        self.read_markers.get(key).copied()
    }

    /// Whether a database write for `key` is in flight.
    pub(crate) fn read_marker_pending(&self, key: &(AccountKey, ChanKey)) -> bool {
        self.pending_read_markers.contains_key(key)
    }

    /// Whether `key` holds one of its account's marker slots: confirmed, or
    /// reserved by a write in flight.
    pub(crate) fn read_marker_slot_held(&self, key: &(AccountKey, ChanKey)) -> bool {
        self.read_markers.contains_key(key) || self.pending_read_markers.contains_key(key)
    }

    /// How many distinct targets `account` holds a marker slot for.
    pub(crate) fn read_marker_slots(&self, account: &AccountKey) -> usize {
        self.read_marker_slots.get(account).copied().unwrap_or(0)
    }

    fn take_read_marker_slot(&mut self, account: &AccountKey) {
        *self.read_marker_slots.entry(account.clone()).or_default() += 1;
    }

    fn free_read_marker_slot(&mut self, account: &AccountKey) {
        let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.read_marker_slots.entry(account.clone())
        else {
            unreachable!("a held marker slot is counted");
        };
        *entry.get_mut() -= 1;
        if *entry.get() == 0 {
            entry.remove();
        }
    }

    /// Record a confirmed marker, returning the value it replaced. For a
    /// permanently deleted account nothing is stored, and the marker is
    /// reported as already current so no caller fans it out.
    pub(crate) fn store_read_marker(
        &mut self,
        key: (AccountKey, ChanKey),
        marker_ms: e6irc_proto::time::Millis,
    ) -> Option<e6irc_proto::time::Millis> {
        if self.account_deleted(&key.0) {
            return Some(marker_ms);
        }
        let held = self.read_marker_slot_held(&key);
        let previous = self.read_markers.insert(key.clone(), marker_ms);
        if !held {
            self.take_read_marker_slot(&key.0);
        }
        previous
    }

    /// Reserve `key` for a database write now in flight.
    pub(crate) fn reserve_read_marker(&mut self, key: (AccountKey, ChanKey)) {
        let held = self.read_marker_slot_held(&key);
        *self.pending_read_markers.entry(key.clone()).or_default() += 1;
        if !held {
            self.take_read_marker_slot(&key.0);
        }
    }

    /// One database write for `key` has been answered. `Err` when none was
    /// reserved — a reply without a request, which the caller reports.
    pub(crate) fn release_read_marker(
        &mut self,
        key: &(AccountKey, ChanKey),
    ) -> Result<(), ReadMarkerNotReserved> {
        match self.pending_read_markers.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) if *entry.get() > 1 => {
                *entry.get_mut() -= 1;
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                entry.remove();
                if !self.read_markers.contains_key(key) {
                    self.free_read_marker_slot(&key.0);
                }
                Ok(())
            }
            std::collections::hash_map::Entry::Vacant(_) => Err(ReadMarkerNotReserved),
        }
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
        self.registered_founders.replace(
            rows.into_iter()
                .map(|(name_folded, founder)| (ChanKey(name_folded), AccountKey(founder))),
        );
    }

    /// Load persisted channel successors as `(name_folded, successor_folded)`
    /// rows, after [`Self::preload_founders`].
    pub fn preload_successors(&mut self, rows: Vec<(String, String)>) {
        self.registered_founders.replace_successors(
            rows.into_iter()
                .map(|(name_folded, successor)| (ChanKey(name_folded), AccountKey(successor))),
        );
    }

    /// Record a newly registered channel's founder.
    pub fn register_founder(&mut self, channel: &str, founder_account: &str) {
        let key = self.chan_key(channel);
        let founder = self.account_key(founder_account);
        self.registered_founders.register(key, founder);
    }

    /// Record that a registered channel passed to `founder_account` (see
    /// [`FounderDirectory::transfer`]).
    pub fn transfer_founder(&mut self, channel: &str, founder_account: &str) {
        let key = self.chan_key(channel);
        let founder = self.account_key(founder_account);
        self.registered_founders.transfer(key, founder);
    }

    /// Whether `account` is the registered founder of channel `key`.
    pub fn is_founder(&self, key: &ChanKey, account: &str) -> bool {
        self.registered_founders.founder(key) == Some(self.account_key(account))
    }

    /// Whether channel `key` is registered (ownership recorded).
    pub fn is_registered(&self, key: &ChanKey) -> bool {
        self.registered_founders.founder(key).is_some()
    }

    /// How many channels `account` currently founds or has reserved by an
    /// in-flight registration. Counting both prevents a pipelined REGISTER
    /// burst from stepping around the permanent-map cap before verdicts land.
    pub fn channels_founded_by(&self, account: &str) -> usize {
        let account_key = self.account_key(account);
        let committed = self.registered_founders.count(&account_key);
        let pending = self
            .pending_channel_registrations
            .iter()
            .filter(|(channel, founder)| {
                **founder == account_key && self.registered_founders.founder(channel).is_none()
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
        self.registered_topics.replace(rows.into_iter().map(
            |(name_folded, text, set_by, set_at_secs)| {
                (
                    ChanKey(name_folded),
                    Topic {
                        text,
                        set_by,
                        set_at_secs,
                    },
                )
            },
        ));
    }

    /// Load the registered channels whose KEEPTOPIC is OFF (by folded name).
    pub fn preload_keeptopic_off(&mut self, names: Vec<String>) {
        self.channel_options
            .replace_keeptopic_off(names.into_iter().map(ChanKey));
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
        self.channel_options.replace_mlock(locks);
        Ok(())
    }

    /// Whether setting boolean mode `c` to `adding` would violate `key`'s
    /// mode lock (locked-off mode set on, or locked-on mode set off).
    pub fn mlock_conflict(&self, key: &ChanKey, c: char, adding: bool) -> bool {
        match self.channel_options.mlock(key) {
            Some(m) => (adding && m.off.contains(c)) || (!adding && m.on.contains(c)),
            None => false,
        }
    }

    /// Load persisted channel access as `(name_folded, account_folded,
    /// flags)` rows into the hot access map.
    pub fn preload_access(&mut self, rows: Vec<(String, String, String)>) {
        self.channel_options.replace_access(
            rows.into_iter()
                .map(|(channel, account, flags)| (ChanKey(channel), AccountKey(account), flags)),
        );
    }

    /// Seed the read-marker mirror from persisted `(account, target, millis)`
    /// rows at boot. The dump returns the display-cased account name, so it is
    /// folded here into an `AccountKey` — matching the key MARKREAD builds at
    /// runtime. The stored target is already the casefolded `ChanKey` string (it
    /// was written from `ChanKey::as_str`), so it is wrapped directly.
    pub fn preload_read_markers(&mut self, rows: Vec<(String, String, e6irc_proto::time::Millis)>) {
        self.read_markers.clear();
        // The slot count is rebuilt from what remains (writes still in flight)
        // plus the rows, through the same counting store as a live write.
        self.read_marker_slots.clear();
        let pending: Vec<AccountKey> = self
            .pending_read_markers
            .keys()
            .map(|(account, _)| account.clone())
            .collect();
        for account in &pending {
            self.take_read_marker_slot(account);
        }
        for (account, target, ms) in rows {
            let account = self.account_key(&account);
            self.store_read_marker((account, ChanKey(target)), ms);
        }
    }

    /// Drop mirror entries whose stored row storage maintenance deleted. An
    /// entry is dropped only while it still holds the deleted value (or an
    /// older one): a marker written again after the sweep is a new row the
    /// database holds, and stays. A write still in flight keeps its slot.
    pub(crate) fn expire_read_markers(&mut self, markers: &[crate::core::ExpiredReadMarker]) {
        for marker in markers {
            let key = (
                self.account_key(&marker.account),
                ChanKey(marker.target.clone()),
            );
            let std::collections::hash_map::Entry::Occupied(entry) = self.read_markers.entry(key)
            else {
                continue;
            };
            if *entry.get() > marker.marker_ms {
                continue;
            }
            let (key, _) = entry.remove_entry();
            if !self.pending_read_markers.contains_key(&key) {
                self.free_read_marker_slot(&key.0);
            }
        }
    }

    /// `account` was permanently deleted: drop everything this shard mirrors
    /// of the rows its deletion removed — its read markers, the history lines
    /// it sent and the conversations it took part in (the database purge took
    /// both), and its channel access entries (cascaded). Its suspension stays:
    /// that is the live authentication gate for the retired name.
    ///
    /// The channels it founded with a successor passed to that successor in
    /// the same transaction (`successions`, `(channel, new founder)`): the
    /// founder mirror follows them. It succeeds no channel any more, and its
    /// grouped nicks and nick protection went with the account too.
    pub(crate) fn forget_deleted_account(
        &mut self,
        account: &str,
        successions: &[crate::db::ChannelSuccession],
    ) {
        self.forget_account_read_markers(account);
        let key = self.account_key(account);
        for changed in self.history.forget_account(key.as_str(), self.casemap) {
            self.channel_ring_changed(&changed);
        }
        self.channel_options.remove_account(&key);
        self.nick_registrations.forget_account(&key);
        self.registered_founders.forget_successor(&key);
        for succession in successions {
            let channel = self.chan_key(&succession.channel);
            let founder = self.account_key(&succession.founder);
            self.registered_founders.transfer(channel, founder);
        }
    }

    /// Drop every confirmed read-marker mirror entry of a permanently deleted
    /// `account`: its rows cascaded away with the account. A write still in
    /// flight keeps its slot until its reply releases it, as in
    /// [`Self::expire_read_markers`].
    fn forget_account_read_markers(&mut self, account: &str) {
        let account = self.account_key(account);
        self.deleted_accounts.insert(account.clone());
        let forgotten: Vec<(AccountKey, ChanKey)> = self
            .read_markers
            .keys()
            .filter(|(holder, _)| *holder == account)
            .cloned()
            .collect();
        for key in forgotten {
            self.read_markers.remove(&key);
            if !self.pending_read_markers.contains_key(&key) {
                self.free_read_marker_slot(&key.0);
            }
        }
    }

    /// The `(auto_op, auto_voice)` flags `account` holds on channel `key`.
    pub fn access_modes(&self, key: &ChanKey, account: &str) -> (bool, bool) {
        let account = self.account_key(account);
        match self.channel_options.access_flags(key, &account) {
            Some(flags) => (flags.contains('o'), flags.contains('v')),
            None => (false, false),
        }
    }

    /// Load the persisted server bans still in force.
    pub fn preload_server_bans(
        &mut self,
        rows: Vec<crate::db::PersistedServerBan>,
    ) -> Result<(), String> {
        let casemap = self.casemap;
        let mut bans = Vec::with_capacity(rows.len());
        for row in rows {
            let kind = BanKind::from_token(&row.kind)
                .ok_or_else(|| format!("invalid persisted server-ban kind {:?}", row.kind))?;
            let expires_at_secs = row
                .expires_at
                .map(|at| {
                    u64::try_from(at)
                        .map_err(|_| format!("invalid persisted server-ban expiry {at}"))
                })
                .transpose()?;
            bans.push(ServerBan {
                mask: MaskKey::new(&row.mask, casemap),
                reason: row.reason,
                set_by: row.set_by,
                kind,
                expires_at_secs,
            });
        }
        self.server_bans = bans;
        Ok(())
    }

    /// The server bans in force now, the ones every surface acts on: a
    /// temporary ban past its expiry bans no one and is listed nowhere, even
    /// before the next tick drops it (`oper::expire_server_bans`).
    pub(crate) fn server_bans_in_force(&self) -> impl Iterator<Item = &ServerBan> {
        let now_secs = (self.config.clock)().as_secs();
        self.server_bans
            .iter()
            .filter(move |ban| ban.in_force(now_secs))
    }

    /// The `(kind, reason)` of the first server ban matching `subject`, if any.
    pub(crate) fn ban_match(&self, subject: &ServerBanSubject<'_>) -> Option<(BanKind, String)> {
        self.server_bans_in_force()
            .find(|ban| ban.matches(self.casemap, subject))
            .map(|ban| (ban.kind, ban.reason.clone()))
    }

    /// Seed the grouped-nick and nick-protection mirror from PostgreSQL
    /// (see [`NickRegistrationDirectory`]).
    pub fn preload_nick_registrations(
        &mut self,
        grouped: Vec<(String, String)>,
        enforced: Vec<String>,
    ) {
        let grouped: Vec<(NickKey, AccountKey)> = grouped
            .into_iter()
            .map(|(nick, account)| (self.nick_key(&nick), self.account_key(&account)))
            .collect();
        let enforced: Vec<AccountKey> = enforced.iter().map(|a| self.account_key(a)).collect();
        self.nick_registrations.replace(grouped, enforced);
    }

    /// The account whose ENFORCE protects `nick`, if any: the account it is
    /// grouped to, or the account of the same name.
    pub(crate) fn nick_protector(&self, nick: &NickKey) -> Option<AccountKey> {
        self.nick_registrations
            .protector(nick, self.account_key(nick.as_str()))
    }

    /// Whether `account` was permanently deleted while this process runs: a
    /// late verdict may not add anything of it back to a mirror.
    pub(crate) fn account_deleted(&self, account: &AccountKey) -> bool {
        self.deleted_accounts.contains(account)
    }

    /// The account `name` names for ChanServ: the account a grouped nick
    /// belongs to, or the account of that name (Atheme resolves any of an
    /// account's nicks to it). Storage resolves the same way when it applies
    /// the change; this answers the core's own checks.
    pub(crate) fn resolve_account_key(&self, name: &str) -> AccountKey {
        self.nick_registrations
            .grouped_owner(&self.nick_key(name))
            .unwrap_or_else(|| self.account_key(name))
    }

    /// Whether `nick` belongs to `account`: it is the account's name, or a
    /// nick grouped to it (GHOST and REGAIN act only on a nick one owns).
    pub(crate) fn nick_owned_by(&self, nick: &NickKey, account: &str) -> bool {
        let account = self.account_key(account);
        self.account_key(nick.as_str()) == account
            || self.nick_registrations.grouped_owner(nick) == Some(account)
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

    /// Every registered user, on every shard.
    pub(crate) fn registered_users(&self) -> Vec<Arc<PublicUser>> {
        self.users.all()
    }

    /// How many registered users there are on every shard, and how many are
    /// invisible or operators: counters, not a copy of the directory.
    pub(crate) fn user_counts(&self) -> UserCounts {
        self.users.counts()
    }

    /// A channel's display name and when its history ring last saw an entry a
    /// reader in `scope` can be sent, whichever shard owns the channel (and so
    /// holds the ring).
    pub(crate) fn channel_activity(
        &self,
        key: &ChanKey,
        scope: crate::core::HistoryScope,
    ) -> Option<(String, e6irc_proto::time::Millis)> {
        self.memberships.channel_activity(key, scope)
    }

    /// The oldest history of channel `key` that `account` may read, or `None`
    /// when no such channel exists: the founder and access list of a
    /// registered channel keep its whole record (the rule REST applies), and
    /// everyone else sees only the current incarnation, created when the
    /// channel last came into being. The owner's live channel answers when
    /// this shard owns it, the published record when another shard does.
    pub(crate) fn channel_history_floor(
        &self,
        key: &ChanKey,
        account: Option<&str>,
    ) -> Option<crate::core::HistoryFloor> {
        let created_at = match self.channels.get(key) {
            Some(channel) => channel.created_at,
            None => self.memberships.channel_created_at(key)?,
        };
        let keeps_whole_record = account.is_some_and(|account| {
            self.is_founder(key, account)
                || self
                    .channel_options
                    .access_flags(key, &self.account_key(account))
                    .is_some()
        });
        Some(if keeps_whole_record {
            crate::core::HistoryFloor::Whole
        } else {
            crate::core::HistoryFloor::Since(created_at)
        })
    }

    /// The ring under `key` gained or lost entries. When it is a channel's,
    /// what this shard publishes about that channel is out of date.
    fn channel_ring_changed(&mut self, key: &HistoryKey) {
        if let Some(channel) = key.channel() {
            self.channels.touch_activity(channel);
        }
    }

    /// `target`'s channels as WHOIS shows them to `requester`.
    pub(crate) fn whois_channels(&self, target: ConnId, requester: ConnId) -> Vec<String> {
        let multi_prefix = self
            .sessions
            .get(&requester)
            .is_some_and(|session| session.caps.multi_prefix);
        self.memberships
            .whois_channels(target, requester, multi_prefix)
    }

    /// A channel, on any shard, where `conn` is a plain member banned or
    /// quieted under its current hostmask — see
    /// [`MembershipDirectory::silenced_in`].
    pub(crate) fn silenced_in(&self, conn: ConnId) -> Option<String> {
        let session = &self.sessions[&conn];
        let prefix = session.prefix();
        let subject = session.mask_subject(&prefix);
        self.memberships.silenced_in(conn, self.casemap, &subject)
    }

    /// Where `conn`'s session lives, whether or not it is this shard.
    pub(crate) fn session_shard(&self, conn: ConnId) -> SessionOwner {
        self.shards.session_owner(conn)
    }

    /// The published record of `conn`, on whichever shard it lives.
    pub(crate) fn user(&self, conn: ConnId) -> Option<Arc<PublicUser>> {
        self.users.get(conn)
    }

    /// The registered user holding `key`, on whichever shard they live.
    pub(crate) fn registered_user(&self, key: &NickKey) -> Option<Arc<PublicUser>> {
        self.users.get(self.nicks.registered_owner(key)?.conn())
    }

    pub fn mark_nick_registered(&self, conn: ConnId) {
        if let Some(nick) = self.sessions[&conn].nick() {
            self.nicks.mark_registered(&self.nick_key(nick), conn);
        }
    }

    /// Release `key` only when `conn` still owns it.
    pub fn release_nick(&mut self, key: &NickKey, conn: ConnId) -> bool {
        self.nicks.release_if_owned(key, conn)
    }

    /// A casefolded nick rendered for display: the online user's actual nick
    /// casing when they are connected, otherwise the casefolded form itself
    /// (the only spelling still on record once they have gone).
    pub fn display_nick(&self, folded: &str) -> String {
        self.registered_user(&NickKey(folded.to_string()))
            .map(|user| user.nick.clone())
            .unwrap_or_else(|| folded.to_string())
    }

    /// A conversation participant rendered as a nick for display: the `~`
    /// marker is stripped from an unauthenticated identity, and an account is
    /// shown as the nick currently using it when its owner is online.
    pub fn identity_nick(&self, identity: &str) -> String {
        match identity.strip_prefix('~') {
            Some(nick) => self.display_nick(nick),
            None => self
                .users
                .logged_in_as(identity)
                .map(|user| user.nick.clone())
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
    /// Two successive *unauthenticated* holders of a nick derive the same
    /// `~nick` — without accounts there is nothing stronger to key on. That is
    /// why such a conversation is never written to the database, and why the
    /// rings holding it are freed on every shard the moment the identity is let
    /// go, by disconnecting or by changing nick (`release_unauthenticated_identity`):
    /// it lasts exactly as long as the party it was with.
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
        match self.registered_user(&self.nick_key(nick)) {
            Some(user) => user.identity(self.casemap),
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

    pub fn open(
        &mut self,
        conn: ConnId,
        tx: crate::core::SendQueue,
        host: String,
        transport: crate::core::ConnectionTransport,
    ) {
        let opened_at = (self.config.mono_clock)();
        // The shown host rides as a middle parameter (WHO, WHOIS): an IPv6
        // address that starts with `:` is spelled with a leading `0`, as
        // Solanum does, or every such reply would carry the funnel's `*`.
        let host = crate::sanitize::mask_middle(&host).into_owned();
        let prev = self.sessions.insert(
            conn,
            Session {
                output: SessionOutput::new(tx),
                limit_key: crate::net::PeerLimitKey::for_session_host(&host),
                real_ip: host
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(|address| address.to_canonical()),
                host,
                transport,
                reg: Registration::Registering {
                    nick: None,
                    user: None,
                    realname: None,
                    refused_nick: None,
                },
                cap_negotiating: false,
                cap_302: false,
                caps: Caps::default(),
                account: None,
                sasl: SaslState::default(),
                sasl_verify: None,
                sasl_buf: String::new(),
                credential_attempts: crate::identity::CredentialAttemptBudget::default(),
                pending_identify: None,
                pending_register: None,
                nick_enforcement: NickEnforcement::default(),
                drop_confirmation: None,
                away: None,
                oper: None,
                invisible: false,
                wallops: false,
                bot: false,
                registered_only: false,
                channels: HashSet::new(),
                pending_joins: HashMap::new(),
                part_on_join: HashMap::new(),
                last_knock: None,
                monitoring: HashMap::new(),
                multiline: None,
                channel_list: None,
                paced_who: None,
                label_groups: HashMap::new(),
                anon_read_markers: HashMap::new(),
                // Seed the flood bucket full, with its refill watermark at the
                // open time — NOT a zero `MonoMillis` sentinel. The monotonic
                // clock's epoch is process start, so a zero watermark makes the
                // first refill credit `now - 0 = uptime` seconds: within the
                // first burst-many seconds of uptime the bucket would start
                // at only `min(uptime, burst)` tokens and wrongly kill a client
                // that pipelines a legitimate burst — worst exactly during a
                // post-restart reconnect storm.
                flood_tokens: self.config.command_flood.map_or(0, CommandFlood::burst),
                flood_refilled_to_ms: opened_at,
                // Every monotonic watermark is seeded from the open time, never a
                // zero `MonoMillis` sentinel. A zero would be indistinguishable
                // from a real early reading (the mono epoch IS process start), so
                // the first `now - 0 = uptime` read would misbehave in the first
                // moments of uptime — the class that flood-killed fresh clients a
                // sweep ago. Both are re-stamped before they gate anything
                // (`last_active` at registration, `last_ping_sent` when a PING is
                // actually sent), so open-time is a correct, sentinel-free floor.
                last_active: LastActive::new(opened_at),
                signon: e6irc_proto::time::Millis::from_millis(0),
                opened_at,
                awaiting_pong: false,
                deferred_replies: 0,
                history_requests_in_flight: 0,
                published: None,
                held: crate::core::HeldOutput::default(),
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
    fn debug_check_wire_line(&self, bytes: &Bytes) {
        if let Some(violation) = wire_line_violation(bytes) {
            panic!("{violation}: {:?}", String::from_utf8_lossy(bytes));
        }
    }

    /// Deliver bypassing labeled-response capture. Used for messages a
    /// connection *receives* (deliveries), which are never part of the
    /// labeled response to its own command — only direct replies are.
    pub fn send_bytes_uncaptured(&mut self, conn: ConnId, bytes: Bytes) {
        #[cfg(debug_assertions)]
        self.debug_check_wire_line(&bytes);
        // Hold this line behind an in-flight deferred reply, unless it *is*
        // that reply being emitted right now. Held output is bounded exactly
        // like the queue it is waiting to enter: overflowing it is a SendQ
        // kill, not unbounded growth.
        if self.emitting_deferred != Some(conn) {
            let sendq_bytes = self.config.sendq_bytes;
            match self.sessions.output_mut(&conn) {
                Some(session) if session.deferred_replies > 0 => {
                    if !session.held.hold(bytes, sendq_bytes) {
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
        match session.output.write(WireLine::sanitized(bytes)) {
            Ok(Written::Queued) => self.telemetry.record_irc_output(byte_count),
            Ok(Written::AfterGoodbye) => {}
            Err(_sendq_exceeded) => self.doomed.push(conn),
        }
    }

    /// Take one of `conn`'s database history slots; `false` when all are taken.
    pub(crate) fn history_request_started(&mut self, conn: ConnId) -> bool {
        let Some(session) = self.sessions.get_mut(&conn) else {
            return false;
        };
        if session.history_requests_in_flight >= MAX_HISTORY_REQUESTS_IN_FLIGHT {
            return false;
        }
        session.history_requests_in_flight += 1;
        true
    }

    /// The database answered one of `conn`'s history requests.
    pub(crate) fn history_request_finished(&mut self, conn: ConnId) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.history_requests_in_flight =
                session.history_requests_in_flight.saturating_sub(1);
        }
    }

    /// Note that a connection is now waiting on a database-backed reply, so
    /// its later output queues behind it.
    pub fn defer_reply(&mut self, conn: ConnId) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.deferred_replies += 1;
        }
    }

    /// Hold later output behind an asynchronous verdict and tell the capture
    /// collecting this command's replies that the verdict will answer it.
    /// Returns the label the reply must carry: a cross-shard command's result,
    /// or a database verdict, owns the deferred slot and the captured label.
    pub fn defer_captured_reply(&mut self, conn: ConnId) -> Option<String> {
        self.defer_reply(conn);
        self.defer_captured_label(conn)
    }

    /// Tell the capture collecting this command's replies that an answer will
    /// arrive asynchronously *without* holding the connection's later output
    /// behind it (a NickServ verdict, a multiline batch's close), and return
    /// the label that answer must carry. A NickServ verdict is emitted through
    /// [`Self::emit_labeled_unheld`], which gathers it with whatever the
    /// command answered on the spot.
    pub fn defer_captured_label(&mut self, conn: ConnId) -> Option<String> {
        self.capture
            .as_mut()
            .filter(|capture| capture.conn == conn)
            .and_then(Capture::defer)
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
        let captured = self.capture_lines(conn, &label, emit);
        match self.gather_labeled_answer(conn, &label, captured) {
            // This answer's hold is released; the response is not complete.
            None => self.release_deferred(conn),
            Some(lines) => self.emit_deferred(conn, |state| {
                super::handler::frame_labeled(state, conn, &label, lines);
            }),
        }
    }

    /// One asynchronous answer to a labeled command arrived. When the command
    /// left its answer to several paths, or answered part of it on the spot
    /// (see [`Self::await_labeled_answers`]), the pieces are gathered: `None`
    /// while others are outstanding, then every piece in arrival order.
    fn gather_labeled_answer(
        &mut self,
        conn: ConnId,
        label: &str,
        mut captured: Vec<Bytes>,
    ) -> Option<Vec<Bytes>> {
        let Some(session) = self.sessions.output_mut(&conn) else {
            return Some(captured);
        };
        let Some(group) = session.label_groups.get_mut(label) else {
            return Some(captured);
        };
        group.lines.append(&mut captured);
        group.outstanding -= 1;
        if group.outstanding > 0 {
            return None;
        }
        session.label_groups.remove(label).map(|group| group.lines)
    }

    /// A labeled command left `capture`'s answer to asynchronous paths. If it
    /// left it to several, or answered part of it on the spot, those pieces
    /// must still come out as the one response the label is promised.
    pub(crate) fn await_labeled_answers(&mut self, capture: Capture) {
        let Some(label) = capture.label else {
            return;
        };
        if capture.deferrals == 0 || (capture.deferrals == 1 && capture.lines.is_empty()) {
            return; // nothing to gather: the single answer frames itself
        }
        if let Some(session) = self.sessions.output_mut(&capture.conn) {
            session.label_groups.insert(
                label,
                LabelGroup {
                    outstanding: capture.deferrals,
                    lines: capture.lines,
                },
            );
        }
    }

    /// Run `emit` and return the lines it sent to `conn` instead of sending
    /// them (they route to the capture because it targets this conn), so a
    /// framer can tag or batch them — exactly as a synchronous labeled
    /// command's direct replies are captured in `dispatch`.
    pub(crate) fn capture_lines(
        &mut self,
        conn: ConnId,
        label: &str,
        emit: impl FnOnce(&mut Self),
    ) -> Vec<Bytes> {
        debug_assert!(self.capture.is_none(), "deferred reply nested in a capture");
        self.capture = Some(Capture::new(conn, Some(label.to_string()), None, None));
        emit(self);
        self.capture.take().map(|c| c.lines).unwrap_or_default()
    }

    /// A member whose session was gone before its JOIN was answered: the
    /// session's QUIT named only the channels it knew it was in, so this one
    /// never heard. Left alone the member counts toward `+l` forever and the
    /// channel can never empty. The others are told with a PART, which — unlike
    /// a second QUIT — cannot repeat what another shared channel already said.
    pub(crate) fn remove_vanished_member(&mut self, owner: &ChannelOwner, conn: ConnId) {
        assert_eq!(owner.shard(), self.shard, "departure reached wrong shard");
        let key = owner.key();
        let Some(channel) = self.channels.get_mut(key) else {
            return;
        };
        let Some((prefix, origin)) =
            channel
                .member_profiles()
                .find_map(|(member, _, identity, profile)| {
                    (member == conn).then(|| (identity.prefix.clone(), profile.originator()))
                })
        else {
            return;
        };
        channel.remove_member(conn);
        let line = EventLine::by(
            origin,
            (self.config.clock)(),
            format!(":{prefix} PART {}", channel.name),
        );
        self.memberships.part(conn, key);
        self.broadcast_channel(key, &line, None);
        if !self.channels[key].has_members() {
            self.remove_channel(key);
        }
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
                let captured = self.capture_lines(conn, &label, emit);
                if let Some(lines) = self.gather_labeled_answer(conn, &label, captured) {
                    super::handler::frame_labeled(self, conn, &label, lines);
                }
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

    fn reply_target(&self, conn: ConnId) -> String {
        self.capture
            .as_ref()
            .filter(|capture| capture.conn == conn)
            .and_then(|capture| capture.reply_target.clone())
            .or_else(|| {
                self.sessions
                    .get(&conn)
                    .and_then(|session| session.nick().map(String::from))
            })
            .unwrap_or_else(|| "*".into())
    }

    pub fn reply_caps(&self, conn: ConnId) -> Option<Caps> {
        self.capture
            .as_ref()
            .filter(|capture| capture.conn == conn)
            .and_then(|capture| capture.reply_caps)
            .or_else(|| self.sessions.get(&conn).map(|session| session.caps))
    }

    pub fn numeric(&mut self, conn: ConnId, code: u16, middle: &[&str], trailing: Option<&str>) {
        let line = self.numeric_line(conn, code, middle, trailing);
        self.send(conn, &line);
    }

    /// The line [`Self::numeric`] sends, without sending it.
    pub(crate) fn numeric_line(
        &self,
        conn: ConnId,
        code: u16,
        middle: &[&str],
        trailing: Option<&str>,
    ) -> String {
        let target = self.reply_target(conn);
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
        line
    }

    /// `:<server> NOTICE <target> :<text>`, from the server itself, without
    /// sending it; `text` is fitted to the line
    /// ([`server_notice`](crate::core::handler::server_notice)).
    pub(crate) fn server_notice_line(&self, conn: ConnId, text: &str) -> String {
        crate::core::handler::server_notice(
            &self.config.server_name,
            &self.reply_target(conn),
            text,
        )
    }

    /// Send a line straight to `conn`'s queue: past a labeled command's
    /// capture, and past output held behind a deferred reply. For a reply
    /// that is itself earlier than whatever the hold is waiting on — the rows
    /// of a LIST that is still being paced out.
    pub(crate) fn send_unheld(&mut self, conn: ConnId, bytes: Bytes) {
        let previous = self.emitting_deferred.replace(conn);
        self.send_bytes_uncaptured(conn, bytes);
        self.emitting_deferred = previous;
    }

    /// `conn`'s session's paced output of one kind, taken out by `take` to be
    /// sent, with how many more bytes its send queue takes before it is half
    /// full: the most a paced reply may occupy. `None` when there is none to
    /// send — which is also what a closed connection has, its paced output
    /// having gone with its session. What is left over goes back through
    /// [`Self::resume_paced`].
    pub(crate) fn take_paced<T>(
        &mut self,
        conn: ConnId,
        take: impl FnOnce(&mut Session) -> Option<T>,
    ) -> Option<(usize, T)> {
        let session = self.sessions.output_mut(&conn)?;
        let paced = take(session)?;
        Some((session.paced_room(), paced))
    }

    /// Queue a WHO reply to be paced out to `conn`, behind any already
    /// going. A closed connection's paced output went with its session
    /// (`ServerState::close`); so does this.
    pub(crate) fn queue_paced_who(&mut self, conn: ConnId, reply: crate::core::paced::PacedReply) {
        let Some(session) = self.sessions.output_mut(&conn) else {
            return;
        };
        session.paced_who.get_or_insert_default().push(reply);
        self.pacing.insert(conn);
    }

    /// Put `conn`'s paced output back, to be paced on as its send queue
    /// drains. A session that closed while it was out had its paced output
    /// go with it (`ServerState::close`); so does this.
    pub(crate) fn resume_paced<T>(
        &mut self,
        conn: ConnId,
        field: impl FnOnce(&mut Session) -> &mut Option<T>,
        paced: T,
    ) {
        let Some(session) = self.sessions.output_mut(&conn) else {
            return;
        };
        let previous = field(session).replace(paced);
        assert!(previous.is_none(), "paced output resumed over another");
        self.pacing.insert(conn);
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
    ///
    /// This and the two helpers below echo a name the *client* typed, so each
    /// renders it through [`clip_echo`](crate::core::handler::clip_echo) itself:
    /// no call site can forget to, and a trailing-form token with a space
    /// (`INVITE x :a b`) cannot split the reply's parameters.
    pub fn err_nosuchnick(&mut self, conn: ConnId, nick: &str) {
        let nick = crate::core::handler::clip_echo(nick);
        self.numeric(conn, ERR_NOSUCHNICK, &[nick], Some("No such nick/channel"));
    }

    /// `ERR_NOSUCHCHANNEL (<chan>) :No such channel`.
    pub fn err_nosuchchannel(&mut self, conn: ConnId, chan: &str) {
        let chan = crate::core::handler::clip_echo(chan);
        self.numeric(conn, ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
    }

    /// `ERR_NOTONCHANNEL (<chan>) :You're not on that channel`.
    pub fn err_notonchannel(&mut self, conn: ConnId, chan: &str) {
        let chan = crate::core::handler::clip_echo(chan);
        self.numeric(
            conn,
            ERR_NOTONCHANNEL,
            &[chan],
            Some("You're not on that channel"),
        );
    }

    /// `ERR_USERNOTINCHANNEL (<nick> <chan>) :They aren't on that channel`.
    /// `nick` is the client's token, rendered through
    /// [`clip_echo`](crate::core::handler::clip_echo) like the helpers above.
    pub fn err_usernotinchannel(&mut self, conn: ConnId, nick: &str, chan: &str) {
        let nick = crate::core::handler::clip_echo(nick);
        self.numeric(
            conn,
            ERR_USERNOTINCHANNEL,
            &[nick, chan],
            Some("They aren't on that channel"),
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
        let target = self.reply_target(conn);
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
        (now, self.msgids.next(now))
    }

    /// Unique reference for a batch (no associated event timestamp).
    pub fn next_msgid(&mut self) -> String {
        self.stamp().1
    }

    /// The originator tags of `conn`'s session as it is now.
    pub(crate) fn originator(&self, conn: ConnId) -> Originator {
        let session = &self.sessions[&conn];
        Originator {
            account: session.account.clone(),
            bot: session.bot,
        }
    }

    /// A line `conn` originated, stamped now.
    pub(crate) fn user_line(&self, conn: ConnId, body: impl Into<Arc<str>>) -> EventLine {
        EventLine::by(self.originator(conn), (self.config.clock)(), body)
    }

    /// A line the server originated, stamped now.
    pub(crate) fn server_line(&self, body: impl Into<Arc<str>>) -> EventLine {
        EventLine::by_server((self.config.clock)(), body)
    }

    /// Send an event line to one local session (labeled-response capture
    /// applies: this is the session's own answer).
    pub(crate) fn send_event(&mut self, conn: ConnId, line: &EventLine) {
        let Some(caps) = self.reply_caps(conn) else {
            return;
        };
        self.send_bytes(conn, line.render(caps));
    }

    /// Deliver an event line to one recipient on any shard (a delivery, not a
    /// response: labeled-response capture does not apply).
    pub(crate) fn send_event_recipient(&mut self, recipient: Recipient, line: &EventLine) {
        self.send_recipient_uncaptured(recipient, line.render(recipient.caps()));
    }

    /// Serialize once per capability variant, deliver to every member of
    /// a channel except `except`.
    pub(crate) fn broadcast_channel(
        &mut self,
        chan_key: &ChanKey,
        line: &EventLine,
        except: Option<ConnId>,
    ) {
        let Some(chan) = self.channels.get(chan_key) else {
            return;
        };
        debug_assert_eq!(self.channels.owner(chan_key).shard(), self.shard);
        let members = chan.recipients();
        self.broadcast_recipients(
            members
                .iter()
                .copied()
                .filter(|recipient| Some(recipient.conn()) != except),
            line,
        );
    }

    /// Broadcast `line` to `key`'s members for a command `actor` sent,
    /// leaving the actor out, and return the actor's copy when it is a
    /// member. That copy is part of the command's response: the actor's
    /// session emits it, inside the labeled response when the command was
    /// labeled, exactly where one worker's capture puts it — whichever shard
    /// owns the channel.
    pub(crate) fn broadcast_channel_answering(
        &mut self,
        key: &ChanKey,
        line: EventLine,
        actor: ConnId,
    ) -> Option<EventLine> {
        let member = self
            .channels
            .get(key)
            .is_some_and(|channel| channel.is_member(actor));
        self.broadcast_channel(key, &line, Some(actor));
        member.then_some(line)
    }

    /// Serialize once per capability variant, deliver to each recipient.
    fn broadcast_recipients(
        &mut self,
        recipients: impl IntoIterator<Item = Recipient>,
        line: &EventLine,
    ) {
        // Built lazily: a variant no recipient needs is never rendered.
        let mut rendered: [Option<Bytes>; 8] = Default::default();
        for recipient in recipients {
            let bytes = rendered[line.variant(recipient.caps())]
                .get_or_insert_with(|| line.render(recipient.caps()))
                .clone();
            // The connection a capture collects a response for is sent its
            // copy there, on whichever shard its session lives: a channel
            // owner answering another shard's command captures the actor's
            // copy of what the command broadcast, as one worker's dispatch
            // capture does, so it goes out inside the command's response
            // rather than after it.
            let captured = self
                .capture
                .as_ref()
                .is_some_and(|capture| capture.conn == recipient.conn());
            if recipient.shard() != self.shard && !captured {
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
    /// simply be lost. For the same reason what is *already* held is released
    /// first, in production order, exactly as [`Self::close`] does: the client
    /// is owed everything the server produced for it, then the ERROR. The
    /// sockets close when the `Core` is dropped immediately
    /// after this call, which drops every session's `Sender<Output>`; each write
    /// task then drains its queue — flushing this ERROR — before shutting the
    /// socket down.
    pub fn broadcast_shutdown(&mut self, reason: &str) {
        let line = format!(
            "ERROR :Closing Link: {} ({reason})",
            self.config.server_name
        );
        let bytes = Bytes::from(format!("{line}\r\n"));
        // The sessions stay until this worker stops — it still serves the
        // other shards while they drain — but for their clients this is the
        // last line (see `SessionOutput`).
        for session in self.sessions.closing_sessions_mut() {
            session.deferred_replies = 0;
            for held in std::mem::take(&mut session.held) {
                // A queue too full for it is a connection already lost, as for
                // the goodbye itself.
                drop(session.output.write(WireLine::sanitized(held)));
            }
            session
                .output
                .write_goodbye(WireLine::sanitized(bytes.clone()));
        }
    }

    /// The prefix a services pseudo-client (NickServ, ChanServ) speaks with,
    /// `Service!Service@services.<server>` — the one source for its notices
    /// and for the channel modes ChanServ sets (a mode lock, OP/VOICE, access
    /// on join), so a client sees one ChanServ however it acted.
    pub(crate) fn service_prefix(&self, service: &str) -> String {
        format!("{service}!{service}@services.{}", self.config.server_name)
    }

    /// A notice from a services pseudo-client (NickServ, ChanServ).
    pub fn service_notice(&mut self, conn: ConnId, service: &str, text: &str) {
        let nick = self
            .sessions
            .get(&conn)
            .and_then(|s| s.nick().map(String::from))
            .unwrap_or_else(|| "*".into());
        let source = self.service_prefix(service);
        // The text can quote the user's own input back (an unknown flag, a
        // channel name), so it is fitted like any other relayed trailing.
        let line = crate::core::handler::fitted_line(format!(":{source} NOTICE {nick} :"), text);
        let line = self.server_line(line);
        self.send_event(conn, &line);
    }

    /// Refuse `conn` at the end of registration when the SASL requirement
    /// covers it and it has not logged in ([`crate::config::SaslRequirement`]),
    /// as Libera refuses its SASL-only ranges: 465 saying why, then
    /// `ERROR :Closing Link: <host> (SASL access only)`. Returns whether it
    /// was refused.
    pub(crate) fn refuse_unauthenticated(&mut self, conn: ConnId) -> bool {
        let session = &self.sessions[&conn];
        if session.account().is_some()
            || session.transport == crate::core::ConnectionTransport::Local
            || !self.config.sasl_requirement.covers(session.real_ip)
        {
            return false;
        }
        let host = session.host.clone();
        self.numeric(
            conn,
            e6irc_proto::numerics::ERR_YOUREBANNEDCREEP,
            &[],
            Some("You need to identify via SASL to use this server"),
        );
        self.send(
            conn,
            &format!("ERROR :Closing Link: {host} (SASL access only)"),
        );
        self.close(conn, "SASL access only");
        true
    }

    // ---- teardown -------------------------------------------------------

    /// Remove a session: broadcast QUIT to channel peers, free the nick,
    /// drop memberships and empty channels.
    pub fn close(&mut self, conn: ConnId, reason: &str) {
        let Some(session) = self.sessions.get(&conn) else {
            return;
        };
        // Its paced LIST and WHO replies go with the session itself.
        self.pacing.remove(&conn);
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
            self.user_line(conn, format!("{head}{reason}"))
        });
        if let Some(line) = quit_line {
            let owners = self.session_channels_by_shard(conn);
            let event = self.user_event(conn, line, UserEventAudience::Everyone, owners.len());
            for channels in owners {
                let quit = ChannelQuit::new(channels, event.clone());
                if quit.shard() == self.shard {
                    self.quit_channel_member(quit);
                } else {
                    self.route_quit(quit);
                }
            }
        }
        let session = self.sessions.remove(&conn).expect("checked above");
        if let Some(account) = &session.account {
            self.forget_account_session(account, conn);
        }
        self.memberships.release(conn);
        for key in session.monitoring.keys() {
            self.monitors.unwatch(key, conn);
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
                self.release_unauthenticated_identity(nick);
            }
        }
    }

    /// Log `conn` in to `account` — the one way a session gains an account.
    ///
    /// It is also the one place the client is told: RPL_LOGGEDIN (900) is
    /// "sent when the user's account name is set (whether by SASL or
    /// otherwise)", so SASL, NickServ IDENTIFY and account registration all
    /// announce the login the same way by passing through here.
    ///
    /// Its identity changes with it: it was `~nick`, the identity of whoever
    /// holds the nick without an account, and is the account from here on.
    /// `~nick` is therefore let go now, exactly as when an unauthenticated
    /// connection leaves or changes nick, and every shard frees the
    /// conversations kept under it — or the next person to take the nick would
    /// read them. A session already logged in keeps nothing under `~nick`, so
    /// changing accounts releases nothing.
    pub(crate) fn set_account(&mut self, conn: ConnId, account: String) {
        let key = self.account_key(&account);
        let session = self.sessions.get_mut(&conn).expect("session logging in");
        let released = session
            .account
            .is_none()
            .then(|| session.nick().map(str::to_owned))
            .flatten();
        let mask = session.login_mask();
        let previous = session.account.replace(account.clone());
        if let Some(previous) = previous {
            self.forget_account_session(&previous, conn);
        }
        self.numeric(
            conn,
            RPL_LOGGEDIN,
            &[&mask, &account],
            Some(&format!("You are now logged in as {account}")),
        );
        // Identifying to the account protecting a nick settles its clock
        // (NickServ ENFORCE) — the held one's enforcement ends; identifying
        // to any other account settles nothing.
        let settled: Vec<NickKey> = self.sessions[&conn]
            .nick_enforcement
            .clocked()
            .into_iter()
            .filter(|nick| {
                self.nick_protector(nick)
                    .is_none_or(|protector| protector == key)
            })
            .collect();
        let enforcement = &mut self
            .sessions
            .get_mut(&conn)
            .expect("session logging in")
            .nick_enforcement;
        for nick in &settled {
            enforcement.settle(nick);
        }
        self.account_sessions.entry(key).or_default().insert(conn);
        if let Some(nick) = released {
            self.release_unauthenticated_identity(&nick);
        }
    }

    /// Log `conn` out: it is `~nick` again from here on. The client is told
    /// with RPL_LOGGEDOUT (901), sent "when the account name is unset (whether
    /// by SASL or otherwise)".
    pub(crate) fn clear_account(&mut self, conn: ConnId) {
        let session = self.sessions.get_mut(&conn).expect("session logging out");
        let mask = session.login_mask();
        let Some(previous) = session.account.take() else {
            return;
        };
        self.forget_account_session(&previous, conn);
        self.numeric(
            conn,
            RPL_LOGGEDOUT,
            &[&mask],
            Some("You are now logged out"),
        );
    }

    /// An unauthenticated session has let go of `nick` — by leaving, by
    /// changing nick, or by logging in — and with it the `~nick` identity.
    /// Every shard frees the conversations kept with it (each party's shard
    /// keeps a copy).
    pub(crate) fn release_unauthenticated_identity(&mut self, nick: &str) {
        let identity = format!("~{}", self.casemap.casefold(nick));
        self.forget_unauthenticated_identity(&identity);
        self.effects
            .push(CoreEffect::BroadcastIdentityReleased { identity });
    }

    /// Free this shard's direct-message rings of a released `~nick` identity:
    /// a lookup of that identity's conversations, not a pass over every ring.
    pub(crate) fn forget_unauthenticated_identity(&mut self, identity: &str) {
        self.history.forget_identity(identity);
    }

    /// Apply a registered session's departure on the channel-owning shard.
    /// A preceding PART can have removed the member while its response was in
    /// flight to the closing session; that makes this departure already applied
    /// to that channel.
    pub fn quit_channel_member(&mut self, quit: ChannelQuit) {
        assert_eq!(quit.shard(), self.shard, "QUIT reached wrong channel shard");
        let mut peers = Peers::of(quit.event.subject);
        for key in quit.channels.keys() {
            let removed = self
                .channels
                .get_mut(key)
                .and_then(|channel| channel.remove_member(quit.event.subject));
            if removed.is_none() {
                continue;
            }
            peers.extend_channel(&self.channels[key], &quit.event, &self.config.server_name);
            if !self.channels[key].has_members() {
                self.remove_channel(key);
            }
        }
        self.send_user_event_parts(&quit.event, peers);
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
/// included) would be discarded by the recipient's framing. Every recipient
/// holds every line to it — `draft/multiline` does not relax the per-line
/// limit; a long line inside a batch is split with `draft/multiline-concat`.
#[cfg(debug_assertions)]
fn wire_line_violation(line: &[u8]) -> Option<String> {
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
    if body.len() > MAX_LINE_LEN {
        return Some(format!(
            "outbound line's traditional part is {} bytes (limit {MAX_LINE_LEN}) — a client's \
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
    fn holds_the_traditional_limit() {
        let fits = format!(":s PRIVMSG #c :{}\r\n", "x".repeat(490));
        assert!(fits.len() <= 512);
        assert!(wire_line_violation(fits.as_bytes()).is_none());

        let over = format!(":s PRIVMSG #c :{}\r\n", "x".repeat(500));
        assert!(over.len() > 512);
        assert!(wire_line_violation(over.as_bytes()).is_some());

        // Tags spend the tag budget, not the traditional one.
        let tagged = format!("@time=x;msgid=y :s PRIVMSG #c :{}\r\n", "x".repeat(490));
        assert!(wire_line_violation(tagged.as_bytes()).is_none());
        let huge_tags = format!("@a={} :s PING\r\n", "t".repeat(9000));
        assert!(wire_line_violation(huge_tags.as_bytes()).is_some());
    }
}

#[cfg(test)]
mod nick_enforcement_tests {
    use super::{NickEnforcement, NickKey};
    use e6irc_proto::time::MonoMillis;

    /// Cycling through more protected nicks than a session tracks never buys
    /// a clock later than the earliest it already had, and the tracked set
    /// stays bounded.
    #[test]
    fn cycling_through_many_nicks_never_restarts_a_clock() {
        let mut enforcement = NickEnforcement::default();
        let first = enforcement.deadline(&NickKey("n0".into()), MonoMillis::from_millis(100));
        assert_eq!(first, MonoMillis::from_millis(100));
        for (index, fresh) in (1..40u64).map(|index| (index, 100 + index * 10)) {
            let nick = NickKey(format!("n{index}"));
            let deadline = enforcement.deadline(&nick, MonoMillis::from_millis(fresh));
            if index >= NickEnforcement::TRACKED as u64 {
                assert_eq!(deadline, first, "nick {index} got a fresh clock");
            }
            assert!(enforcement.clocked().len() <= NickEnforcement::TRACKED);
        }
        // A nick still tracked keeps its own deadline.
        assert_eq!(
            enforcement.deadline(&NickKey("n0".into()), MonoMillis::from_millis(9_999)),
            first
        );
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
                command_flood: None,
                registration_burst: None,
                sasl_requirement: Default::default(),
                reserved_account_names: crate::identity::ReservedAccountNames::default(),
            },
            db_tx,
            Arc::new(Telemetry::new()),
            CoreDirectories::default(),
        )
    }

    fn register(state: &mut ServerState, conn: ConnId, nick: &str) {
        open(state, conn);
        for line in [format!("NICK {nick}"), format!("USER {nick} 0 * :{nick}")] {
            crate::core::handler::dispatch(state, conn, line.as_bytes());
        }
    }

    /// The count the core reports after every event follows each way a session
    /// starts or stops being registered. (`registered_len` also checks itself
    /// against a full count in debug builds, so every other test checks it too.)
    #[test]
    fn registered_count_follows_registration_close_and_kill() {
        let mut state = state();
        open(&mut state, ConnId(1));
        assert_eq!(state.sessions.registered_len(), 0, "open, not registered");

        register(&mut state, ConnId(2), "alice");
        register(&mut state, ConnId(3), "bob");
        assert_eq!(state.sessions.registered_len(), 2);
        // Completing a registration twice counts it once.
        state.sessions.complete_registration(&ConnId(2));
        assert_eq!(state.sessions.registered_len(), 2);

        state.close(ConnId(1), "never registered");
        assert_eq!(state.sessions.registered_len(), 2);
        state.close(ConnId(2), "Client Quit");
        assert_eq!(state.sessions.registered_len(), 1);
        register(&mut state, ConnId(5), "oper");
        state.sessions.get_mut(&ConnId(5)).expect("oper").oper = Some("god".into());
        crate::core::handler::dispatch(&mut state, ConnId(5), b"KILL bob :bye");
        assert!(state.sessions.get(&ConnId(3)).is_none(), "bob was killed");
        assert_eq!(state.sessions.registered_len(), 1, "only the operator");
        // A reused slot starts unregistered again.
        open(&mut state, ConnId(4));
        assert_eq!(state.sessions.registered_len(), 1);
    }

    #[test]
    fn membership_directory_tracks_shared_channels_and_departures() {
        let directory = MembershipDirectory::default();
        let channel = ChanKey("#chat".into());
        let alice = ConnId(1);
        let bob = ConnId(2);
        directory.join(alice, channel.clone());
        directory.join(bob, channel.clone());
        assert!(directory.shares(alice, bob));
        directory.part(bob, &channel);
        assert!(!directory.shares(alice, bob));
        directory.join(bob, channel);
        directory.release(alice);
        assert!(!directory.shares(alice, bob));
    }

    fn open(state: &mut ServerState, conn: ConnId) {
        let (tx, _rx) = crate::core::send_queue("session-store-output", 512);
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
        let mut channel = Channel::for_test("#chat", ChanModes::default());
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
            e6irc_proto::time::MonoMillis::from_millis(1),
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
            e6irc_proto::time::MonoMillis::from_millis(1),
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
        let mut channel = Channel::for_test("#chat", ChanModes::default());
        channel.add_member(
            Recipient::new(
                SessionOwner::new(ConnId(2), CoreShardId(1)),
                Caps::default(),
            ),
            MemberIdentity::new("[Alice]".into(), "[Alice]!u@h".into(), false),
            MemberModes::default(),
            e6irc_proto::time::MonoMillis::from_millis(1),
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
        let mut channel = Channel::for_test("#chat", ChanModes::default());
        channel.add_member(
            recipient,
            MemberIdentity::new("one".into(), "one!u@h".into(), false),
            MemberModes::default(),
            e6irc_proto::time::MonoMillis::from_millis(1),
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
        let mut channel = Channel::for_test("#chat", ChanModes::default());
        channel.add_member(
            Recipient {
                owner: SessionOwner::new(ConnId(9), CoreShardId(1)),
                caps: Caps {
                    server_time: true,
                    account_tag: true,
                    ..Caps::default()
                },
            },
            MemberIdentity::new("remote".into(), "remote!u@h".into(), false),
            MemberModes::default(),
            e6irc_proto::time::MonoMillis::from_millis(1),
        );
        state.channels.entry(key.clone()).or_insert(channel);

        let origin = Originator {
            account: Some("nickacct".into()),
            bot: false,
        };
        let line = EventLine::by(
            origin,
            e6irc_proto::time::Millis::from_millis(0),
            ":nick JOIN #chat",
        );
        state.broadcast_channel(&key, &line, None);

        let effects = state.take_effects();
        assert_eq!(effects.len(), 1);
        let crate::core::CoreEffect::Delivery { owner, line } = &effects[0] else {
            panic!("expected delivery effect");
        };
        assert_eq!(*owner, SessionOwner::new(ConnId(9), CoreShardId(1)));
        assert_eq!(
            &line[..],
            b"@time=1970-01-01T00:00:00.000Z;account=nickacct :nick JOIN #chat\r\n"
        );
    }

    #[test]
    fn msgids_differ_across_shards_and_restarts_at_the_same_instant() {
        let now = e6irc_proto::time::Millis::from_millis(1_000);
        let mut first = MsgidSource::with_boot(CoreShardId(0), 7);
        let mut other_shard = MsgidSource::with_boot(CoreShardId(1), 7);
        let mut restarted = MsgidSource::with_boot(CoreShardId(0), 8);
        let ids = [
            first.next(now),
            other_shard.next(now),
            restarted.next(now),
            first.next(now),
        ];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "{ids:?}");
        // Tag-safe: no character that needs escaping in a tag value.
        assert!(
            ids.iter()
                .all(|id| id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        );
        // Two real sources (random boot values) never agree either.
        assert_ne!(
            MsgidSource::new(CoreShardId(0)).next(now),
            MsgidSource::new(CoreShardId(0)).next(now)
        );
    }

    #[test]
    fn event_tags_render_every_originator_tag_the_recipient_negotiated() {
        let origin = Originator {
            account: Some("a\\b".into()),
            bot: true,
        };
        let line = EventLine::by(
            origin,
            e6irc_proto::time::Millis::from_millis(0),
            ":n MODE #c +o x",
        );
        let everything = Caps {
            server_time: true,
            account_tag: true,
            message_tags: true,
            ..Caps::default()
        };
        assert_eq!(
            &line.render(everything)[..],
            b"@time=1970-01-01T00:00:00.000Z;account=a\\\\b;bot :n MODE #c +o x\r\n"
        );
        // `bot` rides message-tags; `account` needs only account-tag.
        let account_only = Caps {
            account_tag: true,
            ..Caps::default()
        };
        assert_eq!(
            &line.render(account_only)[..],
            b"@account=a\\\\b :n MODE #c +o x\r\n"
        );
        assert_eq!(&line.render(Caps::default())[..], b":n MODE #c +o x\r\n");
        // A server-originated line carries no originator tags at all.
        let server =
            EventLine::by_server(e6irc_proto::time::Millis::from_millis(0), ":s MODE #c +o x");
        assert_eq!(
            &server.render(everything)[..],
            b"@time=1970-01-01T00:00:00.000Z :s MODE #c +o x\r\n"
        );
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

    /// Every distinct (account, target) pair confirmed or in flight is one
    /// slot: the count kept at the write sites equals a recount of the maps
    /// after every kind of write, and never goes stale or negative.
    #[test]
    fn read_marker_slots_equal_a_recount_after_every_write() {
        fn recount(state: &ServerState, account: &AccountKey) -> usize {
            state
                .read_markers
                .keys()
                .chain(state.pending_read_markers.keys())
                .filter(|(a, _)| a == account)
                .map(|(_, target)| target.clone())
                .collect::<HashSet<_>>()
                .len()
        }
        fn key(state: &ServerState, account: &str, target: &str) -> (AccountKey, ChanKey) {
            (state.account_key(account), state.chan_key(target))
        }
        let ms = |n: u64| e6irc_proto::time::Millis::from_millis(n);
        let mut state = state();
        let alice = state.account_key("Alice");
        let bob = state.account_key("bob");
        let check = |state: &ServerState, expect_alice: usize, expect_bob: usize| {
            assert_eq!(state.read_marker_slots(&alice), recount(state, &alice));
            assert_eq!(state.read_marker_slots(&bob), recount(state, &bob));
            assert_eq!(state.read_marker_slots(&alice), expect_alice);
            assert_eq!(state.read_marker_slots(&bob), expect_bob);
        };
        check(&state, 0, 0);

        // The live MARKREAD sequence: reserve (twice, pipelined), confirm, release.
        state.reserve_read_marker(key(&state, "alice", "#a"));
        state.reserve_read_marker(key(&state, "ALICE", "#A"));
        check(&state, 1, 0);
        state
            .release_read_marker(&key(&state, "alice", "#a"))
            .expect("reserved");
        assert_eq!(
            state.store_read_marker(key(&state, "alice", "#a"), ms(1)),
            None
        );
        state
            .release_read_marker(&key(&state, "alice", "#a"))
            .expect("reserved");
        check(&state, 1, 0);
        // Confirmed then reserved again: still one slot, before and after.
        state.reserve_read_marker(key(&state, "alice", "#a"));
        check(&state, 1, 0);
        state
            .release_read_marker(&key(&state, "alice", "#a"))
            .expect("reserved");
        check(&state, 1, 0);
        // A reservation that never confirms gives its slot back.
        state.reserve_read_marker(key(&state, "alice", "#b"));
        check(&state, 2, 0);
        state
            .release_read_marker(&key(&state, "alice", "#b"))
            .expect("reserved");
        check(&state, 1, 0);
        // Accounts are counted apart; a forward move is not a new slot.
        state.store_read_marker(key(&state, "bob", "#a"), ms(1));
        assert_eq!(
            state.store_read_marker(key(&state, "bob", "#a"), ms(2)),
            Some(ms(1))
        );
        check(&state, 1, 1);
        // A reply with no reservation is refused and changes nothing.
        assert!(
            state
                .release_read_marker(&key(&state, "bob", "#never"))
                .is_err()
        );
        check(&state, 1, 1);

        // Preload replaces the confirmed markers and keeps in-flight
        // reservations; casing variants of one account fold to one slot.
        state.reserve_read_marker(key(&state, "alice", "#c"));
        check(&state, 2, 1);
        state.preload_read_markers(vec![
            ("Alice".into(), "#x".into(), ms(5)),
            ("alice".into(), "#x".into(), ms(6)),
            ("alice".into(), "#y".into(), ms(7)),
            ("bob".into(), "#z".into(), ms(8)),
        ]);
        check(&state, 3, 1);
        assert_eq!(state.read_marker(&key(&state, "alice", "#a")), None);
        assert_eq!(state.read_marker(&key(&state, "ALICE", "#x")), Some(ms(6)));
        state
            .release_read_marker(&key(&state, "alice", "#c"))
            .expect("reserved across the preload");
        check(&state, 2, 1);

        // Deleting an account forgets its confirmed markers, keeps a write in
        // flight counted, and leaves every other account alone.
        state.reserve_read_marker(key(&state, "alice", "#x"));
        state.forget_deleted_account("ALICE", &[]);
        check(&state, 1, 1);
        assert_eq!(state.read_marker(&key(&state, "alice", "#x")), None);
        assert_eq!(state.read_marker(&key(&state, "alice", "#y")), None);
        assert_eq!(state.read_marker(&key(&state, "bob", "#z")), Some(ms(8)));
        // The write in flight answers after the deletion: its confirmation is
        // not stored for an account that no longer exists, and reads as
        // already current so nothing fans it out.
        assert_eq!(
            state.store_read_marker(key(&state, "alice", "#x"), ms(9)),
            Some(ms(9))
        );
        assert_eq!(state.read_marker(&key(&state, "alice", "#x")), None);
        state
            .release_read_marker(&key(&state, "alice", "#x"))
            .expect("reserved across the deletion");
        check(&state, 0, 1);
    }

    /// The account → connections index equals a scan of every session after
    /// each way a session's account changes, and holds no empty entries.
    #[test]
    fn account_index_equals_a_scan_after_login_logout_and_close() {
        fn scan(state: &ServerState, account: &str) -> Vec<ConnId> {
            let want = state.casemap.casefold(account);
            let mut out: Vec<ConnId> = state
                .sessions
                .iter()
                .filter(|(_, s)| {
                    s.account()
                        .is_some_and(|a| state.casemap.casefold(a) == want)
                })
                .map(|(c, _)| *c)
                .collect();
            out.sort_by_key(|c| c.0);
            out
        }
        fn indexed(state: &ServerState, account: &str) -> Vec<ConnId> {
            let mut out = state.account_connections(account);
            out.sort_by_key(|c| c.0);
            out
        }
        let check = |state: &ServerState| {
            for account in ["alice", "ALICE", "Carol", "nobody"] {
                assert_eq!(indexed(state, account), scan(state, account), "{account}");
            }
            assert!(
                state.account_sessions.values().all(|s| !s.is_empty()),
                "no empty index entries"
            );
        };
        let mut state = state();
        register(&mut state, ConnId(1), "alice");
        register(&mut state, ConnId(2), "bob");
        register(&mut state, ConnId(3), "carol");
        check(&state);
        state.set_account(ConnId(1), "Alice".into());
        state.set_account(ConnId(2), "alice".into());
        state.set_account(ConnId(3), "carol".into());
        check(&state);
        assert_eq!(indexed(&state, "ALICE"), vec![ConnId(1), ConnId(2)]);
        // Changing account moves the connection between entries.
        state.set_account(ConnId(2), "carol".into());
        check(&state);
        assert_eq!(indexed(&state, "carol"), vec![ConnId(2), ConnId(3)]);
        // Re-setting the same account is idempotent.
        state.set_account(ConnId(2), "Carol".into());
        check(&state);
        assert_eq!(indexed(&state, "carol"), vec![ConnId(2), ConnId(3)]);
        state.clear_account(ConnId(1));
        check(&state);
        assert!(indexed(&state, "alice").is_empty());
        state.close(ConnId(3), "bye");
        check(&state);
        assert_eq!(indexed(&state, "carol"), vec![ConnId(2)]);
        state.close(ConnId(2), "bye");
        check(&state);
        assert!(state.account_sessions.is_empty());
    }

    /// The user directory's account index and LUSERS counters equal a
    /// recount of its records after every kind of change a published record
    /// goes through: registration, login, account change, mode, operator
    /// status, logout and departure.
    #[test]
    fn user_directory_indexes_equal_a_recount_after_every_change() {
        let mut state = state();
        let step = |state: &mut ServerState| {
            state.publish_changed_sessions();
            state.users.assert_consistent();
        };
        register(&mut state, ConnId(1), "alice");
        register(&mut state, ConnId(2), "bob");
        step(&mut state);
        assert_eq!(state.user_counts().users, 2);
        state.set_account(ConnId(1), "Alice".into());
        step(&mut state);
        assert_eq!(state.identity_nick("alice"), "alice");
        state.set_account(ConnId(2), "carol".into());
        step(&mut state);
        assert_eq!(state.identity_nick("carol"), "bob");
        state.set_account(ConnId(2), "ALICE".into());
        step(&mut state);
        assert_eq!(state.identity_nick("carol"), "carol", "no one is carol now");
        crate::core::handler::dispatch(&mut state, ConnId(2), b"MODE bob +i");
        state.sessions.get_mut(&ConnId(1)).expect("alice").oper = Some("god".into());
        step(&mut state);
        assert_eq!(
            state.user_counts(),
            UserCounts {
                users: 2,
                invisible: 1,
                opers: 1,
            }
        );
        state.clear_account(ConnId(1));
        step(&mut state);
        assert_eq!(state.identity_nick("alice"), "bob");
        state.close(ConnId(2), "bye");
        step(&mut state);
        assert_eq!(
            state.identity_nick("alice"),
            "alice",
            "offline: the identity"
        );
        assert_eq!(
            state.user_counts(),
            UserCounts {
                users: 1,
                invisible: 0,
                opers: 1,
            }
        );
        state.close(ConnId(1), "bye");
        step(&mut state);
        assert_eq!(state.user_counts(), UserCounts::default());
    }

    /// A channel message changes only the channel's newest-message time, and
    /// only that is republished: the message leaves the channel's whole record
    /// untouched, and the published time is the ring's newest.
    #[test]
    fn a_message_republishes_only_the_channels_latest_message() {
        let mut state = state();
        register(&mut state, ConnId(1), "alice");
        crate::core::handler::dispatch(&mut state, ConnId(1), b"JOIN #c");
        state.publish_changed_channels();
        let key = state.chan_key("#c");
        let text = crate::core::HistoryScope::Text;
        assert_eq!(state.channel_activity(&key, text), None, "no message yet");
        crate::core::handler::dispatch(&mut state, ConnId(1), b"PRIVMSG #c :hi");
        assert!(
            state.channels.touched.is_empty(),
            "a message must not mark the channel's whole record stale"
        );
        assert_eq!(state.channels.activity_touched, vec![key.clone()]);
        state.publish_changed_channels();
        let latest = state
            .history
            .get(&HistoryKey::from(&key))
            .and_then(|ring| ring.latest().in_scope(text));
        assert!(latest.is_some());
        assert_eq!(state.channel_activity(&key, text).map(|(_, ts)| ts), latest);
        state.history.assert_consistent();
    }
}
