//! The hot history store: one newest-last ring per channel or direct-message
//! conversation, each bounded in entries and in bytes, under one
//! least-recently-active cap on rings and one on the bytes of them all.
//!
//! Every question asked of it per event is answered from an index kept where
//! the store changes, never by a pass over every ring:
//!
//! - which ring to evict comes from a [`Recency`] order (not a search of a
//!   list of keys on every message);
//! - which conversations an identity takes part in comes from `conversations`
//!   (not a split of every key on every disconnect or CHATHISTORY TARGETS);
//! - a ring's newest timestamp, in each [`HistoryScope`], comes from a running
//!   window maximum (not a pass over its entries each time a channel is
//!   published or CHATHISTORY TARGETS asks);
//! - the bytes a ring, and the store, hold are running sums kept as entries
//!   come and go (not a recount on every message).

use std::collections::{HashMap, HashSet, VecDeque};

use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::time::Millis;

use super::HistoryScope;
use super::state::{HistoryEntry, HistoryKey};
use crate::recency::Recency;

/// Ring capacity per target; older entries live only in PostgreSQL.
pub(crate) const HISTORY_RING_CAP: usize = 500;

/// What bounds the store: rings held at once (`max_hot_channels`), the bytes
/// one ring may hold (`max_history_ring_bytes`) and the bytes of every ring
/// together (`max_hot_history_bytes`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct HotHistoryBounds {
    pub rings: usize,
    pub ring_bytes: usize,
    pub bytes: usize,
}

/// The bytes `entry` holds in a ring: its own fields and the text they own.
/// Every string counts by its length, so what a client controls — its body,
/// its client-only tags, a multiline message's lines — counts in full.
pub(crate) fn footprint(entry: &HistoryEntry) -> usize {
    std::mem::size_of::<HistoryEntry>()
        + entry.msgid.len()
        + entry.sender_prefix.len()
        + entry.sender_account.as_ref().map_or(0, String::len)
        + entry.body.len()
        + entry.multiline.as_ref().map_or(0, String::len)
        + entry.client_tags.len()
}

/// One target's newest-last hot history.
pub(crate) struct HistoryRing {
    entries: VecDeque<HistoryEntry>,
    /// True while the ring holds *every* message this target has ever seen
    /// (never overflowed, never evicted). When false, older history lives
    /// only in Postgres and CHATHISTORY must fall back.
    complete: bool,
    /// Position of `entries.front()` in the sequence of entries this ring has
    /// held since it was last rebuilt; `entries[i]` is at `first + i`.
    first: u64,
    /// The newest timestamp of the entries held, in every scope.
    maxima: ScopedMaxima,
    /// The [`footprint`] of the entries held.
    bytes: usize,
}

/// A buffer's newest activity as each [`HistoryScope`] sees it: a reader
/// without `message-tags` cannot be sent a TAGMSG, so a buffer whose newest
/// entry is one is dated by its newest *text* entry for them — and a buffer
/// holding only TAGMSGs has no activity at all in their scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Latest {
    text: Option<Millis>,
    text_and_tags: Option<Millis>,
}

impl Latest {
    /// The newest entry a reader in `scope` can be sent, if any.
    pub(crate) fn in_scope(self, scope: HistoryScope) -> Option<Millis> {
        match scope {
            HistoryScope::Text => self.text,
            HistoryScope::TextAndTags => self.text_and_tags,
        }
    }
}

/// The sliding-window maximum of some of a ring's timestamps: `(position,
/// ts)` with strictly decreasing `ts`, front the newest timestamp still held.
/// Timestamps come from wall clocks (and from other shards'), so arrival
/// order is not timestamp order and the back entry is not the newest.
#[derive(Default)]
struct WindowMax(VecDeque<(u64, Millis)>);

impl WindowMax {
    fn newest(&self) -> Option<Millis> {
        self.0.front().map(|&(_, ts)| ts)
    }

    fn push(&mut self, at: u64, ts: Millis) {
        while self.0.back().is_some_and(|&(_, newer)| newer <= ts) {
            self.0.pop_back();
        }
        self.0.push_back((at, ts));
    }

    /// The entry at position `at` left the front of the ring.
    fn expire(&mut self, at: u64) {
        if self.0.front().is_some_and(|&(front, _)| front == at) {
            self.0.pop_front();
        }
    }
}

/// One [`WindowMax`] per [`HistoryScope`], each over the entries that scope
/// admits, so every scope's newest entry is a constant-time read.
#[derive(Default)]
struct ScopedMaxima {
    text: WindowMax,
    text_and_tags: WindowMax,
}

impl ScopedMaxima {
    fn scopes(&mut self) -> [(HistoryScope, &mut WindowMax); 2] {
        [
            (HistoryScope::Text, &mut self.text),
            (HistoryScope::TextAndTags, &mut self.text_and_tags),
        ]
    }

    fn push(&mut self, at: u64, entry: &HistoryEntry) {
        for (scope, maxima) in self.scopes() {
            if scope.admits(entry.kind) {
                maxima.push(at, entry.ts);
            }
        }
    }

    fn expire(&mut self, at: u64) {
        for (_, maxima) in self.scopes() {
            maxima.expire(at);
        }
    }

    fn latest(&self) -> Latest {
        Latest {
            text: self.text.newest(),
            text_and_tags: self.text_and_tags.newest(),
        }
    }
}

impl HistoryRing {
    fn new(complete: bool) -> Self {
        Self {
            entries: VecDeque::new(),
            complete,
            first: 0,
            maxima: ScopedMaxima::default(),
            bytes: 0,
        }
    }

    pub(crate) fn entries(&self) -> &VecDeque<HistoryEntry> {
        &self.entries
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    /// The newest timestamp among the entries held, in every scope, in
    /// constant time.
    pub(crate) fn latest(&self) -> Latest {
        self.maxima.latest()
    }

    /// Append `entry`, then drop the oldest entries while the ring holds more
    /// than [`HISTORY_RING_CAP`] of them or more than `budget` bytes — never
    /// the entry just appended, so a ring always holds its newest line.
    fn push(&mut self, entry: HistoryEntry, budget: usize) {
        let at = self.first + self.entries.len() as u64;
        self.maxima.push(at, &entry);
        self.bytes += footprint(&entry);
        self.entries.push_back(entry);
        while self.entries.len() > HISTORY_RING_CAP
            || (self.bytes > budget && self.entries.len() > 1)
        {
            let oldest = self
                .entries
                .pop_front()
                .expect("a ring over its bounds holds entries");
            self.bytes -= footprint(&oldest);
            self.maxima.expire(self.first);
            self.first += 1;
            self.complete = false;
        }
    }

    /// Keep only the entries `keep` admits. A rare, whole-ring operation (an
    /// account's erasure), so the window maximum and the byte count are simply
    /// rebuilt; the ring only shrinks, so no bound can be newly exceeded.
    fn retain(&mut self, keep: impl FnMut(&HistoryEntry) -> bool) -> bool {
        let before = self.entries.len();
        self.entries.retain(keep);
        if self.entries.len() == before {
            return false;
        }
        let entries = std::mem::take(&mut self.entries);
        let complete = self.complete;
        *self = Self::new(complete);
        for entry in entries {
            self.push(entry, usize::MAX);
        }
        true
    }
}

/// Hot history rings, keyed by channel or direct-message conversation.
/// Channels and conversations share one store, one LRU and one cap, so the
/// ring, overflow and eviction rules cannot drift apart between them.
#[derive(Default)]
pub(crate) struct HotHistory {
    rings: HashMap<HistoryKey, HistoryRing>,
    /// The keys of `rings`, least recently active first.
    recency: Recency<HistoryKey>,
    /// Identity → the conversation keys in `rings` it takes part in. Kept by
    /// [`HotHistory::insert`] and [`HotHistory::remove`], the only two places
    /// a ring comes or goes.
    conversations: HashMap<String, HashSet<HistoryKey>>,
    /// The bytes of every ring together: the sum of their `bytes`.
    bytes: usize,
}

impl HotHistory {
    pub(crate) fn get(&self, key: &HistoryKey) -> Option<&HistoryRing> {
        self.rings.get(key)
    }

    /// Append to `key`'s ring, creating it (complete when `whole_record`) if
    /// absent, and make it the most recently active. The ring sheds its oldest
    /// entries past its own bounds; then rings are evicted least recently
    /// active first while there are more than `bounds.rings` of them or they
    /// hold more than `bounds.bytes` together — never the ring just appended
    /// to. The evicted rings' keys are returned.
    pub(crate) fn push(
        &mut self,
        key: &HistoryKey,
        entry: HistoryEntry,
        whole_record: bool,
        bounds: HotHistoryBounds,
    ) -> Vec<HistoryKey> {
        let held = match self.rings.get_mut(key) {
            Some(ring) => {
                self.bytes -= ring.bytes;
                ring.push(entry, bounds.ring_bytes);
                ring.bytes
            }
            None => {
                let mut ring = HistoryRing::new(whole_record);
                ring.push(entry, bounds.ring_bytes);
                let held = ring.bytes;
                self.insert(key.clone(), ring);
                held
            }
        };
        self.bytes += held;
        self.recency.touch(key);
        let mut evicted = Vec::new();
        while self.recency.len() > bounds.rings
            || (self.bytes > bounds.bytes && self.recency.len() > 1)
        {
            let cold = self
                .recency
                .pop_oldest()
                .expect("recency holds more keys than the cap");
            self.forget_ring(&cold);
            evicted.push(cold);
        }
        evicted
    }

    /// Mark `key`'s ring as no longer the whole record.
    pub(crate) fn mark_incomplete(&mut self, key: &HistoryKey) {
        if let Some(ring) = self.rings.get_mut(key) {
            ring.complete = false;
        }
    }

    /// Drop `key`'s ring. Whether there was one.
    pub(crate) fn remove(&mut self, key: &HistoryKey) -> bool {
        self.recency.remove(key);
        self.forget_ring(key)
    }

    /// The conversation keys `identity` takes part in.
    pub(crate) fn conversations_of<'a>(
        &'a self,
        identity: &str,
    ) -> impl Iterator<Item = &'a HistoryKey> + 'a {
        self.conversations.get(identity).into_iter().flatten()
    }

    /// Drop every conversation `identity` takes part in, touching only those.
    pub(crate) fn forget_identity(&mut self, identity: &str) {
        let keys: Vec<HistoryKey> = self.conversations_of(identity).cloned().collect();
        for key in keys {
            self.remove(&key);
        }
    }

    /// Erase an account's lines: every conversation it takes part in (by its
    /// folded identity) and every entry it sent (its sender account folds to
    /// `folded`). The keys of the rings that lost entries but remain are
    /// returned. A pass over every ring, which only an account's permanent
    /// deletion — an administrative act, not per-message traffic — pays.
    pub(crate) fn forget_account(&mut self, folded: &str, casemap: CaseMapping) -> Vec<HistoryKey> {
        self.forget_identity(folded);
        let mut shed = 0;
        let changed = self
            .rings
            .iter_mut()
            .filter_map(|(key, ring)| {
                let before = ring.bytes;
                let changed = ring.retain(|entry| {
                    entry
                        .sender_account
                        .as_deref()
                        .is_none_or(|sender| casemap.casefold(sender) != folded)
                });
                shed += before - ring.bytes;
                changed.then(|| key.clone())
            })
            .collect();
        self.bytes -= shed;
        changed
    }

    fn insert(&mut self, key: HistoryKey, ring: HistoryRing) {
        if let Some((lo, hi)) = key.participants() {
            for identity in [lo, hi] {
                self.conversations
                    .entry(identity.to_string())
                    .or_default()
                    .insert(key.clone());
            }
        }
        self.rings.insert(key, ring);
    }

    /// Drop the ring and its index entries (not its recency slot).
    fn forget_ring(&mut self, key: &HistoryKey) -> bool {
        let Some(ring) = self.rings.remove(key) else {
            return false;
        };
        self.bytes -= ring.bytes;
        if let Some((lo, hi)) = key.participants() {
            for identity in [lo, hi] {
                if let Some(keys) = self.conversations.get_mut(identity) {
                    keys.remove(key);
                    if keys.is_empty() {
                        self.conversations.remove(identity);
                    }
                }
            }
        }
        true
    }

    /// Recount every index from the rings and assert it matches what was kept.
    #[cfg(test)]
    pub(crate) fn assert_consistent(&self) {
        let mut conversations: HashMap<String, HashSet<HistoryKey>> = HashMap::new();
        for key in self.rings.keys() {
            assert!(self.recency.contains(key), "{key:?} has no recency slot");
            if let Some((lo, hi)) = key.participants() {
                for identity in [lo, hi] {
                    conversations
                        .entry(identity.to_string())
                        .or_default()
                        .insert(key.clone());
                }
            }
        }
        assert_eq!(self.recency.len(), self.rings.len());
        assert_eq!(self.conversations, conversations);
        for (key, ring) in &self.rings {
            assert_eq!(
                ring.bytes,
                ring.entries.iter().map(footprint).sum::<usize>(),
                "{key:?}'s byte count"
            );
        }
        assert_eq!(
            self.bytes,
            self.rings.values().map(|ring| ring.bytes).sum::<usize>(),
            "the store's byte count"
        );
        for (key, ring) in &self.rings {
            for scope in [HistoryScope::Text, HistoryScope::TextAndTags] {
                assert_eq!(
                    ring.latest().in_scope(scope),
                    ring.entries
                        .iter()
                        .filter(|entry| scope.admits(entry.kind))
                        .map(|entry| entry.ts)
                        .max(),
                    "{key:?}'s running maximum in {scope:?}"
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn most_recent_first(&self) -> Vec<HistoryKey> {
        self.recency.most_recent_first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, account: Option<&str>) -> HistoryEntry {
        HistoryEntry {
            msgid: format!("m{ts}"),
            ts: Millis::from_millis(ts),
            sender_prefix: "n!u@h".into(),
            sender_account: account.map(str::to_owned),
            kind: crate::core::HistoryKind::Privmsg,
            body: "x".into(),
            sender_is_bot: false,
            multiline: None,
            client_tags: String::new(),
        }
    }

    /// At most `count` rings, with no byte budget binding.
    fn rings(count: usize) -> HotHistoryBounds {
        HotHistoryBounds {
            rings: count,
            ring_bytes: usize::MAX,
            bytes: usize::MAX,
        }
    }

    /// A message carrying `tags` bytes of client-only tags, as a reply or a
    /// reaction with a large payload does (up to 4,094 bytes are kept).
    fn tagged(ts: u64, tags: usize) -> HistoryEntry {
        HistoryEntry {
            client_tags: format!("+x={}", "t".repeat(tags)),
            ..entry(ts, None)
        }
    }

    /// A ring of 4 KB-tagged entries stays within its byte budget, shedding
    /// its oldest entries long before it reaches its entry cap, and keeps its
    /// newest even when that one alone is over the budget.
    #[test]
    fn a_ring_stays_within_its_byte_budget() {
        let budget = 64 * 1024;
        let bounds = HotHistoryBounds {
            rings: 8,
            ring_bytes: budget,
            bytes: usize::MAX,
        };
        let mut history = HotHistory::default();
        let key = HistoryKey::channel_for_test("#big");
        for ts in 0..HISTORY_RING_CAP as u64 {
            history.push(&key, tagged(ts, 4_094), true, bounds);
            let ring = history.get(&key).expect("ring");
            assert!(ring.bytes <= budget, "{} bytes after {ts}", ring.bytes);
            history.assert_consistent();
        }
        let ring = history.get(&key).expect("ring");
        let held = ring.entries().len();
        assert!(held < 20, "{held} four-kilobyte entries in a 64 KiB ring");
        assert_eq!(
            ring.entries().back().map(|entry| entry.ts),
            Some(Millis::from_millis(HISTORY_RING_CAP as u64 - 1)),
            "the newest is kept"
        );
        assert!(!ring.complete(), "shedding entries makes it incomplete");
        let tight = HotHistoryBounds {
            ring_bytes: 1,
            ..bounds
        };
        history.push(&key, tagged(10_000, 4_094), true, tight);
        let ring = history.get(&key).expect("ring");
        assert_eq!(ring.entries().len(), 1, "one entry over the budget is kept");
        history.assert_consistent();
    }

    /// The store's byte budget evicts whole rings, least recently active
    /// first, however few rings there are — never the one just appended to.
    #[test]
    fn rings_are_evicted_by_bytes_least_recently_active_first() {
        let one = footprint(&tagged(0, 4_094));
        let bounds = HotHistoryBounds {
            rings: 1_000,
            ring_bytes: usize::MAX,
            bytes: 10 * one,
        };
        let mut history = HotHistory::default();
        let keys: Vec<HistoryKey> = (0..4)
            .map(|index| HistoryKey::channel_for_test(&format!("#c{index}")))
            .collect();
        // Three entries in each of three rings: nine entries, within ten.
        for ts in 0..3 {
            for key in &keys[..3] {
                assert!(
                    history
                        .push(key, tagged(ts, 4_094), false, bounds)
                        .is_empty()
                );
            }
        }
        history.push(&keys[0], tagged(3, 4_094), false, bounds);
        // A fourth ring passes the budget: #c1, now the least recently active,
        // goes, and only it.
        let evicted = history.push(&keys[3], tagged(4, 4_094), false, bounds);
        assert_eq!(evicted, [keys[1].clone()]);
        assert!(history.bytes <= bounds.bytes);
        history.assert_consistent();
        // One ring alone over the budget stays: there is nothing older to go.
        let alone = HotHistoryBounds {
            bytes: one,
            ..bounds
        };
        let evicted = history.push(&keys[3], tagged(5, 4_094), false, alone);
        assert_eq!(evicted.len(), 2, "{evicted:?}");
        assert!(history.get(&keys[3]).is_some());
        history.assert_consistent();
    }

    fn reaction(ts: u64) -> HistoryEntry {
        HistoryEntry {
            kind: crate::core::HistoryKind::Tagmsg,
            body: String::new(),
            client_tags: "+draft/react=x".into(),
            ..entry(ts, None)
        }
    }

    /// Timestamps out of arrival order, TAGMSGs among the text, and entries
    /// overflowing off the front keep every scope's running maximum equal to a
    /// recount.
    #[test]
    fn running_maximum_matches_a_recount() {
        let mut history = HotHistory::default();
        let key = HistoryKey::channel_for_test("#c");
        let mut seed = 7u64;
        for _ in 0..3 * HISTORY_RING_CAP {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let ts = seed >> 54;
            let pushed = if seed & (1 << 40) == 0 {
                entry(ts, None)
            } else {
                reaction(ts)
            };
            history.push(&key, pushed, true, rings(8));
            history.assert_consistent();
        }
        assert!(!history.get(&key).expect("ring").complete());
    }

    /// A reader without `message-tags` dates a ring by its newest text entry,
    /// and a ring holding only TAGMSGs has no activity in that scope.
    #[test]
    fn a_tagmsg_dates_a_ring_only_for_a_reader_in_its_scope() {
        let mut history = HotHistory::default();
        let key = HistoryKey::channel_for_test("#c");
        history.push(&key, reaction(5), true, rings(8));
        let latest = history.get(&key).expect("ring").latest();
        assert_eq!(latest.in_scope(HistoryScope::Text), None);
        assert_eq!(
            latest.in_scope(HistoryScope::TextAndTags),
            Some(Millis::from_millis(5))
        );
        history.push(&key, entry(7, None), true, rings(8));
        history.push(&key, reaction(9), true, rings(8));
        let latest = history.get(&key).expect("ring").latest();
        assert_eq!(
            latest.in_scope(HistoryScope::Text),
            Some(Millis::from_millis(7))
        );
        assert_eq!(
            latest.in_scope(HistoryScope::TextAndTags),
            Some(Millis::from_millis(9))
        );
        history.assert_consistent();
    }

    /// Every way a ring comes and goes — creation, eviction, removal,
    /// forgetting an identity, forgetting an account — leaves the indexes
    /// equal to a recount from the rings.
    #[test]
    fn indexes_agree_with_a_recount_after_every_mutation() {
        let mut history = HotHistory::default();
        let keys = [
            HistoryKey::channel_for_test("#a"),
            HistoryKey::channel_for_test("#b"),
            HistoryKey::conversation_for_test("~x", "~y"),
            HistoryKey::conversation_for_test("acct", "~y"),
            HistoryKey::conversation_for_test("acct", "acct"),
            HistoryKey::conversation_for_test("other", "~x"),
        ];
        for (i, key) in keys.iter().enumerate() {
            history.push(key, entry(i as u64, Some("Acct")), false, rings(5));
            history.assert_consistent();
        }
        // Six rings under a cap of five: the first was evicted.
        assert!(history.get(&keys[0]).is_none());
        history.push(&keys[1], entry(10, None), false, rings(5));
        history.assert_consistent();
        assert_eq!(history.most_recent_first()[0], keys[1]);

        assert!(history.remove(&keys[2]));
        history.assert_consistent();
        assert!(!history.remove(&keys[2]));

        history.forget_identity("~y");
        history.assert_consistent();
        assert!(history.get(&keys[3]).is_none());
        assert_eq!(history.conversations_of("acct").count(), 1);

        let changed = history.forget_account("acct", CaseMapping::Rfc1459);
        history.assert_consistent();
        assert!(history.get(&keys[4]).is_none());
        assert_eq!(history.conversations_of("acct").count(), 0);
        // #b kept its unauthenticated line and lost the account's.
        assert!(changed.contains(&keys[1]));
        let ring = history.get(&keys[1]).expect("#b kept");
        assert_eq!(ring.entries().len(), 1);
        assert_eq!(
            ring.latest().in_scope(HistoryScope::TextAndTags),
            Some(Millis::from_millis(10))
        );
        // The conversation between two others lost the account's line too.
        assert!(changed.contains(&keys[5]));
        assert!(history.get(&keys[5]).expect("kept").entries().is_empty());
    }

    /// Forgetting an identity touches only its own conversations: with many
    /// unrelated rings held, the work is the size of the index entry.
    #[test]
    fn forgetting_an_identity_visits_only_its_conversations() {
        let mut history = HotHistory::default();
        for i in 0..1_000 {
            history.push(
                &HistoryKey::conversation_for_test(&format!("~p{i}"), &format!("~q{i}")),
                entry(i, None),
                false,
                rings(10_000),
            );
        }
        let mine = HistoryKey::conversation_for_test("~gone", "~q1");
        history.push(&mine, entry(1, None), false, rings(10_000));
        assert_eq!(history.conversations_of("~gone").count(), 1);
        history.forget_identity("~gone");
        assert!(history.get(&mine).is_none());
        assert_eq!(history.rings.len(), 1_000);
        history.assert_consistent();
    }
}
