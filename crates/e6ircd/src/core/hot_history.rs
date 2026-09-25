//! The hot history store: one newest-last ring per channel or direct-message
//! conversation, under one least-recently-active cap.
//!
//! Every question asked of it per event is answered from an index kept where
//! the store changes, never by a pass over every ring:
//!
//! - which ring to evict comes from a [`Recency`] order (not a search of a
//!   list of keys on every message);
//! - which conversations an identity takes part in comes from `conversations`
//!   (not a split of every key on every disconnect or CHATHISTORY TARGETS);
//! - a ring's newest timestamp comes from its running window maximum (not a
//!   pass over its entries each time a channel is published).

use std::collections::{HashMap, HashSet, VecDeque};

use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::time::Millis;

use super::state::{HistoryEntry, HistoryKey};
use crate::recency::Recency;

/// Ring capacity per target; older entries live only in PostgreSQL.
pub(crate) const HISTORY_RING_CAP: usize = 500;

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
    /// The sliding-window maximum of `entries`' timestamps: `(position, ts)`
    /// with strictly decreasing `ts`, front the newest timestamp still held.
    /// Timestamps come from wall clocks (and from other shards'), so arrival
    /// order is not timestamp order and the back entry is not the newest.
    maxima: VecDeque<(u64, Millis)>,
}

impl HistoryRing {
    fn new(complete: bool) -> Self {
        Self {
            entries: VecDeque::new(),
            complete,
            first: 0,
            maxima: VecDeque::new(),
        }
    }

    pub(crate) fn entries(&self) -> &VecDeque<HistoryEntry> {
        &self.entries
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    /// The newest timestamp among the entries held, in constant time.
    pub(crate) fn latest(&self) -> Option<Millis> {
        self.maxima.front().map(|&(_, ts)| ts)
    }

    fn push(&mut self, entry: HistoryEntry) {
        if self.entries.len() == HISTORY_RING_CAP {
            self.entries.pop_front();
            if self.maxima.front().is_some_and(|&(at, _)| at == self.first) {
                self.maxima.pop_front();
            }
            self.first += 1;
            self.complete = false;
        }
        let at = self.first + self.entries.len() as u64;
        while self.maxima.back().is_some_and(|&(_, ts)| ts <= entry.ts) {
            self.maxima.pop_back();
        }
        self.maxima.push_back((at, entry.ts));
        self.entries.push_back(entry);
    }

    /// Keep only the entries `keep` admits. A rare, whole-ring operation (an
    /// account's erasure), so the window maximum is simply rebuilt.
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
            self.push(entry);
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
}

impl HotHistory {
    pub(crate) fn get(&self, key: &HistoryKey) -> Option<&HistoryRing> {
        self.rings.get(key)
    }

    /// Append to `key`'s ring, creating it (complete when `whole_record`) if
    /// absent, and make it the most recently active. Rings beyond `cap` are
    /// evicted least recently active first; their keys are returned.
    pub(crate) fn push(
        &mut self,
        key: &HistoryKey,
        entry: HistoryEntry,
        whole_record: bool,
        cap: usize,
    ) -> Vec<HistoryKey> {
        match self.rings.get_mut(key) {
            Some(ring) => ring.push(entry),
            None => {
                let mut ring = HistoryRing::new(whole_record);
                ring.push(entry);
                self.insert(key.clone(), ring);
            }
        }
        self.recency.touch(key);
        let mut evicted = Vec::new();
        while self.recency.len() > cap {
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
        self.rings
            .iter_mut()
            .filter_map(|(key, ring)| {
                ring.retain(|entry| {
                    entry
                        .sender_account
                        .as_deref()
                        .is_none_or(|sender| casemap.casefold(sender) != folded)
                })
                .then(|| key.clone())
            })
            .collect()
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
        if self.rings.remove(key).is_none() {
            return false;
        }
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
                ring.latest(),
                ring.entries.iter().map(|entry| entry.ts).max(),
                "{key:?}'s running maximum"
            );
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
            kind: crate::core::MessageKind::Privmsg,
            body: "x".into(),
            sender_is_bot: false,
            multiline: None,
        }
    }

    /// Timestamps out of arrival order, and entries overflowing off the
    /// front, keep the running maximum equal to a recount.
    #[test]
    fn running_maximum_matches_a_recount() {
        let mut history = HotHistory::default();
        let key = HistoryKey::channel_for_test("#c");
        let mut seed = 7u64;
        for _ in 0..3 * HISTORY_RING_CAP {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            history.push(&key, entry(seed >> 54, None), true, 8);
            history.assert_consistent();
        }
        assert!(!history.get(&key).expect("ring").complete());
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
            history.push(key, entry(i as u64, Some("Acct")), false, 5);
            history.assert_consistent();
        }
        // Six rings under a cap of five: the first was evicted.
        assert!(history.get(&keys[0]).is_none());
        history.push(&keys[1], entry(10, None), false, 5);
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
        assert_eq!(ring.latest(), Some(Millis::from_millis(10)));
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
                10_000,
            );
        }
        let mine = HistoryKey::conversation_for_test("~gone", "~q1");
        history.push(&mine, entry(1, None), false, 10_000);
        assert_eq!(history.conversations_of("~gone").count(), 1);
        history.forget_identity("~gone");
        assert!(history.get(&mine).is_none());
        assert_eq!(history.rings.len(), 1_000);
        history.assert_consistent();
    }
}
