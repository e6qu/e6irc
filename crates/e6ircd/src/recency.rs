//! Least-recently-used order over a set of keys, in amortized constant time.
//!
//! A bounded cache that evicts its least recently used entry needs two things
//! on every access: move the key to the most-recent end, and — when over the
//! cap — find the least recent one. A `VecDeque` of keys does the second in
//! O(1) but the first only by searching for the key (`retain(|k| k != key)`),
//! which is a pass over every key on every access: work per message that grows
//! with how many conversations the server holds. [`Recency`] stamps each touch
//! instead: the key's current stamp lives in a map, and the queue holds
//! `(stamp, key)` pairs of which only the one matching the map is live. A touch
//! is a map write and a push; a stale pair is skipped when it reaches the
//! front, and the queue is compacted once stale pairs outnumber live ones, so
//! it never holds more than about twice as many pairs as keys.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// Stale pairs tolerated before a compaction regardless of how few keys are
/// live, so a tiny set does not compact on every other touch.
const COMPACTION_SLACK: usize = 32;

/// Keys in least-recently-used order.
#[derive(Debug, Clone)]
pub(crate) struct Recency<K> {
    /// Each live key's current stamp.
    stamps: HashMap<K, u64>,
    /// `(stamp, key)`, oldest first. A pair is live exactly when `stamps`
    /// holds that key at that stamp.
    order: VecDeque<(u64, K)>,
    next: u64,
}

impl<K> Default for Recency<K> {
    fn default() -> Self {
        Self {
            stamps: HashMap::new(),
            order: VecDeque::new(),
            next: 0,
        }
    }
}

impl<K: Hash + Eq + Clone> Recency<K> {
    /// Make `key` the most recently used, adding it when absent.
    pub(crate) fn touch(&mut self, key: &K) {
        let stamp = self.next;
        self.next += 1;
        match self.stamps.get_mut(key) {
            Some(current) => *current = stamp,
            None => {
                self.stamps.insert(key.clone(), stamp);
            }
        }
        self.order.push_back((stamp, key.clone()));
        self.compact_if_sparse();
    }

    /// Forget `key`. Whether it was present.
    pub(crate) fn remove(&mut self, key: &K) -> bool {
        let removed = self.stamps.remove(key).is_some();
        if removed {
            self.compact_if_sparse();
        }
        removed
    }

    /// Remove and return the least recently used key.
    pub(crate) fn pop_oldest(&mut self) -> Option<K> {
        while let Some((stamp, key)) = self.order.pop_front() {
            if self.stamps.get(&key) == Some(&stamp) {
                self.stamps.remove(&key);
                return Some(key);
            }
        }
        None
    }

    /// How many keys are held.
    pub(crate) fn len(&self) -> usize {
        self.stamps.len()
    }

    /// Whether `key` is held.
    #[cfg(test)]
    pub(crate) fn contains(&self, key: &K) -> bool {
        self.stamps.contains_key(key)
    }

    /// The held keys, most recently used first.
    #[cfg(test)]
    pub(crate) fn most_recent_first(&self) -> Vec<K> {
        self.order
            .iter()
            .rev()
            .filter(|(stamp, key)| self.stamps.get(key) == Some(stamp))
            .map(|(_, key)| key.clone())
            .collect()
    }

    /// Queue pairs currently held, live or stale — what bounds the memory.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.order.len()
    }

    /// Drop stale pairs once they outnumber the live keys. Each compaction
    /// costs the queue's length and follows at least that many touches or
    /// removals since the last, so the cost per operation stays constant.
    fn compact_if_sparse(&mut self) {
        if self.order.len() > 2 * self.stamps.len() + COMPACTION_SLACK {
            let stamps = &self.stamps;
            self.order
                .retain(|(stamp, key)| stamps.get(key) == Some(stamp));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_in_least_recently_used_order() {
        let mut recency = Recency::default();
        for key in ["a", "b", "c"] {
            recency.touch(&key);
        }
        recency.touch(&"a");
        assert_eq!(recency.most_recent_first(), vec!["a", "c", "b"]);
        assert_eq!(recency.pop_oldest(), Some("b"));
        assert!(recency.remove(&"c"));
        assert!(!recency.remove(&"c"));
        assert_eq!(recency.len(), 1);
        assert_eq!(recency.pop_oldest(), Some("a"));
        assert_eq!(recency.pop_oldest(), None);
    }

    /// Touching one hot key forever must not grow the queue: stale pairs are
    /// compacted away, so memory stays proportional to the keys held.
    #[test]
    fn a_hot_key_does_not_grow_the_queue() {
        let mut recency = Recency::default();
        recency.touch(&0u32);
        recency.touch(&1u32);
        for _ in 0..100_000 {
            recency.touch(&1u32);
            assert!(recency.queued() <= 2 * recency.len() + COMPACTION_SLACK + 1);
        }
        assert_eq!(recency.pop_oldest(), Some(0));
    }

    /// After any mix of operations the order matches a naive model that
    /// searches a list — the structure `Recency` replaced.
    #[test]
    fn agrees_with_a_linear_model() {
        let mut recency = Recency::default();
        let mut model: VecDeque<u32> = VecDeque::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let key = (seed % 64) as u32;
            match seed % 5 {
                0 => {
                    assert_eq!(recency.remove(&key), model.contains(&key));
                    model.retain(|k| *k != key);
                }
                1 => assert_eq!(recency.pop_oldest(), model.pop_back()),
                _ => {
                    recency.touch(&key);
                    model.retain(|k| *k != key);
                    model.push_front(key);
                }
            }
            assert_eq!(recency.len(), model.len());
            assert!(model.iter().all(|k| recency.contains(k)));
        }
        assert_eq!(recency.most_recent_first(), Vec::from(model));
    }
}
