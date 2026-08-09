use std::num::{NonZeroU64, NonZeroUsize};

use e6irc_proto::time::MonoMillis;

struct Timed<T> {
    tick: u64,
    payload: T,
}

/// Bounded-slot timer wheel keyed by monotonic milliseconds.
pub(crate) struct TimerWheel<T> {
    resolution: NonZeroU64,
    tick: u64,
    buckets: Vec<Vec<Timed<T>>>,
}

impl<T> TimerWheel<T> {
    pub(crate) fn new(now: MonoMillis, resolution: NonZeroU64, slots: NonZeroUsize) -> Self {
        Self {
            resolution,
            tick: now.as_millis() / resolution.get(),
            buckets: (0..slots.get()).map(|_| Vec::new()).collect(),
        }
    }

    pub(crate) fn schedule(&mut self, deadline: MonoMillis, payload: T) {
        let tick = deadline.as_millis() / self.resolution.get();
        let tick = tick.max(self.tick);
        let slot = tick as usize % self.buckets.len();
        self.buckets[slot].push(Timed { tick, payload });
    }

    /// Return every timer due at or before `now`.
    pub(crate) fn advance(&mut self, now: MonoMillis) -> Vec<T> {
        let target = now.as_millis() / self.resolution.get();
        let mut due = Vec::new();
        while self.tick < target {
            self.tick += 1;
            let slot = self.tick as usize % self.buckets.len();
            let bucket = std::mem::take(&mut self.buckets[slot]);
            let (ready, pending): (Vec<_>, Vec<_>) = bucket
                .into_iter()
                .partition(|timer| timer.tick <= self.tick);
            due.extend(ready.into_iter().map(|timer| timer.payload));
            self.buckets[slot] = pending;
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: u64) -> MonoMillis {
        MonoMillis::from_millis(ms)
    }

    #[test]
    fn retains_wrapped_timers_until_their_real_deadline() {
        let mut wheel = TimerWheel::new(
            at(0),
            NonZeroU64::new(10).expect("nonzero resolution"),
            NonZeroUsize::new(2).expect("nonzero slots"),
        );
        wheel.schedule(at(10), "first");
        wheel.schedule(at(30), "later");

        assert_eq!(wheel.advance(at(10)), vec!["first"]);
        assert!(wheel.advance(at(20)).is_empty());
        assert_eq!(wheel.advance(at(30)), vec!["later"]);
    }
}
