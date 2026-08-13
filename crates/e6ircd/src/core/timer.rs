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
        self.drain_current(&mut due);
        if target.saturating_sub(self.tick) >= self.buckets.len() as u64 {
            self.tick = target;
            for bucket in &mut self.buckets {
                Self::drain_bucket(bucket, self.tick, &mut due);
            }
            return due;
        }
        while self.tick < target {
            self.tick += 1;
            let slot = self.tick as usize % self.buckets.len();
            Self::drain_bucket(&mut self.buckets[slot], self.tick, &mut due);
        }
        due
    }

    fn drain_current(&mut self, due: &mut Vec<T>) {
        let slot = self.tick as usize % self.buckets.len();
        Self::drain_bucket(&mut self.buckets[slot], self.tick, due);
    }

    fn drain_bucket(bucket: &mut Vec<Timed<T>>, tick: u64, due: &mut Vec<T>) {
        let timers = std::mem::take(bucket);
        let (ready, pending): (Vec<_>, Vec<_>) =
            timers.into_iter().partition(|timer| timer.tick <= tick);
        due.extend(ready.into_iter().map(|timer| timer.payload));
        *bucket = pending;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: u64) -> MonoMillis {
        MonoMillis::from_millis(ms)
    }

    fn wheel(now: u64) -> TimerWheel<&'static str> {
        TimerWheel::new(
            at(now),
            NonZeroU64::new(10).expect("nonzero resolution"),
            NonZeroUsize::new(2).expect("nonzero slots"),
        )
    }

    #[test]
    fn retains_wrapped_timers_until_their_real_deadline() {
        let mut wheel = wheel(0);
        wheel.schedule(at(10), "first");
        wheel.schedule(at(30), "later");

        assert_eq!(wheel.advance(at(10)), vec!["first"]);
        assert!(wheel.advance(at(20)).is_empty());
        assert_eq!(wheel.advance(at(30)), vec!["later"]);
    }

    #[test]
    fn emits_a_timer_due_now() {
        let mut wheel = wheel(10);
        wheel.schedule(at(10), "now");
        assert_eq!(wheel.advance(at(10)), vec!["now"]);
    }

    #[test]
    fn large_clock_jump_scans_each_slot_once() {
        let mut wheel = wheel(0);
        wheel.schedule(at(10), "due");
        wheel.schedule(at(1_000_010), "future");

        assert_eq!(wheel.advance(at(1_000_000)), vec!["due"]);
        assert_eq!(wheel.advance(at(1_000_010)), vec!["future"]);
    }
}
