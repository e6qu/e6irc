//! Every connection's command allowance, spent where its lines enter the core
//! (DESIGN §7.2).
//!
//! Each line a connection sends — PING and PONG included, and before it has
//! registered — spends one token of its bucket ([`CommandFlood`]: `burst`
//! tokens at most, `rate` regained per second). An empty bucket does not close
//! the connection: the task reading it stops reading until a token is back, so
//! what the client sends too fast waits in its own socket buffers, as Solanum
//! parses a client's receive queue only as fast as its allowance. One
//! connection's lines therefore occupy at most its bucket's worth of the core's
//! queue, whatever it sends. An IRC operator is exempt (Solanum's
//! `no_oper_flood`): the core records which connections are, in
//! [`FloodExemptions`].

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::time::{Duration, Instant};

use super::state::{CommandFlood, ConnId};

/// The connections whose lines are not metered — its IRC operators. Written by
/// the core shard that owns each session as its operator status changes, read
/// by a connection's reader only when its bucket is empty.
#[derive(Clone, Default)]
pub(crate) struct FloodExemptions(Arc<Mutex<HashSet<ConnId>>>);

impl FloodExemptions {
    pub(crate) fn set(&self, conn: ConnId, exempt: bool) {
        let mut exempt_connections = self.0.lock().expect("flood exemptions poisoned");
        if exempt {
            exempt_connections.insert(conn);
        } else {
            exempt_connections.remove(&conn);
        }
    }

    fn contains(&self, conn: ConnId) -> bool {
        self.0
            .lock()
            .expect("flood exemptions poisoned")
            .contains(&conn)
    }
}

/// One connection's allowance, held by the task that hands its lines to the
/// core.
pub(crate) struct LineMeter {
    conn: ConnId,
    /// `None` only for an ingress built without a bucket: the test harnesses',
    /// which pipeline whole scripted sessions at once.
    flood: Option<CommandFlood>,
    tokens: u32,
    /// The instant through which regained tokens have been credited. It
    /// advances by whole tokens' worth only, so a remainder shorter than one
    /// token carries forward instead of being lost to a steady stream.
    refilled_to: Instant,
    exemptions: FloodExemptions,
}

impl LineMeter {
    /// A fresh connection's meter: its bucket full, whenever the process
    /// started.
    pub(crate) fn new(
        conn: ConnId,
        flood: Option<CommandFlood>,
        exemptions: FloodExemptions,
        now: Instant,
    ) -> Self {
        Self {
            conn,
            flood,
            tokens: flood.map_or(0, CommandFlood::burst),
            refilled_to: now,
            exemptions,
        }
    }

    /// When the next line may go: `None` now, or the instant the next token
    /// is regained.
    pub(crate) fn blocked_until(&mut self, now: Instant) -> Option<Instant> {
        let flood = self.flood?;
        let rate = u64::from(flood.rate());
        let elapsed_ms = u64::try_from(now.saturating_duration_since(self.refilled_to).as_millis())
            .unwrap_or(u64::MAX);
        // `credited * 1000 / rate <= elapsed_ms`: the watermark never passes
        // `now`.
        let credited = elapsed_ms.saturating_mul(rate) / 1000;
        self.refilled_to += Duration::from_millis(credited.saturating_mul(1000) / rate);
        let tokens =
            (u64::from(self.tokens).saturating_add(credited)).min(u64::from(flood.burst()));
        self.tokens = u32::try_from(tokens).expect("at most the burst, which is a u32");
        if self.tokens > 0 || self.exemptions.contains(self.conn) {
            return None;
        }
        // The next whole token is credited once `elapsed * rate >= 1000`.
        Some(self.refilled_to + Duration::from_millis(1000u64.div_ceil(rate)))
    }

    /// Spend a token for one line, waiting until one is regained when the
    /// bucket is empty.
    pub(crate) async fn spend(&mut self) {
        while let Some(until) = self.blocked_until(Instant::now()) {
            tokio::time::sleep_until(until).await;
        }
        self.tokens = self.tokens.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meter(burst: usize, rate: usize, start: Instant) -> LineMeter {
        LineMeter::new(
            ConnId(1),
            Some(CommandFlood::new(burst, rate).expect("valid bucket")),
            FloodExemptions::default(),
            start,
        )
    }

    /// Spend at `now` if a token is there.
    fn spend_at(meter: &mut LineMeter, now: Instant) -> bool {
        let free = meter.blocked_until(now).is_none();
        if free {
            meter.tokens = meter.tokens.saturating_sub(1);
        }
        free
    }

    #[test]
    fn a_fresh_meter_holds_the_whole_burst_then_waits_one_token() {
        let start = Instant::now();
        let mut meter = meter(40, 20, start);
        for line in 0..40 {
            assert!(
                spend_at(&mut meter, start),
                "line {line} is within the burst"
            );
        }
        assert_eq!(
            meter.blocked_until(start),
            Some(start + Duration::from_millis(50)),
            "at 20 a second the next token is 50 ms away"
        );
        assert!(spend_at(&mut meter, start + Duration::from_millis(50)));
        assert!(!spend_at(&mut meter, start + Duration::from_millis(50)));
    }

    #[test]
    fn a_remainder_shorter_than_a_token_carries_forward() {
        let start = Instant::now();
        let mut meter = meter(3, 3, start);
        for _ in 0..3 {
            assert!(spend_at(&mut meter, start));
        }
        // 3 a second is a token every 333⅓ ms: two readings 200 ms apart
        // credit one token between them, not none.
        assert!(!spend_at(&mut meter, start + Duration::from_millis(200)));
        assert!(spend_at(&mut meter, start + Duration::from_millis(400)));
        assert!(!spend_at(&mut meter, start + Duration::from_millis(600)));
        assert!(spend_at(&mut meter, start + Duration::from_millis(700)));
    }

    #[test]
    fn idle_time_refills_only_up_to_the_burst() {
        let start = Instant::now();
        let mut meter = meter(5, 1, start);
        for _ in 0..5 {
            assert!(spend_at(&mut meter, start));
        }
        let later = start + Duration::from_secs(3600);
        for _ in 0..5 {
            assert!(spend_at(&mut meter, later));
        }
        assert!(
            !spend_at(&mut meter, later),
            "an hour idle is still one burst"
        );
    }

    #[test]
    fn an_exempt_connection_is_never_blocked_and_loses_the_exemption_with_its_status() {
        let start = Instant::now();
        let exemptions = FloodExemptions::default();
        let mut meter = LineMeter::new(
            ConnId(7),
            Some(CommandFlood::new(1, 1).expect("valid bucket")),
            exemptions.clone(),
            start,
        );
        assert!(spend_at(&mut meter, start));
        assert!(!spend_at(&mut meter, start));
        exemptions.set(ConnId(7), true);
        for _ in 0..1000 {
            assert!(spend_at(&mut meter, start));
        }
        exemptions.set(ConnId(7), false);
        assert!(!spend_at(&mut meter, start));
    }

    #[test]
    fn an_unmetered_ingress_never_blocks() {
        let start = Instant::now();
        let mut meter = LineMeter::new(ConnId(1), None, FloodExemptions::default(), start);
        for _ in 0..10_000 {
            assert!(spend_at(&mut meter, start));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spend_waits_for_the_next_token() {
        let start = Instant::now();
        let mut meter = meter(2, 2, start);
        meter.spend().await;
        meter.spend().await;
        meter.spend().await;
        assert_eq!(
            Instant::now().duration_since(start),
            Duration::from_millis(500),
            "the third line waited for the token regained half a second on"
        );
    }
}
