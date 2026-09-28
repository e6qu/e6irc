//! Every session's command allowance, spent at the edge as each of its lines
//! is handed to the core (DESIGN §7.2, §19.1).
//!
//! Each line a session sends — PING and PONG included, and before it has
//! registered — spends one token of its bucket ([`CommandFlood`]: `burst`
//! tokens at most, `rate` regained per second). An empty bucket does not close
//! the session: the task reading it stops reading until a token is back, so
//! what the client sends too fast waits in its own socket buffers, as Solanum
//! parses a client's receive queue only as fast as its allowance. One session's
//! lines therefore occupy at most its bucket's worth of the core's queue,
//! whatever it sends. The meter is here, where the socket is, because "the
//! reader stops reading" can only happen where the reading is. An IRC operator
//! is exempt (Solanum's `no_oper_flood`): the core pushes the session's
//! [`FloodExemption`] over its link ([`crate::link::CoreEnd::set_flood_exempt`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::time::{Duration, Instant};

/// The most tokens a bucket may hold or regain a second. Configured values
/// past it are refused, so the arithmetic below cannot overflow a `u32`.
pub const MAX_COMMAND_FLOOD_TOKENS: usize = 10_000;

/// A validated command-flood bucket shape: `burst` tokens at most, refilling
/// `rate` per second. Constructed only through [`CommandFlood::new`], so a
/// bucket that never refills (`rate = 0`), that never admits a line
/// (`burst = 0`), or that cannot hold one second of its own rate
/// (`burst < rate`) cannot reach a session's line meter.
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
                "limits.command_burst must be at least 1 (0 never admits a line)"
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
        let maximum = MAX_COMMAND_FLOOD_TOKENS;
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

/// Whether one session's lines are metered: the flag the core sets over the
/// session's link when the session becomes, or stops being, an IRC operator,
/// and the edge reads only when the session's bucket is empty.
#[derive(Clone, Default)]
pub struct FloodExemption(Arc<AtomicBool>);

impl FloodExemption {
    pub(crate) fn set(&self, exempt: bool) {
        self.0.store(exempt, Ordering::Relaxed);
    }

    fn exempt(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// A token bucket of one [`CommandFlood`] shape: `burst` tokens at most,
/// `rate` regained per second. A session's [`LineMeter`] spends one per
/// line it hands the core; the bouncer's `irc` driver spends one per line it
/// writes to an upstream, whose own flood limit is the same shape.
pub struct TokenBucket {
    flood: CommandFlood,
    tokens: u32,
    /// The instant through which regained tokens have been credited. It
    /// advances by whole tokens' worth only, so a remainder shorter than one
    /// token carries forward instead of being lost to a steady stream.
    refilled_to: Instant,
}

impl TokenBucket {
    /// A full bucket at `now`.
    pub fn new(flood: CommandFlood, now: Instant) -> Self {
        Self {
            flood,
            tokens: flood.burst(),
            refilled_to: now,
        }
    }

    /// When the next token is there: `None` now, or the instant it is
    /// regained.
    pub fn blocked_until(&mut self, now: Instant) -> Option<Instant> {
        let rate = u64::from(self.flood.rate());
        let elapsed_ms = u64::try_from(now.saturating_duration_since(self.refilled_to).as_millis())
            .unwrap_or(u64::MAX);
        // `credited * 1000 / rate <= elapsed_ms`: the watermark never passes
        // `now`.
        let credited = elapsed_ms.saturating_mul(rate) / 1000;
        self.refilled_to += Duration::from_millis(credited.saturating_mul(1000) / rate);
        let tokens =
            (u64::from(self.tokens).saturating_add(credited)).min(u64::from(self.flood.burst()));
        self.tokens = u32::try_from(tokens).expect("at most the burst, which is a u32");
        if self.tokens > 0 {
            return None;
        }
        // The next whole token is credited once `elapsed * rate >= 1000`.
        Some(self.refilled_to + Duration::from_millis(1000u64.div_ceil(rate)))
    }

    /// Take a token, or nothing from an empty bucket (an exempt spender's).
    fn take(&mut self) {
        self.tokens = self.tokens.saturating_sub(1);
    }

    /// Spend a token, waiting until one is regained when the bucket is empty.
    pub async fn spend(&mut self) {
        while let Some(until) = self.blocked_until(Instant::now()) {
            tokio::time::sleep_until(until).await;
        }
        self.take();
    }
}

/// One session's allowance, held by the edge task that hands its lines to the
/// core.
pub struct LineMeter {
    /// `None` only for a core that meters nothing: the test harnesses', which
    /// pipeline whole scripted sessions at once.
    bucket: Option<TokenBucket>,
    exemption: FloodExemption,
}

impl LineMeter {
    /// A fresh session's meter: its bucket full, whenever the process
    /// started.
    pub fn new(flood: Option<CommandFlood>, exemption: FloodExemption, now: Instant) -> Self {
        Self {
            bucket: flood.map(|flood| TokenBucket::new(flood, now)),
            exemption,
        }
    }

    /// When the next line may go: `None` now, or the instant the next token
    /// is regained.
    pub fn blocked_until(&mut self, now: Instant) -> Option<Instant> {
        let until = self.bucket.as_mut()?.blocked_until(now)?;
        (!self.exemption.exempt()).then_some(until)
    }

    fn take(&mut self) {
        if let Some(bucket) = &mut self.bucket {
            bucket.take();
        }
    }

    /// Spend a token for one line, waiting until one is regained when the
    /// bucket is empty.
    pub async fn spend(&mut self) {
        while let Some(until) = self.blocked_until(Instant::now()) {
            tokio::time::sleep_until(until).await;
        }
        self.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meter(burst: usize, rate: usize, start: Instant) -> LineMeter {
        LineMeter::new(
            Some(CommandFlood::new(burst, rate).expect("valid bucket")),
            FloodExemption::default(),
            start,
        )
    }

    /// Spend at `now` if a token is there.
    fn spend_at(meter: &mut LineMeter, now: Instant) -> bool {
        let free = meter.blocked_until(now).is_none();
        if free {
            meter.take();
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
    fn an_exempt_session_is_never_blocked_and_loses_the_exemption_with_its_status() {
        let start = Instant::now();
        let exemption = FloodExemption::default();
        let mut meter = LineMeter::new(
            Some(CommandFlood::new(1, 1).expect("valid bucket")),
            exemption.clone(),
            start,
        );
        assert!(spend_at(&mut meter, start));
        assert!(!spend_at(&mut meter, start));
        exemption.set(true);
        for _ in 0..1000 {
            assert!(spend_at(&mut meter, start));
        }
        exemption.set(false);
        assert!(!spend_at(&mut meter, start));
    }

    #[test]
    fn an_unmetered_core_never_blocks() {
        let start = Instant::now();
        let mut meter = LineMeter::new(None, FloodExemption::default(), start);
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

    #[test]
    fn a_bucket_shape_is_refused_by_the_rule_it_breaks() {
        assert_eq!(CommandFlood::new(1, 0), Err(CommandFloodError::RateZero));
        assert_eq!(CommandFlood::new(0, 1), Err(CommandFloodError::BurstZero));
        assert_eq!(
            CommandFlood::new(1, 2),
            Err(CommandFloodError::BurstBelowRate { burst: 1, rate: 2 })
        );
        assert_eq!(
            CommandFlood::new(MAX_COMMAND_FLOOD_TOKENS + 1, 1),
            Err(CommandFloodError::AboveMaximum {
                maximum: MAX_COMMAND_FLOOD_TOKENS
            })
        );
        let flood = CommandFlood::new(40, 20).expect("the default shape");
        assert_eq!((flood.burst(), flood.rate()), (40, 20));
    }
}
