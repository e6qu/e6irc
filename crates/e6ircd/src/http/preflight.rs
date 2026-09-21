//! Admission control for connection tests.
//!
//! A connection test makes this daemon open a socket and register with a host
//! the caller chose, from the address every tenant shares. The ordinary API
//! budget (hundreds of requests a minute) is sized for reads of local state; at
//! that rate one account could get the shared address throttled or banned by a
//! public network for everybody, or map what answers on the daemon's side of
//! the firewall from the typed failures and timings.

use super::*;

/// Connection tests one account may start per minute.
const PER_ACCOUNT_PER_MINUTE: usize = 6;
/// Connection tests the whole process runs at once.
const CONCURRENT: usize = 8;
/// What a caller refused for concurrency is told to wait. A test is bounded by
/// the request deadline, so the slot frees within one; most free much sooner.
const BUSY_RETRY_AFTER_SECONDS: u64 = 5;

pub(crate) struct PreflightLimiter {
    process: Arc<tokio::sync::Semaphore>,
    accounts: Mutex<PreflightAccounts>,
}

#[derive(Default)]
struct PreflightAccounts {
    /// Folded accounts with a test in flight.
    running: std::collections::HashSet<String>,
    started: HashMap<String, (f64, std::time::Instant)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightRefusal {
    AlreadyRunning,
    ProcessBusy,
    AccountAllowanceSpent { retry_after: u64 },
}

impl PreflightLimiter {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            process: Arc::new(tokio::sync::Semaphore::new(CONCURRENT)),
            accounts: Mutex::default(),
        })
    }

    /// Admit one test for `account`, or say why not. A refusal for concurrency
    /// spends nothing from the account's allowance.
    fn admit(
        self: &Arc<Self>,
        account: &str,
        now: std::time::Instant,
    ) -> Result<PreflightPermit, PreflightRefusal> {
        let account = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account);
        let mut accounts = self.accounts.lock().expect("connection test limiter lock");
        if accounts.running.contains(&account) {
            return Err(PreflightRefusal::AlreadyRunning);
        }
        let process = self
            .process
            .clone()
            .try_acquire_owned()
            .map_err(|_| PreflightRefusal::ProcessBusy)?;
        // A bucket untouched for a whole window is full again, which is what an
        // absent bucket means: forgetting it keeps the map to recent callers.
        accounts
            .started
            .retain(|_, (_, last)| now.duration_since(*last) < API_RATE_WINDOW);
        spend_api_bucket(
            &mut accounts.started,
            account.clone(),
            PER_ACCOUNT_PER_MINUTE,
            now,
        )
        .map_err(|retry_after| PreflightRefusal::AccountAllowanceSpent { retry_after })?;
        accounts.running.insert(account.clone());
        Ok(PreflightPermit {
            limiter: self.clone(),
            account,
            _process: process,
        })
    }
}

impl PreflightRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::AlreadyRunning => retry_later(
                "Connection test already running",
                "This account has a connection test in progress. Wait for its result.",
                BUSY_RETRY_AFTER_SECONDS,
            ),
            Self::ProcessBusy => retry_later(
                "Connection tests are busy",
                "The server is running as many connection tests as it allows at once.",
                BUSY_RETRY_AFTER_SECONDS,
            ),
            Self::AccountAllowanceSpent { retry_after } => retry_later(
                "Connection test limit reached",
                "An account may start six connection tests per minute.",
                retry_after,
            ),
        }
    }
}

/// An authenticated account's admission to run one connection test, held for
/// as long as the test runs. The route asks for this instead of
/// [`Authenticated`], so an unbounded connection test cannot be written; a
/// request the HTTP deadline abandons releases its slot when it is dropped.
pub(crate) struct PreflightPermit {
    limiter: Arc<PreflightLimiter>,
    account: String,
    _process: tokio::sync::OwnedSemaphorePermit,
}

impl PreflightPermit {
    /// The account the test runs for.
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
}

impl Drop for PreflightPermit {
    fn drop(&mut self) {
        self.limiter
            .accounts
            .lock()
            .expect("connection test limiter lock")
            .running
            .remove(&self.account);
    }
}

impl axum::extract::FromRequestParts<Arc<AppState>> for PreflightPermit {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated(account, _) = Authenticated::from_request_parts(parts, state).await?;
        state
            .preflight_limiter
            .admit(&account, std::time::Instant::now())
            .map_err(PreflightRefusal::into_response)
    }
}

#[cfg(test)]
mod tests {
    use super::{CONCURRENT, PER_ACCOUNT_PER_MINUTE, PreflightLimiter, PreflightRefusal};

    #[test]
    fn one_account_runs_one_test_at_a_time_and_a_refusal_costs_nothing() {
        let limiter = PreflightLimiter::new();
        let now = std::time::Instant::now();
        let running = limiter.admit("Alice", now).expect("first test");
        assert_eq!(
            limiter.admit("alice", now).err(),
            Some(PreflightRefusal::AlreadyRunning)
        );
        drop(running);
        for _ in 1..PER_ACCOUNT_PER_MINUTE {
            drop(limiter.admit("alice", now).expect("within the allowance"));
        }
        assert!(matches!(
            limiter.admit("alice", now),
            Err(PreflightRefusal::AccountAllowanceSpent { retry_after }) if retry_after > 0
        ));
        let refilled = now + std::time::Duration::from_secs(60);
        assert!(limiter.admit("alice", refilled).is_ok());
    }

    #[test]
    fn the_process_bound_is_shared_and_released_on_drop() {
        let limiter = PreflightLimiter::new();
        let now = std::time::Instant::now();
        let mut running: Vec<_> = (0..CONCURRENT)
            .map(|index| {
                limiter
                    .admit(&format!("account{index}"), now)
                    .expect("slot")
            })
            .collect();
        assert_eq!(
            limiter.admit("late", now).err(),
            Some(PreflightRefusal::ProcessBusy)
        );
        running.pop();
        assert!(limiter.admit("late", now).is_ok());
    }
}
