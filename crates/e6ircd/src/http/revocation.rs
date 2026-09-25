//! Long-lived sockets end with the credential that opened them.
//!
//! A request is authorized once, when it arrives. A socket outlives that
//! moment by hours, so "is this credential still good?" has to be asked again
//! whenever the answer can change: when it is revoked (by any path — the
//! tables announce it themselves, see `crate::db::CredentialChangeListener`)
//! and when it expires. A socket takes a [`CredentialLease`] for the
//! credential it authenticated with and ends when [`CredentialLease::ended`]
//! returns.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::db::{CredentialChange, CredentialChangeListener, DbError, RevocableCredential};

/// Whether a watched credential still authorizes its socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialStanding {
    /// It authorizes until this instant, when it expires.
    Live { until: tokio::time::Instant },
    /// It was revoked, expired, or its account was suspended or deleted.
    Ended,
    /// The store could not be asked whether it still authorizes. The socket
    /// ends too — nothing vouches for it — but the client may reconnect,
    /// which authenticates again.
    Unverifiable,
}

/// What the store answered about a credential: how long it still authorizes,
/// or `None` when it no longer does.
type StoreAnswer = Result<Option<std::time::Duration>, DbError>;

type Watchers = HashMap<RevocableCredential, HashMap<u64, watch::Sender<CredentialStanding>>>;

/// Every credential a live socket holds, and the sockets holding each.
#[derive(Default)]
pub(crate) struct CredentialWatch {
    watchers: Mutex<Watchers>,
    next_lease: AtomicU64,
}

/// One socket's claim on a credential. Dropping it stops the watch.
pub(crate) struct CredentialLease {
    watch: Arc<CredentialWatch>,
    credential: RevocableCredential,
    lease: u64,
    standing: watch::Receiver<CredentialStanding>,
}

impl Drop for CredentialLease {
    fn drop(&mut self) {
        let mut watchers = self.watch.watchers.lock().expect("credential watch lock");
        if let Some(leases) = watchers.get_mut(&self.credential) {
            leases.remove(&self.lease);
            if leases.is_empty() {
                watchers.remove(&self.credential);
            }
        }
    }
}

/// The standing a store answer means.
fn standing(answer: StoreAnswer) -> CredentialStanding {
    match answer {
        Ok(Some(remaining)) => CredentialStanding::Live {
            until: tokio::time::Instant::now() + remaining,
        },
        Ok(None) => CredentialStanding::Ended,
        Err(error) => {
            eprintln!("http: credential standing unavailable: {error}");
            CredentialStanding::Unverifiable
        }
    }
}

impl CredentialWatch {
    pub(crate) fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Start watching `credential` for one socket.
    ///
    /// The watch is registered *before* the store is read, so a revocation
    /// that commits after the request authenticated — while the upgrade was
    /// in flight — is either seen by this read or announced to the lease.
    pub(crate) async fn lease(
        self: &Arc<Self>,
        pool: &sqlx::PgPool,
        credential: RevocableCredential,
    ) -> CredentialLease {
        let lease = self.register(credential);
        let answer = crate::db::credential_remaining(pool, &lease.credential).await;
        lease.settle(answer);
        lease
    }

    /// A lease on `credential` whose standing nothing has read yet.
    fn register(self: &Arc<Self>, credential: RevocableCredential) -> CredentialLease {
        let lease = self.next_lease.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = watch::channel(CredentialStanding::Unverifiable);
        self.watchers
            .lock()
            .expect("credential watch lock")
            .entry(credential.clone())
            .or_default()
            .insert(lease, sender);
        CredentialLease {
            watch: self.clone(),
            credential,
            lease,
            standing: receiver,
        }
    }

    /// Tell every socket holding `credential` what the store answered.
    fn announce(&self, credential: &RevocableCredential, answer: StoreAnswer) {
        let answer = standing(answer);
        if let Some(leases) = self
            .watchers
            .lock()
            .expect("credential watch lock")
            .get(credential)
        {
            for sender in leases.values() {
                sender.send_replace(answer);
            }
        }
    }

    fn is_watched(&self, credential: &RevocableCredential) -> bool {
        self.watchers
            .lock()
            .expect("credential watch lock")
            .contains_key(credential)
    }

    /// Read `credential` again and tell every socket holding it.
    async fn refresh(&self, pool: &sqlx::PgPool, credential: &RevocableCredential) {
        if self.is_watched(credential) {
            self.announce(
                credential,
                crate::db::credential_remaining(pool, credential).await,
            );
        }
    }

    async fn refresh_all(&self, pool: &sqlx::PgPool) {
        let watched: Vec<RevocableCredential> = self
            .watchers
            .lock()
            .expect("credential watch lock")
            .keys()
            .cloned()
            .collect();
        for credential in watched {
            self.refresh(pool, &credential).await;
        }
    }

    /// Follow the store's credential announcements for the life of the
    /// process. A lost connection is re-established with a bounded backoff,
    /// and every watched credential is read again once it is, because what
    /// was announced in between was not heard.
    pub(crate) async fn run(self: Arc<Self>, url: String, pool: sqlx::PgPool) {
        const RETRY_MIN: std::time::Duration = std::time::Duration::from_secs(1);
        const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);
        let mut retry = RETRY_MIN;
        loop {
            let mut listener = match CredentialChangeListener::connect(&url).await {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!(
                        "http: credential-change listener unavailable, retrying in {}s: {error}",
                        retry.as_secs()
                    );
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(RETRY_MAX);
                    continue;
                }
            };
            retry = RETRY_MIN;
            self.refresh_all(&pool).await;
            loop {
                match listener.next().await {
                    Ok(CredentialChange::Changed(credential)) => {
                        self.refresh(&pool, &credential).await;
                    }
                    Ok(CredentialChange::Resynchronize) => self.refresh_all(&pool).await,
                    Err(error) => {
                        eprintln!("http: credential-change listener lost: {error}");
                        break;
                    }
                }
            }
        }
    }
}

impl CredentialLease {
    /// Record the first read of the credential's standing, unless an
    /// announcement has already ended it: a revocation heard while the read
    /// was in flight stays heard.
    fn settle(&self, answer: StoreAnswer) {
        let answer = standing(answer);
        let watchers = self.watch.watchers.lock().expect("credential watch lock");
        if let Some(sender) = watchers
            .get(&self.credential)
            .and_then(|leases| leases.get(&self.lease))
        {
            sender.send_if_modified(|current| {
                if *current == CredentialStanding::Ended {
                    return false;
                }
                *current = answer;
                true
            });
        }
    }

    /// Wait until the credential stops authorizing, and say how it ended:
    /// [`CredentialStanding::Ended`] or [`CredentialStanding::Unverifiable`].
    /// Cancel-safe: dropped inside `select!`, the next call picks up where
    /// this one was.
    pub(crate) async fn ended(&mut self) -> CredentialStanding {
        loop {
            let until = match *self.standing.borrow_and_update() {
                CredentialStanding::Live { until } if tokio::time::Instant::now() < until => until,
                CredentialStanding::Live { .. } => return CredentialStanding::Ended,
                ended => return ended,
            };
            tokio::select! {
                changed = self.standing.changed() => {
                    if changed.is_err() {
                        // The lease's sender lives until the lease is dropped,
                        // so this is unreachable while `self` exists; nothing
                        // would vouch for the credential if it were not.
                        return CredentialStanding::Unverifiable;
                    }
                }
                () = tokio::time::sleep_until(until) => return CredentialStanding::Ended,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A lease the test decides the standing of, with the watch that can
    /// announce changes to it.
    pub(crate) fn lease_for_test(
        credential: RevocableCredential,
        remaining: std::time::Duration,
    ) -> (Arc<CredentialWatch>, CredentialLease) {
        let watch = CredentialWatch::new();
        let lease = watch.register(credential);
        lease.settle(Ok(Some(remaining)));
        (watch, lease)
    }

    pub(crate) fn revoke_for_test(watch: &CredentialWatch, credential: &RevocableCredential) {
        watch.announce(credential, Ok(None));
    }

    #[tokio::test]
    async fn an_announced_revocation_ends_every_lease_on_the_credential_and_no_other() {
        let revoked = RevocableCredential::browser_session("revoked");
        let kept = RevocableCredential::api_token("kept");
        let watch = CredentialWatch::new();
        let mut first = watch.register(revoked.clone());
        let mut second = watch.register(revoked.clone());
        let mut other = watch.register(kept.clone());
        for lease in [&first, &second, &other] {
            lease.settle(Ok(Some(std::time::Duration::from_secs(3600))));
        }
        watch.announce(&revoked, Ok(None));
        assert_eq!(first.ended().await, CredentialStanding::Ended);
        assert_eq!(second.ended().await, CredentialStanding::Ended);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other.ended())
                .await
                .is_err(),
            "a different credential's socket stays open"
        );
        drop((first, second));
        assert!(!watch.is_watched(&revoked), "dropped leases stop the watch");
        assert!(watch.is_watched(&kept));
    }

    #[tokio::test]
    async fn a_revocation_heard_during_the_first_read_is_not_overwritten() {
        let credential = RevocableCredential::browser_session("raced");
        let watch = CredentialWatch::new();
        let mut lease = watch.register(credential.clone());
        watch.announce(&credential, Ok(None));
        lease.settle(Ok(Some(std::time::Duration::from_secs(3600))));
        assert_eq!(lease.ended().await, CredentialStanding::Ended);
    }

    #[tokio::test(start_paused = true)]
    async fn a_credential_ends_when_it_expires() {
        let (_watch, mut lease) = lease_for_test(
            RevocableCredential::api_token("short"),
            std::time::Duration::from_secs(30),
        );
        let started = tokio::time::Instant::now();
        assert_eq!(lease.ended().await, CredentialStanding::Ended);
        assert!(started.elapsed() >= std::time::Duration::from_secs(30));
    }

    #[tokio::test]
    async fn an_unreadable_store_ends_the_socket_as_unverifiable() {
        let credential = RevocableCredential::browser_session("unknown");
        let watch = CredentialWatch::new();
        let mut lease = watch.register(credential);
        lease.settle(Err(DbError::StaleServerSettings));
        assert_eq!(lease.ended().await, CredentialStanding::Unverifiable);
    }
}
