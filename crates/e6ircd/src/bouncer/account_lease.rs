//! An attachment lives only as long as its account's authority.
//!
//! The attach listener authenticates once, at registration, but an attached
//! client stays for days. Suspending or deleting the account, or changing its
//! password, must end it — on a shared network and on an operator-configured
//! one, which neither stops with the account. So an attachment holds an
//! [`AccountLease`] on the account it authenticated as, and ends when the
//! lease is revoked ([`AccountRevocations::revoke`]).
//!
//! Authentication and the lease are two steps, and a revocation can land
//! between them: a password checked a moment before the suspension committed
//! would otherwise open an attachment after the sweep that should have ended
//! it. A [`RevocationTicket`] taken *before* the credential is checked closes
//! that window: [`AccountRevocations::lease`] refuses when the account was
//! revoked after the ticket was taken.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// Every live account lease, and the recent revocations a handshake still in
/// progress must be held to.
#[derive(Default)]
pub struct AccountRevocations {
    state: Mutex<RevocationState>,
}

#[derive(Default)]
struct RevocationState {
    /// Advances at every revocation; a ticket records it.
    epoch: u64,
    /// The epoch each account was last revoked at — only while a ticket
    /// taken before it is outstanding, which is all a later lease compares.
    revoked_at: HashMap<String, u64>,
    /// Outstanding tickets, by the epoch they were taken at.
    tickets: BTreeMap<u64, usize>,
    /// Live leases by folded account.
    leases: HashMap<String, HashMap<u64, watch::Sender<bool>>>,
    next_lease: u64,
}

impl RevocationState {
    /// Forget revocations no outstanding ticket predates.
    fn prune(&mut self) {
        match self.tickets.keys().next().copied() {
            None => self.revoked_at.clear(),
            Some(oldest) => self.revoked_at.retain(|_, at| *at > oldest),
        }
    }

    fn release_ticket(&mut self, epoch: u64) {
        if let Some(count) = self.tickets.get_mut(&epoch) {
            *count -= 1;
            if *count == 0 {
                self.tickets.remove(&epoch);
            }
        }
        self.prune();
    }
}

/// Taken before a credential is checked, and spent on the lease the check
/// earns: a revocation of the account after it was taken refuses that lease.
#[must_use = "a ticket is spent on the lease its credential check earns"]
pub struct RevocationTicket {
    revocations: Arc<AccountRevocations>,
    epoch: u64,
}

impl Drop for RevocationTicket {
    fn drop(&mut self) {
        self.revocations
            .state
            .lock()
            .expect("account revocations lock")
            .release_ticket(self.epoch);
    }
}

/// [`AccountRevocations::lease`] refused: the account was suspended, deleted,
/// or had its password changed after its credential was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRevoked;

impl std::fmt::Display for AccountRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the account was suspended, deleted, or had its password changed while it signed in",
        )
    }
}

impl std::error::Error for AccountRevoked {}

/// One attachment's hold on the authority of the account it authenticated as.
/// Dropping it stops the watch.
pub struct AccountLease {
    revocations: Arc<AccountRevocations>,
    account: String,
    folded: String,
    id: u64,
    revoked: watch::Receiver<bool>,
}

impl Drop for AccountLease {
    fn drop(&mut self) {
        let mut state = self
            .revocations
            .state
            .lock()
            .expect("account revocations lock");
        if let Some(leases) = state.leases.get_mut(&self.folded) {
            leases.remove(&self.id);
            if leases.is_empty() {
                state.leases.remove(&self.folded);
            }
        }
    }
}

fn fold(account: &str) -> String {
    e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account)
}

impl AccountRevocations {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// A ticket for a credential check about to start.
    pub fn ticket(self: &Arc<Self>) -> RevocationTicket {
        let mut state = self.state.lock().expect("account revocations lock");
        let epoch = state.epoch;
        *state.tickets.entry(epoch).or_default() += 1;
        RevocationTicket {
            revocations: self.clone(),
            epoch,
        }
    }

    /// A lease on `account`'s authority for the credential check `ticket` was
    /// taken for, unless the account was revoked since.
    pub fn lease(
        self: &Arc<Self>,
        ticket: RevocationTicket,
        account: &str,
    ) -> Result<AccountLease, AccountRevoked> {
        assert!(
            Arc::ptr_eq(&ticket.revocations, self),
            "a ticket is spent where it was taken"
        );
        let folded = fold(account);
        let mut state = self.state.lock().expect("account revocations lock");
        if state
            .revoked_at
            .get(&folded)
            .is_some_and(|at| *at > ticket.epoch)
        {
            return Err(AccountRevoked);
        }
        let id = state.next_lease;
        state.next_lease += 1;
        let (sender, revoked) = watch::channel(false);
        state
            .leases
            .entry(folded.clone())
            .or_default()
            .insert(id, sender);
        drop(state);
        Ok(AccountLease {
            revocations: self.clone(),
            account: account.to_string(),
            folded,
            id,
            revoked,
        })
    }

    /// End every attachment `account` holds, and refuse the leases of the
    /// credential checks already under way for it. Returns how many
    /// attachments were told.
    pub fn revoke(&self, account: &str) -> usize {
        let folded = fold(account);
        let mut state = self.state.lock().expect("account revocations lock");
        state.epoch += 1;
        let epoch = state.epoch;
        if !state.tickets.is_empty() {
            state.revoked_at.insert(folded.clone(), epoch);
        }
        let told = state.leases.remove(&folded).map_or(0, |leases| {
            for sender in leases.values() {
                sender.send_replace(true);
            }
            leases.len()
        });
        state.prune();
        told
    }
}

impl AccountLease {
    /// The account, as the credential check named it.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Whether the lease has already been revoked.
    pub fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    /// Wait until the account's authority ends. Cancel-safe: dropped inside
    /// `select!`, the next call picks up where this one was.
    pub async fn revoked(&mut self) {
        // The sender goes only when the lease is revoked (or dropped, which
        // `self` prevents), so a closed channel is a revocation too.
        while !*self.revoked.borrow_and_update() {
            if self.revoked.changed().await.is_err() {
                return;
            }
        }
    }
}

/// A lease on `account` from a registry of its own, for a test that attaches
/// without an account lifecycle.
#[cfg(test)]
pub(crate) fn lease_for_test(account: &str) -> AccountLease {
    let revocations = AccountRevocations::new();
    revocations
        .lease(revocations.ticket(), account)
        .expect("nothing revoked it")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ends_soon(lease: &mut AccountLease) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(50), lease.revoked())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn a_revocation_ends_every_lease_of_the_account_and_no_other() {
        let revocations = AccountRevocations::new();
        let mut first = revocations
            .lease(revocations.ticket(), "Alice")
            .expect("lease");
        let mut second = revocations
            .lease(revocations.ticket(), "alice")
            .expect("lease");
        let mut other = revocations
            .lease(revocations.ticket(), "bob")
            .expect("lease");
        assert_eq!(revocations.revoke("ALICE"), 2);
        assert!(ends_soon(&mut first).await && ends_soon(&mut second).await);
        assert!(first.is_revoked());
        assert!(!ends_soon(&mut other).await, "bob's attachment stays");
        assert_eq!(first.account(), "Alice");
    }

    /// The race the ticket closes: the credential was checked, the
    /// revocation's sweep ran, and only then was the lease asked for.
    #[tokio::test]
    async fn a_lease_is_refused_when_the_account_was_revoked_after_its_ticket() {
        let revocations = AccountRevocations::new();
        let raced = revocations.ticket();
        let unrelated = revocations.ticket();
        assert_eq!(revocations.revoke("alice"), 0, "nothing was attached yet");
        assert_eq!(
            revocations.lease(raced, "Alice").err(),
            Some(AccountRevoked)
        );
        assert!(
            revocations.lease(unrelated, "bob").is_ok(),
            "another account's check is unaffected"
        );
        // A check that starts after the revocation read the store after it.
        assert!(revocations.lease(revocations.ticket(), "alice").is_ok());
    }

    #[tokio::test]
    async fn revocations_are_forgotten_once_no_ticket_predates_them() {
        let revocations = AccountRevocations::new();
        let ticket = revocations.ticket();
        revocations.revoke("alice");
        assert_eq!(revocations.state.lock().expect("lock").revoked_at.len(), 1);
        drop(ticket);
        let state = revocations.state.lock().expect("lock");
        assert!(state.revoked_at.is_empty() && state.tickets.is_empty());
        drop(state);
        let lease = revocations
            .lease(revocations.ticket(), "alice")
            .expect("lease");
        drop(lease);
        assert!(revocations.state.lock().expect("lock").leases.is_empty());
    }
}
