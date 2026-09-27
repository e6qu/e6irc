//! An attachment lives only as long as its account's authority, and the
//! credential it signed in with.
//!
//! The attach listener authenticates once, at registration, but an attached
//! client stays for days. Suspending or deleting the account, or changing its
//! password, must end it — on a shared network and on an operator-configured
//! one, which neither stops with the account. So must revoking the app
//! password it signed in with, and nothing the account's other credentials
//! opened. So an attachment holds an [`AccountLease`] on the account it
//! authenticated as and the credential that authenticated it, and ends when
//! either is revoked ([`AccountRevocations::revoke`],
//! [`AccountRevocations::revoke_credential`]).
//!
//! Authentication and the lease are two steps, and a revocation can land
//! between them: a password checked a moment before the suspension committed
//! would otherwise open an attachment after the sweep that should have ended
//! it. A [`RevocationTicket`] taken *before* the credential is checked closes
//! that window: [`AccountRevocations::lease`] refuses when the account or the
//! credential was revoked after the ticket was taken.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::identity::{CredentialId, IssuedCredential};

/// What ended a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Revocation {
    /// The account was suspended or deleted, or its password changed.
    Account,
    /// The app password the attachment signed in with was revoked.
    Credential(IssuedCredential),
    /// The revocation listener was re-connected while the credential was
    /// checked: what it missed is re-checked, and a check read before that
    /// is refused ([`AccountRevocations::refuse_in_flight`]). It ends no
    /// live attachment; the client may sign in again at once.
    Rechecked,
}

impl Revocation {
    /// What the attached client is told as it is detached.
    pub(crate) fn notice(self) -> String {
        let why = match self {
            Self::Account => {
                "your account was suspended or deleted, or its password changed".to_string()
            }
            Self::Credential(credential) => {
                format!("the {} you signed in with was revoked", credential.kind())
            }
            Self::Rechecked => RECHECKED.to_string(),
        };
        format!(":*bnc* NOTICE * :{why}; detaching\r\n")
    }
}

impl std::fmt::Display for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Account => {
                f.write_str("the account was suspended or deleted, or its password changed")
            }
            Self::Credential(credential) => {
                write!(f, "the {credential} it signed in with was revoked")
            }
            Self::Rechecked => f.write_str(RECHECKED),
        }
    }
}

/// Why a check read before a revocation re-check is refused.
const RECHECKED: &str =
    "credentials were re-checked while yours were being verified; please sign in again";

/// What a revocation names: the leases it ends, and the ones it refuses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Revoked {
    Account(String),
    Credential(IssuedCredential),
    /// Every credential checked before the listener re-checked what it
    /// missed.
    Every,
}

impl Revoked {
    fn revocation(&self) -> Revocation {
        match self {
            Self::Account(_) => Revocation::Account,
            Self::Credential(credential) => Revocation::Credential(*credential),
            Self::Every => Revocation::Rechecked,
        }
    }
}

/// Every live account lease, and the recent revocations a handshake still in
/// progress must be held to.
#[derive(Default)]
pub struct AccountRevocations {
    state: Mutex<RevocationState>,
}

struct LiveLease {
    credential: CredentialId,
    ended: watch::Sender<Option<Revocation>>,
}

#[derive(Default)]
struct RevocationState {
    /// Advances at every revocation; a ticket records it.
    epoch: u64,
    /// The epoch each account or credential was last revoked at — only while
    /// a ticket taken before it is outstanding, which is all a later lease
    /// compares.
    revoked_at: HashMap<Revoked, u64>,
    /// Outstanding tickets, by the epoch they were taken at.
    tickets: BTreeMap<u64, usize>,
    /// Live leases by folded account.
    leases: HashMap<String, HashMap<u64, LiveLease>>,
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

    /// Record `revoked` for the tickets outstanding, and end every lease
    /// `ends` picks, telling it why. Returns how many were told.
    fn revoke(&mut self, revoked: Revoked, ends: impl Fn(&str, &LiveLease) -> bool) -> usize {
        self.epoch += 1;
        let epoch = self.epoch;
        let revocation = revoked.revocation();
        if !self.tickets.is_empty() {
            self.revoked_at.insert(revoked, epoch);
        }
        let mut told = 0;
        self.leases.retain(|account, leases| {
            leases.retain(|_, lease| {
                if !ends(account, lease) {
                    return true;
                }
                lease.ended.send_replace(Some(revocation));
                told += 1;
                false
            });
            !leases.is_empty()
        });
        self.prune();
        told
    }
}

/// Taken before a credential is checked, and spent on the lease the check
/// earns: a revocation of the account or the credential after it was taken
/// refuses that lease.
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
/// or had its password changed, or the credential was revoked, after the
/// credential was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRevoked(pub Revocation);

impl std::fmt::Display for AccountRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Revocation::Rechecked => write!(f, "{}", self.0),
            revocation => write!(f, "{revocation} while it signed in"),
        }
    }
}

impl std::error::Error for AccountRevoked {}

/// One attachment's hold on the authority of the account it authenticated as,
/// and of the credential that authenticated it. Dropping it stops the watch.
pub struct AccountLease {
    revocations: Arc<AccountRevocations>,
    account: String,
    folded: String,
    id: u64,
    ended: watch::Receiver<Option<Revocation>>,
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

    /// A lease on `account`'s authority and on `credential`, for the
    /// credential check `ticket` was taken for, unless either was revoked
    /// since.
    pub fn lease(
        self: &Arc<Self>,
        ticket: RevocationTicket,
        account: &str,
        credential: CredentialId,
    ) -> Result<AccountLease, AccountRevoked> {
        assert!(
            Arc::ptr_eq(&ticket.revocations, self),
            "a ticket is spent where it was taken"
        );
        let folded = fold(account);
        let mut state = self.state.lock().expect("account revocations lock");
        let revoked_since = |revoked: &Revoked| {
            state
                .revoked_at
                .get(revoked)
                .is_some_and(|at| *at > ticket.epoch)
        };
        if revoked_since(&Revoked::Account(folded.clone())) {
            return Err(AccountRevoked(Revocation::Account));
        }
        if let CredentialId::Issued(issued) = credential
            && revoked_since(&Revoked::Credential(issued))
        {
            return Err(AccountRevoked(Revocation::Credential(issued)));
        }
        if revoked_since(&Revoked::Every) {
            return Err(AccountRevoked(Revocation::Rechecked));
        }
        let id = state.next_lease;
        state.next_lease += 1;
        let (ended_tx, ended) = watch::channel(None);
        state.leases.entry(folded.clone()).or_default().insert(
            id,
            LiveLease {
                credential,
                ended: ended_tx,
            },
        );
        drop(state);
        Ok(AccountLease {
            revocations: self.clone(),
            account: account.to_string(),
            folded,
            id,
            ended,
        })
    }

    /// End every attachment `account` holds, and refuse the leases of the
    /// credential checks already under way for it. Returns how many
    /// attachments were told.
    pub fn revoke(&self, account: &str) -> usize {
        let folded = fold(account);
        self.state
            .lock()
            .expect("account revocations lock")
            .revoke(Revoked::Account(folded.clone()), |account, _| {
                account == folded
            })
    }

    /// End every attachment `credential` signed in, and refuse the leases of
    /// the checks of it already under way. The account's other attachments
    /// stay. Returns how many attachments were told.
    pub fn revoke_credential(&self, credential: IssuedCredential) -> usize {
        let signed_in = CredentialId::Issued(credential);
        self.state
            .lock()
            .expect("account revocations lock")
            .revoke(Revoked::Credential(credential), |_, lease| {
                lease.credential == signed_in
            })
    }

    /// The revocation listener was re-connected: refuse the lease of every
    /// credential check under way, as it may have read a credential revoked
    /// while nothing listened. Run before the listener re-reads what the live
    /// attachments hold, so a check's lease is either among them or refused.
    pub fn refuse_in_flight(&self) {
        self.state
            .lock()
            .expect("account revocations lock")
            .revoke(Revoked::Every, |_, _| false);
    }

    /// Every issued credential a live attachment signed in with.
    pub(crate) fn held_credentials(&self) -> Vec<IssuedCredential> {
        let state = self.state.lock().expect("account revocations lock");
        let mut held: Vec<IssuedCredential> = state
            .leases
            .values()
            .flat_map(HashMap::values)
            .filter_map(|lease| match lease.credential {
                CredentialId::Issued(issued) => Some(issued),
                CredentialId::AccountPassword => None,
            })
            .collect();
        held.sort_unstable();
        held.dedup();
        held
    }
}

impl AccountLease {
    /// The account, as the credential check named it.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Why the lease has already been revoked, if it has.
    pub fn revocation(&self) -> Option<Revocation> {
        *self.ended.borrow()
    }

    /// Wait until the account's authority or the credential ends, and say
    /// which. Cancel-safe: dropped inside `select!`, the next call picks up
    /// where this one was.
    pub async fn revoked(&mut self) -> Revocation {
        loop {
            if let Some(revocation) = *self.ended.borrow_and_update() {
                return revocation;
            }
            // The sender goes only when the lease is revoked, which says why
            // first, or dropped, which `self` prevents.
            if self.ended.changed().await.is_err() {
                return self
                    .ended
                    .borrow()
                    .expect("a revoked lease is told why before its sender goes");
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
        .lease(revocations.ticket(), account, CredentialId::AccountPassword)
        .expect("nothing revoked it")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: CredentialId = CredentialId::AccountPassword;
    const APP_A: IssuedCredential = IssuedCredential::AppPassword(1);
    const APP_B: IssuedCredential = IssuedCredential::AppPassword(2);

    async fn ends_soon(lease: &mut AccountLease) -> Option<Revocation> {
        tokio::time::timeout(std::time::Duration::from_millis(50), lease.revoked())
            .await
            .ok()
    }

    #[tokio::test]
    async fn a_revocation_ends_every_lease_of_the_account_and_no_other() {
        let revocations = AccountRevocations::new();
        let mut first = revocations
            .lease(revocations.ticket(), "Alice", PASSWORD)
            .expect("lease");
        let mut second = revocations
            .lease(revocations.ticket(), "alice", CredentialId::Issued(APP_A))
            .expect("lease");
        let mut other = revocations
            .lease(revocations.ticket(), "bob", PASSWORD)
            .expect("lease");
        assert_eq!(revocations.revoke("ALICE"), 2);
        assert_eq!(ends_soon(&mut first).await, Some(Revocation::Account));
        assert_eq!(ends_soon(&mut second).await, Some(Revocation::Account));
        assert_eq!(first.revocation(), Some(Revocation::Account));
        assert_eq!(ends_soon(&mut other).await, None, "bob's attachment stays");
        assert_eq!(first.account(), "Alice");
    }

    #[tokio::test]
    async fn a_credential_revocation_ends_exactly_what_it_signed_in() {
        let revocations = AccountRevocations::new();
        let mut with_a = revocations
            .lease(revocations.ticket(), "alice", CredentialId::Issued(APP_A))
            .expect("lease");
        let mut with_b = revocations
            .lease(revocations.ticket(), "alice", CredentialId::Issued(APP_B))
            .expect("lease");
        let mut with_password = revocations
            .lease(revocations.ticket(), "alice", PASSWORD)
            .expect("lease");
        assert_eq!(revocations.held_credentials(), vec![APP_A, APP_B]);
        assert_eq!(revocations.revoke_credential(APP_A), 1);
        assert_eq!(
            ends_soon(&mut with_a).await,
            Some(Revocation::Credential(APP_A))
        );
        assert_eq!(ends_soon(&mut with_b).await, None, "another app password");
        assert_eq!(ends_soon(&mut with_password).await, None, "the password");
        assert_eq!(revocations.held_credentials(), vec![APP_B]);
        assert!(
            Revocation::Credential(APP_A)
                .notice()
                .contains("app password you signed in with was revoked"),
        );
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
            revocations.lease(raced, "Alice", PASSWORD).err(),
            Some(AccountRevoked(Revocation::Account))
        );
        assert!(
            revocations.lease(unrelated, "bob", PASSWORD).is_ok(),
            "another account's check is unaffected"
        );
        // A check that starts after the revocation read the store after it.
        assert!(
            revocations
                .lease(revocations.ticket(), "alice", PASSWORD)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_lease_is_refused_when_its_credential_was_revoked_after_its_ticket() {
        let revocations = AccountRevocations::new();
        let raced = revocations.ticket();
        let other_credential = revocations.ticket();
        let password = revocations.ticket();
        assert_eq!(revocations.revoke_credential(APP_A), 0);
        assert_eq!(
            revocations
                .lease(raced, "alice", CredentialId::Issued(APP_A))
                .err(),
            Some(AccountRevoked(Revocation::Credential(APP_A)))
        );
        assert!(
            revocations
                .lease(other_credential, "alice", CredentialId::Issued(APP_B))
                .is_ok()
        );
        assert!(revocations.lease(password, "alice", PASSWORD).is_ok());
    }

    /// A lost revocation listener refuses, on re-connecting, the lease of
    /// every credential check under way, whatever it checked — it may have
    /// read a credential revoked while nothing listened — and ends no
    /// attachment; a check started after it is leased.
    #[tokio::test]
    async fn a_listener_re_check_refuses_the_leases_of_checks_under_way() {
        let revocations = AccountRevocations::new();
        let mut attached = revocations
            .lease(revocations.ticket(), "alice", CredentialId::Issued(APP_A))
            .expect("lease");
        let under_way = revocations.ticket();
        revocations.refuse_in_flight();
        let refused = revocations
            .lease(under_way, "alice", CredentialId::Issued(APP_B))
            .err()
            .expect("refused");
        assert_eq!(refused, AccountRevoked(Revocation::Rechecked));
        assert!(refused.to_string().contains("please sign in again"));
        assert_eq!(ends_soon(&mut attached).await, None, "nothing live ends");
        assert!(
            revocations
                .lease(revocations.ticket(), "alice", CredentialId::Issued(APP_B))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn revocations_are_forgotten_once_no_ticket_predates_them() {
        let revocations = AccountRevocations::new();
        let ticket = revocations.ticket();
        revocations.revoke("alice");
        revocations.revoke_credential(APP_A);
        assert_eq!(revocations.state.lock().expect("lock").revoked_at.len(), 2);
        drop(ticket);
        let state = revocations.state.lock().expect("lock");
        assert!(state.revoked_at.is_empty() && state.tickets.is_empty());
        drop(state);
        let lease = revocations
            .lease(revocations.ticket(), "alice", PASSWORD)
            .expect("lease");
        drop(lease);
        assert!(revocations.state.lock().expect("lock").leases.is_empty());
    }
}
