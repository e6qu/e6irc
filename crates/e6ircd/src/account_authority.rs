//! An account's authority in the serving process, whichever process changed
//! it (DESIGN §9.1).
//!
//! One process serves a database (DESIGN §18), and a suspension, a deletion
//! or a primary password change is usually committed by that process itself.
//! Not always: `e6ircd recover-administrator` replaces an account's password
//! from a process of its own, and an operator may change a row by hand. The
//! account's IRC sessions and bouncer attachments live in the serving process,
//! which must end them either way. Migration 0095 has the accounts table count
//! every change of an account's authority (`authority_generation`) and
//! announce it on the credential channel; the serving process follows the
//! announcements here.
//!
//! Each counted change is applied once. The [`AuthorityLedger`] remembers, per
//! account, the generation this process has applied and the standing it left:
//! a change this process makes is recorded as applied on the registry's
//! mutation lane, in the same turn it is applied, and the watcher reads the
//! announced row on that lane too, so a change is never applied a second time
//! — which would end the sessions an account had just opened with its new
//! password. The watcher's baseline is read before the rest of the server
//! reads suspended accounts at boot, and read again whenever its connection is
//! lost, so nothing committed in between is missed.
//!
//! Migration 0097 has app passwords and personal access tokens announce their
//! revocation on the same channel. A revocation ends exactly the IRC sessions
//! and attachments that credential signed in, whichever process revoked it;
//! nothing is recorded, since a revoked credential cannot sign in again.
//! After its connection is lost the watcher asks which of the credentials
//! still signed in here are still stored, and ends what the others signed in.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::bouncer::{MutationLane, OwnerHold, Registry, RegistryRefusal, UnwrittenLines};
use crate::core::{AdminRequest, CoreIngress};
use crate::db::{
    AccountAnnouncement, AccountAuthority, Announcements, CREDENTIAL_CHANGED_CHANNEL,
    CredentialChange,
};
use crate::identity::IssuedCredential;

/// Who the core is told acted, for a change another process committed.
const ANOTHER_PROCESS: &str = "another process";

/// An account's standing as this server last applied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Active,
    Suspended,
    Deleted,
}

#[derive(Debug, Clone)]
struct Applied {
    folded: String,
    generation: i64,
    standing: Standing,
}

impl Applied {
    fn of(authority: &AccountAuthority) -> Self {
        Self {
            folded: authority.folded.clone(),
            generation: authority.generation,
            standing: if authority.suspended {
                Standing::Suspended
            } else {
                Standing::Active
            },
        }
    }
}

/// What a change of an account's authority asks of this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorityStep {
    /// The account was suspended: end its sessions and attachments, stop its
    /// networks, and gate it.
    Suspend(String),
    /// The account was reactivated: lift the gate and run its networks again.
    Reactivate(String),
    /// The account's primary password changed: end its sessions and
    /// attachments.
    EndSessions(String),
    /// The account was deleted: as a suspension, and its configured networks
    /// stay held for good.
    Delete(String),
}

/// What this server has applied of each account's authority. Reachable only
/// through the mutation lane ([`MutationLane::authority_ledger`]), so a change
/// is recorded and applied in one turn.
#[derive(Debug, Default)]
pub(crate) struct AuthorityLedger(Mutex<HashMap<i64, Applied>>);

impl AuthorityLedger {
    /// Record a change this server committed and applies itself.
    pub(crate) fn applied(&self, authority: &AccountAuthority) {
        self.0
            .lock()
            .expect("authority ledger poisoned")
            .insert(authority.id, Applied::of(authority));
    }

    /// Record a deletion this server committed and applies itself.
    pub(crate) fn deleted(&self, id: i64, folded: &str) {
        self.0.lock().expect("authority ledger poisoned").insert(
            id,
            Applied {
                folded: folded.to_string(),
                generation: i64::MAX,
                standing: Standing::Deleted,
            },
        );
    }

    /// Take `accounts` as what this server's state already reflects: the
    /// baseline read at boot, before the server read which accounts are
    /// suspended. A change this server recorded since is kept.
    fn seed(&self, accounts: &[AccountAuthority]) {
        let mut ledger = self.0.lock().expect("authority ledger poisoned");
        for authority in accounts {
            ledger
                .entry(authority.id)
                .or_insert_with(|| Applied::of(authority));
        }
    }

    /// The step the account `announced` now asks of this server, as `now`
    /// re-reads it (`None`: deleted), recorded as applied.
    fn step(
        &self,
        announced: &AccountAnnouncement,
        now: Option<&AccountAuthority>,
    ) -> Option<AuthorityStep> {
        let mut ledger = self.0.lock().expect("authority ledger poisoned");
        let known = ledger.get(&announced.id).cloned();
        let step = match (known, now) {
            (Some(known), _) if known.standing == Standing::Deleted => return None,
            (known, None) => {
                let folded = known.map_or_else(|| announced.folded.clone(), |k| k.folded);
                ledger.insert(
                    announced.id,
                    Applied {
                        folded: folded.clone(),
                        generation: i64::MAX,
                        standing: Standing::Deleted,
                    },
                );
                return Some(AuthorityStep::Delete(folded));
            }
            // Created since the baseline: nothing of it predates this read,
            // unless it is already suspended.
            (None, Some(now)) => now
                .suspended
                .then(|| AuthorityStep::Suspend(now.folded.clone())),
            (Some(known), Some(now)) if now.generation <= known.generation => return None,
            (Some(known), Some(now)) => match (known.standing, now.suspended) {
                (Standing::Active, true) => Some(AuthorityStep::Suspend(now.folded.clone())),
                (Standing::Suspended, false) => Some(AuthorityStep::Reactivate(now.folded.clone())),
                (Standing::Active, false) => Some(AuthorityStep::EndSessions(now.folded.clone())),
                // A suspended account's sessions have already ended.
                (Standing::Suspended, true) => None,
                (Standing::Deleted, _) => unreachable!("matched above"),
            },
        };
        if let Some(now) = now {
            ledger.insert(now.id, Applied::of(now));
        }
        step
    }

    /// The steps every account asks of this server after announcements were
    /// missed: `accounts` is every account now.
    fn resynchronize(&self, accounts: &[AccountAuthority]) -> Vec<AuthorityStep> {
        let present: std::collections::HashSet<i64> = accounts.iter().map(|a| a.id).collect();
        let vanished: Vec<AccountAnnouncement> = self
            .0
            .lock()
            .expect("authority ledger poisoned")
            .iter()
            .filter(|(id, known)| known.standing != Standing::Deleted && !present.contains(id))
            .map(|(id, known)| AccountAnnouncement {
                id: *id,
                folded: known.folded.clone(),
            })
            .collect();
        let mut steps: Vec<AuthorityStep> = vanished
            .iter()
            .filter_map(|announced| self.step(announced, None))
            .collect();
        steps.extend(accounts.iter().filter_map(|now| {
            let announced = AccountAnnouncement {
                id: now.id,
                folded: now.folded.clone(),
            };
            self.step(&announced, Some(now))
        }));
        steps
    }
}

/// What this server stopped for a suspension.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SuspendedHere {
    pub(crate) stopped_networks: usize,
    pub(crate) held_configured: usize,
}

/// This server's side of `folded`'s suspension: every attachment ends — on the
/// operator's shared and configured networks too — and a password checked
/// while this ran cannot open another; its stored networks stop; the networks
/// the configuration defines for it are held until it is reactivated; and the
/// core gates it, ending its IRC sessions. The error names what the core said,
/// with what was stopped before it.
pub(crate) async fn suspend_here(
    lane: &MutationLane,
    core_tx: &CoreIngress,
    folded: &str,
    reason: &str,
    actor: &str,
) -> Result<SuspendedHere, (SuspendedHere, String)> {
    lane.revoke_account(folded);
    let stopped_networks = lane.remove_owner(folded, UnwrittenLines::Store).await;
    let held_configured = lane
        .hold_configured_owned(folded, OwnerHold::Suspended)
        .await;
    let stopped = SuspendedHere {
        stopped_networks,
        held_configured,
    };
    core_tx
        .admin_action(AdminRequest::SetAccountSuspended {
            account: folded.to_string(),
            suspended: true,
            reason: reason.to_string(),
            actor: actor.to_string(),
        })
        .await
        .map(|_| stopped)
        .map_err(|error| (stopped, error))
}

/// What this server ran again for a reactivation.
#[derive(Debug, Default)]
pub(crate) struct ReactivatedHere {
    pub(crate) started_networks: usize,
    /// Stored networks not started because a configured network holds the
    /// name.
    pub(crate) held: Vec<String>,
    /// The configured networks the suspension held, running again.
    pub(crate) restarted: Vec<String>,
    /// Configured networks that stay held, each with why.
    pub(crate) unbuildable: Vec<String>,
}

/// This server's side of `folded`'s reactivation: the core lifts its gate,
/// then each of `stored` (its enabled stored networks' drivers) starts and the
/// configured networks its suspension held run again. The error says what
/// stopped it part way.
pub(crate) async fn reactivate_here(
    lane: &MutationLane,
    core_tx: &CoreIngress,
    folded: &str,
    actor: &str,
    stored: Vec<(String, Box<dyn crate::bouncer::NetworkDriver>)>,
) -> Result<ReactivatedHere, String> {
    core_tx
        .admin_action(AdminRequest::SetAccountSuspended {
            account: folded.to_string(),
            suspended: false,
            reason: "Account reactivated".into(),
            actor: actor.to_string(),
        })
        .await
        .map_err(|error| format!("the live IRC core remained gated: {error}"))?;
    let mut reactivated = ReactivatedHere::default();
    for (name, driver) in stored {
        match lane.ensure_running(Some(folded), &name, driver).await {
            Ok(_) => reactivated.started_networks += 1,
            Err(RegistryRefusal::ConfiguredNetworkHeld(_)) => reactivated.held.push(name),
            Err(RegistryRefusal::Closed(closed)) => {
                return Err(format!(
                    "started only {} owned network(s): {closed}",
                    reactivated.started_networks
                ));
            }
        }
    }
    (reactivated.restarted, reactivated.unbuildable) = lane.release_configured_owned(folded);
    Ok(reactivated)
}

/// This server's side of a primary password change: every attachment ends,
/// and the core ends every IRC session and refuses a verdict for a check
/// queued before it.
pub(crate) async fn end_sessions_here(
    lane: &MutationLane,
    core_tx: &CoreIngress,
    folded: &str,
    actor: &str,
) -> Result<(), String> {
    lane.revoke_account(folded);
    core_tx
        .admin_action(AdminRequest::EndAccountSessions {
            account: folded.to_string(),
            reason: "Password changed".into(),
            actor: actor.to_string(),
        })
        .await
        .map(|_| ())
}

/// This server's side of the revocation of an app password or a personal
/// access token: every attachment it signed in ends, a check of it under way
/// cannot open another, and the core ends every IRC session it signed in and
/// refuses a verdict for a check of it queued before. The account's other
/// sessions stay.
pub(crate) async fn end_credential_here(
    registry: &Registry,
    core_tx: &CoreIngress,
    credential: IssuedCredential,
) -> Result<(), String> {
    registry.account_revocations().revoke_credential(credential);
    core_tx
        .admin_action(AdminRequest::EndCredentialSessions { credential })
        .await
        .map(|_| ())
}

/// Connect the listener and read every account's authority: the baseline this
/// server's boot reflects. Called before the boot reads suspended accounts, so
/// a change committed while it boots is announced after the baseline.
pub(crate) async fn listen(
    url: &crate::db::DatabaseUrl,
    pool: &sqlx::PgPool,
) -> Result<AuthorityBaseline, crate::db::DbError> {
    let listener = Announcements::connect(url, CREDENTIAL_CHANGED_CHANNEL).await?;
    let accounts = crate::db::every_account_authority(pool).await?;
    Ok(AuthorityBaseline { listener, accounts })
}

/// A listener connected at boot, with the accounts as the boot saw them.
pub(crate) struct AuthorityBaseline {
    listener: Announcements,
    accounts: Vec<AccountAuthority>,
}

/// Everything following another process's changes touches.
pub(crate) struct AccountAuthorityWatcher {
    pub(crate) url: crate::db::DatabaseUrl,
    pub(crate) pool: sqlx::PgPool,
    pub(crate) core_tx: CoreIngress,
    pub(crate) registry: Arc<Registry>,
    pub(crate) secret_key: Option<Arc<crate::secret::SecretKeyring>>,
    pub(crate) internal_upstreams: crate::egress::InternalUpstreams,
}

impl AccountAuthorityWatcher {
    /// Follow the store's account announcements for the life of the process.
    /// A lost connection is re-established with a bounded backoff, and every
    /// account is read again once it is, because what was announced in
    /// between was not heard.
    pub(crate) async fn run(self, baseline: AuthorityBaseline) {
        let AuthorityBaseline { listener, accounts } = baseline;
        self.registry
            .mutate(move |lane| async move { lane.authority_ledger().seed(&accounts) })
            .await;
        crate::db::follow_announcements(
            self.url.clone(),
            CREDENTIAL_CHANGED_CHANNEL,
            "account authority: listener",
            Some(listener),
            self,
        )
        .await;
    }

    /// Apply what one announced account asks of this server.
    async fn follow(&self, announced: AccountAnnouncement) -> Result<(), String> {
        let this = self.clone_handles();
        self.registry
            .mutate(move |lane| async move {
                let now = crate::db::account_authority(&this.pool, announced.id)
                    .await
                    .map_err(|error| error.to_string())?;
                if let Some(step) = lane.authority_ledger().step(&announced, now.as_ref()) {
                    this.apply(&lane, step).await;
                }
                Ok(())
            })
            .await
    }

    /// Apply what every account asks of this server after announcements were
    /// missed, then end what every credential revoked meanwhile signed in.
    async fn resynchronize(&self) -> Result<(), String> {
        let this = self.clone_handles();
        self.registry
            .mutate(move |lane| async move {
                let accounts = crate::db::every_account_authority(&this.pool)
                    .await
                    .map_err(|error| error.to_string())?;
                for step in lane.authority_ledger().resynchronize(&accounts) {
                    this.apply(&lane, step).await;
                }
                Ok::<(), String>(())
            })
            .await?;
        self.resynchronize_credentials().await
    }

    /// End what every credential signed in here that is no longer stored
    /// signed in: its revocation was announced while no one listened.
    async fn resynchronize_credentials(&self) -> Result<(), String> {
        let mut held = self.core_tx.signed_in_credentials();
        held.extend(self.registry.account_revocations().held_credentials());
        held.sort_unstable();
        held.dedup();
        if held.is_empty() {
            return Ok(());
        }
        let stored = crate::db::issued_credentials_stored(&self.pool, &held)
            .await
            .map_err(|error| error.to_string())?;
        for credential in held {
            if !stored.contains(&credential) {
                self.end_credential(credential).await;
            }
        }
        Ok(())
    }

    /// End what the revoked `credential` signed in here. What cannot be ended
    /// is said on stderr: the revocation is committed, and this server's share
    /// of it is as much as it could do.
    async fn end_credential(&self, credential: IssuedCredential) {
        if let Err(error) = end_credential_here(&self.registry, &self.core_tx, credential).await {
            eprintln!(
                "account authority: the {credential} was revoked, but the IRC sessions it signed \
                 in here were not ended: {error}"
            );
        }
    }

    fn clone_handles(&self) -> Arc<Handles> {
        Arc::new(Handles {
            pool: self.pool.clone(),
            core_tx: self.core_tx.clone(),
            secret_key: self.secret_key.clone(),
            internal_upstreams: self.internal_upstreams,
        })
    }
}

impl crate::db::Follower for AccountAuthorityWatcher {
    async fn on_change(&mut self, announcement: crate::db::Announcement) -> Result<(), String> {
        match CredentialChange::of(announcement) {
            CredentialChange::Account(announced) => self.follow(announced).await,
            CredentialChange::IssuedRevoked(credential) => {
                self.end_credential(credential).await;
                Ok(())
            }
            // A browser credential: the chat sockets' listener's.
            CredentialChange::Changed(_) => Ok(()),
            CredentialChange::Resynchronize => self.resynchronize().await,
        }
    }
}

/// What applying a step touches, moved onto the mutation lane.
struct Handles {
    pool: sqlx::PgPool,
    core_tx: CoreIngress,
    secret_key: Option<Arc<crate::secret::SecretKeyring>>,
    internal_upstreams: crate::egress::InternalUpstreams,
}

impl Handles {
    /// Apply a change another process committed. What cannot be applied is
    /// said on stderr: the change itself is committed, and this process's
    /// share of it is as much as it could do.
    async fn apply(&self, lane: &MutationLane, step: AuthorityStep) {
        match step {
            AuthorityStep::Suspend(folded) => {
                if let Err((_, error)) = suspend_here(
                    lane,
                    &self.core_tx,
                    &folded,
                    "Account suspended",
                    ANOTHER_PROCESS,
                )
                .await
                {
                    eprintln!(
                        "account authority: {folded} was suspended elsewhere, but its live IRC \
                         sessions here were not ended: {error}"
                    );
                }
            }
            AuthorityStep::Reactivate(folded) => {
                let stored = self.stored_drivers(&folded).await;
                match reactivate_here(lane, &self.core_tx, &folded, ANOTHER_PROCESS, stored).await {
                    Ok(reactivated) => {
                        for name in reactivated.held {
                            eprintln!(
                                "account authority: network {folded}/{name} not started: the \
                                 server configuration defines a network of the same name"
                            );
                        }
                        for error in reactivated.unbuildable {
                            eprintln!(
                                "account authority: a configured network of {folded} stays \
                                 stopped: {error}"
                            );
                        }
                    }
                    Err(error) => eprintln!(
                        "account authority: {folded} was reactivated elsewhere, but here {error}"
                    ),
                }
            }
            AuthorityStep::EndSessions(folded) => {
                if let Err(error) =
                    end_sessions_here(lane, &self.core_tx, &folded, ANOTHER_PROCESS).await
                {
                    eprintln!(
                        "account authority: {folded}'s password changed elsewhere, but its live \
                         IRC sessions here were not ended: {error}"
                    );
                }
            }
            AuthorityStep::Delete(folded) => {
                let suspended = suspend_here(
                    lane,
                    &self.core_tx,
                    &folded,
                    "Account permanently deleted",
                    ANOTHER_PROCESS,
                )
                .await;
                // Its name is retired: nothing of it runs here again.
                lane.hold_configured_owned(&folded, OwnerHold::Deleted)
                    .await;
                if let Err((_, error)) = suspended {
                    eprintln!(
                        "account authority: {folded} was deleted elsewhere, but its live IRC \
                         sessions here were not ended: {error}"
                    );
                }
            }
        }
    }

    /// Drivers for `folded`'s enabled stored networks. One that cannot be
    /// built is named on stderr and stays stopped.
    async fn stored_drivers(
        &self,
        folded: &str,
    ) -> Vec<(String, Box<dyn crate::bouncer::NetworkDriver>)> {
        let rows = match crate::db::list_bnc_networks(&self.pool, folded).await {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!(
                    "account authority: the networks of {folded} could not be listed, so they \
                     stay stopped here: {error}"
                );
                return Vec::new();
            }
        };
        let mut drivers = Vec::new();
        for row in rows.into_iter().filter(|row| row.enabled) {
            match crate::bouncer::driver_from_row(
                &row,
                self.secret_key.as_deref(),
                folded,
                self.internal_upstreams,
                crate::bouncer::FirstDial::Immediate,
            ) {
                Ok(driver) => drivers.push((row.name, driver)),
                Err(error) => eprintln!(
                    "account authority: network {folded}/{} cannot be built and stays stopped \
                     here: {error}",
                    row.name
                ),
            }
        }
        drivers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(id: i64, folded: &str, generation: i64, suspended: bool) -> AccountAuthority {
        AccountAuthority {
            id,
            folded: folded.into(),
            generation,
            suspended,
        }
    }

    fn announced(id: i64, folded: &str) -> AccountAnnouncement {
        AccountAnnouncement {
            id,
            folded: folded.into(),
        }
    }

    #[test]
    fn each_counted_change_is_applied_once_and_as_what_it_changed() {
        let ledger = AuthorityLedger::default();
        ledger.seed(&[authority(1, "alice", 1, false)]);
        let alice = announced(1, "alice");
        // A generation already applied asks nothing.
        assert_eq!(
            ledger.step(&alice, Some(&authority(1, "alice", 1, false))),
            None
        );
        assert_eq!(
            ledger.step(&alice, Some(&authority(1, "alice", 2, true))),
            Some(AuthorityStep::Suspend("alice".into()))
        );
        assert_eq!(
            ledger.step(&alice, Some(&authority(1, "alice", 2, true))),
            None
        );
        assert_eq!(
            ledger.step(&alice, Some(&authority(1, "alice", 3, false))),
            Some(AuthorityStep::Reactivate("alice".into()))
        );
        assert_eq!(
            ledger.step(&alice, Some(&authority(1, "alice", 4, false))),
            Some(AuthorityStep::EndSessions("alice".into()))
        );
        assert_eq!(
            ledger.step(&alice, None),
            Some(AuthorityStep::Delete("alice".into()))
        );
        assert_eq!(ledger.step(&alice, None), None, "deleted once");
    }

    #[test]
    fn a_change_this_server_applied_itself_is_not_applied_again() {
        let ledger = AuthorityLedger::default();
        ledger.seed(&[authority(1, "alice", 1, false)]);
        // This server changed the password (generation 2) and applied it; the
        // account then signs in again with the new one.
        ledger.applied(&authority(1, "alice", 2, false));
        assert_eq!(
            ledger.step(
                &announced(1, "alice"),
                Some(&authority(1, "alice", 2, false))
            ),
            None,
            "its own announcement ends nothing"
        );
        ledger.deleted(1, "alice");
        assert_eq!(ledger.step(&announced(1, "alice"), None), None);
        // A seed read before this server's own change does not undo it.
        ledger.seed(&[authority(1, "alice", 1, false)]);
        assert_eq!(ledger.step(&announced(1, "alice"), None), None);
    }

    #[test]
    fn an_account_created_since_the_baseline_asks_nothing_unless_suspended() {
        let ledger = AuthorityLedger::default();
        assert_eq!(
            ledger.step(&announced(7, "bob"), Some(&authority(7, "bob", 1, false))),
            None
        );
        assert_eq!(
            ledger.step(
                &announced(8, "carol"),
                Some(&authority(8, "carol", 1, true))
            ),
            Some(AuthorityStep::Suspend("carol".into()))
        );
        // Deleted before its creation was read: named by its announcement.
        assert_eq!(
            ledger.step(&announced(9, "dave"), None),
            Some(AuthorityStep::Delete("dave".into()))
        );
    }

    #[test]
    fn a_resynchronization_applies_what_was_missed() {
        let ledger = AuthorityLedger::default();
        ledger.seed(&[
            authority(1, "alice", 1, false),
            authority(2, "bob", 1, false),
            authority(3, "carol", 2, true),
            authority(4, "dave", 1, false),
        ]);
        let mut steps = ledger.resynchronize(&[
            authority(1, "alice", 1, false),
            authority(2, "bob", 2, true),
            authority(3, "carol", 3, false),
            authority(5, "erin", 1, false),
        ]);
        steps.sort_by_key(|step| format!("{step:?}"));
        assert_eq!(
            steps,
            vec![
                AuthorityStep::Delete("dave".into()),
                AuthorityStep::Reactivate("carol".into()),
                AuthorityStep::Suspend("bob".into()),
            ]
        );
        assert!(
            ledger.resynchronize(&[]).len() == 4,
            "every remaining account is gone"
        );
    }
}
