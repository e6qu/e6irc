//! Permanent account deletion (DESIGN §9.1): one procedure, reached from the
//! web console (an administrator, or the account itself) and from NickServ
//! DROP. It installs the live authentication gate, stops the account's
//! networks, deletes its rows (passing founded channels to their successors),
//! and tells every core shard — so each caller gets the same succession
//! checks, the same gate, and the same core cleanup.

use std::sync::Arc;

use e6irc_proto::casemap::CaseMapping;

/// Everything a deletion touches besides the request itself.
#[derive(Clone)]
pub(crate) struct AccountDeletion {
    pub(crate) pool: sqlx::PgPool,
    pub(crate) core_tx: crate::core::CoreIngress,
    pub(crate) registry: Arc<crate::bouncer::Registry>,
    pub(crate) secret_key: Option<Arc<crate::secret::SecretKeyring>>,
    pub(crate) internal_upstreams: crate::egress::InternalUpstreams,
    /// Administrators configuration grants: deletion may not remove the last
    /// effective one.
    pub(crate) configured_administrators: crate::identity::ReservedAccountNames,
}

/// Why a deletion did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccountDeletionError {
    /// No account has that id.
    NotFound,
    /// The actor asked to delete its own account through a control that does
    /// not delete oneself.
    OwnAccount,
    /// The deletion would orphan a channel or remove the last administrator.
    Refused(String),
    /// A store or a live component failed; the message says which.
    Unavailable(String),
}

impl AccountDeletion {
    /// Delete one account on the registry's mutation lane, which serializes it
    /// with every network change and account suspension.
    pub(crate) async fn delete(
        &self,
        actor: &str,
        account_id: i64,
        allow_self: bool,
    ) -> Result<String, AccountDeletionError> {
        let (this, actor) = (self.clone(), actor.to_owned());
        self.registry
            .mutate(move |lane| async move {
                this.delete_in_lane(&lane, &actor, account_id, allow_self)
                    .await
            })
            .await
    }

    /// [`Self::delete`], for a caller already holding the lane.
    pub(crate) async fn delete_in_lane(
        &self,
        lane: &crate::bouncer::MutationLane,
        actor: &str,
        account_id: i64,
        allow_self: bool,
    ) -> Result<String, AccountDeletionError> {
        let pool = &self.pool;
        let target = crate::db::account_deletion_target(
            pool,
            account_id,
            &self.configured_administrators.folded_names(),
        )
        .await
        .map_err(deletion_error)?
        .ok_or(AccountDeletionError::NotFound)?;
        if !allow_self && target.folded == CaseMapping::Rfc1459.casefold(actor) {
            return Err(AccountDeletionError::OwnAccount);
        }

        self.core_tx
            .admin_action(crate::core::AdminRequest::SetAccountSuspended {
                account: target.folded.clone(),
                suspended: true,
                reason: "Account permanently deleted".into(),
                actor: actor.to_string(),
            })
            .await
            .map_err(|error| {
                AccountDeletionError::Unavailable(format!(
                    "Could not establish the live authentication gate: {error}"
                ))
            })?;

        // The owner's drivers stop before any row goes — each persistence task
        // finishing the line it is writing — so no late backlog line can land
        // after the deletion (and one that tried would fail the foreign key its
        // network's row no longer satisfies). Drivers for the running networks
        // are built first, so a deletion the database refuses restarts exactly
        // them.
        let restart = self.owner_network_restart(lane, &target).await;
        let stopped_networks = lane
            .remove_owner(&target.folded, crate::bouncer::UnwrittenLines::Discard)
            .await;
        let deleted = match crate::db::delete_account_permanently(
            pool,
            account_id,
            actor,
            &self.configured_administrators.folded_names(),
        )
        .await
        {
            Ok(Some(deleted)) => deleted,
            // The account is already gone: nothing of it may run again.
            Ok(None) => {
                self.undo_gate(&target, actor).await?;
                return Err(AccountDeletionError::NotFound);
            }
            Err(error) => {
                for (name, driver) in restart {
                    lane.ensure_running(Some(&target.folded), &name, driver)
                        .await;
                }
                self.undo_gate(&target, actor).await?;
                return Err(deletion_error(error));
            }
        };
        // The account's read markers, channel access and grouped nicks
        // cascaded away with its row, its messages were purged, and its
        // channels with a successor passed on; every core shard's mirror
        // follows, or it would be stale until a restart. The live gate stays:
        // the name is retired.
        if self
            .core_tx
            .broadcast_account_deleted(&target.folded, &deleted.successions)
            .await
            .is_err()
        {
            return Err(AccountDeletionError::Unavailable(format!(
                "Permanently deleted {}, but a live core shard is unavailable and still mirrors \
                 its read markers, history, channel access and nicks.",
                deleted.name
            )));
        }
        Ok(format!(
            "Permanently deleted {} and stopped {stopped_networks} owned network(s). The account \
             name is retired.",
            deleted.name
        ))
    }

    /// Drivers for every network of `target` that is running now, built from
    /// the stored rows so they can be restarted if its deletion is refused. A
    /// network whose row no longer builds is named on stderr: a refused
    /// deletion leaves it stopped.
    async fn owner_network_restart(
        &self,
        registry: &crate::bouncer::Registry,
        target: &crate::db::AccountDeletionTarget,
    ) -> Vec<(String, Box<dyn crate::bouncer::NetworkDriver>)> {
        let rows = match crate::db::list_bnc_networks(&self.pool, &target.name).await {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!(
                    "account deletion: networks of {} could not be listed for a restart \
                     ({error}); a refused deletion leaves them stopped",
                    target.name
                );
                return Vec::new();
            }
        };
        let mut restart = Vec::new();
        for row in rows {
            if registry.get_owned(&target.folded, &row.name).is_none() {
                continue;
            }
            match crate::bouncer::driver_from_row(
                &row,
                self.secret_key.as_deref(),
                &target.name,
                self.internal_upstreams,
                crate::bouncer::FirstDial::Immediate,
            ) {
                Ok(driver) => restart.push((row.name, driver)),
                Err(error) => eprintln!(
                    "account deletion: network {}/{} cannot be rebuilt ({error}); a refused \
                     deletion leaves it stopped",
                    target.name, row.name
                ),
            }
        }
        restart
    }

    /// Lift the live gate a deletion that did not commit installed, unless the
    /// account was already suspended: that suspension stands.
    async fn undo_gate(
        &self,
        target: &crate::db::AccountDeletionTarget,
        actor: &str,
    ) -> Result<(), AccountDeletionError> {
        if target.suspended {
            return Ok(());
        }
        self.core_tx
            .admin_action(crate::core::AdminRequest::SetAccountSuspended {
                account: target.folded.clone(),
                suspended: false,
                reason: "Account deletion did not commit".into(),
                actor: actor.to_string(),
            })
            .await
            .map(|_| ())
            .map_err(|error| {
                AccountDeletionError::Unavailable(format!(
                    "Deletion did not commit and the live authentication gate could not be \
                     removed: {error}"
                ))
            })
    }
}

fn deletion_error(error: crate::db::DbError) -> AccountDeletionError {
    match error {
        crate::db::DbError::AccountOwnsChannels(_)
        | crate::db::DbError::SuccessorChannelLimit(_)
        | crate::db::DbError::LastAdministrator => AccountDeletionError::Refused(error.to_string()),
        _ => {
            eprintln!("account deletion failed: {error}");
            AccountDeletionError::Unavailable("Database unavailable".into())
        }
    }
}

/// NickServ DROP: verify the account's primary password, then delete it
/// through [`AccountDeletion`] as the account itself. `deletion` is `None`
/// only where the server has no network registry to stop the account's
/// networks through, and then nothing is deleted.
pub(crate) async fn nickserv_drop(
    pool: &sqlx::PgPool,
    deletion: Option<&AccountDeletion>,
    account: &str,
    password: &str,
) -> crate::core::AccountDropOutcome {
    use crate::core::AccountDropOutcome;
    let verified = match crate::db::verify_local_password(pool, account, password).await {
        Ok(Some(verified)) => verified,
        Ok(None) => return AccountDropOutcome::Rejected,
        Err(crate::db::DbError::LoginThrottled(retry_after)) => {
            return AccountDropOutcome::Throttled(retry_after);
        }
        Err(error) => {
            eprintln!("NickServ DROP: password check failed: {error}");
            return AccountDropOutcome::Unavailable;
        }
    };
    let Some(deletion) = deletion else {
        eprintln!("NickServ DROP: no network registry; account deletion is unavailable");
        return AccountDropOutcome::Unavailable;
    };
    let account_id = match crate::db::account_id_by_name(pool, &verified).await {
        Ok(Some(account_id)) => account_id,
        Ok(None) => return AccountDropOutcome::Rejected,
        Err(error) => {
            eprintln!("NickServ DROP: account lookup failed: {error}");
            return AccountDropOutcome::Unavailable;
        }
    };
    match deletion.delete(&verified, account_id, true).await {
        Ok(_) => AccountDropOutcome::Dropped,
        Err(AccountDeletionError::Refused(reason)) => AccountDropOutcome::Refused(reason),
        Err(AccountDeletionError::NotFound) => AccountDropOutcome::Rejected,
        Err(AccountDeletionError::OwnAccount) => {
            unreachable!("NickServ DROP deletes the caller's own account")
        }
        Err(AccountDeletionError::Unavailable(message)) => {
            eprintln!("NickServ DROP: {message}");
            AccountDropOutcome::Unavailable
        }
    }
}
