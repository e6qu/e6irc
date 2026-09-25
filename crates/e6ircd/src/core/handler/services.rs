//! The integrated NickServ and ChanServ pseudo-clients.

use super::*;

// ---- services pseudo-clients --------------------------------------------

/// Clear every hot map scoped to a registration after PostgreSQL confirms the
/// row is gone. `channel_access` cascades with the row; the other fields are
/// columns on it. One cleanup funnel serves ChanServ and the HTTP console.
pub(crate) fn clear_registered_channel(state: &mut ServerState, key: &ChanKey) {
    state.registered_founders.remove(key);
    state.registered_topics.remove(key);
    state.pending_channel_topics.remove(key);
    state.channel_options.remove(key);
}

/// Whether `key` (a casefolded nick) is a reserved services pseudo-client.
/// PRIVMSG to these is intercepted (see `deliver_one_message`), so they are
/// also reserved at NICK — one list ([`crate::identity::SERVICE_NICKS`]) backs
/// both, and account naming too, so the intercept and the reservations can't
/// disagree and let a user seize a service nick.
pub(super) fn is_service_nick(key: &str) -> bool {
    crate::identity::SERVICE_NICKS.contains(&key)
}

pub(super) fn services_dispatch(
    state: &mut ServerState,
    conn: ConnId,
    service_key: &str,
    text: &str,
) {
    let mut words = text.split_whitespace();
    let command = words
        .next()
        .map(|w| w.to_ascii_uppercase())
        .unwrap_or_default();
    let args: Vec<&str> = words.collect();
    match service_key {
        "nickserv" => nickserv(state, conn, &command, &args),
        "chanserv" => chanserv(state, conn, &command, &args),
        _ => unreachable!("caller matched the service key"),
    }
}

pub(super) fn nickserv(state: &mut ServerState, conn: ConnId, command: &str, args: &[&str]) {
    match command {
        "REGISTER" => nickserv_register(state, conn, args),
        "IDENTIFY" => nickserv_identify(state, conn, args),
        "GHOST" => nickserv_ghost(state, conn, args),
        "REGAIN" => nickserv_regain(state, conn, args),
        "GROUP" => nickserv_group(state, conn),
        "UNGROUP" => nickserv_ungroup(state, conn, args),
        "INFO" => nickserv_info(state, conn, args),
        "SET" => nickserv_set(state, conn, args),
        "DROP" => nickserv_drop(state, conn, args),
        "LOGOUT" => {
            // De-identify: clear the account and tell account-notify peers the
            // session is now unauthenticated (`ACCOUNT *`). Founder/access
            // authority is checked live against `account`, so it is revoked at
            // once; a client can now drop its identity without reconnecting.
            if state.sessions[&conn].account().is_none() {
                state.service_notice(conn, "NickServ", "You are not logged in.");
                return;
            }
            state.clear_account(conn);
            super::sasl::notify_account_change(state, conn, "*");
            state.service_notice(conn, "NickServ", "You are now logged out.");
        }
        "HELP" => {
            for line in [
                "***** NickServ Help *****",
                "REGISTER <password> [email] - Register your current nick",
                "IDENTIFY [account] <password> - Log in to your account",
                "LOGOUT - Log out of your account (de-identify)",
                "GHOST <nick> - Disconnect a lingering session on a nick you own",
                "REGAIN <nick> - Take back a nick you own from whoever holds it",
                "GROUP - Add your current nick to your account",
                "UNGROUP [nick] - Remove a grouped nick from your account",
                "INFO [nick] - Show information about a registered nick or account",
                "SET ENFORCE <ON|OFF> - Rename unidentified users of your nicks",
                "DROP <account> <password> - Permanently delete your account",
                "***** End of Help *****",
            ] {
                state.service_notice(conn, "NickServ", line);
            }
        }
        _ => {
            state.service_notice(
                conn,
                "NickServ",
                "Invalid command. Use \x02/msg NickServ HELP\x02 for a command listing.",
            );
        }
    }
}

fn nickserv_register(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let (password, contact_email) = match args {
        [password] if !state.config.registration_require_email => (*password, None),
        [password, email] => match crate::identity::ContactEmail::parse(email) {
            Ok(email) => (*password, Some(email)),
            Err(_) => {
                state.service_notice(
                    conn,
                    "NickServ",
                    "Invalid email address. Syntax: REGISTER <password> [email]",
                );
                return;
            }
        },
        _ => {
            state.service_notice(conn, "NickServ", "Syntax: REGISTER <password> [email]");
            return;
        }
    };
    if state.sessions[&conn].account().is_some() {
        state.service_notice(conn, "NickServ", "You are already logged in.");
        return;
    }
    let name = registered_nick(state, conn);
    if refuse_unclaimable_nick(state, conn, &name) {
        return;
    }
    // Per-IP account-creation throttle (mirrors the REGISTER path): the
    // per-connection budget alone doesn't stop one address minting
    // accounts across a churn of short-lived connections.
    if !state.registration_rate_ok(conn) {
        state.service_notice(
            conn,
            "NickServ",
            "Too many account registrations from your address. Try again later.",
        );
        return;
    }
    // Account creation runs argon2 (a full hash even when the account
    // already exists, via ON CONFLICT), so it must spend from the shared
    // per-connection credential budget — otherwise a loop of REGISTER
    // drives unbounded argon2 work, bypassing the SASL cap. Closes the
    // connection when the budget is exhausted.
    if !credential_attempt_ok(state, conn) {
        return;
    }
    let request = crate::core::DbRequest::CreateAccount {
        conn,
        name,
        contact_email,
        password: password.to_string(),
        origin: crate::core::AccountOrigin::NickServ,
    };
    if state.db_tx.try_push(request).is_err() {
        services_unavailable(state, conn, "NickServ");
    }
}

/// Tell `conn` why no account may claim `nick`, when none may (see
/// [`crate::identity::ReservedAccountNames::claimable`]). NickServ REGISTER and
/// GROUP both ask it, so a nick one refuses the other cannot take.
fn refuse_unclaimable_nick(state: &mut ServerState, conn: ConnId, nick: &str) -> bool {
    let refusal = state.config.reserved_account_names.claimable(nick);
    let Err(refusal) = refusal else {
        return false;
    };
    let why = match refusal {
        crate::identity::NameClaimRefusal::ServiceNick => "is a services nick",
        crate::identity::NameClaimRefusal::ConfiguredAdministrator => {
            "is reserved for a server administrator"
        }
    };
    state.service_notice(
        conn,
        "NickServ",
        &format!("\x02{nick}\x02 {why} and cannot be registered."),
    );
    true
}

fn nickserv_identify(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // IDENTIFY <password> | IDENTIFY <account> <password>
    let (account, password) = match args {
        [password] => (registered_nick(state, conn), *password),
        [account, password] => (account.to_string(), *password),
        _ => {
            state.service_notice(conn, "NickServ", "Syntax: IDENTIFY [account] <password>");
            return;
        }
    };
    // One credential verification may be in flight per connection.
    if state.sessions[&conn].sasl_verify_pending || state.sessions[&conn].pending_identify.is_some()
    {
        state.service_notice(
            conn,
            "NickServ",
            "An authentication is already in progress. Try again in a moment.",
        );
        return;
    }
    // Password verification runs argon2 (even a nonexistent account
    // spends a dummy verify to avoid a timing oracle), so it spends from
    // the shared per-connection credential budget — the same cap SASL
    // enforces, so IDENTIFY can't be looped to brute-force or burn CPU.
    if !credential_attempt_ok(state, conn) {
        return;
    }
    let request = crate::core::DbRequest::VerifyPassword {
        conn,
        account,
        password: password.to_string(),
        origin: crate::core::CredentialOrigin::NickServIdentify,
    };
    if state.db_tx.try_push(request).is_err() {
        // Synchronous failure: the normal dispatch capture frames this
        // under the command's label, so no deferred hold is set up.
        services_unavailable(state, conn, "NickServ");
    } else {
        let label = state.capture.as_mut().and_then(|cap| {
            cap.label.clone().inspect(|_| {
                cap.deferred = true;
            })
        });
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .pending_identify = Some(crate::core::state::PendingServiceReply::new(label));
    }
}

/// The nick of a session that sent a services command: it is registered.
fn registered_nick(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("a services command comes from a registered session")
}

/// GHOST and REGAIN act on a nick the caller owns that another session holds.
/// Returns that session, or `None` once the caller has been told why not.
fn owned_nick_holder(
    state: &mut ServerState,
    conn: ConnId,
    command: &str,
    args: &[&str],
) -> Option<(String, ConnId)> {
    let Some(&nick) = args.first() else {
        state.service_notice(conn, "NickServ", &format!("Syntax: {command} <nick>"));
        return None;
    };
    let account = require_identified(
        state,
        conn,
        "NickServ",
        &format!("You must identify to services before using {command}."),
    )?;
    let key = state.nick_key(nick);
    if !state.nick_owned_by(&key, &account) {
        state.service_notice(conn, "NickServ", &format!("You do not own \x02{nick}\x02."));
        return None;
    }
    let Some(holder) = state.nick_reservation(&key).map(|owner| owner.conn()) else {
        state.service_notice(conn, "NickServ", &format!("\x02{nick}\x02 is not online."));
        return None;
    };
    if holder == conn {
        let verb = command.to_ascii_lowercase();
        state.service_notice(conn, "NickServ", &format!("You may not {verb} yourself."));
        return None;
    }
    Some((nick.to_string(), holder))
}

fn nickserv_ghost(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // GHOST <nick>: disconnect a lingering session holding a nick you own
    // (the account's name, or a nick grouped to it), so you can reclaim it.
    let Some((nick, victim)) = owned_nick_holder(state, conn, "GHOST", args) else {
        return;
    };
    if !audit_nick_action(state, conn, "NICK_GHOST", &nick) {
        return;
    }
    let by = registered_nick(state, conn);
    super::session_action(
        state,
        victim,
        crate::core::state::SessionAction::Ghost { by },
    );
    state.service_notice(
        conn,
        "NickServ",
        &format!("\x02{nick}\x02 has been ghosted."),
    );
}

fn nickserv_regain(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // REGAIN <nick> (Atheme): the session holding a nick you own is renamed to
    // a Guest nick, and you take the nick. The holder may live on another
    // shard: its shard renames it, then hands the nick to this session's.
    let Some((nick, holder)) = owned_nick_holder(state, conn, "REGAIN", args) else {
        return;
    };
    if !audit_nick_action(state, conn, "NICK_REGAIN", &nick) {
        return;
    }
    let by_mask = state.sessions[&conn].prefix();
    let by = state.session_shard(conn);
    super::session_action(
        state,
        holder,
        crate::core::state::SessionAction::Regain { nick, by, by_mask },
    );
}

/// Record a NickServ action on another session's nick — `action` by the
/// caller's account on `nick` — before it is taken; when the audit trail
/// cannot record it, the caller is told and it is not taken.
fn audit_nick_action(state: &mut ServerState, conn: ConnId, action: &str, nick: &str) -> bool {
    let account = state.sessions[&conn]
        .account()
        .map(str::to_owned)
        .expect("a NickServ action on an owned nick comes from an identified session");
    let target = state.nick_key(nick);
    if super::oper::queue_audit(
        state,
        &crate::db::AuditPrincipal::account(&account),
        action,
        &crate::db::AuditPrincipal::nick(target.as_str()),
        "",
    )
    .is_err()
    {
        services_unavailable(state, conn, "NickServ");
        return false;
    }
    true
}

/// On the shard holding a regained nick: rename its holder to a Guest nick,
/// then give the nick to the session that regained it.
pub(crate) fn regain_nick_from(
    state: &mut ServerState,
    holder: ConnId,
    nick: String,
    by: crate::core::SessionOwner,
    by_mask: &str,
) {
    let key = state.nick_key(&nick);
    let holds = state
        .sessions
        .get(&holder)
        .and_then(|session| session.nick())
        .is_some_and(|held| state.nick_key(held) == key);
    if holds {
        state.service_notice(
            holder,
            "NickServ",
            &format!("{by_mask} has regained your nickname."),
        );
        rename_to_guest(state, holder);
    }
    super::session_action(
        state,
        by.conn(),
        crate::core::state::SessionAction::TakeNick { nick },
    );
}

/// On the shard of a session that regained `nick`: take it, now that its
/// holder has let it go.
pub(crate) fn take_regained_nick(state: &mut ServerState, conn: ConnId, nick: &str) {
    if !state.sessions.contains_key(&conn) {
        return;
    }
    if super::force_nick(state, conn, nick) {
        state.service_notice(
            conn,
            "NickServ",
            &format!("\x02{nick}\x02 has been regained."),
        );
    } else {
        state.service_notice(
            conn,
            "NickServ",
            &format!("\x02{nick}\x02 could not be regained: someone else took it first."),
        );
    }
}

fn nickserv_group(state: &mut ServerState, conn: ConnId) {
    // GROUP: add the nick in use to the account identified to.
    let Some(account) = require_identified(
        state,
        conn,
        "NickServ",
        "You must identify to services before using GROUP.",
    ) else {
        return;
    };
    let nick = registered_nick(state, conn);
    if state.nick_owned_by(&state.nick_key(&nick), &account) {
        state.service_notice(
            conn,
            "NickServ",
            &format!("Nick \x02{nick}\x02 is already registered to your account."),
        );
        return;
    }
    if refuse_unclaimable_nick(state, conn, &nick) {
        return;
    }
    let label = captured_label(state, conn);
    let request = crate::core::DbRequest::GroupNick {
        conn,
        account,
        nick,
        label,
    };
    queue_service_verdict(state, conn, "NickServ", request);
}

fn nickserv_ungroup(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // UNGROUP [nick]: remove a grouped nick (the current one by default).
    let Some(account) = require_identified(
        state,
        conn,
        "NickServ",
        "You must identify to services before using UNGROUP.",
    ) else {
        return;
    };
    let nick = match args.first() {
        Some(&nick) => nick.to_string(),
        None => registered_nick(state, conn),
    };
    let key = state.nick_key(&nick);
    if state.account_key(key.as_str()) == state.account_key(&account) {
        state.service_notice(
            conn,
            "NickServ",
            &format!("Nick \x02{nick}\x02 is your account name; you may not remove it."),
        );
        return;
    }
    if !state.nick_owned_by(&key, &account) {
        state.service_notice(
            conn,
            "NickServ",
            &format!("Nick \x02{nick}\x02 is not registered to your account."),
        );
        return;
    }
    let label = captured_label(state, conn);
    let request = crate::core::DbRequest::UngroupNick {
        conn,
        account,
        nick,
        label,
    };
    queue_service_verdict(state, conn, "NickServ", request);
}

fn nickserv_info(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // INFO <nick|account>; with no argument, the caller's own account.
    let target = match (args.first(), state.sessions[&conn].account()) {
        (Some(&target), _) => target.to_string(),
        (None, Some(account)) => account.to_string(),
        (None, None) => {
            state.service_notice(conn, "NickServ", "Syntax: INFO <nick>");
            return;
        }
    };
    let label = captured_label(state, conn);
    let request = crate::core::DbRequest::AccountInfo {
        conn,
        target,
        label,
    };
    queue_service_verdict(state, conn, "NickServ", request);
}

fn nickserv_set(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&option) = args.first() else {
        state.service_notice(conn, "NickServ", "Syntax: SET <option> <value>");
        return;
    };
    let Some(account) = require_identified(
        state,
        conn,
        "NickServ",
        "You must identify to services before using SET.",
    ) else {
        return;
    };
    match option.to_ascii_uppercase().as_str() {
        "ENFORCE" => {
            let enforce = match args.get(1).map(|value| value.to_ascii_uppercase()) {
                Some(value) if value == "ON" => true,
                Some(value) if value == "OFF" => false,
                _ => {
                    state.service_notice(conn, "NickServ", "Syntax: SET ENFORCE <ON|OFF>");
                    return;
                }
            };
            let label = captured_label(state, conn);
            let request = crate::core::DbRequest::SetNickEnforce {
                conn,
                account,
                enforce,
                label,
            };
            queue_service_verdict(state, conn, "NickServ", request);
        }
        other => state.service_notice(
            conn,
            "NickServ",
            &format!("Unknown SET option \x02{other}\x02. Available: ENFORCE."),
        ),
    }
}

fn nickserv_drop(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    // DROP <account> <password> [key]: permanently delete the account the
    // caller is identified to. The first form hands out a confirmation key;
    // repeating the command with it does the deletion (Atheme).
    let (target, password, key) = match args {
        [target, password] => (*target, *password, None),
        [target, password, key] => (*target, *password, Some(*key)),
        _ => {
            state.service_notice(conn, "NickServ", "Syntax: DROP <account> <password>");
            return;
        }
    };
    let Some(account) = require_identified(
        state,
        conn,
        "NickServ",
        "You must identify to services before using DROP.",
    ) else {
        return;
    };
    let account_key = state.account_key(&account);
    if state.account_key(target) != account_key {
        state.service_notice(
            conn,
            "NickServ",
            &format!("You may only drop the account you are identified to, \x02{account}\x02."),
        );
        return;
    }
    let Some(key) = key else {
        let key: String = crate::secret::random_url_safe_token()
            .chars()
            .take(DROP_KEY_LEN)
            .collect();
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .drop_confirmation = Some((account_key, key.clone()));
        state.service_notice(
            conn,
            "NickServ",
            &format!(
                "This is a friendly reminder that you are about to \x02destroy\x02 the account \
                 \x02{account}\x02."
            ),
        );
        state.service_notice(
            conn,
            "NickServ",
            &format!(
                "To avoid accidental use of this command, this operation has to be confirmed. \
                 Please confirm by replying with \x02/msg NickServ DROP {target} <password> \
                 {key}\x02"
            ),
        );
        return;
    };
    let confirmed = state.sessions[&conn]
        .drop_confirmation
        .as_ref()
        .is_some_and(|(confirmed, expected)| *confirmed == account_key && expected == key);
    if !confirmed {
        state.service_notice(
            conn,
            "NickServ",
            &format!("Invalid key for \x02{account}\x02."),
        );
        return;
    }
    state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .drop_confirmation = None;
    // The password is verified with argon2: it spends from the connection's
    // credential budget like IDENTIFY.
    if !credential_attempt_ok(state, conn) {
        return;
    }
    let label = captured_label(state, conn);
    let request = crate::core::DbRequest::DropAccount {
        conn,
        account,
        password: password.to_string(),
        label,
    };
    queue_service_verdict(state, conn, "NickServ", request);
}

/// Length of the NickServ DROP confirmation key: it guards against a mistyped
/// command, not an attacker (the password does that).
const DROP_KEY_LEN: usize = 8;

/// The label of the command being handled for `conn`, carried onto a deferred
/// services verdict.
fn captured_label(state: &ServerState, conn: ConnId) -> Option<String> {
    state
        .capture
        .as_ref()
        .filter(|capture| capture.conn == conn)
        .and_then(|capture| capture.label.clone())
}

fn services_unavailable(state: &mut ServerState, conn: ConnId, service: &str) {
    state.service_notice(conn, service, SERVICES_UNAVAILABLE);
}

/// A NickServ verdict from PostgreSQL. What it confirms is applied to the
/// process-wide mirror even when the requester has gone: the database has
/// committed it.
pub(crate) fn nickserv_db_reply(
    state: &mut ServerState,
    conn: ConnId,
    reply: crate::core::DbReply,
) {
    use crate::db::{NickEnforceChange, NickGroupOutcome};
    let (label, text): (Option<String>, Vec<String>) = match reply {
        crate::core::DbReply::NickGroup {
            account,
            nick,
            outcome,
            label,
        } => {
            // Storage says the nick is this account's either way; the mirror
            // takes that answer too, so it heals if it ever missed a group.
            if matches!(
                outcome,
                Some(NickGroupOutcome::Grouped | NickGroupOutcome::AlreadyYours)
            ) {
                mirror_grouped_nick(state, &nick, &account);
            }
            let text = match outcome {
                Some(NickGroupOutcome::Grouped) => {
                    format!("Nick \x02{nick}\x02 is now registered to your account.")
                }
                Some(NickGroupOutcome::AlreadyYours) => {
                    format!("Nick \x02{nick}\x02 is already registered to your account.")
                }
                Some(NickGroupOutcome::Taken) => {
                    format!("Nick \x02{nick}\x02 is already registered to another account.")
                }
                Some(NickGroupOutcome::TooMany) => format!(
                    "You have too many nicks registered: an account holds at most {}.",
                    crate::db::MAX_NICKS_PER_ACCOUNT
                ),
                Some(NickGroupOutcome::AccountMissing) => {
                    format!("Your account \x02{account}\x02 no longer exists.")
                }
                None => SERVICES_UNAVAILABLE.to_string(),
            };
            (label, vec![text])
        }
        crate::core::DbReply::NickUngroup {
            account,
            nick,
            removed,
            label,
        } => {
            // Either answer means storage holds no grouping of the nick to
            // this account now: the mirror drops one it still has.
            if removed.is_some() {
                let (key, account) = (state.nick_key(&nick), state.account_key(&account));
                state.nick_registrations.ungroup_from(&key, &account);
            }
            let text = match removed {
                Some(true) => format!("Nick \x02{nick}\x02 has been removed from your account."),
                Some(false) => format!("Nick \x02{nick}\x02 is not registered to your account."),
                None => SERVICES_UNAVAILABLE.to_string(),
            };
            (label, vec![text])
        }
        crate::core::DbReply::NickEnforce {
            account,
            enforce,
            outcome,
            label,
        } => {
            if matches!(
                outcome,
                Some(NickEnforceChange::Changed | NickEnforceChange::Unchanged)
            ) {
                let key = state.account_key(&account);
                // A late answer for an account deleted since protects nothing.
                if !(enforce && state.account_deleted(&key)) {
                    state.nick_registrations.set_enforce(key, enforce);
                }
            }
            let text = match (outcome, enforce) {
                (Some(NickEnforceChange::Changed), true) => {
                    format!("The \x02ENFORCE\x02 flag has been set for account \x02{account}\x02.")
                }
                (Some(NickEnforceChange::Changed), false) => format!(
                    "The \x02ENFORCE\x02 flag has been removed for account \x02{account}\x02."
                ),
                (Some(NickEnforceChange::Unchanged), true) => format!(
                    "The \x02ENFORCE\x02 flag is already set for account \x02{account}\x02."
                ),
                (Some(NickEnforceChange::Unchanged), false) => {
                    format!("The \x02ENFORCE\x02 flag is not set for account \x02{account}\x02.")
                }
                (Some(NickEnforceChange::AccountMissing), _) => {
                    format!("Your account \x02{account}\x02 no longer exists.")
                }
                (None, _) => SERVICES_UNAVAILABLE.to_string(),
            };
            (label, vec![text])
        }
        crate::core::DbReply::AccountInfo {
            target,
            info,
            label,
        } => {
            let text = match info {
                // Nothing to show to a requester that has gone.
                Ok(Some(_)) if !state.sessions.contains_key(&conn) => Vec::new(),
                Ok(Some(info)) => account_info_lines(state, conn, &target, info),
                Ok(None) => vec![format!("\x02{target}\x02 is not registered.")],
                Err(()) => vec![SERVICES_UNAVAILABLE.to_string()],
            };
            (label, text)
        }
        crate::core::DbReply::AccountDrop {
            account,
            outcome,
            label,
        } => {
            let text = match outcome {
                crate::core::AccountDropOutcome::Dropped => {
                    format!("The account \x02{account}\x02 has been dropped.")
                }
                crate::core::AccountDropOutcome::Rejected => {
                    format!("Invalid password for \x02{account}\x02.")
                }
                crate::core::AccountDropOutcome::Throttled(retry_after) => format!(
                    "Too many password attempts for \x02{account}\x02; try again in {} seconds.",
                    retry_after.seconds()
                ),
                crate::core::AccountDropOutcome::Refused(reason) => {
                    format!("\x02{account}\x02 cannot be dropped: {reason}.")
                }
                crate::core::AccountDropOutcome::Unavailable => SERVICES_UNAVAILABLE.to_string(),
            };
            (label, vec![text])
        }
        other => unreachable!("not a NickServ verdict: {other:?}"),
    };
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, |state| {
            for line in &text {
                state.service_notice(conn, "NickServ", line);
            }
        });
    }
}

const SERVICES_UNAVAILABLE: &str = "Services are temporarily unavailable. Try again later.";

/// Record in the mirror that storage holds `nick` grouped to `account` —
/// unless the account was deleted since, whose nicks went with it: a late
/// verdict cannot bring them back.
fn mirror_grouped_nick(state: &mut ServerState, nick: &str, account: &str) {
    let (nick_key, account_key) = (state.nick_key(nick), state.account_key(account));
    if state.account_deleted(&account_key) || state.account_key(nick_key.as_str()) == account_key {
        return;
    }
    state.nick_registrations.group(nick_key, account_key);
}

/// NickServ INFO, in Atheme's layout. The account's nicks are shown to the
/// account itself and to operators only.
fn account_info_lines(
    state: &ServerState,
    conn: ConnId,
    target: &str,
    info: crate::db::NickServAccountInfo,
) -> Vec<String> {
    let session = &state.sessions[&conn];
    let account_key = state.account_key(&info.name);
    let privileged = session.oper.is_some()
        || session
            .account()
            .is_some_and(|own| state.account_key(own) == account_key);
    let now = (state.config.clock)();
    let mut lines = vec![
        format!(
            "Information on \x02{target}\x02 (account \x02{}\x02):",
            info.name
        ),
        format!(
            "Registered : {} ({} ago)",
            atheme_time(info.registered_at),
            time_ago(now.saturating_sub(info.registered_at).as_secs())
        ),
    ];
    if state.account_online(&account_key) {
        lines.push("Last seen  : now".to_string());
    }
    if privileged {
        lines.push(format!("Nicks      : {}", info.nicks.join(" ")));
    }
    if info.enforce {
        lines.push("Flags      : Enforce".to_string());
    }
    lines.push("*** \x02End of Info\x02 ***".to_string());
    lines
}

/// `Mon DD HH:MM:SS YYYY` (UTC), the timestamp Atheme's INFO prints.
fn atheme_time(at: e6irc_proto::time::Millis) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // `YYYY-MM-DDThh:mm:ss.sssZ`
    let iso = e6irc_proto::time::server_time(at);
    let month = iso[5..7]
        .parse::<usize>()
        .expect("server-time month is two digits");
    format!(
        "{} {} {} {}",
        MONTHS[month - 1],
        &iso[8..10],
        &iso[11..19],
        &iso[0..4]
    )
}

/// An elapsed time as Atheme's `time_ago` spells it: the two or three largest
/// units, e.g. `1y 2w 3d`, `3d 4h 5m`, `5m 6s`.
fn time_ago(seconds: u64) -> String {
    let (years, rest) = (seconds / 31_536_000, seconds % 31_536_000);
    let (weeks, rest) = (rest / 604_800, rest % 604_800);
    let (days, rest) = (rest / 86_400, rest % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, secs) = (rest / 60, rest % 60);
    if years > 0 {
        format!("{years}y {weeks}w {days}d")
    } else if weeks > 0 {
        format!("{weeks}w {days}d {hours}h")
    } else if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

// ---- nick protection (NickServ ENFORCE) ----------------------------------

/// How long a user holding a protected nick has to identify before it is
/// renamed to a Guest nick (Atheme's default enforcement delay). The rename
/// runs on the first reaper tick at or after the deadline — or at once, for a
/// session returning to a nick whose deadline has already passed.
pub(crate) const NICK_ENFORCE_DELAY_MS: u64 = 30_000;

/// Guest nicks are `Guest` and a number of at most this many digits: every
/// one fits a `NICKLEN` of [`crate::config::MIN_NICKLEN`].
const GUEST_NICK_DIGITS: u32 = 5;
const GUEST_NICK_SPACE: u64 = 10u64.pow(GUEST_NICK_DIGITS);
const _: () = assert!(
    "Guest".len() + GUEST_NICK_DIGITS as usize <= crate::config::MIN_NICKLEN,
    "the longest Guest nick must fit the shortest NICKLEN"
);

/// The account protecting the nick `conn` holds, when the session is not
/// identified to it: the nick is being enforced against this session.
fn enforced_protector(
    state: &ServerState,
    conn: ConnId,
) -> Option<(
    String,
    crate::core::state::NickKey,
    crate::core::state::AccountKey,
)> {
    let session = state.sessions.get(&conn)?;
    let nick = session.nick()?.to_owned();
    let key = state.nick_key(&nick);
    let identified = session.account().map(|account| state.account_key(account));
    let protector = state
        .nick_protector(&key)
        .filter(|protector| identified.as_ref() != Some(protector))?;
    Some((nick, key, protector))
}

/// Whether `conn` is waiting for an IDENTIFY or SASL verdict: enforcement
/// waits for it rather than racing it.
fn verification_in_flight(state: &ServerState, conn: ConnId) -> bool {
    let session = &state.sessions[&conn];
    session.sasl_verify_pending || session.pending_identify.is_some()
}

/// Check the nick `conn` holds against nick protection. When it is protected
/// and the session is not identified to the account protecting it, the
/// session's clock for that nick runs — the one it already had, if it held the
/// nick before, else a fresh one with a warning. A clock that ran out while
/// the session was away renames it on return. Otherwise the session holds no
/// enforced nick (its clocks are kept).
pub(super) fn check_nick_protection(state: &mut ServerState, conn: ConnId) {
    let Some((nick, key, protector)) = enforced_protector(state, conn) else {
        if let Some(session) = state.sessions.get_mut(&conn) {
            session.nick_enforcement.release();
        }
        return;
    };
    let now = (state.config.mono_clock)();
    let enforcement = &mut state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .nick_enforcement;
    if enforcement.held() == Some(&key) {
        return; // a case change of a nick already being enforced
    }
    let deadline = enforcement.deadline(&key, now.saturating_add_millis(NICK_ENFORCE_DELAY_MS));
    enforcement.hold(key.clone());
    if deadline <= now {
        if !verification_in_flight(state, conn) {
            enforce_rename(state, conn, &nick, &key, &protector);
        }
        return;
    }
    state.service_notice(
        conn,
        "NickServ",
        &format!(
            "This nickname is registered. Please choose a different nickname, or identify via \
             \x02/msg NickServ IDENTIFY {} <password>\x02.",
            protector.as_str()
        ),
    );
    state.service_notice(
        conn,
        "NickServ",
        &format!(
            "You have {} seconds to identify to your nickname before it is changed.",
            deadline.saturating_sub(now).as_millis().div_ceil(1000)
        ),
    );
}

/// Rename every session of this shard whose enforcement deadline has passed
/// and that still holds the protected nick unidentified. Driven by the
/// periodic [`crate::core::Input::Tick`]. A session whose IDENTIFY or SASL
/// verification is still running keeps its enforcement for the next tick: the
/// verdict decides, not the timing of the check.
pub(crate) fn enforce_nick_protection(state: &mut ServerState, now: e6irc_proto::time::MonoMillis) {
    let due: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, session)| !session.sasl_verify_pending && session.pending_identify.is_none())
        .filter(|(_, session)| session.nick_enforcement.due(now).is_some())
        .map(|(&conn, _)| conn)
        .collect();
    for conn in due {
        let held = state.sessions[&conn].nick_enforcement.held().cloned();
        match enforced_protector(state, conn) {
            Some((nick, key, protector)) if Some(&key) == held.as_ref() => {
                enforce_rename(state, conn, &nick, &key, &protector);
            }
            // It moved to another nick, identified, or the nick lost its
            // protection.
            _ => state
                .sessions
                .get_mut(&conn)
                .expect("listed above")
                .nick_enforcement
                .release(),
        }
    }
}

/// Rename `conn` off the protected `nick` it failed to identify for, audited
/// (`NICK_GUEST_RENAME`, with the protecting account as actor) before it is
/// done. When the audit trail cannot take the row the session keeps the nick
/// until the next tick tries again.
fn enforce_rename(
    state: &mut ServerState,
    conn: ConnId,
    nick: &str,
    key: &crate::core::state::NickKey,
    protector: &crate::core::state::AccountKey,
) {
    if super::oper::queue_audit(
        state,
        &crate::db::AuditPrincipal::account(protector.as_str()),
        "NICK_GUEST_RENAME",
        &crate::db::AuditPrincipal::nick(key.as_str()),
        "",
    )
    .is_err()
    {
        return;
    }
    state
        .sessions
        .get_mut(&conn)
        .expect("enforced session")
        .nick_enforcement
        .release();
    state.service_notice(
        conn,
        "NickServ",
        &format!("You failed to identify in time for the nickname {nick}"),
    );
    rename_to_guest(state, conn);
}

/// Rename `conn` to a free `Guest<number>` nick that no account protects,
/// starting from a number derived from the connection. Every nick in the
/// space being held is the one case with nowhere to put the session: it is
/// disconnected rather than left on the protected nick.
fn rename_to_guest(state: &mut ServerState, conn: ConnId) {
    let start = conn.0 % GUEST_NICK_SPACE;
    for offset in 0..GUEST_NICK_SPACE {
        let guest = format!("Guest{}", (start + offset) % GUEST_NICK_SPACE);
        if state.nick_protector(&state.nick_key(&guest)).is_some() {
            continue;
        }
        if super::force_nick(state, conn, &guest) {
            return;
        }
    }
    let server = state.config.server_name.clone();
    let reason = "Nickname enforcement: no Guest nick is free";
    state.send(conn, &format!(":{server} ERROR :Closing Link: {reason}"));
    state.close(conn, reason);
}

pub(crate) fn chanserv_register_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> Option<crate::core::state::ChanServRegisterResult> {
    let label = command.label();
    let (owner, actor, target, operation) = command.into_parts();
    assert!(matches!(
        operation,
        crate::core::state::ChannelCommandOperation::ChanServRegister
    ));
    let key = state.chan_key(&target);
    assert_eq!(
        owner.key(),
        &key,
        "ChanServ REGISTER owner does not match target"
    );
    let Some(account) = actor.account.clone() else {
        unreachable!("identified ChanServ actor has no account");
    };
    let is_op = state
        .channels
        .get(&key)
        .and_then(|channel| channel.member(actor.recipient.conn()))
        .is_some_and(|member| member.op);
    if !is_op {
        return Some(
            crate::core::state::ChanServRegisterResult::NotChannelOperator { channel: target },
        );
    }
    if state.channel_registration_pending(&key) {
        return Some(
            crate::core::state::ChanServRegisterResult::RegistrationPending { channel: target },
        );
    }
    if !state.is_founder(&key, &account)
        && state.channels_founded_by(&account)
            >= crate::core::handler::channel::MAX_CHANNELS_PER_ACCOUNT
    {
        return Some(crate::core::state::ChanServRegisterResult::RegistrationLimit);
    }
    let channel = &state.channels[&key];
    let display = channel.name.clone();
    let topic = channel
        .topic
        .as_ref()
        .map(|topic| (topic.text.clone(), topic.set_by.clone(), topic.set_at_secs));
    if state
        .db_tx
        .try_push(crate::core::DbRequest::RegisterChannel {
            owner,
            session: actor.session_owner(),
            channel: display,
            founder_account: account.clone(),
            topic,
            label,
        })
        .is_err()
    {
        return Some(crate::core::state::ChanServRegisterResult::Unavailable);
    }
    state
        .pending_channel_registrations
        .insert(key, state.account_key(&account));
    None
}

pub(crate) fn channel_registration_persisted(
    state: &mut ServerState,
    session: crate::core::SessionOwner,
    channel: String,
    founder_account: String,
    topic: Option<(String, String, u64)>,
    label: Option<String>,
    result: crate::core::ChannelRegistrationResult,
) {
    let key = state.chan_key(&channel);
    state.pending_channel_registrations.remove(&key);
    let result = match result {
        crate::core::ChannelRegistrationResult::Registered => {
            state.register_founder(&channel, &founder_account);
            if let Some((text, set_by, set_at_secs)) = topic {
                state.registered_topics.set(
                    key,
                    crate::core::state::Topic {
                        text,
                        set_by,
                        set_at_secs,
                    },
                );
            }
            crate::core::state::ChanServRegisterResult::Registered { channel }
        }
        crate::core::ChannelRegistrationResult::Exists => {
            crate::core::state::ChanServRegisterResult::Exists
        }
        crate::core::ChannelRegistrationResult::LimitReached => {
            crate::core::state::ChanServRegisterResult::RegistrationLimit
        }
        crate::core::ChannelRegistrationResult::AccountMissing
        | crate::core::ChannelRegistrationResult::Unavailable => {
            crate::core::state::ChanServRegisterResult::Unavailable
        }
    };
    state.route_channel_command_result(
        session,
        crate::core::state::ChannelCommandResult::ChanServRegister(result),
        label,
    );
}

pub(crate) fn emit_chanserv_register_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChanServRegisterResult,
    label: Option<String>,
) {
    state.emit_deferred_labeled(conn, label, |state| {
        emit_chanserv_register_result_now(state, conn, result)
    });
}

fn emit_chanserv_register_result_now(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChanServRegisterResult,
) {
    match result {
        crate::core::state::ChanServRegisterResult::NotChannelOperator { channel } => state
            .service_notice(
                conn,
                "ChanServ",
                &format!("You must be a channel operator in \x02{channel}\x02 to register it."),
            ),
        crate::core::state::ChanServRegisterResult::RegistrationPending { channel } => state
            .service_notice(
                conn,
                "ChanServ",
                &format!("Registration of \x02{channel}\x02 is already in progress."),
            ),
        crate::core::state::ChanServRegisterResult::RegistrationLimit => state.service_notice(
            conn,
            "ChanServ",
            "You have registered too many channels; drop one before registering another.",
        ),
        crate::core::state::ChanServRegisterResult::Registered { channel } => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is now registered to your account."),
        ),
        crate::core::state::ChanServRegisterResult::Exists => {
            state.service_notice(conn, "ChanServ", "That channel is already registered.")
        }
        crate::core::state::ChanServRegisterResult::Unavailable => state.service_notice(
            conn,
            "ChanServ",
            "Services are temporarily unavailable. Try again later.",
        ),
    }
}

pub(super) fn chanserv(state: &mut ServerState, conn: ConnId, command: &str, args: &[&str]) {
    match command {
        "REGISTER" => {
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: REGISTER <#channel>");
                return;
            };
            let Some(_account) = require_identified(
                state,
                conn,
                "ChanServ",
                "You must identify to services before registering a channel.",
            ) else {
                return;
            };
            let owner = state.channel_owner(channel);
            let label = state.channel_reply_label(conn, &owner);
            let command = crate::core::state::ChannelCommand::new(
                owner,
                state.channel_actor(conn),
                channel.to_string(),
                crate::core::state::ChannelCommandOperation::ChanServRegister,
                label,
            );
            if !state.owns_channel(command.owner()) {
                state.route_channel_command(command);
                return;
            }
            // A local refusal is this command's direct reply; only a queued
            // database write leaves a verdict for the connection to wait on.
            match chanserv_register_on_owner(state, command) {
                Some(result) => emit_chanserv_register_result_now(state, conn, result),
                None => state.defer_captured_reply(conn),
            }
        }
        "DROP" => {
            // DROP <#channel>: the founder unregisters their channel.
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: DROP <#channel>");
                return;
            };
            let Some(account) = require_identified(
                state,
                conn,
                "ChanServ",
                "You must identify to services before dropping a channel.",
            ) else {
                return;
            };
            let key = state.chan_key(channel);
            if !state.is_founder(&key, &account) {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("You are not the founder of \x02{channel}\x02."),
                );
                return;
            }
            let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
            let request = crate::core::DbRequest::DropChannel {
                owner: state.channel_owner(key.as_str()),
                channel: key.as_str().to_string(),
                requester: crate::core::ChannelDropRequester::ChanServ {
                    session: state.channel_actor(conn).session_owner(),
                    display: channel.to_string(),
                    label,
                    actor: account,
                },
            };
            queue_service_verdict(state, conn, "ChanServ", request);
        }
        "FLAGS" => chanserv_flags(state, conn, args),
        "ACCESS" => chanserv_access(state, conn, args),
        "OP" => chanserv_status(state, conn, crate::core::state::StatusChange::Op, args),
        "DEOP" => chanserv_status(state, conn, crate::core::state::StatusChange::Deop, args),
        "VOICE" => chanserv_status(state, conn, crate::core::state::StatusChange::Voice, args),
        "DEVOICE" => chanserv_status(state, conn, crate::core::state::StatusChange::Devoice, args),
        "SET" => chanserv_set(state, conn, args),
        "HELP" => {
            for line in [
                "***** ChanServ Help *****",
                "REGISTER <#channel> - Register a channel you operate",
                "DROP <#channel> - Unregister a channel you founded",
                "FLAGS <#channel> [account [+/-ov]] - List or set channel access",
                "ACCESS <#channel> LIST - List the access list with roles",
                "ACCESS <#channel> ADD <account> [AOP|VOP] - Grant a role (VOP by default)",
                "ACCESS <#channel> DEL <account> - Remove an account's role",
                "OP|DEOP <#channel> [nick] - Op or deop yourself or a nick (needs op access)",
                "VOICE|DEVOICE <#channel> [nick] - Voice or devoice (needs voice access)",
                "SET <#channel> FOUNDER <account> - Transfer channel ownership",
                "SET <#channel> SUCCESSOR <account|OFF> - Who inherits the channel if the \
                 founder's account is deleted",
                "SET <#channel> KEEPTOPIC <ON|OFF> - Keep the topic while the channel is empty",
                "SET <#channel> MLOCK <modes|OFF> - Lock channel modes",
                "***** End of Help *****",
            ] {
                state.service_notice(conn, "ChanServ", line);
            }
        }
        _ => {
            state.service_notice(
                conn,
                "ChanServ",
                "Invalid command. Use \x02/msg ChanServ HELP\x02 for a command listing.",
            );
        }
    }
}

/// Apply a `+ov`/`-o`-style change string to a current flag set, keeping only
/// the recognised flags (`o` auto-op, `v` auto-voice), sorted. Returns the first
/// unrecognised flag character as `Err` so the caller can reject the whole change
/// loudly: silently dropping an unknown flag (the previous behaviour) turned
/// `FLAGS #c bob +q` into an empty set — a *revoke* the caller never asked for,
/// reported back as success. Every other ChanServ token parser errors on an
/// unknown token; this is that same contract (DESIGN §2, no silent no-ops).
pub(super) fn apply_flag_changes(current: &str, changes: &str) -> Result<String, char> {
    let mut flags: std::collections::BTreeSet<char> =
        current.chars().filter(|c| matches!(c, 'o' | 'v')).collect();
    let mut adding = true;
    for c in changes.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'v' => {
                if adding {
                    flags.insert(c);
                } else {
                    flags.remove(&c);
                }
            }
            other => return Err(other),
        }
    }
    Ok(flags.into_iter().collect())
}

/// The gate every founder-only ChanServ subcommand applies: the caller must be
/// identified, the channel registered, and the caller its founder. Returns the
/// channel key and the account, or `None` once the caller has been told why not.
///
/// Written once because it is a permission check. Three copies can drift, and
/// the copy that drifts is the one that stops refusing.
fn chanserv_founder_gate(
    state: &mut ServerState,
    channel: &str,
    conn: ConnId,
    identify_hint: &str,
) -> Option<(ChanKey, String)> {
    let (key, account) = chanserv_registered_gate(state, conn, channel, identify_hint)?;
    if !state.is_founder(&key, &account) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("You are not the founder of \x02{channel}\x02."),
        );
        return None;
    }
    Some((key, account))
}

/// Gate a ChanServ command to an identified user on a registered channel:
/// reply and return `None` when the caller is unidentified or the channel is
/// not registered. The privilege-specific gates (founder, access) build on it.
fn chanserv_registered_gate(
    state: &mut ServerState,
    conn: ConnId,
    channel: &str,
    identify_hint: &str,
) -> Option<(ChanKey, String)> {
    let account = require_identified(state, conn, "ChanServ", identify_hint)?;
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return None;
    }
    Some((key, account))
}

/// Take the caller's account, or tell them to identify and return `None` —
/// the login gate every services subcommand applies before touching
/// account-owned state. `service` is the NOTICE sender (ChanServ/NickServ).
fn require_identified(
    state: &mut ServerState,
    conn: ConnId,
    service: &str,
    hint: &str,
) -> Option<String> {
    let Some(account) = state.sessions[&conn].account().map(str::to_owned) else {
        state.service_notice(conn, service, hint);
        return None;
    };
    Some(account)
}

/// ChanServ FLAGS: list a registered channel's access entries, or (founder
/// only) modify one account's flags. Auto-op/voice apply on the account's
/// next join.
pub(super) fn chanserv_flags(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: FLAGS <#channel> [account [+/-flags]]",
        );
        return;
    };
    let Some((key, account)) = chanserv_founder_gate(
        state,
        channel,
        conn,
        "You must identify to services before using FLAGS.",
    ) else {
        return;
    };

    // LIST when no account is given.
    if args.len() == 1 {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("Access list for \x02{channel}\x02:"),
        );
        let mut entries: Vec<(String, String)> = state
            .channel_options
            .access_entries(&key)
            .into_iter()
            .map(|(account, flags)| (account.as_str().to_string(), flags))
            .collect();
        entries.sort();
        for (acct, flags) in &entries {
            state.service_notice(conn, "ChanServ", &format!("{acct} +{flags}"));
        }
        if let Some(successor) = state.registered_founders.successor(&key) {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("{} (successor)", successor.as_str()),
            );
        }
        state.service_notice(conn, "ChanServ", "End of access list.");
        return;
    }

    // MODIFY: FLAGS <#channel> <account> <changes>.
    let target = args[1];
    let Some(&changes) = args.get(2) else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: FLAGS <#channel> <account> <+/-ov>",
        );
        return;
    };
    let target_key = state.resolve_account_key(target);
    let current = state
        .channel_options
        .access_flags(&key, &target_key)
        .unwrap_or_default();
    let new_flags = match apply_flag_changes(&current, changes) {
        Ok(flags) => flags,
        Err(bad) => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Unknown flag \x02{bad}\x02. Valid flags: o (auto-op), v (auto-voice)."),
            );
            return;
        }
    };

    let flags = (!new_flags.is_empty()).then_some(new_flags);
    let change = AccessChange {
        channel,
        target,
        flags,
        frontend: crate::core::AccessFrontend::Flags,
    };
    queue_access_change(state, conn, account, change);
}

/// One access-list change a founder asked for, through FLAGS or ACCESS.
struct AccessChange<'a> {
    channel: &'a str,
    target: &'a str,
    /// The flags the account is to hold; `None` removes its entry.
    flags: Option<String>,
    frontend: crate::core::AccessFrontend,
}

/// Persist an access change. The hot map and the confirmation are applied on
/// the verdict, so a grant to an *unregistered* account (which writes no row)
/// can't leave a phantom hot entry that would auto-op a later registration of
/// that name.
fn queue_access_change(state: &mut ServerState, conn: ConnId, actor: String, change: AccessChange) {
    let request = crate::core::DbRequest::SetChannelAccess {
        owner: state.channel_owner(change.channel),
        session: state.channel_actor(conn).session_owner(),
        channel: change.channel.to_string(),
        display: change.channel.to_string(),
        account: change.target.to_string(),
        flags: change.flags,
        frontend: change.frontend,
        actor,
        label: captured_label(state, conn),
    };
    queue_service_verdict(state, conn, "ChanServ", request);
}

/// The Atheme role an access entry's flags amount to.
fn access_role(flags: &str) -> &'static str {
    if flags.contains('o') { "AOP" } else { "VOP" }
}

/// ChanServ ACCESS: Atheme's role front end over the same access entries
/// FLAGS edits — AOP is auto-op (`+o`), VOP auto-voice (`+v`). Anyone on the
/// access list may LIST it; only the founder may change it, as with FLAGS.
fn chanserv_access(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let (Some(&channel), Some(&subcommand)) = (args.first(), args.get(1)) else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: ACCESS <#channel> <LIST|ADD|DEL> [account] [role]",
        );
        return;
    };
    let hint = "You must identify to services before using ACCESS.";
    match subcommand.to_ascii_uppercase().as_str() {
        "LIST" => {
            let Some((key, account)) = chanserv_registered_gate(state, conn, channel, hint) else {
                return;
            };
            let account_key = state.account_key(&account);
            let entries = state.channel_options.access_entries(&key);
            let founder = state.registered_founders.founder(&key);
            if founder.as_ref() != Some(&account_key)
                && !entries.iter().any(|(holder, _)| *holder == account_key)
            {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!(
                        "You are not authorized to view the access list of \x02{channel}\x02."
                    ),
                );
                return;
            }
            let successor = state.registered_founders.successor(&key);
            let mut rows: Vec<(String, &'static str)> = founder
                .map(|founder| (founder.as_str().to_string(), "Founder"))
                .into_iter()
                .chain(successor.map(|successor| (successor.as_str().to_string(), "Successor")))
                .collect();
            let mut granted: Vec<(String, &'static str)> = entries
                .iter()
                .map(|(holder, flags)| (holder.as_str().to_string(), access_role(flags)))
                .collect();
            granted.sort();
            rows.extend(granted);
            let rule = "----- ---------------------- ----";
            state.service_notice(conn, "ChanServ", "Entry Nickname/Host          Role");
            state.service_notice(conn, "ChanServ", rule);
            for (index, (holder, role)) in rows.iter().enumerate() {
                let entry = index + 1;
                state.service_notice(conn, "ChanServ", &format!("{entry:<5} {holder:<22} {role}"));
            }
            state.service_notice(conn, "ChanServ", rule);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("End of \x02{channel}\x02 ACCESS listing."),
            );
        }
        "ADD" => {
            let Some(&target) = args.get(2) else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Syntax: ACCESS <#channel> ADD <account> [AOP|VOP]",
                );
                return;
            };
            let (role, flags) = match args.get(3).map(|role| role.to_ascii_uppercase()) {
                None => ("VOP", "v"),
                Some(role) if role == "VOP" || role == "VOICE" => ("VOP", "v"),
                Some(role) if role == "AOP" || role == "OP" => ("AOP", "o"),
                Some(role) => {
                    state.service_notice(
                        conn,
                        "ChanServ",
                        &format!(
                            "The role \x02{role}\x02 does not exist. Roles: AOP (auto-op), VOP (auto-voice)."
                        ),
                    );
                    return;
                }
            };
            let Some((_, account)) = chanserv_founder_gate(state, channel, conn, hint) else {
                return;
            };
            let change = AccessChange {
                channel,
                target,
                flags: Some(flags.to_string()),
                frontend: crate::core::AccessFrontend::AccessAdd { role },
            };
            queue_access_change(state, conn, account, change);
        }
        "DEL" => {
            let Some(&target) = args.get(2) else {
                state.service_notice(conn, "ChanServ", "Syntax: ACCESS <#channel> DEL <account>");
                return;
            };
            let Some((key, account)) = chanserv_founder_gate(state, channel, conn, hint) else {
                return;
            };
            let target_key = state.resolve_account_key(target);
            let Some(current) = state.channel_options.access_flags(&key, &target_key) else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!(
                        "\x02{target}\x02 was not found on the access list of \x02{channel}\x02."
                    ),
                );
                return;
            };
            let change = AccessChange {
                channel,
                target,
                flags: None,
                frontend: crate::core::AccessFrontend::AccessDel {
                    role: access_role(&current),
                },
            };
            queue_access_change(state, conn, account, change);
        }
        other => state.service_notice(
            conn,
            "ChanServ",
            &format!("Unknown ACCESS subcommand \x02{other}\x02. Use LIST, ADD or DEL."),
        ),
    }
}

/// ChanServ OP, DEOP, VOICE and DEVOICE: change a member's status on a
/// registered channel for someone whose access allows it (Atheme: `+o` for
/// OP/DEOP, `+v` for VOICE/DEVOICE — an auto-op entry also allows voicing, as
/// Atheme's op roles include `+v`; the founder may do all four).
pub(super) fn chanserv_status(
    state: &mut ServerState,
    conn: ConnId,
    change: crate::core::state::StatusChange,
    args: &[&str],
) {
    let command = change.command();
    let Some(&channel) = args.first() else {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("Syntax: {command} <#channel> [nick]"),
        );
        return;
    };
    if require_identified(
        state,
        conn,
        "ChanServ",
        &format!("You must identify to services before using {command}."),
    )
    .is_none()
    {
        return;
    }
    let target_nick = match args.get(1) {
        Some(&n) => n.to_string(),
        None => registered_nick(state, conn),
    };
    let owner = state.channel_owner(channel);
    let label = state.channel_reply_label(conn, &owner);
    let command = crate::core::state::ChannelCommand::new(
        owner,
        state.channel_actor(conn),
        channel.to_string(),
        crate::core::state::ChannelCommandOperation::ChanServStatus {
            target_nick,
            change,
        },
        label,
    );
    if state.owns_channel(command.owner()) {
        let result = chanserv_status_on_owner(state, command);
        emit_chanserv_status_result(state, conn, result);
    } else {
        state.route_channel_command(command);
    }
}

pub(crate) fn chanserv_status_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> crate::core::state::ChanServStatusResult {
    use crate::core::state::ChanServStatusResult;
    let (owner, actor, target, operation) = command.into_parts();
    let crate::core::state::ChannelCommandOperation::ChanServStatus {
        target_nick,
        change,
    } = operation
    else {
        unreachable!("ChanServ status command operation");
    };
    let key = state.chan_key(&target);
    assert_eq!(
        owner.key(),
        &key,
        "ChanServ status owner does not match target"
    );
    let Some(account) = actor.account else {
        unreachable!("identified ChanServ actor has no account");
    };
    if !state.is_registered(&key) {
        return ChanServStatusResult::NotRegistered { channel: target };
    }
    let (auto_op, auto_voice) = state.access_modes(&key, &account);
    let allowed = state.is_founder(&key, &account)
        || if change.is_op() {
            auto_op
        } else {
            auto_op || auto_voice
        };
    if !allowed {
        return ChanServStatusResult::NoAccess {
            channel: target,
            change,
        };
    }
    let target_key = state.nick_key(&target_nick);
    if state.nick_reservation(&target_key).is_none() {
        return ChanServStatusResult::TargetOffline {
            target: target_nick,
        };
    }
    let casemap = state.casemap;
    let Some(channel) = state.channels.get_mut(&key) else {
        return ChanServStatusResult::TargetNotOnChannel {
            target: target_nick,
            channel: target,
        };
    };
    let display = channel.name.clone();
    // From here on the member is named as the channel knows them, not as
    // typed: the MODE line must carry the nick clients hold for them.
    let Some((target_conn, target_nick)) = channel
        .member_named(casemap, &target_nick)
        .map(|(conn, _, identity)| (conn, identity.nick.clone()))
    else {
        return ChanServStatusResult::TargetNotOnChannel {
            target: target_nick,
            channel: display,
        };
    };
    let member = channel
        .member(target_conn)
        .expect("member_named found this member");
    let held = if change.is_op() {
        member.op
    } else {
        member.voice
    };
    if held == change.grants() {
        return ChanServStatusResult::Unchanged {
            target: target_nick,
            change,
        };
    }
    // It acts on someone else's session: audited, and not made unless it is.
    if super::oper::queue_audit(
        state,
        &crate::db::AuditPrincipal::account(&account),
        change.audit_action(),
        &crate::db::AuditPrincipal::channel(key.as_str()),
        &format!("nick={target_nick}"),
    )
    .is_err()
    {
        return ChanServStatusResult::AuditUnavailable;
    }
    let member = state
        .channels
        .get_mut(&key)
        .and_then(|channel| channel.member_mut(target_conn))
        .expect("member_named found this member");
    if change.is_op() {
        member.op = change.grants();
    } else {
        member.voice = change.grants();
    }
    let line = state.server_line(format!(
        ":{} MODE {display} {} {target_nick}",
        state.config.server_name,
        change.mode()
    ));
    state.broadcast_channel(&key, &line, None);
    ChanServStatusResult::Changed {
        target: target_nick,
        channel: display,
        change,
    }
}

pub(crate) fn emit_chanserv_status_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChanServStatusResult,
) {
    use crate::core::state::{ChanServStatusResult, StatusChange};
    let text = match result {
        ChanServStatusResult::NotRegistered { channel } => {
            format!("\x02{channel}\x02 is not registered.")
        }
        ChanServStatusResult::NoAccess { channel, change } => {
            let kind = if change.is_op() { "op" } else { "voice" };
            format!("You do not have {kind} access on \x02{channel}\x02.")
        }
        ChanServStatusResult::TargetOffline { target } => {
            format!("\x02{target}\x02 is not online.")
        }
        ChanServStatusResult::TargetNotOnChannel { target, channel } => {
            format!("\x02{target}\x02 is not on \x02{channel}\x02.")
        }
        ChanServStatusResult::Unchanged { target, change } => match change {
            StatusChange::Op => format!("\x02{target}\x02 is already opped."),
            StatusChange::Deop => format!("\x02{target}\x02 is not opped."),
            StatusChange::Voice => format!("\x02{target}\x02 is already voiced."),
            StatusChange::Devoice => format!("\x02{target}\x02 is not voiced."),
        },
        ChanServStatusResult::Changed {
            target,
            channel,
            change,
        } => {
            let done = match change {
                StatusChange::Op => "Opped",
                StatusChange::Deop => "Deopped",
                StatusChange::Voice => "Voiced",
                StatusChange::Devoice => "Devoiced",
            };
            format!("{done} \x02{target}\x02 on \x02{channel}\x02.")
        }
        ChanServStatusResult::AuditUnavailable => SERVICES_UNAVAILABLE.to_string(),
    };
    state.service_notice(conn, "ChanServ", &text);
}

/// ChanServ SET: founder-only channel options — FOUNDER and SUCCESSOR (both
/// verified against the database), KEEPTOPIC and MLOCK.
pub(super) fn chanserv_set(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let (Some(&channel), Some(&option)) = (args.first(), args.get(1)) else {
        state.service_notice(conn, "ChanServ", "Syntax: SET <#channel> <option> <value>");
        return;
    };
    let Some((key, account)) = chanserv_founder_gate(
        state,
        channel,
        conn,
        "You must identify to services before using SET.",
    ) else {
        return;
    };
    match option.to_ascii_uppercase().as_str() {
        "FOUNDER" => {
            let Some(&new) = args.get(2) else {
                state.service_notice(conn, "ChanServ", "Syntax: SET <#channel> FOUNDER <account>");
                return;
            };
            let request = crate::core::DbRequest::SetChannelFounder {
                owner: state.channel_owner(channel),
                session: state.channel_actor(conn).session_owner(),
                channel: channel.to_string(),
                new_founder: state.casemap.casefold(new),
                actor: account,
                label: state
                    .capture
                    .as_ref()
                    .and_then(|capture| capture.label.clone()),
            };
            queue_service_verdict(state, conn, "ChanServ", request);
        }
        "SUCCESSOR" => {
            let Some(&value) = args.get(2) else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Syntax: SET <#channel> SUCCESSOR <account|OFF>",
                );
                return;
            };
            let successor =
                (!(value.eq_ignore_ascii_case("OFF") || value == "-")).then(|| value.to_string());
            if successor.as_deref().is_some_and(|successor| {
                state.registered_founders.founder(&key)
                    == Some(state.resolve_account_key(successor))
            }) {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!(
                        "\x02{value}\x02 is the founder of \x02{channel}\x02 and cannot also be \
                         its successor."
                    ),
                );
                return;
            }
            let request = crate::core::DbRequest::SetChannelSuccessor {
                owner: state.channel_owner(channel),
                session: state.channel_actor(conn).session_owner(),
                channel: channel.to_string(),
                successor,
                label: captured_label(state, conn),
                actor: account,
            };
            queue_service_verdict(state, conn, "ChanServ", request);
        }
        "KEEPTOPIC" => {
            let on = match args.get(2).map(|v| v.to_ascii_uppercase()) {
                Some(v) if v == "ON" => true,
                Some(v) if v == "OFF" => false,
                _ => {
                    state.service_notice(
                        conn,
                        "ChanServ",
                        "Syntax: SET <#channel> KEEPTOPIC <ON|OFF>",
                    );
                    return;
                }
            };
            let effective_topic = state
                .pending_channel_topics
                .get(&key)
                .map(|(_, topic)| topic.clone())
                .unwrap_or_else(|| state.channels.get(&key).and_then(|c| c.topic.clone()));
            let topic = on
                .then_some(effective_topic)
                .flatten()
                .map(|t| (t.text.clone(), t.set_by.clone(), t.set_at_secs));
            let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
            let request = crate::core::DbRequest::SetChannelKeeptopic {
                owner: state.channel_owner(channel),
                session: state.channel_actor(conn).session_owner(),
                channel: key.as_str().to_string(),
                display: channel.to_string(),
                keeptopic: on,
                topic,
                label,
                actor: account,
            };
            queue_service_verdict(state, conn, "ChanServ", request);
        }
        "MLOCK" => {
            let spec = args.get(2).copied().unwrap_or("");
            // Clear the lock on empty / OFF / "-".
            if spec.is_empty() || spec.eq_ignore_ascii_case("OFF") || spec == "-" {
                let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
                let request = crate::core::DbRequest::SetChannelMlock {
                    owner: state.channel_owner(channel),
                    session: state.channel_actor(conn).session_owner(),
                    channel: key.as_str().to_string(),
                    display: channel.to_string(),
                    mlock: None,
                    label,
                    actor: account,
                };
                queue_service_verdict(state, conn, "ChanServ", request);
                return;
            }
            let parsed = match crate::core::state::MlockModes::parse(spec) {
                Ok(m) if !m.is_empty() => m,
                Ok(_) => {
                    state.service_notice(conn, "ChanServ", "MLOCK lists no lockable modes.");
                    return;
                }
                Err(bad) => {
                    state.service_notice(
                        conn,
                        "ChanServ",
                        &format!(
                            "\x02{bad}\x02 is not a lockable mode. Lockable: {}.",
                            crate::core::state::MlockModes::LOCKABLE
                                .chars()
                                .map(String::from)
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                    );
                    return;
                }
            };
            let canonical = parsed.render();
            let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
            let request = crate::core::DbRequest::SetChannelMlock {
                owner: state.channel_owner(channel),
                session: state.channel_actor(conn).session_owner(),
                channel: key.as_str().to_string(),
                display: channel.to_string(),
                mlock: Some(canonical.clone()),
                label,
                actor: account,
            };
            queue_service_verdict(state, conn, "ChanServ", request);
        }
        "GUARD" => {
            // GUARD keeps ChanServ in the channel so it is never destroyed
            // and its modes/topic survive. e6irc keeps a registered
            // channel's founder, access, retained topic, and mode lock in
            // persistent state regardless of membership, so that guarantee
            // already holds — there is nothing for an in-channel presence to
            // protect. Answered explicitly rather than silently accepted.
            state.service_notice(
                conn,
                "ChanServ",
                "GUARD is unnecessary here: a registered channel keeps its founder, \
                 access, topic, and mode lock across empty periods without ChanServ \
                 holding it open.",
            );
        }
        other => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!(
                    "Unknown SET option \x02{other}\x02. Available: FOUNDER, SUCCESSOR, \
                     KEEPTOPIC, MLOCK."
                ),
            );
        }
    }
}

/// Queue a services request whose verdict is the command's reply. Every
/// verdict releases one deferred slot, so every queued request must take one
/// here: a bare push would let the verdict release a slot some other reply is
/// holding. `service` is who says so when the queue is full.
fn queue_service_verdict(
    state: &mut ServerState,
    conn: ConnId,
    service: &str,
    request: crate::core::DbRequest,
) {
    if state.db_tx.try_push(request).is_err() {
        services_unavailable(state, conn, service);
    } else {
        state.defer_captured_reply(conn);
    }
}

pub(crate) fn channel_drop_result(
    state: &mut ServerState,
    channel: String,
    requester: crate::core::ChannelDropRequester,
    result: crate::core::ChannelDropResult,
) {
    let key = state.chan_key(&channel);
    if matches!(
        result,
        crate::core::ChannelDropResult::Dropped | crate::core::ChannelDropResult::Missing
    ) {
        clear_registered_channel(state, &key);
    }
    match requester {
        crate::core::ChannelDropRequester::ChanServ {
            session,
            display,
            label,
            actor: _,
        } => {
            state.route_input(crate::core::Input::ChannelDropReply {
                session,
                display,
                label,
                result,
            });
        }
        crate::core::ChannelDropRequester::Admin {
            request_id,
            actor: _,
        } => {
            let outcome = match result {
                crate::core::ChannelDropResult::Dropped => {
                    crate::core::AdminReply::Ok(format!("Unregistered {}", key.as_str()))
                }
                crate::core::ChannelDropResult::Missing => crate::core::AdminReply::ChannelErr {
                    kind: crate::core::ChannelControlError::NotFound,
                    message: format!("{} is no longer a registered channel", key.as_str()),
                },
                // An administrator's drop is not founder-gated, so storage
                // never answers it this way; saying so beats a false success.
                crate::core::ChannelDropResult::NotFounder => crate::core::AdminReply::ChannelErr {
                    kind: crate::core::ChannelControlError::Unavailable,
                    message: "persistence refused the drop as a founder's".into(),
                },
                crate::core::ChannelDropResult::Unavailable => {
                    crate::core::AdminReply::ChannelErr {
                        kind: crate::core::ChannelControlError::Unavailable,
                        message: "persistence unavailable; channel not dropped".into(),
                    }
                }
            };
            match state.pending_admin_channel_drops.remove(&request_id) {
                Some(reply) => {
                    let _ = reply.send(outcome);
                }
                None => {
                    eprintln!("core: channel-drop verdict for unknown admin request {request_id}");
                }
            }
        }
    }
}

pub(crate) fn channel_drop_reply(
    state: &mut ServerState,
    session: crate::core::SessionOwner,
    display: String,
    label: Option<String>,
    result: crate::core::ChannelDropResult,
) {
    let conn = session.conn();
    if !state.sessions.contains_key(&conn) {
        return;
    }
    state.emit_deferred_labeled(conn, label, |state| match result {
        crate::core::ChannelDropResult::Dropped => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{display}\x02 has been dropped."),
        ),
        crate::core::ChannelDropResult::Missing => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{display}\x02 is no longer registered."),
        ),
        crate::core::ChannelDropResult::NotFounder => state.service_notice(
            conn,
            "ChanServ",
            &format!("You are no longer the founder of \x02{display}\x02."),
        ),
        crate::core::ChannelDropResult::Unavailable => state.service_notice(
            conn,
            "ChanServ",
            "Services are temporarily unavailable. Try again later.",
        ),
    });
}

/// Emit a deferred, labeled ChanServ NOTICE to the connection if it is still
/// present — the shared shape of the per-field `*_unavailable` replies.
fn chanserv_deferred_notice(
    state: &mut ServerState,
    conn: ConnId,
    label: Option<String>,
    text: String,
) {
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, move |state| {
            state.service_notice(conn, "ChanServ", &text);
        });
    }
}

/// A channel-field update (KEEPTOPIC, MLOCK) whose services round-trip failed.
pub(super) fn channel_field_unavailable(
    state: &mut ServerState,
    conn: ConnId,
    display: String,
    label: Option<String>,
    field: &str,
) {
    chanserv_deferred_notice(
        state,
        conn,
        label,
        format!(
            "Could not update {field} for \x02{display}\x02 — services are temporarily \
             unavailable."
        ),
    );
}

pub(crate) fn channel_service_persisted(
    state: &mut ServerState,
    session: crate::core::SessionOwner,
    result: crate::core::ChannelServicePersistence,
) {
    let result = match result {
        crate::core::ChannelServicePersistence::FounderChanged {
            channel,
            account,
            display,
            label,
        } => {
            state.transfer_founder(&channel, &account);
            crate::core::ChannelServicePersistence::FounderChanged {
                channel,
                account,
                display,
                label,
            }
        }
        crate::core::ChannelServicePersistence::AccessSet {
            channel,
            display,
            account,
            flags,
            previous,
            frontend,
            label,
        } => {
            let key = state.chan_key(&channel);
            if !state.is_registered(&key) {
                crate::core::ChannelServicePersistence::AccessMissing { display, label }
            } else {
                let account_key = state.account_key(&account);
                state
                    .channel_options
                    .set_access(key, account_key, flags.clone());
                crate::core::ChannelServicePersistence::AccessSet {
                    channel,
                    display,
                    account,
                    flags,
                    previous,
                    frontend,
                    label,
                }
            }
        }
        crate::core::ChannelServicePersistence::KeeptopicSet {
            channel,
            display,
            keeptopic,
            topic,
            label,
        } => {
            let key = state.chan_key(&channel);
            if !state.is_registered(&key) {
                crate::core::ChannelServicePersistence::KeeptopicMissing { display, label }
            } else {
                state.channel_options.set_keeptopic(key.clone(), keeptopic);
                if keeptopic {
                    replace_registered_topic(state, &key, topic.clone());
                } else {
                    state.registered_topics.remove(&key);
                }
                crate::core::ChannelServicePersistence::KeeptopicSet {
                    channel,
                    display,
                    keeptopic,
                    topic,
                    label,
                }
            }
        }
        crate::core::ChannelServicePersistence::MlockSet {
            channel,
            display,
            mlock,
            label,
        } => {
            let key = state.chan_key(&channel);
            if !state.is_registered(&key) {
                crate::core::ChannelServicePersistence::MlockMissing { display, label }
            } else {
                match mlock
                    .as_deref()
                    .map(crate::core::state::MlockModes::parse)
                    .transpose()
                {
                    Ok(Some(modes)) => {
                        state.channel_options.set_mlock(key.clone(), Some(modes));
                        apply_mlock(state, &key);
                        crate::core::ChannelServicePersistence::MlockSet {
                            channel,
                            display,
                            mlock,
                            label,
                        }
                    }
                    Ok(None) => {
                        state.channel_options.set_mlock(key, None);
                        crate::core::ChannelServicePersistence::MlockSet {
                            channel,
                            display,
                            mlock,
                            label,
                        }
                    }
                    Err(bad) => {
                        eprintln!(
                            "core: database echoed invalid canonical MLOCK character {bad:?}"
                        );
                        crate::core::ChannelServicePersistence::MlockInvalid { label }
                    }
                }
            }
        }
        crate::core::ChannelServicePersistence::SuccessorSet {
            display,
            successor,
            outcome,
            label,
        } => {
            if let Some(crate::db::SuccessorChange::Applied { successor: applied }) = &outcome {
                let key = state.chan_key(&display);
                let applied = applied.as_deref().map(|account| state.account_key(account));
                state.registered_founders.set_successor(&key, applied);
            }
            crate::core::ChannelServicePersistence::SuccessorSet {
                display,
                successor,
                outcome,
                label,
            }
        }
        result => result,
    };
    state.route_input(crate::core::Input::ChannelServiceResult { session, result });
}

/// What an access verdict tells the founder, in the language of the command
/// that asked: `account` is the account the name resolved to, `previous` what
/// its entry held before.
fn access_set_text(
    display: &str,
    account: &str,
    flags: Option<&str>,
    previous: Option<&str>,
    frontend: crate::core::AccessFrontend,
) -> String {
    match (frontend, flags) {
        (crate::core::AccessFrontend::Flags, Some(flags)) => {
            format!("Flags for \x02{account}\x02 on \x02{display}\x02 are now +{flags}.")
        }
        (crate::core::AccessFrontend::Flags, None) => {
            format!("Cleared flags for \x02{account}\x02 on \x02{display}\x02.")
        }
        (crate::core::AccessFrontend::AccessAdd { role }, _) => match previous {
            None => format!(
                "\x02{account}\x02 was added with the \x02{role}\x02 role in \x02{display}\x02."
            ),
            Some(previous) if Some(previous) == flags => format!(
                "\x02{account}\x02 already has the \x02{role}\x02 role in \x02{display}\x02."
            ),
            Some(previous) => format!(
                "\x02{account}\x02's role in \x02{display}\x02 was changed from \x02{}\x02 to \
                 \x02{role}\x02.",
                access_role(previous)
            ),
        },
        (crate::core::AccessFrontend::AccessDel { role }, _) => match previous {
            Some(_) => format!(
                "\x02{account}\x02 was removed from the \x02{role}\x02 role in \x02{display}\x02."
            ),
            None => {
                format!("\x02{account}\x02 was not found on the access list of \x02{display}\x02.")
            }
        },
    }
}

pub(crate) fn channel_service_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::ChannelServicePersistence,
) {
    if !state.sessions.contains_key(&conn) {
        return;
    }
    let (label, text) = match result {
        crate::core::ChannelServicePersistence::FounderChanged {
            account,
            display,
            label,
            ..
        } => (
            label,
            format!("Founder of \x02{display}\x02 transferred to \x02{account}\x02."),
        ),
        crate::core::ChannelServicePersistence::FounderMissing { display, label, .. } => (
            label,
            format!("Could not transfer \x02{display}\x02 — no such account."),
        ),
        crate::core::ChannelServicePersistence::FounderLimitReached { display, label } => (
            label,
            format!(
                "Could not transfer \x02{display}\x02 — that account already founds the \
                 maximum of {} channels.",
                crate::db::CHANNEL_FOUNDER_LIMIT
            ),
        ),
        crate::core::ChannelServicePersistence::FounderUnavailable { display, label, .. } => {
            return channel_field_unavailable(state, conn, display, label, "FOUNDER");
        }
        crate::core::ChannelServicePersistence::AccessSet {
            display,
            account,
            flags,
            previous,
            frontend,
            label,
            ..
        } => (
            label,
            access_set_text(
                &display,
                &account,
                flags.as_deref(),
                previous.as_deref(),
                frontend,
            ),
        ),
        crate::core::ChannelServicePersistence::AccessAccountMissing {
            display,
            account,
            frontend,
            label,
        } => (
            label,
            match frontend {
                crate::core::AccessFrontend::Flags => format!(
                    "\x02{account}\x02 is not registered; no flags set on \x02{display}\x02."
                ),
                _ => format!("\x02{account}\x02 is not registered."),
            },
        ),
        crate::core::ChannelServicePersistence::SuccessorSet {
            display,
            successor,
            outcome,
            label,
        } => {
            let Some(outcome) = outcome else {
                return channel_field_unavailable(state, conn, display, label, "SUCCESSOR");
            };
            let requested = successor.unwrap_or_default();
            let text = match outcome {
                crate::db::SuccessorChange::Applied { successor: None } => {
                    format!("\x02{display}\x02 no longer has a successor.")
                }
                crate::db::SuccessorChange::Applied {
                    successor: Some(successor),
                } => {
                    format!("\x02{successor}\x02 is now the successor of \x02{display}\x02.")
                }
                crate::db::SuccessorChange::AccountMissing => {
                    format!("\x02{requested}\x02 is not registered.")
                }
                crate::db::SuccessorChange::IsFounder => format!(
                    "\x02{requested}\x02 is the founder of \x02{display}\x02 and cannot also be \
                     its successor."
                ),
                crate::db::SuccessorChange::Refused(refusal) => refusal_text(&display, refusal),
            };
            (label, text)
        }
        crate::core::ChannelServicePersistence::Refused {
            display,
            refusal,
            label,
        } => (label, refusal_text(&display, refusal)),
        crate::core::ChannelServicePersistence::AccessUnavailable { display, label, .. } => {
            return channel_field_unavailable(state, conn, display, label, "FLAGS");
        }
        crate::core::ChannelServicePersistence::AccessMissing { display, label } => (
            label,
            format!(
                "\x02{display}\x02 is no longer registered; the flags change did not take effect."
            ),
        ),
        crate::core::ChannelServicePersistence::AccessLimitReached { display, label, .. } => (
            label,
            format!(
                "The access list for \x02{display}\x02 is full; revoke an entry before adding \
                 another."
            ),
        ),
        crate::core::ChannelServicePersistence::KeeptopicSet {
            display,
            keeptopic,
            label,
            ..
        } => (
            label,
            format!(
                "KEEPTOPIC for \x02{display}\x02 is now \x02{}\x02.",
                if keeptopic { "ON" } else { "OFF" }
            ),
        ),
        crate::core::ChannelServicePersistence::KeeptopicUnavailable { display, label, .. } => {
            return channel_field_unavailable(state, conn, display, label, "KEEPTOPIC");
        }
        crate::core::ChannelServicePersistence::KeeptopicMissing { display, label }
        | crate::core::ChannelServicePersistence::MlockMissing { display, label } => {
            (label, format!("\x02{display}\x02 is no longer registered."))
        }
        crate::core::ChannelServicePersistence::MlockSet {
            display,
            mlock,
            label,
            ..
        } => (
            label,
            match mlock {
                Some(spec) => format!("MLOCK for \x02{display}\x02 set to \x02{spec}\x02."),
                None => format!("MLOCK for \x02{display}\x02 cleared."),
            },
        ),
        crate::core::ChannelServicePersistence::MlockUnavailable { display, label, .. } => {
            return channel_field_unavailable(state, conn, display, label, "MLOCK");
        }
        crate::core::ChannelServicePersistence::MlockInvalid { label } => (
            label,
            "Could not apply MLOCK — services returned an invalid result.".to_string(),
        ),
    };
    state.emit_deferred_labeled(conn, label, |state| {
        state.service_notice(conn, "ChanServ", &text);
    });
}

/// What a founder-only change refused with the channel row locked tells the
/// requester.
fn refusal_text(display: &str, refusal: crate::db::ChannelRefusal) -> String {
    match refusal {
        crate::db::ChannelRefusal::ChannelMissing => {
            format!("\x02{display}\x02 is no longer registered.")
        }
        crate::db::ChannelRefusal::NotFounder => {
            format!("You are no longer the founder of \x02{display}\x02.")
        }
    }
}

pub(super) fn maybe_complete_registration(state: &mut ServerState, conn: ConnId) {
    {
        let session = &state.sessions[&conn];
        if session.is_registered()
            || session.cap_negotiating
            || session.nick().is_none()
            || session.user().is_none()
            // Hold registration while a SASL credential verify is in flight, so
            // its 900/903 (or 904) can't arrive *after* the 001 welcome burst:
            // a client that sends CAP END before the verdict lands must still
            // see the login result during registration, not out of order. The
            // verify reply re-invokes this once it resolves (`db_reply`).
            || session.sasl_verify_pending
        {
            return;
        }
    }
    // A SASL exchange the client started but never finished (it sent
    // `AUTHENTICATE PLAIN` and then CAP END) cannot hold registration open
    // forever: the SASL spec has the server abort it with 906 and register the
    // client without an account, so a payload arriving later cannot log in a
    // session that has already been welcomed as anonymous.
    if matches!(
        state.sessions[&conn].sasl,
        crate::core::state::SaslState::PlainPending | crate::core::state::SaslState::BearerPending
    ) {
        let session = state.sessions.get_mut(&conn).expect("checked above");
        session.sasl = crate::core::state::SaslState::Idle;
        session.sasl_buf.clear();
        state.numeric(
            conn,
            ERR_SASLABORTED,
            &[],
            Some("SASL authentication aborted"),
        );
    }
    // Server-ban enforcement: refuse a banned session (K/D/X-line) before
    // completing registration.
    {
        let session = &state.sessions[&conn];
        let host = session.host.clone();
        if let Some((kind, reason)) = state.ban_match(&session.server_ban_subject()) {
            let label = kind.label();
            // The operators' half of a `public|private` reason stays theirs.
            let reason = crate::core::state::public_ban_reason(&reason);
            state.numeric(
                conn,
                ERR_YOUREBANNEDCREEP,
                &[],
                Some(&format!("You are banned from this server: {reason}")),
            );
            state.send(
                conn,
                &format!("ERROR :Closing Link: {host} ({label}d: {reason})"),
            );
            state.close(conn, &format!("{label}d: {reason}"));
            return;
        }
    }
    if state.refuse_unauthenticated(conn) {
        return;
    }
    // `signon` is a real timestamp (WHOIS reports the wall-clock time the
    // client connected); `last_active` seeds the idle/reaper clock and is
    // monotonic.
    let signon = (state.config.clock)();
    let active = (state.config.mono_clock)();
    state.sessions.complete_registration(&conn);
    {
        let session = state.sessions.get_mut(&conn).expect("checked");
        session.signon = signon;
        session.last_active.set(active);
    }
    state.mark_nick_registered(conn);
    // Published now rather than with the rest of this event's changes: the
    // welcome below announces the user to whoever MONITORs the nick, and that
    // announcement is made from the published record.
    state.sync_channel_member(conn, crate::core::state::ChannelMemberChange::Identity);
    let prefix = state.sessions[&conn].prefix();
    let (server, network) = (
        state.config.server_name.clone(),
        state.config.network_name.clone(),
    );

    state.numeric(
        conn,
        RPL_WELCOME,
        &[],
        Some(&format!("Welcome to the {network} Network, {prefix}")),
    );
    state.numeric(
        conn,
        RPL_YOURHOST,
        &[],
        Some(&format!(
            "Your host is {server}, running version e6ircd-{}",
            version()
        )),
    );
    state.numeric(
        conn,
        RPL_CREATED,
        &[],
        Some("This server was created at build time"),
    );
    state.numeric(
        conn,
        RPL_MYINFO,
        &[
            &server,
            &format!("e6ircd-{}", version()),
            // Derived from the same mode tables as ISUPPORT CHANMODES/PREFIX, so
            // the two cannot drift: user modes, every channel mode (list and
            // prefix modes included), then the channel modes taking a parameter.
            USER_MODES,
            &myinfo_channel_modes(),
            &myinfo_param_channel_modes(),
        ],
        None,
    );
    send_isupport(state, conn);
    send_lusers(state, conn);
    send_motd(state, conn);
    let nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    monitor_notify(state, &nick, true);
    check_nick_protection(state, conn);
}

pub(super) fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub(super) fn send_lusers(state: &mut ServerState, conn: ConnId) {
    // Server-wide, whichever shards the users and channels live on.
    let crate::core::state::UserCounts {
        users,
        invisible,
        opers,
    } = state.user_counts();
    let visible = users - invisible;
    let (connections, channels, max) = state.census();
    let unknown = connections.saturating_sub(users);
    state.numeric(
        conn,
        RPL_LUSERCLIENT,
        &[],
        Some(&format!(
            "There are {visible} users and {invisible} invisible on 1 servers"
        )),
    );
    if opers > 0 {
        state.numeric(
            conn,
            RPL_LUSEROP,
            &[&opers.to_string()],
            Some("operator(s) online"),
        );
    }
    if unknown > 0 {
        state.numeric(
            conn,
            RPL_LUSERUNKNOWN,
            &[&unknown.to_string()],
            Some("unknown connection(s)"),
        );
    }
    if channels > 0 {
        state.numeric(
            conn,
            RPL_LUSERCHANNELS,
            &[&channels.to_string()],
            Some("channels formed"),
        );
    }
    state.numeric(
        conn,
        RPL_LUSERME,
        &[],
        Some(&format!("I have {users} clients and 0 servers")),
    );
    state.numeric(
        conn,
        RPL_LOCALUSERS,
        &[&users.to_string(), &max.to_string()],
        Some(&format!("Current local users {users}, max {max}")),
    );
    state.numeric(
        conn,
        RPL_GLOBALUSERS,
        &[&users.to_string(), &max.to_string()],
        Some(&format!("Current global users {users}, max {max}")),
    );
}

pub(super) fn send_motd(state: &mut ServerState, conn: ConnId) {
    if state.config.motd.is_empty() {
        state.numeric(conn, ERR_NOMOTD, &[], Some("MOTD File is missing"));
        return;
    }
    let server = state.config.server_name.clone();
    state.numeric(
        conn,
        RPL_MOTDSTART,
        &[],
        Some(&format!("- {server} Message of the day - ")),
    );
    for line in state.config.motd.clone() {
        state.numeric(conn, RPL_MOTD, &[], Some(&format!("- {line}")));
    }
    state.numeric(conn, RPL_ENDOFMOTD, &[], Some("End of /MOTD command."));
}
