//! The integrated NickServ and ChanServ pseudo-clients.

use super::*;

// ---- services pseudo-clients --------------------------------------------

/// Casefolded nicks the built-in services pseudo-clients occupy. PRIVMSG to
/// these is intercepted (see `deliver_one_message`), so they are also reserved
/// at NICK — one list backs both, so the intercept and the reservation can't
/// disagree and let a user seize a service nick.
pub(super) const SERVICE_NICKS: [&str; 2] = ["nickserv", "chanserv"];

/// Whether `key` (a casefolded nick) is a reserved services pseudo-client.
/// Clear every hot map scoped to a registration after PostgreSQL confirms the
/// row is gone. `channel_access` cascades with the row; the other fields are
/// columns on it. One cleanup funnel serves ChanServ and the HTTP console.
pub(crate) fn clear_registered_channel(state: &mut ServerState, key: &ChanKey) {
    state.registered_founders.remove(key);
    state.registered_topics.remove(key);
    state.pending_channel_topics.remove(key);
    state.channel_options.remove(key);
}

pub(super) fn is_service_nick(key: &str) -> bool {
    SERVICE_NICKS.contains(&key)
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
        "REGISTER" => {
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
            if state.sessions[&conn].account.is_some() {
                state.service_notice(conn, "NickServ", "You are already logged in.");
                return;
            }
            // Per-IP account-creation throttle (mirrors the REGISTER path): the
            // per-connection budget alone doesn't stop one address minting
            // accounts across a churn of short-lived connections.
            if !state.registration_rate_ok(&state.sessions[&conn].host.clone()) {
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
            let name = state.sessions[&conn]
                .nick()
                .map(String::from)
                .expect("registered");
            let request = crate::core::DbRequest::CreateAccount {
                conn,
                name,
                contact_email,
                password: password.to_string(),
                origin: crate::core::AccountOrigin::NickServ,
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        "IDENTIFY" => {
            // IDENTIFY <password> | IDENTIFY <account> <password>
            let (account, password) = match args {
                [password] => (
                    state.sessions[&conn]
                        .nick()
                        .map(String::from)
                        .expect("registered"),
                    *password,
                ),
                [account, password] => (account.to_string(), *password),
                _ => {
                    state.service_notice(conn, "NickServ", "Syntax: IDENTIFY [account] <password>");
                    return;
                }
            };
            // One credential verification may be in flight per connection.
            if state.sessions[&conn].sasl_verify_pending
                || state.sessions[&conn].pending_identify.is_some()
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
                state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                );
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
        "GHOST" => {
            // GHOST <nick>: disconnect a lingering session holding a nick
            // you own, so you can reclaim it. An account owns the nick of
            // the same name (nick registration model).
            let Some(&nick) = args.first() else {
                state.service_notice(conn, "NickServ", "Syntax: GHOST <nick>");
                return;
            };
            let Some(account) = require_identified(
                state,
                conn,
                "NickServ",
                "You must identify to services before using GHOST.",
            ) else {
                return;
            };
            if state.casemap.casefold(&account) != state.casemap.casefold(nick) {
                state.service_notice(conn, "NickServ", &format!("You do not own \x02{nick}\x02."));
                return;
            }
            let key = state.nick_key(nick);
            let Some(victim) = state.nick_connection(&key) else {
                state.service_notice(conn, "NickServ", &format!("\x02{nick}\x02 is not online."));
                return;
            };
            if victim == conn {
                state.service_notice(conn, "NickServ", "You cannot ghost yourself.");
                return;
            }
            let by = state.sessions[&conn]
                .nick()
                .map(String::from)
                .unwrap_or_default();
            let server = state.config.server_name.clone();
            let reason = format!("GHOST command used by {by}");
            state.send(victim, &format!("ERROR :Closing Link: {server} ({reason})"));
            state.close(victim, &reason);
            state.service_notice(
                conn,
                "NickServ",
                &format!("\x02{nick}\x02 has been ghosted."),
            );
        }
        "LOGOUT" => {
            // De-identify: clear the account and tell account-notify peers the
            // session is now unauthenticated (`ACCOUNT *`). Founder/access
            // authority is checked live against `account`, so it is revoked at
            // once; a client can now drop its identity without reconnecting.
            if state.sessions[&conn].account.is_none() {
                state.service_notice(conn, "NickServ", "You are not logged in.");
                return;
            }
            state.sessions.get_mut(&conn).expect("checked").account = None;
            super::sasl::notify_account_change(state, conn, "*");
            state.service_notice(conn, "NickServ", "You are now logged out.");
        }
        "HELP" => {
            for line in [
                "***** NickServ Help *****",
                "REGISTER <password> [email] - Register your current nick",
                "IDENTIFY [account] <password> - Log in to your account",
                "LOGOUT - Log out of your account (de-identify)",
                "GHOST <nick> - Disconnect a lingering session on your nick",
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
            state.set_founder(&channel, &founder_account);
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
    state.emit_deferred_labeled(conn, label, |state| match result {
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
    });
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
            let command = crate::core::state::ChannelCommand::new(
                state.channel_owner(channel),
                state.channel_actor(conn),
                channel.to_string(),
                crate::core::state::ChannelCommandOperation::ChanServRegister,
                state
                    .capture
                    .as_ref()
                    .and_then(|capture| capture.label.clone()),
            );
            if state.owns_channel(command.owner()) {
                crate::core::handler::channel_command(state, command);
            } else {
                state.route_channel_command(command);
            }
            state.defer_captured_reply(conn);
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
                channel: key.as_str().to_string(),
                requester: crate::core::ChannelDropRequester::ChanServ {
                    session: state.channel_actor(conn).session_owner(),
                    display: channel.to_string(),
                    label,
                },
            };
            queue_service_verdict(state, conn, request);
        }
        "FLAGS" => chanserv_flags(state, conn, args),
        "OP" => chanserv_op(state, conn, args),
        "SET" => chanserv_set(state, conn, args),
        "HELP" => {
            for line in [
                "***** ChanServ Help *****",
                "REGISTER <#channel> - Register a channel you operate",
                "DROP <#channel> - Unregister a channel you founded",
                "FLAGS <#channel> [account [+/-ov]] - List or set channel access",
                "OP <#channel> [nick] - Op yourself or a nick (needs op access)",
                "SET <#channel> FOUNDER <account> - Transfer channel ownership",
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

/// ChanServ FLAGS: list a registered channel's access entries, or (founder
/// only) modify one account's flags. Auto-op/voice apply on the account's
/// next join.
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
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(conn, service, hint);
        return None;
    };
    Some(account)
}

pub(super) fn chanserv_flags(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: FLAGS <#channel> [account [+/-flags]]",
        );
        return;
    };
    let Some((key, _account)) = chanserv_founder_gate(
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
    let target_key = state.account_key(target);
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

    // Persist first; the hot map and the confirmation are applied on the
    // `ChannelAccessSet` reply, so a grant to an *unregistered* account (which
    // writes no row) can't leave a phantom hot entry that would auto-op a later
    // registration of that name.
    let request = crate::core::DbRequest::SetChannelAccess {
        conn,
        channel: channel.to_string(),
        account: target.to_string(),
        flags: (!new_flags.is_empty()).then_some(new_flags),
    };
    if state.db_tx.try_push(request).is_err() {
        state.service_notice(
            conn,
            "ChanServ",
            "Services are temporarily unavailable. Try again later.",
        );
    }
}

pub(super) fn chanserv_op(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(conn, "ChanServ", "Syntax: OP <#channel> [nick]");
        return;
    };
    if require_identified(
        state,
        conn,
        "ChanServ",
        "You must identify to services before using OP.",
    )
    .is_none()
    {
        return;
    }
    let target_nick = match args.get(1) {
        Some(&n) => n.to_string(),
        None => state.sessions[&conn]
            .nick()
            .map(String::from)
            .expect("registered"),
    };
    let owner = state.channel_owner(channel);
    let label = state.channel_reply_label(conn, &owner);
    let command = crate::core::state::ChannelCommand::new(
        owner,
        state.channel_actor(conn),
        channel.to_string(),
        crate::core::state::ChannelCommandOperation::ChanServOp { target_nick },
        label,
    );
    if state.owns_channel(command.owner()) {
        let result = chanserv_op_on_owner(state, command);
        emit_chanserv_op_result(state, conn, result);
    } else {
        state.route_channel_command(command);
    }
}

pub(crate) fn chanserv_op_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> crate::core::state::ChanServOpResult {
    let (owner, actor, target, operation) = command.into_parts();
    let crate::core::state::ChannelCommandOperation::ChanServOp { target_nick } = operation else {
        unreachable!("ChanServ OP command operation");
    };
    let key = state.chan_key(&target);
    assert_eq!(owner.key(), &key, "ChanServ OP owner does not match target");
    let Some(account) = actor.account else {
        unreachable!("identified ChanServ actor has no account");
    };
    let account = state.account_key(&account);
    if !state.is_registered(&key) {
        return crate::core::state::ChanServOpResult::NotRegistered { channel: target };
    }
    if !(state.is_founder(&key, account.as_str()) || state.access_modes(&key, account.as_str()).0) {
        return crate::core::state::ChanServOpResult::NoAccess { channel: target };
    }
    let target_key = state.nick_key(&target_nick);
    let Some(target_owner) = state.nick_reservation(&target_key) else {
        return crate::core::state::ChanServOpResult::TargetOffline {
            target: target_nick,
        };
    };
    let target_conn = target_owner.conn();
    let Some(channel) = state.channels.get_mut(&key) else {
        return crate::core::state::ChanServOpResult::TargetNotOnChannel {
            target: target_nick,
            channel: target,
        };
    };
    let display = channel.name.clone();
    let Some(member) = channel.member_mut(target_conn) else {
        return crate::core::state::ChanServOpResult::TargetNotOnChannel {
            target: target_nick,
            channel: display,
        };
    };
    if member.op {
        return crate::core::state::ChanServOpResult::AlreadyOpped {
            target: target_nick,
        };
    }
    member.op = true;
    let server = state.config.server_name.clone();
    state.broadcast_channel(
        &key,
        &format!(":{server} MODE {display} +o {target_nick}"),
        None,
    );
    crate::core::state::ChanServOpResult::Opped {
        target: target_nick,
        channel: display,
    }
}

pub(crate) fn emit_chanserv_op_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChanServOpResult,
) {
    match result {
        crate::core::state::ChanServOpResult::NotRegistered { channel } => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        ),
        crate::core::state::ChanServOpResult::NoAccess { channel } => state.service_notice(
            conn,
            "ChanServ",
            &format!("You do not have op access on \x02{channel}\x02."),
        ),
        crate::core::state::ChanServOpResult::TargetOffline { target } => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{target}\x02 is not online."),
        ),
        crate::core::state::ChanServOpResult::TargetNotOnChannel { target, channel } => state
            .service_notice(
                conn,
                "ChanServ",
                &format!("\x02{target}\x02 is not on \x02{channel}\x02."),
            ),
        crate::core::state::ChanServOpResult::AlreadyOpped { target } => state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{target}\x02 is already opped."),
        ),
        crate::core::state::ChanServOpResult::Opped { target, channel } => state.service_notice(
            conn,
            "ChanServ",
            &format!("Opped \x02{target}\x02 on \x02{channel}\x02."),
        ),
    }
}

/// ChanServ SET: founder-only channel options. Currently FOUNDER (transfer
/// ownership to another account, verified against the DB).
pub(super) fn chanserv_set(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let (Some(&channel), Some(&option)) = (args.first(), args.get(1)) else {
        state.service_notice(conn, "ChanServ", "Syntax: SET <#channel> <option> <value>");
        return;
    };
    let Some((key, _account)) = chanserv_founder_gate(
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
                conn,
                channel: channel.to_string(),
                new_founder: state.casemap.casefold(new),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
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
                conn,
                channel: key.as_str().to_string(),
                display: channel.to_string(),
                keeptopic: on,
                topic,
                label,
            };
            queue_service_verdict(state, conn, request);
        }
        "MLOCK" => {
            let spec = args.get(2).copied().unwrap_or("");
            // Clear the lock on empty / OFF / "-".
            if spec.is_empty() || spec.eq_ignore_ascii_case("OFF") || spec == "-" {
                let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
                let request = crate::core::DbRequest::SetChannelMlock {
                    conn,
                    channel: key.as_str().to_string(),
                    display: channel.to_string(),
                    mlock: None,
                    label,
                };
                queue_service_verdict(state, conn, request);
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
                        &format!("\x02{bad}\x02 is not a lockable mode. Lockable: i m n s t C."),
                    );
                    return;
                }
            };
            let canonical = parsed.render();
            let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
            let request = crate::core::DbRequest::SetChannelMlock {
                conn,
                channel: key.as_str().to_string(),
                display: channel.to_string(),
                mlock: Some(canonical.clone()),
                label,
            };
            queue_service_verdict(state, conn, request);
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
                    "Unknown SET option \x02{other}\x02. Available: FOUNDER, KEEPTOPIC, MLOCK."
                ),
            );
        }
    }
}

fn queue_service_verdict(state: &mut ServerState, conn: ConnId, request: crate::core::DbRequest) {
    if state.db_tx.try_push(request).is_err() {
        state.service_notice(
            conn,
            "ChanServ",
            "Services are temporarily unavailable. Try again later.",
        );
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
        } => {
            let conn = session.conn();
            if state.sessions.contains_key(&conn) {
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
                    crate::core::ChannelDropResult::Unavailable => state.service_notice(
                        conn,
                        "ChanServ",
                        "Services are temporarily unavailable. Try again later.",
                    ),
                });
            }
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

pub(super) struct AppliedChannelKeeptopic {
    pub(super) channel: String,
    pub(super) display: String,
    pub(super) keeptopic: bool,
    pub(super) topic: Option<(String, String, u64)>,
    pub(super) applied: bool,
    pub(super) label: Option<String>,
}

pub(super) fn channel_keeptopic_set(
    state: &mut ServerState,
    conn: ConnId,
    result: AppliedChannelKeeptopic,
) {
    let AppliedChannelKeeptopic {
        channel,
        display,
        keeptopic,
        topic,
        applied,
        label,
    } = result;
    let key = state.chan_key(&channel);
    if applied && state.is_registered(&key) {
        if keeptopic {
            state.channel_options.set_keeptopic(key.clone(), true);
            replace_registered_topic(state, &key, topic);
        } else {
            state.channel_options.set_keeptopic(key.clone(), false);
            state.registered_topics.remove(&key);
        }
    }
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, |state| {
            if applied && state.is_registered(&key) {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!(
                        "KEEPTOPIC for \x02{display}\x02 is now \x02{}\x02.",
                        if keeptopic { "ON" } else { "OFF" }
                    ),
                );
            } else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("\x02{display}\x02 is no longer registered."),
                );
            }
        });
    }
}

/// Emit a deferred, labeled ChanServ NOTICE to the connection if it is still
/// present — the shared shape of the per-field `*_unavailable` replies.
pub(super) fn chanserv_deferred_notice(
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

pub(super) fn channel_mlock_set(
    state: &mut ServerState,
    conn: ConnId,
    channel: String,
    display: String,
    mlock: Option<String>,
    applied: bool,
    label: Option<String>,
) {
    let key = state.chan_key(&channel);
    let parsed = mlock
        .as_deref()
        .map(crate::core::state::MlockModes::parse)
        .transpose();
    let valid = match parsed {
        Ok(parsed) => {
            if applied && state.is_registered(&key) {
                match parsed {
                    Some(modes) => {
                        state.channel_options.set_mlock(key.clone(), Some(modes));
                        apply_mlock(state, &key);
                    }
                    None => {
                        state.channel_options.set_mlock(key.clone(), None);
                    }
                }
            }
            true
        }
        Err(bad) => {
            eprintln!("core: database echoed invalid canonical MLOCK character {bad:?}");
            false
        }
    };
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, |state| {
            if !valid {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Could not apply MLOCK — services returned an invalid result.",
                );
            } else if !applied || !state.is_registered(&key) {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("\x02{display}\x02 is no longer registered."),
                );
            } else if let Some(spec) = mlock {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("MLOCK for \x02{display}\x02 set to \x02{spec}\x02."),
                );
            } else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("MLOCK for \x02{display}\x02 cleared."),
                );
            }
        });
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
    // Server-ban enforcement: refuse a banned session (K/D/X-line) before
    // completing registration.
    {
        let session = &state.sessions[&conn];
        let user = session.user().unwrap_or("*");
        let host = session.host.clone();
        let realname = session.realname().unwrap_or("");
        if let Some((kind, reason)) = state.ban_match(user, &host, realname) {
            let label = kind.label();
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
    // `signon` is a real timestamp (WHOIS reports the wall-clock time the
    // client connected); `last_active` seeds the idle/reaper clock and is
    // monotonic.
    let signon = (state.config.clock)();
    let active = (state.config.mono_clock)();
    {
        let session = state.sessions.get_mut(&conn).expect("checked");
        session.complete_registration();
        session.signon = signon;
        session.last_active = active;
    }
    state.mark_nick_registered(conn);
    let registered_now = state
        .sessions
        .values()
        .filter(|s| s.is_registered())
        .count();
    state.max_users = state.max_users.max(registered_now);
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
            // Must match what the server actually implements (RPL_UMODEIS /
            // CHANMODES): user modes +i/+o/+w/+B, channel modes +imnstkl and
            // +C (no-CTCP), prefix modes +o/+v.
            "iowB",
            "imnstklC",
            "ov",
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
}

pub(super) fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub(super) fn send_lusers(state: &mut ServerState, conn: ConnId) {
    let users = state
        .sessions
        .values()
        .filter(|s| s.is_registered())
        .count();
    let invisible = state
        .sessions
        .values()
        .filter(|s| s.is_registered() && s.invisible)
        .count();
    let visible = users - invisible;
    let opers = state
        .sessions
        .values()
        .filter(|s| s.is_registered() && s.oper)
        .count();
    let unknown = state
        .sessions
        .values()
        .filter(|s| !s.is_registered())
        .count();
    let channels = state.channels.len();
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
    let max = state.max_users;
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
