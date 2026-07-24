//! The integrated NickServ and ChanServ pseudo-clients.

use super::*;

// ---- services pseudo-clients --------------------------------------------

/// Casefolded nicks the built-in services pseudo-clients occupy. PRIVMSG to
/// these is intercepted (see `deliver_one_message`), so they are also reserved
/// at NICK — one list backs both, so the intercept and the reservation can't
/// disagree and let a user seize a service nick.
pub(super) const SERVICE_NICKS: [&str; 2] = ["nickserv", "chanserv"];

/// Whether `key` (a casefolded nick) is a reserved services pseudo-client.
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
            let Some(&password) = args.first() else {
                state.service_notice(conn, "NickServ", "Syntax: REGISTER <password> [email]");
                return;
            };
            if state.sessions[&conn].account.is_some() {
                state.service_notice(conn, "NickServ", "You are already logged in.");
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
            let name = state.sessions[&conn].nick.clone().expect("registered");
            let request = crate::core::DbRequest::CreateAccount {
                conn,
                name,
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
                    state.sessions[&conn].nick.clone().expect("registered"),
                    *password,
                ),
                [account, password] => (account.to_string(), *password),
                _ => {
                    state.service_notice(conn, "NickServ", "Syntax: IDENTIFY [account] <password>");
                    return;
                }
            };
            // A SASL verify and an IDENTIFY verify must never be in flight for
            // one connection at once: both are offloaded and their replies
            // routed by ambient flags, so an IDENTIFY reply landing mid-SASL
            // would be taken for the SASL result (logging the client in as the
            // wrong account), and vice-versa. Reject an IDENTIFY while a SASL
            // verify is pending; the SASL verify-start likewise refuses while an
            // IDENTIFY is pending, so the two flows are mutually exclusive. (Two
            // overlapping IDENTIFYs are harmless by contrast — each names an
            // account the client proved it owns — so they stay allowed, bounded
            // by the credential budget below.)
            if state.sessions[&conn].sasl == crate::core::state::SaslState::Verifying {
                state.service_notice(
                    conn,
                    "NickServ",
                    "A SASL authentication is already in progress. Try again in a moment.",
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
            state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .pending_identify = true;
            let request = crate::core::DbRequest::VerifyPassword {
                conn,
                account,
                password: password.to_string(),
            };
            if state.db_tx.try_push(request).is_err() {
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .pending_identify = false;
                state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                );
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
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "NickServ",
                    "You must identify to services before using GHOST.",
                );
                return;
            };
            if state.casemap.casefold(&account) != state.casemap.casefold(nick) {
                state.service_notice(conn, "NickServ", &format!("You do not own \x02{nick}\x02."));
                return;
            }
            let key = state.nick_key(nick);
            let Some(&victim) = state.nicks.get(&key) else {
                state.service_notice(conn, "NickServ", &format!("\x02{nick}\x02 is not online."));
                return;
            };
            if victim == conn {
                state.service_notice(conn, "NickServ", "You cannot ghost yourself.");
                return;
            }
            let by = state.sessions[&conn].nick.clone().unwrap_or_default();
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
        "HELP" => {
            for line in [
                "***** NickServ Help *****",
                "REGISTER <password> [email] - Register your current nick",
                "IDENTIFY [account] <password> - Log in to your account",
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

pub(super) fn chanserv(state: &mut ServerState, conn: ConnId, command: &str, args: &[&str]) {
    match command {
        "REGISTER" => {
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: REGISTER <#channel>");
                return;
            };
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must identify to services before registering a channel.",
                );
                return;
            };
            let key = state.chan_key(channel);
            let is_op = state
                .channels
                .get(&key)
                .and_then(|c| c.members.get(&conn))
                .is_some_and(|m| m.op);
            if !is_op {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must be a channel operator in that channel to register it.",
                );
                return;
            }
            let display = state.channels[&key].name.clone();
            let request = crate::core::DbRequest::RegisterChannel {
                conn,
                channel: display,
                founder_account: account,
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        "DROP" => {
            // DROP <#channel>: the founder unregisters their channel.
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: DROP <#channel>");
                return;
            };
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must identify to services before dropping a channel.",
                );
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
            let request = crate::core::DbRequest::DropChannel {
                channel: key.as_str().to_string(),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
                return;
            }
            // Drop the hot registration too: no more founder-op, topic
            // retention, mode lock, keeptopic override, or access for this
            // channel. `drop_channel` deletes the whole `channels` row — and the
            // mlock/keeptopic settings are columns *on that row* — so every hot
            // map scoped to registration must be cleared, or a later recreation
            // of the channel reapplies a stale lock / keeptopic that the DB no
            // longer holds (a divergence that a restart would silently flip).
            // (The DB row's channel_access cascades on the row delete.)
            state.registered_founders.remove(&key);
            state.registered_topics.remove(&key);
            state.channel_access.remove(&key);
            state.channel_mlock.remove(&key);
            state.keeptopic_off.remove(&key);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{channel}\x02 has been dropped."),
            );
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

/// Apply a `+ov`/`-o`-style change string to a current flag set, keeping
/// only the recognised flags (`o` auto-op, `v` auto-voice), sorted.
pub(super) fn apply_flag_changes(current: &str, changes: &str) -> String {
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
            _ => {}
        }
    }
    flags.into_iter().collect()
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
    conn: ConnId,
    channel: &str,
    identify_hint: &str,
) -> Option<(ChanKey, String)> {
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(conn, "ChanServ", identify_hint);
        return None;
    };
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return None;
    }
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
        conn,
        channel,
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
            .channel_access
            .get(&key)
            .map(|m| {
                m.iter()
                    .map(|(a, f)| (a.as_str().to_string(), f.clone()))
                    .collect()
            })
            .unwrap_or_default();
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
        .channel_access
        .get(&key)
        .and_then(|m| m.get(&target_key))
        .cloned()
        .unwrap_or_default();
    let new_flags = apply_flag_changes(&current, changes);

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

/// ChanServ OP: op yourself (or a named nick) on a registered channel you
/// have op access to (founder or the `o` access flag). The target must be
/// online and on the channel.
pub(super) fn chanserv_op(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(conn, "ChanServ", "Syntax: OP <#channel> [nick]");
        return;
    };
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(
            conn,
            "ChanServ",
            "You must identify to services before using OP.",
        );
        return;
    };
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return;
    }
    if !(state.is_founder(&key, &account) || state.access_modes(&key, &account).0) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("You do not have op access on \x02{channel}\x02."),
        );
        return;
    }

    // Target: the named nick, or the requester's own nick.
    let target_nick = match args.get(1) {
        Some(&n) => n.to_string(),
        None => state.sessions[&conn].nick.clone().expect("registered"),
    };
    let nk = state.nick_key(&target_nick);
    let Some(&target_conn) = state.nicks.get(&nk) else {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{target_nick}\x02 is not online."),
        );
        return;
    };
    match state
        .channels
        .get(&key)
        .and_then(|c| c.members.get(&target_conn))
        .map(|m| m.op)
    {
        None => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{target_nick}\x02 is not on \x02{channel}\x02."),
            );
            return;
        }
        Some(true) => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{target_nick}\x02 is already opped."),
            );
            return;
        }
        Some(false) => {}
    }
    if let Some(chan) = state.channels.get_mut(&key)
        && let Some(member) = chan.members.get_mut(&target_conn)
    {
        member.op = true;
    }
    let display = state.channels[&key].name.clone();
    let server = state.config.server_name.clone();
    state.broadcast_channel(
        &key,
        &format!(":{server} MODE {display} +o {target_nick}"),
        None,
    );
    state.service_notice(
        conn,
        "ChanServ",
        &format!("Opped \x02{target_nick}\x02 on \x02{channel}\x02."),
    );
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
        conn,
        channel,
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
            // Persist first, mutate hot state only on success (no divergence).
            let request = crate::core::DbRequest::SetChannelKeeptopic {
                channel: key.as_str().to_string(),
                keeptopic: on,
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
                return;
            }
            if on {
                state.keeptopic_off.remove(&key);
                // KEEPTOPIC just became effective again; capture the current
                // live topic so it survives the next empty→recreate cycle. The
                // TOPIC path persists only on *change* and the earlier OFF
                // dropped the retained copy, so without this the live topic
                // would be silently lost. Mirrors the registration-time capture.
                if let Some(topic) = state.channels.get(&key).and_then(|c| c.topic.clone()) {
                    state.registered_topics.insert(key.clone(), topic.clone());
                    let request = crate::core::DbRequest::SetChannelTopic {
                        channel: key.as_str().to_string(),
                        topic: Some((topic.text, topic.set_by, topic.set_at_secs)),
                    };
                    if state.db_tx.try_push(request).is_err() {
                        eprintln!(
                            "chanserv: db queue full; retained topic for {} not persisted",
                            key.as_str()
                        );
                    }
                }
            } else {
                state.keeptopic_off.insert(key.clone());
                // Drop any retained topic so it can't be restored later.
                if state.registered_topics.remove(&key).is_some() {
                    let clear = crate::core::DbRequest::SetChannelTopic {
                        channel: key.as_str().to_string(),
                        topic: None,
                    };
                    if state.db_tx.try_push(clear).is_err() {
                        eprintln!(
                            "chanserv: db queue full; cleared topic for {} not persisted",
                            key.as_str()
                        );
                    }
                }
            }
            state.service_notice(
                conn,
                "ChanServ",
                &format!(
                    "KEEPTOPIC for \x02{channel}\x02 is now \x02{}\x02.",
                    if on { "ON" } else { "OFF" }
                ),
            );
        }
        "MLOCK" => {
            let spec = args.get(2).copied().unwrap_or("");
            // Clear the lock on empty / OFF / "-".
            if spec.is_empty() || spec.eq_ignore_ascii_case("OFF") || spec == "-" {
                let request = crate::core::DbRequest::SetChannelMlock {
                    channel: key.as_str().to_string(),
                    mlock: None,
                };
                if state.db_tx.try_push(request).is_err() {
                    state.service_notice(
                        conn,
                        "ChanServ",
                        "Services are temporarily unavailable. Try again later.",
                    );
                    return;
                }
                state.channel_mlock.remove(&key);
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("MLOCK for \x02{channel}\x02 cleared."),
                );
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
            let request = crate::core::DbRequest::SetChannelMlock {
                channel: key.as_str().to_string(),
                mlock: Some(canonical.clone()),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
                return;
            }
            // Persisted: record it and enforce immediately on the live channel.
            state.channel_mlock.insert(key.clone(), parsed);
            apply_mlock(state, &key);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("MLOCK for \x02{channel}\x02 set to \x02{canonical}\x02."),
            );
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

pub(super) fn maybe_complete_registration(state: &mut ServerState, conn: ConnId) {
    {
        let session = &state.sessions[&conn];
        if session.registered
            || session.cap_negotiating
            || session.nick.is_none()
            || session.user.is_none()
        {
            return;
        }
    }
    // Server-ban enforcement: refuse a banned session (K/D/X-line) before
    // completing registration.
    {
        let session = &state.sessions[&conn];
        let user = session.user.as_deref().unwrap_or("*");
        let host = session.host.clone();
        let realname = session.realname.as_deref().unwrap_or("");
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
    let now = (state.config.clock)();
    {
        let session = state.sessions.get_mut(&conn).expect("checked");
        session.registered = true;
        session.signon = now;
        session.last_active = now;
    }
    let registered_now = state.sessions.values().filter(|s| s.registered).count();
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
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    monitor_notify(state, &nick, true);
}

pub(super) fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub(super) fn send_lusers(state: &mut ServerState, conn: ConnId) {
    let users = state.sessions.values().filter(|s| s.registered).count();
    let invisible = state
        .sessions
        .values()
        .filter(|s| s.registered && s.invisible)
        .count();
    let visible = users - invisible;
    let opers = state
        .sessions
        .values()
        .filter(|s| s.registered && s.oper)
        .count();
    let unknown = state.sessions.values().filter(|s| !s.registered).count();
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
