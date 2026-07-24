//! Operator commands: OPER, KILL, server bans and WALLOPS.

use super::*;

// ---- OPER ---------------------------------------------------------------

pub(super) fn cmd_oper(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&name), Some(&password)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["OPER"],
            Some("Not enough parameters"),
        );
        return;
    };
    // Always run the constant-time compare — against a dummy secret when the
    // operator name is unknown — so response timing is name-independent and can't
    // be used to enumerate valid operator names. Short-circuiting on an unknown
    // name (skipping the two SHA-256 hashes) would leak existence by timing,
    // defeating the whole point of `constant_time_eq`.
    let stored = state.config.opers.iter().find(|(n, _)| n == name);
    let candidate_pw = stored
        .map(|(_, pw)| pw.as_bytes())
        .unwrap_or(b"\0no-such-oper\0");
    let matched = constant_time_eq(candidate_pw, password.as_bytes()) && stored.is_some();
    if !matched {
        state.numeric(conn, ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
        return;
    }
    state.sessions.get_mut(&conn).expect("registered").oper = true;
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    record_audit(state, conn, "OPER", name, "");
    state.numeric(
        conn,
        RPL_YOUREOPER,
        &[],
        Some("You are now an IRC operator"),
    );
    let server = state.config.server_name.clone();
    state.send(conn, &format!(":{server} MODE {nick} :+o"));
}

/// Length-independent constant-time comparison: both inputs are reduced to a
/// fixed-size SHA-256 digest first, so neither content nor length leaks via
/// timing (a bare byte-compare early-returns on a length mismatch, leaking the
/// secret's length). The digests never leave the process — they exist only to
/// normalize length for the constant-time compare.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use aws_lc_rs::digest::{SHA256, digest};
    let da = digest(&SHA256, a);
    let db = digest(&SHA256, b);
    aws_lc_rs::constant_time::verify_slices_are_equal(da.as_ref(), db.as_ref()).is_ok()
}

// ---- KILL ---------------------------------------------------------------

pub(super) fn cmd_kill(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["KILL"],
            Some("Not enough parameters"),
        );
        return;
    };
    let key = state.nick_key(target);
    let Some(&victim) = state.nicks.get(&key) else {
        state.numeric(
            conn,
            ERR_NOSUCHNICK,
            &[target],
            Some("No such nick/channel"),
        );
        return;
    };
    let comment = p.get(1).copied().unwrap_or("Killed");
    let oper_nick = state.sessions[&conn].nick.clone().expect("registered");
    let reason = format!("Killed ({oper_nick} ({comment}))");
    let server = state.config.server_name.clone();
    // Audit before the close: a self-kill removes the actor's own session,
    // and recording afterwards would resolve the actor to an empty string —
    // an unattributed row in the log whose whole purpose is attribution.
    record_audit(state, conn, "KILL", target, comment);
    state.send(victim, &format!("ERROR :Closing Link: {server} ({reason})"));
    state.close(victim, &reason);
}

/// Record a privileged oper action in the audit log (best-effort; only
/// when a database is configured to hold it).
pub(super) fn record_audit(
    state: &mut ServerState,
    conn: ConnId,
    action: &str,
    target: &str,
    detail: &str,
) {
    if !state.config.sasl_enabled {
        return;
    }
    let actor = state
        .sessions
        .get(&conn)
        .and_then(|s| s.nick.clone())
        .unwrap_or_default();
    let request = crate::core::DbRequest::AuditLog {
        actor,
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.to_string(),
    };
    if state.db_tx.try_push(request).is_err() {
        eprintln!("audit: db queue full or closed; {action} action not recorded");
    }
}

/// Normalise a K-line target: a bare host/nick becomes `*@target`.
/// Normalize a ban `arg` into a mask for `kind`. A KLINE `user@host` with a
/// bare token becomes `*@host`; DLINE (host/IP) and XLINE (realname) masks
/// are used verbatim.
pub(super) fn ban_mask(kind: BanKind, arg: &str) -> String {
    match kind {
        BanKind::Kline if !arg.contains('@') => format!("*@{arg}"),
        _ => arg.to_string(),
    }
}

/// KLINE/DLINE/XLINE [<mask> [reason]] — oper-only. With no argument, list
/// the current bans of this kind; otherwise add one (persisted; matching
/// registered sessions are disconnected).
pub(super) fn cmd_add_ban(state: &mut ServerState, conn: ConnId, kind: BanKind, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let label = kind.label();
    let command = kind.as_str().to_uppercase();
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    let Some(&mask_arg) = p.first() else {
        // List current bans of this kind.
        let lines: Vec<String> = state
            .server_bans
            .iter()
            .filter(|b| b.kind == kind)
            .map(|b| {
                format!(
                    ":{server} NOTICE {nick} :{label} {} (by {}) :{}",
                    b.mask, b.set_by, b.reason
                )
            })
            .collect();
        for line in lines {
            state.send(conn, &line);
        }
        state.send(
            conn,
            &format!(":{server} NOTICE {nick} :End of {label} list."),
        );
        return;
    };
    let mask = ban_mask(kind, mask_arg);
    let reason = p.get(1).copied().unwrap_or("No reason").to_string();
    // Replace any existing ban of this kind on the same mask.
    state
        .server_bans
        .retain(|b| !(b.kind == kind && b.mask == mask));
    state.server_bans.push(ServerBan {
        mask: mask.clone(),
        reason: reason.clone(),
        set_by: nick.clone(),
        kind,
    });
    if state.config.sasl_enabled {
        let request = crate::core::DbRequest::AddServerBan {
            mask: mask.clone(),
            reason: reason.clone(),
            set_by: nick.clone(),
            kind: kind.as_str().to_string(),
        };
        if state.db_tx.try_push(request).is_err() {
            eprintln!("{command}: db queue full or closed; {label} for {mask} not persisted");
        }
    }
    // Disconnect any matching registered sessions.
    let casemap = state.casemap;
    let victims: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.registered)
        .filter_map(|(&c, s)| {
            let subject = ServerState::ban_subject(
                kind,
                s.user.as_deref().unwrap_or("*"),
                &s.host,
                s.realname.as_deref().unwrap_or(""),
            );
            e6irc_proto::mask::matches(casemap, &mask, &subject).then_some(c)
        })
        .collect();
    for victim in victims {
        state.send(
            victim,
            &format!("ERROR :Closing Link: ({label}d: {reason})"),
        );
        state.close(victim, &format!("{label}d: {reason}"));
    }
    record_audit(state, conn, &command, &mask, &reason);
    state.send(
        conn,
        &format!(":{server} NOTICE {nick} :Added {label} for {mask}"),
    );
}

/// UNKLINE/UNDLINE/UNXLINE <mask> — oper-only. Remove a server ban of the
/// given kind.
pub(super) fn cmd_remove_ban(state: &mut ServerState, conn: ConnId, kind: BanKind, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let label = kind.label();
    let un = format!("UN{}", kind.as_str().to_uppercase());
    let Some(&mask_arg) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &[&un],
            Some("Not enough parameters"),
        );
        return;
    };
    let mask = ban_mask(kind, mask_arg);
    let before = state.server_bans.len();
    state
        .server_bans
        .retain(|b| !(b.kind == kind && b.mask == mask));
    let removed = state.server_bans.len() < before;
    if removed && state.config.sasl_enabled {
        let request = crate::core::DbRequest::RemoveServerBan {
            mask: mask.clone(),
            kind: kind.as_str().to_string(),
        };
        if state.db_tx.try_push(request).is_err() {
            eprintln!("{un}: db queue full or closed; removal of {mask} not persisted");
        }
    }
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    let msg = if removed {
        format!("Removed {label} for {mask}")
    } else {
        format!("No {label} found for {mask}")
    };
    if removed {
        record_audit(state, conn, &un, &mask, "");
    }
    state.send(conn, &format!(":{server} NOTICE {nick} :{msg}"));
}

/// SETHOST <nick> <host> — oper-only. Change a user's displayed host
/// (cloak) and announce it via CHGHOST to capable peers. This is the
/// host-change trigger the chghost cap needs.
pub(super) fn cmd_sethost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let (Some(&nick), Some(&newhost)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["SETHOST"],
            Some("Not enough parameters"),
        );
        return;
    };
    let server = state.config.server_name.clone();
    let oper_nick = state.sessions[&conn].nick.clone().expect("registered");
    // A host must be a single non-empty token without user/prefix chars.
    // A host rides in every future prefix built for this user, so an unbounded
    // one makes every subsequent line unfittable at the source — bound it here
    // (63 bytes, the DNS label/hostname norm) alongside the character rules.
    if newhost.is_empty() || newhost.len() > 63 || newhost.contains([' ', '@', '!', '\0']) {
        state.send(
            conn,
            &format!(":{server} NOTICE {oper_nick} :Invalid host: {newhost}"),
        );
        return;
    }
    let nk = state.nick_key(nick);
    let Some(target) = state.registered_peer(&nk) else {
        state.numeric(conn, ERR_NOSUCHNICK, &[nick], Some("No such nick/channel"));
        return;
    };
    let (user, old_prefix) = {
        let s = &state.sessions[&target];
        (s.user.clone().unwrap_or_default(), s.prefix())
    };
    state.sessions.get_mut(&target).expect("checked").host = newhost.to_string();

    // Announce with the old prefix so clients can match, to every
    // chghost-capable peer (including the target).
    let chghost = format!(":{old_prefix} CHGHOST {user} {newhost}");
    let mut recipients = state.channel_peers(target);
    recipients.push(target);
    for peer in recipients {
        if state.sessions.get(&peer).is_some_and(|s| s.caps.chghost) {
            state.send_timed(peer, &chghost);
        }
    }
    record_audit(state, conn, "SETHOST", nick, newhost);
    state.send(
        conn,
        &format!(":{server} NOTICE {oper_nick} :Set host of {nick} to {newhost}"),
    );
}

// ---- WALLOPS ------------------------------------------------------------

pub(super) fn cmd_wallops(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let Some(&text) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["WALLOPS"],
            Some("Not enough parameters"),
        );
        return;
    };
    let prefix = state.sessions[&conn].prefix();
    // Relayed under the oper's prefix, so fit like every other client-text relay.
    let head = format!(":{prefix} WALLOPS :");
    let text = crate::core::handler::fit_trailing(&head, text);
    let line = format!("{head}{text}");
    let recipients: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.registered && s.wallops)
        .map(|(c, _)| *c)
        .collect();
    for recipient in recipients {
        state.send_timed(recipient, &line);
    }
}
