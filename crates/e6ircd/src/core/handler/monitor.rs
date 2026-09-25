//! MONITOR: presence notification for watched nicks.

use super::*;

// ---- MONITOR ------------------------------------------------------------

pub(super) const MONITOR_LIMIT: usize = 100;

/// Notify everyone monitoring `nick`, on whichever shard they live, that it
/// is now (`online`) or no longer (`offline`) present. The subject is the full
/// prefix when online, the bare nick when offline (per the monitor spec).
pub(crate) fn monitor_notify(state: &mut ServerState, nick: &str, online: bool) {
    let key = state.nick_key(nick);
    let subject = online
        .then(|| state.registered_user(&key))
        .flatten()
        .map(|user| user.prefix())
        .unwrap_or_else(|| nick.to_string());
    let code = e6irc_proto::numerics::code_str(if online {
        RPL_MONONLINE
    } else {
        RPL_MONOFFLINE
    });
    let server = state.config.server_name.clone();
    for watcher in state.monitors.watchers(&key) {
        let Some(watcher) = state.user(watcher) else {
            continue;
        };
        let line = format!(":{server} {code} {} :{subject}\r\n", watcher.nick);
        state.send_recipient_uncaptured(watcher.recipient, bytes::Bytes::from(line));
    }
}

/// The shared fan-out for a user-state event (AWAY, ACCOUNT, SETNAME,
/// CHGHOST): deliver `line` once to each of the subject's channel peers and
/// extended-monitor watchers holding the event's capability. `include_self`
/// echoes the line to the subject itself (SETHOST, which the renamed user must
/// see); identity events that the client already originated skip it.
pub(crate) fn notify_event(
    state: &mut ServerState,
    subject: ConnId,
    line: &EventLine,
    audience: crate::core::state::UserEventAudience,
    include_self: bool,
) {
    state.notify_user_event(subject, line, audience, include_self);
}

pub(super) fn monitor_status(
    state: &mut ServerState,
    conn: ConnId,
    targets: &[(crate::core::state::NickKey, String)],
) {
    let mut online = Vec::new();
    let mut offline = Vec::new();
    for (key, shown) in targets {
        match state.registered_user(key) {
            Some(user) => online.push(user.prefix()),
            None => offline.push(shown.clone()),
        }
    }
    // Split across as many lines as fit the 512-byte wire limit: a client can
    // monitor up to MONITOR_LIMIT nicks, and a single line of that many full
    // `nick!user@host` prefixes would be discarded whole by the client's
    // framing, so it would never learn those nicks are online.
    state.numeric_list(conn, RPL_MONONLINE, &[], &online, ',');
    state.numeric_list(conn, RPL_MONOFFLINE, &[], &offline, ',');
}

pub(super) fn cmd_monitor(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&sub) = p.first() else {
        state.err_needmoreparams(conn, "MONITOR");
        return;
    };
    match sub {
        "+" => {
            let Some(&list) = p.get(1) else {
                state.err_needmoreparams(conn, "MONITOR");
                return;
            };
            let mut added = Vec::new();
            let mut rejected = Vec::new();
            for nick in list.split(',').filter(|n| !n.is_empty()) {
                let key = state.nick_key(nick);
                if state.sessions[&conn].monitoring.contains_key(&key) {
                    continue;
                }
                if state.sessions[&conn].monitoring.len() >= MONITOR_LIMIT {
                    // At the cap: collect every over-limit nick rather than
                    // returning after the first, so the rest of the batch isn't
                    // silently dropped.
                    rejected.push(nick.to_string());
                    continue;
                }
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .monitoring
                    .insert(key.clone(), nick.to_string());
                state.monitors.watch(key.clone(), conn);
                added.push((key, nick.to_string()));
            }
            if !rejected.is_empty() {
                // The rejected targets echo the client's own list, which is
                // bounded only by the input frame — clipped so the refusal is
                // never itself discarded for length.
                let shown = rejected.join(",");
                state.numeric(
                    conn,
                    ERR_MONLISTFULL,
                    &[
                        &MONITOR_LIMIT.to_string(),
                        crate::core::handler::clip_echo(&shown),
                    ],
                    Some("Monitor list is full."),
                );
            }
            // The spec requires an online/offline reply for every added target.
            monitor_status(state, conn, &added);
        }
        "-" => {
            let Some(&list) = p.get(1) else {
                state.err_needmoreparams(conn, "MONITOR");
                return;
            };
            for nick in list.split(',').filter(|n| !n.is_empty()) {
                let key = state.nick_key(nick);
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .monitoring
                    .remove(&key);
                state.monitors.unwatch(&key, conn);
            }
        }
        "C" | "c" => {
            let keys: Vec<_> = state.sessions[&conn].monitoring.keys().cloned().collect();
            for key in keys {
                state.monitors.unwatch(&key, conn);
            }
            state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .monitoring
                .clear();
        }
        "L" | "l" => {
            let shown: Vec<String> = state.sessions[&conn].monitoring.values().cloned().collect();
            state.numeric_list(conn, RPL_MONLIST, &[], &shown, ',');
            state.numeric(conn, RPL_ENDOFMONLIST, &[], Some("End of MONITOR list"));
        }
        "S" | "s" => {
            let targets: Vec<_> = state.sessions[&conn]
                .monitoring
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            monitor_status(state, conn, &targets);
        }
        other => {
            // The command is the one middle parameter; the subcommand the
            // client sent rides the text, so the reply keeps 421's shape.
            state.numeric(
                conn,
                ERR_UNKNOWNCOMMAND,
                &["MONITOR"],
                Some(&format!("Unknown MONITOR subcommand {}", clip_echo(other))),
            );
        }
    }
}
