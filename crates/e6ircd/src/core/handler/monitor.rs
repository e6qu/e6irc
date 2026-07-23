//! MONITOR: presence notification for watched nicks.

use super::*;

// ---- MONITOR ------------------------------------------------------------

pub(super) const MONITOR_LIMIT: usize = 100;

/// Notify everyone monitoring `nick` that it is now (`online`) or no
/// longer (`offline`) present. `subject` is the full prefix when
/// online, the bare nick when offline (per the monitor spec).
pub(crate) fn monitor_notify(state: &mut ServerState, nick: &str, online: bool) {
    let key = state.nick_key(nick);
    let Some(watchers) = state.monitors.get(&key) else {
        return;
    };
    let watchers: Vec<ConnId> = watchers.iter().copied().collect();
    let subject = if online {
        state
            .registered_peer(&key)
            .map(|c| state.sessions[&c].prefix())
            .unwrap_or_else(|| nick.to_string())
    } else {
        nick.to_string()
    };
    let code = if online {
        RPL_MONONLINE
    } else {
        RPL_MONOFFLINE
    };
    for watcher in watchers {
        state.numeric(watcher, code, &[], Some(&subject));
    }
}

pub(super) fn monitor_status(
    state: &mut ServerState,
    conn: ConnId,
    targets: &[(crate::core::state::NickKey, String)],
) {
    let mut online = Vec::new();
    let mut offline = Vec::new();
    for (key, shown) in targets {
        match state.registered_peer(key) {
            Some(c) => online.push(state.sessions[&c].prefix()),
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
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["MONITOR"],
            Some("Not enough parameters"),
        );
        return;
    };
    match sub {
        "+" => {
            let Some(&list) = p.get(1) else {
                state.numeric(
                    conn,
                    ERR_NEEDMOREPARAMS,
                    &["MONITOR"],
                    Some("Not enough parameters"),
                );
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
                state.monitors.entry(key.clone()).or_default().insert(conn);
                added.push((key, nick.to_string()));
            }
            if !rejected.is_empty() {
                state.numeric(
                    conn,
                    ERR_MONLISTFULL,
                    &[&MONITOR_LIMIT.to_string(), &rejected.join(",")],
                    Some("Monitor list is full."),
                );
            }
            // The spec requires an online/offline reply for every added target.
            monitor_status(state, conn, &added);
        }
        "-" => {
            let Some(&list) = p.get(1) else {
                state.numeric(
                    conn,
                    ERR_NEEDMOREPARAMS,
                    &["MONITOR"],
                    Some("Not enough parameters"),
                );
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
                if let Some(watchers) = state.monitors.get_mut(&key) {
                    watchers.remove(&conn);
                    if watchers.is_empty() {
                        state.monitors.remove(&key);
                    }
                }
            }
        }
        "C" | "c" => {
            let keys: Vec<_> = state.sessions[&conn].monitoring.keys().cloned().collect();
            for key in keys {
                if let Some(watchers) = state.monitors.get_mut(&key) {
                    watchers.remove(&conn);
                    if watchers.is_empty() {
                        state.monitors.remove(&key);
                    }
                }
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
            state.numeric(
                conn,
                ERR_UNKNOWNCOMMAND,
                &[&format!("MONITOR {other}")],
                Some("Unknown command"),
            );
        }
    }
}
