//! KICK, INVITE, AWAY, LIST and USERHOST.

use super::*;

// ---- KICK / INVITE / AWAY / LIST / USERHOST -----------------------------

pub(super) fn cmd_kick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&target), Some(&who)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["KICK"],
            Some("Not enough parameters"),
        );
        return;
    };
    let key = state.chan_key(target);
    let Some(chan) = state.channels.get(&key) else {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    };
    let display = chan.name.clone();
    if !chan.members.contains_key(&conn) {
        state.numeric(
            conn,
            ERR_NOTONCHANNEL,
            &[target],
            Some("You're not on that channel"),
        );
        return;
    }
    if !chan.members[&conn].op {
        state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[target],
            Some("You're not a channel operator"),
        );
        return;
    }
    let who_key = state.nick_key(who);
    let victim = state.nicks.get(&who_key).copied();
    let victim_on = victim.is_some_and(|v| state.channels[&key].members.contains_key(&v));
    let Some(victim) = victim.filter(|_| victim_on) else {
        state.numeric(
            conn,
            ERR_USERNOTINCHANNEL,
            &[who, &display],
            Some("They aren't on that channel"),
        );
        return;
    };
    let victim_nick = state.sessions[&victim].nick.clone().expect("registered");
    let prefix = state.sessions[&conn].prefix();
    let kicker_nick = state.sessions[&conn].nick.clone().expect("registered");
    let line = match p.get(2) {
        Some(reason) => {
            // KICKLEN bounds the reason itself; the relayed line also carries
            // the kicker's prefix, so fit against the actual head too.
            let head = format!(":{prefix} KICK {display} {victim_nick} :");
            let reason = crate::core::handler::fit_trailing(&head, truncate_chars(reason, KICKLEN));
            format!("{head}{reason}")
        }
        None => format!(":{prefix} KICK {display} {victim_nick} :{kicker_nick}"),
    };
    state.broadcast_channel(&key, &line, None);
    let chan = state.channels.get_mut(&key).expect("checked");
    chan.members.remove(&victim);
    let empty = chan.members.is_empty();
    if empty {
        state.remove_channel(&key);
    }
    state
        .sessions
        .get_mut(&victim)
        .expect("member")
        .channels
        .remove(&key);
}

pub(super) fn cmd_invite(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&who), Some(&target)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["INVITE"],
            Some("Not enough parameters"),
        );
        return;
    };
    let key = state.chan_key(target);
    let Some(chan) = state.channels.get(&key) else {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    };
    let display = chan.name.clone();
    let Some(member) = chan.members.get(&conn) else {
        state.numeric(
            conn,
            ERR_NOTONCHANNEL,
            &[target],
            Some("You're not on that channel"),
        );
        return;
    };
    if chan.modes.invite_only && !member.op {
        state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[target],
            Some("You're not a channel operator"),
        );
        return;
    }
    let who_key = state.nick_key(who);
    let Some(invitee) = state.registered_peer(&who_key) else {
        state.numeric(conn, ERR_NOSUCHNICK, &[who], Some("No such nick/channel"));
        return;
    };
    if state.channels[&key].members.contains_key(&invitee) {
        state.numeric(
            conn,
            ERR_USERONCHANNEL,
            &[who, &display],
            Some("is already on channel"),
        );
        return;
    }
    let invitee_nick = state.sessions[&invitee].nick.clone().expect("registered");
    // Bound the invitee's pending-invite set — INVITE would otherwise grow it
    // without limit (invites to since-destroyed channels linger). Drop stale
    // entries first; if still at the cap, evict an arbitrary old invite so the
    // set stays bounded while the new one still lands (invites are low-value
    // and the invitee can be re-invited).
    if state.sessions[&invitee].invited.len() >= INVITE_LIMIT {
        let stale: Vec<ChanKey> = state.sessions[&invitee]
            .invited
            .iter()
            .filter(|k| !state.channels.contains_key(*k))
            .cloned()
            .collect();
        let invited = &mut state.sessions.get_mut(&invitee).expect("checked").invited;
        for k in &stale {
            invited.remove(k);
        }
        while invited.len() >= INVITE_LIMIT {
            let Some(victim) = invited.iter().next().cloned() else {
                break;
            };
            invited.remove(&victim);
        }
    }
    state
        .sessions
        .get_mut(&invitee)
        .expect("checked")
        .invited
        .insert(key.clone());
    state.numeric(conn, RPL_INVITING, &[&invitee_nick, &display], None);
    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} INVITE {invitee_nick} :{display}");
    state.send_timed(invitee, &line);
    // invite-notify: other members with the cap see the invite too.
    let watchers: Vec<ConnId> = state.channels[&key]
        .members
        .keys()
        .copied()
        .filter(|c| *c != conn && *c != invitee)
        .collect();
    for watcher in watchers {
        if state
            .sessions
            .get(&watcher)
            .is_some_and(|s| s.caps.invite_notify)
        {
            state.send_timed(watcher, &line);
        }
    }
}

pub(super) fn cmd_away(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let message = p
        .first()
        .filter(|m| !m.is_empty())
        .map(|m| truncate_chars(m, AWAYLEN).to_string());
    let prefix = state.sessions[&conn].prefix();
    let notify = match &message {
        Some(m) => format!(":{prefix} AWAY :{m}"),
        None => format!(":{prefix} AWAY"),
    };
    let is_away = message.is_some();
    state.sessions.get_mut(&conn).expect("checked").away = message;
    if is_away {
        state.numeric(
            conn,
            RPL_NOWAWAY,
            &[],
            Some("You have been marked as being away"),
        );
    } else {
        state.numeric(
            conn,
            RPL_UNAWAY,
            &[],
            Some("You are no longer marked as being away"),
        );
    }
    for peer in state.channel_peers(conn) {
        if state
            .sessions
            .get(&peer)
            .is_some_and(|s| s.caps.away_notify)
        {
            state.send_timed(peer, &notify);
        }
    }
}

pub(super) fn cmd_list(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    // A non-empty first argument is a comma-separated channel list; when
    // present LIST reports only those channels (Modern IRC `LIST <channels>`)
    // instead of enumerating every channel.
    let filter: Option<std::collections::HashSet<ChanKey>> =
        p.first().filter(|s| !s.is_empty()).map(|s| {
            s.split(',')
                .filter(|t| !t.is_empty())
                .map(|t| state.chan_key(t))
                .collect()
        });
    state.numeric(conn, RPL_LISTSTART, &["Channel"], Some("Users  Name"));
    let rows: Vec<(String, usize, String)> = state
        .channels
        .iter()
        .filter(|(k, _)| match &filter {
            Some(f) => f.contains(*k),
            None => true,
        })
        .map(|(_, c)| c)
        .filter(|c| !c.modes.secret || c.members.contains_key(&conn))
        .map(|c| {
            (
                c.name.clone(),
                c.members.len(),
                c.topic.as_ref().map(|t| t.text.clone()).unwrap_or_default(),
            )
        })
        .collect();
    for (name, count, topic) in rows {
        state.numeric(conn, RPL_LIST, &[&name, &count.to_string()], Some(&topic));
    }
    state.numeric(conn, RPL_LISTEND, &[], Some("End of /LIST"));
}

/// Build the `nick[*]=<+|->user@host` entries shared by USERHOST and USERIP
/// (the daemon does no rDNS, so a session's `host` is already the peer IP —
/// the two commands produce the same entries).
pub(super) fn userhost_entries(state: &ServerState, p: &[&str]) -> Vec<String> {
    let mut entries = Vec::new();
    for &nick in p.iter().take(5) {
        let key = state.nick_key(nick);
        if let Some(peer) = state.registered_peer(&key) {
            let s = &state.sessions[&peer];
            let away_marker = if s.away.is_some() { "-" } else { "+" };
            // `*` after the nick marks an IRC operator (Modern RPL_USERHOST),
            // matching the oper flag WHO/WHOIS already surface.
            let oper_marker = if s.oper { "*" } else { "" };
            entries.push(format!(
                "{}{}={}{}@{}",
                s.nick.as_deref().expect("registered"),
                oper_marker,
                away_marker,
                s.user.as_deref().expect("registered"),
                s.host,
            ));
        }
    }
    entries
}

pub(super) fn cmd_userhost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["USERHOST"],
            Some("Not enough parameters"),
        );
        return;
    }
    let entries = userhost_entries(state, p);
    state.numeric(conn, RPL_USERHOST, &[], Some(&entries.join(" ")));
}

pub(super) fn cmd_userip(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["USERIP"],
            Some("Not enough parameters"),
        );
        return;
    }
    let entries = userhost_entries(state, p);
    state.numeric(conn, RPL_USERIP, &[], Some(&entries.join(" ")));
}

pub(super) fn cmd_links(state: &mut ServerState, conn: ConnId) {
    // A single server links only to itself, at hop 0.
    let server = state.config.server_name.clone();
    // `<hopcount> <server info>`: the server's own description, not the
    // network's name — this server is the only link it knows about.
    let info = state.config.description.clone();
    state.numeric(
        conn,
        RPL_LINKS,
        &[&server, &server],
        Some(&format!("0 {info}")),
    );
    state.numeric(conn, RPL_ENDOFLINKS, &["*"], Some("End of /LINKS list"));
}

pub(super) fn cmd_stats(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&letter) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["STATS"],
            Some("Not enough parameters"),
        );
        return;
    };
    // Only the STATS letter's first char is significant.
    let letter = &letter[..letter.len().min(1)];
    if letter == "u" {
        // The clock is milliseconds; STATS u reports whole seconds.
        let uptime = (state.config.clock)().saturating_sub(state.started_at) / 1000;
        let (days, rem) = (uptime / 86400, uptime % 86400);
        let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        state.numeric(
            conn,
            RPL_STATSUPTIME,
            &[],
            Some(&format!("Server Up {days} days {h:02}:{m:02}:{s:02}")),
        );
    }
    // Every STATS query is terminated with the end-of-report numeric; a letter
    // with no data (or one we don't expose) yields just this terminator, which
    // is the conforming "empty report" rather than a silent drop.
    state.numeric(
        conn,
        RPL_ENDOFSTATS,
        &[letter],
        Some("End of /STATS report"),
    );
}

pub(super) fn cmd_knock(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["KNOCK"],
            Some("Not enough parameters"),
        );
        return;
    };
    let key = state.chan_key(target);
    let Some(chan) = state.channels.get(&key) else {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    };
    let display = chan.name.clone();
    // A secret channel is hidden: look non-existent to a non-member.
    if chan.modes.secret && !chan.members.contains_key(&conn) {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    }
    if chan.members.contains_key(&conn) {
        state.numeric(
            conn,
            ERR_KNOCKONCHAN,
            &[&display],
            Some("You are on that channel"),
        );
        return;
    }
    if !chan.modes.invite_only {
        state.numeric(conn, ERR_CHANOPEN, &[&display], Some("Channel is open"));
        return;
    }
    // Deliver the knock to the channel's operators, then confirm to the knocker.
    let prefix = state.sessions[&conn].prefix();
    let ops: Vec<ConnId> = chan
        .members
        .iter()
        .filter(|(_, m)| m.op)
        .map(|(c, _)| *c)
        .collect();
    for op in ops {
        state.numeric(
            op,
            RPL_KNOCK,
            &[&display, &prefix],
            Some("has asked for an invite"),
        );
    }
    state.numeric(
        conn,
        RPL_KNOCKDLVR,
        &[&display],
        Some("Your KNOCK has been delivered"),
    );
}
