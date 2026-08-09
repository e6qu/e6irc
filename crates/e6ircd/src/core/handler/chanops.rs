//! KICK, INVITE, AWAY, LIST and USERHOST.

use super::*;

// ---- KICK / INVITE / AWAY / LIST / USERHOST -----------------------------

pub(super) fn cmd_kick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&channels_param), Some(&users_param)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "KICK");
        return;
    };
    let reason = p.get(2).copied();
    let channels: Vec<&str> = channels_param
        .split(',')
        .filter(|c| !c.is_empty())
        .collect();
    let users: Vec<&str> = users_param.split(',').filter(|u| !u.is_empty()).collect();
    if channels.is_empty() || users.is_empty() {
        state.err_needmoreparams(conn, "KICK");
        return;
    }
    // Pair channels with users per the RFC2812/Modern KICK grammar: one channel
    // kicks each listed user from it (`KICK #c a,b`); equal-length lists pair
    // positionally (`KICK #a,#b u,v` — u from #a, v from #b). Any other
    // multi-channel shape (unequal, non-1 counts) is malformed and refused loudly
    // rather than guessing. Each removal is one KICK line to clients, never a
    // multi-target one (Modern: the server MUST NOT send those).
    let pairs: Vec<(&str, &str)> = if channels.len() == 1 {
        users.iter().map(|&u| (channels[0], u)).collect()
    } else if channels.len() == users.len() {
        channels
            .iter()
            .copied()
            .zip(users.iter().copied())
            .collect()
    } else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["KICK"],
            Some("Channel and user lists must be one channel or of equal length"),
        );
        return;
    };
    let actor = state.channel_actor(conn);
    // Dedup identical (channel, user) pairs; bound the total number of kicks by
    // TARGMAX (the advertised per-KICK target cap), like PRIVMSG's target list.
    let mut seen = std::collections::HashSet::new();
    let mut kicked = 0usize;
    for (channel, who) in pairs {
        if !seen.insert((state.casemap.casefold(channel), state.casemap.casefold(who))) {
            continue;
        }
        if kicked >= TARGMAX {
            state.numeric(
                conn,
                ERR_TOOMANYTARGETS,
                &[who],
                Some("Too many targets; not kicked"),
            );
            break;
        }
        kicked += 1;
        let owner = state.channel_owner(channel);
        let label = if state.owns_channel(&owner) {
            state
                .capture
                .as_ref()
                .and_then(|capture| capture.label.clone())
        } else {
            state.defer_channel_reply(conn)
        };
        let kick = crate::core::state::ChannelKick::new(
            owner,
            actor.clone(),
            channel.to_string(),
            who.to_string(),
            reason.map(str::to_string),
            label.clone(),
        );
        if state.owns_channel(kick.owner()) {
            let result = kick_on_owner(state, kick);
            emit_kick_result_now(state, conn, result);
        } else {
            state.route_kick(kick);
        }
    }
}

/// Resolve `channel`, verify the caller is an opped member of it, and remove
/// `who`. Each error (unknown channel, not on channel, not an operator) is
/// answered with its own numeric, so one bad pair in a multi-target KICK does not
/// stop the others.
pub(super) fn kick_on_owner(
    state: &mut ServerState,
    kick: crate::core::state::ChannelKick,
) -> crate::core::state::ChannelKickResult {
    let (owner, actor, channel, who, reason) = kick.into_parts();
    let conn = actor.recipient.conn();
    let key = state.chan_key(&channel);
    assert_eq!(owner.key(), &key, "KICK owner does not match target");
    let Some(chan) = state.channels.get(&key) else {
        return crate::core::state::ChannelKickResult::NoSuchChannel { target: channel };
    };
    let display = chan.name.clone();
    if !chan.is_member(conn) {
        return crate::core::state::ChannelKickResult::NotOnChannel { target: channel };
    }
    if !chan.member(conn).is_some_and(|member| member.op) {
        return crate::core::state::ChannelKickResult::NotOperator { target: channel };
    }
    let Some((victim, recipient, identity)) =
        state.channels[&key].member_named(state.casemap, &who)
    else {
        return crate::core::state::ChannelKickResult::UserNotInChannel {
            victim: who,
            channel: display,
        };
    };
    let victim_nick = identity.nick.clone();
    let line = match reason.as_deref() {
        Some(reason) => {
            // KICKLEN bounds the reason itself; the relayed line also carries
            // the kicker's prefix, so fit against the actual head too.
            let head = format!(":{} KICK {display} {victim_nick} :", actor.identity.prefix);
            let reason = crate::core::handler::fit_trailing(&head, truncate_chars(reason, KICKLEN));
            format!("{head}{reason}")
        }
        None => format!(
            ":{} KICK {display} {victim_nick} :{}",
            actor.identity.prefix, actor.identity.nick
        ),
    };
    state.broadcast_channel(&key, &line, None);
    let chan = state.channels.get_mut(&key).expect("checked");
    chan.remove_member(victim);
    let empty = !chan.has_members();
    if empty {
        state.remove_channel(&key);
    }
    let owner = recipient.owner();
    if state.owns_session(owner) {
        state.remove_session_channel(victim, &key);
    } else {
        state.route_session_channel_removed(owner, key);
    }
    crate::core::state::ChannelKickResult::Kicked
}

pub(super) fn emit_kick_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelKickResult,
    label: Option<String>,
) {
    state.emit_deferred_labeled(conn, label, |state| {
        emit_kick_result_now(state, conn, result)
    });
}

fn emit_kick_result_now(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelKickResult,
) {
    match result {
        crate::core::state::ChannelKickResult::Kicked => {}
        crate::core::state::ChannelKickResult::NoSuchChannel { target } => {
            state.err_nosuchchannel(conn, clip_echo(&target))
        }
        crate::core::state::ChannelKickResult::NotOnChannel { target } => {
            state.err_notonchannel(conn, &target)
        }
        crate::core::state::ChannelKickResult::NotOperator { target } => state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[&target],
            Some("You're not a channel operator"),
        ),
        crate::core::state::ChannelKickResult::UserNotInChannel { victim, channel } => state
            .numeric(
                conn,
                ERR_USERNOTINCHANNEL,
                &[&victim, &channel],
                Some("They aren't on that channel"),
            ),
    }
}

pub(super) fn cmd_invite(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&who), Some(&target)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "INVITE");
        return;
    };
    let Some(invitee) = state.registered_nick_owner(&state.nick_key(who)) else {
        state.err_nosuchnick(conn, clip_echo(who));
        return;
    };
    let owner = state.channel_owner(target);
    let label = state.channel_reply_label(conn, &owner);
    let command = crate::core::state::ChannelCommand::new(
        owner,
        state.channel_actor(conn),
        target.into(),
        crate::core::state::ChannelCommandOperation::Invite(
            crate::core::state::ChannelInvitee::new(invitee, who.into()),
        ),
        label,
    );
    if state.owns_channel(command.owner()) {
        let result = invite_on_owner(state, command);
        emit_invite_result_now(state, conn, result);
    } else {
        state.route_channel_command(command);
    }
}

pub(super) fn invite_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> crate::core::state::ChannelInviteResult {
    let (owner, actor, target, operation) = command.into_parts();
    let crate::core::state::ChannelCommandOperation::Invite(invitee) = operation else {
        unreachable!("INVITE command operation");
    };
    let key = state.chan_key(&target);
    assert_eq!(owner.key(), &key, "INVITE owner does not match target");
    let Some(chan) = state.channels.get(&key) else {
        return crate::core::state::ChannelInviteResult::NoSuchChannel { target };
    };
    let display = chan.name.clone();
    if !chan.is_member(actor.recipient.conn()) {
        return crate::core::state::ChannelInviteResult::NotOnChannel { target };
    }
    if chan.modes.invite_only && !chan.member(actor.recipient.conn()).is_some_and(|m| m.op) {
        return crate::core::state::ChannelInviteResult::NotOperator { target };
    }
    if chan.is_member(invitee.owner().conn()) {
        return crate::core::state::ChannelInviteResult::UserOnChannel {
            invitee: invitee.requested_nick().into(),
            channel: display,
        };
    }
    let recipients: Vec<_> = chan
        .recipients()
        .iter()
        .copied()
        .filter(|recipient| {
            recipient.conn() != actor.recipient.conn()
                && recipient.conn() != invitee.owner().conn()
                && recipient.caps().invite_notify
        })
        .collect();
    let invited = &mut state.channels.get_mut(&key).expect("checked").invited;
    while invited.len() >= INVITE_LIMIT && !invited.contains(&invitee.owner().conn()) {
        let victim = *invited.iter().next().expect("non-empty at invite cap");
        invited.remove(&victim);
    }
    invited.insert(invitee.owner().conn());
    for recipient in recipients {
        let body = format!(
            ":{} INVITE {} :{display}",
            actor.identity.prefix,
            invitee.requested_nick()
        );
        let line = invite_tags(state, recipient, &actor.account, &body);
        state.send_recipient_uncaptured(recipient, bytes::Bytes::from(format!("{line}\r\n")));
    }
    let event = crate::core::state::ChannelSessionEvent::Invitation {
        inviter_prefix: actor.identity.prefix,
        inviter_account: actor.account,
        channel: display.clone(),
    };
    if state.owns_session(invitee.owner()) {
        emit_invitation(state, invitee.owner().conn(), event);
    } else {
        state.route_channel_session_event(invitee.owner(), event);
    }
    crate::core::state::ChannelInviteResult::Invited {
        invitee: invitee.requested_nick().into(),
        channel: display,
    }
}

pub(super) fn invite_tags(
    state: &ServerState,
    recipient: crate::core::state::Recipient,
    account: &Option<String>,
    body: &str,
) -> String {
    let mut tags = Vec::new();
    if recipient.caps().server_time {
        tags.push(format!("time={}", state.time_tag()));
    }
    if recipient.caps().account_tag
        && let Some(account) = account
    {
        tags.push(format!(
            "account={}",
            e6irc_proto::message::escape_tag_value(account)
        ));
    }
    if tags.is_empty() {
        body.into()
    } else {
        format!("@{} {body}", tags.join(";"))
    }
}

pub(super) fn emit_invitation(
    state: &mut ServerState,
    conn: ConnId,
    event: crate::core::state::ChannelSessionEvent,
) {
    let crate::core::state::ChannelSessionEvent::Invitation {
        inviter_prefix,
        inviter_account,
        channel,
    } = event;
    let nick = state.sessions[&conn].nick().unwrap_or("*");
    let body = format!(":{inviter_prefix} INVITE {nick} :{channel}");
    let recipient = state.local_recipient(conn);
    let line = invite_tags(state, recipient, &inviter_account, &body);
    state.send(conn, &line);
}

pub(super) fn emit_invite_result_now(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelInviteResult,
) {
    match result {
        crate::core::state::ChannelInviteResult::Invited { invitee, channel } => {
            state.numeric(conn, RPL_INVITING, &[&invitee, &channel], None)
        }
        crate::core::state::ChannelInviteResult::NoSuchChannel { target } => {
            state.err_nosuchchannel(conn, clip_echo(&target))
        }
        crate::core::state::ChannelInviteResult::NotOnChannel { target } => {
            state.err_notonchannel(conn, &target)
        }
        crate::core::state::ChannelInviteResult::NotOperator { target } => state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[&target],
            Some("You're not a channel operator"),
        ),
        crate::core::state::ChannelInviteResult::UserOnChannel { invitee, channel } => state
            .numeric(
                conn,
                ERR_USERONCHANNEL,
                &[&invitee, &channel],
                Some("is already on channel"),
            ),
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
    let session = state.sessions.get_mut(&conn).expect("checked");
    // Announce only a real transition (state or message): re-declaring the
    // identical away state is a no-op, and broadcasting it would hand every
    // client an unmetered away-notify spam vector aimed at its channel peers —
    // the same "don't invent phantom transitions" rule the MODE no-op
    // suppression enforces. The numeric to self stays unconditional (the
    // client asked; it always gets its answer).
    let changed = session.away != message;
    session.away = message;
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
    if !changed {
        return;
    }
    notify_event(state, conn, &notify, |c| c.away_notify, false);
}

pub(super) fn cmd_list(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    state.numeric(conn, RPL_LISTSTART, &["Channel"], Some("Users  Name"));
    let targets = p
        .first()
        .filter(|target| !target.is_empty())
        .map(|targets| {
            targets
                .split(',')
                .filter(|target| !target.is_empty())
                .map(str::to_string)
                .collect()
        });
    let label = state.defer_channel_reply(conn);
    let request = state.start_channel_list(conn, label, targets);
    state.route_channel_list(request);
}

pub(crate) fn channel_list(
    state: &mut ServerState,
    request: crate::core::state::ChannelListRequest,
) {
    let conn = request.actor().recipient.conn();
    let rows = state
        .channels
        .iter()
        .filter(|(key, _)| {
            request
                .targets()
                .is_none_or(|targets| targets.contains(key))
        })
        .map(|(_, channel)| channel)
        .filter(|channel| channel.hidden_from(conn).is_none())
        .map(|channel| crate::core::state::ChannelListRow {
            name: channel.name.clone(),
            members: channel.member_count(),
            topic: channel
                .topic
                .as_ref()
                .map(|topic| topic.text.clone())
                .unwrap_or_default(),
        })
        .collect();
    state.route_channel_list_result(crate::core::state::ChannelListResult {
        id: request.id(),
        session: request.session(),
        rows,
    });
}

pub(crate) fn channel_list_result(
    state: &mut ServerState,
    result: crate::core::state::ChannelListResult,
) {
    let session = result.session;
    let Some((label, prefix, mut rows)) = state.take_channel_list(result) else {
        return;
    };
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    state.emit_deferred_labeled(session.conn(), label, |state| {
        if !prefix.is_empty() {
            state
                .capture
                .as_mut()
                .expect("labeled LIST capture exists")
                .lines
                .extend(prefix);
        }
        for row in rows {
            state.numeric(
                session.conn(),
                RPL_LIST,
                &[&row.name, &row.members.to_string()],
                Some(&row.topic),
            );
        }
        state.numeric(session.conn(), RPL_LISTEND, &[], Some("End of /LIST"));
    });
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
                s.nick().expect("registered"),
                oper_marker,
                away_marker,
                s.user().expect("registered"),
                s.host,
            ));
        }
    }
    entries
}

pub(super) fn cmd_userhost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.err_needmoreparams(conn, "USERHOST");
        return;
    }
    let entries = userhost_entries(state, p);
    let trailing = pack_userhost_entries(state, conn, RPL_USERHOST, &entries);
    state.numeric(conn, RPL_USERHOST, &[], Some(&trailing));
}

/// Pack USERHOST/USERIP entries into the single (unsplittable) reply's trailing,
/// dropping any that don't fit rather than letting `numeric` truncate the last
/// entry mid-token into a corrupt string.
fn pack_userhost_entries(
    state: &ServerState,
    conn: ConnId,
    code: u16,
    entries: &[String],
) -> String {
    let target = state.sessions[&conn].nick().unwrap_or("*");
    let head_len = format!(
        ":{} {} {} :",
        state.config.server_name,
        e6irc_proto::numerics::code_str(code),
        target,
    )
    .len();
    crate::core::handler::pack_trailing_list(entries, head_len)
}

pub(super) fn cmd_userip(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.err_needmoreparams(conn, "USERIP");
        return;
    }
    let entries = userhost_entries(state, p);
    let trailing = pack_userhost_entries(state, conn, RPL_USERIP, &entries);
    state.numeric(conn, RPL_USERIP, &[], Some(&trailing));
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
        state.err_needmoreparams(conn, "STATS");
        return;
    };
    // Only the STATS letter's first char is significant. Take it on a char
    // boundary: a byte slice `&letter[..1]` panics when the argument's first
    // character is multi-byte (e.g. `STATS é`), and since one worker serves
    // every connection that panic is an unauthenticated remote DoS.
    let letter = letter.chars().next().map(String::from).unwrap_or_default();
    if letter == "u" {
        // The clock is milliseconds; STATS u reports whole seconds.
        let uptime = (state.config.clock)()
            .saturating_sub(state.started_at)
            .as_secs();
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
        &[&letter],
        Some("End of /STATS report"),
    );
}

pub(super) fn cmd_knock(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.err_needmoreparams(conn, "KNOCK");
        return;
    };
    let owner = state.channel_owner(target);
    let label = if state.owns_channel(&owner) {
        state
            .capture
            .as_ref()
            .and_then(|capture| capture.label.clone())
    } else {
        state.defer_channel_reply(conn)
    };
    let command = crate::core::state::ChannelCommand::new(
        owner,
        state.channel_actor(conn),
        target.to_string(),
        crate::core::state::ChannelCommandOperation::Knock,
        label,
    );
    if state.owns_channel(command.owner()) {
        let result = knock_on_owner(state, command);
        emit_knock_result_now(state, conn, result);
    } else {
        state.route_channel_command(command);
    }
}

pub(super) fn knock_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> crate::core::state::ChannelKnockResult {
    let (owner, actor, target, operation) = command.into_parts();
    debug_assert!(matches!(
        operation,
        crate::core::state::ChannelCommandOperation::Knock
    ));
    let key = state.chan_key(&target);
    assert_eq!(owner.key(), &key, "KNOCK owner does not match target");
    let Some(chan) = state.channels.get(&key) else {
        return crate::core::state::ChannelKnockResult::NoSuchChannel { target };
    };
    let display = chan.name.clone();
    // A secret channel is hidden: look non-existent to a non-member.
    if chan.hidden_from(actor.recipient.conn()).is_some() {
        return crate::core::state::ChannelKnockResult::Hidden { target };
    }
    if chan.is_member(actor.recipient.conn()) {
        return crate::core::state::ChannelKnockResult::AlreadyOnChannel { display };
    }
    if !chan.modes.invite_only {
        return crate::core::state::ChannelKnockResult::ChannelOpen { display };
    }
    // A banned user cannot knock (Solanum refuses with ERR_CANNOTSENDTOCHAN):
    // otherwise +b is no barrier to spamming the channel's ops with knock
    // requests they can't act on.
    let casemap = state.casemap;
    if chan.is_banned(casemap, &actor.identity.prefix) {
        return crate::core::state::ChannelKnockResult::CannotSend { display };
    }
    // Deliver the knock to the channel's operators, then confirm to the knocker.
    let ops = chan.operator_recipients();
    for (recipient, nick) in ops {
        let line = format!(
            ":{} {} {} {} {} :has asked for an invite",
            state.config.server_name,
            e6irc_proto::numerics::code_str(RPL_KNOCK),
            nick,
            display,
            actor.identity.prefix,
        );
        state.send_timed_recipient(recipient, &line);
    }
    crate::core::state::ChannelKnockResult::KnockDelivered
}

pub(super) fn emit_knock_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelKnockResult,
    label: Option<String>,
) {
    state.emit_deferred_labeled(conn, label, |state| {
        emit_knock_result_now(state, conn, result)
    });
}

fn emit_knock_result_now(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelKnockResult,
) {
    match result {
        crate::core::state::ChannelKnockResult::KnockDelivered => state.numeric(
            conn,
            RPL_KNOCKDLVR,
            &[],
            Some("Your KNOCK has been delivered"),
        ),
        crate::core::state::ChannelKnockResult::NoSuchChannel { target }
        | crate::core::state::ChannelKnockResult::Hidden { target } => {
            state.err_nosuchchannel(conn, clip_echo(&target));
        }
        crate::core::state::ChannelKnockResult::AlreadyOnChannel { display } => state.numeric(
            conn,
            ERR_KNOCKONCHAN,
            &[&display],
            Some("You are on that channel"),
        ),
        crate::core::state::ChannelKnockResult::ChannelOpen { display } => {
            state.numeric(conn, ERR_CHANOPEN, &[&display], Some("Channel is open"))
        }
        crate::core::state::ChannelKnockResult::CannotSend { display } => state.numeric(
            conn,
            ERR_CANNOTSENDTOCHAN,
            &[&display],
            Some("Cannot knock on channel (+b)"),
        ),
    }
}
