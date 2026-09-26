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
                &[clip_echo(who)],
                Some("Too many targets; not kicked"),
            );
            break;
        }
        kicked += 1;
        let owner = state.channel_owner(channel);
        let label = state.channel_reply_label(conn, &owner);
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
    if let Some(proof) = chan.hidden_from(conn) {
        return crate::core::state::ChannelKickResult::Hidden {
            target: channel,
            proof,
        };
    }
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
    let line = actor.line((state.config.clock)(), line);
    // The kicker's copy is its command's response (see `ChannelKickResult`).
    state.broadcast_channel(&key, &line, Some(conn));
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
    crate::core::state::ChannelKickResult::Kicked { echo: line }
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
        crate::core::state::ChannelKickResult::Kicked { echo } => state.send_event(conn, &echo),
        crate::core::state::ChannelKickResult::NoSuchChannel { target } => {
            state.err_nosuchchannel(conn, &target)
        }
        crate::core::state::ChannelKickResult::Hidden { target, proof } => {
            deny_hidden(state, conn, &target, proof)
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
        crate::core::state::ChannelKickResult::UserNotInChannel { victim, channel } => {
            state.err_usernotinchannel(conn, &victim, &channel)
        }
    }
}

pub(super) fn cmd_invite(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&who), Some(&target)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "INVITE");
        return;
    };
    let Some(invitee) = state.registered_nick_owner(&state.nick_key(who)) else {
        state.err_nosuchnick(conn, who);
        return;
    };
    // +R keeps a user who is not logged in from inviting this one too
    // (Solanum's `um_regonlymsg` hooks INVITE as it hooks PRIVMSG).
    if let Some(peer) = state.registered_user(&state.nick_key(who))
        && peer.refuses_unregistered(conn, &state.sessions[&conn])
    {
        err_nonreg(state, conn, &peer.nick);
        return;
    }
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
    if let Some(proof) = chan.hidden_from(actor.recipient.conn()) {
        return crate::core::state::ChannelInviteResult::Hidden { target, proof };
    }
    let display = chan.name.clone();
    if !chan.is_member(actor.recipient.conn()) {
        return crate::core::state::ChannelInviteResult::NotOnChannel { target };
    }
    // Inviting takes channel-operator status unless the channel is `+g` (free
    // invite) — Solanum's `m_invite`, "unconditionally require ops, unless the
    // channel is +g", whether or not the channel is `+i`.
    if !chan.modes.free_invite && !chan.member(actor.recipient.conn()).is_some_and(|m| m.op) {
        return crate::core::state::ChannelInviteResult::NotOperator { target };
    }
    if chan.is_member(invitee.owner().conn()) {
        return crate::core::state::ChannelInviteResult::UserOnChannel {
            invitee: invitee.requested_nick().into(),
            channel: display,
        };
    }
    // invite-notify tells the members who could have sent the invitation
    // themselves: the operators, or everyone on a `+g` channel (Solanum sends
    // it to chanops only unless the channel is free-invite). Anyone else would
    // learn who is being let into a channel they cannot let people into.
    let free_invite = chan.modes.free_invite;
    let recipients: Vec<_> = chan
        .recipients_where(|member, modes| {
            member != actor.recipient.conn()
                && member != invitee.owner().conn()
                && (free_invite || modes.op)
        })
        .into_iter()
        .filter(|recipient| recipient.caps().invite_notify)
        .collect();
    // An invitation is a pass through `+i` and past `+l`, so one is recorded
    // only while the channel has either (Solanum stores an invite exactly when
    // it "could affect the ability to join"). One sent while the channel is
    // open is delivered but passes nothing, and `-i` (or `-l` on a channel
    // without `+i`) revokes those held (`channel_mode_by`): none can be
    // stocked to be honoured after operators later lock the channel.
    let chan = state.channels.get_mut(&key).expect("checked");
    if chan.modes.invite_only || chan.modes.limit.is_some() {
        let invited = &mut chan.invited;
        while invited.len() >= INVITE_LIMIT && !invited.contains(&invitee.owner().conn()) {
            let victim = *invited.iter().next().expect("non-empty at invite cap");
            invited.remove(&victim);
        }
        invited.insert(invitee.owner().conn());
    }
    let now = (state.config.clock)();
    let line = actor.line(
        now,
        format!(
            ":{} INVITE {} :{display}",
            actor.identity.prefix,
            invitee.requested_nick()
        ),
    );
    for recipient in recipients {
        state.send_event_recipient(recipient, &line);
    }
    let event = crate::core::state::ChannelSessionEvent::Invitation {
        inviter: actor.originator(),
        inviter_prefix: actor.identity.prefix,
        ts: now,
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

pub(super) fn emit_invitation(
    state: &mut ServerState,
    conn: ConnId,
    event: crate::core::state::ChannelSessionEvent,
) {
    let crate::core::state::ChannelSessionEvent::Invitation {
        inviter_prefix,
        inviter,
        ts,
        channel,
    } = event;
    // The invitee was online when the INVITE was accepted, but the invitation
    // may have crossed shards since, and they may have disconnected meanwhile.
    let Some(session) = state.sessions.get(&conn) else {
        return;
    };
    let nick = session.nick().unwrap_or("*");
    let line = EventLine::by(
        inviter,
        ts,
        format!(":{inviter_prefix} INVITE {nick} :{channel}"),
    );
    state.send_event(conn, &line);
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
            state.err_nosuchchannel(conn, &target)
        }
        crate::core::state::ChannelInviteResult::Hidden { target, proof } => {
            deny_hidden(state, conn, &target, proof)
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
    let notify = state.user_line(
        conn,
        match &message {
            Some(m) => fitted_line(format!(":{prefix} AWAY :"), m),
            None => format!(":{prefix} AWAY"),
        },
    );
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
    state.sync_channel_member(conn, crate::core::state::ChannelMemberChange::Identity);
    notify_event(
        state,
        conn,
        &notify,
        crate::core::state::UserEventAudience::AwayNotify,
        false,
    );
}

pub(super) fn cmd_list(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    use crate::core::list::{InvalidListParameters, ListFilter};
    // A LIST sent while another is still answering aborts that one and asks
    // nothing itself (Solanum): one connection paces at most one LIST.
    if abort_channel_list(state, conn) {
        return;
    }
    let now_secs = (state.config.clock)().as_secs();
    let filter = match ListFilter::parse(p.first().copied(), now_secs, state.casemap) {
        Ok(filter) => filter,
        Err(InvalidListParameters) => {
            state.numeric(conn, RPL_LISTSTART, &["Channel"], Some("Users  Name"));
            let notice = state.server_notice_line(conn, "Invalid parameters for /LIST");
            state.send(conn, &notice);
            state.numeric(conn, RPL_LISTEND, &[], Some("End of /LIST"));
            return;
        }
    };
    // The reply opens now, ahead of whatever the client sent after the LIST;
    // its rows follow page by page as its send queue has room, inside its
    // batch when it is labeled.
    let label = state.defer_captured_label(conn);
    let batch = open_channel_list(state, conn, label);
    state.start_channel_list(conn, batch, filter);
    pace_channel_list(state, conn);
}

/// Open `conn`'s LIST reply — inside a labeled-response batch when the LIST
/// was labeled — and return that batch.
fn open_channel_list(
    state: &mut ServerState,
    conn: ConnId,
    label: Option<String>,
) -> Option<String> {
    let batch = label.map(|label| {
        let batch = state.next_msgid();
        let open = labeled_batch_open(&state.config.server_name, &label, &batch);
        state.send_unheld(conn, bytes::Bytes::from(format!("{open}\r\n")));
        batch
    });
    let start = state.numeric_line(conn, RPL_LISTSTART, &["Channel"], Some("Users  Name"));
    send_list_line(state, conn, batch.as_deref(), start);
    batch
}

/// Answer one page request of a LIST with this shard's channels after its
/// cursor.
pub(crate) fn channel_list(
    state: &mut ServerState,
    request: crate::core::state::ChannelListRequest,
) {
    let (rows, next) = channel_list_page(state, &request);
    state.route_channel_list_result(crate::core::state::ChannelListResult {
        id: request.id(),
        session: request.session(),
        shard: request.shard(),
        rows,
        next,
    });
}

/// The rows of this shard's channels after the request's cursor, in key
/// order, that its connection may see and its conditions admit — at most its
/// limit, from at most [`LIST_PAGE_SCAN`](crate::core::list::LIST_PAGE_SCAN)
/// channels examined — and the key the next page starts after (`None`: no
/// channel is left past them).
fn channel_list_page(
    state: &ServerState,
    request: &crate::core::state::ChannelListRequest,
) -> (Vec<crate::core::state::ChannelListRow>, Option<ChanKey>) {
    use crate::core::list::{LIST_PAGE_SCAN, ListCandidate};
    let conn = request.session().conn();
    let mut rows = Vec::new();
    let mut last: Option<&ChanKey> = None;
    for (examined, (key, channel)) in state.channels.after(request.after()).enumerate() {
        if rows.len() == request.limit() || examined == LIST_PAGE_SCAN {
            return (rows, last.cloned());
        }
        last = Some(key);
        let admitted = channel.hidden_from(conn).is_none()
            && request.filter().admits(&ListCandidate {
                key,
                members: channel.member_count(),
                created_secs: channel.created_at.as_secs(),
                topic_set_secs: channel.topic.as_ref().map(|topic| topic.set_at_secs),
            });
        if admitted {
            rows.push(crate::core::state::ChannelListRow {
                key: key.clone(),
                name: channel.name.clone(),
                members: channel.member_count(),
                topic: channel
                    .topic
                    .as_ref()
                    .map(|topic| topic.text.clone())
                    .unwrap_or_default(),
            });
        }
    }
    (rows, None)
}

/// A page of `conn`'s LIST is in: send what it lets through.
pub(crate) fn channel_list_result(
    state: &mut ServerState,
    result: crate::core::state::ChannelListResult,
) {
    let conn = result.session.conn();
    if state.accept_channel_list_page(result) {
        pace_channel_list(state, conn);
    }
}

/// One line of a LIST reply, tagged into its batch if it has one. It is
/// sent past any hold: the LIST is older than whatever that waits on. Returns
/// the bytes it took in the send queue.
fn send_list_line(
    state: &mut ServerState,
    conn: ConnId,
    batch: Option<&str>,
    line: String,
) -> usize {
    let line = bytes::Bytes::from(format!("{line}\r\n"));
    let line = match batch {
        Some(batch) => inject_tag(&line, &format!("batch={batch}")),
        None => line,
    };
    let size = line.len();
    state.send_unheld(conn, line);
    size
}

/// Close a LIST reply: `RPL_LISTEND`, after a notice when it was aborted, and
/// the end of its batch.
fn finish_channel_list(
    state: &mut ServerState,
    conn: ConnId,
    batch: Option<String>,
    aborted: bool,
) {
    if aborted {
        let notice = state.server_notice_line(conn, "/LIST aborted");
        send_list_line(state, conn, batch.as_deref(), notice);
    }
    let end = state.numeric_line(conn, RPL_LISTEND, &[], Some("End of /LIST"));
    send_list_line(state, conn, batch.as_deref(), end);
    if let Some(batch) = batch {
        let close = format!(":{} BATCH -{batch}", state.config.server_name);
        state.send_unheld(conn, bytes::Bytes::from(format!("{close}\r\n")));
    }
}

/// Abort `conn`'s LIST if it has one in progress; whether it had. Its cursor
/// is dropped; a page still on its way finds no LIST to join.
fn abort_channel_list(state: &mut ServerState, conn: ConnId) -> bool {
    let Some(cursor) = state
        .sessions
        .get_mut(&conn)
        .and_then(|session| session.channel_list.take())
    else {
        return false;
    };
    finish_channel_list(state, conn, cursor.batch, true);
    true
}

/// Send `conn`'s LIST rows while its send queue is under half full, merging
/// the shards' pages in key order, and ask for the next page of every shard
/// whose rows are all out; close the reply after the last row.
pub(super) fn pace_channel_list(state: &mut ServerState, conn: ConnId) {
    use crate::core::list::NextRow;
    let Some((mut room, mut cursor)) =
        state.take_paced(conn, |session| session.channel_list.take())
    else {
        return;
    };
    while room > 0 {
        match cursor.next_row() {
            NextRow::Row(row) => {
                let line = state.numeric_line(
                    conn,
                    RPL_LIST,
                    &[&row.name, &row.members.to_string()],
                    Some(&row.topic),
                );
                let sent = send_list_line(state, conn, cursor.batch.as_deref(), line);
                room = room.saturating_sub(sent);
            }
            NextRow::Waiting => break,
            NextRow::Finished => return finish_channel_list(state, conn, cursor.batch, false),
        }
    }
    // A page is asked for only while the client is reading, and no larger
    // than the room it has made: one that is not reading holds nothing. The
    // room is in bytes; a row is at most one line, so this many rows fit.
    if let Some(limit) =
        std::num::NonZeroUsize::new(room.div_ceil(e6irc_proto::message::MAX_LINE_LEN))
    {
        for (shard, after) in cursor.pages_wanted() {
            state.route_channel_list_page(conn, &cursor, shard, after, limit);
        }
    }
    state.resume_paced(conn, |session| &mut session.channel_list, cursor);
}

/// Build the `nick[*]=<+|->user@host` entries shared by USERHOST and USERIP
/// (the daemon does no rDNS, so a session's `host` is already the peer IP —
/// the two commands produce the same entries).
pub(super) fn userhost_entries(state: &ServerState, p: &[&str]) -> Vec<String> {
    let mut entries = Vec::new();
    for &nick in p.iter().take(5) {
        let key = state.nick_key(nick);
        if let Some(user) = state.registered_user(&key) {
            let away_marker = if user.away.is_some() { "-" } else { "+" };
            // `*` after the nick marks an IRC operator (Modern RPL_USERHOST),
            // matching the oper flag WHO/WHOIS already surface.
            let oper_marker = if user.oper { "*" } else { "" };
            entries.push(format!(
                "{}{}={}{}@{}",
                user.nick, oper_marker, away_marker, user.user, user.host,
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
    // The server-ban listings are operator-only (Solanum's stats access table:
    // a refused letter is ERR_NOPRIVILEGES, and the report still terminates).
    // They show the whole reason, the operators' note after `|` included.
    let ban_kind = match letter.as_str() {
        "k" | "K" => Some(crate::core::state::BanKind::Kline),
        "d" | "D" => Some(crate::core::state::BanKind::Dline),
        "x" | "X" => Some(crate::core::state::BanKind::Xline),
        _ => None,
    };
    if let Some(kind) = ban_kind
        && super::oper::require_oper(state, conn)
    {
        stats_server_bans(state, conn, kind);
    }
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

/// One STATS line per server ban of `kind` in force, in Solanum's shapes: a
/// K-line is `216 K <host> * <user> :<reason>`, a D-line
/// `225 D <address> :<reason>`, an X-line `247 X 0 <mask> :<reason>`. A
/// temporary ban has the lowercase letter, as Solanum marks one, and its
/// reason starts with the time it has left, as ratbox and charybdis wrote it:
/// `Temporary K-Line 42 min. - <reason>`. Each mask part is spelled by
/// [`crate::sanitize::mask_middle`], so an X-line mask with spaces or an IPv6
/// address stays one readable parameter.
fn stats_server_bans(state: &mut ServerState, conn: ConnId, kind: crate::core::state::BanKind) {
    use crate::sanitize::mask_middle;
    let now_secs = (state.config.clock)().as_secs();
    let bans: Vec<(String, String, bool)> = state
        .server_bans_in_force()
        .filter(|ban| ban.kind == kind)
        .map(|ban| match ban.minutes_left(now_secs) {
            Some(left) => (
                ban.mask.as_str().to_string(),
                format!("Temporary {} {left} min. - {}", kind.label(), ban.reason),
                true,
            ),
            None => (ban.mask.as_str().to_string(), ban.reason.clone(), false),
        })
        .collect();
    for (mask, reason, temporary) in bans {
        let letter = |permanent: &'static str, temporary_letter: &'static str| {
            if temporary {
                temporary_letter
            } else {
                permanent
            }
        };
        match kind {
            crate::core::state::BanKind::Kline => {
                let (user, host) = mask.split_once('@').unwrap_or(("*", mask.as_str()));
                state.numeric(
                    conn,
                    RPL_STATSKLINE,
                    &[
                        letter("K", "k"),
                        &mask_middle(host),
                        "*",
                        &mask_middle(user),
                    ],
                    Some(&reason),
                );
            }
            crate::core::state::BanKind::Dline => {
                state.numeric(
                    conn,
                    RPL_STATSDLINE,
                    &[letter("D", "d"), &mask_middle(&mask)],
                    Some(&reason),
                );
            }
            crate::core::state::BanKind::Xline => {
                state.numeric(
                    conn,
                    RPL_STATSXLINE,
                    &[letter("X", "x"), "0", &mask_middle(&mask)],
                    Some(&reason),
                );
            }
        }
    }
}

/// How often one user may KNOCK, and how often one channel may be knocked on
/// (Solanum's `knock_delay` and `knock_delay_channel` defaults), in monotonic
/// milliseconds. Every knock pages each of the channel's operators, so without
/// both a user could page them without bound, and a crowd could per channel.
pub(super) const KNOCK_DELAY_MS: u64 = 5 * 60 * 1000;
pub(super) const KNOCK_DELAY_CHANNEL_MS: u64 = 60 * 1000;

/// Whether a knock last delivered at `last` is still inside `delay_ms` of `now`.
pub(super) fn knock_throttled(
    last: Option<e6irc_proto::time::MonoMillis>,
    now: e6irc_proto::time::MonoMillis,
    delay_ms: u64,
) -> bool {
    last.is_some_and(|last| now.saturating_sub(last).as_millis() < delay_ms)
}

pub(super) fn cmd_knock(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.err_needmoreparams(conn, "KNOCK");
        return;
    };
    // The user's own delay is the session's to know; the channel's owner
    // decides in Solanum's order (open, banned, then the delays), so it is
    // carried along rather than answered here. An operator is exempt from it.
    let session = &state.sessions[&conn];
    let user_throttled = session.oper.is_none()
        && knock_throttled(
            session.last_knock,
            (state.config.mono_clock)(),
            KNOCK_DELAY_MS,
        );
    let owner = state.channel_owner(target);
    let label = state.channel_reply_label(conn, &owner);
    let command = crate::core::state::ChannelCommand::new(
        owner,
        state.channel_actor(conn),
        target.to_string(),
        crate::core::state::ChannelCommandOperation::Knock { user_throttled },
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
    let crate::core::state::ChannelCommandOperation::Knock { user_throttled } = operation else {
        unreachable!("KNOCK command operation");
    };
    let key = state.chan_key(&target);
    assert_eq!(owner.key(), &key, "KNOCK owner does not match target");
    let Some(chan) = state.channels.get(&key) else {
        return crate::core::state::ChannelKnockResult::NoSuchChannel { target };
    };
    let display = chan.name.clone();
    // A secret channel is hidden: look non-existent to a non-member.
    if let Some(proof) = chan.hidden_from(actor.recipient.conn()) {
        return crate::core::state::ChannelKnockResult::Hidden { target, proof };
    }
    if chan.is_member(actor.recipient.conn()) {
        return crate::core::state::ChannelKnockResult::AlreadyOnChannel { display };
    }
    // A knock asks for a way in, so it is for a channel that is closed to the
    // knocker some way an operator can open: invite-only, keyed, or full
    // (Solanum's `m_knock`). Anything else is ERR_CHANOPEN.
    let full = chan
        .modes
        .limit
        .is_some_and(|limit| chan.member_count() >= limit as usize);
    if !(chan.modes.invite_only || chan.modes.key.is_some() || full) {
        return crate::core::state::ChannelKnockResult::ChannelOpen { display };
    }
    // A banned or quieted user cannot knock (Solanum refuses with
    // ERR_CANNOTSENDTOCHAN): otherwise +b/+q is no barrier to spamming the
    // channel's ops with knock requests they can't act on.
    let casemap = state.casemap;
    if chan.is_silenced(casemap, &actor.mask_subject()) {
        return crate::core::state::ChannelKnockResult::CannotSend { display };
    }
    let now = (state.config.mono_clock)();
    if user_throttled {
        return crate::core::state::ChannelKnockResult::TooManyKnocks {
            display,
            scope: "user",
        };
    }
    if knock_throttled(chan.last_knock, now, KNOCK_DELAY_CHANNEL_MS) {
        return crate::core::state::ChannelKnockResult::TooManyKnocks {
            display,
            scope: "channel",
        };
    }
    // Deliver the knock to whoever could let the knocker in — every member of
    // a `+g` channel, else its operators (Solanum's `m_knock`) — then confirm
    // to the knocker. Solanum's RPL_KNOCK names the channel where the
    // recipient's nick would go, so one line serves every recipient.
    let free_invite = chan.modes.free_invite;
    let recipients = chan.recipients_where(|_, modes| free_invite || modes.op);
    state
        .channels
        .get_mut(&key)
        .expect("checked above")
        .last_knock = Some(now);
    let line = state.server_line(format!(
        ":{} {} {display} {display} {} :has asked for an invite.",
        state.config.server_name,
        e6irc_proto::numerics::code_str(RPL_KNOCK),
        actor.identity.prefix,
    ));
    for recipient in recipients {
        state.send_event_recipient(recipient, &line);
    }
    crate::core::state::ChannelKnockResult::KnockDelivered { display }
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
        crate::core::state::ChannelKnockResult::KnockDelivered { display } => {
            // The knocker's delay starts with a knock that was delivered.
            let now = (state.config.mono_clock)();
            if let Some(session) = state.sessions.get_mut(&conn) {
                session.last_knock = Some(now);
            }
            state.numeric(
                conn,
                RPL_KNOCKDLVR,
                &[&display],
                Some("Your KNOCK has been delivered"),
            );
        }
        crate::core::state::ChannelKnockResult::TooManyKnocks { display, scope } => state.numeric(
            conn,
            ERR_TOOMANYKNOCK,
            &[&display],
            Some(&format!("Too many KNOCKs ({scope}).")),
        ),
        crate::core::state::ChannelKnockResult::NoSuchChannel { target } => {
            state.err_nosuchchannel(conn, &target);
        }
        crate::core::state::ChannelKnockResult::Hidden { target, proof } => {
            deny_hidden(state, conn, &target, proof);
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
            Some("Cannot knock on channel (+b/+q)"),
        ),
    }
}
