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
    // An invitation is a pass through `+i` and past `+l`, so one is recorded
    // only while the channel has either (Solanum stores an invite exactly when
    // it "could affect the ability to join"). One sent while the channel is
    // open is delivered but passes nothing: it cannot be stocked to be honoured
    // after operators later lock the channel.
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
    if state.has_single_core_shard() {
        // One worker sees every channel, so the listing is this command's
        // direct reply: nothing is owed later and nothing is held behind it.
        let targets: Option<Vec<_>> = targets.map(|targets: Vec<String>| {
            targets
                .iter()
                .map(|target| state.chan_key(target))
                .collect()
        });
        let rows = visible_channel_rows(state, conn, targets.as_deref());
        emit_channel_list_rows(state, conn, rows);
        return;
    }
    let label = state.defer_channel_reply(conn);
    let request = state.start_channel_list(conn, label, targets);
    state.route_channel_list(request);
}

/// This shard's channels that `conn` may see, narrowed to `targets` if given.
fn visible_channel_rows(
    state: &ServerState,
    conn: ConnId,
    targets: Option<&[crate::core::state::ChanKey]>,
) -> Vec<crate::core::state::ChannelListRow> {
    state
        .channels
        .iter()
        .filter(|(key, _)| targets.is_none_or(|targets| targets.contains(key)))
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
        .collect()
}

pub(crate) fn channel_list(
    state: &mut ServerState,
    request: crate::core::state::ChannelListRequest,
) {
    let rows = visible_channel_rows(state, request.actor().recipient.conn(), request.targets());
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
    let Some((label, prefix, rows)) = state.take_channel_list(result) else {
        return;
    };
    state.emit_deferred_labeled(session.conn(), label, |state| {
        if !prefix.is_empty() {
            state
                .capture
                .as_mut()
                .expect("labeled LIST capture exists")
                .lines
                .extend(prefix);
        }
        emit_channel_list_rows(state, session.conn(), rows);
    });
}

fn emit_channel_list_rows(
    state: &mut ServerState,
    conn: ConnId,
    mut rows: Vec<crate::core::state::ChannelListRow>,
) {
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    for row in rows {
        state.numeric(
            conn,
            RPL_LIST,
            &[&row.name, &row.members.to_string()],
            Some(&row.topic),
        );
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

/// One STATS line per server ban of `kind`, in Solanum's shapes: a K-line is
/// `216 K <host> * <user> :<reason>`, a D-line `225 D <address> :<reason>`, an
/// X-line `247 X 0 <mask> :<reason>` (every ban here is permanent, so the
/// letter is the uppercase one and the X-line hold is 0). Each mask part is
/// spelled by [`crate::sanitize::mask_middle`], so an X-line mask with spaces
/// or an IPv6 address stays one readable parameter.
fn stats_server_bans(state: &mut ServerState, conn: ConnId, kind: crate::core::state::BanKind) {
    use crate::sanitize::mask_middle;
    let bans: Vec<(String, String)> = state
        .server_bans
        .iter()
        .filter(|ban| ban.kind == kind)
        .map(|ban| (ban.mask.as_str().to_string(), ban.reason.clone()))
        .collect();
    for (mask, reason) in bans {
        match kind {
            crate::core::state::BanKind::Kline => {
                let (user, host) = mask.split_once('@').unwrap_or(("*", mask.as_str()));
                state.numeric(
                    conn,
                    RPL_STATSKLINE,
                    &["K", &mask_middle(host), "*", &mask_middle(user)],
                    Some(&reason),
                );
            }
            crate::core::state::BanKind::Dline => {
                state.numeric(
                    conn,
                    RPL_STATSDLINE,
                    &["D", &mask_middle(&mask)],
                    Some(&reason),
                );
            }
            crate::core::state::BanKind::Xline => {
                state.numeric(
                    conn,
                    RPL_STATSXLINE,
                    &["X", "0", &mask_middle(&mask)],
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
    // Deliver the knock to the channel's operators, then confirm to the knocker.
    let ops = chan.operator_recipients();
    state
        .channels
        .get_mut(&key)
        .expect("checked above")
        .last_knock = Some(now);
    for (recipient, nick) in ops {
        let line = format!(
            ":{} {} {} {} {} :has asked for an invite",
            state.config.server_name,
            e6irc_proto::numerics::code_str(RPL_KNOCK),
            nick,
            display,
            actor.identity.prefix,
        );
        let line = state.server_line(line);
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
