//! Channel membership, topic, and modes.

use super::*;

// ---- channels -----------------------------------------------------------

/// Cap on each channel list mode (+b/+q/+e/+I). Bounds channel memory and the
/// per-message match cost; a client that hits it gets ERR_BANLISTFULL.
/// Advertised as `MAXLIST`.
pub(super) const MAXLIST: usize = 100;

/// Cap on channels a single session may be joined to. Bounds `Channel`
/// allocation driven by one connection; hitting it yields ERR_TOOMANYCHANNELS.
/// Advertised as `CHANLIMIT` (matches Libera's `#:250`).
pub(super) const MAX_CHANNELS_PER_SESSION: usize = 250;

/// Max targets accepted in one PRIVMSG/NOTICE. Advertised as `TARGMAX`.
pub(super) const TARGMAX: usize = 4;

/// Cap on stored read markers per account. Markers persist across parts, so
/// without a cap a client could seed the marker map without bound.
pub(super) const MAX_READ_MARKERS_PER_ACCOUNT: usize = 256;

/// Cap on a session's pending-invite set, bounding INVITE-driven growth.
pub(super) const INVITE_LIMIT: usize = 100;

/// Advertised (and enforced) length limits, so a client can pre-truncate and
/// an over-long value can't push the broadcast line past the 512-byte wire
/// limit. Values mirror Libera's order of magnitude.
pub(super) const TOPICLEN: usize = 390;
pub(super) const KICKLEN: usize = 390;
pub(super) const AWAYLEN: usize = 390;
/// Username cap, applied at USER and advertised as `USERLEN`. Solanum uses 10;
/// the username rides in every relayed line's source prefix, so it must be
/// bounded for any line to be fittable.
pub(super) const USERLEN: usize = 10;
/// Realname cap, applied at USER and SETNAME. Not an ISUPPORT token (none is
/// standardized), but WHOIS 311 carries it as a trailing parameter, so an
/// unbounded one overflows that reply.
pub(super) const REALLEN: usize = 150;

/// Canonicalize a channel list-mode (+b/+q/+e/+I) mask to `nick!user@host`,
/// filling missing components with `*` (Solanum's `clean_ban_mask`). Without
/// this a bare `nick` is stored verbatim and never matches `nick!user@host`,
/// so the ban is silently ineffective.
pub(super) fn normalize_ban_mask(mask: &str) -> String {
    fn star(s: &str) -> &str {
        if s.is_empty() { "*" } else { s }
    }
    // Parsed positionally, one separator at a time. Asking whether the mask
    // *contains* `!` and `@` says nothing about their order: `@!x` contains
    // both, yet has no `@` after the `!`, so splitting on the strength of the
    // `contains` answer found nothing there and panicked — reachable by any
    // user, since creating a channel makes you its operator.
    match mask.split_once('!') {
        Some((nick, rest)) => match rest.split_once('@') {
            Some((user, host)) => format!("{}!{}@{}", star(nick), star(user), star(host)),
            None => format!("{}!{}@*", star(nick), star(rest)),
        },
        None => match mask.split_once('@') {
            Some((user, host)) => format!("*!{}@{}", star(user), star(host)),
            None => format!("{}!*@*", star(mask)),
        },
    }
}

/// Truncate `s` to at most `max` bytes on a UTF-8 char boundary. The length
/// caps here (`TOPICLEN`, `KICKLEN`, `AWAYLEN`) are byte budgets, so this is
/// [`e6irc_proto::message::truncate_on_char_boundary`] under a domain name.
pub(super) fn truncate_chars(s: &str, max: usize) -> &str {
    e6irc_proto::message::truncate_on_char_boundary(s, max)
}

pub(super) fn valid_channel_name(name: &str) -> bool {
    name.starts_with('#')
        && name.len() > 1
        && name.len() <= 50
        && !name.bytes().any(|b| matches!(b, b' ' | b',' | 0x07 | b':'))
}

pub(super) fn cmd_join(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&targets) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["JOIN"],
            Some("Not enough parameters"),
        );
        return;
    };
    // Modern IRC: "JOIN 0" is a special form meaning "part every channel".
    if targets == "0" {
        let names: Vec<String> = state.sessions[&conn]
            .channels
            .iter()
            .filter_map(|k| state.channels.get(k).map(|c| c.name.clone()))
            .collect();
        if !names.is_empty() {
            let joined = names.join(",");
            cmd_part(state, conn, &[joined.as_str()]);
        }
        return;
    }
    let keys: Vec<&str> = p.get(1).map(|k| k.split(',').collect()).unwrap_or_default();
    for (i, target) in targets.split(',').filter(|t| !t.is_empty()).enumerate() {
        join_one(state, conn, target, keys.get(i).copied());
    }
}

pub(super) fn join_one(state: &mut ServerState, conn: ConnId, name: &str, join_key: Option<&str>) {
    if !valid_channel_name(name) {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[name], Some("No such channel"));
        return;
    }
    let key = state.chan_key(name);
    // Bound channels per session so one connection can't allocate unbounded
    // Channel state. A rejoin of a channel already held is exempt.
    if !state.sessions[&conn].channels.contains(&key)
        && state.sessions[&conn].channels.len() >= MAX_CHANNELS_PER_SESSION
    {
        state.numeric(
            conn,
            ERR_TOOMANYCHANNELS,
            &[name],
            Some("You have joined too many channels"),
        );
        return;
    }
    let now = (state.config.clock)();
    let user_prefix = state.sessions[&conn].prefix();
    let casemap = state.casemap;
    // A registered channel being (re)created restores its retained topic.
    let newly_created = !state.channels.contains_key(&key);
    let restored_topic = if newly_created {
        state.registered_topics.get(&key).cloned()
    } else {
        None
    };
    let chan = state
        .channels
        .entry(key.clone())
        .or_insert_with(|| Channel {
            name: name.to_string(),
            topic: restored_topic,
            members: std::collections::HashMap::new(),
            modes: crate::core::state::ChanModes {
                no_external: true,
                topic_ops_only: true,
                ..Default::default()
            },
            bans: Vec::new(),
            quiets: Vec::new(),
            ban_exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            // The clock is milliseconds; RPL_CREATIONTIME reports seconds.
            created_at_secs: now.as_secs(),
        });
    if chan.members.contains_key(&conn) {
        return; // already joined: JOIN is idempotent per Solanum
    }
    // Admission checks, Solanum order.
    let was_invited = state.sessions[&conn].invited.contains(&key);
    // A registered channel's founder is opped on join, even when not the
    // first to arrive.
    let account = state.sessions[&conn].account.clone();
    let is_founder = account
        .as_deref()
        .is_some_and(|a| state.is_founder(&key, a));
    // ChanServ access flags grant auto-op / auto-voice on join.
    let (access_op, access_voice) = account
        .as_deref()
        .map(|a| state.access_modes(&key, a))
        .unwrap_or((false, false));
    let chan = state.channels.get_mut(&key).expect("just inserted");
    if chan.modes.invite_only && !was_invited && !chan.is_invite_excepted(casemap, &user_prefix) {
        state.numeric(
            conn,
            ERR_INVITEONLYCHAN,
            &[name],
            Some("Cannot join channel (+i) - you must be invited"),
        );
        return;
    }
    if chan.is_banned(casemap, &user_prefix) {
        state.numeric(
            conn,
            ERR_BANNEDFROMCHAN,
            &[name],
            Some("Cannot join channel (+b) - you are banned"),
        );
        return;
    }
    if let Some(chan_key) = &chan.modes.key
        && !join_key.is_some_and(|k| constant_time_eq(k.as_bytes(), chan_key.as_bytes()))
    {
        // Constant-time so the key isn't recoverable by timing the compare.
        state.numeric(
            conn,
            ERR_BADCHANNELKEY,
            &[name],
            Some("Cannot join channel (+k) - bad key"),
        );
        return;
    }
    if let Some(limit) = chan.modes.limit
        && chan.members.len() >= limit as usize
    {
        state.numeric(
            conn,
            ERR_CHANNELISFULL,
            &[name],
            Some("Cannot join channel (+l) - channel is full"),
        );
        return;
    }
    let first = chan.members.is_empty();
    chan.members.insert(
        conn,
        MemberModes {
            op: first || is_founder || access_op,
            voice: access_voice,
        },
    );
    let display = chan.name.clone();

    let session = state
        .sessions
        .get_mut(&conn)
        .expect("session checked in dispatch");
    session.channels.insert(key.clone());
    session.invited.remove(&key);
    let prefix = session.prefix();

    let (account, realname) = {
        let session = &state.sessions[&conn];
        (
            session.account.clone().unwrap_or_else(|| "*".into()),
            session.realname.clone().expect("registered"),
        )
    };
    let plain_join = format!(":{prefix} JOIN {display}");
    let extended_join = format!(":{prefix} JOIN {display} {account} :{realname}");
    let joiner_away = state.sessions[&conn].away.clone();
    let members: Vec<ConnId> = state.channels[&key].members.keys().copied().collect();
    for member in members {
        let Some(session) = state.sessions.get(&member) else {
            continue;
        };
        let caps = session.caps;
        let line = if caps.extended_join {
            &extended_join
        } else {
            &plain_join
        };
        state.send_timed(member, line);
        // away-notify: an away joiner's status follows the JOIN.
        if member != conn
            && caps.away_notify
            && let Some(away) = &joiner_away
        {
            let away_line = format!(":{prefix} AWAY :{away}");
            state.send_timed(member, &away_line);
        }
    }

    // topic, if set
    if let Some(chan) = state.channels.get(&key)
        && let Some(topic) = &chan.topic
    {
        let (text, set_by, set_at) = (topic.text.clone(), topic.set_by.clone(), topic.set_at_secs);
        state.numeric(conn, RPL_TOPIC, &[&display], Some(&text));
        state.numeric(
            conn,
            RPL_TOPICWHOTIME,
            &[&display, &set_by, &set_at.to_string()],
            None,
        );
    }
    // draft/read-marker: a joining client that negotiated the cap is told the
    // channel's current marker before RPL_ENDOFNAMES.
    if state.sessions[&conn].caps.read_marker {
        send_current_markread(state, conn, &key, &display);
    }
    send_names(state, conn, &key);

    // A registered channel with a mode lock enforces it the moment it is
    // (re)created, so its locked modes survive the channel going empty.
    if newly_created {
        apply_mlock(state, &key);
    }
}

pub(super) fn cmd_part(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&targets) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["PART"],
            Some("Not enough parameters"),
        );
        return;
    };
    let reason = p.get(1).map(|r| r.to_string());
    for target in targets.split(',').filter(|t| !t.is_empty()) {
        let key = state.chan_key(target);
        let on_channel = state
            .channels
            .get(&key)
            .is_some_and(|c| c.members.contains_key(&conn));
        if !on_channel {
            state.numeric(
                conn,
                ERR_NOTONCHANNEL,
                &[target],
                Some("You're not on that channel"),
            );
            continue;
        }
        let display = state.channels[&key].name.clone();
        let prefix = state.sessions[&conn].prefix();
        // A quieted or banned member can't broadcast a PART reason (which would
        // evade the quiet), unless op/voice — same speak-gate as messages.
        let exempt = state.channels[&key]
            .members
            .get(&conn)
            .is_some_and(|m| m.op || m.voice);
        let suppress_reason = !exempt
            && (state.channels[&key].is_banned(state.casemap, &prefix)
                || state.channels[&key].is_quieted(state.casemap, &prefix));
        let line = match &reason {
            Some(r) if !suppress_reason => {
                let head = format!(":{prefix} PART {display} :");
                let r = crate::core::handler::fit_trailing(&head, r);
                format!("{head}{r}")
            }
            _ => format!(":{prefix} PART {display}"),
        };
        state.broadcast_channel(&key, &line, None);
        let chan = state.channels.get_mut(&key).expect("checked");
        chan.members.remove(&conn);
        if chan.members.is_empty() {
            state.remove_channel(&key);
        }
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .channels
            .remove(&key);
    }
}

pub(super) fn send_names(state: &mut ServerState, conn: ConnId, key: &ChanKey) {
    let Some(chan) = state.channels.get(key) else {
        return;
    };
    let display = chan.name.clone();
    // A +s (secret) channel hides its membership from non-members: they get
    // only the terminating numeric, never the member list.
    if chan.modes.secret && !chan.members.contains_key(&conn) {
        state.numeric(
            conn,
            RPL_ENDOFNAMES,
            &[&display],
            Some("End of /NAMES list"),
        );
        return;
    }
    let requester_caps = state.sessions[&conn].caps;
    let mut names: Vec<String> = chan
        .members
        .iter()
        .map(|(m, modes)| {
            let member = &state.sessions[m];
            let shown = if requester_caps.userhost_in_names {
                member.prefix()
            } else {
                member.nick.clone().expect("member is registered")
            };
            let sigil = match (modes.op, modes.voice, requester_caps.multi_prefix) {
                (true, true, true) => "@+",
                (true, _, _) => "@",
                (false, true, _) => "+",
                _ => "",
            };
            format!("{sigil}{shown}")
        })
        .collect();
    names.sort(); // deterministic order
    let symbol = if state.channels[key].modes.secret {
        "@"
    } else {
        "="
    };
    // Split the member list across as many RPL_NAMREPLY lines as needed so no
    // single 353 exceeds the 512-byte wire limit on a large channel.
    state.numeric_list(conn, RPL_NAMREPLY, &[symbol, &display], &names, ' ');
    state.numeric(
        conn,
        RPL_ENDOFNAMES,
        &[&display],
        Some("End of /NAMES list"),
    );
}

pub(super) fn cmd_names(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    match p.first() {
        Some(&targets) => {
            for target in targets.split(',').filter(|t| !t.is_empty()) {
                let key = state.chan_key(target);
                if state.channels.contains_key(&key) {
                    send_names(state, conn, &key);
                } else {
                    state.numeric(conn, RPL_ENDOFNAMES, &[target], Some("End of /NAMES list"));
                }
            }
        }
        None => state.numeric(conn, RPL_ENDOFNAMES, &["*"], Some("End of /NAMES list")),
    }
}

/// One message delivery: the payload plus its sender/tag context. Bundled
/// into a struct (rather than a row of same-typed `&str`/`bool` parameters)
/// so the fields cannot be transposed at a call site.
#[derive(Clone, Copy)]
pub(super) struct Delivery<'a> {
    pub(super) sender_account: Option<&'a str>,
    pub(super) sender_is_bot: bool,
    pub(super) msgid: &'a str,
    pub(super) client_tags: &'a str,
    pub(super) body: &'a str,
    /// Wall-clock millisecond this message was stamped with, paired with
    /// `msgid` by [`ServerState::stamp`]. Passed in rather than read from the
    /// clock here so the `time=` a client sees live is byte-identical to the
    /// one CHATHISTORY later replays.
    pub(super) ts: e6irc_proto::time::Millis,
    /// True to bypass labeled-response capture (echo/fan-out already labeled).
    pub(super) bypass_capture: bool,
}

/// Deliver to `recipients`, then echo the same message back to the sender when
/// it negotiated `echo-message`.
///
/// Both message paths — to a channel and to a user — do exactly this; the only
/// thing that differs is who receives it. Keeping the two steps together means
/// a change to how a message is delivered cannot apply to one kind of target
/// and miss the other.
pub(super) fn deliver_and_echo(
    state: &mut ServerState,
    conn: ConnId,
    recipients: &[ConnId],
    delivery: &Delivery,
) {
    deliver_message(state, recipients, delivery);
    if state.sessions[&conn].caps.echo_message {
        // The echo is the sender's own labeled response, so it is captured.
        let echo = Delivery {
            bypass_capture: false,
            ..*delivery
        };
        deliver_message(state, &[conn], &echo);
    }
}

/// Deliver a message line to recipients, applying per-recipient
/// `server-time` and `account-tag` variants.
pub(super) fn deliver_message(state: &mut ServerState, recipients: &[ConnId], d: &Delivery) {
    let time = e6irc_proto::time::server_time(d.ts);
    for &recipient in recipients {
        let Some(session) = state.sessions.get(&recipient) else {
            continue;
        };
        let caps = session.caps;
        let mut tags: Vec<String> = Vec::new();
        if caps.message_tags {
            tags.push(format!("msgid={}", d.msgid));
        }
        if caps.server_time {
            tags.push(format!("time={time}"));
        }
        if caps.account_tag
            && let Some(account) = d.sender_account
        {
            // The account name is a nick or an OIDC-sanitized name, both of which
            // can contain `\\` (a legal nick char) — a raw backslash in a tag value
            // is an escape introducer, so a client would decode `a\\b` as `ab` and
            // see a different account than the one that spoke. Escape it like any
            // tag value.
            tags.push(format!(
                "account={}",
                e6irc_proto::message::escape_tag_value(account)
            ));
        }
        if caps.message_tags && d.sender_is_bot {
            tags.push("bot".to_string());
        }
        if caps.message_tags && !d.client_tags.is_empty() {
            tags.push(d.client_tags.to_string());
        }
        let line = if tags.is_empty() {
            d.body.to_string()
        } else {
            format!("@{} {}", tags.join(";"), d.body)
        };
        let bytes = bytes::Bytes::from(format!("{line}\r\n"));
        if d.bypass_capture {
            state.send_bytes_uncaptured(recipient, bytes);
        } else {
            state.send_bytes(recipient, bytes);
        }
    }
}

// ---- topic --------------------------------------------------------------

pub(super) fn cmd_topic(state: &mut ServerState, conn: ConnId, msg: &Message, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["TOPIC"],
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

    // Query: exactly one param. Setting requires the second param —
    // distinguished from "TOPIC #c :" (clearing) by has_trailing/params.
    if p.len() == 1 && !msg.has_trailing {
        // A +s channel's topic — and its very existence — is hidden from
        // non-members, like every other query surface (NAMES/WHO/WHOIS/LIST).
        if chan.modes.secret && !chan.members.contains_key(&conn) {
            state.numeric(
                conn,
                ERR_NOTONCHANNEL,
                &[target],
                Some("You're not on that channel"),
            );
            return;
        }
        match &chan.topic {
            Some(t) => {
                let (text, set_by, set_at) = (t.text.clone(), t.set_by.clone(), t.set_at_secs);
                state.numeric(conn, RPL_TOPIC, &[&display], Some(&text));
                state.numeric(
                    conn,
                    RPL_TOPICWHOTIME,
                    &[&display, &set_by, &set_at.to_string()],
                    None,
                );
            }
            None => state.numeric(conn, RPL_NOTOPIC, &[&display], Some("No topic is set")),
        }
        return;
    }

    let member = chan.members.get(&conn);
    let Some(member) = member else {
        state.numeric(
            conn,
            ERR_NOTONCHANNEL,
            &[target],
            Some("You're not on that channel"),
        );
        return;
    };
    if chan.modes.topic_ops_only && !member.op {
        state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[target],
            Some("You're not a channel operator"),
        );
        return;
    }
    // A quieted or banned member can't set the topic (which would evade the
    // quiet by defacing the channel), unless op/voice. This is deliberately
    // only the ban/quiet part of `Channel::may_speak`, not the whole gate: +m
    // (moderated) governs messages, not topic changes, so it must NOT be folded
    // in here — a regular member of a +m, -t channel may still set the topic.
    let exempt = member.op || member.voice;
    if !exempt {
        let prefix = state.sessions[&conn].prefix();
        let blocked = {
            let chan = &state.channels[&key];
            chan.is_banned(state.casemap, &prefix) || chan.is_quieted(state.casemap, &prefix)
        };
        if blocked {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[target],
                Some("Cannot send to channel"),
            );
            return;
        }
    }
    let new_text = truncate_chars(p.get(1).copied().unwrap_or(""), TOPICLEN);
    let prefix = state.sessions[&conn].prefix();
    // TOPICLEN bounds the topic itself; the *relayed* line also carries the
    // setter's prefix, which can push it past the wire limit. Fit against the
    // broadcast head and store the same fitted text, so the broadcast, 332
    // replies and persisted copy all carry one identical topic.
    let new_text =
        crate::core::handler::fit_trailing(&format!(":{prefix} TOPIC {display} :"), new_text);
    let now = (state.config.clock)();
    let new_topic = if new_text.is_empty() {
        None
    } else {
        Some(Topic {
            text: new_text.to_string(),
            set_by: prefix.clone(),
            // The clock is milliseconds; RPL_TOPICWHOTIME reports seconds.
            set_at_secs: now.as_secs(),
        })
    };
    state.channels.get_mut(&key).expect("checked").topic = new_topic.clone();
    let line = format!(":{prefix} TOPIC {display} :{new_text}");
    state.broadcast_channel(&key, &line, None);

    // A registered channel retains its topic across an empty→recreate
    // cycle: keep the hot copy in sync and persist it — unless its
    // ChanServ KEEPTOPIC option is OFF, in which case the topic lives only
    // as long as the channel does.
    if state.is_registered(&key) && state.keeptopic(&key) {
        match &new_topic {
            Some(t) => {
                state.registered_topics.insert(key.clone(), t.clone());
            }
            None => {
                state.registered_topics.remove(&key);
            }
        }
        let request = crate::core::DbRequest::SetChannelTopic {
            channel: key.as_str().to_string(),
            topic: new_topic.map(|t| (t.text, t.set_by, t.set_at_secs)),
        };
        if state.db_tx.try_push(request).is_err() {
            eprintln!(
                "topic: db queue full or closed; retained topic for {} not persisted",
                key.as_str()
            );
        }
    }
}

// ---- MODE ---------------------------------------------------------------

pub(super) fn cmd_mode(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["MODE"],
            Some("Not enough parameters"),
        );
        return;
    };
    if target.starts_with('#') {
        channel_mode(state, conn, target, &p[1..]);
    } else {
        user_mode(state, conn, target, &p[1..]);
    }
}

/// Read a boolean channel mode by its mode char (`None` for non-boolean).
pub(super) fn chan_bool_mode(modes: &crate::core::state::ChanModes, c: char) -> Option<bool> {
    Some(match c {
        'i' => modes.invite_only,
        'm' => modes.moderated,
        'n' => modes.no_external,
        's' => modes.secret,
        't' => modes.topic_ops_only,
        'C' => modes.no_ctcp,
        _ => return None,
    })
}

/// Set a boolean channel mode by its mode char.
pub(super) fn set_chan_bool_mode(modes: &mut crate::core::state::ChanModes, c: char, v: bool) {
    match c {
        'i' => modes.invite_only = v,
        'm' => modes.moderated = v,
        'n' => modes.no_external = v,
        's' => modes.secret = v,
        't' => modes.topic_ops_only = v,
        'C' => modes.no_ctcp = v,
        _ => {}
    }
}

/// Enforce `key`'s mode lock on the live channel: change only the modes
/// that differ from the lock and broadcast the resulting MODE from ChanServ.
/// A no-op when the channel has no lock or is already compliant.
pub(super) fn apply_mlock(state: &mut ServerState, key: &ChanKey) {
    let Some(m) = state.channel_mlock.get(key).cloned() else {
        return;
    };
    let Some(chan) = state.channels.get(key) else {
        return;
    };
    let on_changes: String =
        m.on.chars()
            .filter(|&c| chan_bool_mode(&chan.modes, c) == Some(false))
            .collect();
    let off_changes: String = m
        .off
        .chars()
        .filter(|&c| chan_bool_mode(&chan.modes, c) == Some(true))
        .collect();
    if on_changes.is_empty() && off_changes.is_empty() {
        return;
    }
    let display = chan.name.clone();
    let chan = state.channels.get_mut(key).expect("checked");
    for c in on_changes.chars() {
        set_chan_bool_mode(&mut chan.modes, c, true);
    }
    for c in off_changes.chars() {
        set_chan_bool_mode(&mut chan.modes, c, false);
    }
    let mut spec = String::new();
    if !on_changes.is_empty() {
        spec.push('+');
        spec.push_str(&on_changes);
    }
    if !off_changes.is_empty() {
        spec.push('-');
        spec.push_str(&off_changes);
    }
    let line = format!(":ChanServ MODE {display} {spec}");
    state.broadcast_channel(key, &line, None);
}

pub(super) fn user_mode(state: &mut ServerState, conn: ConnId, target: &str, rest: &[&str]) {
    let self_nick = state.sessions[&conn].nick.clone().expect("registered");
    if state.nick_key(target) != state.nick_key(&self_nick) {
        state.numeric(
            conn,
            ERR_USERSDONTMATCH,
            &[],
            Some("Can't change mode for other users"),
        );
        return;
    }
    if rest.is_empty() {
        let mut modes = String::from("+");
        if state.sessions[&conn].invisible {
            modes.push('i');
        }
        if state.sessions[&conn].oper {
            modes.push('o');
        }
        if state.sessions[&conn].wallops {
            modes.push('w');
        }
        if state.sessions[&conn].bot {
            modes.push('B');
        }
        state.numeric(conn, RPL_UMODEIS, &[&modes], None);
        return;
    }
    // Apply the self-service user modes we support (+i invisible). +o is
    // grantable only via OPER; a self -o (deopering) is accepted.
    let mut adding = true;
    let mut applied = String::new();
    let mut last_sign = ' ';
    let mut unknown = false;
    for c in rest.join("").chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'i' => {
                state.sessions.get_mut(&conn).expect("registered").invisible = adding;
                push_mode(&mut applied, &mut last_sign, adding, 'i');
            }
            'w' => {
                state.sessions.get_mut(&conn).expect("registered").wallops = adding;
                push_mode(&mut applied, &mut last_sign, adding, 'w');
            }
            'B' => {
                state.sessions.get_mut(&conn).expect("registered").bot = adding;
                push_mode(&mut applied, &mut last_sign, adding, 'B');
            }
            'o' if !adding => {
                state.sessions.get_mut(&conn).expect("registered").oper = false;
                push_mode(&mut applied, &mut last_sign, false, 'o');
            }
            'o' => {} // +o only via OPER
            _ => unknown = true,
        }
    }
    if unknown {
        state.numeric(conn, ERR_UMODEUNKNOWNFLAG, &[], Some("Unknown MODE flag"));
    }
    if !applied.is_empty() {
        let nick = state.sessions[&conn].nick.clone().expect("registered");
        let server = state.config.server_name.clone();
        state.send(conn, &format!(":{server} MODE {nick} :{applied}"));
    }
}

pub(super) fn channel_mode(state: &mut ServerState, conn: ConnId, target: &str, rest: &[&str]) {
    let key = state.chan_key(target);
    let Some(chan) = state.channels.get(&key) else {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    };
    let display = chan.name.clone();
    let is_member = chan.members.contains_key(&conn);
    let is_op = chan.members.get(&conn).is_some_and(|m| m.op);

    // A +s channel is hidden from non-members on every surface — including
    // MODE, whose mode string, creation time, and +b/+q mask lists would all
    // otherwise confirm the channel and disclose its state. Look non-existent,
    // like NAMES/WHO/LIST do.
    if chan.modes.secret && !is_member {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    }

    if rest.is_empty() {
        let modes = chan.modes.to_string_with_args(is_member);
        let created = chan.created_at_secs.to_string();
        state.numeric(conn, RPL_CHANNELMODEIS, &[&display, &modes], None);
        state.numeric(conn, RPL_CREATIONTIME, &[&display, &created], None);
        return;
    }

    // A lone "+b"/"+q" is a public list query; "+e"/"+I" list viewing is a
    // chanop privilege (matching Solanum), so a non-op falls through to the
    // ERR_CHANOPRIVSNEEDED gate below rather than reading the exception lists.
    if rest.len() == 1 {
        let chan = &state.channels[&key];
        let query = match rest[0] {
            "+b" | "b" => Some((
                chan.bans.clone(),
                RPL_BANLIST,
                RPL_ENDOFBANLIST,
                None,
                "End of Channel Ban List",
            )),
            "+q" | "q" => Some((
                chan.quiets.clone(),
                RPL_QUIETLIST,
                RPL_ENDOFQUIETLIST,
                Some("q"),
                "End of Channel Quiet List",
            )),
            "+e" | "e" if is_op => Some((
                chan.ban_exceptions.clone(),
                RPL_EXCEPTLIST,
                RPL_ENDOFEXCEPTLIST,
                None,
                "End of Channel Exception List",
            )),
            "+I" | "I" if is_op => Some((
                chan.invite_exceptions.clone(),
                RPL_INVITELIST,
                RPL_ENDOFINVITELIST,
                None,
                "End of Channel Invite Exception List",
            )),
            _ => None,
        };
        if let Some((masks, item_code, end_code, infix, end_text)) = query {
            for mask in masks {
                match infix {
                    Some(ch) => state.numeric(conn, item_code, &[&display, ch, &mask], None),
                    None => state.numeric(conn, item_code, &[&display, &mask], None),
                }
            }
            match infix {
                Some(ch) => state.numeric(conn, end_code, &[&display, ch], Some(end_text)),
                None => state.numeric(conn, end_code, &[&display], Some(end_text)),
            }
            return;
        }
    }

    let is_op = chan.members.get(&conn).is_some_and(|m| m.op);
    if !is_op {
        state.numeric(
            conn,
            ERR_CHANOPRIVSNEEDED,
            &[target],
            Some("You're not a channel operator"),
        );
        return;
    }

    let mut adding = true;
    let mut args = rest[1..].iter();
    // Each applied change as (adding, mode char, optional arg). Collected rather
    // than formatted inline so the broadcast can be split across as many MODE
    // lines as the 512-byte wire limit needs — a single line of many bans is
    // discarded whole by a recipient's framing, hiding bans that are in force.
    let mut changes: Vec<(bool, char, Option<String>)> = Vec::new();

    for c in rest[0].chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'i' | 'm' | 'n' | 's' | 't' | 'C' => {
                // A ChanServ mode lock forbids changing a locked mode the
                // wrong way; such a change is refused (not echoed), leaving
                // the locked state in place.
                if state.mlock_conflict(&key, c, adding) {
                    continue;
                }
                let chan = state.channels.get_mut(&key).expect("checked");
                let field = match c {
                    'i' => &mut chan.modes.invite_only,
                    'm' => &mut chan.modes.moderated,
                    'n' => &mut chan.modes.no_external,
                    's' => &mut chan.modes.secret,
                    't' => &mut chan.modes.topic_ops_only,
                    'C' => &mut chan.modes.no_ctcp,
                    _ => unreachable!("outer arm matched only these mode chars"),
                };
                *field = adding;
                changes.push((adding, c, None));
            }
            'k' => {
                let chan = state.channels.get_mut(&key).expect("checked");
                if adding {
                    let Some(&k) = args.next() else {
                        state.numeric(
                            conn,
                            ERR_NEEDMOREPARAMS,
                            &["MODE"],
                            Some("Not enough parameters"),
                        );
                        // Stop, but still broadcast the modes already applied
                        // this command — returning here would mutate state
                        // (e.g. a preceding +m) without ever announcing it.
                        break;
                    };
                    // Keys with spaces or empty are unusable on the wire.
                    if k.is_empty() || k.contains(' ') {
                        state.numeric(
                            conn,
                            ERR_INVALIDKEY,
                            &[&display, "k", "*"],
                            Some("Key is not well-formed"),
                        );
                        continue;
                    }
                    // A key already set is not silently overwritten: reply
                    // ERR_KEYSET and leave the existing key in place (Solanum).
                    if chan.modes.key.is_some() {
                        state.numeric(
                            conn,
                            ERR_KEYSET,
                            &[&display],
                            Some("Channel key already set"),
                        );
                        continue;
                    }
                    chan.modes.key = Some(k.to_string());
                    changes.push((true, 'k', Some(k.to_string())));
                } else {
                    chan.modes.key = None;
                    // -k conventionally carries a placeholder arg ("*");
                    // consume it so later modes get the right params.
                    let _ = args.next();
                    changes.push((false, 'k', Some("*".into())));
                }
            }
            'l' => {
                let chan = state.channels.get_mut(&key).expect("checked");
                if adding {
                    let Some(&l) = args.next() else {
                        state.numeric(
                            conn,
                            ERR_NEEDMOREPARAMS,
                            &["MODE"],
                            Some("Not enough parameters"),
                        );
                        // Broadcast what already applied before stopping.
                        break;
                    };
                    let n = l.parse::<u32>().ok().filter(|&n| n > 0);
                    let Some(n) = n else {
                        // An empty value can't be a middle param on the
                        // wire; convention shows it as "*".
                        let shown = if l.is_empty() { "*" } else { l };
                        state.numeric(
                            conn,
                            ERR_INVALIDMODEPARAM,
                            &[&display, "l", shown],
                            Some("Invalid channel limit"),
                        );
                        continue;
                    };
                    let chan = state.channels.get_mut(&key).expect("checked");
                    chan.modes.limit = Some(n);
                    changes.push((true, 'l', Some(l.to_string())));
                } else {
                    chan.modes.limit = None;
                    changes.push((false, 'l', None));
                }
            }
            'b' | 'q' | 'e' | 'I' => {
                let Some(&raw_mask) = args.next() else {
                    continue; // handled above for the query form
                };
                // Canonicalize to nick!user@host so a bare `+b nick` actually
                // matches `nick!user@host` (Solanum clean_ban_mask); otherwise
                // banning by nick — a very common op — silently never applies.
                let norm = normalize_ban_mask(raw_mask);
                let mask = norm.as_str();
                // Bound the lists: without a cap a single opped client could
                // stream distinct masks until the core worker OOMs (and every
                // JOIN/PRIVMSG re-scans them). `MAXLIST=bqeI:100` advertises a
                // *combined* total across the four grouped modes (Libera
                // semantics), so cap on their sum, not per list.
                let chan_ref = state.channels.get(&key).expect("checked");
                let list_ref = match c {
                    'b' => &chan_ref.bans,
                    'q' => &chan_ref.quiets,
                    'e' => &chan_ref.ban_exceptions,
                    'I' => &chan_ref.invite_exceptions,
                    _ => unreachable!("outer arm matched only these list-mode chars"),
                };
                let is_new = !list_ref.iter().any(|b| b == mask);
                let combined = chan_ref.bans.len()
                    + chan_ref.quiets.len()
                    + chan_ref.ban_exceptions.len()
                    + chan_ref.invite_exceptions.len();
                let at_cap = combined >= MAXLIST;
                if adding && is_new && at_cap {
                    state.numeric(
                        conn,
                        ERR_BANLISTFULL,
                        &[&display, mask],
                        Some("Channel list is full"),
                    );
                    continue;
                }
                let chan = state.channels.get_mut(&key).expect("checked");
                let list = match c {
                    'b' => &mut chan.bans,
                    'q' => &mut chan.quiets,
                    'e' => &mut chan.ban_exceptions,
                    'I' => &mut chan.invite_exceptions,
                    _ => unreachable!("outer arm matched only these list-mode chars"),
                };
                if adding {
                    if is_new {
                        list.push(mask.to_string());
                    }
                } else {
                    list.retain(|b| b != mask);
                }
                changes.push((adding, c, Some(mask.to_string())));
            }
            'o' | 'v' => {
                let Some(&who) = args.next() else {
                    state.numeric(
                        conn,
                        ERR_NEEDMOREPARAMS,
                        &["MODE"],
                        Some("Not enough parameters"),
                    );
                    // Broadcast what already applied before stopping.
                    break;
                };
                let nick_key = state.nick_key(who);
                let Some(&member_conn) = state.nicks.get(&nick_key) else {
                    state.numeric(conn, ERR_NOSUCHNICK, &[who], Some("No such nick/channel"));
                    continue;
                };
                let chan = state.channels.get_mut(&key).expect("checked");
                let Some(member) = chan.members.get_mut(&member_conn) else {
                    state.numeric(
                        conn,
                        ERR_USERNOTINCHANNEL,
                        &[who, &display],
                        Some("They aren't on that channel"),
                    );
                    continue;
                };
                if c == 'o' {
                    member.op = adding;
                } else {
                    member.voice = adding;
                }
                changes.push((adding, c, Some(who.to_string())));
            }
            other => {
                state.numeric(
                    conn,
                    ERR_UNKNOWNMODE,
                    &[&other.to_string()],
                    Some("is unknown mode char to me"),
                );
            }
        }
    }

    if !changes.is_empty() {
        let prefix = state.sessions[&conn].prefix();
        broadcast_mode_changes(state, &key, &prefix, &display, &changes);
    }
}

/// Announce applied channel-mode changes, split across as many `MODE` lines as
/// the 512-byte wire limit needs. Emitting one line for a command that set many
/// bans would run past the limit, and a recipient's framing discards an
/// over-long line whole — so the modes would be applied server-side yet unseen.
/// Sign coalescing restarts on each line (every line names its own `+`/`-`).
fn broadcast_mode_changes(
    state: &mut ServerState,
    key: &ChanKey,
    prefix: &str,
    display: &str,
    changes: &[(bool, char, Option<String>)],
) {
    let base = format!(":{prefix} MODE {display} ");
    let mut modes = String::new();
    let mut args: Vec<String> = Vec::new();
    let mut last_sign = ' ';
    for (adding, c, arg) in changes {
        let sign = if *adding { '+' } else { '-' };
        // What this change would add to the current line: a sign flip, the mode
        // char, and (with an arg) a space plus the arg.
        let sign_cost = usize::from(last_sign != sign);
        let arg_cost = arg.as_ref().map_or(0, |a| 1 + a.len());
        let args_len: usize = args.iter().map(|a| 1 + a.len()).sum();
        let prospective =
            base.len() + modes.len() + sign_cost + 1 + args_len + arg_cost + 2 /* CRLF */;
        if !modes.is_empty() && prospective > 512 {
            flush_mode_line(state, key, &base, &modes, &args);
            modes.clear();
            args.clear();
            last_sign = ' ';
        }
        if last_sign != sign {
            modes.push(sign);
            last_sign = sign;
        }
        modes.push(*c);
        if let Some(a) = arg {
            args.push(a.clone());
        }
    }
    if !modes.is_empty() {
        flush_mode_line(state, key, &base, &modes, &args);
    }
}

fn flush_mode_line(
    state: &mut ServerState,
    key: &ChanKey,
    base: &str,
    modes: &str,
    args: &[String],
) {
    let mut line = format!("{base}{modes}");
    for a in args {
        line.push(' ');
        line.push_str(a);
    }
    state.broadcast_channel(key, &line, None);
}

pub(super) fn push_mode(applied: &mut String, last_sign: &mut char, adding: bool, c: char) {
    let sign = if adding { '+' } else { '-' };
    if *last_sign != sign {
        applied.push(sign);
        *last_sign = sign;
    }
    applied.push(c);
}
