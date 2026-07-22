//! PRIVMSG/NOTICE/TAGMSG delivery, including multiline batches.

use super::*;

// ---- messaging ----------------------------------------------------------

/// A CTCP message is \x01-delimited; ACTION (/me) is exempt from +C.
pub(super) fn is_blocked_ctcp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.first() == Some(&0x01) && !text.starts_with("\u{1}ACTION")
}

pub(super) fn client_tag_string(msg: &Message) -> String {
    msg.tags
        .iter()
        .filter(|t| t.key.starts_with('+'))
        .map(|t| match &t.value {
            Some(v) => format!("{}={}", t.key, e6irc_proto::message::escape_tag_value(v)),
            None => t.key.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

pub(super) fn cmd_message(
    state: &mut ServerState,
    conn: ConnId,
    msg: &Message,
    p: &[&str],
    kind: &'static str,
) {
    let client_tags = client_tag_string(msg);
    // Per Modern IRC, NOTICE must never trigger automatic replies —
    // including error numerics. The silence below is spec-mandated.
    let loud = kind == "PRIVMSG";
    // A line tagged with an open batch belongs to that batch, not to the wire:
    // it is buffered until BATCH - and delivered as part of one message.
    if multiline_collect(state, conn, msg, p, kind) {
        return;
    }
    let Some(&targets) = p.first() else {
        if loud {
            state.numeric(
                conn,
                ERR_NORECIPIENT,
                &[],
                Some("No recipient given (PRIVMSG)"),
            );
        }
        return;
    };
    let text = p.get(1).copied().unwrap_or("");
    if text.is_empty() {
        if loud {
            state.numeric(conn, ERR_NOTEXTTOSEND, &[], Some("No text to send"));
        }
        return;
    }
    // A comma-separated target list delivers to each recipient, deduped and
    // bounded by TARGMAX (advertised in ISUPPORT). Past the cap the message
    // is refused loudly rather than silently truncated.
    let mut seen = std::collections::HashSet::new();
    let mut delivered = 0usize;
    for target in targets.split(',').filter(|t| !t.is_empty()) {
        // Dedup on the casefolded target so `#a,#A` (or `nick,NICK`) collapse
        // to one delivery rather than two.
        if !seen.insert(state.casemap.casefold(target)) {
            continue;
        }
        if delivered >= TARGMAX {
            if loud {
                state.numeric(
                    conn,
                    ERR_TOOMANYTARGETS,
                    &[target],
                    Some("Too many targets; message not delivered"),
                );
            }
            break;
        }
        delivered += 1;
        deliver_one_message(state, conn, target, text, kind, &client_tags, loud);
    }
}

/// Deliver a PRIVMSG/NOTICE to a single already-split `target`. `loud` is
/// false for NOTICE (which must never trigger error numerics or auto-replies).
/// Record a delivered message in its target's hot ring and, when a database is
/// configured, enqueue it for persistence.
///
/// `dm_peers` carries a direct message's casefolded participants (empty for a
/// channel); it is what lets CHATHISTORY TARGETS find the conversations a user
/// takes part in, which the composite conversation key cannot be searched for.
///
/// Channels and direct messages share this one path deliberately: the ring, the
/// persistence rule and the "a gap exists" bookkeeping must not differ by target
/// kind, or CHATHISTORY would answer differently depending on where a message
/// came from.
pub(super) fn record_history(
    state: &mut ServerState,
    key: &crate::core::state::HistoryKey,
    dm_peers: Vec<String>,
    entry: crate::core::state::HistoryEntry,
    sender_account: Option<String>,
) {
    let (msgid, ts) = (entry.msgid.clone(), entry.ts);
    let (prefix, body, kind) = (entry.sender_prefix.clone(), entry.body.clone(), entry.kind);
    state.push_history(key, entry);
    // Persist only when a database is configured (the same db-present proxy the
    // other DB writes use). Without one the hot ring is the entire record, so
    // there is nothing to enqueue — and enqueuing anyway would fail on every
    // message, flooding stderr and starving the core worker under load.
    if !state.config.sasl_enabled {
        return;
    }
    let log = crate::core::DbRequest::LogMessage {
        msgid,
        target: key.as_str().to_string(),
        dm_peers,
        sender_prefix: prefix,
        sender_account,
        kind: if kind == "PRIVMSG" {
            "privmsg"
        } else {
            "notice"
        },
        body,
        ts,
    };
    if state.db_tx.try_push(log).is_err() {
        eprintln!("history: log queue full or closed; message not persisted");
        // Delivered but not persisted: mark the ring incomplete so CHATHISTORY
        // does not imply a gap-free record.
        state.mark_history_incomplete(key);
    }
}

/// What a message target resolved to, once the sender was allowed to speak.
pub(super) enum ResolvedKind {
    Channel {
        key: crate::core::state::ChanKey,
        /// STATUSMSG sigil (`@`/`+`), or 0 — it narrows the audience and keeps
        /// the message out of history.
        status_prefix: u8,
    },
    User {
        peer: ConnId,
    },
}

pub(super) struct ResolvedTarget {
    pub(super) kind: ResolvedKind,
    /// Everyone who receives it, the sender excluded.
    pub(super) recipients: Vec<ConnId>,
}

/// Resolve a message target and decide whether the sender may speak to it.
///
/// `None` means the message was refused and the refusal already sent. Every
/// kind of message goes through here — single-line and multiline alike — so a
/// ban, `+m`, `+n` or `+C` cannot be evaded by choosing a different way to
/// send the same text.
pub(super) fn resolve_message_target(
    state: &mut ServerState,
    conn: ConnId,
    target: &str,
    text: &str,
    loud: bool,
) -> Option<ResolvedTarget> {
    let prefix = state.sessions[&conn].prefix();
    // STATUSMSG: a leading @ or + restricts delivery to members with at
    // least that status. The prefix stays in the target echoed to
    // recipients.
    let (status_prefix, chan_target) = match target.strip_prefix(['@', '+']) {
        Some(rest) if rest.starts_with('#') => (target.as_bytes()[0], rest),
        _ => (0, target),
    };
    if !chan_target.starts_with('#') {
        let key = state.nick_key(target);
        let Some(peer) = state.registered_peer(&key) else {
            if loud {
                state.numeric(
                    conn,
                    ERR_NOSUCHNICK,
                    &[target],
                    Some("No such nick/channel"),
                );
            }
            return None;
        };
        return Some(ResolvedTarget {
            kind: ResolvedKind::User { peer },
            recipients: vec![peer],
        });
    }
    let key = state.chan_key(chan_target);
    let Some(chan) = state.channels.get(&key) else {
        if loud {
            state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        }
        return None;
    };
    let member = chan.members.get(&conn);
    let may_speak = match member {
        Some(m) if m.op || m.voice => true,
        Some(_) => {
            !chan.modes.moderated
                && !chan.is_banned(state.casemap, &prefix)
                && !chan.is_quieted(state.casemap, &prefix)
        }
        // An external sender (to a -n channel) is still subject to +m and to
        // bans/quiets — being off-channel doesn't exempt a banned mask.
        None => {
            !chan.modes.no_external
                && !chan.modes.moderated
                && !chan.is_banned(state.casemap, &prefix)
                && !chan.is_quieted(state.casemap, &prefix)
        }
    };
    if !may_speak {
        if loud {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[target],
                Some("Cannot send to channel"),
            );
        }
        return None;
    }
    // +C blocks CTCP (\x01-wrapped) except ACTION.
    if chan.modes.no_ctcp && is_blocked_ctcp(text) {
        if loud {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[target],
                Some("Cannot send to channel (+C, no CTCP)"),
            );
        }
        return None;
    }
    let recipients: Vec<ConnId> = chan
        .members
        .iter()
        .filter(|(c, m)| {
            **c != conn
                && match status_prefix {
                    b'@' => m.op,
                    b'+' => m.op || m.voice,
                    _ => true,
                }
        })
        .map(|(c, _)| *c)
        .collect();
    Some(ResolvedTarget {
        kind: ResolvedKind::Channel { key, status_prefix },
        recipients,
    })
}

pub(super) fn deliver_one_message(
    state: &mut ServerState,
    conn: ConnId,
    target: &str,
    text: &str,
    kind: &'static str,
    client_tags: &str,
    loud: bool,
) {
    // Services pseudo-clients intercept before the nick table. NOTICE
    // to services is dropped without reply (spec: NOTICE never triggers
    // automatic responses).
    let target_key = state.nick_key(target);
    if is_service_nick(target_key.as_str()) {
        if loud {
            services_dispatch(state, conn, target_key.as_str(), text);
        }
        return;
    }

    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} {kind} {target} :{text}");
    let Some(resolved) = resolve_message_target(state, conn, target, text, loud) else {
        return;
    };
    if let ResolvedKind::Channel { key, status_prefix } = resolved.kind {
        let recipients = resolved.recipients;
        let sender_account = state.sessions[&conn].account.clone();
        let sender_is_bot = state.sessions[&conn].bot;
        let (ts, msgid) = state.stamp();
        deliver_and_echo(
            state,
            conn,
            &recipients,
            &Delivery {
                sender_account: sender_account.as_deref(),
                sender_is_bot,
                msgid: &msgid,
                client_tags,
                body: &line,
                ts,
                bypass_capture: true,
            },
        );
        // A STATUSMSG (@#/+#) reached only ops/voiced members. It must not
        // enter the shared history ring or the messages table, or CHATHISTORY
        // would replay it to members who were excluded from the live delivery.
        if status_prefix != 0 {
            return;
        }
        record_history(
            state,
            &(&key).into(),
            Vec::new(),
            crate::core::state::HistoryEntry {
                msgid,
                ts,
                sender_prefix: prefix.clone(),
                kind,
                body: text.to_string(),
            },
            sender_account,
        );
    } else {
        let ResolvedKind::User { peer } = resolved.kind else {
            unreachable!("resolve_message_target returns Channel or User");
        };
        let sender_account = state.sessions[&conn].account.clone();
        let sender_is_bot = state.sessions[&conn].bot;
        let (ts, msgid) = state.stamp();
        deliver_and_echo(
            state,
            conn,
            &[peer],
            &Delivery {
                sender_account: sender_account.as_deref(),
                sender_is_bot,
                msgid: &msgid,
                client_tags,
                body: &line,
                ts,
                bypass_capture: true,
            },
        );
        // The conversation is recorded once, under a key both participants
        // derive identically, so each side's CHATHISTORY sees the whole thread
        // rather than only the half it sent.
        let peer_nick = state.sessions[&peer].nick.clone().expect("registered");
        let (conv, peers) =
            state.dm_conversation(&state.conn_identity(conn), &state.conn_identity(peer));
        record_history(
            state,
            &conv,
            peers,
            crate::core::state::HistoryEntry {
                msgid,
                ts,
                sender_prefix: prefix.clone(),
                kind,
                body: text.to_string(),
            },
            sender_account,
        );
        // Away auto-reply, PRIVMSG only (NOTICE must stay reply-free).
        if loud && let Some(away) = state.sessions[&peer].away.clone() {
            state.numeric(conn, RPL_AWAY, &[&peer_nick], Some(&away));
        }
    }
}

/// TAGMSG: tags-only message (message-tags spec). Only clients that
/// negotiated `message-tags` may send it, and only such clients receive
/// it — for everyone else it must not exist at all.
pub(super) fn cmd_tagmsg(state: &mut ServerState, conn: ConnId, msg: &Message, p: &[&str]) {
    if !state.sessions[&conn].caps.message_tags {
        state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &["TAGMSG"],
            Some("Unknown command"),
        );
        return;
    }
    // A multiline batch carries PRIVMSG and NOTICE only. Delivering a
    // batch-tagged TAGMSG on its own would take it out of the message the
    // client was assembling and send it *before* that message, which is not
    // what was asked for — so it is refused rather than quietly re-routed.
    if msg.tags.iter().any(|t| t.key == "batch") {
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "TAGMSG cannot be part of a multiline batch",
        );
        return;
    }
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NORECIPIENT,
            &[],
            Some("No recipient given (TAGMSG)"),
        );
        return;
    };
    // Only client-only tags (`+` prefix) are relayed.
    let prefix = state.sessions[&conn].prefix();
    let msgid = state.next_msgid();
    let base_tags = match client_tag_string(msg) {
        tags if tags.is_empty() => format!("msgid={msgid}"),
        tags => format!("msgid={msgid};{tags}"),
    };
    let tag_part = base_tags;
    let make_line = |extra_time: Option<String>| {
        let mut tags = tag_part.clone();
        if let Some(t) = extra_time {
            if !tags.is_empty() {
                tags.push(';');
            }
            tags.push_str(&format!("time={t}"));
        }
        if tags.is_empty() {
            format!(":{prefix} TAGMSG {target}")
        } else {
            format!("@{tags} :{prefix} TAGMSG {target}")
        }
    };

    let recipients: Vec<ConnId> = if target.starts_with('#') {
        let key = state.chan_key(target);
        let Some(chan) = state.channels.get(&key) else {
            state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
            return;
        };
        let member = chan.members.get(&conn);
        // Same gate as PRIVMSG (incl. ban/quiet), so a banned or quieted member
        // can't relay TAGMSG (typing/reaction tags) it couldn't relay as text.
        let may_speak = match member {
            Some(m) if m.op || m.voice => true,
            Some(_) => {
                !chan.modes.moderated
                    && !chan.is_banned(state.casemap, &prefix)
                    && !chan.is_quieted(state.casemap, &prefix)
            }
            None => {
                !chan.modes.no_external
                    && !chan.modes.moderated
                    && !chan.is_banned(state.casemap, &prefix)
                    && !chan.is_quieted(state.casemap, &prefix)
            }
        };
        if !may_speak {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[target],
                Some("Cannot send to channel"),
            );
            return;
        }
        chan.members
            .keys()
            .copied()
            .filter(|c| *c != conn)
            .collect()
    } else {
        let key = state.nick_key(target);
        let Some(peer) = state.registered_peer(&key) else {
            state.numeric(
                conn,
                ERR_NOSUCHNICK,
                &[target],
                Some("No such nick/channel"),
            );
            return;
        };
        vec![peer]
    };

    let time = state.time_tag();
    for recipient in recipients {
        let caps = state.sessions.get(&recipient).map(|s| s.caps);
        let Some(caps) = caps else { continue };
        if !caps.message_tags {
            continue; // spec: TAGMSG must not reach cap-less clients
        }
        let line = make_line(caps.server_time.then(|| time.clone()));
        // A delivery, not a response: bypass labeled-response capture.
        let bytes = bytes::Bytes::from(format!("{line}\r\n"));
        state.send_bytes_uncaptured(recipient, bytes);
    }
    if state.sessions[&conn].caps.echo_message {
        let caps = state.sessions[&conn].caps;
        let line = make_line(caps.server_time.then(|| time.clone()));
        state.send(conn, &line); // echo is the labeled response
    }
}

/// The `draft/multiline` capability, and the limits advertised as its value.
/// A client must be able to see them before it starts a batch it cannot finish.
pub(super) const MULTILINE_CAP: &str = "draft/multiline";
/// Total bytes of message text one multiline message may carry.
pub(super) const MULTILINE_MAX_BYTES: usize = 4096;
/// Lines one multiline message may carry.
pub(super) const MULTILINE_MAX_LINES: usize = 32;
/// Tag marking a line as continuing the previous one without a break.
pub(super) const MULTILINE_CONCAT_TAG: &str = "draft/multiline-concat";

/// `FAIL BATCH <code> [context] :<description>`, and abandon whatever batch was
/// open: a multiline message is one message, so a batch that went wrong must
/// deliver nothing rather than a truncated version of what the client meant.
pub(super) fn multiline_fail(
    state: &mut ServerState,
    conn: ConnId,
    code: &str,
    context: &[&str],
    detail: &str,
) {
    // Abandoning the batch also inherits its labeled-response label. The batch
    // *was* the response owed to the command that opened it, so if that command
    // was labeled the failure has to carry the label — otherwise a client
    // tracking labels waits forever for a response that will never come.
    let label = state
        .sessions
        .get_mut(&conn)
        .and_then(|session| session.multiline.take())
        .and_then(|batch| batch.label);
    let server = state.config.server_name.clone();
    let mut line = String::new();
    if let Some(label) = &label {
        line.push_str(&format!("@label={label} "));
    }
    line.push_str(&format!(":{server} FAIL BATCH {code}"));
    for param in context {
        line.push(' ');
        line.push_str(param);
    }
    line.push_str(" :");
    line.push_str(detail);
    match label {
        // This answers the BATCH that opened the batch, not whatever line
        // tripped it, so it must not also be framed as the current command's
        // response.
        Some(_) => state.send_bytes_uncaptured(conn, bytes::Bytes::from(format!("{line}\r\n"))),
        None => state.send(conn, &line),
    }
}

/// Client-initiated `BATCH`. Only `draft/multiline` batches are accepted, which
/// is the only batch type a client has any reason to open here.
pub(super) fn cmd_batch(state: &mut ServerState, conn: ConnId, msg: &Message, p: &[&str]) {
    let Some(&reference) = p.first() else {
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "Syntax: BATCH +<reference> draft/multiline <target>",
        );
        return;
    };
    // Split off the leading *character*, not the leading byte: a reference
    // beginning with a multi-byte character (`BATCH \u{61c}x`) would land
    // `split_at(1)` inside it and panic, which any registered client could do.
    let mut chars = reference.chars();
    let sign = chars.next();
    let reference = chars.as_str();
    match sign {
        Some('+') => {
            if !state.sessions[&conn].caps.multiline {
                multiline_fail(
                    state,
                    conn,
                    "MULTILINE_INVALID",
                    &[],
                    "draft/multiline was not negotiated",
                );
                return;
            }
            let (Some(&batch_type), Some(&target)) = (p.get(1), p.get(2)) else {
                multiline_fail(
                    state,
                    conn,
                    "MULTILINE_INVALID",
                    &[],
                    "Syntax: BATCH +<reference> draft/multiline <target>",
                );
                return;
            };
            if batch_type != MULTILINE_CAP {
                multiline_fail(
                    state,
                    conn,
                    "MULTILINE_INVALID",
                    &[],
                    "Only draft/multiline batches may be opened",
                );
                return;
            }
            if state.sessions[&conn].multiline.is_some() {
                multiline_fail(
                    state,
                    conn,
                    "MULTILINE_INVALID",
                    &[],
                    "A batch is already open on this connection",
                );
                return;
            }
            let client_tags = client_tag_string(msg);
            // The response to this command is the batch itself, emitted when
            // the client closes it — so the label travels with the batch and
            // the framer must not ACK this as an empty response.
            let label = state.capture.as_ref().and_then(|c| c.label.clone());
            if let Some(cap) = state.capture.as_mut() {
                cap.deferred = true;
            }
            let session = state.sessions.get_mut(&conn).expect("checked");
            session.multiline = Some(crate::core::state::MultilineBatch {
                reference: reference.to_string(),
                target: target.to_string(),
                client_tags,
                label,
                lines: Vec::new(),
                bytes: 0,
                kind: None,
            });
        }
        Some('-') => {
            let open = state.sessions[&conn]
                .multiline
                .as_ref()
                .is_some_and(|b| b.reference == reference);
            if !open {
                multiline_fail(state, conn, "MULTILINE_INVALID", &[], "No such open batch");
                return;
            }
            let batch = state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .multiline
                .take()
                .expect("checked");
            deliver_multiline(state, conn, batch);
        }
        _ => multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "Batch reference must start with + or -",
        ),
    }
}

/// Deliver a completed multiline batch.
///
/// A multiline message is *one* message: it gets one msgid and one timestamp,
/// and both forms below carry the same pair, so a client that sees the batch
/// and one that sees the flattened lines are looking at the same event.
///
/// Recipients that negotiated `draft/multiline` receive the batch as sent —
/// blank lines and concat tags intact, because those are what the sender wrote.
/// Everyone else receives one message per non-blank line: they have no way to
/// represent a line break inside a PRIVMSG, and a blank line would be an empty
/// message with nothing in it.
pub(super) fn deliver_multiline(
    state: &mut ServerState,
    conn: ConnId,
    batch: crate::core::state::MultilineBatch,
) {
    let kind = batch.kind.unwrap_or("PRIVMSG");
    let loud = kind == "PRIVMSG";
    if batch.lines.is_empty() {
        return; // opened and closed without content: nothing happened
    }
    // Permission checks see the whole message, so a CTCP or a ban cannot be
    // slipped past them by splitting it across lines.
    let joined = batch
        .lines
        .iter()
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let Some(resolved) = resolve_message_target(state, conn, &batch.target, &joined, loud) else {
        return;
    };
    let target = batch.target.as_str();
    let prefix = state.sessions[&conn].prefix();
    let sender_account = state.sessions[&conn].account.clone();
    let sender_is_bot = state.sessions[&conn].bot;
    let (ts, msgid) = state.stamp();
    let time = e6irc_proto::time::server_time(ts);
    let batch_ref = state.next_msgid();

    let mut audience: Vec<(ConnId, bool)> = resolved
        .recipients
        .iter()
        .map(|&c| (c, /* bypass_capture */ true))
        .collect();
    if state.sessions[&conn].caps.echo_message {
        audience.push((conn, false));
    }
    for (recipient, bypass) in audience {
        let Some(session) = state.sessions.get(&recipient) else {
            continue;
        };
        let caps = session.caps;
        // Tags every form carries, in the order the other delivery path uses.
        let mut common: Vec<String> = Vec::new();
        if caps.server_time {
            common.push(format!("time={time}"));
        }
        if caps.account_tag
            && let Some(account) = sender_account.as_deref()
        {
            common.push(format!("account={account}"));
        }
        if sender_is_bot && caps.message_tags {
            common.push("bot".into());
        }
        if caps.multiline && caps.batch {
            let mut open: Vec<String> = Vec::new();
            // Only the sender's own copy is the labeled response to its command.
            if !bypass && let Some(label) = &batch.label {
                open.push(format!("label={label}"));
            }
            if caps.message_tags {
                open.push(format!("msgid={msgid}"));
                if !batch.client_tags.is_empty() {
                    open.push(batch.client_tags.clone());
                }
            }
            open.extend(common.iter().cloned());
            let tags = tag_prefix(&open);
            send_multiline_line(
                state,
                recipient,
                bypass,
                &format!("{tags}:{prefix} BATCH +{batch_ref} {MULTILINE_CAP} {target}"),
            );
            for (text, concat) in &batch.lines {
                let mut line_tags = vec![format!("batch={batch_ref}")];
                if *concat && caps.message_tags {
                    line_tags.push(MULTILINE_CONCAT_TAG.to_string());
                }
                line_tags.extend(common.iter().cloned());
                let tags = tag_prefix(&line_tags);
                send_multiline_line(
                    state,
                    recipient,
                    bypass,
                    &format!("{tags}:{prefix} {kind} {target} :{text}"),
                );
            }
            send_multiline_line(
                state,
                recipient,
                bypass,
                &format!(":{} BATCH -{batch_ref}", state.config.server_name.clone()),
            );
        } else {
            // Flattened: the msgid identifies the message, so it rides the
            // first line only — the rest are the same message continuing.
            let mut first = true;
            for (text, _) in batch.lines.iter().filter(|(t, _)| !t.is_empty()) {
                let mut line_tags: Vec<String> = Vec::new();
                if first && caps.message_tags {
                    line_tags.push(format!("msgid={msgid}"));
                    if !batch.client_tags.is_empty() {
                        line_tags.push(batch.client_tags.clone());
                    }
                } else if caps.message_tags && !batch.client_tags.is_empty() {
                    line_tags.push(batch.client_tags.clone());
                }
                line_tags.extend(common.iter().cloned());
                let tags = tag_prefix(&line_tags);
                send_multiline_line(
                    state,
                    recipient,
                    bypass,
                    &format!("{tags}:{prefix} {kind} {target} :{text}"),
                );
                first = false;
            }
        }
    }

    // History records what a client without the capability would have seen:
    // one entry per non-blank line, the first carrying the message's msgid.
    let (hist_key, peers) = match &resolved.kind {
        ResolvedKind::Channel { key, status_prefix } => {
            if *status_prefix != 0 {
                return; // STATUSMSG never enters history (see the other path)
            }
            (crate::core::state::HistoryKey::from(key), Vec::new())
        }
        ResolvedKind::User { peer } => {
            let peer_nick = state.sessions[peer].nick.clone().expect("registered");
            let _ = peer_nick;
            let (key, peers) =
                state.dm_conversation(&state.conn_identity(conn), &state.conn_identity(*peer));
            (key, peers)
        }
    };
    let mut msgid = Some(msgid);
    for (text, _) in batch.lines.iter().filter(|(t, _)| !t.is_empty()) {
        let entry_msgid = match msgid.take() {
            Some(id) => id,
            None => state.stamp().1,
        };
        record_history(
            state,
            &hist_key,
            peers.clone(),
            crate::core::state::HistoryEntry {
                msgid: entry_msgid,
                ts,
                sender_prefix: prefix.clone(),
                kind,
                body: text.clone(),
            },
            sender_account.clone(),
        );
    }
}

/// `@a;b;c ` or empty — the tag prefix for a line, built once per form.
pub(super) fn tag_prefix(tags: &[String]) -> String {
    if tags.is_empty() {
        String::new()
    } else {
        format!("@{} ", tags.join(";"))
    }
}

/// Send one line of a multiline delivery, honoring labeled-response capture the
/// same way the single-message path does.
pub(super) fn send_multiline_line(
    state: &mut ServerState,
    conn: ConnId,
    bypass_capture: bool,
    line: &str,
) {
    let bytes = bytes::Bytes::from(format!("{line}\r\n"));
    if bypass_capture {
        state.send_bytes_uncaptured(conn, bytes);
    } else {
        state.send_bytes(conn, bytes);
    }
}

/// Buffer one line of an open multiline batch. Returns true when the message
/// was part of a batch (and so must not be delivered on its own).
pub(super) fn multiline_collect(
    state: &mut ServerState,
    conn: ConnId,
    msg: &Message,
    p: &[&str],
    kind: &'static str,
) -> bool {
    let Some(reference) = msg
        .tags
        .iter()
        .find(|t| t.key == "batch")
        .and_then(|t| t.value.clone())
    else {
        return false;
    };
    let matches = state.sessions[&conn]
        .multiline
        .as_ref()
        .is_some_and(|b| b.reference == reference);
    if !matches {
        // A tag naming a batch this connection never opened: the client and the
        // server disagree about what is being assembled, so nothing is sent.
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "That batch is not open on this connection",
        );
        return true;
    }
    let text = p.get(1).copied().unwrap_or("");
    let concat = msg.tags.iter().any(|t| t.key == MULTILINE_CONCAT_TAG);
    if concat && text.is_empty() {
        // Concatenating onto nothing is meaningless, and silently dropping the
        // tag would change what the sender wrote.
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "The concat tag cannot be used on a blank message",
        );
        return true;
    }
    // A batch is one message, so it cannot be half notice: NOTICE exists to
    // say "never reply to this automatically", and relaying it as a PRIVMSG
    // would hand recipients a message the sender never wrote.
    let established = state.sessions[&conn]
        .multiline
        .as_ref()
        .and_then(|b| b.kind);
    if let Some(established) = established
        && established != kind
    {
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "A multiline batch cannot mix PRIVMSG and NOTICE",
        );
        return true;
    }
    let session = state.sessions.get_mut(&conn).expect("checked");
    let batch = session.multiline.as_mut().expect("checked");
    if batch.lines.len() >= MULTILINE_MAX_LINES {
        multiline_fail(
            state,
            conn,
            "MULTILINE_MAX_LINES",
            &[&MULTILINE_MAX_LINES.to_string()],
            "Multiline message has too many lines",
        );
        return true;
    }
    if batch.bytes + text.len() > MULTILINE_MAX_BYTES {
        multiline_fail(
            state,
            conn,
            "MULTILINE_MAX_BYTES",
            &[&MULTILINE_MAX_BYTES.to_string()],
            "Multiline message is too long",
        );
        return true;
    }
    batch.bytes += text.len();
    batch.kind.get_or_insert(kind);
    batch.lines.push((text.to_string(), concat));
    true
}
