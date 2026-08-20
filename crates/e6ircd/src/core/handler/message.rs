//! PRIVMSG/NOTICE/TAGMSG delivery, including multiline batches.

use super::*;

// ---- messaging ----------------------------------------------------------

/// A CTCP message is \x01-delimited; ACTION (/me) is exempt from +C.
pub(super) fn is_blocked_ctcp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.first() == Some(&0x01) && !is_ctcp_action(text)
}

/// Whether `text` is a CTCP whose tag is exactly `ACTION`. The tag ends at the
/// first space or the closing `\x01`, so a prefix test (`starts_with("\x01ACTION")`)
/// would wrongly exempt `\x01ACTIONX\x01` / `\x01ACTIONVERSION\x01` — crafted CTCP
/// that would then slip through a `+C` (no-CTCP) channel.
fn is_ctcp_action(text: &str) -> bool {
    text == "\u{1}ACTION"
        || text.starts_with("\u{1}ACTION ")
        || text.starts_with("\u{1}ACTION\u{1}")
}

/// Yield the unique, non-empty targets of a comma-separated target list,
/// deduplicated by casefold so `#a,#A` (or `nick,NICK`) collapse to one.
///
/// The fold-dedup is applied here *by construction*, so no command that fans out
/// over a target list can forget it — the class that let `#a,#A` double-deliver,
/// or that made one path (TAGMSG) drop all but the first target. Callers apply
/// their own cap (`TARGMAX`, `MONITOR` limit, …) since the loud over-cap reply
/// differs per command; this guarantees only the fold.
pub(super) fn unique_targets(
    targets: &str,
    casemap: e6irc_proto::casemap::CaseMapping,
) -> impl Iterator<Item = &str> {
    let mut seen = std::collections::HashSet::new();
    targets
        .split(',')
        .filter(move |t| !t.is_empty() && seen.insert(casemap.casefold(t)))
}

pub(super) fn cmd_message(
    state: &mut ServerState,
    conn: ConnId,
    msg: &Message,
    p: &[&str],
    kind: crate::core::MessageKind,
) {
    let client_tags = crate::sanitize::client_tag_string(msg);
    // Per Modern IRC, NOTICE must never trigger automatic replies —
    // including error numerics. The silence below is spec-mandated.
    let loud = kind.is_loud();
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
    // A comma-separated target list delivers to each recipient, deduped (by
    // `unique_targets`) and bounded by TARGMAX (advertised in ISUPPORT). Past the
    // cap the message is refused loudly rather than silently truncated.
    let ordered: Vec<String> = unique_targets(targets, state.casemap)
        .map(str::to_string)
        .collect();
    for (delivered, target) in ordered.into_iter().enumerate() {
        if delivered >= TARGMAX {
            if loud {
                state.numeric(
                    conn,
                    ERR_TOOMANYTARGETS,
                    &[&target],
                    Some("Too many targets; message not delivered"),
                );
            }
            break;
        }
        deliver_one_message(state, conn, &target, text, kind, &client_tags, loud);
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
) {
    let (msgid, ts) = (entry.msgid.clone(), entry.ts);
    let (prefix, body, kind) = (entry.sender_prefix.clone(), entry.body.clone(), entry.kind);
    let sender_account = entry.sender_account.clone();
    let sender_is_bot = entry.sender_is_bot;
    let multiline = entry.multiline.clone();
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
        kind,
        body,
        sender_is_bot,
        multiline,
        ts,
    };
    if state.db_tx.try_push(log).is_err() {
        eprintln!("history: log queue full or closed; message not persisted");
        // Delivered but not persisted: mark the ring incomplete so CHATHISTORY
        // does not imply a gap-free record.
        state.mark_history_incomplete(key);
    }
}

/// A STATUSMSG target sigil. `PRIVMSG @#c` reaches only ops, `+#c` only ops and
/// voiced; an ordinary channel message carries `None`. A three-value `u8`
/// (`0`/`b'@'`/`b'+'`) before this, which made "is it a STATUSMSG" a `!= 0`
/// test and the audience rule a byte match; the enum names both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatusSigil {
    /// `@#channel` — ops only.
    OpsOnly,
    /// `+#channel` — ops and voiced.
    Voiced,
}

impl StatusSigil {
    /// Split a leading `@`/`+` STATUSMSG sigil off a channel target. Returns the
    /// sigil (if any) and the bare `#channel`. A sigil on a non-channel target
    /// is not a STATUSMSG and is left in place.
    fn split(target: &str) -> (Option<Self>, &str) {
        match target.as_bytes().first() {
            Some(b'@') if target[1..].starts_with('#') => (Some(Self::OpsOnly), &target[1..]),
            Some(b'+') if target[1..].starts_with('#') => (Some(Self::Voiced), &target[1..]),
            _ => (None, target),
        }
    }

    /// Whether a member with modes `m` is in this sigil's audience.
    fn admits(self, m: &crate::core::state::MemberModes) -> bool {
        match self {
            Self::OpsOnly => m.op,
            Self::Voiced => m.op || m.voice,
        }
    }
}

/// What a message target resolved to, once the sender was allowed to speak.
pub(super) enum ResolvedKind {
    Channel {
        key: crate::core::state::ChanKey,
        /// STATUSMSG sigil, or `None` for an ordinary channel message — it
        /// narrows the audience and keeps the message out of history.
        status_prefix: Option<StatusSigil>,
    },
    User {
        peer: ConnId,
    },
}

pub(super) struct ResolvedTarget {
    pub(super) kind: ResolvedKind,
    /// Everyone who receives it, the sender excluded.
    pub(super) recipients: Vec<Recipient>,
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
    let (status_prefix, chan_target) = StatusSigil::split(target);
    if !chan_target.starts_with('#') {
        let key = state.nick_key(target);
        let Some(peer) = state.registered_peer(&key) else {
            if loud {
                state.err_nosuchnick(conn, target);
            }
            return None;
        };
        return Some(ResolvedTarget {
            kind: ResolvedKind::User { peer },
            recipients: vec![state.local_recipient(peer)],
        });
    }
    let key = state.chan_key(chan_target);
    let Some(chan) = state.channels.get(&key) else {
        if loud {
            state.err_nosuchchannel(conn, clip_echo(target));
        }
        return None;
    };
    let may_speak = chan.may_speak(chan.member(conn), state.casemap, &prefix);
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
    // +C blocks CTCP (\x01-wrapped) except ACTION. `text` is a single message
    // body on the normal path and the `\n`-joined batch on the multiline path,
    // so the marker is checked on *every* line, not just the front of the blob:
    // a multiline batch is flattened back into one PRIVMSG per line for
    // non-multiline recipients, so a CTCP buried on line 2+ would otherwise
    // re-emerge as its own message and slip past +C. A single-line body has no
    // `\n`, so this is exactly `is_blocked_ctcp(text)` there.
    if chan.modes.no_ctcp && text.split('\n').any(is_blocked_ctcp) {
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
    let recipients = chan.recipients_where(|member, modes| {
        member != conn && status_prefix.is_none_or(|sig| sig.admits(modes))
    });
    Some(ResolvedTarget {
        kind: ResolvedKind::Channel { key, status_prefix },
        recipients,
    })
}

/// Truncate `text` on a UTF-8 char boundary so the relayed line
/// `:{prefix} {kind} {target} :{text}` fits the 512-byte wire limit (510 before
/// its CRLF). The source prefix is the server's addition, not the sender's, so
/// a message the sender was allowed to send can still overflow once relayed.
/// Trimming to fit is what keeps a strict client from discarding the line; it
/// must happen once, upstream of both delivery and history, so every observer
/// sees the same message.
fn fit_relayed_text<'a>(prefix: &str, kind: &str, target: &str, text: &'a str) -> &'a str {
    // ":" + prefix + " " + kind + " " + target + " :"
    let overhead = 1 + prefix.len() + 1 + kind.len() + 1 + target.len() + 2;
    let budget = 510usize.saturating_sub(overhead);
    e6irc_proto::message::truncate_on_char_boundary(text, budget)
}

pub(super) fn deliver_one_message(
    state: &mut ServerState,
    conn: ConnId,
    target: &str,
    text: &str,
    kind: crate::core::MessageKind,
    client_tags: &str,
    loud: bool,
) {
    // Services pseudo-clients intercept before the nick table. NOTICE
    // to services is dropped without reply (spec: NOTICE never triggers
    // automatic responses).
    let target_key = state.nick_key(target);
    if is_service_nick(target_key.as_str()) {
        // echo-message covers *every* message the client sends, including one
        // to a services pseudo-client — the echo is how such a client renders
        // its own outgoing line, so without it "/msg NickServ …" silently
        // vanishes from the sender's buffer. Echoed before the service's
        // reply, in send order, and captured so a labeled command's echo is
        // framed as its response like any other echo.
        if state.sessions[&conn].caps.echo_message {
            let prefix = state.sessions[&conn].prefix();
            let text = fit_relayed_text(&prefix, kind.wire(), target, text);
            let line = format!(":{prefix} {} {target} :{text}", kind.wire());
            let sender_account = state.sessions[&conn].account.clone();
            let sender_is_bot = state.sessions[&conn].bot;
            let (ts, msgid) = state.stamp();
            let sender = state.local_recipient(conn);
            deliver_message(
                state,
                &[sender],
                &Delivery {
                    sender_account: sender_account.as_deref(),
                    sender_is_bot,
                    msgid: &msgid,
                    client_tags,
                    body: &line,
                    ts,
                    bypass_capture: false,
                },
            );
        }
        if loud {
            services_dispatch(state, conn, target_key.as_str(), text);
        }
        return;
    }

    let (_, channel_target) = StatusSigil::split(target);
    if channel_target.starts_with('#') {
        let owner = state.channel_owner(channel_target);
        if !state.owns_channel(&owner) {
            let label = state.defer_channel_reply(conn);
            state.route_message(crate::core::state::ChannelMessage::new(
                owner,
                state.channel_actor(conn),
                target.to_string(),
                text.to_string(),
                kind,
                client_tags.to_string(),
                label,
            ));
            return;
        }
    }

    let prefix = state.sessions[&conn].prefix();
    // Permission/CTCP checks see the message as sent (CTCP markers and the
    // hostmask are at the front, which truncation never touches).
    let Some(resolved) = resolve_message_target(state, conn, target, text, loud) else {
        return;
    };
    // The server adds the source prefix the sender did not, so a max-length
    // message overflows the 512-byte wire limit on relay — a strict client then
    // discards or truncates the line. Trim the text to fit here, once, so live
    // recipients, the echo, and CHATHISTORY all carry the identical message
    // rather than each seeing a differently-cut or dropped copy.
    let text = fit_relayed_text(&prefix, kind.wire(), target, text);
    let line = format!(":{prefix} {} {target} :{text}", kind.wire());
    // One stamp, one delivery description, one history entry: the channel and
    // direct-message branches record the same message — only who receives it
    // and under which history key differs, so live delivery and CHATHISTORY
    // replay cannot drift. The delivery borrows the entry's fields, so the
    // entry moves into the branch's `record_history` call after delivery.
    let (ts, msgid) = state.stamp();
    let entry = crate::core::state::HistoryEntry {
        msgid,
        ts,
        sender_prefix: prefix.clone(),
        sender_account: state.sessions[&conn].account.clone(),
        kind,
        body: text.to_string(),
        sender_is_bot: state.sessions[&conn].bot,
        multiline: None,
    };
    let delivery = Delivery {
        sender_account: entry.sender_account.as_deref(),
        sender_is_bot: entry.sender_is_bot,
        msgid: &entry.msgid,
        client_tags,
        body: &line,
        ts: entry.ts,
        bypass_capture: true,
    };
    if let ResolvedKind::Channel { key, status_prefix } = resolved.kind {
        deliver_and_echo(state, conn, &resolved.recipients, &delivery);
        // A STATUSMSG (@#/+#) reached only ops/voiced members. It must not
        // enter the shared history ring or the messages table, or CHATHISTORY
        // would replay it to members who were excluded from the live delivery.
        if status_prefix.is_some() {
            return;
        }
        record_history(state, &(&key).into(), Vec::new(), entry);
    } else {
        let ResolvedKind::User { peer } = resolved.kind else {
            unreachable!("resolve_message_target returns Channel or User");
        };
        deliver_and_echo(state, conn, &resolved.recipients, &delivery);
        // The conversation is recorded once, under a key both participants
        // derive identically, so each side's CHATHISTORY sees the whole thread
        // rather than only the half it sent.
        let peer_nick = state.sessions[&peer]
            .nick()
            .map(String::from)
            .expect("registered");
        let (conv, peers) =
            state.dm_conversation(&state.conn_identity(conn), &state.conn_identity(peer));
        record_history(state, &conv, peers, entry);
        // Away auto-reply, PRIVMSG only (NOTICE must stay reply-free), and never
        // for a message to yourself — you don't need to be told you're away.
        if loud
            && peer != conn
            && let Some(away) = state.sessions[&peer].away.clone()
        {
            state.numeric(conn, RPL_AWAY, &[&peer_nick], Some(&away));
        }
    }
}

/// Execute one parsed channel message on its channel-owning shard.
pub(super) fn message_on_owner(
    state: &mut ServerState,
    message: crate::core::state::ChannelMessage,
) -> crate::core::state::ChannelMessageResult {
    let (owner, actor, target, message_text, kind, client_tags) = message.into_parts();
    let (status_prefix, chan_target) = StatusSigil::split(&target);
    let key = state.chan_key(chan_target);
    assert_eq!(
        owner.key(),
        &key,
        "message owner does not match its channel target"
    );
    let Some(channel) = state.channels.get(&key) else {
        return crate::core::state::ChannelMessageResult::NoSuchChannel {
            target,
            loud: kind.is_loud(),
        };
    };
    if !channel.may_speak(
        channel.member(actor.recipient.conn()),
        state.casemap,
        &actor.identity.prefix,
    ) {
        return crate::core::state::ChannelMessageResult::CannotSend {
            target,
            no_ctcp: false,
            loud: kind.is_loud(),
        };
    }
    if channel.modes.no_ctcp && message_text.split('\n').any(is_blocked_ctcp) {
        return crate::core::state::ChannelMessageResult::CannotSend {
            target,
            no_ctcp: true,
            loud: kind.is_loud(),
        };
    }
    let recipients = channel.recipients_where(|member, modes| {
        member != actor.recipient.conn() && status_prefix.is_none_or(|sig| sig.admits(modes))
    });
    let prefix = &actor.identity.prefix;
    let text = fit_relayed_text(prefix, kind.wire(), &target, &message_text);
    let line = format!(":{prefix} {} {target} :{text}", kind.wire());
    let (ts, msgid) = state.stamp();
    let entry = crate::core::state::HistoryEntry {
        msgid,
        ts,
        sender_prefix: prefix.clone(),
        sender_account: actor.account.clone(),
        kind,
        body: text.to_string(),
        sender_is_bot: actor.bot,
        multiline: None,
    };
    let delivery = Delivery {
        sender_account: entry.sender_account.as_deref(),
        sender_is_bot: entry.sender_is_bot,
        msgid: &entry.msgid,
        client_tags: &client_tags,
        body: &line,
        ts: entry.ts,
        bypass_capture: true,
    };
    deliver_message(state, &recipients, &delivery);
    let echo = actor
        .recipient
        .caps()
        .echo_message
        .then(|| render_delivery(actor.recipient.caps(), &delivery));
    if status_prefix.is_none() {
        record_history(state, &(&key).into(), Vec::new(), entry);
    }
    crate::core::state::ChannelMessageResult::Delivered { echo }
}

pub(super) fn emit_message_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelMessageResult,
    label: Option<String>,
) {
    state.emit_deferred_labeled(conn, label, |state| match result {
        crate::core::state::ChannelMessageResult::Delivered { echo } => {
            if let Some(echo) = echo {
                state.send_bytes(conn, echo);
            }
        }
        crate::core::state::ChannelMessageResult::NoSuchChannel { target, loud } => {
            if loud {
                state.err_nosuchchannel(conn, clip_echo(&target));
            }
        }
        crate::core::state::ChannelMessageResult::CannotSend {
            target,
            no_ctcp,
            loud,
        } => {
            if loud {
                state.numeric(
                    conn,
                    ERR_CANNOTSENDTOCHAN,
                    &[&target],
                    Some(if no_ctcp {
                        "Cannot send to channel (+C, no CTCP)"
                    } else {
                        "Cannot send to channel"
                    }),
                );
            }
        }
    });
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
    let Some(&targets) = p.first() else {
        state.numeric(
            conn,
            ERR_NORECIPIENT,
            &[],
            Some("No recipient given (TAGMSG)"),
        );
        return;
    };
    // Only client-only tags (`+` prefix) are relayed.
    let client_tags = crate::sanitize::client_tag_string(msg);
    // A comma-separated target list delivers to each recipient, deduped (by the
    // shared `unique_targets`) and bounded by TARGMAX — exactly as PRIVMSG/NOTICE
    // do. TAGMSG previously took only the first target, so `TAGMSG #a,#b` failed
    // with ERR_NOSUCHCHANNEL for the whole (unsplit) string while the identical
    // PRIVMSG syntax worked; sharing the splitter keeps them from drifting again.
    let ordered: Vec<String> = unique_targets(targets, state.casemap)
        .map(str::to_string)
        .collect();
    for (delivered, target) in ordered.into_iter().enumerate() {
        if delivered >= TARGMAX {
            state.numeric(
                conn,
                ERR_TOOMANYTARGETS,
                &[&target],
                Some("Too many targets; message not delivered"),
            );
            break;
        }
        deliver_one_tagmsg(state, conn, &target, &client_tags);
    }
}

/// Relay a TAGMSG to a single already-split `target` (channel, STATUSMSG-prefixed
/// channel, or nick). Mirrors `deliver_one_message`: an unknown/forbidden target
/// answers its own error numeric and delivers nothing, so one bad target in a
/// comma list does not stop the others.
fn deliver_one_tagmsg(state: &mut ServerState, conn: ConnId, target: &str, client_tags: &str) {
    let (_, channel_target) = StatusSigil::split(target);
    if channel_target.starts_with('#') {
        let owner = state.channel_owner(channel_target);
        if !state.owns_channel(&owner) {
            let label = state.defer_channel_reply(conn);
            state.route_tagmsg(crate::core::state::ChannelTagmsg::new(
                owner,
                state.channel_actor(conn),
                target.to_string(),
                client_tags.to_string(),
                label,
            ));
            return;
        }
    }
    let prefix = state.sessions[&conn].prefix();
    let msgid = state.next_msgid();
    // The sender's account/bot state. TAGMSG carries `account` (for account-tag
    // recipients) and `bot` (for a bot sender) exactly like PRIVMSG/NOTICE — the
    // IRCv3 account-tag and bot-mode specs list TAGMSG among the messages that
    // bear them, and identity/anti-spam tooling keying on these tags would
    // otherwise silently lose typing/reaction attribution.
    let sender_account = state.sessions[&conn].account.clone();
    let sender_is_bot = state.sessions[&conn].bot;
    let make_line = |server_time: Option<String>, account_tag: bool| {
        let mut tags = vec![format!("msgid={msgid}")];
        if let Some(t) = server_time {
            tags.push(format!("time={t}"));
        }
        if account_tag && let Some(account) = &sender_account {
            tags.push(format!(
                "account={}",
                e6irc_proto::message::escape_tag_value(account)
            ));
        }
        if sender_is_bot {
            tags.push("bot".to_string());
        }
        if !client_tags.is_empty() {
            tags.push(client_tags.to_string());
        }
        format!("@{} :{prefix} TAGMSG {target}", tags.join(";"))
    };

    // A STATUSMSG (`@#chan`/`+#chan`) is valid for TAGMSG too (message-tags
    // spec): route typing/reaction tags to the same op/voice subset PRIVMSG
    // would, rather than falling through to the nick branch and answering
    // ERR_NOSUCHNICK. The echoed `target` keeps the sigil, like PRIVMSG.
    let (status_prefix, chan_target) = StatusSigil::split(target);
    let recipients: Vec<ConnId> = if chan_target.starts_with('#') {
        let key = state.chan_key(chan_target);
        let Some(chan) = state.channels.get(&key) else {
            state.err_nosuchchannel(conn, clip_echo(target));
            return;
        };
        // The same gate PRIVMSG/NOTICE use, so a banned or quieted member can't
        // relay TAGMSG (typing/reaction tags) it couldn't relay as text.
        if !chan.may_speak(chan.member(conn), state.casemap, &prefix) {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[target],
                Some("Cannot send to channel"),
            );
            return;
        }
        chan.members()
            .filter(|(member, modes)| {
                *member != conn && status_prefix.is_none_or(|sig| sig.admits(modes))
            })
            .map(|(member, _)| member)
            .collect()
    } else {
        let key = state.nick_key(target);
        let Some(peer) = state.registered_peer(&key) else {
            state.err_nosuchnick(conn, target);
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
        let line = make_line(caps.server_time.then(|| time.clone()), caps.account_tag);
        // A delivery, not a response: bypass labeled-response capture.
        let bytes = bytes::Bytes::from(format!("{line}\r\n"));
        state.send_bytes_uncaptured(recipient, bytes);
    }
    if state.sessions[&conn].caps.echo_message {
        let caps = state.sessions[&conn].caps;
        let line = make_line(caps.server_time.then(|| time.clone()), caps.account_tag);
        state.send(conn, &line); // echo is the labeled response
    }
}

/// Execute one parsed channel TAGMSG on its channel-owning shard.
pub(super) fn tagmsg_on_owner(
    state: &mut ServerState,
    tagmsg: crate::core::state::ChannelTagmsg,
) -> crate::core::state::ChannelTagmsgResult {
    let (owner, actor, target, client_tags) = tagmsg.into_parts();
    let (status_prefix, channel_target) = StatusSigil::split(&target);
    let key = state.chan_key(channel_target);
    assert_eq!(
        owner.key(),
        &key,
        "TAGMSG owner does not match its channel target"
    );
    let Some(channel) = state.channels.get(&key) else {
        return crate::core::state::ChannelTagmsgResult::NoSuchChannel { target };
    };
    if !channel.may_speak(
        channel.member(actor.recipient.conn()),
        state.casemap,
        &actor.identity.prefix,
    ) {
        return crate::core::state::ChannelTagmsgResult::CannotSend { target };
    }
    let recipients = channel.recipients_where(|member, modes| {
        member != actor.recipient.conn() && status_prefix.is_none_or(|sig| sig.admits(modes))
    });
    let msgid = state.next_msgid();
    let time = state.time_tag();
    for recipient in recipients {
        let caps = recipient.caps();
        if caps.message_tags {
            state.send_recipient_uncaptured(
                recipient,
                render_tagmsg(&actor, &target, &client_tags, &msgid, &time, caps),
            );
        }
    }
    let echo = actor.recipient.caps().echo_message.then(|| {
        render_tagmsg(
            &actor,
            &target,
            &client_tags,
            &msgid,
            &time,
            actor.recipient.caps(),
        )
    });
    crate::core::state::ChannelTagmsgResult::Delivered { echo }
}

fn render_tagmsg(
    actor: &crate::core::state::ChannelActor,
    target: &str,
    client_tags: &str,
    msgid: &str,
    time: &str,
    caps: crate::core::state::Caps,
) -> bytes::Bytes {
    let mut tags = vec![format!("msgid={msgid}")];
    if caps.server_time {
        tags.push(format!("time={time}"));
    }
    if caps.account_tag
        && let Some(account) = &actor.account
    {
        tags.push(format!(
            "account={}",
            e6irc_proto::message::escape_tag_value(account)
        ));
    }
    if actor.bot {
        tags.push("bot".to_string());
    }
    if !client_tags.is_empty() {
        tags.push(client_tags.to_string());
    }
    bytes::Bytes::from(format!(
        "@{} :{} TAGMSG {target}\r\n",
        tags.join(";"),
        actor.identity.prefix
    ))
}

pub(super) fn emit_tagmsg_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelTagmsgResult,
    label: Option<String>,
) {
    state.emit_deferred_labeled(conn, label, |state| match result {
        crate::core::state::ChannelTagmsgResult::Delivered { echo } => {
            if let Some(echo) = echo {
                state.send_bytes(conn, echo);
            }
        }
        crate::core::state::ChannelTagmsgResult::NoSuchChannel { target } => {
            state.err_nosuchchannel(conn, clip_echo(&target));
        }
        crate::core::state::ChannelTagmsgResult::CannotSend { target } => {
            state.numeric(
                conn,
                ERR_CANNOTSENDTOCHAN,
                &[&target],
                Some("Cannot send to channel"),
            );
        }
    });
}

/// The `draft/multiline` capability, and the limits advertised as its value.
/// A client must be able to see them before it starts a batch it cannot finish.
pub(super) const MULTILINE_CAP: &str = "draft/multiline";
/// Total bytes of message text one multiline message may carry.
pub(crate) const MULTILINE_MAX_BYTES: usize = 4096;
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
    line.push_str(&super::fail_line(&server, "BATCH", code, context, detail));
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
            let client_tags = crate::sanitize::client_tag_string(msg);
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
            // The sender's multiline echo answers the *opening* BATCH's label,
            // which `deliver_multiline` applies to the echo inline. If the client
            // also labeled *this* close command, `dispatch` has a capture open for
            // that label — and the echo would be swallowed into it, producing a
            // line with two `label=` tags (the open's inline one plus the close's
            // injected one) and robbing the close of its own ACK. Park the close's
            // capture across delivery so the echo goes out uncaptured with only its
            // inline label; restore it (empty) so the close still gets its own ACK.
            let close_capture = state.capture.take();
            let (_, channel_target) = StatusSigil::split(&batch.target);
            let owner = state.channel_owner(channel_target);
            if !batch.lines.is_empty()
                && channel_target.starts_with('#')
                && !state.owns_channel(&owner)
            {
                state.route_multiline(crate::core::state::ChannelMultiline::new(
                    owner,
                    state.channel_actor(conn),
                    batch,
                ));
            } else {
                deliver_multiline(state, conn, batch);
            }
            state.capture = close_capture;
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
    if batch.lines.is_empty() {
        // Opened and closed without content: nothing happened — but if the
        // opening BATCH was labeled, that command still owes a response (the
        // framer was told not to ACK it when the batch opened), so the "no
        // response" ACK is emitted here or the client waits forever.
        ack_multiline_label(state, conn, batch.label.as_deref());
        return;
    }
    // A non-empty batch always carries the kind `multiline_collect` set from its
    // first line (and enforced identical across every line). `None` here would be
    // a collector logic bug, not client input — so surface it rather than silently
    // defaulting to PRIVMSG (which could deliver a NOTICE batch as PRIVMSG).
    let kind = batch
        .kind
        .expect("a non-empty multiline batch has a kind (set by multiline_collect)");
    let loud = kind.is_loud();
    // Permission checks see the whole message, so a CTCP or a ban cannot be
    // slipped past them by splitting it across lines. Crucially the join
    // respects `draft/multiline-concat`: a concat line is delivered joined to
    // the previous one with *no* separator, so it must be reconstructed the
    // same way here — otherwise a CTCP split across a concat boundary
    // (`\x01ACTION` + concat `VERSION\x01` → the blocked `\x01ACTIONVERSION\x01`)
    // has no single `\n`-delimited line that trips the +C check, yet a
    // concat-capable recipient reassembles the blocked CTCP. Non-concat lines
    // stay `\n`-separated so each is still checked as its own flattened
    // message (what a non-multiline recipient receives). This one string thus
    // mirrors both delivery forms.
    let mut joined = String::new();
    for (i, (text, concat)) in batch.lines.iter().enumerate() {
        if i > 0 && !*concat {
            joined.push('\n');
        }
        joined.push_str(text);
    }
    let Some(resolved) = resolve_message_target(state, conn, &batch.target, &joined, loud) else {
        // Refused (ban, +m, vanished channel, …): the refusal numeric was just
        // sent, but the *opening* BATCH's label is still owed a response — no
        // echo copy will ever carry it. Resolve it with an ACK, mirroring the
        // guarantee multiline_fail gives the collection-time failures.
        ack_multiline_label(state, conn, batch.label.as_deref());
        return;
    };
    let target = batch.target.as_str();
    let prefix = state.sessions[&conn].prefix();
    let sender_account = state.sessions[&conn].account.clone();
    let sender_is_bot = state.sessions[&conn].bot;
    let (ts, msgid) = state.stamp();
    let time = e6irc_proto::time::server_time(ts);
    let batch_ref = state.next_msgid();

    let echo_message = state.sessions[&conn].caps.echo_message;
    let mut audience: Vec<(Recipient, bool)> = resolved
        .recipients
        .iter()
        .map(|&c| (c, /* bypass_capture */ true))
        .collect();
    if echo_message {
        // A self-directed multiline correctly arrives twice with echo-message
        // (recipient copy + captured echo); only the echo carries the label.
        audience.push((state.local_recipient(conn), false));
    }
    for (recipient, bypass) in audience {
        let caps = recipient.caps();
        // Tags every form carries, in the order the other delivery path uses.
        let mut common: Vec<String> = Vec::new();
        if caps.server_time {
            common.push(format!("time={time}"));
        }
        if caps.account_tag
            && let Some(account) = sender_account.as_deref()
        {
            // The account name is a nick or an OIDC-sanitized name, both of which
            // can contain `\\` (a legal nick char) — a raw backslash in a tag value
            // is an escape introducer, so a client would decode `a\\b` as `ab` and
            // see a different account than the one that spoke. Escape it like any
            // tag value.
            common.push(format!(
                "account={}",
                e6irc_proto::message::escape_tag_value(account)
            ));
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
                    &format!("{tags}:{prefix} {} {target} :{text}", kind.wire()),
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
                // Flattened lines go to a client without draft/multiline, which
                // gets one PRIVMSG per line and holds each to the 512-byte limit
                // — so each is trimmed to fit, exactly as a single message is.
                // The batch form above is left full: its recipient negotiated
                // the capability and the larger frame that comes with it.
                let text = fit_relayed_text(&prefix, kind.wire(), target, text);
                send_multiline_line(
                    state,
                    recipient,
                    bypass,
                    &format!("{tags}:{prefix} {} {target} :{text}", kind.wire()),
                );
                first = false;
            }
        }
    }

    // The labeled response to the BATCH that opened this multiline rides the
    // sender's echo copy. A client that negotiated labeled-response + multiline
    // but NOT echo-message gets no such copy, so emit the labeled ACK explicitly
    // — otherwise it waits forever for a response (the framer was told not to ACK
    // the deferred batch). Mirrors the guarantee multiline_fail gives the failure
    // path.
    if !echo_message {
        ack_multiline_label(state, conn, batch.label.as_deref());
    }

    // Away auto-reply, PRIVMSG only — same as the single-line path (a multiline
    // DM to an away user must tell the sender they're away, once, just like an
    // ordinary PRIVMSG does; NOTICE stays reply-free).
    if loud
        && let ResolvedKind::User { peer } = &resolved.kind
        && *peer != conn
        && let Some(away) = state.sessions[peer].away.clone()
    {
        let peer_nick = state.sessions[peer]
            .nick()
            .map(String::from)
            .expect("registered");
        state.numeric(conn, RPL_AWAY, &[&peer_nick], Some(&away));
    }

    // History records what a client without the capability would have seen:
    // one entry per non-blank line, the first carrying the message's msgid.
    let (hist_key, peers) = match &resolved.kind {
        ResolvedKind::Channel { key, status_prefix } => {
            if status_prefix.is_some() {
                return; // STATUSMSG never enters history (see the other path)
            }
            (crate::core::state::HistoryKey::from(key), Vec::new())
        }
        ResolvedKind::User { peer } => {
            let (key, peers) =
                state.dm_conversation(&state.conn_identity(conn), &state.conn_identity(*peer));
            (key, peers)
        }
    };
    // A multiline message is ONE history entry carrying its single (live)
    // msgid and its lines encoded together, so CHATHISTORY reconstructs the
    // whole message under the id it was delivered with (per the CHATHISTORY
    // spec: "msgid MUST be the msgid as originally sent") — rather than one row
    // per line with fresh, never-delivered ids that a msgid-deduplicating client
    // would replay as brand-new messages. `body` holds a plain-line fallback (a
    // reader without the multiline field); `multiline` is authoritative on
    // replay. All lines are kept, blanks included, so the reconstructed batch
    // matches the live one; the flattened replay drops blanks as live does.
    let fallback = batch
        .lines
        .iter()
        .map(|(t, _)| t.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    record_history(
        state,
        &hist_key,
        peers,
        crate::core::state::HistoryEntry {
            msgid,
            ts,
            sender_prefix: prefix.clone(),
            sender_account: sender_account.clone(),
            kind,
            body: fallback,
            sender_is_bot,
            multiline: Some(encode_multiline(&batch.lines)),
        },
    );
}

pub(super) fn multiline_on_owner(
    state: &mut ServerState,
    message: crate::core::state::ChannelMultiline,
) -> crate::core::state::ChannelMultilineResult {
    let (owner, actor, batch) = message.into_parts();
    let kind = batch
        .kind
        .expect("completed non-empty multiline has a kind");
    let (status, channel_target) = StatusSigil::split(&batch.target);
    let key = state.chan_key(channel_target);
    assert_eq!(owner.key(), &key, "multiline owner does not match target");
    let Some(channel) = state.channels.get(&key) else {
        return crate::core::state::ChannelMultilineResult::NoSuchChannel {
            target: batch.target,
            loud: kind.is_loud(),
            label: batch.label,
        };
    };
    if !channel.may_speak(
        channel.member(actor.recipient.conn()),
        state.casemap,
        &actor.identity.prefix,
    ) {
        return crate::core::state::ChannelMultilineResult::CannotSend {
            target: batch.target,
            no_ctcp: false,
            loud: kind.is_loud(),
            label: batch.label,
        };
    }
    let joined = multiline_joined(&batch.lines);
    if channel.modes.no_ctcp && joined.split('\n').any(is_blocked_ctcp) {
        return crate::core::state::ChannelMultilineResult::CannotSend {
            target: batch.target,
            no_ctcp: true,
            loud: kind.is_loud(),
            label: batch.label,
        };
    }
    let recipients = channel.recipients_where(|member, modes| {
        member != actor.recipient.conn() && status.is_none_or(|sig| sig.admits(modes))
    });
    let (ts, msgid) = state.stamp();
    let batch_ref = state.next_msgid();
    for recipient in recipients {
        for line in render_multiline_lines(
            state,
            recipient.caps(),
            &actor,
            &batch,
            kind,
            ts,
            &msgid,
            &batch_ref,
            None,
        ) {
            state.send_recipient_uncaptured(recipient, line);
        }
    }
    let echo = if actor.recipient.caps().echo_message {
        render_multiline_lines(
            state,
            actor.recipient.caps(),
            &actor,
            &batch,
            kind,
            ts,
            &msgid,
            &batch_ref,
            batch.label.as_deref(),
        )
    } else {
        Vec::new()
    };
    if status.is_none() {
        let fallback = batch
            .lines
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        record_history(
            state,
            &(&key).into(),
            Vec::new(),
            crate::core::state::HistoryEntry {
                msgid,
                ts,
                sender_prefix: actor.identity.prefix.clone(),
                sender_account: actor.account.clone(),
                kind,
                body: fallback,
                sender_is_bot: actor.bot,
                multiline: Some(encode_multiline(&batch.lines)),
            },
        );
    }
    crate::core::state::ChannelMultilineResult::Delivered {
        echo,
        label: batch.label,
    }
}

fn multiline_joined(lines: &[(String, bool)]) -> String {
    let mut joined = String::new();
    for (index, (text, concat)) in lines.iter().enumerate() {
        if index > 0 && !concat {
            joined.push('\n');
        }
        joined.push_str(text);
    }
    joined
}

#[allow(clippy::too_many_arguments)]
fn render_multiline_lines(
    state: &ServerState,
    caps: crate::core::state::Caps,
    actor: &crate::core::state::ChannelActor,
    batch: &crate::core::state::MultilineBatch,
    kind: crate::core::MessageKind,
    ts: e6irc_proto::time::Millis,
    msgid: &str,
    batch_ref: &str,
    label: Option<&str>,
) -> Vec<bytes::Bytes> {
    let target = &batch.target;
    let prefix = &actor.identity.prefix;
    let mut common = Vec::new();
    if caps.server_time {
        common.push(format!("time={}", e6irc_proto::time::server_time(ts)));
    }
    if caps.account_tag
        && let Some(account) = &actor.account
    {
        common.push(format!(
            "account={}",
            e6irc_proto::message::escape_tag_value(account)
        ));
    }
    if actor.bot && caps.message_tags {
        common.push("bot".into());
    }
    let mut lines = Vec::new();
    if caps.multiline && caps.batch {
        let mut open = Vec::new();
        if let Some(label) = label {
            open.push(format!("label={label}"));
        }
        if caps.message_tags {
            open.push(format!("msgid={msgid}"));
            if !batch.client_tags.is_empty() {
                open.push(batch.client_tags.clone());
            }
        }
        open.extend(common.iter().cloned());
        lines.push(render_multiline_line(&format!(
            "{}:{prefix} BATCH +{batch_ref} {MULTILINE_CAP} {target}",
            tag_prefix(&open)
        )));
        for (text, concat) in &batch.lines {
            let mut tags = vec![format!("batch={batch_ref}")];
            if *concat && caps.message_tags {
                tags.push(MULTILINE_CONCAT_TAG.into());
            }
            tags.extend(common.iter().cloned());
            lines.push(render_multiline_line(&format!(
                "{}:{prefix} {} {target} :{text}",
                tag_prefix(&tags),
                kind.wire()
            )));
        }
        lines.push(render_multiline_line(&format!(
            ":{} BATCH -{batch_ref}",
            state.config.server_name
        )));
    } else {
        let mut first = true;
        for (text, _) in batch.lines.iter().filter(|(text, _)| !text.is_empty()) {
            let mut tags = Vec::new();
            if caps.message_tags {
                if first {
                    tags.push(format!("msgid={msgid}"));
                }
                if !batch.client_tags.is_empty() {
                    tags.push(batch.client_tags.clone());
                }
            }
            tags.extend(common.iter().cloned());
            let text = fit_relayed_text(prefix, kind.wire(), target, text);
            lines.push(render_multiline_line(&format!(
                "{}:{prefix} {} {target} :{text}",
                tag_prefix(&tags),
                kind.wire()
            )));
            first = false;
        }
    }
    lines
}

pub(super) fn emit_multiline_result(
    state: &mut ServerState,
    conn: ConnId,
    result: crate::core::state::ChannelMultilineResult,
) {
    match result {
        crate::core::state::ChannelMultilineResult::Delivered { echo, label } => {
            let has_echo = !echo.is_empty();
            for line in echo {
                state.send_bytes_uncaptured(conn, line);
            }
            if !has_echo {
                ack_multiline_label(state, conn, label.as_deref());
            }
        }
        crate::core::state::ChannelMultilineResult::NoSuchChannel {
            target,
            loud,
            label,
        } => {
            if loud {
                state.err_nosuchchannel(conn, clip_echo(&target));
            }
            ack_multiline_label(state, conn, label.as_deref());
        }
        crate::core::state::ChannelMultilineResult::CannotSend {
            target,
            no_ctcp,
            loud,
            label,
        } => {
            if loud {
                state.numeric(
                    conn,
                    ERR_CANNOTSENDTOCHAN,
                    &[&target],
                    Some(if no_ctcp {
                        "Cannot send to channel (+C, no CTCP)"
                    } else {
                        "Cannot send to channel"
                    }),
                );
            }
            ack_multiline_label(state, conn, label.as_deref());
        }
    }
}

/// Encode a multiline message's `(text, concat)` lines into one string for
/// history storage: each line is `0`/`1` (its concat flag) followed by its
/// text, lines joined by `\n`. A stored line's text never contains `\n` or NUL
/// (the parser rejects both on input), so the split is unambiguous and the
/// result is safe for a Postgres `TEXT` column. Inverse: [`decode_multiline`].
pub(super) fn encode_multiline(lines: &[(String, bool)]) -> String {
    lines
        .iter()
        .map(|(text, concat)| format!("{}{text}", if *concat { '1' } else { '0' }))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decode what [`encode_multiline`] produced back into `(text, concat)` lines.
pub(super) fn decode_multiline(encoded: &str) -> Vec<(String, bool)> {
    encoded
        .split('\n')
        .map(|line| {
            let concat = line.starts_with('1');
            (line.get(1..).unwrap_or_default().to_string(), concat)
        })
        .collect()
}

/// Answer a multiline batch's *opening* label with a bare `ACK`, when no other
/// line will carry it (empty batch, refused delivery, or no echo copy). The
/// framer was told not to ACK the opening BATCH when it deferred to the batch,
/// so every close-time outcome must resolve the label itself — a labeled
/// command with no response leaves a label-tracking client waiting forever.
/// Uncaptured: it answers the opening BATCH, not the current command.
fn ack_multiline_label(state: &mut ServerState, conn: ConnId, label: Option<&str>) {
    let Some(label) = label else {
        return;
    };
    let server = state.config.server_name.clone();
    state.send_bytes_uncaptured(
        conn,
        bytes::Bytes::from(format!("@label={label} :{server} ACK\r\n")),
    );
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
    recipient: Recipient,
    bypass_capture: bool,
    line: &str,
) {
    let bytes = render_multiline_line(line);
    if bypass_capture {
        state.send_recipient_uncaptured(recipient, bytes);
    } else {
        state.send_recipient(recipient, bytes);
    }
}

/// Render one already-formed multiline wire line.
///
/// Kept separate from delivery so channel owners can produce a sender echo as
/// data for its session owner, without touching that owner's output capture.
pub(super) fn render_multiline_line(line: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("{line}\r\n"))
}

/// Buffer one line of an open multiline batch. Returns true when the message
/// was part of a batch (and so must not be delivered on its own).
pub(super) fn multiline_collect(
    state: &mut ServerState,
    conn: ConnId,
    msg: &Message,
    p: &[&str],
    kind: crate::core::MessageKind,
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

#[cfg(test)]
mod tests {
    use super::is_blocked_ctcp;

    #[test]
    fn ctcp_action_exemption_matches_the_exact_tag() {
        // A genuine ACTION is exempt from +C: bare, with args, or empty-arg.
        assert!(!is_blocked_ctcp("\u{1}ACTION"));
        assert!(!is_blocked_ctcp("\u{1}ACTION waves\u{1}"));
        assert!(!is_blocked_ctcp("\u{1}ACTION\u{1}"));
        // A CTCP whose tag merely *starts with* ACTION is not ACTION and must
        // stay blocked — the prefix test would have leaked these through +C.
        assert!(is_blocked_ctcp("\u{1}ACTIONX\u{1}"));
        assert!(is_blocked_ctcp("\u{1}ACTIONVERSION\u{1}"));
        assert!(is_blocked_ctcp("\u{1}VERSION\u{1}"));
        // Plain text (no CTCP delimiter) is never blocked.
        assert!(!is_blocked_ctcp("hello ACTION"));
    }
}
