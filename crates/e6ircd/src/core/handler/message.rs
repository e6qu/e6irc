//! PRIVMSG/NOTICE/TAGMSG delivery, including multiline batches.

use super::*;
use crate::core::state::SpeakRefusal;

// ---- messaging ----------------------------------------------------------

/// A CTCP message is \x01-delimited; ACTION (/me) is exempt from +C.
pub(super) fn is_blocked_ctcp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.first() == Some(&0x01) && !is_ctcp_action(text)
}

/// Whether `text` is a CTCP whose tag is exactly `ACTION`; see
/// [`crate::sanitize::ctcp_action`], which the bridges read too.
fn is_ctcp_action(text: &str) -> bool {
    crate::sanitize::ctcp_action(text).is_some()
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
    unique_targets_indexed(targets, casemap).map(|(_, target)| target)
}

/// [`unique_targets`] with each kept target's *raw* comma position. JOIN keys
/// align to raw positions (`JOIN #a,,#c k1,k2` gives `#c` no key), so a caller
/// that pairs targets with a parallel list needs the position the fold-dedup
/// would otherwise hide.
pub(super) fn unique_targets_indexed(
    targets: &str,
    casemap: e6irc_proto::casemap::CaseMapping,
) -> impl Iterator<Item = (usize, &str)> {
    let mut seen = std::collections::HashSet::new();
    targets
        .split(',')
        .enumerate()
        .filter(move |(_, t)| !t.is_empty() && seen.insert(casemap.casefold(t)))
}

/// The recipients a message command's target parameter names, deduplicated
/// by [`unique_targets`]. `None` when it names none — the parameter is missing,
/// empty, or only commas (`PRIVMSG , :hi`) — so the caller answers
/// ERR_NORECIPIENT for every one of those shapes alike rather than splitting to
/// an empty list and silently sending nothing.
fn message_targets(state: &ServerState, p: &[&str]) -> Option<Vec<String>> {
    let targets: Vec<String> = unique_targets(p.first()?, state.casemap)
        .map(str::to_string)
        .collect();
    (!targets.is_empty()).then_some(targets)
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
    // A comma-separated target list delivers to each recipient, deduped (by
    // `unique_targets`) and bounded by TARGMAX (advertised in ISUPPORT). Past the
    // cap the message is refused loudly rather than silently truncated. A list
    // with no non-empty entry (`PRIVMSG , :hi`) names no recipient at all —
    // the same ERR_NORECIPIENT as a missing parameter, never a silent no-op.
    let Some(ordered) = message_targets(state, p) else {
        if loud {
            state.numeric(
                conn,
                ERR_NORECIPIENT,
                &[],
                Some(&format!("No recipient given ({})", kind.wire())),
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
    for (delivered, target) in ordered.into_iter().enumerate() {
        if delivered >= TARGMAX {
            if loud {
                state.numeric(
                    conn,
                    ERR_TOOMANYTARGETS,
                    &[Middle::echo(&target)],
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
    // A conversation with an unauthenticated party is never persisted. `~nick`
    // is not a person, it is whoever holds the nick right now: stored under it,
    // the conversation — and the list of who they talked to — would be handed
    // to the next stranger who takes the nick. It lives only in the ring, which
    // is purged when that party disconnects (`ServerState::close`); the other
    // party, authenticated or not, keeps it for exactly that long.
    //
    // Persist only when a database is configured (the same db-present proxy the
    // other DB writes use). Without one the hot ring is the entire record, so
    // there is nothing to enqueue — and enqueuing anyway would fail on every
    // message, flooding stderr and starving the core worker under load.
    if dm_peers.iter().any(|peer| peer.starts_with('~')) || !state.config.sasl_enabled {
        return state.push_history(key, entry);
    }
    let stored = entry.clone();
    state.push_history(key, entry);
    let body = stored.plain_body().into_owned();
    let log = crate::core::DbRequest::LogMessage {
        msgid: stored.msgid,
        target: key.as_str().to_string(),
        dm_peers,
        sender_prefix: stored.sender_prefix,
        sender_account: stored.sender_account,
        kind: stored.kind,
        body,
        sender_is_bot: stored.sender_is_bot,
        multiline: stored.multiline,
        client_tags: stored.client_tags,
        ts: stored.ts,
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

/// The one gate every channel message passes — PRIVMSG/NOTICE, a multiline
/// batch, TAGMSG — on whichever shard it is decided, so a ban, `+m`, `+n`, `+C`
/// or the STATUSMSG privilege cannot be evaded by choosing a different way to
/// send the same thing. `None` admits the message.
///
/// A STATUSMSG (`@#c`, `+#c`) may only be sent by a member holding op or voice
/// in that channel, whichever sigil it carries (Solanum's `is_chanop_voiced`
/// check, answered with ERR_CHANOPRIVSNEEDED): a plain member or an outsider
/// could otherwise page the channel's operators past `+m` and `+n`.
fn speak_refusal(
    chan: &crate::core::state::Channel,
    conn: ConnId,
    casemap: e6irc_proto::casemap::CaseMapping,
    subject: &crate::core::banmask::MaskSubject<'_>,
    status: Option<StatusSigil>,
    carries_blocked_ctcp: bool,
) -> Option<SpeakRefusal> {
    let member = chan.member(conn);
    if status.is_some() && !member.is_some_and(|m| m.op || m.voice) {
        return Some(SpeakRefusal::NotPrivileged);
    }
    if !chan.may_speak(member, casemap, subject) {
        return Some(SpeakRefusal::CannotSend);
    }
    // +C blocks CTCP (\x01-wrapped) except ACTION. The caller says whether the
    // body carries one in any form a recipient can receive it — see
    // `multiline_carries_blocked_ctcp` for why a batch has more than one form.
    if chan.modes.no_ctcp && carries_blocked_ctcp {
        return Some(SpeakRefusal::NoCtcp);
    }
    None
}

/// ERR_NONONREG: `nick`'s +R refused the sender, who is not logged in
/// (Solanum's `um_regonlymsg` wording).
pub(super) fn err_nonreg(state: &mut ServerState, conn: ConnId, nick: &str) {
    state.numeric(
        conn,
        ERR_NONONREG,
        &[Middle::own(nick)],
        Some("You must log in with services to message this user"),
    );
}

/// Tell the sender why [`speak_refusal`] refused its message to `target`.
fn emit_speak_refusal(state: &mut ServerState, conn: ConnId, target: &str, why: SpeakRefusal) {
    let (numeric, text) = match why {
        SpeakRefusal::NotPrivileged => (ERR_CHANOPRIVSNEEDED, "You're not a channel operator"),
        SpeakRefusal::CannotSend => (ERR_CANNOTSENDTOCHAN, "Cannot send to channel"),
        SpeakRefusal::NoCtcp => (ERR_CANNOTSENDTOCHAN, "Cannot send to channel (+C, no CTCP)"),
    };
    state.numeric(conn, numeric, &[Middle::echo(target)], Some(text));
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
        peer: std::sync::Arc<crate::core::state::PublicUser>,
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
    carries_blocked_ctcp: bool,
    loud: bool,
) -> Option<ResolvedTarget> {
    let prefix = state.sessions[&conn].prefix();
    // STATUSMSG: a leading @ or + restricts delivery to members with at
    // least that status. The prefix stays in the target echoed to
    // recipients.
    let (status_prefix, chan_target) = StatusSigil::split(target);
    if !chan_target.starts_with('#') {
        let key = state.nick_key(target);
        let Some(peer) = state.registered_user(&key) else {
            if loud {
                state.err_nosuchnick(conn, target);
            }
            return None;
        };
        // +R: only a logged-in sender (or an operator) reaches this user. A
        // NOTICE is refused silently, as every NOTICE refusal is.
        if peer.refuses_unregistered(conn, &state.sessions[&conn]) {
            if loud {
                err_nonreg(state, conn, &peer.nick);
            }
            return None;
        }
        return Some(ResolvedTarget {
            recipients: vec![peer.recipient],
            kind: ResolvedKind::User { peer },
        });
    }
    let key = state.chan_key(chan_target);
    let Some(chan) = state.channels.get(&key) else {
        if loud {
            state.err_nosuchchannel(conn, target);
        }
        return None;
    };
    let subject = state.sessions[&conn].mask_subject(&prefix);
    let refusal = speak_refusal(
        chan,
        conn,
        state.casemap,
        &subject,
        status_prefix,
        carries_blocked_ctcp,
    );
    if let Some(why) = refusal {
        if loud {
            emit_speak_refusal(state, conn, target, why);
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
            // A password or token sent to a service is not repeated back: the
            // echo lands in whatever the client logs or buffers.
            let shown = if crate::sanitize::sensitive_service_command(target, text) {
                crate::sanitize::SENSITIVE_SERVICE_COMMAND_REDACTED
            } else {
                text
            };
            let text = fit_relayed_text(&prefix, kind.wire(), target, shown);
            let line = format!(":{prefix} {} {target} :{text}", kind.wire());
            let sender_account = state.sessions[&conn].account().map(str::to_owned);
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
            let label = state.defer_captured_reply(conn);
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
    let Some(resolved) = resolve_message_target(state, conn, target, is_blocked_ctcp(text), loud)
    else {
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
        sender_account: state.sessions[&conn].account().map(str::to_owned),
        kind: kind.into(),
        body: text.to_string(),
        sender_is_bot: state.sessions[&conn].bot,
        multiline: None,
        client_tags: crate::sanitize::history_client_tags(client_tags),
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
        record_conversation(state, conn, &peer, entry);
        away_reply(state, conn, &peer, loud);
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
    if let Some(why) = speak_refusal(
        channel,
        actor.recipient.conn(),
        state.casemap,
        &actor.mask_subject(),
        status_prefix,
        is_blocked_ctcp(&message_text),
    ) {
        return crate::core::state::ChannelMessageResult::CannotSend {
            target,
            why,
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
        kind: kind.into(),
        body: text.to_string(),
        sender_is_bot: actor.bot,
        multiline: None,
        client_tags: crate::sanitize::history_client_tags(&client_tags),
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
                state.err_nosuchchannel(conn, &target);
            }
        }
        crate::core::state::ChannelMessageResult::CannotSend { target, why, loud } => {
            if loud {
                emit_speak_refusal(state, conn, &target, why);
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
            &[Middle::own("TAGMSG")],
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
    // A comma-separated target list delivers to each recipient, deduped (by the
    // shared `message_targets`) and bounded by TARGMAX — exactly as PRIVMSG/NOTICE
    // do. TAGMSG previously took only the first target, so `TAGMSG #a,#b` failed
    // with ERR_NOSUCHCHANNEL for the whole (unsplit) string while the identical
    // PRIVMSG syntax worked; sharing the splitter keeps them from drifting again.
    let Some(ordered) = message_targets(state, p) else {
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
    for (delivered, target) in ordered.into_iter().enumerate() {
        if delivered >= TARGMAX {
            state.numeric(
                conn,
                ERR_TOOMANYTARGETS,
                &[Middle::echo(&target)],
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
            let label = state.defer_captured_reply(conn);
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
    // A STATUSMSG (`@#chan`/`+#chan`) is valid for TAGMSG too (message-tags
    // spec): the same gate and op/voice subset PRIVMSG uses, so a banned or
    // quieted member can't relay TAGMSG (typing/reaction tags) it couldn't
    // relay as text. The echoed `target` keeps the sigil, like PRIVMSG.
    let Some(resolved) = resolve_message_target(state, conn, target, false, true) else {
        return;
    };
    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} TAGMSG {target}");
    let (ts, msgid) = state.stamp();
    let entry = tagmsg_history_entry(
        msgid,
        ts,
        prefix,
        state.sessions[&conn].account().map(str::to_owned),
        state.sessions[&conn].bot,
        client_tags,
    );
    // TAGMSG carries `account` (for account-tag recipients) and `bot` (for a
    // bot sender) exactly like PRIVMSG/NOTICE — the IRCv3 account-tag and
    // bot-mode specs list TAGMSG among the messages that bear them.
    let delivery = Delivery {
        sender_account: entry.sender_account.as_deref(),
        sender_is_bot: entry.sender_is_bot,
        msgid: &entry.msgid,
        client_tags,
        body: &line,
        ts: entry.ts,
        bypass_capture: true,
    };
    deliver_and_echo(
        state,
        conn,
        &tagmsg_audience(&resolved.recipients),
        &delivery,
    );
    match resolved.kind {
        ResolvedKind::Channel {
            status_prefix: Some(_),
            ..
        } => {} // STATUSMSG never enters history (see the PRIVMSG path)
        ResolvedKind::Channel { key, .. } => {
            if !entry.client_tags.is_empty() {
                record_history(state, &(&key).into(), Vec::new(), entry);
            }
        }
        ResolvedKind::User { peer } => {
            if !entry.client_tags.is_empty() {
                record_conversation(state, conn, &peer, entry);
            }
        }
    }
}

/// The recipients a TAGMSG reaches: those that negotiated `message-tags`. For
/// everyone else it must not exist at all.
fn tagmsg_audience(recipients: &[Recipient]) -> Vec<Recipient> {
    recipients
        .iter()
        .copied()
        .filter(|recipient| recipient.caps().message_tags)
        .collect()
}

/// The history entry of a TAGMSG: no text, the client-only tags history keeps
/// ([`crate::sanitize::history_client_tags`]). Empty tags mean there is nothing
/// to replay — a typing indicator, or a TAGMSG with no client tags — and the
/// caller records nothing.
fn tagmsg_history_entry(
    msgid: String,
    ts: e6irc_proto::time::Millis,
    sender_prefix: String,
    sender_account: Option<String>,
    sender_is_bot: bool,
    client_tags: &str,
) -> crate::core::state::HistoryEntry {
    crate::core::state::HistoryEntry {
        msgid,
        ts,
        sender_prefix,
        sender_account,
        kind: crate::core::HistoryKind::Tagmsg,
        body: String::new(),
        sender_is_bot,
        multiline: None,
        client_tags: crate::sanitize::history_client_tags(client_tags),
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
    if let Some(why) = speak_refusal(
        channel,
        actor.recipient.conn(),
        state.casemap,
        &actor.mask_subject(),
        status_prefix,
        false,
    ) {
        return crate::core::state::ChannelTagmsgResult::CannotSend { target, why };
    }
    let recipients = tagmsg_audience(&channel.recipients_where(|member, modes| {
        member != actor.recipient.conn() && status_prefix.is_none_or(|sig| sig.admits(modes))
    }));
    let line = format!(":{} TAGMSG {target}", actor.identity.prefix);
    let (ts, msgid) = state.stamp();
    let entry = tagmsg_history_entry(
        msgid,
        ts,
        actor.identity.prefix.clone(),
        actor.account.clone(),
        actor.bot,
        &client_tags,
    );
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
    if status_prefix.is_none() && !entry.client_tags.is_empty() {
        record_history(state, &(&key).into(), Vec::new(), entry);
    }
    crate::core::state::ChannelTagmsgResult::Delivered { echo }
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
            state.err_nosuchchannel(conn, &target);
        }
        crate::core::state::ChannelTagmsgResult::CannotSend { target, why } => {
            emit_speak_refusal(state, conn, &target, why);
        }
    });
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
    multiline_batch_fail(state, conn, label, code, context, detail);
}

/// `FAIL BATCH <code> [context] :<description>` for a batch already taken from
/// the session, under the label of the BATCH that opened it.
fn multiline_batch_fail(
    state: &mut ServerState,
    conn: ConnId,
    label: Option<String>,
    code: &str,
    context: &[&str],
    detail: &str,
) {
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
            // The reference is what every later `@batch=<reference>` line is
            // matched against; an empty one would be matched by a valueless
            // `@batch` tag, so it is refused at the one place a batch opens.
            if reference.is_empty() {
                multiline_fail(
                    state,
                    conn,
                    "MULTILINE_INVALID",
                    &[],
                    "Syntax: BATCH +<reference> draft/multiline <target>",
                );
                return;
            }
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
            // the framer must not ACK this as an empty response. Opening the
            // batch answers nothing on the spot, so every close-time outcome
            // answers the label on its own (see `ack_multiline_label`).
            debug_assert!(
                state.capture.as_ref().is_none_or(|c| c.lines.is_empty()),
                "a multiline batch open answered on the spot"
            );
            let label = state.defer_captured_label(conn);
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
    // A batch closed with no lines in it is no message at all: refused like
    // any other malformed batch, never answered with silence.
    if batch.lines.is_empty() {
        return multiline_batch_fail(
            state,
            conn,
            batch.label,
            "MULTILINE_INVALID",
            &[],
            "Empty batch",
        );
    }
    // Only blank lines: a blank line is a line break, not text, so a message
    // made only of them has no text in it -- exactly what ERR_NOTEXTTOSEND
    // refuses for a PRIVMSG, and what recipients without `draft/multiline`
    // would be sent: nothing. Stored instead, it became a history row that
    // replays as no line at all, so a page of N rows reached such a client as
    // fewer than N messages and read as the end of the buffer.
    if batch.lines.iter().all(|(text, _)| text.is_empty()) {
        if batch.kind.is_some_and(crate::core::MessageKind::is_loud) {
            state.numeric(conn, ERR_NOTEXTTOSEND, &[], Some("No text to send"));
        }
        // The opening BATCH was labeled, so that command still owes a response
        // (the framer was told not to ACK it when the batch opened), or the
        // client waits forever.
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
    // slipped past them by splitting it across lines.
    let Some(resolved) = resolve_message_target(
        state,
        conn,
        &batch.target,
        multiline_carries_blocked_ctcp(&batch.lines),
        loud,
    ) else {
        // Refused (ban, +m, vanished channel, …): the refusal numeric was just
        // sent, but the *opening* BATCH's label is still owed a response — no
        // echo copy will ever carry it. Resolve it with an ACK, mirroring the
        // guarantee multiline_fail gives the collection-time failures.
        ack_multiline_label(state, conn, batch.label.as_deref());
        return;
    };
    let prefix = state.sessions[&conn].prefix();
    let sender_account = state.sessions[&conn].account().map(str::to_owned);
    let (ts, msgid) = state.stamp();
    let batch_ref = state.next_msgid();
    let server = state.config.server_name.clone();
    let message = MultilineMessage {
        prefix: &prefix,
        kind,
        target: &batch.target,
        lines: &batch.lines,
        client_tags: &batch.client_tags,
        msgid: &msgid,
        ts,
        account: sender_account.as_deref(),
        bot: state.sessions[&conn].bot,
    };

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
        let framing = MultilineFraming {
            caps: recipient.caps().into(),
            batch_ref: &batch_ref,
            outer_batch: None,
            // Only the sender's own copy is the labeled response to its command.
            label: batch.label.as_deref().filter(|_| !bypass),
            server: &server,
        };
        for line in render_multiline(&message, &framing) {
            send_multiline_line(state, recipient, bypass, &line);
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
    if let ResolvedKind::User { peer } = &resolved.kind {
        away_reply(state, conn, peer, loud);
    }

    let entry = multiline_history_entry(&message);
    match &resolved.kind {
        // STATUSMSG never enters history (see the other path).
        ResolvedKind::Channel {
            status_prefix: Some(_),
            ..
        } => {}
        ResolvedKind::Channel { key, .. } => record_history(state, &key.into(), Vec::new(), entry),
        ResolvedKind::User { peer } => record_conversation(state, conn, peer, entry),
    }
}

/// Record a direct message in its conversation. The conversation is recorded
/// under a key both participants derive identically, so each side's
/// CHATHISTORY sees the whole thread rather than only the half it sent — and a
/// ring belongs to a shard, so when the two sessions live on different shards
/// the peer's shard is sent the entry to keep its own copy. Only this shard
/// persists it (see `record_history`); the copy is for the ring alone.
fn record_conversation(
    state: &mut ServerState,
    conn: ConnId,
    peer: &crate::core::state::PublicUser,
    entry: crate::core::state::HistoryEntry,
) {
    let (key, peers) =
        state.dm_conversation(&state.conn_identity(conn), &peer.identity(state.casemap));
    let session = peer.recipient.owner();
    if !state.owns_session(session) {
        state.route_input(crate::core::Input::ConversationEntry {
            session,
            key: key.clone(),
            entry: entry.clone(),
        });
    }
    record_history(state, &key, peers, entry);
}

/// Away auto-reply, PRIVMSG only (NOTICE must stay reply-free), and never for a
/// message to yourself — you don't need to be told you're away.
fn away_reply(
    state: &mut ServerState,
    conn: ConnId,
    peer: &crate::core::state::PublicUser,
    loud: bool,
) {
    if loud
        && peer.conn() != conn
        && let Some(away) = &peer.away
    {
        state.numeric(conn, RPL_AWAY, &[Middle::own(&peer.nick)], Some(away));
    }
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
    if let Some(why) = speak_refusal(
        channel,
        actor.recipient.conn(),
        state.casemap,
        &actor.mask_subject(),
        status,
        multiline_carries_blocked_ctcp(&batch.lines),
    ) {
        return crate::core::state::ChannelMultilineResult::CannotSend {
            target: batch.target,
            why,
            loud: kind.is_loud(),
            label: batch.label,
        };
    }
    let recipients = channel.recipients_where(|member, modes| {
        member != actor.recipient.conn() && status.is_none_or(|sig| sig.admits(modes))
    });
    let (ts, msgid) = state.stamp();
    let batch_ref = state.next_msgid();
    let server = state.config.server_name.clone();
    let message = MultilineMessage {
        prefix: &actor.identity.prefix,
        kind,
        target: &batch.target,
        lines: &batch.lines,
        client_tags: &batch.client_tags,
        msgid: &msgid,
        ts,
        account: actor.account.as_deref(),
        bot: actor.bot,
    };
    let render = |caps: crate::core::state::Caps, label: Option<&str>| {
        render_multiline(
            &message,
            &MultilineFraming {
                caps: caps.into(),
                batch_ref: &batch_ref,
                outer_batch: None,
                label,
                server: &server,
            },
        )
        .iter()
        .map(|line| render_multiline_line(line))
        .collect::<Vec<_>>()
    };
    for recipient in recipients {
        for line in render(recipient.caps(), None) {
            state.send_recipient_uncaptured(recipient, line);
        }
    }
    let echo = if actor.recipient.caps().echo_message {
        render(actor.recipient.caps(), batch.label.as_deref())
    } else {
        Vec::new()
    };
    if status.is_none() {
        let entry = multiline_history_entry(&message);
        record_history(state, &(&key).into(), Vec::new(), entry);
    }
    crate::core::state::ChannelMultilineResult::Delivered {
        echo,
        label: batch.label,
    }
}

/// Whether `+C` must refuse this batch: whether any message a recipient can
/// receive from it is a blocked CTCP. A batch reaches recipients in two forms,
/// and a CTCP may exist in only one of them:
///
/// - A recipient with `draft/multiline` reassembles it, joining a
///   `draft/multiline-concat` line to the one before with no separator. A CTCP
///   split across that boundary (`\x01ACTION` + concat `VERSION\x01`) is no
///   CTCP on any raw line, yet reassembles into `\x01ACTIONVERSION\x01`.
/// - A recipient without it is sent every raw line as its own message. A CTCP
///   that is a concat continuation (`hi` + concat `\x01VERSION\x01`) starts no
///   reassembled line, yet arrives bare.
fn multiline_carries_blocked_ctcp(lines: &[(String, bool)]) -> bool {
    let mut reassembled = String::new();
    for (index, (text, concat)) in lines.iter().enumerate() {
        if index > 0 && !concat {
            reassembled.push('\n');
        }
        reassembled.push_str(text);
    }
    reassembled.split('\n').any(is_blocked_ctcp)
        || lines.iter().any(|(raw, _)| is_blocked_ctcp(raw))
}

/// The one history entry a multiline message is kept as: its single (live)
/// msgid and its lines encoded together, so CHATHISTORY reconstructs the whole
/// message under the id it was delivered with (per the CHATHISTORY spec: "msgid
/// MUST be the msgid as originally sent") — rather than one row per line with
/// fresh, never-delivered ids that a msgid-deduplicating client would replay as
/// brand-new messages. `multiline` holds the text, and `body` is left empty:
/// the text is held once, and its plain-line form (what the database's `body`
/// column and the REST history carry) is derived from it
/// ([`crate::core::HistoryRow::plain_body`]). All lines are kept, blanks
/// included, so the reconstructed batch matches the live one; the flattened
/// replay drops blanks as live does.
fn multiline_history_entry(message: &MultilineMessage) -> crate::core::state::HistoryEntry {
    crate::core::state::HistoryEntry {
        msgid: message.msgid.to_string(),
        ts: message.ts,
        sender_prefix: message.prefix.to_string(),
        sender_account: message.account.map(str::to_owned),
        kind: message.kind.into(),
        body: String::new(),
        sender_is_bot: message.bot,
        multiline: Some(encode_multiline(message.lines)),
        client_tags: crate::sanitize::history_client_tags(message.client_tags),
    }
}

/// One multiline message — as delivered live, and as history rebuilds it.
pub(super) struct MultilineMessage<'a> {
    pub(super) prefix: &'a str,
    pub(super) kind: crate::core::MessageKind,
    pub(super) target: &'a str,
    pub(super) lines: &'a [(String, bool)],
    /// The client-only tags the batch was opened with, as relayed.
    pub(super) client_tags: &'a str,
    pub(super) msgid: &'a str,
    pub(super) ts: e6irc_proto::time::Millis,
    pub(super) account: Option<&'a str>,
    pub(super) bot: bool,
}

/// How one recipient's copy of a [`MultilineMessage`] is framed.
pub(super) struct MultilineFraming<'a> {
    pub(super) caps: crate::core::HistoryResponseCaps,
    /// Reference of the `draft/multiline` batch: fresh for each rendering.
    pub(super) batch_ref: &'a str,
    /// The batch the message sits in — the CHATHISTORY batch on replay.
    pub(super) outer_batch: Option<&'a str>,
    /// The sender's own copy answers the label of the BATCH that opened it.
    pub(super) label: Option<&'a str>,
    pub(super) server: &'a str,
}

/// Render a multiline message for one recipient, lines without CRLF. The one
/// renderer live delivery (local and channel-owner) and CHATHISTORY replay
/// share, so a replayed message is the one delivered.
///
/// A recipient that negotiated `draft/multiline` and `batch` gets the batch as
/// sent — blank lines and `draft/multiline-concat` tags intact. Every line in
/// it is still an ordinary IRC line held to the 512-byte limit: a line the
/// relay's source prefix would push past it is split on a character boundary,
/// its continuations marked `draft/multiline-concat` (the capability's way of
/// carrying one logical line in several), or trimmed for a recipient without
/// `message-tags`, which cannot be told a line continues. Anyone else gets one
/// message per non-blank line, each trimmed to fit, the msgid on the first.
pub(super) fn render_multiline(
    message: &MultilineMessage,
    framing: &MultilineFraming,
) -> Vec<String> {
    let caps = framing.caps;
    let verb = message.kind.wire();
    let target = message.target;
    let prefix = message.prefix;
    let head = format!(":{prefix} {verb} {target} :");
    let outer: Vec<String> = framing
        .outer_batch
        .map(|outer| format!("batch={outer}"))
        .into_iter()
        .collect();
    let client_tags = (caps.message_tags && !message.client_tags.is_empty())
        .then(|| message.client_tags.to_string());
    let mut lines = Vec::new();
    if caps.multiline && caps.batch {
        let batch_ref = framing.batch_ref;
        let mut open = outer.clone();
        open.extend(framing.label.map(|label| format!("label={label}")));
        open.extend(caps.event_tags(
            message.ts,
            Some(message.msgid),
            message.account,
            message.bot,
        ));
        open.extend(client_tags);
        lines.push(format!(
            "{}:{prefix} BATCH +{batch_ref} {MULTILINE_CAP} {target}",
            tag_prefix(&open)
        ));
        let common = caps.event_tags(message.ts, None, message.account, message.bot);
        for (text, concat) in message.lines {
            for (index, piece) in split_to_fit(&head, text, caps.message_tags)
                .into_iter()
                .enumerate()
            {
                let mut tags = vec![format!("batch={batch_ref}")];
                tags.extend(common.iter().cloned());
                if caps.message_tags && (*concat || index > 0) {
                    tags.push(MULTILINE_CONCAT_TAG.to_string());
                }
                lines.push(format!("{}{head}{piece}", tag_prefix(&tags)));
            }
        }
        lines.push(format!(
            "{}:{} BATCH -{batch_ref}",
            tag_prefix(&outer),
            framing.server
        ));
    } else {
        let outer: Vec<String> = if caps.batch { outer } else { Vec::new() };
        let mut first = true;
        for (text, _) in message.lines.iter().filter(|(text, _)| !text.is_empty()) {
            let mut tags = outer.clone();
            tags.extend(caps.event_tags(
                message.ts,
                first.then_some(message.msgid),
                message.account,
                message.bot,
            ));
            tags.extend(client_tags.clone());
            let text = super::fit_trailing(&head, text);
            lines.push(format!("{}{head}{text}", tag_prefix(&tags)));
            first = false;
        }
    }
    lines
}

/// `text` as the trailing of lines starting `head`, each within the wire
/// limit: in pieces cut on character boundaries when `continuable` (the pieces
/// after the first continue the line), or trimmed to the first piece when not.
fn split_to_fit<'a>(head: &str, text: &'a str, continuable: bool) -> Vec<&'a str> {
    let mut pieces = Vec::new();
    let mut rest = text;
    loop {
        let mut piece = super::fit_trailing(head, rest);
        if piece.is_empty() && !rest.is_empty() {
            // A budget narrower than one character still moves forward.
            let width = rest.chars().next().map_or(0, char::len_utf8);
            piece = &rest[..width];
        }
        pieces.push(piece);
        rest = &rest[piece.len()..];
        if rest.is_empty() || !continuable {
            return pieces;
        }
    }
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
                state.err_nosuchchannel(conn, &target);
            }
            ack_multiline_label(state, conn, label.as_deref());
        }
        crate::core::state::ChannelMultilineResult::CannotSend {
            target,
            why,
            loud,
            label,
        } => {
            if loud {
                emit_speak_refusal(state, conn, &target, why);
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

/// A multiline message's text as one plain line: its lines, blanks included,
/// joined with spaces — what the database's `body` column holds for it.
pub(crate) fn multiline_plain_text(encoded: &str) -> String {
    decode_multiline(encoded)
        .iter()
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
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
    let Some(tag) = msg.tags.iter().find(|t| t.key == "batch") else {
        return false;
    };
    // A valueless `@batch` names no batch. It is a batch claim all the same,
    // so it is judged as one — an unknown reference, refused — rather than
    // quietly delivered as an ordinary message the sender did not send.
    // (An open batch always has a non-empty reference; `cmd_batch` refuses
    // `BATCH +`, so the empty string can never match one.)
    let reference = tag.value.as_deref().unwrap_or("");
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
    // Every line of a batch is part of one message to one target. A line
    // addressed elsewhere is the spec's MULTILINE_INVALID_TARGET, and the
    // batch is abandoned: the message it was building cannot be completed.
    let batch_target = state.sessions[&conn]
        .multiline
        .as_ref()
        .map(|b| b.target.clone())
        .expect("matched above");
    let line_target = p.first().copied().unwrap_or("");
    if state.casemap.casefold(line_target) != state.casemap.casefold(&batch_target) {
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID_TARGET",
            &[&batch_target, line_target],
            "Multiline batch target does not match message target",
        );
        return true;
    }
    let text = p.get(1).copied().unwrap_or("");
    let concat = msg.tags.iter().any(|t| t.key == MULTILINE_CONCAT_TAG);
    let first_line = state.sessions[&conn]
        .multiline
        .as_ref()
        .is_some_and(|b| b.lines.is_empty());
    if concat && first_line {
        // There is no previous line to concatenate onto (the spec forbids the
        // tag on a batch's first message), and dropping the tag would change
        // what the sender wrote.
        multiline_fail(
            state,
            conn,
            "MULTILINE_INVALID",
            &[],
            "The concat tag cannot be used on the first message of a batch",
        );
        return true;
    }
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

    /// A multiline message's history entry holds its text once, in
    /// `multiline`; the plain line the database stores is derived from it and
    /// is what joining the lines always gave, blanks included.
    #[test]
    fn a_multiline_history_entry_holds_its_text_once() {
        let lines = [
            ("hello".to_string(), false),
            (String::new(), false),
            ("world".to_string(), true),
        ];
        let message = super::MultilineMessage {
            prefix: "alice!a@host",
            kind: crate::core::MessageKind::Privmsg,
            target: "#m",
            lines: &lines,
            client_tags: "",
            msgid: "id",
            ts: e6irc_proto::time::Millis::from_millis(1),
            account: None,
            bot: false,
        };
        let entry = super::multiline_history_entry(&message);
        assert!(entry.body.is_empty(), "{:?}", entry.body);
        assert_eq!(
            entry.multiline.as_deref(),
            Some(super::encode_multiline(&lines).as_str())
        );
        assert_eq!(entry.plain_body(), "hello  world");
    }

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
