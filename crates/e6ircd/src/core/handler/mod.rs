//! Command dispatch: one inbound line → state transitions + replies.

use e6irc_proto::message::Message;
use e6irc_proto::numerics::*;

use super::ConnId;
use super::state::{
    BanKind, CAP_NAMES, ChanKey, Channel, MemberModes, ServerBan, ServerState, Topic,
};

mod channel;
mod chanops;
mod history;
pub(crate) mod message;
mod monitor;
mod oper;
mod query;
mod read_marker;
mod registration;
mod sasl;
mod services;

use channel::*;
use chanops::*;
pub(crate) use history::*;
use message::*;
pub(crate) use monitor::*;
use oper::*;
use query::*;
use read_marker::*;
use registration::*;
pub(crate) use sasl::*;
use services::*;

pub(crate) fn overlong(state: &mut ServerState, conn: ConnId) {
    state.numeric(conn, ERR_INPUTTOOLONG, &[], Some("Input line was too long"));
}

pub(crate) fn dispatch(state: &mut ServerState, conn: ConnId, line: &[u8]) {
    if !state.sessions.contains_key(&conn) {
        return; // line raced a close; session already gone
    }
    let server = state.config.server_name.clone();
    let Ok(text) = std::str::from_utf8(line) else {
        state.send(
            conn,
            &format!(":{server} FAIL * INVALID_UTF8 :Message rejected, not valid UTF-8"),
        );
        return;
    };
    // Length limits per message-tags: 4096 bytes of client tag section
    // (including '@' and the separating space), 510 for the rest.
    let (tag_len, body_len) = match text.strip_prefix('@').and_then(|t| t.split_once(' ')) {
        Some((tags, rest)) => (tags.len() + 2, rest.len()),
        None => (0, text.len()),
    };
    if tag_len > 4096 || body_len > 510 {
        state.numeric(conn, ERR_INPUTTOOLONG, &[], Some("Input line was too long"));
        return;
    }
    let msg = match Message::parse(text) {
        Ok(m) => m,
        Err(_) => {
            state.send(
                conn,
                &format!(":{server} FAIL * INVALID_MESSAGE :Malformed line"),
            );
            return;
        }
    };

    // labeled-response: capture direct replies and frame them under the
    // label. Only for clients that negotiated the cap and sent a label.
    // Re-escape the label: the parser hands us the unescaped tag value, and
    // it is echoed back into the tag section of every framed reply. Without
    // re-escaping, a value like `a\s\nb` would inject a space/newline into the
    // client's own stream and corrupt the labeled response.
    let label = msg
        .tag("label")
        .and_then(|t| t.value.as_deref())
        .filter(|_| state.sessions[&conn].caps.labeled_response)
        .map(e6irc_proto::message::escape_tag_value);
    if let Some(label) = label {
        state.capture = Some(super::state::Capture {
            conn,
            lines: Vec::new(),
            label: Some(label.to_string()),
            deferred: false,
        });
        dispatch_parsed(state, conn, &msg);
        let cap = state.capture.take();
        // A handler that deferred its response to an async path (CHATHISTORY →
        // PostgreSQL) emits its own labeled batch when the reply lands; framing
        // an empty ACK here would wrongly tell the client there was no response.
        if cap.as_ref().is_some_and(|c| c.deferred) {
            return;
        }
        let captured = cap.map(|c| c.lines).unwrap_or_default();
        frame_labeled(state, conn, &label, captured);
        return;
    }
    dispatch_parsed(state, conn, &msg);
}

/// Fit a trailing parameter to the wire limit: the largest prefix of `text`
/// such that `head` + text (+ CRLF) stays within 512 bytes, cut on a UTF-8
/// char boundary. `head` is everything already on the line, including the
/// `" :"` — so the budget can never drift from the line actually built.
///
/// The reason-bearing relays (TOPIC, KICK, PART, QUIT) need this for the same
/// reason PRIVMSG does (`fit_relayed_text`): the sender's input was within the
/// limit, but the relay carries a source prefix the sender never wrote, and a
/// recipient's framing discards an over-long line whole.
pub(crate) fn fit_trailing<'a>(head: &str, text: &'a str) -> &'a str {
    e6irc_proto::message::truncate_on_char_boundary(text, 510usize.saturating_sub(head.len()))
}

/// Clip a client-supplied token for echoing inside a reply. Numerics that
/// attribute an error echo the offending token (an unknown command, a bad CAP
/// subcommand, a rejected target list); the token's length is bounded only by
/// the input frame, so echoing it whole can push the reply past the wire limit
/// and the recipient's framing then discards the very line explaining the
/// error. 64 bytes identifies anything; every reply shape stays well inside
/// the limit with room for its other, server-bounded parameters.
pub(crate) fn clip_echo(token: &str) -> &str {
    e6irc_proto::message::truncate_on_char_boundary(token, 64)
}

/// Inject a tag into the front of an already-serialized wire line
/// (CRLF included), merging with any existing `@tags`.
fn inject_tag(line: &[u8], tag: &str) -> bytes::Bytes {
    let body = &line[..line.len().saturating_sub(2)]; // strip CRLF
    let mut out = Vec::with_capacity(line.len() + tag.len() + 2);
    if let Some(rest) = body.strip_prefix(b"@") {
        out.extend_from_slice(b"@");
        out.extend_from_slice(tag.as_bytes());
        out.push(b';');
        out.extend_from_slice(rest);
    } else {
        out.extend_from_slice(b"@");
        out.extend_from_slice(tag.as_bytes());
        out.push(b' ');
        out.extend_from_slice(body);
    }
    out.extend_from_slice(b"\r\n");
    bytes::Bytes::from(out)
}

/// Frame captured direct responses per the labeled-response spec:
/// zero lines → ACK; one → label-tagged; many → labeled batch.
fn frame_labeled(state: &mut ServerState, conn: ConnId, label: &str, lines: Vec<bytes::Bytes>) {
    let server = state.config.server_name.clone();
    match lines.len() {
        0 => state.send(conn, &format!("@label={label} :{server} ACK")),
        1 => {
            let tagged = inject_tag(&lines[0], &format!("label={label}"));
            state.send_bytes(conn, tagged);
        }
        _ if is_self_contained_batch(&lines) => {
            // The captured reply is already one batch (e.g. CHATHISTORY). Label
            // its opening BATCH line rather than nesting it in another batch —
            // a message must never carry two `batch` tags.
            let mut it = lines.into_iter();
            let open = it.next().expect("len >= 2");
            state.send_bytes(conn, inject_tag(&open, &format!("label={label}")));
            for line in it {
                state.send_bytes(conn, line);
            }
        }
        _ => {
            let batch_ref = state.next_msgid();
            state.send(
                conn,
                &format!("@label={label} :{server} BATCH +{batch_ref} labeled-response"),
            );
            for line in lines {
                let tagged = inject_tag(&line, &format!("batch={batch_ref}"));
                state.send_bytes(conn, tagged);
            }
            state.send(conn, &format!(":{server} BATCH -{batch_ref}"));
        }
    }
}

/// Whether `lines` is a single self-contained batch: the first line opens a
/// `BATCH +ref` and the last closes the same `BATCH -ref`.
fn is_self_contained_batch(lines: &[bytes::Bytes]) -> bool {
    let Some(first) = lines.first() else {
        return false;
    };
    let Some(last) = lines.last() else {
        return false;
    };
    let first = String::from_utf8_lossy(first);
    let last = String::from_utf8_lossy(last);
    match (batch_ref_after(&first, '+'), batch_ref_after(&last, '-')) {
        (Some(open), Some(close)) => open == close,
        _ => false,
    }
}

/// The batch reference following `BATCH <sign>` in a serialized line, if any.
fn batch_ref_after(line: &str, sign: char) -> Option<&str> {
    let marker = if sign == '+' { "BATCH +" } else { "BATCH -" };
    let rest = &line[line.find(marker)? + marker.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Spend one command-flood token. Returns `true` if the command may
/// proceed, `false` if the bucket is empty (the caller closes the link).
/// No-op (always `true`) when the throttle is off, or for pre-registered
/// and oper sessions. Refills one token per elapsed second up to the
/// configured burst; a zero `flood_refilled_to_ms` (fresh session) refills
/// to full on the first command.
fn flood_ok(state: &mut ServerState, conn: ConnId) -> bool {
    let Some(burst) = state.config.command_burst else {
        return true;
    };
    {
        let s = &state.sessions[&conn];
        if !s.registered || s.oper {
            return true;
        }
    }
    let now = (state.config.clock)();
    let s = state.sessions.get_mut(&conn).expect("session present");
    // The clock is milliseconds but the bucket refills per whole second, so
    // credit only elapsed whole seconds and advance the watermark by exactly
    // what was credited — otherwise sub-second command bursts would keep
    // resetting the watermark and the bucket would never refill at all.
    let refill = now.saturating_sub(s.flood_refilled_to_ms).as_secs();
    let tokens = (u64::from(s.flood_tokens) + refill).min(burst as u64) as u32;
    s.flood_refilled_to_ms = s.flood_refilled_to_ms.saturating_add_millis(refill * 1000);
    if tokens == 0 {
        return false;
    }
    s.flood_tokens = tokens - 1;
    true
}

fn dispatch_parsed(state: &mut ServerState, conn: ConnId, msg: &Message) {
    let server = state.config.server_name.clone();
    let command = msg.command.to_ascii_uppercase();
    let p = &msg.params;

    // Command-flood throttle (opt-in). Keepalive is exempt; a depleted
    // bucket closes the link loudly (Excess Flood), never silently drops.
    if command != "PING" && command != "PONG" && !flood_ok(state, conn) {
        state.send(
            conn,
            &format!("ERROR :Closing Link: {server} (Excess Flood)"),
        );
        state.close(conn, "Excess Flood");
        return;
    }

    // Track activity for WHOIS idle / WHOX `l` (keepalive doesn't count).
    if command != "PING"
        && command != "PONG"
        && let Some(session) = state.sessions.get_mut(&conn)
    {
        session.last_active = (state.config.clock)();
        // Any client line proves liveness, so it also answers an outstanding
        // liveness PING — the reaper mustn't close an actively-talking client
        // just because it didn't send a literal PONG.
        session.awaiting_pong = false;
    }

    // Commands legal before registration.
    match command.as_str() {
        "CAP" => return cmd_cap(state, conn, p),
        "AUTHENTICATE" => return cmd_authenticate(state, conn, p),
        "NICK" => return cmd_nick(state, conn, p),
        "USER" => return cmd_user(state, conn, p),
        "PING" => return cmd_ping(state, conn, p),
        "PONG" => {
            // Liveness marker (no protocol reply); clears any outstanding
            // server-initiated PING so the reaper doesn't close a live client.
            if let Some(s) = state.sessions.get_mut(&conn) {
                s.awaiting_pong = false;
            }
            return;
        }
        "QUIT" => return cmd_quit(state, conn, p),
        // Legal before registration only when the server allows it, but it is
        // dispatched here either way so the refusal is the spec's
        // COMPLETE_CONNECTION_REQUIRED rather than a bare "not registered".
        "REGISTER" => return cmd_register(state, conn, p),
        _ => {}
    }
    if !state.sessions[&conn].registered {
        state.numeric(
            conn,
            ERR_NOTREGISTERED,
            &[],
            Some("You have not registered"),
        );
        return;
    }
    match command.as_str() {
        "JOIN" => cmd_join(state, conn, p),
        "PART" => cmd_part(state, conn, p),
        "BATCH" => cmd_batch(state, conn, msg, p),
        "PRIVMSG" => cmd_message(state, conn, msg, p, crate::core::MessageKind::Privmsg),
        "NOTICE" => cmd_message(state, conn, msg, p, crate::core::MessageKind::Notice),
        "TAGMSG" => cmd_tagmsg(state, conn, msg, p),
        "TOPIC" => cmd_topic(state, conn, msg, p),
        "NAMES" => cmd_names(state, conn, p),
        "MODE" => cmd_mode(state, conn, p),
        "WHO" => cmd_who(state, conn, p),
        "WHOIS" => cmd_whois(state, conn, p),
        "WHOWAS" => cmd_whowas(state, conn, p),
        "KICK" => cmd_kick(state, conn, p),
        "INVITE" => cmd_invite(state, conn, p),
        "AWAY" => cmd_away(state, conn, p),
        "LIST" => cmd_list(state, conn, p),
        "USERHOST" => cmd_userhost(state, conn, p),
        "CHATHISTORY" => cmd_chathistory(state, conn, p),
        "MONITOR" => cmd_monitor(state, conn, p),
        "MARKREAD" => cmd_markread(state, conn, p),
        "SETNAME" => cmd_setname(state, conn, p),
        "MOTD" => send_motd(state, conn),
        "LUSERS" => send_lusers(state, conn),
        "TIME" => cmd_time(state, conn),
        "INFO" => cmd_info(state, conn),
        "VERSION" => cmd_version(state, conn),
        "ADMIN" => cmd_admin(state, conn),
        "ISON" => cmd_ison(state, conn, p),
        "USERIP" => cmd_userip(state, conn, p),
        "LINKS" => cmd_links(state, conn),
        "STATS" => cmd_stats(state, conn, p),
        "KNOCK" => cmd_knock(state, conn, p),
        "OPER" => cmd_oper(state, conn, p),
        "KILL" => cmd_kill(state, conn, p),
        "KLINE" => cmd_add_ban(state, conn, BanKind::Kline, p),
        "UNKLINE" => cmd_remove_ban(state, conn, BanKind::Kline, p),
        "DLINE" => cmd_add_ban(state, conn, BanKind::Dline, p),
        "UNDLINE" => cmd_remove_ban(state, conn, BanKind::Dline, p),
        "XLINE" => cmd_add_ban(state, conn, BanKind::Xline, p),
        "UNXLINE" => cmd_remove_ban(state, conn, BanKind::Xline, p),
        "SETHOST" => cmd_sethost(state, conn, p),
        "WALLOPS" => cmd_wallops(state, conn, p),
        _ => state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &[clip_echo(&command)],
            Some("Unknown command"),
        ),
    }
}

// ---- connection-level ---------------------------------------------------

fn cmd_ping(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&token) = p.first() else {
        state.numeric(conn, ERR_NOORIGIN, &[], Some("No origin specified"));
        return;
    };
    let server = state.config.server_name.clone();
    state.send(conn, &format!(":{server} PONG {server} :{token}"));
}

/// Deadline for an unregistered connection to complete registration.
const REGISTRATION_TIMEOUT_MS: u64 = 30_000;
/// Idle duration after which a registered client is sent a liveness PING.
const IDLE_PING_INTERVAL_MS: u64 = 120_000;
/// How long the client then has to PONG before the connection is closed.
const PONG_TIMEOUT_MS: u64 = 60_000;

/// Liveness reaper, driven by the periodic [`super::Input::Tick`]: close
/// connections that never finished registering (slowloris), and PING idle
/// registered clients, closing those that don't PONG in time (dead sockets).
/// Without it a connection that opens and then goes silent holds its `Session`
/// and send queue forever.
pub(crate) fn reap_idle(state: &mut ServerState, now: e6irc_proto::time::Millis) {
    let mut expired: Vec<(ConnId, &'static str)> = Vec::new();
    let mut to_ping: Vec<ConnId> = Vec::new();
    for (&conn, s) in &state.sessions {
        if !s.registered {
            if now.saturating_sub(s.opened_at).as_millis() >= REGISTRATION_TIMEOUT_MS {
                expired.push((conn, "Registration timeout"));
            }
        } else if s.awaiting_pong {
            if now.saturating_sub(s.last_ping_sent).as_millis() >= PONG_TIMEOUT_MS {
                expired.push((conn, "Ping timeout"));
            }
        } else if now
            .saturating_sub(s.last_active.max(s.last_ping_sent))
            .as_millis()
            >= IDLE_PING_INTERVAL_MS
        {
            // Idle since the later of the last real activity and the last
            // liveness PING — so a client that just answered a PING isn't
            // re-pinged every tick. `last_active` stays the pure WHOIS-idle
            // clock (a keepalive PONG must not reset a user's idle time); the
            // ping cadence is driven by `last_ping_sent` here.
            to_ping.push(conn);
        }
    }
    let server = state.config.server_name.clone();
    for conn in to_ping {
        if let Some(s) = state.sessions.get_mut(&conn) {
            s.awaiting_pong = true;
            s.last_ping_sent = now;
        }
        state.send(conn, &format!("PING :{server}"));
    }
    for (conn, reason) in expired {
        state.send(conn, &format!(":{server} ERROR :Closing Link: {reason}"));
        state.close(conn, reason);
    }
}

fn cmd_quit(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let reason = match p.first() {
        Some(r) => format!("Quit: {r}"),
        None => "Quit: Client Quit".to_string(),
    };
    let host = state
        .sessions
        .get(&conn)
        .map(|s| s.host.clone())
        .unwrap_or_default();
    // The reason is echoed inside this ERROR wrapper, whose overhead can push a
    // maximal QUIT reason past the wire limit — fit it like every other relay
    // of client text. The trailing `)` is part of the head's cost, so budget
    // for it by including it before fitting and re-appending after.
    let head = format!("ERROR :Closing Link: {host} (");
    let fitted = fit_trailing(&format!("{head})"), &reason);
    state.send(conn, &format!("{head}{fitted})"));
    state.close(conn, &reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_mask_normalizes_separators_in_any_order() {
        // The ordinary shapes.
        assert_eq!(normalize_ban_mask("n!u@h"), "n!u@h");
        assert_eq!(normalize_ban_mask("n!u"), "n!u@*");
        assert_eq!(normalize_ban_mask("u@h"), "*!u@h");
        assert_eq!(normalize_ban_mask("n"), "n!*@*");
        // Empty components become `*` rather than matching nothing.
        assert_eq!(normalize_ban_mask("!@"), "*!*@*");
        assert_eq!(normalize_ban_mask("n!@h"), "n!*@h");
        // The separators need not appear in the expected order. `@!x` holds
        // both, but has no `@` after the `!` — deciding the shape from
        // `contains` and then splitting on that answer panicked the core
        // worker, which any user could reach by creating a channel (making
        // them its operator) and setting one mode.
        assert_eq!(normalize_ban_mask("@!x"), "@!x@*");
        assert_eq!(normalize_ban_mask("@!"), "@!*@*");
        assert_eq!(normalize_ban_mask("@!:UUU"), "@!:UUU@*");
        // Whatever the input, the result always has both separators exactly
        // once in the right order, so it can be matched against a prefix.
        for mask in ["", "!", "@", "@!x", "a!b@c@d", "!!!", "@@@", "a@b!c"] {
            let out = normalize_ban_mask(mask);
            let (_, rest) = out.split_once('!').expect("normalized mask has a !");
            assert!(rest.contains('@'), "{mask:?} normalized to {out:?}");
        }
    }

    #[test]
    fn ban_mask_canonicalizes_to_nick_user_host() {
        // A bare token is a nick; the missing user/host default to wildcards.
        assert_eq!(normalize_ban_mask("alice"), "alice!*@*");
        // host-only (`@host`) fills nick and user with wildcards.
        assert_eq!(normalize_ban_mask("@evil.example"), "*!*@evil.example");
        // user-only (`nick!user`) fills the host with a wildcard.
        assert_eq!(normalize_ban_mask("alice!bob"), "alice!bob@*");
        // A fully-qualified mask is preserved.
        assert_eq!(normalize_ban_mask("nick!user@host"), "nick!user@host");
        // Empty components in a full mask become wildcards, not empties —
        // otherwise `!@` would match nothing and silently no-op the ban.
        assert_eq!(normalize_ban_mask("!@"), "*!*@*");
        assert_eq!(normalize_ban_mask("nick!@host"), "nick!*@host");
    }
}
