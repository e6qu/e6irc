//! Command dispatch: one inbound line → state transitions + replies.

use e6irc_proto::message::Message;
use e6irc_proto::numerics::*;

use super::ConnId;
use super::state::{CAP_NAMES, ChanKey, Channel, MemberModes, ServerState, Topic};

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
    let label = msg
        .tag("label")
        .and_then(|t| t.value.as_deref())
        .filter(|_| state.sessions[&conn].caps.labeled_response)
        .map(str::to_string);
    if let Some(label) = label {
        state.capture = Some(super::state::Capture {
            conn,
            lines: Vec::new(),
        });
        dispatch_parsed(state, conn, &msg);
        let captured = state.capture.take().map(|c| c.lines).unwrap_or_default();
        frame_labeled(state, conn, &label, captured);
        return;
    }
    dispatch_parsed(state, conn, &msg);
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

/// Spend one command-flood token. Returns `true` if the command may
/// proceed, `false` if the bucket is empty (the caller closes the link).
/// No-op (always `true`) when the throttle is off, or for pre-registered
/// and oper sessions. Refills one token per elapsed second up to the
/// configured burst; a zero `flood_last_sec` (fresh session) refills to
/// full on the first command.
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
    let refill = now.saturating_sub(s.flood_last_sec);
    let tokens = (u64::from(s.flood_tokens) + refill).min(burst as u64) as u32;
    s.flood_last_sec = now;
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
    let _ = &server;

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

    // Commands legal before registration.
    match command.as_str() {
        "CAP" => return cmd_cap(state, conn, p),
        "AUTHENTICATE" => return cmd_authenticate(state, conn, p),
        "NICK" => return cmd_nick(state, conn, p),
        "USER" => return cmd_user(state, conn, p),
        "PING" => return cmd_ping(state, conn, p),
        "PONG" => return, // liveness marker; no reply by protocol
        "QUIT" => return cmd_quit(state, conn, p),
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
        "PRIVMSG" => cmd_message(state, conn, msg, p, "PRIVMSG"),
        "NOTICE" => cmd_message(state, conn, msg, p, "NOTICE"),
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
        "LIST" => cmd_list(state, conn),
        "USERHOST" => cmd_userhost(state, conn, p),
        "CHATHISTORY" => cmd_chathistory(state, conn, p),
        "MONITOR" => cmd_monitor(state, conn, p),
        "MARKREAD" => cmd_markread(state, conn, p),
        "SETNAME" => cmd_setname(state, conn, p),
        "MOTD" => send_motd(state, conn),
        "LUSERS" => send_lusers(state, conn),
        "TIME" => cmd_time(state, conn),
        "INFO" => cmd_info(state, conn),
        "OPER" => cmd_oper(state, conn, p),
        "KILL" => cmd_kill(state, conn, p),
        "KLINE" => cmd_kline(state, conn, p),
        "UNKLINE" => cmd_unkline(state, conn, p),
        "SETHOST" => cmd_sethost(state, conn, p),
        "WALLOPS" => cmd_wallops(state, conn, p),
        _ => state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &[&command],
            Some("Unknown command"),
        ),
    }
}

// ---- registration -------------------------------------------------------

fn valid_nick(nick: &str, nicklen: usize) -> bool {
    let mut bytes = nick.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let special = |b: u8| {
        matches!(
            b,
            b'[' | b']' | b'\\' | b'`' | b'_' | b'^' | b'{' | b'|' | b'}'
        )
    };
    if !(first.is_ascii_alphabetic() || special(first)) {
        return false;
    }
    nick.len() <= nicklen && bytes.all(|b| b.is_ascii_alphanumeric() || special(b) || b == b'-')
}

fn cmd_nick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&nick) = p.first() else {
        state.numeric(conn, ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
        return;
    };
    if !valid_nick(nick, state.config.nicklen) {
        state.numeric(
            conn,
            ERR_ERRONEUSNICKNAME,
            &[nick],
            Some("Erroneous nickname"),
        );
        return;
    }
    let key = state.nick_key(nick);
    if let Some(&owner) = state.nicks.get(&key)
        && owner != conn
    {
        state.numeric(
            conn,
            ERR_NICKNAMEINUSE,
            &[nick],
            Some("Nickname is already in use"),
        );
        return;
    }
    // same owner: casing change falls through as a normal change
    let (registered, prefix, old_key, old_nick_display) = {
        let session = &state.sessions[&conn];
        (
            session.registered,
            session.registered.then(|| session.prefix()),
            session.nick.as_ref().map(|o| state.nick_key(o)),
            session.nick.clone(),
        )
    };
    // A pure case change keeps the same monitor/nick key.
    let case_change_only = old_key.as_ref() == Some(&key);
    if registered && !case_change_only {
        state.record_whowas(conn);
    }
    state.sessions.get_mut(&conn).expect("checked").nick = Some(nick.to_string());
    if let Some(old_key) = old_key {
        state.nicks.remove(&old_key);
    }
    state.nicks.insert(key, conn);

    if registered {
        let line = format!(":{} NICK {nick}", prefix.expect("registered"));
        state.send(conn, &line);
        let peers = state.channel_peers(conn);
        let bytes = bytes::Bytes::from(format!("{line}\r\n"));
        for peer in peers {
            state.send_bytes(peer, bytes.clone());
        }
        if !case_change_only {
            if let Some(old_nick) = old_nick_display {
                monitor_notify(state, &old_nick, false);
            }
            monitor_notify(state, nick, true);
        }
    } else {
        maybe_complete_registration(state, conn);
    }
}

fn cmd_user(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if state.sessions[&conn].registered {
        state.numeric(
            conn,
            ERR_ALREADYREGISTERED,
            &[],
            Some("You may not reregister"),
        );
        return;
    }
    // An empty realname is "not enough parameters" per Modern IRC.
    if p.len() < 4 || p[0].is_empty() || p[3].is_empty() {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["USER"],
            Some("Not enough parameters"),
        );
        return;
    }
    let session = state
        .sessions
        .get_mut(&conn)
        .expect("session checked in dispatch");
    session.user = Some(p[0].to_string());
    session.realname = Some(p[3].to_string());
    maybe_complete_registration(state, conn);
}

// ---- capability negotiation ---------------------------------------------

fn cap_target(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .nick
        .clone()
        .unwrap_or_else(|| "*".into())
}

fn cmd_cap(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let server = state.config.server_name.clone();
    let target = cap_target(state, conn);
    let sub = p
        .first()
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_default();
    match sub.as_str() {
        "LS" => {
            if !state.sessions[&conn].registered {
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .cap_negotiating = true;
            }
            let v302 = p.get(1).is_some_and(|v| *v == "302");
            let mut names: Vec<String> = CAP_NAMES.iter().map(|(n, _)| n.to_string()).collect();
            if state.config.sasl_enabled {
                names.push(if v302 {
                    "sasl=PLAIN,OAUTHBEARER".into()
                } else {
                    "sasl".into()
                });
            }
            state.send(
                conn,
                &format!(":{server} CAP {target} LS :{}", names.join(" ")),
            );
        }
        "LIST" => {
            let mut caps = state.sessions[&conn].caps;
            let mut active: Vec<&str> = CAP_NAMES
                .iter()
                .filter(|(_, get)| *get(&mut caps))
                .map(|(n, _)| *n)
                .collect();
            if caps.sasl {
                active.push("sasl");
            }
            state.send(
                conn,
                &format!(":{server} CAP {target} LIST :{}", active.join(" ")),
            );
        }
        "REQ" => {
            let request = p.get(1).copied().unwrap_or("");
            if !state.sessions[&conn].registered {
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .cap_negotiating = true;
            }
            // All-or-nothing: apply to a copy, commit only if every
            // token is known.
            let mut caps = state.sessions[&conn].caps;
            let mut all_known = !request.is_empty();
            for token in request.split(' ').filter(|t| !t.is_empty()) {
                let (name, enable) = match token.strip_prefix('-') {
                    Some(n) => (n, false),
                    None => (token, true),
                };
                if name == "sasl" && state.config.sasl_enabled {
                    caps.sasl = enable;
                    continue;
                }
                match CAP_NAMES.iter().find(|(n, _)| *n == name) {
                    Some((_, get)) => *get(&mut caps) = enable,
                    None => {
                        all_known = false;
                        break;
                    }
                }
            }
            let verb = if all_known { "ACK" } else { "NAK" };
            if all_known {
                state.sessions.get_mut(&conn).expect("checked").caps = caps;
            }
            state.send(conn, &format!(":{server} CAP {target} {verb} :{request}"));
        }
        "END" => {
            let session = state.sessions.get_mut(&conn).expect("checked");
            if !session.registered && session.cap_negotiating {
                session.cap_negotiating = false;
                maybe_complete_registration(state, conn);
            }
        }
        _ => {
            let shown = if sub.is_empty() { "*" } else { &sub };
            state.numeric(
                conn,
                ERR_INVALIDCAPCMD,
                &[shown],
                Some("Invalid CAP command"),
            );
        }
    }
}

// ---- SASL ---------------------------------------------------------------

fn sasl_fail(state: &mut ServerState, conn: ConnId) {
    state.sessions.get_mut(&conn).expect("checked").sasl = super::state::SaslState::Idle;
    state.numeric(conn, ERR_SASLFAIL, &[], Some("SASL authentication failed"));
}

fn cmd_authenticate(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    use super::state::SaslState;
    if !state.config.sasl_enabled || !state.sessions[&conn].caps.sasl {
        sasl_fail(state, conn);
        return;
    }
    let Some(&arg) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["AUTHENTICATE"],
            Some("Not enough parameters"),
        );
        return;
    };
    if arg == "*" {
        state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Idle;
        state.numeric(
            conn,
            ERR_SASLABORTED,
            &[],
            Some("SASL authentication aborted"),
        );
        return;
    }
    if arg.len() > 400 {
        state.numeric(conn, ERR_SASLTOOLONG, &[], Some("SASL message too long"));
        return;
    }
    match state.sessions[&conn].sasl {
        SaslState::Idle => {
            if arg.eq_ignore_ascii_case("PLAIN") {
                state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::PlainPending;
                state.send(conn, "AUTHENTICATE +");
            } else if arg.eq_ignore_ascii_case("OAUTHBEARER") {
                state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::BearerPending;
                state.send(conn, "AUTHENTICATE +");
            } else {
                state.numeric(
                    conn,
                    RPL_SASLMECHS,
                    &["PLAIN,OAUTHBEARER"],
                    Some("are available SASL mechanisms"),
                );
                sasl_fail(state, conn);
            }
        }
        SaslState::PlainPending => {
            // payload: base64(authzid \0 authcid \0 password)
            let parsed = e6irc_proto::base64::decode(arg).and_then(|raw| {
                let mut parts = raw.split(|&b| b == 0);
                let _authzid = parts.next()?;
                let authcid = String::from_utf8(parts.next()?.to_vec()).ok()?;
                let password = String::from_utf8(parts.next()?.to_vec()).ok()?;
                if parts.next().is_some() || authcid.is_empty() || password.is_empty() {
                    return None;
                }
                Some((authcid, password))
            });
            let Some((account, password)) = parsed else {
                sasl_fail(state, conn);
                return;
            };
            state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Verifying;
            let request = super::DbRequest::VerifyPassword {
                conn,
                account,
                password,
            };
            if state.db_tx.try_push(request).is_err() {
                // DB worker unreachable: fail loudly, never hang.
                sasl_fail(state, conn);
            }
        }
        SaslState::BearerPending => {
            // RFC 7628: gs2-header then \x01-separated key=value fields;
            // the credential is the `auth=Bearer <token>` field.
            let token = e6irc_proto::base64::decode(arg).and_then(|raw| {
                raw.split(|&b| b == 0x01).find_map(|field| {
                    std::str::from_utf8(field)
                        .ok()
                        .and_then(|s| s.strip_prefix("auth=Bearer "))
                        .filter(|t| !t.is_empty())
                        .map(str::to_string)
                })
            });
            let Some(token) = token else {
                sasl_fail(state, conn);
                return;
            };
            state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Verifying;
            let request = super::DbRequest::VerifyToken { conn, token };
            if state.db_tx.try_push(request).is_err() {
                // DB worker unreachable: fail loudly, never hang.
                sasl_fail(state, conn);
            }
        }
        SaslState::Verifying => {
            state.numeric(
                conn,
                ERR_SASLALREADY,
                &[],
                Some("SASL authentication in progress"),
            );
        }
    }
}

pub(crate) fn db_reply(state: &mut ServerState, conn: ConnId, reply: super::DbReply) {
    use super::state::SaslState;
    if !state.sessions.contains_key(&conn) {
        return; // client vanished while the DB worked; nothing to do
    }
    match reply {
        super::DbReply::PasswordVerified { account } => {
            if state.sessions[&conn].sasl != SaslState::Verifying {
                if state.sessions[&conn].pending_identify {
                    let session = state.sessions.get_mut(&conn).expect("checked");
                    session.pending_identify = false;
                    session.account = Some(account.clone());
                    state.service_notice(
                        conn,
                        "NickServ",
                        &format!("You are now identified for \x02{account}\x02."),
                    );
                    notify_account_change(state, conn, &account);
                }
                return; // otherwise: stale reply (e.g. after abort)
            }
            {
                let session = state.sessions.get_mut(&conn).expect("checked");
                session.sasl = SaslState::Idle;
                session.account = Some(account.clone());
            }
            let session = &state.sessions[&conn];
            let nick = session.nick.clone().unwrap_or_else(|| "*".into());
            let user = session.user.clone().unwrap_or_else(|| "*".into());
            let host = session.host.clone();
            state.numeric(
                conn,
                RPL_LOGGEDIN,
                &[&format!("{nick}!{user}@{host}"), &account],
                Some(&format!("You are now logged in as {account}")),
            );
            state.numeric(
                conn,
                RPL_SASLSUCCESS,
                &[],
                Some("SASL authentication successful"),
            );
        }
        super::DbReply::PasswordRejected | super::DbReply::Unavailable => {
            let unavailable = matches!(reply, super::DbReply::Unavailable);
            if state.sessions[&conn].sasl == SaslState::Verifying {
                sasl_fail(state, conn);
            } else if state.sessions[&conn].pending_identify {
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .pending_identify = false;
                let text = if unavailable {
                    "Services are temporarily unavailable. Try again later.".to_string()
                } else {
                    let nick = state.sessions[&conn]
                        .nick
                        .clone()
                        .unwrap_or_else(|| "*".into());
                    format!("Invalid password for \x02{nick}\x02.")
                };
                state.service_notice(conn, "NickServ", &text);
            }
        }
        super::DbReply::AccountCreated { account } => {
            state.sessions.get_mut(&conn).expect("checked").account = Some(account.clone());
            state.service_notice(
                conn,
                "NickServ",
                &format!("\x02{account}\x02 is now registered to your connection."),
            );
            notify_account_change(state, conn, &account);
        }
        super::DbReply::AccountExists => {
            let nick = state.sessions[&conn]
                .nick
                .clone()
                .unwrap_or_else(|| "*".into());
            state.service_notice(
                conn,
                "NickServ",
                &format!("\x02{nick}\x02 is already registered."),
            );
        }
        super::DbReply::ChannelRegistered { channel } => {
            // Record ownership in the hot copy so the founder is re-opped
            // on future joins without waiting for a restart.
            if let Some(account) = state.sessions.get(&conn).and_then(|s| s.account.clone()) {
                state.set_founder(&channel, &account);
            }
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{channel}\x02 is now registered to your account."),
            );
        }
        super::DbReply::ChannelExists => {
            state.service_notice(conn, "ChanServ", "That channel is already registered.");
        }
        super::DbReply::FounderChanged { channel, account } => {
            // Update the hot ownership map so the new founder is re-opped.
            state.set_founder(&channel, &account);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Founder of \x02{channel}\x02 transferred to \x02{account}\x02."),
            );
        }
        super::DbReply::FounderChangeFailed { channel } => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Could not transfer \x02{channel}\x02 — no such account."),
            );
        }
    }
}

/// account-notify: tell channel peers with the cap about a login state
/// change.
fn notify_account_change(state: &mut ServerState, conn: ConnId, account: &str) {
    if !state.sessions.get(&conn).is_some_and(|s| s.registered) {
        return; // pre-registration SASL: peers cannot exist yet
    }
    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} ACCOUNT {account}");
    for peer in state.channel_peers(conn) {
        if state
            .sessions
            .get(&peer)
            .is_some_and(|s| s.caps.account_notify)
        {
            state.send_timed(peer, &line);
        }
    }
}

// ---- services pseudo-clients --------------------------------------------

fn services_dispatch(state: &mut ServerState, conn: ConnId, service_key: &str, text: &str) {
    let mut words = text.split_whitespace();
    let command = words
        .next()
        .map(|w| w.to_ascii_uppercase())
        .unwrap_or_default();
    let args: Vec<&str> = words.collect();
    match service_key {
        "nickserv" => nickserv(state, conn, &command, &args),
        "chanserv" => chanserv(state, conn, &command, &args),
        _ => unreachable!("caller matched the service key"),
    }
}

fn nickserv(state: &mut ServerState, conn: ConnId, command: &str, args: &[&str]) {
    match command {
        "REGISTER" => {
            let Some(&password) = args.first() else {
                state.service_notice(conn, "NickServ", "Syntax: REGISTER <password> [email]");
                return;
            };
            if state.sessions[&conn].account.is_some() {
                state.service_notice(conn, "NickServ", "You are already logged in.");
                return;
            }
            let name = state.sessions[&conn].nick.clone().expect("registered");
            let request = super::DbRequest::CreateAccount {
                conn,
                name,
                password: password.to_string(),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        "IDENTIFY" => {
            // IDENTIFY <password> | IDENTIFY <account> <password>
            let (account, password) = match args {
                [password] => (
                    state.sessions[&conn].nick.clone().expect("registered"),
                    *password,
                ),
                [account, password] => (account.to_string(), *password),
                _ => {
                    state.service_notice(conn, "NickServ", "Syntax: IDENTIFY [account] <password>");
                    return;
                }
            };
            state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .pending_identify = true;
            let request = super::DbRequest::VerifyPassword {
                conn,
                account,
                password: password.to_string(),
            };
            if state.db_tx.try_push(request).is_err() {
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .pending_identify = false;
                state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        "GHOST" => {
            // GHOST <nick>: disconnect a lingering session holding a nick
            // you own, so you can reclaim it. An account owns the nick of
            // the same name (nick registration model).
            let Some(&nick) = args.first() else {
                state.service_notice(conn, "NickServ", "Syntax: GHOST <nick>");
                return;
            };
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "NickServ",
                    "You must identify to services before using GHOST.",
                );
                return;
            };
            if state.casemap.casefold(&account) != state.casemap.casefold(nick) {
                state.service_notice(conn, "NickServ", &format!("You do not own \x02{nick}\x02."));
                return;
            }
            let key = state.nick_key(nick);
            let Some(&victim) = state.nicks.get(&key) else {
                state.service_notice(conn, "NickServ", &format!("\x02{nick}\x02 is not online."));
                return;
            };
            if victim == conn {
                state.service_notice(conn, "NickServ", "You cannot ghost yourself.");
                return;
            }
            let by = state.sessions[&conn].nick.clone().unwrap_or_default();
            let server = state.config.server_name.clone();
            let reason = format!("GHOST command used by {by}");
            state.send(victim, &format!("ERROR :Closing Link: {server} ({reason})"));
            state.close(victim, &reason);
            state.service_notice(
                conn,
                "NickServ",
                &format!("\x02{nick}\x02 has been ghosted."),
            );
        }
        "HELP" => {
            for line in [
                "***** NickServ Help *****",
                "REGISTER <password> [email] - Register your current nick",
                "IDENTIFY [account] <password> - Log in to your account",
                "GHOST <nick> - Disconnect a lingering session on your nick",
                "***** End of Help *****",
            ] {
                state.service_notice(conn, "NickServ", line);
            }
        }
        _ => {
            state.service_notice(
                conn,
                "NickServ",
                "Invalid command. Use \x02/msg NickServ HELP\x02 for a command listing.",
            );
        }
    }
}

fn chanserv(state: &mut ServerState, conn: ConnId, command: &str, args: &[&str]) {
    match command {
        "REGISTER" => {
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: REGISTER <#channel>");
                return;
            };
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must identify to services before registering a channel.",
                );
                return;
            };
            let key = state.chan_key(channel);
            let is_op = state
                .channels
                .get(&key)
                .and_then(|c| c.members.get(&conn))
                .is_some_and(|m| m.op);
            if !is_op {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must be a channel operator in that channel to register it.",
                );
                return;
            }
            let display = state.channels[&key].name.clone();
            let request = super::DbRequest::RegisterChannel {
                conn,
                channel: display,
                founder_account: account,
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        "DROP" => {
            // DROP <#channel>: the founder unregisters their channel.
            let Some(&channel) = args.first() else {
                state.service_notice(conn, "ChanServ", "Syntax: DROP <#channel>");
                return;
            };
            let Some(account) = state.sessions[&conn].account.clone() else {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "You must identify to services before dropping a channel.",
                );
                return;
            };
            let key = state.chan_key(channel);
            if !state.is_founder(&key, &account) {
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!("You are not the founder of \x02{channel}\x02."),
                );
                return;
            }
            let request = super::DbRequest::DropChannel {
                channel: key.as_str().to_string(),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
                return;
            }
            // Drop the hot registration too: no more founder-op, topic
            // retention, or access for this channel. (The DB row's
            // channel_access cascades on the row delete.)
            state.registered_founders.remove(&key);
            state.registered_topics.remove(&key);
            state.channel_access.remove(&key);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{channel}\x02 has been dropped."),
            );
        }
        "FLAGS" => chanserv_flags(state, conn, args),
        "OP" => chanserv_op(state, conn, args),
        "SET" => chanserv_set(state, conn, args),
        "HELP" => {
            for line in [
                "***** ChanServ Help *****",
                "REGISTER <#channel> - Register a channel you operate",
                "DROP <#channel> - Unregister a channel you founded",
                "FLAGS <#channel> [account [+/-ov]] - List or set channel access",
                "OP <#channel> [nick] - Op yourself or a nick (needs op access)",
                "SET <#channel> FOUNDER <account> - Transfer channel ownership",
                "***** End of Help *****",
            ] {
                state.service_notice(conn, "ChanServ", line);
            }
        }
        _ => {
            state.service_notice(
                conn,
                "ChanServ",
                "Invalid command. Use \x02/msg ChanServ HELP\x02 for a command listing.",
            );
        }
    }
}

/// Apply a `+ov`/`-o`-style change string to a current flag set, keeping
/// only the recognised flags (`o` auto-op, `v` auto-voice), sorted.
fn apply_flag_changes(current: &str, changes: &str) -> String {
    let mut flags: std::collections::BTreeSet<char> =
        current.chars().filter(|c| matches!(c, 'o' | 'v')).collect();
    let mut adding = true;
    for c in changes.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'v' => {
                if adding {
                    flags.insert(c);
                } else {
                    flags.remove(&c);
                }
            }
            _ => {}
        }
    }
    flags.into_iter().collect()
}

/// ChanServ FLAGS: list a registered channel's access entries, or (founder
/// only) modify one account's flags. Auto-op/voice apply on the account's
/// next join.
fn chanserv_flags(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: FLAGS <#channel> [account [+/-flags]]",
        );
        return;
    };
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(
            conn,
            "ChanServ",
            "You must identify to services before using FLAGS.",
        );
        return;
    };
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return;
    }
    if !state.is_founder(&key, &account) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("You are not the founder of \x02{channel}\x02."),
        );
        return;
    }

    // LIST when no account is given.
    if args.len() == 1 {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("Access list for \x02{channel}\x02:"),
        );
        let mut entries: Vec<(String, String)> = state
            .channel_access
            .get(&key)
            .map(|m| m.iter().map(|(a, f)| (a.clone(), f.clone())).collect())
            .unwrap_or_default();
        entries.sort();
        for (acct, flags) in &entries {
            state.service_notice(conn, "ChanServ", &format!("{acct} +{flags}"));
        }
        state.service_notice(conn, "ChanServ", "End of access list.");
        return;
    }

    // MODIFY: FLAGS <#channel> <account> <changes>.
    let target = args[1];
    let Some(&changes) = args.get(2) else {
        state.service_notice(
            conn,
            "ChanServ",
            "Syntax: FLAGS <#channel> <account> <+/-ov>",
        );
        return;
    };
    let target_folded = state.casemap.casefold(target);
    let current = state
        .channel_access
        .get(&key)
        .and_then(|m| m.get(&target_folded))
        .cloned()
        .unwrap_or_default();
    let new_flags = apply_flag_changes(&current, changes);

    // Update the hot map, then persist.
    {
        let entry = state.channel_access.entry(key.clone()).or_default();
        if new_flags.is_empty() {
            entry.remove(&target_folded);
        } else {
            entry.insert(target_folded.clone(), new_flags.clone());
        }
    }
    let request = super::DbRequest::SetChannelAccess {
        channel: key.as_str().to_string(),
        account: target_folded,
        flags: (!new_flags.is_empty()).then(|| new_flags.clone()),
    };
    if state.db_tx.try_push(request).is_err() {
        state.service_notice(
            conn,
            "ChanServ",
            "Services are temporarily unavailable. Try again later.",
        );
        return;
    }
    if new_flags.is_empty() {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("Cleared flags for \x02{target}\x02 on \x02{channel}\x02."),
        );
    } else {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("Flags for \x02{target}\x02 on \x02{channel}\x02 are now +{new_flags}."),
        );
    }
}

/// ChanServ OP: op yourself (or a named nick) on a registered channel you
/// have op access to (founder or the `o` access flag). The target must be
/// online and on the channel.
fn chanserv_op(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let Some(&channel) = args.first() else {
        state.service_notice(conn, "ChanServ", "Syntax: OP <#channel> [nick]");
        return;
    };
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(
            conn,
            "ChanServ",
            "You must identify to services before using OP.",
        );
        return;
    };
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return;
    }
    if !(state.is_founder(&key, &account) || state.access_modes(&key, &account).0) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("You do not have op access on \x02{channel}\x02."),
        );
        return;
    }

    // Target: the named nick, or the requester's own nick.
    let target_nick = match args.get(1) {
        Some(&n) => n.to_string(),
        None => state.sessions[&conn].nick.clone().expect("registered"),
    };
    let nk = state.nick_key(&target_nick);
    let Some(&target_conn) = state.nicks.get(&nk) else {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{target_nick}\x02 is not online."),
        );
        return;
    };
    match state
        .channels
        .get(&key)
        .and_then(|c| c.members.get(&target_conn))
        .map(|m| m.op)
    {
        None => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{target_nick}\x02 is not on \x02{channel}\x02."),
            );
            return;
        }
        Some(true) => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{target_nick}\x02 is already opped."),
            );
            return;
        }
        Some(false) => {}
    }
    if let Some(chan) = state.channels.get_mut(&key)
        && let Some(member) = chan.members.get_mut(&target_conn)
    {
        member.op = true;
    }
    let display = state.channels[&key].name.clone();
    let server = state.config.server_name.clone();
    state.broadcast_channel(
        &key,
        &format!(":{server} MODE {display} +o {target_nick}"),
        None,
    );
    state.service_notice(
        conn,
        "ChanServ",
        &format!("Opped \x02{target_nick}\x02 on \x02{channel}\x02."),
    );
}

/// ChanServ SET: founder-only channel options. Currently FOUNDER (transfer
/// ownership to another account, verified against the DB).
fn chanserv_set(state: &mut ServerState, conn: ConnId, args: &[&str]) {
    let (Some(&channel), Some(&option)) = (args.first(), args.get(1)) else {
        state.service_notice(conn, "ChanServ", "Syntax: SET <#channel> <option> <value>");
        return;
    };
    let Some(account) = state.sessions[&conn].account.clone() else {
        state.service_notice(
            conn,
            "ChanServ",
            "You must identify to services before using SET.",
        );
        return;
    };
    let key = state.chan_key(channel);
    if !state.is_registered(&key) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("\x02{channel}\x02 is not registered."),
        );
        return;
    }
    if !state.is_founder(&key, &account) {
        state.service_notice(
            conn,
            "ChanServ",
            &format!("You are not the founder of \x02{channel}\x02."),
        );
        return;
    }
    match option.to_ascii_uppercase().as_str() {
        "FOUNDER" => {
            let Some(&new) = args.get(2) else {
                state.service_notice(conn, "ChanServ", "Syntax: SET <#channel> FOUNDER <account>");
                return;
            };
            let request = super::DbRequest::SetChannelFounder {
                conn,
                channel: channel.to_string(),
                new_founder: state.casemap.casefold(new),
            };
            if state.db_tx.try_push(request).is_err() {
                state.service_notice(
                    conn,
                    "ChanServ",
                    "Services are temporarily unavailable. Try again later.",
                );
            }
        }
        other => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Unknown SET option \x02{other}\x02. Available: FOUNDER."),
            );
        }
    }
}

fn maybe_complete_registration(state: &mut ServerState, conn: ConnId) {
    {
        let session = &state.sessions[&conn];
        if session.registered
            || session.cap_negotiating
            || session.nick.is_none()
            || session.user.is_none()
        {
            return;
        }
    }
    // K-line enforcement: refuse a banned user@host before completing.
    {
        let session = &state.sessions[&conn];
        let subject = format!(
            "{}@{}",
            session.user.as_deref().unwrap_or("*"),
            session.host
        );
        if let Some(reason) = state.kline_match(&subject) {
            let host = state.sessions[&conn].host.clone();
            state.numeric(
                conn,
                ERR_YOUREBANNEDCREEP,
                &[],
                Some(&format!("You are banned from this server: {reason}")),
            );
            state.send(
                conn,
                &format!("ERROR :Closing Link: {host} (K-Lined: {reason})"),
            );
            state.close(conn, &format!("K-Lined: {reason}"));
            return;
        }
    }
    state.sessions.get_mut(&conn).expect("checked").registered = true;
    let registered_now = state.sessions.values().filter(|s| s.registered).count();
    state.max_users = state.max_users.max(registered_now);
    let prefix = state.sessions[&conn].prefix();
    let (server, network) = (
        state.config.server_name.clone(),
        state.config.network_name.clone(),
    );

    state.numeric(
        conn,
        RPL_WELCOME,
        &[],
        Some(&format!("Welcome to the {network} Network, {prefix}")),
    );
    state.numeric(
        conn,
        RPL_YOURHOST,
        &[],
        Some(&format!(
            "Your host is {server}, running version e6ircd-{}",
            version()
        )),
    );
    state.numeric(
        conn,
        RPL_CREATED,
        &[],
        Some("This server was created at build time"),
    );
    state.numeric(
        conn,
        RPL_MYINFO,
        &[
            &server,
            &format!("e6ircd-{}", version()),
            "io",
            "imnstkl",
            "ov",
        ],
        None,
    );
    let nicklen = state.config.nicklen;
    state.numeric(
        conn,
        RPL_ISUPPORT,
        &[
            "CASEMAPPING=rfc1459",
            "CHANTYPES=#",
            &format!("NICKLEN={nicklen}"),
            "CHANNELLEN=50",
            "PREFIX=(ov)@+",
            "STATUSMSG=@+",
            "BOT=B",
            "CHANMODES=eIbq,k,l,imnstC",
            "EXCEPTS",
            "INVEX",
            "UTF8ONLY",
            "MONITOR=100",
            "CHATHISTORY=500",
            "MSGREFTYPES=msgid,timestamp",
            &format!("NETWORK={}", state.config.network_name),
        ],
        Some("are supported by this server"),
    );
    send_lusers(state, conn);
    send_motd(state, conn);
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    monitor_notify(state, &nick, true);
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn send_lusers(state: &mut ServerState, conn: ConnId) {
    let users = state.sessions.values().filter(|s| s.registered).count();
    let channels = state.channels.len();
    state.numeric(
        conn,
        RPL_LUSERCLIENT,
        &[],
        Some(&format!(
            "There are {users} users and 0 invisible on 1 servers"
        )),
    );
    if channels > 0 {
        state.numeric(
            conn,
            RPL_LUSERCHANNELS,
            &[&channels.to_string()],
            Some("channels formed"),
        );
    }
    state.numeric(
        conn,
        RPL_LUSERME,
        &[],
        Some(&format!("I have {users} clients and 0 servers")),
    );
    let max = state.max_users;
    state.numeric(
        conn,
        RPL_LOCALUSERS,
        &[&users.to_string(), &max.to_string()],
        Some(&format!("Current local users {users}, max {max}")),
    );
    state.numeric(
        conn,
        RPL_GLOBALUSERS,
        &[&users.to_string(), &max.to_string()],
        Some(&format!("Current global users {users}, max {max}")),
    );
}

fn send_motd(state: &mut ServerState, conn: ConnId) {
    if state.config.motd.is_empty() {
        state.numeric(conn, ERR_NOMOTD, &[], Some("MOTD File is missing"));
        return;
    }
    let server = state.config.server_name.clone();
    state.numeric(
        conn,
        RPL_MOTDSTART,
        &[],
        Some(&format!("- {server} Message of the day - ")),
    );
    for line in state.config.motd.clone() {
        state.numeric(conn, RPL_MOTD, &[], Some(&format!("- {line}")));
    }
    state.numeric(conn, RPL_ENDOFMOTD, &[], Some("End of /MOTD command."));
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
    state.send(conn, &format!("ERROR :Closing Link: {host} ({reason})"));
    state.close(conn, &reason);
}

// ---- channels -----------------------------------------------------------

fn valid_channel_name(name: &str) -> bool {
    name.starts_with('#')
        && name.len() > 1
        && name.len() <= 50
        && !name.bytes().any(|b| matches!(b, b' ' | b',' | 0x07 | b':'))
}

fn cmd_join(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&targets) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["JOIN"],
            Some("Not enough parameters"),
        );
        return;
    };
    let keys: Vec<&str> = p.get(1).map(|k| k.split(',').collect()).unwrap_or_default();
    for (i, target) in targets.split(',').filter(|t| !t.is_empty()).enumerate() {
        join_one(state, conn, target, keys.get(i).copied());
    }
}

fn join_one(state: &mut ServerState, conn: ConnId, name: &str, join_key: Option<&str>) {
    if !valid_channel_name(name) {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[name], Some("No such channel"));
        return;
    }
    let key = state.chan_key(name);
    let now = (state.config.clock)();
    let user_prefix = state.sessions[&conn].prefix();
    let casemap = state.casemap;
    // A registered channel being (re)created restores its retained topic.
    let restored_topic = if state.channels.contains_key(&key) {
        None
    } else {
        state.registered_topics.get(&key).cloned()
    };
    let chan = state
        .channels
        .entry(key.clone())
        .or_insert_with(|| Channel {
            name: name.to_string(),
            topic: restored_topic,
            members: std::collections::HashMap::new(),
            modes: super::state::ChanModes {
                no_external: true,
                topic_ops_only: true,
                ..Default::default()
            },
            bans: Vec::new(),
            quiets: Vec::new(),
            ban_exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            created_at: now,
            history: std::collections::VecDeque::new(),
            history_complete: true,
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
        && join_key != Some(chan_key.as_str())
    {
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
        let (text, set_by, set_at) = (topic.text.clone(), topic.set_by.clone(), topic.set_at);
        state.numeric(conn, RPL_TOPIC, &[&display], Some(&text));
        state.numeric(
            conn,
            RPL_TOPICWHOTIME,
            &[&display, &set_by, &set_at.to_string()],
            None,
        );
    }
    send_names(state, conn, &key);
}

fn cmd_part(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
        let line = match &reason {
            Some(r) => format!(":{prefix} PART {display} :{r}"),
            None => format!(":{prefix} PART {display}"),
        };
        state.broadcast_channel(&key, &line, None);
        let chan = state.channels.get_mut(&key).expect("checked");
        chan.members.remove(&conn);
        if chan.members.is_empty() {
            state.channels.remove(&key);
        }
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .channels
            .remove(&key);
    }
}

fn send_names(state: &mut ServerState, conn: ConnId, key: &ChanKey) {
    let Some(chan) = state.channels.get(key) else {
        return;
    };
    let display = chan.name.clone();
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
    state.numeric(
        conn,
        RPL_NAMREPLY,
        &[symbol, &display],
        Some(&names.join(" ")),
    );
    state.numeric(
        conn,
        RPL_ENDOFNAMES,
        &[&display],
        Some("End of /NAMES list"),
    );
}

fn cmd_names(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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

/// Deliver a message line to recipients, applying per-recipient
/// `server-time` and `account-tag` variants.
#[allow(clippy::too_many_arguments)]
fn deliver_message(
    state: &mut ServerState,
    recipients: &[ConnId],
    sender_account: Option<&str>,
    sender_is_bot: bool,
    msgid: &str,
    client_tags: &str,
    body: &str,
    bypass_capture: bool,
) {
    let time = state.time_tag();
    for &recipient in recipients {
        let Some(session) = state.sessions.get(&recipient) else {
            continue;
        };
        let caps = session.caps;
        let mut tags: Vec<String> = Vec::new();
        if caps.message_tags {
            tags.push(format!("msgid={msgid}"));
        }
        if caps.server_time {
            tags.push(format!("time={time}"));
        }
        if caps.account_tag
            && let Some(account) = sender_account
        {
            tags.push(format!("account={account}"));
        }
        if caps.message_tags && sender_is_bot {
            tags.push("bot".to_string());
        }
        if caps.message_tags && !client_tags.is_empty() {
            tags.push(client_tags.to_string());
        }
        let line = if tags.is_empty() {
            body.to_string()
        } else {
            format!("@{} {body}", tags.join(";"))
        };
        let bytes = bytes::Bytes::from(format!("{line}\r\n"));
        if bypass_capture {
            state.send_bytes_uncaptured(recipient, bytes);
        } else {
            state.send_bytes(recipient, bytes);
        }
    }
}

// ---- messaging ----------------------------------------------------------

/// A CTCP message is \x01-delimited; ACTION (/me) is exempt from +C.
fn is_blocked_ctcp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.first() == Some(&0x01) && !text.starts_with("\u{1}ACTION")
}

fn client_tag_string(msg: &Message) -> String {
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

fn cmd_message(
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
    let Some(&target) = p.first() else {
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
    // Services pseudo-clients intercept before the nick table. NOTICE
    // to services is dropped without reply (spec: NOTICE never triggers
    // automatic responses).
    let target_key = state.nick_key(target);
    if target_key.as_str() == "nickserv" || target_key.as_str() == "chanserv" {
        if loud {
            services_dispatch(state, conn, target_key.as_str(), text);
        }
        return;
    }

    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} {kind} {target} :{text}");

    // STATUSMSG: a leading @ or + restricts delivery to members with at
    // least that status. The prefix stays in the target echoed to
    // recipients.
    let (status_prefix, chan_target) = match target.strip_prefix(['@', '+']) {
        Some(rest) if rest.starts_with('#') => (target.as_bytes()[0], rest),
        _ => (0, target),
    };
    if chan_target.starts_with('#') {
        let key = state.chan_key(chan_target);
        let Some(chan) = state.channels.get(&key) else {
            if loud {
                state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
            }
            return;
        };
        let member = chan.members.get(&conn);
        let may_speak = match member {
            Some(m) if m.op || m.voice => true,
            Some(_) => {
                !chan.modes.moderated
                    && !chan.is_banned(state.casemap, &prefix)
                    && !chan.is_quieted(state.casemap, &prefix)
            }
            None => !chan.modes.no_external,
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
            return;
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
            return;
        }
        let recipients: Vec<ConnId> = state.channels[&key]
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
        let sender_account = state.sessions[&conn].account.clone();
        let sender_is_bot = state.sessions[&conn].bot;
        let msgid = state.next_msgid();
        deliver_message(
            state,
            &recipients,
            sender_account.as_deref(),
            sender_is_bot,
            &msgid,
            &client_tags,
            &line,
            true,
        );
        if state.sessions[&conn].caps.echo_message {
            deliver_message(
                state,
                &[conn],
                sender_account.as_deref(),
                sender_is_bot,
                &msgid,
                &client_tags,
                &line,
                false,
            );
        }
        let ts = (state.config.clock)();
        state.push_channel_history(
            &key,
            super::state::HistoryEntry {
                msgid: msgid.clone(),
                ts,
                sender_prefix: prefix.clone(),
                kind,
                body: text.to_string(),
            },
        );
        let log = super::DbRequest::LogMessage {
            msgid,
            target: key.as_str().to_string(),
            sender_prefix: prefix.clone(),
            sender_account,
            kind: if loud { "privmsg" } else { "notice" },
            body: text.to_string(),
            ts,
        };
        if state.db_tx.try_push(log).is_err() {
            eprintln!("history: log queue full or closed; message not persisted");
            // Delivered but not persisted: mark the channel's history
            // incomplete so CHATHISTORY does not imply a gap-free record.
            if let Some(chan) = state.channels.get_mut(&key) {
                chan.history_complete = false;
            }
        }
    } else {
        let key = state.nick_key(target);
        let Some(&peer) = state.nicks.get(&key) else {
            if loud {
                state.numeric(
                    conn,
                    ERR_NOSUCHNICK,
                    &[target],
                    Some("No such nick/channel"),
                );
            }
            return;
        };
        let sender_account = state.sessions[&conn].account.clone();
        let sender_is_bot = state.sessions[&conn].bot;
        let msgid = state.next_msgid();
        deliver_message(
            state,
            &[peer],
            sender_account.as_deref(),
            sender_is_bot,
            &msgid,
            &client_tags,
            &line,
            true,
        );
        if state.sessions[&conn].caps.echo_message {
            deliver_message(
                state,
                &[conn],
                sender_account.as_deref(),
                sender_is_bot,
                &msgid,
                &client_tags,
                &line,
                false,
            );
        }
        // Away auto-reply, PRIVMSG only (NOTICE must stay reply-free).
        if loud && let Some(away) = state.sessions[&peer].away.clone() {
            let peer_nick = state.sessions[&peer].nick.clone().expect("registered");
            state.numeric(conn, RPL_AWAY, &[&peer_nick], Some(&away));
        }
    }
}

/// TAGMSG: tags-only message (message-tags spec). Only clients that
/// negotiated `message-tags` may send it, and only such clients receive
/// it — for everyone else it must not exist at all.
fn cmd_tagmsg(state: &mut ServerState, conn: ConnId, msg: &Message, p: &[&str]) {
    if !state.sessions[&conn].caps.message_tags {
        state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &["TAGMSG"],
            Some("Unknown command"),
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
        let may_speak = match member {
            Some(m) => !chan.modes.moderated || m.op || m.voice,
            None => !chan.modes.no_external,
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
        let Some(&peer) = state.nicks.get(&key) else {
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

// ---- topic --------------------------------------------------------------

fn cmd_topic(state: &mut ServerState, conn: ConnId, msg: &Message, p: &[&str]) {
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
        match &chan.topic {
            Some(t) => {
                let (text, set_by, set_at) = (t.text.clone(), t.set_by.clone(), t.set_at);
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
    let new_text = p.get(1).copied().unwrap_or("");
    let prefix = state.sessions[&conn].prefix();
    let now = (state.config.clock)();
    let new_topic = if new_text.is_empty() {
        None
    } else {
        Some(Topic {
            text: new_text.to_string(),
            set_by: prefix.clone(),
            set_at: now,
        })
    };
    state.channels.get_mut(&key).expect("checked").topic = new_topic.clone();
    let line = format!(":{prefix} TOPIC {display} :{new_text}");
    state.broadcast_channel(&key, &line, None);

    // A registered channel retains its topic across an empty→recreate
    // cycle: keep the hot copy in sync and persist it.
    if state.is_registered(&key) {
        match &new_topic {
            Some(t) => {
                state.registered_topics.insert(key.clone(), t.clone());
            }
            None => {
                state.registered_topics.remove(&key);
            }
        }
        let request = super::DbRequest::SetChannelTopic {
            channel: key.as_str().to_string(),
            topic: new_topic.map(|t| (t.text, t.set_by, t.set_at)),
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

fn cmd_mode(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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

fn user_mode(state: &mut ServerState, conn: ConnId, target: &str, rest: &[&str]) {
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

fn channel_mode(state: &mut ServerState, conn: ConnId, target: &str, rest: &[&str]) {
    let key = state.chan_key(target);
    let Some(chan) = state.channels.get(&key) else {
        state.numeric(conn, ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
        return;
    };
    let display = chan.name.clone();

    if rest.is_empty() {
        let modes = chan.modes.to_string_with_args();
        let created = chan.created_at.to_string();
        state.numeric(conn, RPL_CHANNELMODEIS, &[&display, &modes], None);
        state.numeric(conn, RPL_CREATIONTIME, &[&display, &created], None);
        return;
    }

    // A lone "+b"/"+q"/"+e"/"+I" is a list query (no op needed).
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
            "+e" | "e" => Some((
                chan.ban_exceptions.clone(),
                RPL_EXCEPTLIST,
                RPL_ENDOFEXCEPTLIST,
                None,
                "End of Channel Exception List",
            )),
            "+I" | "I" => Some((
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
    let mut applied = String::new();
    let mut applied_args: Vec<String> = Vec::new();
    let mut last_sign = ' ';

    for c in rest[0].chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'i' | 'm' | 'n' | 's' | 't' | 'C' => {
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
                push_mode(&mut applied, &mut last_sign, adding, c);
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
                        return;
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
                    chan.modes.key = Some(k.to_string());
                    applied_args.push(k.to_string());
                } else {
                    chan.modes.key = None;
                    // -k conventionally carries a placeholder arg ("*");
                    // consume it so later modes get the right params.
                    let _ = args.next();
                    applied_args.push("*".into());
                }
                push_mode(&mut applied, &mut last_sign, adding, c);
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
                        return;
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
                    applied_args.push(l.to_string());
                    push_mode(&mut applied, &mut last_sign, adding, c);
                } else {
                    chan.modes.limit = None;
                    push_mode(&mut applied, &mut last_sign, adding, c);
                }
            }
            'b' | 'q' | 'e' | 'I' => {
                let Some(&mask) = args.next() else {
                    continue; // handled above for the query form
                };
                let chan = state.channels.get_mut(&key).expect("checked");
                let list = match c {
                    'b' => &mut chan.bans,
                    'q' => &mut chan.quiets,
                    'e' => &mut chan.ban_exceptions,
                    'I' => &mut chan.invite_exceptions,
                    _ => unreachable!("outer arm matched only these list-mode chars"),
                };
                if adding {
                    if !list.iter().any(|b| b == mask) {
                        list.push(mask.to_string());
                    }
                } else {
                    list.retain(|b| b != mask);
                }
                applied_args.push(mask.to_string());
                push_mode(&mut applied, &mut last_sign, adding, c);
            }
            'o' | 'v' => {
                let Some(&who) = args.next() else {
                    state.numeric(
                        conn,
                        ERR_NEEDMOREPARAMS,
                        &["MODE"],
                        Some("Not enough parameters"),
                    );
                    return;
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
                applied_args.push(who.to_string());
                push_mode(&mut applied, &mut last_sign, adding, c);
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

    if !applied.is_empty() {
        let prefix = state.sessions[&conn].prefix();
        let mut line = format!(":{prefix} MODE {display} {applied}");
        for a in &applied_args {
            line.push(' ');
            line.push_str(a);
        }
        state.broadcast_channel(&key, &line, None);
    }
}

fn push_mode(applied: &mut String, last_sign: &mut char, adding: bool, c: char) {
    let sign = if adding { '+' } else { '-' };
    if *last_sign != sign {
        applied.push(sign);
        *last_sign = sign;
    }
    applied.push(c);
}

// ---- queries ------------------------------------------------------------

/// A `WHO <mask> %fields[,token]` request (the WHOX extension as
/// implemented by charybdis/Solanum and advertised by Libera).
struct WhoxRequest {
    fields: Vec<char>,
    token: Option<String>,
}

fn parse_whox(arg: &str) -> Option<WhoxRequest> {
    let spec = arg.strip_prefix('%')?;
    let (fields_part, token) = match spec.split_once(',') {
        Some((f, t)) => (f, Some(t.to_string())),
        None => (spec, None),
    };
    Some(WhoxRequest {
        fields: fields_part.chars().collect(),
        token,
    })
}

/// Emit one 354 row with fields in the fixed WHOX order:
/// t, c, u, i, h, s, n, f, d, l, a, o, r.
#[allow(clippy::too_many_arguments)]
fn send_whox_row(
    state: &mut ServerState,
    conn: ConnId,
    req: &WhoxRequest,
    channel: &str,
    user: &str,
    host: &str,
    server: &str,
    nick: &str,
    flags: &str,
    account: Option<&str>,
    realname: &str,
) {
    let mut middle: Vec<String> = Vec::new();
    let mut trailing = None;
    for f in "tcuihsnfdlaor".chars() {
        if !req.fields.contains(&f) {
            continue;
        }
        match f {
            't' => middle.push(req.token.clone().unwrap_or_else(|| "0".into())),
            'c' => middle.push(channel.to_string()),
            'u' => middle.push(user.to_string()),
            'i' => middle.push("255.255.255.255".into()), // IPs are not exposed
            'h' => middle.push(host.to_string()),
            's' => middle.push(server.to_string()),
            'n' => middle.push(nick.to_string()),
            'f' => middle.push(flags.to_string()),
            'd' => middle.push("0".into()), // hop count: single server
            'l' => middle.push("0".into()), // idle: not tracked yet
            'a' => middle.push(account.unwrap_or("0").to_string()),
            'o' => middle.push("n/a".into()), // oplevel unused (charybdis)
            'r' => trailing = Some(realname.to_string()),
            _ => {} // unknown field chars are ignored per WHOX practice
        }
    }
    let refs: Vec<&str> = middle.iter().map(String::as_str).collect();
    state.numeric(conn, RPL_WHOSPCRPL, &refs, trailing.as_deref());
}

/// WHO status flags: H (here) or G (gone/away), `*` for opers, then the
/// channel prefix sigil.
fn who_flags(session: &super::state::Session, sigil: &str) -> String {
    let here = if session.away.is_some() { "G" } else { "H" };
    let star = if session.oper { "*" } else { "" };
    let bot = if session.bot { "B" } else { "" };
    format!("{here}{star}{bot}{sigil}")
}

fn cmd_who(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&mask) = p.first() else {
        state.numeric(conn, RPL_ENDOFWHO, &["*"], Some("End of /WHO list"));
        return;
    };
    let whox = p.get(1).and_then(|arg| parse_whox(arg));
    let requester_multi_prefix = state.sessions[&conn].caps.multi_prefix;
    let server = state.config.server_name.clone();
    if mask.starts_with('#') {
        let key = state.chan_key(mask);
        if let Some(chan) = state.channels.get(&key) {
            let display = chan.name.clone();
            let rows: Vec<(String, String, String, String, String, Option<String>)> = chan
                .members
                .iter()
                .map(|(m, modes)| {
                    let s = &state.sessions[m];
                    let sigil = match (modes.op, modes.voice, requester_multi_prefix) {
                        (true, true, true) => "@+",
                        (true, _, _) => "@",
                        (false, true, _) => "+",
                        _ => "",
                    };
                    (
                        s.user.clone().expect("registered"),
                        s.host.clone(),
                        s.nick.clone().expect("registered"),
                        who_flags(s, sigil),
                        s.realname.clone().expect("registered"),
                        s.account.clone(),
                    )
                })
                .collect();
            for (user, host, nick, flags, realname, account) in rows {
                match &whox {
                    Some(req) => send_whox_row(
                        state,
                        conn,
                        req,
                        &display,
                        &user,
                        &host,
                        &server,
                        &nick,
                        &flags,
                        account.as_deref(),
                        &realname,
                    ),
                    None => state.numeric(
                        conn,
                        RPL_WHOREPLY,
                        &[&display, &user, &host, &server, &nick, &flags],
                        Some(&format!("0 {realname}")),
                    ),
                }
            }
        }
    } else {
        // Nick, mask, or "*"/"0" (everyone). Match against nick and host
        // under the server casemapping.
        let match_all = mask == "*" || mask == "0";
        let casemap = state.casemap;
        let targets: Vec<ConnId> = state
            .sessions
            .iter()
            .filter(|(_, s)| s.registered)
            .filter(|(_, s)| {
                match_all || {
                    let nick = s.nick.as_deref().unwrap_or("");
                    e6irc_proto::mask::matches(casemap, mask, nick)
                        || e6irc_proto::mask::matches(casemap, mask, &s.host)
                }
            })
            .map(|(c, _)| *c)
            .collect();
        // Invisible users are hidden from wildcard WHO unless the
        // requester is themselves, shares a channel, or named them
        // exactly.
        let is_wildcard = match_all || mask.contains('*') || mask.contains('?');
        let targets: Vec<ConnId> = targets
            .into_iter()
            .filter(|&peer| {
                !is_wildcard
                    || peer == conn
                    || !state.sessions[&peer].invisible
                    || state.share_channel(conn, peer)
            })
            .collect();
        for peer in targets {
            let s = &state.sessions[&peer];
            let (user, host, nick, realname, account, flags) = (
                s.user.clone().expect("registered"),
                s.host.clone(),
                s.nick.clone().expect("registered"),
                s.realname.clone().expect("registered"),
                s.account.clone(),
                who_flags(s, ""),
            );
            match &whox {
                Some(req) => send_whox_row(
                    state,
                    conn,
                    req,
                    "*",
                    &user,
                    &host,
                    &server,
                    &nick,
                    &flags,
                    account.as_deref(),
                    &realname,
                ),
                None => state.numeric(
                    conn,
                    RPL_WHOREPLY,
                    &["*", &user, &host, &server, &nick, &flags],
                    Some(&format!("0 {realname}")),
                ),
            }
        }
    }
    state.numeric(conn, RPL_ENDOFWHO, &[mask], Some("End of /WHO list"));
}

fn cmd_whois(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    // WHOIS [<server>] <nick>: when two params are given the first is a
    // server target we resolve locally, so the nick is always the last.
    let Some(&target) = p.last().filter(|_| !p.is_empty()) else {
        state.numeric(conn, ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
        return;
    };
    let key = state.nick_key(target);
    match state.nicks.get(&key).copied() {
        Some(peer) => {
            let s = &state.sessions[&peer];
            let (nick, user, host, realname) = (
                s.nick.clone().expect("registered"),
                s.user.clone().expect("registered"),
                s.host.clone(),
                s.realname.clone().expect("registered"),
            );
            let mut chans: Vec<String> = s
                .channels
                .iter()
                .filter_map(|k| {
                    let chan = state.channels.get(k)?;
                    let modes = chan.members.get(&peer)?;
                    let sigil = if modes.op {
                        "@"
                    } else if modes.voice {
                        "+"
                    } else {
                        ""
                    };
                    Some(format!("{sigil}{}", chan.name))
                })
                .collect();
            chans.sort();
            let server = state.config.server_name.clone();
            let network = state.config.network_name.clone();
            state.numeric(
                conn,
                RPL_WHOISUSER,
                &[&nick, &user, &host, "*"],
                Some(&realname),
            );
            if !chans.is_empty() {
                state.numeric(conn, RPL_WHOISCHANNELS, &[&nick], Some(&chans.join(" ")));
            }
            if state.sessions[&peer].bot {
                state.numeric(conn, RPL_WHOISBOT, &[&nick], Some("is a bot"));
            }
            if state.sessions[&peer].oper {
                state.numeric(
                    conn,
                    RPL_WHOISOPERATOR,
                    &[&nick],
                    Some("is an IRC operator"),
                );
            }
            state.numeric(conn, RPL_WHOISSERVER, &[&nick, &server], Some(&network));
            if let Some(away) = state.sessions[&peer].away.clone() {
                state.numeric(conn, RPL_AWAY, &[&nick], Some(&away));
            }
            if let Some(account) = state.sessions[&peer].account.clone() {
                state.numeric(
                    conn,
                    RPL_WHOISACCOUNT,
                    &[&nick, &account],
                    Some("is logged in as"),
                );
            }
            state.numeric(conn, RPL_ENDOFWHOIS, &[&nick], Some("End of /WHOIS list"));
        }
        None => {
            state.numeric(
                conn,
                ERR_NOSUCHNICK,
                &[target],
                Some("No such nick/channel"),
            );
            state.numeric(conn, RPL_ENDOFWHOIS, &[target], Some("End of /WHOIS list"));
        }
    }
}

/// SETNAME (IRCv3): change realname; visible only to setname-capable
/// clients. Clients that never negotiated the cap get 421 on use.
fn cmd_setname(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].caps.setname {
        state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &["SETNAME"],
            Some("Unknown command"),
        );
        return;
    }
    let Some(&new_name) = p.first() else {
        let server = state.config.server_name.clone();
        state.send(
            conn,
            &format!(":{server} FAIL SETNAME INVALID_REALNAME :Realname required"),
        );
        return;
    };
    if new_name.is_empty() {
        let server = state.config.server_name.clone();
        state.send(
            conn,
            &format!(":{server} FAIL SETNAME INVALID_REALNAME :Realname required"),
        );
        return;
    }
    let prefix = state.sessions[&conn].prefix();
    state.sessions.get_mut(&conn).expect("checked").realname = Some(new_name.to_string());
    let line = format!(":{prefix} SETNAME :{new_name}");
    state.send_timed(conn, &line);
    for peer in state.channel_peers(conn) {
        if state.sessions.get(&peer).is_some_and(|s| s.caps.setname) {
            state.send_timed(peer, &line);
        }
    }
}

// ---- KICK / INVITE / AWAY / LIST / USERHOST -----------------------------

fn cmd_kick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
        Some(reason) => format!(":{prefix} KICK {display} {victim_nick} :{reason}"),
        None => format!(":{prefix} KICK {display} {victim_nick} :{kicker_nick}"),
    };
    state.broadcast_channel(&key, &line, None);
    let chan = state.channels.get_mut(&key).expect("checked");
    chan.members.remove(&victim);
    let empty = chan.members.is_empty();
    if empty {
        state.channels.remove(&key);
    }
    state
        .sessions
        .get_mut(&victim)
        .expect("member")
        .channels
        .remove(&key);
}

fn cmd_invite(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
    let Some(&invitee) = state.nicks.get(&who_key) else {
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

fn cmd_away(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let message = p.first().filter(|m| !m.is_empty()).map(|m| m.to_string());
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

fn cmd_list(state: &mut ServerState, conn: ConnId) {
    state.numeric(conn, RPL_LISTSTART, &["Channel"], Some("Users  Name"));
    let rows: Vec<(String, usize, String)> = state
        .channels
        .values()
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

fn cmd_userhost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["USERHOST"],
            Some("Not enough parameters"),
        );
        return;
    }
    let mut entries = Vec::new();
    for &nick in p.iter().take(5) {
        let key = state.nick_key(nick);
        if let Some(&peer) = state.nicks.get(&key) {
            let s = &state.sessions[&peer];
            let away_marker = if s.away.is_some() { "-" } else { "+" };
            entries.push(format!(
                "{}={}{}@{}",
                s.nick.as_deref().expect("registered"),
                away_marker,
                s.user.as_deref().expect("registered"),
                s.host,
            ));
        }
    }
    state.numeric(conn, RPL_USERHOST, &[], Some(&entries.join(" ")));
}

// ---- CHATHISTORY (draft/chathistory, hot ring) --------------------------

fn chathistory_fail(state: &mut ServerState, conn: ConnId, code: &str, detail: &str) {
    let server = state.config.server_name.clone();
    state.send(
        conn,
        &format!(":{server} FAIL CHATHISTORY {code} :{detail}"),
    );
}

/// Serve history from the channel's hot ring. Entries older than the
/// ring live only in PostgreSQL; the DB fallback is tracked in PLAN.md
/// and requests beyond the ring return what the ring holds.
fn cmd_chathistory(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let caps = state.sessions[&conn].caps;
    if !caps.batch || !caps.chathistory {
        chathistory_fail(
            state,
            conn,
            "NEED_CAPS",
            "batch and draft/chathistory required",
        );
        return;
    }
    // TARGETS enumerates buffers, not a single channel — handle it before
    // the channel-target parsing below.
    if p.first().is_some_and(|s| s.eq_ignore_ascii_case("TARGETS")) {
        chathistory_targets(state, conn, p);
        return;
    }
    let (Some(&sub), Some(&target)) = (p.first(), p.get(1)) else {
        chathistory_fail(state, conn, "NEED_MORE_PARAMS", "Missing parameters");
        return;
    };
    let key = state.chan_key(target);
    let is_member = state
        .channels
        .get(&key)
        .is_some_and(|c| c.members.contains_key(&conn));
    if !is_member {
        chathistory_fail(state, conn, "INVALID_TARGET", "You are not on that channel");
        return;
    }
    // BETWEEN takes two selectors then the limit; the others take one
    // selector then the limit.
    let is_between = sub.eq_ignore_ascii_case("BETWEEN");
    let limit: usize = p
        .get(if is_between { 4 } else { 3 })
        .and_then(|l| l.parse().ok())
        .unwrap_or(50)
        .min(500);
    let selector = p.get(2).copied().unwrap_or("*");
    let selector2 = p.get(3).copied().unwrap_or("*");
    let history: std::collections::VecDeque<super::state::HistoryEntry> =
        state.channels[&key].history.clone();

    let position = |sel: &str| -> Option<usize> {
        if let Some(msgid) = sel.strip_prefix("msgid=") {
            history.iter().position(|e| e.msgid == msgid)
        } else if let Some(ts) = sel.strip_prefix("timestamp=") {
            // first entry at/after the timestamp
            let ts = e6irc_proto::time::parse_server_time_seconds(ts)?;
            history.iter().position(|e| e.ts >= ts)
        } else {
            None
        }
    };

    // Resolve to a window against the ring; `covered` is false when the
    // request reaches older than the ring holds (its oldest entry is
    // still inside the requested window), meaning PostgreSQL must serve.
    // The ring answers completely only while it holds the channel's
    // entire history; once overflowed or evicted (LRU), older rows live
    // in Postgres and the request must fall back.
    let complete = state.channels[&key].history_complete;
    let (entries, covered): (Vec<super::state::HistoryEntry>, bool) =
        match sub.to_ascii_uppercase().as_str() {
            "LATEST" => {
                let skip = history.len().saturating_sub(limit);
                let covered = complete || history.len() >= limit;
                (history.iter().skip(skip).cloned().collect(), covered)
            }
            "BEFORE" => match position(selector) {
                Some(pos) => {
                    let start = pos.saturating_sub(limit);
                    let covered = complete || start > 0;
                    (
                        history.iter().take(pos).skip(start).cloned().collect(),
                        covered,
                    )
                }
                // reference past a full ring: only PG can resolve it
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "AFTER" => match position(selector) {
                Some(pos) => (
                    history.iter().skip(pos + 1).take(limit).cloned().collect(),
                    true,
                ),
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "AROUND" => match position(selector) {
                Some(pos) => {
                    let before = limit / 2;
                    let start = pos.saturating_sub(before);
                    let end = (pos + (limit - before)).min(history.len());
                    // Only the older half can reach past the ring's start.
                    let covered = complete || start > 0;
                    (
                        history.iter().take(end).skip(start).cloned().collect(),
                        covered,
                    )
                }
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "BETWEEN" => match (position(selector), position(selector2)) {
                // Both endpoints in the ring: the span between them is
                // contiguous and fully in memory.
                (Some(a), Some(b)) => {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    (
                        history
                            .iter()
                            .take(hi)
                            .skip(lo + 1)
                            .take(limit)
                            .cloned()
                            .collect(),
                        true,
                    )
                }
                // An endpoint missing from the ring: only PG can resolve it.
                _ => (Vec::new(), complete),
            },
            other => {
                chathistory_fail(
                    state,
                    conn,
                    "INVALID_PARAMS",
                    &format!("Unknown subcommand {other}"),
                );
                return;
            }
        };

    let display = state.channels[&key].name.clone();
    let batch_ref = state.next_msgid();

    // Ring miss with a database available: page from PostgreSQL instead,
    // preserving one code path for rendering (history_page).
    if !covered && state.config.sasl_enabled {
        let query = match sub.to_ascii_uppercase().as_str() {
            "LATEST" => super::HistoryQuery::Latest { limit },
            "BEFORE" => super::HistoryQuery::Before {
                before_ts: selector_ts(&history, selector).unwrap_or(u64::MAX),
                limit,
            },
            "AROUND" => super::HistoryQuery::Around {
                around_ts: selector_ts(&history, selector).unwrap_or(0),
                limit,
            },
            "BETWEEN" => {
                let a = selector_ts(&history, selector).unwrap_or(0);
                let b = selector_ts(&history, selector2).unwrap_or(u64::MAX);
                let (after_ts, before_ts) = if a <= b { (a, b) } else { (b, a) };
                super::HistoryQuery::Between {
                    after_ts,
                    before_ts,
                    limit,
                }
            }
            _ => super::HistoryQuery::After {
                after_ts: selector_ts(&history, selector).unwrap_or(0),
                limit,
            },
        };
        let request = super::DbRequest::QueryHistory {
            conn,
            target: key.as_str().to_string(),
            display: display.clone(),
            batch_ref,
            query,
        };
        if state.db_tx.try_push(request).is_err() {
            chathistory_fail(
                state,
                conn,
                "MESSAGE_ERROR",
                "History temporarily unavailable",
            );
        }
        return;
    }

    let rows: Vec<super::HistoryRow> = entries
        .into_iter()
        .map(|e| super::HistoryRow {
            msgid: e.msgid,
            ts: e.ts,
            sender_prefix: e.sender_prefix,
            kind: e.kind.to_string(),
            body: e.body,
        })
        .collect();
    history_page(state, conn, &display, &batch_ref, rows);
}

/// CHATHISTORY TARGETS: enumerate the requester's buffers with activity in
/// a `timestamp=<a> timestamp=<b> <limit>` window (DESIGN §11.2). A
/// bouncer/multi-buffer client uses this to find which channels have
/// backlog on reconnect. Targets are the channels the requester is on;
/// the authoritative source is PostgreSQL, with the hot ring answering
/// when no database is configured.
fn chathistory_targets(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let parse = |i: usize| {
        p.get(i)
            .and_then(|s| s.strip_prefix("timestamp="))
            .and_then(e6irc_proto::time::parse_server_time_seconds)
    };
    let (Some(a), Some(b)) = (parse(1), parse(2)) else {
        chathistory_fail(
            state,
            conn,
            "INVALID_PARAMS",
            "Expected two timestamp= bounds",
        );
        return;
    };
    let (min_ts, max_ts) = if a <= b { (a, b) } else { (b, a) };
    let limit = p
        .get(3)
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);

    // Visible targets are the channels the requester is on.
    let keys: Vec<super::state::ChanKey> = state.sessions[&conn].channels.iter().cloned().collect();
    let batch_ref = state.next_msgid();
    if keys.is_empty() {
        targets_page(state, conn, &batch_ref, Vec::new());
        return;
    }

    if state.config.sasl_enabled {
        let channels = keys.iter().map(|k| k.as_str().to_string()).collect();
        let request = super::DbRequest::QueryTargets {
            conn,
            channels,
            min_ts,
            max_ts,
            limit,
            batch_ref,
        };
        if state.db_tx.try_push(request).is_err() {
            chathistory_fail(
                state,
                conn,
                "MESSAGE_ERROR",
                "History temporarily unavailable",
            );
        }
        return;
    }

    // No database: enumerate from the hot rings.
    let mut targets: Vec<(String, u64)> = Vec::new();
    for key in keys {
        if let Some(chan) = state.channels.get(&key)
            && let Some(latest) = chan
                .history
                .iter()
                .filter(|e| e.ts >= min_ts && e.ts <= max_ts)
                .map(|e| e.ts)
                .max()
        {
            targets.push((chan.name.clone(), latest));
        }
    }
    targets.sort_by_key(|t| std::cmp::Reverse(t.1));
    targets.truncate(limit);
    targets_page(state, conn, &batch_ref, targets);
}

/// Emit a `draft/chathistory-targets` batch: one `CHATHISTORY TARGETS
/// <target> <time>` line per buffer, newest-first.
pub(crate) fn targets_page(
    state: &mut ServerState,
    conn: ConnId,
    batch_ref: &str,
    targets: Vec<(String, u64)>,
) {
    let server = state.config.server_name.clone();
    state.send(
        conn,
        &format!(":{server} BATCH +{batch_ref} draft/chathistory-targets"),
    );
    for (target, ts) in targets {
        // Prefer the channel's display name while it is still in memory.
        let key = state.chan_key(&target);
        let display = state
            .channels
            .get(&key)
            .map(|c| c.name.clone())
            .unwrap_or(target);
        let time = e6irc_proto::time::server_time(ts * 1000);
        state.send(
            conn,
            &format!("@batch={batch_ref} :{server} CHATHISTORY TARGETS {display} {time}"),
        );
    }
    state.send(conn, &format!(":{server} BATCH -{batch_ref}"));
}

/// A ring-missing reference needs PostgreSQL when the ring is full
/// (older rows may exist) and the selector is a timestamp we can bound
/// on directly. A msgid absent from the ring is treated as ring-empty
/// (returns nothing) rather than triggering an unbounded DB scan.
fn needs_db_for_missing_ref(ring_full: bool, selector: &str) -> bool {
    ring_full && selector.starts_with("timestamp=")
}

/// Resolve a msgid=/timestamp= selector to a timestamp for DB paging.
fn selector_ts(
    history: &std::collections::VecDeque<super::state::HistoryEntry>,
    selector: &str,
) -> Option<u64> {
    if let Some(msgid) = selector.strip_prefix("msgid=") {
        history.iter().find(|e| e.msgid == msgid).map(|e| e.ts)
    } else if let Some(ts) = selector.strip_prefix("timestamp=") {
        e6irc_proto::time::parse_server_time_seconds(ts)
    } else {
        None
    }
}

/// Render a resolved history window as a batch. The single choke point
/// for CHATHISTORY output, used by both the ring and DB paths.
pub(crate) fn history_page(
    state: &mut ServerState,
    conn: ConnId,
    display: &str,
    batch_ref: &str,
    rows: Vec<super::HistoryRow>,
) {
    let server = state.config.server_name.clone();
    state.send(
        conn,
        &format!(":{server} BATCH +{batch_ref} chathistory {display}"),
    );
    for row in rows {
        let time = e6irc_proto::time::server_time(row.ts * 1000);
        let line = format!(
            "@batch={batch_ref};msgid={};time={time} :{} {} {display} :{}",
            row.msgid, row.sender_prefix, row.kind, row.body,
        );
        state.send(conn, &line);
    }
    state.send(conn, &format!(":{server} BATCH -{batch_ref}"));
}

// ---- MONITOR ------------------------------------------------------------

const MONITOR_LIMIT: usize = 100;

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
            .nicks
            .get(&key)
            .map(|c| state.sessions[c].prefix())
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

fn monitor_status(
    state: &mut ServerState,
    conn: ConnId,
    targets: &[(super::state::NickKey, String)],
) {
    let mut online = Vec::new();
    let mut offline = Vec::new();
    for (key, shown) in targets {
        match state.nicks.get(key) {
            Some(c) => online.push(state.sessions[c].prefix()),
            None => offline.push(shown.clone()),
        }
    }
    if !online.is_empty() {
        state.numeric(conn, RPL_MONONLINE, &[], Some(&online.join(",")));
    }
    if !offline.is_empty() {
        state.numeric(conn, RPL_MONOFFLINE, &[], Some(&offline.join(",")));
    }
}

fn cmd_monitor(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
            for nick in list.split(',').filter(|n| !n.is_empty()) {
                let key = state.nick_key(nick);
                if state.sessions[&conn].monitoring.contains_key(&key) {
                    continue;
                }
                if state.sessions[&conn].monitoring.len() >= MONITOR_LIMIT {
                    state.numeric(
                        conn,
                        ERR_MONLISTFULL,
                        &[&MONITOR_LIMIT.to_string(), nick],
                        Some("Monitor list is full."),
                    );
                    return;
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
            if !shown.is_empty() {
                state.numeric(conn, RPL_MONLIST, &[], Some(&shown.join(",")));
            }
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

// ---- read-marker (draft/read-marker) ------------------------------------

fn markread_fail(state: &mut ServerState, conn: ConnId, target: &str, code: &str, detail: &str) {
    let server = state.config.server_name.clone();
    state.send(
        conn,
        &format!(":{server} FAIL MARKREAD {code} {target} :{detail}"),
    );
}

fn cmd_markread(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].caps.read_marker {
        state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &["MARKREAD"],
            Some("Unknown command"),
        );
        return;
    }
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["MARKREAD"],
            Some("Not enough parameters"),
        );
        return;
    };
    let Some(account) = state.sessions[&conn].account.clone() else {
        markread_fail(
            state,
            conn,
            target,
            "INTERNAL_ERROR",
            "You must be logged in",
        );
        return;
    };
    let key = state.chan_key(target);
    let server = state.config.server_name.clone();

    // Query form: MARKREAD <target>
    let Some(&arg) = p.get(1) else {
        let marker = state
            .read_markers
            .get(&(account, key))
            .map(|ms| format!("timestamp={}", e6irc_proto::time::server_time(*ms)))
            .unwrap_or_else(|| "*".to_string());
        state.send(conn, &format!(":{server} MARKREAD {target} {marker}"));
        return;
    };

    // Set form: MARKREAD <target> timestamp=<iso>
    let Some(ts) = arg.strip_prefix("timestamp=") else {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Expected timestamp=");
        return;
    };
    let Some(secs) = e6irc_proto::time::parse_server_time_seconds(ts) else {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Malformed timestamp");
        return;
    };
    let new_ms = secs * 1000;
    let slot = state
        .read_markers
        .entry((account.clone(), key.clone()))
        .or_insert(0);
    let moved_forward = new_ms > *slot;
    if moved_forward {
        *slot = new_ms;
        let persist = super::DbRequest::SetReadMarker {
            account: account.clone(),
            target: key.as_str().to_string(),
            marker_ms: new_ms,
        };
        if state.db_tx.try_push(persist).is_err() {
            eprintln!(
                "history: db queue full or closed; read marker for {} not persisted",
                key.as_str()
            );
        }
    }
    let current = *state
        .read_markers
        .get(&(account.clone(), key))
        .expect("just inserted");
    let line = format!(
        ":{server} MARKREAD {target} timestamp={}",
        e6irc_proto::time::server_time(current)
    );
    // A forward move syncs to all the account's clients; a no-op just
    // confirms the current marker to the requester.
    if moved_forward {
        for peer in state.account_connections(&account) {
            state.send(peer, &line);
        }
    } else {
        state.send(conn, &line);
    }
}

// ---- WHOWAS -------------------------------------------------------------

fn cmd_whowas(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&target) = p.first() else {
        state.numeric(conn, ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
        return;
    };
    // Optional count: <= 0 or absent means "all entries".
    let count = p.get(1).and_then(|c| c.parse::<i64>().ok());
    let limit = match count {
        Some(n) if n > 0 => n as usize,
        _ => usize::MAX,
    };
    let key = state.nick_key(target);
    let server = state.config.server_name.clone();
    let matches: Vec<super::state::WhowasEntry> = state
        .whowas
        .iter()
        .filter(|e| state.nick_key(&e.nick) == key)
        .take(limit)
        .cloned()
        .collect();
    if matches.is_empty() {
        state.numeric(
            conn,
            ERR_WASNOSUCHNICK,
            &[target],
            Some("There was no such nickname"),
        );
    } else {
        for entry in matches {
            state.numeric(
                conn,
                RPL_WHOWASUSER,
                &[&entry.nick, &entry.user, &entry.host, "*"],
                Some(&entry.realname),
            );
            state.numeric(
                conn,
                RPL_WHOISSERVER,
                &[&entry.nick, &server],
                Some("(unknown)"),
            );
        }
    }
    state.numeric(conn, RPL_ENDOFWHOWAS, &[target], Some("End of WHOWAS"));
}

// ---- TIME / INFO --------------------------------------------------------

fn cmd_time(state: &mut ServerState, conn: ConnId) {
    let server = state.config.server_name.clone();
    let now = e6irc_proto::time::server_time((state.config.clock)() * 1000);
    state.numeric(conn, RPL_TIME, &[&server], Some(&now));
}

fn cmd_info(state: &mut ServerState, conn: ConnId) {
    for line in [
        concat!("e6ircd version ", env!("CARGO_PKG_VERSION")),
        "A monolithic Rust IRCv3 server.",
    ] {
        state.numeric(conn, RPL_INFO, &[], Some(line));
    }
    state.numeric(conn, RPL_ENDOFINFO, &[], Some("End of INFO list"));
}

// ---- OPER ---------------------------------------------------------------

fn cmd_oper(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&name), Some(&password)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["OPER"],
            Some("Not enough parameters"),
        );
        return;
    };
    let matched = state
        .config
        .opers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, pw)| constant_time_eq(pw.as_bytes(), password.as_bytes()))
        .unwrap_or(false);
    if !matched {
        state.numeric(conn, ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
        return;
    }
    state.sessions.get_mut(&conn).expect("registered").oper = true;
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    record_audit(state, conn, "OPER", name, "");
    state.numeric(
        conn,
        RPL_YOUREOPER,
        &[],
        Some("You are now an IRC operator"),
    );
    let server = state.config.server_name.clone();
    state.send(conn, &format!(":{server} MODE {nick} :+o"));
}

/// Length-independent comparison — oper passwords must not leak length
/// or prefix via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---- KILL ---------------------------------------------------------------

fn cmd_kill(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let Some(&target) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["KILL"],
            Some("Not enough parameters"),
        );
        return;
    };
    let key = state.nick_key(target);
    let Some(&victim) = state.nicks.get(&key) else {
        state.numeric(
            conn,
            ERR_NOSUCHNICK,
            &[target],
            Some("No such nick/channel"),
        );
        return;
    };
    let comment = p.get(1).copied().unwrap_or("Killed");
    let oper_nick = state.sessions[&conn].nick.clone().expect("registered");
    let reason = format!("Killed ({oper_nick} ({comment}))");
    let server = state.config.server_name.clone();
    state.send(victim, &format!("ERROR :Closing Link: {server} ({reason})"));
    state.close(victim, &reason);
    record_audit(state, conn, "KILL", target, comment);
}

/// Record a privileged oper action in the audit log (best-effort; only
/// when a database is configured to hold it).
fn record_audit(state: &mut ServerState, conn: ConnId, action: &str, target: &str, detail: &str) {
    if !state.config.sasl_enabled {
        return;
    }
    let actor = state
        .sessions
        .get(&conn)
        .and_then(|s| s.nick.clone())
        .unwrap_or_default();
    let request = super::DbRequest::AuditLog {
        actor,
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.to_string(),
    };
    if state.db_tx.try_push(request).is_err() {
        eprintln!("audit: db queue full or closed; {action} action not recorded");
    }
}

/// Normalise a K-line target: a bare host/nick becomes `*@target`.
fn kline_mask(arg: &str) -> String {
    if arg.contains('@') {
        arg.to_string()
    } else {
        format!("*@{arg}")
    }
}

/// KLINE [<user@host> [reason]] — oper-only. With no argument, list the
/// current server bans; otherwise add one (persisted, matching users
/// disconnected).
fn cmd_kline(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    let Some(&mask_arg) = p.first() else {
        // List current K-lines.
        let lines: Vec<String> = state
            .klines
            .iter()
            .map(|k| {
                format!(
                    ":{server} NOTICE {nick} :K-Line {} (by {}) :{}",
                    k.mask, k.set_by, k.reason
                )
            })
            .collect();
        for line in lines {
            state.send(conn, &line);
        }
        state.send(
            conn,
            &format!(":{server} NOTICE {nick} :End of K-Line list."),
        );
        return;
    };
    let mask = kline_mask(mask_arg);
    let reason = p.get(1).copied().unwrap_or("No reason").to_string();
    // Replace any existing ban on the same mask.
    state.klines.retain(|k| k.mask != mask);
    state.klines.push(super::state::Kline {
        mask: mask.clone(),
        reason: reason.clone(),
        set_by: nick.clone(),
    });
    if state.config.sasl_enabled {
        let request = super::DbRequest::AddKline {
            mask: mask.clone(),
            reason: reason.clone(),
            set_by: nick.clone(),
        };
        if state.db_tx.try_push(request).is_err() {
            eprintln!("kline: db queue full or closed; K-Line for {mask} not persisted");
        }
    }
    // Disconnect any matching registered sessions.
    let casemap = state.casemap;
    let victims: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.registered)
        .filter_map(|(&c, s)| {
            let subject = format!("{}@{}", s.user.as_deref().unwrap_or("*"), s.host);
            e6irc_proto::mask::matches(casemap, &mask, &subject).then_some(c)
        })
        .collect();
    for victim in victims {
        state.send(victim, &format!("ERROR :Closing Link: (K-Lined: {reason})"));
        state.close(victim, &format!("K-Lined: {reason}"));
    }
    record_audit(state, conn, "KLINE", &mask, &reason);
    state.send(
        conn,
        &format!(":{server} NOTICE {nick} :Added K-Line for {mask}"),
    );
}

/// UNKLINE <user@host> — oper-only. Remove a server ban.
fn cmd_unkline(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let Some(&mask_arg) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["UNKLINE"],
            Some("Not enough parameters"),
        );
        return;
    };
    let mask = kline_mask(mask_arg);
    let before = state.klines.len();
    state.klines.retain(|k| k.mask != mask);
    let removed = state.klines.len() < before;
    if removed && state.config.sasl_enabled {
        let request = super::DbRequest::RemoveKline { mask: mask.clone() };
        if state.db_tx.try_push(request).is_err() {
            eprintln!("unkline: db queue full or closed; removal of {mask} not persisted");
        }
    }
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn].nick.clone().expect("registered");
    let msg = if removed {
        format!("Removed K-Line for {mask}")
    } else {
        format!("No K-Line found for {mask}")
    };
    if removed {
        record_audit(state, conn, "UNKLINE", &mask, "");
    }
    state.send(conn, &format!(":{server} NOTICE {nick} :{msg}"));
}

/// SETHOST <nick> <host> — oper-only. Change a user's displayed host
/// (cloak) and announce it via CHGHOST to capable peers. This is the
/// host-change trigger the chghost cap needs.
fn cmd_sethost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let (Some(&nick), Some(&newhost)) = (p.first(), p.get(1)) else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["SETHOST"],
            Some("Not enough parameters"),
        );
        return;
    };
    let server = state.config.server_name.clone();
    let oper_nick = state.sessions[&conn].nick.clone().expect("registered");
    // A host must be a single non-empty token without user/prefix chars.
    if newhost.is_empty() || newhost.contains([' ', '@', '!', '\0']) {
        state.send(
            conn,
            &format!(":{server} NOTICE {oper_nick} :Invalid host: {newhost}"),
        );
        return;
    }
    let nk = state.nick_key(nick);
    let Some(&target) = state.nicks.get(&nk) else {
        state.numeric(conn, ERR_NOSUCHNICK, &[nick], Some("No such nick/channel"));
        return;
    };
    let (user, old_prefix) = {
        let s = &state.sessions[&target];
        (s.user.clone().unwrap_or_default(), s.prefix())
    };
    state.sessions.get_mut(&target).expect("checked").host = newhost.to_string();

    // Announce with the old prefix so clients can match, to every
    // chghost-capable peer (including the target).
    let chghost = format!(":{old_prefix} CHGHOST {user} {newhost}");
    let mut recipients = state.channel_peers(target);
    recipients.push(target);
    for peer in recipients {
        if state.sessions.get(&peer).is_some_and(|s| s.caps.chghost) {
            state.send_timed(peer, &chghost);
        }
    }
    record_audit(state, conn, "SETHOST", nick, newhost);
    state.send(
        conn,
        &format!(":{server} NOTICE {oper_nick} :Set host of {nick} to {newhost}"),
    );
}

// ---- WALLOPS ------------------------------------------------------------

fn cmd_wallops(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].oper {
        state.numeric(
            conn,
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        return;
    }
    let Some(&text) = p.first() else {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["WALLOPS"],
            Some("Not enough parameters"),
        );
        return;
    };
    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} WALLOPS :{text}");
    let recipients: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.registered && s.wallops)
        .map(|(c, _)| *c)
        .collect();
    for recipient in recipients {
        state.send_timed(recipient, &line);
    }
}
