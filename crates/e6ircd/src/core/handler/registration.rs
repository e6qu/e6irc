//! Connection registration and capability negotiation.

use super::message::{MULTILINE_CAP, MULTILINE_MAX_BYTES, MULTILINE_MAX_LINES};
use super::*;

// ---- registration -------------------------------------------------------

pub(super) fn cmd_nick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&nick) = p.first() else {
        state.numeric(conn, ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
        return;
    };
    if !crate::sanitize::valid_nick(nick, state.config.nicklen) {
        state.numeric(
            conn,
            ERR_ERRONEUSNICKNAME,
            &[nick],
            Some("Erroneous nickname"),
        );
        return;
    }
    let key = state.nick_key(nick);
    // Service pseudo-client nicks are reserved: PRIVMSG to them is intercepted,
    // so a user holding one could never receive messages and could impersonate
    // the service.
    if is_service_nick(key.as_str()) {
        state.numeric(
            conn,
            ERR_ERRONEUSNICKNAME,
            &[nick],
            Some("Nickname is reserved"),
        );
        return;
    }
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
    // NICK to the *exact* current nick (identical bytes, not merely the same
    // casefold) is a no-op: no rename, no broadcast, no reply. A case change
    // (alice→Alice) is a real change and falls through.
    if registered && old_nick_display.as_deref() == Some(nick) {
        return;
    }
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
        // Route through send_timed (self and each peer) so server-time clients
        // get an @time= tag, like every other membership event — a raw
        // send_bytes loop would silently omit it for NICK alone.
        state.send_timed(conn, &line);
        let peers = state.channel_peers(conn);
        for peer in peers {
            state.send_timed(peer, &line);
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

pub(super) fn cmd_user(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
    // Identity fields are bounded at intake (USERLEN/REALLEN below, nick by
    // nicklen): they ride in the source prefix or WHOIS replies of *other*
    // lines, so an unbounded one makes every such line's fixed head unbounded
    // and no per-line fitting can save it. Truncation here is the protocol
    // norm (Solanum does the same) and USERLEN is advertised in ISUPPORT.
    session.user = Some(crate::sanitize::username(p[0], USERLEN));
    session.realname = Some(truncate_chars(p[3], REALLEN).to_string());
    maybe_complete_registration(state, conn);
}

// ---- capability negotiation ---------------------------------------------

pub(super) fn cap_target(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .nick
        .clone()
        .unwrap_or_else(|| "*".into())
}

/// `FAIL REGISTER <code> <account> :<description>` — the spec's shape, with the
/// account the client asked about so it can tell which attempt failed.
pub(super) fn register_fail(
    state: &mut ServerState,
    conn: ConnId,
    code: &str,
    account: &str,
    detail: &str,
) {
    let server = state.config.server_name.clone();
    state.send(
        conn,
        &format!(":{server} FAIL REGISTER {code} {account} :{detail}"),
    );
}

/// `REGISTER <account> <email> <password>` (draft/account-registration).
///
/// The account always takes the registering nick's name: `custom-account-name`
/// is not advertised, so a client cannot register a name it is not currently
/// holding, and "the account you registered is the nick you held" stays true.
pub(super) fn cmd_register(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.config.sasl_enabled {
        // No database means no accounts; the capability is not advertised
        // either, so this is a client ignoring that.
        register_fail(
            state,
            conn,
            "TEMPORARILY_UNAVAILABLE",
            "*",
            "Account registration is not available on this server",
        );
        return;
    }
    let nick = state.sessions[&conn].nick.clone();
    let [account, email, password] = p else {
        register_fail(
            state,
            conn,
            "NEED_MORE_PARAMS",
            nick.as_deref().unwrap_or("*"),
            "Syntax: REGISTER <account|*> <email|*> <password>",
        );
        return;
    };
    // A connection that has not finished registering has not proven it can
    // hold the nick it is asking to register, so this is opt-in.
    if !state.sessions[&conn].registered && !state.config.registration_before_connect {
        register_fail(
            state,
            conn,
            "COMPLETE_CONNECTION_REQUIRED",
            nick.as_deref().unwrap_or("*"),
            "Complete your connection before registering an account",
        );
        return;
    }
    // `*` means "my current nick". Without a nick there is nothing to name the
    // account after — which is the case when the nick the client wanted was
    // already taken, so it is reported as the name being unavailable.
    let Some(nick) = nick else {
        register_fail(
            state,
            conn,
            "ACCOUNT_EXISTS",
            "*",
            "That nickname is already in use, so it cannot be registered",
        );
        return;
    };
    if *account != "*" && !state.casemap.eq(account, &nick) {
        register_fail(
            state,
            conn,
            "ACCOUNT_NAME_MUST_BE_NICK",
            account,
            "You may only register the nickname you are currently using",
        );
        return;
    }
    if state.config.registration_require_email && *email == "*" {
        register_fail(
            state,
            conn,
            "INVALID_EMAIL",
            &nick,
            "An email address is required to register on this server",
        );
        return;
    }
    if state.sessions[&conn].account.is_some() {
        register_fail(
            state,
            conn,
            "ALREADY_AUTHENTICATED",
            &nick,
            "You are already logged in",
        );
        return;
    }
    let request = crate::core::DbRequest::CreateAccount {
        conn,
        name: nick.clone(),
        password: password.to_string(),
        origin: crate::core::AccountOrigin::RegisterCommand,
    };
    if state.db_tx.try_push(request).is_err() {
        register_fail(
            state,
            conn,
            "TEMPORARILY_UNAVAILABLE",
            &nick,
            "Account registration is temporarily unavailable",
        );
    } else {
        // The answer needs a database round trip; hold this connection's later
        // output behind it so the reply cannot be overtaken by, say, the PONG
        // to a PING the client pipelined after REGISTER.
        state.defer_reply(conn);
    }
}

/// The `draft/account-registration` capability name.
pub(super) const ACCOUNT_REGISTRATION_CAP: &str = "draft/account-registration";

/// The capability's advertised value: the policy a client must satisfy,
/// comma-separated. `custom-account-name` is deliberately absent — an account
/// always takes the registering nick's name, which is what makes "the account
/// you registered is the nick you held" true.
pub(super) fn account_registration_flags(state: &ServerState) -> String {
    let mut flags: Vec<&str> = Vec::new();
    if state.config.registration_before_connect {
        flags.push("before-connect");
    }
    if state.config.registration_require_email {
        flags.push("email-required");
    }
    flags.join(",")
}

pub(super) fn cmd_cap(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
                names.push(if v302 {
                    match account_registration_flags(state) {
                        flags if flags.is_empty() => ACCOUNT_REGISTRATION_CAP.into(),
                        flags => format!("{ACCOUNT_REGISTRATION_CAP}={flags}"),
                    }
                } else {
                    ACCOUNT_REGISTRATION_CAP.into()
                });
            }
            names.push(if v302 {
                format!(
                    "{MULTILINE_CAP}=max-bytes={MULTILINE_MAX_BYTES},max-lines={MULTILINE_MAX_LINES}"
                )
            } else {
                MULTILINE_CAP.into()
            });
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
                if name == ACCOUNT_REGISTRATION_CAP && state.config.sasl_enabled {
                    caps.account_registration = enable;
                    continue;
                }
                if name == MULTILINE_CAP {
                    caps.multiline = enable;
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
            let shown = if sub.is_empty() {
                "*"
            } else {
                crate::core::handler::clip_echo(&sub)
            };
            state.numeric(
                conn,
                ERR_INVALIDCAPCMD,
                &[shown],
                Some("Invalid CAP command"),
            );
        }
    }
}
