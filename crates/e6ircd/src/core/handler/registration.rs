//! Connection registration and capability negotiation.

use super::message::{MULTILINE_CAP, MULTILINE_MAX_BYTES, MULTILINE_MAX_LINES};
use super::*;

// ---- registration -------------------------------------------------------

pub(super) fn cmd_nick(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    // An empty nick (`NICK :`) is "no nickname given", not an erroneous one:
    // ERR_NONICKNAMEGIVEN carries no nick parameter, whereas echoing the empty
    // nick into ERR_ERRONEUSNICKNAME's `<nick>` middle would emit an empty
    // parameter that collapses on the wire (a malformed `432 *  :…`).
    let Some(&nick) = p.first().filter(|n| !n.is_empty()) else {
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
    if let Some(owner) = state.nick_reservation(&key)
        && owner.conn() != conn
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
            session.is_registered(),
            session.is_registered().then(|| session.prefix()),
            session.nick().as_ref().map(|o| state.nick_key(o)),
            session.nick().map(String::from),
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
    state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .set_nick(nick.to_string());
    if let Some(old_key) = old_key {
        state.release_nick(&old_key, conn);
    }
    state.reserve_nick(key, conn);

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
    if state.sessions[&conn].is_registered() {
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
        state.err_needmoreparams(conn, "USER");
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
    session.set_user(crate::sanitize::username(p[0], USERLEN));
    session.set_realname(truncate_chars(p[3], REALLEN).to_string());
    maybe_complete_registration(state, conn);
}

// ---- capability negotiation ---------------------------------------------

pub(super) fn cap_target(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .nick()
        .map(String::from)
        .unwrap_or_else(|| "*".to_string())
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
    let nick = state.sessions[&conn].nick().map(String::from);
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
    if !state.sessions[&conn].is_registered() && !state.config.registration_before_connect {
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
    let contact_email = if *email == "*" {
        None
    } else {
        match crate::identity::ContactEmail::parse(email) {
            Ok(email) => Some(email),
            Err(_) => {
                register_fail(
                    state,
                    conn,
                    "INVALID_EMAIL",
                    &nick,
                    "Supply a valid email address or * when email is optional",
                );
                return;
            }
        }
    };
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
    // One account creation may be in flight per connection.
    if state.sessions[&conn].pending_register.is_some() {
        register_fail(
            state,
            conn,
            "TEMPORARILY_UNAVAILABLE",
            &nick,
            "A registration is already in progress",
        );
        return;
    }
    // Per-connection budget stops one *link* from driving unbounded argon2;
    // this per-IP bucket stops one *address* from minting accounts in bulk
    // across a churn of short-lived connections (each of which spends only its
    // own budget). It refills slowly — account creation is rare per genuine
    // client — so a legitimate retry passes while a mint loop is throttled.
    if !state.registration_rate_ok(&state.sessions[&conn].host.clone()) {
        register_fail(
            state,
            conn,
            "TEMPORARILY_UNAVAILABLE",
            &nick,
            "Too many account registrations from your address; try again later",
        );
        return;
    }
    // Account creation runs argon2 (a full hash even for an existing account),
    // so it spends from the shared per-connection credential budget — the same
    // cap SASL/IDENTIFY use — so a REGISTER loop can't drive unbounded hashing.
    // Exhausting the budget closes the connection.
    if !credential_attempt_ok(state, conn) {
        return;
    }
    let request = crate::core::DbRequest::CreateAccount {
        conn,
        name: nick.clone(),
        contact_email,
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
        // Hold later output until the database replies.
        state.defer_reply(conn);
        let label = state.capture.as_mut().and_then(|cap| {
            cap.label.clone().inspect(|_| {
                cap.deferred = true;
            })
        });
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .pending_register = Some(crate::core::state::PendingServiceReply::new(label));
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

/// A capability that carries an LS *value* parameter, so it lives outside
/// [`CAP_NAMES`]. Advertising (CAP LS), accepting (CAP REQ), and reporting (CAP
/// LIST) all derive from this one registry, so an enabled value-cap can't be
/// accept-able but not reported, or advertised but not accept-able — the desync
/// class that once told a re-syncing client a negotiated cap was off. Adding a
/// value-cap is one entry here, not three hand-maintained lists.
struct ValueCap {
    name: &'static str,
    accessor: crate::core::state::CapAccessor,
    /// The exact LS token to advertise (`v302` selects the value form), or `None`
    /// when the cap isn't offered at all (e.g. it needs a database). REQ uses
    /// `ls_token(..).is_some()` as the single "may this be enabled?" gate, so the
    /// offered/acceptable decision is expressed in exactly one place.
    ls_token: fn(&ServerState, bool) -> Option<String>,
}

const VALUE_CAPS: &[ValueCap] = &[
    ValueCap {
        name: "sasl",
        accessor: |c| &mut c.sasl,
        ls_token: |state, v302| {
            state.config.sasl_enabled.then(|| {
                if v302 {
                    "sasl=PLAIN,OAUTHBEARER".into()
                } else {
                    "sasl".into()
                }
            })
        },
    },
    ValueCap {
        name: ACCOUNT_REGISTRATION_CAP,
        accessor: |c| &mut c.account_registration,
        ls_token: |state, v302| {
            state.config.sasl_enabled.then(|| {
                if v302 {
                    match account_registration_flags(state) {
                        flags if flags.is_empty() => ACCOUNT_REGISTRATION_CAP.into(),
                        flags => format!("{ACCOUNT_REGISTRATION_CAP}={flags}"),
                    }
                } else {
                    ACCOUNT_REGISTRATION_CAP.into()
                }
            })
        },
    },
    ValueCap {
        name: MULTILINE_CAP,
        accessor: |c| &mut c.multiline,
        ls_token: |_state, v302| {
            Some(if v302 {
                format!(
                    "{MULTILINE_CAP}=max-bytes={MULTILINE_MAX_BYTES},max-lines={MULTILINE_MAX_LINES}"
                )
            } else {
                MULTILINE_CAP.into()
            })
        },
    },
];

/// Mark a connection as mid-CAP-negotiation (which holds registration) unless
/// it is already registered — shared by CAP LS and CAP REQ.
fn mark_negotiating(state: &mut ServerState, conn: ConnId) {
    if !state.sessions[&conn].is_registered() {
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .cap_negotiating = true;
    }
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
            mark_negotiating(state, conn);
            let v302 = p.get(1).is_some_and(|v| *v == "302");
            let mut names: Vec<String> = CAP_NAMES.iter().map(|(n, _)| n.to_string()).collect();
            // The value-carrying caps advertise from the shared registry, so LS
            // can't offer a cap REQ/LIST don't know about (or vice versa).
            names.extend(
                VALUE_CAPS
                    .iter()
                    .filter_map(|vc| (vc.ls_token)(state, v302)),
            );
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
            // The value-carrying caps report from the same registry LS advertises
            // and REQ accepts, so LIST can't tell a re-syncing client a negotiated
            // cap is off (the desync this used to hand-maintain three lists for).
            active.extend(
                VALUE_CAPS
                    .iter()
                    .filter(|vc| *(vc.accessor)(&mut caps))
                    .map(|vc| vc.name),
            );
            state.send(
                conn,
                &format!(":{server} CAP {target} LIST :{}", active.join(" ")),
            );
        }
        "REQ" => {
            let request = p.get(1).copied().unwrap_or("");
            mark_negotiating(state, conn);
            // All-or-nothing: apply to a copy, commit only if every
            // token is known.
            let mut caps = state.sessions[&conn].caps;
            let mut all_known = !request.is_empty();
            for token in request.split(' ').filter(|t| !t.is_empty()) {
                let (name, enable) = match token.strip_prefix('-') {
                    Some(n) => (n, false),
                    None => (token, true),
                };
                // A value-cap is acceptable iff it is currently offered (its
                // `ls_token` yields Some) — the same gate LS advertises on, so a
                // cap can never be REQ-able but unadvertised. A recognised name
                // that isn't offered (e.g. `sasl` with no database) falls through
                // to the unknown-token path and NAKs, as before.
                if let Some(vc) = VALUE_CAPS.iter().find(|vc| vc.name == name)
                    && (vc.ls_token)(state, false).is_some()
                {
                    *(vc.accessor)(&mut caps) = enable;
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
            // Echo the requested caps, but never emit a line past the wire
            // limit: `request` is client-supplied and can be ~500 bytes, so
            // reflecting it verbatim (`:{server} CAP {target} {verb} :{request}`)
            // overflows 512 — the recipient's framing discards such a line whole,
            // and the debug wire check aborts the single core worker, a
            // client-triggerable DoS reachable unauthenticated pre-registration.
            // A REQ too long to echo in one line isn't a coherent request, so
            // reject it (NAK, apply nothing) and echo only the fitting prefix.
            // ACK and NAK are the same length, so the fit is verb-independent.
            let fits = {
                let head = format!(":{server} CAP {target} ACK :");
                super::fit_trailing(&head, request).len() == request.len()
            };
            let verb = if all_known && fits { "ACK" } else { "NAK" };
            if verb == "ACK" {
                state.sessions.get_mut(&conn).expect("checked").caps = caps;
            }
            let head = format!(":{server} CAP {target} {verb} :");
            let echo = super::fit_trailing(&head, request);
            state.send(conn, &format!("{head}{echo}"));
        }
        "END" => {
            let session = state.sessions.get_mut(&conn).expect("checked");
            if !session.is_registered() && session.cap_negotiating {
                session.cap_negotiating = false;
                maybe_complete_registration(state, conn);
            }
        }
        _ => {
            // clip_echo renders an empty or ':'-leading subcommand as the
            // safe "*" placeholder, so the echo can't break the reply's framing.
            state.numeric(
                conn,
                ERR_INVALIDCAPCMD,
                &[crate::core::handler::clip_echo(&sub)],
                Some("Invalid CAP command"),
            );
        }
    }
}
