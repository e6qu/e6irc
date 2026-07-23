//! Client and server queries: WHO/WHOIS/WHOWAS, TIME, INFO, STATS.

use super::*;

// ---- queries ------------------------------------------------------------

/// A `WHO <mask> %fields[,token]` request (the WHOX extension as
/// implemented by charybdis/Solanum and advertised by Libera).
pub(super) struct WhoxRequest {
    pub(super) fields: Vec<char>,
    pub(super) token: Option<String>,
}

pub(super) fn parse_whox(arg: &str) -> Option<WhoxRequest> {
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
/// The fields of one WHOX reply row. Bundled into a struct (rather than a
/// row of same-typed `&str` parameters) so the fields cannot be transposed
/// at a call site.
pub(super) struct WhoxRow<'a> {
    pub(super) channel: &'a str,
    pub(super) user: &'a str,
    pub(super) host: &'a str,
    pub(super) server: &'a str,
    pub(super) nick: &'a str,
    pub(super) flags: &'a str,
    pub(super) account: Option<&'a str>,
    pub(super) realname: &'a str,
    pub(super) idle_secs: u64,
}

pub(super) fn send_whox_row(
    state: &mut ServerState,
    conn: ConnId,
    req: &WhoxRequest,
    row: &WhoxRow,
) {
    let mut middle: Vec<String> = Vec::new();
    let mut trailing = None;
    for f in "tcuihsnfdlaor".chars() {
        if !req.fields.contains(&f) {
            continue;
        }
        match f {
            't' => middle.push(req.token.clone().unwrap_or_else(|| "0".into())),
            'c' => middle.push(row.channel.to_string()),
            'u' => middle.push(row.user.to_string()),
            'i' => middle.push("255.255.255.255".into()), // IPs are not exposed
            'h' => middle.push(row.host.to_string()),
            's' => middle.push(row.server.to_string()),
            'n' => middle.push(row.nick.to_string()),
            'f' => middle.push(row.flags.to_string()),
            'd' => middle.push("0".into()), // hop count: single server
            'l' => middle.push(row.idle_secs.to_string()), // idle seconds
            'a' => middle.push(row.account.unwrap_or("0").to_string()),
            'o' => middle.push("n/a".into()), // oplevel unused (charybdis)
            'r' => trailing = Some(row.realname.to_string()),
            _ => {} // unknown field chars are ignored per WHOX practice
        }
    }
    let refs: Vec<&str> = middle.iter().map(String::as_str).collect();
    state.numeric(conn, RPL_WHOSPCRPL, &refs, trailing.as_deref());
}

/// WHO status flags: H (here) or G (gone/away), `*` for opers, then the
/// channel prefix sigil.
pub(super) fn who_flags(session: &crate::core::state::Session, sigil: &str) -> String {
    let here = if session.away.is_some() { "G" } else { "H" };
    let star = if session.oper { "*" } else { "" };
    let bot = if session.bot { "B" } else { "" };
    format!("{here}{star}{bot}{sigil}")
}

/// One channel-WHO row, materialized so the `Session` borrow is released
/// before the reply is sent: (user, host, nick, flags, realname, account,
/// idle seconds).
pub(super) type WhoRowData = (String, String, String, String, String, Option<String>, u64);

pub(super) fn cmd_who(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&mask) = p.first() else {
        state.numeric(conn, RPL_ENDOFWHO, &["*"], Some("End of /WHO list"));
        return;
    };
    let whox = p.get(1).and_then(|arg| parse_whox(arg));
    let requester_multi_prefix = state.sessions[&conn].caps.multi_prefix;
    let server = state.config.server_name.clone();
    let now = (state.config.clock)();
    if mask.starts_with('#') {
        let key = state.chan_key(mask);
        if let Some(chan) = state.channels.get(&key) {
            let display = chan.name.clone();
            // A +s channel's membership is hidden from non-members: emit no
            // rows, letting the terminating RPL_ENDOFWHO stand alone.
            let hidden = chan.modes.secret && !chan.members.contains_key(&conn);
            let rows: Vec<WhoRowData> = if hidden {
                Vec::new()
            } else {
                chan.members
                    .iter()
                    // An invisible member is hidden from a WHO by someone who
                    // shares no channel with them (and isn't them) — the same
                    // rule the wildcard/host branch below applies. A fellow
                    // member always shares this channel, so members still see
                    // each other; only an outsider WHOing a public channel is
                    // filtered. Without this, `+i` leaks through channel WHO.
                    .filter(|(m, _)| {
                        **m == conn
                            || !state.sessions[m].invisible
                            || state.share_channel(conn, **m)
                    })
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
                            // The clock is milliseconds; WHOX `l` is seconds.
                            now.saturating_sub(s.last_active).as_secs(),
                        )
                    })
                    .collect()
            };
            for (user, host, nick, flags, realname, account, idle_secs) in rows {
                match &whox {
                    Some(req) => send_whox_row(
                        state,
                        conn,
                        req,
                        &WhoxRow {
                            channel: &display,
                            user: &user,
                            host: &host,
                            server: &server,
                            nick: &nick,
                            flags: &flags,
                            account: account.as_deref(),
                            realname: &realname,
                            idle_secs,
                        },
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
        // Invisible users are hidden unless the requester is themselves, shares
        // a channel, or named them *by their exact nick*. "Named exactly" means
        // a wildcard-free mask that matches the nick specifically: the mask is
        // also matched against the host above, so a literal host like
        // `WHO 10.0.0.5` (no wildcards) would otherwise reveal every `+i` user
        // on that host, and a nick wildcard like `bo*` must still hide them.
        let is_wildcard = match_all || mask.contains('*') || mask.contains('?');
        let targets: Vec<ConnId> = targets
            .into_iter()
            .filter(|&peer| {
                let s = &state.sessions[&peer];
                let named_by_nick = !is_wildcard
                    && e6irc_proto::mask::matches(casemap, mask, s.nick.as_deref().unwrap_or(""));
                peer == conn || !s.invisible || state.share_channel(conn, peer) || named_by_nick
            })
            .collect();
        for peer in targets {
            let s = &state.sessions[&peer];
            let (user, host, nick, realname, account, flags, idle_secs) = (
                s.user.clone().expect("registered"),
                s.host.clone(),
                s.nick.clone().expect("registered"),
                s.realname.clone().expect("registered"),
                s.account.clone(),
                who_flags(s, ""),
                // The clock is milliseconds; WHOX `l` is seconds.
                now.saturating_sub(s.last_active).as_secs(),
            );
            match &whox {
                Some(req) => send_whox_row(
                    state,
                    conn,
                    req,
                    &WhoxRow {
                        channel: "*",
                        user: &user,
                        host: &host,
                        server: &server,
                        nick: &nick,
                        flags: &flags,
                        account: account.as_deref(),
                        realname: &realname,
                        idle_secs,
                    },
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

pub(super) fn cmd_whois(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    // WHOIS [<server>] <nick>: when two params are given the first is a
    // server target we resolve locally, so the nick is always the last.
    let Some(&target) = p.last().filter(|_| !p.is_empty()) else {
        state.numeric(conn, ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
        return;
    };
    let key = state.nick_key(target);
    match state.registered_peer(&key) {
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
                    // A +s (secret) channel is disclosed only to a requester
                    // who also shares it, so WHOIS can't enumerate hidden
                    // channels a target is in.
                    if chan.modes.secret && !chan.members.contains_key(&conn) {
                        return None;
                    }
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
            // Split across as many 319 lines as needed so none exceeds the
            // 512-byte wire limit (the same guard NAMES applies to 353).
            state.numeric_list(conn, RPL_WHOISCHANNELS, &[&nick], &chans, ' ');
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
            {
                let s = &state.sessions[&peer];
                let now = (state.config.clock)();
                // The clock is milliseconds; RPL_WHOISIDLE reports seconds
                // idle and a Unix-*second* signon time.
                let idle = now.saturating_sub(s.last_active).as_secs();
                let signon = s.signon.as_secs();
                state.numeric(
                    conn,
                    RPL_WHOISIDLE,
                    &[&nick, &idle.to_string(), &signon.to_string()],
                    Some("seconds idle, signon time"),
                );
            }
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
pub(super) fn cmd_setname(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
    let new_name = truncate_chars(new_name, REALLEN);
    state.sessions.get_mut(&conn).expect("checked").realname = Some(new_name.to_string());
    let line = format!(":{prefix} SETNAME :{new_name}");
    state.send_timed(conn, &line);
    for peer in state.channel_peers(conn) {
        if state.sessions.get(&peer).is_some_and(|s| s.caps.setname) {
            state.send_timed(peer, &line);
        }
    }
}

// ---- WHOWAS -------------------------------------------------------------

pub(super) fn cmd_whowas(state: &mut ServerState, conn: ConnId, p: &[&str]) {
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
    let matches: Vec<crate::core::state::WhowasEntry> = state
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

pub(super) fn cmd_time(state: &mut ServerState, conn: ConnId) {
    let server = state.config.server_name.clone();
    let now = e6irc_proto::time::server_time((state.config.clock)());
    state.numeric(conn, RPL_TIME, &[&server], Some(&now));
}

pub(super) fn cmd_info(state: &mut ServerState, conn: ConnId) {
    for line in [
        concat!("e6ircd version ", env!("CARGO_PKG_VERSION")),
        "A monolithic Rust IRCv3 server.",
    ] {
        state.numeric(conn, RPL_INFO, &[], Some(line));
    }
    state.numeric(conn, RPL_ENDOFINFO, &[], Some("End of INFO list"));
}

/// Emit the two RPL_ISUPPORT (005) lines — the single source of truth for the
/// advertised ISUPPORT tokens, sent both in the registration burst and after
/// VERSION.
pub(super) fn send_isupport(state: &mut ServerState, conn: ConnId) {
    let nicklen = state.config.nicklen;
    // Derive CASEMAPPING from the active mapping rather than hardcoding it, so
    // 005 can never disagree with how the server actually folds nicks/channels.
    let casemapping = format!("CASEMAPPING={}", state.casemap.isupport_token());
    state.numeric(
        conn,
        RPL_ISUPPORT,
        &[
            &casemapping,
            "CHANTYPES=#",
            &format!("NICKLEN={nicklen}"),
            "CHANNELLEN=50",
            &format!("USERLEN={USERLEN}"),
            &format!("TOPICLEN={TOPICLEN}"),
            &format!("KICKLEN={KICKLEN}"),
            &format!("AWAYLEN={AWAYLEN}"),
            "PREFIX=(ov)@+",
            "STATUSMSG=@+",
            "BOT=B",
            "CHANMODES=eIbq,k,l,imnstC",
            &format!("NETWORK={}", state.config.network_name),
        ],
        Some("are supported by this server"),
    );
    state.numeric(
        conn,
        RPL_ISUPPORT,
        &[
            "EXCEPTS",
            "INVEX",
            "UTF8ONLY",
            "WHOX",
            "MONITOR=100",
            "CHATHISTORY=500",
            "MSGREFTYPES=msgid,timestamp",
            &format!("MAXLIST=bqeI:{MAXLIST}"),
            &format!("CHANLIMIT=#:{MAX_CHANNELS_PER_SESSION}"),
            &format!("TARGMAX=PRIVMSG:{TARGMAX},NOTICE:{TARGMAX},KICK:1"),
        ],
        Some("are supported by this server"),
    );
}

pub(super) fn cmd_version(state: &mut ServerState, conn: ConnId) {
    let server = state.config.server_name.clone();
    let version = concat!("e6ircd-", env!("CARGO_PKG_VERSION"));
    state.numeric(
        conn,
        RPL_VERSION,
        &[version, &server],
        Some("A monolithic Rust IRCv3 server."),
    );
    // A VERSION reply is conventionally followed by the ISUPPORT tokens.
    send_isupport(state, conn);
}

pub(super) fn cmd_admin(state: &mut ServerState, conn: ConnId) {
    let server = state.config.server_name.clone();
    let network = state.config.network_name.clone();
    state.numeric(conn, RPL_ADMINME, &[&server], Some("Administrative info"));
    state.numeric(
        conn,
        RPL_ADMINLOC1,
        &[],
        Some(&format!("{network} network")),
    );
    state.numeric(
        conn,
        RPL_ADMINLOC2,
        &[],
        Some(concat!("Running e6ircd ", env!("CARGO_PKG_VERSION"))),
    );
    state.numeric(conn, RPL_ADMINEMAIL, &[], Some(&server));
}

pub(super) fn cmd_ison(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if p.is_empty() {
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &["ISON"],
            Some("Not enough parameters"),
        );
        return;
    }
    // ISON takes a space-separated nick list (as many middle params, or one
    // trailing param); reply with just those currently online. `registered_peer`
    // (not `nicks`) so a connection that only sent NICK but never finished
    // registration isn't reported as online.
    let online: Vec<String> = p
        .iter()
        .flat_map(|arg| arg.split_whitespace())
        .filter(|nick| state.registered_peer(&state.nick_key(nick)).is_some())
        .map(str::to_string)
        .collect();
    // RPL_ISON is a single reply by RFC 2812 (splitting it would be
    // non-conformant), yet the echoed list is bounded only by the input frame
    // and the reply adds server overhead — so it can overflow the wire limit.
    // Match Solanum: pack nicks while they fit and drop the rest, which a
    // client re-queries next poll anyway (ISON is a polling command).
    let overhead = 1
        + state.config.server_name.len()
        + 5
        + state.sessions[&conn].nick.as_deref().unwrap_or("*").len()
        + 4;
    let budget = 510usize.saturating_sub(overhead);
    let mut shown = String::new();
    for nick in &online {
        let cost = if shown.is_empty() {
            nick.len()
        } else {
            1 + nick.len()
        };
        if shown.len() + cost > budget {
            break;
        }
        if !shown.is_empty() {
            shown.push(' ');
        }
        shown.push_str(nick);
    }
    state.numeric(conn, RPL_ISON, &[], Some(&shown));
}
