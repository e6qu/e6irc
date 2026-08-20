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
    // A fieldless `%` is not a WHOX request: charybdis-family servers fall
    // back to a plain WHO (352) — and a 354 row with zero fields would be a
    // parameterless numeric no client can interpret.
    if fields_part.is_empty() {
        return None;
    }
    // The token is echoed as a middle parameter of every 354 row, so a value
    // that cannot stand as one corrupts the reply's framing for the
    // requester: an empty token collapses into the adjacent space (shifting
    // every later field left one column), and a leading `:` starts a
    // premature trailing that swallows the rest of the row. Treat both as
    // absent — echoed as the conventional "0", matching Solanum's
    // empty-querytype default.
    let token = token.filter(|t| !t.is_empty() && !t.starts_with(':'));
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

fn who_flags_profile(profile: &crate::core::state::ChannelMemberProfile, sigil: &str) -> String {
    let here = if profile.away { "G" } else { "H" };
    let star = if profile.oper { "*" } else { "" };
    let bot = if profile.bot { "B" } else { "" };
    format!("{here}{star}{bot}{sigil}")
}

struct WhoRowData {
    user: String,
    host: String,
    nick: String,
    flags: String,
    realname: String,
    account: Option<String>,
    idle_secs: u64,
}

pub(super) fn cmd_who(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let Some(&mask) = p.first() else {
        state.numeric(conn, RPL_ENDOFWHO, &["*"], Some("End of /WHO list"));
        return;
    };
    if mask.starts_with('#') {
        let owner = state.channel_owner(mask);
        if !state.owns_channel(&owner) {
            let label = state.channel_reply_label(conn, &owner);
            state.route_channel_command(crate::core::state::ChannelCommand::new(
                owner,
                state.channel_actor(conn),
                mask.to_string(),
                crate::core::state::ChannelCommandOperation::Who(
                    crate::core::state::ChannelWhoQuery {
                        argument: p.get(1).copied().unwrap_or("").to_string(),
                    },
                ),
                label,
            ));
            return;
        }
    }
    // The RFC 2812 `o` flag restricts matches to operators; Solanum also
    // accepts it combined with a WHOX spec (`WHO * o%nf`). Anything else in
    // the flags position is ignored, as before.
    let arg = p.get(1).copied().unwrap_or("");
    let (opers_only, whox_part) = match arg.strip_prefix('o') {
        Some(rest) if rest.is_empty() || rest.starts_with('%') => (true, rest),
        _ => (false, arg),
    };
    let whox = parse_whox(whox_part);
    let requester_multi_prefix = state.reply_caps(conn).is_some_and(|caps| caps.multi_prefix);
    let server = state.config.server_name.clone();
    // Monotonic: idle is elapsed time since `last_active` (also monotonic).
    let now = (state.config.mono_clock)();
    if mask.starts_with('#') {
        let key = state.chan_key(mask);
        if let Some(chan) = state.channels.get(&key) {
            let display = chan.name.clone();
            // A +s channel's membership is hidden from non-members: emit no
            // rows, letting the terminating RPL_ENDOFWHO stand alone.
            let hidden = chan.hidden_from(conn).is_some();
            let rows: Vec<WhoRowData> = if hidden {
                Vec::new()
            } else {
                chan.member_profiles()
                    // An invisible member is hidden from a WHO by someone who
                    // shares no channel with them (and isn't them) — the same
                    // rule the wildcard/host branch below applies. A fellow
                    // member always shares this channel, so members still see
                    // each other; only an outsider WHOing a public channel is
                    // filtered. Without this, `+i` leaks through channel WHO.
                    .filter(|(m, _, identity, _)| {
                        *m == conn || !identity.invisible || state.share_channel(conn, *m)
                    })
                    .filter(|(_, _, _, profile)| !opers_only || profile.oper)
                    .map(|(_, modes, identity, profile)| {
                        let sigil = match (modes.op, modes.voice, requester_multi_prefix) {
                            (true, true, true) => "@+",
                            (true, _, _) => "@",
                            (false, true, _) => "+",
                            _ => "",
                        };
                        WhoRowData {
                            user: profile.user.clone(),
                            host: profile.host.clone(),
                            nick: identity.nick.clone(),
                            flags: who_flags_profile(profile, sigil),
                            realname: profile.realname.clone(),
                            account: profile.account.clone(),
                            idle_secs: now.saturating_sub(profile.last_active).as_secs(),
                        }
                    })
                    .collect()
            };
            for row in rows {
                match &whox {
                    Some(req) => send_whox_row(
                        state,
                        conn,
                        req,
                        &WhoxRow {
                            channel: &display,
                            user: &row.user,
                            host: &row.host,
                            server: &server,
                            nick: &row.nick,
                            flags: &row.flags,
                            account: row.account.as_deref(),
                            realname: &row.realname,
                            idle_secs: row.idle_secs,
                        },
                    ),
                    None => state.numeric(
                        conn,
                        RPL_WHOREPLY,
                        &[
                            &display, &row.user, &row.host, &server, &row.nick, &row.flags,
                        ],
                        Some(&format!("0 {}", row.realname)),
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
            .filter(|(_, s)| s.is_registered())
            .filter(|(_, s)| !opers_only || s.oper)
            .filter(|(_, s)| {
                match_all || {
                    let nick = s.nick().unwrap_or("");
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
                    && e6irc_proto::mask::matches(casemap, mask, s.nick().unwrap_or(""));
                peer == conn || !s.invisible || state.share_channel(conn, peer) || named_by_nick
            })
            .collect();
        for peer in targets {
            let s = &state.sessions[&peer];
            let row = WhoRowData {
                user: s.user().map(String::from).expect("registered"),
                host: s.host.clone(),
                nick: s.nick().map(String::from).expect("registered"),
                realname: s.realname().map(String::from).expect("registered"),
                account: s.account.clone(),
                flags: who_flags(s, ""),
                idle_secs: now.saturating_sub(s.last_active).as_secs(),
            };
            match &whox {
                Some(req) => send_whox_row(
                    state,
                    conn,
                    req,
                    &WhoxRow {
                        channel: "*",
                        user: &row.user,
                        host: &row.host,
                        server: &server,
                        nick: &row.nick,
                        flags: &row.flags,
                        account: row.account.as_deref(),
                        realname: &row.realname,
                        idle_secs: row.idle_secs,
                    },
                ),
                None => state.numeric(
                    conn,
                    RPL_WHOREPLY,
                    &["*", &row.user, &row.host, &server, &row.nick, &row.flags],
                    Some(&format!("0 {}", row.realname)),
                ),
            }
        }
    }
    // The mask is raw client input (`WHO :` → empty, `WHO ::x` → ':'-leading);
    // clip_echo renders those as the safe "*" placeholder so the terminating
    // numeric's middle can't break the reply's framing.
    state.numeric(
        conn,
        RPL_ENDOFWHO,
        &[clip_echo(mask)],
        Some("End of /WHO list"),
    );
}

pub(super) fn who_on_owner(
    state: &mut ServerState,
    command: crate::core::state::ChannelCommand,
) -> crate::core::state::ChannelCommandReplies {
    let (owner, actor, target, operation) = command.into_parts();
    let crate::core::state::ChannelCommandOperation::Who(query) = operation else {
        unreachable!("WHO requires its operation")
    };
    let key = state.chan_key(&target);
    assert_eq!(owner.key(), &key, "WHO owner does not match target");
    let conn = super::begin_channel_capture(state, &actor, None);
    cmd_who(state, conn, &[target.as_str(), query.argument.as_str()]);
    let lines = state.capture.take().expect("WHO capture installed").lines;
    crate::core::state::ChannelCommandReplies { lines }
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
                s.nick().map(String::from).expect("registered"),
                s.user().map(String::from).expect("registered"),
                s.host.clone(),
                s.realname().map(String::from).expect("registered"),
            );
            let mut chans: Vec<String> = s
                .channels
                .iter()
                .filter_map(|k| {
                    let chan = state.channels.get(k)?;
                    let modes = chan.member(peer)?;
                    // A +s (secret) channel is disclosed only to a requester
                    // who also shares it, so WHOIS can't enumerate hidden
                    // channels a target is in.
                    if chan.hidden_from(conn).is_some() {
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
                // RPL_WHOISIDLE reports seconds idle (elapsed monotonic time
                // since last activity) and a Unix-*second* signon *timestamp*
                // (wall clock) — the two clocks the type split keeps separate.
                let idle = (state.config.mono_clock)()
                    .saturating_sub(s.last_active)
                    .as_secs();
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
            // `target` is raw client input; clip_echo keeps an empty or
            // ':'-leading value from breaking the echo's framing.
            let shown = clip_echo(target);
            state.err_nosuchnick(conn, shown);
            state.numeric(conn, RPL_ENDOFWHOIS, &[shown], Some("End of /WHOIS list"));
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
    state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .set_realname(new_name.to_string());
    let line = format!(":{prefix} SETNAME :{new_name}");
    // SETNAME echoes to the originator (its own client sees the change), then
    // to the channel-peer / extended-monitor fan-out.
    state.send_timed(conn, &line);
    notify_event(state, conn, &line, |c| c.setname, false);
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
        // Raw client input; keep an empty/':'-leading target from breaking the
        // echo's framing.
        state.numeric(
            conn,
            ERR_WASNOSUCHNICK,
            &[clip_echo(target)],
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
            // The RPL_WHOISSERVER "server info" slot conventionally carries the
            // last-seen time for a WHOWAS entry (Solanum/Ergo). Use the recorded
            // signoff rather than a placeholder.
            let last_seen = e6irc_proto::time::server_time(entry.signoff);
            state.numeric(
                conn,
                RPL_WHOISSERVER,
                &[&entry.nick, &server],
                Some(&format!("last seen {last_seen}")),
            );
        }
    }
    state.numeric(
        conn,
        RPL_ENDOFWHOWAS,
        &[clip_echo(target)],
        Some("End of WHOWAS"),
    );
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
            &format!("CHANNELLEN={}", crate::sanitize::CHANNELLEN),
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
            "KNOCK",
            "UTF8ONLY",
            "WHOX",
            &format!("KEYLEN={KEYLEN}"),
            // Derived from the enforced consts (like MAXLIST/CHANLIMIT below)
            // so the advertisement can never silently drift from enforcement.
            &format!("MONITOR={MONITOR_LIMIT}"),
            &format!("CHATHISTORY={CHATHISTORY_MAX}"),
            "MSGREFTYPES=msgid,timestamp",
            &format!("MAXLIST=bqeI:{MAXLIST}"),
            &format!("CHANLIMIT=#:{MAX_CHANNELS_PER_SESSION}"),
            &format!("TARGMAX=PRIVMSG:{TARGMAX},NOTICE:{TARGMAX},KICK:{TARGMAX}"),
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
        state.err_needmoreparams(conn, "ISON");
        return;
    }
    // ISON takes a space-separated nick list (as many middle params, or one
    // trailing param); reply with just those currently online. `registered_peer`
    // (not `nicks`) so a connection that only sent NICK but never finished
    // registration isn't reported as online.
    // Echo the server's canonical stored nick, not the caller's casing: `ISON
    // AlIcE` for online `alice` replies `alice` (Solanum behaviour).
    let online: Vec<String> = p
        .iter()
        .flat_map(|arg| arg.split_whitespace())
        .filter_map(|nick| {
            let peer = state.registered_peer(&state.nick_key(nick))?;
            state.sessions[&peer].nick().map(String::from)
        })
        .collect();
    // RPL_ISON is a single reply by RFC 2812 (splitting it would be
    // non-conformant), yet the echoed list is bounded only by the input frame
    // and the reply adds server overhead — so it can overflow the wire limit.
    // Match Solanum: pack nicks while they fit and drop the rest, which a
    // client re-queries next poll anyway (ISON is a polling command). Uses the
    // shared whole-item packer (same as USERHOST/USERIP) against the real head.
    let target = state.sessions[&conn].nick().unwrap_or("*");
    let head_len = format!(
        ":{} {} {} :",
        state.config.server_name,
        e6irc_proto::numerics::code_str(RPL_ISON),
        target,
    )
    .len();
    let shown = crate::core::handler::pack_trailing_list(&online, head_len);
    state.numeric(conn, RPL_ISON, &[], Some(&shown));
}

// ---- HELP / HELPOP (Modern 704/705/706) ------------------------------------

/// One help topic. The no-argument index is generated from this same table,
/// so the index and the per-topic answers can never disagree about which
/// commands exist.
pub(super) struct HelpTopic {
    pub(super) name: &'static str,
    /// Oper-only commands are listed by HELPOP but not by HELP.
    pub(super) oper: bool,
    pub(super) lines: &'static [&'static str],
}

pub(super) const HELP_TOPICS: &[HelpTopic] = &[
    HelpTopic {
        name: "NICK",
        oper: false,
        lines: &["NICK <nickname>", "Change your nickname."],
    },
    HelpTopic {
        name: "USER",
        oper: false,
        lines: &[
            "USER <username> <unused> <unused> :<realname>",
            "Supply your identity at registration (clients normally send this for you).",
        ],
    },
    HelpTopic {
        name: "PING",
        oper: false,
        lines: &[
            "PING <token>",
            "Liveness check; the server answers PONG with the same token.",
        ],
    },
    HelpTopic {
        name: "PONG",
        oper: false,
        lines: &[
            "PONG <token>",
            "Answer a server PING; keeps the connection from being reaped as idle.",
        ],
    },
    HelpTopic {
        name: "QUIT",
        oper: false,
        lines: &[
            "QUIT [:<message>]",
            "Disconnect, optionally leaving a parting message.",
        ],
    },
    HelpTopic {
        name: "REGISTER",
        oper: false,
        lines: &[
            "REGISTER <account> [email] <password>",
            "Create an account before connecting (draft/account-registration), when the server policy allows it.",
        ],
    },
    HelpTopic {
        name: "CAP",
        oper: false,
        lines: &[
            "CAP <LS|LIST|REQ|END> [<capabilities>]",
            "Negotiate IRCv3 capabilities during registration.",
        ],
    },
    HelpTopic {
        name: "AUTHENTICATE",
        oper: false,
        lines: &[
            "AUTHENTICATE <mechanism|data>",
            "SASL authentication exchange (PLAIN and OAUTHBEARER when the account store is enabled).",
        ],
    },
    HelpTopic {
        name: "JOIN",
        oper: false,
        lines: &[
            "JOIN <channel>{,<channel>} [<key>{,<key>}]",
            "Enter one or more channels, creating them if they do not exist.",
        ],
    },
    HelpTopic {
        name: "PART",
        oper: false,
        lines: &[
            "PART <channel>{,<channel>} [:<message>]",
            "Leave one or more channels.",
        ],
    },
    HelpTopic {
        name: "BATCH",
        oper: false,
        lines: &[
            "BATCH <+ref|-ref> <type> [<parameters>]",
            "Open or close a client-initiated message batch (requires the batch capability).",
        ],
    },
    HelpTopic {
        name: "PRIVMSG",
        oper: false,
        lines: &[
            "PRIVMSG <target>{,<target>} :<text>",
            "Send a message to a channel or user. Targets are channels, nicks, STATUSMSG-prefixed channels (@#chan/+#chan), or the services NickServ/ChanServ.",
        ],
    },
    HelpTopic {
        name: "NOTICE",
        oper: false,
        lines: &[
            "NOTICE <target>{,<target>} :<text>",
            "Like PRIVMSG, but automated replies must not answer a NOTICE.",
        ],
    },
    HelpTopic {
        name: "TAGMSG",
        oper: false,
        lines: &[
            "TAGMSG <target>",
            "Send client-only message tags with no text (typing indicators, reactions; requires message-tags).",
        ],
    },
    HelpTopic {
        name: "TOPIC",
        oper: false,
        lines: &[
            "TOPIC <channel> [:<topic>]",
            "Show or set a channel's topic.",
        ],
    },
    HelpTopic {
        name: "NAMES",
        oper: false,
        lines: &[
            "NAMES [<channel>{,<channel>}]",
            "List the visible members of channels.",
        ],
    },
    HelpTopic {
        name: "MODE",
        oper: false,
        lines: &[
            "MODE <target> [<modes> [<parameters>]]",
            "Query or change channel modes (bqeI lists, k/l parameters, imnstC flags, o/v prefixes) or your user modes (iwB).",
        ],
    },
    HelpTopic {
        name: "WHO",
        oper: false,
        lines: &[
            "WHO <mask> [%<fields>[,<token>]] [o]",
            "List users matching a channel or mask; the % form is the WHOX field selector.",
        ],
    },
    HelpTopic {
        name: "WHOIS",
        oper: false,
        lines: &[
            "WHOIS <nick>",
            "Show a user's identity, account, channels, idle time, and server.",
        ],
    },
    HelpTopic {
        name: "WHOWAS",
        oper: false,
        lines: &[
            "WHOWAS <nick> [<count>]",
            "Show identity information for a nick that recently disconnected.",
        ],
    },
    HelpTopic {
        name: "KICK",
        oper: false,
        lines: &[
            "KICK <channel> <user> [:<reason>]",
            "Remove a user from a channel (requires channel operator).",
        ],
    },
    HelpTopic {
        name: "INVITE",
        oper: false,
        lines: &[
            "INVITE <nick> <channel>",
            "Invite a user to a channel; on an invite-only channel only operators may invite.",
        ],
    },
    HelpTopic {
        name: "AWAY",
        oper: false,
        lines: &[
            "AWAY [:<message>]",
            "Mark yourself away with a message, or clear your away state.",
        ],
    },
    HelpTopic {
        name: "LIST",
        oper: false,
        lines: &[
            "LIST [<channel>{,<channel>}]",
            "List visible channels, their membership counts, and topics.",
        ],
    },
    HelpTopic {
        name: "USERHOST",
        oper: false,
        lines: &[
            "USERHOST <nick> [<nick> ...]",
            "Reply with nick[*]=[+|-]user@host for up to five online users.",
        ],
    },
    HelpTopic {
        name: "USERIP",
        oper: false,
        lines: &[
            "USERIP <nick> [<nick> ...]",
            "Like USERHOST; IP addresses are never exposed, so the host form is returned.",
        ],
    },
    HelpTopic {
        name: "CHATHISTORY",
        oper: false,
        lines: &[
            "CHATHISTORY <LATEST|BEFORE|AFTER|AROUND|BETWEEN|TARGETS> <target> <selector> <limit>",
            "Page persisted channel and direct-message history (draft/chathistory).",
        ],
    },
    HelpTopic {
        name: "MONITOR",
        oper: false,
        lines: &[
            "MONITOR <+|-|C|L|S> [<nick>{,<nick>}]",
            "Track nick presence: add, remove, clear, list, or query your watch list.",
        ],
    },
    HelpTopic {
        name: "MARKREAD",
        oper: false,
        lines: &[
            "MARKREAD <target> [timestamp=<ts>]",
            "Set or query your per-target read marker (draft/read-marker); stored for identified users.",
        ],
    },
    HelpTopic {
        name: "SETNAME",
        oper: false,
        lines: &[
            "SETNAME :<realname>",
            "Change your displayed realname (requires the setname capability).",
        ],
    },
    HelpTopic {
        name: "MOTD",
        oper: false,
        lines: &["MOTD", "Show the server's message of the day."],
    },
    HelpTopic {
        name: "LUSERS",
        oper: false,
        lines: &["LUSERS", "Show connection and channel counts."],
    },
    HelpTopic {
        name: "TIME",
        oper: false,
        lines: &["TIME", "Show the server's local time."],
    },
    HelpTopic {
        name: "INFO",
        oper: false,
        lines: &["INFO", "Show server software information."],
    },
    HelpTopic {
        name: "VERSION",
        oper: false,
        lines: &["VERSION", "Show the server software version."],
    },
    HelpTopic {
        name: "ADMIN",
        oper: false,
        lines: &["ADMIN", "Show administrative contact information."],
    },
    HelpTopic {
        name: "ISON",
        oper: false,
        lines: &[
            "ISON <nick> [<nick> ...]",
            "Report which of the listed nicks are currently online.",
        ],
    },
    HelpTopic {
        name: "LINKS",
        oper: false,
        lines: &[
            "LINKS",
            "List the servers in the network (this is a single-server network).",
        ],
    },
    HelpTopic {
        name: "STATS",
        oper: false,
        lines: &[
            "STATS <letter>",
            "Server statistics query (letters are documented in the reply to an unknown letter).",
        ],
    },
    HelpTopic {
        name: "KNOCK",
        oper: false,
        lines: &[
            "KNOCK <channel>",
            "Request an invitation to an invite-only channel.",
        ],
    },
    HelpTopic {
        name: "OPER",
        oper: false,
        lines: &["OPER <name> <password>", "Authenticate as an IRC operator."],
    },
    HelpTopic {
        name: "HELP",
        oper: false,
        lines: &[
            "HELP [<subject>]",
            "List help topics or show help on one command.",
        ],
    },
    HelpTopic {
        name: "HELPOP",
        oper: false,
        lines: &[
            "HELPOP [<subject>]",
            "Like HELP, including operator-only commands in the index.",
        ],
    },
    HelpTopic {
        name: "NICKSERV",
        oper: false,
        lines: &[
            "/msg NickServ <command>",
            "Account service: REGISTER, IDENTIFY, GHOST, LOGOUT, HELP.",
        ],
    },
    HelpTopic {
        name: "CHANSERV",
        oper: false,
        lines: &[
            "/msg ChanServ <command>",
            "Channel registration service: REGISTER, DROP, FLAGS, OP, SET (FOUNDER, KEEPTOPIC, MLOCK), HELP.",
        ],
    },
    HelpTopic {
        name: "KILL",
        oper: true,
        lines: &[
            "KILL <nick> :<reason>",
            "Forcibly disconnect a user (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "KLINE",
        oper: true,
        lines: &[
            "KLINE <user@host-mask> :<reason>",
            "Ban a user@host mask from the server (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "UNKLINE",
        oper: true,
        lines: &[
            "UNKLINE <user@host-mask>",
            "Remove a K-line (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "DLINE",
        oper: true,
        lines: &[
            "DLINE <host-mask> :<reason>",
            "Ban a host or IP mask from the server (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "UNDLINE",
        oper: true,
        lines: &[
            "UNDLINE <host-mask>",
            "Remove a D-line (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "XLINE",
        oper: true,
        lines: &[
            "XLINE <realname-mask> :<reason>",
            "Ban a realname (gecos) mask from the server (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "UNXLINE",
        oper: true,
        lines: &[
            "UNXLINE <realname-mask>",
            "Remove an X-line (oper only); audited.",
        ],
    },
    HelpTopic {
        name: "SETHOST",
        oper: true,
        lines: &[
            "SETHOST <nick> <host>",
            "Set a user's visible host (oper only, chghost); audited.",
        ],
    },
    HelpTopic {
        name: "WALLOPS",
        oper: true,
        lines: &[
            "WALLOPS :<message>",
            "Send a message to all operators and +w users (oper only).",
        ],
    },
];

pub(super) fn send_help(state: &mut ServerState, conn: ConnId, subject: &str, lines: &[&str]) {
    let (first, rest) = lines.split_first().expect("topics are non-empty");
    state.numeric(conn, RPL_HELPSTART, &[subject], Some(first));
    for line in rest {
        state.numeric(conn, RPL_HELPTXT, &[subject], Some(line));
    }
    state.numeric(conn, RPL_ENDOFHELP, &[subject], Some("End of help"));
}

pub(super) fn cmd_help(state: &mut ServerState, conn: ConnId, p: &[&str], oper_view: bool) {
    let visible = |t: &&HelpTopic| oper_view || !t.oper;
    match p.first().filter(|s| !s.is_empty()) {
        Some(subject) => {
            match HELP_TOPICS
                .iter()
                .find(|t| visible(t) && t.name.eq_ignore_ascii_case(subject))
            {
                Some(topic) => send_help(state, conn, topic.name, topic.lines),
                None => state.numeric(
                    conn,
                    ERR_HELPNOTFOUND,
                    &[clip_echo(subject)],
                    Some("No help available on this topic"),
                ),
            }
        }
        None => {
            state.numeric(
                conn,
                RPL_HELPSTART,
                &["index"],
                Some(if oper_view {
                    "Available commands (including oper-only)"
                } else {
                    "Available commands"
                }),
            );
            let names: Vec<String> = HELP_TOPICS
                .iter()
                .filter(visible)
                .map(|t| t.name.to_string())
                .collect();
            let target = state.sessions[&conn].nick().unwrap_or("*");
            let head_len = format!(
                ":{} {} {} index :",
                state.config.server_name,
                e6irc_proto::numerics::code_str(RPL_HELPTXT),
                target,
            )
            .len();
            let packed = pack_trailing_list(&names, head_len);
            state.numeric(conn, RPL_HELPTXT, &["index"], Some(&packed));
            state.numeric(conn, RPL_ENDOFHELP, &["index"], Some("End of help"));
        }
    }
}
