//! Operator commands: OPER, KILL, server bans and WALLOPS.

use super::*;

// ---- OPER ---------------------------------------------------------------

pub(super) fn cmd_oper(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&name), Some(&password)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "OPER");
        return;
    };
    // An operator already is one: RPL_YOUREOPER again and nothing else
    // (Solanum's `m_oper`). Checking the credentials would let a second OPER
    // switch the identity privileged actions are audited under, and announce a
    // `MODE +o` that changes nothing.
    if state.sessions[&conn].oper.is_some() {
        you_are_oper(state, conn);
        return;
    }
    // OPER is a password check like SASL and IDENTIFY, so every attempt spends
    // the same per-connection budget: a registered client cannot pipeline
    // guesses at line rate, and the link closes when the budget runs out.
    if !credential_attempt_ok(state, conn) {
        return;
    }
    // Always run the constant-time compare — against a dummy secret when the
    // operator name is unknown — so response timing is name-independent and can't
    // be used to enumerate valid operator names. Short-circuiting on an unknown
    // name (skipping the two SHA-256 hashes) would leak existence by timing,
    // defeating the whole point of `constant_time_eq`.
    let stored = state.config.opers.iter().find(|(n, _)| n == name);
    let candidate_pw = stored
        .map(|(_, pw)| pw.as_bytes())
        .unwrap_or(b"\0no-such-oper\0");
    let matched = constant_time_eq(candidate_pw, password.as_bytes()) && stored.is_some();
    if !matched {
        // A security event, logged like a failed SASL attempt (one bounded
        // line per denial; the budget above caps how many one socket makes).
        // The offered operator name is client text, so it is logged escaped.
        let (nick, host) = {
            let session = &state.sessions[&conn];
            (
                session.nick().unwrap_or("*").to_string(),
                session.host.clone(),
            )
        };
        eprintln!("ircd: OPER authentication failed for {nick} from {host} as {name:?}");
        state.numeric(conn, ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
        return;
    }
    let nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    // The grant is recorded before it takes effect; one that cannot be
    // recorded does not happen.
    let operator = crate::db::AuditPrincipal::operator(&state.casemap.casefold(name));
    if queue_audit(state, &operator, "OPER", &operator, &format!("nick {nick}")).is_err() {
        send_server_notice(
            state,
            conn,
            "Services are temporarily unavailable; OPER not granted \
             (the audit trail cannot record it)",
        );
        return;
    }
    state.sessions.get_mut(&conn).expect("registered").oper = Some(name.to_string());
    you_are_oper(state, conn);
    let server = state.config.server_name.clone();
    state.send(conn, &format!(":{server} MODE {nick} :+o"));
}

fn you_are_oper(state: &mut ServerState, conn: ConnId) {
    state.numeric(
        conn,
        RPL_YOUREOPER,
        &[],
        Some("You are now an IRC operator"),
    );
}

/// Length-independent constant-time comparison: both inputs are reduced to a
/// fixed-size SHA-256 digest first, so neither content nor length leaks via
/// timing (a bare byte-compare early-returns on a length mismatch, leaking the
/// secret's length). The digests never leave the process — they exist only to
/// normalize length for the constant-time compare.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use aws_lc_rs::digest::{SHA256, digest};
    let da = digest(&SHA256, a);
    let db = digest(&SHA256, b);
    aws_lc_rs::constant_time::verify_slices_are_equal(da.as_ref(), db.as_ref()).is_ok()
}

/// Gate an oper-only command: reply `ERR_NOPRIVILEGES` and report `false`
/// when the connection is not an IRC operator.
pub(super) fn require_oper(state: &mut ServerState, conn: ConnId) -> bool {
    if state.sessions[&conn].oper.is_some() {
        return true;
    }
    state.numeric(
        conn,
        ERR_NOPRIVILEGES,
        &[],
        Some("Permission Denied- You're not an IRC operator"),
    );
    false
}

/// The nick of an operator `require_oper` admitted, who is registered.
fn oper_nick(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered")
}

// ---- KILL ---------------------------------------------------------------

pub(super) fn cmd_kill(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !require_oper(state, conn) {
        return;
    }
    let Some(&target) = p.first() else {
        state.err_needmoreparams(conn, "KILL");
        return;
    };
    let Some(victim) = state.registered_user(&state.nick_key(target)) else {
        state.err_nosuchnick(conn, target);
        return;
    };
    let killer = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    let killer_prefix = state.sessions[&conn].prefix();
    let operator = operator_name(state, conn);
    let comment = p.get(1).copied().unwrap_or("Killed").to_string();
    // Recorded here, where the operator is, before the kill is carried out on
    // whichever shard holds the victim; a kill that cannot be recorded is not
    // carried out.
    if queue_audit(
        state,
        &crate::db::AuditPrincipal::operator(&state.casemap.casefold(&operator)),
        "KILL",
        &crate::db::AuditPrincipal::nick(&victim.nick),
        &comment,
    )
    .is_err()
    {
        refuse_unaudited(state, conn, "KILL");
        return;
    }
    session_action(
        state,
        victim.conn(),
        crate::core::state::SessionAction::Kill {
            comment,
            killer,
            killer_prefix,
        },
    );
}

/// The configured operator name `conn` authenticated as with OPER — the actor
/// its privileged actions are recorded under. Callers have passed
/// [`require_oper`].
fn operator_name(state: &ServerState, conn: ConnId) -> String {
    state.sessions[&conn]
        .oper
        .clone()
        .expect("require_oper admitted an operator")
}

/// Tell an operator their command did nothing because its audit row could not
/// be queued.
fn refuse_unaudited(state: &mut ServerState, conn: ConnId, command: &str) {
    send_server_notice(
        state,
        conn,
        &format!(
            "Services are temporarily unavailable; {command} not performed \
             (the audit trail cannot record it)"
        ),
    );
}

/// Send `conn` a server NOTICE through the one fitted shape
/// ([`ServerState::server_notice_line`]): every operator-facing notice here
/// can carry an operator-typed mask, a stored ban reason or a host, none of
/// which a `format!`ed line would keep inside the wire limit.
fn send_server_notice(state: &mut ServerState, conn: ConnId, text: &str) {
    let line = state.server_notice_line(conn, text);
    state.send(conn, &line);
}

/// Carry out `action` on `conn`'s session: here if it lives on this shard,
/// otherwise by sending it to the shard it does live on. A session that is gone
/// by the time the action arrives has nothing left to act on.
pub(crate) fn session_action(
    state: &mut ServerState,
    conn: ConnId,
    action: crate::core::state::SessionAction,
) {
    let session = state.session_shard(conn);
    if !state.owns_session(session) {
        state.route_input(crate::core::Input::SessionAction { session, action });
        return;
    }
    match action {
        // Audited by the shard that decided it (see `cmd_kill`).
        crate::core::state::SessionAction::Kill {
            comment,
            killer,
            killer_prefix,
        } => {
            close_killed(state, conn, &comment, &killer, &killer_prefix);
        }
        crate::core::state::SessionAction::Ghost { by } => {
            let server = state.config.server_name.clone();
            let reason = format!("GHOST command used by {by}");
            state.send(conn, &format!("ERROR :Closing Link: {server} ({reason})"));
            state.close(conn, &reason);
        }
        crate::core::state::SessionAction::Regain { nick, by, by_mask } => {
            super::services::regain_nick_from(state, conn, nick, by, &by_mask);
        }
        crate::core::state::SessionAction::TakeNick { nick } => {
            super::services::take_regained_nick(state, conn, &nick);
        }
        crate::core::state::SessionAction::SetHost {
            host,
            oper,
            oper_nick,
        } => set_host(state, conn, &host, oper, &oper_nick),
    }
}

/// What became of a disconnect the control plane asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    Killed,
    /// No registered connection has that id.
    Missing,
    /// The audit row could not be queued, so the connection was left alone.
    AuditUnavailable,
}

/// Disconnect one exact registered connection, recording `actor` as the
/// killer. HTTP control-plane rows carry this immutable id, so a delayed form
/// or API request cannot follow a released nick onto a different client. The
/// KILL row is queued before the close — a self-kill removes the actor's own
/// session — and a kill whose row cannot be queued is not carried out.
pub(crate) fn kill_connection(
    state: &mut ServerState,
    victim: ConnId,
    comment: &str,
    actor: &str,
) -> KillOutcome {
    let Some(target) = registered_nick(state, victim) else {
        return KillOutcome::Missing;
    };
    if queue_audit(
        state,
        &crate::db::AuditPrincipal::account(&state.casemap.casefold(actor)),
        "KILL",
        &crate::db::AuditPrincipal::nick(&target),
        comment,
    )
    .is_err()
    {
        return KillOutcome::AuditUnavailable;
    }
    let server = state.config.server_name.clone();
    close_killed(state, victim, comment, actor, &server);
    KillOutcome::Killed
}

/// Disconnect every connection an account suspension ends. The suspension's
/// own durable record (`ACCOUNT_SUSPEND`, committed with the flag) covers
/// these closes, so none waits on — or is refused for — a KILL row of its
/// own: a suspension that could not disconnect would leave the account in.
pub(crate) fn disconnect_suspended(
    state: &mut ServerState,
    victim: ConnId,
    reason: &str,
    actor: &str,
) -> bool {
    if registered_nick(state, victim).is_none() {
        return false;
    }
    let server = state.config.server_name.clone();
    close_killed(state, victim, reason, actor, &server);
    true
}

fn registered_nick(state: &ServerState, conn: ConnId) -> Option<String> {
    state
        .sessions
        .get(&conn)
        .filter(|session| session.is_registered())
        .and_then(|session| session.nick())
        .map(str::to_owned)
}

/// Close a killed connection on the shard that holds it: tell the other
/// operators, then the victim — the `KILL` line from `source` (the operator's
/// prefix, or the server name for a control-plane kill), as Solanum sends it,
/// and the closing `ERROR`. The caller has already recorded the kill.
fn close_killed(
    state: &mut ServerState,
    victim: ConnId,
    comment: &str,
    killer: &str,
    source: &str,
) {
    let Some(target) = registered_nick(state, victim) else {
        return;
    };
    let reason = format!("Killed ({killer} ({comment}))");
    let server = state.config.server_name.clone();
    // Snotice every other oper (the victim, if an oper, is about to be closed).
    notify_opers(
        state,
        Some(victim),
        &format!("Received KILL message for {target} from {killer}: {comment}"),
    );
    // The reason is echoed inside this ERROR wrapper, whose overhead can push a
    // maximal KILL comment past the wire limit — fit it like the QUIT path does,
    // or the victim's framing discards the whole close notice (and the debug wire
    // check would abort the core worker on an oper-typed line). The trailing `)`
    // is part of the head's cost: include it before fitting, re-append after.
    let kill = fitted_line(format!(":{source} KILL {target} :"), comment);
    state.send(victim, &kill);
    let head = format!("ERROR :Closing Link: {server} (");
    let fitted = fit_trailing(&format!("{head})"), &reason);
    state.send(victim, &format!("{head}{fitted})"));
    state.close(victim, &reason);
}

/// The database queue would not take an audit row.
#[derive(Debug)]
pub(crate) struct AuditUnavailable;

/// Queue one audit row for a privileged action, recording `actor` (folded, as
/// every audit row names an account or operator). The caller performs the
/// action only when this succeeds: an action the audit trail cannot record is
/// refused, never done silently. A server without a database has no audit
/// trail to write, so there is nothing to refuse for.
pub(crate) fn queue_audit(
    state: &mut ServerState,
    actor: &crate::db::AuditPrincipal,
    action: &str,
    target: &crate::db::AuditPrincipal,
    detail: &str,
) -> Result<(), AuditUnavailable> {
    if !state.config.sasl_enabled {
        return Ok(());
    }
    let request = crate::core::DbRequest::AuditLog {
        actor: actor.clone(),
        action: action.to_string(),
        target: target.clone(),
        detail: detail.to_string(),
    };
    state.db_tx.try_push(request).map(|_| ()).map_err(|_| {
        eprintln!("audit: database queue full or closed; {action} refused");
        AuditUnavailable
    })
}

/// Broadcast an operator server-notice (snotice) to every registered operator,
/// optionally skipping one connection (`except`) — used to spare a KILL victim
/// who is about to be closed. This is the minimal snotice surface: there is no
/// `+s` server-notice mask yet, so every operator sees every privileged-action
/// notice rather than subscribing to flags. Best-effort, like any NOTICE.
pub(super) fn notify_opers(state: &mut ServerState, except: Option<ConnId>, text: &str) {
    let server = state.config.server_name.clone();
    // Every operator, on whichever shard: the published records.
    let recipients: Vec<_> = state
        .registered_users()
        .into_iter()
        .filter(|user| user.oper && Some(user.conn()) != except)
        .collect();
    for user in recipients {
        // `text` can embed client-controlled, unbounded data (a KILL comment, a
        // ban reason), so fit it to the wire limit per recipient — the head's
        // length varies with the recipient's nick — or a maximal comment pushes
        // the line past 512 and the recipient's framing discards it whole.
        let line = server_notice(&server, &user.nick, &format!("*** Notice -- {text}"));
        state.send_recipient_uncaptured(user.recipient, bytes::Bytes::from(line + "\r\n"));
    }
}

/// Normalise a K-line target: a bare host/nick becomes `*@target`.
/// Normalize a ban `arg` into a mask for `kind`. A KLINE `user@host` with a
/// bare token becomes `*@host`; DLINE (host/IP) and XLINE (realname) masks
/// are used verbatim.
pub(super) fn ban_mask(kind: BanKind, arg: &str) -> String {
    match kind {
        BanKind::Kline if !arg.contains('@') => format!("*@{arg}"),
        _ => arg.to_string(),
    }
}

/// Whether a glob token matches *any* value — non-empty and made only of `*`
/// (`*`, `**`, …). Such a token places no constraint at all.
fn glob_matches_all(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b == b'*')
}

/// A parsed, normalized server-ban target, produced *only* by [`BanMask::parse`].
///
/// Parsing is where three concerns that used to be separate ad-hoc steps in the
/// handler are unified — and, being the *only* constructor, is what makes their
/// failure modes unrepresentable downstream (DESIGN §2, "parse, don't validate"):
///
/// 1. **The reason/mask split.** An XLINE targets the gecos, which routinely
///    contains spaces, so its mask spans several IRC params; the reason is
///    present only when sent as a `:trailing`. Keying the split on `has_trailing`
///    here means no other code can re-derive it wrongly (the class of bug where
///    `XLINE *Evil Corp*` banned `*Evil` with reason `Corp*`).
/// 2. **Bare-host normalization** (`ban_mask`): a KLINE `host` becomes `*@host`.
/// 3. **The match-everyone refusal.** A mask that constrains nothing (`*@*`,
///    `*`) is an accidental server-wide ban; parse *rejects* it, so a `BanMask`
///    value that matches every user simply cannot exist — the handler never has
///    to guard against one because the type guarantees its absence.
pub(super) struct BanMask(String);

/// Why an oper's ban command yielded no [`BanMask`].
pub(super) enum BanReject {
    /// The normalized mask matches every user; refused to prevent a netban from
    /// a slipped glob. Carries the offending display mask for the notice.
    MatchesEveryone(String),
    /// The mask could never match as written: a D-line that is not an address,
    /// a CIDR range or an address glob (a D-line matches only the address a
    /// user connected from), or a CIDR host whose prefix is out of range.
    /// Carries the display mask and why.
    Invalid(String, &'static str),
}

impl BanReject {
    /// The refusal as the operator is told it, for a ban of kind `label`.
    /// The mask is shown clipped to the longest a mask may be, so the reason
    /// after it survives the notice's fit to the line.
    pub(super) fn describe(&self, label: &str) -> String {
        let shown = |mask: &str| {
            e6irc_proto::message::truncate_on_char_boundary(mask, super::channel::REALLEN)
                .to_string()
        };
        match self {
            Self::MatchesEveryone(mask) => format!(
                "Refusing {label} for {}: it matches every user (use a more specific mask)",
                shown(mask)
            ),
            Self::Invalid(mask, why) => format!("Refusing {label} for {}: {why}", shown(mask)),
        }
    }
}

/// Whether `mask` can be a D-line: an address or a CIDR range, or a glob made
/// only of address characters (`203.0.113.*`, `2001:db8:*`). A D-line is
/// matched against the address the user connected from and nothing else, so
/// a host name or a `user@host` could never match anyone.
fn valid_dline(mask: &str) -> bool {
    match crate::core::banmask::MaskShape::parse(mask) {
        Ok(crate::core::banmask::MaskShape::Cidr { head: None, .. }) => true,
        Ok(crate::core::banmask::MaskShape::Glob) => {
            mask.contains(['*', '?'])
                && mask
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '*' | '?'))
        }
        _ => false,
    }
}

impl BanMask {
    /// Parse a KLINE/DLINE/XLINE's parameter list into `(mask, reason)`.
    /// `params` is known non-empty by the caller (the bare-command *list* form
    /// is handled before parsing); `has_trailing` is whether the last parameter
    /// carried the `:` trailing marker.
    pub(super) fn parse(
        kind: BanKind,
        params: &[&str],
        has_trailing: bool,
    ) -> Result<(Self, String), BanReject> {
        // XLINE: the gecos mask spans every param; the reason is the last param
        // *iff* it was a trailing. KLINE/DLINE masks are spaceless, so mask is
        // the first param and reason the second (a spaces-in-reason KLINE also
        // uses the trailing, which lands as a single param).
        let (raw_mask, reason) = match kind {
            BanKind::Xline if has_trailing && params.len() >= 2 => (
                params[..params.len() - 1].join(" "),
                params[params.len() - 1].to_string(),
            ),
            BanKind::Xline => (params.join(" "), "No reason".to_string()),
            _ => (
                params[0].to_string(),
                params.get(1).copied().unwrap_or("No reason").to_string(),
            ),
        };
        // Bound the oper-supplied reason: it rides the victim's closing ERROR and
        // the ban-list NOTICE, both single lines the recipient's framing discards
        // whole past 512 bytes. 300 chars is ample with room for the wrapping.
        let reason = e6irc_proto::message::truncate_on_char_boundary(&reason, 300).to_string();
        let display = ban_mask(kind, &raw_mask);
        // Bound the mask like a channel ban's (BANMASKLEN): it rides the ban
        // list, STATS and every operator's notice, and no subject it could
        // match is longer — a `user@host` is far inside 100 bytes, a gecos
        // inside REALLEN. Refused rather than cut: a clipped glob bans
        // someone the operator did not name.
        let bound = match kind {
            BanKind::Xline => super::channel::REALLEN,
            BanKind::Kline | BanKind::Dline => super::channel::BANMASKLEN,
        };
        if display.len() > bound {
            let why = match kind {
                BanKind::Xline => "a realname mask is at most 150 bytes (REALLEN)",
                BanKind::Kline | BanKind::Dline => "a mask is at most 100 bytes (BANMASKLEN)",
            };
            return Err(BanReject::Invalid(display, why));
        }
        // A mask that constrains nothing bans everyone. `user@host` is a netban
        // only when *both* sides are pure wildcard; a single-field DLINE/XLINE
        // glob is one when the whole field is.
        let matches_everyone = match kind {
            BanKind::Kline => match display.split_once('@') {
                Some((user, host)) => glob_matches_all(user) && glob_matches_all(host),
                None => glob_matches_all(&display),
            },
            BanKind::Dline | BanKind::Xline => glob_matches_all(&display),
        };
        if matches_everyone {
            return Err(BanReject::MatchesEveryone(display));
        }
        match kind {
            BanKind::Dline if !valid_dline(&display) => {
                return Err(BanReject::Invalid(
                    display,
                    "a D-line is an IP address, a CIDR range, or an IP glob",
                ));
            }
            BanKind::Kline => {
                if let Err(error) = crate::core::banmask::MaskShape::parse(&display) {
                    return Err(BanReject::Invalid(display, error.describe()));
                }
            }
            BanKind::Dline | BanKind::Xline => {}
        }
        Ok((BanMask(display), reason))
    }

    /// The normalized display mask (operator's casing preserved).
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// KLINE/DLINE/XLINE [<mask> [reason]] — oper-only. With no argument, list
/// the current bans of this kind; otherwise add one (persisted; matching
/// registered sessions are disconnected).
pub(super) fn cmd_add_ban(
    state: &mut ServerState,
    conn: ConnId,
    kind: BanKind,
    p: &[&str],
    has_trailing: bool,
) {
    if !require_oper(state, conn) {
        return;
    }
    let label = kind.label();
    let nick = oper_nick(state, conn);
    if p.is_empty() {
        // List current bans of this kind.
        let now_secs = (state.config.clock)().as_secs();
        let lines: Vec<String> = state
            .server_bans_in_force()
            .filter(|b| b.kind == kind)
            .map(|b| {
                let temporary = b.minutes_left(now_secs).map_or(String::new(), |left| {
                    format!(" (temporary, {left} min. left)")
                });
                state.server_notice_line(
                    conn,
                    &format!(
                        "{label} {}{temporary} (by {}) :{}",
                        b.mask.as_str(),
                        b.set_by,
                        b.reason
                    ),
                )
            })
            .collect();
        for line in lines {
            state.send(conn, &line);
        }
        send_server_notice(state, conn, &format!("End of {label} list."));
        return;
    }
    // Enforcement folds mask and subject under the casemap (`mask::matches`), so
    // the stored mask must fold for comparison too: otherwise `KLINE Baddie@Host`
    // then `UNKLINE baddie@host` would compare case-sensitively, fail to remove,
    // and report "no such ban" while the ban keeps enforcing — and two
    // case-variants would double-store. A `MaskKey` folds for equality while
    // keeping the display casing, so the hot list, the DB `ON CONFLICT`/`DELETE`
    // keys, and matching all agree — the same discipline the channel
    // `+b/+q/+e/+I` lists use.
    let casemap = state.casemap;
    // A leading all-digits argument is a temporary ban's length in minutes
    // (Solanum's `valid_temp_time`), `0` a permanent ban; a mask must follow.
    let (minutes, p) = match p.split_first() {
        Some((first, rest)) => match temporary_minutes(first) {
            Some(minutes) => (Some(minutes), rest),
            None => (None, p),
        },
        None => (None, p),
    };
    if p.is_empty() {
        state.err_needmoreparams(conn, kind.add_command());
        return;
    }
    // A K-line target that can only be a nick — no `@`, nothing a host or an
    // address holds, no glob — bans that user's host, `*@<host>`, and needs
    // the user online to find it (the ratbox-family nick K-line).
    let nick_host;
    let mut params = p.to_vec();
    if kind == BanKind::Kline && names_a_nick(params[0]) {
        let Some(user) = state.registered_user(&state.nick_key(params[0])) else {
            state.err_nosuchnick(conn, params[0]);
            return;
        };
        nick_host = format!("*@{}", user.host);
        params[0] = &nick_host;
    }
    // Parse the params into a guaranteed-well-formed target: the reason/mask
    // split (XLINE-aware, keyed on the trailing marker), the `*@host`
    // normalization, the length bound and the match-everyone refusal all
    // happen inside `BanMask::parse`, so nothing below can see a mis-split
    // fragment or a netban mask. A rejection is reported loudly, never
    // silently narrowed.
    let (parsed_mask, reason) = match BanMask::parse(kind, &params, has_trailing) {
        Ok(parsed) => parsed,
        Err(reject) => {
            send_server_notice(state, conn, &reject.describe(label));
            return;
        }
    };
    let now_secs = (state.config.clock)().as_secs();
    let expiry = minutes
        .and_then(std::num::NonZeroU32::new)
        .map(|minutes| crate::core::ServerBanExpiry::starting(now_secs, minutes));
    // A MaskKey folds for comparison (so a differently-cased UN*LINE removes it)
    // while keeping the operator's casing for STATS and the confirmation — the
    // same discipline the channel ban lists use.
    let mask = crate::core::state::MaskKey::new(parsed_mask.as_str(), casemap);
    let mutation = crate::core::ServerBanMutation::add(&mask, kind, reason, nick.clone(), expiry);
    if !state.config.sasl_enabled {
        send_server_notice(state, conn, &ban_added_text(kind, mask.as_str(), expiry));
        commit_server_ban(state, mutation);
        return;
    }
    begin_oper_server_ban(state, conn, label, &mask, mutation);
}

/// A KLINE/DLINE/XLINE's leading duration (Solanum's `valid_temp_time`): an
/// all-digits argument is minutes, held to
/// [`crate::core::ServerBanExpiry::MAX_MINUTES`] as Solanum holds a longer
/// one; `Some(0)` is a permanent ban. `None` when `arg` is not a duration.
fn temporary_minutes(arg: &str) -> Option<u32> {
    if arg.is_empty() || !arg.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // All digits, so only a number too long for `u64` fails to parse — and it
    // is past the maximum like any other long one.
    let minutes = arg.parse::<u64>().unwrap_or(u64::MAX);
    let max = crate::core::ServerBanExpiry::MAX_MINUTES;
    Some(u32::try_from(minutes).map_or(max, |minutes| minutes.min(max)))
}

/// Whether a K-line target can only be a nick: no `@` (a `user@host`), no
/// `.` `:` `/` (a host, an address, a range) and no glob (`*`, `?`), none of
/// which a nick may hold.
fn names_a_nick(target: &str) -> bool {
    !target.is_empty() && !target.contains(['@', '.', ':', '/', '*', '?'])
}

/// The confirmation of an added ban, as the operator and the console are told
/// it: `Added K-Line for <mask>`, or Solanum's `Added temporary <n> min.
/// K-Line for <mask>`.
pub(super) fn ban_added_text(
    kind: BanKind,
    mask: &str,
    expiry: Option<crate::core::ServerBanExpiry>,
) -> String {
    match expiry {
        Some(expiry) => format!(
            "Added temporary {} min. {} for {mask}",
            expiry.minutes,
            kind.label()
        ),
        None => format!("Added {} for {mask}", kind.label()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueServerBanError {
    AlreadyPending,
    PersistenceUnavailable,
}

/// Reserve and enqueue exactly one mutation of a durable server-ban row.
///
/// IRC and HTTP callers share this boundary so pending-row serialization and
/// the "reserve only after enqueue" ordering cannot drift between origins.
pub(crate) fn queue_server_ban_mutation(
    state: &mut ServerState,
    mutation: crate::core::ServerBanMutation,
    requester: crate::core::ServerBanRequester,
) -> Result<(), QueueServerBanError> {
    let (kind, mask) = mutation.key();
    let pending_key = (kind.to_string(), mask.to_string());
    if state.pending_server_bans.contains(&pending_key) {
        return Err(QueueServerBanError::AlreadyPending);
    }
    let request = crate::core::DbRequest::MutateServerBan {
        mutation,
        requester,
    };
    state
        .db_tx
        .try_push(request)
        .map_err(|_| QueueServerBanError::PersistenceUnavailable)?;
    state.pending_server_bans.insert(pending_key);
    Ok(())
}

fn begin_oper_server_ban(
    state: &mut ServerState,
    conn: ConnId,
    label: &str,
    mask: &crate::core::state::MaskKey,
    mutation: crate::core::ServerBanMutation,
) {
    let unavailable_action = match &mutation {
        crate::core::ServerBanMutation::Add { .. } => "added",
        crate::core::ServerBanMutation::Remove { .. } => "removed",
    };
    let response_label = state.capture.as_ref().and_then(|cap| cap.label.clone());
    let requester = crate::core::ServerBanRequester::Oper {
        session: state.session_owner(conn),
        label: response_label,
        operator: operator_name(state, conn),
    };
    match queue_server_ban_mutation(state, mutation, requester) {
        Ok(()) => {
            state.defer_captured_reply(conn);
        }
        Err(error) => {
            let message = match error {
                QueueServerBanError::AlreadyPending => format!(
                    "A {label} change for {} is already in progress",
                    mask.as_str()
                ),
                QueueServerBanError::PersistenceUnavailable => format!(
                    "Services are temporarily unavailable; {label} not {unavailable_action}"
                ),
            };
            send_server_notice(state, conn, &message);
        }
    }
}

/// Apply a database-confirmed server ban to live state and disconnect matches.
fn apply_server_ban_hot(state: &mut ServerState, ban: ServerBan) {
    let casemap = state.casemap;
    let label = ban.kind.label();
    // Replace any existing ban of this kind on the same mask (folded equality).
    state
        .server_bans
        .retain(|b| !(b.kind == ban.kind && b.mask == ban.mask));
    state.server_bans.push(ban.clone());
    // A temporary ban that lapsed on its way here bans no one.
    if !ban.in_force((state.config.clock)().as_secs()) {
        return;
    }
    // Disconnect any matching registered sessions (possibly including the setter
    // when driven by an oper).
    let victims: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.is_registered())
        .filter_map(|(&c, s)| ban.matches(casemap, &s.server_ban_subject()).then_some(c))
        .collect();
    // The victim, and the peers its QUIT reaches, see only the public half of
    // a `public|private` reason.
    let reason = crate::core::state::public_ban_reason(&ban.reason);
    for victim in victims {
        // A stored reason is bounded where a ban is set, but a row written by
        // an older build or by hand is not: fit it like the KILL close.
        let head = format!("ERROR :Closing Link: ({label}d: ");
        let fitted = fit_trailing(&format!("{head})"), reason);
        state.send(victim, &format!("{head}{fitted})"));
        state.close(victim, &format!("{label}d: {reason}"));
    }
}

/// Stop enforcing the temporary server bans that have lapsed, and tell this
/// shard's operators (Solanum's `Temporary K-line for [mask] expired`). Every
/// shard runs this on the same tick against its own copy of the list, so each
/// operator hears of an expiry once, from the shard its session lives on. The
/// database row is left to storage maintenance.
pub(crate) fn expire_server_bans(state: &mut ServerState) {
    let now_secs = (state.config.clock)().as_secs();
    if state.server_bans.iter().all(|ban| ban.in_force(now_secs)) {
        return;
    }
    let (lapsed, kept): (Vec<ServerBan>, Vec<ServerBan>) = std::mem::take(&mut state.server_bans)
        .into_iter()
        .partition(|ban| !ban.in_force(now_secs));
    state.server_bans = kept;
    let operators: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, session)| session.is_registered() && session.oper.is_some())
        .map(|(&conn, _)| conn)
        .collect();
    for ban in lapsed {
        let text = format!(
            "*** Notice -- Temporary {} for {} expired",
            ban.kind.label(),
            ban.mask.as_str()
        );
        for &conn in &operators {
            send_server_notice(state, conn, &text);
        }
    }
}

/// Remove a database-confirmed server ban from the hot list.
pub(crate) fn remove_server_ban_hot(
    state: &mut ServerState,
    mask: &crate::core::state::MaskKey,
    kind: BanKind,
) -> bool {
    let before = state.server_bans.len();
    state
        .server_bans
        .retain(|b| !(b.kind == kind && b.mask == *mask));
    state.server_bans.len() < before
}

/// Answer the operator whose server-ban command has been waiting on its
/// database verdict. Every verdict for an operator requester ends here, so the
/// reply the connection's output is held behind always arrives.
fn server_ban_oper_verdict(
    state: &mut ServerState,
    conn: ConnId,
    response_label: Option<String>,
    text: &str,
) {
    if !state.sessions.contains_key(&conn) {
        return;
    }
    state.emit_deferred_labeled(conn, response_label, |state| {
        send_server_notice(state, conn, text);
    });
}

/// What a database verdict on a server-ban mutation leaves to be done, once
/// the requester has been answered.
#[derive(Debug)]
pub(crate) enum ServerBanVerdict {
    /// The change did not happen (the database was unavailable, or a removal
    /// pinned to a row id found that row already gone); the hot lists stand.
    Nothing,
    /// The database holds the change: every shard enforces it, and the
    /// operators hear of it once.
    Committed(crate::core::ServerBanMutation),
    /// A removal keyed only by mask found no row: the database holds no such
    /// ban, so every shard stops enforcing one. Nothing was removed, so there
    /// is nothing to announce — the requester was told there was no stored ban.
    Unstored(crate::core::ServerBanMutation),
}

pub(crate) fn server_ban_result(
    state: &mut ServerState,
    mutation: crate::core::ServerBanMutation,
    requester: crate::core::ServerBanRequester,
    result: crate::core::ServerBanResult,
) -> ServerBanVerdict {
    let (kind_token, folded_mask) = mutation.key();
    state
        .pending_server_bans
        .remove(&(kind_token.to_string(), folded_mask.to_string()));
    let Some(kind) = BanKind::from_token(kind_token) else {
        eprintln!("core: database echoed invalid server-ban kind {kind_token:?}");
        finish_server_ban_unavailable(state, requester, "server-ban result was invalid");
        return ServerBanVerdict::Nothing;
    };
    if result == crate::core::ServerBanResult::Unavailable {
        finish_server_ban_unavailable(state, requester, "services are temporarily unavailable");
        return ServerBanVerdict::Nothing;
    }
    if result == crate::core::ServerBanResult::Missing {
        // A removal keyed only by (mask, kind) found no row, so the database
        // holds no such ban and the hot list must stop enforcing one. A removal
        // pinned to a row id proves only that *that* row is gone — the mask may
        // have been banned again under a new id — so it reconciles nothing.
        let unstored = matches!(
            &mutation,
            crate::core::ServerBanMutation::Remove {
                expected_id: None,
                ..
            }
        );
        let (crate::core::ServerBanMutation::Add { mask_display, .. }
        | crate::core::ServerBanMutation::Remove { mask_display, .. }) = &mutation;
        finish_server_ban(
            state,
            requester,
            &format!("No stored {} for {mask_display}", kind.label()),
            crate::core::AdminReply::BanErr {
                kind: crate::core::BanControlError::NotFound,
                message: "server ban no longer exists".into(),
            },
        );
        return if unstored {
            ServerBanVerdict::Unstored(mutation)
        } else {
            ServerBanVerdict::Nothing
        };
    }

    let text = match &mutation {
        crate::core::ServerBanMutation::Add {
            mask_display,
            expiry,
            ..
        } => ban_added_text(kind, mask_display, *expiry),
        crate::core::ServerBanMutation::Remove { mask_display, .. } => {
            format!("Removed {} for {mask_display}", kind.label())
        }
    };
    finish_server_ban(
        state,
        requester,
        &text,
        crate::core::AdminReply::Ok(text.clone()),
    );
    ServerBanVerdict::Committed(mutation)
}

/// Deliver one server-ban verdict to whoever asked for the change: the
/// operator's NOTICE, or the administrative request's reply.
fn finish_server_ban(
    state: &mut ServerState,
    requester: crate::core::ServerBanRequester,
    operator_text: &str,
    admin_reply: crate::core::AdminReply,
) {
    match requester {
        crate::core::ServerBanRequester::Oper { session, label, .. } => {
            server_ban_oper_verdict(state, session.conn(), label, operator_text);
        }
        crate::core::ServerBanRequester::Admin { request_id, .. } => {
            finish_admin_server_ban(state, request_id, admin_reply);
        }
    }
}

/// Commit a server-ban change this shard decided: enforce it here and on
/// every other shard, and tell the operators — once. The other shards apply
/// the broadcast copy without announcing ([`apply_committed_server_ban`]).
pub(crate) fn commit_server_ban(state: &mut ServerState, mutation: crate::core::ServerBanMutation) {
    reconcile_server_ban_everywhere(state, mutation.clone());
    announce_server_ban(state, &mutation);
}

/// Bring every shard's hot list in line with a committed transition, without
/// an announcement: for a removal that found no stored ban, nothing happened
/// that another operator need hear of.
pub(crate) fn reconcile_server_ban_everywhere(
    state: &mut ServerState,
    mutation: crate::core::ServerBanMutation,
) {
    apply_committed_server_ban(state, mutation.clone());
    state.broadcast_server_ban_after_local_apply(mutation);
}

/// Apply a committed server-ban transition on one shard: the hot list, and
/// the disconnection of local sessions the ban matches. Nothing is announced
/// here — the committing shard does that, once, in [`commit_server_ban`].
pub(crate) fn apply_committed_server_ban(
    state: &mut ServerState,
    mutation: crate::core::ServerBanMutation,
) {
    match mutation {
        crate::core::ServerBanMutation::Add {
            mask_display,
            reason,
            set_by,
            kind,
            expiry,
            ..
        } => {
            let (kind, mask, _) = committed_ban_parts(state, &kind, &mask_display);
            apply_server_ban_hot(
                state,
                ServerBan {
                    mask,
                    reason,
                    set_by,
                    kind,
                    expires_at_secs: expiry.map(|expiry| expiry.expires_at_secs),
                },
            );
        }
        crate::core::ServerBanMutation::Remove {
            mask_display, kind, ..
        } => {
            let (kind, mask, _) = committed_ban_parts(state, &kind, &mask_display);
            remove_server_ban_hot(state, &mask, kind);
        }
    }
}

/// The operator server-notice for a committed server-ban change.
fn announce_server_ban(state: &mut ServerState, mutation: &crate::core::ServerBanMutation) {
    let text = match mutation {
        crate::core::ServerBanMutation::Add {
            mask_display,
            reason,
            set_by,
            kind,
            expiry,
            ..
        } => {
            let (_, mask, label) = committed_ban_parts(state, kind, mask_display);
            let temporary = expiry.map_or(String::new(), |expiry| {
                format!("temporary {} min. ", expiry.minutes)
            });
            format!(
                "{set_by} added {temporary}{label} for {} ({reason})",
                mask.as_str()
            )
        }
        crate::core::ServerBanMutation::Remove {
            mask_display,
            actor,
            kind,
            ..
        } => {
            let (_, mask, label) = committed_ban_parts(state, kind, mask_display);
            format!("{actor} removed {label} for {}", mask.as_str())
        }
    };
    notify_opers(state, None, &text);
}

fn committed_ban_parts(
    state: &ServerState,
    kind: &str,
    mask_display: &str,
) -> (BanKind, crate::core::state::MaskKey, &'static str) {
    let Some(kind) = BanKind::from_token(kind) else {
        panic!("validated server-ban mutation has invalid kind");
    };
    let mask = crate::core::state::MaskKey::new(mask_display, state.casemap);
    (kind, mask, kind.label())
}

fn finish_server_ban_unavailable(
    state: &mut ServerState,
    requester: crate::core::ServerBanRequester,
    reason: &str,
) {
    finish_server_ban(
        state,
        requester,
        &format!("Server-ban change failed: {reason}"),
        crate::core::AdminReply::BanErr {
            kind: crate::core::BanControlError::Unavailable,
            message: format!("server-ban change failed: {reason}"),
        },
    );
}

fn finish_admin_server_ban(
    state: &mut ServerState,
    request_id: u64,
    outcome: crate::core::AdminReply,
) {
    match state.pending_admin_server_bans.remove(&request_id) {
        Some(reply) => {
            let _ = reply.send(outcome);
        }
        None => {
            eprintln!("core: server-ban verdict for unknown admin request {request_id}");
        }
    }
}

/// UNKLINE/UNDLINE/UNXLINE <mask> — oper-only. Remove a server ban of the
/// given kind.
pub(super) fn cmd_remove_ban(state: &mut ServerState, conn: ConnId, kind: BanKind, p: &[&str]) {
    if !require_oper(state, conn) {
        return;
    }
    let label = kind.label();
    if p.is_empty() {
        state.err_needmoreparams(conn, kind.remove_command());
        return;
    }
    // Fold to match the folded storage (see cmd_add_ban) so removal is
    // case-insensitive like enforcement — a ban set as `Baddie@Host` is removed
    // by `baddie@host`, and the DB delete key matches the stored (folded) mask.
    // An XLINE mask has no reason, so its whole (space-containing) argument is
    // the mask — rejoin the tokenized params to match how it was stored.
    let casemap = state.casemap;
    let raw_mask = match kind {
        BanKind::Xline => p.join(" "),
        _ => p[0].to_string(),
    };
    let mask = crate::core::state::MaskKey::new(&ban_mask(kind, &raw_mask), casemap);
    let nick = oper_nick(state, conn);
    let exists = state
        .server_bans_in_force()
        .any(|ban| ban.kind == kind && ban.mask == mask);
    if !exists {
        send_server_notice(
            state,
            conn,
            &format!("No {label} found for {}", mask.as_str()),
        );
        return;
    }
    if !state.config.sasl_enabled {
        commit_server_ban(
            state,
            crate::core::ServerBanMutation::remove(&mask, kind, nick.clone()),
        );
        send_server_notice(
            state,
            conn,
            &format!("Removed {label} for {}", mask.as_str()),
        );
        return;
    }
    let mutation = crate::core::ServerBanMutation::remove(&mask, kind, nick);
    begin_oper_server_ban(state, conn, label, &mask, mutation);
}

/// SETHOST <nick> <host> — oper-only. Change a user's displayed host
/// (cloak) and announce it via CHGHOST to capable peers. This is the
/// host-change trigger the chghost cap needs.
pub(super) fn cmd_sethost(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !require_oper(state, conn) {
        return;
    }
    let (Some(&nick), Some(&newhost)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "SETHOST");
        return;
    };
    let oper_nick = oper_nick(state, conn);
    if !valid_visible_host(newhost) {
        send_server_notice(state, conn, &format!("Invalid host: {newhost}"));
        return;
    }
    let Some(target) = state.registered_user(&state.nick_key(nick)) else {
        state.err_nosuchnick(conn, nick);
        return;
    };
    let operator = operator_name(state, conn);
    if queue_audit(
        state,
        &crate::db::AuditPrincipal::operator(&state.casemap.casefold(&operator)),
        "SETHOST",
        &crate::db::AuditPrincipal::nick(nick),
        newhost,
    )
    .is_err()
    {
        refuse_unaudited(state, conn, "SETHOST");
        return;
    }
    let oper = state.session_shard(conn);
    session_action(
        state,
        target.conn(),
        crate::core::state::SessionAction::SetHost {
            host: newhost.to_string(),
            oper,
            oper_nick,
        },
    );
}

/// Whether `host` may be set as a user's visible host: Solanum's `clean_host`
/// whitelist. Only letters, digits and `.` `-` `:` `/`, so it can never be a
/// glob (`*`, `?`) that makes every ban on the user ambiguous, a list (`,`), or
/// a prefix or parameter breaker (`@`, `!`, space). It may not start with `:`
/// — it rides as a middle parameter (CHGHOST, 396, WHO), where a leading `:`
/// would open the trailing early — and the part after its last `/` may not
/// start with a digit, so it cannot read as a CIDR range. It rides in every
/// prefix built for the user, so it is bounded too: 63 bytes, the DNS
/// hostname norm.
fn valid_visible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 63
        && !host.starts_with(':')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'/'))
        && host
            .rsplit_once('/')
            .is_none_or(|(_, tail)| !tail.starts_with(|c: char| c.is_ascii_digit()))
}

/// Apply a SETHOST on the shard the target's session lives on.
fn set_host(
    state: &mut ServerState,
    target: ConnId,
    newhost: &str,
    oper: crate::core::SessionOwner,
    oper_nick: &str,
) {
    let Some(session) = state.sessions.get_mut(&target) else {
        return;
    };
    let (nick, user, old_prefix) = (
        session.nick().map(String::from).unwrap_or_default(),
        session.user().map(String::from).unwrap_or_default(),
        session.prefix(),
    );
    session.host = newhost.to_string();

    // Announce with the old prefix so clients can match, to every
    // chghost-capable peer (including the target), then to extended-monitor
    // watchers of the target's nick. A channel peer without `chghost` sees the
    // user quit and rejoin under the new hostmask instead (chghost spec's
    // fallback), or it would keep matching the old one.
    let chghost = state.user_line(target, format!(":{old_prefix} CHGHOST {user} {newhost}"));
    let session = &state.sessions[&target];
    let fallback = crate::core::state::HostChangeFallback {
        quit: chghost.with_body(format!(":{old_prefix} QUIT :Changing host")),
        prefix: session.prefix(),
        nick: nick.clone(),
        account: session.account().map(str::to_owned),
        realname: session.realname().unwrap_or_default().to_string(),
        away: session.away.clone(),
    };
    let include_self = session.caps.chghost;
    state.notify_host_change(target, &chghost, include_self, fallback);
    // A chghost-capable target learned of the change from the CHGHOST above; a
    // client without the cap would otherwise never be told its own host moved.
    // Fill that gap with RPL_VISIBLEHOST so every target learns its new visible
    // host — the CHGHOST is for *other* clients' view, 396 is for the target's.
    if !state.sessions[&target].caps.chghost {
        state.numeric(
            target,
            RPL_VISIBLEHOST,
            &[Middle::own(newhost)],
            Some("is now your visible host"),
        );
    }
    let server = state.config.server_name.clone();
    let line = server_notice(
        &server,
        oper_nick,
        &format!("Set host of {nick} to {newhost}"),
    );
    state.send_recipient_uncaptured(
        crate::core::state::Recipient::new(oper, Default::default()),
        bytes::Bytes::from(line + "\r\n"),
    );
}

// ---- WALLOPS ------------------------------------------------------------

pub(super) fn cmd_wallops(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !require_oper(state, conn) {
        return;
    }
    // Empty text (`WALLOPS :`) is ERR_NEEDMOREPARAMS, not an empty broadcast to
    // every +w oper.
    let Some(&text) = p.first().filter(|t| !t.is_empty()) else {
        state.err_needmoreparams(conn, "WALLOPS");
        return;
    };
    let prefix = state.sessions[&conn].prefix();
    // Relayed under the oper's prefix, so fit like every other client-text relay.
    let head = format!(":{prefix} WALLOPS :");
    let text = crate::core::handler::fit_trailing(&head, text);
    let line = state.user_line(conn, format!("{head}{text}"));
    let recipients: Vec<_> = state
        .registered_users()
        .into_iter()
        .filter(|user| user.wallops)
        .map(|user| user.recipient)
        .collect();
    for recipient in recipients {
        state.send_event_recipient(recipient, &line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal names the bound it enforces, so the two cannot drift.
    #[test]
    fn a_ban_mask_refusal_names_the_bound_it_enforces() {
        use super::super::channel::{BANMASKLEN, REALLEN};
        for (kind, bound) in [
            (BanKind::Kline, BANMASKLEN),
            (BanKind::Dline, BANMASKLEN),
            (BanKind::Xline, REALLEN),
        ] {
            let mask = "1".repeat(bound + 1);
            match BanMask::parse(kind, &[mask.as_str()], false) {
                Err(BanReject::Invalid(_, why)) => {
                    assert!(why.contains(&format!("at most {bound} bytes")), "{why}");
                }
                _ => panic!(
                    "{}: a {}-byte mask was not refused",
                    kind.label(),
                    mask.len()
                ),
            }
        }
    }
}
